import { createHash } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import {
  EMPTY_BODY_SHA256_HEX,
  randomNonce,
  signPopAuthorization,
  toBase64Url,
  type PopFields,
} from '@ashaveri/receipt';
import { newBearerCredential, newPopCredential, serializeCredentialFile } from '../src/access.js';
import { MINIMUM_RETENTION_SECONDS, RECEIPT_STORE_FILE } from '../src/store.js';

const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
const tempDir = mkdtempSync(join(tmpdir(), 'ashaveri-signerd-'));
const MANIFEST = join(tempDir, 'weights-manifest.json');
writeFileSync(MANIFEST, `{"files":[{"name":"model.safetensors","sha256":"${'ab'.repeat(32)}"}]}`);

const CREDENTIALS = join(tempDir, 'credentials.json');
const ACCESS_DIR = join(tempDir, 'access');
mkdirSync(ACCESS_DIR);
/** An empty list is a valid file: nothing is admitted, which is a starting point and not an error. */
writeFileSync(CREDENTIALS, '{"version":1,"credentials":[]}');

let written = 0;
function credentialFile(text: string): string {
  written += 1;
  const path = join(tempDir, `creds-${String(written)}.json`);
  writeFileSync(path, text);
  return path;
}

afterAll(() => {
  rmSync(tempDir, { recursive: true, force: true });
});

function run(...args: string[]) {
  const env = { ...process.env };
  delete env['DSTACK_SIMULATOR_ENDPOINT'];
  // Every case below is an exit path, so a process still alive after eight seconds is a bug rather
  // than a slow machine. The deadline is what turns a handle that never closes into the named
  // failure on the next line instead of a CI job that waits forever.
  const result = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    env,
    timeout: 8000,
    killSignal: 'SIGKILL',
  });
  // Without this a process that never started leaves `status` null, which reads as the CLI
  // exiting with the wrong code rather than as the spawn itself failing.
  expect(result.error).toBeUndefined();
  return result;
}

/**
 * Start a gateway that serves, read what it printed, and stop it. Every other case in this file is an
 * exit path, so the command returns by itself; a booted gateway has no such ending, which is why the
 * spawn timeout here is the way the test finishes rather than a symptom of one failing.
 */
function runStopped(...args: string[]) {
  const env = { ...process.env };
  delete env['DSTACK_SIMULATOR_ENDPOINT'];
  const result = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    env,
    timeout: 4000,
    killSignal: 'SIGKILL',
  });
  // The only acceptable error is the stop itself: anything else means the process died on its own,
  // and its stdout would then be a refusal message rather than the banner under test. A CLI that
  // grows an exit path of its own must not pass that check by printing a line about a timeout.
  const stopped = result.error as (Error & { code?: string }) | undefined;
  expect(stopped?.code, `the spawn ended with: ${JSON.stringify(result.error)}`).toBe('ETIMEDOUT');
  return result.stdout.split('\n');
}

/**
 * Live mode asks for a credential file and an access log directory before it does anything else, so a
 * case about `--tee` or `--public-url` has to carry them too. A case that is *about* one of those two
 * flags passes its own value after these, and the later one wins.
 */
function liveArgs(...args: string[]): string[] {
  return [
    '--live',
    '--public-url',
    'https://inference.ashaveri.test',
    '--weights-manifest',
    MANIFEST,
    '--credentials-path',
    CREDENTIALS,
    '--access-log-path',
    ACCESS_DIR,
    ...args,
  ];
}

/** The durability bound and the serving bound `gateway/src/cli.ts` opens a volume store with. Both are
 * shipped at ten thousand receipts, which is a capacity decision and not a figure either count owes
 * the other. */
const SHIPPED_RECEIPT_BOUND = 10_000;

/**
 * One receipt record built from the layout the store documents, the way `gateway/test/store.test.ts`
 * builds them: a test that asked the store to write its own fixture would be checking a claim against
 * the source of the claim, and a change to the layout would move both at once.
 *
 * `Record = len:u32 || kind:u8 || prev:32 || iat:u64 || idLen:u16 || id || payload || digest:32`, with
 * the digest taken over kind through payload.
 */
function receiptFrame(prev: Uint8Array, iat: number, id: string, payload: Buffer): Buffer {
  const idBytes = Buffer.from(id, 'utf8');
  const body = Buffer.alloc(1 + 32 + 8 + 2 + idBytes.length + payload.length);
  body.writeUInt8(0, 0);
  Buffer.from(prev).copy(body, 1);
  body.writeBigUInt64BE(BigInt(iat), 33);
  body.writeUInt16BE(idBytes.length, 41);
  idBytes.copy(body, 43);
  payload.copy(body, 43 + idBytes.length);
  const digest = Buffer.from(createHash('sha256').update(body).digest());
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32BE(body.length + digest.length);
  return Buffer.concat([prefix, body, digest]);
}

/**
 * A `receipts.log` carrying `count` receipts spread back over the last `seconds` at the hundred
 * requests a second `docs/access-control.md` states for one address, written in one go.
 *
 * The stamps are taken off the current clock rather than fixed, because the CLI opens a volume with
 * the platform clock and its own 184 day age bound: a fixture stamped in the past would be aged out
 * before the pairing was ever asked about, and the case would be about the clock instead of the bound.
 *
 * Written directly rather than through `openFileReceiptStore` because that store fsyncs every append,
 * and a volume has to reach the bound the CLI sets in the CLI's own terms for the start-up question to
 * be asked at all.
 */
function writeHeldStore(dir: string, count: number, seconds: number): Buffer {
  const newest = Math.floor(Date.now() / 1000);
  const perSecond = Math.max(1, Math.ceil(count / seconds));
  const frames: Buffer[] = [];
  let prev: Uint8Array = new Uint8Array(32);
  let written = 0;
  while (written < count) {
    for (let at = 0; at < perSecond && written < count; at++, written++) {
      const age = Math.floor(written / perSecond);
      const frame = receiptFrame(prev, newest - age, `rcpt_${String(written)}`, Buffer.alloc(8, 7));
      prev = frame.subarray(frame.length - 32);
      frames.push(frame);
    }
  }
  const bytes = Buffer.concat(frames);
  writeFileSync(join(dir, RECEIPT_STORE_FILE), bytes);
  return bytes;
}

/**
 * Start a gateway that serves, and stop it. `runStopped` cannot carry a case about a request: its
 * `spawnSync` blocks until the spawn timeout fires, and by then the process is gone. This resolves on
 * the listening line, which is why `--port 0` prints the port the operating system bound rather than
 * the zero it was asked for, and hands back a `kill` that waits for the exit event, so a case cannot
 * leave a child or its socket behind.
 */
async function bootServing(args: string[]): Promise<{ readonly port: number; readonly kill: () => Promise<void> }> {
  const env = { ...process.env };
  delete env['DSTACK_SIMULATOR_ENDPOINT'];
  const child = spawn(process.execPath, [CLI, '--mock', '--port', '0', ...args], {
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let out = '';
  const stopped = new Promise<void>((resolve) => child.once('exit', () => resolve()));
  const kill = async (): Promise<void> => {
    child.kill('SIGKILL');
    await stopped;
  };
  try {
    child.stdout.setEncoding('utf8');
    child.stderr.resume();
    const port = await new Promise<number>((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new Error(`no listening line within 10s; stdout held ${JSON.stringify(out)}`)),
        10_000,
      );
      const giveUp = (message: string): void => {
        clearTimeout(timer);
        reject(new Error(`${message}; stdout held ${JSON.stringify(out)}`));
      };
      child.once('error', (error) => giveUp(`the gateway failed to spawn: ${error.message}`));
      child.once('exit', (code) => giveUp(`the gateway exited with ${String(code)} before it listened`));
      child.stdout.on('data', (chunk: string) => {
        out += chunk;
        const line = out.split('\n').find((each) => each.startsWith('signerd (mock) listening on '));
        if (line === undefined) return;
        const bound = /^signerd \(mock\) listening on http:\/\/127\.0\.0\.1:([1-9]\d*)\s*$/u.exec(line);
        if (bound?.[1] === undefined) {
          giveUp(`the listening line names no bound port: ${line}`);
          return;
        }
        clearTimeout(timer);
        resolve(Number(bound[1]));
      });
    });
    return { port, kill };
  } catch (error) {
    await kill();
    throw error;
  }
}

describe('signerd cli', () => {
  it('prints usage with --help', () => {
    const result = run('--help');
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('signerd');
    expect(result.stdout).toContain('--mock');
    expect(result.stdout).toContain('--public-url');
    // The default window is a claim about a regulation in the first text an operator reads, so it is
    // checked here as well as on the banner: the floor's name and its number, and no system category
    // standing in for the actor the duty falls on.
    expect(result.stdout).toContain('access log retention');
    expect(result.stdout).toContain('Default: 184');
    expect(result.stdout).not.toContain('Annex III');
    // The connection bound is a limit an operator can set, so its flag and its default are both in the
    // first text they read, and the shape of the value is spelled out rather than left to be guessed.
    expect(result.stdout).toContain('--peer-rate perMinute=<n>,burst=<n>');
    expect(result.stdout).toContain('perMinute=6000,burst=2000');
  });

  it('exits with 2 when --mock is missing', () => {
    const result = run();
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('--mock');
  });

  it('exits with 2 for an invalid port', () => {
    const result = run('--mock', '--port', 'not-a-port');
    expect(result.status).toBe(2);
    expect(result.stderr).toContain("invalid port 'not-a-port'");
  });

  it('exits with 2 for a receipts directory that is not one', () => {
    const result = run('--mock', '--receipts-dir', join(tempDir, 'not-mounted'));
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('--receipts-dir must name an existing directory');
  });

  it('refuses a receipts directory that is a file', () => {
    const result = run('--mock', '--receipts-dir', MANIFEST);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('--receipts-dir must name an existing directory');
  });

  it('exits with 2 when both modes are requested', () => {
    const result = run('--mock', '--live');
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('exactly one of --mock or --live');
  });

  it('names the live argument that is missing', () => {
    const result = run('--live', '--credentials-path', CREDENTIALS, '--access-log-path', ACCESS_DIR);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('--public-url is required in live mode');
  });

  it('rejects a public URL that is not absolute', () => {
    const result = run(
      ...liveArgs(
        '--model',
        'm',
        '--public-url',
        'inference.ashaveri.test',
      ),
    );
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('--public-url is not an absolute URL');
  });

  it('requires at least one model', () => {
    const result = run(...liveArgs('--tee', 'snp'));
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('at least one --model');
  });

  it('rejects an unknown tee kind', () => {
    const result = run(...liveArgs('--model', 'm', '--tee', 'sgx'));
    expect(result.status).toBe(2);
    expect(result.stderr).toContain("--tee must be one of snp, snp+gpucc, tdx, tdx+gpucc, got 'sgx'");
  });

  it('accepts a composite claim over TDX', () => {
    // Past validation and as far as the guest agent, which this environment has none of.
    const result = run(...liveArgs('--model', 'm', '--tee', 'tdx+gpucc'));
    expect(result.stderr).not.toContain('--tee must be');
    expect(result.stderr).toContain('GUEST_ENDPOINT_MISSING');
  });

  it('reports an unreachable guest agent without a stack trace', () => {
    const result = run(...liveArgs('--model', 'm'));
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('GUEST_ENDPOINT_MISSING');
    expect(result.stderr).not.toContain('    at ');
  });
});

describe('the banner a booted gateway prints', () => {
  // A live run cannot boot here: it stops at the guest agent, so only the mock half of the mode
  // label can be seen from a test. The two lines are still pinned to each other, because the first
  // one is what the second one claims to match. The timeout is the stop plus room to reach it,
  // since this case spends most of its life waiting to be interrupted.
  it(
    'names the mode the printed dev credential belongs to',
    () => {
      const banner = runStopped('--mock', '--port', '0');
      const printed = banner.join('\n');
      expect(banner[0], `no listening line; stdout held ${JSON.stringify(printed)}`).toMatch(
        /^signerd \(mock\) listening on http:\/\/127\.0\.0\.1:\d+$/u,
      );
      const credential = banner.find((line) => line.includes('id=dev privateKeyHex='));
      expect(credential, `no dev credential line; stdout held ${JSON.stringify(printed)}`).toMatch(
        /^ {2}dev credential for this mock run: id=dev privateKeyHex=[0-9a-f]{64}$/u,
      );
    },
    12_000,
  );
});

describe('the flags that make the access floor real', () => {
  it('names the missing credential file before it contacts the guest agent', () => {
    const result = run(
      '--live',
      '--public-url',
      'https://inference.ashaveri.test',
      '--weights-manifest',
      MANIFEST,
      '--model',
      'm',
      '--access-log-path',
      ACCESS_DIR,
    );
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('--credentials-path is required in live mode');
    expect(result.stderr).not.toContain('GUEST_ENDPOINT_MISSING');
  });

  it('names the missing access log directory', () => {
    const result = run(
      '--live',
      '--public-url',
      'https://inference.ashaveri.test',
      '--weights-manifest',
      MANIFEST,
      '--model',
      'm',
      '--credentials-path',
      CREDENTIALS,
    );
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('--access-log-path is required in live mode');
  });

  it('refuses an access log path that is not a directory', () => {
    const result = run(...liveArgs('--model', 'm', '--access-log-path', MANIFEST));
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('--access-log-path must name an existing directory');
  });

  it('refuses a credential file it cannot read', () => {
    const result = run(...liveArgs('--model', 'm', '--credentials-path', join(tempDir, 'not-mounted.json')));
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('--credentials-path');
    expect(result.stderr).toContain('could not be read');
  });

  it('refuses a credential file that is not JSON, and names the flag', () => {
    const result = run(...liveArgs('--model', 'm', '--credentials-path', credentialFile('{ not json')));
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('--credentials-path');
    expect(result.stderr).toContain('not JSON');
  });

  it('refuses a record with no public key, and says which one', () => {
    // `read` and not `complete` alone, because a record that completes without reading is refused for
    // its scope pairing before the loader reaches the key field, and this cell is about the key.
    const path = credentialFile(
      '{"version":1,"credentials":[{"id":"a","kind":"pop","scopes":["read"],"createdAt":1}]}',
    );
    const result = run(...liveArgs('--model', 'm', '--credentials-path', path));
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('--credentials-path');
    expect(result.stderr).toContain('credentials[0].publicKey');
  });

  it('refuses a bearer hash that is malformed even with bearer allowed', () => {
    // Coherent scopes, for the same reason as the case above: this cell is about the hash.
    const path = credentialFile(
      '{"version":1,"credentials":[{"id":"b","kind":"bearer","secretHash":"deadbeef","scopes":["read"],"createdAt":1}]}',
    );
    const result = run(...liveArgs('--model', 'm', '--allow-bearer', '--credentials-path', path));
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('--credentials-path');
    expect(result.stderr).toContain('credentials[0].secretHash');
  });

  // The loader names the file the parse layer was reading by adding it to the refusal's detail, which
  // is not the field the constructor prefixes a sentence onto. Counting the clause is the assertion:
  // the flag and the path alone stayed true across the doubling.
  it('says once what is wrong with a credential file, and where it was', () => {
    const path = credentialFile('{"version":2,"credentials":[]}');
    const result = run(...liveArgs('--model', 'm', '--credentials-path', path));
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('--credentials-path');
    expect(result.stderr).toContain(path);
    expect(result.stderr).toContain('version 2');
    expect(result.stderr.match(/the credential file cannot be used/gu)?.length ?? 0, result.stderr).toBe(1);
  });

  it('refuses a retention window that is not a whole number of days', () => {
    const result = run('--mock', '--access-log-days', '0');
    expect(result.status).toBe(2);
    expect(result.stderr).toContain("--access-log-days must be a positive whole number of days, got '0'");
  });

  it('refuses a tolerance that is not a whole number of seconds', () => {
    const result = run('--mock', '--pop-tolerance', '12.5');
    expect(result.status).toBe(2);
    expect(result.stderr).toContain("--pop-tolerance must be a positive whole number of seconds, got '12.5'");
  });

  it('reports the posture a flagless mock run boots into', () => {
    const banner = runStopped('--mock', '--port', '0');
    const printed = banner.join('\n');
    // `--port 0` is the operating system choosing, so a report that echoed the flag would print a
    // port nothing can connect to. The nonzero requirement is the whole point of this pattern.
    expect(banner[0], `no listening line; stdout held ${JSON.stringify(printed)}`).toMatch(
      /^signerd \(mock\) listening on http:\/\/127\.0\.0\.1:[1-9]\d*$/u,
    );
    expect(banner, printed).toContain(
      '  auth: proof of possession, timestamps trusted within 120 seconds; bearer credentials refused',
    );
    expect(banner, printed).toContain('  credentials: 1 record held in this process only');
    expect(banner, printed).toContain(
      '  access log: this process only, kept for 184 days and gone on restart',
    );
    // The bound a flagless run boots with is a fact an operator has to be able to see without reading
    // the source, and it is the number the fifteen-default-credential case in `peer-throttle.test.ts` is
    // set against.
    expect(banner, printed).toContain(
      '  rate limits: 6000 requests a minute and 2000 at once per connection address, taken ahead of every credential check, the default; a credential with no rate in its record holds 60 a minute and 120 at once',
    );
    // `banner` is an array, so `not.toContain` with a line prefix compared whole elements and could
    // never have found what it was looking for: this asks the lines themselves.
    expect(banner.some((line) => line.includes('bearer credentials also accepted')), printed).toBe(false);
  });

  it('says what bearer mode costs when it is turned on', () => {
    const banner = runStopped('--mock', '--port', '0', '--allow-bearer');
    const printed = banner.join('\n');
    const line = banner.find((each) => each.includes('bearer credentials also accepted'));
    expect(line, `no bearer line; stdout held ${JSON.stringify(printed)}`).toContain(
      'a stolen bearer credential is undetectable',
    );
  });

  it('names a shortened window as the choice it is', () => {
    const banner = runStopped('--mock', '--port', '0', '--access-log-days', '30');
    const printed = banner.join('\n');
    expect(banner, printed).toContain('  access log: this process only, kept for 30 days and gone on restart');
    const note = banner.find((each) => each.startsWith('  note: '));
    expect(note, `no note line; stdout held ${JSON.stringify(printed)}`).toContain('30 days');
    expect(note, printed).toContain('184-day floor');
    // The floor is six months rounded up to whole days, and the two articles name two actors:
    // 19(1) the provider, 26(6) the deployer. Neither names a period, and neither is qualified by a
    // system category, so a banner that says otherwise is a wrong claim in operator-facing text.
    expect(note, printed).toContain('six months rounded up to whole days');
    expect(note, printed).toContain(
      'Article 19(1) sets for a provider of a high-risk system and Article 26(6) states in the same terms for a deployer',
    );
    expect(note, printed).not.toContain('Annex III');
  });

  it('reports the directory and what was already in it', () => {
    const dir = join(tempDir, 'already-held');
    mkdirSync(dir);
    // A name the log's own pattern produces, so the count is of files this tool recognises and not of
    // whatever a stray on the volume happens to be called.
    writeFileSync(join(dir, 'access-2026-09-16-000.jsonl'), '');
    const banner = runStopped('--mock', '--port', '0', '--access-log-path', dir);
    const printed = banner.join('\n');
    const line = banner.find((each) => each.startsWith('  access log: '));
    expect(line, `no access log line; stdout held ${JSON.stringify(printed)}`).toContain(dir);
    expect(line, printed).toContain('kept for 184 days');
    expect(line, printed).toContain('with 1 file from before this boot');
    expect(line, printed).not.toContain('this process only');
  });

  // Two boots, because the claim is about a difference between them: one run has no credential file and
  // one has. Each boot is stopped by the spawn timeout, so this case spends about twice what a
  // single-boot case does and needs the runner's allowance raised the same way.
  it(
    'keeps the dev credential to the run that has no credential file',
    () => {
      const banner = runStopped('--mock', '--port', '0');
      expect(banner.some((each) => each.includes('id=dev privateKeyHex=')), banner.join('\n')).toBe(true);
      const held = runStopped('--mock', '--port', '0', '--credentials-path', CREDENTIALS);
      expect(held.some((each) => each.includes('id=dev')), held.join('\n')).toBe(false);
      // An empty file parses, so nothing else about this gateway says that it will refuse everything.
      expect(
        held,
        held.join('\n'),
      ).toContain(
        `  credentials: 0 records read from ${CREDENTIALS} at start-up, which leaves every request refused`,
      );
    },
    12_000,
  );

  // The count that line prints is the store's own, so this is the half that says where it came from:
  // a file with two records in it is read once to check it and again by the store, and the banner
  // reports what the store installed. The pair below is what makes the claim mean something - the
  // same process on a file the store will not finish taking prints no banner at all, so the number
  // cannot be a constant, a flag's presence, or a count of what survived.
  it(
    'reports the records the store installed, and refuses to boot on a file it cannot take',
    () => {
      const pop = newPopCredential({ id: 'banner-pop', scopes: ['read', 'complete'] });
      const bearer = newBearerCredential({ id: 'banner-bearer', scopes: ['read'] });
      const path = credentialFile(serializeCredentialFile({ version: 1, credentials: [pop.record, bearer.record] }));
      const banner = runStopped('--mock', '--port', '0', '--credentials-path', path);
      expect(
        banner.some((each) => each.startsWith(`  credentials: 2 records read from ${path} at start-up`)),
        banner.join('\n'),
      ).toBe(true);

      // A record whose key is a byte short of the width its kind needs: the parser refuses the file,
      // which is the same rule the store applies to a file handed to it in memory, and start-up is
      // where an operator reads it rather than a request that named the id.
      const short = credentialFile(
        serializeCredentialFile({
          version: 1,
          credentials: [
            pop.record,
            { id: 'banner-short', kind: 'pop', scopes: ['read'], createdAt: 1_772_000_000, publicKey: new Uint8Array(3) },
          ],
        }),
      );
      const refused = run('--mock', '--port', '0', '--credentials-path', short);
      expect(refused.status, refused.stdout).not.toBe(0);
      expect(refused.stderr).toMatch(/3 bytes, not 32/u);
      expect(refused.stdout, 'a process that refused to boot printed a banner').not.toContain('listening on');
    },
    12_000,
  );
});

/**
 * `--peer-rate` is the only knob on the bound every request spends from, so both halves of it are
 * checked: that a value the bucket cannot hold stops the boot, and that a value it can hold is the number
 * the process reports and the number a request is refused by.
 */
describe('the bound one connection address is held to', () => {
  it('refuses a peer rate with one of its two fields missing', () => {
    const noBurst = run('--mock', '--peer-rate', 'perMinute=6000');
    expect(noBurst.status).toBe(2);
    expect(noBurst.stderr).toContain("--peer-rate wants perMinute=<n>,burst=<n>, got 'perMinute=6000': burst is missing");
    const noRate = run('--mock', '--peer-rate', 'burst=300');
    expect(noRate.status).toBe(2);
    expect(noRate.stderr).toContain(
      "--peer-rate wants perMinute=<n>,burst=<n>, got 'burst=300': perMinute is missing",
    );
    // Nothing after the flag at all, which is the parse layer's refusal and not this one, and the same
    // exit the rest of the usage errors take.
    const noValue = run('--mock', '--peer-rate');
    expect(noValue.status).toBe(2);
    expect(noValue.stderr).toContain('--peer-rate');
  });

  it('refuses a peer rate whose numbers are not counts of requests', () => {
    for (const bad of ['perMinute=0,burst=300', 'perMinute=6000,burst=0']) {
      const result = run('--mock', '--peer-rate', bad);
      expect(result.status, bad).toBe(2);
      expect(result.stderr, bad).toContain('must be a positive whole number');
      expect(result.stderr, bad).toContain("got '0'");
      // A bound of nothing at all is the way to disable a control through a flag that looks like it only
      // sets a size, so it is refused rather than clamped.
      expect(result.stdout, bad).not.toContain('listening on');
    }
    const fractional = run('--mock', '--peer-rate', 'perMinute=12.5,burst=300');
    expect(fractional.status).toBe(2);
    expect(fractional.stderr).toContain("--peer-rate perMinute must be a positive whole number of requests a minute, got '12.5'");
    // A spelling `Number` would accept and no operator wrote: the digits-only rule is what refuses them.
    for (const exotic of ['perMinute=0x10,burst=300', 'perMinute=1e3,burst=300', 'perMinute=-60,burst=300']) {
      const result = run('--mock', '--peer-rate', exotic);
      expect(result.status, exotic).toBe(2);
      expect(result.stderr, exotic).toContain('must be a positive whole number');
    }
  });

  it('refuses a peer rate field it does not have, and one given twice', () => {
    const unknown = run('--mock', '--peer-rate', 'perMinute=6000,bursts=300');
    expect(unknown.status).toBe(2);
    expect(unknown.stderr).toContain("'bursts=300' is not one of those two fields");
    const repeated = run('--mock', '--peer-rate', 'perMinute=6000,perMinute=100');
    expect(repeated.status).toBe(2);
    expect(repeated.stderr).toContain('perMinute is given twice');
    const bare = run('--mock', '--peer-rate', '6000,300');
    expect(bare.status).toBe(2);
    expect(bare.stderr).toContain("'6000' is not one of those two fields");
  });

  it('prints the bound it was given, and says that it was given', () => {
    const banner = runStopped('--mock', '--port', '0', '--peer-rate', 'perMinute=1234,burst=56');
    const printed = banner.join('\n');
    const line = banner.find((each) => each.startsWith('  rate limits: '));
    expect(line, `no rate limits line; stdout held ${JSON.stringify(printed)}`).toContain(
      '1234 requests a minute and 56 at once per connection address',
    );
    expect(line, printed).toContain('from --peer-rate');
    expect(line, printed).not.toContain('the default');
  });

  it('has no spelling that takes the bound off, and one that amounts to it', () => {
    // `0` and a bare word are the two shapes a reader reaches for when they want the control out of the
    // way, and both are refused: a bound of nothing would shed every request this process serves, and a
    // flag that accepted "off" would be a way to remove a security control from a deployment that thinks
    // it has one.
    for (const value of ['off', 'none', '0', 'perMinute=0,burst=0', 'perMinute=0']) {
      const result = run('--mock', '--peer-rate', value);
      expect(result.status, value).toBe(2);
      expect(result.stderr, value).toContain('--peer-rate');
      expect(result.stdout, value).not.toContain('listening on');
    }
    // The way out is a number big enough never to be reached, and it stays a number the banner reports:
    // a run that is effectively unbounded reads as one with a large limit, not as one with none. This
    // case stops at the credential file, which the rate is parsed before, so it says the value was taken
    // without booting a listener.
    const huge = run(
      '--mock',
      '--peer-rate',
      'perMinute=999999999,burst=999999999',
      '--credentials-path',
      join(tempDir, 'not-mounted.json'),
    );
    expect(huge.stderr).not.toContain('--peer-rate wants');
    expect(huge.stderr).not.toContain('must be a positive whole number');
    expect(huge.stderr).toContain('--credentials-path');
  });
});

/**
 * Which of the two shapes of the deployment manifest this process serves is a fact an operator has to be
 * able to read off the banner: a sealed document and a plain one mean different things to whoever stands
 * at the other end of the deployment, and the difference comes from one flag handed to one process.
 */
describe('the banner names the manifest posture', () => {
  it('says a deployment with no manifest key serves the plain document', () => {
    const banner = runStopped('--mock', '--port', '0');
    const printed = banner.join('\n');
    const line = banner.find((each) => each.startsWith('  manifest: '));
    expect(line, `no manifest line; stdout held ${JSON.stringify(printed)}`).toContain('served as plain JSON');
    expect(line, printed).toContain('unauthenticated');
  });

  it('documents the second key as an option and the duty it discharges', () => {
    const help = run('--help');
    expect(help.stdout).toContain('--manifest-key-path <path>');
    expect(help.stdout).toContain('--manifest-key-purpose <purpose>');
  });
});

/**
 * What the access flags do to a request, as opposed to what they do to a line of text. Each case boots
 * the built CLI for real, because the flag is read at start-up and the decision is made in the
 * process that holds the store: nothing in this file up to here has shown a request outcome move.
 */
describe('a gateway that serves answers the way its banner says', () => {
  const url = (port: number): string => `http://127.0.0.1:${String(port)}/v1/deployment-manifest`;

  // The pair is the assertion. A banner that promises bearer is accepted beside a store that was
  // never told about it is the failure this file exists to prevent, and neither half catches it
  // alone: the flagless refusal is what an always-refusing store still gets right.
  it(
    'accepts a bearer credential only when the flag says so',
    async () => {
      const bearer = newBearerCredential({ id: 'bearer-1', scopes: ['read', 'complete'] });
      const path = credentialFile(serializeCredentialFile({ version: 1, credentials: [bearer.record] }));
      const headers = { authorization: `Bearer ${toBase64Url(bearer.secret)}` };

      const allowed = await bootServing(['--allow-bearer', '--credentials-path', path]);
      try {
        const response = await fetch(url(allowed.port), { headers });
        const body = await response.text();
        expect(response.status, body).toBe(200);
        expect(JSON.parse(body) as { v?: unknown }).toHaveProperty('v', 1);
      } finally {
        await allowed.kill();
      }

      const refused = await bootServing(['--credentials-path', path]);
      try {
        const response = await fetch(url(refused.port), { headers });
        const body = await response.text();
        expect(response.status, body).toBe(401);
        expect(body).toContain('AUTH_SCHEME');
        expect(body).toContain('this deployment requires a proof of possession');
      } finally {
        await refused.kill();
      }
    },
    20_000,
  );

  it(
    'holds one connection to the bound the flag set it',
    async () => {
      // A burst of three on an address, far below the 2,000 this process would have booted with, so the
      // only way the fourth signed request is refused is that the flag reached the store the requests are
      // admitted by. The minute behind the burst is sixty rather than a large number because these five
      // requests are milliseconds apart on a wall clock, and a bucket refilling at ten tokens a
      // millisecond would never be seen empty: what is pinned here is the burst the flag set.
      const pop = newPopCredential({ id: 'peer-rate-pop', scopes: ['read', 'complete'] });
      const path = credentialFile(serializeCredentialFile({ version: 1, credentials: [pop.record] }));
      const served = await bootServing([
        '--credentials-path',
        path,
        '--peer-rate',
        'perMinute=60,burst=3',
      ]);
      const target = '/v1/deployment-manifest';
      try {
        const codes: Array<string | undefined> = [];
        const messages: string[] = [];
        const statuses: number[] = [];
        const retryAfters: Array<string | null> = [];
        for (let at = 0; at < 5; at++) {
          const nonce = randomNonce();
          const fields: PopFields = {
            ts: Math.floor(Date.now() / 1000),
            nonce,
            method: 'GET',
            target,
            bodyDigestHex: EMPTY_BODY_SHA256_HEX,
          };
          const response = await fetch(url(served.port), {
            headers: {
              authorization: signPopAuthorization(fields, pop.record.id, pop.privateKey),
              'x-ashaveri-nonce': toBase64Url(nonce),
            },
          });
          const body = await response.text();
          statuses.push(response.status);
          messages.push(body);
          retryAfters.push(response.headers.get('retry-after'));
          codes.push((JSON.parse(body) as { error?: { code?: string } }).error?.code);
        }
        // Three served, then the bound the flag set, in the words that name which bucket fired. Under
        // the bound this process would have booted with, all five are served, so the pair of lines below
        // is what says the number travelled from the flag to the store rather than only to the banner.
        expect(codes.slice(0, 3), JSON.stringify(codes)).toEqual([undefined, undefined, undefined]);
        expect(codes.slice(3), JSON.stringify(codes)).toEqual(['RATE_LIMITED', 'RATE_LIMITED']);
        expect(statuses.slice(0, 3), JSON.stringify(statuses)).toEqual([200, 200, 200]);
        expect(statuses.slice(3), JSON.stringify(statuses)).toEqual([429, 429]);
        expect(messages[4]).toContain('per connection address');
        // The hint is a header, and it is the reason this refusal is retryable at all.
        expect(Number(retryAfters[3]), JSON.stringify(retryAfters)).toBeGreaterThanOrEqual(1);
        expect(Number(retryAfters[4]), JSON.stringify(retryAfters)).toBeGreaterThanOrEqual(1);
      } finally {
        await served.kill();
      }
    },
    20_000,
  );

  it(
    'trusts a proof of possession only inside the tolerance it was given',
    async () => {
      const pop = newPopCredential({ id: 'pop-1', scopes: ['read', 'complete'] });
      const path = credentialFile(serializeCredentialFile({ version: 1, credentials: [pop.record] }));
      const served = await bootServing(['--credentials-path', path, '--pop-tolerance', '1']);
      const target = '/v1/deployment-manifest';
      // A proof of possession is frozen at the moment its headers are built, because the signature
      // covers the timestamp and not the delivery: what varies below is the stamp, and the fetch that
      // follows is the same either way. These are the three calls `packages/sdk`'s `authorizedFetch`
      // makes per request, which is not a dependency of this package, so the signing string is asked
      // for from `@ashaveri/receipt`, where both the SDK and this gateway read it.
      try {
        const staleNonce = randomNonce();
        const stale: PopFields = {
          ts: Math.floor(Date.now() / 1000) - 5,
          nonce: staleNonce,
          method: 'GET',
          target,
          bodyDigestHex: EMPTY_BODY_SHA256_HEX,
        };
        const refused = await fetch(url(served.port), {
          headers: {
            authorization: signPopAuthorization(stale, pop.record.id, pop.privateKey),
            'x-ashaveri-nonce': toBase64Url(staleNonce),
          },
        });
        const staleBody = await refused.text();
        expect(refused.status, staleBody).toBe(401);
        expect(staleBody).toContain('AUTH_STALE');
        expect(staleBody).toContain('outside the 1s tolerance');

        const freshNonce = randomNonce();
        const fresh: PopFields = {
          ts: Math.floor(Date.now() / 1000),
          nonce: freshNonce,
          method: 'GET',
          target,
          bodyDigestHex: EMPTY_BODY_SHA256_HEX,
        };
        const answered = await fetch(url(served.port), {
          headers: {
            authorization: signPopAuthorization(fresh, pop.record.id, pop.privateKey),
            'x-ashaveri-nonce': toBase64Url(freshNonce),
          },
        });
        const freshBody = await answered.text();
        expect(answered.status, freshBody).toBe(200);
      } finally {
        await served.kill();
      }
    },
    20_000,
  );
});

/**
 * A receipt store is opened with a durability bound, the count of receipts a volume keeps, and a
 * serving bound, the count one query holds at a time, beside a period. `gateway/src/cli.ts` configures
 * all three, and the shipped pair says nothing about whether the count can hold the period. These are
 * the cases for that question at the only moment it can still be refused cheaply: a start, before a
 * receipt is served and before a caller holds an id.
 *
 * They go through the built binary rather than a call into the store, because the refusal is worth
 * nothing if it is only what `openFileReceiptStore` returns to a caller that ignores it. The operator
 * has to see which number is short, and which of the two counts raising fixes nothing, in the
 * process's own exit and on its stderr.
 */
describe('a volume whose receipts have to outlive the start', () => {
  /**
   * The receipts a 184 day period takes at the traffic `writeHeldStore(dir, 10_000, 100)` writes: ten
   * thousand receipts spread over ninety-nine seconds are a rate of one hundred and one receipts per
   * second round about, so the period takes 9,999 * 15,897,600 / 99 = 1,605,657,600 receipts plus the
   * one stamped at its older edge. The store derives this; the case states it so the number an operator
   * is told to set is the number the code worked out.
   */
  const PERIOD_RECEIPTS = 1_605_657_601;

  it(
    'refuses the start on a volume at its bound and below its window', () => {
      const dir = join(tempDir, 'window-unheld');
      mkdirSync(dir);
      // Ten thousand receipts, the durability bound this CLI ships, over the hundred seconds the
      // measured volume takes to write them, against a period configured in the same file as 184 days.
      const bytes = writeHeldStore(dir, SHIPPED_RECEIPT_BOUND, 100);

      const result = run('--mock', '--port', '0', '--receipts-dir', dir);
      expect(result.status, result.stderr).toBe(1);
      const refused = `${result.stdout}\n${result.stderr}`;
      expect(refused).toContain('signerd: RETENTION_WINDOW_UNHOLDABLE:');
      // Both quantities that disagree, named in the sentence an operator reads, and the count that the
      // store's own traffic says the window takes. The first two come from this CLI's configuration and
      // the third from the file, so no one of them is the other's restatement.
      expect(refused).toContain(`durability bound of ${String(SHIPPED_RECEIPT_BOUND)} receipts`);
      expect(refused).toContain(`${String(MINIMUM_RETENTION_SECONDS)} seconds`);
      expect(refused).toContain('receipts at the rate this store has been carrying');
      // How far short the bound is, so the number to set is read off the line rather than worked out,
      // and the other count this CLI ships named as the one that is not the problem: a process started
      // with both counts says which of them it is objecting to.
      expect(refused).toContain(`short by ${String(PERIOD_RECEIPTS - SHIPPED_RECEIPT_BOUND)} receipts`);
      expect(refused).toContain(`the serving bound of ${String(SHIPPED_RECEIPT_BOUND)} receipts is not`);
      expect(refused, 'a process that refused to boot printed a banner').not.toContain('listening on');

      // The receipts are the evidence the refusal is read from, and this is the one moment an operator
      // learns the pairing was wrong: a start-up that rewrote or shed them would destroy the only
      // measurement of what the bound cannot hold.
      expect(readFileSync(join(dir, RECEIPT_STORE_FILE))).toEqual(bytes);
    },
    // The volume is written in one go and read back by a start that refuses it: measured here at
    // 3.1s, which is past what the runner's five-second default leaves room for on a slower machine, so
    // the case carries its own stop rather than the one that has bitten this estate before.
    20_000,
  );

  it(
    'starts the same volume once its durability bound can hold the period', () => {
      const dir = join(tempDir, 'window-raised');
      mkdirSync(dir);
      writeHeldStore(dir, SHIPPED_RECEIPT_BOUND, 100);

      const banner = runStopped(
        '--mock',
        '--port',
        '0',
        '--receipts-dir',
        dir,
        '--receipts-keep',
        String(PERIOD_RECEIPTS),
      );
      const printed = banner.join('\n');
      const line = banner.find((each) => each.startsWith('  receipts kept in '));
      expect(line, `no receipts line; stdout held ${JSON.stringify(printed)}`).toContain(dir);
      expect(line, printed).toContain(`a durability bound of ${String(PERIOD_RECEIPTS)} receipts`);
      // The serving bound is reported as installed, which is the point: the volume now keeps a period
      // that takes a sixth of a billion receipts and a query still holds ten thousand of them.
      expect(line, printed).toContain(`a serving bound of ${String(SHIPPED_RECEIPT_BOUND)} receipts to a query`);
    },
    // The same ten thousand receipts on disk, read by a start that was told a durability bound big
    // enough to hold 184 days of them with a serving bound nobody raised: measured here at 4.1s, four
    // of which are the spawn waiting for its listening line.
    20_000,
  );

  it(
    'starts the same pairing on a volume that has not reached its bound', () => {
      const dir = join(tempDir, 'window-held');
      mkdirSync(dir);
      // The same window and the same bound, and traffic nowhere near the bound. Nothing is being shed
      // here, so nothing is asked: a store that has issued less than it can serve is a quiet
      // deployment, and refusing it would refuse it for being quiet.
      writeHeldStore(dir, 200, 100);

      const banner = runStopped('--mock', '--port', '0', '--receipts-dir', dir);
      const printed = banner.join('\n');
      const line = banner.find((each) => each.startsWith('  receipts kept in '));
      expect(line, `no receipts line; stdout held ${JSON.stringify(printed)}`).toContain(dir);
      // The start-up report states the pair as configuration, not as a period kept: a store that opens
      // has compared its two bounds against its own traffic and nothing more.
      expect(line, printed).toContain('as configured');
      expect(line, printed).toContain('a durability bound of 10000 receipts');
    },
    12_000,
  );

  it('refuses a bound that is not a count of receipts', () => {
    for (const flag of ['--receipts-keep', '--receipts-per-query']) {
      const result = run('--mock', '--port', '0', flag, '12.5');
      expect(result.status, result.stderr).toBe(2);
      expect(result.stderr).toContain(`--${flag.slice(2)} must be a positive whole number`);
    }
  });
});

describe('the durability guard read while serving', () => {

  const COMPLETION = '{"model":"mock-model-1","messages":[{"role":"user","content":"guard"}]}';
  /**
   * A signed GET. Every route this gateway serves is behind the pipeline, so the read that has to keep
   * serving while intake refuses is a read a credential asked for, not an anonymous fetch.
   */
  async function readStatus(
    port: number,
    pop: { record: { id: string }; privateKey: Uint8Array },
    target: string,
  ): Promise<number> {
    const nonce = randomNonce();
    const fields: PopFields = {
      ts: Math.floor(Date.now() / 1000),
      nonce,
      method: 'GET',
      target,
      bodyDigestHex: EMPTY_BODY_SHA256_HEX,
    };
    return await (
      await fetch(`http://127.0.0.1:${String(port)}${target}`, {
        headers: {
          authorization: signPopAuthorization(fields, pop.record.id, pop.privateKey),
          'x-ashaveri-nonce': toBase64Url(nonce),
        },
      })
    ).status;
  }

  /** A signed completion against a booted process, with the two things a caller can branch on. */
  async function complete(
    port: number,
    pop: { record: { id: string }; privateKey: Uint8Array },
  ): Promise<{ status: number; code: string | undefined; receiptId: string | null; text: string }> {
    const nonce = randomNonce();
    const fields: PopFields = {
      ts: Math.floor(Date.now() / 1000),
      nonce,
      method: 'POST',
      target: '/v1/chat/completions',
      bodyDigestHex: createHash('sha256').update(COMPLETION).digest('hex'),
    };
    const response = await fetch(`http://127.0.0.1:${String(port)}/v1/chat/completions`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: signPopAuthorization(fields, pop.record.id, pop.privateKey),
        'x-ashaveri-nonce': toBase64Url(nonce),
      },
      body: COMPLETION,
    });
    const text = await response.text();
    return {
      status: response.status,
      code: (JSON.parse(text) as { error?: { code?: string } }).error?.code,
      receiptId: response.headers.get('x-ashaveri-receipt-id'),
      text,
    };
  }

  it('documents the threshold and the opt-in, each with what it is settled by', () => {
    const result = run('--help');
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('--receipts-guard-at <percent>');
    expect(result.stdout).toContain('--receipts-grow-past-guard');
    // Read with the folds closed: the usage text wraps an option's prose under its flag, and a sentence
    // checked across that wrap would fail for its layout rather than for its content.
    const help = result.stdout.replace(/\s+/gu, ' ');
    // The default is a number an operator has to be able to see they are not changing, and the reason
    // it is that number: 100 per cent of the bound is the state a store already refuses to open at.
    expect(help).toContain('Default: 100, which is the bound itself and the state a store will not open at');
    // The opt-in names its own cost in the same text, because a flag that read as a capacity switch
    // would be a way to discover it inside a write instead.
    expect(help).toContain('the window served is the shorter one that bound reaches');
    expect(help).toContain('stops this volume opening at the next restart');
  });

  it('refuses a threshold that is not a whole percentage of the bound', () => {
    for (const given of ['0', '101', '12.5', 'not-a-number']) {
      const result = run('--mock', '--port', '0', '--receipts-guard-at', given);
      expect(result.status, `${given}: ${result.stderr}`).toBe(2);
      expect(result.stderr, given).toContain('--receipts-guard-at must be a whole percentage from 1 to 100');
    }
  });

  it(
    'prints the guard as this process installed it, in both settings',
    () => {
      const printed = runStopped('--mock', '--port', '0').join('\n');
      const armed = runStopped('--mock', '--port', '0').find((line) => line.startsWith('  receipt intake guard:'));
      expect(armed, `no guard line; stdout held ${printed}`).toContain('armed at 100% of the durability bound');
      expect(armed, printed).toContain('RECEIPT_WINDOW_UNHOLDABLE');
      expect(armed, printed).toContain('184 days');
      expect(armed, printed).toContain('--receipts-grow-past-guard turns this off');

      const half = runStopped('--mock', '--port', '0', '--receipts-guard-at', '50').find((line) =>
        line.startsWith('  receipt intake guard:'),
      );
      expect(half, `a threshold the flag set is not on the banner; stdout held ${printed}`).toContain(
        'armed at 50% of the durability bound',
      );

      const off = runStopped('--mock', '--port', '0', '--receipts-grow-past-guard').find((line) =>
        line.startsWith('  receipt intake guard:'),
      );
      expect(off, `no guard line for the opt-in; stdout held ${printed}`).toContain('off, as configured with');
      // One line, whichever way it goes: a run that printed both would be describing a posture it is not
      // in, and the opt-in is the one that has to be legible on its own.
      expect(off, printed).not.toContain('armed at');
      expect(off, printed).toContain('the window served is the shorter one that bound reaches');
    },
    // Three boots, each stopped by the spawn timeout rather than by its own ending, so this case is
    // three times a single boot: measured here at 16.1s for the three, which is past the runner's
    // five-second default on one boot let alone three.
    25_000,
  );

  /**
   * A volume at 10,000 receipts spread over a hundred seconds, against a durability bound of 20,000.
   * That pairing opens, because the retained set is short of its bound, so the only thing in this
   * process that can refuse a request on it is the guard, and the only thing that can put a number in
   * the guard is the flag. The two cases below differ by one flag and one answer.
   */
  function guardedVolume(name: string): {
    readonly dir: string;
    readonly args: string[];
    readonly pop: { readonly record: { readonly id: string }; readonly privateKey: Uint8Array };
  } {
    const dir = join(tempDir, name);
    mkdirSync(dir);
    writeHeldStore(dir, SHIPPED_RECEIPT_BOUND, 100);
    const pop = newPopCredential({ id: 'guard-pop', scopes: ['read', 'complete'] });
    const path = credentialFile(serializeCredentialFile({ version: 1, credentials: [pop.record] }));
    return {
      dir,
      pop,
      args: [
        '--receipts-dir',
        dir,
        '--credentials-path',
        path,
        '--receipts-keep',
        String(SHIPPED_RECEIPT_BOUND * 2),
        '--receipts-guard-at',
        '50',
      ],
    };
  }

  it(
    'refuses a completion the threshold the flag set has been reached by',
    async () => {
      // At half the bound the retained set has met the threshold and the 184 days beside it cannot be
      // held at the rate the file's own stamps measure, so the completion is refused ahead of any
      // inference while a read of the manifest, on the same credential in the same process, is served.
      const volume = guardedVolume('guard-at-half-the-bound');
      const served = await bootServing(volume.args);
      try {
        const refused = await complete(served.port, volume.pop);
        expect(refused.status, refused.text).toBe(429);
        expect(refused.code).toBe('RECEIPT_WINDOW_UNHOLDABLE');
        expect(refused.receiptId, 'a refusal mints no id').toBeNull();
        expect(refused.text).toContain('of the 20000 receipts its durability bound allows');
        expect(refused.text).toContain('refusing from 10000 of them');
        expect(refused.text).not.toContain('retry-after');
        expect(
          await readStatus(served.port, volume.pop, '/v1/deployment-manifest'),
          'a read is served while intake refuses',
        ).toBe(200);
      } finally {
        await served.kill();
      }
    },
    // One boot over a volume of 10,000 chained records, which the opening reads back before a request
    // can be refused against it: measured here at 0.6s for the write, the boot and the two requests,
    // and the runner's default is a five-second ceiling on a slower machine.
    15_000,
  );

  it(
    'serves the same completion, on the same volume, once the opt-in is set',
    async () => {
      // The pair the case above cannot make on its own, because one process cannot be started both
      // ways: the same argv with the opt-in appended issues the receipt the other run refused, and the
      // store is the same volume. This is the whole of what the flag buys, so it is asserted as an
      // answer and a receipt id and not as a line on a banner.
      const volume = guardedVolume('opt-in-past-the-guard');
      const served = await bootServing([...volume.args, '--receipts-grow-past-guard']);
      try {
        const answered = await complete(served.port, volume.pop);
        expect(answered.status, answered.text).toBe(200);
        expect(answered.receiptId, 'the opt-in issues, and says so in a receipt id').not.toBeNull();
        expect(
          await readStatus(served.port, volume.pop, '/v1/deployment-manifest'),
          'and keeps serving everything the guarded run serves',
        ).toBe(200);
      } finally {
        await served.kill();
      }
    },
    // The same shape as the case above it, measured at 0.65s here.
    15_000,
  );
});
