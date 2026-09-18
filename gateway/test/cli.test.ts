import { spawn, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
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
});

/**
 * What the two flags do to a request, as opposed to what they do to a line of text. Both cases boot
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
