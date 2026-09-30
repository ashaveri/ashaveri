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
import { MINIMUM_RETENTION_SECONDS, openFileReceiptStore, RECEIPT_STORE_FILE } from '../src/store.js';

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
    timeout: SPAWN_DEADLINE_MS,
    killSignal: 'SIGKILL',
  });
  // Without this a process that never started leaves `status` null, which reads as the CLI
  // exiting with the wrong code rather than as the spawn itself failing.
  expect(result.error).toBeUndefined();
  return result;
}

/**
 * Start a gateway that serves, read the banner it printed, and stop it.
 *
 * `gateway/src/cli.ts:763` writes the whole banner in one call, measured here as a single 1746 byte
 * chunk whose last byte is the newline that ends it, so the chunk carrying the listening line carries
 * every line behind it too. This resolves on that line once the write has ended, rather than on a
 * deadline expiring: a case asks for the banner and gets it as soon as it is printed, a gateway that
 * never prints fails with what stdout held, and a slow machine slows the case instead of redding it.
 *
 * It returns `stdout.split('\n')`, the same lines the cases were written against, and leaves no child
 * behind: the kill runs on every road out, including the refused ones, and waits for the exit event.
 * A case that has to make a request over the same boot uses `bootServing` below instead.
 */
async function readBanner(...args: string[]): Promise<string[]> {
  const env = { ...process.env };
  delete env['DSTACK_SIMULATOR_ENDPOINT'];
  const child = spawn(process.execPath, [CLI, ...args], {
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
    return await new Promise<string[]>((resolve, reject) => {
      let done = false;
      // Both windows live on one object so the road out can clear whichever is armed without either
      // timer being read before it is set.
      const timers: { deadline?: NodeJS.Timeout; quiet?: NodeJS.Timeout } = {};
      const stop = (): void => {
        done = true;
        if (timers.deadline !== undefined) clearTimeout(timers.deadline);
        if (timers.quiet !== undefined) clearTimeout(timers.quiet);
      };
      const giveUp = (message: string): void => {
        stop();
        reject(new Error(`${message}; stdout held ${JSON.stringify(out)}`));
      };
      // 10s is the same allowance `bootServing` spends on the same question, and it is what turns a
      // listener that never reports in a named failure rather than a case that hangs the runner.
      timers.deadline = setTimeout(
        () => giveUp(`no listening line within ${String(BOOT_DEADLINE_MS / 1_000)}s`),
        BOOT_DEADLINE_MS,
      );
      child.once('error', (error) => giveUp(`the gateway failed to spawn: ${error.message}`));
      child.once('exit', (code) =>
        giveUp(`the gateway exited with ${String(code)} before it printed its listening line`),
      );
      child.stdout.on('data', (chunk: string) => {
        out += chunk;
        if (done) return;
        if (timers.quiet !== undefined) clearTimeout(timers.quiet);
        const listed = out.split('\n').some((line) => /^signerd \(\w+\) listening on http:\/\//u.test(line));
        if (!listed || !out.endsWith('\n')) return;
        // The end of the write, not just its first line: a chunk that arrives inside this window means
        // the banner split on the way here, and the resolve waits for the rest of it.
        timers.quiet = setTimeout(() => {
          stop();
          resolve(out.split('\n'));
        }, 0);
      });
    });
  } finally {
    await kill();
  }
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
/**
 * The two waits a case can spend, named once because a case's ceiling has to be read off them.
 *
 * `SPAWN_DEADLINE_MS` bounds one command that is expected to exit by itself; `BOOT_DEADLINE_MS` bounds one
 * gateway that is expected to print its banner. A ceiling below the sum of a case's calls and their own
 * deadlines is a ceiling that fires first, and what it reports is the runner's timeout rather than the named
 * failure the deadline exists to produce. So `budgetFor` states the arithmetic, and every case that spawns
 * or boots passes its count through it: the worst case is what a hang costs, and a hang is a defect worth
 * waiting for once rather than misreading.
 */
const SPAWN_DEADLINE_MS = 8_000;
const BOOT_DEADLINE_MS = 10_000;
const budgetFor = (calls: number, deadline: number): number => calls * deadline + 2_000;
const spawnBudget = (calls: number): number => budgetFor(calls, SPAWN_DEADLINE_MS);
const bootBudget = (boots: number): number => budgetFor(boots, BOOT_DEADLINE_MS);

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
 * The first record of a store file, read out of the framing rather than through the store that wrote it,
 * so a case can name the kind byte and the payload a run actually put on the volume.
 */
function firstRecordOf(file: Buffer): { kind: number; id: string; payload: Buffer } {
  const idLength = file.readUInt16BE(45);
  const payloadAt = 47 + idLength;
  return {
    kind: file.readUInt8(4),
    id: file.subarray(47, payloadAt).toString('utf8'),
    payload: file.subarray(payloadAt, 4 + file.readUInt32BE(0) - 32),
  };
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

/** How long a request that got no answer waits for the exit event before it describes the child. */
const DEPARTURE_SETTLE_MS = 250;

/**
 * A gateway `bootServing` booted and left listening, and the two things a case can do to it.
 *
 * `reached` is for the question a request that got no answer cannot answer for itself: whether the
 * process that printed the listening line still holds that port, and if it does not, how it went away
 * and what it printed on the way out. A `TypeError: fetch failed` carries none of that, and the two
 * readings a case would otherwise have to guess between, a start that went away behind its own banner
 * and a port the client refuses before it opens a socket, look alike without it.
 */
interface ServedGateway {
  readonly port: number;
  readonly kill: () => Promise<void>;
  readonly reached: () => Promise<string>;
}

/**
 * Start a gateway that serves, and stop it. `readBanner` above answers with the printed lines once the
 * write that carries them has ended, and stops the child before it returns, so it cannot carry a case
 * about a request: by the time it does return the process is gone. This resolves on the listening line,
 * which is why `--port 0` prints the port the operating system bound rather than the zero it was asked
 * for, and hands back a `kill` that waits for the exit event, so a case cannot leave a child or its
 * socket behind.
 *
 * Resolving on that line leaves one window the helper does not police: a child that printed it can still
 * go away before the case asks it for anything, and the case then reads a fetch error about a port nobody
 * holds. So the child's state is kept here instead of inferred downstream. `kill` fails a case whose child
 * left of its own accord after it said it was listening, `reached` says where that child got to, and `ask`
 * below puts both into the request that got no answer. The stderr that used to be drained and thrown away
 * is kept, because it is where a gateway that is about to stop says why.
 */
async function bootServing(args: string[]): Promise<ServedGateway> {
  const env = { ...process.env };
  delete env['DSTACK_SIMULATOR_ENDPOINT'];
  const child = spawn(process.execPath, [CLI, '--mock', '--port', '0', ...args], {
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let out = '';
  let err = '';
  // The two facts a departure is made of: how the child went, and whether this helper was the one that
  // asked. `undefined` while it is listening.
  let departed: { readonly exit: string; readonly asked: boolean } | undefined;
  let asking = false;
  // The port the listening line named. It stands for whether the child ever said it was listening, which
  // is the difference between an exit to name as a start that never served and an exit to name as a
  // gateway that left after it promised a port, and it is the number a request was aimed at.
  let bound: number | undefined;
  const stopped = new Promise<void>((resolve) => {
    child.once('exit', (code, signal) => {
      departed = { exit: signal === null ? `exit code ${String(code)}` : `signal ${signal}`, asked: asking };
      resolve();
    });
  });

  /** The child, as far as this helper can tell it: whether it is there, and what it printed. */
  async function reached(): Promise<string> {
    // A refused connection and the exit event are in flight together at the moment a child goes away, so
    // this waits for whichever of the two arrives first, up to a short settle. The sentence then says the
    // child had gone, rather than that this helper had not yet been told of it.
    await Promise.race([stopped, new Promise((resolve) => setTimeout(resolve, DEPARTURE_SETTLE_MS))]);
    const where =
      departed === undefined
        ? 'was still running when this was read'
        : `had gone with ${departed.exit}${departed.asked ? ', after this helper asked for the kill' : ', of its own accord'}`;
    return (
      `the gateway this helper started as pid ${String(child.pid)} with [--mock --port 0 ${args.join(' ')}] ` +
      `${where}. The port its listening line named, and the one this request was aimed at, is ${String(bound)}. ` +
      `Its stderr held ${JSON.stringify(err)} and the first line of its stdout held ${JSON.stringify(out.split('\n')[0] ?? '')}`
    );
  }

  const kill = async (): Promise<void> => {
    asking = true;
    child.kill('SIGKILL');
    await stopped;
    if (bound !== undefined && departed !== undefined && !departed.asked) {
      throw new Error(`the gateway exited after it printed its listening line and before this helper stopped it; ${await reached()}`);
    }
  };
  try {
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stderr.on('data', (chunk: string) => {
      err += chunk;
    });
    const port = await new Promise<number>((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new Error(`no listening line within ${String(BOOT_DEADLINE_MS / 1_000)}s; stdout held ${JSON.stringify(out)}`)),
        BOOT_DEADLINE_MS,
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
        const named = /^signerd \(mock\) listening on http:\/\/127\.0\.0\.1:([1-9]\d*)\s*$/u.exec(line);
        if (named?.[1] === undefined) {
          giveUp(`the listening line names no bound port: ${line}`);
          return;
        }
        bound = Number(named[1]);
        clearTimeout(timer);
        resolve(bound);
      });
    });
    return { port, kill, reached };
  } catch (error) {
    await kill();
    throw error;
  }
}

/**
 * One request to a gateway `bootServing` booted, and a failure that names the child it aimed at.
 *
 * A connection that reaches nothing arrives as `TypeError: fetch failed`, which says neither the port it
 * was aimed at nor the reason the stack gave, and a case read on a runner cannot go and ask the child. The
 * three facts that tell a start which left after it printed its listening line apart from a port the
 * client refuses before it opens a socket are the port, the reason the connection carried, and whether the
 * process is still there to be carried by, so the failure is rebuilt out of those. The original error
 * stays as the cause, which is what keeps the fetch's own stack in the report.
 */
async function ask(served: ServedGateway, target: string, init: RequestInit): Promise<Response> {
  try {
    return await fetch(`http://127.0.0.1:${String(served.port)}${target}`, init);
  } catch (error) {
    throw new Error(`no answer at ${target}: ${connectionReason(error)}; ${await served.reached()}`, { cause: error });
  }
}

/** The reason a connection failed, as the layer under `fetch` spelled it, since `fetch failed` never does. */
function connectionReason(error: unknown): string {
  const cause = error instanceof Error ? error.cause : undefined;
  if (!(cause instanceof Error)) return String(error);
  const code = (cause as NodeJS.ErrnoException).code;
  return `${cause.message}${code === undefined ? '' : ` (${code})`}`;
}

/**
 * One completion, and the two things a caller can branch on, against a booted process. Two describes
 * below ask what a flag does to a served completion, which is why this sits at module scope rather than
 * beside the first of them.
 */
const COMPLETION = '{"model":"mock-model-1","messages":[{"role":"user","content":"guard"}]}';

async function complete(
  served: ServedGateway,
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
  const response = await ask(served, '/v1/chat/completions', {
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
  // one is what the second one claims to match, and both are in the one write `readBanner` waits for.
  it('names the mode the printed dev credential belongs to', async () => {
    const banner = await readBanner('--mock', '--port', '0');
    const printed = banner.join('\n');
    expect(banner[0], `no listening line; stdout held ${JSON.stringify(printed)}`).toMatch(
      /^signerd \(mock\) listening on http:\/\/127\.0\.0\.1:\d+$/u,
    );
    const credential = banner.find((line) => line.includes('id=dev privateKeyHex='));
    expect(credential, `no dev credential line; stdout held ${JSON.stringify(printed)}`).toMatch(
      /^ {2}dev credential for this mock run: id=dev privateKeyHex=[0-9a-f]{64}$/u,
    );
  });
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

  it('reports the posture a flagless mock run boots into', async () => {
    const banner = await readBanner('--mock', '--port', '0');
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

  it('says what bearer mode costs when it is turned on', async () => {
    const banner = await readBanner('--mock', '--port', '0', '--allow-bearer');
    const printed = banner.join('\n');
    const line = banner.find((each) => each.includes('bearer credentials also accepted'));
    expect(line, `no bearer line; stdout held ${JSON.stringify(printed)}`).toContain(
      'a stolen bearer credential is undetectable',
    );
  });

  it('names a shortened window as the choice it is', async () => {
    const banner = await readBanner('--mock', '--port', '0', '--access-log-days', '30');
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

  it('reports the directory and what was already in it', async () => {
    const dir = join(tempDir, 'already-held');
    mkdirSync(dir);
    // A name the log's own pattern produces, so the count is of files this tool recognises and not of
    // whatever a stray on the volume happens to be called.
    writeFileSync(join(dir, 'access-2026-09-16-000.jsonl'), '');
    const banner = await readBanner('--mock', '--port', '0', '--access-log-path', dir);
    const printed = banner.join('\n');
    const line = banner.find((each) => each.startsWith('  access log: '));
    expect(line, `no access log line; stdout held ${JSON.stringify(printed)}`).toContain(dir);
    expect(line, printed).toContain('kept for 184 days');
    expect(line, printed).toContain('with 1 file from before this boot');
    expect(line, printed).not.toContain('this process only');
  });

  // Two boots, because the claim is about a difference between them: one run has no credential file and
  // one has. Two boots of a gateway that serves, so this case spends twice what a single-boot case
  // does, and the allowance beside it is read off that count.
  it(
    'keeps the dev credential to the run that has no credential file',
    async () => {
      const banner = await readBanner('--mock', '--port', '0');
      expect(banner.some((each) => each.includes('id=dev privateKeyHex=')), banner.join('\n')).toBe(true);
      const held = await readBanner('--mock', '--port', '0', '--credentials-path', CREDENTIALS);
      expect(held.some((each) => each.includes('id=dev')), held.join('\n')).toBe(false);
      // An empty file parses, so nothing else about this gateway says that it will refuse everything.
      expect(
        held,
        held.join('\n'),
      ).toContain(
        `  credentials: 0 records read from ${CREDENTIALS} at start-up, which leaves every request refused`,
      );
    },
    // Two boots of an empty volume, measured here at 0.9s together: the runner's default covers that
    // with room, so no ceiling of its own is set beside the case.
  );

  // The count that line prints is the store's own, so this is the half that says where it came from:
  // a file with two records in it is read once to check it and again by the store, and the banner
  // reports what the store installed. The pair below is what makes the claim mean something - the
  // same process on a file the store will not finish taking prints no banner at all, so the number
  // cannot be a constant, a flag's presence, or a count of what survived.
  it(
    'reports the records the store installed, and refuses to boot on a file it cannot take',
    async () => {
      const pop = newPopCredential({ id: 'banner-pop', scopes: ['read', 'complete'] });
      const bearer = newBearerCredential({ id: 'banner-bearer', scopes: ['read'] });
      const path = credentialFile(serializeCredentialFile({ version: 1, credentials: [pop.record, bearer.record] }));
      const banner = await readBanner('--mock', '--port', '0', '--credentials-path', path);
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
    // One boot over a two-record credential file and one exit-path refusal, measured here at 0.8s
    // together, which the runner's default covers: no ceiling of its own is set beside the case.
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

  it(
    'refuses a peer rate whose numbers are not counts of requests',
    () => {
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
      expect(fractional.stderr).toContain(
        "--peer-rate perMinute must be a positive whole number of requests a minute, got '12.5'",
      );
      // A spelling `Number` would accept and no operator wrote: the digits-only rule is what refuses them.
      for (const exotic of ['perMinute=0x10,burst=300', 'perMinute=1e3,burst=300', 'perMinute=-60,burst=300']) {
        const result = run('--mock', '--peer-rate', exotic);
        expect(result.status, exotic).toBe(2);
        expect(result.stderr, exotic).toContain('must be a positive whole number');
      }
    },
    // Six refusals, each its own exit-path spawn: measured here at 2.0s together, about 330 ms a
    // refusal, so the ceiling is a second a refusal rather than a figure carried over from another case.
    spawnBudget(6),
  );

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

  it('prints the bound it was given, and says that it was given', async () => {
    const banner = await readBanner('--mock', '--port', '0', '--peer-rate', 'perMinute=1234,burst=56');
    const printed = banner.join('\n');
    const line = banner.find((each) => each.startsWith('  rate limits: '));
    expect(line, `no rate limits line; stdout held ${JSON.stringify(printed)}`).toContain(
      '1234 requests a minute and 56 at once per connection address',
    );
    expect(line, printed).toContain('from --peer-rate');
    expect(line, printed).not.toContain('the default');
  });

  it(
    'has no spelling that takes the bound off, and one that amounts to it',
    () => {
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
    },
    // Five spellings refused at the flag and one taken past it, six exit-path spawns: measured here at
    // 2.0s together, about 330 ms a spawn, so the ceiling is a second a spawn.
    spawnBudget(6),
  );
});

/**
 * Which of the two shapes of the deployment manifest this process serves is a fact an operator has to be
 * able to read off the banner: a sealed document and a plain one mean different things to whoever stands
 * at the other end of the deployment, and the difference comes from one flag handed to one process.
 */
describe('the banner names the manifest posture', () => {
  it('says a deployment with no manifest key serves the plain document', async () => {
    const banner = await readBanner('--mock', '--port', '0');
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
  const manifestTarget = '/v1/deployment-manifest';

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
        const response = await ask(allowed, manifestTarget, { headers });
        const body = await response.text();
        expect(response.status, body).toBe(200);
        expect(JSON.parse(body) as { v?: unknown }).toHaveProperty('v', 1);
      } finally {
        await allowed.kill();
      }

      const refused = await bootServing(['--credentials-path', path]);
      try {
        const response = await ask(refused, manifestTarget, { headers });
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
          const response = await ask(served, target, {
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
        const refused = await ask(served, target, {
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
        const answered = await ask(served, target, {
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
    // The volume is written in one go and read back by a start that refuses it, and framing
    // SHIPPED_RECEIPT_BOUND receipts is the whole of the work: measured here at 3.1s, about a third of a
    // millisecond a receipt, so the ceiling is three times that, a millisecond a receipt, with a five
    // second floor for the spawn rather than a figure carried over from another case.
    bootBudget(1) + SHIPPED_RECEIPT_BOUND,
  );

  it(
    'starts the same volume once its durability bound can hold the period', async () => {
      const dir = join(tempDir, 'window-raised');
      mkdirSync(dir);
      writeHeldStore(dir, SHIPPED_RECEIPT_BOUND, 100);

      const banner = await readBanner(
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
    // The same ten thousand receipts on disk, framed and written in one go, read back by a start that
    // was told a durability bound big enough to hold 184 days of them with a serving bound nobody
    // raised: measured here at 0.6s against the 3.1s the refusing start takes on the same volume, so the
    // ceiling is read off the receipt count the case writes, one millisecond a receipt.
    bootBudget(1) + SHIPPED_RECEIPT_BOUND,
  );

  // Two hundred receipts and one boot that prints its banner, measured here at 0.44s: the runner's
  // default covers that with room, so the case carries no ceiling of its own.
  it('starts the same pairing on a volume that has not reached its bound', async () => {
    const dir = join(tempDir, 'window-held');
    mkdirSync(dir);
    // The same window and the same bound, and traffic nowhere near the bound. Nothing is being shed
    // here, so nothing is asked: a store that has issued less than it can serve is a quiet
    // deployment, and refusing it would refuse it for being quiet.
    writeHeldStore(dir, 200, 100);

    const banner = await readBanner('--mock', '--port', '0', '--receipts-dir', dir);
    const printed = banner.join('\n');
    const line = banner.find((each) => each.startsWith('  receipts kept in '));
    expect(line, `no receipts line; stdout held ${JSON.stringify(printed)}`).toContain(dir);
    // The start-up report states the pair as configuration, not as a period kept: a store that opens
    // has compared its two bounds against its own traffic and nothing more.
    expect(line, printed).toContain('as configured');
    expect(line, printed).toContain('a durability bound of 10000 receipts');
  });

  it('refuses a bound that is not a count of receipts', () => {
    for (const flag of ['--receipts-keep', '--receipts-per-query']) {
      const result = run('--mock', '--port', '0', flag, '12.5');
      expect(result.status, result.stderr).toBe(2);
      expect(result.stderr).toContain(`--${flag.slice(2)} must be a positive whole number`);
    }
  });
});

describe('the durability guard read while serving', () => {

  /**
   * A signed GET. Every route this gateway serves is behind the pipeline, so the read that has to keep
   * serving while intake refuses is a read a credential asked for, not an anonymous fetch.
   */
  async function readStatus(
    served: ServedGateway,
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
      await ask(served, target, {
        headers: {
          authorization: signPopAuthorization(fields, pop.record.id, pop.privateKey),
          'x-ashaveri-nonce': toBase64Url(nonce),
        },
      })
    ).status;
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

  // The four spellings a guard threshold refuses, named so the ceiling is read off their count rather
  // than guessed at: each one is a command that has to exit, and the deadline each carries is the same.
  const guardThresholdRefusals = ['0', '101', '12.5', 'not-a-number'];
  it(
    'refuses a threshold that is not a whole percentage of the bound',
    () => {
      for (const given of guardThresholdRefusals) {
        const result = run('--mock', '--port', '0', '--receipts-guard-at', given);
        expect(result.status, `${given}: ${result.stderr}`).toBe(2);
        expect(result.stderr, given).toContain('--receipts-guard-at must be a whole percentage from 1 to 100');
      }
    },
    spawnBudget(guardThresholdRefusals.length),
  );

  it(
    'prints the guard as this process installed it, in both settings',
    async () => {
      const printed = (await readBanner('--mock', '--port', '0')).join('\n');
      const armed = (await readBanner('--mock', '--port', '0')).find((line) =>
        line.startsWith('  receipt intake guard:'),
      );
      expect(armed, `no guard line; stdout held ${printed}`).toContain('armed at 100% of the durability bound');
      expect(armed, printed).toContain('RECEIPT_WINDOW_UNHOLDABLE');
      expect(armed, printed).toContain('184 days');
      expect(armed, printed).toContain('--receipts-grow-past-guard turns this off');

      const half = (await readBanner('--mock', '--port', '0', '--receipts-guard-at', '50')).find((line) =>
        line.startsWith('  receipt intake guard:'),
      );
      expect(half, `a threshold the flag set is not on the banner; stdout held ${printed}`).toContain(
        'armed at 50% of the durability bound',
      );

      const off = (await readBanner('--mock', '--port', '0', '--receipts-grow-past-guard')).find((line) =>
        line.startsWith('  receipt intake guard:'),
      );
      expect(off, `no guard line for the opt-in; stdout held ${printed}`).toContain('off, as configured with');
      // One line, whichever way it goes: a run that printed both would be describing a posture it is not
      // in, and the opt-in is the one that has to be legible on its own.
      expect(off, printed).not.toContain('armed at');
      expect(off, printed).toContain('the window served is the shorter one that bound reaches');
    },
    // Four boots of an empty volume, one per posture the case reads: measured here at 1.9s together,
    // about 470 ms a boot, so the ceiling is a second a boot and not a figure carried from elsewhere.
    bootBudget(4),
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
        const refused = await complete(served, volume.pop);
        expect(refused.status, refused.text).toBe(429);
        expect(refused.code).toBe('RECEIPT_WINDOW_UNHOLDABLE');
        expect(refused.receiptId, 'a refusal mints no id').toBeNull();
        expect(refused.text).toContain('of the 20000 receipts its durability bound allows');
        expect(refused.text).toContain('refusing from 10000 of them');
        expect(refused.text).not.toContain('retry-after');
        expect(
          await readStatus(served, volume.pop, '/v1/deployment-manifest'),
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
        const answered = await complete(served, volume.pop);
        expect(answered.status, answered.text).toBe(200);
        expect(answered.receiptId, 'the opt-in issues, and says so in a receipt id').not.toBeNull();
        expect(
          await readStatus(served, volume.pop, '/v1/deployment-manifest'),
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

/**
 * Which kind of receipt record a store appends is a fact about the volume rather than about a request,
 * and a run that cannot name it cannot choose it: `--receipts-record-kind` is the only road from a
 * command line to the bounded layout, and these are the cases for the whole of it. The value's two
 * spellings, the bytes a run that named one then appends, the answer a run gets when it points at a
 * volume made of the other kind, and the line that says which of the three this process installed.
 */
describe('the record kind a volume is written under', () => {
  /** Receipt bytes, opaque to the store, and 64 of them so a period in front is visible. */
  const RECEIPT_BYTES = Buffer.alloc(64, 9);
  /** The bounded kind's own spelling on a command line, and the period it states. */
  const BOUNDED_VALUE = 'bounded=300';

  it('documents the flag, both of its spellings and what it refuses to do', () => {
    const result = run('--help');
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('--receipts-record-kind <receipt | bounded=<seconds>>');
    // Read with the folds closed, as the other usage claims in this file are.
    const help = result.stdout.replace(/\s+/gu, ' ');
    expect(help).toContain('A volume whose records were written under the other kind is refused');
    expect(help).toContain('never converted');
    // The period is written and not enforced, and the first text an operator reads has to say so rather
    // than leave a number in a record reading like a bound the volume keeps.
    expect(help).toContain('Nothing enforces the period yet');
    expect(help).toContain('Default: receipt');
  });

  it(
    'refuses a value that names neither record kind',
    () => {
      // `bounded` without its number, a number that is not one, and the kind that takes none given one:
      // each is a spelling with no record to write, so the start stops rather than a default stepping in.
      for (const given of ['bounded', 'bounded=', 'bounded=abc', 'bounded= 300', 'receipt=300', 'both']) {
        const result = run('--mock', '--port', '0', '--receipts-record-kind', given);
        expect(result.status, `${given}: ${result.stderr}`).toBe(2);
        expect(result.stderr, given).toContain(
          `--receipts-record-kind must be 'receipt' or 'bounded=<seconds>', got '${given}'`,
        );
        expect(result.stdout, given).not.toContain('listening on');
      }
    },
    // Six spellings, each its own exit-path spawn: measured here at 1.9s together, about 310 ms a
    // refusal, so the ceiling is a second a refusal, read off the count the loop walks.
    spawnBudget(6),
  );

  it(
    'appends the kind the flag names, and the kind it does not when the flag is absent',
    async () => {
      // The pair is the assertion: one run names the bounded kind and one names nothing, on volumes of
      // their own, and the bytes each leaves behind differ by the kind byte and by the four period bytes
      // in front of a receipt. A flag that reached only the banner would leave both files the same.
      const bounded = join(tempDir, 'kind-bounded');
      mkdirSync(bounded);
      const boundedPop = newPopCredential({ id: 'kind-bounded-pop', scopes: ['read', 'complete'] });
      const boundedCreds = credentialFile(
        serializeCredentialFile({ version: 1, credentials: [boundedPop.record] }),
      );
      const boundedRun = await bootServing([
        '--receipts-dir',
        bounded,
        '--credentials-path',
        boundedCreds,
        '--receipts-record-kind',
        BOUNDED_VALUE,
      ]);
      let boundedReceipt: string | null = null;
      try {
        const answered = await complete(boundedRun, boundedPop);
        expect(answered.status, answered.text).toBe(200);
        boundedReceipt = answered.receiptId;
      } finally {
        await boundedRun.kill();
      }
      expect(boundedReceipt, 'the completion minted no id to file').not.toBeNull();

      const plain = join(tempDir, 'kind-plain');
      mkdirSync(plain);
      const plainPop = newPopCredential({ id: 'kind-plain-pop', scopes: ['read', 'complete'] });
      const plainCreds = credentialFile(serializeCredentialFile({ version: 1, credentials: [plainPop.record] }));
      const plainRun = await bootServing(['--receipts-dir', plain, '--credentials-path', plainCreds]);
      let plainReceipt: string | null = null;
      try {
        const answered = await complete(plainRun, plainPop);
        expect(answered.status, answered.text).toBe(200);
        plainReceipt = answered.receiptId;
        expect(plainReceipt).not.toBeNull();
      } finally {
        await plainRun.kill();
      }

      // What each run left on its volume, read out of the framing: the kind byte, and behind it the
      // bytes the record carries. The bounded record opens with the period it states; the unflagged run
      // writes the layout every store file this repository has published is made of, receipt first.
      const boundedRecord = firstRecordOf(readFileSync(join(bounded, RECEIPT_STORE_FILE)));
      expect(boundedRecord.kind).toBe(2);
      expect(boundedRecord.payload.readUInt32BE(0)).toBe(300);
      const plainRecord = firstRecordOf(readFileSync(join(plain, RECEIPT_STORE_FILE)));
      expect(plainRecord.kind).toBe(0);

      // And the id the completion handed the client is the record behind that period, whole: the four
      // bytes in front of it stay in front of it, which is the difference between a record the run wrote
      // and a receipt the caller can no longer read.
      const boundedStore = await openFileReceiptStore({ dir: bounded, receiptKind: { kind: 'bounded', boundSeconds: 300 } });
      expect(Array.from((await boundedStore.get(boundedReceipt!))!)).toEqual(
        Array.from(boundedRecord.payload.subarray(4)),
      );
      const plainStore = await openFileReceiptStore({ dir: plain });
      expect(Array.from((await plainStore.get(plainReceipt!))!)).toEqual(Array.from(plainRecord.payload));
    },
    // Two boots over two volumes, each with a signed completion behind it and a reopening after it.
    25_000,
  );

  it(
    'refuses a bounded run pointed at a volume of records that state no period, with the store sentence',
    async () => {
      const dir = join(tempDir, 'volume-of-the-other-kind');
      mkdirSync(dir);
      const writer = await openFileReceiptStore({ dir });
      await writer.put('rcpt_01', RECEIPT_BYTES, Math.floor(Date.now() / 1000));
      const volume = readFileSync(join(dir, RECEIPT_STORE_FILE));

      // The store's own answer when this volume is opened under the kind it is not made of. The case
      // below compares a process refusal against it, because the flag adds a road to that refusal and
      // not a sentence of its own: one message for one state, from either side.
      const refusal = await openFileReceiptStore({
        dir,
        receiptKind: { kind: 'bounded', boundSeconds: 300 },
      }).then(
        () => null,
        (error: unknown) => (error as Error).message,
      );
      expect(refusal).not.toBeNull();
      expect(refusal).toContain('STORE_RECEIPT_KIND_MISMATCH');
      expect(refusal).toContain('rcpt_01');

      const result = run('--mock', '--port', '0', '--receipts-dir', dir, '--receipts-record-kind', BOUNDED_VALUE);
      expect(result.status, result.stderr).toBe(1);
      expect(result.stderr.trim(), result.stderr).toBe(`signerd: ${refusal}`);
      expect(result.stdout, 'a process that refused to boot printed a banner').not.toContain('listening on');
      // Nothing was converted, and nothing was rewritten: the records are the evidence the refusal is
      // read from, and the volume still belongs to the kind that wrote it.
      expect(readFileSync(join(dir, RECEIPT_STORE_FILE))).toEqual(volume);

      // The other half of the pair, which the refusal above cannot say alone: the same volume boots on a
      // run that names the kind it holds, and the flag is the only thing that moved.
      const banner = await readBanner('--mock', '--port', '0', '--receipts-dir', dir, '--receipts-record-kind', 'receipt');
      const printed = banner.join('\n');
      const line = banner.find((each) => each.startsWith('  receipts kept in '));
      expect(line, `no receipts line; stdout held ${printed}`).toContain(dir);
      expect(line, printed).toContain('every record stating no retention period of its own');
    },
    // A boot that refuses, a boot that answers, and two openings of the volume between them: measured
    // here at 0.7s, which the runner's default covers, so the case carries no ceiling of its own.
  );

  it(
    'prints the kind this process was told to write, in both settings',
    async () => {
      // The receipts line is where a start-up report says what a volume is made of, and which kind that
      // is cannot be read off a flag's presence alone: a bounded run states the period it stamps into
      // every record, and a run that named nothing states that its records say nothing.
      const bounded = await readBanner('--mock', '--port', '0', '--receipts-record-kind', BOUNDED_VALUE);
      const boundedLine = bounded.find((each) => each.startsWith('  receipts kept in '));
      expect(boundedLine, `no receipts line; stdout held ${bounded.join('\n')}`).toContain(
        'every record stating a retention period of 300 seconds ahead of its receipt bytes, from --receipts-record-kind',
      );

      const plain = await readBanner('--mock', '--port', '0');
      const plainLine = plain.find((each) => each.startsWith('  receipts kept in '));
      expect(plainLine, `no receipts line; stdout held ${plain.join('\n')}`).toContain(
        'every record stating no retention period of its own, the receipt kind a run without --receipts-record-kind writes',
      );
    },
    // Two boots of a gateway that serves, one per kind: measured here at 0.8s together, which the
    // runner's default covers, so the case carries no ceiling of its own.
  );
});
