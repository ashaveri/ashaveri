import { createInterface } from 'node:readline';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { Worker } from 'node:worker_threads';
import {
  buildGateway,
  CREDENTIALS_FILE_VERSION,
  CredentialStore,
  newPopCredential,
  openFileAccessLog,
  type AccessLog,
  type CredentialRecord,
  type GatewayInstance,
} from '@ashaveri/signerd';
import { chunkedScrubPart } from './chunked-pass.ts';
import { ACK_GRACE_MS, distribution, watchLoopGaps, type Distribution } from './metrics.ts';
import { partName } from './part-fixture.ts';
import { wholeFilePass, type PassFacts } from './unit-facts.ts';

/**
 * The process that is measured.
 *
 * It is a serving process rather than an instrumented stand-in: it binds a loopback socket and runs the
 * gateway's own pipeline end to end, admission and receipt signing and the per-request access log
 * included, and it is this same process that runs the erasure. A request has to cross a socket to be
 * counted here, because what is under measurement is one loop being busy while something else waits on
 * it, and a request injected in process never waits on anything.
 *
 * The load does not come from inside it either. A client sharing this loop would be stalled by the very
 * work it is timing, and the figure would be the sum of two effects nobody can separate; the client runs
 * in a process of its own, so what it reports is what a caller sees.
 *
 * Every line this writes to stdout is one JSON object, and every reply carries the `id` of the request
 * that produced it.
 */
interface ChildConfig {
  /** Where this process keeps its own access log: never a directory a pass is scrubbing. */
  accessLogDir: string;
  workerPath: string;
}

function readConfig(): ChildConfig {
  const raw = process.argv[2];
  if (typeof raw !== 'string') throw new Error('erasure-pass: the serving process needs its configuration as argv[2]');
  return JSON.parse(Buffer.from(raw, 'base64').toString('utf8')) as ChildConfig;
}

const config = readConfig();

/**
 * The rate this credential and this connection address are held to.
 *
 * Both bounds sit far above the traffic this run generates, and that is deliberate rather than lenient.
 * What is measured is how long a request waits behind an erasure, and a request shed by a token bucket is
 * answered in microseconds and never queues at all: left at the shipped defaults, the tail this run exists
 * to print would be replaced by a count of refusals. The caller checks the status of every response, so a
 * bound that has been reached fails the run rather than quieting it.
 */
const RATE = { perMinute: 1_000_000, burst: 1_000_000 };

const issued = newPopCredential({ id: 'erasure-load', scopes: ['complete', 'read'] });
const record: CredentialRecord = { ...issued.record, rate: RATE };

const access = new CredentialStore({
  file: { version: CREDENTIALS_FILE_VERSION, credentials: [record] },
  peerRate: RATE,
});

let accessLog: AccessLog | null = null;
let app: GatewayInstance | null = null;

const out = (value: unknown): void => {
  process.stdout.write(`${JSON.stringify(value)}\n`);
};

interface Request {
  id: number;
  cmd: 'idle' | 'run' | 'steps' | 'throttle' | 'quit';
  seconds?: number;
  shape?: 'today' | 'chunked' | 'worker';
  dirs?: string[];
  /** The two sides of a second-request measurement: each is a walk over parts, in its own directories. */
  firstDirs?: string[];
  secondDirs?: string[];
  credential?: string;
  budgetMs?: number;
  mode?: 'reject' | 'queue';
  offsetMs?: number;
}

/** One unit of erasure work: a pass over one part, and what the loop it ran on saw while it did. */
interface Unit {
  dir: string;
  wallMs: number;
  facts: PassFacts;
  /** The chunked pass reports the longest synchronous stretch it took; the whole-file pass cannot, as
   * its own step is the pass. The loop gap in `gaps` covers both, which is why both are reported. */
  maxStepMs?: number;
  batchLines?: number;
  steps?: { name: string; ms: number }[];
  gaps: Distribution;
}

async function main(): Promise<void> {
  accessLog = await openFileAccessLog({ dir: config.accessLogDir, days: 184 });
  app = buildGateway({ access, accessLog });
  const address = await app.listen({ host: '127.0.0.1', port: 0 });
  out({
    serving: {
      port: Number(new URL(address).port),
      credentialId: record.id,
      secretKeyHex: Buffer.from(issued.privateKey).toString('hex'),
      pid: process.pid,
    },
  });
  createInterface({ input: process.stdin }).on('line', (text) => {
    void respond(text);
  });
}

async function respond(text: string): Promise<void> {
  let request: Request;
  try {
    request = JSON.parse(text) as Request;
  } catch {
    out({ ok: false, reason: 'erasure-pass: a command that is not JSON' });
    return;
  }
  out({ id: request.id, ok: true, ack: true });
  try {
    await handle(request);
  } catch (error) {
    out({ id: request.id, ok: false, reason: error instanceof Error ? error.message : String(error) });
  }
}

async function handle(request: Request): Promise<void> {
  switch (request.cmd) {
    case 'quit': {
      await app?.close();
      await accessLog?.close();
      out({ id: request.id, ok: true, bye: true });
      process.exit(0);
      return;
    }
    case 'idle': {
      await sleep(ACK_GRACE_MS);
      const gaps = watchLoopGaps();
      await sleep((request.seconds ?? 3) * 1000);
      out({ id: request.id, ok: true, gaps: gaps.stop() });
      return;
    }
    case 'run': {
      await sleep(ACK_GRACE_MS);
      const units: Unit[] = [];
      let workerStartMs: number | null = null;
      if (request.shape === 'worker') {
        workerStartMs = await startWorker();
      }
      try {
        for (const dir of request.dirs ?? []) {
          units.push(await runUnit(request, dir));
        }
      } finally {
        await stopWorker();
      }
      out({
        id: request.id,
        ok: true,
        units,
        workerStartMs,
        aggregate: distribution(units.map((each) => each.wallMs)),
        // The single longest thing the loop held onto across the run, which is what a caller feels as one
        // frozen request rather than as a distribution of them.
        worstGapMs: Math.max(0, ...units.map((each) => each.gaps.max)),
      });
      return;
    }
    case 'steps': {
      await sleep(ACK_GRACE_MS);
      const rows: Record<string, number>[] = [];
      for (const dir of request.dirs ?? []) {
        rows.push(await primitiveSteps(dir, request.credential ?? ''));
      }
      out({ id: request.id, ok: true, steps: rows });
      return;
    }
    case 'throttle': {
      await sleep(ACK_GRACE_MS);
      out({ id: request.id, ok: true, ...(await throttle(request)) });
      return;
    }
  }
}

/** A whole part, through the shape the request names. */
async function runUnit(request: Request, dir: string): Promise<Unit> {
  const credential = request.credential ?? '';
  const gaps = watchLoopGaps();
  const started = performance.now();
  if (request.shape === 'chunked') {
    const result = await chunkedScrubPart({
      path: join(dir, partName(0)),
      credential,
      budgetMs: request.budgetMs ?? 2,
    });
    return {
      dir,
      wallMs: performance.now() - started,
      facts: {
        removed: result.removed,
        files: 1,
        beforeBytes: result.beforeBytes,
        beforeSha256: result.beforeSha256,
        afterBytes: result.afterBytes,
        afterSha256: result.afterSha256,
      },
      maxStepMs: result.maxStepMs,
      batchLines: result.batchLines,
      steps: result.steps,
      gaps: gaps.stop(),
    };
  }
  if (request.shape === 'worker') {
    const reply = (await askWorker({ dir, credential })) as Record<string, unknown>;
    if (reply.ok !== true) throw new Error(`erasure-pass: the scrub worker refused: ${String(reply.reason)}`);
    return {
      dir,
      wallMs: reply.wallMs as number,
      facts: {
        removed: reply.removed as number,
        files: reply.files as number,
        beforeBytes: reply.beforeBytes as number,
        beforeSha256: reply.beforeSha256 as string,
        afterBytes: reply.afterBytes as number,
        afterSha256: reply.afterSha256 as string,
      },
      gaps: gaps.stop(),
    };
  }
  const pass = await wholeFilePass(dir, credential);
  return { dir, wallMs: pass.wallMs, facts: pass.facts, gaps: gaps.stop() };
}

/**
 * A second erasure arriving while one is running.
 *
 * Two answers are available and both are measured: refuse the second request and make whoever sent it
 * retry, or hold it until the first is done. The first costs the serving loop nothing beyond the run
 * already under way; the second costs it two runs, and the caller whose erasure was queued waits out the
 * first before its own begins. Which of the two is cheaper is a question about a queue that would
 * otherwise always be empty, so `offsetMs` drops the second request into the middle of the first run,
 * which is when anyone actually sends one.
 */
let inFlight: Promise<Unit[]> | null = null;

/** A walk over several parts, which is what one erasure request is when the log holds more than one. */
async function runPass(request: Request, dirs: string[]): Promise<Unit[]> {
  const units: Unit[] = [];
  for (const dir of dirs) {
    units.push(await runUnit(request, dir));
  }
  return units;
}

async function throttle(request: Request): Promise<Record<string, unknown>> {
  const firstDirs = request.firstDirs ?? [];
  const secondDirs = request.secondDirs ?? [];
  if (firstDirs.length === 0 || secondDirs.length === 0) {
    throw new Error('erasure-pass: a refusal measurement needs parts on both sides');
  }
  if (request.mode === undefined) throw new Error('erasure-pass: a refusal measurement needs a mode');
  const gaps = watchLoopGaps();
  const first = runPass(request, firstDirs);
  inFlight = first;
  await sleep(request.offsetMs ?? 150);
  const held = inFlight;
  const arrivedAt = performance.now();
  let accepted = true;
  let queueWaitMs = 0;
  if (held !== null) {
    if (request.mode === 'reject') {
      accepted = false;
    } else {
      const at = performance.now();
      await held.catch(() => undefined);
      queueWaitMs = performance.now() - at;
    }
  }
  let second: Unit[] | null = null;
  if (accepted) {
    const run = runPass(request, secondDirs);
    inFlight = run;
    second = await run;
  }
  // For a refusal this is the whole answer the caller gets, from the instant it arrived to the instant it
  // was told no, and it is what a rejected erasure request has to be judged on.
  const answeredMs = performance.now() - arrivedAt;
  inFlight = null;
  return {
    mode: request.mode,
    shape: request.shape,
    accepted,
    answeredMs,
    queueWaitMs,
    gaps: gaps.stop(),
    first: await first,
    second,
  };
}

/**
 * The parts of today's pass, taken apart, so that a whole-file figure can be read as a sum.
 *
 * These are the operations the shipped scrub performs on one part, stood up one at a time against the
 * same bytes. The point is attribution: a run of the published scrub reads, decodes, splits, digests and
 * parses a part more than once over, and the only way to say what one repeat is worth is to time one of
 * them by itself. Nothing here writes to the part, and the scratch file the second-to-last step makes is
 * removed before this returns.
 */
async function primitiveSteps(dir: string, credential: string): Promise<Record<string, number>> {
  const path = join(dir, partName(0));
  const scratch = join(dir, `.scratch-${String(process.pid)}.jsonl`);
  const row: Record<string, number> = {};
  const time = async (name: string, body: () => unknown): Promise<void> => {
    const at = performance.now();
    await body();
    // Each of these is one synchronous call with no yield inside it, so the time it took is exactly the
    // time nothing else ran. A loop-delay watch here would report this host's timer granularity, about
    // 15ms, for every step including the ones that cost a millisecond, and that is a number about the
    // instrument rather than about the work.
    row[name] = performance.now() - at;
  };
  let bytes: Buffer = Buffer.alloc(0);
  let text = '';
  let lines: string[] = [];
  let kept: string[] = [];
  let rendered = '';
  // Read once, untimed, so every step below is measured against the page cache rather than against the
  // volume: the difference between a number that repeats and one that does not.
  await readFile(path);
  await time('read whole part', () => {
    bytes = readFileSync(path);
  });
  await time('decode as utf8', () => {
    text = bytes.toString('utf8');
  });
  await time('split on newline', () => {
    lines = text.split('\n');
  });
  await time('digest the part', () => {
    return createHash('sha256').update(bytes).digest('hex');
  });
  await time('filter kept lines', () => {
    kept = lines.filter((line) => line.length > 0 && !namesSubject(line, credential));
  });
  await time('join kept lines', () => {
    rendered = `${kept.join('\n')}\n`;
  });
  await time('buffer the rewrite', () => {
    return Buffer.from(rendered, 'utf8');
  });
  await time('write the rewrite', () => {
    writeFileSync(scratch, rendered, 'utf8');
  });
  await time('read it back', () => {
    return readFileSync(scratch).byteLength;
  });
  unlinkSync(scratch);
  return row;
}

/**
 * The one reading rule every pass applies, restated here so the filter step is timed over the lines a
 * real run keeps rather than over a count of them.
 */
function namesSubject(line: string, credential: string): boolean {
  try {
    return (JSON.parse(line) as { cred?: unknown }).cred === credential;
  } catch {
    return false;
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise<void>((resolve) => {
    setTimeout(resolve, ms);
  });
}

/**
 * One worker per run, so a thread's start-up is measured rather than amortised away and the number for a
 * warm unit stays separable from the number for a cold one. A deployment would keep a pool of them, and
 * the difference between the two is the first unit of a run against the rest of it.
 */
let worker: Worker | null = null;

async function startWorker(): Promise<number> {
  const at = performance.now();
  const thread = new Worker(config.workerPath);
  worker = thread;
  await new Promise<void>((resolve, reject) => {
    thread.once('error', reject);
    thread.once('message', (value: { ready?: boolean }) => {
      if (value.ready === true) resolve();
    });
  });
  return performance.now() - at;
}

function askWorker(job: { dir: string; credential: string }): Promise<unknown> {
  const thread = worker;
  if (thread === null) return Promise.reject(new Error('erasure-pass: no worker is running'));
  return new Promise<unknown>((resolve, reject) => {
    const onMessage = (value: unknown): void => {
      thread.off('message', onMessage);
      thread.off('error', onError);
      resolve(value);
    };
    const onError = (error: Error): void => {
      thread.off('message', onMessage);
      thread.off('error', onError);
      reject(error);
    };
    thread.on('message', onMessage);
    thread.on('error', onError);
    thread.postMessage(job);
  });
}

async function stopWorker(): Promise<void> {
  const thread = worker;
  worker = null;
  if (thread === null) return;
  await thread.terminate();
}

void main().catch((error: unknown) => {
  out({ fatal: error instanceof Error ? error.message : String(error) });
  process.exit(1);
});
