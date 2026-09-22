import { spawn, type ChildProcessByStdio } from 'node:child_process';
import type { Readable, Writable } from 'node:stream';
import { createInterface } from 'node:readline';
import { mkdirSync, copyFileSync, writeFileSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { cpus, release, totalmem, tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ACK_GRACE_MS, distribution, ms, MIN_P99_SAMPLES, sleep, type Distribution } from './metrics.ts';
import { generatePart, subjectCredential, type GeneratedPart } from './part-fixture.ts';
import { chunkedScrubPart } from './chunked-pass.ts';
import { createDriver, windowSamples } from './load-driver.ts';
import type { PassFacts } from './unit-facts.ts';

/**
 * What an erasure pass costs a live request.
 *
 * Run it as `pnpm measure:erasure-pass` from the workspace root, which builds first: this reads the
 * compiled scrub and the compiled gateway, because the pass being measured is the one the published
 * command runs, and a re-typed copy of it would make every number here a claim about the copy.
 *
 * Three shapes, over the same bytes, in a serving process of their own:
 *
 * - `today` runs the shipped whole-file pass inside the serving process, which is what an erasure route
 *   would be if it held no further thought than that.
 * - `chunked` runs the same job over the same part, sliced so that no single synchronous step runs longer
 *   than the stated budget, yielding between the slices.
 * - `worker` runs the shipped whole-file pass again, unchanged, on a worker thread, so that the serving
 *   loop is free for the whole of it.
 *
 * Each line reports what a part cost, what the serving loop saw while it was being scrubbed, and what a
 * concurrent inference request waited. The last is the number a decision turns on, and it comes from
 * requests crossing a real socket into a process whose loop is busy: a client inside the measured process
 * would have been stalled by the very work it was timing.
 *
 * The fixture parts are built in the system's temporary directory and removed at the end of the run.
 * Nothing here writes inside the repository, and nothing here writes a vector anyone regenerates.
 */
const MIB = 1024 * 1024;
const KIB = 1024;
const DEFAULT_SIZES = [1, 8, 32];
const SHAPES = ['today', 'chunked', 'worker'] as const;
/** Candidate rates, highest first: the run takes the first one the machine serves with room to spare. */
const RATE_CANDIDATES = [400, 300, 200, 150, 100, 60];
/**
 * What counts as room to spare.
 *
 * A serving loop close to saturation and a serving loop with gaps in it answer the same erasure
 * differently, and only the second one is the case anyone is asking about: with the loop already busy, a
 * part's pass spends its life waiting between awaits rather than holding the loop, and the number printed
 * for the cost of a part is a number about the queue. The ceiling is therefore set at a latency a request
 * pays when nothing is being scrubbed, well under the shortest stall this run measures.
 */
const IDLE_P50_CEILING_MS = 4;
const IDLE_P99_CEILING_MS = 12;
/** Seconds a cell lets its own connection ramp settle before the idle reference starts counting. */
const RAMP_SECONDS = 1.5;
/** Parts per cell: enough of them that a run holds the loop for seconds, not one part's milliseconds. */
const PART_TARGET_BYTES = 128 * MIB;
const MIN_PARTS = 4;
const MAX_PARTS = 48;
const BASELINE_SECONDS = 3;
const SETTLE_SECONDS = 1.5;
/** The ceiling on one synchronous step of the chunked pass, and what its batch size is tuned against. */
const STEP_BUDGET_MS = 2;
/** Parts per side of a second-request measurement, so the second request has a run to land inside. */
const THROTTLE_PARTS = 2;
/** One seed per size, held across runs: repetition is meant to measure the machine, not new content. */
const FIXTURE_SEED = 4242;
/** How many parts the step breakdown is taken over, which is a few hundred milliseconds of reading. */
const STEP_PARTS = 3;

const TARGET = '/v1/chat/completions';
const BODY = `{"model":"mock-model-1","messages":[{"role":"user","content":"an inference request while a part is being scrubbed"}]}`;

interface Options {
  reps: number;
  sizes: number[];
  shapes: string[];
  rate: number | null;
}

function parseArgs(argv: string[]): Options {
  const given = new Map<string, string>();
  for (let at = 0; at < argv.length; at += 2) {
    const key = argv[at];
    if (key === undefined || !key.startsWith('--')) {
      throw new Error(`erasure-pass: unexpected argument '${String(key)}'`);
    }
    given.set(key.slice(2), argv[at + 1] ?? '');
  }
  const chosen = (name: string, allowed: readonly string[]): string[] => {
    const raw = given.get(name);
    if (raw === undefined || raw.length === 0) return [...allowed];
    const list = raw.split(',').map((each) => each.trim());
    if (list.some((each) => !allowed.includes(each))) {
      throw new Error(`erasure-pass: --${name} takes some of ${allowed.join(', ')}`);
    }
    return list;
  };
  const whole = (name: string, fallback: number): number => {
    const raw = given.get(name);
    if (raw === undefined) return fallback;
    const value = Number(raw);
    if (!Number.isInteger(value) || value < 1) throw new Error(`erasure-pass: --${name} wants a whole number`);
    return value;
  };
  const sizes = chosen('sizes', DEFAULT_SIZES.map(String)).map(Number);
  const rate = given.get('rate');
  return {
    reps: whole('reps', 3),
    sizes,
    shapes: chosen('shapes', SHAPES),
    rate: rate === undefined ? null : Number(rate),
  };
}

const say = (text: string): void => {
  process.stdout.write(`${text}\n`);
};

/** One part, where its copy for a shape stands, and what a pass over it has to report. */
interface Unit {
  dir: string;
  part: GeneratedPart;
}

interface ServingInfo {
  port: number;
  credentialId: string;
  secretKeyHex: string;
  pid: number;
}

/** A reply from the serving process, with the instant its acknowledgement arrived. */
interface Reply {
  ackAt: number;
  value: Record<string, unknown>;
}

/**
 * The measured process, as seen from here.
 *
 * The acknowledgement of a command and its answer are two lines carrying one id. That is not ceremony:
 * the answer arrives after the erasure has finished, and the window the requests are sorted into has to
 * open when the erasure opened, which the acknowledgement is the only notice of.
 */
class Serving {
  readonly up: Promise<ServingInfo>;
  private readonly child: ChildProcessByStdio<Writable, Readable, null>;
  private readonly lines: ReturnType<typeof createInterface>;
  private readonly pending = new Map<number, { resolve: (r: Reply) => void; reject: (e: unknown) => void }>();
  private readonly acks = new Map<number, number>();
  private readonly label: string;
  private nextId = 0;

  constructor(label: string, accessLogDir: string) {
    this.label = label;
    const here = (name: string): string => fileURLToPath(new URL(`./${name}`, import.meta.url));
    const config = Buffer.from(
      JSON.stringify({ accessLogDir, workerPath: here('scrub-worker.ts') }),
      'utf8',
    ).toString('base64');
    this.child = spawn(process.execPath, [here('serving-process.ts'), config], { stdio: ['pipe', 'pipe', 'inherit'] });
    this.lines = createInterface({ input: this.child.stdout });
    this.up = new Promise<ServingInfo>((resolve, reject) => {
      this.lines.once('line', (text) => {
        const parsed = JSON.parse(text) as { serving?: ServingInfo; fatal?: string };
        if (parsed.serving === undefined) {
          reject(new Error(`${this.label}: the serving process said ${parsed.fatal ?? text}`));
          return;
        }
        resolve(parsed.serving);
      });
    });
    this.lines.on('line', (text) => this.receive(text));
    this.child.on('exit', (code) => {
      const held = [...this.pending.values()];
      this.pending.clear();
      for (const each of held) each.reject(new Error(`${this.label}: the serving process exited with ${String(code)}`));
    });
  }

  private receive(text: string): void {
    let value: Record<string, unknown>;
    try {
      value = JSON.parse(text) as Record<string, unknown>;
    } catch {
      return;
    }
    const id = value.id;
    if (typeof id !== 'number') return;
    const held = this.pending.get(id);
    if (held === undefined) return;
    if (value.ack === true) {
      this.acks.set(id, performance.now());
      return;
    }
    this.pending.delete(id);
    if (value.ok === false) {
      held.reject(new Error(`${this.label}: ${String(value.reason)}`));
      return;
    }
    held.resolve({ ackAt: this.acks.get(id) ?? performance.now(), value });
  }

  send(cmd: Record<string, unknown>): Promise<Reply> {
    const id = (this.nextId += 1);
    const reply = new Promise<Reply>((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
    });
    this.child.stdin.write(`${JSON.stringify({ id, ...cmd })}\n`);
    return reply;
  }

  /**
   * Ask the serving process to stop, and stop it if it does not hear.
   *
   * The request to shut down is polite because a gateway that leaves its access log mid-write is a worse
   * artefact than a slow one; the timer is there because a run that has already failed cannot wait on a
   * process that is not going to exit, and the temporary directory it holds open cannot be removed while
   * it is running.
   *
   * The wait is on `close`, not `exit`: the second says the process stopped, the first that its side of
   * the pipes went with it, and it is the difference between a log directory whose last writer has left
   * and one the run tries to clear while that writer is still finishing. A process that closed before the
   * listener was attached never emits again, so the wait is bounded and the removal below retries.
   */
  async quit(): Promise<void> {
    const child = this.child;
    await this.send({ cmd: 'quit' }).catch(() => undefined);
    const gone = new Promise<void>((resolve) => {
      child.once('close', () => resolve());
    });
    const killer = setTimeout(() => child.kill('SIGKILL'), 5000);
    await Promise.race([gone, sleep(8000)]);
    clearTimeout(killer);
    this.lines.close();
  }
}

/**
 * Remove a directory the run made, retrying rather than reporting a failure nobody asked about.
 *
 * A directory keeps answering to its last writer for a moment after the process holding it is gone, and a
 * removal that runs the instant that process closes can meet a name still busy. A run of this size leaves
 * hundreds of megabytes of parts behind if it cannot clear them, and a tree that outlives the run is a
 * mess in the system's temporary directory rather than a measurement that went wrong. So the last word
 * here is a line on stdout, and never an error thrown over the one the run was about to print.
 */
async function discard(path: string): Promise<void> {
  for (let attempt = 1; attempt <= 10; attempt += 1) {
    try {
      await rm(path, { recursive: true, force: true });
      return;
    } catch (error) {
      if (attempt === 10) {
        const reason = error instanceof Error ? error.message : String(error);
        say(`erasure-pass: left '${path}' behind, which is a temporary directory and not a failed run: ${reason}`);
        return;
      }
      await sleep(attempt * 250);
    }
  }
}

/**
 * The parts one cell scrubs, each alone in a directory of its own.
 *
 * One part per directory is not a simplification of the walk: the shipped command opens every part a
 * directory holds, so a directory holding one part is one unit of that walk and its receipt covers exactly
 * that part. Timed per unit the numbers say what a part costs; run back to back the same units hold the
 * loop long enough for the requests arriving beside them to be a distribution rather than a few samples.
 *
 * Every unit directory holds its part under the same name, because the serving process reaches a part by
 * name and a directory of one has nothing to list.
 */
function prepareUnits(root: string, label: string, sizeMiB: number, count: number, credential: string): Unit[] {
  const units: Unit[] = [];
  for (let at = 0; at < count; at += 1) {
    const part = generatePart(0, FIXTURE_SEED + sizeMiB + at * 7919, sizeMiB * MIB, credential);
    const dir = join(root, `${label}-u${String(at).padStart(3, '0')}`);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, part.name), part.bytes);
    units.push({ dir, part });
  }
  return units;
}

/** Enough parts of this size to scrub for a few seconds, so a cell measures a tail and not one part. */
function partsFor(sizeMiB: number): number {
  return Math.max(MIN_PARTS, Math.min(MAX_PARTS, Math.round(PART_TARGET_BYTES / (sizeMiB * MIB))));
}

/** The same bytes again under new names, because a pass consumes what it scrubs. */
function copyUnits(units: Unit[], label: string): Unit[] {
  const copies: Unit[] = [];
  for (const each of units) {
    const dir = `${each.dir}-${label}`;
    mkdirSync(dir, { recursive: true });
    copyFileSync(join(each.dir, each.part.name), join(dir, each.part.name));
    copies.push({ dir, part: each.part });
  }
  return copies;
}

/**
 * The gate every number in this output stands on.
 *
 * A pass that did not take out exactly the records the fixture wrote in, and leave exactly the others
 * standing byte for byte, has not done the job the other shapes did and its latency belongs beside
 * nothing. The expectation is the generator's own tally, so no pass is checked against another pass.
 */
function checkFacts(label: string, got: PassFacts, part: GeneratedPart): void {
  const problems: string[] = [];
  if (got.beforeBytes !== part.bytes.byteLength) {
    problems.push(`read ${String(got.beforeBytes)} bytes, the part holds ${String(part.bytes.byteLength)}`);
  }
  if (got.beforeSha256 !== part.sha256) problems.push('the digest it read is not the digest of the part');
  if (got.afterSha256 !== part.keptSha256) {
    problems.push(`left ${got.afterSha256.slice(0, 12)}…, which is not ${part.keptSha256.slice(0, 12)}…`);
  }
  if (got.afterBytes !== part.keptBytes) problems.push(`left ${String(got.afterBytes)} bytes, expected ${String(part.keptBytes)}`);
  if (got.removed !== part.subjectLines) {
    problems.push(`counted ${String(got.removed)} records removed, the part held ${String(part.subjectLines)}`);
  }
  if (problems.length > 0) throw new Error(`erasure-pass: ${label}: ${problems.join('; ')}`);
}

interface UnitAnswer {
  dir: string;
  wallMs: number;
  facts: PassFacts;
  maxStepMs?: number;
  batchLines?: number;
  steps?: { name: string; ms: number }[];
  gaps: Distribution;
}

interface Cell {
  label: string;
  partBytes: number;
  lines: number;
  subjectLines: number;
  parts: number;
  wall: Distribution;
  /** The longest stall each part's pass caused, over the parts of the run. */
  gaps: Distribution;
  worstGap: number;
  baseline: Distribution;
  during: Distribution;
  /** The deepest queue this cell's own driver let build up, which says where a long answer was waiting. */
  peakInFlight: number;
  longestStep: number;
  batchLines: number;
  threadStartMs: number | null;
}

function signed(value: number): string {
  return `${value >= 0 ? '+' : ''}${ms(value)}`;
}

/**
 * A percentile with the number of samples behind it, and a marker when the two disagree about what it is
 * worth.
 *
 * The count travels with every percentile this prints, and not only on the line a reader would think to
 * check: a p99 taken over the parts of one cell is a maximum wearing a label however many requests ran
 * beside it, and the request lines and the part lines answer different questions from different lists.
 */
function sampled(value: number, count: number, kind: string): string {
  const thin = count < MIN_P99_SAMPLES ? ` [${String(count)} ${kind}, which is not a p99]` : '';
  return `${ms(value)} (${String(count)} ${kind})${thin}`;
}

function render(cell: Cell): string {
  const addedP50 = cell.during.p50 - cell.baseline.p50;
  const addedP99 = cell.during.p99 - cell.baseline.p99;
  const parts = `${String(cell.parts)} parts`;
  const rows = [
    `  ${cell.label}`,
    `    part            ${(cell.partBytes / MIB).toFixed(2)} MiB, ${String(cell.lines)} lines, ${String(cell.subjectLines)} of them the subject's, ${String(cell.parts)} parts in the run`,
    `    cost of a part  p50 ${ms(cell.wall.p50)}  p90 ${ms(cell.wall.p90)}  max ${ms(cell.wall.max)}  (${parts})`,
    `    loop held for   p50 ${ms(cell.gaps.p50)}  p99 ${sampled(cell.gaps.p99, cell.parts, 'parts')}  longest single gap ${ms(cell.worstGap)}  (${parts})`,
    `    request p50     ${sampled(cell.baseline.p50, cell.baseline.count, 'idle samples')} with nothing running -> ${sampled(cell.during.p50, cell.during.count, 'requests')} during, added ${signed(addedP50)}`,
    `    request p99     ${sampled(cell.baseline.p99, cell.baseline.count, 'idle samples')} with nothing running -> ${sampled(cell.during.p99, cell.during.count, 'requests')} during, added ${signed(addedP99)}`,
  ];
  if (cell.longestStep > 0) {
    rows.push(
      `    longest step    ${ms(cell.longestStep)} at ${String(cell.batchLines)} lines per batch, ` +
        `against a ${ms(STEP_BUDGET_MS)} budget, over ${parts}`,
    );
  }
  // Worth one line because it says which queue a long answer came from: a client that had nothing
  // outstanding when the loop stalled is a client that waited inside the measured process.
  rows.push(`    sent by the load driver  ${String(cell.peakInFlight)} requests in flight at the deepest`);
  if (cell.threadStartMs !== null) {
    rows.push(`    thread start    ${ms(cell.threadStartMs)} once for the run, and the first part pays for it`);
  }
  return rows.join('\n');
}

function drive(info: ServingInfo, perSecond: number): ReturnType<typeof createDriver> {
  return createDriver({
    port: info.port,
    credentialId: info.credentialId,
    secretKey: Buffer.from(info.secretKeyHex, 'hex'),
    perSecond,
    body: BODY,
    target: TARGET,
  });
}

/** A response that was not the completion asked for invalidates the run rather than narrowing it. */
function requireServed(driver: ReturnType<typeof createDriver>, where: string): void {
  const failures = driver.failures();
  if (failures.length > 0) {
    throw new Error(`erasure-pass: ${String(failures.length)} requests during ${where} were not completed: ${failures.slice(0, 3).join(', ')}`);
  }
}

function checkUnits(units: Unit[], answers: UnitAnswer[], shape: string): void {
  const byDir = new Map(units.map((each) => [each.dir, each]));
  for (const unit of answers) {
    const held = byDir.get(unit.dir);
    if (held === undefined) throw new Error(`erasure-pass: an answer named '${unit.dir}', which was never asked about`);
    checkFacts(`${shape} over ${held.part.name}`, unit.facts, held.part);
  }
}

/**
 * One shape, over parts of one size, with requests arriving beside it.
 *
 * The window a request is sorted into opens at the acknowledgement plus the grace the serving process
 * sleeps before it starts, and closes when its answer arrives. Requests outside it are the idle
 * reference, taken over the same connections in the same minutes, so what prints as `added` is the
 * difference of two things that differ in nothing but the erasure running under one of them.
 */
async function runCell(
  serving: Serving,
  units: Unit[],
  shape: string,
  credential: string,
  rate: number,
  info: ServingInfo,
): Promise<Cell> {
  const driver = drive(info, rate);
  driver.start();
  await sleep(RAMP_SECONDS * 1000);
  const baselineFrom = performance.now();
  await sleep(BASELINE_SECONDS * 1000);
  const reply = await serving.send({
    cmd: 'run',
    shape,
    dirs: units.map((each) => each.dir),
    credential,
    budgetMs: STEP_BUDGET_MS,
  });
  const from = reply.ackAt + ACK_GRACE_MS + 5;
  // The window closes when the answer arrives, which is the end of the last part. The settle below is
  // only for draining: a request issued inside the last stall answers after it, and it is already counted
  // because a sample is placed by the instant it was sent.
  const to = performance.now() - 2;
  await sleep(SETTLE_SECONDS * 1000);
  const samples = driver.samples();
  await driver.stop();
  requireServed(driver, `the ${shape} run over ${String(units.length)} parts`);
  const answers = (reply.value.units as UnitAnswer[] | undefined) ?? [];
  checkUnits(units, answers, shape);
  return {
    label: shape,
    partBytes: answers[0]?.facts.beforeBytes ?? 0,
    lines: units[0]?.part.lines ?? 0,
    subjectLines: units[0]?.part.subjectLines ?? 0,
    parts: answers.length,
    wall: distribution(answers.map((each) => each.wallMs)),
    gaps: distribution(answers.map((each) => each.gaps.max)),
    worstGap: Math.max(0, ...answers.map((each) => each.gaps.max)),
    baseline: distribution(windowSamples(samples, baselineFrom + 250, reply.ackAt - 50)),
    during: distribution(windowSamples(samples, from, to)),
    peakInFlight: driver.peakInFlight(),
    longestStep: Math.max(0, ...answers.map((each) => each.maxStepMs ?? 0)),
    batchLines: answers[answers.length - 1]?.batchLines ?? 0,
    threadStartMs: typeof reply.value.workerStartMs === 'number' ? (reply.value.workerStartMs as number) : null,
  };
}

/** The request rate this machine serves without the queue that would hide a tail. */
async function calibrate(serving: Serving, info: ServingInfo): Promise<number> {
  for (const rate of RATE_CANDIDATES) {
    const driver = drive(info, rate);
    driver.start();
    const reply = await serving.send({ cmd: 'idle', seconds: 2 });
    await sleep(300);
    const samples = driver.samples();
    await driver.stop();
    requireServed(driver, `the rate probe at ${String(rate)} a second`);
    const window = distribution(windowSamples(samples, reply.ackAt + ACK_GRACE_MS + 5, performance.now()));
    if (window.p50 < IDLE_P50_CEILING_MS && window.p99 < IDLE_P99_CEILING_MS && window.count > 100) {
      say(`  request rate: ${String(rate)} a second, served at p50 ${ms(window.p50)} and p99 ${ms(window.p99)} with nothing refused`);
      // The probe leaves a queue on the gateway; a cell that started measuring immediately would take its
      // idle reference from the tail of that queue and call it a baseline.
      await sleep(RAMP_SECONDS * 2000);
      return rate;
    }
    say(
      `  request rate: ${String(rate)} a second is past this machine, p50 ${ms(window.p50)} and p99 ${ms(window.p99)} ` +
        `with nothing running, ${String(window.count)} samples`,
    );
  }
  throw new Error('erasure-pass: no candidate request rate was served without queueing');
}

/**
 * Today's pass taken apart, so that a whole-file figure can be read as a sum.
 *
 * The shipped scrub reads, decodes, splits, digests and parses a part more than once on the way to its
 * rewrite, and the only way to say what one of those repeats costs is to stand one up by itself and time
 * it. No requests run alongside this: a step's own duration is the stall it causes, and nothing about it
 * depends on who is waiting.
 */
async function reportSteps(serving: Serving, units: Unit[], credential: string, sizeMiB: number): Promise<void> {
  const reply = await serving.send({
    cmd: 'steps',
    dirs: units.slice(0, STEP_PARTS).map((each) => each.dir),
    credential,
  });
  const rows = (reply.value.steps as Record<string, number>[] | undefined) ?? [];
  const first = rows[0];
  if (first === undefined) return;
  say(`  one part of ${String(sizeMiB)} MiB step by step, over ${String(rows.length)} parts`);
  for (const name of Object.keys(first)) {
    const values = rows.map((row) => row[name] ?? 0);
    say(`    ${name.padEnd(20)} p50 ${ms(distribution(values).p50)}  max ${ms(Math.max(...values))}`);
  }
}

/**
 * A second erasure while one is running, refused and queued.
 *
 * Both sides are a walk over several parts, because the question is which answer is cheaper for the
 * requests that have nothing to do with either, and a single 1 MiB part ends before a second request ever
 * gets there. A refusal costs the loop nothing and costs the operator a retry; a queue costs the operator
 * the wait and costs the loop a second run. Both print on the axis the shapes print on, and so does how
 * long each took to answer the erasure itself, because an instant refusal is not an erasure that happened.
 */
async function runThrottle(
  serving: Serving,
  firstUnits: Unit[],
  secondUnits: Unit[],
  mode: 'reject' | 'queue',
  shape: string,
  credential: string,
  rate: number,
  offsetMs: number,
  info: ServingInfo,
): Promise<Cell> {
  const driver = drive(info, rate);
  driver.start();
  await sleep(RAMP_SECONDS * 1000);
  const baselineFrom = performance.now();
  await sleep(BASELINE_SECONDS * 1000);
  const reply = await serving.send({
    cmd: 'throttle',
    mode,
    shape,
    firstDirs: firstUnits.map((each) => each.dir),
    secondDirs: secondUnits.map((each) => each.dir),
    credential,
    offsetMs,
    budgetMs: STEP_BUDGET_MS,
  });
  const from = reply.ackAt + ACK_GRACE_MS + 5;
  const to = performance.now() - 2;
  await sleep(SETTLE_SECONDS * 1000);
  const samples = driver.samples();
  await driver.stop();
  requireServed(driver, `the ${mode} throttle over ${shape}`);
  const first = (reply.value.first as UnitAnswer[] | undefined) ?? [];
  const second = (reply.value.second as UnitAnswer[] | null) ?? null;
  checkUnits(firstUnits, first, `${shape}, first of two erasures`);
  if (second !== null) checkUnits(secondUnits, second, `${shape}, second of two erasures`);
  const gaps = reply.value.gaps as Distribution | undefined;
  const answeredMs = (reply.value.answeredMs as number | undefined) ?? 0;
  const queueWaitMs = (reply.value.queueWaitMs as number | undefined) ?? 0;
  const workerStartMs = typeof reply.value.workerStartMs === 'number' ? reply.value.workerStartMs : null;
  const units = second === null ? first : [...first, ...second];
  say(
    `  a second ${shape} erasure ${mode === 'reject' ? 'refused' : 'queued'} ${ms(offsetMs)} into the first: ` +
      `answered in ${ms(answeredMs)}${second === null ? '' : `, of which ${ms(queueWaitMs)} was waiting`}`,
  );
  return {
    label: `${shape}, second request ${mode === 'reject' ? 'refused' : 'queued'}`,
    partBytes: first[0]?.facts.beforeBytes ?? 0,
    lines: firstUnits[0]?.part.lines ?? 0,
    subjectLines: firstUnits[0]?.part.subjectLines ?? 0,
    parts: units.length,
    wall: distribution(units.map((each) => each.wallMs)),
    gaps: distribution(units.map((each) => each.gaps.max)),
    worstGap: Math.max(gaps?.max ?? 0, ...units.map((each) => each.gaps.max)),
    baseline: distribution(windowSamples(samples, baselineFrom + 250, reply.ackAt - 50)),
    during: distribution(windowSamples(samples, from, to)),
    peakInFlight: driver.peakInFlight(),
    longestStep: 0,
    batchLines: 0,
    threadStartMs: workerStartMs,
  };
}

/**
 * The chunked pass against read blocks small enough to land inside a multi-byte character.
 *
 * Every field this gateway writes is ASCII, so the multi-byte bytes a part can hold are foreign ones, and
 * the only way to make a pass meet a character split across two blocks is to set the block size against
 * the bytes by hand. The check is the digest: a split that mangled a character changes the bytes of the
 * line that survives, and this stops the run there. It costs a few milliseconds, and it is the one claim
 * here about foreign bytes that does not rest on a comparison between shapes.
 */
async function checkSplitBlocks(root: string): Promise<void> {
  const credential = subjectCredential(991);
  const dir = join(root, 'block-check');
  mkdirSync(dir, { recursive: true });
  const part = generatePart(0, 991, 64 * KIB, credential);
  const path = join(dir, part.name);
  for (const blockBytes of [7, 61, 64 * KIB]) {
    writeFileSync(path, part.bytes);
    const result = await chunkedScrubPart({ path, credential, budgetMs: STEP_BUDGET_MS, blockBytes });
    checkFacts(
      `a ${String(blockBytes)}-byte block`,
      {
        removed: result.removed,
        files: 1,
        beforeBytes: result.beforeBytes,
        beforeSha256: result.beforeSha256,
        afterBytes: result.afterBytes,
        afterSha256: result.afterSha256,
      },
      part,
    );
  }
  say('split-block check: blocks of 7, of 61 and of 65536 bytes each leave the same part behind');
}

/** A metric collected across runs, so the spread of a number prints beside the number. */
function collect(into: Map<string, number[]>, key: string, metric: string, value: number): void {
  into.set(`${key}|${metric}`, [...(into.get(`${key}|${metric}`) ?? []), value]);
}

function printStability(collected: Map<string, number[]>): void {
  say('');
  say('STABILITY  the same bytes at the same rate over the runs above');
  say('           take the median; spread is (max - min) / median across the runs');
  for (const [name, values] of collected) {
    if (values.length < 2) continue;
    const sorted = [...values].sort((left, right) => left - right);
    const median = sorted[Math.floor(sorted.length / 2)] as number;
    const high = sorted[sorted.length - 1] as number;
    const low = sorted[0] as number;
    const spread = median > 0 ? (high - low) / median : 0;
    const at = name.lastIndexOf('|');
    const key = name.slice(0, at);
    const metric = name.slice(at + 1);
    say(`  ${key.padEnd(26)} ${metric.padEnd(22)} ${values.map((each) => ms(each)).join('  ')}  median ${ms(median)}  spread ${(spread * 100).toFixed(0)}%`);
  }
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  const root = await mkdtemp(join(tmpdir(), 'erasure-pass-'));
  const collected = new Map<string, number[]>();
  say(`erasure pass measurement, ${new Date().toISOString()}`);
  say(
    `node ${process.version} on ${process.platform} ${release()}, ${String(cpus().length)} cores of ${cpus()[0]?.model ?? 'unknown cpu'}, ` +
      `${(totalmem() / 1073741824).toFixed(1)} GiB`,
  );
  say(
    `one synchronous step is held to ${ms(STEP_BUDGET_MS)}, the idle reference runs ${String(BASELINE_SECONDS)}s before each cell, ` +
      `${String(options.reps)} runs over ${options.sizes.join('/')} MiB parts, shapes ${options.shapes.join(', ')}`,
  );
  let rate = options.rate;
  try {
    await checkSplitBlocks(root);
    for (let rep = 1; rep <= options.reps; rep += 1) {
      say('');
      say(`RUN ${String(rep)} of ${String(options.reps)}`);
      const accessLogDir = join(root, `log-${String(rep)}`);
      mkdirSync(accessLogDir, { recursive: true });
      const serving = new Serving(`run ${String(rep)}`, accessLogDir);
      const info = await serving.up;
      if (rate === null) rate = await calibrate(serving, info);
      const largest = Math.max(...options.sizes);
      /** What one part cost this run, per shape, which is how the second request is timed to land. */
      const partCost = new Map<string, number>();
      for (const sizeMiB of options.sizes) {
        const credential = subjectCredential(FIXTURE_SEED + sizeMiB);
        const count = partsFor(sizeMiB);
        const units = prepareUnits(root, `r${String(rep)}s${String(sizeMiB)}`, sizeMiB, count, credential);
        say(`  ${String(sizeMiB)} MiB parts: ${String(count)} of them, erasing ${credential}`);
        for (const shape of options.shapes) {
          const copies = copyUnits(units, shape);
          const cell = await runCell(serving, copies, shape, credential, rate, info);
          say(render(cell));
          partCost.set(shape, cell.wall.p50);
          const key = `${String(sizeMiB)}MiB ${shape}`;
          collect(collected, key, 'cost of a part', cell.wall.p50);
          collect(collected, key, 'longest loop gap', cell.worstGap);
          collect(collected, key, 'request p50 during', cell.during.p50);
          collect(collected, key, 'request p99 during', cell.during.p99);
          collect(collected, key, 'request p99 idle', cell.baseline.p99);
          for (const copy of copies) await discard(copy.dir);
        }
        await reportSteps(serving, units, credential, sizeMiB);
        if (sizeMiB === largest) {
          // Every shape this run measured gets the second request, including a worker: the question a
          // throttle asks about a thread is whether that thread is busy when the second erasure arrives,
          // and answering it for two of three shapes would leave the chosen one unasked.
          for (const shape of options.shapes) {
            // A third of the run measured for this shape: early enough that the first erasure is
            // certainly still going, late enough that it is past its own opening reads.
            const offsetMs = Math.max(5, Math.round((partCost.get(shape) ?? 100) / 3));
            for (const mode of ['reject', 'queue'] as const) {
              // Both sides get their own copy of the same parts, so the two runs in one cell are the same
              // work over the same bytes and only the answer to the second request differs between cells.
              const first = copyUnits(units.slice(0, THROTTLE_PARTS), `${shape}-${mode}-a`);
              const second = copyUnits(units.slice(0, THROTTLE_PARTS), `${shape}-${mode}-b`);
              const cell = await runThrottle(serving, first, second, mode, shape, credential, rate, offsetMs, info);
              say(render(cell));
              const key = `${String(sizeMiB)}MiB ${shape} ${mode}`;
              collect(collected, key, 'request p50 during', cell.during.p50);
              collect(collected, key, 'request p99 during', cell.during.p99);
              collect(collected, key, 'longest loop gap', cell.worstGap);
              for (const copy of [...first, ...second]) await discard(copy.dir);
            }
          }
        }
        for (const each of units) await discard(each.dir);
      }
      await serving.quit();
    }
    printStability(collected);
    say('');
    say('every part was checked against the records the fixture wrote into it and the bytes meant to survive it;');
    say('a shape whose output differed from the fixture would have stopped this run where it stood.');
  } finally {
    await discard(root);
  }
}

void main().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.stack ?? error.message : String(error)}\n`);
  process.exitCode = 1;
});
