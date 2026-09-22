import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { open, rename, stat, unlink } from 'node:fs/promises';

/**
 * What one part costs when the same job is sliced so that no single synchronous step is longer than a
 * stated budget.
 *
 * Three choices make this pass what it is, and each is a choice about the serving loop rather than about
 * the result:
 *
 * - The part is read in blocks and a line is cut at the byte that ends it, never at the boundary the
 *   reader happened to stop at. A `0x0a` byte cannot appear inside a multi-byte UTF-8 sequence, so a
 *   line's bytes are whole whenever they are decoded, and a foreign line cannot be silently re-spelled by
 *   a block ending mid-character. Decoding whole blocks and splitting the text would run at the same speed
 *   and be wrong on exactly the lines this file is most careful about.
 * - Every step yields: the filter, the write of one batch, the re-read that checks the destination, the
 *   re-read that confirms the published file. Between two yields the loop is free, and that is where a
 *   queued inference request goes.
 * - The batch size is not a constant. It is adjusted every turn against the budget, because what a batch
 *   costs depends on how long its lines are and on what else the machine is doing, and a number picked in
 *   advance will be wrong on somebody else's host.
 *
 * The bytes published here are the bytes the whole-file pass publishes, including the lines neither
 * program can read. That is checked part by part by the runner, not assumed.
 */
export interface ChunkedPassInput {
  path: string;
  credential: string;
  /** The ceiling on one synchronous stretch, in milliseconds. */
  budgetMs: number;
  /** Bytes per read. Left at the stream default except by the check that aims a block at a character. */
  blockBytes?: number;
  batchLines?: number;
}

export interface ChunkedPassResult {
  beforeBytes: number;
  beforeSha256: string;
  afterBytes: number;
  afterSha256: string;
  removed: number;
  /** Lines in the part as this pass counted them, blank lines included. */
  lines: number;
  /** The longest synchronous stretch between two yields, measured against `budgetMs`. */
  maxStepMs: number;
  /** Lines per batch when the pass finished, which is where the budget settled. */
  batchLines: number;
  wallMs: number;
  steps: { name: string; ms: number }[];
}

const NEWLINE = 0x0a;

/** A batch of lines costs something to write, so a yield between batches is not free at either end. */
const MIN_BATCH_LINES = 16;
const MAX_BATCH_LINES = 32_768;

/**
 * The longest run of synchronous work between two waits.
 *
 * Two calls, and where each one goes is the whole measurement. `settle` runs before a wait and books the
 * time since the last reset as synchronous work, which is what it was: nothing yielded in between. `reset`
 * runs after one and moves the clock without booking anything, because the time a promise spent waiting
 * belongs to whoever held the loop, not to this pass. Booking after a wait instead would charge this pass
 * the whole of a starvation episode and print a 2-millisecond budget as a five-second one.
 */
interface StepMeter {
  since: number;
  max: number;
  /** Synchronous time booked since the last batch, which is the figure the batch size is tuned on. */
  batch: number;
}

function settle(meter: StepMeter): number {
  const now = performance.now();
  const took = now - meter.since;
  meter.since = now;
  if (took > meter.max) meter.max = took;
  meter.batch += took;
  return took;
}

function reset(meter: StepMeter): void {
  meter.since = performance.now();
}

/**
 * Give the event loop back between batches.
 *
 * `setImmediate` rather than `setTimeout(0)`: the point of a yield is to hand the check phase to whatever
 * is waiting there, and a timer takes an extra loop turn plus a clamp of at least a millisecond, which over
 * the tens of thousands of batches a full part runs would add seconds of its own to the pass and be read as
 * the cost of the design rather than the cost of the primitive.
 */
function yieldTurn(meter: StepMeter): Promise<void> {
  settle(meter);
  return new Promise<void>((resolve) => {
    setImmediate(() => {
      reset(meter);
      resolve();
    });
  });
}

/** One line's bytes, decoded: a line is whole here, or this function is not reached. */
function isSubject(line: string, credential: string): boolean {
  try {
    return (JSON.parse(line) as { cred?: unknown }).cred === credential;
  } catch {
    return false;
  }
}

export async function chunkedScrubPart(input: ChunkedPassInput): Promise<ChunkedPassResult> {
  const started = performance.now();
  const meter: StepMeter = { since: started, max: 0, batch: 0 };
  const steps: { name: string; ms: number }[] = [];
  const blockBytes = input.blockBytes ?? 64 * 1024;
  const budgetMs = input.budgetMs;

  const mode = (await stat(input.path)).mode & 0o777;
  reset(meter);

  const tmp = `${input.path}.tmp-${String(process.pid)}`;
  const handle = await open(tmp, 'wx', mode);
  reset(meter);
  // Set again after the create, because a create mode is masked by the process umask. This is the same
  // correction the whole-file writer makes, and for the same reason: a part that comes back unwritable has
  // cost its gateway the log it appends to.
  await handle.chmod(mode);
  reset(meter);

  const hash = createHash('sha256');
  let sourceBytes = 0;
  let lines = 0;
  let subjectLines = 0;
  let keptLines = 0;
  let batchLines = input.batchLines ?? 128;
  let written = 0;
  let carry = Buffer.alloc(0);
  const kept: string[] = [];

  /** One complete line, in the order the part holds them. */
  function take(text: string): void {
    lines += 1;
    if (text.length === 0) return;
    if (isSubject(text, input.credential)) {
      subjectLines += 1;
      return;
    }
    keptLines += 1;
    kept.push(text);
  }

  /**
   * Grow the batch while a turn finishes well inside the budget and halve it when it does not. The figure
   * this tunes on is synchronous time this pass booked itself, so a wait for the loop is never charged to
   * the batch, and a batch that really is too big is never excused.
   */
  function tune(): void {
    const took = meter.batch;
    meter.batch = 0;
    if (took > budgetMs) batchLines = Math.max(MIN_BATCH_LINES, Math.floor(batchLines / 2));
    else if (took < budgetMs / 3) batchLines = Math.min(MAX_BATCH_LINES, batchLines * 2);
  }

  /**
   * One batch's worth of kept lines, appended at the offset this pass has reached.
   *
   * The offset is carried here rather than left to the handle: `filehandle.writeFile` puts its data at the
   * start of the file each time it is called, so a pass that wrote a part in batches with it would end with
   * only the last batch on disk and a digest agreeing with nothing. A positioned write says what it means,
   * and the running total is then a number this pass can check itself against.
   */
  async function flush(): Promise<void> {
    // A turn can run past the budget without a full batch in hand, and a batch with nothing in it has one
    // line to write: nothing. Joining an empty batch would publish a lone newline, which is a blank line in
    // a part nobody wrote blank lines into.
    if (kept.length === 0) {
      await yieldTurn(meter);
      return;
    }
    const bytes = Buffer.from(`${kept.join('\n')}\n`, 'utf8');
    settle(meter);
    await handle.write(bytes, 0, bytes.length, written);
    reset(meter);
    written += bytes.length;
    kept.length = 0;
    await yieldTurn(meter);
  }

  try {
    const at = performance.now();
    for await (const chunk of createReadStream(input.path, { highWaterMark: blockBytes })) {
      reset(meter);
      hash.update(chunk);
      sourceBytes += chunk.length;
      const buf = carry.length === 0 ? chunk : Buffer.concat([carry, chunk]);
      let from = 0;
      for (;;) {
        const end = buf.indexOf(NEWLINE, from);
        if (end === -1) break;
        take(buf.subarray(from, end).toString('utf8'));
        from = end + 1;
        // The budget is consulted once per batch rather than once per line, because a clock reading per
        // line would itself be a share of the pass's cost. An overrun is then bounded by one batch of
        // lines, which is what a ceiling on a step means.
        if (kept.length >= batchLines || meter.batch + (performance.now() - meter.since) > budgetMs) {
          await flush();
          tune();
        }
      }
      // Copied rather than sliced, and always: a block that holds no newline leaves the whole of it as the
      // carry, and a block that ends mid-line leaves its tail. The reader's buffer is not ours to hold on
      // to, because a short read is served out of a pool the next read overwrites.
      carry = Buffer.from(buf.subarray(from));
      settle(meter);
    }
    // A part whose last byte is not a newline still ends in one after the rewrite, as it does after the
    // whole-file pass: that pass splits on the newline, keeps the trailing fragment as a line, and joins
    // with a newline after the last kept line.
    if (carry.length > 0) take(carry.toString('utf8'));
    if (kept.length > 0) {
      await flush();
      tune();
    }
    settle(meter);
    await handle.close();
    reset(meter);
    steps.push({ name: 'read, filter, write', ms: performance.now() - at });
  } catch (error) {
    settle(meter);
    await handle.close().catch(() => undefined);
    await unlink(tmp).catch(() => undefined);
    throw error;
  }

  const beforeSha256 = hash.digest('hex');

  // The destination is asked whether it still holds what was read, in the instant before the rename, which
  // is the question the whole-file writer asks at the same point. Here it costs a streaming read rather
  // than a second copy of the part in memory.
  const atCheck = performance.now();
  const seen = await digestFile(input.path, blockBytes, meter);
  steps.push({ name: 'recheck the source', ms: performance.now() - atCheck });
  if (seen.bytes !== sourceBytes || seen.sha256 !== beforeSha256) {
    settle(meter);
    await unlink(tmp).catch(() => undefined);
    throw new Error(`erasure-pass: '${input.path}' changed while this pass was reading it, so it published nothing`);
  }

  const atRename = performance.now();
  settle(meter);
  await rename(tmp, input.path);
  steps.push({ name: 'rename', ms: performance.now() - atRename });
  reset(meter);

  const atConfirm = performance.now();
  const published = await readPartFacts(input.path, input.credential, blockBytes, meter);
  steps.push({ name: 'confirm the published part', ms: performance.now() - atConfirm });
  // The bytes written and the bytes found are the same count only if no batch was dropped and none was
  // written twice, which is the one failure mode a positioned write has that a single write cannot have.
  if (published.bytes !== written) {
    throw new Error(`erasure-pass: '${input.path}' holds ${String(published.bytes)} bytes after ${String(written)} were written`);
  }

  // A part this pass emptied is unlinked rather than rewritten as an empty file: a name the retention
  // sweep can no longer match would keep every removed line on the volume, and that is the same decision
  // the whole-file pass makes, for the same reason.
  if (keptLines === 0) {
    settle(meter);
    await unlink(input.path);
    published.bytes = 0;
    published.sha256 = EMPTY_SHA256;
    published.subjectLines = 0;
    reset(meter);
  }

  const total = performance.now() - started;
  return {
    beforeBytes: sourceBytes,
    beforeSha256,
    afterBytes: published.bytes,
    afterSha256: published.sha256,
    removed: Math.max(0, subjectLines - published.subjectLines),
    lines,
    maxStepMs: meter.max,
    batchLines,
    wallMs: total,
    steps: [...steps, { name: 'pass total', ms: total }],
  };
}

/** The digest of no bytes, which is what a part that is gone reports. */
const EMPTY_SHA256 = createHash('sha256').digest('hex');

async function digestFile(
  path: string,
  blockBytes: number,
  meter: StepMeter,
): Promise<{ bytes: number; sha256: string }> {
  const hash = createHash('sha256');
  let bytes = 0;
  for await (const chunk of createReadStream(path, { highWaterMark: blockBytes })) {
    reset(meter);
    hash.update(chunk);
    bytes += chunk.length;
    await yieldTurn(meter);
  }
  return { bytes, sha256: hash.digest('hex') };
}

/**
 * The published part, counted from the disk rather than from what this pass meant to write: what a receipt
 * says about a part has to come from a read of the part.
 */
async function readPartFacts(
  path: string,
  credential: string,
  blockBytes: number,
  meter: StepMeter,
): Promise<{ bytes: number; sha256: string; lines: number; subjectLines: number }> {
  const hash = createHash('sha256');
  let bytes = 0;
  let lines = 0;
  let subjectLines = 0;
  let carry = Buffer.alloc(0);
  function count(text: string): void {
    if (text.length === 0) return;
    lines += 1;
    if (isSubject(text, credential)) subjectLines += 1;
  }
  for await (const chunk of createReadStream(path, { highWaterMark: blockBytes })) {
    reset(meter);
    hash.update(chunk);
    bytes += chunk.length;
    const buf = carry.length === 0 ? chunk : Buffer.concat([carry, chunk]);
    let from = 0;
    for (;;) {
      const end = buf.indexOf(NEWLINE, from);
      if (end === -1) break;
      count(buf.subarray(from, end).toString('utf8'));
      from = end + 1;
    }
    carry = Buffer.from(buf.subarray(from));
    await yieldTurn(meter);
  }
  if (carry.length > 0) count(carry.toString('utf8'));
  settle(meter);
  return { bytes, sha256: hash.digest('hex'), lines, subjectLines };
}
