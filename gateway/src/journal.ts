import { appendFile, mkdir, readdir, readFile, unlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

/**
 * Journal parts hold rendered access lines whose `record()` has resolved and whose part files do
 * not hold them yet. The writer appends a line here and resolves; a background consumer drains
 * the lines into the part files in order and unlinks each part once every line it holds has been
 * drained; a start that finds parts left behind replays them through the same sink, deduplicated
 * by the record ids the parts already carry.
 *
 * The name carries a sequence and no date on purpose. The gateway's retention sweep matches
 * `access` and `scrub` parts, whose ages are read from dates in their names, and it must never
 * match this family: a part the sweep collected while the consumer had not drained it yet would
 * take acknowledged records with it. Erasure across the family is the published CLI scrub's
 * contract instead, which is why `packages/cli` carries its own copy of this name shape, held
 * next to its copy of the access part name by `packages/cli/test/accesslog.test.ts`.
 */
export const JOURNAL_PART_NAME = /^journal-(\d+)\.jsonl$/u;

export function journalPartName(seq: number): string {
  return `journal-${String(seq).padStart(3, '0')}.jsonl`;
}

/** A missing `code` is not a missing file, so the `in` check carries the narrowing. */
function isNotFound(err: unknown): boolean {
  return err instanceof Error && 'code' in err && err.code === 'ENOENT';
}

function whenNotFound<T>(fallback: T): (err: unknown) => T {
  return (err: unknown): T => {
    if (!isNotFound(err)) throw err;
    return fallback;
  };
}

/**
 * Splits a journal part's text into the lines a following newline makes complete and the tail
 * bytes a crash interrupted. A complete line keeps its newline: the journal carries rendered
 * lines verbatim, so the sink writes what it receives and no layer re-derives the terminator.
 * The empty string a final newline leaves behind is no tail: a part whose bytes end in a
 * newline carries no fragment.
 */
export function splitCompleteLines(text: string): { complete: string[]; tornTail: string | null } {
  const complete: string[] = [];
  let start = 0;
  for (;;) {
    const at = text.indexOf('\n', start);
    if (at === -1) break;
    complete.push(text.slice(start, at + 1));
    start = at + 1;
  }
  const tornTail = start < text.length ? text.slice(start) : null;
  return { complete, tornTail };
}

export interface JournalPartRef {
  name: string;
  seq: number;
}

export async function scanJournalPartNames(dir: string): Promise<JournalPartRef[]> {
  const names = await readdir(dir).catch(whenNotFound<string[]>([]));
  const parts: JournalPartRef[] = [];
  for (const name of names) {
    const match = JOURNAL_PART_NAME.exec(name);
    if (match === null) continue;
    const seq = match[1];
    if (seq === undefined) continue;
    parts.push({ name, seq: Number(seq) });
  }
  return parts.sort((left, right) => left.seq - right.seq);
}

export interface AccessJournal {
  /**
   * Writes the line into the current journal part and resolves once the bytes are in the file, in
   * the kernel's page cache: a killed process leaves them behind, a power cut can still take
   * them, and a start replays whatever a crash left. The line carries its own newline: the
   * journal stores rendered lines verbatim.
   */
  append(line: string): Promise<void>;
  /**
   * Resolves once every line handed to `append` before this call has reached the sink, or once
   * a drain attempt has failed and warned: the lines stay in their parts for the next start.
   */
  drain(): Promise<void>;
  /**
   * Drains what the scheduler has not yet drained by running the tick itself, then unlinks every
   * journal part. Lines the sink refused stay in their parts and reach the parts on the next
   * start's replay.
   */
  close(): Promise<void>;
}

export interface AccessJournalOptions {
  dir: string;
  maxBytesPerFile: number;
  /**
   * Receives each drained line in journal order, exactly once per line the writer settled, as
   * the writer rendered it: the newline is part of the line, and the sink writes what it
   * receives.
   */
  sink: (line: string) => Promise<void>;
  /**
   * Schedules the background drain's ticks. The default is `setImmediate`, which keeps a burst of
   * appends from paying one scan per record. Tests that must hold the drain back pass a scheduler
   * they pump themselves.
   */
  schedule?: (task: () => void) => void;
}

const DRAIN_RETRY_MILLIS = 1_000;

export async function openAccessJournal(options: AccessJournalOptions): Promise<AccessJournal> {
  const { dir, maxBytesPerFile, sink } = options;
  const scheduleTick = options.schedule ?? ((task: () => void): void => {
    setImmediate(task);
  });

  let closed = false;
  let closeStarted = false;
  let chain: Promise<void> = Promise.resolve();
  const existing = await scanJournalPartNames(dir);
  const last = existing.at(-1);
  let writeSeq = last !== undefined ? last.seq : 0;
  let writeSize = 0;
  if (last !== undefined) {
    writeSize = await readFile(join(dir, last.name))
      .then((buffer) => buffer.byteLength)
      .catch(whenNotFound(0));
  }

  let ticking = false;
  let tickQueued = false;
  let inflight: Promise<void> | null = null;
  let dirty = false;
  let pendingRemained = false;
  let failed = false;
  let stopped = false;
  const stalledParts = new Set<string>();
  const drainedBytes = new Map<string, number>();
  const seenBytes = new Map<string, number>();
  let idleWaiters: (() => void)[] = [];

  function enqueue(task: () => Promise<void>): Promise<void> {
    const settled = chain.then(task);
    chain = settled.then(
      () => undefined,
      () => undefined,
    );
    return settled;
  }

  function settleIdle(): void {
    const settled = !dirty && !pendingRemained && !ticking;
    if (settled || failed || stalledParts.size > 0) {
      const waiters = idleWaiters;
      idleWaiters = [];
      for (const waiter of waiters) waiter();
    }
  }

  function scheduleConsumer(): void {
    if (stopped || closed || ticking || tickQueued) return;
    tickQueued = true;
    scheduleTick(() => {
      tickQueued = false;
      const running = runTick();
      inflight = running;
      void running.finally(() => {
        if (inflight === running) inflight = null;
      });
    });
  }

  async function tickOnce(): Promise<void> {
    failed = false;
    // The flag clears here rather than in the tick loop: a scan that runs while appends land
    // must learn about them from the flag the appends set, and clearing inside the scan keeps
    // the loop's read free of a same-scope reset that would hide the appends' writes.
    dirty = false;
    const parts = await scanJournalPartNames(dir);
    let sawPending = false;
    for (const part of parts) {
      if (stalledParts.has(part.name)) continue;
      const bytes = await readFile(join(dir, part.name)).catch(whenNotFound(Buffer.alloc(0)));
      const size = bytes.byteLength;
      const priorBytes = seenBytes.get(part.name);
      if (priorBytes !== undefined && size < priorBytes) {
        /**
         * The part's bytes shrank under this consumer, which no writer here does: a rewrite of the
         * family from outside the process. The position this consumer had drained no longer names
         * anything in the file, and redraining from zero would put lines the parts already hold
         * into them a second time. The part is left for the next start's replay, which reads it
         * fresh and deduplicates against the parts by record id, and its drain is suspended while
         * this process lives.
         */
        stalledParts.add(part.name);
        process.emitWarning(
          `access journal part ${part.name} was rewritten outside this process; its records wait for the next start`,
          { code: 'ASHAVERI_ACCESS_JOURNAL_DRAIN_STALLED' },
        );
        continue;
      }
      seenBytes.set(part.name, size);
      // The drain reads only the bytes past its position. A full re-read of a growing part would
      // make every tick pay for the whole run again, and the position always sits just after a
      // newline byte, so an incremental read never splits a UTF-8 character; a torn tail that
      // ends mid-character is held back here and re-read whole once its bytes complete.
      const drained = drainedBytes.get(part.name) ?? 0;
      const { complete, tornTail } = splitCompleteLines(
        drained < size ? bytes.subarray(drained).toString('utf8') : '',
      );
      if (tornTail !== null && part.seq !== writeSeq) {
        throw new Error(`access journal part ${part.name} ends in a partial line while a later part exists`);
      }
      let advanced = drained;
      for (const line of complete) {
        await sink(line);
        // The position advances per sunk line, not per tick: a sink that threw after earlier
        // lines landed must not put those lines into the part a second time when the retry
        // drains the part again.
        advanced += Buffer.byteLength(line);
        drainedBytes.set(part.name, advanced);
      }
      if (tornTail !== null) sawPending = true;
      const isCurrent = part.seq === writeSeq;
      if (!isCurrent && tornTail === null) {
        await unlink(join(dir, part.name)).catch(whenNotFound(undefined));
        drainedBytes.delete(part.name);
        seenBytes.delete(part.name);
      }
    }
    pendingRemained = sawPending;
  }

  /**
   * Every tick run, scheduled or close-driven, serializes here. `close()` starts its own tick
   * without going through `scheduleConsumer`'s gates, so two runs could otherwise scan and sink
   * the same undrained lines concurrently and put each of them into the parts twice.
   */
  let tickChain: Promise<void> = Promise.resolve();

  function runTick(): Promise<void> {
    const running = tickChain.then(() => runTickBody());
    tickChain = running.then(
      () => undefined,
      () => undefined,
    );
    return running;
  }

  async function runTickBody(): Promise<void> {
    ticking = true;
    try {
      do {
        await tickOnce();
      } while (dirty);
    } catch (err) {
      failed = true;
      process.emitWarning(
        `the access journal drain stopped: ${err instanceof Error ? err.message : String(err)}`,
        { code: 'ASHAVERI_ACCESS_JOURNAL_DRAIN_FAILED' },
      );
      if (!stopped && !closed) {
        setTimeout(() => {
          scheduleConsumer();
        }, DRAIN_RETRY_MILLIS).unref();
      }
    } finally {
      ticking = false;
    }
    if (dirty || pendingRemained) {
      // A tick that drained lines has not proven emptiness, only that its snapshot held nothing
      // more: one confirmation scan after the writer has gone quiet is what a waiting drain
      // settles on.
      scheduleConsumer();
    } else {
      settleIdle();
    }
  }

  return {
    append(line) {
      if (closed) return Promise.reject(new Error('the access journal is closed'));
      const bytes = Buffer.byteLength(line);
      return enqueue(async () => {
        if (writeSize > 0 && writeSize + bytes > maxBytesPerFile) {
          writeSeq += 1;
          writeSize = 0;
        }
        const path = join(dir, journalPartName(writeSeq));
        await appendFile(path, line, 'utf8').catch(async (err: unknown) => {
          if (!isNotFound(err)) throw err;
          await mkdir(dir, { recursive: true });
          await writeFile(path, line, 'utf8');
        });
        writeSize += bytes;
        dirty = true;
        scheduleConsumer();
      });
    },
    drain() {
      if (closed) return Promise.resolve();
      return enqueue(async () => {}).then(() => {
        scheduleConsumer();
        return new Promise<void>((resolve) => {
          idleWaiters.push(resolve);
          settleIdle();
        });
      });
    },
    async close() {
      if (closeStarted) return;
      closeStarted = true;
      closed = true;
      await enqueue(async () => {});
      for (;;) {
        const current = inflight;
        if (current !== null) {
          await current;
        } else {
          const running = runTick();
          inflight = running;
          try {
            await running;
          } finally {
            if (inflight === running) inflight = null;
          }
        }
        if ((!dirty && !pendingRemained) || failed || stalledParts.size > 0) break;
      }
      stopped = true;
      const waiters = idleWaiters;
      idleWaiters = [];
      for (const waiter of waiters) waiter();
      for (const part of await scanJournalPartNames(dir)) {
        // A stalled part's undrained lines are still the only copy of those records, so close
        // leaves the file for the next start's replay instead of taking it with the process.
        if (stalledParts.has(part.name)) continue;
        await unlink(join(dir, part.name)).catch(whenNotFound(undefined));
      }
    },
  };
}
