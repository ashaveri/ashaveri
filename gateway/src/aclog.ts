import { mkdir, readdir, readFile, unlink, appendFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { AccessRecord } from './access-record.js';
import { HOST_CLOCK_SOURCE, type TimeSource } from './store.js';
import {
  openAccessJournal,
  scanJournalPartNames,
  splitCompleteLines,
  type AccessJournal,
} from './journal.js';

export type { AccessRecord } from './access-record.js';
export const ACCESS_RECORD_FIELDS: readonly (keyof AccessRecord)[] = [
  't',
  'rid',
  'cred',
  'auth',
  'scope',
  'm',
  'p',
  'rcp',
  'nce',
  'st',
  'dur',
  'deny',
];

/**
 * The same floor as `MINIMUM_RETENTION_SECONDS` in store.ts, stated in days. They are two literals
 * in two files, tied by an assertion in `test/aclog.test.ts`: drift is caught by a red test, not
 * prevented by the type system, and an import of the store from here is the coupling this file
 * does not have.
 */
export const MINIMUM_RETENTION_DAYS = 184;
export const MAX_ACCESS_FILE_BYTES = 32 * 1024 * 1024;
const FILE_PREFIX = 'access-';
const FILE_SUFFIX = '.jsonl';
/**
 * The name this writer makes and the name the sweep collects. Exported for the same reason as the
 * pattern below: the published CLI opens these files and cannot import this module at run time, so it
 * carries its own copy of this shape, and `packages/cli/test/accesslog.test.ts` holds the two copies
 * to the same set of names. Without that gate a widened part name here would leave the scrub skipping
 * real parts while reporting a count and a marker, which reads as an erasure that did not happen.
 */
export const ACCESS_PART_NAME = /^access-(\d{4}-\d{2}-\d{2})-(\d{3})\.jsonl$/u;
/**
 * The two families retention owns. A scrub marker is personal data at the level of a credential id,
 * so it cannot outlive the window that erased its subject, and it carries a date in its name for
 * exactly that reason. Only the sweep matches it: a marker is not a part this log writes to, counts
 * in its window, or shows in the start-up file list, and all three read names through
 * `ACCESS_PART_NAME`.
 *
 * Exported because the published CLI writes these names and cannot import this module at run time, so
 * the rule that a marker must be collectable lives in both packages. Its naming function is checked
 * against this pattern, and the CLI's copy of the part pattern above is checked against both, in
 * `packages/cli/test/accesslog.test.ts`.
 */
export const RETENTION_SWEEP_NAME = /^(?:access|scrub)-(\d{4}-\d{2}-\d{2})-(\d{3})\.jsonl$/u;
const DAY_MS = 86_400_000;
const ACCESS_FIELD_NAMES: ReadonlySet<string> = new Set<string>(ACCESS_RECORD_FIELDS);

export interface AccessWindow {
  from: number | null;
  to: number | null;
  count: number;
}

export interface AccessLog {
  record(entry: AccessRecord): Promise<void>;
  drain(): Promise<void>;
  window(): Promise<AccessWindow>;
  files(): Promise<string[]>;
  close(): Promise<void>;
}

/**
 * The question this log asks about one day before its sweep collects a part: does something other than
 * this window keep it.
 *
 * It is an injected predicate and not a record type, for the reason `store.ts` gives its own suspension:
 * which instruction names a day, what span it covers and whether it still stands belong to the
 * deployment, and weighing them where the ages are read keeps one rule rather than two. A day is handed
 * as the `YYYY-MM-DD` string read off the file name, because that is the only fact about age this sweep
 * owns: `store.ts` asks about a record's stamp, and this arm asks about the day a part is named for,
 * since a part carries many stamps and none of them may be re-read to decide an age.
 */
export interface AccessLogHold {
  /**
   * Whether the day named in a part's own name is kept at the instant `nowMillis` the sweep reads.
   * A day the caller answers false for is aged exactly as it was before this option existed.
   */
  coversDay(day: string, nowMillis: number): boolean;
}

export interface AccessLogOptions {
  /**
   * A request, not a clamp: `MINIMUM_RETENTION_DAYS` is the default when no value is named, and it
   * binds as a floor only where a caller agrees to one. Enforcing it against a caller is the job of
   * the surface that reads the operator's configuration. That surface is `gateway/src/cli.ts`, and what
   * a deployment's agreement is made with is its instruction record, `gateway/src/instruction-record.ts`:
   * the period that deployment states it owes, and whether it takes this floor as its own. The record
   * reaches this writer only as the number the run opened with, so a window a deployment wrote down and
   * a window it was offered are the same bytes here, and nothing in this file weighs one against the
   * other.
   */
  days?: number;
  /**
   * Suspends the sweep for the days it covers, which are then kept whatever this window says. Absent
   * means nothing is suspended: every part whose name-day is past the window is collected, which is the
   * answer every log this repository has published was aged under. It is an argument of one opening,
   * like the store's, so an opening without one reaches no instruction and ages what it always aged.
   */
  hold?: AccessLogHold;
  maxBytesPerFile?: number;
  /**
   * The clock this log ages by, in milliseconds, for a caller that has one to hand. It draws the
   * retention cutoff and nothing else: which day a line is written under comes from the record's own
   * stamp, so this stays a millisecond read whatever the source below declares.
   */
  nowMillis?: () => number;
  /**
   * Where `nowMillis` comes from when it names nothing: the same named source the rest of this process
   * stamps with, read at whole-second resolution. Absent means `HOST_CLOCK_SOURCE`, so how long a line
   * is kept, and when a day's files are collected, answer to a source the deployment named rather than
   * to one it was never told about. A source reads seconds and this log compares milliseconds, so one
   * multiply at the fallback below is the whole of the reconciliation; a caller needing sub-second
   * resolution passes `nowMillis` and stays in milliseconds. The `t` on the records this bound ages is
   * read through that same source where the line is written, in `server.ts`, so a cutoff and the stamp
   * it ages never come from two clocks that have not met.
   */
  time?: TimeSource;
  /**
   * Schedules the journal consumer's background ticks, for a caller that must hold the drain back and
   * pump it by hand. Absent means `setImmediate`, and no production caller passes this.
   */
  schedule?: (task: () => void) => void;
}

function dayOf(millis: number): string {
  return new Date(millis).toISOString().slice(0, 10);
}

function isJsonObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * The allowlist is applied here rather than trusted from the caller: an object
 * written by a future hook cannot add a field to the line, because only these names
 * are read out of it. That is the whole control, so it does not live in the code
 * that assembles the record.
 */
export function renderAccessLine(entry: AccessRecord): string {
  const out: Record<string, unknown> = {};
  for (const field of ACCESS_RECORD_FIELDS) out[field] = entry[field];
  return `${JSON.stringify(out)}\n`;
}

function textField(raw: Record<string, unknown>, field: string): string {
  const value = raw[field];
  if (typeof value !== 'string') throw new Error(`access field ${field} is not a string`);
  return value;
}

function numberField(raw: Record<string, unknown>, field: string): number {
  const value = raw[field];
  if (typeof value !== 'number') throw new Error(`access field ${field} is not a number`);
  return value;
}

function nullableTextField(raw: Record<string, unknown>, field: string): string | null {
  const value = raw[field];
  if (value === null) return null;
  if (typeof value !== 'string') throw new Error(`access field ${field} is neither a string nor null`);
  return value;
}

export function parseAccessLine(line: string): AccessRecord {
  const value: unknown = JSON.parse(line);
  if (!isJsonObject(value)) {
    throw new Error('access line is not an object');
  }
  for (const key of Object.keys(value)) {
    if (!ACCESS_FIELD_NAMES.has(key)) {
      throw new Error(`unknown field in access line: ${key}`);
    }
  }
  for (const field of ACCESS_RECORD_FIELDS) {
    if (!(field in value)) throw new Error(`missing field in access line: ${field}`);
  }
  const auth = nullableTextField(value, 'auth');
  if (auth !== null && auth !== 'pop' && auth !== 'bearer') {
    throw new Error('access field auth is neither pop, bearer, nor null');
  }
  return {
    t: numberField(value, 't'),
    rid: textField(value, 'rid'),
    cred: nullableTextField(value, 'cred'),
    auth,
    scope: nullableTextField(value, 'scope'),
    m: textField(value, 'm'),
    p: textField(value, 'p'),
    rcp: nullableTextField(value, 'rcp'),
    nce: nullableTextField(value, 'nce'),
    st: numberField(value, 'st'),
    dur: numberField(value, 'dur'),
    deny: nullableTextField(value, 'deny'),
  };
}

export interface MemoryAccessLog extends AccessLog {
  /** Test and inspection only; nothing on a request path reads this. */
  entries(): AccessRecord[];
  prune(atMillis: number): Promise<void>;
}

export function openMemoryAccessLog(options: AccessLogOptions = {}): MemoryAccessLog {
  const days = options.days ?? MINIMUM_RETENTION_DAYS;
  const hold = options.hold;
  const time = options.time ?? HOST_CLOCK_SOURCE;
  const nowMillis = options.nowMillis ?? ((): number => Math.floor(time.nowSeconds()) * 1000);
  let kept: AccessRecord[] = [];
  let closed = false;
  /**
   * A record is dropped when its age passes the window and no hold covers the day its own stamp falls
   * on. The day is taken the way the file arm takes it, from the stamp rather than from a name, so a
   * held day survives whole here as it does there: dropping the records a hold names would be the loss
   * the suspension exists to prevent.
   */
  async function pruneLocked(at: number): Promise<void> {
    kept = kept.filter(
      (entry) => entry.t > at - days * DAY_MS || (hold !== undefined && hold.coversDay(dayOf(entry.t), at)),
    );
  }
  return {
    async record(entry) {
      if (closed) throw new Error('the access log is closed');
      kept.push(entry);
      await pruneLocked(nowMillis());
    },
    async drain() {},
    async prune(at) {
      await pruneLocked(at);
    },
    async window() {
      if (kept.length === 0) return { from: null, to: null, count: 0 };
      const times = kept.map((entry) => entry.t);
      return { from: Math.min(...times), to: Math.max(...times), count: kept.length };
    },
    async files() {
      return [];
    },
    entries() {
      return [...kept];
    },
    async close() {
      closed = true;
      kept = [];
    },
  };
}

interface DayPart {
  day: string;
  part: number;
}

/** A `DayPart` plus the name it was listed under, which is the only thing two families share. */
interface ListedFile extends DayPart {
  name: string;
}

function ordered<T extends DayPart>(parts: T[]): T[] {
  return [...parts].sort((left, right) =>
    left.day === right.day ? left.part - right.part : left.day < right.day ? -1 : 1,
  );
}

function baseName(entry: DayPart): string {
  return `${FILE_PREFIX}${entry.day}-${String(entry.part).padStart(3, '0')}${FILE_SUFFIX}`;
}

function fileOf(dir: string, entry: DayPart): string {
  return join(dir, baseName(entry));
}

/** A missing `code` is not a missing file, so the `in` check carries the narrowing. */
function isNotFound(err: unknown): boolean {
  return err instanceof Error && 'code' in err && err.code === 'ENOENT';
}

/**
 * Turns a missing file into the empty answer it deserves and lets every other error through. A
 * file deleted between listing and reading shortens nothing by lying; a file that cannot be read
 * has to surface, because "nothing was retained" and "the retention is unreadable" are different
 * answers to a compliance question.
 */
function whenNotFound<T>(fallback: T): (err: unknown) => T {
  return (err: unknown): T => {
    if (!isNotFound(err)) throw err;
    return fallback;
  };
}

/**
 * Reads the journal parts a previous run left behind and hands their lines to the part writer
 * again, minus the lines the part files already hold, then unlinks every journal part. A start
 * that finds no journal parts pays one directory read and nothing else.
 *
 * The deduplication is by record id over the stamps the journal lines carry, because the crash
 * this recovery answers can sit anywhere between the journal append and the journal unlink: a
 * line may be in both places, in neither, or torn. A record id is unique per request across
 * restarts, so a line that survived into a part is recognized by its id and skipped exactly once,
 * and one that did not reach a part is appended exactly once. Reading only the parts whose
 * name-days overlap the journal's stamp span keeps the deduplication pass proportional to what
 * the journal held rather than to the whole log.
 *
 * A torn tail is answered only on the last part, where it is the mark of a write the previous
 * process died inside, and the record it was carrying had not resolved to any caller, so dropping
 * the fragment keeps the promise the resolution makes. The same fragment on an earlier part is
 * corruption, because rotation happens in a task that follows the append that filled the part.
 */
async function replayJournalIntoParts(
  dir: string,
  appendPart: (line: string) => Promise<void>,
  listAccessParts: () => Promise<ListedFile[]>,
): Promise<void> {
  const parts = await scanJournalPartNames(dir);
  if (parts.length === 0) return;
  const lines: string[] = [];
  const rids: string[] = [];
  let from = Number.POSITIVE_INFINITY;
  let to = Number.NEGATIVE_INFINITY;
  for (const [index, part] of parts.entries()) {
    const bytes = await readFile(join(dir, part.name)).catch(whenNotFound(Buffer.alloc(0)));
    const { complete, tornTail } = splitCompleteLines(bytes.toString('utf8'));
    if (tornTail !== null && index !== parts.length - 1) {
      throw new Error(`access journal part ${part.name} ends in a partial line while a later part exists`);
    }
    for (const line of complete) {
      let parsed: AccessRecord;
      try {
        parsed = parseAccessLine(line);
      } catch (err) {
        throw new Error(`access journal part ${part.name} holds a line that is not an access record`, {
          cause: err,
        });
      }
      lines.push(line);
      rids.push(parsed.rid);
      if (parsed.t < from) from = parsed.t;
      if (parsed.t > to) to = parsed.t;
    }
  }
  const seen = new Set<string>();
  if (lines.length > 0) {
    const fromDay = dayOf(from);
    const toDay = dayOf(to);
    for (const each of await listAccessParts()) {
      if (each.day < fromDay || each.day > toDay) continue;
      const text = await readFile(fileOf(dir, each), 'utf8').catch(whenNotFound(''));
      for (const line of text.split('\n')) {
        if (line.length === 0) continue;
        let parsed: AccessRecord;
        try {
          parsed = parseAccessLine(line);
        } catch {
          continue;
        }
        seen.add(parsed.rid);
      }
    }
    for (const [index, line] of lines.entries()) {
      const rid = rids[index];
      if (rid !== undefined && seen.has(rid)) continue;
      await appendPart(line);
    }
  }
  for (const part of parts) {
    await unlink(join(dir, part.name)).catch(whenNotFound(undefined));
  }
}

export async function openFileAccessLog(options: AccessLogOptions & { dir: string }): Promise<AccessLog> {
  const days = options.days ?? MINIMUM_RETENTION_DAYS;
  const hold = options.hold;
  const maxBytes = options.maxBytesPerFile ?? MAX_ACCESS_FILE_BYTES;
  const time = options.time ?? HOST_CLOCK_SOURCE;
  const nowMillis = options.nowMillis ?? ((): number => Math.floor(time.nowSeconds()) * 1000);
  const schedule = options.schedule;
  const dir = options.dir;
  await mkdir(dir, { recursive: true });

  let queue: Promise<void> = Promise.resolve();
  let sizeOfCurrent = 0;
  let currentDay: string | null = null;
  let currentPart = 0;
  let sweptDay: string | null = null;
  let closed = false;

  /**
   * One name parse behind both patterns, and a listing carries the name it was read from: rebuilding
   * `access-<day>-<part>.jsonl` from a marker's day and part would name a part that is not the file.
   */
  async function listNamed(pattern: RegExp): Promise<ListedFile[]> {
    const names = await readdir(dir).catch(whenNotFound<string[]>([]));
    return ordered(
      names.flatMap((name) => {
        const match = pattern.exec(name);
        if (match === null) return [];
        const day = match[1];
        const part = match[2];
        if (day === undefined || part === undefined) return [];
        return [{ day, part: Number(part), name }];
      }),
    );
  }

  function listOwnFiles(): Promise<ListedFile[]> {
    return listNamed(ACCESS_PART_NAME);
  }

  /**
   * Settles which file the next line belongs to and returns it, so no caller has to
   * reach for the mutable state or promise that a day has been chosen.
   */
  async function rotateIfNeeded(day: string, bytesAboutToAdd: number): Promise<ListedFile> {
    if (currentDay === null) {
      const newest = (await listOwnFiles()).at(-1);
      if (newest !== undefined) {
        currentDay = newest.day;
        currentPart = newest.part;
        sizeOfCurrent = await readFile(fileOf(dir, newest))
          .then((buffer) => buffer.byteLength)
          .catch(whenNotFound(0));
      }
    }
    if (currentDay !== day || sizeOfCurrent + bytesAboutToAdd > maxBytes) {
      if (currentDay !== day) {
        currentDay = day;
        currentPart = 0;
        const names = await readdir(dir).catch(whenNotFound<string[]>([]));
        while (names.includes(baseName({ day, part: currentPart }))) {
          currentPart += 1;
        }
      } else {
        currentPart += 1;
      }
      sizeOfCurrent = 0;
    }
    return { day: currentDay, part: currentPart, name: baseName({ day: currentDay, part: currentPart }) };
  }

  /**
   * Age is read from the file name, not from a stat time. A volume can be mounted
   * with whatever timestamps a copy gave it, and a rotation that trusted those would
   * delete the newest data on an operator's bad `cp -a`.
   *
   * A held day is kept whole. The sweep is already conservative in one direction, since a part is kept
   * while its name-day is inside the window and a day is the widest age it can read, so a part whose day
   * overlaps an active hold leaves with the whole of a day rather than with the records inside the hold:
   * keeping the part is the only answer this posture can give without opening the file. One reading of the
   * clock decides both halves of that, so the cut the name is weighed against and the instant the
   * suspension is asked about are the same instant, as they are in the store's retirement.
   */
  async function pruneLocked(): Promise<void> {
    const now = nowMillis();
    const cutoff = dayOf(now - days * DAY_MS);
    for (const candidate of await listNamed(RETENTION_SWEEP_NAME)) {
      if (candidate.day >= cutoff) continue;
      if (hold !== undefined && hold.coversDay(candidate.day, now)) continue;
      // Only a file that vanished between the listing and this call is forgiven. Swallowing every
      // failure would let a directory the process cannot delete age out of the retention in the
      // operator's head while its bytes stayed on the volume.
      await unlink(join(dir, candidate.name)).catch(whenNotFound(undefined));
    }
  }

  /**
   * Age is read from whole days in file names, so a second sweep inside the same incoming day can
   * only re-see what the first deleted. Without this gate every request paid a `readdir` of the log
   * directory; a rolled day always sweeps again, even if the clock only moved by a millisecond.
   *
   * `sweptDay` moves only after a sweep has finished without throwing, so a sweep that failed on an
   * unreadable or undeletable file is attempted again by the next request rather than waiting for
   * the day to roll. That makes `record()` reject for a reason the caller did not cause, which is
   * deliberate and safe in this order: the line is settled before the sweep runs, and `server.ts`
   * turns the rejection into a warning line rather than a failed response.
   */
  async function pruneOnNewDay(day: string): Promise<void> {
    if (sweptDay === day) return;
    await pruneLocked();
    sweptDay = day;
  }

  /**
   * The chain itself only ever settles resolved, so a failed link cannot skip the links queued
   * behind it: the rejection travels on the promise returned here, to the caller whose write it
   * was, and nowhere else. Chaining the task onto a link that could reject would otherwise turn
   * one bad write into a log that is silently and permanently off.
   */
  function enqueue(task: () => Promise<void>): Promise<void> {
    const settled = queue.then(task);
    queue = settled.then(
      () => undefined,
      () => undefined,
    );
    return settled;
  }

  /**
   * The one writer of access parts. Every line reaches its part through this function, from a
   * request's journal append and from a start's replay alike, so the rotation, the per-part size
   * bound and the day sweep weigh exactly one queue and no line can pass another.
   */
  async function appendPartLine(line: string): Promise<void> {
    const bytes = Buffer.byteLength(line);
    const parsed = parseAccessLine(line);
    const day = dayOf(parsed.t);
    await enqueue(async () => {
      const path = fileOf(dir, await rotateIfNeeded(day, bytes));
      await appendFile(path, line, 'utf8').catch(async (err: unknown) => {
        if (!isNotFound(err)) throw err;
        await mkdir(dir, { recursive: true });
        await writeFile(path, line, 'utf8');
      });
      sizeOfCurrent += bytes;
      try {
        await pruneOnNewDay(day);
      } catch (err) {
        // The line is settled: its bytes are in the part. A sweep the volume refuses outlives
        // this line, so it travels as a warning and the day retries, never as a failure of a
        // write that already landed: a sink rejection here would re-sink the landed line.
        process.emitWarning(
          `the access log sweep stopped: ${err instanceof Error ? err.message : String(err)}`,
          { code: 'ASHAVERI_ACCESS_SWEEP_FAILED' },
        );
      }
    });
  }

  /**
   * Replay runs before the journal opens, so a corrupt part left by a previous run refuses this
   * start with the file named, before any request is served into the state it contradicts.
   */
  await replayJournalIntoParts(dir, appendPartLine, listOwnFiles);
  const journal: AccessJournal = await openAccessJournal({
    dir,
    maxBytesPerFile: maxBytes,
    schedule,
    sink: appendPartLine,
  });

  return {
    async record(entry) {
      if (closed) throw new Error('the access log is closed');
      const line = renderAccessLine(entry);
      // An out-of-band stamp is refused at the caller: a line the sink could never render into a
      // part would otherwise sit in the journal, warning on every drain and refusing every start.
      dayOf(entry.t);
      await journal.append(line);
    },
    async drain() {
      await journal.drain();
      await queue;
    },
    async window() {
      await journal.drain();
      await queue;
      const files = await listOwnFiles();
      if (files.length === 0) return { from: null, to: null, count: 0 };
      let count = 0;
      let from: number | null = null;
      let to: number | null = null;
      for (const each of files) {
        const text = await readFile(fileOf(dir, each), 'utf8').catch(whenNotFound(''));
        for (const line of text.split('\n')) {
          if (line.length === 0) continue;
          let parsed: AccessRecord;
          try {
            parsed = parseAccessLine(line);
          } catch {
            continue;
          }
          count += 1;
          from = from === null ? parsed.t : Math.min(from, parsed.t);
          to = to === null ? parsed.t : Math.max(to, parsed.t);
        }
      }
      return { from, to, count };
    },
    async files() {
      await journal.drain();
      await queue;
      return (await listOwnFiles()).map((each) => fileOf(dir, each));
    },
    async close() {
      await journal.close();
      await queue;
      closed = true;
    },
  };
}
