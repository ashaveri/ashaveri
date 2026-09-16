import { mkdir, readdir, readFile, unlink, writeFile, appendFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { AccessRecord } from './access-record.js';

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
const FILE_NAME = /^access-(\d{4}-\d{2}-\d{2})-(\d{3})\.jsonl$/u;
/**
 * The two families retention owns. A scrub marker is personal data at the level of a credential id,
 * so it cannot outlive the window that erased its subject, and it carries a date in its name for
 * exactly that reason. Only the sweep matches it: a marker is not a part this log writes to, counts
 * in its window, or shows in the start-up file list, and all three read names through `FILE_NAME`.
 *
 * Exported because the published CLI writes these names and cannot import this module at run time, so
 * the rule that a marker must be collectable lives in both packages. Its naming function is checked
 * against this pattern in `packages/cli/test/accesslog.test.ts`, which is the only thing that keeps
 * the two copies from drifting apart in silence.
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

export interface AccessLogOptions {
  /**
   * A request, not a clamp: `MINIMUM_RETENTION_DAYS` is the default when no value is named, and it
   * binds as a floor only where a caller agrees to one. Enforcing it against a caller is the job of
   * the surface that reads the operator's configuration.
   */
  days?: number;
  maxBytesPerFile?: number;
  now?: () => number;
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
  const now = options.now ?? (() => Date.now());
  let kept: AccessRecord[] = [];
  let closed = false;
  async function pruneLocked(at: number): Promise<void> {
    kept = kept.filter((entry) => entry.t > at - days * DAY_MS);
  }
  return {
    async record(entry) {
      if (closed) throw new Error('the access log is closed');
      kept.push(entry);
      await pruneLocked(now());
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

export async function openFileAccessLog(options: AccessLogOptions & { dir: string }): Promise<AccessLog> {
  const days = options.days ?? MINIMUM_RETENTION_DAYS;
  const maxBytes = options.maxBytesPerFile ?? MAX_ACCESS_FILE_BYTES;
  const now = options.now ?? (() => Date.now());
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

  function listOwnFiles(): Promise<DayPart[]> {
    return listNamed(FILE_NAME);
  }

  /**
   * Age is read from the file name, not from a stat time. A volume can be mounted
   * with whatever timestamps a copy gave it, and a rotation that trusted those would
   * delete the newest data on an operator's bad `cp -a`.
   */
  async function pruneLocked(): Promise<void> {
    const cutoff = dayOf(now() - days * DAY_MS);
    for (const candidate of await listNamed(RETENTION_SWEEP_NAME)) {
      if (candidate.day < cutoff) {
        // Only a file that vanished between the listing and this call is forgiven. Swallowing every
        // failure would let a directory the process cannot delete age out of the retention in the
        // operator's head while its bytes stayed on the volume.
        await unlink(join(dir, candidate.name)).catch(whenNotFound(undefined));
      }
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
   * deliberate and safe in this order: the line is on disk before the sweep runs, so the request
   * that triggers a failing sweep has already had its record written, and `server.ts` turns the
   * rejection into a warning line rather than a failed response.
   */
  async function pruneOnNewDay(day: string): Promise<void> {
    if (sweptDay === day) return;
    await pruneLocked();
    sweptDay = day;
  }

  /**
   * Settles which file the next line belongs to and returns it, so no caller has to
   * reach for the mutable state or promise that a day has been chosen.
   */
  async function rotateIfNeeded(day: string, bytesAboutToAdd: number): Promise<DayPart> {
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
    return { day: currentDay, part: currentPart };
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

  return {
    async record(entry) {
      if (closed) throw new Error('the access log is closed');
      const line = renderAccessLine(entry);
      const bytes = Buffer.byteLength(line);
      const day = dayOf(entry.t);
      await enqueue(async () => {
        const path = fileOf(dir, await rotateIfNeeded(day, bytes));
        await appendFile(path, line, 'utf8').catch(async (err: unknown) => {
          if (!isNotFound(err)) throw err;
          await mkdir(dir, { recursive: true });
          await writeFile(path, line, 'utf8');
        });
        sizeOfCurrent += bytes;
        await pruneOnNewDay(day);
      });
    },
    async drain() {
      await queue;
    },
    async window() {
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
      await queue;
      return (await listOwnFiles()).map((each) => fileOf(dir, each));
    },
    async close() {
      await queue;
      closed = true;
    },
  };
}
