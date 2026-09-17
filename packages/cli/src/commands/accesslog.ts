import { readdir, readFile, stat, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { publishNew, writeAtomically } from '../atomic.js';
import { checkId } from '../records.js';
import { UsageError, writeJson } from '../usage.js';

/**
 * The parts this program will open, which is the gateway's own log-file name copied rather than
 * imported: the published CLI cannot depend on the private package at run time. Exported so
 * `test/accesslog.test.ts` can hold the two ideas of a collectable name to the same set of names.
 */
export const ACCESS_FILE = /^access-(\d{4}-\d{2}-\d{2})-(\d{3})\.jsonl$/u;

/** A day's whole allotment of marker names, and the mode one is published at. */
const MARKER_SLOTS = 1_000;
const MARKER_MODE = 0o600;

export interface ScrubMarker {
  t: number;
  credential: string;
  removed: number;
  files: number;
}

export interface ScrubResult {
  removed: number;
  files: number;
  marker: string | null;
}

export interface AccessLogFlags {
  'access-log'?: string;
  credential?: string;
  json?: boolean;
}

/**
 * Erasure with a receipt of itself. An erasure request that leaves a silence cannot be told apart
 * from a gap in the retention, so the scrub records that it happened, names the credential it
 * emptied, and carries a count and nothing else.
 *
 * A line this program cannot read stays in the file exactly as it was found, byte for byte: the
 * erasure was asked for one credential's records, and a scrub that quietly discarded what it did not
 * understand is not a scrub. The bytes that can move are the ones the writer always appends, so the
 * promise is per-line preservation plus a possible trailing newline in a file that had none.
 */
export async function accesslogScrub(dir: string, credential: string, now: () => number): Promise<ScrubResult> {
  // Settled first, before a single part is opened: a day the retention sweep cannot match would
  // otherwise be discovered after the erasure it is meant to record, which leaves the operator the
  // choice between a receipt nothing will collect and no receipt at all.
  const at = now();
  const day = markerDay(at);
  const names = await readdirOrThrow(dir);
  const targets = names.filter((each) => ACCESS_FILE.test(each)).sort();
  if (targets.length === 0) {
    throw new UsageError('--access-log holds no access-*.jsonl files; point it at the directory signerd writes');
  }
  let removed = 0;
  let touched = 0;
  try {
    for (const name of targets) {
      const path = join(dir, name);
      const lines = (await readPart(path)).split('\n');
      const kept: string[] = [];
      let present = 0;
      for (const line of lines) {
        if (line.length === 0) continue;
        present += 1;
        let cred: unknown;
        try {
          cred = (JSON.parse(line) as { cred?: unknown }).cred;
        } catch {
          kept.push(line);
          continue;
        }
        if (cred === credential) continue;
        kept.push(line);
      }
      if (kept.length === present) continue;
      if (kept.length === 0) {
        // A fully scrubbed part is unlinked, not renamed. A copy under a name the gateway's retention
        // can no longer match would keep every removed line on the volume forever, and it would read
        // as a completed erasure that left the data behind.
        await removePart(path);
      } else {
        await writeAtomically(path, `${kept.join('\n')}\n`, await modeOf(path), 'cannot rewrite access log part');
      }
      // Counted only once the part carrying them is gone: a scan that matched records and then failed
      // to write has removed nothing, and a marker claiming otherwise is worse than no marker.
      removed += present - kept.length;
      touched += 1;
    }
  } catch (error) {
    // Records are gone at this point, and the marker is the only evidence an operator has of which
    // ones, so a scrub that dies halfway writes the receipt for the parts it already rewrote before it
    // reports the failure. The refusal keeps its own first sentence: a marker that cannot be written is
    // not the story, and it must not push the real one off the line. Nothing is attempted when this run
    // has removed nothing, because then there is no erasure to evidence and the failure stands alone.
    if (removed === 0) throw error;
    const reason = error instanceof Error ? error.message : String(error);
    const receipt = await writeReceipt(dir, at, day, credential, removed, touched).catch(() => null);
    if (receipt === null) throw counts(reason, removed, touched);
    throw new UsageError(`${reason}; the removals that landed are marked in '${receipt}'`);
  }
  if (removed === 0) return { removed: 0, files: 0, marker: null };
  // The erasure has already happened and cannot be taken back, so this refusal cannot be the writer's
  // bare sentence about a file: a run that removed records and left no receipt is exactly the silence
  // the marker exists to prevent, and the numbers have to reach the operator some other way.
  const marker = await writeReceipt(dir, at, day, credential, removed, touched).catch((error: unknown) => {
    throw counts(error instanceof Error ? error.message : String(error), removed, touched);
  });
  return { removed, files: touched, marker };
}

/**
 * The counts a scrub has taken out of the volume, appended to the sentence about the failure that
 * stopped it. Both routes here are a run that has erased and reported nothing, and the second is the
 * easier to lose: a failure halfway through the loop reports the part that stopped the run, while the
 * numbers belong to the parts behind it, and a re-run reads `removed 0` because those lines are gone.
 */
function counts(reason: string, removed: number, files: number): UsageError {
  const record = removed === 1 ? 'record' : 'records';
  const part = files === 1 ? 'file' : 'files';
  return new UsageError(
    `${reason}; ${String(removed)} ${record} removed from ${String(files)} ${part} with no marker written`,
  );
}

/**
 * The receipt itself, at the mode this program chooses: the marker is a file the scrub makes, not a
 * part whose bits it inherited from a running gateway, so `0600` is right for it and wrong for those.
 * The name is claimed as part of the write rather than chosen and then renamed into, because a rename
 * replaces whatever stands at the name, which would destroy the receipt an earlier run left there.
 */
async function writeReceipt(
  dir: string,
  atMillis: number,
  day: string,
  credential: string,
  removed: number,
  files: number,
): Promise<string> {
  const receipt: ScrubMarker = { t: atMillis, credential, removed, files };
  const text = `${JSON.stringify(receipt)}\n`;
  const names = await readdirOrThrow(dir);
  return chooseScrubName(names, day, async (name) =>
    publishNew(join(dir, name), text, MARKER_MODE, 'cannot write the scrub marker'),
  );
}

async function readdirOrThrow(dir: string): Promise<string[]> {
  try {
    return await readdir(dir);
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    throw new UsageError(`cannot read --access-log directory '${dir}': ${reason}`);
  }
}

/**
 * A part the listing named but the open refused is a fixable condition with a name worth printing by
 * hand: the operating system's own sentence carries no path for this failure (`EISDIR: illegal
 * operation on a directory, read`), and an uncaught error reaches the terminal as a stack over several
 * lines that no guard has read.
 */
async function readPart(path: string): Promise<string> {
  try {
    return await readFile(path, 'utf8');
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    throw new UsageError(`cannot read access log part '${path}': ${reason}`);
  }
}

/**
 * The marker is named like a log part, one family of its own, so the retention sweep ages it out on
 * the day in its name and the log never reads one as a record. That reason is also the ceiling: the
 * sweep matches exactly three digits, so a fourth is not a later marker but a file nothing will ever
 * collect, holding a credential id. A day that has filled its thousand is refused out loud.
 *
 * The listing is a moment old by the time it is read, so a name it calls free is only a candidate.
 * `claim` publishes at it and reports whether the name was there to take, and a name another run has
 * since filled is passed over like one the listing had already seen. Without that, the search would
 * end in a write that replaces the earlier run's marker, destroying the only receipt that erasure has
 * while this one prints a line saying it made its own.
 */
export async function chooseScrubName(
  names: readonly string[],
  day: string,
  claim: (name: string) => Promise<boolean>,
): Promise<string> {
  checkDay(day);
  const taken = new Set(names);
  for (let seq = 0; seq < MARKER_SLOTS; seq += 1) {
    const candidate = `scrub-${day}-${String(seq).padStart(3, '0')}.jsonl`;
    if (taken.has(candidate)) continue;
    if (await claim(candidate)) return candidate;
    taken.add(candidate);
  }
  throw new UsageError(
    `--access-log already holds a thousand markers for ${day}; the slot is three digits because that is all the retention sweep matches`,
  );
}

/**
 * The day a marker is named for, in the only shape its name can carry: four digits, a dash, two, a
 * dash, two. `toISOString()` leaves that shape for a clock outside the years it can hold, printing a
 * signed six-digit year instead, and `--now` reaches such a clock. A name in that form is not a later
 * marker but a file nothing will collect, holding a credential id on the volume past the window that
 * aged its subject out, so it is a refusal rather than a name.
 */
const DAY = /^\d{4}-\d{2}-\d{2}$/u;

function checkDay(day: string): string {
  if (!DAY.test(day)) {
    throw new UsageError(
      `cannot name a scrub marker for the day '${day}': the retention sweep matches a date of four digits`,
    );
  }
  return day;
}

function markerDay(atMillis: number): string {
  return checkDay(new Date(atMillis).toISOString().slice(0, 10));
}

/**
 * A part's own permission bits, so a scrub run by one operator does not silently re-mode a file a
 * running gateway is appending to. `gateway/src/aclog.ts` creates parts with the process default mode,
 * and a rewrite that imposed its own would leave that writer unable to append, which the gateway
 * reports as a warning rather than a failure. The value has to be read rather than picked, because
 * `rename` replaces the destination's inode whole: any mode not read here is a mode invented on the way
 * out. A name that cannot be read is therefore a refusal, not a default: the common reason is the
 * retention sweep having taken the part between the listing and here, and a rewrite that went ahead
 * would put that name back on the volume carrying records the sweep had already aged out, at a mode
 * nobody chose. The gap between this read and the rename is stated rather than closed, because nothing
 * in `node:fs` makes a rename conditional on the destination being there already. Exported because the
 * refusal has no gate at the command's own height: making `stat` fail on a name the listing produced
 * takes a permission bit, and the same bit stops the write that follows a step later, so the only route
 * that reaches this sentence is the function itself.
 */
export async function modeOf(path: string): Promise<number> {
  let mode: number;
  try {
    mode = (await stat(path)).mode;
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    throw new UsageError(`cannot read the permissions of access log part '${path}': ${reason}`);
  }
  return mode & 0o777;
}

/**
 * An emptied part is deleted, and a deletion that fails has to say so: the scrub's whole claim is that
 * the removed lines are gone, and a refusal that exits 1 with a stack reads as a crash rather than as
 * the erasure that did not happen.
 */
async function removePart(path: string): Promise<void> {
  try {
    await unlink(path);
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    throw new UsageError(`cannot remove emptied access log part '${path}': ${reason}`);
  }
}

export async function runAccessLog(sub: string[], flags: AccessLogFlags, now: () => number): Promise<number> {
  const name = sub[0];
  if (name !== 'scrub') {
    throw new UsageError('expected an accesslog command: scrub');
  }
  const dir = flags['access-log'];
  if (dir === undefined) throw new UsageError('accesslog scrub needs --access-log <dir>');
  const credential = flags.credential;
  if (credential === undefined) throw new UsageError('accesslog scrub needs --credential <id>');
  // Checked before any file is rewritten: this value comes back in the summary line and in the
  // marker, and an erasure whose own report can carry a forged line is a receipt that proves nothing.
  checkId(credential, '--credential');
  const result = await accesslogScrub(dir, credential, now);
  if (flags.json === true) {
    writeJson(result);
    return 0;
  }
  const noun = result.files === 1 ? 'file' : 'files';
  const count = result.removed === 1 ? 'record' : 'records';
  process.stdout.write(`removed ${String(result.removed)} ${count} for ${credential} in ${String(result.files)} ${noun}\n`);
  if (result.marker !== null) {
    process.stdout.write(`marker: ${result.marker}\n`);
  }
  return 0;
}
