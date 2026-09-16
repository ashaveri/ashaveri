import { readdir, readFile, stat, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { writeAtomically } from '../atomic.js';
import { checkId } from '../records.js';
import { UsageError, writeJson } from '../usage.js';

const ACCESS_FILE = /^access-(\d{4}-\d{2}-\d{2})-(\d{3})\.jsonl$/u;

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
    // ones, so a scrub that dies halfway still writes the receipt for the parts it already rewrote
    // before it reports the failure. The refusal keeps its own first sentence: a marker that cannot
    // be written is not the story, and it must not push the real one off the line. Both tests here
    // come before the write, not after it: an error this function will not name on the line must not
    // leave the marker it did make sitting in the directory either.
    if (removed === 0 || !(error instanceof UsageError)) throw error;
    const receipt = await writeReceipt(dir, now(), credential, removed, touched).catch(() => null);
    if (receipt === null) throw error;
    throw new UsageError(`${error.message}; the removals that landed are marked in '${receipt}'`);
  }
  if (removed === 0) return { removed: 0, files: 0, marker: null };
  let marker: string;
  try {
    marker = await writeReceipt(dir, now(), credential, removed, touched);
  } catch (error) {
    // The erasure has already happened and cannot be taken back, so this refusal cannot be the
    // writer's bare sentence about a file: a run that removed records and left no receipt is exactly
    // the silence the marker exists to prevent, and the numbers have to reach the operator some other
    // way.
    const reason = error instanceof Error ? error.message : String(error);
    throw new UsageError(
      `${reason}; ${String(removed)} ${removed === 1 ? 'record' : 'records'} removed from ${String(touched)} ${touched === 1 ? 'file' : 'files'} with no marker written`,
    );
  }
  return { removed, files: touched, marker };
}

/**
 * The receipt itself, at the mode this program chooses: the marker is a file the scrub makes, not a
 * part whose bits it inherited from a running gateway, so `0600` is right for it and wrong for those.
 */
async function writeReceipt(dir: string, atMillis: number, credential: string, removed: number, files: number): Promise<string> {
  const name = await nextScrubName(dir, atMillis);
  const receipt: ScrubMarker = { t: atMillis, credential, removed, files };
  await writeAtomically(join(dir, name), `${JSON.stringify(receipt)}\n`, 0o600, 'cannot write the scrub marker');
  return name;
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
 */
export function chooseScrubName(names: readonly string[], day: string): string {
  for (let seq = 0; seq < 1000; seq += 1) {
    const candidate = `scrub-${day}-${String(seq).padStart(3, '0')}.jsonl`;
    if (!names.includes(candidate)) return candidate;
  }
  throw new UsageError(`--access-log already holds a thousand markers for ${day}; the slot is three digits because that is all the retention sweep matches`);
}

async function nextScrubName(dir: string, atMillis: number): Promise<string> {
  const day = new Date(atMillis).toISOString().slice(0, 10);
  return chooseScrubName(await readdirOrThrow(dir), day);
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
 * in `node:fs` makes a rename conditional on the destination being there already.
 */
async function modeOf(path: string): Promise<number> {
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
