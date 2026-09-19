import { lstat, readdir, readFile, stat, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { sha256Hex } from '@ashaveri/receipt';
import { publishNew, writeGuarded } from '../atomic.js';
import { checkId } from '../records.js';
import { escapeInvisibleJson, UsageError, writeJson } from '../usage.js';

/**
 * The parts this program will open, which is the gateway's own log-file name copied rather than
 * imported: the published CLI cannot depend on the private package at run time. Exported so
 * `test/accesslog.test.ts` can hold the two ideas of a collectable name to the same set of names.
 */
export const ACCESS_FILE = /^access-(\d{4}-\d{2}-\d{2})-(\d{3})\.jsonl$/u;

/** A day's whole allotment of marker names, and the mode one is published at. */
const MARKER_SLOTS = 1_000;
const MARKER_MODE = 0o600;

/**
 * How many times one part is read, filtered and offered to the writer before this run refuses it.
 * A retry is what closes the window between reading a part and publishing over it, and the window that
 * survives is the one between the last look at the destination and the rename that follows it, which
 * nothing in `node:fs` can be made conditional. Three turns is enough to be past an append that
 * happens to land mid-run and short enough that a part written on every pass is a refusal the operator
 * reads rather than a loop that never ends.
 */
const PART_ATTEMPTS = 3;

/** The longest request reference a marker carries. See `ScrubMarker` for what the field is for. */
const REQUEST_MAX = 200;

/**
 * One part this run worked on, on both sides of the rewrite. A count says how many records left the
 * volume and nothing about the volume, so a third party holding the marker can check the arithmetic of
 * the erasure against `sha256sum` of the file in front of them: these are the byte lengths and the
 * SHA-256 digests of the exact bytes this run read, and of the exact bytes at that name when this run
 * read it back after publishing. The before pair always comes off the disk. The after pair does too
 * except where the name is gone, and a gone name is given the empty file's facts because that is the
 * whole of what can be said about it: this run deleted the part itself, or a sweep or a second scrub
 * deleted it a moment after this run rewrote it. Those three share one pair, `0` and the digest of no
 * bytes, and nothing in this record separates them. The second pair agrees with the file only while
 * nobody has appended to that part since, which is why the command asks for a deployment that is not
 * serving.
 */
export interface ScrubPartRecord {
  name: string;
  beforeBytes: number;
  beforeSha256: string;
  afterBytes: number;
  afterSha256: string;
}

/**
 * The line the scrub files as its receipt. Two of its numbers are not one measure: `removed` is the
 * records this run can attribute to itself, floored at zero per part and then summed, and `files` is the
 * parts it rewrote or deleted. A peer or a gateway can hand back every record this run took out, and the
 * marker then carries a `parts` entry naming the part and no count of its own, because the count lives
 * only in the total: a clean part beside one whose records came back reads as a run that removed
 * something, and nothing but the digests says which part gave nothing back.
 */
export interface ScrubMarker {
  t: number;
  credential: string;
  removed: number;
  files: number;
  parts: ScrubPartRecord[];
  /**
   * The operator's own reference for the instruction this erasure discharges, or `null`. A marker says
   * what was removed and where the bytes went; it cannot say why anyone was allowed to move them, and
   * that is the question a marker is later asked. The field exists so a removal can be traced back to
   * the instruction behind it, which is a fact about the paper trail and not about the volume, so the
   * operator supplies it and nothing here invents it. It is `null` rather than absent when no reference
   * was given so that two markers read the same way.
   */
  request: string | null;
}

/**
 * What one scrub run reports. `marker` is `null` exactly when no part was rewritten or deleted, which is
 * not the same as when nothing was removed: a part holding only the subject's records is deleted outright
 * and is receipted. A zero count beside a marker name is therefore a run that worked on a part and had
 * its records come back; see {@link ScrubMarker} for why the two numbers are not one measure.
 */
export interface ScrubResult {
  removed: number;
  files: number;
  marker: string | null;
}

export interface AccessLogFlags {
  'access-log'?: string;
  credential?: string;
  request?: string;
  json?: boolean;
}

export interface ScrubOptions {
  /** The request reference, validated by `runAccessLog`. Absent here means a marker with `null`. */
  request?: string | null;
  /**
   * The directory listing the marker's slot search works from. This is a seam and not a setting: the
   * only way to make a listing stale on purpose inside one process is to hand one over, and a listing
   * that predates the markers on the volume is the state the claim below exists for. See the case named
   * in `test/accesslog.test.ts` that passes it an empty listing over a directory holding two markers.
   */
  markerListing?: (dir: string) => Promise<string[]>;
}

/**
 * Erasure with a receipt of itself. An erasure request that leaves a silence cannot be told apart
 * from a gap in the retention, so the scrub records that it happened, names the credential it emptied,
 * carries the count, and carries the bytes on both sides of every rewrite so the count can be checked.
 *
 * A line this program cannot read stays in the file exactly as it was found, byte for byte: the
 * erasure was asked for one credential's records, and a scrub that quietly discarded what it did not
 * understand is not a scrub. The bytes that can move are the ones the writer always appends, so the
 * promise is per-line preservation plus a possible trailing newline in a file that had none.
 */
export async function accesslogScrub(
  dir: string,
  credential: string,
  now: () => number,
  options: ScrubOptions = {},
): Promise<ScrubResult> {
  // Settled first, before a single part is opened: a day the retention sweep cannot match would
  // otherwise be discovered after the erasure it is meant to record, which leaves the operator the
  // choice between a receipt nothing will collect and no receipt at all.
  const at = now();
  const day = markerDay(at);
  const names = await readdirOrThrow(dir);
  const targets = names.filter((each) => ACCESS_FILE.test(each)).sort();
  if (targets.length === 0) {
    throw new UsageError(
      '--access-log holds no file named access-YYYY-MM-DD-NNN.jsonl; point it at the directory the gateway writes its access log into',
    );
  }
  const request = options.request ?? null;
  const markerListing = options.markerListing ?? readdirOrThrow;
  const parts: ScrubPartRecord[] = [];
  let removed = 0;
  try {
    for (const name of targets) {
      const outcome = await scrubPart(dir, name, credential);
      if (outcome === null) continue;
      // Counted and recorded only once the part carrying them is gone or rewritten: a scan that matched
      // records and then failed to write has removed nothing, and a marker claiming otherwise is worse
      // than no marker.
      parts.push(outcome.record);
      removed += outcome.removed;
    }
  } catch (error) {
    // Records are gone at this point, and the marker is the only evidence an operator has of which
    // ones, so a scrub that dies halfway writes the receipt for the parts it already rewrote before it
    // reports the failure. The refusal keeps its own first sentence: a marker that cannot be written is
    // not the story, and it must not push the real one off the line. Nothing is attempted when this run
    // has landed nothing at any name, because then there is no change to evidence and the failure
    // stands alone.
    if (parts.length === 0) throw error;
    const receipt = await writeReceipt(
      dir, at, day, credential, removed, parts, request, markerListing,
    ).catch(() => null);
    if (receipt === null) throw counts(reasonOf(error), removed, parts.length);
    throw new UsageError(`${reasonOf(error)}; the removals that landed are marked in '${receipt}'`);
  }
  if (parts.length === 0) return { removed: 0, files: 0, marker: null };
  // The erasure has already happened and cannot be taken back, so this refusal cannot be the writer's
  // bare sentence about a file: a run that removed records and left no receipt is exactly the silence
  // the marker exists to prevent, and the numbers have to reach the operator some other way.
  const marker = await writeReceipt(dir, at, day, credential, removed, parts, request, markerListing).catch(
    (error: unknown) => {
      throw counts(reasonOf(error), removed, parts.length);
    },
  );
  return { removed, files: parts.length, marker };
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

/** A part's bytes as this run read them, with everything derived from those bytes and nothing else. */
interface PartSnapshot {
  bytes: Buffer;
  length: number;
  sha256: string;
  lines: string[];
  present: number;
}

/** What a name holds when it holds nothing, which is also the facts of a part this run deleted. */
const NOTHING: PartSnapshot = snapshotOf(Buffer.alloc(0));

function snapshotOf(bytes: Buffer): PartSnapshot {
  const lines = bytes.toString('utf8').split('\n');
  let present = 0;
  for (const line of lines) {
    if (line.length > 0) present += 1;
  }
  return { bytes, length: Buffer.byteLength(bytes), sha256: sha256Hex(bytes), lines, present };
}

/** Two reads of one name, decided on the exact bytes rather than on a timestamp a clock can move. */
function sameBytes(one: PartSnapshot, other: PartSnapshot): boolean {
  return one.length === other.length && one.sha256 === other.sha256;
}

/**
 * The lines that survive, kept as the strings that were read rather than as parsed-and-rendered
 * records. A line this program cannot read is a line it has no business re-spelling: the erasure asked
 * for one credential's records, and a scrub that quietly discarded what it did not understand is not a
 * scrub. `present` and this length agreeing is therefore the whole test of whether a part holds
 * anything to remove.
 */
function linesExceptTarget(lines: readonly string[], credential: string): string[] {
  return lines.filter((line) => line.length > 0 && !isSubjectLine(line, credential));
}

/** Whether one raw line is a record of the credential being erased, read for the one field that says. */
function isSubjectLine(line: string, credential: string): boolean {
  if (line.length === 0) return false;
  try {
    return (JSON.parse(line) as { cred?: unknown }).cred === credential;
  } catch {
    return false;
  }
}

/**
 * How many of a read's lines belong to the subject. The per-part count is the difference of two of
 * these rather than a difference of line totals, because a total counts whatever a gateway appended
 * after this run published, and an unrelated record is not this run putting one back.
 */
function heldBy(snapshot: PartSnapshot, credential: string): number {
  return snapshot.lines.filter((line) => isSubjectLine(line, credential)).length;
}

/**
 * What one part gave up: the subject's records in the bytes this run read, less the subject's records
 * at that name when this run last looked. Floored at zero because a peer that renames an older copy
 * back can leave more of the subject's lines at the name than this run read, and a count this run
 * publishes must not go negative on someone else's stale write. The floor does hide that case from the
 * number: what carries it is the after-pair, a digest of bytes that still hold those records, so a
 * reader who can reproduce them sees the subject's lines at the name beside a count that omits them,
 * and a re-run of this command takes them out again.
 */
function heldDelta(before: PartSnapshot, after: PartSnapshot, credential: string): number {
  return Math.max(0, heldBy(before, credential) - heldBy(after, credential));
}

/**
 * One part, read once and published only while the bytes on disk are the bytes that were read.
 * Returns `null` when the part holds nothing for this credential, which is the case that has to keep
 * touching nothing at all: the rewrite is owed to parts that held a record, and rewriting a part for
 * no reason is how a scrub reopens the window it is here to narrow.
 *
 * Each attempt filters the snapshot it holds, so `kept` never comes from a second read, and each
 * attempt ends by reading the destination back off the disk. The count and both pairs of bytes and
 * digests come from those reads, not from the string this run wrote, with one exception the reads force:
 * a destination that has been deleted since this run looked gives the empty file's facts, because no
 * read of it is possible and a name that is gone holds nothing.
 */
async function scrubPart(
  dir: string,
  name: string,
  credential: string,
): Promise<{ record: ScrubPartRecord; removed: number } | null> {
  const path = join(dir, name);
  let snapshot = await readPart(path);
  for (let attempt = 1; attempt <= PART_ATTEMPTS; attempt += 1) {
    const kept = linesExceptTarget(snapshot.lines, credential);
    if (kept.length === snapshot.present) return null;
    // Asked of a part this run has something to remove from, and before it publishes anything at the
    // name, because both of the remaining outcomes receipt the bytes: a rewrite that leaves a second
    // name holding them and an unlink that removes one name of several are the same false claim. Not
    // higher up, because a shared name the subject has never written to is no reason to refuse the
    // erasure, and a backup that hard-links a whole log would make this command useless about every
    // credential in it. That is the same discipline that leaves a read-only part alone when it holds
    // nothing of the subject's.
    await refuseSharedName(path);
    if (kept.length === 0) {
      // A fully scrubbed part is unlinked, not renamed. A copy under a name the gateway's retention
      // can no longer match would keep every removed line on the volume forever, and it would read
      // as a completed erasure that left the data behind. The comparison runs here for the same
      // reason it runs before a rename: an unlink takes whatever a gateway appended since this run
      // read the part, and that append is not one this run was asked to erase.
      const seen = await readPart(path);
      if (!sameBytes(seen, snapshot)) {
        snapshot = seen;
        continue;
      }
      await removePart(path);
      // The after read of a name that is gone holds no lines at all, so this is the subject's whole
      // count from the snapshot. It is written as the same difference the rewrite uses because a name
      // that came back, holding the subject's records again, is a part this run did not clear.
      const after = await readAfterRemoval(path);
      return { record: partRecord(name, snapshot, after), removed: heldDelta(snapshot, after, credential) };
    }
    // Read again on every attempt rather than once per part, because the copy is renamed over the part
    // and `rename` replaces the destination's inode whole: the mode this run publishes is the mode the
    // gateway wakes up to on its next append.
    const mode = await modeOf(path);
    refuseUnwritable(path, mode);
    const text = `${kept.join('\n')}\n`;
    const published = snapshotOf(Buffer.from(text, 'utf8'));
    const held = await writeGuarded(path, text, mode, 'cannot rewrite access log part', () => holdsStill(path, snapshot));
    if (!held) {
      // Somebody wrote between this run's read and its rename, so the copy in hand is a snapshot of a
      // file that no longer exists. It is dropped, not patched, and the newer bytes are filtered from
      // the start: a scrub that merged the two would be writing its own opinion of a log line.
      snapshot = await readPart(path);
      continue;
    }
    const after = await confirmPublished(path, published, heldBy(snapshot, credential));
    return { record: partRecord(name, snapshot, after), removed: heldDelta(snapshot, after, credential) };
  }
  throw new UsageError(
    `cannot rewrite access log part '${path}': it would not hold still across ${String(PART_ATTEMPTS)} attempts, and this run published nothing to it`,
  );
}

function partRecord(name: string, before: PartSnapshot, after: PartSnapshot): ScrubPartRecord {
  return {
    name,
    beforeBytes: before.length,
    beforeSha256: before.sha256,
    afterBytes: after.length,
    afterSha256: after.sha256,
  };
}

/**
 * The question the writer asks in the instant before the rename. A false answer costs this run's
 * temporary and nothing else: the name keeps the bytes it had, and this run goes and reads them.
 *
 * This is as close to the rename as `node:fs` reaches, and it is not the rename itself. An append that
 * lands in the moment between this read and that call is the residue the usage text states, and it is
 * why the receipt reports digests rather than a promise: the two reads it names are the bytes this run
 * took from the part and the bytes it found at the name afterwards, and the records that arrived in
 * between belong to neither, so they appear in no count and under no digest.
 */
async function holdsStill(path: string, snapshot: PartSnapshot): Promise<boolean> {
  return sameBytes(await readSnapshot(path), snapshot);
}

/**
 * The destination read back after the rename, for the facts the receipt carries and for one test: that
 * the bytes this run published are the bytes now at the name. A mismatch has two shapes and they are not
 * the same event. A gateway that appends while this runs leaves a destination that begins with exactly
 * this run's copy and then holds someone's newer record, which is a publish that landed and is the
 * ordinary state of a serving log; measuring it as a refusal made a run that had erased everything it
 * was asked to erase exit 2 over a line the deployment wrote afterwards. A destination that does not
 * begin with those bytes is a peer that renamed its own copy over this one, and a receipt about a file
 * nobody holds is not something a retry can undo, so that one is the refusal.
 *
 * A read that fails outright has the same two shapes. A name that is gone is this run's own erasure
 * completed by somebody else's deletion, and there are three ways to that: the retention sweep ageing
 * the part out, a second scrub of another credential emptying and unlinking the same part, and a parent
 * directory that has been moved, which answers `ENOENT` for the file on either system. All three leave
 * the same after-facts as an `unlink` did, the empty file's, and refusing would throw away a run that had
 * already taken the record out and file no receipt for it. Every other code, and this arm is a bucket and
 * not an example, since `EACCES`, `EISDIR`, `EPERM` and `EBUSY` each reach it on a host that is holding
 * the name open, is a name this run rewrote and cannot now read. Nothing can then say what stands at it,
 * so the sentence claims only the two facts this run holds: its own rename reported success at that name,
 * and the count it published away is named there because no marker will ever carry it.
 */
async function confirmPublished(path: string, published: PartSnapshot, erased: number): Promise<PartSnapshot> {
  let after: PartSnapshot;
  try {
    after = await readSnapshot(path);
  } catch (error) {
    if (isNotFound(error)) return NOTHING;
    const record = erased === 1 ? 'record' : 'records';
    throw new UsageError(
      `cannot confirm access log part '${path}': ${reasonOf(error)}. This run's rename at that name reported success and left none of the ${String(erased)} ${record} it had read there, and no marker has been filed for it`,
    );
  }
  if (!sameBytes(after, published) && !after.bytes.subarray(0, published.length).equals(published.bytes)) {
    throw new UsageError(
      `cannot confirm access log part '${path}': the bytes there are ${String(after.length)} of them and do not begin with the ${String(published.length)} this run published`,
    );
  }
  return after;
}

/**
 * A part the running gateway cannot write to is not this command's to republish. `rename` replaces the
 * destination's inode whole, so the mode this run publishes is the mode the part carries afterwards: a
 * part found at a mode with no owner write bit and renamed back at that same mode leaves a gateway
 * unable to append to its own log, which was measured as `EACCES` on the append after a printed
 * success. Adding the bit back would reach a writable log by another route, and it is not this
 * command's to choose: a part pinned against its owner's write is somebody's decision about a live
 * log, so the run refuses, and the name has to be in the sentence because the operator has to go and
 * read what those bits mean.
 */
function refuseUnwritable(path: string, mode: number): void {
  if ((mode & 0o200) !== 0) return;
  throw new UsageError(
    `cannot rewrite access log part '${path}': its mode ${modeText(mode)} gives its owner no write bit, and this command will not take a live log's permission to write away`,
  );
}

function modeText(mode: number): string {
  return (mode & 0o777).toString(8).padStart(3, '0');
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
  parts: readonly ScrubPartRecord[],
  request: string | null,
  listing: (dir: string) => Promise<string[]>,
): Promise<string> {
  const receipt: ScrubMarker = { t: atMillis, credential, removed, files: parts.length, parts: [...parts], request };
  // `escapeInvisibleJson` says why the platform's own stringifier is not enough here. What is local to
  // this call is that `--request` is operator text which nothing sanitises, only trims and measures, so
  // one line separator inside it would make this receipt a two-line document to anything that splits
  // lines that way, and a directional override would show a reader a sentence other than the bytes.
  const text = `${escapeInvisibleJson(JSON.stringify(receipt))}\n`;
  const names = await listing(dir);
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
async function readPart(path: string): Promise<PartSnapshot> {
  try {
    return await readSnapshot(path);
  } catch (err) {
    // A link to nothing is read as a missing file, and an operator told that a name standing in the
    // listing is not there goes looking for a deletion rather than for the link. Only the refusal path
    // pays for this question.
    if (isNotFound(err) && (await isLinkAt(path))) {
      throw linkRefusal(path, '; this run cannot read the part, because the link leads to a file that is not there');
    }
    throw new UsageError(`cannot read access log part '${path}': ${reasonOf(err)}`);
  }
}

/** Whether the name itself is a link, as far as one `lstat` can tell. */
async function isLinkAt(path: string): Promise<boolean> {
  try {
    return (await lstat(path)).isSymbolicLink();
  } catch {
    return false;
  }
}

/**
 * Raised from two routes, so the head is shared and the tail is not, because what a link hides depends on
 * which question was being asked. At the guard this run already holds the part's bytes, which it read
 * through the link, so it can say where those records stand. At the read the target is by definition not
 * there, which is why the open answered `ENOENT`, and a sentence about records standing at a file would
 * describe bytes this run never saw.
 */
function linkRefusal(path: string, tail: string): UsageError {
  return new UsageError(
    `cannot scrub access log part '${path}': the name is a symlink, and neither a rewrite nor a deletion of it touches the file it points at${tail}`,
  );
}

/** The same read with the operating system's own refusal left whole, for a caller that wraps it. */
async function readSnapshot(path: string): Promise<PartSnapshot> {
  return snapshotOf(await readFile(path));
}

/**
 * What a name holds after an unlink. The name being gone is the expected answer and is this run's own
 * doing, so the part's after-facts are the empty file's; a name that came back holds a writer's newer
 * bytes, and the honest receipt reports those rather than the nothing this run removed.
 */
async function readAfterRemoval(path: string): Promise<PartSnapshot> {
  try {
    return await readSnapshot(path);
  } catch (err) {
    if (isNotFound(err)) return NOTHING;
    throw new UsageError(`cannot confirm removed access log part '${path}': ${reasonOf(err)}`);
  }
}

function reasonOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function isNotFound(error: unknown): boolean {
  return error instanceof Error && 'code' in error && error.code === 'ENOENT';
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
 * nobody chose. A name that is a directory is refused beside it, and for the same reason: a
 * directory's bits describe a directory, and measured on both systems `stat` answers that name without
 * objection, `666` on Windows and `755` on Linux, so a function that only masked bits would hand a
 * directory's own bits to whatever reaches the rename. Checking `isDirectory` on the stat this function
 * already performs is what keeps a name that is not a part from being published over at all. The gap
 * between this read and the rename is stated rather than closed, because nothing in `node:fs` makes a
 * rename conditional on the destination being there already.
 *
 * Both of this function's refusals are gated at its own height, which is why it is exported. They miss
 * the command's height for different reasons: a name that is a directory is refused one step earlier,
 * where the read answers `EISDIR` on either system, and making `stat` itself refuse takes a permission
 * bit, which stops the write that follows a step later too.
 */
export async function modeOf(path: string): Promise<number> {
  let mode: number;
  let isDir: boolean;
  try {
    const info = await stat(path);
    mode = info.mode;
    isDir = info.isDirectory();
  } catch (err) {
    throw new UsageError(`cannot read the permissions of access log part '${path}': ${reasonOf(err)}`);
  }
  if (isDir) {
    throw new UsageError(
      `cannot read the permissions of access log part '${path}': it is a directory, and a directory's mode bits are not a log part's`,
    );
  }
  return mode & 0o777;
}

/**
 * A part that another name also holds is a part this command cannot honestly receipt, so it is refused
 * before this run publishes anything at that name.
 *
 * The marker's `removed` says records left the volume, and a rewrite or an `unlink` takes them out of one
 * name. `rename` replaces the destination name, not the bytes behind it, so a hard link leaves the second
 * name holding the original lines and a symlink leaves the file it points at doing the same; the run then
 * exits 0 with a receipt naming a count of records that are still on the disk. Measured: a part linked to
 * a second name came back `removed 1` with the second name still holding the subject's line, byte for
 * byte. This is not a hostile shape either. A snapshot-style backup is exactly the tool that hard-links an
 * append-only log it does not want to copy, and the operator of that deployment is the person who would
 * otherwise read a receipt for an erasure that did not happen.
 *
 * Asked once per attempt rather than once per part, because the question is only worth asking of a part
 * this run is about to change, which is not known until the part has been read and filtered, and because a
 * link planted while this run was working is the one it can still catch on the next pass. What it does not
 * do is close the window: a link planted between this answer and the rename is invisible to it, and no
 * `node:fs` call makes a rename conditional on anything. Refusing what can be seen is the whole claim,
 * which is why the sentence names the count of links rather than only saying no.
 */
async function refuseSharedName(path: string): Promise<void> {
  let here: Awaited<ReturnType<typeof lstat>>;
  try {
    here = await lstat(path);
  } catch (error) {
    // The read that comes before this question already holds the part's lines, so a name missing here is
    // one the sweep took while this run was deciding what else to ask. Its refusal belongs to whichever
    // step asks the next question, which is the second read on the deletion route and the mode read on
    // the rewrite route, and not to a function that was asked about links. This one's answer is silence.
    if (isNotFound(error)) return;
    throw new UsageError(`cannot inspect access log part '${path}': ${reasonOf(error)}`);
  }
  // Asked of the `lstat` result and not the `stat` one, because a link whose target is gone answers the
  // second call with `ENOENT`. A run that looked through the link to decide would then call that name
  // missing, and an operator reading "no such file or directory" about a file standing in the listing
  // would be sent to look for a deletion rather than for the link.
  if (here.isSymbolicLink()) {
    throw linkRefusal(path, '; that file is where every record this run was asked to remove would still stand');
  }
  // The link count is a fact about a regular file. A directory's `nlink` is `2` plus its subdirectories,
  // which counts entries inside it and not names holding it, so asking the question of one answers with a
  // number that means something else entirely. Measured on Linux: a part name holding a directory came
  // back `nlink` 2 and was refused as "2 names hold those bytes", while this host answers 1 for the same
  // directory and the case that plants one fell through to the read. Anything that is not a regular file
  // this run cannot rewrite anyway, and the step that next asks about the name refuses it in its own words.
  if (!here.isFile()) return;
  // Once the name is known to be a regular file there is nothing left to look through, so `lstat` and
  // `stat` report the same inode and the same count of names holding it. Asking the second call anyway
  // would add a window in which the answer can change and a refusal that is not this run's to make.
  if (here.nlink > 1) {
    throw new UsageError(
      `cannot scrub access log part '${path}': ${String(here.nlink)} names hold those bytes, and this run can take the records out of one of them`,
    );
  }
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
    throw new UsageError(`cannot remove emptied access log part '${path}': ${reasonOf(error)}`);
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
  const result = await accesslogScrub(dir, credential, now, { request: requestOf(flags.request) });
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

/**
 * The operator's reference for the instruction the erasure answers, in the shape the marker keeps.
 * Trimmed, because the value is typed at a prompt and the whitespace around a reference is not part of
 * it, and a reference that trims to nothing names nothing so it is stored as `null` like an absent one.
 * Bounded at {@link REQUEST_MAX} because the marker is one line that a person reads: a field longer
 * than that is a document, and a document belongs in the operator's own system next to the reference
 * that points at it. Nothing else about it is checked, because nothing here can tell a real reference
 * from an invented one; that is why the field says who was asked and not what was proven.
 */
function requestOf(raw: string | undefined): string | null {
  if (raw === undefined) return null;
  const trimmed = raw.trim();
  if (trimmed.length === 0) return null;
  if (trimmed.length > REQUEST_MAX) {
    throw new UsageError(
      `--request is ${String(trimmed.length)} characters, over the ${String(REQUEST_MAX)} a marker carries`,
    );
  }
  return trimmed;
}
