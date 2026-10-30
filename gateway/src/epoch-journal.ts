import { open, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { SigningKey } from '@ashaveri/receipt';
import { toBase64Url } from './b64.js';
import { sha256, toHex } from './digest.js';
import {
  declarationOf,
  HOST_CLOCK_SOURCE,
  renameWhenVolumeAllows,
  type StampDeclaration,
  type TimeSource,
} from './store.js';

/**
 * The record a gateway keeps of the epochs it has signed under, and of the keys they were signed with.
 *
 * The manifest format has carried a rotation history since section 4.4 of `docs/receipt-spec.md` named the
 * two optional members of a `keys[]` entry, and nothing in the estate wrote them: the served document held
 * the one key the process stood on, so a rotation published by the shipped binary dropped the predecessor
 * and its window, and a receipt from before the rotation stopped verifying. The history is not something an
 * operator types, either. A process knows three things no one else can assert about them, the key it signs
 * with, the epoch it was started under, and the instant it began serving, and this file is where those three
 * become a document. On the first boot under an epoch the journal does not already name, one entry is
 * appended for it; every boot publishes `keys[]` from the entries, so rotating means a new key, a higher
 * `--epk`, and a restart, and nobody writes a kid, a public key or a Unix second.
 *
 * Five rules shape everything below, and each is a refusal of a cheaper design.
 *
 * **An entry is written by the epoch it describes.** Every field comes from this process: `kid` and
 * `publicKey` from the key it holds, `epk` from the epoch it was started under, `validFrom` from the instant
 * it first served, and `stamped` from the same source that read that instant. An entry about somebody else's
 * epoch would be the same hearsay the manifest exists to replace.
 *
 * **The file is append-only as content, and says so.** Each entry names the digest of the entries before it, so
 * an entry rewritten or dropped breaks the digest its successor states and the next boot stops rather than
 * publishing it. What the chain reaches is stated with its limit: it is computed over the entries and signed by
 * nobody, so a hand that can write this file can recompute every digest in it, and what the check answers is a
 * partial edit, an accident, and a truncation, not a deliberate whole rewrite. That is why a history of more
 * than one entry is published only through the sealed manifest, which is signed, and why the digest is not
 * offered as evidence of anything a reader could not have written itself. A document whose prefix does not chain
 * is refused on read, by name, before any of it is published, and a write appends and replaces the file by
 * rename, waiting out a held reader the way a store compaction does.
 *
 * **Restarting an epoch records nothing.** Idempotence is per `(epk, kid)`: the second boot under the pair
 * this journal already names leaves the file exactly as it stands, byte for byte, because a restart is not a
 * rotation and a history that grows on restarts says it rotated when it did not.
 *
 * **The shape of a history is not this file's rule.** One epoch declared with two starts, starts that do not
 * ascend with their epochs, and a half-filled member pair are refused by `parseManifest` in
 * `packages/sdk/src/manifest.ts`, which is where those rules live and where a client reads them from. Nothing
 * here re-states them: a rule written in two packages is the defect `gateway/src/index.ts` names, and it
 * drifts quietly. What this file does hold is the arithmetic of its own stamp, because a second process
 * cannot be allowed to move an instant that is already published.
 *
 * **The stamp is second-granular and never goes backwards.** `validFrom` is whole Unix seconds, like every
 * instant in the estate, and an instant already recorded is a floor: a clock that has stepped back can delay
 * the opening of a new window, it cannot buy one that overlaps the last epoch's. That is the same high-water
 * discipline `gateway/src/time-source-state.ts` applies to the answers a wired source gives.
 *
 * What a journal is not is stated twice because both absences are load-bearing. It is not receipts: it holds
 * no personal data, only which key served when, so it is outside the `--receipts-days` window and outside the
 * access log's erasure, and it has to outlive the receipts whose epochs it explains. And it is not a claim
 * about a clock: the source's name and bound travel with the instant, so a deployment wired through
 * `--time-source-state` records the source it read and how far that source can be wrong, and one wired
 * nothing records `host clock` at `null`, which is this host's own claim and not UTC traceability.
 */

/** The file an epoch journal is kept in, beside the receipt log it explains. */
export const EPOCH_JOURNAL_FILE = 'epoch-journal.json';

/** The one version of a journal document this writer writes and this reader reads. */
export const EPOCH_JOURNAL_VERSION = 1;

/**
 * One epoch this gateway has served under, as this gateway recorded it.
 *
 * `kid` and `publicKey` are the served forms, hex and base64url, because they go into `keys[]` unchanged: a
 * history that had to be re-encoded on the way out is a history where a digest can be mismatched by the
 * writer. `validFrom` is the first instant this process served under the pair, and `stamped` says which
 * source read it.
 */
export interface EpochJournalEntry {
  readonly epk: number;
  readonly kid: string;
  readonly publicKey: string;
  readonly validFrom: number;
  readonly stamped: StampDeclaration;
  /** The digest of the entries before this one, which is what makes a rewrite of them visible. */
  readonly prev: string;
}

/** An epoch journal, read and, if this epoch was new, written. */
export interface EpochJournal {
  /** The file this journal was opened at, named so a refusal and a start-up line can point at one path. */
  readonly path: string;
  /** The whole history, in the order it was recorded, this process's own entry last. */
  readonly entries: readonly EpochJournalEntry[];
  /** The entry this opening wrote, or null when it named this pair already and nothing was written. */
  readonly appended: EpochJournalEntry | null;
}

export interface EpochJournalOptions {
  /**
   * The volume the journal is kept in, which is the directory the receipts store was opened with. The journal
   * belongs to the deployment rather than to one process, so it is filed where the deployment's own durable
   * state is, and it is refused with the store when that directory is not there. One file per volume, named
   * here rather than handed over: a history an operator can point at two paths is two histories, and the
   * second one explains nothing about the first.
   */
  readonly dir: string;
  /**
   * The file inside it. Absent means `EPOCH_JOURNAL_FILE`, which is the one name a deployment's own journal
   * is kept under and the one an operator reads on the start-up line; naming another is for a caller holding
   * two volumes in one directory, and nothing shipped reaches it.
   */
  readonly file?: string;
  /** The key this process signs receipts with. Its kid and public key are recorded as the entry's own. */
  readonly key: SigningKey;
  /** The epoch this process was started under, which is the epoch the entry describes and no other. */
  readonly epk: number;
  /**
   * Whether the deployment opening this journal holds a key that can seal the manifest publishing it.
   *
   * The answer is asked for before an entry is written rather than only when the document is served, because an
   * entry for an epoch that never served is a window the deployment would go on publishing: a rotation stopped
   * by the refusal below leaves the journal exactly as the epoch before it left it, and the operator's next
   * start is a fresh decision rather than a repair of a history that had grown one entry nobody stood on. It is
   * a required member because it is one fact with two owners, the seal key this process was handed and the
   * history it is asked to publish, and a run that recorded an epoch without stating the other half would
   * record on a rule no caller had answered.
   */
  readonly sealed: boolean;
  /**
   * The source this process reads its instants from. Absent means `HOST_CLOCK_SOURCE`, and the entry then
   * names `host clock` at `null`, which is this host's claim at a bound nobody measured.
   */
  readonly time?: TimeSource;
}

/**
 * Why a journal refused, named as its own class because a refusal about a volume and a refusal about a
 * configuration reach an operator differently, and one of them is fixed by editing a file.
 */
export class EpochJournalError extends Error {
  constructor(detail: string) {
    super(detail);
    this.name = 'EpochJournalError';
  }
}

/** The digest an entry names as the entries before it, over a fixed field order so a rewrite is comparable. */
function prefixDigest(entries: readonly EpochJournalEntry[]): string {
  const canonical = JSON.stringify(
    entries.map((entry) => ({
      epk: entry.epk,
      kid: entry.kid,
      publicKey: entry.publicKey,
      validFrom: entry.validFrom,
      stamped: { name: entry.stamped.name, uncertaintySeconds: entry.stamped.uncertaintySeconds },
    })),
  );
  return toHex(sha256(new TextEncoder().encode(canonical)));
}

function isWholeSeconds(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

/**
 * One entry of a document, read back.
 *
 * The types are checked and the shape is not argued about. This file may state what its own bytes have to
 * hold, an integer, a string, an object of two fields, because a value that is not those is not an entry this
 * writer wrote and nothing sensible can be published from it. It may not ask whether an epoch is declared
 * twice with two starts or whether the starts ascend: those are `parseManifest`'s rules, they are read by
 * every client that reaches a deployment through the served document, and a second copy here would be a rule
 * that has to be kept in step with the first by somebody who is not looking at the first.
 */
function readEntry(value: unknown, path: string, index: number): EpochJournalEntry {
  const refuse: (detail: string) => never = (detail) => {
    throw new EpochJournalError(`${path} is not an epoch journal: entry ${String(index)} ${detail}`);
  };
  if (typeof value !== 'object' || value === null) refuse('is not an object');
  const raw = value as Record<string, unknown>;
  const entryEpoch = raw['epk'];
  const kid = raw['kid'];
  const publicKey = raw['publicKey'];
  const start = raw['validFrom'];
  const prev = raw['prev'];
  const stamped = raw['stamped'];
  if (!isWholeSeconds(entryEpoch)) refuse('states an epk that is not a whole number of at least zero');
  if (typeof kid !== 'string' || kid.length === 0) refuse('states no kid');
  if (typeof publicKey !== 'string' || publicKey.length === 0) refuse('states no publicKey');
  if (!isWholeSeconds(start)) refuse('states a validFrom that is not a whole number of at least zero');
  if (typeof prev !== 'string' || prev.length === 0) refuse('states no digest of the entries before it');
  if (typeof stamped !== 'object' || stamped === null) refuse('states no stamped source');
  const declared = (stamped as Record<string, unknown>)['name'];
  const statedBound = (stamped as Record<string, unknown>)['uncertaintySeconds'];
  if (typeof declared !== 'string' || declared.length === 0) refuse('states a stamped source with no name');
  let bound: number | null;
  if (statedBound === null) bound = null;
  else if (isWholeSeconds(statedBound)) bound = statedBound;
  else refuse('states a stamped bound that is neither null nor a whole number of at least zero');
  return {
    epk: entryEpoch,
    kid,
    publicKey,
    validFrom: start,
    prev,
    stamped: { name: declared, uncertaintySeconds: bound },
  };
}

/**
 * The document's entries, or the refusal that says what is wrong with it.
 *
 * An absent file is an empty history and not a fault, which is the state a fresh volume is in. A file that
 * exists and will not parse is a different matter: an operator may have edited it, a run may have died
 * midway through a rename, and either way the next process is being asked to publish what it cannot read. So
 * it is refused by name and nothing is written over it.
 *
 * Each entry's digest is re-derived against the entries before it. An entry rewritten in place breaks the digest
 * its successor names, and an entry removed breaks the one that followed it, so an edit that left the rest of
 * the file alone stops the run rather than being served as the deployment's own account of its keys. A rewrite
 * that recomputed every digest would not be caught here, and is caught by nothing else in this file: the
 * published answer to whether a history may be believed is the manifest's signature, not this chain.
 */
async function readEntries(path: string): Promise<EpochJournalEntry[]> {
  let text: string;
  try {
    text = await readFile(path, 'utf8');
  } catch (error) {
    const code = (error as { readonly code?: unknown }).code;
    if (code === 'ENOENT') return [];
    throw new EpochJournalError(`${path} could not be read: ${error instanceof Error ? error.message : String(error)}`);
  }
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch (error) {
    throw new EpochJournalError(
      `${path} is not an epoch journal: it is not readable as JSON (${error instanceof Error ? error.message : String(error)})`,
    );
  }
  if (typeof value !== 'object' || value === null) {
    throw new EpochJournalError(`${path} is not an epoch journal: the document is not an object`);
  }
  const raw = value as Record<string, unknown>;
  if (raw['v'] !== EPOCH_JOURNAL_VERSION) {
    throw new EpochJournalError(
      `${path} states version ${String(raw['v'])}, and this gateway reads and writes version ${String(EPOCH_JOURNAL_VERSION)} journals`,
    );
  }
  const entriesRaw = raw['entries'];
  if (!Array.isArray(entriesRaw)) {
    throw new EpochJournalError(`${path} is not an epoch journal: entries is not an array`);
  }
  const entries = entriesRaw.map((each, index) => readEntry(each, path, index));
  for (const [index, entry] of entries.entries()) {
    const expected = prefixDigest(entries.slice(0, index));
    if (entry.prev !== expected) {
      throw new EpochJournalError(
        `${path} holds an entry ${String(index)} whose stated digest of the entries before it is ${entry.prev}, ` +
          `while those entries digest to ${expected}: an entry has been rewritten or removed, and a history ` +
          'that was edited after it was recorded is refused rather than published. Nothing was written',
      );
    }
  }
  return entries;
}

/**
 * The instant a new entry may open at, or the refusal that stands in its place.
 *
 * Whole seconds off the source this process was given, and an instant the journal already names is a floor:
 * a new entry is recorded at what its own source reads, and a reading that has reached or fallen behind the
 * last recorded instant stops the run instead of writing it. That is the high-water discipline
 * `gateway/src/time-source-state.ts` applies to the answers a wired source gives, seen from the side of the
 * file rather than the clock: no instant this journal has published is ever superseded by an earlier one, so
 * a clock that steps back delays the opening of a window and cannot buy one that overlaps the epoch above it.
 * Writing the floor itself is the one answer that is refused, because two epochs opening at one instant is a
 * history no reader can walk, and the cheaper sentence is the one that stops a deployment being served a
 * document every client rejects.
 */
function stampEntry(
  path: string,
  entries: readonly EpochJournalEntry[],
  source: TimeSource,
): { readonly validFrom: number } | { readonly refusal: string } {
  const read = Math.floor(source.nowSeconds());
  if (!Number.isSafeInteger(read) || read < 0) {
    return {
      refusal:
        `${path}: the source named ${source.name} read ${String(source.nowSeconds())}, which is not a whole number ` +
        'of Unix seconds of at least zero, and an instant in that shape cannot open a window',
    };
  }
  let highest = -1;
  for (const entry of entries) highest = Math.max(highest, entry.validFrom);
  if (highest >= 0 && read <= highest) {
    return {
      refusal:
        `${path} already names an epoch opening at ${String(highest)}, and the source named ${source.name} reads ` +
        `${String(read)}, which does not follow it: an epoch cannot open at or behind an instant this deployment ` +
        'has already recorded for another one, so the new key is not recorded and nothing was written. Wait for ' +
        'the recorded instant to fall behind this source, or start under an epoch this journal already names',
    };
  }
  return { validFrom: read };
}

/**
 * Open the journal beside a receipt volume, and record this epoch if the journal does not name it.
 *
 * One call does the read, the idempotence check, the append and the rename, because splitting them would let
 * a caller publish an entry it had not proved unrecorded. The pair `(epk, kid)` is the key of idempotence:
 * the same epoch under the same key is the same window opening, so the file is left untouched and the return
 * says so with `appended` null. A different epoch, or the same epoch under a different key, is a rotation,
 * and a rotation is exactly the thing the file exists to hold.
 *
 * The write is a temporary file moved over the journal, through the same rename discipline a store compaction
 * uses, so an interrupted append leaves the previous document whole and a reader that still holds the old
 * file open does not lose the move.
 */
export async function openEpochJournal(options: EpochJournalOptions): Promise<EpochJournal> {
  const path = join(options.dir, options.file ?? EPOCH_JOURNAL_FILE);
  const source = options.time ?? HOST_CLOCK_SOURCE;
  const key = { kid: toHex(options.key.kid), publicKey: toBase64Url(options.key.publicKey) };
  if (!Number.isSafeInteger(options.epk) || options.epk < 0) {
    throw new EpochJournalError(
      `${path}: this process was started under epoch ${String(options.epk)}, which is not a whole number of at ` +
        'least zero, and an epoch in that shape states nothing about a key',
    );
  }
  const entries = await readEntries(path);
  if (entries.some((entry) => entry.epk === options.epk && entry.kid === key.kid)) {
    return { path, entries, appended: null };
  }
  const stamped = stampEntry(path, entries, source);
  if ('refusal' in stamped) throw new EpochJournalError(stamped.refusal);
  const entry: EpochJournalEntry = {
    epk: options.epk,
    kid: key.kid,
    publicKey: key.publicKey,
    validFrom: stamped.validFrom,
    stamped: declarationOf(source),
    prev: prefixDigest(entries),
  };
  const written = [...entries, entry];
  const unsealed = unsealedHistoryRefusal({ path, entries: written, appended: entry }, options.sealed);
  if (unsealed !== null) throw new EpochJournalError(unsealed);
  const bytes = JSON.stringify({ v: EPOCH_JOURNAL_VERSION, entries: written });
  const temp = `${path}.appending`;
  try {
    const out = await open(temp, 'w');
    try {
      await out.writeFile(bytes);
      await out.sync();
    } finally {
      await out.close();
    }
    await renameWhenVolumeAllows(temp, path);
  } catch (error) {
    throw new EpochJournalError(
      `${path} could not be written: ${error instanceof Error ? error.message : String(error)}. The journal ` +
        'stands where it was, and the epoch this process holds is not recorded in it',
    );
  }
  return { path, entries: written, appended: entry };
}

/** What one run of this gateway records about its own epoch, which is nothing in two of its shapes. */
export interface EpochRunRecord {
  /** The volume the receipts live on, as the operator named it. Absent means the run keeps no receipts. */
  readonly receiptsDir: string | undefined;
  /** Whether this run is a `--mock` run, whose key is generated when the process starts. */
  readonly mock: boolean;
  /** The key this run signs receipts with, whose kid and public key an entry states. */
  readonly key: SigningKey;
  /** The key that would seal the manifest publishing this history, or nothing where the run holds none. */
  readonly manifestKey: SigningKey | undefined;
  /** The epoch this run was started under. */
  readonly epk: number;
  /** The source every instant of this run is read from, so the entry names the same clock a stamp does. */
  readonly time?: TimeSource;
}

/**
 * Record this run's epoch on the volume it keeps its receipts on, or answer that it records nothing.
 *
 * The two absences are the whole of what a run cannot say for itself. A process with no `--receipts-dir` keeps
 * its receipts in memory and nothing about its keys survives its exit, so there is no volume to hold a history
 * and no later process to read one. A `--mock` run signs with a key generated when the process started and
 * thrown away when it exits, so an entry for that key would state a rotation this deployment never performed
 * and a window nobody ever served under: history invented rather than recorded, and the run that met two of
 * them would then be refused for publishing it unsigned.
 *
 * Everything else about the opening is read from the run rather than stated beside it, which is the reason this
 * function exists instead of two calls that could disagree. The seal answer is the deployment's own key, the
 * same object the manifest route signs with, because an entry is refused before it is written when the run
 * could not publish it and a run that answered this twice, once here and once at the caller, is a run that can
 * record an epoch it then refuses to serve.
 */
export async function recordEpochForRun(run: EpochRunRecord): Promise<EpochJournal | undefined> {
  if (run.receiptsDir === undefined || run.mock) return undefined;
  return openEpochJournal({
    dir: run.receiptsDir,
    key: run.key,
    epk: run.epk,
    sealed: run.manifestKey !== undefined,
    ...(run.time === undefined ? {} : { time: run.time }),
  });
}

/**
 * Whether this deployment may publish the history it holds, or has to say why it may not.
 *
 * The served document is the deployment's own account of which keys signed which receipts, and a reader only
 * weighs it as far as it is authenticated: a plain JSON manifest is bytes anybody between the client and this
 * process could have written. One entry states nothing beyond the key the document already carries, so it is
 * today's behaviour and stays allowed unsigned. Two entries state a window for a key that is no longer in
 * use, which is a claim about the past, and a claim about the past that signs nothing is not published. The
 * refusal is the deployment's to answer with a manifest sealing key, and the seal path is already the
 * manifest route's own.
 */
export function unsealedHistoryRefusal(
  journal: EpochJournal,
  manifestKeyPresent: boolean,
): string | null {
  if (manifestKeyPresent || journal.entries.length < 2) return null;
  return (
    `${journal.path} names ${String(journal.entries.length)} epochs and this deployment holds no key to seal the ` +
    'manifest that would publish them, so the start is refused: a served history that signs nothing is a claim ' +
    'about retired keys that any observer could have written. Hand this process --manifest-key-path, so the ' +
    'document that states the history is signed by the deployment, or start it under the one epoch the journal ' +
    'names, which is served as the plain document it has always been'
  );
}
