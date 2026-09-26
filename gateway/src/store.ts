import { appendFile, open, readFile, rename, truncate, type FileHandle } from 'node:fs/promises';
import type { Stats } from 'node:fs';
import { join } from 'node:path';
import { sha256 } from './digest.js';

/**
 * Receipts appended to one file, and rewritten only when retention retires a prefix. Every
 * record carries the digest of the record before it, so deleting a middle record breaks every
 * digest after it and rewriting one breaks its own. The chain is what makes removal detectable;
 * durability alone would only answer whether a receipt is still there. The one thing that is
 * repaired instead of reported is a partial record at the tail, which is an append that never
 * finished rather than a receipt anyone was given the id for.
 *
 * Retention may only drop a prefix, and a prefix is the one thing a chain cannot speak for:
 * nothing after it changes. So a policy that would evict a record sitting in the middle of the
 * chain stops short of it, and a compaction appends a trim record to the run at the front of the
 * file, naming the digest the surviving chain starts from, which bound retired how many, and the
 * policy it retired under. A hole in the middle stays a broken link; a retired prefix stays a
 * statement that every later compaction leaves in place.
 *
 * Two numbers bound this store and they bound different things. The durability bound is how long the
 * file keeps records, stated as a period and as a count, and it is the only bound retirement reads.
 * The serving bound is how many records one range query holds at once, and it is the only bound a
 * walk reads: nothing leaves the file because a query is small, and a query over a window wider than
 * the serving bound is answered in batches and returns all of it. A deployment that keeps half a year
 * of traffic and answers a question about an hour of it needs both, which is why neither is a setting
 * of the other and why only the first is ever refused against a period.
 *
 * An opening used to answer what it holds by reading every byte of `receipts.log` and hashing every
 * record in it, so the cost of starting a process grew with the file and never stopped. A store now
 * keeps a second file beside it, `receipts.log.index`, holding the positions and digests an opening
 * used to re-derive, and a checkpoint saying how much of the store file it speaks for. The store file
 * remains the only authority: the second file is written by the code that reads the first, is thrown
 * away at the first disagreement with it, and can be declined outright. What a checkpoint changes is
 * stated at `loadSidecar`, and it is the one thing an operator needs to know about these two files:
 * the receipts are in one of them, and the other only says where to look.
 */

/** The file a deployment backs up. Named because an operator needs to know which one it is. */
export const RECEIPT_STORE_FILE = 'receipts.log';

/**
 * The index the same store keeps beside that file, and restores from it. Disposable: deleting it costs
 * an opening the walk it used to do, and changing nothing else about the answers.
 */
export const RECEIPT_SIDECAR_FILE = 'receipts.log.index';

const KIND_BYTES = 1;
const PREV_BYTES = 32;
const IAT_BYTES = 8;
const ID_LEN_BYTES = 2;
const FRAME_LEN_BYTES = 4;
const DIGEST_BYTES = 32;
const COUNT_BYTES = 4;
/** seam + two causes + the two bounds that produced them. */
const TRIM_PAYLOAD_BYTES = PREV_BYTES + 4 * COUNT_BYTES;
/** kind + prev + iat + idLen + digest, with the id and the payload still to come. */
const MIN_BODY_BYTES = KIND_BYTES + PREV_BYTES + IAT_BYTES + ID_LEN_BYTES + DIGEST_BYTES;
/** Everything before the id in a record body. */
const HEADER_BYTES = KIND_BYTES + PREV_BYTES + IAT_BYTES + ID_LEN_BYTES;
const MAX_ID_BYTES = 0xffff;
const MAX_COUNTER = 0xffffffff;
const KIND_RECEIPT = 0;
const KIND_TRIM = 1;

/**
 * The sidecar's own layout: `magic:4 || version:u16 || identityLen:u16 || identity`, then blocks, each
 * one `recordCount:u32 || checkpointBytes:u64` followed by that many entries and a closing check.
 * An entry is `recordStart:u64 || seq:u64 || iat:u64 || payloadLen:u32 || idLen:u16 || id || digest:32`.
 * Nothing is rewritten in place: a block is appended, and the whole file is replaced only when the
 * store file it speaks for has been replaced, which is the only moment its header stops being true.
 */
const SIDECAR_MAGIC = 'ASRI';
const SIDECAR_VERSION = 1;
/** magic, version, and the width of the volume pair this sidecar names its store file by. */
const SIDECAR_HEADER_BYTES = 4 + 2 + 2;
/** Everything of an entry that is not the id it names or the digest it carries. */
const SIDECAR_ENTRY_HEAD_BYTES = 8 + 8 + 8 + 4 + 2;
/** How many entries a block counts, and the byte of the store file the block speaks for. */
const SIDECAR_BLOCK_HEAD_BYTES = 4 + 8;
/**
 * Records per block. A block is the unit the index hashes once and appends once, so this number trades
 * the cost of reading an index against the cost of keeping one: hashing each entry on its own costs an
 * opening more than the walk it saves, and hashing a few hundred at a time does not. An append's entry
 * waits for a block, and a record waiting for one is read from the store file by the next opening, so
 * what this costs is a walk of up to this many records after a process was killed, and nothing at all
 * to a receipt.
 */
export const SIDECAR_BLOCK_RECORDS = 256;

/** One record's place in the store file, as the sidecar keeps it. */
interface CheckpointEntry {
  /** The byte the record's length prefix starts at. */
  readonly recordStart: number;
  /** Its position in the chain, which is the order a reader has to walk it in. */
  readonly seq: number;
  readonly iat: number;
  readonly id: string;
  readonly idLength: number;
  /** The payload's width, which with the id width gives the frame's width. */
  readonly length: number;
  readonly digest: Buffer;
}

/** The sidecar speaks for the store file up to the byte one past this entry's frame. */
function endOfEntry(entry: CheckpointEntry): number {
  return entry.recordStart + FRAME_LEN_BYTES + HEADER_BYTES + entry.idLength + entry.length + DIGEST_BYTES;
}

/** Where one entry's record sits in the file, in the terms the served paths read. */
function locationOf(entry: CheckpointEntry): Location {
  return {
    iat: entry.iat,
    seq: entry.seq,
    recordStart: entry.recordStart,
    offset: entry.recordStart + FRAME_LEN_BYTES + HEADER_BYTES + entry.idLength,
    length: entry.length,
    digest: entry.digest,
  };
}

/** A record's own counts, which have no room to be anything but a 32 bit saturating integer. */
function counter(value: number): Buffer {
  const out = Buffer.alloc(COUNT_BYTES);
  out.writeUInt32BE(value > MAX_COUNTER ? MAX_COUNTER : value);
  return out;
}

/** Everything one trim record says, in the two places the layout keeps it. */
interface TrimRecord {
  readonly prev: Uint8Array;
  readonly at: number;
  readonly seam: Uint8Array;
  readonly byAge: number;
  readonly byCount: number;
  readonly maxAgeSeconds: number;
  readonly maxCount: number;
}

/** Where one receipt sits in the file, and what the file said about those bytes when it was read. */
interface Location {
  readonly iat: number;
  /** This record's position in the chain, which is the order a reader has to walk it in. */
  readonly seq: number;
  /** The byte the record's length prefix starts at, so dead space is measurable. */
  readonly recordStart: number;
  readonly offset: number;
  readonly length: number;
  /**
   * The digest this record carried in its own frame, copied out of the file the index was read from.
   * A served read hashes the bytes it is about to hand over against this, because this is the only
   * statement in the index about the file's contents rather than about which file the volume named.
   */
  readonly digest: Buffer;
}

interface StoreState {
  records: Map<string, Location>;
  /** The digest the next appended receipt names as its predecessor. */
  head: Buffer;
  size: number;
  /**
   * Which file the volume had open when this index was read, in the volume's own terms. A served read
   * compares its handle against this before it takes any bytes, which is what lets one handle stand
   * where an open per record used to be, and what lets a walk follow the file a compaction moved into
   * this path instead of refusing it. It is not a statement about the bytes: see `serialOf`.
   */
  identity: string;
  /** The position the next chained record takes, which is one past the last record ever written. */
  nextSeq: number;
  /** Bytes the leading run of trim records occupies, so a compaction keeps them rather than eats them. */
  trimRunEnd: number;
  /** The digest the oldest surviving receipt was chained from, which is the newest seam. */
  anchor: Buffer;
  /** What each compaction wrote down, oldest first. */
  trims: TrimEvent[];
  /** Receipts retired by retention since the last trim was written, by cause. */
  dropped: { byAge: number; byCount: number };
}

/**
 * Where a store's instants come from: one named source, and the distance between two of its own
 * readings that no verdict here may report as a difference.
 *
 * The name and the bound travel together because a reading without them is a number nobody can weigh.
 * A deployment that wires a source of its own takes both with it, and a deployment that wires nothing
 * gets `HOST_CLOCK_SOURCE`, which says plainly that the instant is this host's own claim and that
 * nobody measured how far that claim can be.
 */
export interface TimeSource {
  /** What this process reads, in the operator's own words: `host clock` is the shipped answer. */
  readonly name: string;
  /**
   * Seconds a reading of this source can be away from the instant it names, as far as anyone has
   * measured. Null means nobody measured it, which is a different sentence from zero: a bound of zero
   * is a claim this source is right, and a null is a statement that nothing here knows.
   */
  readonly uncertaintySeconds: number | null;
  /**
   * The next reading, in whole Unix seconds, which is the unit every stamp this store writes, compares
   * and retires by is written in. A source that reads in another unit is this function's to convert.
   */
  readonly now: () => number;
}

/**
 * The source a deployment that configures nothing reads: this host's own clock, at the bound nobody
 * measured. Every whole-second stamp in this package falls back to it, which is why it is a value
 * rather than a comment: a reader that wants to know what an unstamped deployment rests on is reading
 * the same three fields the process does, and `docs/configured-values.md` quotes this line whole.
 */
export const HOST_CLOCK_SOURCE: TimeSource = { name: 'host clock', uncertaintySeconds: null, now: () => Math.floor(Date.now() / 1000) };

/** Two readings of one source, weighed against what that source can resolve between them. */
export type ReadingsApart =
  | {
      readonly state: 'indistinguishable';
      readonly apartSeconds: number;
      readonly resolutionSeconds: number;
      readonly uncertaintySeconds: number;
      readonly source: string;
    }
  | {
      readonly state: 'apart';
      readonly apartSeconds: number;
      readonly resolutionSeconds: number;
      readonly uncertaintySeconds: number;
      readonly source: string;
    }
  | { readonly state: 'unmeasured'; readonly apartSeconds: number; readonly source: string };

/**
 * How many times a source's bound has to fit into a distance between two of its own readings before
 * this package calls that distance a difference. Each reading may be away from the instant it names by
 * the whole bound and the two may lean opposite ways, so the factor is written once, here.
 */
const PAIRWISE_FACTOR = 2;

/**
 * How far apart two readings of one source are, in that source's own terms. One sentence for the
 * arithmetic and for what an operator is quoted, because both go through the one factor above.
 */
export function readingsApart(source: TimeSource, first: number, second: number): ReadingsApart {
  const apartSeconds = Math.abs(first - second);
  const bound = source.uncertaintySeconds;
  if (bound === null) {
    return { state: 'unmeasured', apartSeconds, source: source.name };
  }
  const resolutionSeconds = PAIRWISE_FACTOR * bound;
  return {
    state: apartSeconds <= resolutionSeconds ? 'indistinguishable' : 'apart',
    apartSeconds,
    resolutionSeconds,
    uncertaintySeconds: bound,
    source: source.name,
  };
}

/**
 * The durability bound: how long this file keeps the records it holds.
 *
 * Both halves are bounds on what the file keeps, and retirement acts on either by dropping a prefix.
 * Neither is a bound on what one query may ask for, which is `ReceiptServing`. The pair is a
 * deployment's own decision, and no value of either is checked against a period anyone owes: what a
 * period is owed for, to whom, and whether a receipt is one of the logs a duty counts, are questions
 * this interface does not hold the facts to answer.
 */
export interface ReceiptRetention {
  /**
   * The period records are kept for: a receipt is retained, and so served, while its `iat` is at or
   * after `now - maxAgeSeconds`. Absent means nothing ages out, and a short period is a deployment's
   * own choice rather than a value this store argues with.
   */
  readonly maxAgeSeconds?: number;
  /**
   * The number of receipts the file keeps, which is the ceiling that stops a volume filling. It is a
   * capacity number and not a memory one: past it the oldest-dated receipts leave as a prefix. Absent
   * means nothing is shed by count.
   *
   * `openFileReceiptStore` reads this count against the period configured beside it and refuses the
   * pairing when the count cannot hold the period at the traffic the file has already carried, which
   * is the only claim about this number this store is able to make.
   */
  readonly maxCount?: number;
  /**
   * The instant this store ages records against, and the source that instant comes from. Absent means
   * `HOST_CLOCK_SOURCE`, which is this host's clock at a bound nobody measured.
   *
   * It is one named thing rather than a reading function because a six month window is a statement
   * about time, and a statement about time that does not say where its numbers come from cannot be
   * weighed by whoever reads it. It is injectable because a six month window is otherwise only
   * testable by waiting.
   */
  readonly time?: TimeSource;
}

/**
 * The serving bound: how many records one range query may hold at once.
 *
 * It bounds the working set of a walk over the retained set and nothing else. Receipt bytes are read
 * one at a time whichever way a walk is configured, so what this caps is how many records a query has
 * resolved into an ordered list before it hands the first one over. Nothing retires because of it: a
 * store keeping more receipts than this answers a query over all of them in batches of this size and
 * returns every one of them, which is the reason it is a separate number from the durability bound
 * rather than a second name for it.
 *
 * The value appears in no record, no pack and no document. A bound a third party had to read in order
 * to check a verdict would place a deployment's memory setting inside the artifact that carries the
 * store's claim about what left the file, so the trim record states the policy a prefix retired under,
 * which is the durability bound, and says nothing about how a query is walked.
 */
export interface ReceiptServing {
  /**
   * The largest number of records one range walk holds at a time. Absent, or anything that is not a
   * positive whole number, means the walk resolves the whole window it matches before it yields the
   * first receipt, which is what a store that never bounded a query does.
   */
  readonly maxServedReceipts?: number;
}

/**
 * What a deployment keeps by default, and which rule the default answers to. Article 19(1) requires
 * providers of a high-risk AI system to keep the logs such a system generates automatically under
 * Article 12(1), to the extent those logs are under their control, for a period appropriate to the
 * system's intended purpose and of at least six months. Article 26(6) states the same duty for a
 * deployer. This default treats a receipt as one of those logs, which is an assumption the code
 * cannot check: whether a per-request receipt is an Article 12(1) log turns on the system and the
 * actor, and neither is settled by anything in this file.
 *
 * Two qualifiers travel with the number. Both articles yield to applicable Union or national law,
 * "in particular in Union law on the protection of personal data", so a data-protection rule can cut
 * this window as well as lengthen it. And where the operator is itself a financial institution,
 * Articles 19(2) and 26(6) maintain those logs as part of the documentation kept under the relevant
 * financial-services law instead, where the applicable period is longer and is not ours to name.
 *
 * A deployer inside that law raises this period together with the durability count beside it, because
 * a count is a bound on storage and nothing more: `gateway/src/cli.ts` ships one of 10,000 receipts,
 * which is a hundred seconds of the hundred requests a second that `docs/access-control.md` states for
 * one address, and under a week at one receipt a minute, so it closes a multi-year window however long
 * this period is set to. The two are not free to contradict each other in silence, so
 * `openFileReceiptStore` compares the window a configuration asks for with the window the receipts it
 * holds actually cover, and refuses to open when the durability count cannot hold the period. That
 * refusal is the reason the count is its own number rather than the serving bound under another name:
 * what a query holds at once cannot shorten a window, so only what the file keeps is measured against
 * one. Rounded up to whole days past the shortest six months, so the configured window is never shorter
 * than the floor it answers to. What that floor is owed to, and whether a receipt is one of the logs
 * the article speaks of, is settled elsewhere and not by this number: a store that opens has said what
 * it serves, which is a different question from a duty discharged.
 */
export const MINIMUM_RETENTION_SECONDS = 184 * 24 * 60 * 60;

export interface FileReceiptStoreOptions {
  readonly dir: string;
  /** Absent means nothing is evicted, which is the right default for a fixture store. */
  readonly retention?: ReceiptRetention;
  /** Absent means a range query resolves the whole window it is asked for. */
  readonly serving?: ReceiptServing;
  /**
   * Declines the sidecar index. The store then touches only `receipts.log`: every opening reads all of
   * it and re-hashes every record in it, which is the cost the index exists to avoid and the only way
   * to make the proof an opening rests on come from the bytes rather than from saved state. Absent, or
   * true, means keep and use the index. It is an option rather than an environment variable because
   * the process that has to answer for a chain claim is the one that opens the store.
   */
  readonly sidecarIndex?: boolean;
}

/** One retained receipt as the store hands it out: what to check, and when it was issued. */
export interface StoredReceipt {
  readonly id: string;
  readonly iat: number;
  readonly receipt: Uint8Array;
  /** What the source that stamped this record supports about its place in the window asked for. */
  readonly claim: WindowClaim;
}

/**
 * The source a store reads, as the store states it: a name, and how far its readings can be from the
 * instants they name. Null is not a small bound. It says nobody measured, and every report that carries
 * it has to say so rather than let the absence read as accuracy.
 */
export interface StampDeclaration {
  readonly name: string;
  readonly uncertaintySeconds: number | null;
}

/**
 * What one record's stamp supports about the half-open window it was read out of.
 *
 * Membership is the raw stamp's, and this changes nothing about it: a store serves the receipts its
 * index matches, because a walk that dropped a record whose stamp sits near an edge would be deleting
 * evidence on a guess about the clock. What this adds is the honesty of the claim beside the record, in
 * the two cases a reader can act on differently.
 *
 * `inside-window` is the only state here that supports "this record's instant is inside the span asked
 * for": the stamp is further from both edges than the source's own resolution, so no reading of that
 * source could have put the record elsewhere. `at-edge` says the nearest edge is inside what the source
 * can resolve, so the record may or may not belong to the span and nothing in the store can say which.
 * `bound-unknown` says the source was never measured, which is neither of the two and is never reported
 * as a satisfied claim.
 */
export type WindowClaim =
  | { readonly state: 'inside-window'; readonly stamped: StampDeclaration }
  | {
      readonly state: 'at-edge';
      /**
       * Seconds the stamp has before the nearer edge, counted so that 1 is the edge itself: the older
       * edge belongs to the window, so a stamp sitting on it has one second of slack and no more.
       */
      readonly marginSeconds: number;
      readonly stamped: StampDeclaration;
    }
  | { readonly state: 'bound-unknown'; readonly stamped: StampDeclaration };

/**
 * The claim one record's stamp supports against one half-open window, read through the source that
 * wrote the stamp.
 *
 * Both edges are measured because the window is bounded at both: `from` is included and `to` is not, so
 * a stamp at the older edge is in the span by the rule itself and a stamp one second below the newer
 * edge is in by one second. That asymmetry is why the margin below counts the edge's own second rather
 * than the bare distance to it, and why a source declaring an exact clock reports every stamp it wrote
 * as inside rather than hedging the ones that sit on an edge. The nearer of the two is the whole
 * question, and it is weighed against the same `PAIRWISE_FACTOR` a distance between two readings is
 * weighed against, so an edge claim and a span measurement cannot drift apart.
 */
function windowClaim(source: TimeSource, iat: number, from: number, to: number): WindowClaim {
  const stamped: StampDeclaration = { name: source.name, uncertaintySeconds: source.uncertaintySeconds };
  const bound = source.uncertaintySeconds;
  if (bound === null) {
    return { state: 'bound-unknown', stamped };
  }
  const marginSeconds = Math.min(iat - from + 1, to - iat);
  return marginSeconds > PAIRWISE_FACTOR * bound
    ? { state: 'inside-window', stamped }
    : { state: 'at-edge', marginSeconds, stamped };
}

/**
 * Three refusals, answering three different questions about three different things.
 *
 * `STORE_CHAIN_BROKEN` is about the file on the volume: what is there no longer chains to itself, and
 * there is no safe way to serve from it. A short read, an unreadable volume and a corrupt file are
 * different answers to different questions, and only this one has no safe response.
 * `RECORD_STAMP_OUT_OF_RANGE` is about a value being written now: the stamp a caller is filing a
 * receipt under is not a whole number of Unix seconds this record layout can hold. It is reachable
 * because the stamp is handed to the store rather than read off a clock the store owns, and it belongs
 * to this union because the layout's 8-byte field is what sets the bound. An operator told their chain
 * is broken when the caller's time source is unreadable would go looking at the volume.
 * `RETENTION_WINDOW_UNHOLDABLE` is about a configuration: the durability bound and the period this store
 * was opened with cannot both be honoured at the traffic the file has already carried. It says which
 * bound is short and by how much, and it is refused at the opening rather than left for whoever reads
 * the shortfall out of the retained window afterwards.
 */
export type StoreErrorCode =
  | 'STORE_CHAIN_BROKEN'
  | 'RECORD_STAMP_OUT_OF_RANGE'
  | 'RETENTION_WINDOW_UNHOLDABLE';

export class StoreError extends Error {
  readonly code: StoreErrorCode;

  constructor(code: StoreErrorCode, detail: string) {
    super(`${code}: ${detail}`);
    this.name = 'StoreError';
    this.code = code;
  }
}

/** One compaction: when space was reclaimed, what left, and under what policy it left. */
export interface TrimEvent {
  readonly at: number;
  readonly byAge: number;
  readonly byCount: number;
  readonly under: { readonly maxAgeSeconds?: number; readonly maxCount?: number };
}

/**
 * What a retention manifest states about the chain and about the receipts no longer in it.
 *
 * `anchor` is the digest the oldest retained receipt was chained from, which is where a reader
 * holding only a pack starts recomputing forward to `head()`. `retired` is the only place the
 * store says which bound removed what, because `window()` reports the surviving set and cannot
 * report why anything is missing from it.
 */
export interface ChainState {
  readonly anchor: Uint8Array;
  readonly retired: {
    readonly byAge: number;
    readonly byCount: number;
    readonly trims: readonly TrimEvent[];
  };
}

/** What a store's retained set says about the window it is holding, bounds inclusive. */
export interface RetainedWindow {
  readonly from: number;
  readonly to: number;
  readonly count: number;
}

export interface ReceiptStore {
  put(id: string, receipt: Uint8Array, iat: number): Promise<void>;
  get(id: string): Promise<Uint8Array | null>;

  /** Inclusive bounds and a count, so a retention manifest can state them. */
  window(): Promise<RetainedWindow>;

  /**
   * Every receipt stamped in a half-open interval, in the order they were chained, for packs.
   *
   * The set is the store's retained set intersected with the interval, whatever the serving bound is:
   * the bound sizes a walk's working set and does not choose which receipts a caller is told about.
   */
  range(from: number, to: number): AsyncIterable<StoredReceipt>;

  /** Head of the hash chain. Publishing it is what makes deletion detectable. */
  head(): Promise<Uint8Array>;

  /**
   * The source this store reads, as it was declared when the store opened.
   *
   * A stamp is this source's claim, so whoever needs the bound a record was issued under asks the store
   * and reads it beside the record. It cannot travel inside the record: the framing in section 5.2 of
   * `docs/receipt-spec.md` has no byte for it, those bytes are published as conformance vectors, and a
   * bound belongs to the store's declaration rather than to the signed payload.
   */
  timeSource(): StampDeclaration;

  /** The anchor and the retirement history, which `window()` and `head()` cannot supply. */
  chainState(): Promise<ChainState>;
}

/**
 * A record's stamp is written by a caller that chose the instant, so the store has to say what it can
 * hold rather than discover the answer in a Buffer range error after the receipt was signed and, on a
 * stream, after the bytes reached the client.
 *
 * The bound is the largest integer a JavaScript number carries exactly, not the 8-byte field's own
 * maximum. A stamp past it would fit the field and still be a different instant than the one the
 * caller named, because the number arriving here has already been rounded, and a chain that records a
 * rounded stamp cannot be recomputed from what a reader holds. Fractions and negatives are refused for
 * the same reason in the other direction: the layout has no spelling for either, and a stamp the record
 * cannot state is not a stamp.
 */
function assertStamp(iat: number): void {
  if (!Number.isInteger(iat) || iat < 0 || iat > Number.MAX_SAFE_INTEGER) {
    throw new StoreError(
      'RECORD_STAMP_OUT_OF_RANGE',
      `a receipt stamp of ${String(iat)} is not a whole number of Unix seconds between 0 and ${String(Number.MAX_SAFE_INTEGER)}, so no record this store writes can state it`,
    );
  }
}

/**
 * `Record = len:u32 || kind:u8 || prev:32 || iat:u64 || idLen:u16 || id || payload || digest:32`,
 * with `digest = sha256(everything between len and digest)`. `len` covers kind through digest.
 */
function encode(kind: number, prev: Uint8Array, iat: number, id: string, payload: Uint8Array): { frame: Buffer; digest: Buffer } {
  const idBytes = Buffer.from(id, 'utf8');
  if (idBytes.length > MAX_ID_BYTES) {
    throw new Error(`receipt id of ${idBytes.length} bytes exceeds the ${MAX_ID_BYTES} byte record limit`);
  }
  assertStamp(iat);
  const stamp = Buffer.alloc(IAT_BYTES);
  stamp.writeBigUInt64BE(BigInt(iat));
  const idLength = Buffer.alloc(ID_LEN_BYTES);
  idLength.writeUInt16BE(idBytes.length);
  const body = Buffer.concat([Buffer.from([kind]), Buffer.from(prev), stamp, idLength, idBytes, Buffer.from(payload)]);
  const digest = Buffer.from(sha256(body));
  const prefix = Buffer.alloc(FRAME_LEN_BYTES);
  prefix.writeUInt32BE(body.length + DIGEST_BYTES);
  return { frame: Buffer.concat([prefix, body, digest]), digest };
}

/**
 * A compaction written down. The predecessor the record names is the digest of whatever physically
 * precedes it, which is the previous trim or the empty digest at the start of the file, so the run
 * of them chains and a reader can tell a removed or reordered retirement from an edited one.
 *
 * `payload = seam:32 || byAge:u32 || byCount:u32 || maxAgeSeconds:u32 || maxCount:u32`. The seam is
 * the digest the receipts the compaction kept were chained from, which no surviving record carries
 * and no reader can recompute. A bound of zero says none was configured: the field has no other way
 * to say it, and a reader has to tell "no cap" apart from a cap of one.
 */
function encodeTrimRecord(record: TrimRecord): Buffer {
  return encode(
    KIND_TRIM,
    record.prev,
    record.at,
    '',
    Buffer.concat([
      Buffer.from(record.seam),
      counter(record.byAge),
      counter(record.byCount),
      counter(record.maxAgeSeconds),
      counter(record.maxCount),
    ]),
  ).frame;
}

function decodeTrimRecord(prev: Uint8Array, at: number, payload: Buffer): TrimRecord {
  return {
    prev,
    at,
    seam: payload.subarray(0, PREV_BYTES),
    byAge: payload.readUInt32BE(32),
    byCount: payload.readUInt32BE(36),
    maxAgeSeconds: payload.readUInt32BE(40),
    maxCount: payload.readUInt32BE(44),
  };
}

/** The record states a bound of zero where the configuration states none, and the two meet here. */
function trimEvent(record: TrimRecord): TrimEvent {
  return {
    at: record.at,
    byAge: record.byAge,
    byCount: record.byCount,
    under: {
      maxAgeSeconds: record.maxAgeSeconds === 0 ? undefined : record.maxAgeSeconds,
      maxCount: record.maxCount === 0 ? undefined : record.maxCount,
    },
  };
}

/**
 * Which file a handle is on, in the volume's own terms: the volume it belongs to and the number that
 * volume carries for the file. Read off a handle rather than off a name, so it answers "which file is
 * this handle on" and never "which file does the path name right now".
 *
 * It is a fast path and not an identity, for two reasons no volume's number can answer away. The
 * number is an allocator's: delete one file and create another and the new one can be handed the
 * number the old one had. And it comes back through a JavaScript number, which on this host carries
 * the file reference past `Number.MAX_SAFE_INTEGER`, where representable values are two apart, so two
 * files living at once can be reported with the same number as easily as two dead ones can. What the
 * pair does answer is whether this handle is on the file the store last wrote, which is what lets a
 * walk follow the file a compaction moved over the path instead of refusing it, and the bytes a walk
 * then takes are checked against the index by `readReceipt`.
 *
 * Size and the timestamps are deliberately not part of the pair. The store grows the file as a matter
 * of course, so a handle discarded for a different size would be an open per record again under
 * another name, and a backup or an archiver that only sets attributes moves a timestamp while leaving
 * every byte alone, which is an ordinary thing to happen to a log meant to live for years and is not a
 * reason to refuse a receipt.
 */
function serialOf(stats: Stats): string {
  return `${String(stats.dev)}:${String(stats.ino)}`;
}

/** What a scan has read so far, in the order the file holds it. */
interface Scan {
  readonly records: Map<string, Location>;
  readonly trims: TrimEvent[];
  /** What the next receipt has to name as its predecessor: the newest seam while the run lasts, then a digest. */
  expectedPrev: Buffer;
  /** The digest of the last record read, which is what the next trim record has to name. */
  lastDigest: Buffer;
  anchor: Buffer;
  /** The position the next record takes, which is one past the last record read. */
  seq: number;
  trimRunEnd: number;
  /** The byte past the last complete record this scan read. */
  end: number;
}

function emptyScan(): Scan {
  const none = Buffer.alloc(PREV_BYTES);
  return {
    records: new Map<string, Location>(),
    trims: [],
    expectedPrev: none,
    lastDigest: none,
    anchor: none,
    seq: 0,
    trimRunEnd: 0,
    end: 0,
  };
}

/** The index, the head and the retirement state a scan read out of the file, in the store's own terms. */
function stateOf(scan: Scan, identity: string): StoreState {
  return {
    records: scan.records,
    head: scan.expectedPrev,
    size: scan.end,
    identity,
    nextSeq: scan.seq,
    trimRunEnd: scan.trimRunEnd,
    anchor: scan.anchor,
    trims: scan.trims,
    dropped: { byAge: 0, byCount: 0 },
  };
}

/**
 * Parses every complete record in `bytes`, which begins at position `base` in the store file, into
 * `scan`, and collects one entry per receipt when an index is being written beside the file.
 *
 * A scan can start anywhere that begins a record, given the state the records in front of it left
 * behind, which is what lets an opening resume from a checkpoint instead of reading from the first
 * byte. `base` is only ever what an error says the position of a record was: a record is indexed by
 * where the file holds it, not by where the buffer this scan was handed starts.
 *
 * From the first byte the chain has two rules and they are checked here, nowhere else: a receipt names
 * the digest of the record the chain runs through, and a trim names the digest of the record
 * physically in front of it. Both are checked against what the bytes say, so a hole in the middle of
 * the chain and an edited digest are refusals rather than a shorter history.
 */
function parseRecords(bytes: Buffer, base: number, scan: Scan, entries: CheckpointEntry[] | null): void {
  let at = 0;
  while (at + FRAME_LEN_BYTES <= bytes.length) {
    const position = base + at;
    const length = bytes.readUInt32BE(at);
    const body = at + FRAME_LEN_BYTES;
    const end = body + length;
    // Missing bytes are the one signature an interrupted append cannot fake, so this is the only
    // stop that is not a refusal: every record after it is unnamed, and a partial record nobody
    // holds an id for is worth less than the receipts sitting behind it.
    if (end > bytes.length) {
      break;
    }
    // From here the frame is whole, so anything that cannot be read out of it was written wrong
    // rather than cut short. Truncating here would delete the tail an editor meant to hide.
    if (length < MIN_BODY_BYTES) {
      throw new StoreError('STORE_CHAIN_BROKEN', `receipt store chain is broken at byte ${position}: a record claims a frame ${length} bytes long, which is too short to hold its own header`);
    }
    const idLength = bytes.readUInt16BE(body + KIND_BYTES + PREV_BYTES + IAT_BYTES);
    const idStart = body + HEADER_BYTES;
    const payloadStart = idStart + idLength;
    const payloadEnd = end - DIGEST_BYTES;
    if (payloadStart > payloadEnd) {
      throw new StoreError('STORE_CHAIN_BROKEN', `receipt store chain is broken at byte ${position}: a record's ${idLength} byte id does not fit inside its own frame`);
    }
    const kind = bytes.readUInt8(body);
    const prev = bytes.subarray(body + KIND_BYTES, body + KIND_BYTES + PREV_BYTES);
    const iat = Number(bytes.readBigUInt64BE(body + KIND_BYTES + PREV_BYTES));
    const digest = bytes.subarray(payloadEnd, end);
    if (!digest.equals(Buffer.from(sha256(bytes.subarray(body, payloadEnd))))) {
      throw new StoreError('STORE_CHAIN_BROKEN', `receipt store chain is broken at byte ${position}: a record's digest does not match its own bytes`);
    }
    if (kind === KIND_TRIM) {
      // A retirement is a fact about where the surviving receipts start, which is the front of the
      // file. Anywhere else it describes a hole in the middle as if it were intended.
      if (scan.seq !== 0) {
        throw new StoreError('STORE_CHAIN_BROKEN', `receipt store chain is broken at byte ${position}: a trim record follows a receipt`);
      }
      if (!prev.equals(scan.lastDigest)) {
        throw new StoreError('STORE_CHAIN_BROKEN', `receipt store chain is broken at byte ${position}: a trim record names a predecessor that is not the record in front of it`);
      }
      if (payloadEnd - payloadStart !== TRIM_PAYLOAD_BYTES) {
        throw new StoreError('STORE_CHAIN_BROKEN', `receipt store chain is broken at byte ${position}: a trim record carries ${payloadEnd - payloadStart} bytes where the layout states ${TRIM_PAYLOAD_BYTES}`);
      }
      const trim = decodeTrimRecord(prev, iat, bytes.subarray(payloadStart, payloadEnd));
      scan.trims.push(trimEvent(trim));
      // The survivors chain from the seam, not from the record that states it. Copied because a
      // view of the file read would hold the whole file open for as long as the store is.
      const seam = Buffer.from(trim.seam);
      scan.expectedPrev = seam;
      scan.anchor = seam;
      scan.lastDigest = Buffer.from(digest);
      scan.trimRunEnd = base + end;
    } else {
      if (!prev.equals(scan.expectedPrev)) {
        throw new StoreError('STORE_CHAIN_BROKEN', `receipt store chain is broken at byte ${position}: a record names a predecessor that is not the one before it`);
      }
      const entry: CheckpointEntry = {
        recordStart: position,
        seq: scan.seq,
        iat,
        id: bytes.subarray(idStart, payloadStart).toString('utf8'),
        idLength,
        length: payloadEnd - payloadStart,
        // Copied out of the file read for the same reason the seam is: a view of it would keep the
        // whole file alive for as long as the store is.
        digest: Buffer.from(digest),
      };
      scan.expectedPrev = entry.digest;
      scan.lastDigest = entry.digest;
      scan.records.set(entry.id, locationOf(entry));
      entries?.push(entry);
      scan.seq += 1;
    }
    at = end;
    scan.end = base + end;
  }
}

/**
 * Reads every complete record of the store file and checks that they chain.
 *
 * A trailing partial record is repaired rather than failed: it is what an append interrupted by
 * a crash leaves behind, and it can never verify because its bytes never all arrived. Left in
 * place it would cost more than the one record it is, because the walk stops where it cannot
 * read and so hides every record appended after it. Dropping it costs a receipt nobody was
 * given the id for.
 */
async function walk(path: string, file: FileHandle, entries: CheckpointEntry[] | null): Promise<StoreState> {
  // Taken before the bytes, from the same handle that reads them, so the index and this statement
  // about which file it describes are answers about one and the same file.
  const identity = serialOf(await file.stat());
  const bytes = await file.readFile();
  const scan = emptyScan();
  parseRecords(bytes, 0, scan, entries);
  if (scan.end < bytes.length) {
    // By path, not through the handle: an append-mode handle cannot set the end of a file.
    await truncate(path, scan.end);
  }
  return stateOf(scan, identity);
}

/** Reads a span of the store file, or as much of it as the file actually holds. */
async function readSpan(file: FileHandle, from: number, length: number): Promise<Buffer> {
  if (length <= 0) {
    return Buffer.alloc(0);
  }
  const buffer = Buffer.alloc(length);
  const { bytesRead } = await file.read(buffer, 0, length, from);
  return bytesRead === length ? buffer : buffer.subarray(0, bytesRead);
}

/** The header every block chains from: which store file this index speaks for, and in what layout. */
function sidecarHeader(identity: string): Buffer {
  const name = Buffer.from(identity, 'utf8');
  const out = Buffer.alloc(SIDECAR_HEADER_BYTES + name.length);
  out.write(SIDECAR_MAGIC, 0, 'utf8');
  out.writeUInt16BE(SIDECAR_VERSION, 4);
  out.writeUInt16BE(name.length, 6);
  name.copy(out, SIDECAR_HEADER_BYTES);
  return out;
}

function entryBytes(entry: CheckpointEntry): Buffer {
  const out = Buffer.alloc(SIDECAR_ENTRY_HEAD_BYTES + entry.idLength + DIGEST_BYTES);
  out.writeBigUInt64BE(BigInt(entry.recordStart), 0);
  out.writeBigUInt64BE(BigInt(entry.seq), 8);
  out.writeBigUInt64BE(BigInt(entry.iat), 16);
  out.writeUInt32BE(entry.length, 24);
  out.writeUInt16BE(entry.idLength, 28);
  out.write(entry.id, SIDECAR_ENTRY_HEAD_BYTES, 'utf8');
  entry.digest.copy(out, SIDECAR_ENTRY_HEAD_BYTES + entry.idLength);
  return out;
}

/** A block's own bytes, chained from the block before it: the only hashing the index does. */
function blockCheck(previous: Buffer, body: Buffer): Buffer {
  return Buffer.from(sha256(Buffer.concat([previous, body])));
}

/**
 * One block: how many records it carries, the byte of the store file it speaks for, the entries, and
 * the check that closes it. The checkpoint is stated rather than left to be inferred so that a sidecar
 * whose checkpoint disagrees with the records it carries is a disagreement a reader can see without
 * the store file in front of it.
 */
function encodeBlock(previous: Buffer, chunk: readonly CheckpointEntry[]): { bytes: Buffer; check: Buffer } {
  const last = chunk.at(-1);
  if (last === undefined) {
    throw new Error('an index block is only ever written when it carries a record');
  }
  const head = Buffer.alloc(SIDECAR_BLOCK_HEAD_BYTES);
  head.writeUInt32BE(chunk.length, 0);
  head.writeBigUInt64BE(BigInt(endOfEntry(last)), 4);
  const body = Buffer.concat([head, ...chunk.map(entryBytes)]);
  const check = blockCheck(previous, body);
  return { bytes: Buffer.concat([body, check]), check };
}

/** The index this store keeps beside its file, or nothing at all when the opening declined one. */
interface SidecarState {
  readonly path: string;
  /**
   * The check the last block on disk closed with, which the next block chains from. Null says the
   * index is not being maintained any more, either because it was never written or because a write
   * refused, and it stays null until an opening rebuilds it from the store file.
   */
  previous: Buffer | null;
  /** Entries written since the last block, so a lost one costs an opening a walk of its own records. */
  pending: CheckpointEntry[];
}

/** Writes the index whole: a header naming the store file, then a block per run of entries. */
async function writeSidecar(sidecar: SidecarState, identity: string, entries: readonly CheckpointEntry[]): Promise<void> {
  try {
    const header = sidecarHeader(identity);
    let previous: Buffer = Buffer.from(sha256(header));
    const file = await open(sidecar.path, 'w');
    try {
      await file.write(header);
      for (let at = 0; at < entries.length; at += SIDECAR_BLOCK_RECORDS) {
        const block = encodeBlock(previous, entries.slice(at, at + SIDECAR_BLOCK_RECORDS));
        await file.write(block.bytes);
        previous = block.check;
      }
    } finally {
      await file.close();
    }
    sidecar.previous = previous;
    sidecar.pending = [];
  } catch {
    // A store whose index could not be written serves its file, which is all it ever promised. The
    // next opening reads the whole file and tries again, so a full volume is a slow start and not a
    // refusal, and nothing about the receipts depends on this having worked.
    sidecar.previous = null;
  }
}

/** Appends the entries written since the last block as one more block, chained from the one before. */
async function flushSidecar(sidecar: SidecarState): Promise<void> {
  const previous = sidecar.previous;
  if (previous === null || sidecar.pending.length === 0) {
    return;
  }
  const block = encodeBlock(previous, sidecar.pending);
  sidecar.pending = [];
  try {
    // Deliberately not synced. The record this entry indexes is already durable, and an index that
    // was never told is a store file with an opening that reads a few more records from it.
    await appendFile(sidecar.path, block.bytes);
    sidecar.previous = block.check;
  } catch {
    sidecar.previous = null;
  }
}

/** Notes one appended record. Costs a put nothing until the entries fill a block. */
async function noteEntry(sidecar: SidecarState | null, entry: CheckpointEntry): Promise<void> {
  if (sidecar === null || sidecar.previous === null) {
    return;
  }
  sidecar.pending.push(entry);
  if (sidecar.pending.length >= SIDECAR_BLOCK_RECORDS) {
    await flushSidecar(sidecar);
  }
}

/** What a usable index says before a single record of the store file has been read. */
interface Checkpoint {
  /** The scan holding every record the index speaks for, parked at the byte the index ends at. */
  readonly scan: Scan;
  /** The byte of the store file the index speaks for: everything past this is read from the file. */
  readonly checkpointBytes: number;
  readonly previous: Buffer;
}

/**
 * Reads the index beside the store file and returns what it may be believed for, or nothing.
 *
 * Any refusal is a fallback rather than an error out of the store: nothing comes back from here that
 * makes an opening fail, because an index that cannot be read is a store that reads its file instead.
 * That includes an error of this function's own, which is swallowed rather than reported.
 */
async function loadSidecar(file: FileHandle, path: string, identity: string, fileSize: number): Promise<Checkpoint | null> {
  try {
    return await readCheckpoint(file, path, identity, fileSize);
  } catch {
    return null;
  }
}

/**
 * Decides whether the index may be believed, which is the whole of what an opening that does not
 * re-derive the file owes the file.
 *
 * What is checked, and what is not. Every byte of the index is hashed, block by block, so a changed
 * position, stamp, id or digest anywhere in it is a disagreement and not an answer. The index names the
 * store file by the volume's pair, and the byte it speaks for has to be inside the file that is there
 * now. The leading run of trim records is read out of the store file and re-verified, so the anchor and
 * the retirement history an opening reports are recomputed from bytes and never remembered. And the
 * record the index ends on is read back out of the store file and hashed, because that one record is
 * where an index written from these bytes is tied to these bytes: it also fixes the checkpoint at a real
 * record boundary, so a resume can never truncate a file on the strength of a number it was handed.
 *
 * What is not checked is the claim the rest of the index carries, which is that the records it indexes
 * before that boundary still hold the bytes they held when the index was written. That is the residual a
 * checkpoint is: the proof for the prefix rests on saved state rather than on recomputation, so whoever
 * can write the index can shorten the proof an opening makes. It is not a byte served unchecked, which
 * is the other half of the same trade: a location out of the index is read through `readReceipt`, which
 * hashes the bytes it is about to hand over against the digest the index holds and refuses if they
 * disagree. What an index can change is what an opening refuses at the opening, never what it serves.
 * `FileReceiptStoreOptions.sidecarIndex` declines the index outright, which is how an operator who needs
 * the whole chain recomputed asks for it without touching the file that holds the receipts.
 */
async function readCheckpoint(file: FileHandle, path: string, identity: string, fileSize: number): Promise<Checkpoint | null> {
  const bytes = await readFile(path).catch(() => null);
  if (bytes === null) {
    return null;
  }
  const identityLength = bytes.length >= SIDECAR_HEADER_BYTES ? bytes.readUInt16BE(6) : 0;
  const headerEnd = SIDECAR_HEADER_BYTES + identityLength;
  if (
    identityLength === 0 ||
    bytes.length < headerEnd + SIDECAR_BLOCK_HEAD_BYTES ||
    bytes.subarray(0, 4).toString('utf8') !== SIDECAR_MAGIC ||
    bytes.readUInt16BE(4) !== SIDECAR_VERSION ||
    bytes.subarray(SIDECAR_HEADER_BYTES, headerEnd).toString('utf8') !== identity
  ) {
    return null;
  }

  // The index is read straight into the state an opening resumes from, one block at a time: what an
  // opening that trusts the index allocates is that state and the block it is checking, so reading a
  // hundred thousand records out of the index costs no more than the records themselves.
  const scan = emptyScan();
  let first: CheckpointEntry | undefined;
  let last: CheckpointEntry | undefined;
  let previous: Buffer = Buffer.from(sha256(bytes.subarray(0, headerEnd)));
  let at = headerEnd;
  /** The byte the index file can be cut back to when the block that follows it never finished. */
  let whole = headerEnd;
  let checkpointBytes = 0;
  while (at + SIDECAR_BLOCK_HEAD_BYTES <= bytes.length) {
    const bodyStart = at;
    const count = bytes.readUInt32BE(at);
    const claimed = Number(bytes.readBigUInt64BE(at + 4));
    at += SIDECAR_BLOCK_HEAD_BYTES;
    const block: CheckpointEntry[] = [];
    let torn = false;
    for (let i = 0; i < count; i++) {
      if (at + SIDECAR_ENTRY_HEAD_BYTES + DIGEST_BYTES > bytes.length) {
        torn = true;
        break;
      }
      const idLength = bytes.readUInt16BE(at + 28);
      if (at + SIDECAR_ENTRY_HEAD_BYTES + idLength + DIGEST_BYTES > bytes.length) {
        torn = true;
        break;
      }
      const entry: CheckpointEntry = {
        recordStart: Number(bytes.readBigUInt64BE(at)),
        seq: Number(bytes.readBigUInt64BE(at + 8)),
        iat: Number(bytes.readBigUInt64BE(at + 16)),
        length: bytes.readUInt32BE(at + 24),
        idLength,
        id: bytes.subarray(at + SIDECAR_ENTRY_HEAD_BYTES, at + SIDECAR_ENTRY_HEAD_BYTES + idLength).toString('utf8'),
        digest: Buffer.from(bytes.subarray(at + SIDECAR_ENTRY_HEAD_BYTES + idLength, at + SIDECAR_ENTRY_HEAD_BYTES + idLength + DIGEST_BYTES)),
      };
      at += SIDECAR_ENTRY_HEAD_BYTES + idLength + DIGEST_BYTES;
      // Records are contiguous in the file and their chain positions are consecutive, because both are
      // the order the store appended them in. An index that describes anything else describes a file it
      // never read.
      const before = block.at(-1) ?? last;
      if (before === undefined ? entry.seq !== 0 : entry.recordStart !== endOfEntry(before) || entry.seq !== before.seq + 1) {
        return null;
      }
      block.push(entry);
    }
    if (torn || at + DIGEST_BYTES > bytes.length) {
      // A block whose check never arrived says nothing: its records are past the checkpoint and are read
      // out of the store file, which is the other thing an index is not trusted for.
      break;
    }
    const check = Buffer.from(bytes.subarray(at, at + DIGEST_BYTES));
    at += DIGEST_BYTES;
    const end = block.at(-1);
    if (
      end === undefined ||
      !blockCheck(previous, bytes.subarray(bodyStart, at - DIGEST_BYTES)).equals(check) ||
      claimed !== endOfEntry(end) ||
      claimed > fileSize
    ) {
      return null;
    }
    for (const entry of block) {
      scan.records.set(entry.id, locationOf(entry));
    }
    first ??= block[0];
    last = end;
    previous = check;
    checkpointBytes = claimed;
    whole = at;
  }
  // An index with nothing in it is not worth an opening's time: what it speaks for is a file with no
  // receipts in it, which is the cheapest walk there is.
  if (first === undefined || last === undefined) {
    return null;
  }
  if (whole < bytes.length) {
    // The block that never finished sits behind the checkpoint. Cutting it off first is what lets the
    // next appended block chain from the last whole one.
    await truncate(path, whole).catch(() => undefined);
  }

  // What the index supplied is the receipts. The run in front of them, and the record the checkpoint
  // ends on, come from the store file, because those are the two facts an index cannot vouch for.
  try {
    // The run is read from the file rather than taken from the index, so the seam an opening reports is
    // the one the trim records state and not the one the index was last told.
    const run = emptyScan();
    parseRecords(await readSpan(file, 0, first.recordStart), 0, run, null);
    if (run.seq !== 0 || run.records.size !== 0 || run.trimRunEnd !== first.recordStart) {
      return null;
    }
    // The record the checkpoint ends on, hashed as though it were about to be served. This is the tie
    // between the index and the bytes, and without it a store file rewritten through its own name
    // would answer out of an index that was written for what used to be there.
    await readReceipt(file, locationOf(last), last.id);
    scan.trims.push(...run.trims);
    scan.anchor = run.anchor;
    scan.trimRunEnd = run.trimRunEnd;
  } catch {
    return null;
  }

  scan.expectedPrev = last.digest;
  scan.lastDigest = last.digest;
  scan.seq = last.seq + 1;
  scan.end = checkpointBytes;
  return { scan, checkpointBytes, previous };
}

/**
 * Reads what the store file holds, from the index where the index speaks for it and from the file where
 * it does not, and leaves the index speaking for the whole of the file either way.
 */
async function readStore(path: string, file: FileHandle, sidecar: SidecarState | null): Promise<StoreState> {
  const stats = await file.stat();
  const identity = serialOf(stats);
  if (sidecar !== null) {
    const loaded = await loadSidecar(file, sidecar.path, identity, stats.size);
    if (loaded !== null) {
      try {
        const tail: CheckpointEntry[] = [];
        const bytes = await readSpan(file, loaded.checkpointBytes, stats.size - loaded.checkpointBytes);
        parseRecords(bytes, loaded.checkpointBytes, loaded.scan, tail);
        if (loaded.scan.end < stats.size) {
          await truncate(path, loaded.scan.end);
        }
        sidecar.previous = loaded.previous;
        sidecar.pending = tail;
        await flushSidecar(sidecar);
        return stateOf(loaded.scan, identity);
      } catch {
        // Past the checkpoint the file answers for itself, and a tail that cannot be read is read again
        // from the first byte rather than refused: the store file is the authority here.
      }
    }
  }
  const entries: CheckpointEntry[] = [];
  const state = await walk(path, file, sidecar === null ? null : entries);
  if (sidecar !== null) {
    await writeSidecar(sidecar, identity, entries);
  }
  return state;
}

/** Opens the store file, creating it when absent, and closes it once the reading is done. */
async function scan(path: string, sidecar: SidecarState | null): Promise<StoreState> {
  const file = await open(path, 'a+');
  try {
    return await readStore(path, file, sidecar);
  } finally {
    await file.close();
  }
}

/** The ids each bound of a retention policy retired, kept apart because the cause is the report. */
interface Retirement {
  readonly byAge: string[];
  readonly byCount: string[];
}

/**
 * The receipts a retention policy retires, which are always a prefix of the chain.
 *
 * Membership is the policy's: everything older than the window, then the oldest-dated of what is
 * left until the count cap fits. The shape is the chain's: a hash chain tolerates losing a prefix
 * and nothing else, so the retirement walks the records in the order they were chained and stops
 * at the first one the policy would keep.
 *
 * That stop is the whole reason a stamp taken out of order cannot cost a receipt. Retiring a
 * record in the middle of the chain leaves the hole the chain exists to make visible, and no
 * reader could tell it apart from someone deleting evidence. Holding a receipt past its window by
 * the skew of its neighbours is the same rule's cost, and it falls on the side that keeps data.
 */
function retire(
  entries: Iterable<readonly [string, { iat: number; seq: number }]>,
  retention: ReceiptRetention | undefined,
  now: number,
): Retirement {
  const byAge: string[] = [];
  const byCount: string[] = [];
  if (retention === undefined) {
    return { byAge, byCount };
  }
  const cutoff = retention.maxAgeSeconds === undefined ? Number.NEGATIVE_INFINITY : now - retention.maxAgeSeconds;
  const aged = new Set<string>();
  const live: [string, number][] = [];
  for (const [id, where] of entries) {
    if (where.iat < cutoff) {
      aged.add(id);
    } else {
      live.push([id, where.iat]);
    }
  }
  // Sorted by stamp rather than by chain position because the cap is a statement about how many
  // receipts are served, and the ones it gives up on are the ones the window covers least.
  const capped = new Set<string>();
  const max = retention.maxCount;
  if (max !== undefined) {
    live.sort((a, b) => a[1] - b[1]);
    for (const [id] of live.slice(0, Math.max(0, live.length - max))) {
      capped.add(id);
    }
  }
  const prefix = [...entries].sort((a, b) => a[1].seq - b[1].seq);
  for (const [id] of prefix) {
    if (aged.delete(id)) {
      byAge.push(id);
    } else if (capped.delete(id)) {
      byCount.push(id);
    } else {
      break;
    }
  }
  return { byAge, byCount };
}

/**
 * Applies the policy to the index and tallies what fell out of it. Dropping from the index is what
 * makes a receipt unserved; the bytes stay in the file until a compaction takes them, which is the
 * only rewrite this store ever performs.
 *
 * The tally is held here rather than left to the trim run because retirement and compaction are not
 * the same moment: a reader asking what the store retired has to get an answer in between.
 */
function prune(state: StoreState, retention: ReceiptRetention | undefined, now: number): void {
  const { byAge, byCount } = retire(state.records, retention, now);
  for (const id of byAge) {
    state.records.delete(id);
  }
  for (const id of byCount) {
    state.records.delete(id);
  }
  state.dropped.byAge += byAge.length;
  state.dropped.byCount += byCount.length;
}

/** A span the file's own indexing claims is there. A short read is a failure, never a short file. */
async function readRange(file: FileHandle, length: number, position: number): Promise<Buffer> {
  const buffer = Buffer.alloc(length);
  const { bytesRead } = await file.read(buffer, 0, length, position);
  if (bytesRead !== length) {
    throw new Error(`store file ended ${length - bytesRead} bytes short of the span its index claims`);
  }
  return buffer;
}

/**
 * Rewrites the file as its own trim run, one more trim record, and the receipts retention kept.
 *
 * It runs only when the dead prefix outweighs the live tail, which amortizes the copy across many
 * appends instead of paying it on every one. Because it drops a prefix, no surviving record's
 * digest changes and the head the next pack publishes is the head before it.
 *
 * What the rewrite cannot do is keep the chain honest about the records it removed, which is why it
 * says so in a record rather than leaving a hole for a reader to explain. The run is copied rather
 * than rewritten so every retirement the file has ever made stays in it and chained: a store that
 * replaced its trim record on each compaction would forget the reason for all of the earlier ones
 * the moment it reset the counter they were counted with.
 *
 * `releaseHeld` puts down every read handle a walk is holding, and it has to happen before the
 * rename: a volume refuses to move a file over one a handle still reads, and a volume that allowed
 * it would leave that handle answering from the bytes that used to be there while the index had
 * already moved to the new ones.
 *
 * The index beside the file is rewritten by the reading that follows the move, which is the right
 * direction for it to be invalidated in: the new file is a different file by the volume's own answer,
 * so an opening that came after this one finds an index that does not name it and re-derives the chain
 * from the run of trim records this one just appended.
 */
async function compact(
  path: string,
  state: StoreState,
  trimmedAt: number,
  retention: ReceiptRetention | undefined,
  releaseHeld: () => Promise<void>,
  sidecar: SidecarState | null,
): Promise<void> {
  let first = state.size;
  for (const where of state.records.values()) {
    first = Math.min(first, where.recordStart);
  }
  const dead = first;
  if (dead === state.trimRunEnd || dead <= state.size - dead) {
    return;
  }
  const file = await open(path, 'r');
  let run: Buffer;
  let tail: Buffer;
  try {
    run = await readRange(file, state.trimRunEnd, 0);
    tail = await readRange(file, state.size - dead, dead);
  } finally {
    await file.close();
  }
  // The digest the retained chain starts from: the first surviving record names it in its own
  // prev, and a fully retired file names the last record the file held.
  const seam =
    tail.length === 0
      ? state.head
      : tail.subarray(FRAME_LEN_BYTES + KIND_BYTES, FRAME_LEN_BYTES + KIND_BYTES + PREV_BYTES);
  // A trim follows the file rather than the chain, so it names whatever byte sits in front of it.
  const prev = run.length === 0 ? new Uint8Array(PREV_BYTES) : run.subarray(run.length - DIGEST_BYTES);
  const trimmed = Buffer.concat([
    run,
    encodeTrimRecord({
      prev,
      at: trimmedAt,
      seam,
      byAge: state.dropped.byAge,
      byCount: state.dropped.byCount,
      maxAgeSeconds: retention?.maxAgeSeconds ?? 0,
      maxCount: retention?.maxCount ?? 0,
    }),
    tail,
  ]);
  // Written beside the file and moved over it, so an interrupted compaction leaves the
  // pre-compaction store intact rather than half a store.
  const temp = `${path}.compacting`;
  const out = await open(temp, 'w');
  try {
    await out.writeFile(trimmed);
    await out.sync();
  } finally {
    await out.close();
  }
  // Every handle a walk is holding goes down before the move. A volume refuses to move a file over
  // one an open handle still reads, so this is what keeps a compaction possible while a caller is
  // mid-window, and a volume that allowed it would leave that handle answering from the bytes that
  // used to be there while the index below had already moved to the new offsets.
  await releaseHeld();
  await rename(temp, path);
  const recovered = await scan(path, sidecar);
  state.records = recovered.records;
  state.head = recovered.head;
  state.size = recovered.size;
  state.identity = recovered.identity;
  state.nextSeq = recovered.nextSeq;
  state.trimRunEnd = recovered.trimRunEnd;
  state.anchor = recovered.anchor;
  state.trims = recovered.trims;
  state.dropped = { byAge: 0, byCount: 0 };
}

/**
 * The retained set as a retention manifest states it: inclusive bounds and a count. Zero bounds
 * mean nothing is retained, and the count is what says so.
 */
function windowOf(retained: Iterable<{ iat: number }>): RetainedWindow {
  let from = Number.POSITIVE_INFINITY;
  let to = Number.NEGATIVE_INFINITY;
  let count = 0;
  for (const where of retained) {
    from = Math.min(from, where.iat);
    to = Math.max(to, where.iat);
    count += 1;
  }
  return count === 0 ? { from: 0, to: 0, count: 0 } : { from, to, count };
}

/**
 * How many receipts it takes to hold a window of `maxAgeSeconds` at the rate a store's own retained
 * receipts measure, or null when those receipts measure nothing.
 *
 * The rate is read off the records a store holds because that is the only issuance rate this package
 * has. Nothing here is told how many completions a deployment serves, and a number written into this
 * file would be one whoever edited it last chose, which is how a bound on storage comes to be read as a
 * promise about time. Two stamps and the receipts between them are a measurement: the count over the
 * span they cover is the rate, and a window holds that many receipts for every second it is asked to
 * hold, plus the one stamped at its older edge.
 *
 * The span is the source's, so it is read through the source. Two of its own readings a bound apart are
 * not a span of the distance between them: the true distance is smaller by up to twice the bound, and a
 * smaller span is a faster rate and a larger count, so the count this derives is the one the pairing
 * supports rather than the one the two numbers print. A source carrying no bound has nothing to narrow
 * by, and the count it derives is then a reading of the stamps and not a measurement, which every report
 * that names it has to say. `HOST_CLOCK_SOURCE` is that case, and it is the shipped one.
 *
 * A span no wider than the source can resolve is read as one second rather than as a rate of infinity,
 * which is the oldest state of this rule and the same decision: receipts sharing an instant, or close
 * enough to one for the source to be unable to tell, is the fastest traffic a file can report, so the
 * count derived from it is the smallest one a refusal could rest on, and possibly far fewer than truth.
 *
 * Null is not a pass. It says there is nothing to measure, either because fewer than two receipts have
 * ever been filed or because no period was configured, and a store that has measured nothing of its
 * own traffic cannot be refused for holding less than it was asked to.
 */
export function receiptsNeededForWindow(
  maxAgeSeconds: number,
  held: RetainedWindow,
  source: TimeSource = HOST_CLOCK_SOURCE,
): number | null {
  if (maxAgeSeconds <= 0 || held.count < 2) {
    return null;
  }
  return Math.ceil(((held.count - 1) * maxAgeSeconds) / measurableSpanSeconds(held, source)) + 1;
}

/**
 * The span a store's two end stamps support, in seconds, narrowed by whatever its source declares and
 * never below one. This is the denominator the rate above is taken over, so it is where a bound enters
 * the arithmetic: a source that can be away by seconds narrows what its own two readings can claim, and
 * a source nobody measured claims the distance printed.
 *
 * Exported beside `receiptsNeededForWindow` for the same reason that one is: a refusal that quotes a span
 * has to quote the span the count was derived over, and a second copy of this line where the sentence is
 * written would drift from the number the operator is told to raise.
 */
export function measurableSpanSeconds(held: RetainedWindow, source: TimeSource): number {
  const apart = readingsApart(source, held.from, held.to);
  return Math.max(apart.apartSeconds - (apart.state === 'unmeasured' ? 0 : apart.resolutionSeconds), 1);
}

/**
 * The source as a refusal names it, with the bound it declared or the sentence that there is none. An
 * operator raising a count has to know which of the two the number was derived under, because the same
 * stamps give a wider need under a measured bound than under one nobody took. Exported because the
 * admission refusal in `server.ts` quotes the same span and must not re-derive the wording.
 */
export function sourceSentence(declared: StampDeclaration): string {
  const bound = declared.uncertaintySeconds;
  if (bound === null) {
    return `the source named ${declared.name}, on which nobody measured an uncertainty`;
  }
  return (
    `the source named ${declared.name}, whose readings can each be away from the instant they name by ` +
    `${String(bound)} seconds, so two of its own readings resolve no distance above ` +
    `${String(PAIRWISE_FACTOR * bound)} seconds`
  );
}

/**
 * Refuses an opening where the durability bound cannot hold the period the same configuration asks for.
 *
 * Three conditions keep this from refusing a deployment that is simply quiet. A policy bounded only by
 * count, or only by a period, has no pairing to contradict and is never checked here. A retained set
 * below its durability bound is keeping everything its period asked for, however few receipts that
 * turned out to be: nothing is being shed, and the traffic that would decide the question has not
 * arrived. And a store at its durability bound whose stamps do span the configured period holds what it
 * asked for at the rate it has been carrying, so it starts.
 *
 * That leaves the case this is for: a store at its durability bound whose retained stamps span less time
 * than the period it was configured with, which means the bound is what cut the window short and the
 * next receipt will cut it shorter. The count that pairing needs is derived above from the configured
 * period and the traffic this file has actually carried, so the refusal names two quantities that
 * disagree rather than repeating a number an operator could raise until the message went away, and it
 * names the shortfall as well so the number to set is readable off the line rather than worked out.
 *
 * The comparison is with the durability bound alone, which is the case a deployment that configures
 * both counts can now ask for and the one the split was for. A single number used to be both how much
 * the file keeps and how much one query holds, so one sentence covered two quantities and an operator
 * could raise either and read the same message. A serving bound cannot shorten a window, because it
 * retires nothing and a walk over a wider window is simply answered in more batches, so it is refused
 * here never: the message says which of the two is short, and when a serving bound is configured it
 * says that that one is not the number to raise.
 *
 * A store that starts has not kept anything for anyone. This compares a period with a count, and whether
 * a period is owed, to whom, and for how long, is not a question this file holds the facts to answer.
 */
function assertWindowHeldable(
  retention: ReceiptRetention | undefined,
  serving: ReceiptServing | undefined,
  held: RetainedWindow,
): void {
  const maxAgeSeconds = retention?.maxAgeSeconds;
  const maxCount = retention?.maxCount;
  if (maxAgeSeconds === undefined || maxCount === undefined || held.count !== maxCount) {
    return;
  }
  const source = retention?.time ?? HOST_CLOCK_SOURCE;
  const needed = receiptsNeededForWindow(maxAgeSeconds, held, source);
  if (needed === null || needed <= maxCount) {
    return;
  }
  const maxServed = serving?.maxServedReceipts;
  throw new StoreError(
    'RETENTION_WINDOW_UNHOLDABLE',
    `this store is at its durability bound of ${String(maxCount)} receipts and they span ` +
      `${String(held.to - held.from)} seconds as read from ${sourceSentence(source)}, which leaves ` +
      `${String(measurableSpanSeconds(held, source))} of those seconds this store can derive a rate from, while ` +
      `the configured period is ${String(maxAgeSeconds)} seconds, which takes ${String(needed)} receipts ` +
      `at the rate this store has been carrying: the durability bound is short by ` +
      `${String(needed - maxCount)} receipts` +
      // Two counts on one screen is the moment an operator needs to know which one the sentence is
      // about, because raising the serving bound changes what a query holds and nothing about what the
      // file keeps.
      (maxServed === undefined
        ? ''
        : `, and the serving bound of ${String(maxServed)} receipts is not the number to raise`),
  );
}

/**
 * How many records a walk holds at a time: the serving bound when it is one that can be counted, and
 * the whole matched window otherwise. Nothing here is told what a batch costs, so a bound that is not
 * a positive whole number of records is read as no bound rather than as an instruction to hold
 * nothing, which would be a way for a configuration to stop a query serving receipts at all.
 */
function batchLimit(maxServedReceipts: number | undefined): number {
  return maxServedReceipts !== undefined && Number.isInteger(maxServedReceipts) && maxServedReceipts > 0
    ? maxServedReceipts
    : Number.POSITIVE_INFINITY;
}

/**
 * The records a range walk serves, in the order they were chained, in batches no larger than the
 * serving bound.
 *
 * The interval is the policy's, because a window is a statement about time. The order is the
 * chain's, because a reader recomputing a digest per receipt has to visit them the way the store
 * did, and two stamps taken out of order are still one record after the other.
 *
 * `snapshot` is the index as it stood when the walk was asked for and `through` is the position the
 * next record would have taken at that moment. Those two fix membership the way a copied list of the
 * matched records did, which is what a walk over a store that is still issuing receipts owes, because
 * a receipt issued halfway through belongs to the next window: one written after the call sits at or
 * past `through`, and one retired while the walk runs is answered by the live index and not by this
 * snapshot. What they leave out is the copy, so the walk holds a batch of positions at a time instead
 * of the whole retained window, and hands over the same receipts either way.
 *
 * Exported for the same reason `receiptsNeededForWindow` is: the rule a walk batches by has to be
 * checkable at the numbers rather than inferred from a result set that is deliberately identical either
 * way, and a second copy of it in a test would drift from the one that decides. It is not part of what
 * the package entry point hands out, which is the store contract and nothing else.
 */
export function* servedBatches<T extends { iat: number; seq: number }>(
  snapshot: Iterable<readonly [string, T]>,
  from: number,
  to: number,
  through: number,
  maxServedReceipts: number | undefined,
): Generator<readonly (readonly [string, T])[]> {
  const limit = batchLimit(maxServedReceipts);
  let batch: (readonly [string, T])[] = [];
  for (const entry of snapshot) {
    // Skipped rather than stopped at, because a batch is ordered before it is handed over: the index
    // runs in chain order except where a caller re-filed an id it had already used, which keeps that
    // record's old place in the index and gives it a new position in the chain.
    if (entry[1].seq >= through) continue;
    if (entry[1].iat < from || entry[1].iat >= to) continue;
    batch.push(entry);
    if (batch.length >= limit) {
      yield chained(batch);
      batch = [];
    }
  }
  if (batch.length > 0) {
    yield chained(batch);
  }
}

/** A batch in the order the records were chained, which is the order a reader has to walk them in. */
function chained<T extends { seq: number }>(
  batch: (readonly [string, T])[],
): readonly (readonly [string, T])[] {
  return batch.sort((a, b) => a[1].seq - b[1].seq);
}

/**
 * Reads one record at the position the index claims and checks the bytes against the index before
 * handing them over.
 *
 * The frame is read whole rather than just its payload, because the digest a record carries covers
 * its kind, its predecessor, its stamp and its id as well as the payload, and those are exactly the
 * bytes a reader cannot re-derive from a payload that has been swapped. A foreign store built from the
 * same ids at the same stamps self-verifies record by record, so a digest recomputed and thrown away
 * proves nothing: what makes the check bite is that it is compared with the digest this index read off
 * this record, which is a fact about the indexed file rather than about the file that answered now.
 *
 * A short read is a failure rather than a miss: the index and the file then disagree about what is
 * stored, and serving a truncated receipt would hand a client bytes that cannot verify.
 */
async function readReceipt(file: FileHandle, where: Location, id: string): Promise<Uint8Array> {
  const payloadAt = where.offset - where.recordStart;
  const frame = Buffer.alloc(payloadAt + where.length + DIGEST_BYTES);
  const { bytesRead } = await file.read(frame, 0, frame.length, where.recordStart);
  if (bytesRead !== frame.length) {
    throw new Error(`store file ended ${String(frame.length - bytesRead)} bytes short of the span its index claims`);
  }
  const recomputed = Buffer.from(sha256(frame.subarray(FRAME_LEN_BYTES, frame.length - DIGEST_BYTES)));
  if (!recomputed.equals(where.digest) || !frame.subarray(payloadAt + where.length).equals(where.digest)) {
    throw new Error(
      `receipt ${id} is indexed at byte ${String(where.recordStart)} of the store file, which does not hold the record that index was read from, so its bytes are not safe to serve`,
    );
  }
  return frame.subarray(payloadAt, payloadAt + where.length);
}

/** The read handle one range walk holds, empty until the walk reads its first record. */
interface WalkHandle {
  file: FileHandle | null;
}

/** Puts a walk's handle down, once. A read that arrives afterwards opens the file again. */
async function putDown(walk: WalkHandle): Promise<void> {
  const file = walk.file;
  walk.file = null;
  if (file !== null) {
    await file.close();
  }
}

/**
 * One record's bytes, through the handle the walk holding this record is holding.
 *
 * Two questions get answered before a byte is taken, and they are different questions. Which file is
 * this handle on is answered by the volume's pair, and it has to be answered first: a compaction
 * moves a new file over the path while a walk is parked, and a walk that kept reading the file it had
 * open would be reading bytes no index describes any more, so the handle goes down, the path is
 * opened again, and the walk carries on from the file the index moved to. Which bytes are there is
 * answered by `readReceipt`, and it is the question the pair cannot answer: a replacement that
 * arrives at this path can carry the number the indexed file carried, at the same length, with nothing
 * but the receipts different.
 *
 * Opening afresh is not the same as the file the index describes, so a handle that still disagrees
 * with the index after the reopen means the index and the path disagree about which file the receipts
 * are in at all, and the record is refused rather than read out of a file nothing indexed. A refusal
 * is a worse answer than a short one for a caller that only wanted this receipt, and it is the better
 * answer for a store that cannot say which of its positions are still true.
 */
async function readServed(
  walk: WalkHandle,
  state: StoreState,
  path: string,
  where: Location,
  id: string,
): Promise<Uint8Array> {
  const held = walk.file;
  if (held !== null && serialOf(await held.stat()) === state.identity) {
    return readReceipt(held, where, id);
  }
  await putDown(walk);
  walk.file = await open(path, 'r');
  if (serialOf(await walk.file.stat()) !== state.identity) {
    throw new Error(
      `receipt store file ${path} is not the file its index was read from, so receipt ${id} has no position that is safe to read`,
    );
  }
  return readReceipt(walk.file, where, id);
}

/**
 * Reads one record at the position the index claims, opening the file for the read.
 *
 * A single record has no other record to share an open with, so this is the shape that holds no
 * handle between operations and costs nothing extra for that. A walk of many records holds one handle
 * for its own length instead, and `readServed` is what makes that safe to do. Either way the bytes
 * come back through `readReceipt`, so neither path answers out of a file the index was not built from.
 */
async function readAt(path: string, where: Location, id: string): Promise<Uint8Array> {
  const file = await open(path, 'r');
  try {
    return await readReceipt(file, where, id);
  } finally {
    await file.close();
  }
}

export async function openFileReceiptStore(options: FileReceiptStoreOptions): Promise<ReceiptStore> {
  const path = join(options.dir, RECEIPT_STORE_FILE);
  const retention = options.retention;
  const serving = options.serving;
  const source = retention?.time ?? HOST_CLOCK_SOURCE;
  // Floored here as well as at the issuance seam: a stamp is a whole second, and a record layout with an
  // 8-byte unsigned field has no spelling for anything else.
  const now = (): number => Math.floor(source.now());
  // Nothing else is read from this object but its path, so declining the index is exactly a store with
  // one file in its directory: no read, no write, no answer that the walk could not have given.
  const sidecar: SidecarState | null =
    options.sidecarIndex === false ? null : { path: join(options.dir, RECEIPT_SIDECAR_FILE), previous: null, pending: [] };
  const state = await scan(path, sidecar);
  // A deployment that was down over a weekend has aged receipts on disk it must not serve.
  prune(state, retention, now());
  // What a file can serve is known once it has been read and pruned, and this is the last moment a
  // refusal is cheap: no receipt has been served from it and no caller is holding an id. The in-process
  // engine has no equivalent call because it is empty when it is constructed, and a store that has never
  // issued a receipt has measured nothing of its own traffic.
  assertWindowHeldable(retention, serving, windowOf(state.records.values()));

  /**
   * One operation touches the file at a time, which is the whole of the concurrency control.
   * Two completions issuing receipts simultaneously otherwise both encode the head the first one
   * has not yet moved, and the file ends up with two records naming the same predecessor. Reads
   * queue for the same reason from the other side: a compaction renames a file whose records sit
   * at different offsets than the index a read resolved a moment ago.
   */
  let queue: Promise<unknown> = Promise.resolve();
  function serialized<T>(work: () => Promise<T>): Promise<T> {
    const result = queue.then(work, work);
    // A refusal belongs to the caller that got it, never to the queue behind it.
    queue = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }

  /**
   * The handle each walk in flight is reading through. Walks are registered here rather than holding
   * one handle between them because a walk that has been asked for and abandoned must not be the
   * reason another walk keeps a file open, and because a compaction needs all of them: it replaces
   * the file, and a handle that outlives that is a reader on a file nothing points at.
   */
  const walks = new Set<WalkHandle>();

  /** Puts down every handle a walk is holding, which is what makes a rename over the path possible. */
  async function putDownWalks(): Promise<void> {
    for (const walk of walks) {
      await putDown(walk);
    }
  }

  return {
    put(id: string, receipt: Uint8Array, iat: number): Promise<void> {
      return serialized(async () => {
        const record = encode(KIND_RECEIPT, state.head, iat, id, receipt);
        // An append handle with no offset, so it has to be the only one in flight.
        const file = await open(path, 'a');
        try {
          await file.writeFile(record.frame);
          // The claim this store exists for is that a receipt outlives the process that wrote
          // it, and a write still sitting in the page cache does not survive the machine too.
          await file.sync();
        } finally {
          await file.close();
        }
        // Nothing was retained, so this record is the oldest one and its predecessor is the anchor
        // a reader starts from. Once a set exists it only ever grows at the back.
        const entry: CheckpointEntry = {
          recordStart: state.size,
          seq: state.nextSeq++,
          iat,
          id,
          idLength: Buffer.byteLength(id, 'utf8'),
          length: receipt.length,
          // The writer records what it wrote, so a served read has something other than the volume's
          // number to compare the bytes it is about to hand over against.
          digest: record.digest,
        };
        if (state.records.size === 0) {
          state.anchor = state.head;
        }
        state.records.set(id, locationOf(entry));
        state.head = record.digest;
        state.size += record.frame.length;
        // Told to the index before retention is applied, because the index speaks for the records the
        // file holds: a receipt that retirement drops out of the served set is still bytes in the file
        // until a compaction says otherwise, and an opening that re-derives the file would index it.
        await noteEntry(sidecar, entry);
        prune(state, retention, now());
        await compact(path, state, now(), retention, putDownWalks, sidecar);
      });
    },

    get(id: string): Promise<Uint8Array | null> {
      return serialized(async () => {
        const found = state.records.get(id);
        return found === undefined ? null : readAt(path, found, id);
      });
    },

    range(from: number, to: number): AsyncIterable<StoredReceipt> {
      // Membership is fixed at the call by the index that exists now and the position the next record
      // would take, which is the promise a walk over a store that is still issuing receipts owes. See
      // `servedBatches` for what the two leave out, which is the copy of the matched list: a store
      // keeping more receipts than one query may hold answers a walk over all of them regardless.
      const snapshot = state.records;
      const through = state.nextSeq;
      return {
        async *[Symbol.asyncIterator](): AsyncIterator<StoredReceipt> {
          // One handle for the walk and nothing longer: opened by the first record this walk reads and
          // put down when the walk ends, whether it ended by running out of receipts or by being
          // abandoned. A caller sweeping a wide window pays the open once instead of once per record,
          // which is the cost this path was measured at, and the window in which a rewrite finds
          // itself waiting on a reader is the walk's own length rather than the life of the store.
          const walk: WalkHandle = { file: null };
          walks.add(walk);
          try {
            for (const batch of servedBatches(snapshot, from, to, through, serving?.maxServedReceipts)) {
              // Only the bytes are read late, one queued operation at a time. A walk that held the
              // queue for its whole length would be a way to stop serving receipts by generating a pack
              // about them.
              for (const [id, where] of batch) {
                const receipt = await serialized(async () => {
                  // The position comes from the live index, and the handle comes from `readServed`,
                  // which only answers from the file that index was read from: a compaction that ran
                  // while this walk was parked moved both.
                  const still = state.records.get(id);
                  return still === undefined ? null : await readServed(walk, state, path, still, id);
                });
                // Retired by retention while this walk ran, which the window has already said it kept.
                if (receipt !== null) {
                  yield { id, iat: where.iat, receipt, claim: windowClaim(source, where.iat, from, to) };
                }
              }
            }
          } finally {
            walks.delete(walk);
            await putDown(walk);
          }
        },
      };
    },

    async window(): Promise<RetainedWindow> {
      return windowOf(state.records.values());
    },

    async head(): Promise<Uint8Array> {
      return new Uint8Array(state.head);
    },

    timeSource(): StampDeclaration {
      return { name: source.name, uncertaintySeconds: source.uncertaintySeconds };
    },

    async chainState(): Promise<ChainState> {
      return {
        anchor: new Uint8Array(state.records.size === 0 ? state.head : state.anchor),
        retired: {
          byAge: state.trims.reduce((total, trim) => total + trim.byAge, state.dropped.byAge),
          byCount: state.trims.reduce((total, trim) => total + trim.byCount, state.dropped.byCount),
          trims: [...state.trims],
        },
      };
    },
  };
}

/**
 * The same interface with nothing behind it but the process, which is what `--mock` and every
 * test that is not about durability asks for. It chains exactly as the file engine does, so
 * `head()` means one thing across both, and a restart takes it back to the empty digest because
 * there is nowhere else for it to live.
 */
export function openMemoryReceiptStore(options: {
  readonly retention?: ReceiptRetention;
  readonly serving?: ReceiptServing;
} = {}): ReceiptStore {
  const retention = options.retention;
  const serving = options.serving;
  const source = retention?.time ?? HOST_CLOCK_SOURCE;
  // The same whole-second floor the file store reads a source through, so the two stores age a record
  // at the same instant when handed the same source and the same period.
  const now = (): number => Math.floor(source.now());
  const entries = new Map<string, { iat: number; seq: number; prev: Uint8Array; receipt: Uint8Array }>();
  let chainHead: Uint8Array = new Uint8Array(PREV_BYTES);
  let chainSeq = 0;
  let retiredByAge = 0;
  let retiredByCount = 0;

  return {
    async put(id, receipt, iat) {
      const prev = chainHead;
      chainHead = encode(KIND_RECEIPT, chainHead, iat, id, receipt).digest;
      entries.set(id, { iat, seq: chainSeq++, prev, receipt });
      const retired = retire(entries, retention, now());
      for (const doomed of [...retired.byAge, ...retired.byCount]) {
        entries.delete(doomed);
      }
      retiredByAge += retired.byAge.length;
      retiredByCount += retired.byCount.length;
    },

    async get(id) {
      return entries.get(id)?.receipt ?? null;
    },

    range(from, to) {
      // The same promise the file engine makes: the set is fixed when the walk is asked for, and the
      // serving bound sizes what the walk holds rather than what it serves.
      const snapshot = entries;
      const through = chainSeq;
      return {
        async *[Symbol.asyncIterator](): AsyncIterator<StoredReceipt> {
          for (const batch of servedBatches(snapshot.entries(), from, to, through, serving?.maxServedReceipts)) {
            for (const [id, where] of batch) {
              yield {
                id,
                iat: where.iat,
                receipt: where.receipt,
                claim: windowClaim(source, where.iat, from, to),
              };
            }
          }
        },
      };
    },

    async window() {
      return windowOf(entries.values());
    },

    async head() {
      return new Uint8Array(chainHead);
    },

    timeSource(): StampDeclaration {
      return { name: source.name, uncertaintySeconds: source.uncertaintySeconds };
    },

    async chainState(): Promise<ChainState> {
      // The first item a reader would walk, in the order it would walk it: starting anywhere else
      // means the digests recompute to a head this store never had. The lowest chain position still
      // retained is that item, and it is the position rather than the stamp that decides, because two
      // stamps taken out of order are still one record after the other.
      let oldestPrev: Uint8Array | undefined;
      let oldestSeq = Number.POSITIVE_INFINITY;
      for (const where of entries.values()) {
        if (where.seq < oldestSeq) {
          oldestSeq = where.seq;
          oldestPrev = where.prev;
        }
      }
      return {
        anchor: new Uint8Array(oldestPrev ?? chainHead),
        retired: { byAge: retiredByAge, byCount: retiredByCount, trims: [] },
      };
    },
  };
}
