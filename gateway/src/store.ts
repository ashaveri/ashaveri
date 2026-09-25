import { open, rename, truncate, type FileHandle } from 'node:fs/promises';
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
 */

/** The file a deployment backs up. Named because an operator needs to know which one it is. */
export const RECEIPT_STORE_FILE = 'receipts.log';

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

/** Where one receipt sits in the file. */
interface Location {
  readonly iat: number;
  /** This record's position in the chain, which is the order a reader has to walk it in. */
  readonly seq: number;
  /** The byte the record's length prefix starts at, so dead space is measurable. */
  readonly recordStart: number;
  readonly offset: number;
  readonly length: number;
}

interface StoreState {
  records: Map<string, Location>;
  /** The digest the next appended receipt names as its predecessor. */
  head: Buffer;
  size: number;
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
  /** Injectable because a six month window is otherwise only testable by waiting. */
  readonly now?: () => number;
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
}

/** One retained receipt as the store hands it out: what to check, and when it was issued. */
export interface StoredReceipt {
  readonly id: string;
  readonly iat: number;
  readonly receipt: Uint8Array;
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

/** Opens the store file, creating it when absent, and closes it once the walk is done. */
async function scan(path: string): Promise<StoreState> {
  const file = await open(path, 'a+');
  try {
    return await walk(path, file);
  } finally {
    await file.close();
  }
}

/**
 * Reads every complete record and checks that they chain.
 *
 * A trailing partial record is repaired rather than failed: it is what an append interrupted by
 * a crash leaves behind, and it can never verify because its bytes never all arrived. Left in
 * place it would cost more than the one record it is, because the walk stops where it cannot
 * read and so hides every record appended after it. Dropping it costs a receipt nobody was
 * given the id for.
 */
async function walk(path: string, file: FileHandle): Promise<StoreState> {
  const bytes = await file.readFile();
  const records = new Map<string, Location>();
  const trims: TrimEvent[] = [];
  // What a record's predecessor slot has to hold. A receipt follows the chain, so it names the
  // digest of the record before it; a trim follows the file, so it names the digest of whatever
  // byte lies in front of it, which is the previous trim or nothing at all.
  let lastDigest = Buffer.alloc(PREV_BYTES);
  let expectedPrev = Buffer.alloc(PREV_BYTES);
  let anchor = expectedPrev;
  let offset = 0;
  let seq = 0;
  let trimRunEnd = 0;
  while (offset + FRAME_LEN_BYTES <= bytes.length) {
    const length = bytes.readUInt32BE(offset);
    const body = offset + FRAME_LEN_BYTES;
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
      throw new StoreError('STORE_CHAIN_BROKEN', `receipt store chain is broken at byte ${offset}: a record claims a frame ${length} bytes long, which is too short to hold its own header`);
    }
    const idLength = bytes.readUInt16BE(body + KIND_BYTES + PREV_BYTES + IAT_BYTES);
    const idStart = body + HEADER_BYTES;
    const payloadStart = idStart + idLength;
    const payloadEnd = end - DIGEST_BYTES;
    if (payloadStart > payloadEnd) {
      throw new StoreError('STORE_CHAIN_BROKEN', `receipt store chain is broken at byte ${offset}: a record's ${idLength} byte id does not fit inside its own frame`);
    }
    const kind = bytes.readUInt8(body);
    const prev = bytes.subarray(body + KIND_BYTES, body + KIND_BYTES + PREV_BYTES);
    const iat = Number(bytes.readBigUInt64BE(body + KIND_BYTES + PREV_BYTES));
    const digest = bytes.subarray(payloadEnd, end);
    if (!digest.equals(Buffer.from(sha256(bytes.subarray(body, payloadEnd))))) {
      throw new StoreError('STORE_CHAIN_BROKEN', `receipt store chain is broken at byte ${offset}: a record's digest does not match its own bytes`);
    }
    if (kind === KIND_TRIM) {
      // A retirement is a fact about where the surviving receipts start, which is the front of the
      // file. Anywhere else it describes a hole in the middle as if it were intended.
      if (seq !== 0) {
        throw new StoreError('STORE_CHAIN_BROKEN', `receipt store chain is broken at byte ${offset}: a trim record follows a receipt`);
      }
      if (!prev.equals(lastDigest)) {
        throw new StoreError('STORE_CHAIN_BROKEN', `receipt store chain is broken at byte ${offset}: a trim record names a predecessor that is not the record in front of it`);
      }
      if (payloadEnd - payloadStart !== TRIM_PAYLOAD_BYTES) {
        throw new StoreError('STORE_CHAIN_BROKEN', `receipt store chain is broken at byte ${offset}: a trim record carries ${payloadEnd - payloadStart} bytes where the layout states ${TRIM_PAYLOAD_BYTES}`);
      }
      const trim = decodeTrimRecord(prev, iat, bytes.subarray(payloadStart, payloadEnd));
      trims.push(trimEvent(trim));
      // The survivors chain from the seam, not from the record that states it. Copied because a
      // view of the file read would hold the whole file open for as long as the store is.
      const seam = Buffer.from(trim.seam);
      expectedPrev = seam;
      anchor = seam;
      lastDigest = digest;
      trimRunEnd = end;
    } else {
      if (!prev.equals(expectedPrev)) {
        throw new StoreError('STORE_CHAIN_BROKEN', `receipt store chain is broken at byte ${offset}: a record names a predecessor that is not the one before it`);
      }
      expectedPrev = digest;
      lastDigest = digest;
      records.set(bytes.subarray(idStart, payloadStart).toString('utf8'), {
        iat,
        seq: seq++,
        recordStart: offset,
        offset: payloadStart,
        length: payloadEnd - payloadStart,
      });
    }
    offset = end;
  }
  if (offset < bytes.length) {
    // By path, not through the handle: an append-mode handle cannot set the end of a file.
    await truncate(path, offset);
  }
  return {
    records,
    head: expectedPrev,
    size: offset,
    nextSeq: seq,
    trimRunEnd,
    anchor,
    trims,
    dropped: { byAge: 0, byCount: 0 },
  };
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
 */
async function compact(
  path: string,
  state: StoreState,
  trimmedAt: number,
  retention: ReceiptRetention | undefined,
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
  await rename(temp, path);
  const recovered = await scan(path);
  state.records = recovered.records;
  state.head = recovered.head;
  state.size = recovered.size;
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
 * A span of no seconds at all is read as one second rather than as a rate of infinity. Receipts sharing
 * one stamp is the fastest traffic a file can report, so the count derived from it is the smallest one
 * a refusal could rest on: a store holding its whole bound at a single instant needs at least this
 * many, and possibly far more.
 *
 * Null is not a pass. It says there is nothing to measure, either because fewer than two receipts have
 * ever been filed or because no period was configured, and a store that has measured nothing of its
 * own traffic cannot be refused for holding less than it was asked to.
 */
export function receiptsNeededForWindow(maxAgeSeconds: number, held: RetainedWindow): number | null {
  if (maxAgeSeconds <= 0 || held.count < 2) {
    return null;
  }
  return Math.ceil(((held.count - 1) * maxAgeSeconds) / Math.max(held.to - held.from, 1)) + 1;
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
  const needed = receiptsNeededForWindow(maxAgeSeconds, held);
  if (needed === null || needed <= maxCount) {
    return;
  }
  const maxServed = serving?.maxServedReceipts;
  throw new StoreError(
    'RETENTION_WINDOW_UNHOLDABLE',
    `this store is at its durability bound of ${String(maxCount)} receipts and they span ` +
      `${String(held.to - held.from)} seconds, while the configured period is ${String(maxAgeSeconds)} seconds, ` +
      `which takes ${String(needed)} receipts at the rate this store has been carrying: the durability bound is ` +
      `short by ${String(needed - maxCount)} receipts` +
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
 */
function* servedBatches<T extends { iat: number; seq: number }>(
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
 * Reads one record's bytes at the position the index claims. A short read is a failure rather
 * than a miss: the index and the file then disagree about what is stored, and serving a
 * truncated receipt would hand a client bytes that cannot verify.
 */
async function readReceipt(file: FileHandle, where: Location, id: string): Promise<Uint8Array> {
  const bytes = Buffer.alloc(where.length);
  const { bytesRead } = await file.read(bytes, 0, bytes.length, where.offset);
  if (bytesRead !== bytes.length) {
    throw new Error(`receipt ${id} is indexed at ${where.offset} but only ${bytesRead} of ${bytes.length} bytes are there`);
  }
  return bytes;
}

/**
 * Reads one record's bytes at the position the index claims, opening the file for the read rather
 * than holding a handle across an operation that might be queued behind a rewrite.
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
  const now = retention?.now ?? ((): number => Math.floor(Date.now() / 1000));
  const state = await scan(path);
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
        if (state.records.size === 0) {
          state.anchor = state.head;
        }
        state.records.set(id, {
          iat,
          seq: state.nextSeq++,
          recordStart: state.size,
          offset: state.size + FRAME_LEN_BYTES + HEADER_BYTES + Buffer.byteLength(id, 'utf8'),
          length: receipt.length,
        });
        state.head = record.digest;
        state.size += record.frame.length;
        prune(state, retention, now());
        await compact(path, state, now(), retention);
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
          for (const batch of servedBatches(snapshot, from, to, through, serving?.maxServedReceipts)) {
            // Only the bytes are read late, one queued operation at a time. A walk that held the
            // queue for its whole length would be a way to stop serving receipts by generating a pack
            // about them.
            for (const [id, where] of batch) {
              const receipt = await serialized(async () => {
                const still = state.records.get(id);
                return still === undefined ? null : await readAt(path, still, id);
              });
              // Retired by retention while this walk ran, which the window has already said it kept.
              if (receipt !== null) {
                yield { id, iat: where.iat, receipt };
              }
            }
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
  const now = retention?.now ?? ((): number => Math.floor(Date.now() / 1000));
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
              yield { id, iat: where.iat, receipt: where.receipt };
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
