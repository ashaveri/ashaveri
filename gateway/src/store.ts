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
 * Retention drops the oldest records, which are the file's prefix, and a prefix is the one
 * thing a chain cannot speak for: nothing after it changes. So a compaction writes a trim
 * record in front of what it kept, naming the digest the surviving chain starts from and how
 * many records retired. A hole in the middle stays a broken link; a retired prefix stays a
 * statement.
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
/** kind + prev + iat + idLen + digest, with the id and the payload still to come. */
const MIN_BODY_BYTES = KIND_BYTES + PREV_BYTES + IAT_BYTES + ID_LEN_BYTES + DIGEST_BYTES;
/** Everything before the id in a record body. */
const HEADER_BYTES = KIND_BYTES + PREV_BYTES + IAT_BYTES + ID_LEN_BYTES;
const MAX_ID_BYTES = 0xffff;
const KIND_RECEIPT = 0;
const KIND_TRIM = 1;

/** Where one receipt sits in the file. */
interface Location {
  readonly iat: number;
  /** The byte the record's length prefix starts at, so dead space is measurable. */
  readonly recordStart: number;
  readonly offset: number;
  readonly length: number;
}

interface StoreState {
  records: Map<string, Location>;
  head: Buffer;
  size: number;
  /** Records retired by retention since the last trim was written. */
  dropped: number;
}

export interface ReceiptRetention {
  /** A receipt is served while its `iat` is at or after `now - maxAgeSeconds`. */
  readonly maxAgeSeconds?: number;
  /** How many receipts are served, so a busy deployment does not exhaust its volume. */
  readonly maxCount?: number;
  /** Injectable because a six month window is otherwise only testable by waiting. */
  readonly now?: () => number;
}

/**
 * What a deployment keeps by default. Six months is the floor Article 19(1) sets, not the period a
 * financial institution owes: Articles 19(2) and 26(6) route its logs into Union financial-services
 * law, where five years or more applies. A deployer inside that law raises this together with
 * `MAX_SERVED_RECEIPTS` in the CLI, because the count bound closes a five-year window at about six
 * months no matter how long the age bound is set to. Rounded up to whole days past the shortest six
 * months, so the window is never shorter than the one it answers to.
 */
export const MINIMUM_RETENTION_SECONDS = 184 * 24 * 60 * 60;

export interface FileReceiptStoreOptions {
  readonly dir: string;
  /** Absent means nothing is evicted, which is the right default for a fixture store. */
  readonly retention?: ReceiptRetention;
}

/** One retained receipt as the store hands it out: what to check, and when it was issued. */
export interface StoredReceipt {
  readonly id: string;
  readonly iat: number;
  readonly receipt: Uint8Array;
}

/**
 * One code because there is one way this store can refuse to open: the file it was handed no
 * longer chains to itself. A short read, an unreadable volume and a corrupt file are different
 * answers to different questions, and only this one has no safe response.
 */
export type StoreErrorCode = 'STORE_CHAIN_BROKEN';

export class StoreError extends Error {
  readonly code: StoreErrorCode;

  constructor(code: StoreErrorCode, detail: string) {
    super(`${code}: ${detail}`);
    this.name = 'StoreError';
    this.code = code;
  }
}

export interface ReceiptStore {
  put(id: string, receipt: Uint8Array, iat: number): Promise<void>;
  get(id: string): Promise<Uint8Array | null>;

  /** Inclusive bounds and a count, so a retention manifest can state them. */
  window(): Promise<{ from: number; to: number; count: number }>;

  /** Every receipt in a half-open interval, oldest first, for pack generation. */
  range(from: number, to: number): AsyncIterable<StoredReceipt>;

  /** Head of the hash chain. Publishing it is what makes deletion detectable. */
  head(): Promise<Uint8Array>;
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

function encodeTrimRecord(seam: Uint8Array, trimmedAt: number, dropped: number): Buffer {
  const count = Buffer.alloc(COUNT_BYTES);
  count.writeUInt32BE(dropped > 0xffffffff ? 0xffffffff : dropped);
  return encode(KIND_TRIM, seam, trimmedAt, '', count).frame;
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
  let head = Buffer.alloc(PREV_BYTES);
  // The digest the next record has to name. An untouched store starts at the empty one, and a
  // compacted store starts at the seam its leading trim record states instead.
  let expectedPrev = Buffer.alloc(PREV_BYTES);
  let offset = 0;
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
    const digest = bytes.subarray(payloadEnd, end);
    if (!digest.equals(Buffer.from(sha256(bytes.subarray(body, payloadEnd))))) {
      throw new StoreError('STORE_CHAIN_BROKEN', `receipt store chain is broken at byte ${offset}: a record's digest does not match its own bytes`);
    }
    if (kind === KIND_TRIM) {
      // A retirement is only a fact about where the surviving records start, which is the front
      // of the file. Anywhere else it describes a hole in the middle as if it were intended.
      if (offset !== 0) {
        throw new StoreError('STORE_CHAIN_BROKEN', `receipt store chain is broken at byte ${offset}: a trim record follows another record`);
      }
      expectedPrev = prev;
    } else {
      if (!prev.equals(expectedPrev)) {
        throw new StoreError('STORE_CHAIN_BROKEN', `receipt store chain is broken at byte ${offset}: a record names a predecessor that is not the one before it`);
      }
      expectedPrev = digest;
      records.set(bytes.subarray(idStart, payloadStart).toString('utf8'), {
        iat: Number(bytes.readBigUInt64BE(body + KIND_BYTES + PREV_BYTES)),
        recordStart: offset,
        offset: payloadStart,
        length: payloadEnd - payloadStart,
      });
    }
    // A trim record is chained like anything else: it is the head's predecessor, and it is what
    // the file says about its own start.
    head = digest;
    offset = end;
  }
  if (offset < bytes.length) {
    // By path, not through the handle: an append-mode handle cannot set the end of a file.
    await truncate(path, offset);
  }
  return { records, head, size: offset, dropped: 0 };
}

/**
 * The ids a retention policy retires: everything older than the window, then the oldest of what
 * is left until the count cap fits. Sorted rather than taken in write order because a place in
 * the store is not a promise about an `iat`. Equal timestamps fall out in write order, which is
 * how the index is built in both engines.
 */
function retire(
  entries: Iterable<readonly [string, { iat: number }]>,
  retention: ReceiptRetention | undefined,
  now: number,
): string[] {
  if (retention === undefined) {
    return [];
  }
  const cutoff = retention.maxAgeSeconds === undefined ? Number.NEGATIVE_INFINITY : now - retention.maxAgeSeconds;
  const live: [string, number][] = [];
  const doomed: string[] = [];
  for (const [id, where] of entries) {
    if (where.iat < cutoff) {
      doomed.push(id);
    } else {
      live.push([id, where.iat]);
    }
  }
  const max = retention.maxCount;
  if (max !== undefined) {
    live.sort((a, b) => a[1] - b[1]);
    for (const [id] of live.slice(0, Math.max(0, live.length - max))) {
      doomed.push(id);
    }
  }
  return doomed;
}

/**
 * Applies the policy to the index and counts what fell out of it. Dropping from the index is
 * what makes a receipt unserved; the bytes stay in the file until a compaction takes them, which
 * is the only rewrite this store ever performs.
 */
function prune(state: StoreState, retention: ReceiptRetention | undefined, now: number): void {
  for (const id of retire(state.records, retention, now)) {
    state.records.delete(id);
    state.dropped += 1;
  }
}

/**
 * Rewrites the file as one trim record followed by the records retention kept, byte for byte.
 *
 * It runs only when the dead prefix outweighs the live tail, which amortizes the copy across
 * many appends instead of paying it on every one. Because it drops a prefix, no surviving
 * record's digest changes and the head the next pack publishes is the head before it: what the
 * rewrite cannot do is keep the chain honest about the records it removed, which is why it says
 * so in a chained record rather than leaving a hole for a reader to explain.
 */
async function compact(path: string, state: StoreState, trimmedAt: number): Promise<void> {
  let first = state.size;
  for (const where of state.records.values()) {
    first = Math.min(first, where.recordStart);
  }
  const dead = first;
  if (dead === 0 || dead <= state.size - dead) {
    return;
  }
  const file = await open(path, 'r');
  let tail: Buffer;
  try {
    tail = Buffer.alloc(state.size - dead);
    const { bytesRead } = await file.read(tail, 0, tail.length, dead);
    if (bytesRead !== tail.length) {
      throw new Error(`store file ended ${tail.length - bytesRead} bytes short of its own index`);
    }
  } finally {
    await file.close();
  }
  // The digest the retained chain starts from: the first surviving record names it in its own
  // prev, and a fully retired file names the last record the file held.
  const seam =
    tail.length === 0
      ? state.head
      : tail.subarray(FRAME_LEN_BYTES + KIND_BYTES, FRAME_LEN_BYTES + KIND_BYTES + PREV_BYTES);
  const trimmed = Buffer.concat([encodeTrimRecord(seam, trimmedAt, state.dropped), tail]);
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
  state.dropped = 0;
}

/**
 * The retained set as a retention manifest states it: inclusive bounds and a count. Zero bounds
 * mean nothing is retained, and the count is what says so.
 */
function windowOf(retained: Iterable<{ iat: number }>): { from: number; to: number; count: number } {
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
 * What a half-open window covers, oldest first. A snapshot rather than a live walk: pack
 * generation reads for a long time, and a receipt issued halfway through belongs to the next
 * window. Equal timestamps keep the order the engine indexed them in, which is write order,
 * because the sort is stable.
 */
function inRange<T extends { iat: number }>(
  entries: Iterable<readonly [string, T]>,
  from: number,
  to: number,
): readonly (readonly [string, T])[] {
  return [...entries]
    .filter(([, where]) => where.iat >= from && where.iat < to)
    .sort((a, b) => a[1].iat - b[1].iat);
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
  const now = retention?.now ?? ((): number => Math.floor(Date.now() / 1000));
  const state = await scan(path);
  // A deployment that was down over a weekend has aged receipts on disk it must not serve.
  prune(state, retention, now());

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
        state.records.set(id, {
          iat,
          recordStart: state.size,
          offset: state.size + FRAME_LEN_BYTES + HEADER_BYTES + Buffer.byteLength(id, 'utf8'),
          length: receipt.length,
        });
        state.head = record.digest;
        state.size += record.frame.length;
        prune(state, retention, now());
        await compact(path, state, now());
      });
    },

    get(id: string): Promise<Uint8Array | null> {
      return serialized(async () => {
        const found = state.records.get(id);
        return found === undefined ? null : readAt(path, found, id);
      });
    },

    range(from: number, to: number): AsyncIterable<StoredReceipt> {
      const wanted = inRange(state.records.entries(), from, to);
      return {
        async *[Symbol.asyncIterator](): AsyncIterator<StoredReceipt> {
          // Membership was fixed by the snapshot above; only the bytes are read late, one queued
          // operation at a time. A walk that held the queue for its whole length would be a way
          // to stop serving receipts by generating a pack about them.
          for (const [id, where] of wanted) {
            const receipt = await serialized(async () => {
              const still = state.records.get(id);
              return still === undefined ? null : await readAt(path, still, id);
            });
            // Retired by retention while this walk ran, which the window has already said it kept.
            if (receipt !== null) {
              yield { id, iat: where.iat, receipt };
            }
          }
        },
      };
    },

    async window(): Promise<{ from: number; to: number; count: number }> {
      return windowOf(state.records.values());
    },

    async head(): Promise<Uint8Array> {
      return new Uint8Array(state.head);
    },
  };
}

/**
 * The same interface with nothing behind it but the process, which is what `--mock` and every
 * test that is not about durability asks for. It chains exactly as the file engine does, so
 * `head()` means one thing across both, and a restart takes it back to the empty digest because
 * there is nowhere else for it to live.
 */
export function openMemoryReceiptStore(options: { readonly retention?: ReceiptRetention } = {}): ReceiptStore {
  const retention = options.retention;
  const now = retention?.now ?? ((): number => Math.floor(Date.now() / 1000));
  const entries = new Map<string, { iat: number; receipt: Uint8Array }>();
  let chainHead: Uint8Array = new Uint8Array(PREV_BYTES);

  return {
    async put(id, receipt, iat) {
      chainHead = encode(KIND_RECEIPT, chainHead, iat, id, receipt).digest;
      entries.set(id, { iat, receipt });
      for (const doomed of retire(entries, retention, now())) {
        entries.delete(doomed);
      }
    },

    async get(id) {
      return entries.get(id)?.receipt ?? null;
    },

    range(from, to) {
      const wanted = inRange(entries.entries(), from, to);
      return {
        async *[Symbol.asyncIterator](): AsyncIterator<StoredReceipt> {
          for (const [id, where] of wanted) {
            yield { id, iat: where.iat, receipt: where.receipt };
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
  };
}
