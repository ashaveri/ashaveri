import { createHash } from 'node:crypto';

/**
 * The receipt volume read and written as bytes rather than through the store that owns it.
 *
 * A drill that asks the store to plant a missing record would be checking the store's claim against the
 * store, and one that reads its ids through `openFileReceiptStore` could not tell a lost record apart from
 * a pruned one. So the framing is spelled out here a second time, the way `gateway/test/store.test.ts` and
 * `gateway/test/cli.test.ts` each already carry their own copy: a reader that agrees with the writer about
 * every byte is a reader that cannot see a byte that moved.
 *
 * `Record = len:u32 || kind:u8 || prev:32 || iat:u64 || idLen:u16 || id || payload || digest:32`, with the
 * digest taken over kind through payload and `prev` the digest of the record before it, zeros at the head
 * of the file.
 */
export function receiptFrame(prev: Uint8Array, iat: number, id: string, payload: Buffer): Buffer {
  const idBytes = Buffer.from(id, 'utf8');
  const body = Buffer.alloc(1 + 32 + 8 + 2 + idBytes.length + payload.length);
  body.writeUInt8(0, 0);
  Buffer.from(prev).copy(body, 1);
  body.writeBigUInt64BE(BigInt(iat), 33);
  body.writeUInt16BE(idBytes.length, 41);
  idBytes.copy(body, 43);
  payload.copy(body, 43 + idBytes.length);
  const digest = Buffer.from(createHash('sha256').update(body).digest());
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32BE(body.length + digest.length);
  return Buffer.concat([prefix, body, digest]);
}

/**
 * The first record of a store file, read out of the framing rather than through the store that wrote it,
 * so a case can name the kind byte and the payload a run actually put on the volume.
 */
export function firstRecordOf(file: Buffer): { kind: number; id: string; payload: Buffer } {
  const idLength = file.readUInt16BE(45);
  const payloadAt = 47 + idLength;
  return {
    kind: file.readUInt8(4),
    id: file.subarray(47, payloadAt).toString('utf8'),
    payload: file.subarray(payloadAt, 4 + file.readUInt32BE(0) - 32),
  };
}

/** One receipt as the volume states it, with the two digests a reader weighs: its own and the one it chains from. */
export interface VolumeRecord {
  /** The chain position: receipts count, in file order, and trim records do not. */
  readonly seq: number;
  readonly at: number;
  readonly id: string;
  readonly payload: Buffer;
  readonly digest: string;
  readonly prev: string;
  readonly offset: number;
  readonly bytes: number;
}

/** What a whole volume reads to: the receipts in it, and where the chain stopped agreeing with itself. */
export interface VolumeReading {
  readonly records: readonly VolumeRecord[];
  /** The byte offset the last complete record ends at, which is the end of what the file speaks for. */
  readonly endAt: number;
  /** The first record whose `prev` is not the digest before it, or null while every link agrees. */
  readonly brokenAtSeq: number | null;
}

/** Reads every frame of a `receipts.log`, refusing to invent a record a short or torn frame cannot be. */
export function readVolume(file: Buffer): VolumeReading {
  const records: VolumeRecord[] = [];
  let at = 0;
  let previous: string | null = null;
  let brokenAtSeq: number | null = null;
  while (at + 4 <= file.length) {
    const declared = file.readUInt32BE(at);
    if (at + 4 + declared > file.length) break;
    const body = file.subarray(at + 4, at + 4 + declared - 32);
    const digest = Buffer.from(createHash('sha256').update(body).digest()).toString('hex');
    const stored = file.subarray(at + 4 + declared - 32, at + 4 + declared).toString('hex');
    const idLength = body.readUInt16BE(41);
    const seq = records.length;
    const prev = body.subarray(1, 33).toString('hex');
    if (stored !== digest) {
      // A record whose own bytes do not hash to the digest it carries is not a link to weigh; it is the
      // end of what this volume can be read as, and the store refuses the same file at its opening.
      brokenAtSeq = brokenAtSeq ?? seq;
      return { records, endAt: at, brokenAtSeq };
    }
    if (previous !== null && prev !== previous) brokenAtSeq = brokenAtSeq ?? seq;
    records.push({
      seq,
      at: Number(body.readBigUInt64BE(33)),
      id: body.subarray(43, 43 + idLength).toString('utf8'),
      payload: Buffer.from(body.subarray(43 + idLength, body.length)),
      digest,
      prev,
      offset: at,
      bytes: 4 + declared,
    });
    previous = digest;
    at += 4 + declared;
  }
  return { records, endAt: at, brokenAtSeq };
}

/** The head this volume states: the digest of its last receipt, and nothing at all where it holds none. */
export function volumeHead(volume: VolumeReading): { sequence: number; sha256: string } | null {
  const last = volume.records.at(-1);
  return last === undefined ? null : { sequence: last.seq, sha256: last.digest };
}

/**
 * Rebuilds a volume from the receipts a caller names, chaining each from the digest of the one before it.
 *
 * This is what a loss that leaves a *valid* file looks like: a reader holding only the bytes cannot tell a
 * rebuilt volume from one that never held the dropped record, so the only witness left is the head someone
 * pinned while the records were still all there. Re-chaining is the arm the drill needs the pin for.
 */
export function buildVolume(receipts: readonly { at: number; id: string; payload: Buffer }[]): Buffer {
  let prev: Uint8Array = new Uint8Array(32);
  const frames: Buffer[] = [];
  for (const each of receipts) {
    const frame = receiptFrame(prev, each.at, each.id, each.payload);
    prev = frame.subarray(frame.length - 32);
    frames.push(frame);
  }
  return Buffer.concat(frames);
}
