import { afterEach, describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  openFileReceiptStore,
  RECEIPT_SIDECAR_FILE,
  RECEIPT_STORE_FILE,
  SIDECAR_BLOCK_RECORDS,
  type ReceiptRetention,
} from '../src/store.js';
import { fixedClock } from './helpers.js';

/**
 * The disposable sidecar index a durable receipt store keeps beside `receipts.log`, and the checkpoint
 * inside it.
 *
 * These cases are written as comparisons, because that is the claim: the store file is the authority,
 * so an opening served by the sidecar has to answer what an opening that re-derived the whole file
 * answers. `answer()` makes that one statement per case, returning everything an opening reports, a
 * refusal included, as one string, and the declined opening (which neither reads nor writes a sidecar)
 * is the ground truth. That shape is what the store did before a sidecar existed at all.
 *
 * The sidecar's layout is read here by a second copy of it, the way `store.test.ts` reads the record
 * frames, so a case that corrupts one field cannot be fooled by the writer and the reader agreeing with
 * each other about a byte neither was told to write.
 */

const RECEIPT = Uint8Array.from(Array.from({ length: 64 }, (_, i) => (i * 7) % 256));
const OTHER_RECEIPT = Uint8Array.from(Array.from({ length: 48 }, (_, i) => (i * 11) % 256));
/** Receipt bytes one away from `RECEIPT` at every byte, so a replacement file holds equal frames. */
const FOREIGN = Uint8Array.from(RECEIPT, (byte) => (byte + 1) % 256);
const STAMP = 1_780_000_000;
const IDS = ['rcpt_01', 'rcpt_02', 'rcpt_03'];
/**
 * Durable appends are what these fixtures are made of and each one fsyncs. The widest case here writes
 * fifteen of them and opens the store three times, measured at 0.4s; the stop is the one
 * `store.test.ts` carries for ten durable appends and an open, which is the same order of volume.
 */
const CASE_TIMEOUT = 15_000;

function sha256(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(createHash('sha256').update(bytes).digest());
}

const hex = (bytes: Uint8Array | undefined): string =>
  bytes === undefined ? 'absent' : Buffer.from(bytes).toString('hex');

/** Splits a store file into whole length-prefixed records, from the frame layout rather than the store. */
function frames(bytes: Buffer): Buffer[] {
  const out: Buffer[] = [];
  let at = 0;
  while (at + 4 <= bytes.length) {
    const length = bytes.readUInt32BE(at);
    out.push(bytes.subarray(at, at + 4 + length));
    at += 4 + length;
  }
  return out;
}

function readFrame(frame: Buffer): {
  kind: number;
  prev: Buffer;
  iat: number;
  id: string;
  payload: Buffer;
  digest: Buffer;
} {
  const idLength = frame.readUInt16BE(45);
  return {
    kind: frame.readUInt8(4),
    prev: frame.subarray(5, 37),
    iat: Number(frame.readBigUInt64BE(37)),
    id: frame.subarray(47, 47 + idLength).toString('utf8'),
    payload: frame.subarray(47 + idLength, frame.length - 32),
    digest: frame.subarray(frame.length - 32),
  };
}

const frameDigest = (frame: Buffer): Buffer => Buffer.from(sha256(frame.subarray(4, frame.length - 32)));

/** The byte a record the sidecar indexes ends at, from the widths the store's own layout states. */
function endOfRecord(start: number, id: string, payloadLen: number): number {
  return start + 4 + 1 + 32 + 8 + 2 + Buffer.byteLength(id) + payloadLen + 32;
}

/** One entry of the sidecar, with the offset in the sidecar file where it starts. */
interface SidecarEntry {
  readonly at: number;
  readonly recordStart: number;
  readonly seq: number;
  readonly iat: number;
  readonly payloadLen: number;
  readonly id: string;
  readonly digest: Buffer;
}

interface Sidecar {
  readonly magic: string;
  readonly version: number;
  readonly identity: string;
  readonly entries: SidecarEntry[];
}

/**
 * `magic:4 || version:u16 || identityLen:u16 || identity`, then blocks, each one `recordCount:u32 ||
 * checkpointBytes:u64` followed by that many entries and a 32 byte check. An entry is
 * `recordStart:u64 || seq:u64 || iat:u64 || payloadLen:u32 || idLen:u16 || id || digest:32`.
 */
function readSidecar(bytes: Buffer): Sidecar {
  const identityLength = bytes.length >= 8 ? bytes.readUInt16BE(6) : 0;
  const header = {
    magic: bytes.subarray(0, 4).toString('utf8'),
    version: bytes.readUInt16BE(4),
    identity: bytes.subarray(8, 8 + identityLength).toString('utf8'),
  };
  const entries: SidecarEntry[] = [];
  let at = 8 + identityLength;
  while (at + 12 <= bytes.length) {
    const count = bytes.readUInt32BE(at);
    at += 12;
    for (let i = 0; i < count; i++) {
      const start = at;
      const recordStart = Number(bytes.readBigUInt64BE(at));
      const seq = Number(bytes.readBigUInt64BE(at + 8));
      const iat = Number(bytes.readBigUInt64BE(at + 16));
      const payloadLen = bytes.readUInt32BE(at + 24);
      const idLen = bytes.readUInt16BE(at + 28);
      if (at + 30 + idLen + 32 > bytes.length) {
        return { ...header, entries };
      }
      at += 30;
      const id = bytes.subarray(at, at + idLen).toString('utf8');
      at += idLen;
      const digest = bytes.subarray(at, at + 32);
      at += 32;
      entries.push({ at: start, recordStart, seq, iat, payloadLen, id, digest });
    }
    if (at + 32 > bytes.length) {
      return { ...header, entries };
    }
    at += 32;
  }
  return { ...header, entries };
}

/** Where one sidecar entry keeps a given field, so a case can name the byte it means to change. */
function fieldAt(entry: SidecarEntry, field: 'recordStart' | 'seq' | 'iat' | 'payloadLen' | 'id' | 'digest'): number {
  const offsets = { recordStart: 0, seq: 8, iat: 16, payloadLen: 24, id: 30, digest: 30 + Buffer.byteLength(entry.id) };
  return entry.at + offsets[field];
}

let created: string[] = [];

async function emptyDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'ashaveri-sidecar-'));
  created.push(dir);
  return dir;
}

const storeFile = (dir: string): string => join(dir, RECEIPT_STORE_FILE);
const sidecarFile = (dir: string): string => join(dir, RECEIPT_SIDECAR_FILE);
const sidecarBytes = (dir: string): Promise<Buffer> => readFile(sidecarFile(dir));

/** Flips one byte of a file in place, leaving its length and the volume's answer for it alone. */
async function poison(path: string, at: number): Promise<void> {
  const bytes = await readFile(path);
  bytes[at] = (bytes[at]! + 1) % 256;
  await writeFile(path, bytes);
}

interface Asking {
  /** Open as if no sidecar existed: neither read nor written. */
  readonly declined?: boolean;
  readonly retention?: ReceiptRetention;
  readonly ids?: readonly string[];
}

/**
 * Everything one opening answers, as one string: the window, the head, the anchor and the retirement
 * history, every receipt a walk over the whole store hands over, and what `get` says of each id named.
 * A refusal is part of the answer rather than an exception out of it, so two openings can be compared on
 * a file one of them objects to.
 */
async function answer(dir: string, asking: Asking = {}): Promise<string> {
  const options = {
    dir,
    ...(asking.declined === true ? { sidecarIndex: false } : {}),
    ...(asking.retention === undefined ? {} : { retention: asking.retention }),
  };
  const opened = await openFileReceiptStore(options).then(
    (store) => ({ store, refused: null as string | null }),
    (error: unknown) => ({ store: null, refused: String((error as { code?: string }).code) }),
  );
  if (opened.store === null) return JSON.stringify({ refused: opened.refused });

  const store = opened.store;
  const asked: Record<string, string> = {};
  for (const id of asking.ids ?? []) {
    asked[id] = await store.get(id).then(
      (found) => (found === null ? 'absent' : hex(found)),
      (error: unknown) => `refused: ${(error as Error).message}`,
    );
  }
  const walked: { id: string; iat: number; receipt: string }[] = [];
  let walkRefused: string | null = null;
  try {
    for await (const item of store.range(0, 2_000_000_000)) {
      walked.push({ id: item.id, iat: item.iat, receipt: hex(item.receipt) });
    }
  } catch (error) {
    walkRefused = (error as Error).message;
  }
  const state = await store.chainState();
  return JSON.stringify({
    refused: null,
    window: await store.window(),
    head: hex(await store.head()),
    anchor: hex(state.anchor),
    retired: state.retired,
    walked,
    walkRefused,
    asked,
  });
}

/**
 * Writes `ids` receipts a minute apart, and opens the store once more afterwards. The opening is what
 * leaves the index speaking for the whole file: an append's entry waits for a block of them, so a
 * store that has been restarted since it was written is the state a checkpoint is built for.
 */
async function fileWith(
  dir: string,
  ids: readonly string[],
  payload: Uint8Array = RECEIPT,
  declined = false,
): Promise<void> {
  const options = declined ? { dir, sidecarIndex: false } : { dir };
  const store = await openFileReceiptStore(options);
  for (const [i, id] of ids.entries()) {
    await store.put(id, payload, STAMP + i * 60);
  }
  await openFileReceiptStore(options);
}

/** The volume's own answer to which file the store file is, read the way the store reads it. */
async function serial(path: string): Promise<string> {
  const found = await stat(path);
  return `${String(found.dev)}:${String(found.ino)}`;
}

afterEach(async () => {
  const dirs = created;
  created = [];
  await Promise.all(dirs.map((dir) => rm(dir, { recursive: true, force: true })));
});

describe('the store file is the only authority', () => {
  it(
    'serves the same store with the sidecar deleted mid-life as with it never written',
    { timeout: CASE_TIMEOUT },
    async () => {
      const dir = await emptyDir();
      await fileWith(dir, IDS);
      const neverDir = await emptyDir();
      await fileWith(neverDir, IDS, RECEIPT, true);
      const asking = { ids: IDS };
      expect(await readdir(neverDir)).toEqual([RECEIPT_STORE_FILE]);

      await rm(sidecarFile(dir));
      expect(await readdir(dir)).toEqual([RECEIPT_STORE_FILE]);
      expect(await answer(dir, asking)).toBe(await answer(neverDir, { ...asking, declined: true }));
      // And the walk that answered has left a sidecar behind, which is what makes the next opening cheap.
      expect((await stat(sidecarFile(dir))).size).toBeGreaterThan(0);
    },
  );

  it(
    'states the same retirement arithmetic across two compactions, sidecar or no sidecar',
    { timeout: CASE_TIMEOUT },
    async () => {
      // Ten receipts aged out, four kept, then a restart and one more receipt, which retires and
      // compacts again: the file ends with a run of two trim records and one receipt, so the anchor, the
      // trim history and the served set are all reported from a prefix no reader holds.
      const run = async (dir: string, declined: boolean): Promise<void> => {
        let now = STAMP;
        const retention: ReceiptRetention = { maxAgeSeconds: 1_000, time: fixedClock(() => now) };
        const options = { dir, retention, ...(declined ? { sidecarIndex: false } : {}) };
        const first = await openFileReceiptStore(options);
        for (let i = 0; i < 10; i++) {
          await first.put(`old_${String(i)}`, RECEIPT, now + i);
        }
        now = STAMP + 1_010;
        for (let i = 0; i < 4; i++) {
          await first.put(`new_${String(i)}`, OTHER_RECEIPT, now + i);
        }
        const second = await openFileReceiptStore(options);
        await second.put('only', RECEIPT, now + 1_010);
      };
      const sidecarDir = await emptyDir();
      const walkedDir = await emptyDir();
      await run(sidecarDir, false);
      await run(walkedDir, true);

      expect(await readdir(walkedDir)).toEqual([RECEIPT_STORE_FILE]);
      const retention: ReceiptRetention = { maxAgeSeconds: 1_000, time: fixedClock(() => STAMP + 2_020) };
      const asking = { retention, ids: ['old_0', 'new_0', 'only'] };
      expect(await readFile(storeFile(sidecarDir))).toEqual(await readFile(storeFile(walkedDir)));
      expect(await answer(sidecarDir, asking)).toBe(await answer(walkedDir, { ...asking, declined: true }));
    },
  );

  it('writes nothing beside the store file when the sidecar is declined', { timeout: CASE_TIMEOUT }, async () => {
    const dir = await emptyDir();
    await fileWith(dir, IDS, RECEIPT, true);
    expect(await readdir(dir)).toEqual([RECEIPT_STORE_FILE]);
    // Declining is not a read-only opening: the store still answers, and answers the same.
    const first = await answer(dir, { declined: true, ids: IDS });
    expect(JSON.parse(first).refused).toBeNull();
    expect(await answer(dir, { declined: true, ids: IDS })).toBe(first);
  });

  it(
    'refuses a store whose middle record was removed, sidecar or no sidecar',
    { timeout: CASE_TIMEOUT },
    async () => {
      const dir = await emptyDir();
      await fileWith(dir, IDS);
      const records = frames(await readFile(storeFile(dir)));
      expect(records).toHaveLength(3);
      // Taking the middle record out shortens the file, which is one of the ways a checkpoint learns it
      // no longer speaks for what is there.
      await writeFile(storeFile(dir), Buffer.concat([records[0]!, records[2]!]));

      const truth = await answer(dir, { declined: true, ids: IDS });
      expect(JSON.parse(truth).refused).toBe('STORE_CHAIN_BROKEN');
      expect(await answer(dir, { ids: IDS })).toBe(truth);
    },
  );

  it(
    'keeps a receipt retention dropped from the served set, so a clock that steps back serves what the walk serves',
    { timeout: CASE_TIMEOUT },
    async () => {
      // Why the index is written from the records the file holds rather than from the served set: a
      // pruned receipt is still bytes in the file until a compaction takes them, and an opening that
      // re-derives the file indexes it again. Forward both openings retire it; back, both serve it.
      // The kept receipts outweigh the retired one, which is the condition a compaction needs before it
      // rewrites the file and makes the retirement permanent in bytes as well as in the served set.
      const dir = await emptyDir();
      const store = await openFileReceiptStore({ dir });
      await store.put('aged', RECEIPT, STAMP);
      for (let i = 0; i < 3; i++) {
        await store.put(`kept_${String(i)}`, OTHER_RECEIPT, STAMP + 5_000 + i);
      }
      const ids = ['aged', 'kept_0', 'kept_1', 'kept_2'];

      const forward = { retention: { maxAgeSeconds: 1_000, time: fixedClock(() => STAMP + 5_002) }, ids };
      expect(await answer(dir, forward)).toBe(await answer(dir, { ...forward, declined: true }));
      expect(JSON.parse(await answer(dir, forward)).window.count).toBe(3);
      expect(JSON.parse(await answer(dir, forward)).asked.aged).toBe('absent');

      const back = { retention: { maxAgeSeconds: 1_000, time: fixedClock(() => STAMP) }, ids };
      expect(await answer(dir, back)).toBe(await answer(dir, { ...back, declined: true }));
      expect(JSON.parse(await answer(dir, back)).window.count).toBe(4);
      expect(JSON.parse(await answer(dir, back)).asked.aged).toBe(hex(RECEIPT));
    },
  );
});

describe('a sidecar that does not agree with the store file is discarded', () => {
  /** Three receipts, and the sidecar that speaks for the whole of the file holding them. */
  async function prepared(): Promise<string> {
    const dir = await emptyDir();
    await fileWith(dir, IDS);
    expect(readSidecar(await sidecarBytes(dir)).entries.map((entry) => entry.id)).toEqual(IDS);
    return dir;
  }

  /** Every opening of the poisoned directory answers what the walk alone answers. */
  async function agreesWithWalk(dir: string): Promise<void> {
    const truth = await answer(dir, { declined: true, ids: IDS });
    expect(JSON.parse(truth).refused).toBeNull();
    expect(await answer(dir, { ids: IDS })).toBe(truth);
  }

  it('discards one truncated in the middle of an entry, and serves the file', { timeout: CASE_TIMEOUT }, async () => {
    const dir = await prepared();
    const bytes = await readFile(sidecarFile(dir));
    await writeFile(sidecarFile(dir), bytes.subarray(0, bytes.length - 20));
    await agreesWithWalk(dir);
  });

  it('discards one that is empty, and serves the file', { timeout: CASE_TIMEOUT }, async () => {
    const dir = await prepared();
    await writeFile(sidecarFile(dir), Buffer.alloc(0));
    await agreesWithWalk(dir);
  });

  it('discards one whose checkpoint claims more bytes than the file holds', { timeout: CASE_TIMEOUT }, async () => {
    const dir = await prepared();
    const records = frames(await readFile(storeFile(dir)));
    // The newest receipt is gone and what remains still chains to itself, so the walk has an answer and
    // it is not the answer the checkpoint would have let the opening give.
    await writeFile(storeFile(dir), Buffer.concat([records[0]!, records[1]!]));
    const truth = await answer(dir, { declined: true, ids: IDS });
    expect(JSON.parse(truth).window.count).toBe(2);
    expect(JSON.parse(truth).asked.rcpt_03).toBe('absent');
    expect(await answer(dir, { ids: IDS })).toBe(truth);
  });

  it('discards one naming a file the store file is not', { timeout: CASE_TIMEOUT }, async () => {
    const dir = await prepared();
    expect(readSidecar(await sidecarBytes(dir)).identity).toBe(await serial(storeFile(dir)));
    await poison(sidecarFile(dir), 10);
    await agreesWithWalk(dir);
  });

  it('discards one whose record digest was changed', { timeout: CASE_TIMEOUT }, async () => {
    const dir = await prepared();
    const entry = readSidecar(await sidecarBytes(dir)).entries[1]!;
    await poison(sidecarFile(dir), fieldAt(entry, 'digest'));
    await agreesWithWalk(dir);
  });

  it('discards one whose chain position was changed', { timeout: CASE_TIMEOUT }, async () => {
    const dir = await prepared();
    const entry = readSidecar(await sidecarBytes(dir)).entries[2]!;
    await poison(sidecarFile(dir), fieldAt(entry, 'seq'));
    await agreesWithWalk(dir);
  });

  it('discards one whose record position was changed', { timeout: CASE_TIMEOUT }, async () => {
    const dir = await prepared();
    const entry = readSidecar(await sidecarBytes(dir)).entries[1]!;
    await poison(sidecarFile(dir), fieldAt(entry, 'recordStart'));
    await agreesWithWalk(dir);
  });

  it('discards one whose receipt stamp was changed', { timeout: CASE_TIMEOUT }, async () => {
    const dir = await prepared();
    const entry = readSidecar(await sidecarBytes(dir)).entries[0]!;
    await poison(sidecarFile(dir), fieldAt(entry, 'iat'));
    await agreesWithWalk(dir);
  });

  it('discards one whose payload length was changed', { timeout: CASE_TIMEOUT }, async () => {
    const dir = await prepared();
    const entry = readSidecar(await sidecarBytes(dir)).entries[1]!;
    await poison(sidecarFile(dir), fieldAt(entry, 'payloadLen'));
    await agreesWithWalk(dir);
  });

  it('discards one whose id was changed, and serves the receipts the file names', {
    timeout: CASE_TIMEOUT,
  }, async () => {
    const dir = await prepared();
    const entry = readSidecar(await sidecarBytes(dir)).entries[1]!;
    await poison(sidecarFile(dir), fieldAt(entry, 'id'));
    const truth = await answer(dir, { declined: true, ids: IDS });
    expect(await answer(dir, { ids: IDS })).toBe(truth);
    expect(JSON.parse(await answer(dir, { ids: IDS })).asked[IDS[1]!]).toBe(hex(RECEIPT));
  });

  it('discards a store file rewritten in place, same length and same volume pair, and serves the new receipts', {
    timeout: CASE_TIMEOUT,
  }, async () => {
    const dir = await prepared();
    const before = await stat(storeFile(dir));
    const other = await emptyDir();
    await fileWith(other, IDS, FOREIGN);
    const foreign = await readFile(storeFile(other));
    expect(foreign.length).toBe(before.size);

    // Through the store's own name rather than beside it, so the volume keeps its answer for which file
    // this is: only the bytes the checkpoint ends on can say the index is stale.
    await writeFile(storeFile(dir), foreign);
    const after = await stat(storeFile(dir));
    expect(`${String(after.dev)}:${String(after.ino)}`).toBe(`${String(before.dev)}:${String(before.ino)}`);
    expect(after.size).toBe(before.size);

    const truth = await answer(dir, { declined: true, ids: IDS });
    expect(JSON.parse(truth).refused).toBeNull();
    expect(JSON.parse(truth).walked.map((item: { id: string }) => item.id)).toEqual(IDS);
    expect(await answer(dir, { ids: IDS })).toBe(truth);
    // Discarding is a walk, and the walk leaves a sidecar for the bytes that answered.
    expect(readSidecar(await sidecarBytes(dir)).entries.map((entry) => hex(entry.digest))).toEqual(
      frames(foreign).map((frame) => hex(frameDigest(frame))),
    );
  });

  it('discards one carried from a different store file, and serves the file it was given', {
    timeout: CASE_TIMEOUT,
  }, async () => {
    const dir = await prepared();
    const other = await emptyDir();
    await fileWith(other, IDS, FOREIGN);
    await writeFile(sidecarFile(dir), await sidecarBytes(other));
    const truth = await answer(dir, { declined: true, ids: IDS });
    expect(await answer(dir, { ids: IDS })).toBe(truth);
    expect(JSON.parse(truth).walked[0].receipt).toBe(hex(RECEIPT));
  });

  it(
    'writes a fresh sidecar that speaks for the whole file after discarding one',
    { timeout: CASE_TIMEOUT },
    async () => {
      const dir = await prepared();
      await writeFile(sidecarFile(dir), Buffer.alloc(0));
      await answer(dir, { ids: IDS });

      const file = await readFile(storeFile(dir));
      const written = readSidecar(await readFile(sidecarFile(dir)));
      expect(written.magic).toBe('ASRI');
      expect(written.version).toBe(1);
      expect(written.identity).toBe(await serial(storeFile(dir)));
      expect(written.entries).toHaveLength(3);
      expect(endOfRecord(written.entries[2]!.recordStart, IDS[2]!, written.entries[2]!.payloadLen)).toBe(
        file.length,
      );
    },
  );

  it(
    'serves receipts written past the checkpoint a sidecar speaks for',
    { timeout: CASE_TIMEOUT },
    async () => {
      // The state a lost checkpoint leaves behind: the file holds five records and the sidecar was last
      // written when it held three. Only the two past the checkpoint may be read out of the file, and
      // every receipt has to be served either way.
      const dir = await emptyDir();
      await fileWith(dir, IDS);
      const behind = await sidecarBytes(dir);
      const store = await openFileReceiptStore({ dir });
      await store.put('rcpt_04', RECEIPT, STAMP + 180);
      await store.put('rcpt_05', OTHER_RECEIPT, STAMP + 240);
      await writeFile(sidecarFile(dir), behind);

      const asking = { ids: [...IDS, 'rcpt_04', 'rcpt_05'] };
      const truth = await answer(dir, { ...asking, declined: true });
      const served = await answer(dir, asking);
      expect(served).toBe(truth);
      expect(JSON.parse(served).walked.map((item: { id: string }) => item.id)).toEqual([
        ...IDS,
        'rcpt_04',
        'rcpt_05',
      ]);
    },
  );
});

describe('no byte leaves without the guard checking it', () => {
  it(
    'refuses a receipt edited inside the checkpointed prefix, and serves its neighbours',
    { timeout: CASE_TIMEOUT },
    async () => {
      const dir = await emptyDir();
      await fileWith(dir, IDS);
      const records = frames(await readFile(storeFile(dir)));
      const edited = Buffer.from(await readFile(storeFile(dir)));
      // One byte of the middle receipt's payload. The file keeps its length, the volume keeps its answer
      // for which file this is, and the record the checkpoint ends on is untouched, so nothing an opening
      // can check at the boundary of what it speaks for has moved.
      const second = records[1]!;
      const payloadAt = records[0]!.length + second.length - 32 - readFrame(second).payload.length;
      edited[payloadAt] = (edited[payloadAt]! + 1) % 256;
      await writeFile(storeFile(dir), edited);

      const report = JSON.parse(await answer(dir, { ids: IDS })) as {
        refused: string | null;
        asked: Record<string, string>;
        walked: { id: string }[];
        walkRefused: string | null;
      };
      // The receipt whose bytes disagree with the index is refused, the two around it are served, and a
      // walk stops at the record it cannot check rather than handing it over.
      expect(report.refused).toBeNull();
      expect(report.asked.rcpt_01).toBe(hex(RECEIPT));
      expect(report.asked.rcpt_03).toBe(hex(RECEIPT));
      expect(report.asked.rcpt_02).toContain('does not hold the record that index was read from');
      expect(report.walked.map((item) => item.id)).toEqual(['rcpt_01']);
      expect(report.walkRefused).toContain('does not hold the record that index was read from');

      // The same bytes re-derived from the file are what the store has always called a broken chain, so
      // what a checkpoint skips is the re-derivation and never the check on a served byte.
      expect(JSON.parse(await answer(dir, { declined: true, ids: IDS })).refused).toBe('STORE_CHAIN_BROKEN');
    },
  );

  it('refuses a receipt a walk reaches through a checkpoint the same way a get does', {
    timeout: CASE_TIMEOUT,
  }, async () => {
    const dir = await emptyDir();
    await fileWith(dir, IDS);
    const records = frames(await readFile(storeFile(dir)));
    const edited = Buffer.from(await readFile(storeFile(dir)));
    // The first record this time, which is the one a reader of a pack starts from.
    const first = records[0]!;
    edited[first.length - 33] = (edited[first.length - 33]! + 1) % 256;
    await writeFile(storeFile(dir), edited);

    const report = JSON.parse(await answer(dir, { ids: IDS })) as {
      walked: { id: string }[];
      walkRefused: string | null;
      asked: Record<string, string>;
    };
    expect(report.walked).toEqual([]);
    expect(report.walkRefused).toContain('does not hold the record that index was read from');
    expect(report.asked.rcpt_01).toContain('refused:');
    expect(report.asked.rcpt_03).toBe(hex(RECEIPT));
  });
});

describe('a compaction invalidates the sidecar in the right direction', () => {
  /** Ten receipts aged out and four kept, so the file ends with a trim record and a new seam. */
  async function compacted(
    dir: string,
    declined: boolean,
  ): Promise<{ anchorBefore: string; sidecarBefore: Buffer }> {
    let now = STAMP;
    const retention: ReceiptRetention = { maxAgeSeconds: 1_000, time: fixedClock(() => now) };
    const options = { dir, retention, ...(declined ? { sidecarIndex: false } : {}) };
    const store = await openFileReceiptStore(options);
    for (let i = 0; i < 10; i++) {
      await store.put(`old_${String(i)}`, RECEIPT, now + i);
    }
    // The opening in the middle of the run is what writes an index for the file as it stands, so what
    // comes back from it is the stale statement a later compaction has to make untrue.
    const reopened = await openFileReceiptStore(options);
    const anchorBefore = hex((await reopened.chainState()).anchor);
    const sidecarBefore = declined ? Buffer.alloc(0) : await sidecarBytes(dir);
    now = STAMP + 1_010;
    for (let i = 0; i < 4; i++) {
      await reopened.put(`new_${String(i)}`, OTHER_RECEIPT, now + i);
    }
    return { anchorBefore, sidecarBefore };
  }

  const AFTER = { maxAgeSeconds: 1_000, time: fixedClock(() => STAMP + 1_013) };

  it('reports the seam a compaction moved to, not the chain before it', { timeout: CASE_TIMEOUT }, async () => {
    const dir = await emptyDir();
    const before = await compacted(dir, false);
    const report = JSON.parse(await answer(dir, { retention: AFTER, ids: ['old_0', 'new_0'] })) as {
      anchor: string;
      head: string;
      walked: { id: string; iat: number; receipt: string }[];
    };
    const file = frames(await readFile(storeFile(dir)));
    const seam = hex(readFrame(file[0]!).payload.subarray(0, 32));

    // The anchor is the seam the trim record states, read out of the file rather than remembered, and the
    // chain before it is gone: a reader recomputing forward from the anchor lands on the head.
    expect(report.anchor).toBe(seam);
    expect(report.anchor).not.toBe(before.anchorBefore);
    expect(report.walked.map((item) => item.id)).toEqual(['new_0', 'new_1', 'new_2', 'new_3']);
    let prev = Buffer.from(report.anchor, 'hex');
    for (const item of report.walked) {
      const receipt = Buffer.from(item.receipt, 'hex');
      const idBytes = Buffer.from(item.id, 'utf8');
      const body = Buffer.alloc(1 + 32 + 8 + 2 + idBytes.length + receipt.length);
      Buffer.from(prev).copy(body, 1);
      body.writeBigUInt64BE(BigInt(item.iat), 33);
      body.writeUInt16BE(idBytes.length, 41);
      idBytes.copy(body, 43);
      receipt.copy(body, 43 + idBytes.length);
      prev = Buffer.from(sha256(body));
    }
    expect(hex(prev)).toBe(report.head);
  });

  it('does not report a pre-compaction chain when the stale sidecar is planted back', {
    timeout: CASE_TIMEOUT,
  }, async () => {
    const dir = await emptyDir();
    const { sidecarBefore } = await compacted(dir, false);
    const walkedDir = await emptyDir();
    await compacted(walkedDir, true);

    const asking = { retention: AFTER, ids: ['old_0', 'new_0'] };
    const truth = await answer(walkedDir, { ...asking, declined: true });
    expect(await answer(dir, asking)).toBe(truth);

    // The sidecar the file used to have, written back over the one the compaction replaced: it names a
    // store file of a length and an identity that are no longer there.
    await writeFile(sidecarFile(dir), sidecarBefore);
    const after = JSON.parse(await answer(dir, asking)) as { anchor: string; refused: string | null };
    expect(after.refused).toBeNull();
    expect(await answer(dir, asking)).toBe(truth);
    expect(after.anchor).toBe(JSON.parse(truth).anchor);
  });

  it('leaves an index that speaks for every receipt the compacted file holds', {
    timeout: CASE_TIMEOUT,
  }, async () => {
    const dir = await emptyDir();
    await compacted(dir, false);
    await answer(dir, { retention: AFTER, ids: ['old_0', 'new_0'] });
    const file = await readFile(storeFile(dir));
    const sidecar = readSidecar(await sidecarBytes(dir));
    const receipts = frames(file).filter((frame) => readFrame(frame).kind === 0);
    // File faithful: one entry per receipt the compaction left, the newest ending exactly where the file
    // ends, and nothing indexed for the prefix the trim record retired.
    expect(sidecar.entries.map((entry) => entry.id)).toEqual(receipts.map((frame) => readFrame(frame).id));
    const last = sidecar.entries[sidecar.entries.length - 1]!;
    expect(endOfRecord(last.recordStart, last.id, last.payloadLen)).toBe(file.length);
    expect(sidecar.entries[0]!.recordStart).toBe(file.length - receipts.reduce((n, f) => n + f.length, 0));
  });
});

describe('the sidecar is maintained by an append, not rebuilt', () => {
  it('carries one entry per record in the file, including a receipt refiled under an id already used', {
    timeout: CASE_TIMEOUT,
  }, async () => {
    const dir = await emptyDir();
    await fileWith(dir, IDS);
    const store = await openFileReceiptStore({ dir });
    await store.put(IDS[1]!, FOREIGN, STAMP + 180);
    await answer(dir, { ids: IDS });

    const file = await readFile(storeFile(dir));
    const sidecar = readSidecar(await sidecarBytes(dir));
    expect(sidecar.entries).toHaveLength(4);
    expect(sidecar.entries.map((entry) => entry.id)).toEqual([...IDS, IDS[1]!]);
    let at = 0;
    expect(sidecar.entries.map((entry) => entry.recordStart)).toEqual(
      frames(file).map((frame) => {
        const start = at;
        at += frame.length;
        return start;
      }),
    );
    // The served answer is the later record, and it is the same whichever way the opening got there.
    expect(await answer(dir, { ids: IDS })).toBe(await answer(dir, { declined: true, ids: IDS }));
    expect(JSON.parse(await answer(dir, { ids: IDS })).asked.rcpt_02).toBe(hex(FOREIGN));
  });

  it('reads receipts appended since the index was written out of the store file, then indexes them', {
    timeout: CASE_TIMEOUT,
  }, async () => {
    const dir = await emptyDir();
    await fileWith(dir, IDS);
    const store = await openFileReceiptStore({ dir });
    await store.put('rcpt_04', RECEIPT, STAMP + 180);
    // An append's entry waits for a block, so the fourth receipt is not in the index yet and the one
    // it is written into is read from the file. What the opening answers cannot depend on that.
    expect(readSidecar(await sidecarBytes(dir)).entries).toHaveLength(3);

    const asking = { ids: [...IDS, 'rcpt_04'] };
    const served = await answer(dir, asking);
    expect(served).toBe(await answer(dir, { ...asking, declined: true }));
    expect(JSON.parse(served).walked.map((item: { id: string }) => item.id)).toEqual([...IDS, 'rcpt_04']);

    const file = await readFile(storeFile(dir));
    const sidecar = readSidecar(await sidecarBytes(dir));
    expect(sidecar.entries).toHaveLength(4);
    const last = sidecar.entries[3]!;
    expect(endOfRecord(last.recordStart, last.id, last.payloadLen)).toBe(file.length);
    expect(last.digest).toEqual(frames(file)[3]!.subarray(frames(file)[3]!.length - 32));
  });

  it(
    'writes an appended block without waiting for another opening',
    // Two hundred and fifty six durable appends, one per record a block carries, measured at 0.9s here.
    // The stop is the one the cases above carry times the twenty six appends this one adds.
    { timeout: 60_000 },
    async () => {
      const dir = await emptyDir();
      const store = await openFileReceiptStore({ dir });
      const ids = Array.from({ length: SIDECAR_BLOCK_RECORDS - 1 }, (_, i) => `rcpt_${String(i)}`);
      for (const [i, id] of ids.entries()) {
        await store.put(id, RECEIPT, STAMP + i);
      }
      // Nothing has reached the index: a block is the unit it is written in, and this is the unit's size.
      expect(readSidecar(await sidecarBytes(dir)).entries).toHaveLength(0);
      await store.put(`rcpt_${String(SIDECAR_BLOCK_RECORDS - 1)}`, OTHER_RECEIPT, STAMP + ids.length);

      const file = await readFile(storeFile(dir));
      const sidecar = readSidecar(await sidecarBytes(dir));
      expect(sidecar.entries).toHaveLength(SIDECAR_BLOCK_RECORDS);
      const last = sidecar.entries[sidecar.entries.length - 1]!;
      expect(endOfRecord(last.recordStart, last.id, last.payloadLen)).toBe(file.length);
      expect(await answer(dir, { declined: true, ids: ['rcpt_0'] })).toBe(await answer(dir, { ids: ['rcpt_0'] }));
    },
  );

  it('drops a sidecar that disagrees and rebuilds it from the file, leaving the answers unchanged', {
    timeout: CASE_TIMEOUT,
  }, async () => {
    const dir = await emptyDir();
    await fileWith(dir, IDS);
    await writeFile(sidecarFile(dir), Buffer.from('ASRI', 'utf8'));
    const asking = { ids: IDS };
    const truth = await answer(dir, { ...asking, declined: true });
    expect(await answer(dir, asking)).toBe(truth);
    expect(readSidecar(await sidecarBytes(dir)).entries).toHaveLength(3);
  });
});
