import { afterEach, describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { appendFile, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  openFileReceiptStore,
  openMemoryReceiptStore,
  receiptsNeededForWindow,
  RECEIPT_STORE_FILE,
  type ReceiptRetention,
  type ReceiptServing,
  type ReceiptStore,
  type RetainedWindow,
} from '../src/store.js';

const RECEIPT = Uint8Array.from(Array.from({ length: 64 }, (_, i) => (i * 7) % 256));
const OTHER_RECEIPT = Uint8Array.from(Array.from({ length: 48 }, (_, i) => (i * 11) % 256));
const ZERO_HEAD = new Uint8Array(32);

function sha256(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(createHash('sha256').update(bytes).digest());
}

/**
 * `digest = sha256(kind || prev || iat || idLen || id || receipt)` from the record layout, built
 * here rather than read out of the store so a change to the layout has to be made twice to pass.
 */
function digestOf(prev: Uint8Array, iat: number, id: string, receipt: Uint8Array): Uint8Array {
  const idBytes = Buffer.from(id, 'utf8');
  const body = Buffer.alloc(1 + 32 + 8 + 2 + idBytes.length + receipt.length);
  body[0] = 0;
  Buffer.from(prev).copy(body, 1);
  body.writeBigUInt64BE(BigInt(iat), 33);
  body.writeUInt16BE(idBytes.length, 41);
  idBytes.copy(body, 43);
  Buffer.from(receipt).copy(body, 43 + idBytes.length);
  return sha256(body);
}

/**
 * Splits the file into whole length-prefixed records. Written from the frame layout rather than
 * the store's own reader, so a test that removes a record cannot be fooled by the store agreeing
 * with itself about where the records start.
 */
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

/**
 * One frame read straight out of the layout, so a test can name the bytes a store is making a
 * claim from. The payload is what the record's own digest covers along with its header, and the
 * digest is the trailing 32 bytes of the frame.
 */
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

/**
 * One record's digest recomputed from its own bytes, so a test can check a link between two
 * records without asking the store to agree with itself about what it wrote.
 */
function frameDigest(frame: Buffer): Uint8Array {
  return sha256(frame.subarray(4, frame.length - 32));
}

/** A trim record's report, read out of the payload at the offsets the layout states. */
function readTrimReport(payload: Buffer): {
  seam: Buffer;
  byAge: number;
  byCount: number;
  maxAgeSeconds: number;
  maxCount: number;
} {
  return {
    seam: payload.subarray(0, 32),
    byAge: payload.readUInt32BE(32),
    byCount: payload.readUInt32BE(36),
    maxAgeSeconds: payload.readUInt32BE(40),
    maxCount: payload.readUInt32BE(44),
  };
}

let created: string[] = [];

async function emptyDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'ashaveri-store-'));
  created.push(dir);
  return dir;
}

/**
 * A store that has compacted twice, so its file begins with a run of two trim records and ends with
 * the one receipt the second retirement left. The timestamps are fixed because a caller states the
 * window it expects back.
 */
async function twiceCompacted(): Promise<string> {
  const dir = await emptyDir();
  let now = 1_780_000_000;
  const retention = { maxAgeSeconds: 1_000, now: () => now };
  const first = await openFileReceiptStore({ dir, retention });
  for (let i = 0; i < 10; i++) {
    await first.put(`old_${i}`, RECEIPT, now + i);
  }
  now = 1_780_001_010;
  for (let i = 0; i < 4; i++) {
    await first.put(`new_${i}`, RECEIPT, now + i);
  }
  now = 1_780_002_020;
  const second = await openFileReceiptStore({ dir, retention });
  await second.put('only', OTHER_RECEIPT, now);
  return dir;
}

afterEach(async () => {
  const dirs = created;
  created = [];
  await Promise.all(dirs.map((dir) => rm(dir, { recursive: true, force: true })));
});

describe('receipt store', () => {
  it('serves a receipt written by a previous process', async () => {
    const dir = await emptyDir();
    const first = await openFileReceiptStore({ dir });
    await first.put('rcpt_01', RECEIPT, 1_780_000_000);

    const reopened = await openFileReceiptStore({ dir });
    const bytes = await reopened.get('rcpt_01');
    expect(bytes).not.toBeNull();
    expect(Array.from(bytes!)).toEqual(Array.from(RECEIPT));
  });

  it('states the retained window as its inclusive bounds and a count', async () => {
    const dir = await emptyDir();
    const store = await openFileReceiptStore({ dir });
    expect(await store.window()).toEqual({ from: 0, to: 0, count: 0 });

    // Written newest first, so a store that read insertion order would state the bounds backwards.
    await store.put('rcpt_01', RECEIPT, 1_780_000_120);
    await store.put('rcpt_02', OTHER_RECEIPT, 1_780_000_000);
    expect(await store.window()).toEqual({ from: 1_780_000_000, to: 1_780_000_120, count: 2 });
  });

  it('yields a half-open range in the order the receipts were chained', async () => {
    const dir = await emptyDir();
    const store = await openFileReceiptStore({ dir });
    // Written newest first, so the order a range comes back in cannot be the order of its stamps.
    await store.put('rcpt_03', RECEIPT, 1_780_000_240);
    await store.put('rcpt_01', OTHER_RECEIPT, 1_780_000_000);
    await store.put('rcpt_02', RECEIPT, 1_780_000_120);

    const excluded: string[] = [];
    for await (const item of store.range(1_780_000_000, 1_780_000_240)) {
      excluded.push(item.id);
    }
    expect(excluded).toEqual(['rcpt_01', 'rcpt_02']);

    // A window is a statement about time, so the interval is the stamps'. A reader recomputing one
    // digest per receipt has to visit them the way the store did, so the order is the chain's, and
    // these three come back with their dates running backwards.
    const every: { id: string; iat: number; receipt: Uint8Array }[] = [];
    for await (const item of store.range(0, 2_000_000_000)) {
      every.push(item);
    }
    expect(every.map((item) => item.id)).toEqual(['rcpt_03', 'rcpt_01', 'rcpt_02']);
    expect(every[0]!.iat).toBe(1_780_000_240);
    expect(Array.from(every[0]!.receipt)).toEqual(Array.from(RECEIPT));
  });

  it('stops serving a receipt once it falls outside the retention window', async () => {
    const dir = await emptyDir();
    const store = await openFileReceiptStore({
      dir,
      retention: { maxAgeSeconds: 3_600, now: () => 1_780_000_000 },
    });
    await store.put('expired', RECEIPT, 1_779_996_399);
    await store.put('edge', OTHER_RECEIPT, 1_779_996_400);
    await store.put('recent', RECEIPT, 1_780_000_000);

    expect(await store.get('expired')).toBeNull();
    expect(await store.get('edge')).not.toBeNull();
    expect(await store.window()).toEqual({ from: 1_779_996_400, to: 1_780_000_000, count: 2 });
  });

  it('keeps the newest receipts when the count cap binds before the age window', async () => {
    const dir = await emptyDir();
    const store = await openFileReceiptStore({
      dir,
      retention: { maxAgeSeconds: 3_600, maxCount: 2, now: () => 1_780_000_000 },
    });
    await store.put('first', RECEIPT, 1_779_999_000);
    await store.put('second', OTHER_RECEIPT, 1_779_999_500);
    await store.put('third', RECEIPT, 1_780_000_000);

    const window = await store.window();
    expect(window).toEqual({ from: 1_779_999_500, to: 1_780_000_000, count: 2 });
    expect(await store.get('first')).toBeNull();
    expect(await store.get('second')).not.toBeNull();
    // The cap announces itself: an age-only window cannot start later than its own cutoff,
    // so a retention manifest can say which bound bit without being told.
    expect(window.from).toBeGreaterThan(1_780_000_000 - 3_600);
  });

  it('refuses to open a store whose middle record was removed', async () => {
    const dir = await emptyDir();
    const store = await openFileReceiptStore({ dir });
    await store.put('rcpt_01', RECEIPT, 1_780_000_000);
    await store.put('rcpt_02', OTHER_RECEIPT, 1_780_000_060);
    await store.put('rcpt_03', RECEIPT, 1_780_000_120);

    const file = join(dir, RECEIPT_STORE_FILE);
    const records = frames(await readFile(file));
    expect(records).toHaveLength(3);
    // Two whole, well-framed records that simply do not chain: this is the edit a store with
    // no chain would never notice.
    await writeFile(file, Buffer.concat([records[0]!, records[2]!]));

    const opened = openFileReceiptStore({ dir });
    await expect(opened).rejects.toThrow(/chain/u);
    await opened.catch((error: unknown) => {
      expect(error).toMatchObject({ code: 'STORE_CHAIN_BROKEN' });
    });
  });

  it('refuses to open a store whose frame length was edited, and keeps the bytes it objects to', async () => {
    const dir = await emptyDir();
    const store = await openFileReceiptStore({ dir });
    await store.put('rcpt_01', RECEIPT, 1_780_000_000);
    await store.put('rcpt_02', OTHER_RECEIPT, 1_780_000_060);
    await store.put('rcpt_03', RECEIPT, 1_780_000_120);

    const file = join(dir, RECEIPT_STORE_FILE);
    const records = frames(await readFile(file));
    // A frame no record can be, with every byte of the file still in place: an edit, not an
    // append that never finished. The third receipt is still there to be read around it.
    records[1]!.writeUInt32BE(2, 0);
    const edited = Buffer.concat(records);
    await writeFile(file, edited);

    await expect(openFileReceiptStore({ dir })).rejects.toMatchObject({ code: 'STORE_CHAIN_BROKEN' });
    // Refusing has to leave the file as found. Truncating the tail here would destroy the very
    // evidence the record was edited to hide, which no edit could otherwise accomplish outright.
    expect(await readFile(file)).toEqual(edited);
  });

  it('drops the partial record an interrupted append leaves at the tail', async () => {
    const dir = await emptyDir();
    const store = await openFileReceiptStore({ dir });
    await store.put('rcpt_01', RECEIPT, 1_780_000_000);
    await store.put('rcpt_02', OTHER_RECEIPT, 1_780_000_060);

    const file = join(dir, RECEIPT_STORE_FILE);
    // A frame header promising more bytes than arrived: what a crash mid-append leaves behind.
    await appendFile(file, Buffer.alloc(30, 0xa5));

    const reopened = await openFileReceiptStore({ dir });
    expect(await reopened.get('rcpt_02')).not.toBeNull();

    await reopened.put('rcpt_03', RECEIPT, 1_780_000_120);
    const afterRestart = await openFileReceiptStore({ dir });
    expect(await afterRestart.get('rcpt_03')).not.toBeNull();
    expect(frames(await readFile(file))).toHaveLength(3);
  });

  it('chains two receipts written while each other is in flight', async () => {
    const dir = await emptyDir();
    const store = await openFileReceiptStore({ dir });
    // Two simultaneous completions issue two receipts, and both appends are in the air at once:
    // a store that reads which record it follows only after its own write has settled appends
    // two records naming the same predecessor, and the next open rightly calls that a break.
    await Promise.all([store.put('rcpt_a', RECEIPT, 1_780_000_000), store.put('rcpt_b', OTHER_RECEIPT, 1_780_000_060)]);

    const reopened = await openFileReceiptStore({ dir });
    expect(Array.from((await reopened.get('rcpt_a'))!)).toEqual(Array.from(RECEIPT));
    expect(Array.from((await reopened.get('rcpt_b'))!)).toEqual(Array.from(OTHER_RECEIPT));
    expect(await reopened.window()).toEqual({ from: 1_780_000_000, to: 1_780_000_060, count: 2 });
  });

  it('reclaims the space a trimmed prefix occupied without disturbing the chain', async () => {
    const dir = await emptyDir();
    let now = 1_780_000_000;
    const retention: ReceiptRetention = { maxAgeSeconds: 1_000, now: () => now };
    const store = await openFileReceiptStore({ dir, retention });
    for (let i = 0; i < 10; i++) {
      await store.put(`old_${i}`, RECEIPT, now + i);
    }
    const sizeBeforeTrim = (await stat(join(dir, RECEIPT_STORE_FILE))).size;

    // The window passes over all ten, and four receipts arrive behind it. Ten dead records
    // against four live ones is the point where an append-only file has to give ground.
    now = 1_780_001_010;
    for (let i = 0; i < 4; i++) {
      await store.put(`new_${i}`, RECEIPT, now + i);
    }
    const window = await store.window();
    const head = await store.head();
    expect(window).toEqual({ from: 1_780_001_010, to: 1_780_001_013, count: 4 });
    expect((await stat(join(dir, RECEIPT_STORE_FILE))).size).toBeLessThan(sizeBeforeTrim);

    const reopened = await openFileReceiptStore({ dir, retention });
    expect(await reopened.window()).toEqual(window);
    expect(Array.from(await reopened.head())).toEqual(Array.from(head));
    expect(await reopened.get('old_0')).toBeNull();
    expect(await reopened.get('new_0')).not.toBeNull();
  });

  it('carries a chain head that is the digest of the record just written', async () => {
    const dir = await emptyDir();
    const store = await openFileReceiptStore({ dir });
    expect(Array.from(await store.head())).toEqual(Array.from(ZERO_HEAD));

    await store.put('rcpt_01', RECEIPT, 1_780_000_000);
    const afterFirst = digestOf(ZERO_HEAD, 1_780_000_000, 'rcpt_01', RECEIPT);
    expect(Array.from(await store.head())).toEqual(Array.from(afterFirst));

    await store.put('rcpt_02', OTHER_RECEIPT, 1_780_000_060);
    expect(Array.from(await store.head())).toEqual(
      Array.from(digestOf(afterFirst, 1_780_000_060, 'rcpt_02', OTHER_RECEIPT)),
    );
  });

  it('makes the head a function of the records and nothing else', async () => {
    // The whole value of publishing a head is that a restore reproduces it. Anything the store
    // folds in besides the records it was handed, a path or an open time or a per-file nonce,
    // would make a faithful rebuild look like a forgery.
    const written = async (dir: string): Promise<Uint8Array> => {
      const store = await openFileReceiptStore({ dir });
      await store.put('rcpt_01', RECEIPT, 1_780_000_000);
      await store.put('rcpt_02', OTHER_RECEIPT, 1_780_000_060);
      return store.head();
    };
    const first = await written(await emptyDir());
    expect(Array.from(await written(await emptyDir()))).toEqual(Array.from(first));

    // A rebuild that left a record out chains perfectly, so this is the only thing at the store
    // seam that says so. The removed-record test above is the half the walk does catch.
    const shortened = await openFileReceiptStore({ dir: await emptyDir() });
    await shortened.put('rcpt_02', OTHER_RECEIPT, 1_780_000_060);
    expect(Array.from(await shortened.head())).not.toEqual(Array.from(first));
    expect(await shortened.get('rcpt_02')).not.toBeNull();
  });
});

describe('trim records', () => {
  it('chains from the empty digest and carries the seam the survivors start from', async () => {
    // A trim record describes the records that were in front of it, and the slot it has been using
    // to say so is the one every other record spends on the digest it follows. That is why a file
    // could only ever hold one: a second has nowhere to put what it knows.
    const dir = await emptyDir();
    let now = 1_780_000_000;
    const store = await openFileReceiptStore({ dir, retention: { maxAgeSeconds: 1_000, now: () => now } });
    for (let i = 0; i < 10; i++) {
      await store.put(`old_${i}`, RECEIPT, now + i);
    }
    now = 1_780_001_010;
    for (let i = 0; i < 4; i++) {
      await store.put(`new_${i}`, RECEIPT, now + i);
    }

    const records = frames(await readFile(join(dir, RECEIPT_STORE_FILE)));
    expect(records).toHaveLength(5);
    const trim = readFrame(records[0]!);
    const survivor = readFrame(records[1]!);
    expect(trim.kind).toBe(1);
    expect(trim.id).toBe('');
    expect(Array.from(trim.prev)).toEqual(Array.from(ZERO_HEAD));
    expect(Array.from(survivor.prev)).toEqual(Array.from(trim.payload.subarray(0, 32)));
    // The seam is the digest of the last record the file no longer holds, and it is the whole
    // claim the record makes, so a test that accepted zeros here would pass without checking it.
    expect(Array.from(survivor.prev)).not.toEqual(Array.from(ZERO_HEAD));
  });

  it('keeps every retirement it has ever written down, chained in the order they happened', async () => {
    // A compaction that overwrote the record the last one left would forget why the earlier
    // receipts had gone, and a store that had to say so twice had nowhere to say it. Both are the
    // same missing thing: a run of records that chain to each other instead of to the survivors.
    const dir = await twiceCompacted();
    const records = frames(await readFile(join(dir, RECEIPT_STORE_FILE)));
    expect(records).toHaveLength(3);
    const older = readFrame(records[0]!);
    const newer = readFrame(records[1]!);
    const survivor = readFrame(records[2]!);
    expect([older.kind, newer.kind, survivor.kind]).toEqual([1, 1, 0]);
    expect(Array.from(older.prev)).toEqual(Array.from(ZERO_HEAD));
    expect(Array.from(newer.prev)).toEqual(Array.from(frameDigest(records[0]!)));
    expect(Array.from(newer.digest)).toEqual(Array.from(frameDigest(records[1]!)));
    expect(Array.from(survivor.prev)).toEqual(Array.from(newer.payload.subarray(0, 32)));
    expect(Array.from(older.payload.subarray(0, 32))).not.toEqual(Array.from(survivor.prev));

    const reopened = await openFileReceiptStore({ dir });
    expect(Array.from((await reopened.get('only'))!)).toEqual(Array.from(OTHER_RECEIPT));
    expect(await reopened.window()).toEqual({ from: 1_780_002_020, to: 1_780_002_020, count: 1 });
  });

  it('names the bound that retired each receipt and the policy it retired under', async () => {
    // A surviving window cannot say which bound emptied it, and the window is all a manifest would
    // otherwise have to go on. The compaction is the one moment that knows, and the only record
    // that survives a restart knowing it, so both the pair and the policy behind it go in the file.
    const agedDir = await emptyDir();
    let now = 1_780_000_000;
    const byAge = await openFileReceiptStore({ dir: agedDir, retention: { maxAgeSeconds: 1_000, now: () => now } });
    for (let i = 0; i < 10; i++) {
      await byAge.put(`old_${i}`, RECEIPT, now + i);
    }
    now = 1_780_001_010;
    for (let i = 0; i < 4; i++) {
      await byAge.put(`new_${i}`, RECEIPT, now + i);
    }

    const frame = frames(await readFile(join(agedDir, RECEIPT_STORE_FILE)))[0]!;
    const trimmed = readFrame(frame);
    expect(trimmed.payload).toHaveLength(48);
    const aged = readTrimReport(trimmed.payload);
    expect(aged.byAge).toBe(10);
    expect(aged.byCount).toBe(0);
    expect(aged.maxAgeSeconds).toBe(1_000);
    // Zero is how the record says no cap was configured. A cap of one is a different store, and a
    // reader that cannot tell the two apart cannot tell a full window from an uncapped one.
    expect(aged.maxCount).toBe(0);

    const cappedDir = await emptyDir();
    const byCount = await openFileReceiptStore({
      dir: cappedDir,
      retention: { maxCount: 4, now: () => 1_780_000_000 },
    });
    for (let i = 0; i < 9; i++) {
      await byCount.put(`rcpt_${i}`, RECEIPT, 1_780_000_000 + i);
    }

    const capped = readTrimReport(readFrame(frames(await readFile(join(cappedDir, RECEIPT_STORE_FILE)))[0]!).payload);
    expect(capped.byAge).toBe(0);
    expect(capped.byCount).toBe(5);
    expect(capped.maxAgeSeconds).toBe(0);
    expect(capped.maxCount).toBe(4);
  });

  it('refuses to open a store whose trim history was edited', async () => {
    // The run is the only account the file gives of the receipts it no longer holds, so it is worth
    // deleting for someone who wants a store to look smaller than it was. Each record in it names
    // the digest of the one in front of it, and the survivors name the newest seam, so taking
    // either out of a two record run leaves a link that does not close.
    const dir = await twiceCompacted();
    const file = join(dir, RECEIPT_STORE_FILE);
    const records = frames(await readFile(file));
    expect(records).toHaveLength(3);

    await writeFile(file, Buffer.concat([records[0]!, records[2]!]));
    await expect(openFileReceiptStore({ dir })).rejects.toMatchObject({ code: 'STORE_CHAIN_BROKEN' });

    await writeFile(file, Buffer.concat([records[1]!, records[2]!]));
    await expect(openFileReceiptStore({ dir })).rejects.toMatchObject({ code: 'STORE_CHAIN_BROKEN' });
  });
});

describe('chain state', () => {
  it('anchors an empty store at its own head, so a reader has one rule not two', async () => {
    // With nothing retained there is no oldest record to take a predecessor from. Reporting the
    // head means recomputing forward over zero items returns the anchor unchanged and the check
    // the populated case passes is the same check this one passes.
    const store = openMemoryReceiptStore();
    const state = await store.chainState();
    expect(Array.from(state.anchor)).toEqual(Array.from(await store.head()));
    expect(state.retired).toEqual({ byAge: 0, byCount: 0, trims: [] });
  });

  it('credits a retirement to the age bound that caused it', async () => {
    // window() can only report what survives, and a window that starts after its own cutoff is
    // equally consistent with an old quiet store and with a cap that evicted most of a young one.
    // Only the code that dropped the record knows which, so that is where the split has to come from.
    const store = openMemoryReceiptStore({
      retention: { maxAgeSeconds: 3_600, maxCount: 100, now: () => 1_780_000_000 },
    });
    await store.put('expired', RECEIPT, 1_779_996_399);
    await store.put('recent', OTHER_RECEIPT, 1_780_000_000);

    expect((await store.window()).count).toBe(1);
    expect(await store.chainState()).toMatchObject({
      retired: { byAge: 1, byCount: 0, trims: [] },
    });
  });

  it('publishes an anchor the retained receipts chain forward to the head from', async () => {
    // The whole reason an anchor is worth publishing is that a reader holding a pack and nothing
    // else can start at the anchor, recompute a digest per receipt, and land on the head. That is
    // a proof rather than a promise, and it only works if the anchor is the predecessor of the
    // oldest retained receipt rather than wherever the chain happens to have finished.
    const store = openMemoryReceiptStore({ retention: { maxCount: 2, now: () => 1_780_000_000 } });
    await store.put('rcpt_01', RECEIPT, 1_780_000_000);
    await store.put('rcpt_02', OTHER_RECEIPT, 1_780_000_060);
    await store.put('rcpt_03', RECEIPT, 1_780_000_120);

    const retained: { id: string; iat: number; receipt: Uint8Array }[] = [];
    for await (const item of store.range(0, 2_000_000_000)) {
      retained.push(item);
    }
    expect(retained.map((item) => item.id)).toEqual(['rcpt_02', 'rcpt_03']);

    let prev = (await store.chainState()).anchor;
    for (const item of retained) {
      prev = digestOf(prev, item.iat, item.id, item.receipt);
    }
    expect(Array.from(prev)).toEqual(Array.from(await store.head()));
  });

  it('retires a prefix of the chain even when the timestamps do not line up that way', async () => {
    // Three completions whose stamps were taken out of order: the oldest-dated receipt sits in the
    // middle of the chain, so a policy that reads it as the oldest record would leave a hole where
    // it stood. A hole is what the chain exists to make visible, and a retained set with one in it
    // cannot be walked from any anchor to any head, so the store has to retire up to the chain and
    // no further than the chain.
    const store = openMemoryReceiptStore({ retention: { maxCount: 2, now: () => 1_780_000_000 } });
    await store.put('rcpt_c', RECEIPT, 1_780_000_120);
    await store.put('rcpt_a', OTHER_RECEIPT, 1_780_000_000);
    await store.put('rcpt_b', RECEIPT, 1_780_000_060);

    const retained: { id: string; iat: number; receipt: Uint8Array }[] = [];
    for await (const item of store.range(0, 2_000_000_000)) {
      retained.push(item);
    }
    const state = await store.chainState();
    let prev = state.anchor;
    for (const item of retained) {
      prev = digestOf(prev, item.iat, item.id, item.receipt);
    }
    expect(Array.from(prev)).toEqual(Array.from(await store.head()));
  });

  it('walks a compacted store from its anchor to its head after a restart', async () => {
    // The anchor is only worth publishing if a reader holding nothing but the pack can start at it
    // and land on the head, and the store cannot answer that from memory: the receipts the chain
    // starts from are no longer in the file, so the digest has to have been written down before
    // they went.
    const dir = await emptyDir();
    let now = 1_780_000_000;
    const retention = { maxAgeSeconds: 1_000, now: () => now };
    const written = await openFileReceiptStore({ dir, retention });
    for (let i = 0; i < 10; i++) {
      await written.put(`old_${i}`, RECEIPT, now + i);
    }
    now = 1_780_001_010;
    for (let i = 0; i < 4; i++) {
      await written.put(`new_${i}`, OTHER_RECEIPT, now + i);
    }

    const store = await openFileReceiptStore({ dir, retention });
    const retained: { id: string; iat: number; receipt: Uint8Array }[] = [];
    for await (const item of store.range(0, 2_000_000_000)) {
      retained.push(item);
    }
    expect(retained.map((item) => item.id)).toEqual(['new_0', 'new_1', 'new_2', 'new_3']);

    let prev = (await store.chainState()).anchor;
    for (const item of retained) {
      prev = digestOf(prev, item.iat, item.id, item.receipt);
    }
    expect(Array.from(prev)).toEqual(Array.from(await store.head()));
  });

  it('states what a restarted store retired, and why', async () => {
    // Nothing in the surviving window says which bound emptied it, and the process that applied the
    // bound is gone. This is the one place the answer outlives it.
    const dir = await emptyDir();
    let now = 1_780_000_000;
    const retention = { maxAgeSeconds: 1_000, maxCount: 100, now: () => now };
    const written = await openFileReceiptStore({ dir, retention });
    for (let i = 0; i < 10; i++) {
      await written.put(`old_${i}`, RECEIPT, now + i);
    }
    now = 1_780_001_010;
    for (let i = 0; i < 4; i++) {
      await written.put(`new_${i}`, RECEIPT, now + i);
    }

    const store = await openFileReceiptStore({ dir, retention });
    const state = await store.chainState();
    expect(state.retired.trims).toEqual([
      { at: 1_780_001_010, byAge: 10, byCount: 0, under: { maxAgeSeconds: 1_000, maxCount: 100 } },
    ]);
    expect(state.retired.byAge).toBe(10);
    expect(state.retired.byCount).toBe(0);
    // The equation a pack generator can assert and a verifier can re-check without being told the
    // traffic: what is served plus what left is everything that was ever issued.
    expect((await store.window()).count + state.retired.byAge + state.retired.byCount).toBe(14);
  });
});

describe('a stamp the record cannot state', () => {
  /** Four instants the 8-byte field has no spelling for, and the largest one it has a spelling for. */
  const REFUSED = [1.5, -1, Number.MAX_SAFE_INTEGER + 1, Number.NaN];

  it('is refused by the file engine before a byte reaches the file', async () => {
    const dir = await emptyDir();
    const store = await openFileReceiptStore({ dir });
    for (const iat of REFUSED) {
      await expect(store.put('rcpt_bad', RECEIPT, iat)).rejects.toMatchObject({
        code: 'RECORD_STAMP_OUT_OF_RANGE',
      });
    }
    // Refusing has to cost nothing. An append that stopped after its first bytes is the one shape the
    // walk repairs rather than reports, so a record written and then objected to would read back as an
    // interrupted append and take its own tail off the file.
    expect((await stat(join(dir, RECEIPT_STORE_FILE))).size).toBe(0);
    expect(await store.window()).toEqual({ from: 0, to: 0, count: 0 });
    expect(Array.from(await store.head())).toEqual(Array.from(ZERO_HEAD));

    await store.put('rcpt_max', RECEIPT, Number.MAX_SAFE_INTEGER);
    expect(await store.window()).toEqual({ from: Number.MAX_SAFE_INTEGER, to: Number.MAX_SAFE_INTEGER, count: 1 });
    // Reopening is the check that the refusals left a file rather than a promise: the walk has to read
    // the one record back and call the chain whole.
    const reopened = await openFileReceiptStore({ dir });
    expect(Array.from((await reopened.get('rcpt_max'))!)).toEqual(Array.from(RECEIPT));
  });

  it('is refused by the memory engine without moving the chain', async () => {
    const store = openMemoryReceiptStore();
    await store.put('rcpt_first', RECEIPT, 1_780_000_000);
    const head = await store.head();
    for (const iat of REFUSED) {
      await expect(store.put('rcpt_bad', RECEIPT, iat)).rejects.toMatchObject({
        code: 'RECORD_STAMP_OUT_OF_RANGE',
      });
    }
    // The receipt before them still chains, and the refused id was never filed under it: a head that
    // moved on a record nobody holds the id for would be a hole the chain exists to make visible.
    expect(Array.from(await store.head())).toEqual(Array.from(head));
    expect(await store.get('rcpt_bad')).toBeNull();
    expect((await store.window()).count).toBe(1);
  });
});

describe('the window a store is configured to hold', () => {
  /** Five years of whole 365-day years, the multi-year period a count bound is asked to cover. */
  const FIVE_YEARS_SECONDS = 5 * 365 * 24 * 60 * 60;
  /**
   * The volume this estate states for one gateway address: 6,000 requests a minute, which
   * `DEFAULT_PEER_RATE` in `gateway/src/access.ts` and section 1 of `docs/access-control.md` both read
   * as a hundred requests a second sustained. A receipt is issued per admitted request, so a single busy
   * address fills a store at this rate and a deployment behind one reverse proxy, which is the shape that
   * document names, serves all of its traffic through it. Past one address the store fills faster, which
   * only ever raises the count a window takes.
   *
   * This number is used at the arithmetic, not at the disk. The file store fsyncs every append it makes,
   * which is the durability the receipts depend on and is not the thing these cases are about, so a
   * fixture that wrote a second of measured traffic through the store spent its budget on syncs: at a
   * hundred appends two of the cases below exceeded the runner's default window while the same rules pass
   * on ten. The rate rule is therefore asserted whole, at this number, in the case that derives a count
   * from a period and a spacing with no file in sight.
   */
  const MEASURED_RECEIPTS_PER_SECOND = 100;
  /** Receipts in a fixture that ends up at its bound: ten, the size every other case here writes. */
  const FIXTURE_RECEIPTS = 10;
  /** The bound those fixtures sit at, so the pairing this unit refuses is the one being exercised. */
  const FIXTURE_BOUND = FIXTURE_RECEIPTS / 2;
  /** One instant, because a burst inside a second does not cross a second boundary. */
  const STAMP = 1_780_000_000;
  /**
   * The stop for a case that opens a real file: ten durable appends and up to three opens cost well under
   * a tenth of this locally, and the runner is slower per sync by a wide margin, so this is the room to
   * reach the stop rather than a ceiling raised to hide a slow case.
   */
  const FILE_CASE_TIMEOUT = 15_000;

  /** `count` receipts, all stamped at one instant. */
  async function burst(store: ReceiptStore, count: number): Promise<void> {
    for (let i = 0; i < count; i++) {
      await store.put(`rcpt_${String(i).padStart(3, '0')}`, RECEIPT, STAMP);
    }
  }

  it('refuses to open a bound that cannot hold the five-year period beside it', { timeout: FILE_CASE_TIMEOUT }, async () => {
    // The pairing this unit exists to stop: a period configured in years and a storage bound
    // configured in receipts, with the traffic to show that the second cannot cover the first. It is
    // the reopening that knows, because the rate is the file's own.
    const dir = await emptyDir();
    const retention: ReceiptRetention = {
      maxAgeSeconds: FIVE_YEARS_SECONDS,
      maxCount: FIXTURE_BOUND,
      now: () => STAMP + 10,
    };
    const written = await openFileReceiptStore({ dir, retention });
    await burst(written, FIXTURE_RECEIPTS);
    expect(await written.window()).toEqual({ from: STAMP, to: STAMP, count: FIXTURE_BOUND });

    const file = join(dir, RECEIPT_STORE_FILE);
    const bytes = await readFile(file);
    await expect(openFileReceiptStore({ dir, retention })).rejects.toMatchObject({
      code: 'RETENTION_WINDOW_UNHOLDABLE',
    });
    // A refused opening has to leave the file as it found it: this is the one moment an operator learns
    // the pairing was wrong, and the receipts are the evidence for it.
    expect(await readFile(file)).toEqual(bytes);
    expect(frames(bytes)).toHaveLength(FIXTURE_RECEIPTS);
  });

  it('names the period, the bound and the count the period takes in the refusal', { timeout: FILE_CASE_TIMEOUT }, async () => {
    const dir = await emptyDir();
    const retention: ReceiptRetention = {
      maxAgeSeconds: FIVE_YEARS_SECONDS,
      maxCount: FIXTURE_BOUND,
      now: () => STAMP + 10,
    };
    const written = await openFileReceiptStore({ dir, retention });
    await burst(written, FIXTURE_RECEIPTS);

    const message = await openFileReceiptStore({ dir, retention }).then(
      () => 'opened, no refusal',
      (error: unknown) => (error as Error).message,
    );
    // The two quantities that disagree, and the derived number that decides between them, in one
    // sentence: an operator raising the bound has to be able to see what they are raising it to. The
    // count is written out rather than recomputed here, and it is the derivation the refusal states:
    // five retained receipts stamped at one instant are read as the fastest traffic a file can report,
    // so the window has to hold one receipt for each of the four gaps between them per second, which is
    // 4 * 157,680,000 = 630,720,000 receipts, plus the one stamped at its older edge.
    expect(message).toContain(`${String(FIVE_YEARS_SECONDS)} seconds`);
    expect(message).toContain('bound of 5 receipts');
    expect(message).toContain('630720001 receipts');
    expect(message).toContain('RETENTION_WINDOW_UNHOLDABLE');
  });

  it('opens the same five-year period on a bound the burst cannot reach', { timeout: FILE_CASE_TIMEOUT }, async () => {
    // The refusal is about a pairing, not about a long period: configured the other half, the same
    // traffic and the same five years start.
    const dir = await emptyDir();
    const written = await openFileReceiptStore({
      dir,
      retention: { maxAgeSeconds: FIVE_YEARS_SECONDS, maxCount: 1_000_000_000_000, now: () => STAMP + 10 },
    });
    await burst(written, FIXTURE_RECEIPTS);
    const reopened = await openFileReceiptStore({
      dir,
      retention: { maxAgeSeconds: FIVE_YEARS_SECONDS, maxCount: 1_000_000_000_000, now: () => STAMP + 10 },
    });
    expect(await reopened.window()).toEqual({ from: STAMP, to: STAMP, count: FIXTURE_RECEIPTS });
  });

  it('holds a window its bound does cover, on either side of the line', async () => {
    // Fifty receipts sharing one stamp is a store at its bound either way. What separates the two
    // cases is the period asked for: one second is inside what those stamps cover, two seconds is not.
    const held = async (maxAgeSeconds: number): Promise<string> => {
      const dir = await emptyDir();
      const retention: ReceiptRetention = { maxAgeSeconds, maxCount: 10, now: () => STAMP };
      const store = await openFileReceiptStore({ dir, retention });
      await burst(store, 10);
      return openFileReceiptStore({ dir, retention }).then(
        () => 'opened',
        (error: unknown) => String((error as { code?: string }).code),
      );
    };
    expect(await held(1)).toBe('opened');
    expect(await held(2)).toBe('RETENTION_WINDOW_UNHOLDABLE');
  });

  it('leaves a store below its bound alone, however narrow its stamps are', async () => {
    // Three receipts in one second say nothing about a five-year window: nothing is being shed, and
    // the traffic that would decide the question has not arrived. Refusing here would refuse a quiet
    // deployment for being quiet.
    const dir = await emptyDir();
    const retention: ReceiptRetention = { maxAgeSeconds: FIVE_YEARS_SECONDS, maxCount: 10, now: () => STAMP };
    const store = await openFileReceiptStore({ dir, retention });
    await burst(store, 3);
    const reopened = await openFileReceiptStore({ dir, retention });
    expect(await reopened.window()).toEqual({ from: STAMP, to: STAMP, count: 3 });
  });

  it('asks nothing of a store bounded on one side only', async () => {
    // A configuration with no age bound asks the store to hold no span of time, and one with no count
    // bound asks it to hold every receipt it has. Neither has a pairing to contradict, so neither is
    // asked, and both are opened here at the same traffic the cases above refuse at: ten receipts at the
    // bound, all of them inside one second.
    const atBound = async (retention: ReceiptRetention): Promise<string> => {
      const dir = await emptyDir();
      const store = await openFileReceiptStore({ dir, retention });
      await burst(store, 10);
      return openFileReceiptStore({ dir, retention }).then(
        () => 'opened',
        (error: unknown) => String((error as { code?: string }).code),
      );
    };
    expect(await atBound({ maxCount: 10, now: () => STAMP })).toBe('opened');
    expect(await atBound({ maxAgeSeconds: FIVE_YEARS_SECONDS, now: () => STAMP })).toBe('opened');
  });

  it(
    'keeps a long period and answers a short query on the same volume',
    // Ten durable appends, two opens and ten reads, measured here at 32ms: the same volume as the
    // cases above, so the same stop, which the comment on `FILE_CASE_TIMEOUT` measures.
    { timeout: FILE_CASE_TIMEOUT },
    async () => {
      // The pairing the split was for. The durability bound holds the period, the serving bound holds
      // the query, and neither asks the other for room: ten receipts one second apart are exactly what
      // a store that keeps ten receipts and is asked to keep nine seconds of them has to hold, and a
      // walk over all ten is resolved two at a time.
      const dir = await emptyDir();
      const spaced: ReceiptRetention = { maxAgeSeconds: 9, maxCount: FIXTURE_RECEIPTS, now: () => STAMP + 9 };
      const serving: ReceiptServing = { maxServedReceipts: 2 };
      const written = await openFileReceiptStore({ dir, retention: spaced, serving });
      for (let i = 0; i < FIXTURE_RECEIPTS; i++) {
        await written.put(`rcpt_${String(i).padStart(2, '0')}`, RECEIPT, STAMP + i);
      }
      expect(await written.window()).toEqual({
        from: STAMP,
        to: STAMP + FIXTURE_RECEIPTS - 1,
        count: FIXTURE_RECEIPTS,
      });

      // Reopened rather than kept, because the question this answers is one a volume is asked at a
      // start. Compare against the old single number, which was two here, and this store does not open.
      const reopened = await openFileReceiptStore({ dir, retention: spaced, serving });
      const walked: string[] = [];
      for await (const item of reopened.range(0, 2_000_000_000)) {
        walked.push(item.id);
      }
      // Every receipt the store kept, in the order they were chained, from a walk that was never held
      // more than two of them at a time.
      expect(walked).toEqual(
        Array.from({ length: FIXTURE_RECEIPTS }, (_, i) => `rcpt_${String(i).padStart(2, '0')}`),
      );
    },
  );

  it(
    'refuses on the durability bound and names the serving bound as not the short one',
    { timeout: FILE_CASE_TIMEOUT },
    async () => {
      const dir = await emptyDir();
      const retention: ReceiptRetention = {
        maxAgeSeconds: FIVE_YEARS_SECONDS,
        maxCount: FIXTURE_BOUND,
        now: () => STAMP + 10,
      };
      // A serving bound ten times the durability bound, which is a lawful pairing and the one a single
      // number could not state: what one query may hold says nothing about what the file keeps.
      const serving: ReceiptServing = { maxServedReceipts: 100 };
      const written = await openFileReceiptStore({ dir, retention, serving });
      await burst(written, FIXTURE_RECEIPTS);

      const message = await openFileReceiptStore({ dir, retention, serving }).then(
        () => 'opened, no refusal',
        (error: unknown) => (error as Error).message,
      );
      // One line, read by an operator with two counts in front of them: the bound that is short, the
      // count the period takes, the shortfall, and which of the two numbers raising fixes nothing.
      expect(message).toContain('RETENTION_WINDOW_UNHOLDABLE');
      expect(message).toContain('durability bound of 5 receipts');
      // Five retained receipts stamped at one instant are read as the fastest traffic a file can
      // report, so the window takes 4 * 157,680,000 = 630,720,000 receipts plus the one stamped at its
      // older edge, which is 630,719,996 more than the bound this store was opened with holds.
      expect(message).toContain('630720001 receipts');
      expect(message).toContain('short by 630719996 receipts');
      expect(message).toContain('the serving bound of 100 receipts is not the number to raise');
    },
  );

  it('derives the count a window takes from the period and the traffic, and declines to guess', () => {
    const at = (count: number, from: number, to: number): RetainedWindow => ({ from, to, count });
    // The receipt at the older edge is the `+ 1`: ten receipts one second apart span nine seconds, so
    // a ten second window at that rate needs the eleventh that lands on the far edge of it.
    expect(receiptsNeededForWindow(10, at(10, 1_000, 1_009))).toBe(11);
    // The same traffic asked to hold one second needs only the two receipts on either side of it.
    expect(receiptsNeededForWindow(1, at(10, 1_000, 1_009))).toBe(2);
    // Stamps covering no time at all are read as one second, the fastest traffic a file can report, so
    // the number derived is the smallest a refusal could rest on rather than an infinity.
    expect(receiptsNeededForWindow(2, at(10, 1_000, 1_000))).toBe(19);
    // Null both times: one record measures no rate, and a window bounded only by count asks for no
    // span of time to hold.
    expect(receiptsNeededForWindow(10, at(1, 1_000, 1_000))).toBeNull();
    expect(receiptsNeededForWindow(0, at(10, 1_000, 1_009))).toBeNull();
    // The measured volume, at the arithmetic rather than on disk. A hundred receipts sharing one instant
    // is one second of traffic at the rate `docs/access-control.md` states for an address, and a
    // five-year window at that rate takes 99 * 157,680,000 = 15,610,320,000 receipts plus the one at
    // its older edge, which is 1.56 million times the bound of ten thousand this CLI opens.
    expect(receiptsNeededForWindow(FIVE_YEARS_SECONDS, at(MEASURED_RECEIPTS_PER_SECOND, STAMP, STAMP))).toBe(
      15_610_320_001,
    );
    // The same hundred receipts with their older and newer edges ninety-nine seconds apart ask for a
    // ninety-ninth of that: the derivation reads the file's own spacing, which is why a quiet store and a
    // busy one get different answers and why neither answer is a constant anybody configured.
    expect(receiptsNeededForWindow(FIVE_YEARS_SECONDS, at(MEASURED_RECEIPTS_PER_SECOND, STAMP, STAMP + 99))).toBe(
      157_680_001,
    );
  });
});

/**
 * The serving bound and the durability bound govern two different things, so these cases hold one still
 * and move the other. The durability bound is what a store keeps and the only bound retirement reads;
 * the serving bound is what one walk holds at a time and retires nothing, so a walk over a window
 * holding more receipts than it returns every receipt the store kept, in the order they were chained,
 * resolved in batches. That equivalence is the claim: a bound that changed which receipts a caller is
 * told about would be a shorter window wearing a different name.
 *
 * The in-process engine carries most of them, because the claim is about a walk and not about a volume
 * and an engine with nothing behind it answers the same question in milliseconds. The one case that is
 * about a volume is the last: it runs a retirement and a compaction underneath a walk in flight, which
 * is the moment a walk that resolved positions rather than ids would read a receipt from where it no
 * longer sits.
 */
describe('the serving bound', () => {
  const STAMP = 1_780_000_000;
  const WALKED = 12;

  /** `count` receipts, stamped a second apart and named for the order they are chained in. */
  async function filled(store: ReceiptStore, count: number): Promise<string[]> {
    const ids: string[] = [];
    for (let i = 0; i < count; i++) {
      const id = `rcpt_${String(i).padStart(2, '0')}`;
      ids.push(id);
      await store.put(id, RECEIPT, STAMP + i);
    }
    return ids;
  }

  /** Every receipt a walk over the whole store hands back, in the order it hands them back. */
  async function walked(store: ReceiptStore): Promise<string[]> {
    const seen: string[] = [];
    for await (const item of store.range(0, 2_000_000_000)) {
      seen.push(item.id);
    }
    return seen;
  }

  it('serves the whole retained window at every serving bound, in the chain order', async () => {
    const expected = await filled(openMemoryReceiptStore(), WALKED);
    // One is the smallest bound there can be and the widest is the whole retained set, so the row of
    // them is the arithmetic of the batching with no file and no clock in the way.
    for (const maxServedReceipts of [1, 2, 5, WALKED, WALKED * 10, undefined]) {
      const store = openMemoryReceiptStore({ serving: maxServedReceipts === undefined ? {} : { maxServedReceipts } });
      await filled(store, WALKED);
      expect(await walked(store), `a serving bound of ${String(maxServedReceipts)} is a walk's own room`).toEqual(
        expected,
      );
    }
  });

  it('retires nothing, however far below the retained set it sits', async () => {
    const store = openMemoryReceiptStore({
      retention: { maxCount: 100, now: () => STAMP + 10 },
      serving: { maxServedReceipts: 1 },
    });
    await filled(store, 5);
    // Five receipts kept, a query allowed one at a time, and a retirement report that says nothing left.
    expect(await store.window()).toEqual({ from: STAMP, to: STAMP + 4, count: 5 });
    expect(await store.chainState()).toMatchObject({ retired: { byAge: 0, byCount: 0 } });
    expect(await walked(store)).toHaveLength(5);
  });

  it('leaves the durability bound the only bound that drops a prefix', async () => {
    const store = openMemoryReceiptStore({
      retention: { maxCount: 3, now: () => STAMP },
      serving: { maxServedReceipts: 1 },
    });
    for (let i = 0; i < 5; i++) {
      await store.put(`rcpt_${String(i)}`, RECEIPT, STAMP);
    }
    // The count bound took the front of the chain and the tail is intact, which is the shape a chain
    // can prove: a serving bound of one receipt did not reach into the retained set at all.
    expect(await walked(store)).toEqual(['rcpt_2', 'rcpt_3', 'rcpt_4']);
    expect(await store.chainState()).toMatchObject({ retired: { byCount: 2, byAge: 0 } });
  });

  it('holds a walk to the receipts issued before it was asked for', async () => {
    const store = openMemoryReceiptStore({ serving: { maxServedReceipts: 2 } });
    const expected = await filled(store, 6);
    const walk = store.range(0, 2_000_000_000)[Symbol.asyncIterator]();
    const seen: string[] = [];
    let step = await walk.next();
    // Issued while the walk is paused with one batch behind it: these belong to the next window, which
    // is what a store that is still signing completions owes a reader recomputing a chain head.
    await store.put('rcpt_late_0', RECEIPT, STAMP);
    await store.put('rcpt_late_1', RECEIPT, STAMP);
    while (!step.done) {
      seen.push(step.value.id);
      step = await walk.next();
    }
    expect(seen).toEqual(expected);
    expect(await store.window()).toEqual({ from: STAMP, to: STAMP + 5, count: 8 });
    expect(await walked(store)).toEqual([...expected, 'rcpt_late_0', 'rcpt_late_1']);
  });

  it(
    'reads a receipt from where it lies after a compaction moved it under the walk',
    // Nine durable appends and one open, four of them landing while a walk is parked between two
    // yields, measured here at 26ms. The stop is the one the cases in the describe above carry for the
    // same volume of appends, which is ten durable writes and an open at 15s.
    { timeout: 15_000 },
    async () => {
      const dir = await emptyDir();
      let now = STAMP;
      const store = await openFileReceiptStore({
        dir,
        retention: { maxAgeSeconds: 1_000, now: () => now },
        serving: { maxServedReceipts: 1 },
      });
      // Four receipts that the next clock reading ages out, three that it keeps, and the ages chosen so
      // the dead prefix outweighs the live tail: that is when a compaction runs, and it rewrites every
      // survivor to a new offset while the walk below is parked between two yields.
      for (let i = 0; i < 4; i++) {
        await store.put(`aged_${String(i)}`, RECEIPT, STAMP);
      }
      for (let i = 0; i < 3; i++) {
        await store.put(`kept_${String(i)}`, OTHER_RECEIPT, STAMP + 2_000);
      }
      const walk = store.range(0, 2_000_000_000)[Symbol.asyncIterator]();
      const seen: string[] = [];
      let step = await walk.next();
      now = STAMP + 2_000;
      await store.put('kept_later', RECEIPT, now);
      while (!step.done) {
        seen.push(step.value.id);
        step = await walk.next();
      }
      // The first receipt the walk had already reached, then the three that survived the retirement,
      // read from the offsets the compaction gave them. `aged_1` onward left the store while the walk
      // was parked, which is what its window had already said it kept, and `kept_later` was issued
      // after the walk was asked for.
      expect(seen).toEqual(['aged_0', 'kept_0', 'kept_1', 'kept_2']);
      expect(await walked(store)).toEqual(['kept_0', 'kept_1', 'kept_2', 'kept_later']);
    },
  );
});


