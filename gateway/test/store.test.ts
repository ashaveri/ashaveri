import { afterEach, describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { appendFile, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { openFileReceiptStore, RECEIPT_STORE_FILE, type ReceiptRetention } from '../src/store.js';

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

let created: string[] = [];

async function emptyDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'ashaveri-store-'));
  created.push(dir);
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

  it('yields a half-open range oldest first, with the bytes to verify', async () => {
    const dir = await emptyDir();
    const store = await openFileReceiptStore({ dir });
    await store.put('rcpt_03', RECEIPT, 1_780_000_240);
    await store.put('rcpt_01', OTHER_RECEIPT, 1_780_000_000);
    await store.put('rcpt_02', RECEIPT, 1_780_000_120);

    const excluded: string[] = [];
    for await (const item of store.range(1_780_000_000, 1_780_000_240)) {
      excluded.push(item.id);
    }
    expect(excluded).toEqual(['rcpt_01', 'rcpt_02']);

    const every: { id: string; iat: number; receipt: Uint8Array }[] = [];
    for await (const item of store.range(0, 2_000_000_000)) {
      every.push(item);
    }
    expect(every.map((item) => item.id)).toEqual(['rcpt_01', 'rcpt_02', 'rcpt_03']);
    expect(every[0]!.iat).toBe(1_780_000_000);
    expect(Array.from(every[0]!.receipt)).toEqual(Array.from(OTHER_RECEIPT));
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
