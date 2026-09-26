import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { exportRecordDigest, fromBase64Url, toHex } from '@ashaveri/receipt';
import {
  openFileReceiptStore,
  RECEIPT_STORE_FILE,
  StoreError,
  type ReceiptRetention,
  type ReceiptStore,
} from '@ashaveri/signerd';
import {
  loadChainVectors,
  type ChainRecord,
  type ChainScenario,
  type ChainVectorFile,
} from '../src/index.js';

const file: ChainVectorFile = loadChainVectors();

const LENGTH_BYTES = 4;
const KIND_BYTES = 1;
const PREV_BYTES = 32;
const IAT_BYTES = 8;
const ID_LENGTH_BYTES = 2;
const DIGEST_BYTES = 32;
const HEADER_BYTES = KIND_BYTES + PREV_BYTES + IAT_BYTES + ID_LENGTH_BYTES;
/** What a record names as its predecessor when the chain has nothing behind it yet. */
const NO_PREDECESSOR = '00'.repeat(PREV_BYTES);
const RECEIPT = 0;

const bytes = (encoded: string): Buffer => Buffer.from(fromBase64Url(encoded));

function scenarioNamed(name: string): ChainScenario {
  const found = file.scenarios.find((each) => each.name === name);
  if (found === undefined) throw new Error(`data/chain-v1.json has no scenario named ${name}`);
  return found;
}

function receiptsOf(scenario: ChainScenario): ChainRecord[] {
  return scenario.records.filter((record) => record.kind === RECEIPT);
}

function trimsOf(scenario: ChainScenario): ChainRecord[] {
  return scenario.records.filter((record) => record.kind === file.layout.kinds.trim);
}

/**
 * The frame a record's stated fields describe, put together by hand.
 *
 * This assembles published fields and compares them to bytes the store wrote; it never recomputes a
 * digest, which is the one thing a vector test must not do for itself. A field table that disagreed
 * with the image standing beside it would fail here rather than teach a port a layout nothing
 * writes.
 */
function assemble(record: ChainRecord): Buffer {
  const id = Buffer.from(record.id, 'utf8');
  const length = Buffer.alloc(LENGTH_BYTES);
  length.writeUInt32BE(record.length);
  const stamp = Buffer.alloc(IAT_BYTES);
  stamp.writeBigUInt64BE(BigInt(record.iat));
  const idLength = Buffer.alloc(ID_LENGTH_BYTES);
  idLength.writeUInt16BE(id.length);
  return Buffer.concat([
    length,
    Buffer.from([record.kind]),
    Buffer.from(record.prevHex, 'hex'),
    stamp,
    idLength,
    id,
    bytes(record.payloadBase64Url),
    Buffer.from(record.digestHex, 'hex'),
  ]);
}

/** The trim payload the stated seam and counts describe. */
function assembleTrim(record: ChainRecord): Buffer {
  const trim = record.trim;
  if (trim === undefined) throw new Error(`a record of kind ${record.kind} states no trim payload`);
  const counters = Buffer.alloc(16);
  counters.writeUInt32BE(trim.byAge, 0);
  counters.writeUInt32BE(trim.byCount, 4);
  counters.writeUInt32BE(trim.maxAgeSeconds, 8);
  counters.writeUInt32BE(trim.maxCount, 12);
  return Buffer.concat([Buffer.from(trim.seamHex, 'hex'), counters]);
}

/**
 * The digest the record at `index` has to name, read off the record the file puts in front of it:
 * a receipt chains from the digest before it, a trim chains from the bytes in front of it, and the
 * survivor of a retirement chains from the seam the trim states. The same rule answers for the head
 * when `index` is one past the end.
 */
function expectedPredecessor(records: ChainRecord[], index: number): string {
  if (index === 0) return NO_PREDECESSOR;
  const before = records[index - 1];
  if (before === undefined) throw new Error(`no record before index ${index}`);
  if (before.kind === file.layout.kinds.trim) {
    const seam = before.trim?.seamHex;
    if (seam === undefined) throw new Error('a trim record states no seam');
    return seam;
  }
  return before.digestHex;
}

/**
 * One frame of an image, read by nothing but the layout this file states. Used to walk a published
 * image without the store's help, so the field table can be checked against the bytes rather than
 * against the reader that produced them.
 */
function decodeFrames(image: Buffer): ChainRecord[] {
  const out: ChainRecord[] = [];
  let offset = 0;
  while (offset + LENGTH_BYTES <= image.length) {
    const length = image.readUInt32BE(offset);
    const frame = image.subarray(offset, offset + LENGTH_BYTES + length);
    const idStart = LENGTH_BYTES + HEADER_BYTES;
    const idLength = frame.readUInt16BE(LENGTH_BYTES + KIND_BYTES + PREV_BYTES + IAT_BYTES);
    const payloadStart = idStart + idLength;
    const payloadEnd = LENGTH_BYTES + length - DIGEST_BYTES;
    out.push({
      offset,
      kind: frame.readUInt8(LENGTH_BYTES),
      length,
      frameByteLength: frame.length,
      prevHex: toHex(frame.subarray(LENGTH_BYTES + KIND_BYTES, LENGTH_BYTES + KIND_BYTES + PREV_BYTES)),
      iat: Number(frame.readBigUInt64BE(LENGTH_BYTES + KIND_BYTES + PREV_BYTES)),
      id: frame.subarray(idStart, payloadStart).toString('utf8'),
      payloadBase64Url: frame.subarray(payloadStart, payloadEnd).toString('base64url'),
      digestHex: toHex(frame.subarray(payloadEnd, LENGTH_BYTES + length)),
      frameBase64Url: frame.toString('base64url'),
    });
    offset += LENGTH_BYTES + length;
  }
  return out;
}

function retentionOf(scenario: ChainScenario): ReceiptRetention | undefined {
  const configured = scenario.retention;
  return configured === undefined
    ? undefined
    : { ...configured, now: () => scenario.clockSeconds };
}

async function withDir<T>(work: (dir: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(join(tmpdir(), 'ashaveri-chain-vectors-'));
  try {
    return await work(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

function retentionOption(scenario: ChainScenario): { retention?: ReceiptRetention } {
  const retention = retentionOf(scenario);
  return retention === undefined ? {} : { retention };
}

/** What a store serves of the ids asked for, in the encoding the file publishes payloads in. */
async function servedBy(store: ReceiptStore, ids: readonly string[]): Promise<Record<string, string>> {
  const served: Record<string, string> = {};
  for (const id of ids) {
    const found = await store.get(id);
    if (found !== null) served[id] = Buffer.from(found).toString('base64url');
  }
  return served;
}

/** A scenario replayed through the production store: the writes it states, and the file after them. */
async function replay(
  scenario: ChainScenario,
): Promise<{ image: Buffer; head: string; window: unknown; state: unknown; served: Record<string, string> }> {
  return withDir(async (dir) => {
    const store = await openFileReceiptStore({ dir, ...retentionOption(scenario) });
    for (const each of scenario.puts) {
      await store.put(each.id, bytes(each.payloadBase64Url), each.iat);
    }
    const state = await store.chainState();
    return {
      image: await readFile(join(dir, RECEIPT_STORE_FILE)),
      head: toHex(await store.head()),
      window: await store.window(),
      state: {
        anchorHex: toHex(state.anchor),
        retired: {
          byAge: state.retired.byAge,
          byCount: state.retired.byCount,
          trims: state.retired.trims,
        },
      },
      served: await servedBy(store, scenario.puts.map((each) => each.id)),
    };
  });
}

describe('data/chain-v1.json', () => {
  it('states the record layout it publishes', () => {
    expect(file.version).toBe(1);
    expect(file.layout.file).toBe(RECEIPT_STORE_FILE);
    expect(file.layout.record).toBe(
      'len:u32 || kind:u8 || prev:32 || iat:u64 || idLen:u16 || id || payload || digest:32',
    );
    expect(file.layout.digest).toBe('sha256 of that input');
    expect(file.layout.integers).toBe('unsigned, big-endian');
    expect(file.layout.kinds).toEqual({ receipt: RECEIPT, trim: 1 });
    expect(file.layout.notes.length).toBeGreaterThanOrEqual(4);
    expect(file.scenarios.length).toBeGreaterThanOrEqual(4);
    expect(file.refusals.length).toBeGreaterThanOrEqual(3);
    expect(file.tails.length).toBe(1);
  });

  it('publishes a field table the image standing beside it agrees with', () => {
    for (const scenario of file.scenarios) {
      const image = bytes(scenario.fileBase64Url);
      expect(image).toHaveLength(scenario.fileByteLength);
      let offset = 0;
      for (const record of scenario.records) {
        const frame = assemble(record);
        expect(frame, `${scenario.name} field table against its frame`).toEqual(bytes(record.frameBase64Url));
        expect(record.length + LENGTH_BYTES).toBe(record.frameByteLength);
        // The boundary the frames ahead of this one add up to, which is what the published offset has
        // to be. A port told a difference localizes to a width, an endianness or a coverage rule is
        // pointed at a record by that number, so it is published rather than left to be summed.
        expect(record.offset, `${scenario.name} record at ${offset}`).toBe(offset);
        expect(image.subarray(offset, offset + record.frameByteLength)).toEqual(frame);
        if (record.kind === file.layout.kinds.trim) {
          expect(assembleTrim(record)).toEqual(bytes(record.payloadBase64Url));
        }
        offset += record.frameByteLength;
      }
      expect(offset).toBe(image.length);
    }
  });

  it.each(file.scenarios)('the store writes $name as the published image', async (scenario) => {
    const written = await replay(scenario);
    expect(written.image).toEqual(bytes(scenario.fileBase64Url));
    expect(written.head).toBe(scenario.headHex);
    expect(written.window).toEqual(scenario.window);
    expect(written.state).toEqual(scenario.chainState);
    expect(written.served).toEqual(scenario.served);
  });

  it.each(file.scenarios)('a reader of the published $name image serves the same set', async (scenario) => {
    await withDir(async (dir) => {
      await writeFile(join(dir, RECEIPT_STORE_FILE), bytes(scenario.fileBase64Url));
      const reopened = await openFileReceiptStore({ dir, ...retentionOption(scenario) });
      expect(toHex(await reopened.head())).toBe(scenario.headHex);
      expect(await reopened.window()).toEqual(scenario.window);
      expect(await servedBy(reopened, scenario.puts.map((each) => each.id))).toEqual(scenario.served);
      const state = await reopened.chainState();
      expect(toHex(state.anchor)).toBe(scenario.chainState.anchorHex);
      expect(state.retired.trims).toEqual(scenario.chainState.retired.trims);
    });
  });

  it('serves exactly the receipts the file leaves standing', () => {
    for (const scenario of file.scenarios) {
      expect(Object.keys(scenario.served).sort()).toEqual(receiptsOf(scenario).map((record) => record.id).sort());
      for (const [id, payload] of Object.entries(scenario.served)) {
        const written = scenario.puts.find((each) => each.id === id);
        expect(written, `${id} is served but was never written`).toBeDefined();
        expect(written?.payloadBase64Url, `${id} is served as something other than what was stored`).toBe(payload);
      }
    }
  });

  it('chains every record to the one the file puts in front of it', () => {
    for (const scenario of file.scenarios) {
      scenario.records.forEach((record, index) => {
        expect(record.prevHex, `${scenario.name} record ${index} names the wrong predecessor`).toBe(
          expectedPredecessor(scenario.records, index),
        );
      });
      // A retirement states where the surviving receipts start, so it can only sit ahead of all of
      // them: anywhere else it describes a hole in the middle of a chain as if it were intended.
      const kinds = scenario.records.map((record) => record.kind);
      expect([...kinds].sort((left, right) => right - left), `${scenario.name} record order`).toEqual(kinds);
    }
  });

  it('reports the head, the anchor and the retirements a reader recomputes from', () => {
    for (const scenario of file.scenarios) {
      expect(scenario.headHex).toBe(expectedPredecessor(scenario.records, scenario.records.length));
      const trims = trimsOf(scenario);
      const last = trims[trims.length - 1];
      expect(scenario.chainState.anchorHex, `${scenario.name} anchor`).toBe(
        trims.length === 0 ? NO_PREDECESSOR : last?.trim?.seamHex,
      );
      expect(scenario.chainState.retired.trims).toHaveLength(trims.length);
      let byAge = 0;
      let byCount = 0;
      trims.forEach((record, index) => {
        expect(record.id, 'a trim record addresses nothing').toBe('');
        const event = scenario.chainState.retired.trims[index];
        const trim = record.trim;
        expect(event?.at).toBe(record.iat);
        expect(event?.byAge).toBe(trim?.byAge);
        expect(event?.byCount).toBe(trim?.byCount);
        // A bound of zero in a record states that no bound was configured, which is what the reader
        // reports as an absent one.
        expect(event?.under).toEqual({
          ...(trim?.maxAgeSeconds === 0 ? {} : { maxAgeSeconds: trim?.maxAgeSeconds }),
          ...(trim?.maxCount === 0 ? {} : { maxCount: trim?.maxCount }),
        });
        byAge += trim?.byAge ?? 0;
        byCount += trim?.byCount ?? 0;
      });
      expect(scenario.chainState.retired.byAge).toBe(byAge);
      expect(scenario.chainState.retired.byCount).toBe(byCount);
      // The retention window the reader states is the surviving set's own span, inclusive at both
      // ends, and zero at both when nothing survived.
      const stamps = receiptsOf(scenario).map((record) => record.iat);
      expect(stamps.length).toBe(scenario.window.count);
      expect(scenario.window.from).toBe(stamps.length === 0 ? 0 : Math.min(...stamps));
      expect(scenario.window.to).toBe(stamps.length === 0 ? 0 : Math.max(...stamps));
    }
  });

  it.each(file.refusals)('$name is refused the way the file states', async (refusal) => {
    await withDir(async (dir) => {
      const image = bytes(refusal.imageBase64Url);
      expect(image).toHaveLength(refusal.imageByteLength);
      await writeFile(join(dir, RECEIPT_STORE_FILE), image);
      const failure = await openFileReceiptStore({ dir }).then(
        () => null,
        (error: unknown) => error,
      );
      expect(failure, `${refusal.name} opened without refusing`).toBeInstanceOf(StoreError);
      const storeFailure = failure as StoreError;
      expect(storeFailure.code).toBe(refusal.code);
      // The whole sentence and not just the code: these four images refuse for four different
      // reasons, and a check on the code alone would pass however the reader explained itself.
      expect(storeFailure.message).toBe(refusal.message);
      expect(storeFailure.message.startsWith(`${refusal.code}: `)).toBe(true);
    });
  });

  it('refuses an image the store itself wrote, once one byte of it is wrong', () => {
    // The tampered image and its untampered twin are one bit apart, so the only thing standing
    // between an accepted file and a refusal is the digest each record carries over its own bytes.
    const tampered = file.refusals.find((each) => each.name === 'tampered-record-byte');
    if (tampered === undefined) throw new Error('data/chain-v1.json states no tampered-record-byte refusal');
    const intact = bytes(scenarioNamed(String(tampered.tamper['of'])).fileBase64Url);
    const after = bytes(tampered.imageBase64Url);
    expect(after).toHaveLength(intact.length);
    expect(after).not.toEqual(intact);
    const differing = [...intact].filter((each, index) => each !== after[index]);
    expect(differing).toHaveLength(1);
    expect(tampered.code).toBe('STORE_CHAIN_BROKEN');
  });

  it('takes back an append that never finished and keeps the chain', async () => {
    const tail = file.tails[0];
    if (tail === undefined) throw new Error('data/chain-v1.json states no tail vector');
    const image = bytes(scenarioNamed(tail.of).fileBase64Url);
    const cut = bytes(tail.imageBase64Url);
    expect(cut).toEqual(image.subarray(0, image.length - tail.cutBytes));
    await withDir(async (dir) => {
      await writeFile(join(dir, RECEIPT_STORE_FILE), cut);
      const store = await openFileReceiptStore({ dir });
      // The incomplete record is taken back off the file rather than reported as a broken chain.
      expect(await readFile(join(dir, RECEIPT_STORE_FILE))).toEqual(bytes(tail.repairedImageBase64Url));
      expect(toHex(await store.head())).toBe(tail.headHex);
      expect(await servedBy(store, Object.keys(tail.served))).toEqual(tail.served);
      for (const id of tail.unserved) {
        expect(await store.get(id)).toBeNull();
      }
      await store.put(tail.next.id, bytes(tail.next.payloadBase64Url), tail.next.iat);
      // The next receipt chains from the head the surviving record stated, so the repair costs the
      // record that was never finished and nothing else.
      const continued = await readFile(join(dir, RECEIPT_STORE_FILE));
      expect(continued).toEqual(bytes(tail.imageAfterNextBase64Url));
      const records = decodeFrames(continued);
      expect(records.map((record) => record.offset)).toEqual(tail.recordsAfterNext.map((record) => record.offset));
      expect(records.map((record) => record.digestHex)).toEqual(tail.recordsAfterNext.map((record) => record.digestHex));
      expect(records.map((record) => record.prevHex)).toEqual(tail.recordsAfterNext.map((record) => record.prevHex));
      expect(records[1]?.prevHex).toBe(tail.headHex);
      expect((await store.window()).count).toBe(2);
    });
  });
});

describe('one framing, both formats', () => {
  it('reproduces a published store digest through the export framing', () => {
    // A reviewer recomputes an export's walk with `exportRecordDigest` and compares it against the chain
    // the store published, so the two framings have to be the same arithmetic. Two readings of one layout
    // agree only until somebody edits one of them, which is what this case is for: it fails the moment
    // they part, and it passed on neither until both named the store's offsets.
    for (const name of ['first-record', 'two-records', 'trim-after-count-cap', 'all-retired-by-age']) {
      for (const record of receiptsOf(scenarioNamed(name))) {
        const digest = exportRecordDigest({
          id: record.id,
          iat: record.iat,
          p: Buffer.from(record.prevHex, 'hex'),
          bytes: fromBase64Url(record.payloadBase64Url),
        });
        expect(toHex(digest), `${name} / ${record.id}`).toBe(record.digestHex);
      }
    }
  });
});
