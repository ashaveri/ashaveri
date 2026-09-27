import { writeFileSync } from 'node:fs';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { toBase64Url, toHex } from '@ashaveri/receipt';
import { openFileReceiptStore, RECEIPT_STORE_FILE, type ReceiptRecordKind, type ReceiptRetention } from '@ashaveri/signerd';
import { labeled } from './seed.ts';

const DATA = join(dirname(fileURLToPath(import.meta.url)), '..', 'data');

const LENGTH_BYTES = 4;
const KIND_BYTES = 1;
const PREV_BYTES = 32;
const IAT_BYTES = 8;
const ID_LENGTH_BYTES = 2;
const DIGEST_BYTES = 32;
/** Everything in a record body ahead of the id: kind, predecessor, stamp and id length. */
const HEADER_BYTES = KIND_BYTES + PREV_BYTES + IAT_BYTES + ID_LENGTH_BYTES;
/** The instant every scenario is written at, and the instant its retention is measured from. */
const CLOCK = 1_772_000_000;

/**
 * The second receipt kind, and the period its records state.
 *
 * The images published for this kind are published as bytes a store of that kind sealed, because a
 * refusal is only a reading of a layout if the bytes it objects to came out of a writer. The period is
 * a stand-in of the same order as the 64 byte payload stand-in below: these vectors state where the
 * field sits and how it is read, and nothing in a chain digest depends on the number it holds.
 */
const BOUND_SECONDS = 300;
const BOUNDED: ReceiptRecordKind = { kind: 'bounded', boundSeconds: BOUND_SECONDS };

const receiptId = (label: string): string => toHex(labeled(`ashaveri-chain-v1/id/${label}`, 24));
/**
 * The bytes a scenario stores where a receipt goes. Two digest-widths joined because the chain
 * treats the payload as opaque and a stand-in of a round 64 bytes reads as one.
 */
const storedBytes = (label: string): Uint8Array =>
  new Uint8Array(
    Buffer.concat([
      Buffer.from(labeled(`ashaveri-chain-v1/receipt/${label}/a`)),
      Buffer.from(labeled(`ashaveri-chain-v1/receipt/${label}/b`)),
    ]),
  );

interface Put {
  readonly id: string;
  readonly iat: number;
  readonly payload: Uint8Array;
}

interface Scenario {
  readonly name: string;
  readonly note: string;
  /** Absent means nothing is ever retired, which is how the first two scenarios are written. */
  readonly retention: ReceiptRetention | null;
  readonly puts: readonly Put[];
}

const SCENARIOS: readonly Scenario[] = [
  {
    name: 'first-record',
    note: 'One record appended to a file that did not exist. The predecessor slot holds thirty-two zero bytes, because nothing precedes the head of an empty chain, and the anchor a reader starts recomputing from is that same run of zeros.',
    retention: null,
    puts: [{ id: receiptId('first'), iat: CLOCK, payload: storedBytes('first') }],
  },
  {
    name: 'two-records',
    note: 'The second record names the first record digest as its predecessor, and the file is the two frames concatenated with nothing between them.',
    retention: null,
    puts: [
      { id: receiptId('older'), iat: CLOCK, payload: storedBytes('older') },
      { id: receiptId('newer'), iat: CLOCK + 1, payload: storedBytes('newer') },
    ],
  },
  {
    name: 'trim-after-count-cap',
    note: 'Three receipts written under a count cap of one, which retires a prefix twice and then reclaims the space. The file is rewritten as one trim record followed by the single surviving receipt. The retirement is what the trim states, so the receipt that stays still points at a record that is no longer in the file, and the seam inside the trim names the digest the survivors chain from. A trim follows the bytes of the file rather than the receipt chain, so its own predecessor is thirty-two zero bytes.',
    retention: { maxCount: 1 },
    puts: [
      { id: receiptId('capped-a'), iat: CLOCK, payload: storedBytes('capped-a') },
      { id: receiptId('capped-b'), iat: CLOCK + 1, payload: storedBytes('capped-b') },
      { id: receiptId('capped-c'), iat: CLOCK + 2, payload: storedBytes('capped-c') },
    ],
  },
  {
    name: 'all-retired-by-age',
    note: 'One receipt stamped outside the age bound and nothing else. It leaves the served set and the file is rewritten as a lone trim record, so a reader holds a retirement with no receipts behind it: head, anchor and seam all name the digest of the record nothing serves.',
    retention: { maxAgeSeconds: 100 },
    puts: [{ id: receiptId('aged'), iat: CLOCK - 1_000, payload: storedBytes('aged') }],
  },
];

/** One frame of a file image, beside the offset the file puts it at. */
interface Framed {
  readonly offset: number;
  readonly frame: Uint8Array;
}

function decodeFrames(image: Uint8Array): Framed[] {
  const view = Buffer.from(image);
  const out: Framed[] = [];
  let offset = 0;
  while (offset + LENGTH_BYTES <= view.length) {
    const length = view.readUInt32BE(offset);
    out.push({ offset, frame: new Uint8Array(view.subarray(offset, offset + LENGTH_BYTES + length)) });
    offset += LENGTH_BYTES + length;
  }
  return out;
}

/** One frame, field by field, as the layout states it, at the offset the file holds it at. */
function describeFrame(framed: Framed): Record<string, unknown> {
  const buffer = Buffer.from(framed.frame);
  const length = buffer.readUInt32BE(0);
  const end = LENGTH_BYTES + length;
  const idStart = LENGTH_BYTES + HEADER_BYTES;
  const idLength = buffer.readUInt16BE(LENGTH_BYTES + KIND_BYTES + PREV_BYTES + IAT_BYTES);
  const payloadStart = idStart + idLength;
  const payloadEnd = end - DIGEST_BYTES;
  const kind = buffer.readUInt8(LENGTH_BYTES);
  const record: Record<string, unknown> = {
    // Where the frame starts, counted in bytes from the first byte of the file. A reader that found a
    // difference inside one record has to say which record, and the offsets of the frames in front of
    // it are the only way to know; the walking is done here so the table carries the answer.
    offset: framed.offset,
    kind,
    // What the length prefix states: the span from the kind byte through the digest.
    length,
    frameByteLength: buffer.length,
    prevHex: toHex(buffer.subarray(LENGTH_BYTES + KIND_BYTES, LENGTH_BYTES + KIND_BYTES + PREV_BYTES)),
    iat: Number(buffer.readBigUInt64BE(LENGTH_BYTES + KIND_BYTES + PREV_BYTES)),
    id: buffer.subarray(idStart, payloadStart).toString('utf8'),
    payloadBase64Url: toBase64Url(buffer.subarray(payloadStart, payloadEnd)),
    digestHex: toHex(buffer.subarray(payloadEnd, end)),
    frameBase64Url: toBase64Url(buffer),
  };
  if (kind === 1) {
    const payload = buffer.subarray(payloadStart, payloadEnd);
    record['trim'] = {
      seamHex: toHex(payload.subarray(0, PREV_BYTES)),
      byAge: payload.readUInt32BE(PREV_BYTES),
      byCount: payload.readUInt32BE(PREV_BYTES + 4),
      maxAgeSeconds: payload.readUInt32BE(PREV_BYTES + 8),
      maxCount: payload.readUInt32BE(PREV_BYTES + 12),
    };
  }
  return record;
}

async function inStore<T>(work: (dir: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(join(tmpdir(), 'ashaveri-chain-vector-'));
  try {
    return await work(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

const published = (scenario: Scenario): Record<string, unknown> => ({
  name: scenario.name,
  note: scenario.note,
  ...(scenario.retention === null ? {} : { retention: scenario.retention }),
  clockSeconds: CLOCK,
  puts: scenario.puts.map((each) => ({
    id: each.id,
    iat: each.iat,
    payloadBase64Url: toBase64Url(each.payload),
  })),
});

/** Writes one scenario through the store and states what the file and a reader ended up with. */
async function runScenario(scenario: Scenario): Promise<Record<string, unknown>> {
  return inStore(async (dir) => {
    const store = await openFileReceiptStore({
      dir,
      ...(scenario.retention === null
        ? {}
        : {
            retention: {
              ...scenario.retention,
              time: { name: 'chain vector generator', uncertaintySeconds: null, now: () => CLOCK },
            },
          }),
    });
    for (const each of scenario.puts) {
      await store.put(each.id, each.payload, each.iat);
    }
    const image = new Uint8Array(await readFile(join(dir, RECEIPT_STORE_FILE)));
    const state = await store.chainState();
    const served: Record<string, string> = {};
    for (const each of scenario.puts) {
      const found = await store.get(each.id);
      if (found !== null) served[each.id] = toBase64Url(found);
    }
    return {
      ...published(scenario),
      fileBase64Url: toBase64Url(image),
      fileByteLength: image.length,
      records: decodeFrames(image).map(describeFrame),
      headHex: toHex(await store.head()),
      window: await store.window(),
      served,
      chainState: {
        anchorHex: toHex(state.anchor),
        retired: {
          byAge: state.retired.byAge,
          byCount: state.retired.byCount,
          trims: state.retired.trims,
        },
      },
    };
  });
}

/** The refusal an image earns when it is opened, stated exactly as the reader words it. */
async function refusalOf(
  image: Uint8Array,
  name: string,
  openedWith: ReceiptRecordKind | undefined,
): Promise<{ code: string; message: string }> {
  return inStore(async (dir) => {
    await writeFile(join(dir, RECEIPT_STORE_FILE), image);
    try {
      await openFileReceiptStore({
        dir,
        ...(openedWith === undefined ? {} : { receiptKind: openedWith }),
      });
    } catch (error) {
      const code = (error as { code?: unknown }).code;
      if (!(error instanceof Error) || typeof code !== 'string') {
        throw new Error(`${dir}: the store refused ${name} with something other than a coded error`);
      }
      return { code, message: error.message };
    }
    throw new Error(`${name} is published as a refusal and opened without refusing`);
  });
}

/**
 * The frames a store of the given kind sealed, one per label, in a directory of its own.
 *
 * A published refusal for the second receipt kind has to object to bytes some writer produced rather
 * than to a shape drawn here: the layout the reader under test refuses is the layout a bounded store
 * puts on a volume, period, ids, stamps and digest included.
 */
async function sealedFrames(kind: ReceiptRecordKind, labels: readonly string[]): Promise<Uint8Array[]> {
  return inStore(async (dir) => {
    const store = await openFileReceiptStore({ dir, receiptKind: kind });
    for (const [index, label] of labels.entries()) {
      await store.put(receiptId(label), storedBytes(label), CLOCK + index);
    }
    return decodeFrames(new Uint8Array(await readFile(join(dir, RECEIPT_STORE_FILE)))).map((each) => each.frame);
  });
}

function flip(image: Uint8Array, offset: number, mask: number): Uint8Array {
  const out = new Uint8Array(image);
  const byte = out[offset];
  if (byte === undefined) throw new Error(`no byte at offset ${offset} of the image to tamper with`);
  out[offset] = byte ^ mask;
  return out;
}

function copy(image: Uint8Array, from: number, to: number): Uint8Array {
  return new Uint8Array(Buffer.from(image).subarray(from, to));
}

async function main(): Promise<void> {
  const scenarios: Record<string, unknown>[] = [];
  for (const each of SCENARIOS) {
    scenarios.push(await runScenario(each));
  }
  const scenario = (name: string): Record<string, unknown> => {
    const found = scenarios.find((each) => each['name'] === name);
    if (found === undefined) throw new Error(`no scenario named ${name}`);
    return found;
  };
  const imageOf = (name: string): Uint8Array =>
    new Uint8Array(Buffer.from(String(scenario(name)['fileBase64Url']), 'base64url'));
  const recordOf = (name: string, index: number): Record<string, unknown> => {
    const records = scenario(name)['records'] as Record<string, unknown>[];
    const record = records[index];
    if (record === undefined) throw new Error(`scenario ${name} has no record at ${index}`);
    return record;
  };
  const frameOf = (name: string, index: number): Uint8Array =>
    new Uint8Array(Buffer.from(String(recordOf(name, index)['frameBase64Url']), 'base64url'));

  const twoRecords = imageOf('two-records');
  const firstRecord = imageOf('first-record');
  const olderLength = Number(recordOf('two-records', 0)['frameByteLength']);
  // Three bytes into the second record payload: past the length, the kind, the predecessor, the
  // stamp, the id length and the id, so nothing a reader consults before the digest is disturbed.
  const payloadByte =
    olderLength +
    LENGTH_BYTES +
    HEADER_BYTES +
    String(recordOf('two-records', 1)['id']).length +
    3;

  const cut = copy(twoRecords, 0, twoRecords.length - 7);
  const olderId = String(recordOf('two-records', 0)['id']);
  const newerId = String(recordOf('two-records', 1)['id']);
  const tail = await inStore(async (dir) => {
    await writeFile(join(dir, RECEIPT_STORE_FILE), cut);
    const store = await openFileReceiptStore({ dir });
    const headHex = toHex(await store.head());
    const repaired = toBase64Url(new Uint8Array(await readFile(join(dir, RECEIPT_STORE_FILE))));
    const served: Record<string, string> = {};
    const unserved: string[] = [];
    for (const id of [olderId, newerId]) {
      const found = await store.get(id);
      if (found === null) unserved.push(id);
      else served[id] = toBase64Url(found);
    }
    const next: Put = { id: receiptId('after-repair'), iat: CLOCK + 9, payload: storedBytes('after-repair') };
    await store.put(next.id, next.payload, next.iat);
    const continued = new Uint8Array(await readFile(join(dir, RECEIPT_STORE_FILE)));
    return {
      of: 'two-records',
      cutBytes: 7,
      imageBase64Url: toBase64Url(cut),
      headHex,
      repairedImageBase64Url: repaired,
      served,
      unserved,
      next: { id: next.id, iat: next.iat, payloadBase64Url: toBase64Url(next.payload) },
      imageAfterNextBase64Url: toBase64Url(continued),
      recordsAfterNext: decodeFrames(continued).map(describeFrame),
    };
  });

  const refusals: Record<string, unknown>[] = [];
  // The record the mixture below appends, sealed by a store that writes the bounded kind, so the refusal
  // is read off bytes a writer made rather than off a drawing of them. Its id is the label's own, which
  // is the id the published message has to name.
  const boundedId = receiptId('bounded-refusal');
  const boundedFrame = (await sealedFrames(BOUNDED, ['bounded-refusal']))[0];
  if (boundedFrame === undefined) throw new Error('a bounded store sealed no record to publish as a refusal');
  const cases: readonly {
    image: Uint8Array;
    name: string;
    note: string;
    tamper: Record<string, unknown>;
    /** The receipt kind the opening writes, which is the receipt kind unless the row says otherwise. */
    openedWith?: ReceiptRecordKind;
  }[] = [
    {
      name: 'tampered-record-byte',
      note: 'One bit flipped inside a record payload. The record still states its own length and names the right predecessor; only its digest over its own bytes stops matching, and that is what a reader checks.',
      tamper: { of: 'two-records', offset: payloadByte, xoredWith: 1 },
      image: flip(twoRecords, payloadByte, 0x01),
    },
    {
      name: 'deleted-first-record',
      note: 'The first of two records lifted out of the file. What is left is whole by its own digest and states its own length, and it is still refused: its predecessor slot names a record the reader was never shown.',
      tamper: { of: 'two-records', droppedBytesFromFront: olderLength },
      image: copy(twoRecords, olderLength, twoRecords.length),
    },
    {
      name: 'trim-after-a-receipt',
      note: 'A receipt record followed by the trim record from the compaction scenario, which is a retirement written behind the receipts it could describe. A trim states where the surviving receipts start, so one anywhere else describes a hole in the middle of a chain and is refused on that alone.',
      tamper: { of: 'first-record', appendedTrimFrom: 'trim-after-count-cap' },
      image: new Uint8Array(Buffer.concat([Buffer.from(firstRecord), Buffer.from(frameOf('trim-after-count-cap', 0))])),
    },
    {
      name: 'frame-length-too-short',
      note: 'A record whose length prefix claims fewer bytes than the layout needs for its own header. Nothing inside a frame can be trusted once its size lies, so the reader stops at the size and never reaches the digest.',
      tamper: { of: 'first-record', relengthedTo: 40 },
      image: (() => {
        const out = Buffer.from(firstRecord);
        out.writeUInt32BE(40, 0);
        return new Uint8Array(out);
      })(),
    },
    {
      name: 'bounded-record-in-a-receipt-log',
      note: 'The one-record image of a store that writes the receipt kind, with one bounded record appended behind it: a log holding receipt records of both kinds. The record the store writes is of the kind the opening runs, so the refusal is given for the record appended behind it, named by its id and by the byte its frame starts at. The appended record is whole and self-verifying by its own digest, and its predecessor slot names a chain it is not part of: the kind is answered before the link, because a record of a kind this store does not write has no predecessor anything can interpret, and a reader that checked the link first would report a broken chain for a file nothing edited.',
      tamper: { of: 'first-record', appendedBoundedFrameSealedFor: boundedId, boundSeconds: BOUND_SECONDS },
      image: new Uint8Array(Buffer.concat([Buffer.from(firstRecord), Buffer.from(boundedFrame)])),
    },
    {
      name: 'receipt-log-opened-as-bounded',
      note: 'The two-record image of a store that writes the receipt kind, byte for byte as that store wrote it, read by an opening configured for the bounded kind. Nothing is appended, edited or missing: the disagreement is between the file and the configuration, and it shows at the first record the reader meets, so the id the refusal names is the oldest receipt in the file. One log holds receipt records of one kind, so a store cannot serve a bounded record it did not write any more than it can serve an unbounded one it did.',
      tamper: { of: 'two-records', openedUnderTheBoundedKind: true },
      image: twoRecords,
      openedWith: BOUNDED,
    },
  ];
  for (const each of cases) {
    refusals.push({
      name: each.name,
      note: each.note,
      tamper: each.tamper,
      imageBase64Url: toBase64Url(each.image),
      imageByteLength: each.image.length,
      ...(each.openedWith === undefined ? {} : { openedWith: each.openedWith }),
      ...(await refusalOf(each.image, each.name, each.openedWith)),
    });
  }

  writeFileSync(
    join(DATA, 'chain-v1.json'),
    `${JSON.stringify(
      {
        version: 1,
        description:
          'The receipt store record format, published as file images a gateway store wrote and the state a reader derives from them. Each scenario names the writes it performed and states what the file held afterwards byte for byte, alongside the head, the served set and the retention state a reader reports for it. Every image here came out of the store rather than out of a description of it, and a scenario is one directory whose chain lives in one file named receipts.log. A store appends receipt records of one kind per file, the receipt kind or the bounded kind, and a refusal row states the kind its image is read under wherever that is not the receipt kind. A default store also writes a disposable receipts.log.index beside that file, holding record positions and a checkpoint so an opening need not re-walk bytes it has already verified; it is rebuilt from the log at any disagreement, it carries no byte of the chain, and no scenario publishes it.',
        layout: {
          file: RECEIPT_STORE_FILE,
          record: 'len:u32 || kind:u8 || prev:32 || iat:u64 || idLen:u16 || id || payload || digest:32',
          lengthCovers: 'kind through digest, so len counts everything after the length prefix itself',
          digestInput: 'kind through payload, that is every byte between the length prefix and the digest',
          digest: 'sha256 of that input',
          integers: 'unsigned, big-endian',
          kinds: { receipt: 0, trim: 1, bounded: 2 },
          receiptPayload:
            'the receipt bytes, stored unaltered and opaque to the chain. These vectors carry a 64 byte stand-in rather than a signed receipt, because nothing in a record digest depends on what the payload holds.',
          boundedPayload: 'boundSeconds:u32 || receipt',
          trimPayload: 'seam:32 || byAge:u32 || byCount:u32 || maxAgeSeconds:u32 || maxCount:u32',
          notes: [
            'A receipt record names the digest of the record before it in the chain, and the first record of an empty file names thirty-two zero bytes.',
            'A trim record names the digest of the bytes in front of it, which is the previous trim or the thirty-two zero bytes at the start of a file, and it appears ahead of every receipt and nowhere else.',
            'The seam a trim carries is the digest the surviving receipts chain from, which the first survivor also names in its own header.',
            'A bound of zero in a trim states that no such bound was configured, which a reader has to tell apart from a bound of one.',
            'A partial record at the tail is an append that never finished: a reader takes it back off the file and opens the rest, and nothing can sit behind it because it was never written.',
            'Deleting a record from the middle of a chain, or editing one, is refused rather than worked around, and the refusal names the byte offset it stopped at.',
            'Each record states the offset its frame starts at, counted in bytes from the first byte of the file image, beside the frame, so a difference localizes to a record without adding up the lengths of everything ahead of it.',
            'A store writes receipt records of one kind per file, and one kind per opening: the receipt kind, whose payload is the receipt bytes, or the bounded kind, whose payload states a retention period ahead of them inside the digest the chain folds. A log holding both has no single reading, because the receipt sits four bytes further back in a bounded record than it does in an unbounded one.',
            'A bounded log and a receipt log differ only in what sits between the id and the receipt bytes, so a file of the kind an opening does not write is refused for the first record it meets, named by id and byte, and the refusal arrives before any predecessor link is read. Trim records are neither kind: they are the store bookkeeping a retired prefix, they address no receipt, and a run of them ahead of the receipts of either kind is one kind of receipt record.',
          ],
        },
        scenarios,
        tails: [
          {
            name: 'partial-tail-repair',
            note: 'Two records with the last seven bytes of the second taken off, which is what an append interrupted by a crash leaves behind. A reader takes the incomplete tail back off the file, keeps serving the record that is whole, reports the head the surviving record states, and chains the next receipt onto that head as if nothing had been lost.',
            ...tail,
          },
        ],
        refusals,
      },
      null,
      2,
    )}\n`,
  );

  console.log(
    `${join(DATA, 'chain-v1.json')}: ${String(scenarios.length)} scenarios, ${String(refusals.length)} refusals, 1 tail`,
  );
}

await main();
