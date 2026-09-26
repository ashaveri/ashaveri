import { describe, expect, it } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  PACK_CONTENT_TYPE,
  ReceiptError,
  decodeCanonical,
  decodePack,
  encodeCanonical,
  encodePackManifest,
  encodePackProtectedHeader,
  issueReceipt,
  packRecordDigest,
  packSigStructure,
  sealPack,
  signPack,
  signingKeyFromSeed,
  toHex,
  verifyPack,
  type PackItem,
  type PackManifest,
  type PackOrderingFindingKind,
  type ReceiptPayloadV1,
  type SigningKey,
} from '../src/index.js';
import { PACK_MANIFEST_MEMBERS } from '../src/pack.js';

/**
 * The pack writer, and the ordering finding a verified pack reports rather than refuses.
 *
 * `pack-reader.test.ts` builds its bytes by hand, which is what keeps that suite's refusals independent of the
 * code that now makes the same bytes. This file asks the opposite question: does the writer produce those bytes,
 * does it produce no others, and does what it produces read back through the shipped reader. The two meet at one
 * byte-for-byte case, where the envelope the writer signs and the envelope its own published pieces assemble
 * have to be one document, because a writer and a reader that drift apart make a deployment refuse its own pack.
 *
 * The writer takes a manifest and signs it, so the properties worth pinning are the ones about what it will not
 * do. `signPack` runs the bytes it just made through this package's own structural parser and then through its
 * own walk before it signs them. A fault of the manifest is a document whose records, chain and receipts are
 * all honest while the manifest contradicts itself; a fault of the chain is a run that does not reach the head
 * it names. Both are refused where the bytes are made, under the code the reader would have answered with, and
 * the documents that are meant to be refused are assembled from the published pieces instead.
 *
 * The ordering finding is the third field of a verified pack's outcome and the one thing here that must never
 * refuse. A pack whose stamps run backwards against its links is lawful output, because the store chains under
 * whatever stamp it was handed and a deployment that corrected its clock produces exactly that. The case below is
 * that the reader answers with the run, the window and a named disagreement, and with no error, while the two
 * checks that do bind those bytes, the walk and the item-stamp equality, are asked of the same document so a
 * change that turned the finding into a refusal or let a moved stamp through shows up here rather than in the
 * field alone.
 */

const KEY: SigningKey = signingKeyFromSeed(new Uint8Array(32).fill(31));
const SECOND: SigningKey = signingKeyFromSeed(new Uint8Array(32).fill(32));
const BASE = 1_772_000_000;
const SPAN_FROM = BASE - 60;
const SPAN_TO = BASE + 3;

function bytesOf(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

function thrownBy(run: () => unknown): unknown {
  try {
    run();
    return null;
  } catch (err) {
    return err;
  }
}

function codeOf(run: () => unknown): string {
  const thrown = thrownBy(run);
  if (thrown === null) return 'accepted';
  return thrown instanceof ReceiptError ? thrown.code : `UNCODED:${String(thrown)}`;
}

/** Bytewise order, which is the comparison core deterministic encoding puts map keys in. */
function compareBytes(a: Uint8Array, b: Uint8Array): number {
  for (let index = 0; index < Math.max(a.length, b.length); index += 1) {
    const diff = (a[index] ?? 0) - (b[index] ?? 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

/** A receipt payload whose every field is the width its kind needs, moving only by stamp and nonce. */
function receiptPayload(iat: number, nonce: number): ReceiptPayloadV1 {
  const digest = sha256(new Uint8Array([nonce]));
  return {
    v: 1,
    iss: 'ashaveri-pack-writer',
    ins: 'cvm-pack-1',
    iat,
    nce: new Uint8Array(16).fill(nonce),
    req: digest,
    res: digest,
    mdl: 'mock-model-1',
    wts: digest,
    meas: { tee: 'software', m: digest },
    att: { d: digest, ts: iat - 60, url: 'https://inference.ashaveri.example/v1/attestation' },
    epk: 0,
    tok: { p: 1, c: 1 },
  };
}

/**
 * Records chained in the order given, each receipt attesting the stamp its record was hashed with, from an
 * anchor of thirty-two zero bytes unless a retirement put a seam in front. The entries of a case name the stamp
 * the chain carries, so a pack whose stamps run against its links is the same helper with the stamps spelled the
 * other way round.
 */
function chained(
  entries: Iterable<{ id: string; iat: number; nonce: number; key?: SigningKey }>,
  anchor = new Uint8Array(32),
): { items: PackItem[]; anchor: Uint8Array; head: Uint8Array } {
  const items: PackItem[] = [];
  let prev: Uint8Array = anchor;
  for (const entry of entries) {
    const item: PackItem = {
      id: entry.id,
      iat: entry.iat,
      prev,
      receipt: issueReceipt(receiptPayload(entry.iat, entry.nonce), entry.key ?? KEY),
    };
    items.push(item);
    prev = packRecordDigest(item);
  }
  return { items, anchor, head: prev };
}

/** The three records of the honest run, chained oldest stamp first. */
const ENTRIES = [
  { id: 'receipt-0', iat: BASE, nonce: 1 },
  { id: 'receipt-1', iat: BASE + 1, nonce: 2 },
  { id: 'receipt-2', iat: BASE + 2, nonce: 3 },
];

/** The same three records with the stamps running the other way, chained from the newest. */
const BACKWARDS = [
  { id: 'receipt-2', iat: BASE + 2, nonce: 3 },
  { id: 'receipt-1', iat: BASE + 1, nonce: 2 },
  { id: 'receipt-0', iat: BASE, nonce: 1 },
];

function manifestFor(run: { items: PackItem[]; anchor: Uint8Array; head: Uint8Array }, over: Partial<PackManifest> = {}): PackManifest {
  return {
    v: 1,
    at: SPAN_TO,
    span: { from: SPAN_FROM, to: SPAN_TO },
    chain: { anchor: run.anchor, head: run.head },
    duty: { art: '19(1)', rev: SPAN_TO - 30, required: 3_600, held: SPAN_TO - BASE },
    items: run.items,
    ...over,
  };
}

function manifestOf(over: Partial<PackManifest> = {}): PackManifest {
  return manifestFor(chained(ENTRIES), over);
}

/** The manifest a store produced after correcting its clock: the links ascend, the stamps descend. */
function backwardsManifest(): PackManifest {
  return manifestFor(chained(BACKWARDS));
}

/**
 * A manifest sealed through the four published pieces rather than through `signPack`, which is how a document
 * that is meant to be refused is made. The header, the framing and the signature are the writer's own, so the
 * only thing these bytes differ by is the position the case names.
 */
function sealedFromPieces(manifest: PackManifest, key: SigningKey = KEY): Uint8Array {
  const payloadBytes = encodePackManifest(manifest);
  const header = encodePackProtectedHeader(key.kid);
  return sealPack(header, payloadBytes, ed25519.sign(packSigStructure(header, payloadBytes), key.privateKey));
}

/** The bytes of a sealed pack as one digest, which is what a before-and-after comparison reads. */
function digestOf(bytes: Uint8Array): string {
  return toHex(sha256(bytes));
}

/** The CBOR map the writer is held to, spelled here rather than by the writer. */
function handManifestMap(manifest: PackManifest): Map<string, unknown> {
  return new Map<string, unknown>([
    ['v', manifest.v],
    ['at', manifest.at],
    ['span', new Map<string, unknown>([['from', manifest.span.from], ['to', manifest.span.to]])],
    ['chain', new Map<string, unknown>([['anchor', manifest.chain.anchor], ['head', manifest.chain.head]])],
    [
      'duty',
      new Map<string, unknown>([
        ['art', manifest.duty.art],
        ['rev', manifest.duty.rev],
        ['required', manifest.duty.required],
        ['held', manifest.duty.held],
      ]),
    ],
    [
      'items',
      manifest.items.map((one) =>
        new Map<string, unknown>([
          ['id', one.id],
          ['iat', one.iat],
          ['prev', one.prev],
          ['receipt', one.receipt],
        ]),
      ),
    ],
  ]);
}

describe('the pack writer', () => {
  it('makes the bytes the reader reads back, and the same bytes every time', () => {
    const manifest = manifestOf();
    const bytes = signPack(manifest, KEY);
    expect(() => verifyPack(bytes, { publicKey: KEY.publicKey })).not.toThrow();
    const read = decodePack(bytes);
    // Every member comes back as it went in, digests and stamps included, which is what a caller comparing its
    // own records against a reader's answer has to be able to do.
    expect(read.manifest.v).toBe(1);
    expect(read.manifest.at).toBe(manifest.at);
    expect(read.manifest.span).toEqual(manifest.span);
    expect(toHex(read.manifest.chain.anchor)).toBe(toHex(manifest.chain.anchor));
    expect(toHex(read.manifest.chain.head)).toBe(toHex(manifest.chain.head));
    expect(read.manifest.duty).toEqual(manifest.duty);
    expect(read.manifest.items.map((one) => [one.id, one.iat])).toEqual(manifest.items.map((one) => [one.id, one.iat]));
    for (const [index, one] of read.manifest.items.entries()) {
      expect(toHex(one.prev)).toBe(toHex(manifest.items[index]!.prev));
      expect(toHex(one.receipt)).toBe(toHex(manifest.items[index]!.receipt));
    }
    expect(read.header.contentType).toBe(PACK_CONTENT_TYPE);
    expect(toHex(read.header.kid)).toBe(toHex(KEY.kid));
    // Determinism, which is the reason a published vector file can be diffed at all: the same manifest written
    // twice is one byte string, and nothing in the encoding reaches for a clock or a random draw.
    expect(toHex(signPack(manifest, KEY))).toBe(toHex(bytes));
    expect(toHex(encodePackManifest(manifest))).toBe(toHex(encodePackManifest(manifest)));
  });

  it('writes the envelope its own published pieces assemble, byte for byte', () => {
    // The four pieces are public so a caller can build a document the writer will not sign, which is what a
    // conformance vector is. That freedom is only honest if the pieces spell what `signPack` spells, or the two
    // paths to a pack would be two formats.
    const manifest = manifestOf();
    const payloadBytes = encodePackManifest(manifest);
    const protectedBytes = encodePackProtectedHeader(KEY.kid);
    const assembled = sealPack(
      protectedBytes,
      payloadBytes,
      ed25519.sign(packSigStructure(protectedBytes, payloadBytes), KEY.privateKey),
    );
    expect(toHex(assembled)).toBe(toHex(signPack(manifest, KEY)));
    expect(toHex(payloadBytes)).toBe(toHex(encodeCanonical(handManifestMap(manifest))));
    // The header names the three labels the format declares, in the order core deterministic encoding puts them,
    // and nothing else.
    const header = decodeCanonical(protectedBytes);
    expect(header).toBeInstanceOf(Map);
    expect([...(header as Map<unknown, unknown>).keys()]).toEqual([1, 3, 4]);
    expect((header as Map<unknown, unknown>).get(3)).toBe(PACK_CONTENT_TYPE);
    // The unprotected map is the one a signer fills at will and the reader reads nothing out of, so the writer
    // leaves it empty by default and takes it as an argument rather than refusing to be told.
    const filled = new Map<unknown, unknown>([['note', 'outside the signature']]);
    const withNote = sealPack(protectedBytes, payloadBytes, ed25519.sign(packSigStructure(protectedBytes, payloadBytes), KEY.privateKey), filled);
    expect(decodePack(withNote).envelope.unprotected.get('note')).toBe('outside the signature');
    expect(decodePack(assembled).envelope.unprotected.size).toBe(0);
    expect(() => verifyPack(withNote, { publicKey: KEY.publicKey })).not.toThrow();
  });

  it('writes canonical bytes, whatever order the members are assembled in', () => {
    // One Map per map, and the encoder never sorts: core deterministic encoding is what puts the members in
    // order, so the bytes a deployment signs and the bytes a reader recomputes digests over are one answer. A
    // writer that relied on insertion order would make a caller's object literal part of the format.
    const honest = manifestOf();
    const payloadBytes = encodePackManifest(honest);
    const scrambled = new Map<string, unknown>([
      ['items', honest.items.map((one) => new Map<string, unknown>([['receipt', one.receipt], ['prev', one.prev], ['iat', one.iat], ['id', one.id]]))],
      ['duty', new Map<string, unknown>([['held', honest.duty.held], ['required', honest.duty.required], ['rev', honest.duty.rev], ['art', honest.duty.art]])],
      ['chain', new Map<string, unknown>([['head', honest.chain.head], ['anchor', honest.chain.anchor]])],
      ['span', new Map<string, unknown>([['to', honest.span.to], ['from', honest.span.from]])],
      ['at', honest.at],
      ['v', honest.v],
    ]);
    expect(toHex(encodeCanonical(scrambled))).toBe(toHex(payloadBytes));
    const encoded = decodeCanonical(payloadBytes) as Map<unknown, unknown>;
    // What a reader is handed is the bytewise order of the labels, derived here from the names the format
    // declares rather than typed out, so the claim is about the rule and not about one document's rendering.
    const canonical = (members: readonly string[]): string[] =>
      [...members].sort((a, b) => compareBytes(encodeCanonical(a), encodeCanonical(b)));
    expect([...encoded.keys()]).toEqual(canonical(PACK_MANIFEST_MEMBERS));
    expect([...(encoded.get('span') as Map<unknown, unknown>).keys()]).toEqual(canonical(['from', 'to']));
    expect([...(encoded.get('chain') as Map<unknown, unknown>).keys()]).toEqual(canonical(['anchor', 'head']));
    expect([...(encoded.get('duty') as Map<unknown, unknown>).keys()]).toEqual(canonical(['art', 'rev', 'required', 'held']));
    const first = (encoded.get('items') as Map<unknown, unknown>[])[0]!;
    expect([...first.keys()]).toEqual(canonical(['id', 'iat', 'prev', 'receipt']));
    // The numbers are integers and the byte strings are byte strings, which is what the closed decode the reader
    // runs insists on: a stamp written as a float is a document this package refuses.
    expect(first.get('iat')).toBe(BASE);
    expect(first.get('prev')).toBeInstanceOf(Uint8Array);
    expect(first.get('receipt')).toBeInstanceOf(Uint8Array);
    // The writer takes a `Buffer` for the bytes it carries and writes it as a bstr, which is the case an
    // assembler reading a store file off disk reaches, and `plainByteInputs` in `cbor.ts` decides.
    const buffered: PackManifest = {
      ...honest,
      items: honest.items.map((one) => ({ ...one, receipt: Buffer.from(one.receipt) })),
    };
    expect(() => verifyPack(signPack(buffered, KEY), { publicKey: KEY.publicKey })).not.toThrow();
  });

  it('will not sign a manifest it would refuse to read, and answers with the reader code', () => {
    const honest = manifestOf();
    const run = chained(ENTRIES);
    const faults: Array<[string, PackManifest, string]> = [
      ['assembly before the span closed', { ...honest, at: SPAN_TO - 1 }, 'PACK_BAD_MANIFEST'],
      ['an item stamped outside the span', manifestFor(chained([{ id: 'late', iat: SPAN_TO, nonce: 4 }])), 'PACK_BAD_MANIFEST'],
      ['a revision after the reads', manifestFor(run, { duty: { art: '19(1)', rev: SPAN_TO + 1, required: 3_600, held: SPAN_TO - BASE } }), 'PACK_BAD_MANIFEST'],
      ['a held figure younger than the oldest receipt', manifestFor(run, { duty: { art: '19(1)', rev: SPAN_TO - 30, required: 3_600, held: 0 } }), 'PACK_BAD_MANIFEST'],
      ['an instant before the epoch', { ...honest, at: -1 }, 'PACK_BAD_MANIFEST'],
      ['a duration below zero', manifestFor(run, { duty: { art: '19(1)', rev: SPAN_TO - 30, required: -1, held: SPAN_TO - BASE } }), 'PACK_BAD_MANIFEST'],
      ['a duty label that is not text', manifestFor(run, { duty: { art: 19 as unknown as string, rev: SPAN_TO - 30, required: 3_600, held: SPAN_TO - BASE } }), 'PACK_BAD_MANIFEST'],
      ['no items at all', manifestFor(run, { items: [] }), 'PACK_BAD_MANIFEST'],
      ['two items answering to one name', manifestFor(run, { items: [...run.items, { ...run.items[1]!, id: 'receipt-0' }] }), 'PACK_DUPLICATE_ID'],
      ['a predecessor of another width', manifestFor(run, { items: run.items.map((one, index) => (index === 0 ? { ...one, prev: new Uint8Array(31) } : one)) }), 'PACK_BAD_MANIFEST'],
      ['an id of no bytes', manifestFor(run, { items: run.items.map((one, index) => (index === 0 ? { ...one, id: '' } : one)) }), 'PACK_BAD_MANIFEST'],
      ['a chain endpoint of another width', manifestFor(run, { chain: { anchor: run.anchor, head: new Uint8Array(33) } }), 'PACK_BAD_MANIFEST'],
      ['an item carrying something other than bytes', manifestFor(run, { items: run.items.map((one, index) => (index === 0 ? { ...one, receipt: 'not a receipt' as unknown as Uint8Array } : one)) }), 'PACK_BAD_MANIFEST'],
      ['a version no format has used', { ...honest, v: 2 as unknown as 1 }, 'PACK_UNSUPPORTED_VERSION'],
    ];
    const headerBytes = encodePackProtectedHeader(KEY.kid);
    for (const [name, manifest, code] of faults) {
      const thrown = thrownBy(() => signPack(manifest, KEY));
      expect(thrown, `${name} was signed`).toBeInstanceOf(ReceiptError);
      expect((thrown as ReceiptError).code, name).toBe(code);
      // The same fault sealed through the published pieces rather than through `signPack`, which is how a vector
      // of this class is made, is answered by the reader with the code the writer refused to sign under. The two
      // answers are one rule rather than two that were written to agree.
      const payloadBytes = encodePackManifest(manifest);
      const sealed = sealPack(headerBytes, payloadBytes, ed25519.sign(packSigStructure(headerBytes, payloadBytes), KEY.privateKey));
      expect(codeOf(() => decodePack(sealed)), `${name} answered differently once it was made anyway`).toBe(code);
    }
    expect(codeOf(() => signPack(honest, KEY))).toBe('accepted');
  });

  it('refuses a signing key whose kid resolves to no key', () => {
    // A pack whose header names a kid nothing hashes to is unverifiable by construction, and `verifyPack`
    // answers that as `PACK_KID_MISMATCH` against any key a caller can hold. The writer refuses it where the
    // bytes are made, which is the rule `manifest-seal.ts` keeps for the same reason.
    expect(codeOf(() => signPack(manifestOf(), { ...KEY, kid: new Uint8Array(32) }))).toBe('BAD_SIGNING_KEY');
    expect(codeOf(() => signPack(manifestOf(), { ...KEY, kid: SECOND.kid }))).toBe('BAD_SIGNING_KEY');
    expect(codeOf(() => signPack(manifestOf(), { ...KEY, privateKey: new Uint8Array(31) }))).toBe('BAD_SIGNING_KEY');
    expect(codeOf(() => signPack(manifestOf(), KEY))).toBe('accepted');
  });

  it('chains from either endpoint shape and crosses a key rotation without help', () => {
    // The writer is not a chain builder: the records and the endpoints arrive inside one manifest, so a
    // deployment that retired a prefix, or rotated its signing key inside the window, writes through this call.
    const seam = sha256(bytesOf('the seam a trim record carried'));
    const retired = chained(ENTRIES, seam);
    expect(() => verifyPack(signPack(manifestFor(retired), KEY), { publicKey: KEY.publicKey })).not.toThrow();
    const rotated = chained(ENTRIES.map((one, index) => ({ ...one, key: index === 0 ? SECOND : KEY })));
    const bytes = signPack(manifestFor(rotated), KEY);
    const read = verifyPack(bytes, { resolveKey: (kid) => [KEY, SECOND].find((one) => toHex(one.kid) === toHex(kid))?.publicKey });
    expect(read.outcome.walked.map((one) => one.item.id)).toEqual(['receipt-0', 'receipt-1', 'receipt-2']);
    expect(read.outcome.ordering).toEqual([]);
  });
});

/**
 * The walk the seal runs, on the writer's side of the signature.
 *
 * `docs/receipt-spec.md` states that `signPack` will not sign a manifest its own reader refuses, and the run
 * from the anchor to the head is part of what that reader refuses over. These cases are the difference between
 * a document that contradicts itself, which the structural parse answers, and a document whose links do not
 * add up to the endpoints it names, which only a walk sees. The second is what a deployment reaches when its
 * window is not contiguous in chain order, and every one of these bytes used to leave the writer signed.
 *
 * Both directions are pinned, and the accept side is pinned as a digest rather than as a shape: a guard that
 * moved a byte of arithmetic would show up here as surely as a missing guard shows up in the refusals.
 */
describe('the pack seal walks the run it signs', () => {
  it('refuses the non-contiguous window a corrected clock produces, under the reader code', () => {
    // Three records chained in the order the store appended them, and the middle one stamped before its own
    // predecessor because the clock moved backwards between the two appends. The store answers a window by
    // stamp, so the two records inside this one are `a` and `c`, and `b`, which `c` chains from, is not in the
    // set. Nothing here is a forgery: the receipts are honest and every `prev` is the digest its record has.
    const store = chained([
      { id: 'a', iat: BASE, nonce: 1 },
      { id: 'b', iat: BASE - 100, nonce: 2 },
      { id: 'c', iat: BASE + 1, nonce: 3 },
    ]);
    const window = manifestFor({
      items: [store.items[0]!, store.items[2]!],
      anchor: store.anchor,
      head: store.head,
    });
    const refused = thrownBy(() => signPack(window, KEY)) as ReceiptError;
    expect(refused, 'the seal signed a run that stops short of its own head').toBeInstanceOf(ReceiptError);
    expect(refused.code).toBe('PACK_CHAIN_BROKEN');
    // The refusal says what the walk reached, which is the sentence the reader states and the reason the
    // caller can tell a lifted record from a fork without opening the manifest.
    expect(refused.message).toMatch(/the walk reached 1 item\(s\) and stopped at a digest that is not the head/u);
    // One rule, not two written to agree: made anyway through the published pieces, the reader answers this
    // document with the same code and the same sentence.
    const fromTheReader = thrownBy(() => verifyPack(sealedFromPieces(window), { publicKey: KEY.publicKey })) as ReceiptError;
    expect(fromTheReader.code).toBe(refused.code);
    expect(fromTheReader.message).toBe(refused.message);
    // The same three records are a pack for a window that reaches back over the stamp the clock moved: the
    // span binds every item, so the record the chain runs through has to be inside the window it links.
    const whole = manifestFor(store, {
      span: { from: BASE - 100, to: SPAN_TO },
      duty: { art: '19(1)', rev: SPAN_TO - 200, required: 3_600, held: SPAN_TO - (BASE - 100) },
    });
    expect(codeOf(() => signPack(whole, KEY))).toBe('accepted');
  });

  it('seals a closing run as the exact bytes the published pieces assemble', () => {
    // `signPack` and the four pieces are pinned to one document by the case above, so the digest of the
    // piecewise bytes is what the writer produced before any walk ran at the seal. Same digest on every run
    // below says the guard refused more documents without writing a different one, which is the whole of what
    // a change to a seal may do to a signed byte: nothing.
    const seam = sha256(bytesOf('the seam a trim record carried'));
    const accepted: Array<[string, PackManifest]> = [
      ['three records from an empty anchor', manifestOf()],
      ['one record from an empty anchor', manifestFor(chained([ENTRIES[0]!]))],
      ['three records from a retired seam', manifestFor(chained(ENTRIES, seam))],
      ['a run whose stamps run against its links', backwardsManifest()],
      ['a span crossing a key rotation', manifestFor(chained(ENTRIES.map((one, index) => ({ ...one, key: index === 0 ? SECOND : KEY }))))],
      ['two records stamped in one second', manifestFor(chained([
        { id: 'twin-0', iat: BASE, nonce: 4 },
        { id: 'twin-1', iat: BASE, nonce: 5 },
      ]))],
    ];
    for (const [name, manifest] of accepted) {
      expect(digestOf(signPack(manifest, KEY)), `${name} moved`).toBe(digestOf(sealedFromPieces(manifest)));
    }
  });

  it('answers the three shapes a walk guard gets wrong, in both directions', () => {
    const seam = sha256(bytesOf('the seam a trim record carried'));
    // A single record is a whole run when the anchor it names is the anchor the manifest names and its own
    // digest is the head. One step, no pair, and the case a loop over successive items forgets.
    const single = chained([ENTRIES[0]!]);
    expect(codeOf(() => signPack(manifestFor(single), KEY))).toBe('accepted');
    // The same single record naming a predecessor nobody handed it: nothing links from the anchor, so the walk
    // reaches no item at all and the head stays out of reach.
    const orphaned = manifestFor({ ...single, items: [{ ...single.items[0]!, prev: seam }] });
    const noStep = thrownBy(() => signPack(orphaned, KEY)) as ReceiptError;
    expect(noStep.code).toBe('PACK_CHAIN_BROKEN');
    expect(noStep.message).toMatch(/the walk reached 0 item\(s\)/u);
    // An empty items array is a fault of the manifest and the parse answers it first, which is the only answer
    // that keeps a walk over nothing from closing vacuously and signing an artifact that reads as evidence.
    expect(codeOf(() => signPack(manifestFor(single, { items: [] }), KEY))).toBe('PACK_BAD_MANIFEST');
    // The vacuous pair itself, an anchor and a head that are the same thirty-two zero bytes over no records,
    // refused by the parse rather than by a walk that would have found nothing to disagree with.
    expect(codeOf(() => signPack(manifestFor({ items: [], anchor: new Uint8Array(32), head: new Uint8Array(32) }), KEY))).toBe('PACK_BAD_MANIFEST');
    // An anchor that is not the digest the first item names, on a run that is chained from a seam and states
    // thirty-two zero bytes instead. The links are perfect and the walk has no door in.
    const retired = chained(ENTRIES, seam);
    expect(codeOf(() => signPack(manifestFor(retired), KEY))).toBe('accepted');
    const misanchored = thrownBy(() => signPack(manifestFor({ ...retired, anchor: new Uint8Array(32) }), KEY)) as ReceiptError;
    expect(misanchored.code).toBe('PACK_CHAIN_BROKEN');
    expect(misanchored.message).toMatch(/the walk reached 0 item\(s\)/u);
    // The trap in that same shape with the head equal to the anchor, where a guard that only asked "did the
    // run reach the head" would sign: the walk reaches nothing, the cursor is the head already, and only the
    // count of what it reached against the array it was handed sees the three records outside it.
    const vacuous = thrownBy(() =>
      signPack(manifestFor({ ...retired, anchor: new Uint8Array(32), head: new Uint8Array(32) }), KEY),
    ) as ReceiptError;
    expect(vacuous.code).toBe('PACK_ITEM_UNREACHED');
    expect(vacuous.message).toMatch(/receipt-0, receipt-1, receipt-2/u);
    // Two items claiming one predecessor, where the reader would have to take whichever it met first.
    const rival: PackItem = { id: 'rival', iat: BASE, prev: new Uint8Array(32), receipt: issueReceipt(receiptPayload(BASE, 6), KEY) };
    const run = chained(ENTRIES);
    const forked = thrownBy(() => signPack(manifestFor({ ...run, items: [rival, ...run.items] }), KEY)) as ReceiptError;
    expect(forked.code).toBe('PACK_CHAIN_BROKEN');
    expect(forked.message).toMatch(/2 items name the same predecessor, so the run forks at/u);
    expect(forked.message).toMatch(/rival/u);
    expect(forked.message).toMatch(/receipt-0/u);
    // A record parked beside a run it is not part of, which is the half of the rule the endpoints cannot see.
    const parked: PackItem = { id: 'parked', iat: BASE + 1, prev: seam, receipt: issueReceipt(receiptPayload(BASE + 1, 7), KEY) };
    const unreached = thrownBy(() => signPack(manifestFor({ ...run, items: [...run.items, parked] }), KEY)) as ReceiptError;
    expect(unreached.code).toBe('PACK_ITEM_UNREACHED');
    expect(unreached.message).toMatch(/: parked$/u);
  });
});

/**
 * Every kind of ordering finding a verified pack can carry, one row each.
 *
 * `Record<PackOrderingFindingKind, string>` is what makes this a pin rather than a note: a kind added to
 * the union without a row here fails to compile, and a row whose kind has gone fails the same way, so the
 * vocabulary cannot move on one side of the boundary only. The case under this block asks the question a
 * type cannot, which is whether each declared name is one a document actually produces; a kind in a union
 * that no reader ever emits is a claim about an output this format does not have.
 *
 * One row is the whole of the vocabulary, and a second would be a second way the two orders a pack holds
 * can part. Either way it would stay a finding on a verdict rather than a refusal, because the store files
 * a receipt under the stamp it was handed and a corrected clock therefore makes honest stamps that run
 * backwards against the links.
 */
const ORDERING_FINDING_KINDS: Record<PackOrderingFindingKind, string> = {
  'stamp-runs-backwards': 'a step whose successor carries a stamp earlier than its own',
};

describe('the ordering finding a verified pack carries', () => {
  it('reports a pack whose stamps run against the links and accepts it', () => {
    // The store appended `receipt-2` first and `receipt-0` last, because its clock moved between the two, and
    // each receipt still attests the stamp its record was chained under. Nothing about these bytes is a forgery,
    // and this is the case that says so.
    const bytes = signPack(backwardsManifest(), KEY);
    const read = verifyPack(bytes, { publicKey: KEY.publicKey });
    expect(read.outcome.walked.map((one) => one.item.id)).toEqual(['receipt-2', 'receipt-1', 'receipt-0']);
    expect(read.outcome.span).toEqual({ from: SPAN_FROM, to: SPAN_TO });
    expect(read.outcome.ordering).toEqual([
      { kind: 'stamp-runs-backwards', from: 'receipt-2', to: 'receipt-1', fromIat: BASE + 2, toIat: BASE + 1 },
      { kind: 'stamp-runs-backwards', from: 'receipt-1', to: 'receipt-0', fromIat: BASE + 1, toIat: BASE },
    ]);
    // One entry per step that moved backwards, in chain order, each with a stable name beside the two ids and the
    // two stamps. A caller quotes a disagreement rather than recomputing it, and the name is the field that
    // outlives whatever words the report of it eventually uses.
    for (const one of read.outcome.ordering) {
      expect(one.kind).toBe('stamp-runs-backwards');
      expect(one.toIat).toBeLessThan(one.fromIat);
    }
    // Nothing refused, and nothing else about the reading changed: the same bytes are what `decodePack` accepts,
    // and the array the items arrived in is none of the finding's business.
    expect(() => decodePack(bytes)).not.toThrow();
    const manifest = decodePack(bytes).manifest;
    const reversedArray = verifyPack(signPack({ ...manifest, items: [...manifest.items].reverse() }, KEY), { publicKey: KEY.publicKey });
    expect(reversedArray.outcome.walked.map((one) => one.item.id)).toEqual(read.outcome.walked.map((one) => one.item.id));
    expect(reversedArray.outcome.ordering).toEqual(read.outcome.ordering);
  });

  it('keeps the set of finding kinds closed, in both directions, against what the reader emits', () => {
    const declared = Object.keys(ORDERING_FINDING_KINDS).sort();
    // The declared vocabulary, and one name only. This list and the sentence in
    // `docs/receipt-spec.md` are the same statement about the same field.
    expect(declared).toEqual(['stamp-runs-backwards']);
    // Emission, the other half: a document that disagrees emits every declared name and no other, and a
    // document that agrees emits none, so neither an undeclared kind nor an unreachable one passes here.
    const backwards = verifyPack(signPack(backwardsManifest(), KEY), { publicKey: KEY.publicKey }).outcome.ordering;
    expect([...new Set(backwards.map((one) => one.kind))].sort()).toEqual(declared);
    const agreeing = verifyPack(signPack(manifestOf(), KEY), { publicKey: KEY.publicKey }).outcome.ordering;
    expect([...new Set(agreeing.map((one) => one.kind))]).toEqual([]);
    // And the disagreement is still an answer rather than a refusal, which is what the row above is a
    // finding about: these bytes carry a kind, verify, and are handed back whole.
    expect(backwards.length).toBeGreaterThan(0);
    expect(() => verifyPack(signPack(backwardsManifest(), KEY), { publicKey: KEY.publicKey })).not.toThrow();
  });

  it('reports no disagreement where the two orders agree, including one stamp shared by two records', () => {
    expect(verifyPack(signPack(manifestOf(), KEY), { publicKey: KEY.publicKey }).outcome.ordering).toEqual([]);
    // A store serving two records inside one second chains them under the same stamp and the links still order
    // them, so equality is not a disagreement and a reader reports nothing rather than a run of empty findings.
    const sameSecond = chained([
      { id: 'first', iat: BASE, nonce: 4 },
      { id: 'second', iat: BASE, nonce: 5 },
      { id: 'third', iat: BASE + 1, nonce: 6 },
    ]);
    expect(verifyPack(signPack(manifestFor(sameSecond), KEY), { publicKey: KEY.publicKey }).outcome.ordering).toEqual([]);
    // A single-item pack has no step to disagree at, which is the case a loop over pairs has to answer at all.
    const single = chained([ENTRIES[0]!]);
    expect(verifyPack(signPack(manifestFor(single), KEY), { publicKey: KEY.publicKey }).outcome.ordering).toEqual([]);
    // The field is there when it is empty, so a caller reads a shape rather than testing for one.
    expect(Object.keys(verifyPack(signPack(manifestOf(), KEY), { publicKey: KEY.publicKey }).outcome).sort()).toEqual([
      'ordering',
      'span',
      'walked',
    ]);
  });

  it('names only the step where the stamps moved backwards, not every later one', () => {
    // Chain order with the middle stamp one second ahead of the last: one step disagrees, and a report naming the
    // whole run rather than the step would be a caller's work done for it badly.
    const run = chained([
      { id: 'receipt-0', iat: BASE, nonce: 1 },
      { id: 'receipt-1', iat: BASE + 2, nonce: 2 },
      { id: 'receipt-2', iat: BASE + 1, nonce: 3 },
    ]);
    const read = verifyPack(signPack(manifestFor(run), KEY), { publicKey: KEY.publicKey });
    expect(read.outcome.ordering).toEqual([
      { kind: 'stamp-runs-backwards', from: 'receipt-1', to: 'receipt-2', fromIat: BASE + 2, toIat: BASE + 1 },
    ]);
  });

  it('binds the same bytes it reports on, so the finding is not a licence', () => {
    const backwards = signPack(backwardsManifest(), KEY);
    const manifest = decodePack(backwards).manifest;
    // The walk still refuses a gap in a pack whose stamps run backwards. These bytes are made from the pieces,
    // because the writer now refuses to sign a run that does not close.
    const gapped = { ...manifest, items: [manifest.items[0]!, manifest.items[2]!] };
    expect(codeOf(() => verifyPack(sealedFromPieces(gapped), { publicKey: KEY.publicKey }))).toBe('PACK_CHAIN_BROKEN');
    // The item-stamp equality still refuses on these records. A stamp written to agree with the order the chain
    // fixes, while the receipt inside the item attests the stamp it was issued at, is the move the equality
    // exists for, and it is refused whether the honest stamps ran forwards or backwards. The reader reaches
    // that answer before the walk, which is why these bytes are made from the pieces and what the seal says
    // about them is the case below.
    const lied: PackItem[] = manifest.items.map((one, index) => ({ ...one, iat: one.iat + index }));
    expect(codeOf(() => verifyPack(sealedFromPieces({ ...manifest, items: lied }), { publicKey: KEY.publicKey }))).toBe('PACK_RECEIPT_STAMP_MISMATCH');
    // A parked receipt is still refused, ordering finding or not.
    const parked: PackItem = {
      id: 'parked',
      iat: BASE,
      prev: sha256(bytesOf('another chain entirely')),
      receipt: issueReceipt(receiptPayload(BASE, 8), KEY),
    };
    expect(codeOf(() => verifyPack(sealedFromPieces({ ...manifest, items: [...manifest.items, parked] }), { publicKey: KEY.publicKey }))).toBe('PACK_ITEM_UNREACHED');
    // The document these three were cut from is accepted, so none of the answers above is a fault of the shape.
    expect(codeOf(() => verifyPack(backwards, { publicKey: KEY.publicKey }))).toBe('accepted');
  });

  it('holds both halves of the chain rule, the walk and the count of what it reached', () => {
    // `pack.cddl` states that a conforming reader's check has two halves and that a verifier implementing only
    // the first has implemented half a rule. Both are pinned here on bytes sealed from the published pieces, so
    // the reader is asked about documents its writer now refuses to sign, and neither half can go missing
    // without this case failing.
    const run = chained(ENTRIES);
    const honest = manifestFor(run);
    expect(verifyPack(signPack(honest, KEY), { publicKey: KEY.publicKey }).outcome.walked).toHaveLength(3);
    // The count half, which is the one with eyes for a receipt parked beside a span it is not part of. The parked
    // item names a predecessor no item here carries, so the walk reaches the signed head without ever needing it,
    // and only the count of what it reached sees the array it arrived in.
    const parked: PackItem = {
      id: 'parked',
      iat: BASE + 1,
      prev: sha256(bytesOf('a digest nobody in this run names')),
      receipt: issueReceipt(receiptPayload(BASE + 1, 7), KEY),
    };
    const unreached = thrownBy(() => verifyPack(sealedFromPieces({ ...honest, items: [...honest.items, parked] }), { publicKey: KEY.publicKey })) as ReceiptError;
    expect(unreached.code).toBe('PACK_ITEM_UNREACHED');
    expect(unreached.message).toMatch(/: parked$/u);
    // The walk half, on the same three records with one lifted out and nothing else moved: the run stops short
    // of the head the writer signed, which is what publishing the head inside the signature buys.
    const short = thrownBy(() => verifyPack(sealedFromPieces({ ...honest, items: [honest.items[0]!, honest.items[2]!] }), { publicKey: KEY.publicKey })) as ReceiptError;
    expect(short.code).toBe('PACK_CHAIN_BROKEN');
    expect(short.message).toMatch(/the walk reached 1 item\(s\) and stopped at a digest that is not the head/u);
    // A fork is refused rather than resolved by the order the array happened to be in.
    const rival: PackItem = { id: 'rival', iat: BASE, prev: run.anchor, receipt: issueReceipt(receiptPayload(BASE, 9), KEY) };
    expect(codeOf(() => verifyPack(sealedFromPieces({ ...honest, items: [rival, ...honest.items] }), { publicKey: KEY.publicKey }))).toBe('PACK_CHAIN_BROKEN');
    // And the pack these three edits were cut from is accepted, so no answer above is a fault of the document.
    expect(codeOf(() => verifyPack(signPack(honest, KEY), { publicKey: KEY.publicKey }))).toBe('accepted');
  });
});
