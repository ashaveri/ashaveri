import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha2.js';
import { Ajv2020 } from 'ajv/dist/2020.js';
import {
  PACK_CONTENT_TYPE,
  REDACTION_CONTENT_TYPE,
  ReceiptError,
  decodeCanonical,
  decodePack,
  decodeRedaction,
  encodeCanonical,
  encodePackManifest,
  encodePackProtectedHeader,
  encodeRedactionManifest,
  encodeRedactionProtectedHeader,
  issueReceipt,
  packRecordDigest,
  packSigStructure,
  redactionPackDigest,
  redactionSigStructure,
  redactionSurvivorChain,
  redactionSurvivorDigest,
  sealPack,
  sealRedaction,
  signPack,
  signRedaction,
  signingKeyFromSeed,
  toHex,
  verifyPack,
  verifyRedaction,
  type PackItem,
  type PackManifest,
  type RedactionManifest,
  type RedactionVerifyOptions,
  type ReceiptPayloadV1,
  type SigningKey,
} from '../src/index.js';
import { REDACTION_MANIFEST_MEMBERS } from '../src/redaction.js';

/**
 * The redaction manifest: a signed statement that a record came out of a closed pack, and the arithmetic a
 * reader does to hold that statement to the pack.
 *
 * A pack's chain is linear, so the record after a removed one names the removed record's digest as its own
 * predecessor and the walk breaks rather than shortening. The pack is therefore never rewritten: this
 * document states the removal, and everything a reader is owed has to be recomputable from the pack's own
 * bytes. The four properties a reader holding one pack and one redaction is owed are what the cases below are
 * grouped around, each asked in the way that would fail if the property were dropped.
 *
 * Two sources of bytes, and the split is deliberate. Honest documents come from `signRedaction`, so the writer
 * is witnessed producing what the reader accepts, and every document meant to be refused is assembled from the
 * published pieces and re-sealed under the key its own header names, because a writer that runs its own
 * structural parse before signing cannot be asked to make a fault it refuses to sign. The pack each redaction
 * speaks about comes from `signPack` and never from a hand-built copy, so a disagreement between the two
 * documents is about the statement rather than about how either pair of bytes was assembled.
 */

const KEY: SigningKey = signingKeyFromSeed(new Uint8Array(32).fill(41));
const RETIRED: SigningKey = signingKeyFromSeed(new Uint8Array(32).fill(42));
const SECOND: SigningKey = signingKeyFromSeed(new Uint8Array(32).fill(43));

const BASE = 1_772_000_000;
const SPAN_FROM = BASE - 60;
const SPAN_TO = BASE + 3;
const REDACTION_AT = SPAN_TO + 10;
const ZEROS = new Uint8Array(32);
const STATES = 'one receipt removed on the instruction of the holder of the key that signed this document';

const redactionCddlPath = fileURLToPath(new URL('../redaction.cddl', import.meta.url));
const redactionSchemaPath = fileURLToPath(new URL('../schemas/redaction-v1.schema.json', import.meta.url));
const errorsPath = fileURLToPath(new URL('../src/errors.ts', import.meta.url));

function thrownCode(run: () => unknown): string {
  try {
    run();
    return 'accepted';
  } catch (err) {
    return err instanceof ReceiptError ? err.code : `UNCODED:${String(err)}`;
  }
}

/** A pack as it is handed over: the sealed bytes, and the manifest those bytes decode back into. */
interface SealedPack {
  readonly bytes: Uint8Array;
  readonly manifest: PackManifest;
}

function receiptPayload(iat: number, nonce: number): ReceiptPayloadV1 {
  const digest = sha256(new Uint8Array([nonce]));
  return {
    v: 1,
    iss: 'ashaveri-redaction-writer',
    ins: 'cvm-redaction-1',
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
 * anchor of thirty-two zero bytes unless a retirement put a seam in front.
 */
function chained(
  entries: Iterable<{ id: string; iat: number; nonce: number; key?: SigningKey }>,
  anchor = ZEROS,
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

const ENTRIES = [
  { id: 'receipt-0', iat: BASE, nonce: 1 },
  { id: 'receipt-1', iat: BASE + 1, nonce: 2 },
  { id: 'receipt-2', iat: BASE + 2, nonce: 3 },
];

function packManifest(
  run: { items: PackItem[]; anchor: Uint8Array; head: Uint8Array },
  over: Partial<PackManifest> = {},
): PackManifest {
  return {
    v: 1,
    at: SPAN_TO,
    span: { from: SPAN_FROM, to: SPAN_TO },
    chain: { anchor: run.anchor, head: run.head },
    duty: {
      art: '19(1)',
      rev: SPAN_TO - 30,
      required: 3_600,
      held: SPAN_TO - Math.min(...run.items.map((one) => one.iat)),
    },
    items: run.items,
    ...over,
  };
}

function sealed(manifest: PackManifest): SealedPack {
  const bytes = signPack(manifest, KEY);
  return sealedOf(bytes);
}

/** The bytes a case already assembled, read back into the manifest they carry. */
function sealedOf(bytes: Uint8Array): SealedPack {
  return { bytes, manifest: decodePack(bytes).manifest };
}

/** The three-record pack every honest case here speaks about, and the other shapes a reader meets. */
const PACK: SealedPack = sealed(packManifest(chained(ENTRIES)));
const OTHER_PACK: SealedPack = sealed(packManifest(chained([{ id: 'other-0', iat: BASE, nonce: 9 }, { id: 'other-1', iat: BASE + 1, nonce: 10 }])));
const SEAM_PACK: SealedPack = sealed(
  packManifest(chained(ENTRIES, sha256(new TextEncoder().encode('the seam a trim record carried')))),
);
const SINGLE_PACK: SealedPack = sealed(packManifest(chained([ENTRIES[0]!])));
const ROTATED_PACK: SealedPack = sealed(
  packManifest(chained([{ id: 'receipt-0', iat: BASE, nonce: 1, key: RETIRED }, ENTRIES[1]!, ENTRIES[2]!])),
);

/**
 * The survivors in chain order, read off the pack by walking its links rather than by slicing its array,
 * which is the rule the shipped reader applies. An expectation built any other way would agree with whichever
 * order the writer happened to list the items in.
 */
function survivorsOf(manifest: PackManifest, removed: readonly string[]): PackItem[] {
  const dropped = new Set(removed);
  const visited = new Set<string>();
  const reached: PackItem[] = [];
  let cursor = manifest.chain.anchor;
  for (;;) {
    const next = manifest.items.find((one) => !visited.has(one.id) && toHex(one.prev) === toHex(cursor));
    if (next === undefined) break;
    visited.add(next.id);
    reached.push(next);
    cursor = packRecordDigest(next);
  }
  return reached.filter((one) => !dropped.has(one.id));
}

/** The manifest a writer would build for one pack and one removal: both computed, neither copied. */
function baseManifest(pack: SealedPack, removed: readonly string[]): RedactionManifest {
  return {
    v: 1,
    at: REDACTION_AT,
    pack: redactionPackDigest(pack.bytes),
    removed,
    reduced: redactionSurvivorDigest(pack.manifest.chain.anchor, survivorsOf(pack.manifest, removed)),
    states: STATES,
  };
}

function honestRedaction(pack: SealedPack, removed: readonly string[], over: Partial<RedactionManifest> = {}): Uint8Array {
  return signRedaction({ ...baseManifest(pack, removed), ...over }, KEY);
}

/**
 * A manifest with one position moved, sealed through the published pieces rather than `signRedaction`, which
 * would refuse to sign it. The signature is good on these bytes unless the case names the signer otherwise, so
 * the only fault is the position edited, and each refusal below is about one rule rather than about a document
 * nobody signed.
 */
function mutant(
  pack: SealedPack,
  removed: readonly string[],
  edit: (root: Map<unknown, unknown>) => void,
  signer: SigningKey = KEY,
  headerKid: SigningKey = signer,
): Uint8Array {
  const payloadBytes = encodeRedactionManifest({ ...baseManifest(pack, removed) });
  const root = decodeCanonical(payloadBytes);
  if (!(root instanceof Map)) throw new Error('a manifest this file encoded did not come back as a map');
  edit(root);
  const editedBytes = encodeCanonical(root);
  const header = encodeRedactionProtectedHeader(headerKid.kid);
  return sealRedaction(header, editedBytes, ed25519.sign(redactionSigStructure(header, editedBytes), signer.privateKey));
}

function asMap(bytes: Uint8Array): Map<unknown, unknown> {
  const decoded = decodeCanonical(bytes);
  if (!(decoded instanceof Map)) throw new Error('a payload this file sealed is not a map');
  return decoded;
}

function elementsOf(bytes: Uint8Array): unknown[] {
  const contents = (decodeCanonical(bytes) as { contents?: unknown }).contents;
  if (!Array.isArray(contents)) throw new Error('a document this file sealed is not a four-element envelope');
  return contents;
}

/** The payload of a sealed redaction, which is the third element of the envelope. */
function payloadOf(bytes: Uint8Array): Uint8Array {
  return elementsOf(bytes)[2] as Uint8Array;
}

/** The declared three labels, with whatever a case adds, moves or drops on top of them. */
function headerWith(alter: (map: Map<unknown, unknown>) => void): Uint8Array {
  const header = asMap(encodeRedactionProtectedHeader(KEY.kid));
  alter(header);
  return encodeCanonical(header);
}

function sealedUnder(header: Uint8Array, payloadBytes: Uint8Array, signer: SigningKey = KEY): Uint8Array {
  return sealRedaction(header, payloadBytes, ed25519.sign(redactionSigStructure(header, payloadBytes), signer.privateKey));
}

/** Where `needle` starts inside `haystack`, or -1. A byte string's own search takes a value, not a run. */
function indexOfBytes(haystack: Uint8Array, needle: Uint8Array): number {
  outer: for (let start = 0; start + needle.length <= haystack.length; start += 1) {
    for (let index = 0; index < needle.length; index += 1) {
      if (haystack[start + index] !== needle[index]) continue outer;
    }
    return start;
  }
  return -1;
}

/** One byte of the last item's receipt flipped, and the pack's own signature left as it was made. */
function withPackReceiptByteFlipped(pack: SealedPack): Uint8Array {
  const [header, , payload, signature] = elementsOf(pack.bytes);
  const receipt = pack.manifest.items[pack.manifest.items.length - 1]!.receipt;
  const payloadBytes = new Uint8Array(payload as Uint8Array);
  const start = indexOfBytes(payloadBytes, receipt);
  if (start < 0) throw new Error('the signed pack payload does not carry the receipt this case edits');
  payloadBytes[start + 12] = (payloadBytes[start + 12] ?? 0) ^ 0x01;
  return sealPack(header as Uint8Array, payloadBytes, signature as Uint8Array);
}

const readWith = (pack: SealedPack, key: SigningKey = KEY): RedactionVerifyOptions => ({
  publicKey: key.publicKey,
  packBytes: pack.bytes,
});

const honest = honestRedaction(PACK, ['receipt-1']);
const honestRead = () => verifyRedaction(honest, readWith(PACK));

describe('the redaction writer and its own reader', () => {
  it('assembles a document through the published pieces exactly as it signs one', () => {
    // The refusals below are built from the pieces, so the pieces have to be the writer's own bytes or a
    // fault case would differ from a deployment's document in more positions than the one it edits.
    const manifest = baseManifest(PACK, ['receipt-1']);
    const payloadBytes = encodeRedactionManifest(manifest);
    const protectedBytes = encodeRedactionProtectedHeader(KEY.kid);
    const piecewise = sealRedaction(
      protectedBytes,
      payloadBytes,
      ed25519.sign(redactionSigStructure(protectedBytes, payloadBytes), KEY.privateKey),
    );
    expect(toHex(piecewise)).toBe(toHex(signRedaction(manifest, KEY)));
    expect(() => verifyRedaction(piecewise, readWith(PACK))).not.toThrow();
  });

  it('refuses to sign bytes its own reader would reject', () => {
    // Each case is a document whose pack, records and chain are honest and whose manifest contradicts its own
    // format, so the refusal is structural and no key is consulted. This is also what the writer is not asked
    // to do: it does not reach the pack's questions, because the pack is none of its arguments.
    const manifest = baseManifest(PACK, ['receipt-1']);
    const faults: Array<[string, RedactionManifest, string]> = [
      ['a removal list with nothing in it', { ...manifest, removed: [] }, 'REDACTION_BAD_MANIFEST'],
      ['an empty id in the list', { ...manifest, removed: [''] }, 'REDACTION_BAD_MANIFEST'],
      [
        'an id wider than the two-byte length the framing gives it',
        { ...manifest, removed: ['x'.repeat(65_536)] },
        'REDACTION_BAD_MANIFEST',
      ],
      ['two entries answering to one id', { ...manifest, removed: ['receipt-1', 'receipt-1'] }, 'REDACTION_DUPLICATE_ID'],
      ['a stamp before the epoch', { ...manifest, at: -1 }, 'REDACTION_BAD_MANIFEST'],
      ['a stamp spelled as a float', { ...manifest, at: REDACTION_AT + 0.5 }, 'REDACTION_BAD_MANIFEST'],
      ['a designation one byte short', { ...manifest, pack: new Uint8Array(31) }, 'REDACTION_BAD_MANIFEST'],
      ['a reduced digest one byte long', { ...manifest, reduced: new Uint8Array(1) }, 'REDACTION_BAD_MANIFEST'],
      ['a sentence with nothing in it', { ...manifest, states: '' }, 'REDACTION_BAD_MANIFEST'],
      ['a sentence past the bound the format states', { ...manifest, states: 'x'.repeat(2_049) }, 'REDACTION_BAD_MANIFEST'],
      ['a version no format has used', { ...manifest, v: 2 as unknown as 1 }, 'REDACTION_UNSUPPORTED_VERSION'],
    ];
    for (const [name, edited, code] of faults) {
      expect(thrownCode(() => signRedaction(edited, KEY)), `${name} was signed`).toBe(code);
    }
  });

  it('refuses a signing key whose kid is not sha256 of its public half', () => {
    // A header naming a kid that resolves to nothing is a document no reader can verify, so this is refused
    // where the bytes are made rather than where somebody finds out.
    const manifest = baseManifest(PACK, ['receipt-1']);
    expect(thrownCode(() => signRedaction(manifest, { ...KEY, kid: ZEROS }))).toBe('BAD_SIGNING_KEY');
    expect(thrownCode(() => signRedaction(manifest, { ...KEY, publicKey: SECOND.publicKey }))).toBe('BAD_SIGNING_KEY');
  });

  it('reads back the manifest it wrote as exactly the members the format declares', () => {
    expect([...asMap(payloadOf(honest)).keys()].sort()).toEqual([...REDACTION_MANIFEST_MEMBERS].sort());
    expect(decodeRedaction(honest).manifest).toEqual(baseManifest(PACK, ['receipt-1']));
  });
});

describe('the designation: a key it names and a pack a reader recomputes', () => {
  it('verifies under the key the header designates and refuses the rest', () => {
    expect(honestRead().manifest.removed).toEqual(['receipt-1']);
    // Sealed by another deployment's key: the bytes are a whole redaction and their signature holds against
    // the header that names them, so the refusal is that this caller does not designate that key.
    expect(thrownCode(() => verifyRedaction(honest, readWith(PACK, SECOND)))).toBe('REDACTION_KID_MISMATCH');
    expect(thrownCode(() => verifyRedaction(honest, { packBytes: PACK.bytes }))).toBe('REDACTION_UNKNOWN_KEY');
    expect(thrownCode(() => verifyRedaction(honest, { resolveKey: () => undefined, packBytes: PACK.bytes }))).toBe(
      'REDACTION_UNKNOWN_KEY',
    );
  });

  it('identifies the pack by a digest of its own bytes and not by a name the writer chose', () => {
    // The designation is sha256 over the whole sealed document, tag and signature included. The two other
    // readings available were worse: a digest of the manifest alone would let one manifest travel in two
    // envelopes and not say which the removal was made from, and an id would be a string with nothing to
    // recompute it against.
    expect(toHex(redactionPackDigest(PACK.bytes))).toBe(toHex(sha256(PACK.bytes)));
    expect(toHex(redactionPackDigest(PACK.bytes))).not.toBe(toHex(sha256(encodePackManifest(PACK.manifest))));
    expect(asMap(payloadOf(honest)).get('pack')).toEqual(sha256(PACK.bytes));
    // One manifest travelling in a second envelope is a second pack to this statement about, which is the half
    // a digest of the manifest alone would have missed. The pack below is honest and verifies: same manifest,
    // another signing key, so both documents are evidence and only one of them is the one removed from.
    const manifestBytes = encodePackManifest(PACK.manifest);
    const resealedHeader = encodePackProtectedHeader(SECOND.kid);
    const resealed = sealPack(
      resealedHeader,
      manifestBytes,
      ed25519.sign(packSigStructure(resealedHeader, manifestBytes), SECOND.privateKey),
    );
    expect(
      verifyPack(resealed, {
        resolveKey: (kid: Uint8Array) =>
          toHex(kid) === toHex(KEY.kid) ? KEY.publicKey : toHex(kid) === toHex(SECOND.kid) ? SECOND.publicKey : undefined,
      }).manifest,
    ).toEqual(PACK.manifest);
    expect(toHex(redactionPackDigest(resealed))).not.toBe(toHex(redactionPackDigest(PACK.bytes)));
    expect(thrownCode(() => verifyRedaction(honest, { publicKey: KEY.publicKey, packBytes: resealed }))).toBe(
      'REDACTION_PACK_MISMATCH',
    );
  });

  it('refuses a redaction pointed at a pack the reader does not hold, in both directions', () => {
    // Neither document is at fault and the pair cannot be read together, so this is refused rather than
    // answered with the wrong pack's chain.
    expect(thrownCode(() => verifyRedaction(honestRedaction(OTHER_PACK, ['other-0']), readWith(PACK)))).toBe(
      'REDACTION_PACK_MISMATCH',
    );
    expect(thrownCode(() => verifyRedaction(honest, readWith(OTHER_PACK)))).toBe('REDACTION_PACK_MISMATCH');
    // And the reader handed only the redaction: a statement about a document it cannot see is refused by name,
    // because accepting it would be reporting on material the reader never looked at.
    expect(
      thrownCode(() => verifyRedaction(honest, { publicKey: KEY.publicKey, packBytes: undefined as unknown as Uint8Array })),
    ).toBe('REDACTION_PACK_UNAVAILABLE');
  });

  it('refuses a redaction that predates the pack it removes from', () => {
    // Both stamps are inside signatures, one over each document, so this is a pair that cannot both be true
    // rather than one document contradicting itself, and it answers a different code for that reason.
    expect(
      thrownCode(() => verifyRedaction(mutant(PACK, ['receipt-1'], (root) => root.set('at', SPAN_TO - 1)), readWith(PACK))),
    ).toBe('REDACTION_PACK_DISAGREES');
    // Equal instants are not a disagreement, and neither is a redaction stated in the second the reads began.
    expect(() => verifyRedaction(mutant(PACK, ['receipt-1'], (root) => root.set('at', SPAN_TO)), readWith(PACK))).not.toThrow();
  });
});

describe('the removal set: every name present, nothing else gone', () => {
  it('refuses an id the designated pack does not carry', () => {
    expect(thrownCode(() => verifyRedaction(honestRedaction(PACK, ['receipt-9']), readWith(PACK)))).toBe(
      'REDACTION_ITEM_ABSENT',
    );
    // The id is the pack's own name for a record, so this is refused only against the pack: the same
    // statement read with no pack in hand is a shape question, and a shape question has no answer here.
    expect(thrownCode(() => decodeRedaction(honestRedaction(PACK, ['receipt-9'])))).toBe('accepted');
  });

  it('refuses a removal larger than the one stated, by recomputation rather than by trust', () => {
    // Two records lifted out of the pack and one named here, with the chain the shorter survivor sequence
    // hashes to. Nothing about the manifest is malformed and no membership check can see it: what refuses it
    // is that the reader's survivor set is the larger one, and its fold a different digest.
    const understated = mutant(PACK, ['receipt-1'], (root) =>
      root.set('reduced', redactionSurvivorDigest(PACK.manifest.chain.anchor, [PACK.manifest.items[0]!])),
    );
    expect(thrownCode(() => verifyRedaction(understated, readWith(PACK)))).toBe('REDACTION_SURVIVOR_CHAIN_MISMATCH');
    // The honest pair of the same statement, so the refusal above is about the set and not about the shape.
    expect(honestRead().outcome.survivors.map((one) => one.item.id)).toEqual(['receipt-0', 'receipt-2']);
  });

  it('refuses one id named twice, which is a count disagreeing with the set it states', () => {
    const twice = mutant(PACK, ['receipt-1'], (root) => root.set('removed', ['receipt-1', 'receipt-1']));
    expect(thrownCode(() => verifyRedaction(twice, readWith(PACK)))).toBe('REDACTION_DUPLICATE_ID');
    expect(thrownCode(() => decodeRedaction(twice))).toBe('REDACTION_DUPLICATE_ID');
  });

  it('refuses a redaction that removes nothing, before a key or a pack is consulted', () => {
    // A no-op redaction exists only to state that the pack's signed head still holds, and a container that
    // could say that is one in which a no-op and a forgery look alike. The empty list is malformed, so the
    // sentence cannot be signed at all, and the reader refuses it with no key in hand.
    const noop: RedactionManifest = { ...baseManifest(PACK, []), removed: [], reduced: PACK.manifest.chain.head };
    expect(thrownCode(() => signRedaction(noop, KEY))).toBe('REDACTION_BAD_MANIFEST');
    const header = encodeRedactionProtectedHeader(KEY.kid);
    const payloadBytes = encodeRedactionManifest(noop);
    const bytes = sealRedaction(header, payloadBytes, ed25519.sign(redactionSigStructure(header, payloadBytes), KEY.privateKey));
    expect(thrownCode(() => decodeRedaction(bytes))).toBe('REDACTION_BAD_MANIFEST');
    expect(thrownCode(() => verifyRedaction(bytes, readWith(PACK)))).toBe('REDACTION_BAD_MANIFEST');
  });

  it('refuses a survivor sequence with nothing in it, and does not answer with the anchor', () => {
    // A redaction that removes a pack's only record leaves no chain, and the value a fold would return for
    // nothing is the anchor it started from: a digest that reads as a chain head while attesting no record.
    // The writer cannot compute one, so these bytes are assembled by the writer that states a value rather
    // than derives it, which is the case the reader's own fold exists to refuse.
    const empties = signRedaction(
      {
        v: 1,
        at: REDACTION_AT,
        pack: redactionPackDigest(SINGLE_PACK.bytes),
        removed: ['receipt-0'],
        reduced: SINGLE_PACK.manifest.chain.anchor,
        states: STATES,
      },
      KEY,
    );
    expect(thrownCode(() => verifyRedaction(empties, readWith(SINGLE_PACK)))).toBe('REDACTION_SURVIVORS_EMPTY');
    expect(thrownCode(() => redactionSurvivorDigest(ZEROS, []))).toBe('REDACTION_SURVIVORS_EMPTY');
    expect(thrownCode(() => redactionSurvivorChain(SINGLE_PACK.manifest.chain.anchor, []))).toBe('REDACTION_SURVIVORS_EMPTY');
    // One record surviving is a whole chain rather than a degenerate one: the item that is first and last is
    // the same item, and its digest relinked from the anchor is what the document carries.
    const oneLeft = honestRedaction(SEAM_PACK, ['receipt-0', 'receipt-1']);
    const read = verifyRedaction(oneLeft, readWith(SEAM_PACK));
    expect(read.outcome.survivors.map((one) => one.item.id)).toEqual(['receipt-2']);
    expect(toHex(read.outcome.reduced)).toBe(
      toHex(packRecordDigest({ ...SEAM_PACK.manifest.items[2]!, prev: SEAM_PACK.manifest.chain.anchor })),
    );
    expect(toHex(read.outcome.reduced)).not.toBe(toHex(read.outcome.originalHead));
  });
});

describe('the chain over the surviving records', () => {
  it('is the pack rule folded over the survivors, relinked from the pack anchor', () => {
    // An independent fold: the framing `pack.ts` publishes, applied in this file to the survivors with each
    // predecessor replaced by the digest recomputed for the survivor before it. A construction that drifted in
    // the shipped module would show up as a disagreement here rather than agreeing with itself.
    const survivors = survivorsOf(PACK.manifest, ['receipt-1']);
    let cursor = PACK.manifest.chain.anchor;
    const expected: string[] = [];
    for (const one of survivors) {
      cursor = packRecordDigest({ id: one.id, iat: one.iat, prev: cursor, receipt: one.receipt });
      expected.push(toHex(cursor));
    }
    expect(expected).toHaveLength(2);
    expect(redactionSurvivorChain(PACK.manifest.chain.anchor, survivors).map(toHex)).toEqual(expected);
    expect(toHex(honestRead().outcome.reduced)).toBe(expected[1]);
    expect(toHex(honestRead().manifest.reduced)).toBe(expected[1]);
  });

  it('returns the pack head when nothing is removed and never when something is', () => {
    // The fact the no-op refusal rests on. With nothing dropped, each survivor's relinked predecessor is the
    // predecessor its record already names, so the fold is the pack's own walk and ends at its signed head.
    // Anything removed changes at least one hashed term, and the fold cannot return that value.
    expect(toHex(redactionSurvivorDigest(PACK.manifest.chain.anchor, PACK.manifest.items))).toBe(
      toHex(PACK.manifest.chain.head),
    );
    for (const removed of [['receipt-0'], ['receipt-1'], ['receipt-2'], ['receipt-0', 'receipt-2']]) {
      const reduced = redactionSurvivorDigest(PACK.manifest.chain.anchor, survivorsOf(PACK.manifest, removed));
      expect(toHex(reduced), `${removed.join('+')} removed and the head still stated`).not.toBe(
        toHex(PACK.manifest.chain.head),
      );
    }
    // A document that states the original head beside a real removal is refused rather than read as a chain
    // claim: this is the statement the artifact exists to make unproducible.
    const claimsHead = mutant(PACK, ['receipt-1'], (root) => root.set('reduced', PACK.manifest.chain.head));
    expect(thrownCode(() => verifyRedaction(claimsHead, readWith(PACK)))).toBe('REDACTION_SURVIVOR_CHAIN_MISMATCH');
  });

  it('is not a chain that keeps the predecessors the survivors carry', () => {
    // The other construction a reimplementer reaches for is to fold over the survivors using each record's own
    // `prev`. That is a chain with holes in it rather than a chain over the survivors, and the two readings
    // part whenever anything but the last record is dropped. The last record's case is asserted as equal on
    // purpose: it is where the two agree, and a suite that showed only the difference would not pin which of
    // the two readings this format states.
    const survivors = survivorsOf(PACK.manifest, ['receipt-1']);
    expect(toHex(redactionSurvivorDigest(PACK.manifest.chain.anchor, survivors))).not.toBe(
      toHex(packRecordDigest(survivors[1]!)),
    );
    const lastOnly = survivorsOf(PACK.manifest, ['receipt-2']);
    expect(toHex(redactionSurvivorDigest(PACK.manifest.chain.anchor, lastOnly))).toBe(
      toHex(packRecordDigest(lastOnly[1]!)),
    );
  });

  it('starts at the pack anchor, which a retired prefix moves', () => {
    // Chaining from the pack's anchor and chaining from thirty-two zero bytes are one statement only before a
    // retirement. The seam pack carries a nonzero anchor, so the two readings part, and a reader that
    // invented a start would be starting the walk wherever it liked.
    const survivors = survivorsOf(SEAM_PACK.manifest, ['receipt-1']);
    const fromSeam = redactionSurvivorDigest(SEAM_PACK.manifest.chain.anchor, survivors);
    expect(toHex(fromSeam)).not.toBe(toHex(redactionSurvivorDigest(ZEROS, survivors)));
    const read = verifyRedaction(honestRedaction(SEAM_PACK, ['receipt-1']), readWith(SEAM_PACK));
    expect(toHex(read.outcome.reduced)).toBe(toHex(fromSeam));
    expect(toHex(read.outcome.originalHead)).toBe(toHex(SEAM_PACK.manifest.chain.head));
  });

  it('answers a removal of the first record and a removal of the last with two different chains', () => {
    const firstOut = verifyRedaction(honestRedaction(PACK, ['receipt-0']), readWith(PACK));
    const lastOut = verifyRedaction(honestRedaction(PACK, ['receipt-2']), readWith(PACK));
    expect(toHex(firstOut.outcome.reduced)).not.toBe(toHex(lastOut.outcome.reduced));
    expect(firstOut.outcome.survivors.map((one) => one.item.id)).toEqual(['receipt-1', 'receipt-2']);
    expect(lastOut.outcome.survivors.map((one) => one.item.id)).toEqual(['receipt-0', 'receipt-1']);
    // Dropping the first record relinks the second onto the anchor, so no remaining record keeps the digest
    // the pack signs for it. Dropping the last leaves every remaining digest exactly as the pack has it, and
    // the reduced head is the digest the pack already signs for the record that is now last.
    const relinkedSecond = redactionSurvivorChain(PACK.manifest.chain.anchor, survivorsOf(PACK.manifest, ['receipt-0']))[0]!;
    expect(toHex(relinkedSecond)).not.toBe(toHex(PACK.manifest.items[1]!.prev));
    expect(toHex(firstOut.outcome.reduced)).not.toBe(toHex(PACK.manifest.chain.head));
    expect(toHex(lastOut.outcome.reduced)).toBe(toHex(PACK.manifest.items[2]!.prev));
  });

  it('orders survivors by the links and not by the array handed over', () => {
    // The pack's own rule, inherited: array order bears nothing, so a redaction of a pack whose items arrived
    // reversed states the same chain as one whose items arrived in chain order, and a reader that sorted by
    // position would state a different digest.
    const reversed = sealed({ ...PACK.manifest, items: [...PACK.manifest.items].reverse() });
    const againstReversed = honestRedaction(reversed, ['receipt-1']);
    expect(toHex(verifyRedaction(againstReversed, readWith(reversed)).outcome.reduced)).toBe(
      toHex(honestRead().outcome.reduced),
    );
  });
});

describe('the original pack, untouched by the document written about it', () => {
  it('verifies exactly as it did before, with the same run and the same head', () => {
    // Property four, stated as a comparison rather than as an argument: the pack is read on its own, then read
    // again through the redaction, and the two readings agree on every item, on the head and on the bytes. A
    // redaction is a second signature over a second document and has no way to reach the first.
    const before = verifyPack(PACK.bytes, { publicKey: KEY.publicKey });
    const after = honestRead();
    expect(after.outcome.pack.outcome.walked.map((one) => one.item.id)).toEqual(
      before.outcome.walked.map((one) => one.item.id),
    );
    expect(toHex(after.outcome.originalHead)).toBe(toHex(before.manifest.chain.head));
    expect(after.outcome.pack.manifest).toEqual(before.manifest);
    expect(toHex(PACK.bytes)).toBe(toHex(signPack(PACK.manifest, KEY)));
  });

  it('keeps the reduced head and the pack head apart in the answer and in the bytes', () => {
    const read = honestRead();
    expect(toHex(read.outcome.reduced)).not.toBe(toHex(read.outcome.originalHead));
    expect(read.outcome.survivors).toHaveLength(2);
    expect(read.outcome.pack.outcome.walked).toHaveLength(3);
    // Neither endpoint of the pack travels in this document, so no caller can read one field as the other: the
    // pack's head is signed in the pack and `reduced` is a fold over a chain the pack does not contain.
    const keys = [...asMap(read.envelope.payloadBytes).keys()];
    expect(keys).not.toContain('head');
    expect(keys).not.toContain('anchor');
  });

  it('refuses a pair whose pack cannot be read, and keeps the pack for the pack codes', () => {
    // A pack whose bytes moved after it was sealed, while the redaction still names the pack it was written
    // about. The designation is what disagrees first: this is a reader holding different bytes, which is a
    // finding about the pair, not a claim that is false.
    const moved = withPackReceiptByteFlipped(PACK);
    expect(thrownCode(() => verifyRedaction(honest, { publicKey: KEY.publicKey, packBytes: moved }))).toBe(
      'REDACTION_PACK_MISMATCH',
    );
    // The same moved pack with the designation recomputed over it, so the reading reaches the pack: the pack's
    // own refusal surfaces through the redaction reading, in a sentence that names a pack.
    const designated = honestRedaction({ bytes: moved, manifest: PACK.manifest }, ['receipt-1']);
    expect(thrownCode(() => verifyRedaction(designated, { publicKey: KEY.publicKey, packBytes: moved }))).toBe(
      'INVALID_SIGNATURE',
    );
    // A record lifted out of the middle of a signed run and nothing else touched, so the successor still names
    // the predecessor it had and the head is the one the whole run hashed to. The walk stops at the hole, and
    // the redaction inherits that answer rather than inventing one of its own.
    const broken = sealedOf(signPack({ ...PACK.manifest, items: [PACK.manifest.items[0]!, PACK.manifest.items[2]!] }, KEY));
    const aboutBroken = honestRedaction(broken, ['receipt-1']);
    expect(thrownCode(() => verifyRedaction(aboutBroken, readWith(broken)))).toBe('PACK_CHAIN_BROKEN');
    // A caller that retained one epoch of a pack whose span crosses a rotation has too few keys, and the pack
    // says so in its own code: neither document is at fault and neither is this reader.
    const rotated = honestRedaction(ROTATED_PACK, ['receipt-2']);
    expect(thrownCode(() => verifyRedaction(rotated, readWith(ROTATED_PACK)))).toBe('PACK_RECEIPT_INVALID');
    const both: RedactionVerifyOptions = {
      resolveKey: (kid: Uint8Array) =>
        toHex(kid) === toHex(KEY.kid) ? KEY.publicKey : toHex(kid) === toHex(RETIRED.kid) ? RETIRED.publicKey : undefined,
      packBytes: ROTATED_PACK.bytes,
    };
    expect(verifyRedaction(rotated, both).outcome.survivors.map((one) => one.item.id)).toEqual([
      'receipt-0',
      'receipt-1',
    ]);
    expect(thrownCode(() => verifyRedaction(rotated, { resolveKey: (kid: Uint8Array) => (toHex(kid) === toHex(KEY.kid) ? KEY.publicKey : undefined), packBytes: ROTATED_PACK.bytes }))).toBe(
      'PACK_UNKNOWN_KEY',
    );
  });

  it('leaves the pack acceptable to a reader that never hears of the redaction', () => {
    // The availability rule. Nothing in the pack refers to this document and no rule of the pack reader is
    // answered by it, so evidence that was never redacted stays evidence when the redaction is unreachable.
    const withoutIt = verifyPack(PACK.bytes, { publicKey: KEY.publicKey });
    expect(withoutIt.outcome.walked.map((one) => one.item.id)).toEqual(['receipt-0', 'receipt-1', 'receipt-2']);
    expect(thrownCode(() => decodeRedaction(PACK.bytes))).toBe('REDACTION_BAD_HEADER');
  });
});

describe('the shapes this format refuses', () => {
  it('refuses another container at the header, before any key is consulted', () => {
    const payloadBytes = encodeRedactionManifest(baseManifest(PACK, ['receipt-1']));
    for (const contentType of ['ashaveri/receipt', PACK_CONTENT_TYPE, 'ashaveri/export']) {
      const bytes = sealedUnder(encodeRedactionProtectedHeader(KEY.kid, contentType), payloadBytes);
      expect(
        thrownCode(() => verifyRedaction(bytes, { packBytes: PACK.bytes, resolveKey: () => KEY.publicKey })),
        contentType,
      ).toBe('REDACTION_BAD_HEADER');
      expect(thrownCode(() => decodeRedaction(bytes)), contentType).toBe('REDACTION_BAD_HEADER');
    }
    // And a pack handed to this reader, which is the confusion the content type is the whole answer to.
    expect(thrownCode(() => verifyRedaction(PACK.bytes, readWith(PACK)))).toBe('REDACTION_BAD_HEADER');
  });

  it('refuses a header that is not the header this format declares', () => {
    const payloadBytes = encodeRedactionManifest(baseManifest(PACK, ['receipt-1']));
    expect(thrownCode(() => decodeRedaction(sealedUnder(headerWith((map) => map.set(5, 'what')), payloadBytes)))).toBe(
      'REDACTION_BAD_HEADER',
    );
    expect(
      thrownCode(() => decodeRedaction(sealedUnder(headerWith((map) => map.set(4, KEY.kid.slice(0, 31))), payloadBytes))),
    ).toBe('REDACTION_BAD_HEADER');
    expect(thrownCode(() => decodeRedaction(sealedUnder(headerWith((map) => map.set(1, -7)), payloadBytes)))).toBe(
      'UNSUPPORTED_ALG',
    );
    // A protected header carrying the designated kid and a signature the designated key did not make: the kid
    // check passes and the signature is what refuses, which is the report about tampering rather than about a
    // caller holding the wrong key.
    const split = mutant(PACK, ['receipt-1'], () => undefined, SECOND, KEY);
    expect(toHex(split)).not.toBe(toHex(honest));
    expect(thrownCode(() => verifyRedaction(split, readWith(PACK)))).toBe('INVALID_SIGNATURE');
  });

  it('refuses an envelope that is not an envelope', () => {
    expect(thrownCode(() => decodeRedaction(encodeCanonical(elementsOf(honest))))).toBe('NOT_COSE_SIGN1');
    const [header, , payload, signature] = elementsOf(honest);
    expect(
      thrownCode(() =>
        decodeRedaction(sealRedaction(header as Uint8Array, payload as Uint8Array, (signature as Uint8Array).slice(0, 63))),
      ),
    ).toBe('NOT_COSE_SIGN1');
    expect(thrownCode(() => decodeRedaction(honest.slice(0, 20)))).toBe('REDACTION_MALFORMED_CBOR');
  });

  it('closes the manifest and the header against the block that declares them', () => {
    // Which members exist is the CDDL's answer, read here rather than restated: a list written in a test and
    // in the format is edited in one of the two places and stays plausible in the other.
    const cddl = readFileSync(redactionCddlPath, 'utf8');
    expect([...REDACTION_MANIFEST_MEMBERS]).toEqual(declaredMembers(cddl, 'Ashaveri-Redaction-Manifest'));
    expect(cddlRule(cddl, 'Ashaveri-Redaction-Manifest')).not.toContain('...');
    expect(headerLabels(cddl)).toEqual([1, 3, 4]);
    expect(cddl).toContain(`"${REDACTION_CONTENT_TYPE}"`);
    expect(removalIsASetOfIds(cddl)).toBe(true);
    // Closed at read time as well as in the definition. `head` and `anchor` are the two members an
    // implementer might reach for in order to state the original chain here, which is the sentence this
    // format refuses to let a second document carry.
    for (const member of ['met', 'reason', 'anchor', 'head', 'excision']) {
      expect(
        thrownCode(() => decodeRedaction(mutant(PACK, ['receipt-1'], (root) => root.set(member, true)))),
        `${member} was read as a member of the format`,
      ).toBe('REDACTION_BAD_MANIFEST');
    }
  });
});

describe('the JSON twin of the manifest', () => {
  it('compiles under strict mode and closes the map the writer writes', () => {
    const schema = JSON.parse(readFileSync(redactionSchemaPath, 'utf8')) as Record<string, unknown>;
    const validate = new Ajv2020({ strict: true }).compile(schema);
    const payload = {
      v: 1,
      at: REDACTION_AT,
      pack: toHex(redactionPackDigest(PACK.bytes)),
      removed: ['receipt-1'],
      reduced: toHex(redactionSurvivorDigest(PACK.manifest.chain.anchor, survivorsOf(PACK.manifest, ['receipt-1']))),
      states: STATES,
    };
    const projection = { protectedHeader: { alg: 'EdDSA', kid: toHex(KEY.kid), typ: REDACTION_CONTENT_TYPE }, payload };
    expect(validate(projection), JSON.stringify(validate.errors)).toBe(true);
    const negative: Array<[string, Record<string, unknown>]> = [
      ['a member the format does not define', { ...payload, met: true }],
      ['a removal list with nothing in it', { ...payload, removed: [] }],
      ['a designation of another width', { ...payload, pack: 'deadbeef' }],
      ['a stamp that is not a whole number', { ...payload, at: REDACTION_AT + 0.5 }],
      ['a version that is not this one', { ...payload, v: 2 }],
    ];
    for (const [name, edited] of negative) {
      expect(validate({ ...projection, payload: edited }), `${name} was accepted by the twin`).toBe(false);
    }
    for (const member of ['at', 'pack', 'removed', 'reduced', 'states']) {
      const without: Record<string, unknown> = { ...payload };
      delete without[member];
      expect(validate({ ...projection, payload: without }), `${member} was not required by the twin`).toBe(false);
    }
  });

  it('carries floors and no ceiling, which is the sentence the projection states', () => {
    const text = readFileSync(redactionSchemaPath, 'utf8');
    for (const keyword of ['maxLength', 'maxItems', 'maximum', 'exclusiveMaximum']) {
      expect(text, `the twin grew a ${keyword}, which belongs to the CDDL`).not.toContain(keyword);
    }
    expect(text).toContain('the byte ceiling belongs to `redaction.cddl`');
  });
});

describe('every refusal this container names is reached', () => {
  it('has a case in this file that answers with it', () => {
    // Read off the declared union rather than from a list repeated here, which is the only way an addition
    // cannot pass unnoticed: a code with no case is a word nothing is measured against.
    const runs: Array<() => string> = [
      () => thrownCode(() => decodeRedaction(honest.slice(0, 20))),
      () => thrownCode(() => decodeRedaction(encodeCanonical(elementsOf(honest)))),
      () =>
        thrownCode(() =>
          decodeRedaction(
            sealedUnder(headerWith((map) => map.set(1, -7)), encodeRedactionManifest(baseManifest(PACK, ['receipt-1']))),
          ),
        ),
      () => thrownCode(() => decodeRedaction(PACK.bytes)),
      () => thrownCode(() => verifyRedaction(honest, readWith(PACK, SECOND))),
      () => thrownCode(() => verifyRedaction(honest, { packBytes: PACK.bytes })),
      () =>
        thrownCode(() =>
          verifyRedaction(honest, { publicKey: KEY.publicKey, packBytes: undefined as unknown as Uint8Array }),
        ),
      () => thrownCode(() => verifyRedaction(honest, readWith(OTHER_PACK))),
      () =>
        thrownCode(() =>
          verifyRedaction(mutant(PACK, ['receipt-1'], (root) => root.set('at', SPAN_TO - 1)), readWith(PACK)),
        ),
      () => thrownCode(() => verifyRedaction(honestRedaction(PACK, ['receipt-9']), readWith(PACK))),
      () =>
        thrownCode(() =>
          verifyRedaction(
            honestRedaction(SINGLE_PACK, ['receipt-0'], { reduced: SINGLE_PACK.manifest.chain.anchor }),
            readWith(SINGLE_PACK),
          ),
        ),
      () =>
        thrownCode(() =>
          verifyRedaction(mutant(PACK, ['receipt-1'], (root) => root.set('reduced', PACK.manifest.chain.head)), readWith(PACK)),
        ),
      () => thrownCode(() => decodeRedaction(mutant(PACK, ['receipt-1'], (root) => root.set('v', 2)))),
      () => thrownCode(() => decodeRedaction(mutant(PACK, ['receipt-1'], (root) => root.set('met', true)))),
      () =>
        thrownCode(() =>
          decodeRedaction(mutant(PACK, ['receipt-1'], (root) => root.set('removed', ['receipt-1', 'receipt-1']))),
        ),
      () => thrownCode(() => verifyRedaction(mutant(PACK, ['receipt-1'], () => undefined, SECOND, KEY), readWith(PACK))),
      () => thrownCode(() => decodeRedaction(encodeCanonical([]))),
    ];
    const observed = new Set(runs.map((run) => run()));
    for (const one of observed) {
      expect(one, 'a case answered with something no registry declares').not.toMatch(/^UNCODED/);
    }
    const declared = [
      ...new Set([...readFileSync(errorsPath, 'utf8').matchAll(/'(REDACTION_[A-Z0-9_]+)'/gu)].map((found) => found[1]!)),
    ];
    expect(declared.length).toBeGreaterThanOrEqual(13);
    for (const code of declared) {
      expect(observed, `${code} is declared and no case here reaches it`).toContain(code);
    }
  });
});

/**
 * The text of one CDDL rule of this format, from its opening brace to the line that closes it. Kept here
 * rather than imported because `test/cddl.ts` is `receipt.cddl`'s reader and its failures name that file, so a
 * rule missing from this format would be reported as missing from the receipt's.
 */
function cddlRule(cddl: string, rule: string): string {
  const start = cddl.indexOf(`${rule} = {`);
  if (start < 0) throw new Error(`${rule} is not declared in redaction.cddl`);
  const end = cddl.indexOf('\n}', start);
  if (end < 0) throw new Error(`${rule} in redaction.cddl never closes`);
  return cddl.slice(start, end);
}

/** The members one block declares by text label, in the order it declares them, comments stripped. */
function declaredMembers(cddl: string, rule: string): string[] {
  const members: string[] = [];
  for (const line of cddlRule(cddl, rule).split('\n').slice(1)) {
    for (const piece of line.split(';')[0]!.split(',')) {
      const found = /^\s*([a-z][a-z0-9_]*)\s*:/u.exec(piece);
      if (found) members.push(found[1]!);
    }
  }
  if (members.length === 0) throw new Error(`${rule} declares no member`);
  return members;
}

/** The integer labels the signed header block declares, including the negative one the COSE registry uses. */
function headerLabels(cddl: string): number[] {
  const labels: number[] = [];
  for (const line of cddlRule(cddl, 'Ashaveri-Redaction-Protected-Header').split('\n').slice(1)) {
    const declaration = line.split(';')[0]!;
    if (declaration.trim() === '') continue;
    const found = /^\s*(-?\d+)\s*:/u.exec(declaration);
    if (!found) throw new Error(`this reader takes one integer-labelled member per line and cannot read "${declaration.trim()}"`);
    labels.push(Number(found[1]));
  }
  if (labels.length === 0) throw new Error('the signed header declares no member by label');
  return labels.sort((a, b) => a - b);
}

/**
 * That the removal list is a set of ids and not a table of facts: the manifest declares it as a non-empty array
 * of a rule of its own, and that rule is a bound text. A reader that found a map behind each entry would be
 * reading per-removal facts the format says are the pack's to carry.
 */
function removalIsASetOfIds(cddl: string): boolean {
  const list = /^\s*removed:\s*\[\+\s*([a-z-]+)\]/mu.exec(cddlRule(cddl, 'Ashaveri-Redaction-Manifest'));
  return list?.[1] === 'removed-id' && cddl.includes('removed-id = tstr');
}
