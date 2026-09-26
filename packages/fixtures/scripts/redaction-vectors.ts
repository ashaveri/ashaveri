import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { writeFileSync } from 'node:fs';
import { ed25519 } from '@noble/curves/ed25519';
import {
  PACK_CONTENT_TYPE,
  REDACTION_CONTENT_TYPE,
  ReceiptError,
  decodeCanonical,
  decodePack,
  decodeRedaction,
  encodeCanonical,
  encodeRedactionManifest,
  encodeRedactionProtectedHeader,
  packRecordDigest,
  redactionPackDigest,
  redactionSigStructure,
  redactionSurvivorChain,
  redactionSurvivorDigest,
  sealPack,
  sealRedaction,
  signRedaction,
  signingKeyFromSeed,
  toBase64Url,
  toHex,
  verifyPack,
  verifyRedaction,
  type PackItem,
  type PackManifest,
  type RedactionManifest,
  type SigningKey,
  type VerifiedRedaction,
} from '@ashaveri/receipt';
import { labeled } from './seed.ts';
import { fixtureKey } from './receipt-envelope.ts';
import { loadPackVectors } from '../src/index.ts';

const DATA = join(dirname(fileURLToPath(import.meta.url)), '..', 'data');

/**
 * The redaction manifest vectors: whole redactions, the pack each one is checked against, and the verdict the
 * shipped reader owes the pair.
 *
 * A redaction states a removal from a pack that is already closed and sealed, so every row here is a pair of
 * documents, and a row that hands over only one of them is a refusal by itself. The packs are not rebuilt for
 * this suite: each one is a document `packages/fixtures/data/pack-v1.json` already publishes, named by its row
 * in the `packOf` field beside the bytes, so a third party reading these files meets one set of pack bytes in
 * two places and can check that the removal is stated about evidence this repository already stands behind.
 * Nothing here rewrites a pack, and that is the artifact's whole premise.
 *
 * Two verdicts are published per row because the reader has two entry points that answer different questions.
 * `structural` is what `decodeRedaction` says about the bytes with no key and no pack in hand, and `verdict` is
 * what `verifyRedaction` says against the pack the row states. The pair matters more here than anywhere else in
 * this repository: a redaction's claims are checkable only against a second document, so a row that is
 * `verify-ok` structurally and a refusal in `verdict` is refusing about a pack, a key or the arithmetic over the
 * survivors, and a port that merged those two would report a manifest that contradicts itself where the fault is
 * a reader holding the wrong evidence.
 *
 * The third column is the chain. Each accepted row publishes the survivors in the order the pack's links fix
 * them, the head the fold over them reaches, and the pack's own head beside it, because the sentence those two
 * numbers exist to keep apart is the one this container must never let a reader merge: the pack's head holds over
 * the pack's own run, and the reduced head holds over a shorter chain the pack does not contain.
 */

/** The three labels `redaction.cddl` declares for a signed redaction header, and no fourth. */
const LABEL_ALG = 1;
const LABEL_TYP = 3;
const LABEL_KID = 4;

/**
 * The keys this suite publishes.
 *
 * The pack half of every pair here was sealed by the committed fixture receipt key, which is the key the pack
 * suite publishes and the key a deployment signs its live traffic with, so a redaction of that pack is sealed by
 * the same key family rather than by an invented issuer. `RETIRED` is the epoch a deployment superseded inside a
 * span, and `OTHER` is another deployment's key, used for the row whose redaction is sealed under a key its
 * caller does not designate, the row whose header names one key while another made the signature, and the pack
 * re-sealed over an honest manifest by a different hand. The generator stops unless every kid here matches a kid
 * `pack-v1.json` publishes, which is what makes these the same keys and not a second family of the same shape.
 */
const CURRENT: SigningKey = fixtureKey();
const RETIRED: SigningKey = signingKeyFromSeed(labeled('ashaveri-pack-v1/receipt-key-b'));
const OTHER: SigningKey = signingKeyFromSeed(labeled('ashaveri-pack-v1/signer-b'));

const KEY_MATERIAL: readonly { key: SigningKey; seed: string; role: string }[] = [
  {
    key: CURRENT,
    seed: "sha256 of 'ashaveri-fixtures/receipt-key/v1', the committed fixture receipt key",
    role: 'seals every honest redaction here and every pack they speak about',
  },
  {
    key: RETIRED,
    seed: "sha256 of 'ashaveri-pack-v1/receipt-key-b'",
    role: 'the epoch superseded inside a span, whose receipts a pack this suite redacts still carries',
  },
  {
    key: OTHER,
    seed: "sha256 of 'ashaveri-pack-v1/signer-b'",
    role: "another deployment's key, for the redaction sealed under a key its caller does not designate, the signature not made by the key its header names, and the pack re-sealed over an honest manifest",
  },
];

/** The published pack suite, which is where every pack named here comes from. */
const packSuite = loadPackVectors();
const packRows = new Map(packSuite.vectors.map((one) => [one.name, one]));
const publishedKids = new Set(packSuite.layout.keyMaterial.map((one) => one.kidHex));

const bytes = (base64url: string): Uint8Array => new Uint8Array(Buffer.from(base64url, 'base64url'));

/**
 * One published pack, with the manifest its own bytes decode back into. `edited` states that the bytes handed
 * to the reader are the named row's bytes with one position moved, which is the only departure from handing
 * over a published document exactly as it stands.
 */
interface PackPair {
  readonly name: string;
  readonly edited?: string;
  readonly bytes: Uint8Array;
  readonly manifest: PackManifest;
}

/**
 * A pack taken out of the published suite rather than rebuilt. The row it came from is carried with it, so a
 * reader of these files can go and check that the pack is the one the pack suite states a verdict for, and the
 * key it names is one the pack suite publishes: a redaction of evidence nobody sealed would be a suite about
 * nothing.
 */
function packFrom(row: string): PackPair {
  const found = packRows.get(row);
  if (found === undefined) throw new Error(`pack-v1.json publishes no ${row} document for this suite to redact`);
  const documentBytes = bytes(found.documentBase64Url);
  const decoded = decodePack(documentBytes);
  if (decoded.header.contentType !== PACK_CONTENT_TYPE) throw new Error(`${row} is not a pack document`);
  if (!publishedKids.has(toHex(decoded.header.kid))) {
    throw new Error(`${row} names a kid the pack suite publishes no key for`);
  }
  return { name: row, bytes: documentBytes, manifest: decoded.manifest };
}

const HONEST = packFrom('well-formed-three-items');
const REVERSED = packFrom('array-order-bears-nothing');
const SEAM = packFrom('retired-prefix-behind-a-seam');
const SINGLE = packFrom('single-item-pack');
const ROTATED = packFrom('span-crossing-a-key-rotation');
const SHORTENED = packFrom('shortened-run-closing-at-its-own-head');
const BROKEN = packFrom('record-lifted-out-of-the-middle');
const RESEALED = packFrom('sealed-under-another-deployment-key');

/** Where `needle` starts inside `haystack`, or -1. The payload is searched, not assumed. */
function indexOfBytes(haystack: Uint8Array, needle: Uint8Array): number {
  outer: for (let start = 0; start + needle.length <= haystack.length; start += 1) {
    for (let index = 0; index < needle.length; index += 1) {
      if (haystack[start + index] !== needle[index]) continue outer;
    }
    return start;
  }
  return -1;
}

function elementsOf(documentBytes: Uint8Array): unknown[] {
  const contents = (decodeCanonical(documentBytes) as { contents?: unknown }).contents;
  if (!Array.isArray(contents)) throw new Error('a document this file sealed is not a four-element envelope');
  return contents;
}

/**
 * A pack with one byte of one receipt flipped afterwards and its own signature kept. The receipt bytes sit
 * inside the hash of the record they belong to and are opaque to the manifest's decode, so the pack still reads
 * and the pack's seal is what refuses, which is the order a reader of the pair has to keep and the edit a
 * handover carried through a loose file meets.
 */
function withPackReceiptByteFlipped(pack: PackPair, index: number, at: number): Uint8Array {
  const [header, , payload, signature] = elementsOf(pack.bytes);
  const payloadBytes = new Uint8Array(payload as Uint8Array);
  const receipt = pack.manifest.items[index]!.receipt;
  const start = indexOfBytes(payloadBytes, receipt);
  if (start < 0) throw new Error('the signed pack payload does not carry the receipt this case edits');
  payloadBytes[start + at] = (payloadBytes[start + at] ?? 0) ^ 0x01;
  return sealPack(header as Uint8Array, payloadBytes, signature as Uint8Array);
}

/**
 * The honest pack with one byte of its first receipt flipped after it was sealed, its signature left as it was
 * made. The pack's manifest is unchanged by that edit, because the receipt bytes are opaque to the pack's own
 * decode, which is what makes this pair a test of the designation rather than of a shape.
 */
const MOVED: PackPair = {
  name: 'well-formed-three-items',
  edited: 'one byte of items[0].receipt flipped after the pack was sealed',
  bytes: withPackReceiptByteFlipped(HONEST, 0, 12),
  manifest: HONEST.manifest,
};

/** The instant every published fixture in this repository is issued at, so regenerating changes no byte. */
const BASE = HONEST.manifest.items[0]!.iat;

/**
 * The redaction's own stamp: a day after the pack it speaks about was assembled, which is the shape a cold tier
 * takes, the pack closed on one day and the removal stated on a later one. It is never before the pack's `at`,
 * which is the relation one refusal row below turns on.
 */
const STATED_AT = BASE + 86_400;

const STATES = 'one receipt removed from this pack on the instruction of the holder of the key that signed this document';
const STATES_SHORT = 'a receipt named by its store id is no longer carried by the pack';

/**
 * The pack's records in the order its links fix them, walked from the signed anchor. Read from the manifest
 * rather than taken from the array, because array order bears nothing in either container, and a suite that took
 * the order from the array would publish a chain a conforming reader cannot reach.
 */
function walkedChain(manifest: PackManifest): PackItem[] {
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
  return reached;
}

function survivors(manifest: PackManifest, removed: readonly string[]): PackItem[] {
  const dropped = new Set(removed);
  return walkedChain(manifest).filter((one) => !dropped.has(one.id));
}

/** How a row hands the reader its keys: the one key pinned, or the set a resolver answers from. */
interface Designation {
  readonly pinned?: string;
  readonly retained?: readonly { kid: string; publicKeyBase64Url: string }[];
}

const PINNED_CURRENT: Designation = { pinned: toBase64Url(CURRENT.publicKey) };
const RETAINED_BOTH: Designation = {
  retained: [CURRENT, RETIRED].map((one) => ({ kid: toHex(one.kid), publicKeyBase64Url: toBase64Url(one.publicKey) })),
};
const RETAINED_CURRENT_ONLY: Designation = {
  retained: [{ kid: toHex(CURRENT.kid), publicKeyBase64Url: toBase64Url(CURRENT.publicKey) }],
};

function optionsFor(read: Designation): { publicKey?: Uint8Array; resolveKey?: (kid: Uint8Array) => Uint8Array | undefined } {
  if (read.pinned !== undefined) return { publicKey: bytes(read.pinned) };
  if (read.retained !== undefined) {
    const byKid = new Map(read.retained.map((one) => [one.kid, one.publicKeyBase64Url]));
    return {
      resolveKey: (kid) => {
        const found = byKid.get(toHex(kid));
        return found === undefined ? undefined : bytes(found);
      },
    };
  }
  return {};
}

/** The manifest a writer would build for one pack and one removal, with both computed values folded in. */
function manifestFor(pack: PackPair, removed: readonly string[], over: Partial<RedactionManifest> = {}): RedactionManifest {
  return {
    v: 1,
    at: STATED_AT,
    pack: redactionPackDigest(pack.bytes),
    removed,
    reduced: redactionSurvivorDigest(pack.manifest.chain.anchor, survivors(pack.manifest, removed)),
    states: STATES,
    ...over,
  };
}

/** The honest seal, through the shipped writer. */
function sealed(manifest: RedactionManifest, key: SigningKey = CURRENT): Uint8Array {
  return signRedaction(manifest, key);
}

/**
 * A manifest with one position moved, sealed through the published pieces rather than `signRedaction`, which
 * would refuse to sign it. The header names the key that makes the signature, so the document is authentic and
 * the only fault is the position its `edited` field names.
 */
function mutant(pack: PackPair, removed: readonly string[], edit: (root: Map<unknown, unknown>) => void, key: SigningKey = CURRENT): Uint8Array {
  const root = asMap(encodeRedactionManifest(manifestFor(pack, removed)));
  edit(root);
  return underType(REDACTION_CONTENT_TYPE, encodeCanonical(root), key);
}

/** A document whose header names one key and whose signature was made by another. */
function sealSplit(headerKid: SigningKey, signer: SigningKey, payloadBytes: Uint8Array): Uint8Array {
  const header = encodeRedactionProtectedHeader(headerKid.kid);
  return sealRedaction(header, payloadBytes, ed25519.sign(redactionSigStructure(header, payloadBytes), signer.privateKey));
}

/** The whole document under another content type, which is how five containers share one key. */
function underType(contentType: string, payloadBytes: Uint8Array, key: SigningKey = CURRENT): Uint8Array {
  const header = encodeRedactionProtectedHeader(key.kid, contentType);
  return sealRedaction(header, payloadBytes, ed25519.sign(redactionSigStructure(header, payloadBytes), key.privateKey));
}

/** A document under a header of the caller's choosing, signed by the key that header names. */
function sealedUnder(header: Uint8Array, payloadBytes: Uint8Array, key: SigningKey = CURRENT): Uint8Array {
  return sealRedaction(header, payloadBytes, ed25519.sign(redactionSigStructure(header, payloadBytes), key.privateKey));
}

/** The honest manifest with the unprotected map filled, which is the one map a signer fills at will. */
function sealedUnprotected(manifest: RedactionManifest): Uint8Array {
  const payloadBytes = encodeRedactionManifest(manifest);
  const header = encodeRedactionProtectedHeader(CURRENT.kid);
  return sealRedaction(
    header,
    payloadBytes,
    ed25519.sign(redactionSigStructure(header, payloadBytes), CURRENT.privateKey),
    new Map<unknown, unknown>([['note', 'outside the signature']]),
  );
}

function asMap(payload: Uint8Array): Map<unknown, unknown> {
  const decoded = decodeCanonical(payload);
  if (!(decoded instanceof Map)) throw new Error('a manifest this file encoded did not come back as a map');
  return decoded;
}

/** The three declared labels with a fourth on, spelled out of the parts the format names. */
function headerWithFourthLabel(): Uint8Array {
  return encodeCanonical(
    new Map<number, unknown>([
      [LABEL_ALG, -8],
      [LABEL_TYP, REDACTION_CONTENT_TYPE],
      [LABEL_KID, CURRENT.kid],
      [5, 'what'],
    ]),
  );
}

/** The declared labels with a `kid` of the caller's width, which is a shape fault and not an unknown label. */
function headerWithKidWidth(width: number): Uint8Array {
  return encodeCanonical(
    new Map<number, unknown>([
      [LABEL_ALG, -8],
      [LABEL_TYP, REDACTION_CONTENT_TYPE],
      [LABEL_KID, CURRENT.kid.slice(0, width)],
    ]),
  );
}

/** The same header with an `alg` of the caller's choosing, which is the one label the writers here fix. */
function algHeader(alg: number): Uint8Array {
  return encodeCanonical(
    new Map<number, unknown>([
      [LABEL_ALG, alg],
      [LABEL_TYP, REDACTION_CONTENT_TYPE],
      [LABEL_KID, CURRENT.kid],
    ]),
  );
}

interface Case {
  readonly name: string;
  readonly note: string;
  /** The pack handed to the reader, or `null` for the row that states a removal with no pack in hand. */
  readonly pack: PackPair | null;
  readonly bytes: Uint8Array;
  readonly read: Designation;
  /** What `verifyRedaction` answers: `verify-ok`, or the code it throws. */
  readonly verdict: string;
  /** What `decodeRedaction` answers for the same bytes with no key and no pack. */
  readonly structural: string;
  /** The survivors in chain order, published on every row the reader accepts. */
  readonly survivors?: readonly string[];
  /** The head the fold over those survivors reaches, and the pack's own head beside it. */
  readonly reducedHex?: string;
  readonly originalHeadHex?: string;
  /** The id a refusal names, where the code reports by naming one. */
  readonly item?: string;
  /** The one position a fault case moved. */
  readonly edited?: string;
}

const CASES: readonly Case[] = [
  {
    name: 'removed-middle-record',
    note: "One record lifted out of a three-record pack, stated by the id the pack carries for it, and checked against the pack whose whole bytes the digest designates. This is the state a handover arrives in, and the four things a reader is entitled to say about it: the statement is sealed by a key it designates, the pack is the pack it names by a digest of that pack's own bytes, the name in the removal list is a record of that pack, and the chain over the two survivors reaches a head that is not the pack's head.",
    pack: HONEST,
    bytes: sealed(manifestFor(HONEST, ['receipt-1'])),
    read: PINNED_CURRENT,
    verdict: 'verify-ok',
    structural: 'verify-ok',
    survivors: ['receipt-0', 'receipt-2'],
  },
  {
    name: 'removed-first-record',
    note: "The first record of the run removed. Its successor is relinked onto the pack's anchor, so no surviving record keeps the digest the pack signs for it, which is the case that shows the reduced chain is a chain of its own and not a suffix of the original one.",
    pack: HONEST,
    bytes: sealed(manifestFor(HONEST, ['receipt-0'])),
    read: PINNED_CURRENT,
    verdict: 'verify-ok',
    structural: 'verify-ok',
    survivors: ['receipt-1', 'receipt-2'],
  },
  {
    name: 'removed-last-record',
    note: "The last record removed, which leaves the earlier digests exactly as the pack has them and makes the digest the pack already signs for the record that is now last the reduced head. The pack's own head is one term further on and is not this value, and both numbers are published so that a port cannot report one where the other belongs.",
    pack: HONEST,
    bytes: sealed(manifestFor(HONEST, ['receipt-2'])),
    read: PINNED_CURRENT,
    verdict: 'verify-ok',
    structural: 'verify-ok',
    survivors: ['receipt-0', 'receipt-1'],
  },
  {
    name: 'removed-two-records-one-sentence',
    note: "Two records removed and one sentence stating it. The removal list is a set of the pack's ids and nothing else, so the survivor sequence is one shorter than the run the pack walks and the fold has one term fewer, and the record that remains is relinked from the anchor rather than from either predecessor it was chained with.",
    pack: HONEST,
    bytes: sealed(manifestFor(HONEST, ['receipt-0', 'receipt-2'], { states: STATES_SHORT })),
    read: PINNED_CURRENT,
    verdict: 'verify-ok',
    structural: 'verify-ok',
    survivors: ['receipt-1'],
  },
  {
    name: 'array-order-bears-nothing',
    note: "The same removal stated about the pack whose items arrived in the reverse of the order the chain puts them in. The survivors are read by following the `prev` links, so the reduced head this row publishes is the same number the first row publishes, which is the rule that keeps a retirement or a compaction from having to rewrite either document.",
    pack: REVERSED,
    bytes: sealed(manifestFor(REVERSED, ['receipt-1'])),
    read: PINNED_CURRENT,
    verdict: 'verify-ok',
    structural: 'verify-ok',
    survivors: ['receipt-0', 'receipt-2'],
  },
  {
    name: 'removed-from-a-pack-behind-a-seam',
    note: "A removal from a run that began after a retirement, chained from the seam the trim record carried rather than from thirty-two zero bytes. The reduced chain starts from the pack's own anchor, so this row is where a reader that assumed zero bytes would be caught: the survivors are the same two records as the first row's and the head it reaches is not.",
    pack: SEAM,
    bytes: sealed(manifestFor(SEAM, ['receipt-1'])),
    read: PINNED_CURRENT,
    verdict: 'verify-ok',
    structural: 'verify-ok',
    survivors: ['receipt-0', 'receipt-2'],
  },
  {
    name: 'removed-across-a-key-rotation',
    note: "A removal from a pack whose span crosses the epoch a deployment retired inside the window. The redaction is sealed by the current key, the envelope and every receipt answer to the key their own header names, and the caller that hands the reader the epochs it retained reads the pair whole, which is the same rule that makes a pack of that span readable at all.",
    pack: ROTATED,
    bytes: sealed(manifestFor(ROTATED, ['receipt-2'])),
    read: RETAINED_BOTH,
    verdict: 'verify-ok',
    structural: 'verify-ok',
    survivors: ['receipt-0', 'receipt-1'],
  },
  {
    name: 'removed-from-a-two-record-pack',
    note: "One record removed from the shortest run that leaves something to walk: a pack of two and a survivor of one. The first and the last record of a one-record chain are the same record, and the reduced head is that record's digest relinked from the anchor, which is a whole chain rather than a degenerate one.",
    pack: SHORTENED,
    bytes: sealed(manifestFor(SHORTENED, ['receipt-0'])),
    read: PINNED_CURRENT,
    verdict: 'verify-ok',
    structural: 'verify-ok',
    survivors: ['receipt-2'],
  },
  {
    name: 'stated-the-second-the-reads-began',
    note: "A redaction stamped at the pack's own assembly instant rather than after it. The bound the format states is that a redaction is never earlier than the pack it removes from, and equality is not earlier, so this is accepted: a removal stated inside the same second the reads began in is a fact about a clock this format does not own.",
    pack: HONEST,
    bytes: sealed(manifestFor(HONEST, ['receipt-1'], { at: HONEST.manifest.at })),
    read: PINNED_CURRENT,
    verdict: 'verify-ok',
    structural: 'verify-ok',
    survivors: ['receipt-0', 'receipt-2'],
  },
  {
    name: 'unprotected-map-carries-a-parameter',
    note: "The honest document with the unprotected map filled instead of left empty. That map is the one place in this container a signer fills at will: it sits outside the signature, so nothing written in it travels as a claim about the removal, and enforcing that it is empty would buy strictness with no security content behind it.",
    pack: HONEST,
    bytes: sealedUnprotected(manifestFor(HONEST, ['receipt-1'])),
    read: PINNED_CURRENT,
    verdict: 'verify-ok',
    structural: 'verify-ok',
    survivors: ['receipt-0', 'receipt-2'],
  },
  {
    name: 'no-pack-handed',
    note: "A whole redaction and a reader that was handed nothing else. The document is well-formed and its seal holds, and none of that can be checked against a pack that is not there, so the answer is a refusal naming what the reader lacked rather than a verdict about the removal. This is the availability rule stated on the side that has to be stated: a reader with the pack and not the redaction still verifies the pack, and the pack suite is where that reader's verdicts are published.",
    pack: null,
    bytes: sealed(manifestFor(HONEST, ['receipt-1'])),
    read: PINNED_CURRENT,
    verdict: 'REDACTION_PACK_UNAVAILABLE',
    structural: 'verify-ok',
  },
  {
    name: 'redaction-naming-another-pack',
    note: "The removal stated about the honest pack, read against the pack behind a seam. Neither document is at fault, and the reader's own hash of the bytes in its hand is what says so, which is why this is a code of its own rather than a chain disagreement: nothing about either document is wrong, and the pair cannot be read together.",
    pack: SEAM,
    bytes: sealed(manifestFor(HONEST, ['receipt-1'])),
    read: PINNED_CURRENT,
    verdict: 'REDACTION_PACK_MISMATCH',
    structural: 'verify-ok',
  },
  {
    name: 'honest-redaction-read-against-the-wrong-pack',
    note: "The other direction of the same pair: a reader holding the pack the first row speaks about, handed a redaction written about the two-record pack. The designation is recomputed from the pack before the pack is opened at all, so this is refused without walking a run the statement has nothing to say about.",
    pack: HONEST,
    bytes: sealed(manifestFor(SHORTENED, ['receipt-0'])),
    read: PINNED_CURRENT,
    verdict: 'REDACTION_PACK_MISMATCH',
    structural: 'verify-ok',
  },
  {
    name: 'redaction-naming-a-pack-and-not-its-envelope',
    note: "One honest pack manifest travelling in two envelopes: the one the pack suite publishes, and a second sealed by another deployment's key over exactly the same manifest bytes. The redaction names the first by a digest of its whole bytes, so the second is refused, which is the half a digest of the manifest alone would have missed: a re-signed pack is a different pack to a statement about removals, and the seal is part of what the removal was stated about.",
    pack: RESEALED,
    bytes: sealed(manifestFor(HONEST, ['receipt-1'])),
    read: PINNED_CURRENT,
    verdict: 'REDACTION_PACK_MISMATCH',
    structural: 'verify-ok',
  },
  {
    name: 'redaction-predating-the-pack',
    note: "A removal stated at an instant before the pack it removes from began to be assembled. Both stamps are inside signatures, one over each document, so this is two documents that cannot both be true rather than one that contradicts itself, and it answers a different code from the malformed-manifest family for that reason.",
    pack: HONEST,
    bytes: mutant(HONEST, ['receipt-1'], (root) => root.set('at', HONEST.manifest.at - 1)),
    read: PINNED_CURRENT,
    verdict: 'REDACTION_PACK_DISAGREES',
    structural: 'verify-ok',
    edited: 'at, to one second before the pack states its reads began',
  },
  {
    name: 'naming-an-id-the-pack-does-not-carry',
    note: "A removal list that names a record the designated pack never contained. The id is the pack's own name for a receipt and the reader holds the pack, so this is not a lookup miss: the statement is about a receipt that run does not have, and the refusal says which id.",
    pack: HONEST,
    bytes: mutant(HONEST, ['receipt-9'], () => undefined),
    read: PINNED_CURRENT,
    verdict: 'REDACTION_ITEM_ABSENT',
    structural: 'verify-ok',
    item: 'receipt-9',
    edited: 'the removed list, naming a record this pack does not carry',
  },
  {
    name: 'one-record-named-twice',
    note: "Two entries of the removal list answering to one id, which is a count of removals that disagrees with the set of removals stated. The survivor sequence is the same either way and nothing about the chain reports the collision, so the refusal is the only place it can be told.",
    pack: HONEST,
    bytes: mutant(HONEST, ['receipt-1'], (root) => root.set('removed', ['receipt-1', 'receipt-1'])),
    read: PINNED_CURRENT,
    verdict: 'REDACTION_DUPLICATE_ID',
    structural: 'REDACTION_DUPLICATE_ID',
    item: 'receipt-1',
    edited: 'the removed list, with one entry duplicated',
  },
  {
    name: 'removing-every-record-of-the-pack',
    note: "A removal that leaves nothing to walk, with the value a fold over no records returns stated as the chain head: the pack's own anchor, which is a digest that reads as a chain claim while attesting no record. Pack v1 refuses an empty items array for the same reason, and a redaction that empties a pack belongs to the artifact that states windows rather than to this one.",
    pack: SINGLE,
    bytes: sealed({
      v: 1,
      at: STATED_AT,
      pack: redactionPackDigest(SINGLE.bytes),
      removed: ['receipt-0'],
      reduced: SINGLE.manifest.chain.anchor,
      states: 'the only record this pack carried is no longer held',
    }),
    read: PINNED_CURRENT,
    verdict: 'REDACTION_SURVIVORS_EMPTY',
    structural: 'verify-ok',
    edited: 'the survivor sequence, emptied',
  },
  {
    name: 'claiming-the-packs-own-head-still-holds',
    note: "A real removal stated beside the pack's own signed head rather than the digest of a shorter chain. The fold over the survivors returns the pack's head exactly when nothing is dropped, so this value is reachable only by a writer that removed nothing or by one that is wrong about what it removed, and the recomputation refuses it. This is the claim the container exists to make unproducible.",
    pack: HONEST,
    bytes: mutant(HONEST, ['receipt-1'], (root) => root.set('reduced', HONEST.manifest.chain.head)),
    read: PINNED_CURRENT,
    verdict: 'REDACTION_SURVIVOR_CHAIN_MISMATCH',
    structural: 'verify-ok',
    edited: 'reduced, to the head the pack signs for its own run',
  },
  {
    name: 'removing-more-than-the-list-names',
    note: "Two records lifted out of the pack and one named in the removal list, with the chain the shorter survivor sequence hashes to stated honestly. Nothing about the manifest is malformed and no membership check can see the second removal: what refuses it is that the reader's survivor set is the larger one and its fold a different digest, which is the half of the promise that nothing else is removed.",
    pack: HONEST,
    bytes: mutant(HONEST, ['receipt-1'], (root) =>
      root.set('reduced', redactionSurvivorDigest(HONEST.manifest.chain.anchor, [HONEST.manifest.items[0]!])),
    ),
    read: PINNED_CURRENT,
    verdict: 'REDACTION_SURVIVOR_CHAIN_MISMATCH',
    structural: 'verify-ok',
    edited: 'the pack, one record shorter than the removal list states',
  },
  {
    name: 'survivor-chain-started-at-zero-bytes',
    note: "A redaction of the pack behind a seam whose chain was folded from thirty-two zero bytes instead of the pack's own anchor. The survivors and the terms hashed are the honest ones, so this is the reading a port reaches by assuming a run begins at nothing, and the disagreement names it.",
    pack: SEAM,
    bytes: mutant(SEAM, ['receipt-1'], (root) =>
      root.set('reduced', redactionSurvivorDigest(new Uint8Array(32), survivors(SEAM.manifest, ['receipt-1']))),
    ),
    read: PINNED_CURRENT,
    verdict: 'REDACTION_SURVIVOR_CHAIN_MISMATCH',
    structural: 'verify-ok',
    edited: "reduced, folded from thirty-two zero bytes rather than from the pack's anchor",
  },
  {
    name: 'survivor-chain-keeping-each-predecessor',
    note: "The other construction a reimplementer reaches for: fold over the survivors using the predecessor each record already carries. That is a chain with a hole in it rather than a chain over the survivors, and it closes at nothing, so the digest it lands on is one the recomputation cannot reach.",
    pack: HONEST,
    bytes: mutant(HONEST, ['receipt-1'], (root) => root.set('reduced', packRecordDigest(HONEST.manifest.items[2]!))),
    read: PINNED_CURRENT,
    verdict: 'REDACTION_SURVIVOR_CHAIN_MISMATCH',
    structural: 'verify-ok',
    edited: "reduced, taken from the last survivor's own predecessor rather than relinked",
  },
  {
    name: 'pack-whose-receipt-byte-moved-after-sealing',
    note: "One byte of the pack's first receipt flipped after the pack was sealed, and a redaction written honestly about those bytes. The designation matches, because the digest is of the pack the reader holds, and what refuses is the pack's own seal: a pack's sentence names a pack, and an operator reading this code is told the evidence moved rather than that the claim about it is false.",
    pack: MOVED,
    bytes: sealed(manifestFor(MOVED, ['receipt-1'])),
    read: PINNED_CURRENT,
    verdict: 'INVALID_SIGNATURE',
    structural: 'verify-ok',
    edited: "the thirteenth byte of the pack's items[0].receipt, under the pack signature made for it",
  },
  {
    name: 'pack-with-a-record-lifted-out-of-its-middle',
    note: "A redaction stated about a pack that is itself a lie: the middle record was taken out of a signed run and nothing else touched, so the successor still names the record that is gone. The walk stops at the hole and the redaction inherits that answer, which is the pack's own code and the pack's own sentence, because the pair cannot be read when one half of it does not chain.",
    pack: BROKEN,
    bytes: sealed(manifestFor(BROKEN, ['receipt-1'])),
    read: PINNED_CURRENT,
    verdict: 'PACK_CHAIN_BROKEN',
    structural: 'verify-ok',
    edited: "the pack's items, with the middle record removed and the head left as it was signed",
  },
  {
    name: 'rotation-read-with-one-pinned-key',
    note: "Those same two documents, read by a caller that retained only the current epoch. The redaction's envelope verifies, the pack's envelope verifies, and the first receipt inside the pack does not, so the refusal names the item and the answer its own receipt gave: neither document is at fault and the caller is holding too few keys.",
    pack: ROTATED,
    bytes: sealed(manifestFor(ROTATED, ['receipt-2'])),
    read: PINNED_CURRENT,
    verdict: 'PACK_RECEIPT_INVALID',
    structural: 'verify-ok',
    item: 'receipt-0',
  },
  {
    name: 'rotation-read-without-the-retired-epoch',
    note: "The same pair and a resolver that answers for the current kid only. This is the inner refusal the redaction reader does not rename: nothing about either document contradicts itself, and the action is to retain the key the deployment's manifest names and read the pair again.",
    pack: ROTATED,
    bytes: sealed(manifestFor(ROTATED, ['receipt-2'])),
    read: RETAINED_CURRENT_ONLY,
    verdict: 'PACK_UNKNOWN_KEY',
    structural: 'verify-ok',
    item: 'receipt-0',
  },
  {
    name: 'sealed-under-another-deployment-key',
    note: "The honest manifest sealed by a key this reader was not given, under that key's own kid. The bytes are a whole redaction and their signature holds against the header that names them; the refusal is that this caller does not designate that key, which is a different finding from tampering and the reason the two are separate codes.",
    pack: HONEST,
    bytes: sealed(manifestFor(HONEST, ['receipt-1']), OTHER),
    read: PINNED_CURRENT,
    verdict: 'REDACTION_KID_MISMATCH',
    structural: 'verify-ok',
  },
  {
    name: 'header-naming-one-key-signed-by-another',
    note: 'A protected header carrying the designated kid and a signature the designated key did not make, which is the shape that separates a wrong key from an edited document. The kid check passes and the signature is what refuses, so the report is about tampering.',
    pack: HONEST,
    bytes: sealSplit(CURRENT, OTHER, encodeRedactionManifest(manifestFor(HONEST, ['receipt-1']))),
    read: PINNED_CURRENT,
    verdict: 'INVALID_SIGNATURE',
    structural: 'verify-ok',
    edited: 'the private half that made the signature, with the header naming the other key',
  },
  {
    name: 'no-designation-at-all',
    note: 'The honest document, the pack it names, and a call that handed the reader neither a pinned key nor a resolver. The fault is in the call, so it is answered before a byte is read: a document question about bytes nobody has been given a key to check would send an operator to the evidence rather than to their own configuration.',
    pack: HONEST,
    bytes: sealed(manifestFor(HONEST, ['receipt-1'])),
    read: {},
    verdict: 'REDACTION_UNKNOWN_KEY',
    structural: 'verify-ok',
  },
  {
    name: 'protected-content-type-of-a-pack',
    note: "The redaction manifest inside an envelope whose `typ` is the pack's. Both containers are `COSE_Sign1` over four elements signed by this same key and each verifies cleanly under it, so the mistake a content type exists to prevent is exactly this one, and it is refused at the header before any resolver is consulted.",
    pack: HONEST,
    bytes: underType(PACK_CONTENT_TYPE, encodeRedactionManifest(manifestFor(HONEST, ['receipt-1']))),
    read: PINNED_CURRENT,
    verdict: 'REDACTION_BAD_HEADER',
    structural: 'REDACTION_BAD_HEADER',
    edited: 'typ, from ashaveri/redaction to ashaveri/pack',
  },
  {
    name: 'protected-content-type-of-a-receipt',
    note: 'That same pair under the receipt type, which is the second of the five documents one deployment key seals. A reader that answered with the document it was hoping for would be reporting the wrong claim under a signature that held.',
    pack: HONEST,
    bytes: underType('ashaveri/receipt', encodeRedactionManifest(manifestFor(HONEST, ['receipt-1']))),
    read: PINNED_CURRENT,
    verdict: 'REDACTION_BAD_HEADER',
    structural: 'REDACTION_BAD_HEADER',
    edited: 'typ, from ashaveri/redaction to ashaveri/receipt',
  },
  {
    name: 'protected-header-carries-a-fourth-label',
    note: 'A protected header carrying a label this format does not declare, beside the three it does, and signed over as always. The header closes where a reader might be tempted to be open, because its bytes are hashed into the `Sig_structure`: a fourth label is an authenticated parameter and a reader that took the three it knows would hand on a document other than the one the deployment signed.',
    pack: HONEST,
    bytes: sealedUnder(headerWithFourthLabel(), encodeRedactionManifest(manifestFor(HONEST, ['receipt-1']))),
    read: PINNED_CURRENT,
    verdict: 'REDACTION_BAD_HEADER',
    structural: 'REDACTION_BAD_HEADER',
    edited: 'a fourth protected label, 5, carrying a tstr',
  },
  {
    name: 'protected-kid-of-another-width',
    note: 'A `kid` of thirty-one bytes, a declared label holding the wrong shape. The width is what makes the field an id at all: it is sha256 of a public key, and a reader that took a shorter one would be resolving a key from bytes nothing hashes to.',
    pack: HONEST,
    bytes: sealedUnder(headerWithKidWidth(31), encodeRedactionManifest(manifestFor(HONEST, ['receipt-1']))),
    read: PINNED_CURRENT,
    verdict: 'REDACTION_BAD_HEADER',
    structural: 'REDACTION_BAD_HEADER',
    edited: 'the protected kid, one byte short of the digest it is meant to be',
  },
  {
    name: 'protected-alg-naming-another-suite',
    note: 'An `alg` of -7 where this container signs with EdDSA. The header refusal and this one are separate codes on purpose: one says the map is not the map this format declares, the other says the map is right and names a suite nothing here produces.',
    pack: HONEST,
    bytes: sealedUnder(algHeader(-7), encodeRedactionManifest(manifestFor(HONEST, ['receipt-1']))),
    read: PINNED_CURRENT,
    verdict: 'UNSUPPORTED_ALG',
    structural: 'UNSUPPORTED_ALG',
    edited: 'alg, from -8 to -7',
  },
  {
    name: 'manifest-version-two',
    note: 'A manifest declaring a redaction version no format has used. The answer is about the reach of this reader rather than about the bytes being broken, and it arrives with no key and no pack in hand because a version is a fact of the document.',
    pack: HONEST,
    bytes: mutant(HONEST, ['receipt-1'], (root) => root.set('v', 2)),
    read: PINNED_CURRENT,
    verdict: 'REDACTION_UNSUPPORTED_VERSION',
    structural: 'REDACTION_UNSUPPORTED_VERSION',
    edited: 'v, from 1 to 2',
  },
  {
    name: 'manifest-member-unknown-to-version-one',
    note: "A manifest carrying a member this version names nowhere, and the member is the one an implementer might reach for in order to state the original chain here. The map is closed, so the document is malformed rather than read with the unexpected member dropped: a member a reader ignores is a claim inside the signature that nobody looked at, and a member carrying the pack's head would be a second statement of a number the pack already signs.",
    pack: HONEST,
    bytes: mutant(HONEST, ['receipt-1'], (root) => root.set('head', HONEST.manifest.chain.head)),
    read: PINNED_CURRENT,
    verdict: 'REDACTION_BAD_MANIFEST',
    structural: 'REDACTION_BAD_MANIFEST',
    edited: "a member named 'head' added to the manifest",
  },
  {
    name: 'no-removal-stated-at-all',
    note: "A redaction whose removal list is empty, carrying the pack's own head as the chain claim. A document that removes nothing exists to state that a signed head still holds, and a container in which that sentence and a forgery look alike is not one; the list is non-empty and the refusal is structural, answered with no key and no pack in hand.",
    pack: HONEST,
    bytes: mutant(HONEST, ['receipt-1'], (root) => {
      root.set('removed', []);
      root.set('reduced', HONEST.manifest.chain.head);
    }),
    read: PINNED_CURRENT,
    verdict: 'REDACTION_BAD_MANIFEST',
    structural: 'REDACTION_BAD_MANIFEST',
    edited: "the removed list, emptied, and reduced, set to the pack's head",
  },
  {
    name: 'stamp-spelled-as-a-float',
    note: "The assembly stamp written as the half-precision float of the integer it stands for rather than as an integer. A float is a different major type and the only reader that can ever tell them apart is one reading the bytes, because a decoder that hands both over as one number leaves a check placed afterwards nothing to distinguish. The refusal is the format's integer rule, and it arrives where the bytes are decoded.",
    pack: HONEST,
    bytes: mutant(HONEST, ['receipt-1'], (root) => root.set('at', STATED_AT + 0.5)),
    read: PINNED_CURRENT,
    verdict: 'REDACTION_BAD_MANIFEST',
    structural: 'REDACTION_BAD_MANIFEST',
    edited: 'at, written as the float of a whole number',
  },
  {
    name: 'sentence-with-nothing-in-it',
    note: "An empty `states`. The sentence is the writer's own and a reader checks nothing about its content, and the one thing it does check is that the position is filled: an empty statement is the silence this member exists to refuse.",
    pack: HONEST,
    bytes: mutant(HONEST, ['receipt-1'], (root) => root.set('states', '')),
    read: PINNED_CURRENT,
    verdict: 'REDACTION_BAD_MANIFEST',
    structural: 'REDACTION_BAD_MANIFEST',
    edited: 'states, emptied',
  },
  {
    name: 'designation-of-another-width',
    note: 'A `pack` member of sixteen bytes, which is a width no digest this estate produces has. The designation is what a reader recomputes and compares, so a shorter one is not a truncated name to be padded out but a document that cannot be about any pack.',
    pack: HONEST,
    bytes: mutant(HONEST, ['receipt-1'], (root) => root.set('pack', CURRENT.kid.slice(0, 16))),
    read: PINNED_CURRENT,
    verdict: 'REDACTION_BAD_MANIFEST',
    structural: 'REDACTION_BAD_MANIFEST',
    edited: 'pack, to sixteen bytes where the format declares thirty-two',
  },
  {
    name: 'envelope-without-its-tag',
    note: 'The four elements of a `COSE_Sign1` with the tag around them missing, which is a shape a reader cannot recover by being tolerant: tag 18 is what says these bytes are an envelope at all.',
    pack: HONEST,
    bytes: encodeCanonical(elementsOf(sealed(manifestFor(HONEST, ['receipt-1'])))),
    read: PINNED_CURRENT,
    verdict: 'NOT_COSE_SIGN1',
    structural: 'NOT_COSE_SIGN1',
    edited: 'the CBOR tag 18 around the four envelope elements',
  },
  {
    name: 'envelope-whose-signature-is-not-64-bytes',
    note: 'The honest envelope with one byte taken off the end of its signature, which is a shape refusal rather than a cryptography failure: a reader that reached the verification step with a truncated signature would be reporting a wrong answer about the wrong bytes.',
    pack: HONEST,
    bytes: (() => {
      const [header, , payload, signature] = elementsOf(sealed(manifestFor(HONEST, ['receipt-1'])));
      return sealRedaction(header as Uint8Array, payload as Uint8Array, (signature as Uint8Array).slice(0, 63));
    })(),
    read: PINNED_CURRENT,
    verdict: 'NOT_COSE_SIGN1',
    structural: 'NOT_COSE_SIGN1',
    edited: 'the last byte of the signature',
  },
  {
    name: 'document-truncated-mid-envelope',
    note: 'The first twenty-four bytes of a whole redaction, so nothing decodes and no header, key or manifest is ever reached.',
    pack: HONEST,
    bytes: sealed(manifestFor(HONEST, ['receipt-1'])).slice(0, 24),
    read: PINNED_CURRENT,
    verdict: 'REDACTION_MALFORMED_CBOR',
    structural: 'REDACTION_MALFORMED_CBOR',
  },
];

/** The options the row's designation builds, plus the pack it hands beside them. */
function readOptionsFor(one: Case): {
  publicKey?: Uint8Array;
  resolveKey?: (kid: Uint8Array) => Uint8Array | undefined;
  packBytes: Uint8Array;
} {
  return {
    ...optionsFor(one.read),
    packBytes: one.pack === null ? (undefined as unknown as Uint8Array) : one.pack.bytes,
  };
}

/** What `verifyRedaction` answers, which is the verdict a conforming reader owes the row. */
function verdictOf(one: Case): string {
  let read: VerifiedRedaction | null = null;
  try {
    read = verifyRedaction(one.bytes, readOptionsFor(one));
  } catch (err) {
    if (err instanceof ReceiptError) {
      if (one.item !== undefined && !err.message.includes(one.item)) {
        throw new Error(`${one.name}: ${err.code} did not name the item this file says it names (${one.item})`);
      }
      return err.code;
    }
    throw new Error(`${one.name}: the reader raised something with no code (${String(err)})`);
  }
  // An accepted row states more than a word, and each of those is asked of the same reading: the survivors in
  // the order the pack's links reached them, the head the fold over them reaches, and the pack's own head.
  if (read === null) throw new Error(`${one.name}: the reader returned nothing and stated no refusal`);
  const reached = read.outcome.survivors.map((each) => each.item.id);
  if (one.survivors === undefined) throw new Error(`${one.name}: an accepted row states no survivor run to compare`);
  if (reached.join(' ') !== one.survivors.join(' ')) {
    throw new Error(`${one.name}: the survivors are ${reached.join(', ')}, which this file says are ${one.survivors.join(', ')}`);
  }
  if (one.reducedHex === undefined || one.originalHeadHex === undefined) {
    throw new Error(`${one.name}: an accepted row states no chain heads to compare`);
  }
  if (toHex(read.outcome.reduced) !== one.reducedHex) {
    throw new Error(`${one.name}: the reduced head is ${toHex(read.outcome.reduced)}, not ${one.reducedHex}`);
  }
  if (toHex(read.outcome.originalHead) !== one.originalHeadHex) {
    throw new Error(`${one.name}: the pack head read back is ${toHex(read.outcome.originalHead)}, not ${one.originalHeadHex}`);
  }
  // The pair of numbers has to stay apart, which is the sentence the whole container exists to keep true.
  if (one.reducedHex === one.originalHeadHex) {
    throw new Error(`${one.name}: an accepted row states one head for the pack and for the survivors`);
  }
  return 'verify-ok';
}

/** What `decodeRedaction` answers for the same bytes, with no key and no pack. */
function structuralOf(one: Case): string {
  try {
    decodeRedaction(one.bytes);
    return 'verify-ok';
  } catch (err) {
    if (err instanceof ReceiptError) return err.code;
    throw new Error(`${one.name}: the structural reader raised something with no code (${String(err)})`);
  }
}

/**
 * Fills the three chain columns of an accepted row from the reader's own answer. The values are witnessed rather
 * than asserted, and `verdictOf` then asks the same reading again, so a row cannot state a number the reader
 * does not reach.
 */
function withChain(row: Case): Case {
  if (row.verdict !== 'verify-ok') return row;
  const read = verifyRedaction(row.bytes, readOptionsFor(row));
  return {
    ...row,
    survivors: read.outcome.survivors.map((one) => one.item.id),
    reducedHex: toHex(read.outcome.reduced),
    originalHeadHex: toHex(read.outcome.originalHead),
  };
}

function published(one: Case): Record<string, unknown> {
  return {
    name: one.name,
    note: one.note,
    documentBase64Url: toBase64Url(one.bytes),
    documentByteLength: one.bytes.length,
    ...(one.pack === null
      ? {}
      : {
          packOf: one.pack.name,
          ...(one.pack.edited === undefined ? {} : { packEdited: one.pack.edited }),
          packBase64Url: toBase64Url(one.pack.bytes),
          packByteLength: one.pack.bytes.length,
        }),
    read: one.read,
    verdict: one.verdict,
    structural: one.structural,
    ...(one.survivors === undefined ? {} : { survivors: one.survivors }),
    ...(one.reducedHex === undefined ? {} : { reducedHex: one.reducedHex }),
    ...(one.originalHeadHex === undefined ? {} : { originalHeadHex: one.originalHeadHex }),
    ...(one.item === undefined ? {} : { item: one.item }),
    ...(one.edited === undefined ? {} : { edited: one.edited }),
  };
}

/**
 * The pack's own run, in chain order, with what the row names for removal beside each record. A reader needs the
 * dropped record too: without it the relinked predecessor of a survivor cannot be told from one the reader was
 * never given.
 */
function runTable(pack: PackPair, removed: readonly string[]): Record<string, unknown>[] {
  const dropped = new Set(removed);
  return walkedChain(pack.manifest).map((one, index) => ({
    position: index,
    id: one.id,
    iat: one.iat,
    prevHex: toHex(one.prev),
    digestHex: toHex(packRecordDigest(one)),
    namedForRemoval: dropped.has(one.id),
  }));
}

/**
 * The survivor chain of the first row, field by field. A reader recomputes each of these from the pack's own
 * bytes: the predecessor the pack's record carries, the predecessor the fold used instead, and the digest that
 * came out, which is the redaction's own reading of the framing `chain-v1.json` publishes for a store file. The
 * two predecessor columns are equal for the first record of a run and differ for every later one, which is the
 * construction stated as data rather than as a sentence.
 */
function survivorTable(pack: PackPair, removed: readonly string[]): Record<string, unknown>[] {
  const dropped = new Set(removed);
  const anchor = pack.manifest.chain.anchor;
  const chain = survivors(pack.manifest, removed);
  const digests = redactionSurvivorChain(anchor, chain);
  return chain.map((one, index) => ({
    position: index,
    id: one.id,
    iat: one.iat,
    prevInPackHex: toHex(one.prev),
    relinkedFromHex: toHex(index === 0 ? anchor : digests[index - 1] ?? anchor),
    digestHex: toHex(digests[index] ?? anchor),
    namedForRemoval: dropped.has(one.id),
  }));
}

/** The pack reader's own answer to a redaction, witnessed rather than asserted. */
function packRefusalOf(documentBytes: Uint8Array): string {
  try {
    verifyPack(documentBytes, { publicKey: CURRENT.publicKey });
    return 'verify-ok';
  } catch (err) {
    if (err instanceof ReceiptError) return err.code;
    throw new Error(`the pack reader raised something with no code: ${String(err)}`);
  }
}

function main(): void {
  // The keys this suite signs with have to be the keys the pack suite publishes, or these documents would be
  // redactions of nobody's evidence: the same seed derivation in both files is checked rather than assumed.
  for (const one of KEY_MATERIAL) {
    if (!publishedKids.has(toHex(one.key.kid))) {
      throw new Error(`pack-v1.json publishes no kid for the key used as ${one.role}`);
    }
  }
  // The piecewise path is only honest for the fault rows if it writes what the shipping writer writes: same
  // header, same manifest, same key, same bytes.
  const manifest = manifestFor(HONEST, ['receipt-1']);
  const header = encodeRedactionProtectedHeader(CURRENT.kid);
  const payloadBytes = encodeRedactionManifest(manifest);
  const piecewise = sealRedaction(header, payloadBytes, ed25519.sign(redactionSigStructure(header, payloadBytes), CURRENT.privateKey));
  if (toHex(piecewise) !== toHex(sealed(manifest))) {
    throw new Error('the piecewise envelope is not the one signRedaction writes');
  }
  // And a document that is meant to be refused cannot come out of the writer: a removal list with nothing in it
  // is refused before a signature is made, which is why every fault row below is assembled from the pieces.
  let writerRefused = false;
  try {
    signRedaction(manifestFor(HONEST, []), CURRENT);
  } catch (err) {
    writerRefused = err instanceof ReceiptError && err.code === 'REDACTION_BAD_MANIFEST';
  }
  if (!writerRefused) throw new Error('the redaction writer signed a removal list with nothing in it');
  // The writer also refuses a key whose kid is not sha256 of its public half, so this suite carries no row for
  // a header naming an id that resolves to nothing: no deployment can seal one.
  let keyRefused = false;
  try {
    signRedaction(manifest, { ...CURRENT, kid: new Uint8Array(32) });
  } catch (err) {
    keyRefused = err instanceof ReceiptError && err.code === 'BAD_SIGNING_KEY';
  }
  if (!keyRefused) throw new Error('the redaction writer accepted a signing key whose kid is not its digest');

  const rows = CASES.map(withChain);
  for (const one of rows) {
    const observed = verdictOf(one);
    if (observed !== one.verdict) {
      throw new Error(`${one.name}: the reader answers ${observed}, not the ${one.verdict} this file states`);
    }
    const structure = structuralOf(one);
    if (structure !== one.structural) {
      throw new Error(`${one.name}: the structural reader answers ${structure}, not the ${one.structural} this file states`);
    }
    // A row that names a published pack row names those exact bytes, unless it states the one position it
    // moved: this suite redacts evidence this repository already publishes rather than a rebuild of it that
    // happens to look the same.
    if (one.pack !== null) {
      const found = packRows.get(one.pack.name);
      if (found === undefined) throw new Error(`${one.name}: ${one.pack.name} is no document pack-v1.json publishes`);
      const publishedBytes = toHex(bytes(found.documentBase64Url));
      if (one.pack.edited === undefined) {
        if (toHex(one.pack.bytes) !== publishedBytes) {
          throw new Error(`${one.name}: the pack it calls ${one.pack.name} is not the bytes pack-v1.json publishes`);
        }
      } else if (toHex(one.pack.bytes) === publishedBytes) {
        throw new Error(`${one.name}: the pack states an edit and carries the published bytes unchanged`);
      }
    }
  }

  const names = rows.map((one) => one.name);
  if (new Set(names).size !== names.length) throw new Error('two cases of this suite share a name');
  const accepted = rows.filter((one) => one.verdict === 'verify-ok');
  if (accepted.length < 8) throw new Error(`${accepted.length} accepted rows, and the states a pair arrives in are more than that`);
  const refused = rows.filter((one) => one.verdict !== 'verify-ok');
  if (refused.length < 20) throw new Error(`${refused.length} refusals, and the format names more faults than that`);
  const wrongPairs = rows.filter((one) => one.verdict === 'REDACTION_PACK_MISMATCH' || one.verdict === 'REDACTION_PACK_UNAVAILABLE');
  if (wrongPairs.length < 4) throw new Error('this suite states fewer than four ways a reader can be handed the wrong half of a pair');
  const chainRefusals = rows.filter((one) => one.verdict === 'REDACTION_SURVIVOR_CHAIN_MISMATCH');
  if (chainRefusals.length < 3) throw new Error('this suite states fewer than three wrong constructions of the survivor chain');

  writeFileSync(
    join(DATA, 'redaction-v1.json'),
    JSON.stringify(
      {
        version: 1,
        description:
          "Redaction manifests in the shapes a deployment hands them over in, each beside the pack it speaks about, and the verdict the shipped redaction reader owes the pair: a removal accepted with the chain over the survivors published apart from the pack's own head, and one refusal for every fault the format names, including the three ways a survivor chain can be computed wrongly and the four ways a reader can be handed the wrong half of a pair.",
        layout: {
          format: 'packages/receipt/redaction.cddl',
          twin: 'packages/receipt/schemas/redaction-v1.schema.json',
          prose:
            'docs/receipt-spec.md section 5.2 for the framing the reduced member is folded over; the field set itself is stated by redaction.cddl and its JSON twin',
          contentType: REDACTION_CONTENT_TYPE,
          writer:
            'signRedaction in @ashaveri/receipt, which every honest seal here went through, and encodeRedactionManifest, encodeRedactionProtectedHeader, redactionSigStructure and sealRedaction, which assembled the rows that writer refuses to sign',
          reader:
            'verifyRedaction in @ashaveri/receipt, which is the verdict column and which reads the pack with verifyPack, and decodeRedaction, which is the structural column and needs no key and no pack',
          headerLabels: { alg: LABEL_ALG, typ: LABEL_TYP, kid: LABEL_KID },
          headerCloses:
            'the protected header carries exactly the three labels above and no fourth, because its bytes are hashed into the signature; the manifest map closes the same way',
          sigStructure:
            'RFC 9052 section 4.4: the array ["Signature1", the protected bstr as written, the external AAD, the payload bstr], canonically encoded. The external AAD is empty for this container and nothing inside the envelope carries which one was used.',
          packDesignation:
            "sha256 over the whole sealed pack document as the reader holds it, tag 18 and all four elements included. It is recomputed from the pack's bytes and never resolved by a name, and a digest of the pack's manifest alone would not tell two envelopes carrying that manifest apart, which is what the row named `redaction-naming-a-pack-and-not-its-envelope` is made to show.",
          survivorChain:
            "the pack's items in the order its prev links fix them, with the named records dropped, re-chained from the pack's own anchor: the first survivor hashed with the anchor as its predecessor and every later survivor hashed with the digest recomputed for the survivor before it, each by the pack's own record digest. With nothing dropped the fold returns the pack's signed head, which is why a document stating that head after a removal is refused, and why a removal list with nothing in it is refused before that.",
          recordDigest:
            'sha256 over 0x00 || prev || iat as eight big-endian bytes || the byte length of id as two big-endian bytes || id || receipt bytes, which is packRecordDigest from @ashaveri/receipt and the framing section 5.2 of docs/receipt-spec.md publishes. Nothing in this container restates it.',
          removedRule:
            "a set of the pack's own ids, at least one, no entry duplicated, every entry the name of exactly one item of the pack the designation binds. The survivor set is computed as the pack's walked items minus those names, so a removal larger than the one stated changes the chain the reader hashes, which is the half of the promise that nothing else is removed.",
          stampRule:
            "at is never before the pack's own at, which is the instant that pack's assembly began. Equality is not earlier and is accepted, and the bound is a relation between two signed documents rather than one document contradicting itself, which is why it answers a code of its own.",
          availabilityRule:
            "a reader that cannot reach a redaction still verifies the original pack, because no rule of the pack refers to this document and nothing here rewrites it. The converse is the row named `no-pack-handed`: a redaction pointed at a pack the reader lacks is refused rather than accepted on its own word.",
          encodings: 'documents and byte strings unpadded base64url, digests, kids, predecessors and signatures lowercase hex, instants unix seconds',
          verdictFields: ['verdict', 'structural', 'survivors', 'reducedHex', 'originalHeadHex', 'item', 'edited'],
          verdictMeaning:
            "`verdict` is what verifyRedaction answers for the pair the row states: `verify-ok`, or the code it throws. `structural` is what decodeRedaction answers for the redaction bytes alone, with no key and no pack, so a row that is `verify-ok` there and a refusal in `verdict` is refusing about a pack, a key or an arithmetic over survivors rather than about a manifest that contradicts itself. `survivors` is the run that remains in the order the pack's links fix it, `reducedHex` is the head of the chain over it and `originalHeadHex` is the pack's own signed head; all three are published on every accepted row, and the last two are never equal on one.",
          readFields:
            "`read.pinned` is the one key the caller holds, which designates the redaction's envelope and every receipt inside the pack. `read.retained` is the set a resolver answers from, one key per kid, which is how a pair whose pack crosses a key rotation is read. A row with neither is the call that designated nothing and is refused before a byte is read. The pack itself is handed beside the designation, and a row that states no pack at all is the reader that was handed one document of the pair.",
          packFields:
            "`packOf` names the row of `packages/fixtures/data/pack-v1.json` whose document this row hands the reader, `packBase64Url` carries those bytes and `packByteLength` their length. No pack here is rebuilt: every pack this suite redacts is evidence the pack suite already publishes. Where a row moves one position of such a pack before handing it over it says so in `packEdited`, and its bytes then differ from that row's by the edit named and nothing else.",
          chainRule:
            "the pack's walk is run by verifyPack over the bytes the designation binds, so the survivor sequence is the pack's own run with the named records dropped and the original head is re-established on every reading of a redaction. A reader that reports the reduced head where the pack's head belongs, or the reverse, is merging two findings this suite publishes apart.",
          run: runTable(HONEST, ['receipt-1']),
          records: survivorTable(HONEST, ['receipt-1']),
          codes: [...new Set(rows.map((one) => one.verdict))].sort(),
          assembled:
            "every honest redaction is `signRedaction` and no hand-built bytes. Where a row needs something that writer refuses to sign, the manifest is encoded, one position of its map is changed, and the result is signed over the published `Sig_structure` and sealed by `sealRedaction` under the key its header names; the generator stops unless that path reproduces `signRedaction` byte for byte on the canonical header, so each fault below is the one position its `edited` field names and nothing else. The writer is also asked to sign a removal list with nothing in it and a redaction under a key whose kid is not sha256 of its public half, and refuses both, which is why this suite carries no row that a deployment could have produced by accident.",
          keyMaterial: KEY_MATERIAL.map((one) => ({
            id: toHex(one.key.kid).slice(0, 8),
            seed: one.seed,
            kidHex: toHex(one.key.kid),
            publicKeyHex: toHex(one.key.publicKey),
            publicKeyBase64Url: toBase64Url(one.key.publicKey),
            role: one.role,
          })),
          keyNote:
            'test-only, published so a port can produce these signatures itself rather than only checking them, and protecting nothing. The redactions here are sealed by the same key the pack suite seals the packs they speak about, which is the key a deployment names in its manifest and the one a reader of a pack is handed for the receipts inside it.',
        },
        vectors: rows.map(published),
        crossReading: {
          note: "Five containers, one signing key, and each reader refusing the others' document at its protected header before a key is consulted. Both directions of the pack half are published: a pack handed to the redaction reader is the row named `protected-content-type-of-a-pack`, and the redaction handed to the pack reader is the case below, which is the confusion the content type exists to prevent.",
          cases: [
            {
              name: 'redaction-read-as-pack',
              note: "The honest redaction, handed to the pack reader under the key it names. The envelope decodes, the signature holds, and the typ is not the pack's, so the answer is the header refusal rather than a manifest problem these bytes do not have.",
              documentBase64Url: toBase64Url(sealed(manifestFor(HONEST, ['receipt-1']))),
              expected: packRefusalOf(sealed(manifestFor(HONEST, ['receipt-1']))),
            },
          ],
        },
      },
      null,
      2,
    ) + '\n',
  );

  for (const one of rows) console.log(`${one.name}: ${one.structural} -> ${one.verdict}`);
}

main();
