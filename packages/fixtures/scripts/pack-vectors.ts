import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  ALG_EDDSA,
  EXPORT_CONTENT_TYPE,
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
  toBase64Url,
  toHex,
  verifyExport,
  verifyPack,
  type PackItem,
  type PackManifest,
  type PackOrderingFinding,
  type ReceiptPayload,
  type ReceiptPayloadV1,
  type SigningKey,
  type VerifiedPack,
} from '@ashaveri/receipt';
import { labeled } from './seed.ts';
import { FIXED_IAT, fixtureKey, fixturePayload } from './receipt-envelope.ts';

const DATA = join(dirname(fileURLToPath(import.meta.url)), '..', 'data');

/**
 * The evidence pack vectors: whole packs in both shapes a reader is handed, the key material it designates
 * beside each one, and the verdict the shipped reader owes it.
 *
 * A pack is the fourth published container and the last one with no suite, which leaves a third party
 * implementing a reader with nothing to read. Every row here is bytes `packages/receipt/src/pack.ts` made, so
 * the file records what the writer and the reader agree on rather than what either of them was described as
 * doing: the honest seals come from `signPack`, and where a row needs bytes that writer will not sign, which is
 * every row whose manifest contradicts itself or whose header names something the format does not declare, the
 * document is assembled from the four pieces the package publishes and re-sealed under the key its header
 * names. `main` stops the run unless the piecewise path reproduces `signPack` byte for byte on the canonical
 * header, so a fault case differs from what a deployment signs only in the position its `edited` field names.
 *
 * Two verdicts are published per row because the pack reader has two entry points and they answer different
 * questions. `structural` is what `decodePack` says about the bytes with no key in hand, and `verdict` is what
 * `verifyPack` says under the designation the row states. A row whose `structural` is `verify-ok` and whose
 * `verdict` is a refusal is refusing about a key the caller holds or a signature over whole structure, which is
 * the pair of actions a port has to keep apart to report a pack honestly.
 *
 * The third column is `ordering`, and it exists because a pack carries two orders that are free to disagree.
 * The walk follows the `prev` links, and an item's `iat` is the stamp that record was chained under, and the
 * store chains under whatever stamp it was handed: a deployment that corrected its clock signs an honest pack
 * whose stamps run backwards. That document is accepted, and the disagreement is reported beside the run it
 * arrived in, never as a refusal. `stamps-run-backwards-accepted` is the row that pins which of the two a
 * conforming reader does.
 */

/** The three labels `pack.cddl` declares for a signed pack header, and no fourth. */
const LABEL_ALG = 1;
const LABEL_TYP = 3;
const LABEL_KID = 4;

const EMPTY = new Uint8Array(0);
const ZEROS = new Uint8Array(32);

/**
 * The keys this suite publishes.
 *
 * A pack's envelope and the receipts inside it are signed by the same key a deployment signs its live traffic
 * with, which is what makes the rotation-spanning row the interesting one: the epoch retired inside a window
 * still has to answer for the receipts it signed. So the honest packs here are sealed by `CURRENT`, the
 * committed fixture receipt key this repository already publishes in `data/keys/receipt-key-v1.json`, and
 * `RETIRED` is the epoch that was superseded inside the span. `OTHER` is another deployment's key, used for the
 * rows about a signature that was not made by the key its header names and a designation that reached nothing.
 */
const CURRENT: SigningKey = fixtureKey();
const RETIRED: SigningKey = signingKeyFromSeed(labeled('ashaveri-pack-v1/receipt-key-b'));
const OTHER: SigningKey = signingKeyFromSeed(labeled('ashaveri-pack-v1/signer-b'));
const ALL_KEYS: readonly SigningKey[] = [CURRENT, RETIRED, OTHER];
const KEY_BY_KID = new Map(ALL_KEYS.map((one) => [toHex(one.kid), one]));

const KEY_MATERIAL: readonly { key: SigningKey; seed: string; role: string }[] = [
  {
    key: CURRENT,
    seed: "sha256 of 'ashaveri-fixtures/receipt-key/v1', the committed fixture receipt key",
    role: 'seals the honest packs and signs the receipts inside them',
  },
  {
    key: RETIRED,
    seed: "sha256 of 'ashaveri-pack-v1/receipt-key-b'",
    role: 'the epoch superseded inside a span, whose receipts the pack still carries',
  },
  {
    key: OTHER,
    seed: "sha256 of 'ashaveri-pack-v1/signer-b'",
    role: 'another deployment\'s key, for the seal that names a kid it is not and the designation that reaches nothing',
  },
];

/** The instant every published fixture in this repository is issued at, so regenerating changes no byte. */
const BASE = FIXED_IAT;
const SPAN_FROM = BASE - 60;
const SPAN_TO = BASE + 3;

/** The duty the honest packs answer for: the store's own floor, met by a deployment holding to it. */
const HONEST_DUTY = { art: '19(1)', rev: SPAN_TO - 30, required: 15_897_600, held: 15_897_600 };

const digest = (bytes: Uint8Array): Uint8Array => sha256(bytes);
const text = (value: string): Uint8Array => new TextEncoder().encode(value);

/** One record's receipt, under the key that epoch held, attesting the stamp it is chained with. */
function receiptFor(id: string, iat: number, key: SigningKey = CURRENT, marked = false): Uint8Array {
  const fields: ReceiptPayloadV1 = {
    ...fixturePayload({ iat }),
    nce: labeled(`ashaveri-pack-v1/nonce/${id}`, 16),
  };
  const payload: ReceiptPayload = marked ? { ...fields, v: 2 as const, mk: { sch: 'none', d: digest(EMPTY) } } : fields;
  return issueReceipt(payload, key);
}

interface Entry {
  readonly id: string;
  readonly iat: number;
  readonly key?: SigningKey;
  readonly marked?: boolean;
}

/**
 * Records chained in the order given, each receipt attesting the stamp its record was hashed with. `anchor` is
 * the endpoint the run starts from, so a case about a retired prefix hands over the seam a trim record carried
 * rather than thirty-two zero bytes.
 */
function chained(entries: readonly Entry[], anchor: Uint8Array = ZEROS): { items: PackItem[]; anchor: Uint8Array; head: Uint8Array } {
  const items: PackItem[] = [];
  let prev = anchor;
  for (const entry of entries) {
    const item: PackItem = { id: entry.id, iat: entry.iat, prev, receipt: receiptFor(entry.id, entry.iat, entry.key ?? CURRENT, entry.marked) };
    items.push(item);
    prev = packRecordDigest(item);
  }
  return { items, anchor, head: prev };
}

const ENTRIES: readonly Entry[] = [
  { id: 'receipt-0', iat: BASE },
  { id: 'receipt-1', iat: BASE + 1 },
  { id: 'receipt-2', iat: BASE + 2 },
];

/**
 * A manifest from a run, honest in every relation the format states. The duty figures default to the ones a
 * deployment meeting its period signs; the row about a duty that falls short moves `required` and nothing else,
 * because the reader is not where that comparison is made.
 */
function manifestFor(run: { items: PackItem[]; anchor: Uint8Array; head: Uint8Array }, over: Partial<PackManifest> = {}): PackManifest {
  return {
    v: 1,
    at: SPAN_TO,
    span: { from: SPAN_FROM, to: SPAN_TO },
    chain: { anchor: run.anchor, head: run.head },
    duty: { ...HONEST_DUTY, held: Math.max(HONEST_DUTY.held, SPAN_TO - Math.min(...run.items.map((one) => one.iat))) },
    items: run.items,
    ...over,
  };
}

const HONEST = chained(ENTRIES);
const honestManifest = manifestFor(HONEST);

/** The envelope a deployment of this moment signs, through the shipped writer and nothing else. */
const honestBytes = signPack(honestManifest, CURRENT);

/**
 * A manifest with one position moved, then signed through the published pieces rather than `signPack`, which
 * would refuse to sign it. The bytes are decoded back into the maps the format declares, edited, re-encoded and
 * re-sealed under the key the header names, so the signature is good and the only fault is the edit.
 */
function mutant(manifest: PackManifest, edit: (root: Map<unknown, unknown>) => void, key: SigningKey = CURRENT): Uint8Array {
  const root = asMap(encodePackManifest(manifest));
  edit(root);
  return underType(PACK_CONTENT_TYPE, encodeCanonical(root), key);
}

/**
 * A document whose header names one key and whose signature was made by another, which is the shape that
 * separates a wrong key from an edited document: the kid check is answered by the header and the signature by
 * the private half, and only one of the two can be wrong about the same bytes.
 */
function sealSplit(headerKid: SigningKey, signer: SigningKey, payloadBytes: Uint8Array): Uint8Array {
  const header = encodePackProtectedHeader(headerKid.kid);
  return sealPack(header, payloadBytes, ed25519.sign(packSigStructure(header, payloadBytes), signer.privateKey));
}

/** The whole document under another content type, which is how four containers share one key. */
function underType(contentType: string, payloadBytes: Uint8Array, key: SigningKey = CURRENT): Uint8Array {
  const header = encodePackProtectedHeader(key.kid, contentType);
  return sealPack(header, payloadBytes, ed25519.sign(packSigStructure(header, payloadBytes), key.privateKey));
}

function asMap(payload: Uint8Array): Map<unknown, unknown> {
  const decoded = decodeCanonical(payload);
  if (!(decoded instanceof Map)) throw new Error('a manifest this file encoded did not come back as a map');
  return decoded;
}

function elementsOf(bytes: Uint8Array): unknown[] {
  const contents = (decodeCanonical(bytes) as { contents?: unknown }).contents;
  if (!Array.isArray(contents)) throw new Error('a document this file sealed is not a four-element envelope');
  return contents;
}

function blockOf(root: Map<unknown, unknown>, member: string): Map<unknown, unknown> {
  const value = root.get(member);
  if (!(value instanceof Map)) throw new Error(`this case builds a manifest with a ${member} block`);
  return value;
}

function itemOf(root: Map<unknown, unknown>, index: number): Map<unknown, unknown> {
  const items = root.get('items');
  const one = Array.isArray(items) ? items[index] : undefined;
  if (!(one instanceof Map)) throw new Error(`this case builds a manifest with an item at ${String(index)}`);
  return one;
}

/**
 * A manifest sealed whole but not through `signPack`, for the rows whose bytes that writer refuses to make
 * and a reader still has to answer. The pieces are the same four and the header is the one the format
 * declares, so the only thing these documents differ from a deployment's own by is the position the row names.
 */
function despiteGuard(manifest: PackManifest, key: SigningKey = CURRENT): Uint8Array {
  return underType(PACK_CONTENT_TYPE, encodePackManifest(manifest), key);
}

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

/**
 * A whole document with one byte of one item's receipt flipped afterwards and the signature kept. The receipt
 * bytes are inside the payload and opaque to the manifest's own decode, so the structure still reads and the
 * signature is what refuses, which is the order a reader has to keep and the edit a handover carried through a
 * loose file meets.
 */
function withReceiptByteFlipped(bytes: Uint8Array, item: PackItem, at: number): Uint8Array {
  const [header, , payload, signature] = elementsOf(bytes);
  const payloadBytes = payload as Uint8Array;
  const start = indexOfBytes(payloadBytes, item.receipt);
  if (start < 0) throw new Error('the signed payload does not carry the receipt this case edits');
  const edited = new Uint8Array(payloadBytes);
  edited[start + at] = (edited[start + at] ?? 0) ^ 0x01;
  return sealPack(header as Uint8Array, edited, signature as Uint8Array);
}

/** A document under a header of the caller's choosing, signed by the key that header names. */
function sealedUnder(header: Uint8Array, payloadBytes: Uint8Array = encodePackManifest(honestManifest), key: SigningKey = CURRENT): Uint8Array {
  return sealPack(header, payloadBytes, ed25519.sign(packSigStructure(header, payloadBytes), key.privateKey));
}

/** A record chained from a digest nothing in this run carries, which the walk never needs to reach. */
function parkedItem(id: string, iat: number): PackItem {
  return { id, iat, prev: digest(text('a digest nobody in this run names')), receipt: receiptFor(id, iat) };
}

/** The designation a row hands the reader: one pinned key, the set a resolver answers from, or neither. */
interface Designation {
  readonly pinned?: string;
  readonly retained?: readonly { kid: string; publicKeyBase64Url: string }[];
}

const PINNED_CURRENT: Designation = { pinned: toBase64Url(CURRENT.publicKey) };
const PINNED_OTHER: Designation = { pinned: toBase64Url(OTHER.publicKey) };
const RETAINED_BOTH: Designation = { retained: [CURRENT, RETIRED].map((one) => ({ kid: toHex(one.kid), publicKeyBase64Url: toBase64Url(one.publicKey) })) };
const RETAINED_CURRENT_ONLY: Designation = { retained: [{ kid: toHex(CURRENT.kid), publicKeyBase64Url: toBase64Url(CURRENT.publicKey) }] };

const bytes = (base64url: string): Uint8Array => new Uint8Array(Buffer.from(base64url, 'base64url'));

/** The options the row's designation builds, which are the reader's own two shapes and no third. */
function optionsFor(read: Designation): { publicKey?: Uint8Array; resolveKey?: (kid: Uint8Array) => Uint8Array | undefined } {
  if (read.pinned !== undefined) return { publicKey: bytes(read.pinned) };
  if (read.retained !== undefined) {
    const byKid = new Map(read.retained.map((one) => [one.kid, one.publicKeyBase64Url]));
    return { resolveKey: (kid) => { const found = byKid.get(toHex(kid)); return found === undefined ? undefined : bytes(found); } };
  }
  return {};
}

interface Case {
  readonly name: string;
  readonly note: string;
  readonly bytes: Uint8Array;
  readonly read: Designation;
  /** What `verifyPack` answers: `verify-ok`, or the code it throws. */
  readonly verdict: string;
  /** What `decodePack` answers for the same bytes with no key in hand. */
  readonly structural: string;
  /** The order the walk reaches, published on every row the reader accepts. */
  readonly walk?: readonly string[];
  /** The ordering findings, published on every row the reader accepts. */
  readonly ordering?: readonly PackOrderingFinding[];
  /** The item a refusal names, where the code reports by naming one. */
  readonly item?: string;
  /** The span as the accepted row states it, published where the window is the point. */
  readonly span?: { from: number; to: number };
  /** The one position a fault case moved, published so a port finds it without a diff. */
  readonly edited?: string;
}

const ROTATED = chained([
  { id: 'receipt-0', iat: BASE, key: RETIRED },
  { id: 'receipt-1', iat: BASE + 1, key: RETIRED },
  { id: 'receipt-2', iat: BASE + 2 },
]);

const BACKWARDS = chained([
  { id: 'receipt-2', iat: BASE + 2 },
  { id: 'receipt-1', iat: BASE + 1 },
  { id: 'receipt-0', iat: BASE },
]);

const SAME_SECOND = chained([
  { id: 'receipt-0', iat: BASE },
  { id: 'receipt-1', iat: BASE },
  { id: 'receipt-2', iat: BASE + 1 },
]);

const SHORTER = chained([ENTRIES[0]!, ENTRIES[2]!]);
const SINGLE = chained([ENTRIES[0]!]);
const MARKED = chained([{ id: 'receipt-0', iat: BASE, marked: true }, ENTRIES[1]!, ENTRIES[2]!]);
const SEAM = chained(ENTRIES, digest(text('the seam a trim record carried')));

const CASES: readonly Case[] = [
  {
    name: 'well-formed-three-items',
    note: 'Three receipts chained from an anchor of thirty-two zero bytes to a head inside the signature, sealed by the key that signed every receipt in the container, and read by a caller that pinned that key. This is the state a handover arrives in and everything a reader is entitled to say about it: the run the links fix, and the window the manifest states, as two separate findings.',
    bytes: honestBytes,
    read: PINNED_CURRENT,
    verdict: 'verify-ok',
    structural: 'verify-ok',
    walk: ['receipt-0', 'receipt-1', 'receipt-2'],
    ordering: [],
    span: { from: SPAN_FROM, to: SPAN_TO },
  },
  {
    name: 'array-order-bears-nothing',
    note: 'The same pack with its items handed over in the reverse of the order the chain puts them. The walk starts at the item naming the anchor and follows the links, so the run it reports is the run it would have reported, which is the rule that keeps a retirement or a compaction from having to rewrite an array.',
    bytes: signPack({ ...honestManifest, items: [...honestManifest.items].reverse() }, CURRENT),
    read: PINNED_CURRENT,
    verdict: 'verify-ok',
    structural: 'verify-ok',
    walk: ['receipt-0', 'receipt-1', 'receipt-2'],
    ordering: [],
  },
  {
    name: 'retired-prefix-behind-a-seam',
    note: 'A run that began after a retirement, chained from the seam the trim record carried rather than from zero bytes. The anchor arrives as the same member either way and a reader does not have to know which happened to start walking.',
    bytes: signPack(manifestFor(SEAM), CURRENT),
    read: PINNED_CURRENT,
    verdict: 'verify-ok',
    structural: 'verify-ok',
    walk: ['receipt-0', 'receipt-1', 'receipt-2'],
    ordering: [],
  },
  {
    name: 'single-item-pack',
    note: 'One receipt, which is a whole walk rather than a degenerate one: the item whose `prev` is the anchor is first and the item whose own digest is the head is last, and here they are the same item. The format refuses a pack with no items at all, because a walk over nothing closes vacuously and would read as evidence.',
    bytes: signPack(manifestFor(SINGLE), CURRENT),
    read: PINNED_CURRENT,
    verdict: 'verify-ok',
    structural: 'verify-ok',
    walk: ['receipt-0'],
    ordering: [],
  },
  {
    name: 'span-crossing-a-key-rotation',
    note: 'The receipts of the epoch a deployment retired inside the window, beside those of the key that replaced it, sealed by the current one. A caller that hands the reader the keys it retained reads the whole run; each item verifies under the key its own header names, and the envelope under the one that signed it.',
    bytes: signPack(manifestFor(ROTATED), CURRENT),
    read: RETAINED_BOTH,
    verdict: 'verify-ok',
    structural: 'verify-ok',
    walk: ['receipt-0', 'receipt-1', 'receipt-2'],
    ordering: [],
  },
  {
    name: 'rotation-read-with-one-pinned-key',
    note: 'Those same bytes read by a caller that retained only the current epoch. The envelope verifies and the first item does not, and the refusal names the item and the answer its own receipt gave, because the pack is not the thing at fault: the caller is holding too few keys.',
    bytes: signPack(manifestFor(ROTATED), CURRENT),
    read: PINNED_CURRENT,
    verdict: 'PACK_RECEIPT_INVALID',
    structural: 'verify-ok',
    item: 'receipt-0',
  },
  {
    name: 'rotation-read-without-the-retired-epoch',
    note: 'The same span and a resolver that answers for the current kid only. This is the one inner refusal the reader does not keep as a receipt\'s answer: nothing about the pack contradicts itself, and the action is to go and retain the key the deployment\'s manifest names rather than to refuse these bytes.',
    bytes: signPack(manifestFor(ROTATED), CURRENT),
    read: RETAINED_CURRENT_ONLY,
    verdict: 'PACK_UNKNOWN_KEY',
    structural: 'verify-ok',
    item: 'receipt-0',
  },
  {
    name: 'marked-receipt-inside-a-pack',
    note: 'A v2 receipt carrying a marking member of the `none` scheme, chained among v1 documents. A pack states which receipts it carries and nothing about which payload versions a caller reads, so the marked original is verified as the receipt it is.',
    bytes: signPack(manifestFor(MARKED), CURRENT),
    read: PINNED_CURRENT,
    verdict: 'verify-ok',
    structural: 'verify-ok',
    walk: ['receipt-0', 'receipt-1', 'receipt-2'],
    ordering: [],
  },
  {
    name: 'duty-short-of-the-period-it-states',
    note: 'A whole pack whose `held` figure is younger than the `required` period its own revision names. The document is not at fault and the reader has no opinion to hand back: `met` is absent from the format so that a deployment signs evidence rather than its own conclusion, and the arithmetic belongs to whoever holds the mapping.',
    bytes: signPack(manifestFor(HONEST, { duty: { art: '19(1)', rev: SPAN_TO - 30, required: 15_897_600, held: 3 } }), CURRENT),
    read: PINNED_CURRENT,
    verdict: 'verify-ok',
    structural: 'verify-ok',
    walk: ['receipt-0', 'receipt-1', 'receipt-2'],
    ordering: [],
  },
  {
    name: 'unprotected-map-carries-a-parameter',
    note: 'The honest document with the unprotected map filled instead of left empty. That map is the one place in this container a signer fills at will: it sits outside the signature, so nothing written in it travels as a claim about the span, and enforcing that it is empty would buy strictness with no security content behind it.',
    bytes: sealPack(
      encodePackProtectedHeader(CURRENT.kid),
      encodePackManifest(honestManifest),
      ed25519.sign(packSigStructure(encodePackProtectedHeader(CURRENT.kid), encodePackManifest(honestManifest)), CURRENT.privateKey),
      new Map<unknown, unknown>([['note', 'outside the signature']]),
    ),
    read: PINNED_CURRENT,
    verdict: 'verify-ok',
    structural: 'verify-ok',
    walk: ['receipt-0', 'receipt-1', 'receipt-2'],
    ordering: [],
  },
  {
    name: 'stamps-run-backwards-accepted',
    note: 'The two orders a pack carries, disagreeing. The store chains a receipt under whatever stamp it was handed, so a deployment that corrected its clock produces this document: the links ascend, the stamps descend, and every record digest comes out. It is accepted and the disagreement is reported as a finding naming the step, because refusing it would reject lawful output on a ground no rule of this format states.',
    bytes: signPack(manifestFor(BACKWARDS), CURRENT),
    read: PINNED_CURRENT,
    verdict: 'verify-ok',
    structural: 'verify-ok',
    walk: ['receipt-2', 'receipt-1', 'receipt-0'],
    ordering: [
      { kind: 'stamp-runs-backwards', from: 'receipt-2', to: 'receipt-1', fromIat: BASE + 2, toIat: BASE + 1 },
      { kind: 'stamp-runs-backwards', from: 'receipt-1', to: 'receipt-0', fromIat: BASE + 1, toIat: BASE },
    ],
  },
  {
    name: 'two-records-under-one-stamp',
    note: 'A store that served two records inside the same second chains them under one stamp, and the links still order them. Equal stamps are not a disagreement, so this row is accepted with no finding beside it: a reader that reported equality as an ordering fault would bury the steps where the two orders really do part.',
    bytes: signPack(manifestFor(SAME_SECOND), CURRENT),
    read: PINNED_CURRENT,
    verdict: 'verify-ok',
    structural: 'verify-ok',
    walk: ['receipt-0', 'receipt-1', 'receipt-2'],
    ordering: [],
  },
  {
    name: 'shortened-run-closing-at-its-own-head',
    note: 'The middle record lifted out and the run re-chained to the head that shorter run hashes to, which is what a deployment that removed a receipt and re-signed the endpoints would hand over. Every check the container supports passes and the deletion is invisible from these bytes alone: publishing the head makes deletion detectable against a copy a reader held from before, and this reader is handed none. The run it reports is two items, and the window it states is the window it was signed to answer for.',
    bytes: signPack(manifestFor(SHORTER), CURRENT),
    read: PINNED_CURRENT,
    verdict: 'verify-ok',
    structural: 'verify-ok',
    walk: ['receipt-0', 'receipt-2'],
    ordering: [],
    span: { from: SPAN_FROM, to: SPAN_TO },
  },
  {
    name: 'no-designation-at-all',
    note: 'The honest document and a call that handed the reader neither a pinned key nor a resolver. The fault is in the call, so it is answered before a byte is read: a document question about bytes nobody has been given a key to check would send an operator to the pack rather than to their own configuration.',
    bytes: honestBytes,
    read: {},
    verdict: 'PACK_UNKNOWN_KEY',
    structural: 'verify-ok',
  },
  {
    name: 'sealed-under-another-deployment-key',
    note: 'The honest manifest sealed by a key this reader was not given, under that key\'s own kid. The bytes are a whole pack and their signature holds against the header that names them; the refusal is that this caller does not designate that key, which is a different finding from tampering and the reason the two are separate codes.',
    bytes: signPack(honestManifest, OTHER),
    read: PINNED_CURRENT,
    verdict: 'PACK_KID_MISMATCH',
    structural: 'verify-ok',
  },
  {
    name: 'header-naming-one-key-signed-by-another',
    note: 'A protected header carrying the designated kid and a signature the designated key did not make, which is the shape that separates a wrong key from an edited document. The kid check passes and the signature is what refuses, so the report is about tampering.',
    bytes: sealSplit(CURRENT, OTHER, encodePackManifest(honestManifest)),
    read: PINNED_CURRENT,
    verdict: 'INVALID_SIGNATURE',
    structural: 'verify-ok',
    edited: 'the private half that made the signature, with the header naming the other key',
  },
  {
    name: 'receipt-byte-changed-after-sealing',
    note: 'One byte of the first item\'s receipt flipped after the document was signed, with the old signature left in place. The manifest still decodes and every width and relation in it holds, because the receipt bytes are opaque to the structure and inside the hash of the record they belong to, so what refuses is the signature and nothing else.',
    bytes: withReceiptByteFlipped(honestBytes, honestManifest.items[0]!, 12),
    read: PINNED_CURRENT,
    verdict: 'INVALID_SIGNATURE',
    structural: 'verify-ok',
    edited: 'the thirteenth byte of items[0].receipt, under the signature made for it',
  },
  {
    name: 'protected-content-type-of-a-receipt',
    note: 'The pack manifest inside an envelope whose `typ` is the receipt\'s. Both containers are `COSE_Sign1` over four elements signed by this same key and each verifies cleanly under it, so the mistake a content type exists to prevent is exactly this one, and it is refused at the header before any resolver is consulted.',
    bytes: underType('ashaveri/receipt', encodePackManifest(honestManifest)),
    read: PINNED_CURRENT,
    verdict: 'PACK_BAD_HEADER',
    structural: 'PACK_BAD_HEADER',
    edited: 'typ, from ashaveri/pack to ashaveri/receipt',
  },
  {
    name: 'protected-content-type-of-an-export',
    note: 'That same pair in the other direction, under the export type, which is the third container one deployment key signs. A reader that answered with the document it was hoping for would be reporting the wrong claim under a signature that held.',
    bytes: underType(EXPORT_CONTENT_TYPE, encodePackManifest(honestManifest)),
    read: PINNED_CURRENT,
    verdict: 'PACK_BAD_HEADER',
    structural: 'PACK_BAD_HEADER',
    edited: 'typ, from ashaveri/pack to ashaveri/export',
  },
  {
    name: 'protected-header-carries-a-fourth-label',
    note: 'A protected header carrying a label this format does not declare, beside the three it does, and signed over as always. The header closes where a reader might be tempted to be open, because its bytes are hashed into the `Sig_structure`: a fourth label is an authenticated parameter and a reader that took the three it knows would hand on a document other than the one the deployment signed.',
    bytes: sealedUnder(headerWithFourthLabel()),
    read: PINNED_CURRENT,
    verdict: 'PACK_BAD_HEADER',
    structural: 'PACK_BAD_HEADER',
    edited: 'a fourth protected label, 5, carrying a tstr',
  },
  {
    name: 'protected-kid-of-another-width',
    note: 'A `kid` of thirty-one bytes, a declared label holding the wrong shape. The width is what makes the field an id at all: it is sha256 of a public key, and a reader that took a shorter one would be resolving a key from bytes nothing hashes to.',
    bytes: sealedUnder(headerWithKidWidth(31)),
    read: PINNED_CURRENT,
    verdict: 'PACK_BAD_HEADER',
    structural: 'PACK_BAD_HEADER',
    edited: 'the protected kid, one byte short of the digest it is meant to be',
  },
  {
    name: 'protected-alg-naming-another-suite',
    note: 'An `alg` of -7 where this container signs with EdDSA. The header refusal and this one are separate codes on purpose: one says the map is not the map this format declares, the other says the map is right and names a suite nothing here produces.',
    bytes: sealedUnder(algHeader(-7)),
    read: PINNED_CURRENT,
    verdict: 'UNSUPPORTED_ALG',
    structural: 'UNSUPPORTED_ALG',
    edited: 'alg, from -8 to -7',
  },
  {
    name: 'manifest-version-two',
    note: 'A manifest declaring a pack version no format has used. The answer is about the reach of this reader rather than about the bytes being broken, and it arrives with no key in hand because a version is a fact of the document.',
    bytes: mutant(honestManifest, (root) => root.set('v', 2)),
    read: PINNED_CURRENT,
    verdict: 'PACK_UNSUPPORTED_VERSION',
    structural: 'PACK_UNSUPPORTED_VERSION',
    edited: 'v, from 1 to 2',
  },
  {
    name: 'manifest-member-unknown-to-version-one',
    note: 'A manifest carrying a member this version names nowhere. The map is closed, so the document is malformed rather than read with the unexpected member dropped: a member a reader ignores is a claim inside the signature that nobody looked at.',
    bytes: mutant(honestManifest, (root) => root.set('met', true)),
    read: PINNED_CURRENT,
    verdict: 'PACK_BAD_MANIFEST',
    structural: 'PACK_BAD_MANIFEST',
    edited: "a member named 'met' added to the manifest",
  },
  {
    name: 'item-stamped-outside-its-span',
    note: 'One item whose stamp is at the excluded end of the span the same signature states. Both bounds bind every item, which is the set the store\'s own range query serves for those two stamps, so this is two signed members contradicting each other and not a deployment that failed to hold what it answered for.',
    bytes: mutant(honestManifest, (root) => itemOf(root, 2).set('iat', SPAN_TO)),
    read: PINNED_CURRENT,
    verdict: 'PACK_BAD_MANIFEST',
    structural: 'PACK_BAD_MANIFEST',
    edited: 'items[2].iat, to the instant the span excludes',
  },
  {
    name: 'assembly-before-the-span-closed',
    note: 'A pack whose reads began before the window it answers for ended. A span still receiving has no completeness for a deployment to have signed, and both stamps are inside one signature, so the disagreement is the document\'s and is refused whoever signed it.',
    bytes: mutant(honestManifest, (root) => root.set('at', SPAN_TO - 1)),
    read: PINNED_CURRENT,
    verdict: 'PACK_BAD_MANIFEST',
    structural: 'PACK_BAD_MANIFEST',
    edited: 'at, to one second before the span closed',
  },
  {
    name: 'revision-after-the-reads',
    note: 'A duty mapping revision that postdates the instant the assembly began, which is not the revision the period was read from. Without this the artifact would date its own conclusion by the day somebody opened it.',
    bytes: mutant(honestManifest, (root) => blockOf(root, 'duty').set('rev', SPAN_TO + 1)),
    read: PINNED_CURRENT,
    verdict: 'PACK_BAD_MANIFEST',
    structural: 'PACK_BAD_MANIFEST',
    edited: 'duty.rev, to one second after at',
  },
  {
    name: 'held-younger-than-the-oldest-item',
    note: 'A `held` figure below the age of the oldest receipt this pack carries. The duty runs against everything still retained and the oldest item need not be it, but a pack covering a receipt is a statement that the store held that receipt, so a smaller figure contradicts the document carrying it.',
    bytes: mutant(honestManifest, (root) => blockOf(root, 'duty').set('held', 2)),
    read: PINNED_CURRENT,
    verdict: 'PACK_BAD_MANIFEST',
    structural: 'PACK_BAD_MANIFEST',
    edited: 'duty.held, to two seconds where the oldest item is three',
  },
  {
    name: 'no-items-at-all',
    note: 'A pack with an empty items array. Its walk would be vacuous, its head would equal its anchor, and the artifact would read as evidence while proving only that somebody signed two digests. That a window held nothing is a statement about the window and belongs to the artifact that states windows.',
    bytes: mutant(honestManifest, (root) => root.set('items', [])),
    read: PINNED_CURRENT,
    verdict: 'PACK_BAD_MANIFEST',
    structural: 'PACK_BAD_MANIFEST',
    edited: 'the items array, emptied',
  },
  {
    name: 'stamp-spelled-as-a-float',
    note: 'An item stamp written as the half-precision float 1.0 of the integer it stands for... rather than as an integer. A float is a different major type and the only reader that can ever tell them apart is one reading the bytes, because a decoder that hands both over as one number leaves a check placed afterwards nothing to distinguish. The refusal is the format\'s integer rule, and it arrives where the bytes are decoded.',
    bytes: mutant(honestManifest, (root) => itemOf(root, 1).set('iat', BASE + 0.5)),
    read: PINNED_CURRENT,
    verdict: 'PACK_BAD_MANIFEST',
    structural: 'PACK_BAD_MANIFEST',
    edited: 'items[1].iat, written as the float of a whole number',
  },
  {
    name: 'two-items-answering-to-one-name',
    note: 'The same `id` carried by two items, chained honestly over the records as given so that every link is right. The name sits inside the hash, so both spellings hash perfectly and nothing about a chain reports the collision; a refusal that names an item would otherwise mean whichever of the two a reader met first.',
    bytes: despiteGuard({ ...honestManifest, items: [...honestManifest.items, { ...honestManifest.items[1]!, id: 'receipt-0' }] }),
    read: PINNED_CURRENT,
    verdict: 'PACK_DUPLICATE_ID',
    structural: 'PACK_DUPLICATE_ID',
    item: 'receipt-0',
  },
  {
    name: 'item-receipt-is-not-a-receipt',
    note: 'An item whose `receipt` is a sentence rather than a signed document. The originals are read before the walk, so what a caller hears is that this pack carries something other than the receipts it claims, and the refusal names which item and with what answer.',
    bytes: signPack({ ...honestManifest, items: [{ ...honestManifest.items[0]!, receipt: text('not a receipt at all') }, ...honestManifest.items.slice(1)] }, CURRENT),
    read: PINNED_CURRENT,
    verdict: 'PACK_RECEIPT_INVALID',
    structural: 'verify-ok',
    item: 'receipt-0',
  },
  {
    name: 'item-chained-under-a-stamp-it-does-not-attest',
    note: 'The middle item restamped to a value its own receipt does not carry, with its successor\'s link recomputed over the moved stamp so that the run still closes at the signed head. The store chains under the stamp it was handed, so the item\'s `iat` and the receipt\'s are two statements and their equality is part of the walk: this is a receipt moved into a window it was never issued in, and the links say nothing about it.',
    bytes: signPack(
      {
        ...honestManifest,
        items: [
          honestManifest.items[0]!,
          { ...honestManifest.items[1]!, iat: honestManifest.items[1]!.iat + 1 },
          { ...honestManifest.items[2]!, prev: packRecordDigest({ ...honestManifest.items[1]!, iat: honestManifest.items[1]!.iat + 1 }) },
        ],
      },
      CURRENT,
    ),
    read: PINNED_CURRENT,
    verdict: 'PACK_RECEIPT_STAMP_MISMATCH',
    structural: 'verify-ok',
    item: 'receipt-1',
    edited: 'items[1].iat, one second past the stamp its receipt attests, and the successor relinked over it',
  },
  {
    name: 'record-lifted-out-of-the-middle',
    note: 'The middle record taken out of a signed run and nothing else touched, so the successor still names the predecessor it had and the head is the one the whole run hashed to. What remains is whole by its own digest and the walk stops at the hole, which is the deletion publishing the head inside the signature exists to make visible.',
    bytes: signPack({ ...honestManifest, items: [honestManifest.items[0]!, honestManifest.items[2]!] }, CURRENT),
    read: PINNED_CURRENT,
    verdict: 'PACK_CHAIN_BROKEN',
    structural: 'verify-ok',
    edited: 'the items array, with the middle record removed',
  },
  {
    name: 'two-items-naming-one-predecessor',
    note: 'A second item claiming the anchor as its predecessor, the rest of the run untouched. The walk would take whichever it met first and report the other as unreached, so a fork is refused rather than resolved by the order the array happened to be in.',
    bytes: signPack({ ...honestManifest, items: [{ id: 'rival', iat: BASE, prev: HONEST.anchor, receipt: receiptFor('rival', BASE) }, ...honestManifest.items] }, CURRENT),
    read: PINNED_CURRENT,
    verdict: 'PACK_CHAIN_BROKEN',
    structural: 'verify-ok',
    edited: 'a rival item chained from the same anchor as the first record',
  },
  {
    name: 'item-parked-beside-the-run',
    note: 'A receipt handed over beside a run it is not part of, naming a predecessor nobody here carries. The walk reaches the signed head and never had to visit it, so the count of what the walk reached against the array is the half of the rule with eyes for it, and a verifier that implements only the walk passes this pack.',
    bytes: signPack({ ...honestManifest, items: [...honestManifest.items, parkedItem('parked', BASE + 1)] }, CURRENT),
    read: PINNED_CURRENT,
    verdict: 'PACK_ITEM_UNREACHED',
    structural: 'verify-ok',
    item: 'parked',
    edited: 'a fourth item chained from a digest no item in this run carries',
  },
  {
    name: 'envelope-without-its-tag',
    note: 'The four elements of a `COSE_Sign1` with the tag around them missing, which is a shape a reader cannot recover by being tolerant: tag 18 is what says these bytes are an envelope at all.',
    bytes: encodeCanonical(elementsOf(honestBytes)),
    read: PINNED_CURRENT,
    verdict: 'NOT_COSE_SIGN1',
    structural: 'NOT_COSE_SIGN1',
    edited: 'the CBOR tag 18 around the four envelope elements',
  },
  {
    name: 'envelope-whose-signature-is-not-64-bytes',
    note: 'The honest envelope with one byte taken off the end of its signature, which is a shape refusal rather than a cryptography failure: a reader that reached the verification step with a truncated signature would be reporting a wrong answer about the wrong bytes.',
    bytes: (() => {
      const [header, , payload, signature] = elementsOf(honestBytes);
      return sealPack(header as Uint8Array, payload as Uint8Array, (signature as Uint8Array).slice(0, 63));
    })(),
    read: PINNED_CURRENT,
    verdict: 'NOT_COSE_SIGN1',
    structural: 'NOT_COSE_SIGN1',
    edited: 'the last byte of the signature',
  },
  {
    name: 'document-truncated-mid-envelope',
    note: 'The first twenty-four bytes of a whole pack, so nothing decodes and no header, key or manifest is ever reached.',
    bytes: honestBytes.slice(0, 24),
    read: PINNED_CURRENT,
    verdict: 'PACK_MALFORMED_CBOR',
    structural: 'PACK_MALFORMED_CBOR',
  },
];

/** The three declared labels with a fourth on, spelled out of the parts the format names. */
function headerWithFourthLabel(): Uint8Array {
  return encodeCanonical(
    new Map<number, unknown>([
      [LABEL_ALG, ALG_EDDSA],
      [LABEL_TYP, PACK_CONTENT_TYPE],
      [LABEL_KID, CURRENT.kid],
      [5, 'what'],
    ]),
  );
}

/** The declared labels with a `kid` of the caller's width, which is a shape fault and not an unknown label. */
function headerWithKidWidth(width: number): Uint8Array {
  return encodeCanonical(
    new Map<number, unknown>([
      [LABEL_ALG, ALG_EDDSA],
      [LABEL_TYP, PACK_CONTENT_TYPE],
      [LABEL_KID, CURRENT.kid.slice(0, width)],
    ]),
  );
}

/** The same header with an `alg` of the caller's choosing, which is the one label the writers here fix. */
function algHeader(alg: number): Uint8Array {
  return encodeCanonical(
    new Map<number, unknown>([
      [LABEL_ALG, alg],
      [LABEL_TYP, PACK_CONTENT_TYPE],
      [LABEL_KID, CURRENT.kid],
    ]),
  );
}

/** What `verifyPack` answers, which is the verdict a conforming reader owes the row. */
function verdictOf(one: Case): string {
  let read: VerifiedPack | null = null;
  let code = 'verify-ok';
  try {
    read = verifyPack(one.bytes, optionsFor(one.read));
  } catch (err) {
    if (err instanceof ReceiptError) {
      if (one.item !== undefined && !err.message.includes(one.item)) {
        throw new Error(`${one.name}: ${err.code} did not name the item this file says it names (${one.item})`);
      }
      return err.code;
    }
    throw new Error(`${one.name}: the reader raised something with no code (${String(err)})`);
  }
  // The accepted rows carry more than a word, so each of those is asked of the same reading: the order the
  // links reached, the steps where the stamps disagree, and the window the manifest states.
  const walked = (read?.outcome.walked ?? []).map((each) => each.item.id);
  if (one.walk === undefined) throw new Error(`${one.name}: an accepted row states no walk to compare`);
  if (walked.join(' ') !== one.walk.join(' ')) {
    throw new Error(`${one.name}: the walk reached ${walked.join(', ')}, which this file says is ${one.walk.join(', ')}`);
  }
  const ordering = read?.outcome.ordering ?? [];
  if (JSON.stringify(ordering) !== JSON.stringify(one.ordering ?? [])) {
    throw new Error(`${one.name}: the ordering finding is ${JSON.stringify(ordering)}, which this file says is ${JSON.stringify(one.ordering ?? [])}`);
  }
  if (one.span !== undefined && JSON.stringify(read?.outcome.span) !== JSON.stringify(one.span)) {
    throw new Error(`${one.name}: the window reported is ${JSON.stringify(read?.outcome.span)}, not ${JSON.stringify(one.span)}`);
  }
  return code;
}

/** What `decodePack` answers for the same bytes, with no key in hand. */
function structuralOf(one: Case): string {
  try {
    decodePack(one.bytes);
    return 'verify-ok';
  } catch (err) {
    if (err instanceof ReceiptError) return err.code;
    throw new Error(`${one.name}: the structural reader raised something with no code (${String(err)})`);
  }
}

function published(one: Case): Record<string, unknown> {
  return {
    name: one.name,
    note: one.note,
    documentBase64Url: toBase64Url(one.bytes),
    documentByteLength: one.bytes.length,
    read: one.read,
    verdict: one.verdict,
    structural: one.structural,
    ...(one.walk === undefined ? {} : { walk: one.walk }),
    ...(one.ordering === undefined ? {} : { ordering: one.ordering }),
    ...(one.span === undefined ? {} : { span: one.span }),
    ...(one.item === undefined ? {} : { item: one.item }),
    ...(one.edited === undefined ? {} : { edited: one.edited }),
  };
}

/**
 * The record framing of the honest run, published field by field. A reader recomputes each item's digest from
 * the bytes it was handed and compares the run against the two endpoints inside the signature, so the table is
 * the pack's own version of the images `chain-v1.json` publishes for a store file: the predecessor and the
 * digest that came out of it, for the receipt bytes the item carries.
 */
function recordTable(manifest: PackManifest): Record<string, unknown>[] {
  return manifest.items.map((one, index) => ({
    position: index,
    id: one.id,
    iat: one.iat,
    prevHex: toHex(one.prev),
    receiptByteLength: one.receipt.length,
    digestHex: toHex(packRecordDigest(one)),
  }));
}

function main() {
  // The piecewise path is only honest for the fault rows if it writes what the shipping writer writes, so that
  // is checked before a single case is: same header, same manifest, same key, same bytes.
  const header = encodePackProtectedHeader(CURRENT.kid);
  const payloadBytes = encodePackManifest(honestManifest);
  const piecewise = sealPack(header, payloadBytes, ed25519.sign(packSigStructure(header, payloadBytes), CURRENT.privateKey));
  if (toHex(piecewise) !== toHex(honestBytes)) {
    throw new Error('the piecewise envelope is not the one signPack writes');
  }
  // And a document that is meant to be refused cannot come out of the writer: a manifest whose span contradicts
  // one of its stamps is refused before a signature is made, which is why every fault row below is assembled
  // from the pieces rather than signed.
  let writerRefused = false;
  try {
    signPack(mutantManifest(), CURRENT);
  } catch (err) {
    writerRefused = err instanceof ReceiptError && err.code === 'PACK_BAD_MANIFEST';
  }
  if (!writerRefused) throw new Error('the pack writer signed a manifest that contradicts its own span');
  // The writer also refuses a key whose kid is not sha256 of its public half, so this suite carries no row for
  // a header naming an id that resolves to nothing: no deployment can seal one.
  let keyRefused = false;
  try {
    signPack(honestManifest, { ...CURRENT, kid: ZEROS });
  } catch (err) {
    keyRefused = err instanceof ReceiptError && err.code === 'BAD_SIGNING_KEY';
  }
  if (!keyRefused) throw new Error('the pack writer accepted a signing key whose kid is not its digest');

  for (const one of CASES) {
    const observed = verdictOf(one);
    if (observed !== one.verdict) {
      throw new Error(`${one.name}: the reader answers ${observed}, not the ${one.verdict} this file states`);
    }
    const structure = structuralOf(one);
    if (structure !== one.structural) {
      throw new Error(`${one.name}: the structural reader answers ${structure}, not the ${one.structural} this file states`);
    }
  }

  const names = CASES.map((one) => one.name);
  if (new Set(names).size !== names.length) throw new Error('two cases of this suite share a name');
  const accepted = CASES.filter((one) => one.verdict === 'verify-ok');
  if (accepted.length < 6) throw new Error(`${accepted.length} accepted rows, and the states a pack arrives in are more than that`);
  const refused = CASES.filter((one) => one.verdict !== 'verify-ok');
  if (refused.length < 10) throw new Error(`${refused.length} refusals, and the format names more faults than that`);
  const reported = CASES.filter((one) => (one.ordering?.length ?? 0) > 0);
  if (reported.length < 1) throw new Error('this suite publishes no pack whose two orders disagree');
  const unreached = CASES.filter((one) => one.verdict === 'PACK_ITEM_UNREACHED');
  if (unreached.length < 1) throw new Error('this suite publishes no pack that reaches its head with an item left over');

  writeFileSync(
    join(DATA, 'pack-v1.json'),
    JSON.stringify(
      {
        version: 1,
        description:
          'Evidence packs in the shapes a deployment hands them over in, the keys a reader designates beside each one, and the verdict the shipped pack reader owes: whole documents accepted with the run and the window reported apart, an honest pack whose stamps run against its links reported and not refused, and one refusal for every fault the format names.',
        layout: {
          format: 'packages/receipt/pack.cddl',
          twin: 'packages/receipt/schemas/pack-v1.schema.json',
          prose: 'docs/receipt-spec.md section 5.2',
          contentType: PACK_CONTENT_TYPE,
          writer:
            'signPack in @ashaveri/receipt, which every honest seal here went through, and encodePackManifest, encodePackProtectedHeader, packSigStructure and sealPack, which assembled the rows that writer refuses to sign',
          reader:
            'verifyPack in @ashaveri/receipt, which is the verdict column, and decodePack, which is the structural column and needs no key',
          headerLabels: { alg: LABEL_ALG, typ: LABEL_TYP, kid: LABEL_KID },
          headerCloses:
            'the protected header carries exactly the three labels above and no fourth, because its bytes are hashed into the signature; every map inside the payload closes the same way',
          sigStructure:
            'RFC 9052 section 4.4: the array ["Signature1", the protected bstr as written, the external AAD, the payload bstr], canonically encoded. The external AAD is empty for this container and nothing inside the envelope carries which one was used.',
          recordDigest:
            'sha256 over 0x00 || prev || iat as eight big-endian bytes || the byte length of id as two big-endian bytes || id || receipt bytes. Every integer in that input is unsigned and big-endian, which is the framing section 5.2 publishes and the images in chain-v1.json show.',
          chainRule:
            'the walk starts at the item whose prev is the signed anchor, recomputes each record digest from the bytes the item carries, and ends at the signed head; every item of the array has to be reached, which is the second half of the rule and the only one with eyes for a receipt parked beside a run it is not part of',
          spanRule:
            'the span is half-open, from included and to excluded, and both bounds bind every item. at is never before to, and duty.rev is never after at',
          dutyRule:
            'held is at least the age of the oldest receipt in this pack, measured at at. A held short of required is nothing of that kind: the document is whole and the reader states no verdict on the duty, because met is absent from the format on purpose',
          orderingRule:
            'the links fix the order of the run and an item iat is the stamp that record was chained under, and the two are free to disagree because the store chains under whatever stamp it was handed. A reader reports a disagreement on the result and never refuses it: the lawful output of a deployment that corrected its clock is a pack with the finding beside a clean walk',
          encodings: 'documents and byte strings unpadded base64url, digests, kids, predecessors and signatures lowercase hex, instants unix seconds',
          verdictFields: ['verdict', 'structural', 'walk', 'ordering', 'span', 'item', 'edited'],
          verdictMeaning:
            '`verdict` is what verifyPack answers under the designation the row states: `verify-ok`, or the code it throws. `structural` is what decodePack answers for the same bytes with no key, so a row that is `verify-ok` there and a refusal in `verdict` is refusing about a key or a signature and not about a manifest that contradicts itself. `walk` is the order the links reached and `ordering` the steps where the stamps disagree; both are published on every accepted row.',
          readFields:
            '`read.pinned` is the one key the caller holds, which designates the envelope and every receipt inside it. `read.retained` is the set a resolver answers from, one key per kid, which is how a span crossing a rotation is read. A row with neither is the call that designated nothing and is refused before a byte is read.',
          records: recordTable(honestManifest),
          codes: [...new Set(CASES.map((one) => one.verdict))].sort(),
          assembled:
            'every honest pack is `signPack` and no hand-built bytes. Where a row needs something that writer refuses to sign, the manifest is encoded, one position of its map is changed, and the result is signed over the published `Sig_structure` and sealed by `sealPack` under the key its header names; the generator stops unless that path reproduces `signPack` byte for byte on the canonical header, so each fault below is the one position its `edited` field names and nothing else. The writer is also asked to sign a manifest that contradicts its own span and a pack under a key whose kid is not sha256 of its public half, and refuses both, which is why this suite carries no row that a deployment could have produced by accident.',
          keyMaterial: KEY_MATERIAL.map((one) => ({
            id: toHex(one.key.kid).slice(0, 8),
            seed: one.seed,
            kidHex: toHex(one.key.kid),
            publicKeyHex: toHex(one.key.publicKey),
            publicKeyBase64Url: toBase64Url(one.key.publicKey),
            role: one.role,
          })),
          keyNote:
            'test-only, published so a port can produce these signatures itself rather than only checking them, and protecting nothing. The honest packs here are sealed by the same key the committed receipt fixtures are issued under, which is the key a deployment names in its manifest and the one a reader of a pack is handed for the receipts inside it.',
        },
        vectors: CASES.map(published),
        crossReading: {
          note: 'Four containers, one signing key, and each reader refusing the others\' document at its protected header before a key is consulted. The pack half of that pair is in the rows named `protected-content-type-*`; these are the pack document given to the reader of an export, which is the confusion the content type exists to prevent.',
          cases: [
            {
              name: 'pack-read-as-export',
              note: 'The honest pack, handed to the export reader under the key it names. The envelope decodes, the signature holds, and the typ is not the export\'s, so the answer is the header refusal rather than a manifest problem these bytes do not have.',
              documentBase64Url: toBase64Url(honestBytes),
              expected: exportRefusalOf(honestBytes),
            },
          ],
        },
      },
      null,
      2,
    ) + '\n',
  );

  for (const one of CASES) console.log(`${one.name}: ${one.structural} -> ${one.verdict}`);
}

/** A manifest whose manifest-level stamps disagree with the span, which is the class the writer refuses to sign. */
function mutantManifest(): PackManifest {
  return { ...honestManifest, at: SPAN_TO - 1 };
}

/** The export reader's own answer to a pack, witnessed rather than asserted. */
function exportRefusalOf(bytes: Uint8Array): string {
  try {
    verifyExport(bytes, CURRENT.publicKey);
    return 'verify-ok';
  } catch (err) {
    if (err instanceof ReceiptError) return err.code;
    throw new Error(`the export reader raised something with no code: ${String(err)}`);
  }
}

main();
