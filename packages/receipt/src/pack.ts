import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha2.js';
import { Tag } from 'cbor2';
import { decodeCanonical, decodeClosedDocument, decodedMap, encodeCanonical } from './cbor.js';
import {
  ALG_EDDSA,
  COSE_HEADER_ALG,
  COSE_HEADER_CONTENT_TYPE,
  COSE_HEADER_KID,
  COSE_SIGN1_TAG,
  equalBytes,
  keyId,
  type CoseSign1,
  type ProtectedHeader,
} from './cose.js';
import { ReceiptError } from './errors.js';
import { verifyReceipt, type VerifiedReceipt } from './receipt.js';

/**
 * The reader of an evidence pack: what `packages/receipt/pack.cddl` states, run.
 *
 * A receipt attests one response. A pack attests that the responses inside one window are all of them, and
 * carries the two chain endpoints a reader walks between. This module reads that container and answers three
 * questions about it, separately: whether the bytes are a well-formed pack, whether the key it was handed
 * signed them, and whether the receipts inside walk from the anchor the manifest names to the head it names.
 * It is a checker and not a verdict engine. It answers nothing about a legal duty, nothing about whether the
 * deployment still holds anything else, and nothing about freshness, and it resolves nothing: a verification
 * key arrives as an argument and no code path here reaches a network, a filesystem or a key directory.
 *
 * The two findings a reader takes away are kept apart on purpose, because merging them is the defect this
 * container exists to make impossible. A reproduced walk shows that nothing between the first item and the
 * last is missing, and the span is what shows whether the run it covers is the period somebody asked for.
 * `decodePack` answers what is true of the document whoever signed it, and `verifyPack` adds what is only
 * true against a signature a reader has accepted, which is the same split `export.ts` makes.
 *
 * Two things this reader deliberately does not do are decisions rather than gaps. It does not enforce that the
 * `unprotected` map is empty and reads nothing out of it: the format declares that map as the one a signer
 * fills at will, outside the signature, carrying no claim about the span. And it does not compare `held` with
 * `required`, because `pack.cddl` leaves `met` out so that a deployment signs evidence rather than its own
 * conclusion; the arithmetic belongs to whoever holds the duty mapping, and both integers are handed back
 * untouched.
 *
 * There is no writer here, which is the format's own order: nothing in this repository assembles a pack, and a
 * document meant to be refused cannot come out of a function that signs it first. The framing helpers below,
 * `packSigStructure` and `packRecordDigest`, are the bytes a signature and a digest are taken over, published
 * because a reimplementer who cannot see them cannot compare two readers' refusals.
 */

/** The content type that keeps a pack from being read as a receipt or as an export, at label 3. */
export const PACK_CONTENT_TYPE = 'ashaveri/pack';

/**
 * The three labels `pack.cddl` declares for a signed pack header, exported for the same reason `cose.ts`
 * exports its own list: which labels exist is the format's answer, and only a reader of both the file and
 * this list can see that the two are one answer.
 */
export const DECLARED_PACK_PROTECTED_LABELS: readonly number[] = [
  COSE_HEADER_ALG,
  COSE_HEADER_CONTENT_TYPE,
  COSE_HEADER_KID,
];

/**
 * The member list of every map this format closes, in the order the CDDL declares them. Exported for a test
 * to hold against the blocks rather than against this file's reading of them, and exported from `pack.ts`
 * alone: the package's public surface gains the reader, not a roster.
 */
export const PACK_MANIFEST_MEMBERS = ['v', 'at', 'span', 'chain', 'duty', 'items'] as const;
export const PACK_SPAN_MEMBERS = ['from', 'to'] as const;
export const PACK_CHAIN_MEMBERS = ['anchor', 'head'] as const;
export const PACK_DUTY_MEMBERS = ['art', 'rev', 'required', 'held'] as const;
export const PACK_ITEM_MEMBERS = ['id', 'iat', 'prev', 'receipt'] as const;

export interface PackSpan {
  /** unix seconds, included. */
  readonly from: number;
  /** unix seconds, excluded. */
  readonly to: number;
}

export interface PackChain {
  /** The digest the first item was chained from, or thirty-two zero bytes before any retirement. */
  readonly anchor: Uint8Array;
  /** The digest of the last item in the chain. */
  readonly head: Uint8Array;
}

export interface PackDuty {
  /**
   * A label from the retention-duty registry, which this format declares a `tstr` rather than an enum. This
   * reader checks that it is a text string and nothing else about it, which is the narrower of the two
   * readings available to a package that publishes no registry of its own; see the note on `duty` below.
   */
  readonly art: string;
  /** unix seconds, the revision of the mapping `required` was read from. */
  readonly rev: number;
  /** seconds that revision required. No default is supplied here, because the period is the deployment's statement. */
  readonly required: number;
  /** seconds the store has held the oldest receipt it retains, measured at `at`. */
  readonly held: number;
}

export interface PackItem {
  /** The store's own id for the receipt, as the record names it. */
  readonly id: string;
  /** unix seconds, the stamp the record was chained at. */
  readonly iat: number;
  /** The digest of the record before it, or the anchor for the first item. */
  readonly prev: Uint8Array;
  /** The signed receipt bytes, whole and unaltered. */
  readonly receipt: Uint8Array;
}

export interface PackManifest {
  readonly v: 1;
  readonly at: number;
  readonly span: PackSpan;
  readonly chain: PackChain;
  readonly duty: PackDuty;
  readonly items: readonly PackItem[];
}

/** One item, beside the receipt its bytes were verified into. */
export interface VerifiedPackItem {
  readonly item: PackItem;
  readonly receipt: VerifiedReceipt;
}

/**
 * The two findings, in two fields. `walked` is the run the chain establishes, in the order the links put it
 * in and never the order it arrived; `span` is the manifest's own statement of the window it answers for, and
 * it is the same object the manifest carries rather than a second reading of it. A caller that prints one of
 * these two fields as though it were the other is reporting that a deployment was short of evidence because
 * its chain closed, which is the conflation this shape refuses to make easy.
 */
export interface PackOutcome {
  readonly walked: readonly VerifiedPackItem[];
  readonly span: PackSpan;
}

export interface DecodedPack {
  readonly manifest: PackManifest;
  readonly header: ProtectedHeader;
  readonly envelope: CoseSign1;
}

export interface VerifiedPack extends DecodedPack {
  readonly outcome: PackOutcome;
}

const encoder = new TextEncoder();

/** The widths the format writes beside each position, named once rather than per check site. */
const DIGEST_BYTES = 32;
const SIGNATURE_BYTES = 64;
const ID_MAX_BYTES = 65_535;
/** The framing's own two byte count of an id, which is why the ceiling above is 65535 and not larger. */
const ID_LENGTH_BYTES = 2;
const IAT_BYTES = 8;

function badManifest(detail: string): ReceiptError {
  return new ReceiptError('PACK_BAD_MANIFEST', detail);
}

/** How a map key names itself back in a refusal, without leaning on an object's default rendering. */
function memberName(key: unknown): string {
  if (typeof key === 'string') return `'${key}'`;
  if (key instanceof Uint8Array) return `a bstr key of length ${key.length}`;
  if (typeof key === 'number' || typeof key === 'bigint') return `the numeric key ${String(key)}`;
  return 'a key that is not a text label';
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (one) => one.toString(16).padStart(2, '0')).join('');
}

interface DefinedMap {
  readonly members: readonly string[];
  readonly nested?: Readonly<Record<string, DefinedMap>>;
}

/**
 * The closedness rule, applied to one map and then to the maps it opens. A member no position of this version
 * defines makes the document malformed rather than a member a reader agreed to forget, and the walk has to
 * reach the maps a document actually opened: a `span` whose bounds were read and then dropped on the way to a
 * verifier is the silence the rule exists to refuse. A value the format makes an array of maps is closed at its
 * elements rather than at the array, which is the items' case and is handled by the reader of that array.
 */
function assertDefined(raw: Map<unknown, unknown>, members: readonly string[], where: string, nested: Readonly<Record<string, DefinedMap>> = {}): void {
  for (const [key, value] of raw) {
    if (typeof key !== 'string' || !members.includes(key)) {
      throw badManifest(`${where} carries a member this version does not define: ${memberName(key)}`);
    }
    const inner = nested[key];
    if (inner === undefined) continue;
    const nestedMap = decodedMap(value);
    // A value the format makes a map and is not one is the member read's answer, not this walk's: refusing it
    // here would report a membership problem at a position whose type has not been read.
    if (nestedMap !== null) assertDefined(nestedMap, inner.members, `${where}.${key}`, inner.nested);
  }
}

/**
 * The whole `Sig_structure` of this container, exactly as RFC 9052 section 4.4 frames it and as `cose.ts`
 * frames a receipt's: the context string, the protected bstr, the external AAD and the payload bstr,
 * canonically encoded. This reader verifies with an empty AAD, which is what `pack.cddl` describes a pack as
 * carrying, and publishes the framing so a stranger can see which bytes a pack's signature covers.
 */
export function packSigStructure(
  protectedBytes: Uint8Array,
  payloadBytes: Uint8Array,
  externalAad: Uint8Array = new Uint8Array(0),
): Uint8Array {
  return encodeCanonical(['Signature1', protectedBytes, externalAad, payloadBytes]);
}

/**
 * The framing a chained item's record digest is taken over, which is section 5.2 of `docs/receipt-spec.md`
 * and the images in `packages/fixtures/data/chain-v1.json`, and nothing of this file's own: kind byte 0, the
 * predecessor digest, `iat` as eight big-endian bytes, the byte length of the id as two big-endian bytes, the
 * id, and the receipt bytes. No length prefix and no copy of the digest itself are inside the hash, which is
 * what the store's frame adds around it and a recomputation never sees.
 */
export function packRecordDigest(item: {
  readonly id: string;
  readonly iat: number;
  readonly prev: Uint8Array;
  readonly receipt: Uint8Array;
}): Uint8Array {
  if (item.prev.length !== DIGEST_BYTES) {
    throw badManifest(`a predecessor of ${item.prev.length} bytes, where the format declares ${DIGEST_BYTES}`);
  }
  const id = encoder.encode(item.id);
  if (id.length === 0 || id.length > ID_MAX_BYTES) {
    throw badManifest(`an id of ${id.length} bytes, outside the 1..${ID_MAX_BYTES} the format declares`);
  }
  const input = new Uint8Array(1 + DIGEST_BYTES + IAT_BYTES + ID_LENGTH_BYTES + id.length + item.receipt.length);
  const view = new DataView(input.buffer);
  input[0] = 0;
  input.set(item.prev, 1);
  view.setBigUint64(1 + DIGEST_BYTES, BigInt(item.iat));
  view.setUint16(1 + DIGEST_BYTES + IAT_BYTES, id.length);
  input.set(id, 1 + DIGEST_BYTES + IAT_BYTES + ID_LENGTH_BYTES);
  input.set(item.receipt, 1 + DIGEST_BYTES + IAT_BYTES + ID_LENGTH_BYTES + id.length);
  return sha256(input);
}

function recordDigest(record: VerifiedPackItem): Uint8Array {
  return packRecordDigest(record.item);
}

function requireText(value: unknown, position: string, maxBytes: number): string {
  if (typeof value !== 'string') throw badManifest(`${position} must be a tstr`);
  const bytes = encoder.encode(value).length;
  if (bytes < 1 || bytes > maxBytes) {
    throw badManifest(`${position} must be between 1 and ${maxBytes} bytes, got ${bytes}`);
  }
  return value;
}

/**
 * A unix time, which the format types `int` and bounds with a rule about meaning rather than about type: no
 * instant it names lies before the epoch. A reader that let a negative stamp through would be accepting a
 * document whose quantities it cannot compare with the ones the rest of the manifest states.
 */
function requireStamp(value: unknown, position: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw badManifest(`${position} must be a unix time no earlier than the epoch`);
  }
  return value;
}

/**
 * A duration, which is the other half of the same sentence: a whole number of seconds no smaller than zero.
 * A negative `held` is a malformed document rather than an unusual way of writing a quantity, and the decode
 * this value arrives through has already refused the floating-point spelling of it.
 */
function requireDuration(value: unknown, position: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw badManifest(`${position} must be a whole number of seconds no smaller than zero`);
  }
  return value;
}

function requireDigest(value: unknown, position: string): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== DIGEST_BYTES) {
    throw badManifest(`${position} must be a ${DIGEST_BYTES}-byte bstr`);
  }
  return value;
}

/**
 * The signed header. Read under the rule the format sets for this map, which closes its labels as well as its
 * values: a label written as the float `1.0` takes the same map slot as the integer `1`, so the two spellings
 * are indistinguishable by the time anything could ask which one the issuer signed.
 *
 * The content type is answered before the key parameters of the header are. That order is the whole reason the
 * four signed containers carry four content types: a reader that reported a `kid` of the wrong width, or an
 * unsupported suite, about a document that is not a pack at all would be describing a parameter of a container
 * it should never have opened, and the mistake a content type exists to prevent is reading another document as
 * this one, which is not recoverable afterwards because both of them pass their own checks.
 */
function readHeader(bytes: Uint8Array): ProtectedHeader {
  const raw = decodedMap(decodeClosedDocument(bytes, 'PACK_BAD_HEADER'));
  if (raw === null) throw new ReceiptError('PACK_BAD_HEADER', 'not a map');
  for (const label of raw.keys()) {
    if (!(DECLARED_PACK_PROTECTED_LABELS as readonly unknown[]).includes(label)) {
      throw new ReceiptError('PACK_BAD_HEADER', `it carries a label the format does not define: ${memberName(label)}`);
    }
  }
  const contentType = raw.get(COSE_HEADER_CONTENT_TYPE);
  if (typeof contentType !== 'string') {
    throw new ReceiptError('PACK_BAD_HEADER', `typ must be a tstr, got ${typeof contentType}`);
  }
  if (contentType !== PACK_CONTENT_TYPE) {
    throw new ReceiptError('PACK_BAD_HEADER', `typ=${contentType}`);
  }
  const alg = raw.get(COSE_HEADER_ALG);
  if (typeof alg !== 'number') throw new ReceiptError('UNSUPPORTED_ALG', `alg must be an integer label, got ${typeof alg}`);
  if (alg !== ALG_EDDSA) throw new ReceiptError('UNSUPPORTED_ALG', `alg=${alg}`);
  const kid = raw.get(COSE_HEADER_KID);
  if (!(kid instanceof Uint8Array) || kid.length !== DIGEST_BYTES) {
    throw new ReceiptError('PACK_BAD_HEADER', 'kid must be a 32-byte bstr');
  }
  return { alg: ALG_EDDSA, kid, contentType };
}

/**
 * The envelope, and the header read inside it. The `unprotected` map is decoded under the rule that admits
 * anything, because it sits outside the signature and carries no claim: a floating-point number inside it is
 * nobody's integer wearing a different coat, and nothing here reads a value out of it.
 */
function readEnvelope(bytes: Uint8Array): CoseSign1 & { header: ProtectedHeader } {
  const top = decodeCanonical(bytes, 'PACK_MALFORMED_CBOR');
  if (!(top instanceof Tag) || top.tag !== COSE_SIGN1_TAG) {
    throw new ReceiptError('NOT_COSE_SIGN1', 'missing CBOR tag 18');
  }
  const arr = top.contents;
  if (!Array.isArray(arr) || arr.length !== 4) throw new ReceiptError('NOT_COSE_SIGN1', 'not a 4-element array');
  const [protectedBytes, unprotectedMap, payloadBytes, signature] = arr as unknown[];
  if (!(protectedBytes instanceof Uint8Array)) throw new ReceiptError('NOT_COSE_SIGN1', 'protected is not a bstr');
  const unprotected = decodedMap(unprotectedMap);
  if (unprotected === null) throw new ReceiptError('NOT_COSE_SIGN1', 'unprotected is not a map');
  if (!(payloadBytes instanceof Uint8Array)) throw new ReceiptError('NOT_COSE_SIGN1', 'payload is not a bstr');
  if (!(signature instanceof Uint8Array) || signature.length !== SIGNATURE_BYTES) {
    throw new ReceiptError('NOT_COSE_SIGN1', `signature is not a ${SIGNATURE_BYTES}-byte bstr`);
  }
  return { protectedBytes, unprotected, payloadBytes, signature, header: readHeader(protectedBytes) };
}

function readSpan(raw: Map<unknown, unknown>, at: number): PackSpan {
  const from = requireStamp(raw.get('from'), 'span.from');
  const to = requireStamp(raw.get('to'), 'span.to');
  // `at` never before `to`. A window whose end has not arrived is still receiving, and a deployment that began
  // its reads inside the span it is answering for signed a completeness nobody was in a position to have at
  // that instant. Both stamps are inside one signature, so a disagreement is the document contradicting itself
  // and not a deployment that misremembered, which is the distinction the container exists to keep decidable.
  if (at < to) throw badManifest(`assembly began at ${at}, before the span closed at ${to}`);
  return { from, to };
}

function readChain(raw: Map<unknown, unknown>): PackChain {
  return {
    anchor: requireDigest(raw.get('anchor'), 'chain.anchor'),
    head: requireDigest(raw.get('head'), 'chain.head'),
  };
}

/**
 * The duty this pack answers, read and not judged.
 *
 * `rev` is never after `at`, because a mapping revision that lands after the reads began is not the revision
 * the period was read from: that is one contradiction between two signed members, and it is refused. What is
 * refused nowhere here is a `held` short of a `required`, which is nothing of that kind. The document is
 * whole, the arithmetic comes out the way it comes out, and the duty is not met; whether it was ever owed at
 * all turns on the mapping `rev` names and on the law behind it, which this package does not interpret. So no
 * comparison of those two integers happens below, and the reader has no opinion to hand back about them.
 */
function readDuty(raw: Map<unknown, unknown>, at: number): PackDuty {
  const art = raw.get('art');
  if (typeof art !== 'string') throw badManifest('duty.art must be a tstr');
  const rev = requireStamp(raw.get('rev'), 'duty.rev');
  const required = requireDuration(raw.get('required'), 'duty.required');
  const held = requireDuration(raw.get('held'), 'duty.held');
  if (rev > at) throw badManifest(`the mapping revision ${rev} postdates the reads at ${at}`);
  return { art, rev, required, held };
}

/**
 * The items, closed element by element and then bounded by the span that answers for them.
 *
 * `[+ …]` requires at least one item, and the reason is not tidiness: a pack of nothing has no first node, so
 * its walk is vacuous, and a reader could check only that the head equals the anchor and be handed an artifact
 * that reads as evidence while proving that somebody signed two digests. That a window held no receipts at all
 * is a statement about the window, and it belongs to the artifact that states windows.
 *
 * Both bounds bind every item, which is a rule and not a tendency, and it is refused here rather than reported
 * as a shortage: the set the rule states is the set the store's own range query serves for the same two
 * stamps, so a pack carrying a receipt stamped outside its span is two signed members contradicting each
 * other. Read the other way, every inconvenient window would arrive as a formatting error and every formatting
 * error as a verdict about the deployment, which is the pair of mistakes a third party reads these bytes in
 * order not to make.
 */
function readItems(raw: unknown, span: PackSpan): readonly PackItem[] {
  if (!Array.isArray(raw)) throw badManifest('items must be an array');
  if (raw.length === 0) throw badManifest('a pack declares a non-empty items and carries none');
  const items = raw.map((one, index) => readItem(one, `items[${index}]`));
  for (const one of items) {
    if (one.iat < span.from || one.iat >= span.to) {
      throw badManifest(`${one.id} is stamped ${one.iat}, outside the span ${span.from} to ${span.to}`);
    }
  }
  const seen = new Set<string>();
  for (const one of items) {
    // A refusal names an item, and two items answering to one name make that report mean whichever of the two
    // a reader happened to meet first. The links order the items and the name identifies them, and neither of
    // those is a matter of arrival.
    if (seen.has(one.id)) throw new ReceiptError('PACK_DUPLICATE_ID', one.id);
    seen.add(one.id);
  }
  return items;
}

function readItem(raw: unknown, position: string): PackItem {
  const map = decodedMap(raw);
  if (map === null) throw badManifest(`${position} must be a map`);
  assertDefined(map, PACK_ITEM_MEMBERS, position);
  const receipt = map.get('receipt');
  if (!(receipt instanceof Uint8Array)) throw badManifest(`${position}.receipt must be a bstr`);
  return {
    id: requireText(map.get('id'), `${position}.id`, ID_MAX_BYTES),
    iat: requireStamp(map.get('iat'), `${position}.iat`),
    prev: requireDigest(map.get('prev'), `${position}.prev`),
    receipt,
  };
}

/**
 * The `held` floor, which is the one statement in the manifest about the store as a whole that the container
 * carrying it can check. A pack covers one span and the duty runs against everything still held, so the oldest
 * receipt in the container need not be the oldest one retained; what follows from being in here at all is that
 * the store held it, so a figure below the age of the oldest item contradicts the pack the same way a stamp
 * outside the span does, and is refused the same way.
 */
function assertHeldCoversItems(manifest: PackManifest): void {
  const oldest = Math.min(...manifest.items.map((one) => one.iat));
  const floor = manifest.at - oldest;
  if (manifest.duty.held < floor) {
    throw badManifest(
      `the pack states ${manifest.duty.held} seconds held at ${manifest.at} and carries a receipt stamped ${oldest}, ${floor} seconds old`,
    );
  }
}

function parseManifest(bytes: Uint8Array): PackManifest {
  const raw = decodedMap(decodeClosedDocument(bytes, 'PACK_BAD_MANIFEST'));
  if (raw === null) throw badManifest('payload is not a map');
  const version = raw.get('v');
  if (typeof version !== 'number' || !Number.isInteger(version)) {
    throw badManifest('v must be an integer pack version');
  }
  if (version !== 1) {
    throw new ReceiptError('PACK_UNSUPPORTED_VERSION', `pack manifest version ${version} is not a format this package reads`);
  }
  assertDefined(raw, PACK_MANIFEST_MEMBERS, 'manifest', {
    span: { members: PACK_SPAN_MEMBERS },
    chain: { members: PACK_CHAIN_MEMBERS },
    duty: { members: PACK_DUTY_MEMBERS },
  });
  const spanMap = decodedMap(raw.get('span'));
  const chainMap = decodedMap(raw.get('chain'));
  const dutyMap = decodedMap(raw.get('duty'));
  if (spanMap === null) throw badManifest('span must be a map');
  if (chainMap === null) throw badManifest('chain must be a map');
  if (dutyMap === null) throw badManifest('duty must be a map');
  const at = requireStamp(raw.get('at'), 'at');
  const span = readSpan(spanMap, at);
  const manifest: PackManifest = {
    v: 1,
    at,
    span,
    chain: readChain(chainMap),
    duty: readDuty(dutyMap, at),
    items: readItems(raw.get('items'), span),
  };
  assertHeldCoversItems(manifest);
  return manifest;
}

/**
 * A manifest read and a signature not yet checked: shape, version, closure, widths, the epoch and zero floors,
 * the span's bound on every item, the two stamps that order themselves against `at`, unique names and the one
 * item the format refuses to be without. None of it needs a key to be true, so a document that contradicts
 * itself is refused whoever signed it.
 */
export function decodePack(bytes: Uint8Array): DecodedPack {
  const envelope = readEnvelope(bytes);
  return { manifest: parseManifest(envelope.payloadBytes), header: envelope.header, envelope };
}

/**
 * Every original, checked as an original. The bytes an item carries have to parse and verify under the key the
 * manifest's own header designates, which is the same key the pack was just verified under, and the stamp the
 * record was chained with has to equal the `iat` the receipt inside it attests.
 *
 * Those two statements are the store's own and this reader does not merge them into one. It chains a receipt
 * under the stamp it was handed, so a reader who checked the walk and not the equality would accept a receipt
 * moved into a window it was never issued in, which is why the equality is part of the walk rather than a
 * courtesy beside it. A refusal out of a receipt keeps that receipt's own code, because the fault is a property
 * of that document and the sentence naming it says receipt; the item it belongs to rides along in the detail,
 * which is what makes the report about this pack rather than about a receipt in isolation.
 */
function checkOriginals(items: readonly PackItem[], publicKey: Uint8Array): VerifiedPackItem[] {
  return items.map((item) => {
    let receipt: VerifiedReceipt;
    try {
      receipt = verifyReceipt(item.receipt, { publicKey });
    } catch (err) {
      if (err instanceof ReceiptError) {
        throw new ReceiptError('PACK_RECEIPT_INVALID', `${item.id} answers ${err.code}: ${err.message}`);
      }
      throw new ReceiptError('PACK_RECEIPT_INVALID', `${item.id}: ${err instanceof Error ? err.message : String(err)}`);
    }
    if (receipt.payload.iat !== item.iat) {
      throw new ReceiptError(
        'PACK_RECEIPT_STAMP_MISMATCH',
        `${item.id} is chained under ${item.iat} and its receipt attests ${receipt.payload.iat}`,
      );
    }
    return { item, receipt };
  });
}

/**
 * The walk, over the links and not over the array: begin at the item whose predecessor is the anchor,
 * recompute each record's digest from what the item carries, and take the unvisited item naming that digest as
 * its predecessor. Two halves, both refused by name, because the links alone cannot see a receipt parked
 * beside a span it is not part of: the run from the anchor to the head, and the count of what that run reached
 * against the array that was handed over. A verifier that implements one half has implemented half a rule.
 */
function walk(records: readonly VerifiedPackItem[], anchor: Uint8Array, head: Uint8Array): VerifiedPackItem[] {
  const walked: VerifiedPackItem[] = [];
  const visited = new Set<string>();
  let cursor = anchor;
  for (;;) {
    const candidates = records.filter((one) => !visited.has(one.item.id) && equalBytes(one.item.prev, cursor));
    if (candidates.length > 1) {
      throw new ReceiptError(
        'PACK_CHAIN_BROKEN',
        `${candidates.length} items name the same predecessor, so the run forks at ${candidates.map((one) => one.item.id).join(', ')}`,
      );
    }
    const next = candidates[0];
    if (next === undefined) break;
    visited.add(next.item.id);
    walked.push(next);
    cursor = recordDigest(next);
  }
  if (!equalBytes(cursor, head)) {
    throw new ReceiptError(
      'PACK_CHAIN_BROKEN',
      `the walk reached ${walked.length} item(s) and stopped at a digest that is not the head`,
    );
  }
  const unreached = records.filter((one) => !visited.has(one.item.id));
  if (unreached.length > 0) {
    throw new ReceiptError('PACK_ITEM_UNREACHED', unreached.map((one) => one.item.id).join(', '));
  }
  return walked;
}

/**
 * Verify a pack: the envelope and its content type, then the key designation and the signature over the
 * `Sig_structure` this format frames, then the structure of the manifest, then every original, then the walk.
 *
 * The order is what keeps a report honest. A document that is not a pack is refused before its bytes are
 * compared with any key, because a pack's manifest and a receipt's payload are two documents that both pass
 * their own checks. Structure comes before the originals because a manifest that contradicts itself does so
 * whoever signed it, and the originals before the walk because a run that closes across receipts nobody can
 * verify is a chain finding those bytes did not earn.
 *
 * What this answers and what it does not are two different things, and the returned shape says so. A
 * reproduced walk shows that nothing between the first item and the last is missing; it does not show that the
 * run covered the period somebody asked for, and it does not show that the deployment still holds anything
 * else, because the head makes deletion detectable against a copy a reader held from before and this reader is
 * not handed one. `outcome.span` is the manifest's own statement of the window, and comparing it with the
 * window you wanted is the other half of the verdict; `manifest.duty` is the deployment's statement of the
 * period it answers to, and the comparison the format leaves out is left out here too.
 */
export function verifyPack(bytes: Uint8Array, publicKey: Uint8Array): VerifiedPack {
  const envelope = readEnvelope(bytes);
  if (!equalBytes(envelope.header.kid, keyId(publicKey))) {
    throw new ReceiptError('PACK_KID_MISMATCH', `header kid=${toHex(envelope.header.kid)} key kid=${toHex(keyId(publicKey))}`);
  }
  if (
    !ed25519.verify(
      envelope.signature,
      packSigStructure(envelope.protectedBytes, envelope.payloadBytes),
      publicKey,
      { zip215: false },
    )
  ) {
    throw new ReceiptError('INVALID_SIGNATURE');
  }
  const manifest = parseManifest(envelope.payloadBytes);
  const walked = walk(checkOriginals(manifest.items, publicKey), manifest.chain.anchor, manifest.chain.head);
  return {
    manifest,
    header: envelope.header,
    envelope,
    outcome: { walked, span: manifest.span },
  };
}
