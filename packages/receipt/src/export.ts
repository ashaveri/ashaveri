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
  buildProtectedHeader,
  equalBytes,
  keyId,
  sealCoseSign1,
  type CoseSign1,
  type ProtectedHeader,
  type SigningKey,
} from './cose.js';
import { ReceiptError } from './errors.js';
import { packRecordDigest } from './pack.js';

/**
 * The reader of a technical export: what `packages/receipt/export.cddl` states, run.
 *
 * This is a checker and not a verdict engine. It answers whether the bytes are a well-formed export,
 * whether the key it was handed signed them, whether each item's original hashes to the digest beside it,
 * and whether an anchored collection walks from the anchor it names to the head it names. It answers
 * nothing about a legal duty, nothing about whether the material is complete at its source, and nothing
 * about whether it is fresh, and the codes that could be misread as such a verdict are marked below as
 * saying which of three different things happened: `EXPORT_BAD_MANIFEST` is a document that contradicts
 * itself, `EXPORT_ORIGINAL_UNAVAILABLE` is a reader that was handed too little, and
 * `EXPORT_ENDPOINT_MISMATCH` is a reader that was holding something else.
 *
 * It resolves nothing. A verification key, a companion file's bytes and the endpoints a caller already
 * has cause to believe all arrive as arguments, so no code path here reaches a network, a filesystem or a
 * key directory, and a reader reports only on what it was handed. That is the whole reason the companion
 * arm of `orig` refuses to be checked silently: an absent companion is told to the caller by name rather
 * than passed over, because a handover that reported on material it never looked at is the defect this
 * container exists not to have.
 *
 * Two entry points, split where the pack's prose splits evidence from claim. `decodeExport` checks
 * structure and needs no key, because a document that contradicts itself does so whoever signed it;
 * `verifyExport` adds the signature, the digests, the walk and the caller's own endpoints, which are the
 * checks that mean something only against a signature the reader has accepted.
 */

/** The content type that keeps an export from being read as a receipt or as a pack, at label 3. */
export const EXPORT_CONTENT_TYPE = 'ashaveri/export';

/**
 * The three labels `export.cddl` declares for a signed export header, exported for the same reason
 * `cose.ts` exports its own list: which labels exist is the format's answer, and only a reader of both
 * the file and this list can see that the two are one answer.
 */
export const DECLARED_EXPORT_PROTECTED_LABELS: readonly number[] = [
  COSE_HEADER_ALG,
  COSE_HEADER_CONTENT_TYPE,
  COSE_HEADER_KID,
];

/** The two assertions a claim can make about a material's history, and neither is a legal category. */
export const EXPORT_CLAIM_KINDS = ['provenance', 'custody'] as const;

export type ExportClaimKind = (typeof EXPORT_CLAIM_KINDS)[number];

export function isExportClaimKind(value: unknown): value is ExportClaimKind {
  return typeof value === 'string' && (EXPORT_CLAIM_KINDS as readonly string[]).includes(value);
}

/**
 * The member lists of every map this format closes, in the order the CDDL declares them. Exported for a
 * test to hold against the blocks rather than against this file's reading of them, and exported from
 * `export.ts` alone: the package's public surface is what it was before this container existed.
 */
export const EXPORT_MANIFEST_MEMBERS = ['v', 'at', 'assessment', 'collection', 'claim'] as const;
export const EXPORT_ASSESSMENT_MEMBERS = ['k', 'states'] as const;
export const EXPORT_CLAIM_MEMBERS = ['made', 'by', 'kind', 'states'] as const;
export const EXPORT_ANCHORED_MEMBERS = ['k', 'anchor', 'head', 'items'] as const;
export const EXPORT_PLAIN_MEMBERS = ['k', 'items'] as const;
export const EXPORT_VOID_MEMBERS = ['k', 'states'] as const;
export const EXPORT_ITEM_MEMBERS = ['id', 'iat', 'd', 'orig'] as const;
export const EXPORT_CHAINED_ITEM_MEMBERS = ['id', 'iat', 'd', 'p', 'orig'] as const;
export const EXPORT_INLINE_MEMBERS = ['k', 'bytes'] as const;
export const EXPORT_COMPANION_MEMBERS = ['k', 'name'] as const;

/** The labels that choose a shape, at the three positions that carry one. */
export const EXPORT_COLLECTION_ARMS = ['anchored', 'plain', 'void'] as const;
export const EXPORT_ORIGINAL_ARMS = ['inline', 'companion'] as const;
export const EXPORT_ASSESSMENT_ARMS = ['none'] as const;

export interface ExportInlineOriginal {
  readonly k: 'inline';
  readonly bytes: Uint8Array;
}

export interface ExportCompanionOriginal {
  readonly k: 'companion';
  readonly name: string;
}

export type ExportOriginal = ExportInlineOriginal | ExportCompanionOriginal;

export interface ExportItem {
  readonly id: string;
  readonly iat: number;
  /** sha256 of the exact original bytes, whether they travel inline or beside the document. */
  readonly d: Uint8Array;
  readonly orig: ExportOriginal;
}

/** An item of an anchored collection, which also names the digest its record was chained from. */
export interface ExportChainedItem extends ExportItem {
  readonly p: Uint8Array;
}

export interface ExportAssessment {
  readonly k: 'none';
  readonly states: string;
}

export interface ExportClaim {
  readonly made: number;
  readonly by: string;
  readonly kind: ExportClaimKind;
  readonly states: string;
}

export interface ExportAnchoredCollection {
  readonly k: 'anchored';
  readonly anchor: Uint8Array;
  readonly head: Uint8Array;
  readonly items: readonly ExportChainedItem[];
}

export interface ExportPlainCollection {
  readonly k: 'plain';
  readonly items: readonly ExportItem[];
}

/** The explicit empty outcome: no items, and the writer's own sentence saying so. */
export interface ExportVoidCollection {
  readonly k: 'void';
  readonly states: string;
}

export type ExportCollection = ExportAnchoredCollection | ExportPlainCollection | ExportVoidCollection;

export interface ExportManifest {
  readonly v: 1;
  readonly at: number;
  readonly assessment: ExportAssessment;
  readonly collection: ExportCollection;
  readonly claim: ExportClaim;
}

export interface ExportVerifyOptions {
  /**
   * The bytes of companion files the reader was given, keyed by the name the item uses. A name with no
   * entry here is refused rather than skipped, and an entry no item names is left alone: this is what the
   * reader was handed, not what it was told to find.
   */
  readonly companions?: ReadonlyMap<string, Uint8Array>;
  /** An anchor the reader already has cause to believe, compared against the signed one. */
  readonly expectedAnchor?: Uint8Array;
  /** A head the reader already has cause to believe, compared against the signed one. */
  readonly expectedHead?: Uint8Array;
}

export interface DecodedExport {
  readonly manifest: ExportManifest;
  readonly header: ProtectedHeader;
  readonly envelope: CoseSign1;
}

/**
 * What a verified export says about the material it carries. The void arm of a collection reports itself
 * as the emptiness it states and carries no items and no walk, so a caller cannot print a count of
 * verified material it was not given, which is the rule that keeps an empty export from reading as a
 * successful one.
 */
export type ExportRead =
  | { readonly kind: 'anchored'; readonly items: readonly ExportChainedItem[]; readonly walked: readonly ExportChainedItem[] }
  | { readonly kind: 'plain'; readonly items: readonly ExportItem[] }
  | { readonly kind: 'void'; readonly states: string };

export interface VerifiedExport extends DecodedExport {
  readonly outcome: ExportRead;
}

const encoder = new TextEncoder();

/** The widths the format writes beside each position, named once rather than per check site. */
const DIGEST_BYTES = 32;
const SIGNATURE_BYTES = 64;
const ID_MAX_BYTES = 65_535;
const NAME_MAX_BYTES = 255;
const ASSESSMENT_STATES_MAX_BYTES = 256;
const COLLECTION_STATES_MAX_BYTES = 256;
const CLAIM_BY_MAX_BYTES = 256;
const CLAIM_STATES_MAX_BYTES = 2_048;

/** A record of a chained run: the item, and the bytes its digest and its frame were checked against. */
interface ChainedRecord {
  readonly item: ExportChainedItem;
  readonly bytes: Uint8Array;
}

function badManifest(detail: string): ReceiptError {
  return new ReceiptError('EXPORT_BAD_MANIFEST', detail);
}

function unsupportedLabel(detail: string): ReceiptError {
  return new ReceiptError('EXPORT_UNSUPPORTED_LABEL', detail);
}

/** How a map key names itself back in a refusal, without leaning on an object's default rendering. */
function memberName(key: unknown): string {
  if (typeof key === 'string') return `'${key}'`;
  if (key instanceof Uint8Array) return `a bstr key of length ${key.length}`;
  if (typeof key === 'number' || typeof key === 'bigint') return `the numeric key ${String(key)}`;
  return 'a key that is not a text label';
}

interface DefinedMap {
  readonly members: readonly string[];
  readonly nested?: Readonly<Record<string, DefinedMap>>;
}

/**
 * The closedness rule, applied to one map and then to the maps it opens. A member no position of this
 * version defines makes the document malformed rather than a member a reader agreed to forget, and the
 * walk has to reach the arms a document actually took: an `anchored` collection whose endpoints were read
 * and then dropped on the way to a verifier is the silence the arms exist to refuse.
 *
 * A position whose shape is chosen by a label is closed by the reader that resolves the label, because
 * which member list stands behind `collection` depends on the arm its `k` names, and a value the format
 * makes an array of maps is closed at its elements rather than at the array.
 */
function assertDefined(raw: Map<unknown, unknown>, members: readonly string[], where: string, nested: Readonly<Record<string, DefinedMap>> = {}): void {
  for (const [key, value] of raw) {
    if (typeof key !== 'string' || !members.includes(key)) {
      throw badManifest(`${where} carries a member this version does not define: ${memberName(key)}`);
    }
    const arm = nested[key];
    if (arm === undefined) continue;
    const inner = decodedMap(value);
    // A value the format makes a map and is not one is the member read's answer, not this walk's:
    // refusing it here would report a membership problem at a position whose type has not been read.
    if (inner !== null) assertDefined(inner, arm.members, `${where}.${key}`, arm.nested);
  }
}

/**
 * The whole `Sig_structure` of this container, exactly as RFC 9052 section 4.4 frames it and as
 * `cose.ts` frames a receipt's: the context string, the protected bstr, the external AAD and the payload
 * bstr, canonically encoded. It is published because the bytes a signature covers are the whole contract of
 * a COSE document, and a reimplementer who cannot see them cannot compare two implementations' refusals.
 */
export function exportSigStructure(
  protectedBytes: Uint8Array,
  payloadBytes: Uint8Array,
  externalAad: Uint8Array = new Uint8Array(0),
): Uint8Array {
  return encodeCanonical(['Signature1', protectedBytes, externalAad, payloadBytes]);
}

/**
 * The signed header, carrying the content type the caller means it to carry. Which three labels exist and
 * how they encode is the receipt's answer; this format's own contribution is the name in label 3, so the
 * builder is shared and only that name is passed.
 */
export function encodeExportProtectedHeader(kid: Uint8Array, contentType: string = EXPORT_CONTENT_TYPE): Uint8Array {
  return buildProtectedHeader(kid, contentType);
}

/**
 * The four elements of a `COSE_Sign1-Export-COSE`, tagged, as the format writes them. `export.cddl`
 * declares the `unprotected` map as the one a signer fills at will and that carries no claim, so it stays
 * an argument here rather than a fixed empty map, and the framing it goes into is the shared one.
 */
export function sealExport(
  protectedBytes: Uint8Array,
  payloadBytes: Uint8Array,
  signature: Uint8Array,
  unprotected: Map<unknown, unknown> = new Map(),
): Uint8Array {
  return sealCoseSign1(protectedBytes, payloadBytes, signature, unprotected);
}

export function encodeExportManifest(manifest: ExportManifest): Uint8Array {
  // Maps rather than plain objects, so key order is bytewise per RFC 8949 CDE and no field order in this
  // file or in a caller's object can move a byte of what gets signed.
  const orig = (one: ExportOriginal): Map<string, unknown> =>
    one.k === 'inline'
      ? new Map<string, unknown>([['k', 'inline'], ['bytes', one.bytes]])
      : new Map<string, unknown>([['k', 'companion'], ['name', one.name]]);
  // The two item rules differ by the one member the CDDL puts between `d` and `orig`, and the order of
  // the rest is the order `ExportItem` declares them in.
  const item = (one: ExportItem): Map<string, unknown> => {
    const fields: Array<readonly [string, unknown]> = [
      ['id', one.id],
      ['iat', one.iat],
      ['d', one.d],
    ];
    if ('p' in one) fields.push(['p', one.p]);
    fields.push(['orig', orig(one.orig)]);
    return new Map<string, unknown>(fields);
  };
  const collection = (one: ExportCollection): Map<string, unknown> => {
    if (one.k === 'void') return new Map<string, unknown>([['k', 'void'], ['states', one.states]]);
    if (one.k === 'plain') {
      return new Map<string, unknown>([['k', 'plain'], ['items', one.items.map(item)]]);
    }
    return new Map<string, unknown>([
      ['k', 'anchored'],
      ['anchor', one.anchor],
      ['head', one.head],
      ['items', one.items.map(item)],
    ]);
  };
  return encodeCanonical(
    new Map<string, unknown>([
      ['v', manifest.v],
      ['at', manifest.at],
      ['assessment', new Map<string, unknown>([['k', manifest.assessment.k], ['states', manifest.assessment.states]])],
      ['collection', collection(manifest.collection)],
      [
        'claim',
        new Map<string, unknown>([
          ['made', manifest.claim.made],
          ['by', manifest.claim.by],
          ['kind', manifest.claim.kind],
          ['states', manifest.claim.states],
        ]),
      ],
    ]),
  );
}

/**
 * Sign an export. The manifest is encoded, run back through this module's own structural parser, walked for
 * the arm that claims a run, and only then signed, because a writer that produced bytes its own reader refuses
 * has made a document that cannot be handed over.
 *
 * The walk an anchored collection offers is the reader's own function over the reader's own records, so a gap,
 * a fork, a run stopping short of the head and an item outside the run are refused here with the code the
 * reader states, before a signature makes the document unalterable. It runs only where every item's original
 * travels inline, because a record's digest is taken over those bytes and a companion's are not in the
 * writer's hand: an anchored collection naming one is sealed on the structural half and left to a reader that
 * will be handed the files, which is the one question here that has no answer inside the document.
 *
 * A caller who wants to hand a reader a document that is *meant* to be refused, which is what a conformance
 * vector is, assembles it from the three pieces above rather than through this function.
 */
export function signExport(manifest: ExportManifest, key: SigningKey): Uint8Array {
  const payloadBytes = encodeExportManifest(manifest);
  const parsed = parseManifest(payloadBytes);
  if (parsed.collection.k === 'anchored') {
    assertAnchoredRunCloses(parsed.collection);
  }
  const protectedBytes = encodeExportProtectedHeader(key.kid);
  const signature = ed25519.sign(exportSigStructure(protectedBytes, payloadBytes), key.privateKey);
  return sealExport(protectedBytes, payloadBytes, signature);
}

/**
 * The reader's walk, over the records a seal can see. On an inline-only collection every item carries the
 * bytes the reader hashes, so the question "does this run close" is answered by one function on each side of
 * the signature rather than by two that have to be kept agreeing.
 */
function assertAnchoredRunCloses(collection: ExportAnchoredCollection): void {
  const records: ChainedRecord[] = [];
  for (const item of collection.items) {
    if (item.orig.k !== 'inline') return;
    records.push({ item, bytes: item.orig.bytes });
  }
  walk(records, collection.anchor, collection.head);
}

/**
 * The framing a chained item's record digest is taken over, which is section 5.2 of
 * `docs/receipt-spec.md` and nothing of this file's own: kind byte 0, the predecessor digest, `iat` as
 * eight big-endian bytes, the byte length of the id as two big-endian bytes, the id, and the original
 * bytes. No length prefix and no copy of the digest itself are inside the hash, which is what the store's
 * frame adds around it and a recomputation never sees.
 *
 * This is `packRecordDigest` rather than a second reading of the same layout, because a reviewer who
 * recomputes an export's walk has to arrive at the digests the store's own chain states, and two
 * implementations of one framing agree only for as long as nobody edits either of them.
 */
export function exportRecordDigest(item: {
  readonly id: string;
  readonly iat: number;
  readonly p: Uint8Array;
  readonly bytes: Uint8Array;
}): Uint8Array {
  return packRecordDigest({ id: item.id, iat: item.iat, prev: item.p, receipt: item.bytes });
}

function recordDigest(record: ChainedRecord): Uint8Array {
  return exportRecordDigest({
    id: record.item.id,
    iat: record.item.iat,
    p: record.item.p,
    bytes: record.bytes,
  });
}

function requireText(value: unknown, position: string, maxBytes: number): string {
  if (typeof value !== 'string') throw badManifest(`${position} must be a tstr`);
  const bytes = encoder.encode(value).length;
  if (bytes < 1 || bytes > maxBytes) {
    throw badManifest(`${position} must be between 1 and ${maxBytes} bytes, got ${bytes}`);
  }
  return value;
}

function requireStamp(value: unknown, position: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw badManifest(`${position} must be a non-negative integer of seconds`);
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
 * A companion's name, checked as the file name the format says it is. This reader never resolves one, so
 * this is not a traversal guard for code here: it is the rule that keeps the promise `export.cddl` makes
 * about what the member holds, and that promise matters to whoever does open a file, which is why a
 * separator or a scheme is refused as a malformed document rather than passed on to a filesystem.
 */
function requireFileName(value: unknown, position: string): string {
  const name = requireText(value, position, NAME_MAX_BYTES);
  if (name.includes('/') || name.includes('\\') || name.includes(':') || name === '.' || name === '..') {
    throw badManifest(`${position} must be a file name and not a path or a location`);
  }
  return name;
}

function readHeader(bytes: Uint8Array): ProtectedHeader {
  // Decoded under the rule the format sets for this map, which closes its labels as well as its values:
  // a label written as the float `1.0` takes the same map slot as the integer `1`, so the two spellings
  // are indistinguishable by the time anything could ask which one the issuer signed.
  const raw = decodedMap(decodeClosedDocument(bytes, 'EXPORT_BAD_HEADER'));
  if (raw === null) throw new ReceiptError('EXPORT_BAD_HEADER', 'not a map');
  for (const label of raw.keys()) {
    if (!(DECLARED_EXPORT_PROTECTED_LABELS as readonly unknown[]).includes(label)) {
      throw new ReceiptError('EXPORT_BAD_HEADER', `it carries a label the format does not define: ${memberName(label)}`);
    }
  }
  const alg = raw.get(COSE_HEADER_ALG);
  if (typeof alg !== 'number') throw new ReceiptError('UNSUPPORTED_ALG', `alg must be an integer label, got ${typeof alg}`);
  if (alg !== ALG_EDDSA) throw new ReceiptError('UNSUPPORTED_ALG', `alg=${alg}`);
  const kid = raw.get(COSE_HEADER_KID);
  if (!(kid instanceof Uint8Array) || kid.length !== DIGEST_BYTES) {
    throw new ReceiptError('EXPORT_BAD_HEADER', 'kid must be a 32-byte bstr');
  }
  const contentType = raw.get(COSE_HEADER_CONTENT_TYPE);
  if (typeof contentType !== 'string') {
    throw new ReceiptError('EXPORT_BAD_HEADER', `typ must be a tstr, got ${typeof contentType}`);
  }
  // Before any member of the manifest is read, and refused whatever else the document holds: the payload
  // of a pack and the payload of an export are two documents that both pass their own checks, and the one
  // mistake a content type exists to prevent is reading the second as the first.
  if (contentType !== EXPORT_CONTENT_TYPE) {
    throw new ReceiptError('EXPORT_BAD_HEADER', `typ=${contentType}`);
  }
  return { alg: ALG_EDDSA, kid, contentType };
}

function readEnvelope(bytes: Uint8Array): CoseSign1 & { header: ProtectedHeader } {
  const top = decodeCanonical(bytes, 'EXPORT_MALFORMED_CBOR');
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

function readOriginal(raw: Map<unknown, unknown>, where: string): ExportOriginal {
  const arm = raw.get('k');
  if (typeof arm !== 'string') throw badManifest(`${where}.k must be a tstr naming an arm`);
  if (arm === 'inline') {
    assertDefined(raw, EXPORT_INLINE_MEMBERS, `${where} (inline)`);
    const bytes = raw.get('bytes');
    if (!(bytes instanceof Uint8Array)) throw badManifest(`${where}.bytes must be a bstr`);
    return { k: 'inline', bytes };
  }
  if (arm === 'companion') {
    assertDefined(raw, EXPORT_COMPANION_MEMBERS, `${where} (companion)`);
    return { k: 'companion', name: requireFileName(raw.get('name'), `${where}.name`) };
  }
  throw unsupportedLabel(`${where}.k='${arm}' is not one of ${EXPORT_ORIGINAL_ARMS.join(', ')}`);
}

function readItem(raw: unknown, position: string, chained: boolean): ExportItem | ExportChainedItem {
  const map = decodedMap(raw);
  if (map === null) throw badManifest(`${position} must be a map`);
  // The two item rules differ by exactly one member, and a reader that let one carry the other's digest
  // would be reading a chained run out of a collection that claims none. So the member list a closed map
  // is checked against is the one the arm names, and the position that differs between the two arms is
  // answered first, by the fault it is: an item naming a predecessor in a plain collection, or naming
  // none in an anchored one, is a disagreement about the collection's own label and not about a name
  // nobody defined.
  const hasPredecessor = map.get('p') !== undefined;
  if (hasPredecessor !== chained) {
    throw badManifest(
      `${position}${hasPredecessor ? ' names a predecessor in a collection that claims no chain' : ' names no predecessor in a collection that claims one'}`,
    );
  }
  assertDefined(map, chained ? EXPORT_CHAINED_ITEM_MEMBERS : EXPORT_ITEM_MEMBERS, position);
  const id = requireText(map.get('id'), `${position}.id`, ID_MAX_BYTES);
  const iat = requireStamp(map.get('iat'), `${position}.iat`);
  const d = requireDigest(map.get('d'), `${position}.d`);
  const p = chained ? requireDigest(map.get('p'), `${position}.p`) : undefined;
  const orig = decodedMap(map.get('orig'));
  if (orig === null) throw badManifest(`${position}.orig must be a map`);
  const original = readOriginal(orig, `${position}.orig`);
  return p === undefined ? { id, iat, d, orig: original } : { id, iat, d, p, orig: original };
}

function readItems(raw: unknown, position: string, chained: boolean): Array<ExportItem | ExportChainedItem> {
  if (!Array.isArray(raw)) throw badManifest(`${position} must be an array`);
  // The non-void arms are the arms that carry material, and each requires at least one item. A writer
  // with nothing to carry reaches for the arm that states so, and an empty array under either of these is
  // a document whose own label says there is something in it.
  if (raw.length === 0) {
    throw badManifest(`the ${chained ? 'anchored' : 'plain'} arm declares a non-empty ${position}`);
  }
  const items = raw.map((one, index) => readItem(one, `${position}[${index}]`, chained));
  const seen = new Set<string>();
  for (const one of items) {
    // A refusal names an item, and two items answering to one name make that report mean whichever of the
    // two a reader happened to meet first. The links order an anchored collection and the name identifies
    // it, and neither of those is a matter of arrival.
    if (seen.has(one.id)) throw new ReceiptError('EXPORT_DUPLICATE_ID', one.id);
    seen.add(one.id);
  }
  return items;
}

function readCollection(raw: Map<unknown, unknown>): ExportCollection {
  const label = raw.get('k');
  if (typeof label !== 'string') throw badManifest('collection.k must be a tstr naming an arm');
  const members = label === 'anchored' ? EXPORT_ANCHORED_MEMBERS : label === 'plain' ? EXPORT_PLAIN_MEMBERS : label === 'void' ? EXPORT_VOID_MEMBERS : undefined;
  if (members === undefined) {
    throw unsupportedLabel(`collection.k='${label}' is not one of ${EXPORT_COLLECTION_ARMS.join(', ')}`);
  }
  assertDefined(raw, members, 'collection');
  if (label === 'void') {
    return { k: 'void', states: requireText(raw.get('states'), 'collection.states', COLLECTION_STATES_MAX_BYTES) };
  }
  const items = readItems(raw.get('items'), 'collection.items', label === 'anchored');
  if (label === 'plain') return { k: 'plain', items };
  return {
    k: 'anchored',
    anchor: requireDigest(raw.get('anchor'), 'collection.anchor'),
    head: requireDigest(raw.get('head'), 'collection.head'),
    items: items as readonly ExportChainedItem[],
  };
}

function readAssessment(raw: Map<unknown, unknown>): ExportAssessment {
  assertDefined(raw, EXPORT_ASSESSMENT_MEMBERS, 'assessment');
  const label = raw.get('k');
  if (typeof label !== 'string') throw badManifest('assessment.k must be a tstr naming the assessment made');
  // The refusal that keeps "the writer assessed something" from arriving in a v1 document and being read
  // as the statement that nothing was assessed. Which of the two it was is not a question a reader may
  // answer by preference, and the labels of a later version are that version's business.
  if (label !== 'none') {
    throw unsupportedLabel(`assessment.k='${label}' is not the label this version defines (${EXPORT_ASSESSMENT_ARMS.join(', ')})`);
  }
  return { k: 'none', states: requireText(raw.get('states'), 'assessment.states', ASSESSMENT_STATES_MAX_BYTES) };
}

function readClaim(raw: Map<unknown, unknown>, at: number): ExportClaim {
  assertDefined(raw, EXPORT_CLAIM_MEMBERS, 'claim');
  const made = requireStamp(raw.get('made'), 'claim.made');
  const by = requireText(raw.get('by'), 'claim.by', CLAIM_BY_MAX_BYTES);
  const kind = raw.get('kind');
  if (typeof kind !== 'string') throw badManifest('claim.kind must be a tstr');
  if (!isExportClaimKind(kind)) {
    throw unsupportedLabel(`claim.kind='${kind}' is not one of ${EXPORT_CLAIM_KINDS.join(', ')}`);
  }
  const states = requireText(raw.get('states'), 'claim.states', CLAIM_STATES_MAX_BYTES);
  // A claim stamped after the assembly of the document carrying it is another document's claim, and this
  // one cannot mean it. Both stamps are inside one signature, so a disagreement is the document
  // contradicting itself rather than a deployment that misremembered.
  if (made > at) throw badManifest(`claim.made=${made} postdates the assembly stamp at=${at}`);
  return { made, by, kind, states };
}

function parseManifest(bytes: Uint8Array): ExportManifest {
  const raw = decodedMap(decodeClosedDocument(bytes, 'EXPORT_BAD_MANIFEST'));
  if (raw === null) throw badManifest('payload is not a map');
  const version = raw.get('v');
  if (typeof version !== 'number' || !Number.isInteger(version)) {
    throw badManifest('v must be an integer export version');
  }
  if (version !== 1) {
    throw new ReceiptError('EXPORT_UNSUPPORTED_VERSION', `export manifest version ${version} is not a format this package reads`);
  }
  assertDefined(raw, EXPORT_MANIFEST_MEMBERS, 'manifest', {
    assessment: { members: EXPORT_ASSESSMENT_MEMBERS },
    claim: { members: EXPORT_CLAIM_MEMBERS },
  });
  const assessment = decodedMap(raw.get('assessment'));
  if (assessment === null) throw badManifest('assessment must be a map');
  const collection = decodedMap(raw.get('collection'));
  if (collection === null) throw badManifest('collection must be a map');
  const claim = decodedMap(raw.get('claim'));
  if (claim === null) throw badManifest('claim must be a map');
  const at = requireStamp(raw.get('at'), 'at');
  return {
    v: 1,
    at,
    assessment: readAssessment(assessment),
    collection: readCollection(collection),
    claim: readClaim(claim, at),
  };
}

/**
 * A manifest read and a signature not yet checked: how a document is inspected before anybody has decided
 * to trust it, and enough on its own for everything that is a property of the document rather than of who
 * wrote it. Shape, version, labels, widths, non-negativity, name uniqueness and the one tie between two
 * stamps are answered here, because none of them needs a key to be true.
 */
export function decodeExport(bytes: Uint8Array): DecodedExport {
  const envelope = readEnvelope(bytes);
  return { manifest: parseManifest(envelope.payloadBytes), header: envelope.header, envelope };
}

/**
 * An item's original bytes, from the document or from what the caller was handed beside it, and the
 * digest check that follows from them. An inline item is always checkable. A companion is checkable
 * against the bytes somebody put in the reader's hand and against nothing else, so an absent one is
 * refused by name: a reader that passed it would be reporting on material it never looked at.
 */
function checkOriginal(item: ExportItem, companions: ReadonlyMap<string, Uint8Array> | undefined): Uint8Array {
  if (item.orig.k === 'inline') {
    return checkedAgainst(item, item.orig.bytes);
  }
  const bytes = companions?.get(item.orig.name);
  if (bytes === undefined) {
    throw new ReceiptError('EXPORT_ORIGINAL_UNAVAILABLE', `${item.id} names ${item.orig.name}`);
  }
  return checkedAgainst(item, bytes);
}

function checkedAgainst(item: ExportItem, bytes: Uint8Array): Uint8Array {
  const computed = sha256(bytes);
  if (!equalBytes(computed, item.d)) {
    throw new ReceiptError('EXPORT_DIGEST_MISMATCH', `${item.id}: sha256 is ${toHex(computed)}, the item carries ${toHex(item.d)}`);
  }
  return bytes;
}

/**
 * The walk, over the links and not over the array: begin at the item whose predecessor is the anchor,
 * recompute each record's digest from what the item carries, and take the unvisited item naming that
 * digest as its predecessor. Two halves, both refused by name, because the links alone cannot see a
 * receipt parked beside a run it is not part of: the run from the anchor to the head, and the count of
 * what that run reached against the array that was handed over. A verifier that implements one half has
 * implemented half a rule.
 */
function walk(records: readonly ChainedRecord[], anchor: Uint8Array, head: Uint8Array): readonly ExportChainedItem[] {
  const walked: ChainedRecord[] = [];
  const visited = new Set<string>();
  let cursor = anchor;
  for (;;) {
    const candidates = records.filter((one) => !visited.has(one.item.id) && equalBytes(one.item.p, cursor));
    if (candidates.length > 1) {
      throw new ReceiptError(
        'EXPORT_CHAIN_BROKEN',
        `${String(candidates.length)} items name the same predecessor, so the run forks at ${candidates.map((one) => one.item.id).join(', ')}`,
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
      'EXPORT_CHAIN_BROKEN',
      `the walk reached ${String(walked.length)} item(s) and stopped at a digest that is not the head`,
    );
  }
  const unreached = records.filter((one) => !visited.has(one.item.id));
  if (unreached.length > 0) {
    throw new ReceiptError('EXPORT_ITEM_UNREACHED', unreached.map((one) => one.item.id).join(', '));
  }
  return walked.map((one) => one.item);
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (one) => one.toString(16).padStart(2, '0')).join('');
}

/**
 * Verify an export: the envelope, the signature over the `Sig_structure` this format frames, then the
 * structure, then the caller's own endpoints, then every item's digest, then the walk an anchored
 * collection offers. The order is what keeps a reader's report honest. A document nobody signed gets no
 * verdict about its contents, because a manifest under an unchecked signature is the writer's say-so and
 * nothing more. Digests come before the walk because an edited original inside a run that otherwise
 * closes is a different finding from a broken run, and the two arrive with different codes.
 *
 * Nothing here reports on a legal duty, on completeness at the source, or on freshness. The first is not
 * this package's question. The second is a property of the writer's store, which no walk can see: the head
 * makes deletion detectable only against a copy the reader had before, which is what `expectedHead` is for
 * and why it is an argument rather than a conclusion. The third needs a clock this package does not own,
 * so `manifest.at` is returned for whoever decides it matters, and nothing here compares it to anything.
 */
export function verifyExport(
  bytes: Uint8Array,
  publicKey: Uint8Array,
  options: ExportVerifyOptions = {},
): VerifiedExport {
  const envelope = readEnvelope(bytes);
  if (!equalBytes(envelope.header.kid, keyId(publicKey))) {
    throw new ReceiptError('EXPORT_KID_MISMATCH', `header kid=${toHex(envelope.header.kid)} key kid=${toHex(keyId(publicKey))}`);
  }
  if (
    !ed25519.verify(
      envelope.signature,
      exportSigStructure(envelope.protectedBytes, envelope.payloadBytes),
      publicKey,
      { zip215: false },
    )
  ) {
    throw new ReceiptError('INVALID_SIGNATURE');
  }
  const manifest = parseManifest(envelope.payloadBytes);
  const collection = manifest.collection;
  const pinned = options.expectedAnchor === undefined && options.expectedHead === undefined;
  if (!pinned) {
    if (collection.k !== 'anchored') {
      // The reader came with an endpoint in hand and the document states none, which is the same
      // disagreement as a different value: the two cannot be the same run's endpoints. Refusing here is
      // what stops a pin from being silently unused.
      throw new ReceiptError('EXPORT_ENDPOINT_MISMATCH', 'the reader expected an endpoint and the collection states none');
    }
    if (options.expectedAnchor !== undefined && !equalBytes(collection.anchor, options.expectedAnchor)) {
      throw new ReceiptError('EXPORT_ENDPOINT_MISMATCH', `anchor=${toHex(collection.anchor)}`);
    }
    if (options.expectedHead !== undefined && !equalBytes(collection.head, options.expectedHead)) {
      throw new ReceiptError('EXPORT_ENDPOINT_MISMATCH', `head=${toHex(collection.head)}`);
    }
  }

  const records: ChainedRecord[] = [];
  if (collection.k !== 'void') {
    for (const item of collection.items) {
      const original = checkOriginal(item, options.companions);
      if ('p' in item) records.push({ item, bytes: original });
    }
  }
  if (collection.k === 'void') {
    return { manifest, header: envelope.header, envelope, outcome: { kind: 'void', states: collection.states } };
  }
  if (collection.k === 'plain') {
    return { manifest, header: envelope.header, envelope, outcome: { kind: 'plain', items: collection.items } };
  }
  return {
    manifest,
    header: envelope.header,
    envelope,
    outcome: { kind: 'anchored', items: collection.items, walked: walk(records, collection.anchor, collection.head) },
  };
}
