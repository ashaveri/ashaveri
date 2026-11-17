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
  decodeCoseSign1,
  equalBytes,
  keyId,
  sealCoseSign1,
  type CoseSign1,
  type ProtectedHeader,
  type SigningKey,
} from './cose.js';
import { ReceiptError } from './errors.js';
import { firstForgingCodePoint } from './line-text.js';
import { signEd25519 } from './signing.js';

/**
 * A destruction receipt, read and written: what `packages/receipt/destruction-receipt.cddl` states, run.
 *
 * A redaction states that a named record came out of one closed pack and says nothing about the other places
 * those bytes sit. The question an erasure leaves behind is the other one: which copies did the destruction
 * reach. This module reads and writes the answer, and it is a checker and not a verdict engine. It answers
 * whether the bytes are a well-formed destruction receipt, whether the key it was handed signed them, whether
 * every copy class the format enumerates carries exactly one reach statement, whether the reach it states
 * stays inside what the format will say, and, when a caller hands over the bytes the receipt designates,
 * whether those bytes hash to the designation and carry the document type the receipt names. It answers
 * nothing about whether the material is unreachable anywhere else, nothing about whether the destroyed key
 * can still sign, and nothing about a duty, and it resolves nothing by itself: every key and every extra
 * document arrives as an argument.
 *
 * What the receipt binds, and what it therefore cannot be read as. One object, by the sha256 of its exact
 * bytes as handed over, beside the content type naming which document those bytes are, because a digest names
 * no document on its own. One key, by its kid, which is sha256 over its public half and so a public label
 * rather than key material: the two 32-byte positions this manifest carries are the only positions a bstr
 * goes into, the map is closed, and a value of any other width at `key` is refused, so a seed, a keypair or
 * an exported key has nowhere to be written. A reach per copy class, over the five classes the format
 * enumerates, one statement each and no class left unstated. The deployment's signature, under a key other
 * than the one it names as destroyed. And the boundary: a copy class the format declares out of reach may
 * only ever be stated `not-reached`, so no document this reader accepts claims it took a copy somebody else
 * holds.
 *
 * Two refusals are about this layout's honesty rather than about its shape and carry codes of their own:
 * `DESTRUCTION_RECEIPT_MISSING_COPY_CLASS` for a class the record says nothing about, which is the silence a
 * reach statement turns into a claim, and `DESTRUCTION_RECEIPT_REACH_OVERREACH` for a reach claimed past the
 * format's limit. An unknown class label is not one of those: it is a member outside a closed registry in the
 * same way an unknown manifest member is, so it answers `DESTRUCTION_RECEIPT_BAD_MANIFEST`.
 *
 * The split into two entry points is the one `redaction.ts` and `pack.ts` make. `decodeDestructionReceipt`
 * answers what is true of the document whoever signed it, with no key and no object in hand, because a
 * manifest that contradicts itself does so quietly. `verifyDestructionReceipt` adds the signature and, when
 * the caller happens to hold the bytes this receipt says were destroyed, the recomputation of the designation
 * and of the type claim beside it. Those are the checks that mean something only against a key the reader has
 * accepted, and the object is optional on purpose: the bytes a destruction receipt designates are the bytes a
 * destruction removed, so a reader that was required to produce them could never read the document at all.
 *
 * The writer is `encodeDestructionReceiptManifest`, `encodeDestructionReceiptProtectedHeader`,
 * `sealDestructionReceipt` and `signDestructionReceipt`, and `destructionObjectDigest` is the computation a
 * caller needs in order to fill the designation rather than invent one. `signDestructionReceipt` guarantees
 * the structural half, which is the half that needs no other document, exactly as `signRedaction` does; a
 * document meant to be refused, which is what a conformance vector is, is assembled from the published pieces
 * rather than through it.
 */

/** The content type that keeps a destruction receipt from being read as one of the five documents a deployment key also seals. */
export const DESTRUCTION_RECEIPT_CONTENT_TYPE = 'ashaveri/destruction-receipt';

/**
 * The three labels `destruction-receipt.cddl` declares for a signed header, exported for the same reason the
 * other containers export theirs: which labels exist is the format's answer, and only a reader of both the
 * file and this list can see that the two are one answer.
 */
export const DECLARED_DESTRUCTION_RECEIPT_PROTECTED_LABELS: readonly number[] = [
  COSE_HEADER_ALG,
  COSE_HEADER_CONTENT_TYPE,
  COSE_HEADER_KID,
];

/**
 * The member list of the map this format closes, in the order the CDDL declares it. Exported for a test to
 * hold against the block rather than against this file's reading of it.
 */
export const DESTRUCTION_RECEIPT_MANIFEST_MEMBERS = ['v', 'at', 'object', 'kind', 'key', 'reach', 'states'] as const;

/** The members of one reach entry, in the order the CDDL declares them. */
export const DESTRUCTION_RECEIPT_ENTRY_MEMBERS = ['class', 'outcome'] as const;

/**
 * The copy classes the format enumerates, in the order the CDDL publishes them. Every one of them carries
 * exactly one statement in every receipt, which is what makes the list a claim rather than a selection.
 */
export const DESTRUCTION_COPY_CLASSES = ['store', 'pack', 'export', 'backup', 'handout'] as const;
export type DestructionCopyClass = (typeof DESTRUCTION_COPY_CLASSES)[number];

/**
 * The classes no act of this deployment reaches. Stated as its own list rather than folded into a sentence
 * because the reader refuses against it, and a refusal has to name what it weighed. A copy that has left the
 * deployment's hands is somebody else's bytes, and a receipt claiming to have destroyed them would be the one
 * artifact of this estate that overstates itself.
 */
export const DESTRUCTION_UNREACHABLE_COPY_CLASSES: readonly DestructionCopyClass[] = ['handout'];

/**
 * The document kinds a destruction may designate: the content types this estate signs with, so a kind is a
 * name a reader can settle against the bytes rather than a label a writer picked. A deployment manifest and an
 * anchor provenance ledger are absent because this container states the destruction of evidence about a run,
 * and neither is that; widening the registry is a decision about the format.
 */
export const DESTRUCTION_OBJECT_KINDS = [
  'ashaveri/receipt',
  'ashaveri/pack',
  'ashaveri/export',
  'ashaveri/redaction',
  'ashaveri/epoch-inventory',
] as const;
export type DestructionObjectKind = (typeof DESTRUCTION_OBJECT_KINDS)[number];

/** The two reach outcomes, spelled as integers so that neither has a default and neither is falsy. */
export const DESTRUCTION_REACH_REACHED = 1;
export const DESTRUCTION_REACH_NOT_REACHED = 2;
export const DESTRUCTION_REACH_OUTCOMES = [DESTRUCTION_REACH_REACHED, DESTRUCTION_REACH_NOT_REACHED] as const;

/** One copy class and what this destruction reached there. */
export interface DestructionReachEntry {
  readonly class: DestructionCopyClass;
  readonly outcome: (typeof DESTRUCTION_REACH_OUTCOMES)[number];
}

/** A destruction receipt manifest at the one version the format declares. */
export interface DestructionReceiptManifest {
  readonly v: 1;
  /** unix seconds, the instant the destruction was stated. */
  readonly at: number;
  /** sha256 of the exact bytes this destruction took. */
  readonly object: Uint8Array;
  /** Which document those bytes are, from the registry above. */
  readonly kind: DestructionObjectKind;
  /** The kid of the destroyed key: sha256 of its public half. Never any of its material. */
  readonly key: Uint8Array;
  /** Exactly one statement per copy class, in the order the format enumerates them. */
  readonly reach: readonly DestructionReachEntry[];
  /** The writer's own sentence stating this destruction. Checked for shape and never for content. */
  readonly states: string;
}

export interface DecodedDestructionReceipt {
  readonly manifest: DestructionReceiptManifest;
  readonly header: ProtectedHeader;
  readonly envelope: CoseSign1;
}

export interface VerifiedDestructionReceipt extends DecodedDestructionReceipt {
  readonly outcome: DestructionOutcome;
}

/** What the reader recomputed beside what the document stated, with the optional half absent when unhanded. */
export interface DestructionOutcome {
  /** The kid the header carries, which is the key that sealed the statement and never the key it names. */
  readonly signer: Uint8Array;
  /** The key this receipt states was destroyed, as the document carries it. */
  readonly destroyed: Uint8Array;
  /** The reach as the document states it, one entry per class. */
  readonly reach: readonly DestructionReachEntry[];
  /** sha256 of the object bytes handed to this reader. Present exactly where `objectBytes` was handed. */
  readonly objectSha256?: Uint8Array;
  /** The content type the handed object bytes carry in their own signed header, beside the kind stated. */
  readonly objectKind?: string;
}

/**
 * How a caller hands this reader the key it designates, and optionally the bytes it designates.
 *
 * The two key fields are the pack's and the redaction's, answered the same way: a `publicKey` says which
 * single key the caller means and a header naming another is a configuration disagreement, and a `resolveKey`
 * is asked for the kid the header carries. `objectBytes` is what a reviewer holds when the destruction took a
 * copy that reached them: handed, the digest is recomputed and the type claim is read out of the bytes; left
 * out, the receipt still verifies and the two answers are simply absent, because the bytes are gone by the
 * receipt's own statement.
 */
export interface DestructionReceiptVerifyOptions {
  readonly publicKey?: Uint8Array;
  readonly resolveKey?: (kid: Uint8Array) => Uint8Array | undefined;
  readonly objectBytes?: Uint8Array;
}

const encoder = new TextEncoder();

/** The widths the format writes beside each position, named once rather than per check site. */
const DIGEST_BYTES = 32;
const SIGNATURE_BYTES = 64;
const STATES_MAX_BYTES = 2_048;

function badManifest(detail: string): ReceiptError {
  return new ReceiptError('DESTRUCTION_RECEIPT_BAD_MANIFEST', detail);
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

/**
 * The closedness rule, for the manifest and for one reach entry alike. A member no position of this version
 * defines makes the document malformed rather than a member a reader agreed to forget, and there is no such
 * thing as a spare position here: an undeclared bstr is where key material would arrive.
 */
function assertDefined(raw: Map<unknown, unknown>, members: readonly string[], where: string): void {
  for (const key of raw.keys()) {
    if (typeof key !== 'string' || !members.includes(key)) {
      throw badManifest(`${where} carries a member this version does not define: ${memberName(key)}`);
    }
  }
}

/**
 * The whole `Sig_structure` of this container, exactly as RFC 9052 section 4.4 frames it and as the other
 * signed documents frame theirs. A reader verifies with an empty AAD, which is what the CDDL describes, and
 * nothing inside the envelope carries which one was used, so the framing is published rather than implied.
 */
export function destructionReceiptSigStructure(
  protectedBytes: Uint8Array,
  payloadBytes: Uint8Array,
  externalAad: Uint8Array = new Uint8Array(0),
): Uint8Array {
  return encodeCanonical(['Signature1', protectedBytes, externalAad, payloadBytes]);
}

/**
 * The signed header this format writes, carrying the content type that keeps a destruction receipt apart from
 * the five documents one key also seals. The `contentType` argument exists for the one caller who needs a
 * header naming something else, which is a document assembled to be refused.
 */
export function encodeDestructionReceiptProtectedHeader(
  kid: Uint8Array,
  contentType: string = DESTRUCTION_RECEIPT_CONTENT_TYPE,
): Uint8Array {
  return buildProtectedHeader(kid, contentType);
}

/** The four elements of a `COSE_Sign1-Destruction-Receipt-COSE`, tagged, as the format writes them. */
export function sealDestructionReceipt(
  protectedBytes: Uint8Array,
  payloadBytes: Uint8Array,
  signature: Uint8Array,
  unprotected: Map<unknown, unknown> = new Map(),
): Uint8Array {
  return sealCoseSign1(protectedBytes, payloadBytes, signature, unprotected);
}

/**
 * The designation member, as the format computes it: sha256 over the exact bytes of the object, every byte of
 * it as it was handed to the deployment. Not of a canonical re-encoding, because a reviewer holding a file
 * hashes the file.
 */
export function destructionObjectDigest(objectBytes: Uint8Array): Uint8Array {
  return sha256(objectBytes);
}

/** One bstr this layout declares: exactly 32 bytes, because the only bstr positions are digests and a kid. */
function requireDigest(value: unknown, position: string): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== DIGEST_BYTES) {
    throw badManifest(`${position} must be a ${DIGEST_BYTES}-byte bstr`);
  }
  return value;
}

function requireStamp(value: unknown, position: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw badManifest(`${position} must be a unix time no earlier than the epoch`);
  }
  return value;
}

/**
 * The writer's sentence: a `tstr` between one byte and the ceiling the format states, carrying no character of
 * the printed-line class. The class is asked because this is the one position that is opaque text rather than
 * a declared member, and a sentence that can end or reorder the row it is printed on is a way of forging a
 * line rather than a statement about a destruction.
 */
function requireStates(value: unknown, position: string): string {
  if (typeof value !== 'string') throw badManifest(`${position} must be a tstr`);
  const bytes = encoder.encode(value).length;
  if (bytes < 1 || bytes > STATES_MAX_BYTES) {
    throw badManifest(`${position} must be between 1 and ${STATES_MAX_BYTES} bytes, got ${bytes}`);
  }
  const forging = firstForgingCodePoint(value);
  if (forging !== undefined) {
    throw badManifest(`${position} carries the character U+${forging.toString(16).toUpperCase().padStart(4, '0')}, which forges the line it is printed on`);
  }
  return value;
}

/** One class label, weighed against the closed registry rather than read as a name nobody checked. */
function requireClassName(value: unknown, position: string): DestructionCopyClass {
  if (typeof value !== 'string') throw badManifest(`${position} must be a tstr copy class`);
  if (!(DESTRUCTION_COPY_CLASSES as readonly string[]).includes(value)) {
    throw badManifest(`${position} names ${JSON.stringify(value)}, outside the copy classes the format enumerates`);
  }
  return value as DestructionCopyClass;
}

/** One kind label, weighed against the closed registry for the same reason a class is. */
function requireKind(value: unknown, position: string): DestructionObjectKind {
  if (typeof value !== 'string') throw badManifest(`${position} must be a tstr document kind`);
  if (!(DESTRUCTION_OBJECT_KINDS as readonly string[]).includes(value)) {
    throw badManifest(`${position} names ${JSON.stringify(value)}, outside the document kinds the format enumerates`);
  }
  return value as DestructionObjectKind;
}

/**
 * The reach list, read as a statement per class rather than as a list of statements.
 *
 * The list is checked three ways and each answer is a different finding. An entry naming a class outside the
 * registry is a member outside a closed set, the same fault an unknown manifest member is, and answers
 * `DESTRUCTION_RECEIPT_BAD_MANIFEST`. A registry class with no entry is the one fault that cannot be caught by
 * looking at what is present, because the document is complete-looking and silent, and it answers
 * `DESTRUCTION_RECEIPT_MISSING_COPY_CLASS`: a receipt that says nothing about `backup` reads as a receipt that
 * reached everything it named. And a `reached` claim at a class the format declares out of reach answers
 * `DESTRUCTION_RECEIPT_REACH_OVERREACH`, which is not a shape fault at all: the document is well-formed and it
 * claims more than this artifact is allowed to say.
 */
function readReach(raw: unknown): readonly DestructionReachEntry[] {
  if (!Array.isArray(raw)) throw badManifest('reach must be an array of entries');
  if (raw.length === 0) throw badManifest('reach declares at least one entry and carries nothing in it');
  const stated = new Map<DestructionCopyClass, DestructionReachEntry>();
  const entries = raw.map((one, index): DestructionReachEntry => {
    const site = `reach[${String(index)}]`;
    const entry = decodedMap(decodeEntry(one, site));
    if (entry === null) throw badManifest(`${site} is not a map`);
    assertDefined(entry, DESTRUCTION_RECEIPT_ENTRY_MEMBERS, site);
    const name = requireClassName(entry.get('class'), `${site}.class`);
    const outcome = entry.get('outcome');
    if (typeof outcome !== 'number' || !(DESTRUCTION_REACH_OUTCOMES as readonly number[]).includes(outcome)) {
      throw badManifest(`${site}.outcome must be ${String(DESTRUCTION_REACH_REACHED)} for reached or ${String(DESTRUCTION_REACH_NOT_REACHED)} for not-reached`);
    }
    if (stated.has(name)) {
      throw badManifest(`reach states ${JSON.stringify(name)} twice, so one class carries two statements`);
    }
    const built: DestructionReachEntry = { class: name, outcome: outcome as (typeof DESTRUCTION_REACH_OUTCOMES)[number] };
    if (DESTRUCTION_UNREACHABLE_COPY_CLASSES.includes(name) && outcome === DESTRUCTION_REACH_REACHED) {
      throw new ReceiptError(
        'DESTRUCTION_RECEIPT_REACH_OVERREACH',
        `${JSON.stringify(name)} is a class no act of this deployment reaches, and the receipt states it reached`,
      );
    }
    stated.set(name, built);
    return built;
  });
  for (const name of DESTRUCTION_COPY_CLASSES) {
    if (!stated.has(name)) {
      throw new ReceiptError(
        'DESTRUCTION_RECEIPT_MISSING_COPY_CLASS',
        `reach states nothing about ${JSON.stringify(name)}, and a silence at a copy class reads as a claim that the destruction reached it`,
      );
    }
  }
  return entries;
}

/** One element of the reach list, which the caller has already shown to be an array member of any shape. */
function decodeEntry(value: unknown, site: string): unknown {
  if (value instanceof Map) return value;
  throw badManifest(`${site} is not a map`);
}

/**
 * The manifest, as the CBOR map the CDDL declares it: one Map, so key order is bytewise under Core
 * Deterministic Encoding and no field order in a caller's object can move a byte of what gets signed. Every
 * integer goes out through `encodeCanonical`, the package's one place where the bytes of a number are chosen,
 * because a reader recomputes the designation over bytes a reviewer holds and a writer that spelled a number
 * another way would make a deployment refuse its own receipt.
 */
/**
 * The reach list before it is spread into the encoder's map. A caller who steps around the declared type with
 * a cast would otherwise answer `TypeError: manifest.reach is not iterable`, a fault with no code on it, so the
 * question is asked here and the sentence is `readReach`'s own.
 */
function encodableReach(value: unknown): readonly DestructionReachEntry[] {
  if (!Array.isArray(value)) throw badManifest('reach must be an array of entries before a document can be written');
  return value as readonly DestructionReachEntry[];
}

export function encodeDestructionReceiptManifest(manifest: DestructionReceiptManifest): Uint8Array {
  const reach = encodableReach(manifest.reach).map((one): Map<string, unknown> => {
    if (!(DESTRUCTION_COPY_CLASSES as readonly string[]).includes(one.class)) {
      throw badManifest(`reach names ${JSON.stringify(one.class)}, outside the copy classes the format enumerates`);
    }
    if (!(DESTRUCTION_REACH_OUTCOMES as readonly number[]).includes(one.outcome)) {
      throw badManifest(`reach[${JSON.stringify(one.class)}].outcome is not an outcome the format declares`);
    }
    if (DESTRUCTION_UNREACHABLE_COPY_CLASSES.includes(one.class) && one.outcome === DESTRUCTION_REACH_REACHED) {
      throw new ReceiptError(
        'DESTRUCTION_RECEIPT_REACH_OVERREACH',
        `${JSON.stringify(one.class)} is a class no act of this deployment reaches, and this writer will not state it reached`,
      );
    }
    return new Map<string, unknown>([['class', one.class], ['outcome', one.outcome]]);
  });
  return encodeCanonical(
    new Map<string, unknown>([
      ['v', manifest.v],
      ['at', manifest.at],
      ['object', manifest.object],
      ['kind', manifest.kind],
      ['key', manifest.key],
      ['reach', reach],
      ['states', manifest.states],
    ]),
  );
}

function parseManifest(bytes: Uint8Array): DestructionReceiptManifest {
  const raw = decodedMap(decodeClosedDocument(bytes, 'DESTRUCTION_RECEIPT_BAD_MANIFEST'));
  if (raw === null) throw badManifest('payload is not a map');
  const version = raw.get('v');
  if (typeof version !== 'number' || !Number.isInteger(version)) {
    throw badManifest('v must be an integer destruction receipt version');
  }
  if (version !== 1) {
    throw new ReceiptError(
      'DESTRUCTION_RECEIPT_UNSUPPORTED_VERSION',
      `destruction receipt version ${String(version)} is not a format this package reads`,
    );
  }
  assertDefined(raw, DESTRUCTION_RECEIPT_MANIFEST_MEMBERS, 'manifest');
  const manifest: DestructionReceiptManifest = {
    v: 1,
    at: requireStamp(raw.get('at'), 'at'),
    object: requireDigest(raw.get('object'), 'object'),
    kind: requireKind(raw.get('kind'), 'kind'),
    key: requireDigest(raw.get('key'), 'key'),
    reach: readReach(raw.get('reach')),
    states: requireStates(raw.get('states'), 'states'),
  };
  return manifest;
}

/**
 * The signed header, read under the rule the format sets for this map, which closes its labels as well as its
 * values. The content type is answered before the key parameters, for the reason the redaction gives with more
 * force here: six documents come from one key, each of which passes its own checks, and reading a destruction
 * receipt as one of the other five is not recoverable afterwards.
 */
function readHeader(bytes: Uint8Array): ProtectedHeader {
  const raw = decodedMap(decodeClosedDocument(bytes, 'DESTRUCTION_RECEIPT_BAD_HEADER'));
  if (raw === null) throw new ReceiptError('DESTRUCTION_RECEIPT_BAD_HEADER', 'not a map');
  for (const label of raw.keys()) {
    if (!(DECLARED_DESTRUCTION_RECEIPT_PROTECTED_LABELS as readonly unknown[]).includes(label)) {
      throw new ReceiptError('DESTRUCTION_RECEIPT_BAD_HEADER', `it carries a label the format does not define: ${memberName(label)}`);
    }
  }
  const contentType = raw.get(COSE_HEADER_CONTENT_TYPE);
  if (typeof contentType !== 'string') {
    throw new ReceiptError('DESTRUCTION_RECEIPT_BAD_HEADER', `typ must be a tstr, got ${typeof contentType}`);
  }
  if (contentType !== DESTRUCTION_RECEIPT_CONTENT_TYPE) {
    throw new ReceiptError('DESTRUCTION_RECEIPT_BAD_HEADER', `typ=${contentType}`);
  }
  const alg = raw.get(COSE_HEADER_ALG);
  if (typeof alg !== 'number') throw new ReceiptError('UNSUPPORTED_ALG', `alg must be an integer label, got ${typeof alg}`);
  if (alg !== ALG_EDDSA) throw new ReceiptError('UNSUPPORTED_ALG', `alg=${alg}`);
  const kid = raw.get(COSE_HEADER_KID);
  if (!(kid instanceof Uint8Array) || kid.length !== DIGEST_BYTES) {
    throw new ReceiptError('DESTRUCTION_RECEIPT_BAD_HEADER', `kid must be a ${DIGEST_BYTES}-byte bstr`);
  }
  return { alg: ALG_EDDSA, kid, contentType };
}

/** The envelope, and the header read inside it. The `unprotected` map carries no claim and is read for shape only. */
function readEnvelope(bytes: Uint8Array): CoseSign1 & { header: ProtectedHeader } {
  const top = decodeCanonical(bytes, 'DESTRUCTION_RECEIPT_MALFORMED_CBOR');
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

/**
 * A manifest read and a signature not yet checked: shape, version, closure, the two digest widths, the kind
 * and class registries, the completeness of the reach list, the format's own reach limit, the epoch floor,
 * the bound sentence and the two distinct keys. None of it needs a key or an object to be true, so a document
 * that contradicts itself is refused whoever signed it and whatever it was written about.
 */
export function decodeDestructionReceipt(bytes: Uint8Array): DecodedDestructionReceipt {
  const envelope = readEnvelope(bytes);
  const manifest = parseManifest(envelope.payloadBytes);
  if (equalBytes(manifest.key, envelope.header.kid)) {
    throw new ReceiptError(
      'DESTRUCTION_RECEIPT_KEY_IS_SIGNER',
      `the receipt names ${toHex(manifest.key)} as destroyed and its own header is sealed by that kid`,
    );
  }
  return { manifest, header: envelope.header, envelope };
}

/**
 * Sign a destruction receipt.
 *
 * The manifest is encoded, run back through this file's own structural parser, and only then signed, because
 * a writer that produced bytes its own reader refuses has made a document that cannot be handed over. That
 * covers the structural half, which is every refusal `decodeDestructionReceipt` makes. The designation is not
 * checked against an object, because the object is not an argument here and a writer that claimed to check
 * what it cannot see would be signing a stronger statement than it had made.
 *
 * The key is checked as the redaction writer checks its own, and one refusal is added that belongs to this
 * container alone: a writer may not seal a receipt under the kid it names as destroyed. A caller that wants
 * the refused shape is a conformance vector, and a vector assembles the four published pieces rather than
 * going through this function.
 */
export function signDestructionReceipt(manifest: DestructionReceiptManifest, key: SigningKey): Uint8Array {
  if (key.kid.length !== DIGEST_BYTES || key.privateKey.length !== DIGEST_BYTES || key.publicKey.length !== DIGEST_BYTES) {
    throw new ReceiptError('BAD_SIGNING_KEY', `a destruction receipt signing key is a ${DIGEST_BYTES}-byte Ed25519 key and a ${DIGEST_BYTES}-byte kid`);
  }
  if (!equalBytes(keyId(key.publicKey), key.kid)) {
    throw new ReceiptError('BAD_SIGNING_KEY', 'the kid of a destruction receipt signing key is sha256 of its public key');
  }
  if (equalBytes(manifest.key, key.kid)) {
    throw new ReceiptError(
      'DESTRUCTION_RECEIPT_KEY_IS_SIGNER',
      'a deployment cannot seal a statement that its own signing key is destroyed under that key',
    );
  }
  const payloadBytes = encodeDestructionReceiptManifest(manifest);
  parseManifest(payloadBytes);
  const protectedBytes = encodeDestructionReceiptProtectedHeader(key.kid);
  const signature = signEd25519(destructionReceiptSigStructure(protectedBytes, payloadBytes), key.privateKey);
  return sealDestructionReceipt(protectedBytes, payloadBytes, signature);
}

/**
 * The key a destruction receipt verifies under, from whichever of the two designations the caller used. The
 * two shapes and the precedence between them are the redaction's, stated there and named here rather than
 * restated. The disagreement is refused by name rather than left to the signature check, because a wrong key
 * and an edited document send an operator to two different places.
 */
function envelopeKey(kid: Uint8Array, options: DestructionReceiptVerifyOptions): Uint8Array {
  const designated = options.publicKey !== undefined ? options.publicKey : options.resolveKey?.(kid);
  if (designated === undefined) {
    throw new ReceiptError('DESTRUCTION_RECEIPT_UNKNOWN_KEY', `header kid=${toHex(kid)}`);
  }
  const expected = keyId(designated);
  if (!equalBytes(kid, expected)) {
    throw new ReceiptError('DESTRUCTION_RECEIPT_KID_MISMATCH', `header kid=${toHex(kid)} key kid=${toHex(expected)}`);
  }
  return designated;
}

/**
 * The optional half: the bytes a caller holds that this receipt says were destroyed. The digest is recomputed
 * over exactly these bytes and compared, and the kind claim is read out of the bytes' own signed header,
 * which is what makes `kind` a check rather than a caption. A document the envelope reader refuses is refused
 * as a disagreement with the kind, because the only question these bytes are asked here is whether they are
 * the document the receipt names.
 */
function readHandedObject(
  objectBytes: Uint8Array,
  manifest: DestructionReceiptManifest,
): { objectSha256: Uint8Array; objectKind: string } {
  const objectSha256 = destructionObjectDigest(objectBytes);
  if (!equalBytes(manifest.object, objectSha256)) {
    throw new ReceiptError(
      'DESTRUCTION_RECEIPT_OBJECT_MISMATCH',
      `the receipt designates ${toHex(manifest.object)} and the bytes handed hash to ${toHex(objectSha256)}`,
    );
  }
  try {
    return { objectSha256, objectKind: decodeCoseSign1(objectBytes, manifest.kind).header.contentType };
  } catch (reason) {
    if (!(reason instanceof ReceiptError)) throw reason;
    throw new ReceiptError(
      'DESTRUCTION_RECEIPT_KIND_DISAGREES',
      `the receipt names ${JSON.stringify(manifest.kind)} and the designated bytes answer as ${reason.code}: ${reason.message}`,
    );
  }
}

/**
 * Verify a destruction receipt, and the object it designates when the caller holds one.
 *
 * The order keeps the report honest. No designation is answered before a byte is read, because it is a fault
 * in the call. Then the envelope and its content type, before any resolver is consulted, since a document
 * that is not a destruction receipt must not reach a caller's key set. Then this document's own key, its
 * signature, and its structure. Then the optional object, whose digest is compared before its type is read:
 * bytes that are not the designated ones are not the object, and reading a content type out of them would
 * answer a question this receipt never asked.
 *
 * What the reader does not do is fail because the object was not handed. The bytes a destruction receipt
 * designates are the bytes a destruction took, so a reader that required them could only ever verify a receipt
 * whose statement is false. `outcome.objectSha256` and `outcome.objectKind` are present exactly where the
 * bytes were handed, and their absence is the reader saying which half it could not check rather than a
 * silence a caller reads as a pass.
 */
export function verifyDestructionReceipt(
  bytes: Uint8Array,
  options: DestructionReceiptVerifyOptions,
): VerifiedDestructionReceipt {
  if (options.publicKey === undefined && options.resolveKey === undefined) {
    throw new ReceiptError('DESTRUCTION_RECEIPT_UNKNOWN_KEY', 'no publicKey or resolveKey provided');
  }
  const decoded = decodeDestructionReceipt(bytes);
  const publicKey = envelopeKey(decoded.header.kid, options);
  if (
    !ed25519.verify(
      decoded.envelope.signature,
      destructionReceiptSigStructure(decoded.envelope.protectedBytes, decoded.envelope.payloadBytes),
      publicKey,
      { zip215: false },
    )
  ) {
    throw new ReceiptError('INVALID_SIGNATURE');
  }
  const handed =
    options.objectBytes === undefined
      ? undefined
      : readHandedObject(options.objectBytes, decoded.manifest);
  return {
    ...decoded,
    outcome: {
      signer: decoded.header.kid,
      destroyed: decoded.manifest.key,
      reach: decoded.manifest.reach,
      ...(handed === undefined ? {} : { objectSha256: handed.objectSha256, objectKind: handed.objectKind }),
    },
  };
}

