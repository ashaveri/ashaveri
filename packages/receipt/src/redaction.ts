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
import { packRecordDigest, verifyPack, type PackVerifyOptions, type VerifiedPack, type VerifiedPackItem } from './pack.js';

/**
 * A redaction manifest, read and written: what `packages/receipt/redaction.cddl` states, run.
 *
 * A pack attests that the receipts inside one window are all of them, and its chain is linear: the record
 * after a removed one names the removed record's digest as its own predecessor, so lifting a middle record
 * out breaks the walk rather than shortening it. An erasure aimed at one receipt inside a closed pack
 * therefore has no answer inside the pack, and the ruled answer is a second signed document that states the
 * removal instead of a rewritten first one. This module reads and writes that document. It is a checker and
 * not a verdict engine: it answers whether the bytes are a well-formed redaction, whether the key it was
 * handed signed them, whether the pack it names is the pack it was handed, whether every id it names is a
 * record of that pack, and what the chain over the records that remain hashes to. It answers nothing about a
 * duty, nothing about whether the removed bytes are unreachable anywhere else, and nothing about freshness,
 * and it resolves nothing by itself: every key arrives as an argument and the pack arrives as bytes.
 *
 * Four things a reader is owed, and where each is settled here. That the redaction was sealed by a key it
 * designates, and which pack it speaks about, by a digest recomputed from that pack's own bytes rather than
 * by an id the writer chose: `redactionPackDigest` over the bytes handed, compared against `manifest.pack`.
 * That every named item is present in that pack and that nothing else is removed: the ids are matched
 * against the pack's walked items, and the survivor set is the walk minus the names, so a larger removal
 * than the one stated changes the digest the reader recomputes. What the surviving sequence's chain digest
 * is, under the rule the pack itself uses: `redactionSurvivorDigest`, which folds `packRecordDigest` over
 * the survivors relinked from the pack's own anchor. And that the redaction cannot alter the original: the
 * pack is only ever handed to `verifyPack`, whose seal and walk are re-checked here, so the original head
 * and the reduced head are two numbers a reader is shown side by side rather than one number a writer chose.
 *
 * The split into two entry points is the one `pack.ts` and `export.ts` make. `decodeRedaction` answers what
 * is true of the document whoever signed it and needs no key and no pack, because a manifest that
 * contradicts itself does so quietly. `verifyRedaction` adds the signature, the pack and the arithmetic over
 * the survivors, which are the checks that mean something only against a signature the reader has accepted
 * and only against the pack this statement is about.
 *
 * Two refusals are about the reader's inputs rather than about the bytes and are answered before anything is
 * decoded, for the reason `verifyPack` gives: no designation is a fault in the call, and so is being handed
 * a redaction without the pack it names. The second of those is the availability rule stated the other way
 * round. A reader that cannot reach a redaction still verifies the original pack, because the pack was never
 * rewritten and refers to nothing here; a reader that has the redaction and not the pack can say nothing at
 * all, and says that by name rather than accepting the document on its own word.
 *
 * The writer is `encodeRedactionManifest`, `encodeRedactionProtectedHeader`, `sealRedaction` and
 * `signRedaction`, and `redactionSurvivorDigest` and `redactionPackDigest` are the two computations a caller
 * needs in order to fill the two members that are not its own invention. They are published for the same
 * reason `packRecordDigest` is: a reader recomputes both, and a reimplementer who cannot see them cannot
 * compare two readers' refusals. `signRedaction` guarantees the structural half and not the pack-dependent
 * half, exactly as `signPack` guarantees the shape of a manifest and leaves the chain to the caller, because
 * the pack is not an argument here and a writer that claimed to check what it cannot see would be signing a
 * stronger statement than it had made.
 */

/** The content type that keeps a redaction from being read as a receipt, a pack or an export, at label 3. */
export const REDACTION_CONTENT_TYPE = 'ashaveri/redaction';

/**
 * The three labels `redaction.cddl` declares for a signed redaction header, exported for the same reason
 * the other containers export theirs: which labels exist is the format's answer, and only a reader of both
 * the file and this list can see that the two are one answer.
 */
export const DECLARED_REDACTION_PROTECTED_LABELS: readonly number[] = [
  COSE_HEADER_ALG,
  COSE_HEADER_CONTENT_TYPE,
  COSE_HEADER_KID,
];

/**
 * The member list of the map this format closes, in the order the CDDL declares it. Exported for a test to
 * hold against the block rather than against this file's reading of it, and exported from `redaction.ts`
 * alone: the package's public surface gains the reader and the writer, not a roster.
 */
export const REDACTION_MANIFEST_MEMBERS = ['v', 'at', 'pack', 'removed', 'reduced', 'states'] as const;

/** One record of a chain, as the fold that relinks it needs it: the name, the stamp and the bytes. */
export interface SurvivorRecord {
  readonly id: string;
  readonly iat: number;
  readonly receipt: Uint8Array;
}

export interface RedactionManifest {
  readonly v: 1;
  /** unix seconds, the instant the removal was stated. Never before the pack's own `at`. */
  readonly at: number;
  /** sha256 of the whole sealed pack document this redaction speaks about. */
  readonly pack: Uint8Array;
  /** The pack's own ids for the records taken out of it, at least one, unique, in no particular order. */
  readonly removed: readonly string[];
  /** The head of the chain over the surviving records, relinked from the pack's own anchor. */
  readonly reduced: Uint8Array;
  /** The writer's own sentence stating the removal. Checked for shape and never for content. */
  readonly states: string;
}

/** What a redaction states about the pack it names, and what the reader recomputed beside it. */
export interface RedactionOutcome {
  /** sha256 of the pack bytes handed to this reader, recomputed here and equal to `manifest.pack`. */
  readonly packSha256: Uint8Array;
  /** The ids as the document states them, each one matched to a record of the pack. */
  readonly removed: readonly string[];
  /** The surviving records, in the order the pack's links fix them. */
  readonly survivors: readonly VerifiedPackItem[];
  /** The head of the chain over those survivors. Recomputed here and equal to `manifest.reduced`. */
  readonly reduced: Uint8Array;
  /** The pack's own head, which still holds over the pack's own run and is not the field above. */
  readonly originalHead: Uint8Array;
  /** The pack read whole: its seal verified, every original verified, and its walk completed. */
  readonly pack: VerifiedPack;
}

export interface DecodedRedaction {
  readonly manifest: RedactionManifest;
  readonly header: ProtectedHeader;
  readonly envelope: CoseSign1;
}

export interface VerifiedRedaction extends DecodedRedaction {
  readonly outcome: RedactionOutcome;
}

/**
 * How a caller hands this reader the key it designates and the pack the redaction speaks about.
 *
 * The two key fields are the pack's, answered the same way and forwarded to `verifyPack` whole rather than
 * resolved once here, because the pack's own run may cross a key rotation and its receipts must be checked
 * against the epochs the caller retained. `packBytes` is the pack, as it was handed over: the reader hashes
 * exactly these bytes and compares the digest against the one the manifest carries, so a redaction pointed
 * at one pack is never read against another. It is required, and a call that leaves it out is refused before
 * a byte of the redaction is read, because the fault is in the call.
 */
export interface RedactionVerifyOptions extends PackVerifyOptions {
  readonly packBytes: Uint8Array;
}

const encoder = new TextEncoder();

/** The widths the format writes beside each position, named once rather than per check site. */
const DIGEST_BYTES = 32;
const SIGNATURE_BYTES = 64;
const ID_MAX_BYTES = 65_535;
const STATES_MAX_BYTES = 2_048;

function badManifest(detail: string): ReceiptError {
  return new ReceiptError('REDACTION_BAD_MANIFEST', detail);
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
 * The closedness rule for this container's one map. A member no position of this version defines makes the
 * document malformed rather than a member a reader agreed to forget, which is the same rule every other
 * signed document in this package enforces; there is no nested map to walk into, because the removal list is
 * a list of names and not a list of facts about each removal.
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
 * three documents frame theirs: the context string, the protected bstr, the external AAD and the payload
 * bstr, canonically encoded. A reader verifies with an empty AAD, which is what `redaction.cddl` describes,
 * and nothing inside the envelope carries which one was used, so the framing is published rather than
 * implied.
 */
export function redactionSigStructure(
  protectedBytes: Uint8Array,
  payloadBytes: Uint8Array,
  externalAad: Uint8Array = new Uint8Array(0),
): Uint8Array {
  return encodeCanonical(['Signature1', protectedBytes, externalAad, payloadBytes]);
}

/**
 * The signed header this format writes, carrying the content type that keeps a redaction from being read as
 * one of the three documents a deployment key also seals. The `contentType` argument exists for the one
 * caller who needs a header naming something else, which is a document assembled to be refused: no honest
 * redaction writes another type, and the reader answers this position before it consults a key.
 */
export function encodeRedactionProtectedHeader(kid: Uint8Array, contentType: string = REDACTION_CONTENT_TYPE): Uint8Array {
  return buildProtectedHeader(kid, contentType);
}

/**
 * The four elements of a `COSE_Sign1-Redaction-COSE`, tagged, as the format writes them. The `unprotected`
 * map is the one a signer fills at will and this reader reads nothing out of, and the framing is the shared
 * one, because a redaction and a pack differ in label 3 and nowhere in how a signed document is assembled.
 */
export function sealRedaction(
  protectedBytes: Uint8Array,
  payloadBytes: Uint8Array,
  signature: Uint8Array,
  unprotected: Map<unknown, unknown> = new Map(),
): Uint8Array {
  return sealCoseSign1(protectedBytes, payloadBytes, signature, unprotected);
}

/**
 * The designation member, as the format computes it: sha256 over the whole sealed pack document, the tagged
 * four elements exactly as they were handed over. The whole document and not the manifest inside it, because
 * a pack is its signature as well as its claims, and a redaction that bound only the manifest would not say
 * which of two envelopes carrying that manifest it removed receipts from.
 */
export function redactionPackDigest(packBytes: Uint8Array): Uint8Array {
  return sha256(packBytes);
}

/**
 * The chain over the surviving records, one digest per record in the order the pack's links put them in.
 *
 * The fold is the pack's own rule and nothing else: every term goes through `packRecordDigest` in
 * `pack.ts`, the function the pack reader hashes a walk with, fed the survivor's `id`, its `iat` and its
 * receipt bytes, and a predecessor that is the digest recomputed for the survivor before it. The pack's
 * anchor starts the run, because that is the seam both documents can see: the alternative, chaining the
 * first survivor from the predecessor its record names, would start a chain from the digest of a record the
 * redaction claims to have removed.
 *
 * Two consequences are why this is the construction and not a shorter one. With nothing dropped, every
 * survivor's recomputed predecessor is the predecessor its record already carries, so the fold returns the
 * pack's signed head: a document that named no removal and claimed the original head still held would be
 * stating this value, and `redaction.cddl` refuses the empty list before that claim can be made. With
 * anything dropped, at least one hashed term changes, so the fold cannot return that head, and a reader
 * recomputing over the records it can see cannot be told that a larger removal was a smaller one.
 *
 * An empty survivor sequence has no head, and no value stands in for one. The refusal is raised here rather
 * than at the call site so that the writer's fold and the reader's recomputation answer the same way: a
 * reader that returned the anchor for nothing would accept a redaction that removes a pack's only receipt
 * and states the anchor as the chain it left behind.
 */
export function redactionSurvivorChain(anchor: Uint8Array, survivors: readonly SurvivorRecord[]): Uint8Array[] {
  return survivorFold(anchor, survivors).digests;
}

/** The head of the chain over the surviving records, which is the value the `reduced` member carries. */
export function redactionSurvivorDigest(anchor: Uint8Array, survivors: readonly SurvivorRecord[]): Uint8Array {
  return survivorFold(anchor, survivors).head;
}

/**
 * The fold itself, in one place, returning the chain it built and its head. The head is the last digest by
 * construction rather than by an index read, so the two published answers cannot come from two walks.
 */
function survivorFold(anchor: Uint8Array, survivors: readonly SurvivorRecord[]): { digests: Uint8Array[]; head: Uint8Array } {
  if (anchor.length !== DIGEST_BYTES) {
    throw badManifest(`an anchor of ${anchor.length} bytes, where the format declares ${DIGEST_BYTES}`);
  }
  if (survivors.length === 0) {
    throw new ReceiptError('REDACTION_SURVIVORS_EMPTY', 'a chain over no records has no head');
  }
  const digests: Uint8Array[] = [];
  let prev = anchor;
  for (const one of survivors) {
    prev = packRecordDigest({ id: one.id, iat: one.iat, prev, receipt: one.receipt });
    digests.push(prev);
  }
  return { digests, head: prev };
}

/**
 * The manifest, as the CBOR map `redaction.cddl` declares it: one Map, so key order is bytewise under Core
 * Deterministic Encoding and no field order in a caller's object can move a byte of what gets signed. The
 * members come in the order the CDDL lists them, and every integer goes out through `encodeCanonical`, the
 * package's one place where the bytes of a number are chosen. That is not cosmetics: a reader recomputes the
 * designation over the pack's bytes and the chain over the survivors' bytes, and a writer that spelled a
 * number another way would make a deployment refuse its own redaction.
 */
export function encodeRedactionManifest(manifest: RedactionManifest): Uint8Array {
  return encodeCanonical(
    new Map<string, unknown>([
      ['v', manifest.v],
      ['at', manifest.at],
      ['pack', manifest.pack],
      ['removed', [...manifest.removed]],
      ['reduced', manifest.reduced],
      ['states', manifest.states],
    ]),
  );
}

/**
 * Sign a redaction manifest.
 *
 * The manifest is encoded, run back through this file's own structural parser, and only then signed, because
 * a writer that produced bytes its own reader refuses has made a document that cannot be handed over. That
 * covers the structural half, which is the half that needs no pack: the version, the closure of the map, the
 * two digest widths, an empty removal list, a duplicated id, a name outside the framing's bound, a sentence
 * with nothing in it and a stamp before the epoch all arrive here before a signature is made. The
 * pack-dependent half is not checked, because the pack is not an argument to this call, and a writer that
 * claimed to check what it cannot see would be signing a stronger statement than it had made. A caller that
 * wants the whole statement checked reads the finished document back with `verifyRedaction`, and a document
 * meant to be refused, which is what a conformance vector is, is assembled from the four pieces above rather
 * than through this function.
 *
 * The key is checked as the pack writer checks its own: `kid` has to be sha256 of the public half travelling
 * beside it, because a header naming a kid that resolves to nothing is a document no reader can verify.
 */
export function signRedaction(manifest: RedactionManifest, key: SigningKey): Uint8Array {
  if (key.kid.length !== DIGEST_BYTES || key.privateKey.length !== DIGEST_BYTES || key.publicKey.length !== DIGEST_BYTES) {
    throw new ReceiptError('BAD_SIGNING_KEY', 'a redaction signing key is a 32-byte Ed25519 key and a 32-byte kid');
  }
  if (!equalBytes(keyId(key.publicKey), key.kid)) {
    throw new ReceiptError('BAD_SIGNING_KEY', 'the kid of a redaction signing key is sha256 of its public key');
  }
  const payloadBytes = encodeRedactionManifest(manifest);
  parseManifest(payloadBytes);
  const protectedBytes = encodeRedactionProtectedHeader(key.kid);
  const signature = ed25519.sign(redactionSigStructure(protectedBytes, payloadBytes), key.privateKey);
  return sealRedaction(protectedBytes, payloadBytes, signature);
}

function requireStamp(value: unknown, position: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw badManifest(`${position} must be a unix time no earlier than the epoch`);
  }
  return value;
}

function requireDigest(value: unknown, position: string): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== DIGEST_BYTES) {
    throw badManifest(`${position} must be a ${DIGEST_BYTES}-byte bstr`);
  }
  return value;
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
 * The removal list, read and bounded. `[+ …]` requires at least one id, and the reason is the artifact's
 * purpose rather than tidiness: a redaction that removes nothing exists to state that the pack's signed head
 * still holds, which is a true and useless sentence, and a container that could state it is one in which a
 * no-op and a forgery look alike. So the empty list is malformed, refused before any pack is consulted.
 *
 * No two entries name one id. The pack refuses duplicate ids among its items and a reader reports a refusal by
 * naming one, so a list naming a record twice would be a count of removals that disagrees with the set of
 * removals it states, and the survivor set would be the same either way while the document read as two.
 */
function readRemoved(raw: unknown): readonly string[] {
  if (!Array.isArray(raw)) throw badManifest('removed must be an array of ids');
  if (raw.length === 0) throw badManifest('a redaction declares a non-empty removed and carries nothing in it');
  const ids = raw.map((one, index) => requireText(one, `removed[${String(index)}]`, ID_MAX_BYTES));
  const seen = new Set<string>();
  for (const one of ids) {
    if (seen.has(one)) throw new ReceiptError('REDACTION_DUPLICATE_ID', one);
    seen.add(one);
  }
  return ids;
}

/**
 * The signed header, read under the rule the format sets for this map, which closes its labels as well as its
 * values. The content type is answered before the key parameters of the header are, for the reason the pack
 * gives and with more force here: a redaction, a pack and an export are three documents one key signs, each
 * of which passes its own checks, and the mistake a content type exists to prevent is reading the second as
 * the third, which is not recoverable afterwards.
 */
function readHeader(bytes: Uint8Array): ProtectedHeader {
  const raw = decodedMap(decodeClosedDocument(bytes, 'REDACTION_BAD_HEADER'));
  if (raw === null) throw new ReceiptError('REDACTION_BAD_HEADER', 'not a map');
  for (const label of raw.keys()) {
    if (!(DECLARED_REDACTION_PROTECTED_LABELS as readonly unknown[]).includes(label)) {
      throw new ReceiptError('REDACTION_BAD_HEADER', `it carries a label the format does not define: ${memberName(label)}`);
    }
  }
  const contentType = raw.get(COSE_HEADER_CONTENT_TYPE);
  if (typeof contentType !== 'string') {
    throw new ReceiptError('REDACTION_BAD_HEADER', `typ must be a tstr, got ${typeof contentType}`);
  }
  if (contentType !== REDACTION_CONTENT_TYPE) {
    throw new ReceiptError('REDACTION_BAD_HEADER', `typ=${contentType}`);
  }
  const alg = raw.get(COSE_HEADER_ALG);
  if (typeof alg !== 'number') throw new ReceiptError('UNSUPPORTED_ALG', `alg must be an integer label, got ${typeof alg}`);
  if (alg !== ALG_EDDSA) throw new ReceiptError('UNSUPPORTED_ALG', `alg=${alg}`);
  const kid = raw.get(COSE_HEADER_KID);
  if (!(kid instanceof Uint8Array) || kid.length !== DIGEST_BYTES) {
    throw new ReceiptError('REDACTION_BAD_HEADER', 'kid must be a 32-byte bstr');
  }
  return { alg: ALG_EDDSA, kid, contentType };
}

/**
 * The envelope, and the header read inside it. The `unprotected` map is decoded under the rule that admits
 * anything, because it sits outside the signature and carries no claim: a floating-point number inside it is
 * nobody's integer wearing a different coat, and nothing here reads a value out of it.
 */
function readEnvelope(bytes: Uint8Array): CoseSign1 & { header: ProtectedHeader } {
  const top = decodeCanonical(bytes, 'REDACTION_MALFORMED_CBOR');
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

function parseManifest(bytes: Uint8Array): RedactionManifest {
  const raw = decodedMap(decodeClosedDocument(bytes, 'REDACTION_BAD_MANIFEST'));
  if (raw === null) throw badManifest('payload is not a map');
  const version = raw.get('v');
  if (typeof version !== 'number' || !Number.isInteger(version)) {
    throw badManifest('v must be an integer redaction version');
  }
  if (version !== 1) {
    throw new ReceiptError('REDACTION_UNSUPPORTED_VERSION', `redaction manifest version ${String(version)} is not a format this package reads`);
  }
  assertDefined(raw, REDACTION_MANIFEST_MEMBERS, 'manifest');
  const manifest: RedactionManifest = {
    v: 1,
    at: requireStamp(raw.get('at'), 'at'),
    pack: requireDigest(raw.get('pack'), 'pack'),
    removed: readRemoved(raw.get('removed')),
    reduced: requireDigest(raw.get('reduced'), 'reduced'),
    states: requireText(raw.get('states'), 'states', STATES_MAX_BYTES),
  };
  return manifest;
}

/**
 * A manifest read and a signature not yet checked: shape, version, closure, widths, the epoch floor, the
 * non-empty and unique removal list and the bounded sentence. None of it needs a key or a pack to be true, so
 * a document that contradicts itself is refused whoever signed it and whatever it was written about.
 */
export function decodeRedaction(bytes: Uint8Array): DecodedRedaction {
  const envelope = readEnvelope(bytes);
  return { manifest: parseManifest(envelope.payloadBytes), header: envelope.header, envelope };
}

/**
 * The key a redaction verifies under, from whichever of the two designations the caller used. The two shapes
 * and the precedence between them are the pack's, stated once there and named here rather than restated: a
 * `publicKey` says which single key the caller means and a header naming another is a configuration
 * disagreement, and a `resolveKey` is asked for the kid the header carries and answers nothing for a kid it
 * holds no key for. The disagreement is refused by name rather than left to the signature check, because a
 * wrong key and an edited document send an operator to two different places.
 */
function envelopeKey(kid: Uint8Array, options: RedactionVerifyOptions): Uint8Array {
  const designated = options.publicKey !== undefined ? options.publicKey : options.resolveKey?.(kid);
  if (designated === undefined) {
    throw new ReceiptError('REDACTION_UNKNOWN_KEY', `header kid=${toHex(kid)}`);
  }
  const expected = keyId(designated);
  if (!equalBytes(kid, expected)) {
    throw new ReceiptError('REDACTION_KID_MISMATCH', `header kid=${toHex(kid)} key kid=${toHex(expected)}`);
  }
  return designated;
}

/**
 * The pack the caller handed, or the refusal that says none arrived. The argument is required by the type
 * and checked at runtime all the same, because the callers this format is written for pass bytes read off a
 * disk or decoded out of a request, and a call that left the pack out is a fault in the call, which is
 * answered before a byte of the redaction is read rather than as a document question.
 */
function handedPack(packBytes: Uint8Array | undefined): Uint8Array {
  if (!(packBytes instanceof Uint8Array)) {
    throw new ReceiptError('REDACTION_PACK_UNAVAILABLE', 'a redaction is checked against the pack it names and none was handed to the reader');
  }
  return packBytes;
}

/**
 * Verify a redaction against the pack it names.
 *
 * The order is what keeps a report honest. Two faults in the call are answered before a byte is read: no
 * designation, and no pack handed, because a redaction without its pack is a statement nothing can be
 * checked against and the caller's action is to hand over the other document rather than to re-read these
 * bytes. Then the envelope and its content type, before any resolver is consulted, since a document that is
 * not a redaction must not reach a caller's key set. Then this document's own key and signature, then its
 * structure, then the pack it speaks about: the designation is recomputed from the bytes handed and compared
 * before the pack is opened at all, because if those two differ nothing about the pack is a fact about this
 * statement, and reading on would answer the wrong question. Then the two stamps, then the pack's seal and
 * walk, then the removal itself.
 *
 * The pack is read by `verifyPack`, with the caller's designation forwarded whole rather than resolved once
 * here, which is what makes the fourth property structural instead of argued: the original seal and the
 * original walk are re-checked on every reading, over exactly the bytes the designation binds, and a refusal
 * from inside that call keeps the pack's own code, because a pack's sentence says pack and that is the
 * finding. `PACK_UNKNOWN_KEY` is not folded into anything either: a caller whose key set does not reach an
 * epoch the pack's receipts were signed under has too few keys, not a broken pair of documents.
 *
 * Only then is the removal settled, and both halves of it are arithmetic. The ids have to name records the
 * pack's walk reached, or the redaction is about a pack that never carried them. The survivors are the walk
 * with those records dropped, which is the set the reader computes and not the set the document states, so a
 * removal larger than the one named changes the survivor sequence and so changes the digest the fold returns.
 * `reduced` is that fold: the pack's own `packRecordDigest` over the survivors in chain order, relinked from
 * the pack's anchor, and it is compared rather than believed.
 *
 * What comes back keeps the two heads apart, because merging them is the mistake this artifact exists to make
 * impossible. `outcome.originalHead` is the pack's signed head, which holds over the pack's own run and is
 * not the number above it; `outcome.reduced` is the head of a chain the pack does not contain. A caller that
 * prints one where the other belongs is reporting that a receipt was never removed, or that a pack lost its
 * chain, and the two fields are named separately so that neither report is the default.
 */
export function verifyRedaction(bytes: Uint8Array, options: RedactionVerifyOptions): VerifiedRedaction {
  if (options.publicKey === undefined && options.resolveKey === undefined) {
    throw new ReceiptError('REDACTION_UNKNOWN_KEY', 'no publicKey or resolveKey provided');
  }
  const packBytes = handedPack(options.packBytes);
  const envelope = readEnvelope(bytes);
  const publicKey = envelopeKey(envelope.header.kid, options);
  if (
    !ed25519.verify(
      envelope.signature,
      redactionSigStructure(envelope.protectedBytes, envelope.payloadBytes),
      publicKey,
      { zip215: false },
    )
  ) {
    throw new ReceiptError('INVALID_SIGNATURE');
  }
  const manifest = parseManifest(envelope.payloadBytes);
  const packSha256 = redactionPackDigest(packBytes);
  if (!equalBytes(manifest.pack, packSha256)) {
    throw new ReceiptError(
      'REDACTION_PACK_MISMATCH',
      `redaction names pack=${toHex(manifest.pack)} reader holds ${toHex(packSha256)}`,
    );
  }
  // The pack is read by the shipped pack reader, with the caller's designation forwarded whole rather than
  // resolved once here: the pack's own run may cross a key rotation, and its receipts have to be checked
  // against the epochs the caller retained. `packBytes` rides along inside the object and answers nothing in
  // `verifyPack`, which reads the two key fields and nothing else. A refusal from inside this call keeps the
  // pack's own code, because a pack's sentence says pack and that is the finding an operator needs.
  const pack = verifyPack(packBytes, options);
  // The two instants belong to two documents, and both are inside signatures, so a redaction stamped before
  // the pack it removes from began to be assembled is a pair that cannot both be true. This is refused after
  // the pack's own seal and walk because those are what make the pack's `at` worth comparing at all.
  if (manifest.at < pack.manifest.at) {
    throw new ReceiptError(
      'REDACTION_PACK_DISAGREES',
      `the redaction states ${String(manifest.at)} and the pack states assembly begun at ${String(pack.manifest.at)}`,
    );
  }
  const reached = pack.outcome.walked;
  for (const id of manifest.removed) {
    if (!reached.some((one) => one.item.id === id)) {
      throw new ReceiptError('REDACTION_ITEM_ABSENT', `${id} is named by this redaction and carried by no item of the pack it designates`);
    }
  }
  const removed = new Set(manifest.removed);
  const survivors = reached.filter((one) => !removed.has(one.item.id));
  // The fold takes the record's own three terms, and a `PackItem` carries them beside the verified receipt:
  // the predecessor each item names is deliberately not one of them, because relinking is the whole of the
  // construction and an item's own `prev` is a fact about the chain the redaction says is broken.
  const reduced = redactionSurvivorDigest(pack.manifest.chain.anchor, survivors.map((one) => one.item));
  if (!equalBytes(manifest.reduced, reduced)) {
    throw new ReceiptError(
      'REDACTION_SURVIVOR_CHAIN_MISMATCH',
      `${String(survivors.length)} survivor record(s) relinked from the pack's anchor hash to ${toHex(reduced)}, the document carries ${toHex(manifest.reduced)}`,
    );
  }
  return {
    manifest,
    header: envelope.header,
    envelope,
    outcome: {
      packSha256,
      removed: manifest.removed,
      survivors,
      reduced,
      originalHead: pack.manifest.chain.head,
      pack,
    },
  };
}
