import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha2.js';
import { Tag } from 'cbor2';
import { encodeCanonical, decodeCanonical, decodeClosedDocument, decodedMap } from './cbor.js';
import { ReceiptError } from './errors.js';

export const COSE_SIGN1_TAG = 18;
export const ALG_EDDSA = -8;
export const COSE_HEADER_ALG = 1;
export const COSE_HEADER_CONTENT_TYPE = 3;
export const COSE_HEADER_KID = 4;
export const RECEIPT_CONTENT_TYPE = 'ashaveri/receipt';
/**
 * The content type of the anchor provenance ledger, one of the documents that travel in the framing
 * this module writes. It is named here because it belongs to the family, whose members are all a `COSE_Sign1`
 * over the same three labels sealed by the same key family, and so a reader that is told which of them it
 * holds is told by label 3 and by nothing else in the envelope.
 *
 * The ledger's own reader lives in `@ashaveri/attest-core`, which ships the bytes the ledger speaks of, and
 * that package takes this constant from here rather than spelling the name again: `packages/receipt` is the
 * one owner of the family's content types, and
 * `packages/attest-core/test/anchor-ledger.test.ts` holds the reader's own name for the document against
 * this declaration and against the block `anchor-provenance.cddl` writes. Which label names which document
 * stays this package's answer.
 */
export const ANCHOR_PROVENANCE_CONTENT_TYPE = 'ashaveri/anchor-provenance';

export interface ProtectedHeader {
  alg: number;
  kid: Uint8Array;
  contentType: string;
}

export interface CoseSign1 {
  protectedBytes: Uint8Array;
  unprotected: Map<unknown, unknown>;
  payloadBytes: Uint8Array;
  signature: Uint8Array;
}

export interface SigningKey {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  kid: Uint8Array;
}

export function keyId(publicKey: Uint8Array): Uint8Array {
  return sha256(publicKey);
}

export function generateSigningKey(): SigningKey {
  return signingKeyFromSeed(ed25519.utils.randomSecretKey());
}

/** Rebuilds a signing key from a 32-byte Ed25519 seed, as a TEE key derivation returns one. */
export function signingKeyFromSeed(seed: Uint8Array): SigningKey {
  if (seed.length !== 32) {
    throw new ReceiptError('BAD_SIGNING_KEY', `seed must be 32 bytes, got ${seed.length}`);
  }
  const publicKey = ed25519.getPublicKey(seed);
  return { privateKey: seed, publicKey, kid: keyId(publicKey) };
}

/**
 * The labels `receipt.cddl` declares for a protected header. The set the parser refuses everything
 * else with, exported so a test can hold it against the block that file names rather than against
 * this module's own reading of it: which three labels exist is the format's answer, and only a reader
 * of both can see that this list is that answer.
 */
export const DECLARED_PROTECTED_LABELS: readonly number[] = [
  COSE_HEADER_ALG,
  COSE_HEADER_CONTENT_TYPE,
  COSE_HEADER_KID,
];

/**
 * How a label the reader was not told about names itself back. COSE header labels are integers, so
 * one that is not is described by what it is rather than rendered through a value's default
 * `toString`, and one that is a number the decoder cannot hold as a `number` is called an integer too:
 * a tag 2 or tag 3 key, and any CBOR integer wider than 2^53-1, all arrive as `bigint`, which is an
 * integer outside the range a label occupies rather than something that is not an integer. Saying
 * otherwise sends whoever reads the log looking for a type bug instead of at the label space.
 * `ReceiptError` bounds the detail and keeps it to one line whoever raised it, which is what lets this
 * site quote a name out of bytes the caller chose.
 */
function labelName(label: unknown): string {
  if (typeof label === 'number') return String(label);
  if (typeof label === 'string') return `'${label}'`;
  if (label instanceof Uint8Array) return `a bstr label of length ${label.length}`;
  if (typeof label === 'bigint') return 'an integer outside the range a COSE label occupies';
  return 'a label that is not an integer';
}

/**
 * The signed header as the framing reads it back, closed against the three labels and answered for the one
 * content type the caller's format names.
 *
 * The content type is an argument for the same reason `buildProtectedHeader` takes one: the three labels,
 * their order and their encodings are the family's answer, and which document a reader is holding is the
 * caller's. It defaults to this package's own name because the framing belongs to the receipt format, and
 * every other member of the family borrows the framing rather than the answer in label 3.
 */
function parseProtectedHeader(bytes: Uint8Array, declaredContentType: string = RECEIPT_CONTENT_TYPE): ProtectedHeader {
  // Read under the closed-document rule, which is what closes this map's labels as well as its
  // values: a label written as the float `1.0` decodes to the same map key as the integer label `1`
  // and takes its slot, so a check placed after the decode would be reading one merged entry and
  // could not tell which of the two labels the bytes carried. Refused here, at the decode, the way
  // the format's own type rule refuses it.
  const raw = decodedMap(decodeClosedDocument(bytes, 'BAD_PROTECTED_HEADER'));
  if (raw === null) throw new ReceiptError('BAD_PROTECTED_HEADER', 'not a map');
  // Closed, as the payload maps are, and for the same reason plus one true only here: these bytes are
  // inside the signature, because the `Sig_structure` hashes the protected bstr itself. A label the
  // format does not declare is therefore an authenticated parameter, and a reader that walked past it
  // would hand a verifier a document other than the one the issuer signed. Refused by name, before
  // any declared label is read, so the refusal a caller hears does not depend on what else the map
  // happened to hold.
  for (const label of raw.keys()) {
    if (!(DECLARED_PROTECTED_LABELS as readonly unknown[]).includes(label)) {
      throw new ReceiptError('BAD_PROTECTED_HEADER', `it carries a label the format does not define: ${labelName(label)}`);
    }
  }
  const alg = raw.get(COSE_HEADER_ALG);
  if (typeof alg !== 'number') throw new ReceiptError('UNSUPPORTED_ALG', `alg must be an integer label, got ${typeof alg}`);
  if (alg !== ALG_EDDSA) throw new ReceiptError('UNSUPPORTED_ALG', `alg=${alg}`);
  const kid = raw.get(COSE_HEADER_KID);
  if (!(kid instanceof Uint8Array) || kid.length !== 32) {
    throw new ReceiptError('BAD_PROTECTED_HEADER', 'kid must be a 32-byte bstr');
  }
  const contentType = raw.get(COSE_HEADER_CONTENT_TYPE);
  if (typeof contentType !== 'string') {
    throw new ReceiptError('BAD_PROTECTED_HEADER', `typ must be a tstr, got ${typeof contentType}`);
  }
  if (contentType !== declaredContentType) {
    throw new ReceiptError('BAD_PROTECTED_HEADER', `typ=${contentType}`);
  }
  return { alg: ALG_EDDSA, kid, contentType };
}

function sigStructure(protectedBytes: Uint8Array, externalAad: Uint8Array, payloadBytes: Uint8Array): Uint8Array {
  return encodeCanonical(['Signature1', protectedBytes, externalAad, payloadBytes]);
}

/**
 * The signed header: `alg`, `typ` and `kid`, in the order the CDDL lists them, canonically encoded so
 * key order is bytewise and no caller can move a byte of what gets signed.
 *
 * The content type is the one parameter the documents this package writes do not share. They are
 * all a `COSE_Sign1` over the same three labels, sealed by the same key family, and a receipt, a pack,
 * an export and a deployment manifest all pass their own checks, so the field that tells them apart has
 * to be answered before anything about the payload is. It arrives as an argument rather than being read
 * from the payload for that reason, and it defaults to the receipt's own name because this module is the
 * receipt format's, and every other format borrows the framing rather than the answer in label 3.
 */
export function buildProtectedHeader(kid: Uint8Array, contentType: string = RECEIPT_CONTENT_TYPE): Uint8Array {
  return encodeCanonical(
    new Map<number, unknown>([
      [COSE_HEADER_ALG, ALG_EDDSA],
      [COSE_HEADER_CONTENT_TYPE, contentType],
      [COSE_HEADER_KID, kid],
    ]),
  );
}

/**
 * The four elements of a `COSE_Sign1`, tagged 18, exactly as RFC 9052 section 4.4 orders them. This is
 * the whole of what a writer of any of these documents does last, and the formats share it byte for
 * byte, so it lives here once and each format's own sealer names it rather than restating it: a second
 * copy is a second place where a signed document could be assembled differently from the one a reader
 * expects.
 *
 * `unprotected` is an argument because each format declares that map `{ * any => any }` in its
 * own CDDL, so a writer of any one of them may fill it. It sits outside the `Sig_structure`, so nothing
 * written there travels as a claim about anything, and a reader that refused a document for the contents of
 * that map would be refusing bytes no signature covers. A receipt and a manifest seal reach this function
 * without naming a map, because those two writers have nothing to say beside what they sign.
 */
export function sealCoseSign1(
  protectedBytes: Uint8Array,
  payloadBytes: Uint8Array,
  signature: Uint8Array,
  unprotected: Map<unknown, unknown> = new Map(),
): Uint8Array {
  return encodeCanonical(new Tag(COSE_SIGN1_TAG, [protectedBytes, unprotected, payloadBytes, signature]));
}

/**
 * A `COSE_Sign1` over a payload, sealed by the framing this module owns.
 *
 * The content type is the last argument and defaults to this package's own name, for the reason every
 * other member of the family passes one: the header's three labels, the kid rule and the `Sig_structure`
 * are the framing's answer, and which document these bytes are is the caller's. A format whose reader lives
 * in another package, which is the anchor provenance ledger's case, seals through here rather than writing
 * the framing a second time beside itself.
 */
export function signCoseSign1(
  payloadBytes: Uint8Array,
  key: SigningKey,
  externalAad: Uint8Array = new Uint8Array(0),
  contentType: string = RECEIPT_CONTENT_TYPE,
): Uint8Array {
  const protectedBytes = buildProtectedHeader(key.kid, contentType);
  const toSign = sigStructure(protectedBytes, externalAad, payloadBytes);
  const signature = ed25519.sign(toSign, key.privateKey);
  return sealCoseSign1(protectedBytes, payloadBytes, signature);
}

export function decodeCoseSign1(
  bytes: Uint8Array,
  contentType: string = RECEIPT_CONTENT_TYPE,
): CoseSign1 & { header: ProtectedHeader } {
  const top = decodeCanonical(bytes);
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
  if (!(signature instanceof Uint8Array) || signature.length !== 64) {
    throw new ReceiptError('NOT_COSE_SIGN1', 'signature is not a 64-byte bstr');
  }
  const header = parseProtectedHeader(protectedBytes, contentType);
  return { protectedBytes, unprotected, payloadBytes, signature, header };
}

export function verifyCoseSign1(
  bytes: Uint8Array,
  publicKey: Uint8Array,
  externalAad: Uint8Array = new Uint8Array(0),
  contentType: string = RECEIPT_CONTENT_TYPE,
): CoseSign1 & { header: ProtectedHeader } {
  const cose = decodeCoseSign1(bytes, contentType);
  const expectedKid = keyId(publicKey);
  if (!equalBytes(cose.header.kid, expectedKid)) throw new ReceiptError('KID_MISMATCH');
  const toSign = sigStructure(cose.protectedBytes, externalAad, cose.payloadBytes);
  // Strict (RFC 8032) verification, the same rule the proof-of-possession verifier keeps to, because
  // both are handed a public key that an operator configured and pasted into a manifest.
  if (!ed25519.verify(cose.signature, toSign, publicKey, { zip215: false })) {
    throw new ReceiptError('INVALID_SIGNATURE');
  }
  return cose;
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (const [i, byte] of a.entries()) diff |= byte ^ (b[i] ?? 0);
  return diff === 0;
}
