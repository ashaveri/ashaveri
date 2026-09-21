import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha2.js';
import { Tag } from 'cbor2';
import { encodeCanonical, decodeCanonical, decodedMap } from './cbor.js';
import { ReceiptError } from './errors.js';

export const COSE_SIGN1_TAG = 18;
export const ALG_EDDSA = -8;
export const COSE_HEADER_ALG = 1;
export const COSE_HEADER_CONTENT_TYPE = 3;
export const COSE_HEADER_KID = 4;
export const RECEIPT_CONTENT_TYPE = 'ashaveri/receipt';

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
 * `toString`. `ReceiptError` bounds the detail and keeps it to one line whoever raised it, which is
 * what lets this site quote a name out of bytes the caller chose.
 */
function labelName(label: unknown): string {
  if (typeof label === 'number') return String(label);
  if (typeof label === 'string') return `'${label}'`;
  if (label instanceof Uint8Array) return `a bstr label of length ${label.length}`;
  return 'a label that is not an integer';
}

function parseProtectedHeader(bytes: Uint8Array): ProtectedHeader {
  const raw = decodedMap(decodeCanonical(bytes, 'BAD_PROTECTED_HEADER'));
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
  if (contentType !== RECEIPT_CONTENT_TYPE) {
    throw new ReceiptError('BAD_PROTECTED_HEADER', `typ=${contentType}`);
  }
  return { alg: ALG_EDDSA, kid, contentType };
}

function sigStructure(protectedBytes: Uint8Array, externalAad: Uint8Array, payloadBytes: Uint8Array): Uint8Array {
  return encodeCanonical(['Signature1', protectedBytes, externalAad, payloadBytes]);
}

export function buildProtectedHeader(kid: Uint8Array): Uint8Array {
  return encodeCanonical(
    new Map<number, unknown>([
      [COSE_HEADER_ALG, ALG_EDDSA],
      [COSE_HEADER_CONTENT_TYPE, RECEIPT_CONTENT_TYPE],
      [COSE_HEADER_KID, kid],
    ]),
  );
}

export function signCoseSign1(
  payloadBytes: Uint8Array,
  key: SigningKey,
  externalAad: Uint8Array = new Uint8Array(0),
): Uint8Array {
  const protectedBytes = buildProtectedHeader(key.kid);
  const toSign = sigStructure(protectedBytes, externalAad, payloadBytes);
  const signature = ed25519.sign(toSign, key.privateKey);
  return encodeCanonical(new Tag(COSE_SIGN1_TAG, [protectedBytes, new Map(), payloadBytes, signature]));
}

export function decodeCoseSign1(bytes: Uint8Array): CoseSign1 & { header: ProtectedHeader } {
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
  const header = parseProtectedHeader(protectedBytes);
  return { protectedBytes, unprotected, payloadBytes, signature, header };
}

export function verifyCoseSign1(bytes: Uint8Array, publicKey: Uint8Array, externalAad: Uint8Array = new Uint8Array(0)): CoseSign1 & { header: ProtectedHeader } {
  const cose = decodeCoseSign1(bytes);
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
