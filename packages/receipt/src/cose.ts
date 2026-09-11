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

function parseProtectedHeader(bytes: Uint8Array): ProtectedHeader {
  const raw = decodedMap(decodeCanonical(bytes, 'BAD_PROTECTED_HEADER'));
  if (raw === null) throw new ReceiptError('BAD_PROTECTED_HEADER', 'not a map');
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
  if (!ed25519.verify(cose.signature, toSign, publicKey)) throw new ReceiptError('INVALID_SIGNATURE');
  return cose;
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (const [i, byte] of a.entries()) diff |= byte ^ (b[i] ?? 0);
  return diff === 0;
}
