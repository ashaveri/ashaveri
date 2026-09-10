import { sha384 } from '@noble/hashes/sha2.js';

const HASH_LENGTH = 48;

function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  let result = 1n;
  let b = base % modulus;
  let e = exponent;
  while (e > 0n) {
    if (e & 1n) {
      result = (result * b) % modulus;
    }
    b = (b * b) % modulus;
    e >>= 1n;
  }
  return result;
}

function u32be(value: number): Uint8Array {
  return new Uint8Array([(value >> 24) & 0xff, (value >> 16) & 0xff, (value >> 8) & 0xff, value & 0xff]);
}

// MGF1 with the same hash as the PSS digest (SHA-384 for AMD certificates).
function mgf1(seed: Uint8Array, length: number): Uint8Array {
  const out = new Uint8Array(length);
  let pos = 0;
  let counter = 0;
  while (pos < length) {
    const block = sha384(concat(seed, u32be(counter)));
    const take = Math.min(block.length, length - pos);
    out.set(block.subarray(0, take), pos);
    pos += take;
    counter++;
  }
  return out;
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function bigintToBytes(value: bigint, length: number): Uint8Array {
  const out = new Uint8Array(length);
  for (let i = length - 1; i >= 0; i--) {
    out[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  return out;
}

function bytesToBigint(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const b of bytes) {
    value = (value << 8n) | BigInt(b);
  }
  return value;
}

function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) {
    out[i] = (a[i] as number) ^ (b[i] as number);
  }
  return out;
}

// RSASSA-PSS verification (RFC 8017 9.1.2) with SHA-384, MGF1-SHA384, and an
// explicit salt length. AMD's ARK and ASK sign with a 48-byte salt over 4096-bit
// RSA keys; parameters come from the certificate's signatureAlgorithm field.
export function verifyRsaPssSha384(
  message: Uint8Array,
  signature: Uint8Array,
  modulus: bigint,
  exponent: bigint,
  saltLength: number,
): boolean {
  const modulusBits = modulus.toString(2).length;
  const keyLength = Math.ceil(modulusBits / 8);
  if (signature.length !== keyLength) {
    return false;
  }
  const signatureValue = bytesToBigint(signature);
  if (signatureValue <= 0n || signatureValue >= modulus) {
    return false;
  }
  const emBits = modulusBits - 1;
  const emLength = Math.ceil(emBits / 8);
  if (emLength < HASH_LENGTH + saltLength + 2) {
    return false;
  }
  const em = bigintToBytes(modPow(signatureValue, exponent, modulus), keyLength).subarray(keyLength - emLength);
  if ((em[emLength - 1] as number) !== 0xbc) {
    return false;
  }
  const maskedDbLength = emLength - HASH_LENGTH - 1;
  const maskedDb = em.subarray(0, maskedDbLength);
  const hash = em.subarray(maskedDbLength, emLength - 1);
  const zeroBits = 8 * emLength - emBits;
  // RFC 8017 9.1.2 steps 6 and 9: the leftmost zeroBits bits of the first
  // octet must be zero in maskedDB and are cleared after unmasking.
  const mask = zeroBits > 0 ? (0xff << (8 - zeroBits)) & 0xff : 0;
  if (zeroBits > 0 && (maskedDb[0] as number) & mask) {
    return false;
  }
  const db = xorBytes(maskedDb, mgf1(hash, maskedDbLength));
  if (zeroBits > 0) {
    db[0] = (db[0] as number) & (0xff ^ mask);
  }
  const psLength = maskedDbLength - saltLength - 1;
  for (let i = 0; i < psLength; i++) {
    if ((db[i] as number) !== 0) {
      return false;
    }
  }
  if ((db[psLength] as number) !== 0x01) {
    return false;
  }
  const salt = db.subarray(psLength + 1);
  const messageHash = sha384(message);
  const digestInput = concat(concat(new Uint8Array(8), messageHash), salt);
  return equalBytes(sha384(digestInput), hash);
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}
