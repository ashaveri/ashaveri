import { ed25519 } from '@noble/curves/ed25519';

/**
 * One signature, one message, one public key, and a yes or no under a stated strictness rule. Every reader in
 * this package answers through a function of this shape, so a deployment can say which implementation it wants
 * and nothing else about the choice changes.
 */
export type Ed25519Verifier = (signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array) => boolean;

const SIGNATURE_BYTES = 64;
const POINT_BYTES = 32;
const SCALAR_BYTES = 32;
const KEY_BYTES = 32;
/** The high bit of the last byte of a point encoding: the sign of `x`, not part of `y`. */
const SIGN_BIT = 0x80;
const Y_MASK = 0x7f;
/** The field prime, and the largest `y` a canonical encoding of it carries. */
const FIELD_PRIME = (1n << 255n) - 19n;
/** `x` is zero exactly at these two values of `y`, which are the only encodings whose sign bit is meaningless. */
const Y_OF_ZERO_X_LOW = 1n;
const Y_OF_ZERO_X_HIGH = FIELD_PRIME - 1n;

/** `2^255 - 20 - 1` as bytes, little endian: the largest `y` a canonical encoding carries. */
const FIELD_PRIME_MINUS_ONE = [
  0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
] as const;

/** The group order minus one, little endian: the largest scalar a signature may state. */
const GROUP_ORDER_MINUS_ONE = [
  0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
] as const;

/**
 * The eight encodings of the points whose order divides the cofactor. A key among these is a universal acceptor
 * under the tolerant rule, where one all-zero signature verifies for every message, so the strict rule refuses
 * them, and a platform that refuses some but not all of them cannot be the one that decides. Derived from the
 * curve - `(L - 1)R + R` for random points - and pinned here as bytes because a shipping guard compares bytes;
 * `test/strict-ed25519.test.ts` re-derives the set on every run rather than trusting these literals, since an
 * entry missing here is a silent widening of what a gateway built on this module admits.
 */
export const SMALL_ORDER_ENCODINGS: readonly Uint8Array[] = [
  '0000000000000000000000000000000000000000000000000000000000000000',
  '0000000000000000000000000000000000000000000000000000000000000080',
  '0100000000000000000000000000000000000000000000000000000000000000',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
].map((hexValue) => Uint8Array.from(Buffer.from(hexValue, 'hex')));

/** True when the little-endian value in `bytes` is at or below `limit`, both read over the same width. */
function atMost(bytes: Uint8Array, limit: readonly number[]): boolean {
  for (let index = bytes.length - 1; index >= 0; index -= 1) {
    const value = bytes[index] ?? 0;
    const bound = limit[index] ?? 0;
    if (value > bound) return false;
    if (value < bound) return true;
  }
  return true;
}

/** The `y` an encoding states: its low 255 bits, with the sign bit of `x` removed. */
function yValue(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let index = POINT_BYTES - 2; index >= 0; index -= 1) value = (value << 8n) | BigInt(bytes[index] ?? 0);
  return value | (BigInt((bytes[POINT_BYTES - 1] ?? 0) & Y_MASK) << 248n);
}

/**
 * A canonical point encoding: `y` below the field prime, and no sign bit on the two encodings whose `x` is zero,
 * because zero carries no sign and the strict rule refuses a spelling that claims one. A runtime that reads `y`
 * modulo the prime accepts both spellings as the same point, which is the difference this clause exists to make.
 */
export function isCanonicalPointEncoding(bytes: Uint8Array): boolean {
  if (bytes.length !== POINT_BYTES) return false;
  if ((bytes[POINT_BYTES - 1] ?? 0) & SIGN_BIT) {
    const y = yValue(bytes);
    if (y === Y_OF_ZERO_X_LOW || y === Y_OF_ZERO_X_HIGH) return false;
  }
  const withoutSign = Uint8Array.from(bytes);
  withoutSign[POINT_BYTES - 1] = (withoutSign[POINT_BYTES - 1] ?? 0) & Y_MASK;
  return atMost(withoutSign, FIELD_PRIME_MINUS_ONE);
}

/** True when the key is one of the eight encodings of a point of small order, which the strict rule refuses outright. */
export function isSmallOrderPublicKey(bytes: Uint8Array): boolean {
  if (bytes.length !== KEY_BYTES) return false;
  return SMALL_ORDER_ENCODINGS.some(
    (one) => one.length === bytes.length && one.every((byte, index) => byte === bytes[index]),
  );
}

/** The scalar half of a signature, read little endian over all 256 bits, must sit inside the group order. */
export function isScalarInGroupOrder(scalarBytes: Uint8Array): boolean {
  if (scalarBytes.length !== SCALAR_BYTES) return false;
  return atMost(scalarBytes, GROUP_ORDER_MINUS_ONE);
}

/**
 * The refusals this module owns, named rather than boolean, because a witness that a clause is load-bearing has
 * to say which one it removed. These are everything the shipped strict rule decides before it does arithmetic,
 * which is why the runtime's own verify is safe underneath them: the platform is asked only the group equation,
 * and every input the tolerant rule would have absorbed is refused above it.
 */
export function refusalBeforeTheEquation(signature: Uint8Array, publicKey: Uint8Array): string | null {
  if (signature.length !== SIGNATURE_BYTES) return 'the signature is not 64 bytes';
  if (publicKey.length !== KEY_BYTES) return 'the public key is not 32 bytes';
  if (!isScalarInGroupOrder(signature.subarray(POINT_BYTES))) return 'the scalar is at or past the group order';
  if (!isCanonicalPointEncoding(publicKey)) return 'the public key is not a canonical point encoding';
  if (!isCanonicalPointEncoding(signature.subarray(0, POINT_BYTES))) return 'the point half is not a canonical encoding';
  if (isSmallOrderPublicKey(publicKey)) return 'the public key is a point of small order';
  return null;
}

/** What the pure JavaScript reader answers: the library's own strict rule, refusals and equation together. */
export const nobleStrictVerify: Ed25519Verifier = (signature, message, publicKey) => {
  try {
    return ed25519.verify(signature, message, publicKey, { zip215: false });
  } catch {
    return false;
  }
};

interface RuntimeCrypto {
  createPublicKey(input: { key: Uint8Array; format: 'der'; type: 'spki' }): unknown;
  verify(algorithm: null, message: Uint8Array, publicKey: unknown, signature: Uint8Array): boolean;
}

/** The SubjectPublicKeyInfo prefix that says "Ed25519, then a 32-byte point". */
const SPKI_ED25519_PREFIX = Uint8Array.from([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]);

/**
 * The same rule, checked here, with the runtime's own primitive answering the equation. A factory rather than a
 * constant, so a proof can hand it a runtime that answers nothing and watch the fallback be taken instead of
 * assuming which runtime this module happened to be loaded under.
 */
export function runtimeStrictVerify(crypto: RuntimeCrypto | null): Ed25519Verifier | null {
  if (crypto === null) return null;
  return (signature, message, publicKey) => {
    if (refusalBeforeTheEquation(signature, publicKey) !== null) return false;
    const der = new Uint8Array(SPKI_ED25519_PREFIX.length + KEY_BYTES);
    der.set(SPKI_ED25519_PREFIX);
    der.set(publicKey, SPKI_ED25519_PREFIX.length);
    try {
      return crypto.verify(
        null,
        message,
        crypto.createPublicKey({ key: der, format: 'der', type: 'spki' }),
        signature,
      );
    } catch {
      // A key the runtime will not build is a refusal rather than a crash: the widths and the encodings above
      // are checked, and what is left is the runtime's own judgement about its own formats.
      return false;
    }
  };
}

/** The two builtin functions the primitive is reached through, read structurally as the signer's are. */
function runtimeCrypto(): RuntimeCrypto | null {
  const host = globalThis as { process?: { getBuiltinModule?: (id: string) => unknown } };
  const builtin = host.process?.getBuiltinModule?.('node:crypto');
  if (typeof builtin !== 'object' || builtin === null) return null;
  const candidate = builtin as Partial<RuntimeCrypto>;
  if (typeof candidate.createPublicKey !== 'function' || typeof candidate.verify !== 'function') return null;
  return candidate as RuntimeCrypto;
}

/**
 * The verifier this build prefers where the runtime exposes a primitive: the refusals above, then the platform's
 * equation, which costs between a seventh and a sixteenth of what the JavaScript reader costs for the same field
 * and the same group law. `nobleStrictVerify` on a browser or an edge runtime, which is where the pure JavaScript
 * reader stays in charge and nothing about the rule changes.
 */
export const preferredStrictVerify: Ed25519Verifier =
  runtimeStrictVerify(runtimeCrypto()) ?? nobleStrictVerify;

/** Which implementation a run answers with, for the sentence a start-up report prints. */
export const strictVerifySource: 'runtime' | 'library' =
  preferredStrictVerify === nobleStrictVerify ? 'library' : 'runtime';
