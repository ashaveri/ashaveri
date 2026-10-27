import { ed25519 } from '@noble/curves/ed25519';

/** One Ed25519 seed in, one 64-byte signature out. */
export type Ed25519Signer = (message: Uint8Array, seed: Uint8Array) => Uint8Array;

const SEED_BYTES = 32;

/**
 * `createPrivateKey` takes a seed only inside a PKCS#8 wrapper: version 0, the `id-EdDSA-Ed25519` algorithm
 * identifier, then a 32-byte OCTET STRING holding the seed. A test holds these bytes against what the runtime
 * exports for a key it generated itself, so they are the runtime's spelling of a seed and not an assumption.
 */
const PKCS8_ED25519_SEED_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

/**
 * The two builtin functions the primitive is reached through, read structurally so this package keeps no Node
 * import of its own: a client compiled for a browser or an edge runtime links this module and finds no such
 * runtime, which is what leaves the library path live there rather than a link error.
 */
interface RuntimeCrypto {
  createPrivateKey(input: { key: Uint8Array; format: 'der'; type: 'pkcs8' }): unknown;
  sign(algorithm: null, message: Uint8Array, privateKey: unknown): Uint8Array;
}

function runtimeCrypto(): RuntimeCrypto | null {
  const host = globalThis as { process?: { getBuiltinModule?: (id: string) => unknown } };
  const builtin = host.process?.getBuiltinModule?.('node:crypto');
  if (typeof builtin !== 'object' || builtin === null) return null;
  const candidate = builtin as Partial<RuntimeCrypto>;
  if (typeof candidate.createPrivateKey !== 'function' || typeof candidate.sign !== 'function') return null;
  return candidate as RuntimeCrypto;
}

/**
 * The seed inside the wrapper the runtime reads, or nothing for a width the runtime would read short: it takes
 * the bytes its own header declares and drops whatever follows them, so a longer key must reach the library,
 * which refuses a key by length rather than signing a seed its caller never handed it.
 */
function pkcs8Seed(seed: Uint8Array): Uint8Array | null {
  if (seed.length !== SEED_BYTES) return null;
  const wrapper = new Uint8Array(PKCS8_ED25519_SEED_PREFIX.length + SEED_BYTES);
  wrapper.set(PKCS8_ED25519_SEED_PREFIX);
  wrapper.set(seed, PKCS8_ED25519_SEED_PREFIX.length);
  return wrapper;
}

/**
 * The runtime's own Ed25519 signer, or `null` where the runtime exposes none. Exported for the proof that the
 * two backends spell one signature alike; the seal sites below name no backend and take this one where it exists.
 */
export const nativeEd25519Signer: Ed25519Signer | null = (() => {
  const crypto = runtimeCrypto();
  if (crypto === null) return null;
  return (message, seed) => {
    const wrapper = pkcs8Seed(seed);
    if (wrapper === null) return ed25519.sign(message, seed);
    // A null algorithm is the one Ed25519 has: the message reaches the primitive whole, with nothing prehashed.
    return new Uint8Array(crypto.sign(null, message, crypto.createPrivateKey({ key: wrapper, format: 'der', type: 'pkcs8' })));
  };
})();

/**
 * Signs one message with one private key, at each of this package's seal sites: through the runtime's primitive
 * where the runtime has one, through the pure JavaScript curve library where it has none.
 *
 * The third argument is the seam that hides the runtime primitive. Passing `null` is what a runtime without one
 * does of its own accord, so a proof can hold the fallback to the bytes it already agrees to rather than assume them.
 */
export function signEd25519(
  message: Uint8Array,
  privateKey: Uint8Array,
  signer: Ed25519Signer | null = nativeEd25519Signer,
): Uint8Array {
  return signer === null ? ed25519.sign(message, privateKey) : signer(message, privateKey);
}
