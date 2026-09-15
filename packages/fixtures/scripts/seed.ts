import { sha256 } from '@noble/hashes/sha2.js';

/**
 * Deterministic bytes from a label, so every published artefact in this package falls out
 * of a seed instead of a random draw. A length truncates the digest to the width wanted,
 * which is how a 32-byte key and a 16-byte nonce come from the same helper.
 */
export function labeled(label: string, length?: number): Uint8Array {
  const digest = sha256(new TextEncoder().encode(label));
  return length === undefined ? digest : digest.slice(0, length);
}
