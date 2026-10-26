import { createPrivateKey, createPublicKey, sign as signWithKey, verify as verifyWithKey } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { ED25519_TORSION_SUBGROUP, ed25519 } from '@noble/curves/ed25519';
import { decodeCoseSign1, encodeCanonical, signingKeyFromSeed, type SigningKey } from '../src/index.js';

/**
 * The proof a backend swap needs: the runtime's own Ed25519 primitive and the pure JavaScript curve
 * library held to one another over every receipt vector this repository publishes, in both directions.
 *
 * Nothing here names a key, a message or a signature as a literal. A vector is one published document,
 * its signing input is rebuilt from the bytes of that document, and its key is the seed the corpus
 * publishes for the kid that travels inside the document's own protected header, so a vector added to
 * the corpus is proven or refuses without this file changing.
 */
interface PublishedVector {
  name: string;
  key: SigningKey;
  signingInput: Uint8Array;
  shippedSignature: Uint8Array;
}

const DATA = fileURLToPath(new URL('../../fixtures/data', import.meta.url));
const RECEIPTS = join(DATA, 'receipts');
const KEY_DIRECTORY = join(DATA, 'keys');

// `node:crypto` takes an Ed25519 key only as DER, so these are the two wrappers that turn the raw bytes
// the corpus publishes into a key object: PKCS#8 around a seed, and SPKI around a public point.
const PKCS8_ED25519_SEED = Buffer.from('302e020100300506032b657004220420', 'hex');
const SPKI_ED25519_POINT = Buffer.from('302a300506032b6570032100', 'hex');

function nativeSecretKey(seed: Uint8Array) {
  return createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_SEED, Buffer.from(seed)]), format: 'der', type: 'pkcs8' });
}

function nativePublicKey(point: Uint8Array) {
  return createPublicKey({ key: Buffer.concat([SPKI_ED25519_POINT, Buffer.from(point)]), format: 'der', type: 'spki' });
}

/** Signs through the runtime primitive, which is the backend a swap would prefer. */
function nativeSign(vector: PublishedVector): Uint8Array {
  return signWithKey(null, Buffer.from(vector.signingInput), nativeSecretKey(vector.key.privateKey));
}

function nativeVerifies(vector: PublishedVector, signature: Uint8Array): boolean {
  return verifyWithKey(null, Buffer.from(vector.signingInput), nativePublicKey(vector.key.publicKey), Buffer.from(signature));
}

/** Verifies under the rule the shipped verifier keeps to, read as `{ zip215: false }` means it. */
function pureVerifies(vector: PublishedVector, signature: Uint8Array): boolean {
  return ed25519.verify(signature, vector.signingInput, vector.key.publicKey, { zip215: false });
}

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex');
}

/** Every key the corpus publishes, indexed by the kid the package's own derivation gives it. */
function publishedKeys(): Map<string, SigningKey> {
  const ring = new Map<string, SigningKey>();
  for (const file of readdirSync(KEY_DIRECTORY).filter((name) => name.endsWith('.json')).sort()) {
    const stated = JSON.parse(readFileSync(join(KEY_DIRECTORY, file), 'utf8')) as { privateKey: string };
    // Only the seed is taken from the file: the point and the kid come back through the shipped
    // derivation, so a key that no longer agrees with a vector's header is refused rather than trusted.
    const key = signingKeyFromSeed(new Uint8Array(Buffer.from(stated.privateKey, 'hex')));
    ring.set(hex(key.kid), key);
  }
  return ring;
}

/** The published receipt documents, all of them, in directory order. */
function publishedVectors(): PublishedVector[] {
  const ring = publishedKeys();
  return readdirSync(RECEIPTS)
    .filter((name) => name.endsWith('.cbor'))
    .sort()
    .map((file) => {
      const document = decodeCoseSign1(new Uint8Array(readFileSync(join(RECEIPTS, file))));
      const key = ring.get(hex(document.header.kid));
      if (!key) throw new Error(`${file}: no published key carries the kid its protected header states`);
      return {
        name: file.slice(0, -'.cbor'.length),
        key,
        // RFC 9052 section 4.4: the array of the marker, the protected bstr, the external AAD and the
        // payload bstr, canonically encoded. Every published receipt signs an empty external AAD, which
        // is what the shipped verifier passes, so the input here is that document's own bytes.
        signingInput: encodeCanonical(['Signature1', document.protectedBytes, new Uint8Array(0), document.payloadBytes]),
        shippedSignature: document.signature,
      };
    });
}

/** The vectors the corpus itself publishes as carrying a signature that does not hold. */
function publishedSignatureRefusals(): Set<string> {
  const manifest = JSON.parse(readFileSync(join(DATA, 'manifest.json'), 'utf8')) as {
    fixtures: { name: string; expected: string }[];
  };
  return new Set(manifest.fixtures.filter((row) => row.expected === 'INVALID_SIGNATURE').map((row) => row.name));
}

/** The names the corpus indexes its published receipts under. */
function publishedVectorNames(): string[] {
  const manifest = JSON.parse(readFileSync(join(DATA, 'manifest.json'), 'utf8')) as { fixtures: { name: string }[] };
  return manifest.fixtures.map((row) => row.name).sort();
}

function littleEndianScalar(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) value = (value << 8n) | BigInt(bytes[i] ?? 0);
  return value;
}

/** True of an encoding the tolerant rule reads and the strict rule refuses, which is the edge itself. */
function refusedOnlyByTheStrictRule(point: Uint8Array): boolean {
  try {
    ed25519.Point.fromHex(point, true);
  } catch {
    return false;
  }
  try {
    ed25519.Point.fromHex(point, false);
  } catch {
    return true;
  }
  return false;
}

/** What a vector's own shipped bytes say about the three edges the two strictness rules disagree on. */
function strictnessEdges(vector: PublishedVector): string[] {
  const edges: string[] = [];
  for (const [label, point] of [
    ['the public key', vector.key.publicKey],
    ['the signature point', vector.shippedSignature.subarray(0, 32)],
  ] as [string, Uint8Array][]) {
    if (ED25519_TORSION_SUBGROUP.includes(hex(point))) edges.push(`${label} is of small order`);
    if (refusedOnlyByTheStrictRule(point)) edges.push(`${label} is encoded past the field prime`);
  }
  if (littleEndianScalar(vector.shippedSignature.subarray(32)) >= ed25519.CURVE.n) {
    edges.push('the signature scalar is outside the group order');
  }
  return edges;
}

describe('Ed25519 backend agreement over the published vectors', () => {
  const vectors = publishedVectors();
  const refusals = publishedSignatureRefusals();

  it('enumerates the corpus the manifest indexes rather than a selection of it', () => {
    expect(vectors.map((vector) => vector.name).sort(), 'a vector added to the corpus must be proven here').toEqual(publishedVectorNames());
    expect(vectors.length).toBeGreaterThan(0);
    expect(refusals.size).toBeGreaterThan(0);
  });

  it('signs byte-identical signatures under both backends for every published key', () => {
    for (const vector of vectors) {
      const native = Buffer.from(nativeSign(vector));
      const pure = Buffer.from(ed25519.sign(vector.signingInput, vector.key.privateKey));
      expect(native.equals(pure), `${vector.name}: the two backends spelled the signature differently`).toBe(true);
    }
  });

  it('verifies the signature the runtime made under the library and its shipped strict rule', () => {
    for (const vector of vectors) {
      expect(pureVerifies(vector, nativeSign(vector)), `${vector.name}: the library refused what the runtime signed`).toBe(true);
    }
  });

  it('verifies the signature the library made under the runtime primitive', () => {
    for (const vector of vectors) {
      expect(nativeVerifies(vector, ed25519.sign(vector.signingInput, vector.key.privateKey)), `${vector.name}: the runtime refused what the library signed`).toBe(true);
    }
  });

  it('reaches one verdict on the shipped signature bytes, and the verdict the corpus publishes', () => {
    for (const vector of vectors) {
      const pure = pureVerifies(vector, vector.shippedSignature);
      expect(nativeVerifies(vector, vector.shippedSignature), `${vector.name}: the backends disagreed about the published signature`).toBe(pure);
      // The negative the corpus does publish: a document whose payload moved under its own signature is
      // refused by both, so agreement here is not the same as both accepting everything.
      expect(pure, `${vector.name}: the published signature does not answer the verdict the manifest states`).toBe(!refusals.has(vector.name));
    }
  });

  it('reproduces every published signature byte with the runtime primitive', () => {
    let held = 0;
    for (const vector of vectors) {
      if (refusals.has(vector.name)) continue;
      held++;
      expect(Buffer.from(nativeSign(vector)).equals(Buffer.from(vector.shippedSignature)), `${vector.name}: the runtime could not spell the published signature`).toBe(true);
    }
    expect(held, 'the published signatures the runtime is held to').toBe(vectors.length - refusals.size);
  });

  it('proves nothing about the small-order and malleable edge, because no published vector carries it', () => {
    const edges: string[] = [];
    for (const vector of vectors) {
      for (const edge of strictnessEdges(vector)) edges.push(`${vector.name}: ${edge}`);
    }
    // An empty list is the finding, not the pass: `{ zip215: false }` refuses small-order keys, encodings
    // past the field prime and scalars past the group order, and this corpus holds none of them, so the
    // corpus cannot say whether the platform primitive keeps the same rule. The swap needs that answer
    // from a vector, not from this file's silence.
    expect(edges, `of ${vectors.length} published vectors, these carry the edge the two rules disagree on`).toEqual([]);
  });
});
