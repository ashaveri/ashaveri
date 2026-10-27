import { createPrivateKey, createPublicKey, generateKeyPairSync, sign as signWithKey, verify as verifyWithKey } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { ED25519_TORSION_SUBGROUP, ed25519 } from '@noble/curves/ed25519';
import { decodeCoseSign1, encodeCanonical, generateSigningKey, signingKeyFromSeed, type SigningKey } from '../src/index.js';
import { nativeEd25519Signer, signEd25519 } from '../src/signing.js';

/**
 * The proof a backend swap needs: the runtime's own Ed25519 primitive and the pure JavaScript curve
 * library held to one another over every receipt vector this repository publishes, in both directions,
 * and the one signer the package routes its seals through held to both of them.
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
const SOURCE_DIRECTORY = fileURLToPath(new URL('../src', import.meta.url));

/** The seal sites that sign through the package's own signer, and no other number: a new one has to be proven here first. */
const SEAL_SITES = 7;

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

/** A message of one length, filled by rule so a failure can be made again from the length alone. */
function messageOfLength(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  for (let i = 0; i < length; i++) bytes[i] = (i * 31 + 7) % 256;
  return bytes;
}

/** The rule every reader of this package keeps to, applied to a message and a key rather than to a vector. */
function strictVerifies(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  return ed25519.verify(signature, message, publicKey, { zip215: false });
}

/**
 * Keys made for this run, not read from the corpus: the corpus proves the published documents and these
 * prove the widths a published document never reaches.
 */
function freshKeys(count: number): SigningKey[] {
  return Array.from({ length: count }, () => generateSigningKey());
}

interface SweepCase {
  label: string;
  key: SigningKey;
  message: Uint8Array;
}

/** The message widths the sweep signs at: empty, the field and point widths, and the page boundary. */
const MESSAGE_LENGTHS = [0, 1, 2, 3, 31, 32, 33, 63, 64, 65, 127, 128, 255, 256, 257, 1023, 1024, 4095, 65_536, 65_537];
const FRESH_KEY_COUNT = 12;

function sweepCases(): SweepCase[] {
  const cases: SweepCase[] = [];
  for (const [index, key] of freshKeys(FRESH_KEY_COUNT).entries()) {
    for (const length of MESSAGE_LENGTHS) {
      cases.push({ label: `key ${index}, seed ${hex(key.privateKey)}, ${length}-byte message`, key, message: messageOfLength(length) });
    }
  }
  return cases;
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

/**
 * The one signer this package's seal sites call, held to both backends. The agreement above is between two
 * libraries; this is between the libraries and the surface that actually spells the published bytes, so a
 * swap proven above still means nothing until the signer is seen to be the same bytes in either direction.
 */
describe('the package signer against both backends', () => {
  const vectors = publishedVectors();
  const sweep = sweepCases();
  const runtime = nativeEd25519Signer;

  it('signs the bytes the library signs at every published vector', () => {
    for (const vector of vectors) {
      const throughSigner = signEd25519(vector.signingInput, vector.key.privateKey);
      const throughLibrary = ed25519.sign(vector.signingInput, vector.key.privateKey);
      expect(Buffer.from(throughSigner).equals(Buffer.from(throughLibrary)), `${vector.name}: the signer and the library spelled it differently`).toBe(true);
    }
  });

  it('signs the bytes the library signs at every freshly generated key and message width', () => {
    for (const each of sweep) {
      const throughSigner = signEd25519(each.message, each.key.privateKey);
      const throughLibrary = ed25519.sign(each.message, each.key.privateKey);
      expect(Buffer.from(throughSigner).equals(Buffer.from(throughLibrary)), `${each.label}: the two backends diverged`).toBe(true);
    }
  });

  it('passes the strict rule every reader keeps, at every vector and every sweep case', () => {
    for (const vector of vectors) {
      expect(strictVerifies(signEd25519(vector.signingInput, vector.key.privateKey), vector.signingInput, vector.key.publicKey), `${vector.name}: refused under the shipped rule`).toBe(true);
    }
    for (const each of sweep) {
      expect(strictVerifies(signEd25519(each.message, each.key.privateKey), each.message, each.key.publicKey), `${each.label}: refused under the shipped rule`).toBe(true);
    }
  });

  it('signs the same bytes with the runtime primitive hidden', () => {
    for (const vector of vectors) {
      const hidden = signEd25519(vector.signingInput, vector.key.privateKey, null);
      const taken = signEd25519(vector.signingInput, vector.key.privateKey);
      expect(Buffer.from(hidden).equals(Buffer.from(taken)), `${vector.name}: the fallback path spells other bytes`).toBe(true);
      expect(strictVerifies(hidden, vector.signingInput, vector.key.publicKey), `${vector.name}: the fallback byte string is refused`).toBe(true);
    }
    for (const each of sweep) {
      const hidden = signEd25519(each.message, each.key.privateKey, null);
      expect(Buffer.from(hidden).equals(Buffer.from(ed25519.sign(each.message, each.key.privateKey))), `${each.label}: the fallback path spells other bytes`).toBe(true);
      expect(strictVerifies(hidden, each.message, each.key.publicKey), `${each.label}: the fallback byte string is refused`).toBe(true);
    }
  });

  it('reaches the runtime primitive once for each signature where the runtime exposes one', () => {
    if (runtime === null) throw new Error('this runtime exposes no Ed25519 primitive, so the preferred path has no witness here');
    const reached: string[] = [];
    const witness = (message: Uint8Array, seed: Uint8Array): Uint8Array => {
      reached.push(`${message.length}`);
      return runtime(message, seed);
    };
    for (const vector of vectors) {
      const throughWitness = signEd25519(vector.signingInput, vector.key.privateKey, witness);
      const throughLibrary = ed25519.sign(vector.signingInput, vector.key.privateKey);
      expect(Buffer.from(throughWitness).equals(Buffer.from(throughLibrary)), `${vector.name}: the runtime primitive disagreed with the library`).toBe(true);
    }
    for (const each of sweep) {
      const throughWitness = signEd25519(each.message, each.key.privateKey, witness);
      expect(Buffer.from(throughWitness).equals(Buffer.from(ed25519.sign(each.message, each.key.privateKey))), `${each.label}: the runtime primitive disagreed with the library`).toBe(true);
    }
    expect(reached.length, 'one call to the primitive per signature, and no second backend in the same call').toBe(vectors.length + sweep.length);
  });

  it('wraps a seed in exactly the bytes the runtime writes for a key it made itself', () => {
    if (runtime === null) throw new Error('this runtime exposes no Ed25519 primitive to wrap a seed for');
    const generated = generateKeyPairSync('ed25519');
    const der = Buffer.from(generated.privateKey.export({ format: 'der', type: 'pkcs8' }));
    expect(der.subarray(0, PKCS8_ED25519_SEED.length).toString('hex'), 'the wrapper the runtime puts in front of a seed').toBe(PKCS8_ED25519_SEED.toString('hex'));
    const seed = Uint8Array.from(der.subarray(PKCS8_ED25519_SEED.length));
    expect(seed.length, 'and the seed is the whole rest of it').toBe(32);
    const rebuilt = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_SEED, Buffer.from(seed)]), format: 'der', type: 'pkcs8' });
    expect(Buffer.from(rebuilt.export({ format: 'der', type: 'pkcs8' })).equals(der), 'the wrapper and the seed are the key the runtime made').toBe(true);
    const message = messageOfLength(200);
    expect(Buffer.from(runtime(message, seed)).equals(Buffer.from(signWithKey(null, Buffer.from(message), generated.privateKey))), 'the wrapped seed signs as the generated key does').toBe(true);
  });

  it('refuses a key that is not a seed, where the runtime would have read it short', () => {
    const message = messageOfLength(48);
    const key = generateSigningKey();
    for (const width of [0, 31, 33, 64]) {
      expect(() => signEd25519(message, new Uint8Array(width)), `a ${width}-byte key`).toThrow(/private key of length 32 expected/u);
    }
    // The trap the guard exists for: the runtime reads a wrapper by the length its own header declares and drops
    // whatever follows it, so a padded seed signs as its leading 32 bytes. The signer refuses that width rather
    // than trading a caller's key material for a signature the caller never asked for.
    const padded = Uint8Array.from([...key.privateKey, 0, 0, 0, 0]);
    expect(() => signEd25519(message, padded)).toThrow(/private key of length 32 expected/u);
    const signedPadded = signWithKey(null, Buffer.from(message), nativeSecretKey(padded));
    const signedSeed = signWithKey(null, Buffer.from(message), nativeSecretKey(key.privateKey));
    expect(Buffer.from(signedPadded).equals(Buffer.from(signedSeed)), 'what the runtime does with a padded seed, unwitnessed by the signer').toBe(true);
  });

  it('signs through one helper at every seal site and through the library at none of them', () => {
    const direct: string[] = [];
    let routed = 0;
    for (const file of readdirSync(SOURCE_DIRECTORY).filter((name) => name.endsWith('.ts')).sort()) {
      if (file === 'signing.ts') continue;
      const lines = readFileSync(join(SOURCE_DIRECTORY, file), 'utf8').split('\n');
      for (const [index, line] of lines.entries()) {
        if (line.includes('signEd25519(')) routed++;
        if (line.includes('ed25519.sign(')) direct.push(`${file}:${index + 1}`);
      }
    }
    // The seven are `signCoseSign1`, `signEpochInventory`, `signExport`, `sealDeploymentManifest`, `signPack`,
    // `signPopAuthorization` and `signRedaction`: a site that signs beside the helper would be a backend choice
    // no proof above reaches, and a new one has to be named here before it can be added.
    expect(direct, 'src lines that sign through the library rather than the package helper').toEqual([]);
    expect(routed, 'the seal sites this proof covers').toBe(SEAL_SITES);
  });
});
