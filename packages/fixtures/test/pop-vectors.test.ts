import { describe, expect, it } from 'vitest';
import {
  EMPTY_BODY_SHA256_HEX,
  POP_NONCE_BYTES,
  POP_SCHEME,
  fromBase64Url,
  parsePopAuthorization,
  popSigningString,
  sha256Hex,
  signPopAuthorization,
  verifyPopSignature,
} from '@ashaveri/receipt';
import { loadPopVectors, type PopVector } from '../src/index.js';

const file = loadPopVectors();
const privateKey = new Uint8Array(Buffer.from(file.key.privateKeyHex, 'hex'));
const publicKey = new Uint8Array(Buffer.from(file.key.publicKeyHex, 'hex'));

function asFields(vector: PopVector) {
  return {
    ts: vector.fields.ts,
    nonce: fromBase64Url(vector.fields.nonce),
    method: vector.fields.method,
    target: vector.fields.target,
    bodyDigestHex: vector.fields.bodyDigestHex,
  };
}

describe('data/pop-v1.json', () => {
  it('publishes the scheme and the separator an independent client needs', () => {
    expect(file.version).toBe(1);
    expect(file.scheme).toBe(POP_SCHEME);
    expect(file.separator).toBe('\n');
    expect(file.emptyBodySha256Hex).toBe(EMPTY_BODY_SHA256_HEX);
    expect(file.vectors.length).toBeGreaterThanOrEqual(4);
  });

  it('signs every vector with its own nonce of the width the scheme requires', () => {
    const nonces = file.vectors.map((vector) => {
      expect(fromBase64Url(vector.fields.nonce)).toHaveLength(POP_NONCE_BYTES);
      return vector.fields.nonce;
    });
    // Reusing a nonce across two signed requests is the replay this scheme exists to catch,
    // so a corpus that printed one nonce for all its cases would teach a client author the
    // opposite of the rule. One frozen timestamp is fine and intended: it is what lets the
    // file regenerate byte for byte.
    expect(new Set(nonces).size).toBe(nonces.length);
    expect(new Set(file.vectors.map((vector) => vector.fields.ts)).size).toBe(1);
  });

  it.each(file.vectors)('$name', (vector) => {
    const body = fromBase64Url(vector.fields.bodyBase64Url);
    expect(sha256Hex(body)).toBe(vector.fields.bodyDigestHex);
    expect(popSigningString(asFields(vector))).toBe(vector.signingString);
    expect(signPopAuthorization(asFields(vector), file.key.id, privateKey)).toBe(vector.authorization);
    const parsed = parsePopAuthorization(vector.authorization);
    expect(parsed.credential).toBe(file.key.id);
    expect(verifyPopSignature(asFields(vector), parsed.signature, publicKey)).toBe(true);
  });

  it('covers a bodyless route and a route with a signed query', () => {
    const targets = file.vectors.map((vector) => `${vector.fields.method} ${vector.fields.target}`);
    expect(targets).toContain('POST /v1/chat/completions');
    expect(targets.some((target) => target.startsWith('GET') && target.includes('?'))).toBe(true);
    for (const vector of file.vectors.filter((each) => each.fields.bodyBase64Url.length === 0)) {
      expect(vector.fields.bodyDigestHex).toBe(EMPTY_BODY_SHA256_HEX);
    }
  });

  it('keeps the fixture key marked as test-only', () => {
    expect(file.key.id).toBe('pop-vector-key-v1');
    expect(privateKey).toHaveLength(32);
    expect(publicKey).toHaveLength(32);
    expect(file.key.privateKeyHex).toBe('d1332ee54c62ab3f5336167d4d694944ed98509395a5529e165e043013de19dd');
    expect(file.key.publicKeyHex).toBe('6eba020f7a7c86e778cabcb42813e24d4c81546106bbd4ef5d4fc9e1d052bdb7');
  });
});
