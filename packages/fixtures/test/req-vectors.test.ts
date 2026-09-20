import { describe, expect, it } from 'vitest';
import {
  EMPTY_BODY_SHA256_HEX,
  fromBase64Url,
  hashRequest,
  sha256Hex,
  toHex,
} from '@ashaveri/receipt';
import { loadPopVectors, loadReqVectors, type RequestVector } from '../src/index.js';

const file = loadReqVectors();

/**
 * The digest the gateway and the SDK both compute, taken over the bytes this file publishes. Every
 * value here is produced by `hashRequest`: it is the function the gateway signs `req` with and the
 * one a client recomputes it with, so a vector checked against anything else would be checking a
 * copy of the rule rather than the rule.
 */
function digestOf(vector: RequestVector): string {
  return toHex(hashRequest(fromBase64Url(vector.bodyBase64Url)));
}

function vectorNamed(name: string): RequestVector {
  const found = file.vectors.find((each) => each.name === name);
  if (found === undefined) throw new Error(`data/req-v1.json has no vector named ${name}`);
  return found;
}

describe('data/req-v1.json', () => {
  it('states which receipt field it pins and how the digest is written', () => {
    expect(file.version).toBe(1);
    expect(file.rule.receiptField).toBe('req');
    expect(file.rule.algorithm).toBe('sha256');
    expect(file.rule.encoding).toBe('lowercase hex, 64 characters');
    expect(file.vectors.length).toBeGreaterThanOrEqual(6);
    for (const vector of file.vectors) {
      expect(vector.reqHex).toMatch(/^[0-9a-f]{64}$/u);
      expect(Buffer.from(vector.reqHex, 'hex')).toHaveLength(32);
      expect(fromBase64Url(vector.bodyBase64Url)).toHaveLength(vector.bodyByteLength);
    }
    expect(new Set(file.vectors.map((vector) => vector.name)).size).toBe(file.vectors.length);
  });

  it.each(file.vectors)('$name', (vector) => {
    expect(digestOf(vector)).toBe(vector.reqHex);
  });

  it('hashes the body of a request that has none, at the width the scheme states', () => {
    const empty = vectorNamed('empty-body');
    expect(empty.bodyBase64Url).toBe('');
    expect(empty.bodyByteLength).toBe(0);
    expect(empty.reqHex).toBe(EMPTY_BODY_SHA256_HEX);
  });

  it('agrees with the proof-of-possession vectors on the same bytes', () => {
    // Two files, one set of bytes: a proof-of-possession signing string carries the hex digest of
    // the body it authorises, and a receipt carries sha256 of the same body in `req`. A port that
    // implemented the two differently would notice only by holding both, which is why both exist.
    const byBody = new Map(file.vectors.map((vector) => [vector.bodyBase64Url, vector]));
    for (const pop of loadPopVectors().vectors) {
      const match = byBody.get(pop.fields.bodyBase64Url);
      expect(match, `no request vector carries the body of ${pop.name}`).toBeDefined();
      expect(match?.reqHex).toBe(pop.fields.bodyDigestHex);
      expect(sha256Hex(fromBase64Url(pop.fields.bodyBase64Url))).toBe(pop.fields.bodyDigestHex);
    }
  });

  it('refuses to equate two bodies a JSON reader cannot tell apart', () => {
    const written = vectorNamed('same-object-reformatted');
    const plain = vectorNamed('buffered-completion');
    expect(written.bodyBase64Url).not.toBe(plain.bodyBase64Url);
    expect(written.reqHex).not.toBe(plain.reqHex);
    // The objects are the same, so the two digests differ on bytes alone: exactly the equivalence
    // a receipt does not grant.
    expect(JSON.parse(Buffer.from(fromBase64Url(written.bodyBase64Url)).toString('utf8'))).toEqual(
      JSON.parse(Buffer.from(fromBase64Url(plain.bodyBase64Url)).toString('utf8')),
    );
  });

  it('keeps multi-byte content a byte fact rather than a character one', () => {
    const nonAscii = vectorNamed('non-ascii-content');
    const text = Buffer.from(fromBase64Url(nonAscii.bodyBase64Url)).toString('utf8');
    expect(text).toContain('☕');
    // More bytes than characters, because the body is published as UTF-8 and hashed as octets.
    expect(nonAscii.bodyByteLength).toBeGreaterThan(text.length);
    expect(digestOf(nonAscii)).toBe(nonAscii.reqHex);
  });
});
