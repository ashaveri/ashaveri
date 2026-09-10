import { describe, it, expect } from 'vitest';
import {
  generateSigningKey,
  keyId,
  issueReceipt,
  decodeReceipt,
  verifyReceipt,
  encodePayload,
  randomNonce,
  ReceiptError,
  equalBytes,
} from '../src/index.js';
import type { ReceiptPayload } from '../src/index.js';
import { sha256 } from '@noble/hashes/sha2.js';

const FIXED_NOW = 1_772_000_000;

function samplePayload(overrides: Partial<ReceiptPayload> = {}): ReceiptPayload {
  return {
    v: 1,
    iss: 'dpl-9f2a41',
    ins: 'cvm-i-047f',
    iat: FIXED_NOW,
    nce: new Uint8Array(16).fill(0xab),
    req: sha256(new TextEncoder().encode('{"model":"m","messages":[]}')),
    res: sha256(new TextEncoder().encode('{"choices":[]}')),
    mdl: 'meta-llama/Llama-3.1-8B-Instruct',
    wts: sha256(new TextEncoder().encode('manifest')),
    meas: { tee: 'snp+h100cc', m: sha256(new Uint8Array(32).fill(1)) },
    att: { d: sha256(new Uint8Array(64).fill(2)), ts: FIXED_NOW - 60, url: 'https://inference.ashaveri.com/v1/attestation' },
    epk: 3,
    tok: { p: 128, c: 64 },
    ...overrides,
  };
}

describe('COSE_Sign1 receipt codec', () => {
  it('round-trips: issue, verify, decode agree', () => {
    const key = generateSigningKey();
    const payload = samplePayload();
    const bytes = issueReceipt(payload, key);

    const verified = verifyReceipt(bytes, { publicKey: key.publicKey, now: FIXED_NOW });
    expect(verified.payload.mdl).toBe(payload.mdl);
    expect(equalBytes(verified.payload.nce, payload.nce)).toBe(true);
    expect(equalBytes(keyId(key.publicKey), verified.header.kid)).toBe(true);

    const decoded = decodeReceipt(bytes);
    expect(decoded.payload.iss).toBe(payload.iss);
  });

  it('is canonical: re-encoding the decoded payload yields identical bytes', () => {
    const key = generateSigningKey();
    const payload = samplePayload();
    const bytes = issueReceipt(payload, key);
    const decoded = decodeReceipt(bytes);
    const payloadBytes = encodePayload(decoded.payload);
    // payloadBytes in the COSE structure is exactly the canonical encoding
    expect(equalBytes(payloadBytes, decoded.cose.payloadBytes)).toBe(true);
    const bytes2 = issueReceipt(decoded.payload, key);
    expect(equalBytes(bytes, bytes2)).toBe(true);
  });

  it('rejects a tampered payload byte with INVALID_SIGNATURE', () => {
    const key = generateSigningKey();
    const bytes = issueReceipt(samplePayload(), key);
    const tampered = new Uint8Array(bytes);
    tampered[tampered.length - 10]! ^= 0x01;
    expectErrorCode(() => verifyReceipt(tampered, { publicKey: key.publicKey, now: FIXED_NOW }), 'INVALID_SIGNATURE');
  });

  it('rejects a signature from a different key', () => {
    const signer = generateSigningKey();
    const other = generateSigningKey();
    const bytes = issueReceipt(samplePayload(), signer);
    expectErrorCode(() => verifyReceipt(bytes, { publicKey: other.publicKey, now: FIXED_NOW }), 'KID_MISMATCH');
  });

  it('resolves keys via resolveKey by kid', () => {
    const key = generateSigningKey();
    const other = generateSigningKey();
    const bytes = issueReceipt(samplePayload(), key);
    const resolver = (kid: Uint8Array) => (equalBytes(kid, keyId(key.publicKey)) ? key.publicKey : undefined);
    expect(() => verifyReceipt(bytes, { resolveKey: resolver, now: FIXED_NOW })).not.toThrow();
    const badResolver = () => other.publicKey;
    expectErrorCode(() => verifyReceipt(bytes, { resolveKey: badResolver, now: FIXED_NOW }), 'KID_MISMATCH');
    expectErrorCode(() => verifyReceipt(bytes, { resolveKey: () => undefined, now: FIXED_NOW }), 'UNKNOWN_KEY');
  });

  it('enforces nonce echo', () => {
    const key = generateSigningKey();
    const nonce = randomNonce();
    const bytes = issueReceipt(samplePayload({ nce: nonce }), key);
    expect(() => verifyReceipt(bytes, { publicKey: key.publicKey, expectedNonce: nonce, now: FIXED_NOW })).not.toThrow();
    expectErrorCode(
      () => verifyReceipt(bytes, { publicKey: key.publicKey, expectedNonce: randomNonce(), now: FIXED_NOW }),
      'NONCE_MISMATCH',
    );
  });

  it('enforces receipt and evidence freshness windows', () => {
    const key = generateSigningKey();
    const bytes = issueReceipt(samplePayload(), key);
    const now = FIXED_NOW + 3600;
    expect(() => verifyReceipt(bytes, { publicKey: key.publicKey, now, freshnessSeconds: 7200, evidenceFreshnessSeconds: 7200 })).not.toThrow();
    expectErrorCode(() => verifyReceipt(bytes, { publicKey: key.publicKey, now, freshnessSeconds: 60 }), 'STALE_RECEIPT');
    expectErrorCode(
      () => verifyReceipt(bytes, { publicKey: key.publicKey, now, freshnessSeconds: 7200, evidenceFreshnessSeconds: 60 }),
      'STALE_EVIDENCE',
    );
  });

  it('rejects structurally invalid payloads with BAD_PAYLOAD', () => {
    const key = generateSigningKey();
    const payload = samplePayload();
    // @ts-expect-error deliberately malformed
    const bad = { ...payload, nce: new Uint8Array(15) };
    const bytes = issueReceipt(bad as ReceiptPayload, key);
    expectErrorCode(() => verifyReceipt(bytes, { publicKey: key.publicKey, now: FIXED_NOW }), 'BAD_PAYLOAD');
  });

  it('generates a deterministic kid (sha256 of public key)', () => {
    const key = generateSigningKey();
    expect(key.kid).toEqual(sha256(key.publicKey));
    const key2 = generateSigningKey();
    expect(equalBytes(key.kid, key2.kid)).toBe(false);
  });
});

function expectErrorCode(fn: () => unknown, code: string) {
  try {
    fn();
  } catch (e) {
    expect((e as ReceiptError).code).toBe(code);
    return;
  }
  throw new Error(`expected ReceiptError with code ${code}, but no error was thrown`);
}
