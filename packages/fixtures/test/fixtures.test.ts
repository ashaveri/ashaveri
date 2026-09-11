import { describe, it, expect } from 'vitest';
import { verifyReceipt } from '@ashaveri/receipt';
import { ReceiptError } from '@ashaveri/receipt';
import { loadReceiptFixture, loadFixtureKey, loadManifest } from '../src/index.js';

const FIXED_NOW = 1_772_000_000;

function errorCode(fn: () => unknown): string | 'no-error' {
  try {
    fn();
    return 'no-error';
  } catch (e) {
    return (e as ReceiptError).code;
  }
}

describe('golden fixtures', () => {
  it('valid receipt fixture verifies against the fixture key', () => {
    const fixture = loadReceiptFixture('receipt-valid-v1');
    const key = loadFixtureKey();
    const verified = verifyReceipt(fixture.bytes, { publicKey: key.publicKey, now: FIXED_NOW });
    expect(verified.payload.mdl).toBe('meta-llama/Llama-3.1-8B-Instruct');
    expect(verified.payload.tok).toEqual({ p: 128, c: 64 });
  });

  it('software receipt fixture verifies and makes no TEE claim', () => {
    const fixture = loadReceiptFixture('receipt-software-v1');
    const key = loadFixtureKey();
    const verified = verifyReceipt(fixture.bytes, { publicKey: key.publicKey, now: FIXED_NOW });
    expect(verified.payload.meas.tee).toBe('software');
    expect(verified.payload.meas.m).toHaveLength(32);
  });

  it('valid fixture is byte-stable (digest matches manifest)', () => {
    const manifest = loadManifest();
    expect(manifest.version).toBe(1);
    expect(manifest.fixtures).toHaveLength(4);
    for (const entry of manifest.fixtures) {
      const fixture = loadReceiptFixture(entry.name);
      expect(Buffer.from(fixture.digest).toString('hex')).toBe(entry.digestSha256);
    }
  });

  it('every shipped vector behaves as its manifest entry promises', () => {
    const key = loadFixtureKey();
    for (const entry of loadManifest().fixtures) {
      const fixture = loadReceiptFixture(entry.name);
      const outcome = errorCode(() => verifyReceipt(fixture.bytes, { publicKey: key.publicKey, now: FIXED_NOW }));
      const observed = outcome === 'no-error' ? 'verify-ok' : outcome;
      expect(`${entry.name}: ${observed}`).toBe(`${entry.name}: ${entry.expected}`);
    }
  });

  it('tampered fixture fails with INVALID_SIGNATURE', () => {
    const fixture = loadReceiptFixture('receipt-tampered-v1');
    const key = loadFixtureKey();
    try {
      verifyReceipt(fixture.bytes, { publicKey: key.publicKey, now: FIXED_NOW });
      throw new Error('expected ReceiptError');
    } catch (e) {
      expect((e as ReceiptError).code).toBe('INVALID_SIGNATURE');
    }
  });

  it('valid fixture honors nonce and freshness options', () => {
    const fixture = loadReceiptFixture('receipt-valid-v1');
    const key = loadFixtureKey();
    const nonce = JSON.parse(
      JSON.stringify(loadReceiptFixture('receipt-valid-v1').json?.payload.nce ?? ''),
    ) as string;
    expect(nonce).toMatch(/^[0-9a-f]{32}$/);
    const options = {
      publicKey: key.publicKey,
      expectedNonce: new Uint8Array(Buffer.from(nonce, 'hex')),
      now: FIXED_NOW,
      freshnessSeconds: 3600,
      evidenceFreshnessSeconds: 3600,
    };
    expect(() => verifyReceipt(fixture.bytes, options)).not.toThrow();
  });
});
