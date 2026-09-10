import { describe, expect, it } from 'vitest';
import { parseManifest } from '../src/manifest.js';

const KEY = { kid: 'a'.repeat(64), alg: 'Ed25519', publicKey: 'A'.repeat(43) };

function manifest(meas: unknown): Record<string, unknown> {
  return {
    v: 1,
    iss: 'ashaveri-demo',
    ins: 'cvm-1',
    epk: 0,
    keys: [KEY],
    models: [{ id: 'mock-model-1', wts: 'b'.repeat(64) }],
    meas,
  };
}

describe('deployment manifest measurement', () => {
  it('accepts a 48-byte SHA-384 TDX MRTD', () => {
    const parsed = parseManifest(manifest({ tee: 'tdx', m: 'c'.repeat(96) }));
    expect(parsed.meas).toEqual({ tee: 'tdx', m: 'c'.repeat(96) });
  });

  it('accepts a 32-byte SHA-256 software measurement', () => {
    expect(parseManifest(manifest({ tee: 'snp', m: 'd'.repeat(64) })).meas.m).toBe('d'.repeat(64));
  });

  it.each(['', 'e'.repeat(63), 'e'.repeat(65), 'e'.repeat(95), 'e'.repeat(97), 'f'.repeat(64).toUpperCase()])(
    'rejects measurement %p',
    (m) => {
      expect(() => parseManifest(manifest({ tee: 'snp', m }))).toThrowError(
        /meas\.m must be a hex SHA-256 or SHA-384 digest/,
      );
    },
  );

  it('keeps key ids and weights digests at 32 bytes', () => {
    const wideKid = manifest({ tee: 'snp', m: 'd'.repeat(64) });
    wideKid['keys'] = [{ ...KEY, kid: 'a'.repeat(96) }];
    expect(() => parseManifest(wideKid)).toThrowError(/kid must be 64 hex characters/);
    const wideWts = manifest({ tee: 'snp', m: 'd'.repeat(64) });
    wideWts['models'] = [{ id: 'mock-model-1', wts: 'b'.repeat(96) }];
    expect(() => parseManifest(wideWts)).toThrowError(/wts must be 64 hex characters/);
  });
});
