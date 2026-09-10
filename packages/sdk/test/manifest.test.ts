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
    const parsed = parseManifest(manifest({ tee: 'software', m: 'd'.repeat(64) }));
    expect(parsed.meas).toEqual({ tee: 'software', m: 'd'.repeat(64) });
  });

  it('rejects a width that belongs to a different environment kind', () => {
    expect(() => parseManifest(manifest({ tee: 'snp', m: 'd'.repeat(64) }))).toThrowError(
      /meas\.m must be 96 hex characters for tee 'snp'/,
    );
    expect(() => parseManifest(manifest({ tee: 'software', m: 'c'.repeat(96) }))).toThrowError(
      /meas\.m must be 64 hex characters for tee 'software'/,
    );
  });

  it('rejects an unknown environment kind', () => {
    expect(() => parseManifest(manifest({ tee: 'sgx', m: 'c'.repeat(96) }))).toThrowError(
      /meas\.tee is not a known environment kind/,
    );
  });

  it.each([
    ['snp', ''],
    ['snp', 'e'.repeat(95)],
    ['snp', 'e'.repeat(97)],
    ['snp', 'f'.repeat(96).toUpperCase()],
    ['software', 'e'.repeat(63)],
    ['software', 'e'.repeat(65)],
    ['software', 'f'.repeat(64).toUpperCase()],
  ])('rejects measurement %p with a malformed digest', (tee, m) => {
    expect(() => parseManifest(manifest({ tee, m }))).toThrowError(/meas\.m must be \d+ hex characters/);
  });

  it('keeps key ids and weights digests at 32 bytes', () => {
    const wideKid = manifest({ tee: 'software', m: 'd'.repeat(64) });
    wideKid['keys'] = [{ ...KEY, kid: 'a'.repeat(96) }];
    expect(() => parseManifest(wideKid)).toThrowError(/kid must be 64 hex characters/);
    const wideWts = manifest({ tee: 'software', m: 'd'.repeat(64) });
    wideWts['models'] = [{ id: 'mock-model-1', wts: 'b'.repeat(96) }];
    expect(() => parseManifest(wideWts)).toThrowError(/wts must be 64 hex characters/);
  });
});
