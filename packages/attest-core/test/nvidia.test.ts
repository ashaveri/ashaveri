import { describe, it, expect } from 'vitest';
import { parseNvidiaEvidenceBundle, readNvidiaChallenge, verifyNvidiaRats } from '../src/index.js';
import { expectErrorCode, fixture } from './helpers.js';

const toBase64 = (bytes: Uint8Array): string => Buffer.from(bytes).toString('base64');
const bundleBytes = (json: string): Uint8Array => new TextEncoder().encode(json);

// A real Hopper GPU attestation report signed by the device itself, plus the
// certificate chain it was captured with; see test/fixtures/README.md.
const report = fixture('nvidia-hopper-report.bin');
const certChain = fixture('nvidia-hopper-cert-chain.pem');
const deviceRoot = fixture('nvidia-device-identity-ca.pem');

// Pinned inside every certificate window in the chain: the leaf starts 2020-10-17
// and the device root 2021-11-05, both expiring in the year 9999.
const now = Date.UTC(2024, 0, 15);

/** The challenge this sample's GPU signed. */
const CHALLENGE = new Uint8Array([
  0x08, 0xf2, 0xfd, 0x1f, 0x8b, 0xb7, 0x69, 0xd0, 0x87, 0xf6, 0xb0, 0xde, 0x1b, 0x38, 0x95, 0x94,
  0xe6, 0xcd, 0x24, 0x15, 0xc2, 0xf9, 0x2c, 0xf4, 0x89, 0x4f, 0xd6, 0x17, 0xd8, 0xdd, 0xd7, 0xe6,
]);

/** One byte of a buffer. A missing byte means these are not the bytes this file describes. */
function byteAt(bytes: Uint8Array, offset: number): number {
  const byte = bytes[offset];
  if (byte === undefined) {
    throw new Error(`no byte at offset ${offset} of a ${bytes.length}-byte buffer`);
  }
  return byte;
}

/** Where the 32-byte nonce sits: past the 37-byte request and the measurement record. */
function nonceOffset(bytes: Uint8Array): number {
  const recordLength = byteAt(bytes, 42) + (byteAt(bytes, 43) << 8) + (byteAt(bytes, 44) << 16);
  return 37 + 8 + recordLength;
}

describe('NVIDIA GPU evidence', () => {
  it('verifies a real Hopper report offline against the pinned device root', () => {
    const result = verifyNvidiaRats({ report, certChain }, { now, trustedRoots: [deviceRoot] });

    expect(result.signatureVerified).toBe(true);
    // The nonce the GPU was challenged with, taken from the signed region of the
    // response rather than from a field the host could overwrite.
    expect(result.nonce).toEqual(CHALLENGE);
  });

  it('accepts a report that answers the challenge it is checked against', () => {
    const result = verifyNvidiaRats({ report, certChain }, { now, trustedRoots: [deviceRoot], expectedNonce: CHALLENGE });
    expect(result.signatureVerified).toBe(true);
  });

  it('rejects a report that answers a different challenge', () => {
    const other = Uint8Array.from(CHALLENGE);
    other[31] = byteAt(other, 31) ^ 0x01;
    expectErrorCode(
      () => verifyNvidiaRats({ report, certChain }, { now, trustedRoots: [deviceRoot], expectedNonce: other }),
      'CHALLENGE_MISMATCH',
    );
  });

  it('rejects a report whose signature does not match the bytes', () => {
    expectErrorCode(
      () => verifyNvidiaRats({ report: fixture('nvidia-hopper-report-bad-signature.bin'), certChain }, { now, trustedRoots: [deviceRoot] }),
      'BAD_SIGNATURE',
    );
  });

  it('refuses a chain that does not reach the pinned root', () => {
    // The chain is well formed and self-consistent; only the anchor makes it a
    // hardware claim, so pinning some other vendor's root must not satisfy it.
    expectErrorCode(
      () => verifyNvidiaRats({ report, certChain }, { now, trustedRoots: [fixture('amd-ark-milan.pem')] }),
      'MISSING_TRUST_ROOT',
    );
  });

  it('refuses to verify before the pinned root was valid', () => {
    expectErrorCode(
      () => verifyNvidiaRats({ report, certChain }, { now: Date.UTC(2019, 0, 1), trustedRoots: [deviceRoot] }),
      'CERT_EXPIRED',
    );
  });

  it('cannot be handed a substituted nonce without breaking the signature', () => {
    const tampered = Uint8Array.from(report);
    const offset = nonceOffset(tampered);
    tampered[offset] = byteAt(tampered, offset) ^ 0x01;
    expect(offset + 32).toBeLessThan(tampered.length);
    expectErrorCode(
      () => verifyNvidiaRats({ report: tampered, certChain }, { now, trustedRoots: [deviceRoot] }),
      'BAD_SIGNATURE',
    );
  });

  it('reads which challenge a report answers without its certificate chain', () => {
    expect(readNvidiaChallenge(report)).toEqual(CHALLENGE);
  });

  it('refuses to read a challenge out of a truncated report', () => {
    expectErrorCode(() => readNvidiaChallenge(report.subarray(0, 100)), 'MALFORMED_REPORT');
  });
});

describe('parseNvidiaEvidenceBundle', () => {
  it('reads the per-device reports out of the array nvattest writes', () => {
    const bundle = bundleBytes(
      JSON.stringify([{ arch: 'HOPPER', evidence: toBase64(report), certificate: toBase64(certChain), version: '1.0' }]),
    );
    expect(parseNvidiaEvidenceBundle(bundle)).toEqual([{ report, certChain }]);
  });

  it('takes an empty array as a bundle that names no device', () => {
    expect(parseNvidiaEvidenceBundle(bundleBytes('[]'))).toEqual([]);
  });

  it('refuses a document that is not the array the format promises', () => {
    for (const json of ['not json', '{"evidences":[]}', '[]]', '[null]', '[{"certificate":"AAAA"}]', '[{"evidence":"####","certificate":"AAAA"}]']) {
      expectErrorCode(() => parseNvidiaEvidenceBundle(bundleBytes(json)), 'MALFORMED_GPU_BUNDLE');
    }
  });
});
