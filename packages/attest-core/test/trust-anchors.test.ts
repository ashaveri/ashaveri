import { describe, expect, it } from 'vitest';
import { DEFAULT_AMD_ARKS, DEFAULT_INTEL_SGX_ROOTS, parseCertificate, verifyTdxQuote } from '../src/index.js';
import { fixture, pemToDer } from './helpers.js';

// Any moment inside the PCK chain's validity windows.
const NOW = Date.UTC(2026, 0, 15);

// The bundled constants are what makes offline verification meaningful for
// everyone who does not bring their own roots, so they are checked three ways:
// byte for byte against the published files, as self-signed CAs, and by using
// them to verify real vendor-signed evidence.
describe('bundled trust anchors', () => {
  it('ships the published Intel SGX root CA unchanged', () => {
    expect(pemToDer(DEFAULT_INTEL_SGX_ROOTS[0]!)).toEqual(pemToDer(fixture('intel-sgx-root-ca.pem')));
  });

  it('ships the published AMD Milan ARK unchanged', () => {
    expect(pemToDer(DEFAULT_AMD_ARKS[0]!)).toEqual(pemToDer(fixture('amd-ark-milan.pem')));
  });

  it('carries only self-signed certificate authorities', () => {
    for (const pem of [...DEFAULT_AMD_ARKS, ...DEFAULT_INTEL_SGX_ROOTS]) {
      const cert = parseCertificate(pemToDer(pem));
      expect(cert.isCa).toBe(true);
      expect(cert.subject).toEqual(cert.issuer);
    }
  });

  it('verifies a real Intel-signed quote with nothing but the defaults', () => {
    const result = verifyTdxQuote(fixture('tdx-quote-v4.bin'), { trustedRoots: DEFAULT_INTEL_SGX_ROOTS, now: NOW });
    expect(result.pckChain).toHaveLength(3);
    expect(result.trustedRoot.isCa).toBe(true);
  });
});
