import { describe, it, expect } from 'vitest';
import { parseQeReportCertificationData, parseTdxQuote, parseTdxQuoteSignature, verifyAttestation, verifyTdxQuote } from '../src/index.js';
import { encodeV0Tdx, expectErrorCode, fixture } from './helpers.js';

// A real Intel-signed TD quote (version 4, TDX) captured by the go-tdx-qpl
// project; see test/fixtures/README.md for provenance.
const quote = fixture('tdx-quote-v4.bin');

describe('TDX quote signature block', () => {
  it('reads the signature, attestation key and certification data of a real quote', () => {
    const parsed = parseTdxQuoteSignature(quote);
    expect(parsed.signature.length).toBe(64);
    expect(parsed.attestationKey.length).toBe(64);
    // Type 6 is the QE-report certification data, the shape TDX quotes carry.
    expect(parsed.certificationDataType).toBe(6);
    expect(parsed.certificationData.length).toBe(4166);
    expect(parsed.signature).toEqual(quote.slice(636, 700));
    expect(parsed.attestationKey).toEqual(quote.slice(700, 764));
  });

  it('rejects a quote that is shorter than its declared signature length', () => {
    expectErrorCode(() => parseTdxQuoteSignature(quote.slice(0, 1000)), 'MALFORMED_QUOTE');
  });

  it('rejects a declared signature length that leaves trailing bytes', () => {
    const altered = Uint8Array.from(quote);
    const view = new DataView(altered.buffer);
    view.setUint32(632, 4299, true);
    expectErrorCode(() => parseTdxQuoteSignature(altered), 'MALFORMED_QUOTE');
  });

  it('rejects a non-TDX quote', () => {
    const altered = Uint8Array.from(quote);
    new DataView(altered.buffer).setUint32(0x04, 0x00, true);
    expectErrorCode(() => parseTdxQuoteSignature(altered), 'UNSUPPORTED_QUOTE');
  });

  it('rejects a quote version this package cannot verify', () => {
    const altered = Uint8Array.from(quote);
    new DataView(altered.buffer).setUint16(0x00, 5, true);
    expectErrorCode(() => parseTdxQuoteSignature(altered), 'UNSUPPORTED_QUOTE');
  });
});

function asText(bytes: Uint8Array): string {
  return new TextDecoder('latin1').decode(bytes);
}

describe('TDX QE report certification data', () => {
  const certification = parseTdxQuoteSignature(quote).certificationData;

  it('splits the report, its signature, the QE auth data and the PCK chain', () => {
    const qe = parseQeReportCertificationData(certification);
    expect(qe.enclaveReport.length).toBe(384);
    expect(qe.enclaveReportSignature.length).toBe(64);
    expect(qe.authData.length).toBe(32);
    expect(qe.innerCertificationDataType).toBe(5);
    expect(asText(qe.pckCertChain).match(/-----BEGIN CERTIFICATE-----/g)?.length).toBe(3);
    expect(qe.enclaveReport).toEqual(certification.slice(0, 384));
  });

  it('rejects certification data that is too short to hold the report', () => {
    expectErrorCode(() => parseQeReportCertificationData(certification.slice(0, 400)), 'MALFORMED_QUOTE');
  });

  it('rejects a QE auth data length that runs past the buffer', () => {
    const altered = Uint8Array.from(certification);
    new DataView(altered.buffer).setUint16(448, 4000, true);
    expectErrorCode(() => parseQeReportCertificationData(altered), 'MALFORMED_QUOTE');
  });

  it('rejects an inner certification data length that does not reach the end', () => {
    const altered = Uint8Array.from(certification);
    new DataView(altered.buffer).setUint32(450 + 32 + 2, 100, true);
    expectErrorCode(() => parseQeReportCertificationData(altered), 'MALFORMED_QUOTE');
  });
});

describe('TDX DCAP verification', () => {
  const trustedRoots = [fixture('intel-sgx-root-ca.pem')];
  // Any moment inside this quote's PCK chain validity windows.
  const NOW = Date.UTC(2026, 0, 15);

  function flip(bytes: Uint8Array, offset: number): Uint8Array {
    const copy = Uint8Array.from(bytes);
    copy[offset] = (copy[offset] as number) ^ 0xff;
    return copy;
  }

  function verify(bytes: Uint8Array, now: number = NOW): unknown {
    return verifyTdxQuote(bytes, { trustedRoots, now });
  }

  it('accepts an Intel-signed quote anchored at the pinned Intel root CA', () => {
    const result = verifyTdxQuote(quote, { trustedRoots, now: NOW });
    expect(result.attestationKey).toEqual(quote.slice(700, 764));
    expect(result.pckChain.map((cert) => cert.isCa)).toEqual([false, true, true]);
    expect(result.trustedRoot).toBe(result.pckChain[2]);
  });

  it('rejects a tampered byte inside the signed region', () => {
    expectErrorCode(() => verify(flip(quote, 0x100)), 'BAD_SIGNATURE');
  });

  it('rejects a tampered quote signature', () => {
    expectErrorCode(() => verify(flip(quote, 640)), 'BAD_SIGNATURE');
  });

  it('rejects a tampered QE report', () => {
    // The QE report is signed by the platform PCK, so one changed byte breaks it.
    expectErrorCode(() => verify(flip(quote, 800)), 'BAD_SIGNATURE');
  });

  it('rejects QE auth data that no longer binds the attestation key', () => {
    // Auth data sits outside both signatures. Only the digest inside the signed
    // QE report ties it, and through it the attestation key, to the platform.
    expectErrorCode(() => verify(flip(quote, 1220)), 'QE_REPORT_MISMATCH');
  });

  it('rejects a chain that does not lead to a pinned root', () => {
    expectErrorCode(
      () => verifyTdxQuote(quote, { trustedRoots: [fixture('amd-ark-milan.pem')], now: NOW }),
      'MISSING_TRUST_ROOT',
    );
  });

  it('rejects a verification time past the PCK leaf certificate expiry', () => {
    expectErrorCode(() => verify(quote, Date.UTC(2030, 5, 1)), 'CERT_EXPIRED');
  });
});

// The quote's RTMR-3 is all zeros and its runtime event list is therefore empty,
// which lets the whole envelope path run against real Intel-signed bytes offline.
// This proves the DCAP result reaches the top level; it says nothing about
// measurement replay, which the synthetic-quote tests in tdx.test.ts cover.
describe('TDX end to end with a real Intel quote', () => {
  const parsed = parseTdxQuote(quote);
  const envelope = encodeV0Tdx({
    quote,
    eventLog: [],
    runtimeEvents: [],
    reportData: parsed.reportData,
    config: 'tdx-dcap-e2e',
  });
  const options = { trustedIntelRoots: [fixture('intel-sgx-root-ca.pem')], now: Date.UTC(2026, 0, 15) };

  it('reports the quote signature verified through the envelope path', () => {
    const result = verifyAttestation(envelope, options);
    expect(result.platformKind).toBe('tdx');
    expect(result.quoteSignatureVerified).toBe(true);
    expect(result.reportData).toEqual(parsed.reportData);
    expect(result.runtimeEvents).toEqual([]);
    expect(result.config).toBe('tdx-dcap-e2e');
    expect(result.tdx?.mrConfig).toBeNull();
  });

  it('still requires the pinned root', () => {
    expectErrorCode(
      () => verifyAttestation(envelope, { ...options, trustedIntelRoots: [fixture('amd-ark-milan.pem')] }),
      'MISSING_TRUST_ROOT',
    );
  });

  it('rejects an envelope whose report data is not the quoted one', () => {
    const forged = encodeV0Tdx({
      quote,
      eventLog: [],
      runtimeEvents: [],
      reportData: new Uint8Array(64),
      config: 'tdx-dcap-e2e',
    });
    expectErrorCode(() => verifyAttestation(forged, options), 'REPORT_DATA_MISMATCH');
  });
});
