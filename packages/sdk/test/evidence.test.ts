import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parseTdxQuote } from '@ashaveri/attest-core';
import { sha256 } from '@noble/hashes/sha2.js';
import type { ReceiptPayload, SdkErrorCode, TeeKind } from '../src/index.js';
import { evidenceReportData, SdkError, verifyCompletionEvidence } from '../src/index.js';

function fixture(name: string): Uint8Array {
  return new Uint8Array(readFileSync(new URL(`../../attest-core/test/fixtures/${name}`, import.meta.url)));
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function expectSdkErrorCode(fn: () => unknown, code: SdkErrorCode): void {
  try {
    fn();
  } catch (err) {
    expect(err).toBeInstanceOf(SdkError);
    expect((err as SdkError).code).toBe(code);
    return;
  }
  throw new Error(`expected SdkError with code ${code}, but nothing was thrown`);
}

/**
 * A real Intel-signed TD quote (provenance: attest-core/test/fixtures/README.md)
 * wrapped in the v0 envelope dStack's guest API serves, so the whole strict-mode
 * check runs against bytes Intel signed rather than a synthetic stand-in.
 *
 * The report data and MRTD are literals copied from the quote. Deriving them in
 * place would let a parser bug agree with itself.
 */
const QUOTE = fixture('tdx-quote-v4.bin');
const REPORT_DATA =
  '48656c6c6f2066726f6d20456467656c6573732053797374656d73210000000000000000' + '00000000000000000000000000000000000000000000000000000000';
const MR_TD = 'b65ea009e424e6f761fdd3d7c8962439453b37ecdf62da04f7bc5d327686bb8bafc8a5d24a9c31cee60e4aba87c2f71b';
// Any moment inside the PCK chain's validity windows.
const NOW = Date.UTC(2026, 0, 15);

function fromHex(value: string): Uint8Array {
  return new Uint8Array(value.match(/../g)!.map((pair) => Number.parseInt(pair, 16)));
}

// Test-side SCALE writer, independent of the reader in @ashaveri/attest-core,
// trimmed to what an empty-log TDX envelope needs.
class ScaleWriter {
  private readonly bytes: number[] = [];

  finish(): Uint8Array {
    return new Uint8Array(this.bytes);
  }

  byte(value: number): this {
    this.bytes.push(value);
    return this;
  }

  compact(value: number): this {
    if (value < 0x40) {
      this.bytes.push((value << 2) | 0x00);
    } else if (value < 0x4000) {
      const v = ((value << 2) | 0x01) & 0xffff;
      this.bytes.push(v & 0xff, (v >>> 8) & 0xff);
    } else {
      const v = ((value << 2) | 0x02) >>> 0;
      this.bytes.push(v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff);
    }
    return this;
  }

  fixed(value: Uint8Array): this {
    for (const b of value) {
      this.bytes.push(b);
    }
    return this;
  }

  vec(value: Uint8Array): this {
    return this.compact(value.length).fixed(value);
  }

  string(value: string): this {
    return this.vec(utf8(value));
  }
}

function encodeV0Tdx(quote: Uint8Array, reportData: Uint8Array): Uint8Array {
  const w = new ScaleWriter();
  w.byte(0x00).byte(0);
  w.vec(quote);
  w.compact(0);
  w.compact(0);
  w.fixed(reportData);
  w.string('ashaveri-strict-test');
  return w.finish();
}

const DOCUMENT = encodeV0Tdx(QUOTE, fromHex(REPORT_DATA));

function signedReceipt(overrides: { tee?: TeeKind; measurement?: Uint8Array; evidenceDigest?: Uint8Array } = {}): ReceiptPayload {
  return {
    v: 1,
    iss: 'tdx-cvm',
    ins: 'instance-1',
    iat: Math.floor(NOW / 1000),
    nce: new Uint8Array(16),
    req: sha256(utf8('request bytes')),
    res: sha256(utf8('response bytes')),
    mdl: 'model-1',
    wts: sha256(utf8('weights')),
    meas: { tee: overrides.tee ?? 'tdx', m: overrides.measurement ?? fromHex(MR_TD) },
    att: {
      d: overrides.evidenceDigest ?? sha256(DOCUMENT),
      ts: Math.floor(NOW / 1000),
      url: 'https://cvm.ashaveri.test/v1/attestation',
    },
    epk: 0,
    tok: { p: 1, c: 1 },
  };
}

function verify(document: Uint8Array = DOCUMENT, payload = signedReceipt()) {
  return verifyCompletionEvidence({
    document,
    expectedReportData: fromHex(REPORT_DATA),
    payload,
    now: NOW,
  });
}

describe('evidenceReportData', () => {
  it('digests the nonce and the request hash together', () => {
    const nonce = new Uint8Array(16).fill(7);
    const requestHash = sha256(utf8('body'));
    expect(toHex(evidenceReportData(nonce, requestHash))).toBe(toHex(sha256(new Uint8Array([...nonce, ...requestHash]))));
  });

  it('changes when either input changes', () => {
    const nonce = new Uint8Array(16).fill(7);
    const otherNonce = new Uint8Array(16).fill(8);
    const requestHash = sha256(utf8('body'));
    const bound = evidenceReportData(nonce, requestHash);
    expect(toHex(bound)).not.toBe(toHex(evidenceReportData(otherNonce, requestHash)));
    expect(toHex(bound)).not.toBe(toHex(evidenceReportData(nonce, sha256(utf8('other body')))));
  });
});

describe('verifyCompletionEvidence', () => {
  it('accepts Intel-signed evidence with the bundled trust anchors', () => {
    const evidence = verify();
    expect(evidence.tee).toBe('tdx');
    expect(evidence.platformKind).toBe('tdx');
    expect(evidence.quoteSignatureVerified).toBe(true);
    expect(toHex(evidence.measurement)).toBe(MR_TD);
    expect(toHex(evidence.reportData)).toBe(REPORT_DATA);
    expect(evidence.document).toEqual(DOCUMENT);
    // RTMR-3 of this quote is empty, so no compose hash was measured.
    expect(evidence.composeHash).toBeNull();
  });

  it('rejects evidence that declares no hardware protection', () => {
    expectSdkErrorCode(
      () => verifyCompletionEvidence({
        document: DOCUMENT,
        expectedReportData: fromHex(REPORT_DATA),
        payload: signedReceipt({ tee: 'software' }),
        now: NOW,
      }),
      'EVIDENCE_NOT_HARDWARE',
    );
  });

  it('rejects an evidence document the receipt did not sign', () => {
    expectSdkErrorCode(
      () => verify(DOCUMENT, signedReceipt({ evidenceDigest: sha256(utf8('other document')) })),
      'EVIDENCE_DIGEST_MISMATCH',
    );
  });

  it('rejects evidence bound to a different request', () => {
    expectSdkErrorCode(
      () =>
        verifyCompletionEvidence({
          document: DOCUMENT,
          expectedReportData: new Uint8Array(64),
          payload: signedReceipt(),
          now: NOW,
        }),
      'EVIDENCE_REPORT_DATA_MISMATCH',
    );
  });

  it('rejects a measurement the hardware did not attest to', () => {
    expectSdkErrorCode(
      () => verify(DOCUMENT, signedReceipt({ measurement: new Uint8Array(48) })),
      'EVIDENCE_MEASUREMENT_MISMATCH',
    );
  });

  it('rejects a measurement shorter than the platform reports', () => {
    expectSdkErrorCode(
      () => verify(DOCUMENT, signedReceipt({ measurement: new Uint8Array(32) })),
      'EVIDENCE_MEASUREMENT_MISMATCH',
    );
  });

  it('rejects evidence from a platform the receipt does not claim', () => {
    // Only AMD roots are pinned, so nothing here verified the Intel signature.
    // That guard fires before the tee comparison, which would fail too.
    expectSdkErrorCode(
      () =>
        verifyCompletionEvidence({
          document: DOCUMENT,
          expectedReportData: fromHex(REPORT_DATA),
          payload: signedReceipt({ tee: 'snp' }),
          anchors: { amdArks: [fixture('amd-ark-milan.pem')], intelSgxRoots: [] },
          now: NOW,
        }),
      'EVIDENCE_NOT_VERIFIED',
    );
    expectSdkErrorCode(
      () => verify(DOCUMENT, signedReceipt({ tee: 'snp' })),
      'EVIDENCE_TEE_MISMATCH',
    );
  });

  it('refuses to guess when no root is pinned for the declared environment', () => {
    expectSdkErrorCode(
      () =>
        verifyCompletionEvidence({
          document: DOCUMENT,
          expectedReportData: fromHex(REPORT_DATA),
          payload: signedReceipt(),
          anchors: { intelSgxRoots: [] },
          now: NOW,
        }),
      'EVIDENCE_NO_TRUST_ANCHORS',
    );
  });

  it('rejects a chain that does not lead to a pinned root', () => {
    try {
      verifyCompletionEvidence({
        document: DOCUMENT,
        expectedReportData: fromHex(REPORT_DATA),
        payload: signedReceipt(),
        anchors: { intelSgxRoots: [fixture('amd-ark-milan.pem')] },
        now: NOW,
      });
      throw new Error('expected verification to fail');
    } catch (err) {
      expect(err).toBeInstanceOf(SdkError);
      expect((err as SdkError).code).toBe('EVIDENCE_VERIFICATION_FAILED');
      expect((err as SdkError).message).toContain('MISSING_TRUST_ROOT');
    }
  });

  it('rejects bytes that are not an attestation document', () => {
    const junk = utf8('this is not a quote');
    // Served in place of the document the receipt signed.
    expectSdkErrorCode(() => verify(junk, signedReceipt()), 'EVIDENCE_DIGEST_MISMATCH');
    // Signed over honestly, but still not something a platform would produce.
    expectSdkErrorCode(() => verify(junk, signedReceipt({ evidenceDigest: sha256(junk) })), 'EVIDENCE_VERIFICATION_FAILED');
  });

  it('reports a tampered quote as a failed verification', () => {
    const tampered = Uint8Array.from(DOCUMENT);
    // The envelope header plus its compact length prefix is 6 bytes, so this is
    // offset 640 of the quote: its ECDSA signature.
    tampered[646] = (tampered[646] as number) ^ 0xff;
    expectSdkErrorCode(
      () => verify(tampered, signedReceipt({ evidenceDigest: sha256(tampered) })),
      'EVIDENCE_VERIFICATION_FAILED',
    );
  });
});
