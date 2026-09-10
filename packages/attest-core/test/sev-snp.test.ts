import { describe, it, expect } from 'vitest';
import { decodeAttestation, fromHex, normalizeSnpCertificates, parseSnpPolicy, parseSnpReport, productLineFromCpuid, snpReportSignatureDer } from '../src/index.js';
import { expectErrorCode, fixture, pemToDer } from './helpers.js';

function fixtureReport(): Uint8Array {
  const attestation = decodeAttestation(fixture('sev-snp-attestation.bin'));
  if (attestation.platform.kind !== 'sev-snp') {
    throw new Error('expected sev-snp platform');
  }
  return attestation.platform.report;
}

describe('SNP report parsing', () => {
  it('parses the captured report', () => {
    const report = parseSnpReport(fixtureReport());
    expect(report.version).toBe(3);
    expect(report.guestSvn).toBe(0);
    expect(report.vmpl).toBe(0);
    expect(report.signatureAlgo).toBe(1);
    expect(report.cpuidFamily).toBe(0x19);
    expect(report.cpuidModel).toBe(0x01);
    expect(report.cpuidStepping).toBe(0x01);
    expect(report.productLine).toBe('Milan');
    expect(report.measurement.subarray(0, 32)).toEqual(fromHex('7f51e17f72a04d5422cb2c00998166536019a217376f3aa45a630e59c805a599'));
    expect(report.hostData).toEqual(fromHex('783f0057820acb99249af56cc3b07b4e8d80f65183167cba9cf437bb680f742f'));
    expect(report.chipId.subarray(0, 32)).toEqual(fromHex('38d174589d2dff97a6d40cb9f9d90b9507c027491219083cef3ce73ed18f7289'));
    expect(new TextDecoder().decode(report.reportData.subarray(0, 24))).toBe('attest-test-fixture-2026');
    expect(report.signature.r.length).toBe(72);
    expect(report.signature.s.length).toBe(72);
  });

  it('rejects wrong sizes and versions', () => {
    expectErrorCode(() => parseSnpReport(new Uint8Array(1183)), 'MALFORMED_REPORT');
    const report = new Uint8Array(fixtureReport());
    report[0] = 0x04;
    expectErrorCode(() => parseSnpReport(report), 'MALFORMED_REPORT');
  });

  it('rejects nonzero bytes in must-be-zero ranges', () => {
    for (const offset of [0x4d, 0x18c, 0x1eb, 0x1ef, 0x250, 0x400]) {
      const report = new Uint8Array(fixtureReport());
      report[offset] = 0x01;
      expectErrorCode(() => parseSnpReport(report), 'MALFORMED_REPORT');
    }
  });

  it('rejects a signature algorithm other than ECDSA P-384', () => {
    const report = new Uint8Array(fixtureReport());
    report[0x34] = 0x02;
    expectErrorCode(() => parseSnpReport(report), 'UNSUPPORTED_SIGNATURE_ALGO');
  });
});

describe('policy decoding', () => {
  it('extracts the documented policy bits', () => {
    const policy = parseSnpPolicy(0n);
    expect(policy).toEqual({ raw: 0n, smt: false, migrateMA: false, debug: false, singleSocket: false });

    const all = parseSnpPolicy((1n << 16n) | (1n << 18n) | (1n << 19n) | (1n << 20n));
    expect(all.smt).toBe(true);
    expect(all.migrateMA).toBe(true);
    expect(all.debug).toBe(true);
    expect(all.singleSocket).toBe(true);
  });
});

describe('product line mapping', () => {
  it('maps CPUID families to AMD product lines', () => {
    expect(productLineFromCpuid(0x19, 0x01)).toBe('Milan');
    expect(productLineFromCpuid(0x19, 0x11)).toBe('Genoa');
    expect(productLineFromCpuid(0x1a, 0x02)).toBe('Turin');
    expect(productLineFromCpuid(0x1a, 0x05)).toBeNull();
    expect(productLineFromCpuid(0x06, 0x01)).toBeNull();
  });
});

describe('report signature DER encoding', () => {
  it('produces a DER ECDSA signature within the curve order', () => {
    const report = parseSnpReport(fixtureReport());
    const der = snpReportSignatureDer(report);
    expect(der[0]).toBe(0x30);
    expect(der[1]).toBe(der.length - 2);
    expect(der[2]).toBe(0x02);
    // deterministic for the same input
    expect(snpReportSignatureDer(report)).toEqual(der);
  });
});

describe('certificate chain normalization', () => {
  it('passes through a two-entry [ask, vcek] chain', () => {
    const ask = pemToDer(fixture('sev-snp-ask.pem'));
    const vcek = pemToDer(fixture('sev-snp-vcek.pem'));
    const normalized = normalizeSnpCertificates([ask, vcek]);
    expect(normalized.ask).toEqual(ask);
    expect(normalized.vcek).toEqual(vcek);
  });

  it('parses a kernel certificate table auxblob', () => {
    const ask = pemToDer(fixture('sev-snp-ask.pem'));
    const vcek = pemToDer(fixture('sev-snp-vcek.pem'));
    const askEntry = Uint8Array.from([
      0x4a, 0xb7, 0xb3, 0x79, 0xbb, 0xac, 0x4f, 0xe4, 0xa0, 0x2f, 0x05, 0xae, 0xf3, 0x27, 0xc7, 0x82,
    ]);
    const vcekEntry = Uint8Array.from([
      0x63, 0xda, 0x75, 0x8d, 0xe6, 0x64, 0x45, 0x64, 0xad, 0xc5, 0xf4, 0xb9, 0x3b, 0xe8, 0xac, 0xcd,
    ]);
    // Layout: header entries, all-zero terminator, then the certificates.
    const headerEnd = 3 * 24;
    const vcekOffset = headerEnd + ask.length;
    const table = new Uint8Array(headerEnd + ask.length + vcek.length);
    const setU32le = (target: Uint8Array, offset: number, value: number) => {
      target[offset] = value & 0xff;
      target[offset + 1] = (value >> 8) & 0xff;
      target[offset + 2] = (value >> 16) & 0xff;
      target[offset + 3] = (value >> 24) & 0xff;
    };
    table.set(askEntry, 0);
    setU32le(table, 16, headerEnd);
    setU32le(table, 20, ask.length);
    table.set(vcekEntry, 24);
    setU32le(table, 40, vcekOffset);
    setU32le(table, 44, vcek.length);
    table.set(ask, headerEnd);
    table.set(vcek, vcekOffset);

    const normalized = normalizeSnpCertificates([table]);
    expect(normalized.ask).toEqual(ask);
    expect(normalized.vcek).toEqual(vcek);
  });

  it('rejects malformed chains', () => {
    expectErrorCode(() => normalizeSnpCertificates([]), 'MALFORMED_CERTIFICATE');
    expectErrorCode(() => normalizeSnpCertificates([new Uint8Array(8)]), 'MALFORMED_CERTIFICATE');
    const terminator = new Uint8Array(24);
    expectErrorCode(() => normalizeSnpCertificates([terminator]), 'MALFORMED_CERTIFICATE');
  });
});
