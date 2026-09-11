import { describe, it, expect } from 'vitest';
import { decodeAttestation, equalBytes, pinnedComposeHash, platformMeasurement, verifyAttestation } from '../src/index.js';
import type { Attestation } from '../src/index.js';
import { encodeV0Snp, encodeV1Snp, expectErrorCode, fixture, pemToDer } from './helpers.js';

const ATTESTATION = fixture('sev-snp-attestation.bin');
const ARK = fixture('amd-ark-milan.pem');
const ASK = fixture('sev-snp-ask.pem');
const VCEK = fixture('sev-snp-vcek.pem');

// The fixture was captured 2026-06-17; VCEK validity is 2026-06-17 to 2033-06-17.
const NOW = Date.UTC(2026, 8, 10);

const OPTIONS = {
  now: NOW,
  trustedArks: [ARK],
  askCert: ASK,
  vcekCert: VCEK,
};

function decodeFixture(): Attestation {
  return decodeAttestation(ATTESTATION);
}

function snpFields(attestation: Attestation) {
  if (attestation.platform.kind !== 'sev-snp') {
    throw new Error('expected sev-snp platform');
  }
  return {
    report: attestation.platform.report,
    certChain: attestation.platform.certChain,
    mrConfig: attestation.platform.mrConfig,
    runtimeEvents: attestation.stack.runtimeEvents,
    reportData: attestation.stack.reportData,
    config: attestation.stack.config,
  };
}

describe('dStack SEV-SNP attestation verification', () => {
  it('verifies the captured fixture end-to-end', () => {
    const result = verifyAttestation(ATTESTATION, OPTIONS);
    expect(result.platformKind).toBe('sev-snp');
    expect(result.version).toBe(0);
    expect(result.quoteSignatureVerified).toBe(true);

    const text = new TextDecoder().decode(result.reportData.subarray(0, 24));
    expect(text).toBe('attest-test-fixture-2026');
    expect(result.reportData.length).toBe(64);

    expect(result.runtimeEvents.map((e) => e.event)).toEqual([
      'system-preparing',
      'app-id',
      'compose-hash',
      'instance-id',
      'boot-mr-done',
      'os-image-hash',
      'key-provider',
      'storage-fs',
      'system-ready',
    ]);
    expect(result.runtimeEvents.every((e) => e.version === 1)).toBe(true);
    expect(result.config.length).toBeGreaterThan(0);
  });

  it('exposes the verified report and mr_config binding', () => {
    const result = verifyAttestation(ATTESTATION, OPTIONS);
    const { report, mrConfig } = result.snp as NonNullable<typeof result.snp>;
    expect(report.version).toBe(3);
    expect(report.productLine).toBe('Milan');
    expect(report.cpuidFamily).toBe(0x19);
    expect(report.cpuidModel).toBe(0x01);
    expect(report.guestSvn).toBe(0);
    expect(report.vmpl).toBe(0);
    expect(report.policy.debug).toBe(false);
    expect(report.currentTcb).toEqual({
      blSPL: 4,
      teeSPL: 0,
      spl4: 0,
      spl5: 0,
      spl6: 0,
      spl7: 0,
      snpSPL: 24,
      ucodeSPL: 213,
    });
    expect(mrConfig.keyProvider).toBe('kms');
    expect(mrConfig.composeHash.length).toBe(32);
    expect(mrConfig.appId).not.toBeNull();
    expect(mrConfig.instanceId).not.toBeNull();
  });

  it('exposes the compose hash and measurement a deployment pins', () => {
    const result = verifyAttestation(ATTESTATION, OPTIONS);
    const { report, mrConfig } = result.snp as NonNullable<typeof result.snp>;
    expect(platformMeasurement(result)).toEqual(report.measurement);
    expect(platformMeasurement(result)).toHaveLength(48);
    expect(pinnedComposeHash(result)).toEqual(mrConfig.composeHash);
    // The document is the authority for SEV-SNP; the event is the only source on TDX.
    const event = result.runtimeEvents.find((entry) => entry.event === 'compose-hash');
    expect(event).toBeDefined();
    expect(equalBytes(mrConfig.composeHash, event?.payload ?? new Uint8Array())).toBe(true);
  });

  it('decodes the V0 envelope fields', () => {
    const attestation = decodeFixture();
    expect(attestation.version).toBe(0);
    expect(attestation.platform.kind).toBe('sev-snp');
    expect(attestation.platform.report.length).toBe(1184);
    expect(attestation.platform.certChain).toEqual([]);
    expect(attestation.platform.mrConfig).toContain('"key_provider":"kms"');
    expect(attestation.stack.reportData.length).toBe(64);
    expect(attestation.stack.runtimeEvents.length).toBe(9);
    expect(attestation.stack.stackKind).toBe('dstack');
  });

  it('re-encodes the decoded V0 envelope byte-for-byte', () => {
    const fields = snpFields(decodeFixture());
    const reencoded = encodeV0Snp(fields);
    expect(reencoded.length).toBe(ATTESTATION.length);
    expect(equalBytes(reencoded, ATTESTATION)).toBe(true);
  });

  it('verifies a V1 msgpack envelope carrying the same evidence', () => {
    const fields = snpFields(decodeFixture());
    const v1 = encodeV1Snp({
      ...fields,
      certChain: [pemToDer(ASK), pemToDer(VCEK)],
    });
    const result = verifyAttestation(v1, { now: NOW, trustedArks: [ARK] });
    expect(result.version).toBe(1);
    expect(result.platformKind).toBe('sev-snp');
    expect(result.quoteSignatureVerified).toBe(true);
    expect(result.runtimeEvents.length).toBe(9);

    const decoded = decodeAttestation(v1);
    expect(decoded.version).toBe(1);
    if (decoded.platform.kind !== 'sev-snp') {
      throw new Error('expected sev-snp platform');
    }
    expect(decoded.platform.certChain.length).toBe(2);
    expect(decoded.stack.reportData.length).toBe(64);
  });

  it('rejects a tampered stack report_data', () => {
    const fields = snpFields(decodeFixture());
    const reportData = new Uint8Array(fields.reportData);
    reportData[0]! ^= 0x01;
    const tampered = encodeV0Snp({ ...fields, reportData });
    expectErrorCode(() => verifyAttestation(tampered, OPTIONS), 'REPORT_DATA_MISMATCH');
  });

  it('rejects a tampered mr_config document', () => {
    const fields = snpFields(decodeFixture());
    const mrConfig = fields.mrConfig.replace('"kms"', '"none"');
    expect(mrConfig).not.toBe(fields.mrConfig);
    const tampered = encodeV0Snp({ ...fields, mrConfig });
    expectErrorCode(() => verifyAttestation(tampered, OPTIONS), 'MR_CONFIG_MISMATCH');
  });

  it('rejects a tampered report signature', () => {
    const fields = snpFields(decodeFixture());
    const report = new Uint8Array(fields.report);
    report[0x2a0]! ^= 0x01;
    const tampered = encodeV0Snp({ ...fields, report });
    expectErrorCode(() => verifyAttestation(tampered, OPTIONS), 'BAD_SIGNATURE');
  });

  it('rejects a tampered ASK certificate', () => {
    const ask = new Uint8Array(pemToDer(ASK));
    ask[ask.length - 1]! ^= 0x01;
    expectErrorCode(() => verifyAttestation(ATTESTATION, { ...OPTIONS, askCert: ask }), 'BAD_SIGNATURE');
  });

  it('requires a matching trust root', () => {
    expectErrorCode(() => verifyAttestation(ATTESTATION, { ...OPTIONS, trustedArks: [] }), 'MISSING_TRUST_ROOT');
    // The VCEK is not an ARK for this ASK; its subject does not match the ASK issuer.
    expectErrorCode(() => verifyAttestation(ATTESTATION, { ...OPTIONS, trustedArks: [VCEK] }), 'MISSING_TRUST_ROOT');
  });

  it('requires certificates when the cert_chain is empty', () => {
    expectErrorCode(
      () => verifyAttestation(ATTESTATION, { now: NOW, trustedArks: [ARK] }),
      'MISSING_TRUST_ROOT',
    );
  });

  it('rejects verification outside the certificate validity window', () => {
    expectErrorCode(() => verifyAttestation(ATTESTATION, { ...OPTIONS, now: Date.UTC(2035, 0, 1) }), 'CERT_EXPIRED');
    expectErrorCode(() => verifyAttestation(ATTESTATION, { ...OPTIONS, now: Date.UTC(2020, 0, 1) }), 'CERT_EXPIRED');
  });

  it('rejects malformed envelopes', () => {
    expectErrorCode(() => decodeAttestation(new Uint8Array(0)), 'MALFORMED_ATTESTATION');
    expectErrorCode(() => decodeAttestation(new Uint8Array([0x01, 0x02, 0x03])), 'MALFORMED_ATTESTATION');
    const truncated = ATTESTATION.subarray(0, 100);
    expectErrorCode(() => decodeAttestation(new Uint8Array(truncated)), 'MALFORMED_ATTESTATION');
    const trailing = new Uint8Array(ATTESTATION.length + 1);
    trailing.set(ATTESTATION, 0);
    expectErrorCode(() => decodeAttestation(trailing), 'TRAILING_BYTES');
  });
});
