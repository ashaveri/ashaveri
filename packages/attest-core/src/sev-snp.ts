import { p384 } from '@noble/curves/p384';
import { sha384 } from '@noble/hashes/sha2.js';
import {
  checkCertificateValidity,
  derEcdsaSignature,
  parseCertificateChain,
  verifyCertificateSignature,
  type ParsedCertificate,
} from './der.js';
import { fail } from './errors.js';
import { equalBytes } from './events.js';
import { tcbFromU64, type SnpPolicy, type SnpReport } from './types.js';

export const SNP_REPORT_SIZE = 0x4a0;
export const SNP_SIGNED_SIZE = 0x2a0;
export const SNP_SIGNATURE_OFFSET = 0x2a0;
export const SNP_R_LENGTH = 0x48;
export const SNP_SIGN_ECDSA_P384_SHA384 = 1;

const POLICY_SMT_BIT = 16n;
const POLICY_MIGRATE_MA_BIT = 18n;
const POLICY_DEBUG_BIT = 19n;
const POLICY_SINGLE_SOCKET_BIT = 20n;
const PLATFORM_SMT_BIT = 0n;

// CPUID.1.EAX with stepping zeroed, keyed to the AMD product line that AMD KDS
// issues certificates for. Siena/Bergamo parts are served by the Genoa endpoint.
const PRODUCT_LINE_CPUID: Record<number, string> = {
  0x00a00f10: 'Milan',
  0x00a10f10: 'Genoa',
  0x00b00f20: 'Turin',
};

const ASK_CERT_GUID = Uint8Array.from([0x4a, 0xb7, 0xb3, 0x79, 0xbb, 0xac, 0x4f, 0xe4, 0xa0, 0x2f, 0x05, 0xae, 0xf3, 0x27, 0xc7, 0x82]);
const VCEK_CERT_GUID = Uint8Array.from([0x63, 0xda, 0x75, 0x8d, 0xe6, 0x64, 0x45, 0x64, 0xad, 0xc5, 0xf4, 0xb9, 0x3b, 0xe8, 0xac, 0xcd]);
const CERT_TABLE_ENTRY_SIZE = 24;

function readU32le(data: Uint8Array, offset: number): number {
  return ((data[offset] as number) | ((data[offset + 1] as number) << 8) | ((data[offset + 2] as number) << 16) | ((data[offset + 3] as number) << 24)) >>> 0;
}

function readU64le(data: Uint8Array, offset: number): bigint {
  let value = 0n;
  for (let i = 7; i >= 0; i--) {
    value = (value << 8n) | BigInt(data[offset + i] as number);
  }
  return value;
}

function isZeroRange(data: Uint8Array, start: number, end: number, context: string): void {
  for (let i = start; i < end; i++) {
    if ((data[i] as number) !== 0) {
      fail('MALFORMED_REPORT', `${context}: byte 0x${i.toString(16)} must be zero`);
    }
  }
}

export function parseSnpPolicy(raw: bigint): SnpPolicy {
  return {
    raw,
    smt: (raw & (1n << POLICY_SMT_BIT)) !== 0n,
    migrateMA: (raw & (1n << POLICY_MIGRATE_MA_BIT)) !== 0n,
    debug: (raw & (1n << POLICY_DEBUG_BIT)) !== 0n,
    singleSocket: (raw & (1n << POLICY_SINGLE_SOCKET_BIT)) !== 0n,
  };
}

export function parseSnpReport(report: Uint8Array): SnpReport {
  if (report.length !== SNP_REPORT_SIZE) {
    fail('MALFORMED_REPORT', `report is ${report.length} bytes, expected ${SNP_REPORT_SIZE}`);
  }
  const version = readU32le(report, 0x00);
  if (version !== 2 && version !== 3) {
    fail('MALFORMED_REPORT', `report version ${version} is not 2 or 3`);
  }
  const signatureAlgo = readU32le(report, 0x34);
  if (signatureAlgo !== SNP_SIGN_ECDSA_P384_SHA384) {
    fail('UNSUPPORTED_SIGNATURE_ALGO', `algorithm id ${signatureAlgo}`);
  }
  isZeroRange(report, 0x4c, 0x50, 'report');
  const mbzAfterTcbStart = version >= 3 ? 0x18b : 0x188;
  isZeroRange(report, mbzAfterTcbStart, 0x1a0, 'report');
  isZeroRange(report, 0x1eb, 0x1ec, 'report');
  isZeroRange(report, 0x1ef, 0x1f0, 'report');
  isZeroRange(report, 0x208, SNP_SIGNATURE_OFFSET, 'report');
  isZeroRange(report, SNP_SIGNATURE_OFFSET + 2 * SNP_R_LENGTH, SNP_REPORT_SIZE, 'report');

  const signerInfoRaw = readU32le(report, 0x48);
  let cpuidFamily: number;
  let cpuidModel: number;
  let cpuidStepping: number | null = null;
  let productLine: string | null = null;
  if (version >= 3) {
    cpuidFamily = report[0x188] as number;
    cpuidModel = report[0x189] as number;
    cpuidStepping = report[0x18a] as number;
    productLine = productLineFromCpuid(cpuidFamily, cpuidModel);
  } else {
    cpuidFamily = 0;
    cpuidModel = 0;
  }

  return {
    raw: report,
    version,
    guestSvn: readU32le(report, 0x04),
    policy: parseSnpPolicy(readU64le(report, 0x08)),
    familyId: report.slice(0x10, 0x20),
    imageId: report.slice(0x20, 0x30),
    vmpl: readU32le(report, 0x30),
    signatureAlgo,
    currentTcb: tcbFromU64(readU64le(report, 0x38)),
    platformInfo: readU64le(report, 0x40),
    signerInfo: {
      signingKey: (signerInfoRaw >> 2) & 7,
      maskChipKey: (signerInfoRaw & 2) !== 0,
      authorKeyEn: (signerInfoRaw & 1) !== 0,
    },
    reportData: report.slice(0x50, 0x90),
    measurement: report.slice(0x90, 0xc0),
    hostData: report.slice(0xc0, 0xe0),
    idKeyDigest: report.slice(0xe0, 0x110),
    authorKeyDigest: report.slice(0x110, 0x140),
    reportId: report.slice(0x140, 0x160),
    reportIdMa: report.slice(0x160, 0x180),
    reportedTcb: tcbFromU64(readU64le(report, 0x180)),
    chipId: report.slice(0x1a0, 0x1e0),
    committedTcb: tcbFromU64(readU64le(report, 0x1e0)),
    launchTcb: Number(readU64le(report, 0x1f0)),
    cpuidFamily,
    cpuidModel,
    cpuidStepping,
    productLine,
    signature: {
      r: report.slice(SNP_SIGNATURE_OFFSET, SNP_SIGNATURE_OFFSET + SNP_R_LENGTH),
      s: report.slice(SNP_SIGNATURE_OFFSET + SNP_R_LENGTH, SNP_SIGNATURE_OFFSET + 2 * SNP_R_LENGTH),
    },
  };
}

export function productLineFromCpuid(family: number, model: number): string | null {
  const extendedFamily = family >= 0xf ? family - 0xf : 0;
  const familyId = family >= 0xf ? 0xf : family;
  const extendedModel = model >> 4;
  const modelId = model & 0xf;
  const maskedEax = (extendedFamily << 20) | (extendedModel << 16) | (familyId << 8) | (modelId << 4);
  return PRODUCT_LINE_CPUID[maskedEax] ?? null;
}

// The AMD report stores R and S as fixed 72-byte little-endian buffers; ECDSA
// wants them as a DER SEQUENCE of unsigned big-endian integers.
export function snpReportSignatureDer(report: SnpReport): Uint8Array {
  return derEcdsaSignature(leToBigint(report.signature.r), leToBigint(report.signature.s), p384.CURVE.n);
}

function leToBigint(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    value = (value << 8n) | BigInt(bytes[i] as number);
  }
  return value;
}

export function verifySnpReportSignature(report: SnpReport, vcek: ParsedCertificate): void {
  if (vcek.publicKey.kind !== 'ec-p384') {
    fail('UNSUPPORTED_CERT_ALGORITHM', 'VCEK public key is not EC P-384');
  }
  const signed = report.raw.subarray(0, SNP_SIGNED_SIZE);
  const valid = p384.verify(snpReportSignatureDer(report), sha384(signed), vcek.publicKey.point, { format: 'der' });
  if (!valid) {
    fail('BAD_SIGNATURE', 'report signature does not verify under the VCEK');
  }
}

// Resolves the ASK and VCEK certificate blobs from the attestation's
// cert_chain: dStack emits either [ask, vcek] or a single kernel certificate
// table auxblob (GUID-indexed entries followed by the certificates).
export function normalizeSnpCertificates(certChain: readonly Uint8Array[]): { ask: Uint8Array; vcek: Uint8Array } {
  if (certChain.length === 2) {
    return { ask: certChain[0] as Uint8Array, vcek: certChain[1] as Uint8Array };
  }
  if (certChain.length === 1) {
    return normalizeKernelCertTable(certChain[0] as Uint8Array);
  }
  fail('MALFORMED_CERTIFICATE', `cert_chain must hold an ASK and VCEK or one kernel certificate table, got ${certChain.length} entries`);
}

function normalizeKernelCertTable(blob: Uint8Array): { ask: Uint8Array; vcek: Uint8Array } {
  let ask: Uint8Array | null = null;
  let vcek: Uint8Array | null = null;
  let pos = 0;
  for (;;) {
    if (pos + CERT_TABLE_ENTRY_SIZE > blob.length) {
      fail('MALFORMED_CERTIFICATE', 'kernel certificate table is missing its terminator');
    }
    const entry = blob.subarray(pos, pos + CERT_TABLE_ENTRY_SIZE);
    const offset = readU32le(entry, 16);
    const length = readU32le(entry, 20);
    if (equalBytes(entry.subarray(0, 16), new Uint8Array(16)) && offset === 0 && length === 0) {
      break;
    }
    if (offset < CERT_TABLE_ENTRY_SIZE || length === 0 || offset + length > blob.length) {
      fail('MALFORMED_CERTIFICATE', 'kernel certificate table entry has invalid bounds');
    }
    const guid = entry.subarray(0, 16);
    if (equalBytes(guid, ASK_CERT_GUID)) {
      ask = blob.subarray(offset, offset + length);
    } else if (equalBytes(guid, VCEK_CERT_GUID)) {
      vcek = blob.subarray(offset, offset + length);
    }
    pos += CERT_TABLE_ENTRY_SIZE;
  }
  if (ask === null || vcek === null) {
    fail('MALFORMED_CERTIFICATE', 'kernel certificate table is missing the ASK or VCEK certificate');
  }
  return { ask, vcek };
}

// Verifies the AMD KDS chain shape: a self-signed ARK CA certifying the ASK CA
// which certifies the VCEK. Issuer/subject are compared as raw DER so an
// attacker cannot substitute a same-named certificate with different fields.
export function verifyAmdCertificateChain(ark: ParsedCertificate, ask: ParsedCertificate, vcek: ParsedCertificate, now: number): void {
  if (ark.isCa !== true || ask.isCa !== true) {
    fail('CERT_CHAIN_INVALID', 'AMD ARK and ASK certificates must be certificate authorities');
  }
  if (!equalBytes(ark.issuer, ark.subject)) {
    fail('CERT_CHAIN_INVALID', 'ARK certificate is not self-signed');
  }
  if (!equalBytes(ask.issuer, ark.subject)) {
    fail('CERT_CHAIN_INVALID', 'ASK issuer does not match the ARK subject');
  }
  if (!equalBytes(vcek.issuer, ask.subject)) {
    fail('CERT_CHAIN_INVALID', 'VCEK issuer does not match the ASK subject');
  }
  checkCertificateValidity(ark, now, 'ARK');
  checkCertificateValidity(ask, now, 'ASK');
  checkCertificateValidity(vcek, now, 'VCEK');
  verifyCertificateSignature(ark, ark, 'ARK');
  verifyCertificateSignature(ark, ask, 'ASK');
  verifyCertificateSignature(ask, vcek, 'VCEK');
}

// Selects the ARK (from the caller's trusted set) that actually issued the
// presented ASK. A miss is a missing trust root, not a bad signature.
export function findMatchingArk(trustedArks: readonly ParsedCertificate[], ask: ParsedCertificate): ParsedCertificate {
  for (const ark of trustedArks) {
    if (equalBytes(ark.subject, ask.issuer)) {
      return ark;
    }
  }
  fail('MISSING_TRUST_ROOT', 'no trusted ARK certificate matches the ASK issuer');
}

// Binds the VCEK to the exact chip that produced the report (KDS HWID
// extension) and to the product line the report's CPUID identifies.
export function verifyVcekMatchesReport(vcek: ParsedCertificate, report: SnpReport): void {
  if (vcek.productName === null) {
    fail('PRODUCT_MISMATCH', 'VCEK certificate has no AMD product name extension');
  }
  const line = vcek.productName.split('-')[0] as string;
  if (report.productLine !== null && report.productLine !== line) {
    fail('PRODUCT_MISMATCH', `report CPUID identifies a ${report.productLine} platform but the VCEK is for ${line}`);
  }
  if (vcek.hwid === null) {
    fail('CERT_CHAIN_INVALID', 'VCEK certificate has no HWID extension');
  }
  if (!equalBytes(vcek.hwid, report.chipId)) {
    fail('CERT_CHAIN_INVALID', 'VCEK HWID does not match the report chip ID');
  }
}

export function validateSnpPolicy(report: SnpReport, allowDebug: boolean): void {
  if (report.vmpl !== 0) {
    fail('POLICY_NOT_ALLOWED', `report was generated at VMPL ${report.vmpl}, expected 0`);
  }
  if (report.policy.debug && !allowDebug) {
    fail('DEBUG_NOT_ALLOWED', 'guest policy permits host-assisted debugging of the guest');
  }
  if (report.policy.migrateMA) {
    fail('POLICY_NOT_ALLOWED', 'guest policy permits a migration agent');
  }
  if (report.signerInfo.signingKey !== 0) {
    fail('POLICY_NOT_ALLOWED', `report signing key id ${report.signerInfo.signingKey}, expected VCEK`);
  }
  if (report.signerInfo.maskChipKey) {
    fail('POLICY_NOT_ALLOWED', 'report masks the chip signing key');
  }
  if (!report.policy.smt && (report.platformInfo & (1n << PLATFORM_SMT_BIT)) !== 0n) {
    fail('POLICY_NOT_ALLOWED', 'platform has SMT enabled but the guest policy does not allow SMT');
  }
}

// A blob supplied as the ASK or VCEK must hold exactly one certificate; ARK
// blobs may carry several certificates and every one is a trust candidate.
export function parseSingleCertificate(bytes: Uint8Array, name: string): ParsedCertificate {
  const certs = parseCertificateChain(bytes);
  if (certs.length !== 1) {
    fail('MALFORMED_CERTIFICATE', `${name} input holds ${certs.length} certificates, expected exactly one`);
  }
  return certs[0] as ParsedCertificate;
}

export function parseTrustCandidates(bytes: Uint8Array): ParsedCertificate[] {
  return parseCertificateChain(bytes);
}
