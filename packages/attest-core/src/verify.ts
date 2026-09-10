import { sha256 } from '@noble/hashes/sha2.js';
import { decodeAttestation } from './decode.js';
import { fail } from './errors.js';
import { equalBytes, fromHex, replayRtmr3, validateEventLog } from './events.js';
import {
  findMatchingArk,
  normalizeSnpCertificates,
  parseSingleCertificate,
  parseSnpReport,
  parseTrustCandidates,
  validateSnpPolicy,
  verifyAmdCertificateChain,
  verifySnpReportSignature,
  verifyVcekMatchesReport,
} from './sev-snp.js';
import { parseTdxQuote } from './tdx.js';
import type { Attestation, RuntimeEvent, SnpReport, TdxQuote } from './types.js';

const MR_CONFIG_DOMAIN = 'dstack-mr-config-v3:';

export interface VerifyOptions {
  /** Verification time in milliseconds since the Unix epoch. Defaults to now. */
  readonly now?: number;
  /** Trusted AMD root (ARK) certificates as PEM or DER bytes. Each blob may hold several certificates. */
  readonly trustedArks?: readonly Uint8Array[];
  /** ASK certificate for attestations whose cert_chain is empty (PEM or DER). */
  readonly askCert?: Uint8Array;
  /** VCEK certificate for attestations whose cert_chain is empty (PEM or DER). */
  readonly vcekCert?: Uint8Array;
  /** Accept reports whose guest policy permits debugging. Defaults to false. */
  readonly allowDebug?: boolean;
}

export interface MrConfigDetails {
  readonly raw: string;
  readonly version: number | null;
  readonly appId: Uint8Array | null;
  readonly composeHash: Uint8Array;
  readonly gpuPolicyHash: Uint8Array | null;
  readonly keyProvider: string | null;
  readonly keyProviderId: Uint8Array | null;
  readonly instanceId: Uint8Array | null;
}

export interface SnpVerification {
  readonly report: SnpReport;
  readonly mrConfig: MrConfigDetails;
}

export interface TdxVerification {
  readonly quote: TdxQuote;
}

export interface VerificationResult {
  readonly version: 0 | 1;
  readonly platformKind: 'sev-snp' | 'tdx';
  /** Whether the hardware quote's own signature was verified. False for TDX, where Intel DCAP verification is out of scope. */
  readonly quoteSignatureVerified: boolean;
  readonly reportData: Uint8Array;
  readonly runtimeEvents: readonly RuntimeEvent[];
  readonly config: string;
  readonly snp?: SnpVerification;
  readonly tdx?: TdxVerification;
}

export function verifyAttestation(bytes: Uint8Array, options: VerifyOptions = {}): VerificationResult {
  const attestation = decodeAttestation(bytes);
  switch (attestation.platform.kind) {
    case 'sev-snp':
      return verifySevSnp(attestation, options);
    case 'tdx':
      return verifyTdx(attestation);
    default:
      fail('UNSUPPORTED_PLATFORM', `verification is not implemented for platform kind ${attestation.platform.kind}`);
  }
}

function verifySevSnp(attestation: Attestation, options: VerifyOptions): VerificationResult {
  const platform = attestation.platform;
  if (platform.kind !== 'sev-snp') {
    fail('UNSUPPORTED_PLATFORM', 'expected sev-snp platform evidence');
  }
  const report = parseSnpReport(platform.report);

  let askBytes = options.askCert;
  let vcekBytes = options.vcekCert;
  if (platform.certChain.length > 0) {
    const normalized = normalizeSnpCertificates(platform.certChain);
    askBytes = normalized.ask;
    vcekBytes = normalized.vcek;
  }
  if (askBytes === undefined || vcekBytes === undefined) {
    fail('MISSING_TRUST_ROOT', 'attestation carries no certificate chain; supply askCert and vcekCert');
  }
  const ask = parseSingleCertificate(askBytes, 'ASK');
  const vcek = parseSingleCertificate(vcekBytes, 'VCEK');

  const candidates = (options.trustedArks ?? []).flatMap((blob) => parseTrustCandidates(blob));
  const ark = findMatchingArk(candidates, ask);

  const now = options.now ?? Date.now();
  verifyAmdCertificateChain(ark, ask, vcek, now);
  verifyVcekMatchesReport(vcek, report);
  verifySnpReportSignature(report, vcek);
  validateSnpPolicy(report, options.allowDebug ?? false);

  if (!equalBytes(attestation.stack.reportData, report.reportData)) {
    fail('REPORT_DATA_MISMATCH', 'stack report_data differs from the report REPORT_DATA field');
  }

  const mrConfig = verifyMrConfigHostData(platform.mrConfig, report);

  return {
    version: attestation.version,
    platformKind: 'sev-snp',
    quoteSignatureVerified: true,
    reportData: attestation.stack.reportData,
    runtimeEvents: attestation.stack.runtimeEvents,
    config: attestation.stack.config,
    snp: { report, mrConfig },
  };
}

// The mr_config document is pinned into the report at launch: HOST_DATA is the
// AMD-measured hash of the verbatim document bytes, so the verifier sees the
// exact configuration the control plane committed to before the guest started.
function verifyMrConfigHostData(mrConfig: string, report: SnpReport): MrConfigDetails {
  const domain = new TextEncoder().encode(MR_CONFIG_DOMAIN);
  const document = new TextEncoder().encode(mrConfig);
  const input = new Uint8Array(domain.length + 1 + document.length);
  input.set(domain, 0);
  input[domain.length] = 0;
  input.set(document, domain.length + 1);
  if (!equalBytes(sha256(input), report.hostData)) {
    fail('MR_CONFIG_MISMATCH', 'sha256 of the mr_config document does not equal the report HOST_DATA');
  }
  return parseMrConfig(mrConfig);
}

function parseMrConfig(raw: string): MrConfigDetails {
  let document: unknown;
  try {
    document = JSON.parse(raw);
  } catch {
    fail('MR_CONFIG_MISMATCH', 'mr_config document is not valid JSON');
  }
  if (document === null || typeof document !== 'object' || Array.isArray(document)) {
    fail('MR_CONFIG_MISMATCH', 'mr_config document is not a JSON object');
  }
  const fields = document as Record<string, unknown>;
  return {
    raw,
    version: optionalUint(fields['version']),
    appId: optionalHex(fields['app_id']),
    composeHash: requiredHex(fields['compose_hash'], 'compose_hash'),
    gpuPolicyHash: optionalHex(fields['gpu_policy_hash']),
    keyProvider: typeof fields['key_provider'] === 'string' ? fields['key_provider'] : null,
    keyProviderId: optionalHex(fields['key_provider_id']),
    instanceId: optionalHex(fields['instance_id']),
  };
}

function requiredHex(value: unknown, name: string): Uint8Array {
  if (typeof value !== 'string') {
    fail('MR_CONFIG_MISMATCH', `mr_config document is missing ${name}`);
  }
  try {
    const bytes = fromHex(value);
    if (bytes.length !== 32) {
      fail('MR_CONFIG_MISMATCH', `mr_config ${name} is ${bytes.length} bytes, expected 32`);
    }
    return bytes;
  } catch (error) {
    if (error instanceof Error && error.name === 'AttestationError') {
      throw error;
    }
    fail('MR_CONFIG_MISMATCH', `mr_config ${name} is not a hex string`);
  }
}

function optionalHex(value: unknown): Uint8Array | null {
  if (typeof value !== 'string') {
    return null;
  }
  try {
    return fromHex(value);
  } catch {
    return null;
  }
}

function optionalUint(value: unknown): number | null {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0 ? value : null;
}

function verifyTdx(attestation: Attestation): VerificationResult {
  const platform = attestation.platform;
  if (platform.kind !== 'tdx') {
    fail('UNSUPPORTED_PLATFORM', 'expected tdx platform evidence');
  }
  const quote = parseTdxQuote(platform.quote);
  validateEventLog(platform.eventLog, attestation.stack.runtimeEvents);
  const replayed = replayRtmr3(attestation.stack.runtimeEvents);
  if (!equalBytes(replayed, quote.rtmr[3] as Uint8Array)) {
    fail('RTMR_MISMATCH', 'replayed RTMR3 from runtime events differs from the quote');
  }
  if (!equalBytes(attestation.stack.reportData, quote.reportData)) {
    fail('REPORT_DATA_MISMATCH', 'stack report_data differs from the quote REPORT_DATA field');
  }
  return {
    version: attestation.version,
    platformKind: 'tdx',
    quoteSignatureVerified: false,
    reportData: attestation.stack.reportData,
    runtimeEvents: attestation.stack.runtimeEvents,
    config: attestation.stack.config,
    tdx: { quote },
  };
}
