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
import { parseTdxQuote, isZero } from './tdx.js';
import type { Attestation, RuntimeEvent, SnpReport, TdxQuote } from './types.js';

const MR_CONFIG_DOMAIN = 'dstack-mr-config-v3:';
/** dstack-types writes tag 3 followed by the document digest and 15 zero bytes. */
const MR_CONFIG_ID_TAG = 3;
const MR_CONFIG_ID_SIZE = 48;
const MR_CONFIG_DIGEST_SIZE = 32;
const MAX_INIT_SCRIPTS = 5;

/**
 * dstack pins an application's configuration into the CVM by hashing the
 * verbatim mr_config document under this domain prefix. SEV-SNP commits the
 * digest to the report's HOST_DATA, TDX to MR_CONFIG_ID bytes 1 through 33.
 */
export function mrConfigDocumentDigest(document: string): Uint8Array {
  const domain = new TextEncoder().encode(MR_CONFIG_DOMAIN);
  const bytes = new TextEncoder().encode(document);
  const input = new Uint8Array(domain.length + 1 + bytes.length);
  input.set(domain, 0);
  input[domain.length] = 0;
  input.set(bytes, domain.length + 1);
  return sha256(input);
}

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
  /** Ordered digests of the init scripts the platform ran, capped at five. */
  readonly initScriptHashes: readonly Uint8Array[] | null;
}

export interface SnpVerification {
  readonly report: SnpReport;
  readonly mrConfig: MrConfigDetails;
}

export interface TdxMrConfig {
  /** Binding tag the platform wrote into MR_CONFIG_ID[0]. */
  readonly tag: number;
  /** Domain-prefixed digest of the mr_config document: MR_CONFIG_ID[1..33]. */
  readonly digest: Uint8Array;
}

export interface TdxVerification {
  readonly quote: TdxQuote;
  /** Null when MR_CONFIG_ID is empty, meaning no application configuration is pinned. */
  readonly mrConfig: TdxMrConfig | null;
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
  if (!equalBytes(mrConfigDocumentDigest(mrConfig), report.hostData)) {
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
    // Widths are enforced only where the platform fixes them: the guest compares
    // app_id against a [u8; 20], and the digests are SHA-256. instance_id and
    // key_provider_id are identifiers of varying shape and stay unchecked.
    appId: hexField(fields['app_id'], 'app_id', 20, false),
    composeHash: hexField(fields['compose_hash'], 'compose_hash', MR_CONFIG_DIGEST_SIZE, true),
    gpuPolicyHash: hexField(fields['gpu_policy_hash'], 'gpu_policy_hash', null, false),
    keyProvider: typeof fields['key_provider'] === 'string' ? fields['key_provider'] : null,
    keyProviderId: hexField(fields['key_provider_id'], 'key_provider_id', null, false),
    instanceId: hexField(fields['instance_id'], 'instance_id', null, false),
    initScriptHashes: parseInitScriptHashes(fields['init_script_hashes']),
  };
}

function hexField(value: unknown, name: string, byteLength: number | null, required: true): Uint8Array;
function hexField(value: unknown, name: string, byteLength: number | null, required: false): Uint8Array | null;
function hexField(
  value: unknown,
  name: string,
  byteLength: number | null,
  required: boolean,
): Uint8Array | null {
  if (typeof value !== 'string') {
    if (required) {
      fail('MR_CONFIG_MISMATCH', `mr_config document is missing ${name}`);
    }
    return null;
  }
  let bytes: Uint8Array;
  try {
    bytes = fromHex(value);
  } catch {
    fail('MR_CONFIG_MISMATCH', `mr_config ${name} is not a hex string`);
  }
  if (byteLength !== null && bytes.length !== byteLength) {
    fail('MR_CONFIG_MISMATCH', `mr_config ${name} is ${bytes.length} bytes, expected ${byteLength}`);
  }
  return bytes;
}

function parseInitScriptHashes(value: unknown): readonly Uint8Array[] | null {
  if (value === undefined || value === null) {
    return null;
  }
  if (!Array.isArray(value)) {
    fail('MR_CONFIG_MISMATCH', 'mr_config init_script_hashes is not an array');
  }
  if (value.length > MAX_INIT_SCRIPTS) {
    fail('MR_CONFIG_MISMATCH', `mr_config init_script_hashes has ${value.length} entries, at most ${MAX_INIT_SCRIPTS}`);
  }
  return value.map((entry, index) =>
    hexField(entry, `init_script_hashes[${index}]`, MR_CONFIG_DIGEST_SIZE, true),
  );
}

function optionalUint(value: unknown): number | null {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0 ? value : null;
}

// TDX carries no mr_config document in the attestation envelope, so a remote
// verifier pins the digest the platform committed to at launch instead.
function readTdxMrConfig(mrConfigId: Uint8Array): TdxMrConfig | null {
  if (mrConfigId.length !== MR_CONFIG_ID_SIZE) {
    fail('MALFORMED_QUOTE', `MR_CONFIG_ID is ${mrConfigId.length} bytes, expected ${MR_CONFIG_ID_SIZE}`);
  }
  if (isZero(mrConfigId)) {
    return null;
  }
  const tag = mrConfigId[0] as number;
  if (tag !== MR_CONFIG_ID_TAG) {
    fail('BAD_MR_CONFIG_ID', `tag ${String(tag)} is not supported, only tag ${MR_CONFIG_ID_TAG}`);
  }
  if (!isZero(mrConfigId.subarray(1 + MR_CONFIG_DIGEST_SIZE))) {
    fail('BAD_MR_CONFIG_ID', 'MR_CONFIG_ID bytes after the digest must be zero');
  }
  return { tag, digest: mrConfigId.slice(1, 1 + MR_CONFIG_DIGEST_SIZE) };
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
    tdx: { quote, mrConfig: readTdxMrConfig(quote.mrConfigId) },
  };
}

/** The launch measurement this evidence attests to: the SNP launch digest or the TDX MRTD. */
export function platformMeasurement(result: VerificationResult): Uint8Array {
  if (result.snp) {
    return result.snp.report.measurement;
  }
  if (result.tdx) {
    return result.tdx.quote.mrTd;
  }
  return fail('UNSUPPORTED_PLATFORM', 'the verified result carries no platform measurement');
}

/**
 * The compose hash the platform committed to. SEV-SNP hashes the mr_config
 * document into HOST_DATA, so the document itself is the authority. TDX carries
 * no document in the envelope, so the value comes from the runtime events, which
 * the RTMR3 replay inside verifyTdx already tied to the quote.
 */
export function pinnedComposeHash(result: VerificationResult): Uint8Array | null {
  if (result.snp) {
    return result.snp.mrConfig.composeHash;
  }
  const event = result.runtimeEvents.find((entry) => entry.event === 'compose-hash');
  return event?.payload ?? null;
}
