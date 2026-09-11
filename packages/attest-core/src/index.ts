export { AttestationError, fail } from './errors.js';
export type { AttestationErrorCode } from './errors.js';
export { decodeAttestation } from './decode.js';
export {
  canonicalEventJsonV2,
  equalBytes,
  fromHex,
  replayRtmr3,
  runtimeEventDigest,
  runtimeEventPreimage,
  validateEventLog,
} from './events.js';
export { parseTdxQuote } from './tdx.js';
export { parseQeReportCertificationData, parseTdxQuoteSignature, verifyTdxQuote } from './tdx-dcap.js';
export type { QeReportCertificationData, TdxDcapOptions, TdxQuoteSignature, TdxQuoteVerification } from './tdx-dcap.js';
export { verifyNvidiaRats } from './nvidia.js';
export type { NvidiaEvidence, NvidiaOptions, NvidiaVerification } from './nvidia.js';
export {
  AMD_ARK_MILAN_PEM,
  DEFAULT_AMD_ARKS,
  DEFAULT_INTEL_SGX_ROOTS,
  DEFAULT_NVIDIA_DEVICE_ROOTS,
  INTEL_SGX_ROOT_CA_PEM,
  NVIDIA_DEVICE_IDENTITY_CA_PEM,
} from './trust-anchors.js';
export {
  normalizeSnpCertificates,
  parseSnpReport,
  parseSnpPolicy,
  productLineFromCpuid,
  snpReportSignatureDer,
  SNP_REPORT_SIZE,
  SNP_SIGNED_SIZE,
  SNP_SIGNATURE_OFFSET,
} from './sev-snp.js';
export { verifyAttestation, mrConfigDocumentDigest, pinnedComposeHash, platformMeasurement } from './verify.js';
export type {
  MrConfigDetails,
  SnpVerification,
  TdxMrConfig,
  TdxVerification,
  VerificationResult,
  VerifyOptions,
} from './verify.js';
export { parseCertificate, parseCertificateChain } from './der.js';
export type { CertificatePublicKey, ParsedCertificate, SignatureAlgorithm } from './der.js';
export { DSTACK_RUNTIME_EVENT_TYPE, tcbFromU64 } from './types.js';
export type {
  Attestation,
  EventLogVersion,
  PlatformEvidence,
  RuntimeEvent,
  SnpPolicy,
  SnpReport,
  StackEvidence,
  TcbVersion,
  TdxEvent,
  TdxQuote,
} from './types.js';
