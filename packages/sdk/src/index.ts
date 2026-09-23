export { AshaveriClient } from './client.js';
export type {
  AshaveriClientOptions,
  ChatCompletion,
  ChatCompletionChunk,
  ChatCompletionChunkChoice,
  ChatCompletionChoice,
  ChatCompletionMessageParam,
  ChatCompletionParams,
  ChatCompletionUsage,
  ChunkStream,
  CompletionResult,
  VerificationOutcome,
  VerifyMode,
} from './client.js';
export { authorizedFetch, credentialFromEnv, CREDENTIAL_ENV } from './auth.js';
export type { AshaveriCredential, AuthOptions } from './auth.js';
export { wrapOpenAI } from './wrap.js';
export type { AshaveriTracker, WrapOptions } from './wrap.js';
export { GatewaySession } from './gateway.js';
export type {
  GatewaySessionOptions,
  VerifiedCompletion,
  VerifyCompletionOptions,
  VerifyReceiptedParams,
} from './gateway.js';
export { deviceReports, evidenceReportData, verifyCompletionEvidence } from './evidence.js';
export type { EvidenceTrustAnchors, VerifiedEvidence, VerifyEvidenceParams } from './evidence.js';
export { verifyCompletionReceipt } from './verify.js';
export type { VerifyCompletionParams } from './verify.js';
export { parseManifest } from './manifest.js';
export type { DeploymentManifest, DeclaredEpoch, ManifestKey, ManifestModel, TeeKind } from './manifest.js';
export { adjudicateReceiptEpoch } from './epoch.js';
export type { EpochAccepted, EpochRefused, EpochVerdict, ReceiptEpochClaim } from './epoch.js';
export { readDeploymentManifest } from './manifest-auth.js';
export type { ManifestAuthentication, ReadManifestResult } from './manifest-auth.js';
export {
  DEFAULT_MAX_EVIDENCE_AGE_SECONDS,
  DEFAULT_MAX_RECEIPT_AGE_SECONDS,
  policyFromManifest,
  policyKeyByKid,
} from './policy.js';
export type { AshaveriPolicy } from './policy.js';
export {
  ANCHOR_FAMILIES,
  loadPolicyFile,
  loadPolicyFromText,
  parsePolicyFile,
  PINNED_TEXT_PATTERN,
  POLICY_DIGEST_PREFIX,
  POLICY_FORMAT_VERSION,
  policyFileDigest,
  policyFileFromPolicy,
  policyFileToJson,
} from './policy-file.js';
export type {
  AnchorFamily,
  LoadedPolicy,
  LoadedPolicyAnchor,
  PolicyAnchorFamily,
  PolicyFile,
  PolicyFileTrustAnchors,
  PolicyTrustAnchor,
} from './policy-file.js';
export { assessCapture, CAPTURE_FORMAT_VERSION, captureRecordKey, parseCaptureRecord } from './capture.js';
export type {
  AssessCaptureParams,
  CaptureAbsent,
  CaptureAppliedLimits,
  CaptureDeclaredAbsence,
  CaptureHeld,
  CapturePresence,
  CaptureRecord,
  CaptureRootReference,
  CaptureSink,
  CaptureSlot,
  CaptureSourceKind,
  CaptureVerdict,
  CaptureWriteOutcome,
} from './capture.js';
export { SdkError, sdkError } from './errors.js';
export type { SdkErrorCode } from './errors.js';
export { fromBase64Url, toBase64Url, toHex } from './b64.js';
export {
  claimsConfidentialDevice,
  decodeReceipt,
  generateSigningKey,
  hashRequest,
  randomNonce,
  receiptBytesToJson,
  receiptToJson,
  verifyReceipt,
} from '@ashaveri/receipt';
export type { ReceiptJson, ReceiptPayload, SigningKey, VerifiedReceipt } from '@ashaveri/receipt';
export { ReceiptError } from '@ashaveri/receipt';
