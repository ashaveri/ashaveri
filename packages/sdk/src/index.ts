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
export type { DeploymentManifest, ManifestKey, ManifestModel, TeeKind } from './manifest.js';
export {
  DEFAULT_MAX_EVIDENCE_AGE_SECONDS,
  DEFAULT_MAX_RECEIPT_AGE_SECONDS,
  policyFromManifest,
  policyKeyByKid,
} from './policy.js';
export type { AshaveriPolicy } from './policy.js';
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
