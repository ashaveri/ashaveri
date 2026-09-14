export { buildGateway } from './server.js';
export type { GatewayOptions, ManifestJson } from './server.js';
export { mockBackend } from './backend.js';
export type { BackendResponse, CompletionBackend, CompletionUsage } from './backend.js';
export { mockDeployment, mockWeights } from './deployment.js';
export type { AttestationBundle, Deployment, ModelInfo, MockDeploymentOptions, TeeKind } from './deployment.js';
export { GuestClient, GuestError, MAX_REPORT_DATA_BYTES } from './guest.js';
export type { GpuEvidenceBundle, GuestApi, GuestClientOptions, GuestErrorCode, GuestInfo, GuestKey } from './guest.js';
export { dstackDeployment, DstackError } from './dstack.js';
export type { DstackDeploymentOptions, DstackErrorCode } from './dstack.js';
export { upstreamBackend } from './upstream.js';
export type { UpstreamOptions } from './upstream.js';
export {
  completionJson,
  completionSse,
  mockCompletion,
  parseChatCompletionRequest,
  DEFAULT_MOCK_MODEL,
} from './mock.js';
export type { ChatCompletionRequest, ChatMessage, MockCompletion } from './mock.js';
export { RequestError } from './mock.js';
export { fromBase64Url, toBase64Url } from './b64.js';
export { fromHex, sha256, toHex } from './digest.js';
// The store is exported because the evidence-pack generator is a separate program that reads a live
// store through this contract. Declaring these types a second time where it lives could drift from
// the engine without a compile error, and a chain head produced against a stale copy of the shape
// is a number a regulator would read without knowing it had never been checked.
export {
  MINIMUM_RETENTION_SECONDS,
  openFileReceiptStore,
  openMemoryReceiptStore,
  RECEIPT_STORE_FILE,
  StoreError,
} from './store.js';
export type {
  ChainState,
  FileReceiptStoreOptions,
  ReceiptRetention,
  ReceiptStore,
  StoreErrorCode,
  StoredReceipt,
  TrimEvent,
} from './store.js';
