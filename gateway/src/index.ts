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
// The credential file's shape and the admission decision are exported for the same reason the
// store's is: the tooling that writes a credential and the code that checks one are compiled
// separately, and a second copy of these shapes could drift from the parser and the pipeline that
// refuse them without a compile error anywhere.
export {
  accessStatus,
  AccessError,
  CredentialStore,
  CREDENTIALS_FILE_VERSION,
  DEFAULT_RATE,
  loadCredentialFile,
  MAX_CREDENTIALS,
  newBearerCredential,
  newPopCredential,
  parseCredentialFile,
  ReplaySet,
  REPLAY_WINDOW_SECONDS,
  ROUTE_SCOPES,
  routeScope,
  scopeSatisfied,
  serializeCredentialFile,
  TokenBucket,
  type AccessErrorCode,
  type Admission,
  type AdmissionInput,
  type CredentialFile,
  type CredentialRate,
  type CredentialRecord,
  type CredentialStoreOptions,
  type RouteScope,
  type Scope,
} from './access.js';
// The scrub tooling rewrites these files from a separate program, so the renderer, the parser and
// the field allowlist they are checked against are part of the entry point rather than private to
// the writer that appends them.
export {
  ACCESS_RECORD_FIELDS,
  MAX_ACCESS_FILE_BYTES,
  MINIMUM_RETENTION_DAYS,
  openFileAccessLog,
  openMemoryAccessLog,
  parseAccessLine,
  renderAccessLine,
  type AccessLog,
  type AccessLogOptions,
  type AccessRecord,
  type AccessWindow,
  type MemoryAccessLog,
} from './aclog.js';
