export type SdkErrorCode =
  | 'NO_POLICY'
  | 'BAD_MANIFEST'
  | 'MANIFEST_KEY_NOT_PINNED'
  | 'RECEIPT_NOT_FOUND'
  | 'REQUEST_HASH_MISMATCH'
  | 'RESPONSE_HASH_MISMATCH'
  | 'ISSUER_NOT_ALLOWED'
  | 'INSTANCE_NOT_ALLOWED'
  | 'MEASUREMENT_NOT_ALLOWED'
  | 'GATEWAY_ERROR'
  | 'NOT_RECEIPTED'
  // Strict mode only: the hardware evidence behind a receipt. Listed in the order
  // the checks run, so the code identifies the stage that rejected the document.
  | 'EVIDENCE_NOT_FOUND'
  | 'EVIDENCE_NOT_HARDWARE'
  | 'EVIDENCE_NO_TRUST_ANCHORS'
  | 'EVIDENCE_DIGEST_MISMATCH'
  | 'EVIDENCE_VERIFICATION_FAILED'
  | 'EVIDENCE_NOT_VERIFIED'
  | 'EVIDENCE_REPORT_DATA_MISMATCH'
  | 'EVIDENCE_TEE_MISMATCH'
  | 'EVIDENCE_GPU_MISSING'
  | 'EVIDENCE_MEASUREMENT_MISMATCH'
  // A credential the client cannot use, refused before anything went on the wire.
  | 'AUTH_CONFIG'
  // A verification policy read out of a file. The format is a trust anchor, so every one of these
  // is a refusal to publish a digest over a document the loader is not certain it read correctly.
  | 'POLICY_FILE_INVALID'
  | 'POLICY_FILE_UNREADABLE'
  | 'POLICY_NOTHING_PINNED'
  | 'POLICY_EMPTY_PIN'
  | 'POLICY_ANCHOR_UNREADABLE'
  | 'POLICY_ANCHOR_DIGEST_MISMATCH';

export class SdkError extends Error {
  readonly code: SdkErrorCode;

  constructor(code: SdkErrorCode, message: string) {
    super(message);
    this.name = 'SdkError';
    this.code = code;
  }
}

export function sdkError(code: SdkErrorCode, message: string): never {
  throw new SdkError(code, message);
}
