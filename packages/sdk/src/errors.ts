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
  | 'EVIDENCE_MEASUREMENT_MISMATCH';

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
