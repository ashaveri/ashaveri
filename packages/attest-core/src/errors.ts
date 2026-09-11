export type AttestationErrorCode =
  | 'MALFORMED_ATTESTATION'
  | 'UNSUPPORTED_VERSION'
  | 'UNKNOWN_PLATFORM'
  | 'UNKNOWN_STACK'
  | 'UNSUPPORTED_PLATFORM'
  | 'TRAILING_BYTES'
  | 'MALFORMED_QUOTE'
  | 'UNSUPPORTED_QUOTE'
  | 'MALFORMED_REPORT'
  | 'MALFORMED_GPU_BUNDLE'
  | 'UNSUPPORTED_SIGNATURE_ALGO'
  | 'BAD_EVENT_DIGEST'
  | 'BAD_EVENT_PREIMAGE'
  | 'EVENT_LOG_MISMATCH'
  | 'RTMR_MISMATCH'
  | 'REPORT_DATA_MISMATCH'
  | 'NONCE_MISMATCH'
  | 'QE_REPORT_MISMATCH'
  | 'MR_CONFIG_MISMATCH'
  | 'BAD_MR_CONFIG_ID'
  | 'PIN_MISMATCH'
  | 'MALFORMED_CERTIFICATE'
  | 'UNSUPPORTED_CERT_ALGORITHM'
  | 'CERT_CHAIN_INVALID'
  | 'CERT_EXPIRED'
  | 'PRODUCT_MISMATCH'
  | 'MISSING_TRUST_ROOT'
  | 'BAD_SIGNATURE'
  | 'DEBUG_NOT_ALLOWED'
  | 'POLICY_NOT_ALLOWED';

const ERROR_MESSAGE: Record<AttestationErrorCode, string> = {
  MALFORMED_ATTESTATION: 'attestation bytes do not decode as a dStack VersionedAttestation',
  UNSUPPORTED_VERSION: 'attestation uses an unsupported version',
  UNKNOWN_PLATFORM: 'platform evidence uses an unknown kind',
  UNKNOWN_STACK: 'stack evidence uses an unknown kind',
  UNSUPPORTED_PLATFORM: 'platform evidence is decodable but verification is not implemented for it',
  TRAILING_BYTES: 'attestation has trailing bytes after the encoded value',
  MALFORMED_QUOTE: 'TDX quote bytes are malformed',
  UNSUPPORTED_QUOTE: 'TDX quote uses a format this package cannot verify',
  MALFORMED_REPORT: 'SEV-SNP report bytes are malformed',
  MALFORMED_GPU_BUNDLE: 'device evidence is not the JSON bundle nvattest writes',
  UNSUPPORTED_SIGNATURE_ALGO: 'SEV-SNP report signature algorithm is not ECDSA-P384-SHA384',
  BAD_EVENT_DIGEST: 'event log digest does not match the recomputed digest',
  BAD_EVENT_PREIMAGE: 'V2 event digest preimage is missing or does not match',
  EVENT_LOG_MISMATCH: 'platform event log and stack runtime events disagree',
  RTMR_MISMATCH: 'replayed RTMR3 does not match the value in the TDX quote',
  REPORT_DATA_MISMATCH: 'attestation report data does not match the quote',
  NONCE_MISMATCH: 'the attested device did not sign the challenge it is checked against',
  QE_REPORT_MISMATCH: 'the QE report inside the quote does not bind the attestation key that signed it',
  MR_CONFIG_MISMATCH: 'mr_config document does not match the measurement pinned by the platform',
  BAD_MR_CONFIG_ID: 'MR_CONFIG_ID is neither empty nor a recognized dstack configuration binding',
  PIN_MISMATCH: 'a pinned deployment claim does not match the verified evidence',
  MALFORMED_CERTIFICATE: 'certificate bytes are not valid X.509',
  UNSUPPORTED_CERT_ALGORITHM: 'certificate uses a signature algorithm or curve this package does not support',
  CERT_CHAIN_INVALID: 'certificate chain does not link from leaf to a certificate authority',
  CERT_EXPIRED: 'certificate is not valid at the verification time',
  PRODUCT_MISMATCH: 'certificate product name does not match the report platform',
  MISSING_TRUST_ROOT: 'no trusted root certificate matches the anchor of the presented chain',
  BAD_SIGNATURE: 'cryptographic signature verification failed',
  DEBUG_NOT_ALLOWED: 'SEV-SNP policy enables debug mode',
  POLICY_NOT_ALLOWED: 'SEV-SNP report policy violates the verification profile',
};

export class AttestationError extends Error {
  readonly code: AttestationErrorCode;

  constructor(code: AttestationErrorCode, detail?: string) {
    super(detail ? `${ERROR_MESSAGE[code]}: ${detail}` : ERROR_MESSAGE[code]);
    this.name = 'AttestationError';
    this.code = code;
  }
}

export function fail(code: AttestationErrorCode, detail?: string): never {
  throw new AttestationError(code, detail);
}
