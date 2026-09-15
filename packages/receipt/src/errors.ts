export type ReceiptErrorCode =
  | 'MALFORMED_CBOR'
  | 'NOT_COSE_SIGN1'
  | 'UNSUPPORTED_ALG'
  | 'BAD_PROTECTED_HEADER'
  | 'KID_MISMATCH'
  | 'UNKNOWN_KEY'
  | 'INVALID_SIGNATURE'
  | 'NONCE_MISMATCH'
  | 'STALE_EVIDENCE'
  | 'STALE_RECEIPT'
  | 'BAD_PAYLOAD'
  | 'BAD_SIGNING_KEY'
  | 'BAD_POP_HEADER'
  | 'BAD_POP_NONCE'
  | 'AUTH_SCHEME_MISMATCH';

const ERROR_MESSAGE: Record<ReceiptErrorCode, string> = {
  MALFORMED_CBOR: 'receipt bytes are not valid canonical CBOR',
  NOT_COSE_SIGN1: 'top-level value is not a COSE_Sign1 (tag 18) structure',
  UNSUPPORTED_ALG: 'protected header alg is not EdDSA (-8)',
  BAD_PROTECTED_HEADER: 'protected header is missing required parameters',
  KID_MISMATCH: 'resolved key does not match the receipt kid',
  UNKNOWN_KEY: 'no key found for the receipt kid',
  INVALID_SIGNATURE: 'Ed25519 signature verification failed',
  NONCE_MISMATCH: 'receipt nonce does not match the expected client nonce',
  STALE_EVIDENCE: 'attestation evidence timestamp is outside the freshness window',
  STALE_RECEIPT: 'receipt issuance time is outside the freshness window',
  BAD_PAYLOAD: 'payload does not match the receipt-v1 CDDL schema',
  BAD_SIGNING_KEY: 'signing key is not a valid Ed25519 key',
  BAD_POP_HEADER: 'the PoP Authorization header is not parseable',
  BAD_POP_NONCE: 'the PoP nonce is not unpadded base64url of the right width',
  AUTH_SCHEME_MISMATCH: 'the Authorization header is not an Ashaveri-PoP header',
};

/**
 * A detail quotes what the raise site was looking at, and the sites that parse a header quote
 * bytes chosen by whoever sent it. The code is the contract and the sentence is fixed, so this
 * bounds only the quoted part: a diagnostic stays readable and cannot become a copy of a
 * multi-kilobyte request header on its way into a log line.
 */
const MAX_DETAIL = 200;

function bounded(detail: string): string {
  return detail.length > MAX_DETAIL ? `${detail.slice(0, MAX_DETAIL)}...` : detail;
}

export class ReceiptError extends Error {
  readonly code: ReceiptErrorCode;

  constructor(code: ReceiptErrorCode, detail?: string) {
    super(detail ? `${ERROR_MESSAGE[code]}: ${bounded(detail)}` : ERROR_MESSAGE[code]);
    this.name = 'ReceiptError';
    this.code = code;
  }
}
