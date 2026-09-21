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
  | 'UNSUPPORTED_VERSION'
  | 'BAD_PAYLOAD'
  | 'UNSUPPORTED_SCHEME'
  | 'MARK_MISMATCH'
  | 'BAD_SIGNING_KEY'
  | 'BAD_POP_HEADER'
  | 'BAD_POP_NONCE'
  | 'AUTH_SCHEME_MISMATCH';

const ERROR_MESSAGE: Record<ReceiptErrorCode, string> = {
  MALFORMED_CBOR: 'receipt bytes are not valid canonical CBOR',
  NOT_COSE_SIGN1: 'top-level value is not a COSE_Sign1 (tag 18) structure',
  UNSUPPORTED_ALG: 'protected header alg is not EdDSA (-8)',
  // What this code answers, in the order `cose.ts` reaches it: the protected bstr holds no map, the map
  // carries a label the format does not declare, or one of the declared parameters `kid` and `typ` is
  // absent or ill-shaped. It is not one code for every fault a header can carry. `alg` keeps its own,
  // `UNSUPPORTED_ALG`, for both of its shapes, an absent parameter and a suite this format does not
  // sign with, because a header missing `alg` is not saying the map is the wrong map, it is saying
  // nothing about which suite produced the signature. Both codes are terminal refusals, so the split
  // names what failed rather than changing what a caller does next.
  BAD_PROTECTED_HEADER: 'protected header does not hold exactly the parameters the format declares',
  KID_MISMATCH: 'resolved key does not match the receipt kid',
  UNKNOWN_KEY: 'no key found for the receipt kid',
  INVALID_SIGNATURE: 'Ed25519 signature verification failed',
  NONCE_MISMATCH: 'receipt nonce does not match the expected client nonce',
  STALE_EVIDENCE: 'attestation evidence timestamp is outside the freshness window',
  STALE_RECEIPT: 'receipt issuance time is outside the freshness window',
  // One code for both refusals: a version this package cannot parse and one it can parse but the
  // caller did not accept are the same answer to whoever sent the bytes, and which of the two it
  // was is not a fact about those bytes.
  UNSUPPORTED_VERSION: 'receipt payload declares a version this package cannot parse or is not configured to accept',
  BAD_PAYLOAD: 'payload does not match the CDDL schema for its receipt version',
  UNSUPPORTED_SCHEME: 'marking scheme is not in the registry this package can interpret',
  MARK_MISMATCH: 'the marked region does not hash to the digest the receipt carries in mk.d',
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

/**
 * Bounding the length does not close the second way a header can write itself into a message.
 * `parsePopAuthorization` quotes a parameter name it did not recognise, and a name is anything up
 * to an `=` sign, which includes a line feed. A refusal that carries one is two lines to anything
 * that reads a log by lines. The character set is the one the CLI escapes before printing, stated
 * again here because the packages share no module and the promise belongs to whoever builds the
 * message: a `ReceiptError` is one line of visible text, whoever raised it. The bound runs first,
 * on the raw text, so what it limits is what the caller sent rather than how long the escapes got.
 */
const INVISIBLE = /[\p{Cc}\p{Cf}\u{2028}\u{2029}\u{e0000}-\u{e007f}]/gu;

function asOneLine(message: string): string {
  return message.replace(INVISIBLE, (char) => {
    // One escape per UTF-16 unit, walked by index, so a surrogate pair leaves no half behind.
    const units: string[] = [];
    for (let index = 0; index < char.length; index += 1) {
      units.push(`\\u${char.charCodeAt(index).toString(16).padStart(4, '0')}`);
    }
    return units.join('');
  });
}

export class ReceiptError extends Error {
  readonly code: ReceiptErrorCode;

  constructor(code: ReceiptErrorCode, detail?: string) {
    super(asOneLine(detail ? `${ERROR_MESSAGE[code]}: ${bounded(detail)}` : ERROR_MESSAGE[code]));
    this.name = 'ReceiptError';
    this.code = code;
  }
}
