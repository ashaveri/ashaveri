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
  | 'CHALLENGE_MISMATCH'
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
  CHALLENGE_MISMATCH: 'the attested device did not sign the challenge it is checked against',
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

/**
 * Some of the messages this class carries quote a name the document chose: `decode.ts` folds a
 * decoded msgpack key into the context of whatever follows it, and a key is only checked to be
 * valid UTF-8, which a newline is. A refusal that carries one is two lines to anything that reads
 * a log by lines, and the second line is written by whoever sent the document.
 *
 * The set is the one the CLI escapes before printing (`packages/cli/src/usage.ts`): the control
 * characters, which include both line feeds and the C1 next-line, the format characters, which
 * include the bidi overrides that make a credential id read as something other than what it is,
 * and the two Unicode separators. Restated here rather than imported because the packages share
 * no module, and because the promise belongs to whoever builds the message: an `AttestationError`
 * is one line of visible text, whoever raised it.
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

/**
 * A detail quotes what the raise site was looking at, and the sites that decode a document quote
 * names chosen by whoever sent it, so this bounds the quoted part before it is escaped: a refusal
 * stays a readable sentence instead of becoming a copy of the document on its way into a log line
 * and a reply body. The order matters, and it is the order `ReceiptError` uses: the bound runs
 * first, on the raw text, so what it limits is what the caller sent rather than how long the
 * escapes got, and a detail of this many raw characters still comes out six times wider when every
 * one of them is a control character spelled as an escape.
 *
 * The number is not `ReceiptError`'s 200, because a sentence here can be legitimately longer than a
 * header parameter: a pin refusal names both the measurement the evidence carries and the one the
 * operator pinned, 96 hexadecimal characters each, and at 200 the cut lands in the middle of the
 * pair, taking the second value, which is the one an operator has to read off the reply to fix the
 * pin. 512 is headroom over that sentence, not a measured ceiling on this package's vocabulary.
 */
const MAX_DETAIL = 512;

function bounded(detail: string): string {
  return detail.length > MAX_DETAIL ? `${detail.slice(0, MAX_DETAIL)}...` : detail;
}

export class AttestationError extends Error {
  readonly code: AttestationErrorCode;

  constructor(code: AttestationErrorCode, detail?: string) {
    super(asOneLine(detail ? `${ERROR_MESSAGE[code]}: ${bounded(detail)}` : ERROR_MESSAGE[code]));
    this.name = 'AttestationError';
    this.code = code;
  }
}

export function fail(code: AttestationErrorCode, detail?: string): never {
  throw new AttestationError(code, detail);
}
