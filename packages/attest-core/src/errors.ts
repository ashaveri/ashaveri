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
  | 'POLICY_NOT_ALLOWED'
  // The anchor provenance ledger family below. A row of that document is a claim about bytes this package
  // ships, and the ledger is read by the same clients that read the evidence, so its refusals belong to
  // this union rather than to a new one. They are prefixed and not folded into the codes above for the
  // reason every other family in this workspace is: a log line carries only the code string, and the
  // sentences fixed above name platform evidence. Reading a ledger's refusal under "certificate bytes are
  // not valid X.509" would hand an operator a diagnosis of the wrong document, which is the same class of
  // mistake the ledger's own content type exists to prevent. One envelope refusal is shared and stays
  // shared: a signature that does not verify is `BAD_SIGNATURE` whichever document carried it, because that
  // sentence names the cryptography and not a document, exactly as the receipt family shares its own.
  | 'ANCHOR_LEDGER_NOT_SEALED'
  | 'ANCHOR_LEDGER_BAD_HEADER'
  | 'ANCHOR_LEDGER_PIN_MISSING'
  | 'ANCHOR_LEDGER_PIN_MISMATCH'
  | 'ANCHOR_LEDGER_KEY_UNDECLARED'
  | 'ANCHOR_LEDGER_UNSUPPORTED_VERSION'
  | 'ANCHOR_LEDGER_BAD_DOCUMENT'
  | 'ANCHOR_LEDGER_FILE_UNNAMED'
  | 'ANCHOR_LEDGER_BYTES_UNAVAILABLE'
  | 'ANCHOR_LEDGER_DIGEST_MISMATCH'
  | 'ANCHOR_LEDGER_SPKI_MISMATCH'
  | 'ANCHOR_LEDGER_LICENCE_UNKNOWN'
  | 'ANCHOR_LEDGER_INSTANT_OUT_OF_RANGE';

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
  // The anchor provenance ledger family, which refuses a signed statement about the bytes this package
  // ships. The three envelope positions come first, because they are answered before one member of the
  // body is read: the document is either a `COSE_Sign1` over this layout's payload or it is nothing, and a
  // reader that went on parsing after the first refused would be reporting the shape of bytes nobody
  // signed.
  ANCHOR_LEDGER_NOT_SEALED: 'the anchor provenance ledger is not a COSE_Sign1 over the body it presents',
  // One code for the shapes a signed header fails in, as the receipt family's `BAD_PROTECTED_HEADER` is: no
  // map, a map that does not decode closed, a label outside the three the format declares, a `kid` of
  // another width, an absent parameter, and a `typ` naming another container, which is how a receipt, a
  // pack or an epoch inventory handed to this reader is refused before one row is read. An algorithm other
  // than EdDSA answers here too: the receipt family keeps a separate code for it because that union already
  // names one, this union has no algorithm position to keep apart from a header, and two codes for one
  // finding would be two voices about the same signed bytes.
  ANCHOR_LEDGER_BAD_HEADER: 'the anchor provenance ledger protected header does not hold exactly the parameters the format declares',
  // Refused before a byte is read, because the fault is in the call and not in the document: the reader was
  // handed no key to verify against. This is never a pass, and it is not `ANCHOR_LEDGER_PIN_MISMATCH`, which
  // says a pin was named and disagrees. A ledger that verified under nobody's decision would be evidence
  // about the estate's own bytes vouched for by those same bytes, which is the circular thing this document
  // exists not to be.
  ANCHOR_LEDGER_PIN_MISSING: 'no verifying key was pinned for this anchor provenance ledger',
  // The caller named a key and the document names another. Either may be whole; what is refused is reading
  // this ledger under that key, and the action sends an operator to their own configuration rather than to
  // the file.
  ANCHOR_LEDGER_PIN_MISMATCH: 'the key pinned by the caller does not match the kid the anchor provenance ledger names',
  // The reader's pin and the signature are answered, and then the ledger contradicts itself about who signs
  // it: the kid that sealed the body is not one of the ids the body lists. This is not the pin's question and
  // not a signature failure, because the bytes the two keys made are both intact, and it is a named refusal
  // rather than a pass because a ledger whose own `keys` list is decoration states nothing about rotation.
  ANCHOR_LEDGER_KEY_UNDECLARED: 'the kid that sealed the anchor provenance ledger is not one the ledger names in its own keys list',
  // One code for the two readings of a `v` this package cannot use, as every other family here has it: a
  // version this package parses and one the caller accepts are not two facts about the bytes. A `v` that is
  // not an integer at all is a malformed document, so it answers `ANCHOR_LEDGER_BAD_DOCUMENT`.
  ANCHOR_LEDGER_UNSUPPORTED_VERSION: 'the anchor provenance ledger declares a version this package cannot parse',
  // Every structural refusal of the body and of the rows inside it: an absent member, a member this version
  // does not define, a digest or a key id of another width, a text member that is empty or carries a
  // character that ends, hides or reorders the printed row it belongs to, a family outside the three the
  // layout enumerates, an empty row list or key list, and the four certificate members arriving apart
  // instead of together. It is also the answer of a number that is not a whole integer, which reaches this code from the
  // decode rather than from a field read: a floating-point spelling of an integer, in a value and in a key
  // alike, becomes the one map entry a check could not tell apart afterwards, so the refusal happens where the
  // bytes are still distinguishable. The one refusal of this family that is not layout is
  // `ANCHOR_LEDGER_FILE_UNNAMED`, because a name the package does not ship is not a malformed document.
  ANCHOR_LEDGER_BAD_DOCUMENT: 'the anchor provenance ledger does not match the layout its declared version defines',
  // A row that speaks of bytes no file or constant of this package is. This is the refusal the ledger exists
  // to make loud: an anchor added beside the ledger, renamed, or swapped out leaves a row that answers to
  // nothing, and a reader that walked past it would be recording provenance for bytes it never looked at.
  ANCHOR_LEDGER_FILE_UNNAMED: 'an anchor provenance row names a file this package does not ship',
  // Not a fault of the document: the row names a file this package does ship, and the bytes of it were not
  // handed to the reader. The embedded anchors resolve from source, so this is the tracked fixture case, and
  // the action is the caller's: open the file and read again. It is a refusal rather than a skip because a
  // reader that passed an unchecked digest would report material it never looked at.
  ANCHOR_LEDGER_BYTES_UNAVAILABLE: 'the bytes an anchor provenance row names were not handed to the reader',
  // The row states the digest of the bytes as shipped and the shipped bytes hash to something else. The
  // document is internally whole and the signature covers it, so this is the one refusal here that says the
  // ledger is true and the repository has moved since, which is what a provenance ledger is for.
  ANCHOR_LEDGER_DIGEST_MISMATCH: 'an anchor provenance row states a digest the bytes it names do not hash to',
  // The row states the digest of the certificate's SubjectPublicKeyInfo and the named bytes carry another
  // key, or carry no single certificate at all. Reached by recomputing over the bytes the row names, so a
  // reader is never adjudicating between two claims about the same file.
  ANCHOR_LEDGER_SPKI_MISMATCH: 'an anchor provenance row states a public-key digest the bytes it names do not carry',
  // A licence class outside the four the format declares, which is a claim no row of this ledger can support
  // and not a class the reader has never heard of. `none-stated` is one of the four and is not this refusal:
  // it is the finding that a source named no code licence behind the bytes it published.
  ANCHOR_LEDGER_LICENCE_UNKNOWN: 'an anchor provenance row states a licence class outside the four the format declares',
  // One code for both instant positions, `generatedAt` and a row's `takenAt`, because the fault is one fault
  // met at two places and the action never changes: the reading is not a second since the epoch this reader
  // could weigh anything against. The band is the receipt format's, stated in the detail, because which unit
  // the number arrived in is the caller's answer and not this reader's guess.
  ANCHOR_LEDGER_INSTANT_OUT_OF_RANGE: 'an anchor provenance ledger states an instant that is not a whole number of Unix seconds inside the band the receipt format states',
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
