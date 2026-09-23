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
  | 'AUTH_SCHEME_MISMATCH'
  | 'EXPORT_MALFORMED_CBOR'
  | 'EXPORT_BAD_HEADER'
  | 'EXPORT_UNSUPPORTED_VERSION'
  | 'EXPORT_BAD_MANIFEST'
  | 'EXPORT_UNSUPPORTED_LABEL'
  | 'EXPORT_DUPLICATE_ID'
  | 'EXPORT_DIGEST_MISMATCH'
  | 'EXPORT_ORIGINAL_UNAVAILABLE'
  | 'EXPORT_CHAIN_BROKEN'
  | 'EXPORT_ITEM_UNREACHED'
  | 'EXPORT_ENDPOINT_MISMATCH'
  | 'EXPORT_KID_MISMATCH';

const ERROR_MESSAGE: Record<ReceiptErrorCode, string> = {
  MALFORMED_CBOR: 'receipt bytes are not valid canonical CBOR',
  NOT_COSE_SIGN1: 'top-level value is not a COSE_Sign1 (tag 18) structure',
  UNSUPPORTED_ALG: 'protected header alg is not EdDSA (-8)',
  // What this code answers, in the order `cose.ts` reaches it: the protected bstr holds no map, the
  // map does not decode under the rule this format sets for it, the map carries a label the format does
  // not declare, or one of the declared parameters `kid` and `typ` is absent or ill-shaped. The second
  // of those is the floating-point case, and it is answered here rather than under the code of the
  // parameter it would have reached: a label written as the float `1.0` occupies the same map slot as
  // the integer `1`, so by the time a reader could ask which parameter is which, the header has one
  // entry where the signed bytes carry two and the question has no answer left in the value. It is not
  // one code for every fault a header can carry. `alg` keeps its own, `UNSUPPORTED_ALG`, for both of
  // its shapes, an absent parameter and an integer suite this format does not sign with, because a
  // header missing `alg` is not saying the map is the wrong map, it is saying nothing about which suite
  // produced the signature. Both codes are terminal refusals, so the split names what failed rather
  // than changing what a caller does next.
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
  // The export family below, and why it is a family rather than a reuse of the codes above. A log line
  // carries only the code string, so a code has to say which document refused, and the sentences this
  // package fixes beside the receipt codes name a receipt: "receipt bytes", "the receipt kid", "its
  // receipt version". Reading an export's bytes under those sentences would hand an operator a diagnosis
  // of the wrong container, which is the same class of mistake the export's own content type exists to
  // prevent. Three envelope refusals are shared and stay shared, because their sentences name the COSE
  // structure and not a document: `NOT_COSE_SIGN1`, `UNSUPPORTED_ALG`, `INVALID_SIGNATURE`.
  EXPORT_MALFORMED_CBOR: 'export bytes are not valid canonical CBOR',
  // The export's signed header, which is the position that answers the question "is this an export at
  // all". One code for the shapes a header can fail in, as `BAD_PROTECTED_HEADER` is for a receipt: no
  // map, a map that does not decode under the rule this format sets for it, a label outside the three it
  // declares, a `kid` of another width, an absent parameter, and a `typ` naming another container, which
  // is how a pack or a receipt handed to this reader is refused before a single member of its manifest
  // is read. The last of those is the reason the code is not folded into the manifest's.
  EXPORT_BAD_HEADER: 'export protected header does not hold exactly the parameters the format declares',
  EXPORT_UNSUPPORTED_VERSION: 'export manifest declares a version this package cannot parse',
  // Every structural refusal of the manifest and of the maps inside it, at every arm of every choice:
  // an absent member, a member no arm of this version defines, a value of the wrong type or width, an
  // integer below zero, a collection arm whose array is empty, a companion name that is a path rather
  // than a name, and a claim stamped after the assembly it travels with. The receipt's payload codes
  // answer for one document's field set, and a floating-point number reaches this code from the decode
  // rather than from a field read, because by the time a check could tell `1` from `1.0` the signed bytes
  // have become one map entry and the question has no answer left in the value.
  EXPORT_BAD_MANIFEST: 'export manifest does not match the layout its declared version defines',
  // One code for both label positions, because the fault is one fault reached at two places: a `k` that
  // this version has no reading for, in an assessment or in an original or a collection, or a
  // `claim.kind` outside the two labels. Which of them it was is in the detail, and the refusal is not
  // guesswork about which label the writer meant, which is what reading a claim as a provenance would
  // be. This is the code a document answers with when it is well-formed and from a later version's
  // vocabulary, and the detail says which position could not be read.
  EXPORT_UNSUPPORTED_LABEL: 'export carries a label this version of the format does not define',
  EXPORT_DUPLICATE_ID: 'two export items answer to the same id',
  EXPORT_DIGEST_MISMATCH: 'the original bytes of an export item do not hash to the digest the item carries',
  // Not a fault of the document: the item is whole and its companion is simply not in the reader's
  // hands. It is a refusal rather than a skip because a reader that passed an unchecked digest would
  // report a set of material it never looked at, which is the one thing a handover container must not
  // do. The caller's action is different from every other code here: go and get the file, then re-read.
  EXPORT_ORIGINAL_UNAVAILABLE: 'the companion file an export item names was not handed to the reader',
  EXPORT_CHAIN_BROKEN: 'the anchored walk across the export items does not close at the head it names',
  EXPORT_ITEM_UNREACHED: 'an export item lies outside the run from the anchor to the head',
  // Reached only when a caller came with an endpoint of its own, which is the one way a reader can do
  // better than checking that a run is internally consistent. The document is not being called a lie
  // here: the signature is good and the walk closed, and what disagrees is this export's endpoint with
  // the one the reader already had cause to believe, which is a finding about which of the two the
  // reader is holding.
  EXPORT_ENDPOINT_MISMATCH: 'the endpoints an export names differ from the ones the reader was told to expect',
  // The reader is handed one key, so this is not a lookup failure: the document names the kid its issuer
  // signed with and the key in the reader's hand hashes to something else, which is a wrong key rather
  // than an edited document. The two answers send an operator to different places, one to their key
  // configuration and one to the bytes, and a signature failure that could have been either is the
  // weaker report.
  EXPORT_KID_MISMATCH: 'the key handed to the reader does not match the kid the export names',
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
