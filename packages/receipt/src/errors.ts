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
  | 'EXPORT_KID_MISMATCH'
  | 'PACK_MALFORMED_CBOR'
  | 'PACK_BAD_HEADER'
  | 'PACK_UNSUPPORTED_VERSION'
  | 'PACK_BAD_MANIFEST'
  | 'PACK_DUPLICATE_ID'
  | 'PACK_RECEIPT_INVALID'
  | 'PACK_RECEIPT_STAMP_MISMATCH'
  | 'PACK_CHAIN_BROKEN'
  | 'PACK_ITEM_UNREACHED'
  | 'PACK_KID_MISMATCH'
  | 'PACK_UNKNOWN_KEY';

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
  // The pack family below, for the same reason the export family above exists. A log line carries only the
  // code string, and the sentences fixed beside the receipt codes name a receipt: "receipt bytes", "the
  // receipt kid", "its receipt version". Reading a pack's bytes under those sentences would hand an operator
  // a diagnosis of the wrong container, which is the same class of mistake the pack's own content type exists
  // to prevent. The three envelope refusals stay shared with the receipt's, because their sentences name the
  // COSE structure and not a document: `NOT_COSE_SIGN1`, `UNSUPPORTED_ALG`, `INVALID_SIGNATURE`. The pack
  // reader has no code for a label a version does not define, because this format carries no label
  // discriminant to read: every map it declares is one shape, so the refusal an unknown `k` earns elsewhere
  // has no site here, and a code with no raise site would be a second voice for a fault nothing answers.
  PACK_MALFORMED_CBOR: 'pack bytes are not valid canonical CBOR',
  // The position that answers "is this a pack at all", and it is answered before any key is consulted: a pack
  // manifest and a receipt payload are two documents that both pass their own checks, and the one mistake
  // that cannot be recovered afterwards is reading the first as the second. One code for the shapes a signed
  // header fails in, as `EXPORT_BAD_HEADER` is for an export: no map, a map that does not decode under the
  // rule this format sets for it, a label outside the three it declares, a `kid` of another width, an absent
  // parameter, and a `typ` naming another container. `alg` keeps its own answer.
  PACK_BAD_HEADER: 'pack protected header does not hold exactly the parameters the format declares',
  // One code for the two readings of a `v` this package cannot use, as the receipt's and the export's are: a
  // version this package parses and one the caller accepts are not two facts about the bytes, and a second
  // code would let a caller probe where the boundary sits. A `v` that is not an integer at all is a malformed
  // manifest, so it answers `PACK_BAD_MANIFEST`.
  PACK_UNSUPPORTED_VERSION: 'pack manifest declares a version this package cannot parse',
  // Every structural refusal of the manifest and of the maps inside it: an absent member, a member this
  // version does not define, a value of the wrong type or width, an instant before the epoch and a duration
  // below zero, the items array with nothing in it, and the contradictions between two signed members, which
  // are the assembly stamp before the span closed, a mapping revision after it, an item stamped outside the
  // span it belongs to, and a retention figure younger than the oldest receipt the pack carries. The last four
  // are this code rather than a verdict about the deployment because the document disagrees with itself, and
  // keeping those two answers apart is what the container exists for. A floating-point number, in a value and
  // in a key alike, answers here too and from the decode rather than from a field read, because by the time a
  // check could tell `1` from `1.0` the signed bytes have become one map entry.
  PACK_BAD_MANIFEST: 'pack manifest does not match the layout its declared version defines',
  PACK_DUPLICATE_ID: 'two pack items answer to the same id',
  // Not a fault of the chain and not a fault of the receipt alone: an item's original is the document the pack
  // attests, and it either parses and verifies under the key the reader holds for it, which is the one the
  // item's own header names, or the pack is carrying something other than the receipts it claims. The detail
  // carries the item's id and the refusal that receipt answered with, so the code says which pack failed and
  // the quoted code says why. A kid the reader was given no key for is the exception and answers
  // `PACK_UNKNOWN_KEY`, because that is a caller with too few keys rather than a pack with a false original.
  PACK_RECEIPT_INVALID: 'a receipt inside the pack does not parse or does not verify under the key the reader holds for it',
  // The equality `pack.cddl` states as part of the walk rather than as a courtesy: an item's `iat` is the
  // stamp the record was chained with, and it has to equal the `iat` the receipt inside it attests, because
  // the store chains a receipt under the stamp it was handed and those are two statements. A reader that
  // checked the walk and not this would accept a receipt moved into a window it was never issued in, which is
  // a different finding from a broken link and the reason it is not folded into that code.
  PACK_RECEIPT_STAMP_MISMATCH: 'the stamp a pack item was chained at is not the iat its own receipt attests',
  // The run from the signed anchor to the signed head does not close: no item names the anchor the walk starts
  // from, two items name one predecessor so the run forks, or the recomputed digests stop short of the head.
  // The detail says which of them it found. A record lifted out of the middle and a hand-edited original look
  // the same from here, which is what the signed head is for.
  PACK_CHAIN_BROKEN: 'the walk across the pack items does not close at the head it names',
  // An item named by nobody's `prev`, or naming a predecessor from another chain, reaches the head exactly as
  // the honest ones do: the walk stops where the head is and never counts what it did not need to visit. This
  // is the half of the rule the endpoints cannot see, and it is why a conforming reader counts what it walked
  // against the array it was handed.
  PACK_ITEM_UNREACHED: 'a pack item lies outside the run from the anchor to the head',
  // The key the reader reached for, by whichever of the two designations the caller used, hashes to something
  // other than the kid the pack's header names. This is not a lookup failure: the lookup answered, and what it
  // answered with disagrees with the document, which is a wrong key rather than an edited document. The two
  // answers send an operator to different places, and a signature failure that could have been either is the
  // weaker report.
  PACK_KID_MISMATCH: 'the key handed to the reader does not match the kid the pack names',
  // The reader was given no key for a kid this pack names: the call carried neither a key nor a resolver, the
  // resolver had nothing for the envelope's kid, or it had nothing for the kid one of the receipts names,
  // which is what a span crossing a key rotation looks like to a caller that retained one epoch. Nothing about
  // the document is refused here, which is why this is not `PACK_RECEIPT_INVALID`: the pack may be whole and the
  // caller's key set simply too small, and the action that closes it, hand over the key the manifest retains and
  // read again, is one a caller has to be able to branch on rather than read out of a message. The detail says
  // which of the three positions the missing key belongs to.
  PACK_UNKNOWN_KEY: 'no key found for the kid a pack names',
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
