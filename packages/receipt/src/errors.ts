import { FORGES_A_LINE_RANGES } from './line-text.js';

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
  // The two windows above weigh a reading the caller handed. This one refuses a reading that cannot
  // be the count of seconds its own parameter names, which is the fault that made those two answers
  // lie. It is not `STALE_RECEIPT` under another name: a stale receipt is a document that aged, and
  // this is an argument that never reached the question.
  | 'VERIFICATION_TIME_OUT_OF_RANGE'
  | 'UNSUPPORTED_VERSION'
  | 'BAD_PAYLOAD'
  | 'UNSUPPORTED_SCHEME'
  | 'MARK_MISMATCH'
  | 'ITEM_STAMP_OUT_OF_ORDER'
  | 'FRAMER_REUSED'
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
  | 'PACK_CARRIED_DIGEST_MISMATCH'
  | 'PACK_CARRIED_DUPLICATE'
  | 'PACK_CARRIED_UNNAMED'
  | 'PACK_CARRIED_UNRESOLVED'
  | 'PACK_KID_MISMATCH'
  | 'PACK_UNKNOWN_KEY'
  | 'REDACTION_MALFORMED_CBOR'
  | 'REDACTION_BAD_HEADER'
  | 'REDACTION_UNSUPPORTED_VERSION'
  | 'REDACTION_BAD_MANIFEST'
  | 'REDACTION_DUPLICATE_ID'
  | 'REDACTION_KID_MISMATCH'
  | 'REDACTION_UNKNOWN_KEY'
  | 'REDACTION_PACK_UNAVAILABLE'
  | 'REDACTION_PACK_MISMATCH'
  | 'REDACTION_PACK_DISAGREES'
  | 'REDACTION_ITEM_ABSENT'
  | 'REDACTION_SURVIVORS_EMPTY'
  | 'REDACTION_SURVIVOR_CHAIN_MISMATCH'
  | 'EPOCH_INVENTORY_MALFORMED_CBOR'
  | 'EPOCH_INVENTORY_MALFORMED_JSON'
  | 'EPOCH_INVENTORY_BAD_HEADER'
  | 'EPOCH_INVENTORY_UNSUPPORTED_VERSION'
  | 'EPOCH_INVENTORY_BAD_DOCUMENT'
  | 'EPOCH_INVENTORY_DUPLICATE_PACK'
  | 'EPOCH_INVENTORY_PACK_MISNAMED'
  | 'EPOCH_INVENTORY_PACK_UNNAMED'
  | 'EPOCH_INVENTORY_RUN_NOT_CONTIGUOUS'
  | 'EPOCH_INVENTORY_SUMMARY_DISAGREES'
  | 'EPOCH_INVENTORY_PRESENCE_UNSEALED'
  | 'EPOCH_INVENTORY_PRESENCE_GAP'
  | 'EPOCH_INVENTORY_PRESENCE_WINDOW_TOO_WIDE'
  | 'EPOCH_INVENTORY_KID_MISMATCH'
  | 'EPOCH_INVENTORY_UNKNOWN_KEY'
  | 'RETENTION_UNSUPPORTED_VERSION'
  | 'RETENTION_BAD_DOCUMENT';

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
  // What the two windows above are measured from, refused at the entry where the reading is taken up.
  // The message carries the band rather than a suggestion about what the caller meant, because the
  // reading is theirs to state: a number between the two ends is accepted whichever way it was counted,
  // and one outside them is the other scale of the same instant or no instant at all.
  VERIFICATION_TIME_OUT_OF_RANGE: 'the verification time handed to this reader is not a whole number of Unix seconds it can weigh a stamp against',
  // One code for both refusals: a version this package cannot parse and one it can parse but the
  // caller did not accept are the same answer to whoever sent the bytes, and which of the two it
  // was is not a fact about those bytes.
  UNSUPPORTED_VERSION: 'receipt payload declares a version this package cannot parse or is not configured to accept',
  BAD_PAYLOAD: 'payload does not match the CDDL schema for its receipt version',
  UNSUPPORTED_SCHEME: 'marking scheme is not in the registry this package can interpret',
  MARK_MISMATCH: 'the marked region does not hash to the digest the receipt carries in mk.d',
  // The two orders one payload states about its own items, compared. Chain order is the array's
  // order and stamp order is `t`, so a receipt whose later item carries an earlier instant is one
  // document contradicting itself, and this is that refusal rather than `BAD_PAYLOAD`: every member is
  // well-typed and in place, and what is wrong is the pair of signed statements. Two items stamped
  // inside the same second are not this refusal, because the stamps are whole seconds and two frames of
  // one completion fall inside one of them routinely. What the check cannot reach is in the specification
  // beside it: a source uniformly away from the truth moves every stamp together, leaves the list tidy,
  // and passes, and no reader holding only this document can see that.
  ITEM_STAMP_OUT_OF_ORDER: 'the per-item stamps are not in the order the item list states them',
  // One framer reads one response: `finish()` takes the items the bytes produced, and a chunk that
  // arrives after that belongs to another response. This refuses a caller's use of a live object rather
  // than a statement about bytes, so it is not `BAD_PAYLOAD`, whose sentence is about a signed document
  // that does not match the schema for its version, and nothing about the response is in question the way
  // it is for the codes above: the items already taken stand, and the code exists so that a second
  // response's frames cannot be appended to an answer somebody is already holding.
  FRAMER_REUSED: 'the response item framer was fed a chunk after its answer was taken',
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
  // The four the carried list answers to. They are four codes and not one because the four facts send a
  // reader to four different places: to the entry, to the pack's own construction, to the issuer's choice of
  // what to include, and to the pack for attesting material it does not hold. Each detail names a position.
  // An entry that does not hash to what it states is the pack contradicting itself about bytes it carries, and
  // the reader recomputes rather than adjudicating between two claims.
  PACK_CARRIED_DIGEST_MISMATCH: 'a carried object does not hash to the digest the pack states beside it',
  // Deduplication is inside the pack, so one object appears once however many sealed receipts name it. A
  // digest carried at two positions is the same object twice under two entries, which makes the count of what
  // a pack carries mean something other than the material it holds.
  PACK_CARRIED_DUPLICATE: 'the pack carries the same digest at two positions of its carried list',
  // The list is a statement about the slots the sealed receipts name, so an entry no slot names is the pack
  // carrying bytes it attests nothing about. This is the other direction from an unresolved slot and the two
  // are separate codes because one is a pack that holds too little and this one is a pack that holds more than
  // it speaks of, which is a different construction to fix.
  PACK_CARRIED_UNNAMED: 'a carried object is named by no slot of any receipt the pack seals',
  // The failure the carried member exists to make impossible: a sealed receipt states material it took in, and
  // the pack that seals that receipt does not carry it. This is the pack's own failure and never a statement
  // about the world, which is why it is not an absence and why a reader reports it as a defect of the document
  // rather than as collateral nobody holds.
  PACK_CARRIED_UNRESOLVED: 'a receipt the pack seals states held collateral the pack does not carry',
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
  // The redaction family below, for the same reason the export's and the pack's exist. A log line carries
  // only the code string, and the sentences fixed beside the receipt codes name a receipt, so reading a
  // redaction's bytes under them would hand an operator a diagnosis of the wrong container. The three
  // envelope refusals stay shared with the receipt's, because their sentences name the COSE structure and
  // not a document: `NOT_COSE_SIGN1`, `UNSUPPORTED_ALG`, `INVALID_SIGNATURE`. This reader has no code for a
  // label a version does not define, because, as with the pack, no map in this format chooses between arms,
  // and a code with no raise site would be a second voice for a fault nothing answers. Refusals raised inside
  // `verifyPack` keep the pack's own codes rather than being folded into a redaction's, because a pack's
  // sentence says pack and that disagreement is about the pack.
  REDACTION_MALFORMED_CBOR: 'redaction bytes are not valid canonical CBOR',
  // The position that answers "is this a redaction at all", answered before any key is consulted. One code
  // for the shapes a signed header fails in, as `PACK_BAD_HEADER` is for a pack: no map, a map that does not
  // decode under the rule this format sets for it, a label outside the three it declares, a `kid` of another
  // width, an absent parameter, and a `typ` naming another container, which is how a receipt, a pack or an
  // export handed to this reader is refused before one member of its payload is read. `alg` keeps its own.
  REDACTION_BAD_HEADER: 'redaction protected header does not hold exactly the parameters the format declares',
  // One code for the two readings of a `v` this package cannot use, as the receipt's, the export's and the
  // pack's are. A `v` that is not an integer at all is a malformed manifest, so it answers
  // `REDACTION_BAD_MANIFEST`.
  REDACTION_UNSUPPORTED_VERSION: 'redaction manifest declares a version this package cannot parse',
  // Every structural refusal of this manifest: an absent member, a member this version does not define, a
  // digest or a sentence or an id of the wrong type or width, a stamp before the epoch, a removal list with
  // nothing in it, and the removal list not being an array of text. The empty list is this code rather than a
  // verdict about an erasure, because a redaction that removes nothing is a document stating that a signed
  // head still holds after a removal of zero records, which is true and useless, and a container in which a
  // no-op and a forgery look alike. A floating-point number, in a value and in a key alike, answers here too
  // and from the decode rather than from a field read, because by the time a check could tell `1` from `1.0`
  // the signed bytes have become one map entry. What is not this code: any disagreement between this
  // document and the pack it names, which is about the pair and not about either half.
  REDACTION_BAD_MANIFEST: 'redaction manifest does not match the layout its declared version defines',
  REDACTION_DUPLICATE_ID: 'two removed entries in one redaction answer to the same id',
  // The key the reader reached for hashes to something other than the kid the redaction's header names. The
  // designation answered, and what it answered with is another key's, which is a wrong key rather than an
  // edited document, and the two send an operator to different places.
  REDACTION_KID_MISMATCH: 'the key handed to the reader does not match the kid the redaction names',
  // The call carried neither a key nor a resolver, or the resolver had nothing for the kid this document
  // names. Nothing about the redaction is refused here, which is why this is not `REDACTION_BAD_MANIFEST`,
  // and the action is the caller's own: hand over the key the deployment's manifest retains and read again.
  // A pack's receipts signed under an epoch the caller kept no key for answer `PACK_UNKNOWN_KEY` instead,
  // because that is the pack's question and its sentence says pack.
  REDACTION_UNKNOWN_KEY: 'no key found for the kid a redaction names',
  // Not a fault of the document and not a fault of the pack: a redaction is a statement about another
  // document, and a reader handed only this one can say nothing about it at all. Refused by name rather than
  // accepted on the writer's word, which is the availability rule stated the only way it can be stated: a
  // reader that cannot reach a redaction still verifies the original pack, and a reader that holds a
  // redaction and not its pack is told which of the two it was handed too little of.
  REDACTION_PACK_UNAVAILABLE: 'the pack a redaction speaks about was not handed to the reader',
  // The reader hashed the pack it was given and got a different digest from the one the redaction
  // designates. Either document may be whole; what is refused is reading this statement against that pack,
  // which is a finding about which pack the reader is holding rather than about either pair of bytes.
  REDACTION_PACK_MISMATCH: 'the pack handed to the reader is not the pack the redaction designates',
  // A redaction stamped before the instant the pack it removes from began to be assembled. Both stamps are
  // inside signatures, one over each document, so the pair cannot both be true, and this is the disagreement
  // between two signed documents rather than one document contradicting itself, which is the distinction
  // `REDACTION_BAD_MANIFEST` is drawn on.
  REDACTION_PACK_DISAGREES: 'the redaction and the pack it designates state instants that cannot both be true',
  // A named id that no record of the designated pack carries. The pack names its items uniquely and the
  // reader has the pack, so this is not a lookup miss: the removal is stated about a receipt the sealed run
  // never contained, and the refusal says which id.
  REDACTION_ITEM_ABSENT: 'a redaction names an id the pack it designates does not carry',
  // The survivor sequence has no head, because there is no sequence. Pack v1 refuses a pack with no items for
  // the same reason: a chain over nothing closes vacuously and would read as a chain claim while attesting
  // nothing. The artifact that states a window held nothing is a different document, and a redaction that
  // empties a pack belongs to it rather than here.
  REDACTION_SURVIVORS_EMPTY: 'a redaction removes every record of the pack it designates, leaving no chain to state',
  // The load-bearing refusal, and the one that answers three findings at once. The reader takes the pack's
  // walked records, drops the named ones, re-links what remains from the pack's own anchor and hashes each
  // with the pack's own record rule, and compares. A writer that removed more than it named states the digest
  // of a longer survivor sequence than the reader can see. A writer that stated the pack's original head
  // instead states a value the fold returns only when nothing was removed. A writer that relinked from some
  // other seam, including the first survivor's own recorded predecessor, states a third value. The detail
  // gives the survivor count, the digest the recomputation reached and the one the document carries, because
  // the count is what tells an operator which of the three they are looking at.
  REDACTION_SURVIVOR_CHAIN_MISMATCH: 'the surviving records do not hash to the reduced chain head the redaction carries',
  // The epoch inventory family below, for the same reason the export's, the pack's and the redaction's exist: a
  // log line carries only the code string, and the sentences fixed beside the receipt codes name a receipt, so
  // reading an inventory's bytes under them would hand an operator a diagnosis of the wrong container. The
  // three envelope refusals stay shared with the receipt's, because their sentences name the COSE structure
  // and not a document: `NOT_COSE_SIGN1`, `UNSUPPORTED_ALG`, `INVALID_SIGNATURE`. This reader has no code for
  // a label a version does not define, because, as with the pack and the redaction, no map in this format
  // chooses between arms. Its codes are also not the commercial rotation's `EpochError` codes, and the
  // `EPOCH_INVENTORY_` prefix is what keeps the two layers apart in one log: those name what a deployment can
  // still supply and which key it may seal with, this one names the document.
  EPOCH_INVENTORY_MALFORMED_CBOR: 'epoch inventory bytes are not valid canonical CBOR',
  // The one refusal of its kind in this package, and the reason it exists is the payload. Every other signed
  // container here carries CBOR, so a float wearing an integer is refused by the decoder; this one carries the
  // JSON document a deployment writes, and the two facts `JSON.parse` settles silently are settled here
  // instead: a repeated member name, where the parser keeps the last value and the bytes state both, and a
  // number written as a fraction or an exponent, where the parser hands back the very value the integer it
  // imitates hands back. Both are refused while the characters are still distinguishable. The third finding
  // this code answers is the nesting: a document deeper than the eight levels this layout holds is stopped
  // where the count is cheap rather than by a stack that gives out later.
  EPOCH_INVENTORY_MALFORMED_JSON: 'the payload of an epoch inventory is not one JSON document of the shapes this layout writes',
  // The position that answers "is this an epoch inventory at all", answered before any key is consulted. One
  // code for the shapes a signed header fails in, as `PACK_BAD_HEADER` is for a pack: no map, a map that does
  // not decode under the rule this format sets for it, a label outside the three it declares, a `kid` of
  // another width, an absent parameter, and a `typ` naming another container, which is how a receipt, a pack,
  // an export or a redaction handed to this reader is refused before one member of its payload is read.
  EPOCH_INVENTORY_BAD_HEADER: 'epoch inventory protected header does not hold exactly the parameters the format declares',
  // One code for the two readings of a `v` this package cannot use, as the receipt's, the export's, the pack's
  // and the redaction's are. A `v` that is not an integer at all is a malformed document, so it answers
  // `EPOCH_INVENTORY_BAD_DOCUMENT`.
  EPOCH_INVENTORY_UNSUPPORTED_VERSION: 'epoch inventory declares a version this package cannot parse',
  // Every structural refusal of the document and of the maps inside it: an absent member, a member this
  // version does not define, a digest or a path or a label of the wrong type or width, a figure below zero or
  // past the widest integer a reader holds exactly, a label carrying a character that ends, hides or reorders
  // the printed row it belongs to, or a pad on either side of one, and the
  // pack list with nothing in it. The empty list is this code rather than a finding about the deployment
  // because an inventory of no packs states a window no pack covers and a chain no pack chained, which is a
  // document whose own figures are vacuous rather than a deployment that sealed nothing.
  EPOCH_INVENTORY_BAD_DOCUMENT: 'epoch inventory does not match the layout its declared version defines',
  // Two entries answering to one pack digest, which is the same pack counted twice. The digest is also the
  // entry's location, so one name covers both spellings of the collision, and every figure the document folds
  // is folded over this list: a run naming one pack twice states an epoch longer than the directory holds.
  EPOCH_INVENTORY_DUPLICATE_PACK: 'two entries of an epoch inventory answer to the same pack',
  // An entry filed under a pack home whose digest is not the one the same entry states. The path is derived
  // from the digest and a reader checks both, so a disagreement is one pack pointed at another's bytes, which
  // is a finding about a location and not about a shape: a reviewer following that path finds a pack, and it
  // is not the one described.
  EPOCH_INVENTORY_PACK_MISNAMED: 'an epoch inventory entry is filed under a digest that is not the pack it states',
  // A `chain.breaks` or `duty.short` row whose pack the fold has nothing to say about, which is two shapes and
  // the message tells them apart: a pack the run does not hold at all, and a pack the run holds between two
  // neighbours that neither break nor fall short. The two lists are statements about entries of the same
  // document, so this is not a lookup miss and nothing is missing from the reader's hands: the row is about a
  // pack this inventory does not describe the stated thing for, and a reader that passed it would be reporting
  // a break or a shortfall against evidence it was never given.
  EPOCH_INVENTORY_PACK_UNNAMED: 'an epoch inventory names a pack its run does not hold',
  // The windows of the run do not meet end to start, so the period the inventory attests is not the period its
  // packs sealed. A gap is the honest half of the refusal and an overlap the worse one, and both arrive here
  // because the document states one window across them: an epoch that skips a period attests nothing about it,
  // and one that seals a window twice puts the same receipts under two signatures and reports them as one run.
  EPOCH_INVENTORY_RUN_NOT_CONTIGUOUS: 'the packs of an epoch inventory do not seal one window after another',
  // The document's own summaries are not the arithmetic of its own entries: the two chain endpoints beside the
  // run that begins and ends it, `continuous` beside the break rows, `carried` beside the shortfall rows, the
  // window beside the outer edges, a break quoted from another pair or with one of its two digests moved, a
  // shortfall whose four figures or its subtraction are not that pack's, and a list whose rows name fewer
  // packs than there are rows, which is one row stated twice and another pack named nowhere. One code, because
  // the fault is one fault met at several positions and the action never changes: the fold has to be redone
  // from the entries, which is what this reader just did, and the detail says which figure it stopped on.
  EPOCH_INVENTORY_SUMMARY_DISAGREES: 'an epoch inventory states a window, a chain or a duty its own packs do not',
  // What the presence fold is handed, and what the run seals. A retention artifact is unsigned by design and
  // travels under the `retentionSha256` an inventory's own signature carries, so an observation the fold reads is
  // evidence only once the bytes it came from hash to a digest the run states. Three findings arrive here and the
  // detail says which: bytes hashing to a digest no entry of the run states, which is a bare retention file handed
  // to a reader and nothing of the run's; one sealed digest handed twice, which is one pack's observation stated
  // twice and folded as though the run held two; and one digest sealed by two entries, which is a store state
  // claimed for two windows and an observation that names no pack it belongs to. None of the three is a fault of
  // either document, which is why this is not `EPOCH_INVENTORY_BAD_DOCUMENT` and not `RETENTION_BAD_DOCUMENT`: the
  // fold was handed something other than what the signature designates, and the action is to hand over the files
  // the run names rather than to edit a document that is already whole.
  EPOCH_INVENTORY_PRESENCE_UNSEALED: 'a presence observation was handed to an epoch inventory under a name that inventory does not seal',
  // One digest named by the store's own observations at two sealing instants and not named at an instant between
  // them. The run's windows meet end to start, so the entries between the two are inside the period the document
  // states it attests and its own duty figures measure against; an observation missing from that stretch is
  // missing evidence about the material, and the interval the fold owes cannot be drawn across it. This is not a
  // window left out of the run, which is `EPOCH_INVENTORY_RUN_NOT_CONTIGUOUS` and says the packs do not meet: here
  // they meet, and what the store said it held at both ends of the stretch goes silent in the middle. The detail
  // names the family, the digest and the window between the two places that name it, in that order, because a
  // quoted detail is cut at a bound and a finding named past the cut is a finding nobody reads.
  EPOCH_INVENTORY_PRESENCE_GAP: 'the presence observations of an epoch inventory leave a period of the run unstated between two places they name one digest',
  // The document's stated `window` reaches further than its observations reach. Where a gap is a hole inside the
  // stretch the observations do draw, this is the stretch itself falling short of the period the document attests:
  // the run's first or last window carries no observation naming what the fold reads, so the interval the entries
  // support is narrower than the interval the document states, and the stated one would be a claim about material
  // no observation of that pack names. A run whose artifacts are all of the version that states no observation
  // arrives here too, which is the honest answer: nothing was folded, so nothing is attested. Refused rather than
  // reported as a shorter interval, because a reader handed a summary that is not the arithmetic of its entries is
  // owed the disagreement, and cannot tell a corrected figure from the writer's silence without it.
  EPOCH_INVENTORY_PRESENCE_WINDOW_TOO_WIDE: 'an epoch inventory states a window wider than the period its presence observations attest',
  // The key the reader reached for hashes to something other than the kid the inventory's header names. The
  // designation answered and what it answered with is another key's, which is a wrong key rather than an
  // edited document, and the two send an operator to different places.
  EPOCH_INVENTORY_KID_MISMATCH: 'the key handed to the reader does not match the kid the epoch inventory names',
  // The call carried neither a key nor a resolver, which is refused before a byte is read because the fault is
  // in the call, or the resolver had nothing for the kid this document names. Nothing about the inventory is
  // refused here, and that is why this is not `EPOCH_INVENTORY_BAD_DOCUMENT`: the document may be whole and the
  // caller's key set simply may not reach the key that sealed it. The `kid` each entry states is a different
  // question and answers with the pack's own code once a reader goes and checks the packs.
  EPOCH_INVENTORY_UNKNOWN_KEY: 'no key found for the kid an epoch inventory names',
  // The retention family below, for the same reason the export's, the pack's, the redaction's and the
  // inventory's exist. A log line carries only the code string, and the sentences fixed beside the receipt codes
  // name a receipt, so reading a retention manifest's bytes under them would hand an operator a diagnosis of the
  // wrong container. This artifact carries no signature, so it carries no envelope either: the three shared
  // envelope refusals have no site here, and a code for a content type or a key would be a second voice for a
  // fault nothing in this layout can raise. What the codes do answer is the layout and nothing else, because
  // every claim a manifest makes about a duty, a chain or a presence is recomputed by a reader beside it, and a
  // reader that called a disagreement a malformed document would be reporting a deployment's arithmetic mistake
  // as its own layout mistake. Which of the two it was is what the inventory's fold says by name.
  // One code for the two readings of a `v` this package cannot use, as the receipt's, the export's, the pack's
  // and the inventory's are. A `v` that is not an integer at all is a malformed document, so it answers
  // `RETENTION_BAD_DOCUMENT`.
  RETENTION_UNSUPPORTED_VERSION: 'retention manifest declares a version this package cannot parse',
  // Every structural refusal of the document and of the maps inside it, at both versions this package reads: an
  // absent member, a member the declared version does not define, which is what a `presence` block at `v: 1` is,
  // a digest or a label of the wrong type or width, a figure below zero, a duty label outside the three the
  // layout enumerates, a presence family whose stated count is not the length of its own list, a digest named
  // twice inside one family, and an empty family carrying a root or chain value it held nothing under. A document
  // of another version's shape answers here too rather than under the version code, because the fault is in the
  // bytes and not in the reader's reach.
  RETENTION_BAD_DOCUMENT: 'retention manifest does not match the layout its declared version defines',
};

/**
 * A detail quotes what the raise site was looking at, and the sites that parse a header quote
 * text a caller chose. The code is the contract and the sentence is fixed, so this bounds only
 * the quoted part, and bounds it in UTF-16 units of that text rather than in the bytes that
 * arrived: a diagnostic stays readable and cannot carry a whole request header into a log line.
 */
const MAX_DETAIL = 200;

function bounded(detail: string): string {
  return detail.length > MAX_DETAIL ? `${detail.slice(0, MAX_DETAIL)}...` : detail;
}

/**
 * Bounding the length does not close the second way a header can write itself into a message.
 * `parsePopAuthorization` quotes a parameter name it did not recognise, and a name is anything up
 * to an `=` sign, which includes a line feed. A refusal that carries one is two lines to anything
 * that reads a log by lines. The characters are the printed-line class `src/line-text.ts` owns, which
 * the two refusal sites of this package refuse their text on, taken here with the global flag because
 * this site rewrites every one of them out of a message rather than asking whether a value carries
 * one: a `ReceiptError` is one line of visible text, whoever raised it. The bound runs first,
 * on the text as this package holds it, so what it limits is that text's units, not the bytes the
 * caller sent and not how long the escapes got.
 */
const INVISIBLE = new RegExp(`[${FORGES_A_LINE_RANGES}]`, 'gu');

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
