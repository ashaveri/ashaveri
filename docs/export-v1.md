# Technical export, version 1

Status: current for export version 1. The normative statement of the container is
[`packages/receipt/export.cddl`](../packages/receipt/export.cddl); its JSON twin is
[`packages/receipt/schemas/export-v1.schema.json`](../packages/receipt/schemas/export-v1.schema.json),
whose identity is `https://ashaveri.com/schemas/export-v1.json`; the conformance vectors are
[`packages/fixtures/data/export-v1.json`](../packages/fixtures/data/export-v1.json) and are read as
described in [vectors.md](vectors.md). The table below is the same layout as the twin, and
`packages/fixtures/test/export-doc.test.ts` holds the two against each other in both directions: every row
resolves to a member the twin defines, with the type and the required-ness the twin gives it, and every
member the twin defines appears as a row. Where a sentence here and the CDDL disagree, the CDDL is the
authority and this prose is wrong.

## What this container is

An export is a signed collection of original material, assembled at one instant, with a statement about
whether any legal assessment was made of it and a claim about where it came from. It is what a deployment
hands to a customer who is going to pass evidence to somebody else, or to an auditor who is carrying
originals out of a deployment, and it is deliberately not an answer for a period of time.

The estate has three signed documents and one key signs all three:

| Document | Content type at COSE label 3 | What it establishes |
|---|---|---|
| Receipt | `ashaveri/receipt` | That the holder of the key vouches for one request and one response, bound by digests |
| Pack | `ashaveri/pack` | That the receipts inside one window are all of them, with the two chain endpoints a reader walks between |
| Export | `ashaveri/export` | That the holder of the key assembled these originals at one instant, and states this about assessment and this about provenance |

A pack cannot do an export's job, and that is why this is a second contract rather than a pack version two.
Its duty block is mandatory, so it has no way to say "no legal assessment was made" as a fact about itself:
absence there would be indistinguishable from a writer that forgot the block, and the whole value of the
statement lies in a reader being able to tell the two apart. Its items are receipts, so it cannot carry the
contract, the ticket screenshot or the exported spreadsheet a handover is often about. Those are two
differences in kind, and a reader must never be able to mistake one document for the other, which is what
the three content types are for.

An export states no window, and no item's stamp is bounded by one. It carries no period, no revision of a
mapping and no retention figure, and it never states whether any duty was met, because it makes no claim that
could be met or missed. The one stamp the container does bound is the claim's own, and it is bounded against
another member of the same document rather than against a span.

## The envelope

The framing is section 2 of [receipt-spec.md](receipt-spec.md), reused unchanged but for the content type: a
COSE_Sign1 (RFC 9052 section 4.2), tagged CBOR tag 18, encoded with Core Deterministic Encoding (RFC 8949
section 4.2.1), with a signature over the `Sig_structure` `["Signature1", protected, external_aad, payload]`
and an empty external AAD.

The protected header contains exactly three parameters, and the list is exhaustive rather than
illustrative:

| Label | Name | Value |
|---|---|---|
| 1 | alg | -8 (EdDSA, Ed25519 per RFC 8032) |
| 3 | typ | `ashaveri/export` |
| 4 | kid | 32-byte key id, sha256 of the Ed25519 public key |

Those bytes are hashed into the `Sig_structure`, so a label this table does not name is a parameter the
issuer authenticated, and a reader that took the three it knows and returned those would hand its caller a
document other than the one that was signed. An export whose header carries another label is refused and
the refusal names the label. A header whose `typ` is the receipt's or the pack's is refused before a single
member of its payload is read, because both of those documents pass their own checks and the confusion is
not recoverable afterwards.

The map outside the signature is the one the format leaves open: `{ * any => any }`, the map that carries no
claim. Its emptiness is not enforced, because enforcing it would add a refusal with nothing behind it.

Every integer in the manifest and in the protected header is a CBOR integer, major type 0 or 1, and no other
major type carries one. Both of those maps are decoded where no floating-point number may appear, in a value
and in a key alike. The float `1.0` is not an integer written in a second way: it is another type, it arrives
at a reader as the number 1, and by then nothing can tell which bytes the issuer signed. Every instant is a
unix time no earlier than the epoch and every count a whole number no smaller than zero, so a negative stamp
is a malformed document and not an unusual way of writing a quantity.

## The manifest

The payload is a closed map at `v: 1`: a member the version a document names does not define makes the
document malformed rather than a document read with that member dropped. That holds of every map below and
of every arm of every choice, so an `anchored` collection cannot be read with the `plain` arm's keywords and
the two signed endpoints fall out on the way to a verifier. Every member of every map is required, so no
position is optional, none carries a default, and a reader never has to work out what an omitted field
meant.

Byte strings are projected as lowercase hex in the twin and in the vectors, and documents and byte strings
are unpadded base64url in the vectors. A byte ceiling belongs to the CDDL: a JSON string length is a
different measure, so the projections state the floor and not the limit.

| Member | Type | Required | What it states |
|---|---|---|---|
| `protectedHeader` | `object` | yes | The three signed parameters above, as the twin projects them. |
| `payload` | `object` | yes | The signed manifest, which is the only part of an export a verifier has to believe before it starts checking. |
| `signature` | `string` | no | Ed25519 over the `Sig_structure`, hex. Named without being demanded, because a display of an unsigned document still shows; `export.cddl` requires four elements and sixty-four bytes. |
| `v` | `1` | yes | Format version, one constant rather than a discriminant. A reader refuses a version it does not define rather than reading the bytes under rules that were not written for them. |
| `at` | `integer` | yes | Unix seconds, the instant the export was assembled. The only clock in this document: it bounds the claim's own stamp and states no window. |
| `assessment` | `object` | yes | Whether any legal assessment was made of the material, stated rather than left to be inferred. |
| `collection` | `object` | yes | The material, in one of three closed shapes named by its `k`: the arms are the blocks `anchored`, `plain` and `void` below. |
| `claim` | `object` | yes | The writer's own assertion about where the material came from or who has held it, which a reader verifies by nothing beyond the signature over it. |
| `assessment.k` | `none` | yes | The only assessment statement version 1 defines. A document carrying another label here has assessed something this version has no reading of, and a reader refuses it rather than guessing which statement the writer meant. |
| `assessment.states` | `string` | yes | The writer's own sentence stating that no legal assessment was made. It cannot be empty. A reader checks that the position is filled and that the label is the one this version defines, and reads nothing out of the sentence's content. |
| `claim.made` | `integer` | yes | Unix seconds, when the assertion was made, and never after `at`. A claim stamped after the assembly of the document carrying it is another document's claim. |
| `claim.by` | `string` | yes | Who asserts it, named by the assertor rather than resolved to an identity a reader could look up. |
| `claim.kind` | `string` | yes | Which of the two assertions this is: `provenance` about where the material came from, or `custody` about who has held it since. Neither is a legal category. A label outside the two is refused rather than read as whichever it resembled. |
| `claim.states` | `string` | yes | The assertion, in the writer's own words. Nothing in a reader checks its content, which is the block's whole honesty: it is inside the signature and outside every recomputation. |
| `anchored.k` | `anchored` | yes | A chained run is claimed over these items, so the walk below applies. |
| `anchored.anchor` | `string` | yes | The digest the first item was chained from: thirty-two zero bytes before any retirement, otherwise the seam a trim record carried. |
| `anchored.head` | `string` | yes | The digest of the last item in the run. Neither endpoint is derivable from the items, and both travel inside the signature, which is what gives the walk its meaning. |
| `anchored.items` | `array` | yes | At least one item, each of which also names its predecessor, so an element is a `chainedItem`. Order in the array bears nothing: the reader follows the links. |
| `plain.k` | `plain` | yes | Originals, with no ordering, run or completeness claimed about them. No endpoints are carried here because none is claimed, and that is a shape rather than an omission: the arm that would have held two digests is the one a reader looks for. |
| `plain.items` | `array` | yes | At least one item, and an element is an `item`, which names no predecessor because no run is claimed. |
| `void.k` | `void` | yes | Nothing is carried. This is how an empty export says so, and it is the only arm that may hold no material. |
| `void.states` | `string` | yes | The writer's own sentence stating the outcome. It cannot be empty, and the arm carries no items, so a reader has nothing to count and no walk to have completed. |
| `item.id` | `string` | yes | The writer's name for the item, and no two items in one collection carry the same one. A refusal reports an item by name, and two items answering to one name make that report mean whichever of the two a reader met first. |
| `item.iat` | `integer` | yes | Unix seconds, the stamp the writer records for the original. This container states no span, so no window bounds it here. |
| `item.d` | `string` | yes | sha256 of the exact original bytes, whole, whether they travel inside the document or beside it. This is the member that makes one altered byte a refusal rather than an unnoticed change. |
| `item.orig` | `object` | yes | The original, either inside this document or named as a companion file travelling beside it, chosen by its own `k`: the arms are `inline` and `companion` below. |
| `chainedItem.id` | `string` | yes | As `item.id`, and a term of the hashed input besides. |
| `chainedItem.iat` | `integer` | yes | Unix seconds, the stamp the record was chained at, and a term of the hashed input: a record restamped into a run it was never chained in breaks a link rather than slipping through. |
| `chainedItem.d` | `string` | yes | sha256 of the exact original bytes, as in an unchained item, and independent of the record digest below. One of the two says these are the bytes, the other says they sit in this run. |
| `chainedItem.p` | `string` | yes | The digest of the record before this one, or the collection's anchor for the first item. Published rather than derived, because the walk follows links and not positions. |
| `chainedItem.orig` | `object` | yes | The signed receipt bytes, whole and unaltered. The walk hashes them as a record's payload and does not open them. |
| `inline.k` | `inline` | yes | The bytes are inside this document, which is the strongest form a reader can verify without a second file. |
| `inline.bytes` | `string` | yes | The exact original bytes, and what the item's digest is taken over. |
| `companion.k` | `companion` | yes | The bytes travel beside this document, under a name. |
| `companion.name` | `string` | yes | A file name and not a location: no scheme, no path that climbs out of the directory the export arrived in, and no resolution rule, because this format fetches nothing. A reader hashes the bytes it was handed under this name against `item.d`, and refuses an item whose companion it was not given by name. |

## The assessment, said out loud

An export is made for a purpose a deployment may not share, and often it is made so that somebody else can
form a view. A deployment that has decided nothing about which legal category its material falls into must
be able to say so, and it must not be able to say so by saying nothing. So the block is required, its one
label is the statement, and its sentence is the writer's own words.

No legal-category vocabulary is defined in this format. There is no mapping, no duty label, no article, no
category, no qualification and no period anywhere in the container. Two reasons, both load-bearing. Whether
a per-request receipt is a log a named article requires turns on the system and the actor, and this estate
does not interpret those questions; a format that enumerated answers would itself be an answer. And the
statement has to survive being made by a writer who is wrong: "no legal assessment was made" is checkable
by a reader against a document that carries none, while "this material is not subject to a duty" is not, and
the second is a conclusion a container should not carry under its own signature as though the signature
established it.

The format requires none of that vocabulary and forbids no later version from defining it. A version that
defined a second assessment label would name what a reader owes the claim, and a reader of version 1 meeting
that label refuses it by code rather than choosing between two statements it was not told how to read.

## The collection, and what an empty one states

A pack refuses an empty collection, because a span that held no receipts is a statement about retention and
belongs to the artifact that states retention. An export decides the other way, deliberately: an auditor asks
for everything held for a period, and "nothing was carried out of this store, and here is the reason the
writer gives" is the honest reply. So `void` is a shape a conforming export may take and it states its
emptiness in a sentence that cannot be empty.

What an empty export may not do is read as a successful one, and two rules make that concrete. A non-empty
arm's array is never empty, so a writer cannot reach the void statement by leaving the array out of the shape
that needs it: an anchored arm with no items is a malformed document, because its own label says there is
something in it. And a reader's answer for a void collection carries no items and no walk, so a caller cannot
print a count of verified material it was not given.

## Chain carry, and the bound on what it shows

Where an export carries receipts whose digests chain, the framing is section 5.2 of
[receipt-spec.md](receipt-spec.md), published as byte images in
[`packages/fixtures/data/chain-v1.json`](../packages/fixtures/data/chain-v1.json). The recomputation is
sha256 over `0x00 || p || iat` as eight big-endian bytes, the byte length of the id as two big-endian bytes,
the id, and the original bytes: unsigned, big-endian, and nothing else. A reader walks from the anchor to the
named head across the carried items, following the predecessor each item publishes, and refuses a gap, a
duplicate claim on one predecessor, an item it cannot reach and a head it cannot reach. The check has two
halves, and a reader that implements only the first has implemented half a rule: the walk from the anchor to
the head, and the count of what that walk reached against the array it was handed. A record parked beside a
run it is not part of reaches the head exactly as the honest ones do, so the second half is the only one with
eyes for it.

What a completed walk does not establish is the part a reimplementer is most likely to over-read:

- It is not proof that the source is complete. A run of records the reader was never handed links to nothing
  the reader holds, and the framing cannot see it. The head makes deletion detectable only against a copy the
  reader had cause to believe before, and the document states its own head; the reader's pin is the argument
  that reaches past that, which is why it is an argument and not a conclusion. The vectors publish the pair:
  a shorter run re-chained to its own consistent head passes every check a reader can run without bringing an
  endpoint, and answers `EXPORT_ENDPOINT_MISMATCH` to one that brought the head it already held.
- It is not proof of freshness. An export states when it was assembled and nothing about whether the store
  has written since. A reader that cares compares `at` against its own clock and says so.
- It is not a verification of the receipts inside it. An anchored item's bytes are the payload the record was
  hashed with, and the walk hashes them without opening them. A reader that wants each receipt's own signature
  checked runs the receipt verifier over those bytes with the key it holds for the kid this document names.
  That is a second check the reader makes, and this container did not perform it.
- It is not a statement that the material is what any law, contract or proceeding requires. That is what the
  assessment block above is for, and this container states that it made no such claim.

## The claim block

Provenance and custody are facts about a process rather than about bytes, and no reader can recompute them.
The alternative to stating them is leaving a reader to infer them from the absence of a statement, so the
block is required, its kind is chosen from two labels this version can mean, and its sentence is bounded but
free. It sits inside the signature, which is the whole of what the signature establishes about it: that the
holder of this key asserted this, at this time, in these words.

## Refusals

Every fault is refused by a code, and a caller branches on the code and not on the sentence. The rows are in
[error-codes.md](error-codes.md) with the conditions and the caller's action; the names are listed here so
one file states the whole set this container can answer with.

| Code | The fault |
|---|---|
| `EXPORT_MALFORMED_CBOR` | The document does not decode as canonical CBOR |
| `NOT_COSE_SIGN1` | The top-level value is not the tagged four-element structure |
| `UNSUPPORTED_ALG` | The header's `alg` is not an integer, or is not EdDSA |
| `EXPORT_BAD_HEADER` | The signed header is not a map, does not decode under this format's rule for it, carries a label outside the three, or names a content type that is not an export |
| `EXPORT_KID_MISMATCH` | The key handed to the reader is not the one the header's kid names |
| `INVALID_SIGNATURE` | The signature does not verify over the `Sig_structure` |
| `EXPORT_UNSUPPORTED_VERSION` | The manifest declares a version no format has used |
| `EXPORT_BAD_MANIFEST` | A member is absent, undefined at this version, of the wrong type or width, negative, a path where a name belongs, an empty array under a non-void arm, or a stamp that contradicts another member |
| `EXPORT_UNSUPPORTED_LABEL` | A `k` or a `kind` names a shape or a label this version defines no reading for |
| `EXPORT_DUPLICATE_ID` | Two items answer to one name |
| `EXPORT_DIGEST_MISMATCH` | An original does not hash to the digest its item carries |
| `EXPORT_ORIGINAL_UNAVAILABLE` | A companion file the reader would need was not handed to it |
| `EXPORT_CHAIN_BROKEN` | A gap, a fork, or a run that stops short of the head |
| `EXPORT_ITEM_UNREACHED` | An item lies outside the run from the anchor to the head |
| `EXPORT_ENDPOINT_MISMATCH` | The endpoints the document names differ from the ones the reader brought |

Three of those answers are about different things and a reader should keep them apart:
`EXPORT_BAD_MANIFEST` is a document that contradicts itself, `EXPORT_ORIGINAL_UNAVAILABLE` is a reader that
was handed too little, and `EXPORT_ENDPOINT_MISMATCH` is a reader that came holding something else.

## Reading and writing these bytes

`@ashaveri/receipt` publishes `decodeExport` and `verifyExport`. A verification key, the bytes of any
companion files, and any endpoints the reader already holds all arrive as arguments: nothing in the reader
resolves a name, opens a file, reaches a network or consults a key directory, and it reports only on what it
was handed. `decodeExport` answers structure and needs no key, because a document that contradicts itself
does so whoever signed it; `verifyExport` adds the signature, the digests, the walk and the caller's own
endpoints, which are the checks that mean something only against a signature the reader has accepted.

The same module publishes the codec the layout is written against: `encodeExportManifest`,
`encodeExportProtectedHeader`, `exportSigStructure`, `sealExport` and `signExport`, plus
`exportRecordDigest` for the framing. `signExport` runs a manifest through the structural parse before it
signs, so a writer cannot produce bytes its own reader rejects, and a document that is meant to be refused
therefore cannot come out of it. Every document in `packages/fixtures/data/export-v1.json` is assembled from
the pieces above rather than through `signExport`, and published beside the verdict it owes and the arguments
it is read with.

## The identity of the schema

| Fact | Value |
|---|---|
| File | `packages/receipt/schemas/export-v1.schema.json` |
| `$id` | `https://ashaveri.com/schemas/export-v1.json` |
| Draft | JSON Schema 2020-12 |
| Version member | `v` is the constant `1`, and the number in the identity is the number in the document |

The identity carries the version because the receipt family is already two documents and a schema named for
neither would have to mean both the day a second export version is defined. `packages/fixtures/test/schema-identity.test.ts`
holds every published schema in this workspace to that rule, so the convention is a checked property of the
tree rather than a habit this sentence asks a reader to trust.
