# Evidence pack, version 2

Status: current for pack version 2. The normative statement of the container is
[`packages/receipt/pack.cddl`](../packages/receipt/pack.cddl); its JSON twin is
[`packages/receipt/schemas/pack-v2.schema.json`](../packages/receipt/schemas/pack-v2.schema.json), whose
identity is `https://ashaveri.com/schemas/pack-v2.json`; the conformance vectors are
[`packages/fixtures/data/pack-v1.json`](../packages/fixtures/data/pack-v1.json) and are read as described in
[vectors.md](vectors.md). The table below is the same layout as the twin, and
`packages/fixtures/test/pack-doc.test.ts` holds the two against each other in both directions: every row
resolves to a member the twin defines, with the type and the required-ness the twin gives it, and every member
the twin defines appears as a row. The byte-level walk this container is built for, and the frames it recomputes,
are section 5.2 of [receipt-spec.md](receipt-spec.md); where a sentence here and that section or the CDDL
disagree, they are the authority and this prose is wrong. A line number is a fact about a file that edits
itself, so nothing here cites one.

## What this container is

A pack is what one deployment hands over when it answers for a span of time rather than for one response. It
states that the receipts inside a window are all of them, carries the two chain endpoints a reader walks
between, states the retention duty the window was answered under and the revision of the mapping the required
period came from, and carries the material its sealed receipts' anchor slots name. It is a statement about a
run of records and the appraisal context that run was taken in, and it is not an answer about any single
response: each receipt inside it is verified as the receipt it is, under its own header's key, and a pack adds
nothing to what one attests.

A pack cannot do an export's job, and [export-v1.md](export-v1.md) states why that is a second contract rather
than a pack version. The two differ in the direction an auditor travels: an export carries originals out of a
deployment, and a pack carries the records a window served, in the order the store chained them.

The container has two entry points and they answer different questions. `decodePack` reads the document's
structure and needs no key, because a manifest that contradicts itself does so whoever signed it;
`verifyPack` adds the signature, each item's receipt, the walk and the resolution of the carried material,
which are the checks that mean something only against a signature the reader has accepted. Every figure in this
document is stated once, here or in the twin, and the reader enforces it.

## The envelope

The framing is section 2 of [receipt-spec.md](receipt-spec.md), reused unchanged but for the content type: a
COSE_Sign1 (RFC 9052 section 4.2), tagged CBOR tag 18, encoded with Core Deterministic Encoding (RFC 8949
section 4.2.1), with a signature over the `Sig_structure` `["Signature1", protected, external_aad, payload]`
and an empty external AAD. Nothing inside the envelope carries which container was signed, which is why the
type in label 3 is the only thing that keeps a pack and a receipt apart in the hands of a reader holding one
key for both.

The protected header contains exactly three parameters, and the list is exhaustive rather than illustrative:

| Label | Name | Value |
|---|---|---|
| 1 | alg | -8 (EdDSA, Ed25519 per RFC 8032) |
| 3 | typ | `ashaveri/pack` |
| 4 | kid | 32-byte key id, sha256 of the Ed25519 public key |

Those bytes are hashed into the `Sig_structure`, so a label this table does not name is a parameter the issuer
authenticated, and a reader that took the three it knows and returned those would hand its caller a document
other than the one that was signed. A pack whose header carries a fourth label is refused and the refusal names
the label. A header whose `typ` is the receipt's, the export's or an amendment's is refused before a single
member of its payload is read, because each of those documents passes its own checks and the confusion is not
recoverable afterwards.

The map outside the signature is the one the format leaves open: `{ * any => any }`, the map that carries no
claim. Its emptiness is not enforced, because enforcing it would add a refusal with nothing behind it.

Every integer the manifest and the protected header carry is a CBOR integer, major type 0 or 1, and no other
major type carries one. Both maps are decoded where no floating-point number may appear, in a value and in a
key alike: the float `1.0` is not an integer written in a second way but another type, and by the time a
decoder has handed it over as one number nothing can tell which bytes the issuer signed. Every instant is a
unix time no earlier than the epoch and every duration a whole number of seconds no smaller than zero, so a
negative stamp is a malformed document and not an unusual way of writing a quantity.

## The manifest

The payload is a closed map at `v: 2`: a member the version a document names does not define makes the document
malformed rather than a document read with that member dropped. That holds of every map below, so a span cannot
be read with a duty's keywords and a carried entry cannot be read as an item. The manifest names seven members
and each is required, so no position is optional, none carries a default, and a reader never has to work out
what an omitted field meant.

Version one named six of these and no more. Version two is the seventh, `carried`, and it is a version rather
than an addition because the member is one a reader must not miss: a pack that carries nothing of what its
receipts' anchors name leaves every held slot weighable only against material the reader has to go somewhere
else for, which is a different document from the one the auditor holds. The version states what the fields
attest, not which software wrote them.

Byte strings are projected as lowercase hex in the twin and in the vectors, and documents and byte strings are
unpadded base64url in the vectors. A byte ceiling belongs to the CDDL: a JSON string length is a different
measure, so the twin states the floor and not the limit.

| Member | Type | Required | What it states |
|---|---|---|---|
| `protectedHeader` | `object` | yes | The three signed parameters above, as the twin projects them. |
| `payload` | `object` | yes | The signed manifest, which is the only part of a pack a verifier has to believe before it starts walking. |
| `signature` | `string` | no | Ed25519 over the `Sig_structure`, hex. Named without being demanded, because a display of an unsigned pack still shows; `pack.cddl` requires four elements and sixty-four bytes. |
| `v` | `2` | yes | Format version, one constant rather than a discriminant. A reader refuses a version it does not define rather than reading the bytes under rules that were not written for them. |
| `at` | `integer` | yes | Unix seconds, the instant assembly began, stamped before the reads rather than after them so that a slow store cannot date a pack later than the window it describes. `held` is measured at it and the span is served as of it. |
| `span` | `object` | yes | The period the pack answers for, half-open: `from` included, `to` excluded. |
| `chain` | `object` | yes | The two endpoints a reader walks between, neither of them derivable from the items. |
| `duty` | `object` | yes | The retention duty this window was answered under, and the revision of the mapping the required period was read from. |
| `items` | `array` | yes | At least one receipt, each naming its predecessor. Order in the array bears nothing: the reader follows the links. |
| `carried` | `array` | yes | The material the held anchor slots of the sealed receipts name, one entry per object the pack holds. It carries no floor, because an empty list is the pack stating that it carries nothing and an absent member would be a different claim. |
| `span.from` | `integer` | yes | Unix seconds, included. |
| `span.to` | `integer` | yes | Unix seconds, excluded: a receipt issued at exactly this stamp belongs to the next pack, not this one. |
| `chain.anchor` | `string` | yes | The digest the first item was chained from: thirty-two zero bytes before any retirement, otherwise the seam a trim record carried. Both arrive as the same member, and a reader does not have to know which happened to start walking. |
| `chain.head` | `string` | yes | The digest of the last item in the chain. Publishing it inside the signature is what makes deletion detectable and makes it the deployment's own statement rather than the reader's guess. |
| `duty.art` | `string` | yes | A label from the retention-duty registry, declared text rather than an enumeration for the reason [export-v1.md](export-v1.md) gives: this estate does not interpret the questions an article answers, and a format that enumerated answers would itself be an answer. |
| `duty.rev` | `integer` | yes | Unix seconds, the revision of the mapping `required` was read from, and never after `at`. The member that makes the other three readable later: a claim opened years after it was signed is read against the revision it was made from. |
| `duty.required` | `integer` | yes | Seconds that revision required. The deployment's to state, and this format supplies no default for it. |
| `duty.held` | `integer` | yes | Seconds the store has held the oldest receipt it retains, measured at `at`. At least the age of the oldest receipt in this pack, because a receipt handed over here is one the store still holds. |
| `item.id` | `string` | yes | The store's own id for the receipt, as the record names it, between 1 and 65535 bytes, and no two items in one pack carry the same one. A refusal reports an item by name, and two items answering to one name make that report mean whichever of the two a reader met first. |
| `item.iat` | `integer` | yes | Unix seconds, the stamp the record was chained at, bounded by the span and equal to the `iat` the receipt itself attests. The store chains under whatever stamp it was handed, so a reader that checked the walk and not this equality would accept a receipt moved into a window it was never issued in. |
| `item.prev` | `string` | yes | The digest of the record before this one, or the anchor for the first item. Published rather than derived, because the walk follows links and not positions. |
| `item.receipt` | `string` | yes | The signed receipt bytes, whole and unaltered, exactly as the record's payload holds them. The walk hashes them as a record's payload and verifies each as its own document. |
| `carried.bytes` | `string` | yes | The material exactly as it arrived, and the whole of it: vendor-signed collateral, a validity window's material, revocation data. Bounded at the same 65535 bytes an `id` is, which is the largest byte count this container already states rather than a number this block invented. |
| `carried.sha256` | `string` | yes | sha256 of the bytes beside it. The reader recomputes it and refuses a disagreement, which makes the entry a statement about its own bytes rather than a label over bytes the reader cannot see. |

## The walk, and the two halves of its check

The record digest is sha256 over `0x00 || prev || iat` as eight big-endian bytes, the byte length of the id as
two big-endian bytes, the id, and the receipt bytes: unsigned, big-endian, and nothing else. That framing is
section 5.2 of [receipt-spec.md](receipt-spec.md), published as byte images in
[`packages/fixtures/data/chain-v1.json`](../packages/fixtures/data/chain-v1.json), and the pack's own framing of
its two honest runs is published as `records` and `carriedRecords` in the vectors' `layout` block.

A reader starts at the item whose `prev` is the signed anchor, recomputes each digest from the bytes the item
carries, and ends at the signed head. The check has two halves, and a reader that implements only the first has
implemented half a rule: the walk from the anchor to the head, and the count of what that walk reached against
the array it was handed. A record parked beside a run it is not part of reaches the head exactly as the honest
ones do, so the second half is the only one with eyes for it.

What a completed walk does not establish is the part a reimplementer is most likely to over-read:

- It is not proof that the source is complete. A run of records the reader was never handed links to nothing the
  reader holds, and the framing cannot see it. The head makes deletion detectable only against a copy the reader
  had cause to believe before, and this document states its own head.
- It is not proof of freshness. A pack states when assembly began and nothing about whether the store has
  written since.
- It is not a claim that these are all the receipts the deployment still holds. That is a question about the
  store, and a reader holding an earlier copy of the same span is the only party who can see a tail go missing.
- It is not a verdict about the duty. Whether `held` meets `required` turns on the mapping `duty.rev` names and
  on the law behind it, and `met` is absent from the format on purpose so that a deployment signs evidence
  rather than its own conclusion.

## The two orders a pack carries

The links fix the order of the run and an item's `iat` is the stamp that record was chained under, and the two
are free to disagree because a store chains under whatever stamp it was handed when it appended. A deployment
that corrected its clock therefore signs an honest pack whose stamps run against its links while every link in
it is right. Nothing about that document contradicts a rule of this format, and refusing lawful output is as
wrong as accepting a forgery, so a reader reports the disagreement and never refuses it: one entry per step
where a successor carries a stamp earlier than its own, in chain order, naming both ids and both stamps, beside
a walk that completed. A conforming reader states the run it reached and the steps where the two orders part as
two separate findings, because a reader that folds them into one number loses which part of the handover a
reviewer should weigh.

## The material a pack carries

An anchor slot of a `v: 3` receipt states either a digest of material that was taken in or the collector's own
sentence for why there are no bytes. A pack that seals such a receipt answers the first kind inside itself: the
`carried` list holds one entry per object, each entry the bytes and the sha256 of exactly those bytes, and
`resolveCarried` hands a caller the object a digest names out of the container rather than an endpoint.

Resolution is by content hash and by nothing else. The pack does not key an object to a receipt, because the
digest a slot states is the only name a reader needs, and a second name for one thing is the thing that drifts.
Deduplication is inside the list, so one object appears once however many sealed receipts name it, and the count
of the list is the count of the material the pack holds rather than the count of the slots naming it. The list is
required and may be empty: a pack whose receipts state no anchor and a pack whose every slot states an absence
both write the member and both write it empty, and an empty list is a statement rather than a silence.

Two ceilings bind it, each taken from a number this container already states rather than one this block
invented. An entry's bytes are capped at 65535 bytes, which is the largest byte count a pack already bounds,
because the framing spends two bytes writing an id's length; inheriting that figure is what keeps the bound the
format's rather than the issuer's. The list is capped at 2 entries per item, which is the count of slots the
receipts this pack seals can name, `col` and `val`; a longer list cannot be all answers, and an entry named by
nothing is already a refusal, so the bound is computable from members a reader has already read. Both figures are
published as data in the vectors' `layout.carriedRule`, read out of the format by its generator rather than
written beside the rule they bound.

The reader enforces all of this before it trusts a statement, and each refusal names the position it found:

- an entry whose bytes do not hash to the digest beside it, quoting both digests;
- one digest carried at two positions, naming both;
- an entry that no held slot of any sealed receipt names;
- a list past the count the items can name, or an entry past the byte ceiling, each stating the figure it met;
- a slot that states `held` while the list carries nothing hashing to the digest it names, which is the pack
  attesting material it does not have.

The last is the pack's own failure and never an absence in the world, and it is the reason the member exists. A
slot stating an absence names no digest and owes no bytes, so a pack carrying nothing beside receipts that took
nothing in is whole. A receipt that does not decode at all is not this refusal either: the originals are read
under their own signatures, and an anchor nobody authenticated states nothing the pack has to answer for.

What the container carries is the material, not a verdict on it. Whether those bytes verify is settled by the
roots a reader stands behind, at the instant the reader asks about, and a pack prints neither.

## Refusals

Every fault is refused by a code, and a caller branches on the code and not on the sentence. The rows are in
[error-codes.md](error-codes.md) with the conditions and the caller's action; the names are listed here so one
file states the whole set this container's reader answers with, and `packages/fixtures/test/pack-doc.test.ts`
holds this table against the codes the published suite names as verdicts.

| Code | The fault |
|---|---|
| `PACK_MALFORMED_CBOR` | The document does not decode as canonical CBOR |
| `NOT_COSE_SIGN1` | The top-level value is not the tagged four-element structure, or an element is not what the envelope declares: the tag, one of the four positions, the signature's width |
| `UNSUPPORTED_ALG` | The header's `alg` is not an integer, or is not EdDSA |
| `PACK_BAD_HEADER` | The signed header is not a map, does not decode under this format's rule for it, carries a label outside the three, or names a content type that is not a pack |
| `PACK_KID_MISMATCH` | The key handed to the reader is not the one the header's kid names |
| `INVALID_SIGNATURE` | The signature does not verify over the `Sig_structure` |
| `PACK_UNSUPPORTED_VERSION` | The manifest declares a version no format has used |
| `PACK_BAD_MANIFEST` | A member is absent, undefined at this version, of the wrong type or width, negative, a stamp outside the span it is bounded by, a duration that contradicts the items it travels with, past a ceiling, or a carried entry that disagrees with the slots its sealed receipts name |
| `PACK_DUPLICATE_ID` | Two items answer to one name |
| `PACK_RECEIPT_INVALID` | A receipt inside the container is not a receipt, or does not verify under the key its own header names |
| `PACK_RECEIPT_STAMP_MISMATCH` | An item's chained stamp differs from the `iat` its own receipt attests |
| `PACK_UNKNOWN_KEY` | Nothing the caller designated answers for the kid one of the documents names |
| `PACK_CHAIN_BROKEN` | A gap, a fork, or a run that stops short of the head |
| `PACK_ITEM_UNREACHED` | An item lies outside the run from the anchor to the head |
| `PACK_CARRIED_DIGEST_MISMATCH` | A carried entry's bytes do not hash to the digest it states |
| `PACK_CARRIED_DUPLICATE` | One digest is carried at two positions |
| `PACK_CARRIED_UNNAMED` | A carried entry is named by no held slot of any sealed receipt |
| `PACK_CARRIED_UNRESOLVED` | A held slot names a digest no carried entry hashes to |

Four of those answers are about different things and a caller should keep them apart. `PACK_BAD_MANIFEST` and
its carried siblings are a document that contradicts itself, and no key changes that. `PACK_RECEIPT_INVALID` and
`PACK_UNKNOWN_KEY` are a caller that has too little: the first when a receipt inside the container does not
verify under the key its own header names, the second when nothing answers for that kid at all, which is the one
inner refusal a pack reader keeps as its own rather than as the receipt's answer. `PACK_KID_MISMATCH` is a
caller that came holding something else. And `PACK_ITEM_UNREACHED` is a pack whose walk is whole and whose array
is longer than the walk, which is the finding a reader that checked only the walk cannot make at all.

The writer refuses what its own reader would refuse, and one further thing. `signPack` runs the structural parse
and the walk before it signs, so a gap, a fork, a run short of its head, an item outside the run and each of the
four ways a carried list can disagree with the slots are refused where the bytes are made rather than after a
signature has made them unalterable. It also refuses `BAD_SIGNING_KEY` outright when a signing key's kid is not
sha256 of its public half, which no document can carry and no reader can be pointed at: a header naming an id
that resolves to nothing is unreachable because no deployment can seal one.

## Reading and writing these bytes

`@ashaveri/receipt` publishes `decodePack` and `verifyPack`. The keys arrive from the caller in either of the two
shapes the receipt verifier already takes: one pinned public key answers the envelope and every receipt inside
the container, and a resolver is asked once for each kid the documents name, so a span crossing a key rotation is
readable by a caller that retained the epoch it retired. Nothing in the reader resolves a name, opens a file, or
reaches a network, and it reports only on what it was handed. `decodePack` needs no key, because a manifest that
contradicts itself does so whoever signed it; `verifyPack` adds the signature, the originals, the walk and the
carried resolution, which are the checks that mean something against a signature.

The same module publishes the codec the layout is written against: `encodePackManifest`,
`encodePackProtectedHeader`, `packSigStructure`, `sealPack` and `signPack`, plus `packRecordDigest` for the
framing and `resolveCarried` for one held slot's material. `ashaveri verify-pack` runs the first pair over a file
and `ashaveri verify-handover` classifies the same bytes by their own content type and reaches the same reader, so
a stranger with one published file and Node can check a pack and report what it says. On that path the roots a
carried entry is weighed against are exactly the files `--intel-root` names, one per flag, and no root bundled
with the verifier is consulted at all: a library default is not this caller's pin, and an appraisal that
inherited one would report a verdict reached on a trust decision nobody made at the command line. The instant an
answer is read at is the stamp the record naming the material was chained at, which the sealed evidence states,
and not a clock the run reads.

## The identity of the schema

| Fact | Value |
|---|---|
| File | `packages/receipt/schemas/pack-v2.schema.json` |
| `$id` | `https://ashaveri.com/schemas/pack-v2.json` |
| Draft | JSON Schema 2020-12 |
| Version member | `v` is the constant `2`, and the number in the identity is the number in the document |

The identity carries the version because a pack manifest states which members a reader owes it, and a schema
named for no version would have to mean two shapes at once the day an eighth member arrives.
`packages/fixtures/test/schema-identity.test.ts` holds every published schema in this workspace to that rule, so
the convention is a checked property of the tree rather than a habit this sentence asks a reader to trust.
