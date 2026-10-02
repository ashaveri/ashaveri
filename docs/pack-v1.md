# Evidence pack, version 1

Status: current for pack version 1. The normative statement of the container is
[`packages/receipt/pack.cddl`](../packages/receipt/pack.cddl); its JSON twin is
[`packages/receipt/schemas/pack-v1.schema.json`](../packages/receipt/schemas/pack-v1.schema.json), whose
identity is `https://ashaveri.com/schemas/pack-v1.json`; the conformance vectors are
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
period came from, and answers each material slot its sealed receipts' anchors name with a signed reference to
where that material was read from. It is a statement about a run of records and the appraisal context that run
was taken in, and it is not an answer about any single response: each receipt inside it is verified as the
receipt it is, under its own header's key, and a pack adds nothing to what one attests.

A pack cannot do an export's job, and [export-v1.md](export-v1.md) states why that is a second contract rather
than a pack version. The two differ in the direction an auditor travels: an export carries originals out of a
deployment, and a pack carries the records a window served, in the order the store chained them. What a service
produced for the store is not an original of this estate, so it travels here as a reference and not as a copy.

The container has two entry points and they answer different questions. `decodePack` reads the document's
structure and needs no key, because a manifest that contradicts itself does so whoever signed it;
`verifyPack` adds the signature, each item's receipt and the walk. Neither resolves a held slot into material:
a reader that wants the bytes a reference names asks for them by digest, and `resolveAttached` is where that
question is answered and where the absence of an attachment is answered too. Every figure in this document is
stated once, here or in the twin, and the reader enforces it.

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

The payload is a closed map at `v: 1`: a member the format does not define makes the document
malformed rather than a document read with that member dropped. That holds of every map below, so a span cannot
be read with a duty's keywords, a reference cannot be read as an item, and the member this version replaced
cannot be read as though it were still standing. The manifest names eight members and each is required, so no
position is optional, none carries a default, and a reader never has to work out what an omitted field meant.

Two members stand where one stood. `custody` is the list of references the sealed receipts' `held` slots answer
for and `attached` is the byte arm those references can resolve to, and together they replaced the single list
that held the material itself. The replacement happened under the number rather than as a new version, because
nothing a deployment ever ran sealed the shape it replaced: the writers of this estate seal this one, and the
bytes that carry the retired member are this repository's own generated vectors, which its generator rewrites on
command. That is also why the retired member is refused by name and not dropped: a `v: 1` manifest whose payload
names `carried` answers `PACK_BAD_MANIFEST` with the position quoted, so a reader that met an old document is
told it is old by the closed-map rule rather than by a version number that says nothing. Both lists are required
and both may be empty, and an empty one is a statement: the pack that writes `custody` empty is the one whose
every sealed slot states an absence, and the pack that writes `attached` empty is the one attaching nothing
beside the references it signs for. The version states what the fields attest, not which software wrote them,
which is why a member that never reached a deployment's own bytes can be replaced under it and a shape a reader
can meet cannot.

Byte strings are projected as lowercase hex in the twin and in the vectors, and documents and byte strings are
unpadded base64url in the vectors. A byte ceiling belongs to the CDDL: a JSON string length is a different
measure, so the twin states the floor and not the limit.

| Member | Type | Required | What it states |
|---|---|---|---|
| `protectedHeader` | `object` | yes | The three signed parameters above, as the twin projects them. |
| `payload` | `object` | yes | The signed manifest, which is the only part of a pack a verifier has to believe before it starts walking. |
| `signature` | `string` | no | Ed25519 over the `Sig_structure`, hex. Named without being demanded, because a display of an unsigned pack still shows; `pack.cddl` requires four elements and sixty-four bytes. |
| `v` | `1` | yes | Format version, one constant rather than a discriminant. A reader refuses a number it does not define rather than reading the bytes under rules that were not written for them. |
| `at` | `integer` | yes | Unix seconds, the instant assembly began, stamped before the reads rather than after them so that a slow store cannot date a pack later than the window it describes. `held` is measured at it and the span is served as of it. |
| `span` | `object` | yes | The period the pack answers for, half-open: `from` included, `to` excluded. |
| `chain` | `object` | yes | The two endpoints a reader walks between, neither of them derivable from the items. |
| `duty` | `object` | yes | The retention duty this window was answered under, and the revision of the mapping the required period was read from. |
| `items` | `array` | yes | At least one receipt, each naming its predecessor. Order in the array bears nothing: the reader follows the links. |
| `custody` | `array` | yes | What the sealed receipts' `held` slots were reached against: one reference per named slot, and no content and no verdict in any of it. It carries no floor, because an empty list is the pack saying it refers to nothing and every sealed slot of such a pack states an absence; the count it is capped at, and the length of the request it states, are in `pack.cddl`. |
| `attached` | `array` | yes | The byte arm: material a deployment attaches beside the references, whole. It carries no floor, because an empty list is the pack attaching nothing, and that is what every pack a deployment of this estate assembles is. The layout permits the arm and no path a deployment runs fills it, because whether a given deployment may hand a service's bytes on is a question of its own agreement with that service and not one this container answers or grants. The vector suite and the offline proof do fill it, with documents their own fixture vendor generated, because an arm nothing ever attached would leave a reader's handling of a pair, and of a body that arrived alone, untested. |
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
| `custody.k` | `object` | yes | Which sealed receipt and which half of its anchor this reference answers for. The slot is the only name a reference is reached by, and an entry naming a slot no sealed receipt states is a record of an observation nobody asked it to stand behind. |
| `custody.o` | `string` | yes | The origin declaration this read, by the name that declaration states for itself. The container names no set of them and its reader checks it against none, because `@ashaveri/receipt` sees no declaration list: a name a build cannot reach is refused where a declaration is actually fetched, in the collateral package, and not here. |
| `custody.u` | `string` | yes | The request as it was asked, path and query members included, bounded at 2048 bytes. That figure is stated once, in `pack.cddl`, which is why no other file of this container writes it again. |
| `custody.i` | `string or null` | yes | The identity the document named for itself, such as the CPU it is about, or null where the answer names none. It is the document's own statement, spelled the way the declaration's `identity` states it, and no reader of a container can compare it with firmware it does not hold. |
| `custody.s` | `integer` | yes | Unix seconds, the instant the document's last byte landed on the clock that run was given. A millisecond spelling of the same instant is a whole number no earlier than the epoch, so the band the receipt format draws for a stamp is what tells the two units apart, and it is enforced before any member of the material is weighed. |
| `custody.n` | `integer or null` | yes | What that source declares about itself, in the same seconds-or-null pair the receipt's own stamp disclosure carries, or null where the source states nothing. It bounds what the instant above is worth and says nothing about whether the document stood at the moment a reader asks. |
| `custody.b` | `string` | yes | sha256 of the body exactly as it arrived. This is the digest the slot it answers for states, and the digest an attached object, where one is attached, has to hash to: a reference is a statement about material, and the pair agreeing is what makes it checkable later. |
| `custody.c` | `string or null` | yes | sha256 of the issuer-chain header exactly as it arrived beside that body, or null where no header arrived. This is the member that decides whether a chain has to come with the bytes, and it is a digest rather than a second run of bytes because a chain's own bytes are no member of this container: the header is the service's response, and a reference says what it hashed to without handing it on. |
| `custody.a` | `string` | yes | Which arm weighed the document at capture, `served` where the issuer chain arrived in a header beside the body and `embedded` where the certificates sit inside the document itself. It is the declaration's own answer and never a reading of the bytes, because a reader that inferred it from a shape it could see would be reporting an opinion about a service's response as a fact the container states. |
| `custody.w` | `object` | yes | The window the document stated for itself, in the vendor's own signed words. Both ends are the document's statement carried through the reference; whether it stood at an instant a reader asks about is that reader's question with its own roots. |
| `custody.y` | `string` | yes | The cache key, spelled from the declaration's `cache.keyMembers`, so a reader that holds these bytes in its own store finds them again under the name the declaration gives them. It is derived from the request and the identity rather than stated beside them, and a second name for one material is the thing that drifts. |
| `custodyKey.item` | `string` | yes | The id the pack gives the record whose anchor states the slot, bounded at the same 65535 bytes an `item.id` is. |
| `custodyKey.slot` | `string` | yes | Which half of that receipt's anchor the reference answers for: `col` for the signed collateral, `val` for the validity context. Two per record, which is the whole of what the count of references is bounded against. |
| `window.from` | `integer` | yes | Unix seconds, the instant the document says it began to stand. |
| `window.to` | `integer` | yes | Unix seconds, the instant it says it stops being read as standing. |
| `attached.bytes` | `string` | yes | The material, whole and exactly as it arrived, where a deployment attaches it. Bounded at the same 65535 bytes an `id` is, which is the largest byte count this container already states rather than a number this block invented. |
| `attached.sha256` | `string` | yes | sha256 of the bytes beside it. The reader recomputes it and refuses a disagreement, which makes the entry a statement about its own bytes rather than a label over bytes the reader cannot see. |
| `attached.chain` | `string or null` | yes | The issuer-chain header that arrived beside those bytes, exactly as it arrived, or null where none did. Present exactly when the digest below is: a header with no digest stated for it is the document contradicting itself about its own arm, and no recomputation settles which half the issuer meant. |
| `attached.chain_sha256` | `string or null` | yes | sha256 of that header, or null where there was no header. The reader recomputes it, refuses a disagreement, and refuses a header carried here beside a reference whose `c` states none. The label is lowercase because every label this format writes is; `resolveAttached` hands the same value back under its object spelling. |

## The walk, and the two halves of its check

The record digest is sha256 over `0x00 || prev || iat` as eight big-endian bytes, the byte length of the id as
two big-endian bytes, the id, and the receipt bytes: unsigned, big-endian, and nothing else. That framing is
section 5.2 of [receipt-spec.md](receipt-spec.md), published as byte images in
[`packages/fixtures/data/chain-v1.json`](../packages/fixtures/data/chain-v1.json), and the pack's own framing of
its two honest runs is published as `records` and `attachedRecords` in the vectors' `layout` block, the second
framing the run whose every held slot is answered by a reference.

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

## What a pack refers to, and the arm beside it

An anchor slot of a sealed receipt states either a digest of material that was taken in or the collector's own
sentence for why there are no bytes. A pack that seals such a receipt answers the first kind with a reference:
one entry per held slot, naming that slot by the record and by the half of its anchor, and stating where the
document was read from, what was asked of it, what it said it was, when its last byte landed and what that
source declares about itself, the digest of its body, the digest of the header that arrived beside it, which arm
weighed the pair, the window it signed for itself, and the cache key it would be found under again. The reference
states no content and no verdict. `custodyForSlot` is the reader's question about it, answered by the same pair
of names the format gives the entry.

Resolution is by the slot and by nothing else. The pack does not key a reference to a receipt by a second name,
because the slot is the only name the format gives it, and a second name for one thing is the thing that drifts.
Every sealed receipt states an anchor with both of its halves, so the pack that writes the list empty is the one
whose every slot states an absence, and an empty list is a statement rather than a silence. A slot stating an
absence names no digest and owes no bytes and owes no reference, so a pack referring to nothing beside receipts
that took nothing in is whole.

Two ceilings bind the two lists, each taken from a number this container already states rather than one this
block invented. The count of references, and the count of attached objects, is capped at 2 entries per item,
which is the count of slots a sealed receipt can name, `col` and `val`; a longer list cannot be all answers, and
an entry named by nothing is already a refusal, so the bound is computable from members a reader has already
read. An attached object's bytes, and the header beside them, are capped at 65535 bytes, which is the largest
byte count a pack already bounds, because the framing spends two bytes writing an id's length. Both figures are
published as data in the vectors' `layout.custodyRule`, read out of the format by its generator rather than
written beside the rule they bound.

The byte arm is the other half of this member and the layout permits it: `attached` holds material whole, beside
the digest of those bytes and, where one arrived, the header and its digest, so an entry can be weighed by a
reader that has the bytes in hand. Nothing in this repository fills it, and no pack published by this estate
attaches a byte. Whether a given deployment may hand a particular service's bytes on is a question of its own
agreement with that service; this container neither grants such a right nor judges one, and a reference is what
this estate distributes.

What a reader enforces before it trusts a statement of the arm, each refusal naming the position it found:

- an entry whose bytes do not hash to the digest beside it, or whose header does not hash to the digest stated
  for it, quoting both;
- an entry that carries a header while stating no digest for it, or the reverse, which is one member of the arm
  contradicting another;
- one digest attached at two positions, naming both;
- an entry the body digest of no reference names, which is the pack attaching material it attests nothing about;
- an entry carrying a header beside a reference whose `c` states none, because the reference is what says whether
  a chain had to arrive at all;
- a list past the count the items can name, or an entry past the byte ceiling, each stating the figure it met.

And what the reference list enforces, in the order a reader reaches it: an entry answering for no held slot, a
held slot no entry answers for, and an instant that is not a whole number of Unix seconds inside the band. The
middle one is the failure this member exists to make impossible, and it is the pack attesting material it does
not have a signed statement about: a sealed receipt names material it took in and the container signs nothing
about where it came from. That is reported as the pack's failure and never as an absence in the world. A receipt
that does not decode is not this refusal either: the originals are read under their own signatures, and an
anchor nobody authenticated states nothing the pack has to answer for.

What a reference names is the material, not a verdict on it, and this is the document that states what one entry
answers for. Whether those bytes verify is settled by the roots a reader stands behind, at the instant the reader
asks about, and a pack prints neither. The reading that needs a chain beside a body is settled by the reference
itself: `a` names the arm that weighed the document at capture and `c` states the digest of the header that
arrived with it, which is the pair that tells a reader holding the bytes whether the material it holds is the
material that was seen. A container that states a digest answers for a header it does not carry, and a reader
that has the header checks it; a reader that has neither has the statement, the instant, and the signature.

An attached object is reached by the lookup and by no other door: `resolveAttached` takes a digest, re-verifies
it, and hands back the material, the header beside it, and the reference that states both. A pack that attaches
nothing is whole and answers that question with `PACK_ATTACHED_UNRESOLVED`, which is the caller reaching past what
the document undertook rather than a defect of the document, and which is why no pack document of this estate
is refused with it: the two container readers never resolve a slot for a caller. The same digest offered to a pack
that attaches it is refused if it disagrees with what the entry states, and the refusal names the position.

A reference is a statement about a vendor's document, not a copy of one, and this container states no way of
taking a copy out on its own: there is nothing to remove from a pack that holds none, and an attached entry
leaves when the pack carrying it leaves, which is the deployment's expiry of that window and not a subject's
request.

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
| `PACK_BAD_MANIFEST` | A member is absent, undefined at this version including the member this version replaced, of the wrong type or width, negative, a stamp outside the span it is bounded by, a duration that contradicts the items it travels with, a list or an entry past a ceiling the format takes from its own contents, an attached header stated with no digest beside it, or a reference list that does not reach the held slots its sealed receipts state |
| `PACK_DUPLICATE_ID` | Two items answer to one name |
| `PACK_RECEIPT_INVALID` | A receipt inside the container is not a receipt, or does not verify under the key its own header names |
| `PACK_RECEIPT_STAMP_MISMATCH` | An item's chained stamp differs from the `iat` its own receipt attests |
| `PACK_UNKNOWN_KEY` | Nothing the caller designated answers for the kid one of the documents names |
| `PACK_CHAIN_BROKEN` | A gap, a fork, or a run that stops short of the head |
| `PACK_ITEM_UNREACHED` | An item lies outside the run from the anchor to the head |
| `PACK_CUSTODY_UNNAMED` | A reference answers for no held slot of any sealed receipt: it names a record the pack does not carry, a slot that states an absence, or a body digest that is not the one the slot names |
| `PACK_CUSTODY_UNRESOLVED` | A sealed receipt states a held slot no reference of this pack answers for, which is the pack attesting material it recorded nothing about |
| `PACK_CUSTODY_UNIT_OUTSIDE_BAND` | A reference states an instant, or an end of the window the document signed for itself, that is not a whole number of Unix seconds inside the band the receipt format draws |
| `PACK_ATTACHED_DIGEST_MISMATCH` | An attached object's bytes do not hash to the digest it states, its header does not hash to the digest stated for it, or it carries a header beside a reference that states none |
| `PACK_ATTACHED_DUPLICATE` | One digest is attached at two positions |
| `PACK_ATTACHED_UNNAMED` | An attached object is the body digest of no reference this pack signs for |

Four of those answers are about different things and a caller should keep them apart. `PACK_BAD_MANIFEST` and
its arm siblings are a document that contradicts itself, and no key changes that. `PACK_RECEIPT_INVALID` and
`PACK_UNKNOWN_KEY` are a caller that has too little: the first when a receipt inside the container does not
verify under the key its own header names, the second when nothing answers for that kid at all, which is the one
inner refusal a pack reader keeps as its own rather than as the receipt's answer. `PACK_KID_MISMATCH` is a
caller that came holding something else. And `PACK_ITEM_UNREACHED` is a pack whose walk is whole and whose array
is longer than the walk, which is the finding a reader that checked only the walk cannot make at all. The three
`PACK_CUSTODY_*` answers join the first group: they are the reference list disagreeing with the receipts sealed
beside it, whoever signed it.

The writer refuses what its own reader would refuse, and one further thing. `signPack` runs the structural parse
and the walk before it signs, so a gap, a fork, a run short of its head, an item outside the run, each way the
references can part from the slots and each way the arm can part from the references are refused where the bytes
are made rather than after a signature has made them unalterable. It also refuses `BAD_SIGNING_KEY` outright when
a signing key's kid is not sha256 of its public half, which no document can carry and no reader can be pointed
at: a header naming an id that resolves to nothing is unreachable because no deployment can seal one.

One refusal joins none of the rows above for the same reason, and it is the lookup's: `PACK_ATTACHED_UNRESOLVED`
is what `resolveAttached` answers a caller that reaches for material a whole pack attaches nothing for. It is not
a fault of a document, because the pack that attaches nothing is the ordinary case, so no pack of this estate is
refused with it and no row above names it; it is stated here, in prose, beside the function that raises it.

## Reading and writing these bytes

`@ashaveri/receipt` publishes `decodePack` and `verifyPack`. The keys arrive from the caller in either of the two
shapes the receipt verifier already takes: one pinned public key answers the envelope and every receipt inside
the container, and a resolver is asked once for each kid the documents name, so a span crossing a key rotation is
readable by a caller that retained the epoch it retired. Nothing in the reader resolves a name, opens a file, or
reaches a network, and it reports only on what it was handed. `decodePack` needs no key, because a manifest that
contradicts itself does so whoever signed it; `verifyPack` adds the signature, the originals and the walk, which
are the checks that mean something against a signature.

The same module publishes the codec the layout is written against: `encodePackManifest`,
`encodePackProtectedHeader`, `packSigStructure`, `sealPack` and `signPack`, plus `packRecordDigest` for the
framing, `custodyForSlot` for the reference one held slot answers to, and `resolveAttached` for the material a
reference names where a deployment has attached it. `ashaveri verify-pack` runs the first pair over a file and
`ashaveri verify-handover` classifies the same bytes by their own content type and reaches the same reader, so
a stranger with one published file and Node can check a pack and report what it says. On the path where material
is handed to a reader beside the pack that refers to it, the roots that material is weighed against are exactly
the files `--intel-root` names, one per flag, and no root bundled with the verifier is consulted at all: a
library default is not this caller's pin, and an appraisal that inherited one would report a verdict reached on
a trust decision nobody made at the command line. The instant a reference is read against is the stamp the record
naming the material was chained at, which the sealed evidence states, and the instant its own last byte landed,
which the reference states; neither is a clock the run reads.

## The identity of the schema

| Fact | Value |
|---|---|
| File | `packages/receipt/schemas/pack-v1.schema.json` |
| `$id` | `https://ashaveri.com/schemas/pack-v1.json` |
| Draft | JSON Schema 2020-12 |
| Version member | `v` is the constant `1`, and the number in the identity is the number in the document |

The identity carries the version because a pack manifest states which members a reader owes it, and a schema
named for no version would have to mean two shapes at once the day a ninth member arrives.
`packages/fixtures/test/schema-identity.test.ts` holds every published schema in this workspace to that rule, so
the convention is a checked property of the tree rather than a habit this sentence asks a reader to trust.
