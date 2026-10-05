# The capture record (capture-v1)

A capture record states, for one piece of evidence, the exact original bytes a source produced and the
context that made them verifiable at the instant they were taken in.

**Nothing in this repository writes one.** A collector fills this shape, apart, in a private repository, and
out of scope here. What is public is the layout a collector has to be written against and the reader a stranger
can run against whatever they are handed. That order is deliberate, and it is the one
`packages/receipt/pack.cddl` keeps for a pack: the
layout, the reader and the encoder are public there, and what decides a pack's contents is not. The claim
about continuity is only checkable by somebody who does not trust us if the shape it travels in is public
and a reader for it exists.

- The record: `packages/sdk/schemas/capture-v1.schema.json`, published as
  `https://ashaveri.com/schemas/capture-v1.json`.
- The reader: `packages/sdk/src/capture.ts`, `parseCaptureRecord` and `assessCapture`.
- Its vectors: `packages/fixtures/data/capture-v1.json`, written by
  `packages/fixtures/scripts/capture-vectors.ts` and replayed row by row through these same two readers by
  `packages/fixtures/test/capture-vectors.test.ts`. Each row states one record, the caller's own pins and clock beside
  it, and the answer this code gave when the file was written, so a stranger can hand the readers bytes this
  repository stands behind and see which answer is owed. `docs/vectors.md` says what the suite pins and how to
  consume it.
- Its tests read real bytes: the originals are `issueReceipt` output from `@ashaveri/receipt` and a
  manifest the estate's own `parseManifest` accepts.

## Where it sits in the format family

A receipt attests one response. A pack attests that the receipts inside a window are all of them. A
capture attests nothing at all, and that is its whole contribution: it holds the bytes a receipt only
digests. `gateway/src/server.ts` stores `sha256(args.evidence.document)` and no part of the document, so
a client that wanted to re-check the evidence later can prove only that a hash existed.

The record is a JSON document beside `policy-v1`, not a CBOR document beside `receipt.cddl`, and it is
signed by nobody. Both choices are load bearing. Its value does not come from the writer's word: it comes
from a reader that recomputes every digest it can see, hands back the stored bytes unchanged, and repeats
the one check a stranger can repeat with its own pins. A signature over the record would attest the
collector's authorship, which is a fact about the collector and not about the evidence.

## The three states, and why two would not do

Every piece of context a capture may hold carries a `presence`:

| state | meaning | what a reader reports |
| --- | --- | --- |
| `held` | the bytes arrived and this record carries them | the slot is checked and every digest it states is recomputed |
| `absent-at-source` | this source never produced it | the verdict is `qualified` |
| `not-taken-in` | it may have existed and nobody put it in the record | the verdict is `unassessed` |

The last two are different outcomes and the reader keeps them apart: the first is a statement about the
world and the second is a statement about the collector. A record that said nothing about its collateral
would be indistinguishable from one whose collateral never existed, which is why every context member is
required and why an absence without a `reason` is refused. `held` is never a claim about a digest: a
reader recomputes it and refuses the record when the two disagree.

## Fields

Each row says what the member states, what a reader may conclude from it, and what a reader may not.

| member | states | a reader may conclude | a reader may not conclude |
| --- | --- | --- | --- |
| `v` | which rules the record is read under | that a reader implementing no other version refused or read it | anything about the bytes |
| `original.sourceKind` | which of this estate's sources produced them | which reading applies, and whether a signature leg can be repeated here | that the source is trustworthy |
| `original.sourceId` | the name the source gave itself | who the collector says it spoke to | that anybody answered |
| `original.bytes` | the exact bytes as they arrived | they are the bytes the record describes, iff `sha256` agrees | that they are the bytes the source produced, which is the collector's claim |
| `original.sha256`, `byteCount` | the digest and length of those bytes | the record is self-consistent, or it is refused | that the digest matches anything outside the record |
| `original.signedBySource` | our assertion that the source signed them | there is a leg to repeat, and the record asserts it | that it holds. Nothing here says so, and no field could |
| `original.signatureEmbedded`, `signature` | where the signature is, and its presence state | that a record claiming a detached signature carries one | that the signature is anyone's |
| `acquired.at` | our clock when the bytes were taken in | how the collector dates its own taking-in | that the bytes were made then, which is what `sourceStatedAt` claims, nor that the answer a collateral slot holds was observed then, which is what its `observedAt` claims on another clock |
| `acquired.sourceStatedAt` | the timestamp the source claimed, or none | that the two stamps agree, or that the record says how they do not | that either is right |
| `manifests.deployment` | the manifest the source served, as served | which pins were in force at that instant, from a document rather than a summary | that the manifest was this deployment's: the record authenticates nothing, and a sealed manifest is only attributed by a reader that holds the key that signed it |
| `check.policyVersion`, `policyDigest` | which policy rules, and the digest of the document used | which pins the check read, given the document | that the check was right to read them |
| `check.receiptFormatVersion` | which receipt version the check read, of the one version the format defines | that a reader reads the bytes at the version named and refuses one it does not | that the version was current, which it need not be |
| `check.verifierVersion` | which verifier build ran | which procedure produced the context | that the procedure was correct |
| `check.appraisedAt` | when the appraisal ran, on our clock | that the appraisal could have seen these bytes | anything about validity, which lives in `context.validity` |
| `context.collateral` | the vendor chain the bytes were appraised against, and the answer those bytes are | that a verdict about the signature has something to stand on, and which question that something answered | that the chain was this platform's |
| `context.validity` | the window and the appraisal recorded | that the verdict is about a window rather than forever | that the window was open when it says it was, which a reader cannot re-run |
| `trust.roots` | which references the check believed | that a caller who pinned the same bytes can agree, and one who pinned others is refused | that an unnamed or unpinned root was any root in particular |
| `trust.limits` | how far the check let a clock sit from the bytes | that the verdict was reached under a window this caller would accept | a pass. The reader runs its own windows and reports a difference |

## What a held collateral slot states

A held slot states bytes, a digest and a length, and that is all a manifest or a detached signature is
asked for. A collateral slot is an answer somebody got back from somewhere, so a held one states eight
facts more, and the header an issuer chain arrived in beside the digest of that header. Without them the
record says "we hold something of this length and this digest", which is a statement about a hash and not
about an observation.

| member | states | a reader may conclude | a reader may not conclude |
| --- | --- | --- | --- |
| `origin` | which source declaration the answer came under, named as that declaration names itself | which path the bytes were asked of, and which rules that path reads answers by | that the source is trustworthy, which is a pin |
| `request` | the address the answer was asked at, as it was spelled on the way out, and at most 2,048 bytes of it | that the answer can be gone and re-asked | that the address still answers, which is a question about a route and an instant |
| `identity` | the identity the signed answer names for itself, or null where it names none | what the bytes claim to be about, in the answer's own words | that the claim is true, which is a reading of the signature |
| `observedAt` | unix seconds, whole, the instant the last byte landed | that the observation has an instant of its own, on the clock of the process that watched it | that this is `acquired.at`, which is this collector's clock and a different event |
| `sourceUncertaintySeconds` | how far that clock admits it may stand from the instant it names, or null where nobody measured | that the record states a bound rather than an accuracy, and says which of the two it has | a bound of zero from a null, which is the reading this estate refuses everywhere |
| `chainBytes`, `chainSha256` | the header the chain arrived in, as it arrived, and the digest of it | that the chain's bytes are kept and named, and a reader can recompute the digest | that the chain reaches a root, which is a walk with the reader's own pins |
| `weighedBy` | `served` or `embedded`: which reading weighed the answer | whether the signature travelled inside the bytes or apart from them, which decides what a reader has to hold to re-run the weighing | a verdict about either |
| `window` | the span the answer's own signed statement reaches, `from` included and `to` excluded | what moment the bytes stand for and where they stop standing for anything | that the span is still open today |
| `cacheKey` | the key the answer was kept under, spelled from the members that decide which question a kept blob answers | which entry of a store a record is describing, and that the same bytes kept for a different question are a different record | that the store still holds it |

Three of these are worth naming as separations rather than as fields. The instant an answer was observed is
not the instant this collector took the record in, and the record keeps both because a deployment that
appraised on a schedule and issued later has two clocks in it and one number could not hold them apart.
The bound on the first of those clocks is the source's own statement, which is why it is nullable and why
a null is not zero. And `request` and `window` are a claim about an address and a span at an instant: a
reader that wants to know whether the route still answers goes and asks, which is the whole design of
stating them, and nothing in this record says what happened after.

A collector that watched none of this happened cannot state the answer as held, and the honest spelling is
the state this record already carries for exactly that case: `not-taken-in`, with the reason in its own
words. An absence is a statement. A held slot that names no source is not an absence and not an
observation, and no reader is asked to guess which of the two it meant.

These are the parts a pack's custody reference is made of, and the naming runs one to one: the slot's own
`sha256` is the entry's `b`, the digest a reader finds the entry by, and the members above are its `o`,
`u`, `i`, `s`, `n`, `c`, `a`, `w` and `y` in that order, the chain's two halves together making the one `c`.
Which anchor slot of which receipt an entry answers is the entry's own statement and is named by no member
of this record. The two documents describe one reference from its two ends: `docs/pack-v1.md` states what
an entry is and what a reader does with it, and this one states what the bytes it points at were taken in
as, by whom, and on whose clock.

## Which authority binds which rule

The layout has two authorities and they bind different rules, so this is the split a reader of the
published schema has to know.

The schema binds what a document is made of. It closes every block, gives each member its type and shape,
requires the eight facts of a held collateral slot at `#/$defs/collateralSlot`, and requires either half of
the chain pair with the other. A document any of that refuses is refused before a reader is asked anything
about it.

The reader binds the rules no JSON Schema states, because they are arithmetic and spelling rather than
shape: the digest a chain states has to be the digest of the chain bytes beside it; unpadded base64url has
one spelling a reader reproduces rather than any that decodes; and the address a slot states is bounded at
2,048 bytes, which counts bytes and no keyword of the published document counts bytes. It is also the
authority that asks a collateral slot for its eight and asks no other slot for them. That is a rule about a
role, and the schema states it as far as it can: the ten members are legal in any held slot, so a validity
slot, a signature slot or a manifest slot carrying them is a document neither authority refuses for
carrying them, and every rule above still binds what such a slot states. What reaches a verdict is the
collateral slot's statement and no other's, which is what `test/capture-reader.test.ts` reads a validity
slot carrying a whole observation to prove.

`test/capture.test.ts` reads one document through both and refuses their disagreeing, in either direction.

## Which receipt version a record may name

`check.receiptFormatVersion` carries `1`, which is every payload version
[`receipt.cddl`](../packages/receipt/receipt.cddl) defines and every version `@ashaveri/receipt` parses.
The list is the same on both sides of the reader: `enum: [1]` in the published schema and
`IMPLEMENTED_RECEIPT_FORMAT_VERSIONS` in `capture.ts`, held to each other by
`packages/sdk/test/capture.test.ts` at the boundary of the list, so a version gained on one side without the
other fails the assertion belonging to the side that moved rather than passing in silence.

That set is the format's and not a narrowing of it, and the reason is the gateway's: a deployment signs the
one receipt version for every response whose bytes frame into items, and serves no completion at all for a
stream that sent no `data:` frame. A record naming `1` is therefore the ordinary output of a check a
collector will be written against, and refusing one would leave a client unable to record what it verified.
A version outside the one the format declares is still refused, by the schema and by the reader alike, with `UNSUPPORTED_VERSION` naming what
the record stated and what the reader implements; the refusal is of a number no format has used, measured
against the set the format owns, and not of a set this reader chose to keep narrow.

The same walk reads `original.sourceKind` against the `SOURCE_KINDS` list the reader and its type are made
of, which is the coupling that holds `check.receiptFormatVersion` to its enum: a kind added to one side
alone is a document the published schema refuses and the accepted type admits, and that is the disagreement
a collector outside this repository would only meet in production.

## What the reader refuses

`parseCaptureRecord` and `assessCapture` refuse, each with a code a log line can carry:

- bytes that do not hash to the digest the record states, and a length that does not match the bytes
  beside it: `EVIDENCE_DIGEST_MISMATCH`
- the digest a collateral slot states for its chain header, when the header beside it hashes to something
  else, or when the stated digest is not sixty-four lowercase hex characters: `EVIDENCE_DIGEST_MISMATCH`,
  the same rule the original's bytes are read by and not a new one
- a member no version defines, a context member nobody declared, and bytes spelled in a base64url
  form no reader reproduces: `NOT_CAPTURE_RECORD`
- a held collateral slot that states any of the eight facts beside its bytes and leaves one out, with the
  message naming which: `NOT_CAPTURE_RECORD`
- a chain header stated on one side only, its bytes without their digest or its digest without its bytes,
  and an absence that carries a member only a holding slot can state: `NOT_CAPTURE_RECORD`
- an address stated by a held collateral slot that is longer than the 2,048 bytes a reference carries, a
  chain header stated as no bytes at all, an instant or a bound below zero, and a statement block spelled
  as text or as a list: `NOT_CAPTURE_RECORD`
- a record that claims a detached signature and does not carry one: `CAPTURE_SIGNATURE_NOT_CARRIED`
- a version the reader does not implement, in the record, in the policy or in the receipt format:
  `UNSUPPORTED_VERSION`, a `ReceiptError`, raised before any field is read
- a signature that does not hold over the stored bytes: `INVALID_SIGNATURE` or `KID_MISMATCH`
- a root the record relied on that is none of the caller's: `EVIDENCE_VERIFICATION_FAILED`
- a receipt or evidence stamp outside the caller's own window: `STALE_RECEIPT`, `STALE_EVIDENCE`
- a clock the caller handed that is not a whole number of seconds inside the span the reader weighs
  stamps in: `VERIFICATION_TIME_OUT_OF_RANGE`, a `ReceiptError`, raised before either window runs, so a
  caller who mixed the two scales is told about their reading rather than about the document

Every code that `packages/sdk/src/capture.ts` raises itself is refused by a row of
`packages/fixtures/data/capture-v1.json`: `packages/fixtures/test/capture-vectors.test.ts` reads those call sites out
of that file and requires a published row to reach every one of them, so a refusal added on the reader's side and
never vectored stops being invisible. The verifier's own codes are reached at the leg that runs it: `KID_MISMATCH`
at the row stating a caller whose pin for the kid the header names is another key, `STALE_RECEIPT` at the row
stating a clock past that caller's window, and `MALFORMED_CBOR` at the row stating the re-framed envelope as its own
original. Every code a row refuses with is one of the two error registries' declarations, which the same test reads
out of `packages/sdk/src/errors.ts` and `packages/receipt/src/errors.ts`.

This record's own refusals are two codes of `SdkErrorCode` rather than a borrowing of `NOT_RECEIPTED`,
which is the client's word for a gateway that answered without a receipt header and says nothing about a
file a reader was handed. The breadth of the first is still worth naming: `NOT_CAPTURE_RECORD` covers a
member that is absent, a member that is unnamed, a value of the wrong shape and a spelling no reader
reproduces, which is one word for "this record does not carry what it speaks of" where a caller may want
three. `EVIDENCE_DIGEST_MISMATCH` covers a length that disagrees as well as a digest that does, in an
original or in a chain. See `docs/error-codes.md` for what each code means at its own site.

And what it never does: return a pass. A verdict is `repeated`, `qualified` or `unassessed`. `unassessed`
is a refusal to conclude, and it is what a caller with no pinned key gets, what a collector that did not
take something in gets, and what a record whose appraisal precedes its acquisition gets. `repeated` is
reachable only when the signature leg ran against a key out of the caller's own policy, every context
member is `held`, and every named root matched one the caller pinned.

## Durability

`CaptureSink` is the interface a collector writes to, and its one promise is that `write` resolves after
the original bytes and the context are both durable, or rejects. No implementation ships in
`packages/sdk/src`: the honest one lives in `packages/sdk/test/capture-store.test.ts`, where it stages its
parts one at a time, can be made to give up at a named part, and shows that a failed write leaves the
bytes on disk and no acknowledgement anywhere. A retry of one capture is idempotent under
`captureRecordKey`, which is a digest of the record's canonical JSON, so two documents that say the same
thing are one record and a re-encoded original is a different one. What a collateral slot states about the
answer it holds is part of what the record says, so two captures that agree about every byte and disagree
about where the answer was asked, or about when it landed, are two records and a store holds both.

## What this record cannot support

It states no retention duty period, no compliance result, no count of retained documents, and no verdict
of any kind. It cannot show that bytes were produced by a genuine device: the vendor chain walk belongs to
`verifyCompletionEvidence`, which runs on the evidence document and the caller's own anchors and takes no
collateral input, and this record stores the bytes and the collateral slot beside them without handing either
to that walk; its own reader repeats the receipt leg and names the vendor leg as one it did not run. It
cannot show that the source was honest, only that one party said what it saw and when. It cannot make
custody into verification, and the reader is written so that a caller who wants that must notice the
difference in the verdict's own two halves.
