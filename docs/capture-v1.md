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
| `held` | the bytes arrived and this record carries them | the slot is checked, digests recomputed |
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
| `acquired.at` | our clock when the bytes were taken in | how the collector dates its own custody | that the bytes were made then, which is what `sourceStatedAt` claims |
| `acquired.sourceStatedAt` | the timestamp the source claimed, or none | that the two stamps agree, or that the record says how they do not | that either is right |
| `manifests.deployment` | the manifest the source served, as served | which pins were in force at that instant, from a document rather than a summary | that the manifest was this deployment's: the record authenticates nothing, and a sealed manifest is only attributed by a reader that holds the key that signed it |
| `check.policyVersion`, `policyDigest` | which policy rules, and the digest of the document used | which pins the check read, given the document | that the check was right to read them |
| `check.receiptFormatVersion` | which receipt version the check read | that a reader reads the bytes at the version named and refuses one it does not | that the version was current, which it need not be |
| `check.verifierVersion` | which verifier build ran | which procedure produced the context | that the procedure was correct |
| `check.appraisedAt` | when the appraisal ran, on our clock | that the appraisal could have seen these bytes | anything about validity, which lives in `context.validity` |
| `context.collateral` | the vendor chain the bytes were appraised against | that a verdict about the signature has something to stand on | that the chain was this platform's |
| `context.validity` | the window and the appraisal recorded | that the verdict is about a window rather than forever | that the window was open when it says it was, which a reader cannot re-run |
| `trust.roots` | which references the check believed | that a caller who pinned the same bytes can agree, and one who pinned others is refused | that an unnamed or unpinned root was any root in particular |
| `trust.limits` | how far the check let a clock sit from the bytes | that the verdict was reached under a window this caller would accept | a pass. The reader runs its own windows and reports a difference |

## What the reader refuses

`parseCaptureRecord` and `assessCapture` refuse, each with a code a log line can carry:

- bytes that do not hash to the digest the record states, and a length that does not match the bytes
  beside it: `EVIDENCE_DIGEST_MISMATCH`
- a member no version defines, a context member nobody declared, and bytes spelled in a base64url
  form no reader reproduces: `NOT_CAPTURE_RECORD`
- a record that claims a detached signature and does not carry one: `CAPTURE_SIGNATURE_NOT_CARRIED`
- a version the reader does not implement, in the record, in the policy or in the receipt format:
  `UNSUPPORTED_VERSION`, a `ReceiptError`, raised before any field is read
- a signature that does not hold over the stored bytes: `INVALID_SIGNATURE` or `KID_MISMATCH`
- a root the record relied on that is none of the caller's: `EVIDENCE_VERIFICATION_FAILED`
- a receipt or evidence stamp outside the caller's own window: `STALE_RECEIPT`, `STALE_EVIDENCE`

Two codes were added to `SdkErrorCode` for this record rather than borrowing `NOT_RECEIPTED`, which is
the client's word for a gateway that answered without a receipt header and says nothing about a file a
reader was handed. The remaining breadth is still worth naming: `NOT_CAPTURE_RECORD` covers a member that
is absent, a member that is unnamed, a value of the wrong shape and a spelling no reader reproduces, which
is one word for "this record does not carry what it speaks of" where a caller may want three.
`EVIDENCE_DIGEST_MISMATCH` covers a length that disagrees as well as a digest that does. See `docs/error-codes.md` for what each existing code means at its own site.

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
thing are one record and a re-encoded original is a different one.

## What this record cannot support

It states no retention duty period, no compliance result, no count of retained documents, and no verdict
of any kind. It cannot show that bytes were produced by a genuine device: the vendor chain walk belongs to
`verifyCompletionEvidence`, and this record hands that walk the bytes and the collateral it is about. It
cannot show that the source was honest, only that one party said what it saw and when. It cannot make
custody into verification, and the reader is written so that a caller who wants that must notice the
difference in the verdict's own two halves.
