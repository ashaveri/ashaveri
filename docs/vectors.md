# Conformance vectors

Status: current for format versions 1 and 2. Version 1 is what four of the receipt fixtures carry and
what every other suite here measures; version 2 arrives with the marking member, and what these files
hold of it is the one v2 receipt fixture plus the v2 document each marked-region case publishes beside
its bytes, which is still no v2 field beyond `mk`. The files named here are the contract a
reimplementation is measured against, and this document says what each one states, how to consume it,
and what a disagreement means. The formats themselves are specified in
[receipt-spec.md](receipt-spec.md), [access-control.md](access-control.md) and the CDDL; a vector
never overrides a specification, and where the two appear to disagree that is a defect to report.

Everything published here is machine-generated from the TypeScript implementation, in JSON, one
file per suite, each carrying its own `version`. Nothing is hand-edited: every digest, key and frame
in these files is what the code produced, so a file records behaviour rather than somebody's
description of it. `@ashaveri/fixtures` holds them, and its loaders are the reference reading of
each shape.

## The suites

| Suite | File | What it pins | Version field |
|---|---|---|---|
| Receipt fixtures | `packages/fixtures/data/manifest.json` and `data/receipts/` | The COSE_Sign1 envelope, the payload field set, and the verdict a decoder owes each file | `version` in `manifest.json`, which is the manifest's own format version |
| Proof of possession | `packages/fixtures/data/pop-v1.json` | The signing string, the `Authorization` header built over it, and the signature that header carries | `version: 1` |
| Request digest | `packages/fixtures/data/req-v1.json` | The `req` a receipt claims, over exact request bytes | `version: 1` |
| Response digest | `packages/fixtures/data/res-v1.json` | The `res` a receipt claims, over exact response bytes including framing | `version: 1` |
| Marked region | `packages/fixtures/data/marking-v1.json` | The span inside a response that `mk.d` digests, in both shapes, and what a reader owes a response carrying too few, too many, or not the attested one | `version: 1` |
| Receipt store chain | `packages/fixtures/data/chain-v1.json` | The record frames a gateway writes to `receipts.log`, the state a reader derives from them, and what it refuses | `version: 1` |
| Technical export | `packages/fixtures/data/export-v1.json` | Whole export documents, the arguments a reader is handed beside each one, and the verdict a conforming reader owes it | `version: 1` |

`pop-v1.json`, `req-v1.json`, `res-v1.json`, `marking-v1.json`, `chain-v1.json` and `export-v1.json` each
carry a `description` stating their rule in prose, and the digest, marked-region, chain and export suites
carry a `rule` or `layout` block naming the fields, and the widths and the byte order where a suite pins a
byte layout, so a reader never has to guess what an array of hex is standing for. The manifest
carries no `description`, because it lists the receipt fixtures rather than stating a rule of its
own; what they are for is written in
[receipt-spec.md](receipt-spec.md).

## How to consume a suite

Read the file, and refuse a `version` you do not implement rather than reading it as your own: that
is the whole compatibility contract of this format, and it applies to these files as much as to a
receipt. Then, per vector: decode the published inputs, run your implementation over them, and
compare bytes rather than renderings. Two encodings appear throughout, matching the precedent set by
`pop-v1.json`: byte strings are unpadded base64url, digests and fixed-width fields are lowercase hex.
Report a failure by vector name, because a suite fails in one place for a reason that is usually
specific to that case.

- **Receipt fixtures.** Read `manifest.json`, and for each entry take the `.cbor` bytes, check their
  sha256 against `digestSha256`, decode them, and give the decoder the published key from
  `data/keys/receipt-key-v1.json` at the timestamp the entry's own payload carries. The `expected`
  field states the verdict: `verify-ok`, or the error code a refusal has to answer with. Four entries
  are v1 documents and the fifth is a v2 carrying a marking member. Its `res` and `mk.d` are digests
  of the same bytes the marked-region suite publishes as `buffered-member`, so one response is read
  out of two files and a generator that drifted on either side disagrees here. Decoding that entry
  does not check its mark — no `.cbor` file carries the response — which is what the marked-region
  suite is for. Two entries are deliberately not valid — one signature is broken, one payload carries
  a measurement of a width its `tee` kind cannot hold — and a decoder that accepts either has not
  implemented the rule the other three test.
- **Proof of possession.** Rebuild the signing string from the published fields, verify the signature
  in `authorization` against `key.publicKeyHex`, and check the header parses to the same three
  components. The private half is published too, so a port can produce the signatures itself rather
  than only checking them. The fixed `ts` these vectors carry is a reproducibility value and sits
  outside any freshness window, which the file states: check the signature, not the clock. `refusals`
  are near misses built out of the vectors above rather than junk: a header with two characters taken
  off its signature, one opening on a scheme token that names another version, and a nonce one byte
  narrow. Each states which shipped step answers it, the signer before a header exists or the parser
  after one does, and the code that step throws.
- **Request digest.** For each vector, hash `bodyBase64Url` and compare to `reqHex`. The set is
  chosen where ports go wrong: an empty body, a body whose content is multi-byte, a body carrying
  escape sequences, and a pair of bodies that parse to the same JSON object and still differ in
  `req`. The `req` of the completion body here is also the digest `pop-v1.json` puts in that
  request's signing string, so the two files check each other. `refusals` are the same bytes read the
  wrong way round: each row names one vector whose body a client holds and another whose digest is
  signed into the receipt beside it, and the code a client owes that pair is `REQUEST_HASH_MISMATCH`.
  Two bodies that a JSON reader cannot tell apart are what the first of those rows is made of, and a
  request differing from another by one member is the second.
- **Response digest.** Concatenate `chunksBase64Url` in order, or take `responseBase64Url`, which the
  file states is the same byte string, hash it, and compare to `resHex`. Then, if you can: serve
  those bytes from a gateway of your own and read the digest out of the receipt it signs. The framing
  is inside the hash, so a streamed vector's bytes carry every `data:` prefix, every blank-line
  separator and the terminating `data: [DONE]` line. Two entries exist to make that checkable rather
  than asserted: the same payload text with and without its framing, two byte strings and two
  digests, and a pair of entries whose bytes are identical but whose write boundaries fall inside a
  multi-byte character, which carry one digest because the digest is of the stream. `refusals` publish
  the two ways that goes wrong against a signed receipt: a framed stream presented to a document
  attesting its payloads stripped of their framing, and a body presented to one attesting it without
  its last byte. Both answer `RESPONSE_HASH_MISMATCH`, and each row also states that the other body,
  the one the receipt does attest, is accepted.
- **Marked region.** For each vector, take `responseBase64Url` as the bytes a client holds, run your
  own reading of the rule for the label in `sch`, and compare what you locate against
  `foundRegionBase64Url` — which is `null` exactly where the published rule finds no single region, and
  is not the same thing as the empty region a `none` receipt names. Then hash what you found and compare
  to `dHex`. Two spans are published on purpose: `attestedRegionBase64Url` is the one whose digest the
  receipt carries, and `foundRegionBase64Url` is the one a reader locates in the bytes. They are equal
  for the cases that pass and differ, in one direction or the other, for every case that refuses. The
  suite is where the `exactly one` half of the rule is checkable: a port that resolves a response
  carrying the shape twice by taking the first match, or the last, or the longest, fails here and cannot
  fail anywhere else, because no other artifact in this repository states which it should have done.
  Each row also carries `client.receiptBase64Url`: a v2 document issued under the published fixture key
  over exactly that response, with `res` the digest of the whole bytes and `mk.d` the digest of the
  span the row attests. That makes `expected` a verdict a client owes rather than only a reading of the
  rule, and it is how `MARK_MISMATCH` is reached at all. The marking check runs after the response
  digest is recomputed, so a row whose bytes do not hash to the digest its document claims cannot be
  refused for its mark; every refusing row here is bytes that do, holding a span that does not. The
  `buffered-member` document is byte for byte the committed `receipt-marked-v2.cbor`.
- **Store chain.** Each scenario states the writes it performed and the file they produced. Either
  reproduce it with your writer and compare the image byte for byte, or read the published image with
  your reader and compare what you derive — the head, the served set, the retention window and the
  chain state — against what the file states. The `records` table beside each image decomposes it
  into fields with their offsets — each row states the byte its frame starts at and that frame's
  whole length — so a difference localizes to a width, an endianness or a coverage rule rather than
  to a whole file. `refusals` are images no writer produced: one bit flipped in a payload, a record
  lifted out of the middle, a retirement written behind a receipt, and a frame lying about its
  length. Each carries the refusal the reader gave, and your reader has to refuse them too. Its
  sentence may differ; the fact that it stops may not. `tails` states an append that never finished,
  which is the one case a reader repairs rather than refuses.
- **Technical export.** Decode the base64url document, hand your reader the arguments the case's `read`
  block states, which are the companion bytes it was given, the endpoints it already holds, and the key it
  used, and compare the answer with `verdict`: `verify-ok`, or the code the refusal has to answer with. Where
  the case states `item`, `outcome` or `walk`, the refusal has to name that item and the pass has to report
  that arm and that order. A case whose `read` block names no companion is read with none, which is what makes
  the missing-file answer separate from a digest disagreement. `crossReading` is the pair that keeps the two
  containers apart: an export manifest given to the pack layout, and a pack document given to the export
  reader.

## Every suite refuses something

Each of the seven suites published here carries at least one case whose stated verdict is a refusal, and
every code those cases name is one [error-codes.md](error-codes.md) lists. That is the half a second
implementation cannot agree with by accident: an accepted case and a refused one, drawn from the same
bytes, differ in exactly the rule under test, and a port wrong in the same direction as this one still
has to answer the refusal with the code the row names. A case that fails for some other reason than the
one stated is a wrong vector, and the row's note says which fact it turns on.

The refusals are near misses rather than garbage on purpose. A digest is off by one byte, a signature by
two characters, a nonce by a single byte width, a marked span by one field of one member, a store record
by one bit inside its own bytes or by its length prefix lying about its size. Each is one small edit to
bytes this repository already publishes, so reproducing it is reading a row and not guessing at what the
author meant. The client path over them is in `packages/cli/test/vector-conformance.test.ts`, which
drives each suite through the shipped verification code rather than through a copy of the rule it is
checking, and asserts the verdict in both directions: the accepted rows accepted, the refusing ones
refused for the reason stated.

## Regenerating

```sh
pnpm --filter @ashaveri/fixtures generate
pnpm --filter @ashaveri/fixtures generate:pop
pnpm --filter @ashaveri/fixtures generate:req
pnpm --filter @ashaveri/fixtures generate:res
pnpm --filter @ashaveri/fixtures generate:marking
pnpm --filter @ashaveri/fixtures generate:chain
pnpm --filter @ashaveri/fixtures generate:export
```

The generators live beside the loaders in `packages/fixtures`, and running all of them after a change
to anything they publish has to leave the working tree clean; that is a check in CI, so a published
file cannot quietly fall behind the code it records. The chain generator is the one with a volume in
it: it writes real stores in a temporary directory and publishes what came back off disk.

## What a mismatch means

A single failing vector is a difference in your implementation, not a family of them, and the shape
of the difference usually says where:

- **A digest of a body or a response differs.** You hashed something other than the bytes on the
  wire: a re-serialization after parsing, a decoded text form, a body with a trailing byte you
  trimmed, or a stream hashed a write at a time instead of as a whole.
- **`req` differs between this suite and `pop-v1.json` for one body.** You have two code paths to the
  same hash and they are not fed the same bytes.
- **A chain image differs by its first bytes, or by an alignment you can see.** `len` covers `kind`
  through `digest` and nothing else, every integer is unsigned big-endian, and the digest is taken
  over everything between the length prefix and itself. Most layout disagreements are one of those
  three.
- **A marked region is located but does not hash, or is not located at all.** The region is a span of
  the response's bytes and nothing else: a stream's line is published without its terminator, a
  buffered member is published with its quotes and its colon, and a body whose content is multi-byte
  sits ahead of it counting in bytes. A port that re-serializes a member from a parsed object has
  hashed different bytes and will fail the buffered cases while passing everything else.
- **A refusal is accepted.** Your reader checks a record's digest and not the chain, or checks the
  chain and not the record's own bytes, or treats a retirement as position-independent. This is the
  class of mismatch that matters most: a reader that accepts these images cannot tell an operator
  that a receipt was removed.
- **Everything matches except one encoding.** Unpadded base64url, lowercase hex, and no separator
  characters in either. A port that emits padded base64url or uppercase hex has not failed the
  format, only the reading of it.

If you believe a published vector is wrong, that is an argument to bring to this repository, and not
something to work around in a port. Until it is settled, the file is the contract and your
implementation is the deviation.

## The limit of what this proves

These vectors check bytes. They say nothing about trust:

- Nothing here establishes that a key belongs to anybody. The signing keys published in
  `data/keys/receipt-key-v1.json`, in `pop-v1.json` and in `export-v1.json` are test-only, labelled as such
  in the files themselves, and protect nothing. A port that verifies against them has exercised its
  verifier, not appraised a deployment.
- Nothing here touches attestation. Evidence documents, platform roots, device certificate chains and
  the measurements they name are checked against vendor anchors no file in this directory holds, and
  a byte-exact reimplementation of every suite in `data/` is compatible with a deployment that should
  not be trusted at all.
- A passing port is not a certified port. It is a reimplementation that agrees with this one on the
  cases chosen here, which for payload version 1 are the field set, the digests and the framing, and
  for version 2 are the marking member and nothing else. Those cases are examples of where
  implementations have been known to differ rather than an exhaustive sweep of the format's state
  space. Conformance to bytes and soundness of judgement are different claims, and only the first is
  testable this way.
- The store chain vectors pin a file format and the retention behaviour those vectors exercise: a
  count cap, an age bound, a compaction, a repair. They do not commit anyone to a retention period,
  and what a deployment promises to keep is stated where retention is stated, not here.
