# Conformance vectors

Status: current for format versions 1. The payload carries one version, and it states seventeen members:
the twelve every receipt has always carried, the marking member, the disclosure of a stamped instant, the
anchor of an appraisal context, and the item list of a response. The receipt fixtures under
`data/receipts/` all carry that document, and `data/manifest.json` states beside each row the answer a
reader owes it. The files named here are the
contract a
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
| Receipt fixtures | `packages/fixtures/data/manifest.json` and `data/receipts/` | The COSE_Sign1 envelope, the payload field set of each version a row states, the response bytes and items a document attests, and the verdict a decoder owes each file | `version` in `manifest.json`, which is the manifest's own format version |
| Proof of possession | `packages/fixtures/data/pop-v1.json` | The signing string, the `Authorization` header built over it, and the signature that header carries | `version: 1` |
| Request digest | `packages/fixtures/data/req-v1.json` | The `req` a receipt claims, over exact request bytes | `version: 1` |
| Response digest | `packages/fixtures/data/res-v1.json` | The `res` a receipt claims, over exact response bytes including framing | `version: 1` |
| Marked region | `packages/fixtures/data/marking-v1.json` | The span inside a response that `mk.d` digests, in both shapes, and what a reader owes a response carrying too few, too many, or not the attested one | `version: 1` |
| Receipt store chain | `packages/fixtures/data/chain-v1.json` | The record frames a gateway writes to `receipts.log`, the state a reader derives from them, and what it refuses | `version: 1` |
| Technical export | `packages/fixtures/data/export-v1.json` | Whole export documents, the arguments a reader is handed beside each one, and the verdict a conforming reader owes it | `version: 1` |
| Sealed deployment manifest | `packages/fixtures/data/manifest-v1.json` | One deployment manifest in both shapes it is served in, the signing keys a reader designates beside it, and the verdict the client path owes each | `version: 1` |
| Evidence pack | `packages/fixtures/data/pack-v1.json` | Whole packs in the shapes a deployment hands them over in, the keys a reader designates beside each one, and the verdict the shipped pack reader owes: run and window reported apart, the references a pack signs for the material its sealed receipts name and one accepted pack carrying a served body beside the header that arrived with it, and an honest pack whose stamps run against its links accepted with a finding | `version: 1` |
| Redaction manifest | `packages/fixtures/data/redaction-v1.json` | Redaction manifests each beside the pack they are checked against, the verdict the shipped redaction reader owes the pair, and what `ashaveri verify-handover` answers for the same pair on every row: the chain over the survivors published apart from the pack's own head, a redaction pointed at a pack the reader lacks refused, and the three wrong constructions of a survivor chain refused by recomputation | `version: 1` |
| Epoch inventory | `packages/fixtures/data/epoch-inventory-v1.json` | Whole sealed inventories and the verdict the two shipped inventory readers owe each one: the envelope, the header, the key, the reading of a JSON payload, the arithmetic a reader recomputes over a run of packs, and the names each row of the two folded lists points at, with a refusal for every claim the reader recomputes over the run and answers from it, which is the windows meeting end to start, including one entry whose own two figures do not run forwards, the window, the two chain endpoints beside the run that begins and ends them, the claim each folded list states beside it, and every guard of both lists, and with the acceptances a reviewer would otherwise read as faults | `version: 1` |
| Capture record | `packages/fixtures/data/capture-v1.json` | Whole capture records and the answer the two published capture entry points give each one: one evidence document's exact original bytes held as they arrived beside the context stated with them, a signature re-framed by a second encoder refused as bytes rather than accepted as an equivalent, a context member left unmentioned refused rather than read as an absence, and a digest that is not the digest of the bytes beside it | `version: 1` |

`pop-v1.json`, `req-v1.json`, `res-v1.json`, `marking-v1.json`, `chain-v1.json`, `export-v1.json`,
`manifest-v1.json`, `pack-v1.json`, `redaction-v1.json`, `epoch-inventory-v1.json` and `capture-v1.json` each carry a
`description` stating their rule in prose, and the digest, marked-region, chain, export,
sealed-manifest, pack, redaction, inventory and capture suites carry a `rule` or `layout` block naming the fields,
and the widths and the byte order where a suite pins a byte layout, so a reader never has to guess what an
array of hex is standing for. The manifest carries no `description`, because it lists the receipt fixtures
rather than stating a rule of its own, and it does carry a `layout` block naming the columns its rows
state, the reader each of its two verdicts belongs to, and the encodings the columns are spelled in; what
the fixtures themselves are for is written in [receipt-spec.md](receipt-spec.md).

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
  `data/keys/receipt-key-v1.json` at the timestamp the entry's own payload carries. `expected` states the
  verdict that reading owes: `verify-ok`, or the error code a refusal has to answer with, and `keyless`
  states what the same bytes answer for a reader holding no key at all. The five entries this suite began
  with state no column beyond `expected` and the response bytes their documents digest; every row added
  since names the payload version its bytes
  claim in `v`, the marking setting its response came off in `marking`, the response bytes themselves, and
  the item list as the shipped reader of a response body gives them. Which versions those rows name, and
  how many of them state none, is the `layout` block's business and the tests' arithmetic, not this
  sentence's. Every row states its response bytes because every payload this format reads names a
  marking, and the region a marking attests is read out of the response rather than out of the document:
  a row that published no body would be a row no client path could be run over. The marked entry's `res` and `mk.d` are digests
  of the same bytes the marked-region suite publishes as `buffered-member`, so one response is read
  out of two files and a generator that drifted on either side disagrees here. Decoding that entry
  does not check its mark (no `.cbor` file carries the response), which is what the marked-region
  suite is for; a row that states its response bytes states the mark check too, because those bytes are
  published beside the document that digests them. An entry whose verdict is a refusal names in
  `fault.at` the position the shipped reader quotes when it answers those bytes, which is what makes the
  row about one member rather than about a document nobody could read. Two entries are deliberately not
  valid and predate the column: one signature is broken, one payload carries a measurement of a width its
  `tee` kind cannot hold, and a decoder that accepts either has not implemented the rule the accepted
  rows test.
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
  `foundRegionBase64Url`, which is `null` exactly where the published rule finds no single region, and
  is not the same thing as the empty region a `none` receipt names. Then hash what you found and compare
  to `dHex`. Two spans are published on purpose: `attestedRegionBase64Url` is the one whose digest the
  receipt carries, and `foundRegionBase64Url` is the one a reader locates in the bytes. They are equal
  for the cases that pass and differ, in one direction or the other, for every case that refuses. The
  suite is where the `exactly one` half of the rule is checkable: a port that resolves a response
  carrying the shape twice by taking the first match, or the last, or the longest, fails here and cannot
  fail anywhere else, because no other artifact in this repository states which it should have done.
  Each row also carries `client.receiptBase64Url`: a document issued under the published fixture key
  over exactly that response, with `res` the digest of the whole bytes and `mk.d` the digest of the
  span the row attests. That makes `expected` a verdict a client owes rather than only a reading of the
  rule, and it is how `MARK_MISMATCH` is reached at all. The marking check runs after the response
  digest is recomputed, so a row whose bytes do not hash to the digest its document claims cannot be
  refused for its mark; every refusing row here is bytes that do, holding a span that does not. The
  `buffered-member` document is byte for byte the committed `receipt-marked-v1.cbor`.
- **Store chain.** Each scenario states the writes it performed and the file they produced. Either
  reproduce it with your writer and compare the image byte for byte, or read the published image with
  your reader and compare what you derive (the head, the served set, the retention window and the
  chain state) against what the file states. The `records` table beside each image decomposes it
  into fields with their offsets. Each row states the byte its frame starts at and that frame's
  whole length, so a difference localizes to a width, an endianness or a coverage rule rather than
  to a whole file. `refusals` are images a reader objects to: one bit flipped in a payload, a record
  lifted out of the middle, a retirement written behind a receipt, and a frame lying about its
  length, which are bytes no writer produced. Two more show the rule that one log holds receipt
  records of one kind, and both are bytes a store did seal: an unbounded file with one bounded record
  appended behind it, refused for that appended record, and a published unbounded file untouched and
  read whole by a store configured for the bounded kind, refused for its first record. A refusal row
  states the receipt kind its opening writes wherever that is not the receipt kind, because a
  disagreement between a file and a configuration is not reproducible without the configuration. Each
  carries the refusal the reader gave, and your reader has to refuse them too. Its sentence may
  differ; the fact that it stops may not. `tails` states an append that never finished, which is the
  one case a reader repairs rather than refuses.
- **Technical export.** Decode the base64url document, hand your reader the arguments the case's `read`
  block states, which are the companion bytes it was given, the endpoints it already holds, and the key it
  used, and compare the answer with `verdict`: `verify-ok`, or the code the refusal has to answer with. Where
  the case states `item`, `outcome` or `walk`, the refusal has to name that item and the pass has to report
  that arm and that order. A case whose `read` block names no companion is read with none, which is what makes
  the missing-file answer separate from a digest disagreement. `crossReading` is the pair that keeps the two
  containers apart: an export manifest given to the pack layout, and a pack document given to the export
  reader.
- **Sealed deployment manifest.** Decode `documentBase64Url` and hand it to your reader with the keys the row's
  `read.designates` lists, which are the manifest signing keys a client holds: an id and the public half pinned
  under it, and a row naming none is the state where the reader designates nothing. Compare the answer with
  `verdict`. Where a row states `authentication`, those fields have to be what the reader reports and
  `advisory` says whether it hands over a reason as well; `parsed` states the whole document as the reader's own
  parser leaves it, and `dropped` names members that must appear nowhere in it. `seal` is the same bytes given to
  the envelope reader alone, verified under the key their own header names, and it is published beside
  `verdict` because the two layers refuse for different reasons: a row whose `seal` is `verify-ok` and whose
  `verdict` is a refusal shows a document a reader would not attribute rather than one that moved. `claims` are
  receipt epoch claims, stated as the shipped rule takes them and adjudicated against that row's parsed
  document. The `reveal` block of the first row carries the protected header, the payload bytes, the signature
  and the `Sig_structure` rebuilt from them, so a port can compare its framing without this repository's
  writer.
- **Evidence pack.** Decode `documentBase64Url` and hand it to your reader with the designation the row's `read`
  block states: `pinned` is the one key a caller holds, which answers the envelope and every receipt inside the
  container, `retained` is the set a resolver answers from, one key per kid, which is how the row whose span
  crosses a key rotation is read, and a row stating neither is the call that designated nothing. Compare the
  answer with `verdict`, and compare `structural` with what your reader says about the same bytes before it has
  accepted a signature: a row that is `verify-ok` there and a refusal here is refusing about a key or a signature,
  not about a manifest that contradicts itself. Where a row states `walk`, your reader has to reach that run, in
  the order the `prev` links fix it and not the order the array carried it; where it states `ordering`, those are
  the steps where the stamps disagree with the links, and a conforming reader reports them and accepts the pack.
  `records` and `attachedRecords` in the `layout` block give the predecessor and the record digest of each item of
  the two runs the suite frames, the honest run whose every slot of every sealed receipt states an absence and the
  run whose held slots name material the pack carries, and `framingRule` states which row each table sits beside and
  that both are read out of the sealed bytes of that row. A table is the pack's own reading of the framing `chain-v1.json` publishes for
  a store file, published for the runs a reader is handed whole so that an `itm` entry's digest has a stated answer
  beside it rather than only the bytes in the row. `attached` is the material a pack holds beside the
  references its sealed receipts name: recompute every stated digest from the bytes beside it, and resolve each
  `held` slot of each receipt inside the container against the reference that names it, so a reader holding a pack
  answers a slot without reaching a vendor endpoint. One accepted row fills that arm: `custody-served-weighed` attaches
  a served body beside the issuer-chain header that arrived with it, both made by the fixture vendor this repository
  generates and signed by keys read off labels, so a port that writes that vendor's root to a file can weigh the pair
  its reference names rather than only check a structure wrapped around bytes nothing can open. Every other accepted
  row attaches nothing and is whole, which is the shape no path a deployment runs departs from.
  `custodyRule` in the `layout` block states the whole of it,
  including the two ceilings and the requirement that the list and the slots speak of the same material: an entry
  misstating its own bytes, one digest at two positions, an entry no held slot names and a slot no entry hashes to
  are each refused, and each refusal names the position it found. A slot that states an absence names no digest and
  owes no bytes, so a pack carrying nothing beside receipts that took nothing in is accepted rather than short.
- **Redaction manifest.** Decode `documentBase64Url`, hand your reader the pack in `packBase64Url` beside the
  designation the row's `read` block states, and compare the answer with `verdict`. A row stating no pack is the
  reader that was handed one document of the pair and has to refuse it rather than accept the statement on its own
  word. Recompute `packBase64Url`'s sha256 and compare it with the manifest's `pack` member: the designation is a
  digest of the pack's whole bytes, and a reader that resolved a name instead has not checked which pack the
  removal was stated about. Where a row states `survivors`, your reader has to reach that run in the order the
  pack's `prev` links fix it, having dropped the named records; `reducedHex` is the head of the chain over those
  survivors, relinked from the pack's own anchor by the framing section 5.2 states, and `originalHeadHex` is the
  pack's signed head. The last two are never equal on an accepted row, and a reader that reports one number where
  the other belongs has merged two findings this suite publishes apart. `run` and `records` in the `layout` block
  give each record's predecessor in the pack, the predecessor the reduced chain used instead, and the digest that
  came out, so the construction is checkable against the pack's bytes rather than restated from a writer.
  Each row states its fact at two entry points and the file gives both answers. `verdict` and `structural` are the
  library's, and `verdict` carries the code the format names for the fault, because the reader is where the
  format's rules live. `command` is what `ashaveri verify-handover` answers over the same bytes and the same pack,
  and it is published because a command line and a library call do not always meet a fault at the same step. This
  tool files every `--key` under the id its own bytes hash to, which is the only designation a command line can
  make: it cannot hand a reader one key to answer for every document in the pair, so a document naming another kid
  meets a set holding nothing for it, and it reads label 3 and chooses a reader before a redaction reader is
  consulted, so it can state the same fact one step earlier with the code the classification already uses.
  `command: null` says the command says what `verdict` says, exiting 0 on an accepted row and 1 on a refusal.
  Seven rows carry an object instead, counting them out of the published `command` member, and none of them is
  the tool disagreeing with the library.
  `rotation-read-with-one-pinned-key` and `sealed-under-another-deployment-key` are the two where the row pins one
  key for the whole pair while a document inside that pair names a different kid, which a set matched on each kid
  answers as a kid nothing designates rather than as the receipt's or the envelope's own refusal.
  `no-designation-at-all` is the call that handed no key, which this tool refuses as the gap in the call with exit
  2, naming it `usage`. That word is the name this tool gives the exit a refused call leaves, and not a member of
  any `*ErrorCode` union that `docs/error-codes.md` lists. `protected-content-type-of-a-pack` and
  `protected-content-type-of-a-receipt` are documents wearing
  another container's type, which the dispatch answers by running that container's reader, so `PACK_BAD_MANIFEST`
  and `BAD_PAYLOAD` rather than the header refusal the redaction reader would give. And
  `protected-kid-of-another-width` and `document-truncated-mid-envelope` are refused by the classification on the
  envelope, `BAD_PROTECTED_HEADER` and `MALFORMED_CBOR`, before a reader of either kind is chosen. The 43 rows
  `redaction-v1.json` publishes are replayed through this path by `packages/cli/test/verify-handover.test.ts`,
  which reads the expected answers out of this member rather than keeping a table of its own. That count, and
  the seven above it, are counts of the published rows which
  `packages/fixtures/test/redaction-vectors.test.ts` takes out of them rather than restating them here.

- **Epoch inventory.** Decode `documentBase64Url` and hand it to your reader with the designation the row's
  `read` block states: `pinned` is the one key a caller holds, which answers whatever kid the header names,
  `retained` is the set a resolver answers from, one public half per kid, and a row stating neither is the call
  that designated nothing. A row may also state `read.presence`, which is not about a key: the run's retention
  artifacts as the bytes that sit on the volume, in the order the call hands them, and the reader folds from them
  the interval across which the store reported holding the appraisal context. Hand them and you get that reading;
  hand nothing and you get the reading of the document alone, which is what makes a row
  that is `verify-ok` under one call and a refusal under the other a statement about the pair of inputs rather
  than about the bytes. Compare the answer with `verdict`, and compare `structural` with what your reader
  says about the same bytes before it has accepted a signature: a row that is `verify-ok` there and a refusal
  here is refusing about a key, a signature or the arithmetic over a run, and not about a document that
  contradicts itself. Where a row states `readback`, those are the figures a reader has to hand back as well:
  `runFiles` is the run in the order the entries' own figures put them, which is not necessarily the order
  `statedFiles` arrived in, because position in `packs` carries no claim. Two rows state an `edit` block: the
  same span of the honest document's text replaced with a longer run label, which is the pair differing by one
  byte at one position, one accepted and one refused. Every refusing row carries the sentence this reader gave,
  and a conforming port owes the same code while its wording may differ.
- **Epoch inventory refusals are near misses at two sites.** The two lists a run folds, `chain.breaks` and
  `duty.short`, are guarded apart rather than by one routine, so each fault a list can carry is stated at both
  sites and a refusing row names its site and the guard of that site it reaches: a claim of continuity or of
  carrying contradicted by the list beside it, a list longer than the arithmetic, a list shorter than it, two
  rows naming one pack while another is named nowhere, a row about a pack the run does not hold, a row naming
  a pack the run holds whose own figures carry no such finding, and a row of the right name whose own two
  digests or four figures are not the pair's or the pack's. The lists are keyed by the pack each row names,
  which is why the two rows stating a reversed list are acceptances, and the refusal rows beside them are
  what prove the keying is live rather than absent.
- **Capture record.** A capture record is a JSON document and it is published inline, as the object the reader is
  handed, because a capture's claim about bytes lives inside its members rather than in the spelling of the document
  holding them. Hand the record to `parseCaptureRecord` for the layout's answer and to `assessCapture` for the
  reading's, beside the caller's own pins, its own pinned roots and the clock the row's `read` block states, and
  compare what comes back with the row. `capture-v1.json` publishes 19 accepted rows and 39 refusals, and 8 of the
  refusals state one fact a held collateral slot leaves out, one per member, each naming the member it found missing.
  Where a refused row states `stage`, that is which of the two published steps answered: `layout` where the record
  itself was refused, which `assessCapture` then refuses with the same code because it parses first, and `reading`
  where the record is whole and the answer came from a held slot's recomputed bytes, the signature leg, the pinned
  roots, or the clock. `status` is one of the three a verdict has: `repeated`, `qualified`, `unassessed`. `stated` is
  the record's claim about the bytes it held and `repeated` is what this reader established over them, published
  apart because a verdict carrying one word would let the claim be read as the finding. The original bytes of every
  row but 4 are the document `data/receipts/receipt-valid-v1.cbor` publishes, and
  `packages/fixtures/test/capture-vectors.test.ts` requires each of the rest to be that file byte for byte while
  reading that count out of this sentence rather than keeping its own, so a capture in this suite is of evidence the
  repository already seals. The four that state other bytes say which: the deployment manifest, the receipt with one
  bit changed inside it, and the re-framed envelope stated twice, once against the digest of the document the source
  produced and once as its own original.
  The one bound this suite measures rather than quotes is the address a collateral slot states: a row at 2,048 bytes
  of UTF-8 is taken and a row at 2,049 is refused. The key material this file publishes is public halves and kids;
  the private half beside them is the one `data/keys/receipt-key-v1.json` already publishes, which the last section
  of this document names.

## Every suite refuses something

Each of the twelve suites the table above lists carries at least one case whose stated verdict is a refusal,
and every code those cases name is one [error-codes.md](error-codes.md) lists. The twelve are that table's
rows, which `packages/fixtures/test/vectors-doc.test.ts` counts and compares with this sentence rather than
trusting it. That is the half a second implementation cannot agree with by accident: an accepted case and
a refused one, drawn from the same
bytes, differ in exactly the rule under test, and a port wrong in the same direction as this one still
has to answer the refusal with the code the row names. A case that fails for some other reason than the
one stated is a wrong vector, and the row's note says which fact it turns on.

The refusals are near misses rather than garbage on purpose. A digest is off by one byte, a signature by
two characters, a nonce by a single byte width, a marked span by one field of one member, a store record
by one bit inside its own bytes or by its length prefix lying about its size, a protected header by the one
label it added or the one integer it spelled as a float, a redaction by the one record it did not name or by
the chain head it took from the pack rather than recomputed, an inventory by the one byte at the end of its run
label or by the one row a folded list left out, a capture record by the one bit inside its original, by the
other base64url spelling of the very same bytes, or by the one member of an eight-member statement left unspoken.
Each is one small edit to
bytes this repository already publishes, so reproducing it is reading a row and not guessing at what the
author meant. The client path over them is in `packages/cli/test/vector-conformance.test.ts`, which
drives every suite in this table but the technical export and the capture record through the shipped
verification code rather than
through a copy of the rule it is checking, and asserts the verdict in both directions: the accepted rows
accepted, the refusing ones refused for the reason stated. The export suite travels the client path
through `packages/cli/test/verify-handover.test.ts` instead, beside the command's own cases. The capture
rows are read by the two published capture entry points themselves, `parseCaptureRecord` and `assessCapture` of
`@ashaveri/sdk`, in `packages/fixtures/test/capture-vectors.test.ts`, because those two are the shipped reading of
this format and no command of this package reads a capture record. The inventory
rows are read there by the two exported inventory readers, `verifyEpochInventory` and
`decodeEpochInventory`, rather than through a command, because the claim a port has to satisfy at those two
doors is about the library surface, and that block names the file which answers the same rows at the command
edge. Two verbs reach an epoch inventory at this command line: `ashaveri verify-handover`, which takes the type
out of the document's own protected header, and `ashaveri verify-epoch-inventory`, which is that same dispatch
with the type pinned to one value. Those rows are therefore witnessed three times over the same published
bytes: by `packages/fixtures/test/epoch-inventory-vectors.test.ts`, which reads the format package's own
reader, by the consumer's path named above, and by `packages/cli/test/epoch-inventory-at-the-command-edge.test.ts`,
which replays every row through `ashaveri verify-handover` and holds the pinned verb's report against that one
on the rows it names.

## Regenerating

```sh
pnpm --filter @ashaveri/fixtures generate
pnpm --filter @ashaveri/fixtures generate:pop
pnpm --filter @ashaveri/fixtures generate:req
pnpm --filter @ashaveri/fixtures generate:res
pnpm --filter @ashaveri/fixtures generate:marking
pnpm --filter @ashaveri/fixtures generate:chain
pnpm --filter @ashaveri/fixtures generate:export
pnpm --filter @ashaveri/fixtures generate:manifest
pnpm --filter @ashaveri/fixtures generate:pack
pnpm --filter @ashaveri/fixtures generate:redaction
pnpm --filter @ashaveri/fixtures generate:epoch-inventory
pnpm --filter @ashaveri/fixtures generate:capture
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
  `data/keys/receipt-key-v1.json`, in `pop-v1.json`, in `export-v1.json`, in `manifest-v1.json`, in
  `pack-v1.json`, in `redaction-v1.json`, in `epoch-inventory-v1.json` and in the `layout.keyMaterial` of
  `capture-v1.json` are test-only, labelled as such in the files themselves, and protect nothing. A port that
  verifies against them has exercised its verifier, not appraised a deployment.
- Nothing here touches attestation. Evidence documents, platform roots, device certificate chains and
  the measurements they name are checked against vendor anchors no file in this directory holds, and
  a byte-exact reimplementation of every suite in `data/` is compatible with a deployment that should
  not be trusted at all.
- A passing port is not a certified port. It is a reimplementation that agrees with this one on the
  cases chosen here, which for the one payload version are the field set, the digests and the framing,
  the marking member, the disclosure of the source
  an instant came from, the anchor of the context an appraisal ran on, the list of items a response
  was made of, and the count of those anchor slots a client's policy demands be stated as taken in,
  which the receipt suite publishes as the verdict its reader gives under each posture rather than as a
  rule about bytes. Those cases are examples of where
  implementations have been known to differ rather than an exhaustive sweep of the format's state
  space. Conformance to bytes and soundness of judgement are different claims, and only the first is
  testable this way.
- The store chain vectors pin a file format and the retention behaviour those vectors exercise: a
  count cap, an age bound, a compaction, a repair. They do not commit anyone to a retention period,
  and what a deployment promises to keep is stated where retention is stated, not here.
