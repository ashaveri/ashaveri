# Epoch inventory, version 1

Status: current for epoch inventory version 1. The normative statement of the container is
[`packages/receipt/epoch-inventory.cddl`](../packages/receipt/epoch-inventory.cddl); its JSON twin is
[`packages/receipt/schemas/epoch-inventory-v1.schema.json`](../packages/receipt/schemas/epoch-inventory-v1.schema.json),
whose identity is `https://ashaveri.com/schemas/epoch-inventory-v1.json`. The table below is the same layout as
the twin, and `packages/fixtures/test/epoch-inventory-doc.test.ts` holds the two against each other in both
directions: every row resolves to a member the twin defines, with the type and the required-ness the twin gives
it, and every member the twin defines appears as a row. Where a sentence here and the CDDL disagree, the CDDL is
the authority and this prose is wrong.

## What this document is

An epoch inventory is a deployment's statement about a closed run of packs: which windows it sealed, what each
pack in the run says, and what the run adds up to. A deployment retires receipts out of its live store on the
bounds it configures, and an epoch is what survives that, a directory holding one sealed pack and one retention
artifact per closed window with this document at its root. It is the only artifact of an epoch a reviewer can be
handed alone, so everything in it is a figure the reviewer can re-derive from the packs beside it, and
everything the reader refuses is a place where the document's own statements do not agree with each other.

The layout is published here and the generator that fills it runs on the paid side of this repository's
boundary, and that split is the estate's claim about itself. A customer's auditor checks what a verdict means
using only public code and no service of ours in the loop, so the document an auditor can be handed has to have
its format, its reader and its arithmetic in the same repository as the receipt format. An inventory a reviewer
could not check without us would be a receipt of the deployment's own word.

One thing this container is not: a fifth account of what a pack attests. A pack says that the receipts inside
one window are all of them and carries the chain endpoints a reader walks between. An inventory says which packs
a run contains and what they add up to across windows, and it carries no receipts, no chain to walk and no item
to check. The two are different claims about different sets of bytes, which is why they carry two content types.

## The envelope

The framing is section 2 of [receipt-spec.md](receipt-spec.md), reused unchanged but for the content type: a
COSE_Sign1 (RFC 9052 section 4.2), tagged CBOR tag 18, encoded with Core Deterministic Encoding (RFC 8949
section 4.2.1), with a signature over the `Sig_structure` `["Signature1", protected, external_aad, payload]` and
an empty external AAD.

The protected header contains exactly three parameters, and the list is exhaustive rather than illustrative:

| Label | Name | Value |
|---|---|---|
| 1 | alg | -8 (EdDSA, Ed25519 per RFC 8032) |
| 3 | typ | `ashaveri/epoch-inventory` |
| 4 | kid | 32-byte key id, sha256 of the Ed25519 public key |

Those bytes are hashed into the `Sig_structure`, so a label this table does not name is a parameter the issuer
authenticated, and a reader that took the three it knows and returned those would hand its caller a document
other than the one that was signed. An inventory whose header carries another label is refused and the refusal
names the label. The content type at label 3 is answered before the key parameters and before any member of the
payload: a header whose `typ` is the pack's, the export's or the receipt's is refused there, because each of
those documents passes its own checks and the confusion is not recoverable afterwards.

The payload is the JSON document, as UTF-8, signed byte for byte: no re-encode, no key order chosen by the
sealer, no whitespace decision. That is how a sealed deployment manifest carries its JSON, and for the same
reason. The file an operator leaves in the epoch directory and hands over is a JSON file, and the only way a
reviewer's verdict means something about the bytes read is for the signature to cover those bytes rather than a
canonical rendering of them. A deployment that reformats its own inventory has to reseal it, which is an
operator-visible fact rather than a promise about a serializer.

The map outside the signature is the one the format leaves open: `{ * any => any }`, the map that carries no
claim. Its emptiness is not enforced, because enforcing it would add a refusal with nothing behind it.

## Reading a document of this shape

Two rules belong to the JSON reading rather than to any one member, and the reader enforces both while it is
still reading characters, because afterwards there is nothing left to enforce them on.

No member name appears twice. A parser keeps the last of two values and says nothing, so a payload naming
`packs` twice would read as whichever list the parser reached last while the signed bytes carry both. The
closure rule below already refuses a member this version does not define; this one refuses a member defined
twice, which is the same loss of the writer's intent arrived at from the other side.

Every number is written as an integer, and a reader of this document holds it exactly: `1.0`, `1e2`, `+1`, `01`
and `-0` are refused as spellings rather than read as the numbers they equal. That is the rule every other
signed container in this estate states as "no floating-point number may appear", arrived at through the encoding
this one uses, and it is the same trap: the integer and its float imitation arrive at a check as one value, and
by then nothing can say which the issuer wrote.

## The document

The payload is a closed map at `v: 1`: a member the version a document names does not define makes the document
malformed rather than a document read with that member dropped. That holds of every block below, so a `packs`
entry cannot be read with the `shortfall` block's members and the two digests fall out on the way to a reader.
Every member of every map is required, so no position is optional, none carries a default, and a reader never
has to work out what an omitted field meant.

Byte strings are projected as lowercase hex in the twin and in a document's JSON text, which is how the writer
states every digest, key id and chain endpoint in this container. A byte ceiling belongs to the CDDL: a JSON
string length is a different measure, so the projections state the floor and not the limit.

The CDDL states one byte ceiling, on `epoch`, because the run's label is the only text this container writes
for itself rather than copies, and it is printed beside the run in every report of it. The rest of the text
positions travel from documents that bound them by nothing above one byte: the deployment's two ids, as that
manifest's own schema declares them, and the duty label a pack signs, as `pack.cddl` declares it. A ceiling
written on this side would refuse an inventory whose writer had copied a published manifest and a sealed pack
faithfully, which is the one thing a format that describes artifacts already in the field cannot do; a
narrowing of a copied position arrives as a version of the format, with cases of its own, or it does not
arrive.

| Member | Type | Required | What it states |
|---|---|---|---|
| `protectedHeader` | `object` | yes | The three signed parameters above, as the twin projects them. |
| `payload` | `object` | yes | The signed document, which is the only part of an inventory a verifier has to believe before it starts checking. |
| `signature` | `string` | no | Ed25519 over the `Sig_structure`, hex. Named without being demanded, because a display of an unsigned document still shows; `epoch-inventory.cddl` requires four elements and sixty-four bytes. |
| `v` | `1` | yes | Format version, one constant rather than a discriminant. A reader refuses a version it does not define rather than reading the bytes under rules that were not written for them. |
| `epoch` | `string` | yes | The operator's label for the run: printable text, unpadded, no control character, bounded in bytes by the format because it is printed beside the run in every report of it. It identifies the artifact and decides nothing in it. |
| `manifest` | `object` | yes | Which deployment manifest supplied the keys this run was resolved against, named rather than copied. |
| `packs` | `array` | yes | The run: at least one entry, one per closed window, each stating where its pack is and what the pack says. The order they are written in bears nothing; a reader places them by their windows. |
| `window` | `object` | yes | The period the sealed run covers, folded from the windows the packs themselves state. |
| `chain` | `object` | yes | The two endpoints the run claims to chain between, and each pair of packs where the later one does not continue the earlier. |
| `duty` | `object` | yes | Whether any pack of the run falls short of the period that same pack states as required, and which. |
| `deployment.iss` | `string` | yes | The deployment id, as that manifest states it: never empty, and bounded by no ceiling, because that manifest declares none. |
| `deployment.ins` | `string` | yes | The instance id, as that manifest states it: never empty, and bounded by no ceiling, because that manifest declares none. |
| `deployment.epk` | `integer` | yes | The key epoch number, as that manifest states it. An inventory saying only that keys came from a manifest would name no document, and a reader holding two of them could not tell which one this run was checked against. |
| `pack.file` | `string` | yes | Where the pack is, relative to the epoch directory and with forward slashes: `packs/<digest>/pack-v1.cbor`. The directory is named for this entry's own `sha256`, and an entry filed under another pack's digest is refused by name rather than pointing a reader at bytes that are not the ones described. |
| `pack.retention` | `string` | yes | The retention artifact assembled with this pack, in the same directory: `packs/<digest>/retention-v1.json`. A closed window is the pair: the pack states the duty it answers and the artifact states what the store held and retired at that same instant. |
| `pack.sha256` | `string` | yes | sha256 over the whole sealed pack document as it sits on the volume, tag and signature included, which is the identity a redaction of that pack names it by. |
| `pack.retentionSha256` | `string` | yes | sha256 over the retention artifact's bytes as they sit on the volume. |
| `pack.at` | `integer` | yes | Unix seconds, the instant that pack began to be assembled, copied from the pack after it was read through its own verifier. |
| `pack.span` | `object` | yes | The window that pack sealed, as the pack states it: the arms of the pair are `span.from` and `span.to` below, and the same pair is the shape of `window`. |
| `pack.items` | `integer` | yes | How many receipts that pack carries. The pack is the only place the figure comes from, and a reader that wants it checked counts them out of the file. |
| `pack.chain` | `object` | yes | The two endpoints that pack signs, which is what a reader compares between neighbours to decide whether the run continues itself. |
| `pack.kid` | `string` | yes | The key that pack was sealed with, as its own protected header names it, hex. Where a caller keeps each key, and how the manifest named above came to list it, are the caller's facts. |
| `pack.duty` | `object` | yes | The four integers that pack signs, as signed. A conclusion is not one of them and is not added here. |
| `span.from` | `integer` | yes | Unix seconds, included. |
| `span.to` | `integer` | yes | Unix seconds, excluded: a receipt stamped exactly here belongs to the next window, which is what lets the windows of a run meet without overlapping. |
| `packChain.anchor` | `string` | yes | The digest that pack's first record was chained from, or thirty-two zero bytes before any retirement. |
| `packChain.head` | `string` | yes | The digest of that pack's last record. |
| `packDuty.art` | `string` | yes | A label from the retention-duty registry, declared text rather than an enumeration for the reason [export-v1.md](export-v1.md) gives for the pack's: this estate does not interpret the questions an article answers, and a format that enumerated answers would itself be an answer. It is stated at the width `pack.cddl` states it, which is none, because an inventory copies the label a pack signed. |
| `packDuty.rev` | `integer` | yes | Unix seconds, the revision of the mapping `required` was read from. |
| `packDuty.required` | `integer` | yes | Seconds that revision required. |
| `packDuty.held` | `integer` | yes | Seconds that store had held its oldest retained receipt, measured at `pack.at`. |
| `runChain.anchor` | `string` | yes | The anchor of the pack the run begins with, where the beginning is fixed by the windows and not by an array position. |
| `runChain.head` | `string` | yes | The head of the pack the run ends with. |
| `runChain.continuous` | `boolean` | yes | Whether each pack's anchor is the head before it, which is the claim that lets a reader lay the run end to end. It is the emptiness of `breaks` stated as a word, and a reader refuses the two when they disagree. |
| `runChain.breaks` | `array` | yes | Each pair where the later pack does not continue the earlier, in run order, with the two digests that disagree beside it. An empty list is the statement that the run chains, so this one carries no floor. |
| `break.file` | `string` | yes | The pack that failed to carry the head before it forward, named by one of this document's own `pack.file` values. A row about a pack the document does not describe is a statement about something else, and it is refused rather than dropped. |
| `break.afterHead` | `string` | yes | The head the predecessor pack states. |
| `break.anchor` | `string` | yes | The anchor this pack carries instead. |
| `runDuty.carried` | `boolean` | yes | Whether no pack of the run falls short. It is the emptiness of `short` stated as a word, and a reader refuses the two when they disagree. |
| `runDuty.short` | `array` | yes | One row per pack whose own `held` falls short of its own `required`, in run order. An empty list is the statement that the run carried what it states, so this one carries no floor. |
| `shortfall.file` | `string` | yes | The pack this row is about, named by one of this document's own `pack.file` values. |
| `shortfall.art` | `string` | yes | That pack's own duty label, restated so a reader sees which period was measured, at the width the pack states it. |
| `shortfall.required` | `integer` | yes | That pack's own required seconds. |
| `shortfall.held` | `integer` | yes | That pack's own held seconds. |
| `shortfall.shortBy` | `integer` | yes | `required` minus `held`, never zero. A reader recomputes the subtraction and refuses a row whose figure is not it. |

## What a run states about itself

Three statements are folded from the entries and then restated inside the signature: the window the run covers,
whether the packs chain into each other, and whether each pack's held period reaches the period that same pack
states as required. Restating them is what makes the artifact readable at a glance, and it is also what makes it
refusable: a document whose fold does not match its own entries is contradicting itself, and a reviewer who had
to do the arithmetic to find out would have had to trust the arithmetic to notice. So the reader does it.

The windows meet, and that is the rule the rest of the run rests on. Each entry's own window runs forwards, and
each entry's start is its predecessor's end. A gap is a period the epoch states it attests and does not, and an
overlap seals the same receipts twice under two signatures while reporting them as one run. `window` is then the
outer edges of the windows the packs state and nothing else: it is not the period somebody asked for, and a
reader that cared about that compared it against the request, which no reading of this document can see.

The chain continues pair by pair, which is what gives the two endpoints their meaning. A run that chains from
its anchor to its head is a sequence of packs a reader can lay end to end; a run that does not says so, with the
two digests of each place it does not. A break is reported and not explained away: the digests are the evidence,
and what happened between them is a fact about a deployment's store rather than about this document.

The duty adds up per pack and nowhere as a verdict. `carried` is the emptiness of `short`, `shortBy` is the
subtraction, and each pack is measured against its own two integers and never against a neighbour's, so a routed
article's period is not read against another article's figure. A shortfall is lawful output and this format says
nothing about whether the period was owed, to whom, or under which mapping revision, which is settled outside it
by whoever holds the mapping and the law.

The entries have one order and it is derived, not believed: by the start of each window, then by the instant the
pack was assembled, then by the pack's digest, which is a total order over a document whose digests are unique.
Position in `packs` bears nothing, exactly as position bears nothing in a pack's items, and the reader hands back
the entries in the order its own figures put them so that a caller prints the run rather than the file.

The `packs` array is the only list with a floor. An inventory of no packs states a window no pack covers, two
chain endpoints no pack chained and a duty block that reports having carried nothing, which is a document whose
own figures are vacuous rather than a deployment that sealed nothing. The honest statement that a period held no
receipts belongs to the artifact that states windows and retention, which is a pack's pair and not this document.

## What a verified inventory does not establish

A reimplementer who has just read the word `verify` is most likely to over-read exactly this, so the list is
plain and the reader's answer is shaped to keep the two apart.

- It is not a claim that the packs exist, or that they say what this document says they say. The reader is handed
  this document and nothing else; the two digests, the item counts and the per-pack figures are the writer's
  restatement of packs it was never given. A reviewer who wants that check runs `verifyPack` over the files the
  entries name and compares each entry's `sha256` against `redactionPackDigest` of the bytes in hand. That is a
  second check the reader makes and not a conclusion of this one, and it is why the reader takes a document
  rather than a directory: an inventory is the artifact that travels, and a verdict about it has to be reachable
  by somebody with no access to the volume it was written on.
- It is not a claim that the run is complete. The inventory lists the packs its directory held when it was
  written, and a directory with a window left out of it reads exactly like an epoch that sealed no more. A
  deletion becomes visible only against a copy the reader had cause to believe before, and this container states
  its own figures and no reader's expectation.
- It is not a statement about a duty, a lawful basis or a request, and it is not a verdict about a shortfall.
  `duty.short` is arithmetic on two integers each pack signed.
- It is not a claim about freshness, and it is not a claim about the deployment manifest it names. The three
  figures of `manifest` say which document the writer resolved keys against; whether that document is the
  deployment's own, and whether the keys listed in it are trusted for anything, are answered by reading it, which
  this container neither does nor replaces.

## Refusals

Every fault is refused by a code, and a caller branches on the code and not on the sentence. The rows are in
[error-codes.md](error-codes.md) with the conditions and the caller's action; the names are listed here so one
file states the whole set this container can answer with.

| Code | The fault |
|---|---|
| `EPOCH_INVENTORY_MALFORMED_CBOR` | The document does not decode as canonical CBOR |
| `NOT_COSE_SIGN1` | The top-level value is not the tagged four-element structure |
| `UNSUPPORTED_ALG` | The header's `alg` is not an integer, or is not EdDSA |
| `EPOCH_INVENTORY_BAD_HEADER` | The signed header is not a map, does not decode under this format's rule for it, carries a label outside the three, or names a content type that is not an inventory |
| `EPOCH_INVENTORY_MALFORMED_JSON` | The payload is not one JSON document of the shapes this layout writes: not UTF-8, not parseable, more than one value, a member name stated twice, or a number written other than as an integer |
| `EPOCH_INVENTORY_UNSUPPORTED_VERSION` | The document declares a version no format has used |
| `EPOCH_INVENTORY_BAD_DOCUMENT` | A member is absent, undefined at this version, of the wrong type or width, negative, a path of another shape, a label that cannot be printed, or a pack list with nothing in it |
| `EPOCH_INVENTORY_DUPLICATE_PACK` | Two entries answer to one pack digest, which is the same pack counted twice |
| `EPOCH_INVENTORY_PACK_MISNAMED` | An entry is filed under a pack home whose digest is not the one the same entry states |
| `EPOCH_INVENTORY_PACK_UNNAMED` | A break or a shortfall names a pack the run does not hold |
| `EPOCH_INVENTORY_RUN_NOT_CONTIGUOUS` | The windows of the run leave a gap, overlap, or do not run forwards |
| `EPOCH_INVENTORY_SUMMARY_DISAGREES` | The window, the two chain endpoints, `continuous`, a break's pair of digests, `carried` or a shortfall's figures are not the arithmetic of the entries, or one of the two lists states one pack twice and leaves another of the run's entries unstated |
| `EPOCH_INVENTORY_KID_MISMATCH` | The key handed to the reader is not the one the header's kid names |
| `EPOCH_INVENTORY_UNKNOWN_KEY` | The reader was given no key for the kid the inventory names, including a call that gave it neither a key nor a resolver |
| `INVALID_SIGNATURE` | The signature does not verify over the `Sig_structure` |
| `BAD_SIGNING_KEY` | Raised where the bytes are made and never by a reader: the key handed to the writer is not a 32-byte Ed25519 key whose kid is sha256 of its public half |

Four of those answers are about different things and a reader should keep them apart.
`EPOCH_INVENTORY_BAD_DOCUMENT` is one document contradicting itself at a position.
`EPOCH_INVENTORY_SUMMARY_DISAGREES` is one document contradicting itself across its entries, which is what the
run's arithmetic is for. `EPOCH_INVENTORY_PACK_UNNAMED` is a row about something the document does not describe.
And `EPOCH_INVENTORY_UNKNOWN_KEY` is a reader that was handed too little, where nothing about the inventory is
refused at all.

## Reading and writing these bytes

`@ashaveri/receipt` publishes `decodeEpochInventory` and `verifyEpochInventory`. A verification key arrives as an
argument, either the one key the caller pins or a resolver asked for the kid the header names, which is how a
caller holding the epochs a deployment retained reads an inventory beside a run sealed across a rotation:
nothing in the reader resolves a name, opens a file, reaches a network or consults a key directory, and it
reports only on what it was handed. `decodeEpochInventory` answers shape with no key at all, because a document
that contradicts itself at a position does so whoever signed it. `verifyEpochInventory` answers the envelope, the
key, the signature and the run, which is where the folds sit: a document's claims about its own entries are the
substance of what it attests about a deployment's store, and a reader that reported them before deciding whether
anybody signed them would be handing out a verdict about unauthenticated bytes.

The same module publishes the pieces the layout is written with: `encodeEpochInventoryManifest`,
`encodeEpochInventoryProtectedHeader`, `epochInventorySigStructure`, `sealEpochInventory` and
`signEpochInventory`. `encodeEpochInventoryManifest` renders the document as the file a deployment writes, two
spaces indented and newline terminated, and it is a convenience and not a rule: the signature covers the bytes
handed to `sealEpochInventory`. `signEpochInventory` parses a document and does the run's arithmetic before it
signs, so a writer cannot produce an inventory whose own entries disagree with it: a gap between two windows, a
break smoothed into `continuous` and a shortfall list that does not match the packs are each refused where the
bytes are made, under the code the reader states. A document that is meant to be refused therefore cannot come
out of `signEpochInventory`, and one assembled to be refused is built from the pieces above rather than through
it, which is what a conformance vector is.

## The identity of the schema

| Fact | Value |
|---|---|
| File | `packages/receipt/schemas/epoch-inventory-v1.schema.json` |
| `$id` | `https://ashaveri.com/schemas/epoch-inventory-v1.json` |
| Draft | JSON Schema 2020-12 |
| Version member | `v` is the constant `1`, and the number in the identity is the number in the document |

The identity carries the version because this layout will outlive the first run it describes, and a schema named
for no version would have to mean two documents the day a second one is defined.
`packages/fixtures/test/schema-identity.test.ts` holds every published schema in this workspace to that rule, so
the convention is a checked property of the tree rather than a habit this sentence asks a reader to trust.
