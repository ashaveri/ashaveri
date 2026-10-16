# The import envelope (import-v1)

An import envelope states, for one provider export, the exact bytes the provider served and the
representations this estate's normalization produced from them.

**Nothing in this repository writes one.** The adapter that carries a real provider's export to this shape
belongs to the Confidential half of this unit, holds any credential in a secret manager, and reaches no
file here. What is public is the layout an importer has to be written against, the reading a stranger can
run over whatever they are handed, and the name a store keys on. That order is deliberate, and it is the
one the capture record beside it keeps: the shape a claim travels in is only checkable by somebody who
does not trust us if the shape is public and a reader for it exists.

- The record: `packages/sdk/schemas/import-v1.schema.json`, published as
  `https://ashaveri.com/schemas/import-v1.json`.
- The reader: `packages/sdk/src/import-envelope.ts`, `parseImportEnvelope` and `readImportEnvelope`,
  re-exported from the package entry beside `importEnvelopeKey`.
- The normalization: `packages/sdk/src/import-normalize.ts`, `normalizeProviderExport` and the five named
  rules beside it; the driver and the list of rule names leave by the package entry.
- Its vectors: `packages/fixtures/data/import-v1.json`, written by
  `packages/fixtures/scripts/import-vectors.ts` and replayed row by row through these same readers by
  `packages/fixtures/test/import-vectors.test.ts`. The synthetic provider export the vectors hold is
  committed as `packages/fixtures/data/exports/provider-export-v1.json`, and the generator stops unless
  the rows that name no edit state it byte for byte and the shipped rules read every position of it. Each
  row states one envelope, the answer the published reader gave it when the file was written, and the key
  a store takes it under.
- Its tests read the shipped code: the derived representation every accepted row carries is
  `normalizeProviderExport` output, so a row stands on the same transformation a reader re-runs.

## Where it sits in the format family

A receipt attests one response. A pack attests that the receipts inside a window are all of them. A capture
record holds one piece of evidence's bytes beside the context they were taken in as. An import envelope
holds one provider export's bytes beside the view this estate derives from them, and it exists for one
reason: somebody reads every provider export into a normalized view sooner or later, and the moment that
view is written beside the export without a label, a reader of the pair cannot tell which of the two a
provider's signature covered. So the two stand apart in the record. The original stands for itself, byte
for byte, and every derived representation says what it is, which named rule produced it, and which
original it rests on.

The record is closed and the provider's export is not, and the asymmetry is load bearing. A member this
record's version does not define is refused, because a writer that stated a field no reader knows was
answering a question this record cannot ask, and dropping it quietly turns that answer into a silence. A
position the provider's export states that no normalization rule reads is **reported**, not refused,
because the provider's document is larger than this reading and refusing it would turn every future field
of every provider into an unimportable document while teaching nobody what the field was. The original
bytes stay held whole, so nothing the provider stated is lost by the reading; the report says what the
reading did not take.

## The identity, and the one row it answers twice

`importEnvelopeKey` is sha256, under the domain prefix `ashaveri/import-v1 `, of the canonical JSON of the
record's content: the version, the `provider` block and the `original` block. It is not taken over the
whole record, and the two exclusions are the point of the function:

- `imported` dates and stamps the intake. A second intake of one export states its own instant, derives
  the same view, and writes no second record; a key that covered the stamp would write two.
- `derived` follows from the original under the version's rules. Two rows that disagree cannot both pass
  the reading, and the reading is where that is refused rather than the store.

The unit's own row asks for this and only for this: one paid-scope provider export imported twice produces
one record, not two. The capture record keys the other way, over everything it states including when it was
taken in, because two captures of one instant are two observations; an import is keyed by what it is about.
That departure is stated here on purpose, because a reader who knows the capture contract will expect keys
to differ when the intake stamp does, and this contract means the opposite for a reason the row gives.

The content is one export and the key says so: an export whose bytes differ by one member keys apart, and
one export text spelled twice keys apart too, because the key is taken over the bytes rather than over the
reading. A store keys records by this digest; nothing in this package writes, reads or lists a store.

## Fields

Each row says what the member states, what a reader may conclude from it, and what a reader may not.

| member | states | a reader may conclude | a reader may not conclude |
| --- | --- | --- | --- |
| `v` | which rules the record is read under | that a reader implementing no other version refused or read it | anything about the export |
| `provider.name` | the provider's own name for itself, copied out of the export | who the export says served it | that anybody did, or that the name is anyone's |
| `provider.exportId` | the provider's own name for this export | which of the provider's exports this record is about | that the provider keeps or served a record under that name |
| `original.bytes` | the exact bytes as they arrived | they are the bytes the record describes, iff `sha256` agrees | that they are the bytes the provider produced, which is the adapter's claim |
| `original.sha256`, `byteCount` | the digest and length of those bytes | the record is self-consistent, or it is refused | that the digest matches anything outside the record |
| `original.signedByProvider` | our assertion that the provider signed them | that the record claims it, either way | that it holds. No member here could state that |
| `imported.at` | our clock when the bytes were taken in | how the importer dates its own taking-in | that the export was assembled then, which is what the export's own `issued` is for |
| `derived[].k` | which representation the row holds, of the kinds this version defines | which reading of the bytes applies | that the reading is anybody's but ours |
| `derived[].derivedBy` | the named transformation that produced the row's bytes | which shipped rule a reader re-runs to check them | that the rule was run correctly at import time, which the re-run checks |
| `derived[].basis` | the digest of the original the row was derived from | which original the relationship names | that the two were once together |
| `derived[].bytes`, `sha256`, `byteCount` | the representation's exact bytes and their digest | the row is self-consistent and the rule's output, or it is refused | that the representation is evidence of anything |

## The derived representations, and why the original stays

The label is the record's whole separation. A derived representation is bytes our rules produced, and the
row names the rule in `derivedBy` and the original in `basis`; an original is bytes the provider served,
and it travels in `original` and nowhere else. A reader that wants to know which of the two a provider's
signature covered reads the record, and the answer does not depend on anybody's account of the import.

The reader re-derives. For every derived row, `readImportEnvelope` runs the transformation `derivedBy`
names over the original's bytes again, and the digest the row states has to be the digest that run
produces. A view edited into the envelope, or produced with another rule set, is refused rather than handed
on beside a digest that agrees with nobody's code. The stored bytes reach the caller as the record holds
them: the reading hands back `repeated.originalBytes` exactly as they arrived, never re-encoded, never
re-framed, and `repeated.normalizedSha256` is the digest of what the shipped rules produce, which every
row's `sha256` has to be.

A receipt is never silently converted into equivalent evidence, and this record is where that rule has
teeth for imports: the normalized view is useful, and it is labeled ours, and it never stands in for the
provider's bytes.

## The normalization rules and the report

The provider export these rules read is JSON text, and its vocabulary is the synthetic provider's: the
committed fixture export carries `provider`, `export_id`, `issued`, `model` and `completions`, each entry
of `completions` carrying `ref`, `sha256` and `at`. Five named rules read it, one per estate field, and
`normalizeProviderExport` folds their answers into one normalized document whose members are written in
this order:

| rule | reads | writes |
| --- | --- | --- |
| `normalizeProvider` | `provider` | `provider` |
| `normalizeExportId` | `export_id` | `exportId` |
| `normalizeIssuedAt` | `issued` | `issuedAt` |
| `normalizeModel` | `model` | `model` |
| `normalizeCompletions` | `completions` | `items` |

The normalized document is `{ "v": 1, ... }` over the members the rules produced, and it states no member
a rule could not read. An entry of `completions` whose three members are not all readable is not carried
half-stated: the normalized `items` list holds the entries the rules could state, and the report names
every member left out, so the omission is never silent.

The report is the reading's answer to the provider's document being larger than this rule set, and it is
computed, never read off the record. Every row carries one of two kinds, the position as the export spells
it, and one sentence:

| kind | row | sentence |
| --- | --- | --- |
| `unsupported-field` | the export states a position no rule reads | `the export carries '<field>', which no normalization rule of import version 1 reads` |
| `missing-field` | a rule reads a position the export states nothing at | `the export carries nothing at '<field>', which normalization rule '<rule>' reads` |

The rows are sorted by position, so two spellings of one export that differ only in the order of their
members carry the same report, and the same input always yields the same rows in the same order. The two
kinds never merge: one is the provider's silence and one is our reach, and a reader that merged them would
report a field we chose not to read as one the provider withheld. A position inside a completion entry is
reported as `completions[i]` and the member's own name, `completions[0].cost_micros` and the like.

A value of a shape the rule at that position does not read is the third case, and it is a refusal rather
than a report: the field is one this reading knows and its value is one no rule reads, so the normalized
document would have to omit a field the export did state. The refusal names the position and the shape the
rule reads there, and leaf rules and entry members share the one code.

## Which authority binds which rule

The layout has two authorities and they bind different rules, which is the split a reader of the published
schema has to know.

The schema binds what a document is made of: every block closes, every member has its type and shape, the
two enums under `derived` are the closed sets of representation kinds and transformations, and `derived`
holds at least one row. A document any of that refuses is refused before a reader is asked anything.

The reader binds the rules no JSON Schema states: unpadded base64url has one spelling a reader reproduces
rather than any that decodes; the digest and length a row states are recomputed over what decoded; a
derived row's `basis` has to be the digest of the original beside it; and the derivation itself is
re-run, which no schema can do. It is also the authority that computes the report, which the schema cannot
carry: the report is a function of the original's bytes, and a document that stored one would be stating
its own reading.

`packages/sdk/test/import-envelope.test.ts` reads one document through both and refuses their disagreeing,
in both directions, and `packages/fixtures/test/import-vectors.test.ts` replays the published rows through
the readers themselves.

## What the reader refuses

`parseImportEnvelope` and `readImportEnvelope` refuse, each with a code a log line can carry:

- a version the reader does not implement, before any member is read: `UNSUPPORTED_VERSION`
- bytes that do not hash to the digest a row states, and a length that does not match the bytes beside it,
  at the original and at every derived representation, and a `basis` that is not the digest of the original
  beside it, and a derived representation whose stated digest is not the digest the rule it names produces:
  `EVIDENCE_DIGEST_MISMATCH`
- a member no version defines, an absent member, a value of the wrong shape, a base64url form no reader
  reproduces, a `k` or a `derivedBy` outside the version's closed sets, two derived rows claiming one kind,
  and a normalization that cannot run over the export because a position a rule reads states a value of no
  shape the rule reads: `NOT_IMPORT_ENVELOPE`

A wrong-shaped digest string, or any other member read by a digest rule, answers `EVIDENCE_DIGEST_MISMATCH`
as the capture record's digests do. A provider's export that carries more than this reading knows is not
refused by any code: it is read, and its extra positions are reported.

## What this record cannot support

It states no verdict about the provider, no completeness of the export, and no trust. It cannot show that
the provider produced these bytes: the envelope's claim is the importer's, the provider's own signature
travels in its own framing, and walking it is the adapter's business with the provider's roots, which are
not in this package. It cannot make the normalized view into evidence: the derived row is labeled ours,
the reader hands back the original unchanged, and nothing downstream of this record should read the two as
one document.

Two things remain owed to a real provider, and they are recorded rather than built here. The adapter,
which routes, retries and maintains one provider's integration, is Confidential to the estate and
unreleased; and the provider credential belongs to a secret manager and to no repository of ours at all.
This lane proves what is provable without either: the shape, the rules, the reading, the identity and the
determinism, over a synthetic export the generator builds and no provider's bytes.
