# `retention-assessment-v1`: the document, its members, and what it can prove

A retention manifest states a window between the oldest record a store still holds and the instant the manifest was
written. That window is arithmetic. No subtraction can show that the store held every record across the period between
the two ends: a deployment that crashed, restored a backup, lost a suffix, or acknowledged nothing for a week reports
the same distance from its oldest survivor to now. `retention-assessment-v1` is the document that asks the question the
subtraction cannot answer, and its reader is public so a party who does not trust the writer can run it over the same
bytes.

This page is the layout in prose. A test reads it: `packages/sdk/test/retention-assessment-doc.test.ts` parses the
member and enumeration lines below and compares them, in both directions, against
`packages/sdk/schemas/retention-assessment-v1.schema.json` and the closed sets in
`packages/sdk/src/retention-assessment.ts`, so a page that falls behind the layout fails a suite rather than sitting
beside it.

## The three blocks

`scope` is what the deployment declares. `coverage` is what was observed. `assessment` is the deployment's own
conclusion, in the spirit of a retention manifest's `duty.met`: a claim the reader recomputes rather than believes.

| Member | What it states |
|---|---|
| `v` | The layout version, and this reader implements one: `1`. A document names its own version and never inherits it |
| `scope` | The declaration, below |
| `coverage` | The observation, below |
| `assessment` | The stated outcome, `{ outcome }` |

### `scope`: what is declared

| Member | What it states |
|---|---|
| `subject` | `{ kind, id }`, the system or service the assessment is about. `kind` is `deployment` or `provider` |
| `duty` | `{ article, requiredSeconds }`, the obligation the deployment takes itself to owe and the period it reads from it. `article` is one of `19(1)`, `19(2)`, `26(6)`, and the label is the deployment's own reading: nothing here interprets it |
| `period` | `{ from, to }`, the assessed period, in whole seconds |
| `intake` | `{ from, to, expectedHead }`, the declared intake sequence range and the head pinned outside the deployment |
| `checkpoint` | `{ holder, eachCompletedBatch, maxIntervalSeconds }`, the schedule the checkpoints must witness. The layout names one holder, `customer`; requires completed batches, so `eachCompletedBatch` is `true`; and caps the interval at `3600` seconds |
| `timeBasis` | `{ source, uncertaintySeconds }`, the clock the stamps rest on and the uncertainty declared on it. It is carried and reported, not demanded |
| `excludes` | A list of what the scope leaves out. An empty list states that nothing is left out |

### The expected head, and the four refusals around it

`scope.intake.expectedHead` is `{ sha256, pinnedBy, reason }`. `pinnedBy` is one of `customer`, `external-holder`,
`subject` or `none`, and the block is closed so that an absence has to be said rather than left implied. Four shapes are
refused:

| Stated | Refused because |
|---|---|
| a head with `pinnedBy: 'none'` | a head and nobody who pinned it is a head with no provenance |
| no head while naming a party | the named party is credited with a pin it did not give |
| no head and no reason | the absence would be silent |
| a head and a reason for having none | the block contradicts itself |

A head pinned by `subject` is legal and weighed as self-assertion: it yields `indeterminate`, not `met`. Naming the
intake, the observation or the document as the pinning party is refused outright, because a head the intake wrote beside
its own observation is that observation repeated, and a reader that accepted it would let the document attest itself.

### `coverage`: what was observed

| Member | What it states |
|---|---|
| `runs` | Sequence ranges the store reports holding, each `{ from, to }` |
| `acknowledged` | The ranges it acknowledged, each `{ from, to }` |
| `checkpoints` | Customer-held checkpoint receipts, each `{ range, at, head }` with `range` an `{ from, to }` pair |
| `observedHead` | `{ sequence, sha256 }`, the head the store reports at the declared end |
| `span` | `{ from, to, oldestHead, newestHead }`, the timestamps-only evidence: where this is the only coverage, the answer is `indeterminate` |
| `gaps` | Intervals not held, each `{ from, to, reason }` |
| `duplicates` | Reused sequence positions, each `{ sequence, count }` |
| `rollbacks` | Restored states, each `{ sequence, observedHead, restoredHead }` |
| `suffixLoss` | Intervals lost at the end, `{ from, to, reason }` |

## The members and enumerations, as a test reads them

The lists below are the ones `packages/sdk/schemas/retention-assessment-v1.schema.json` enforces, restated so this page
can be checked against it. A change to the schema that does not reach this list fails the suite.

```layout
members(top): v, scope, coverage, assessment
members(scope): subject, duty, period, intake, checkpoint, timeBasis, excludes
members(scope.subject): kind, id
members(scope.duty): article, requiredSeconds
members(scope.period): from, to
members(scope.intake): from, to, expectedHead
members(scope.intake.expectedHead): sha256, pinnedBy, reason
members(scope.checkpoint): holder, eachCompletedBatch, maxIntervalSeconds
members(scope.timeBasis): source, uncertaintySeconds
members(coverage): runs, acknowledged, checkpoints, observedHead, span, gaps, duplicates, rollbacks, suffixLoss
members(coverage.runs): from, to
members(coverage.acknowledged): from, to
members(coverage.checkpoints): range, at, head
members(coverage.checkpoints.range): from, to
members(coverage.observedHead): sequence, sha256
members(coverage.span): from, to, oldestHead, newestHead
members(coverage.gaps): from, to, reason
members(coverage.duplicates): sequence, count
members(coverage.rollbacks): sequence, observedHead, restoredHead
members(coverage.suffixLoss): from, to, reason
members(assessment): outcome
enum(scope.subject.kind): deployment, provider
enum(scope.duty.article): 19(1), 19(2), 26(6)
enum(scope.intake.expectedHead.pinnedBy): customer, external-holder, subject, none
enum(assessment.outcome): met, not-met, indeterminate
bound(scope.checkpoint.maxIntervalSeconds): 3600
version: 1
```

`scope.checkpoint.holder` and `scope.checkpoint.eachCompletedBatch` are fixed by the layout rather than enumerated: one
holder, `customer`, and a schedule that may not skip completed batches.

## How the outcome is reached

`met` requires all of: the runs covering the declared sequence range; the acknowledgments covering it; checkpoints
witnessing the period at the declared schedule, their ranges tiling the declared intake in order, and the final
checkpoint's head equal to the observed head; the period at least the declared `requiredSeconds`; the expected head
pinned by `customer` or `external-holder`; and the observed head at the declared end and equal to that pin.

A span-only input is `indeterminate` before any head comparison, and has no path to `met`. An interior gap, a duplicate,
a rollback, a suffix loss, a head that differs from the pin, or a period shorter than the declared duty is `not-met`,
because the evidence states the period was not continuously held. A missing checkpoint, a checkpoint list that does not
tile the intake, an unacknowledged interval, no observation at all, or a head the deployment pinned about itself is
`indeterminate`, because the evidence cannot answer either way.

The stated conclusion is recomputed. `parseRetentionAssessment` reads the layout, `assessRetention` computes what the
evidence supports, and a document whose `assessment.outcome` differs from that reading is refused rather than reported
with the difference, so a writer cannot reach `met` by writing the word.

## Refusals

| Code | When |
|---|---|
| `NOT_RETENTION_ASSESSMENT` | The bytes are not a version 1 assessment: a wrong version, a block that is not an object, a member the version does not define, a missing value where the layout has to be told, a digest that is not 64 lowercase hex, a checkpoint schedule outside the bound, or a pin in one of the four shapes above |
| `RETENTION_ASSESSMENT_DISAGREES` | The document parses, and the reading reaches an outcome other than the one it states |

## What this document does not claim

It does not prove continuous retention from timestamps, it does not certify the deployment that wrote it, and it says
nothing about a period it does not state. A `met` here means the evidence in this document supports the declared duty for
the declared period under the declared scope and its exclusions; it is not a compliance verdict, and the layout carries
no claim of one.

## Where a writer builds against it

The schema above is published as `https://ashaveri.com/schemas/retention-assessment-v1.json` and lives in this repository
at `packages/sdk/schemas/retention-assessment-v1.schema.json`. The assessed and refusal cases travel as
`packages/fixtures/data/retention-assessment-v1.json`, described in [vectors.md](vectors.md), and the reader is
`parseRetentionAssessment` and `assessRetention` in `packages/sdk`.
