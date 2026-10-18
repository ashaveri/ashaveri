import {
  assessRetention,
  RETENTION_ASSESSMENT_FORMAT_VERSION,
  type RetentionAssessmentDocument,
  type RetentionAssessmentOutcome,
  type RetentionAssessmentResult,
  type RetentionAssessmentScope,
  type RetentionCoverage,
  type RetentionSequenceRange,
} from './retention-assessment.js';

/**
 * Producing a retention assessment from evidence a deployment actually holds.
 *
 * `retention-assessment.ts` reads a `retention-assessment-v1` document and says what its evidence supports.
 * Nothing in this repository wrote one: the vectors hand the reader documents typed by hand. This module is
 * the writing half. It takes a structured evidence argument, assembles the document, serializes it to
 * canonical bytes, and proves the round trip before it hands anything back.
 *
 * The rule the producer keeps is the rule `assessRetention` states: a span is not coverage, checkpoints must
 * tile the declared intake and close on the observed head, and the head the intake observed must match a head
 * a party outside the deployment pinned. The producer does not restate that rule and does not reach an outcome
 * of its own. It copies the deployment's claim into the `assessment` block and then runs the shipped reader
 * over the bytes it just wrote. If the reader refuses them, the producer refuses: an evidence set the reader
 * reads as `indeterminate` cannot be written up as `met`, because the writer would have to hand back a
 * document its own reader rejects. A producer that hard-coded an outcome would be a second copy of the rule
 * and could disagree with the reader that decides; this one has no outcome of its own to disagree with.
 *
 * The expected head travels through the evidence verbatim. Where a caller supplies a pin, the producer states
 * that pin and its pinner; where the caller states none, the document states none with the reason the caller
 * gave, and the reader treats `none` as the honest answer it is, never as a field the producer quietly
 * filled. The pin and its pinner are what close the stale-replay sentence inside the produced document rather
 * than at a command surface that names no endpoint.
 *
 * The bytes are canonical in the sense a second implementation can be checked against them: every block is
 * written in the member order the published layout declares, so `JSON.stringify` of the assembled document is
 * the same string every time for one evidence set. The document the round trip reads back is compared with
 * what this module handed back, so a serialization that lost or reordered a member stops the run rather than
 * shipping.
 */

/**
 * What the writer is handed: the declared scope, the observed coverage, and the deployment's claim about the
 * pair. `scope` and `coverage` travel in the same shapes the reader parses, so an evidence set that would make
 * a document the reader refuses is refused here at the round trip rather than written up as one that stands.
 * `claim` is the deployment's own conclusion, the `assessment` block the reader recomputes.
 */
export interface RetentionAssessmentEvidence {
  readonly scope: RetentionAssessmentScope;
  readonly coverage: RetentionCoverage;
  readonly claim: RetentionAssessmentOutcome;
}

/** The document, its canonical bytes, and what the shipped reader reached when it read those bytes back. */
export interface ProducedRetentionAssessment {
  readonly document: RetentionAssessmentDocument;
  readonly bytes: string;
  readonly assessment: RetentionAssessmentResult;
}

/**
 * The document, assembled in the member order the layout declares.
 *
 * Each block is rebuilt rather than passed through, because `JSON.stringify` emits keys in insertion order
 * and the evidence object a caller built may list members in any order. Rebuilding here is the one place the
 * canonical order is stated, and the round trip below reads the bytes back through the shipped parser, so an
 * order that dropped a member or wrote one the version does not define is refused by the reader, not by a
 * rule restated here.
 */
function canonicalRange(range: RetentionSequenceRange): RetentionSequenceRange {
  return { from: range.from, to: range.to };
}

function canonicalScope(scope: RetentionAssessmentScope): Record<string, unknown> {
  return {
    subject: { kind: scope.subject.kind, id: scope.subject.id },
    duty: { article: scope.duty.article, requiredSeconds: scope.duty.requiredSeconds },
    period: { from: scope.period.from, to: scope.period.to },
    intake: {
      from: scope.intake.from,
      to: scope.intake.to,
      expectedHead: {
        sha256: scope.intake.expectedHead.sha256,
        pinnedBy: scope.intake.expectedHead.pinnedBy,
        reason: scope.intake.expectedHead.reason,
      },
    },
    checkpoint: {
      holder: scope.checkpoint.holder,
      eachCompletedBatch: scope.checkpoint.eachCompletedBatch,
      maxIntervalSeconds: scope.checkpoint.maxIntervalSeconds,
    },
    timeBasis: { source: scope.timeBasis.source, uncertaintySeconds: scope.timeBasis.uncertaintySeconds },
    excludes: [...scope.excludes],
  };
}

function canonicalCoverage(coverage: RetentionCoverage): Record<string, unknown> {
  return {
    runs: coverage.runs.map(canonicalRange),
    acknowledged: coverage.acknowledged.map(canonicalRange),
    checkpoints: coverage.checkpoints.map((receipt) => ({
      range: canonicalRange(receipt.range),
      at: receipt.at,
      head: receipt.head,
    })),
    observedHead:
      coverage.observedHead === null
        ? null
        : { sequence: coverage.observedHead.sequence, sha256: coverage.observedHead.sha256 },
    span:
      coverage.span === null
        ? null
        : {
            from: coverage.span.from,
            to: coverage.span.to,
            oldestHead: coverage.span.oldestHead,
            newestHead: coverage.span.newestHead,
          },
    gaps: coverage.gaps.map((gap) => ({ from: gap.from, to: gap.to, reason: gap.reason })),
    duplicates: coverage.duplicates.map((duplicate) => ({ sequence: duplicate.sequence, count: duplicate.count })),
    rollbacks: coverage.rollbacks.map((rollback) => ({
      sequence: rollback.sequence,
      observedHead: rollback.observedHead,
      restoredHead: rollback.restoredHead,
    })),
    suffixLoss:
      coverage.suffixLoss === null
        ? null
        : { from: coverage.suffixLoss.from, to: coverage.suffixLoss.to, reason: coverage.suffixLoss.reason },
  };
}

/** The whole document in the order the layout names: version, scope, coverage, the deployment's claim. */
function assemble(evidence: RetentionAssessmentEvidence): RetentionAssessmentDocument {
  const shaped: Record<string, unknown> = {
    v: RETENTION_ASSESSMENT_FORMAT_VERSION,
    scope: canonicalScope(evidence.scope),
    coverage: canonicalCoverage(evidence.coverage),
    assessment: { outcome: evidence.claim },
  };
  return shaped as unknown as RetentionAssessmentDocument;
}

/**
 * Assemble a retention assessment from evidence and hand back the document with its canonical bytes.
 *
 * The writer fills `scope` and `coverage` from the evidence and places the deployment's `claim` in the
 * `assessment` block, which is the deployment's own conclusion and not this module's arithmetic. It then runs
 * `assessRetention` over the bytes it wrote and returns only if the reader takes them: a document the reader
 * would refuse, whether for a layout fault or because the evidence supports an outcome other than the claim,
 * is refused here rather than emitted for a later reader to trip over. The `assessment` field of the result is
 * what the shipped reader reached for these bytes, which is the round trip made visible at the call site.
 */
export function produceRetentionAssessment(evidence: RetentionAssessmentEvidence): ProducedRetentionAssessment {
  const document = assemble(evidence);
  const bytes = JSON.stringify(document);
  const assessment: RetentionAssessmentResult = assessRetention(JSON.parse(bytes));
  return { document, bytes, assessment };
}
