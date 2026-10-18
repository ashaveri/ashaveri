import { describe, expect, it } from 'vitest';
import { SdkError } from '../src/errors.js';
import {
  RETENTION_ASSESSMENT_FORMAT_VERSION,
  type RetentionAssessmentScope,
  type RetentionCoverage,
} from '../src/retention-assessment.js';
import {
  produceRetentionAssessment,
  type RetentionAssessmentEvidence,
} from '../src/retention-assessment-produce.js';

/**
 * Producing a retention assessment from evidence, and the round trip that proves it.
 *
 * The base evidence below is a period genuinely covered: one run across the declared intake range, the same
 * range acknowledged, three customer-held checkpoints from the period open to its close, and an observed head
 * that matches a head the customer pinned. Every other case is one edit to it, so a case that turns red names
 * the rule it turns on.
 *
 * The producer writes the deployment's claim into the `assessment` block and then runs the shipped reader over
 * the bytes. These tests hold that contract from both sides: an honest claim reads back to itself, and a
 * claim the evidence does not support - `met` written over a span, or `met` written where no independent head
 * was pinned - is refused by the producer rather than emitted for a later reader to trip over. That refusal is
 * the whole point: a writer must not be able to state `met` for evidence its own reader would call
 * `indeterminate`.
 *
 * `Mutable` drops the readonly modifiers the published interfaces carry so a case can state one edit to the
 * base without rebuilding every field: the evidence these tests hand the producer is still structurally a
 * `RetentionAssessmentEvidence`, and the producer reads it and refuses it under the same shapes the reader
 * uses.
 */

const HEAD = 'aa'.repeat(32);
const OTHER = 'bb'.repeat(32);
const PERIOD_FROM = 1_000_000;
const PERIOD_TO = PERIOD_FROM + 200;
const RANGE = { from: 1, to: 100 };

type Mutable<T> = { -readonly [K in keyof T]: T[K] };
type ScopeDraft = Mutable<RetentionAssessmentScope>;
type CoverageDraft = Mutable<RetentionCoverage>;

function coveredScope(): ScopeDraft {
  return {
    subject: { kind: 'deployment', id: 'deployment-alpha' },
    duty: { article: '19(1)', requiredSeconds: 200 },
    period: { from: PERIOD_FROM, to: PERIOD_TO },
    intake: { from: 1, to: 100, expectedHead: { sha256: HEAD, pinnedBy: 'customer', reason: null } },
    checkpoint: { holder: 'customer', eachCompletedBatch: true, maxIntervalSeconds: 3_600 },
    timeBasis: { source: 'host clock', uncertaintySeconds: 1 },
    excludes: ['request bodies', 'model weights'],
  };
}

function coveredCoverage(): CoverageDraft {
  return {
    runs: [RANGE],
    acknowledged: [RANGE],
    checkpoints: [
      { range: { from: 1, to: 34 }, at: PERIOD_FROM, head: '11'.repeat(32) },
      { range: { from: 35, to: 67 }, at: PERIOD_FROM + 100, head: '22'.repeat(32) },
      { range: { from: 68, to: 100 }, at: PERIOD_TO, head: HEAD },
    ],
    observedHead: { sequence: 100, sha256: HEAD },
    span: null,
    gaps: [],
    duplicates: [],
    rollbacks: [],
    suffixLoss: null,
  };
}

function spanOnlyCoverage(): CoverageDraft {
  const coverage = coveredCoverage();
  coverage.runs = [];
  coverage.acknowledged = [];
  coverage.checkpoints = [];
  coverage.observedHead = null;
  coverage.span = { from: PERIOD_FROM, to: PERIOD_TO, oldestHead: OTHER, newestHead: HEAD };
  return coverage;
}

function evidenceFor(scope: ScopeDraft, coverage: CoverageDraft, claim: RetentionAssessmentEvidence['claim']): RetentionAssessmentEvidence {
  return { scope, coverage, claim };
}

/** The code a producer refusal carried, or `ok` where the producer handed a document back. */
function produced(run: () => unknown): string {
  try {
    run();
    return 'ok';
  } catch (err) {
    return err instanceof SdkError ? err.code : `non-SdkError: ${String(err)}`;
  }
}

describe('produceRetentionAssessment', () => {
  it('writes a document its own reader reads back to the claim it was given', () => {
    const result = produceRetentionAssessment(evidenceFor(coveredScope(), coveredCoverage(), 'met'));
    expect(result.document.v).toBe(RETENTION_ASSESSMENT_FORMAT_VERSION);
    expect(result.assessment.outcome).toBe('met');
    expect(result.assessment.coverage.result).toBe('covered');
  });

  it('round trips: the bytes parse back to the document the writer assembled', () => {
    const result = produceRetentionAssessment(evidenceFor(coveredScope(), coveredCoverage(), 'met'));
    expect(JSON.parse(result.bytes)).toEqual(result.document);
  });

  it('emits the same bytes for the same evidence run twice', () => {
    expect(produceRetentionAssessment(evidenceFor(coveredScope(), coveredCoverage(), 'met')).bytes).toBe(
      produceRetentionAssessment(evidenceFor(coveredScope(), coveredCoverage(), 'met')).bytes,
    );
  });

  it('emits the same bytes whatever order the caller built the evidence in', () => {
    const result = produceRetentionAssessment(evidenceFor(coveredScope(), coveredCoverage(), 'met'));
    // The canonical order is the writer's, not the caller's: rebuilding the same facts with the coverage
    // members listed from the last to the first cannot move a byte, because assemble writes them in the order
    // the layout declares before it serializes.
    const coverage = coveredCoverage();
    const reordered: CoverageDraft = {
      suffixLoss: coverage.suffixLoss,
      rollbacks: coverage.rollbacks,
      duplicates: coverage.duplicates,
      gaps: coverage.gaps,
      span: coverage.span,
      observedHead: coverage.observedHead,
      checkpoints: coverage.checkpoints,
      acknowledged: coverage.acknowledged,
      runs: coverage.runs,
    };
    expect(produceRetentionAssessment(evidenceFor(coveredScope(), reordered, 'met')).bytes).toBe(result.bytes);
  });

  it('refuses to state met over span-only evidence, which its reader reads as indeterminate', () => {
    expect(produced(() => produceRetentionAssessment(evidenceFor(coveredScope(), spanOnlyCoverage(), 'met')))).toBe(
      'RETENTION_ASSESSMENT_DISAGREES',
    );
  });

  it('states the span-only evidence honestly as indeterminate when the writer does not overclaim it', () => {
    const result = produceRetentionAssessment(evidenceFor(coveredScope(), spanOnlyCoverage(), 'indeterminate'));
    expect(result.assessment.outcome).toBe('indeterminate');
    expect(JSON.parse(result.bytes)).toEqual(result.document);
  });

  it('leaves a missing pin as the honest none it was given and refuses to call it met', () => {
    const scope = coveredScope();
    scope.intake = {
      from: 1,
      to: 100,
      expectedHead: { sha256: null, pinnedBy: 'none', reason: 'no customer held a head for this period' },
    };
    expect(produced(() => produceRetentionAssessment(evidenceFor(scope, coveredCoverage(), 'met')))).toBe(
      'RETENTION_ASSESSMENT_DISAGREES',
    );
    // Stated honestly it reads indeterminate, and the pin block travels through unchanged.
    const honest = produceRetentionAssessment(evidenceFor(scope, coveredCoverage(), 'indeterminate'));
    expect(honest.assessment.outcome).toBe('indeterminate');
    expect(honest.document.scope.intake.expectedHead).toEqual({
      sha256: null,
      pinnedBy: 'none',
      reason: 'no customer held a head for this period',
    });
  });

  it('catches a pinned head that disagrees with the observed head as not-met', () => {
    const coverage = coveredCoverage();
    coverage.observedHead = { sequence: 100, sha256: OTHER };
    coverage.checkpoints = [
      { range: { from: 1, to: 34 }, at: PERIOD_FROM, head: '11'.repeat(32) },
      { range: { from: 35, to: 67 }, at: PERIOD_FROM + 100, head: '22'.repeat(32) },
      { range: { from: 68, to: 100 }, at: PERIOD_TO, head: OTHER },
    ];
    const stale = evidenceFor(coveredScope(), coverage, 'not-met');
    expect(produceRetentionAssessment(stale).assessment.outcome).toBe('not-met');
    // The stale replay is not met, and a writer that claimed met over it is refused.
    expect(produced(() => produceRetentionAssessment(evidenceFor(coveredScope(), coverage, 'met')))).toBe(
      'RETENTION_ASSESSMENT_DISAGREES',
    );
  });

  it('writes an interior gap as not-met and a missing checkpoint as indeterminate', () => {
    const gapCoverage = coveredCoverage();
    gapCoverage.runs = [
      { from: 1, to: 40 },
      { from: 61, to: 100 },
    ];
    gapCoverage.acknowledged = [
      { from: 1, to: 40 },
      { from: 61, to: 100 },
    ];
    gapCoverage.checkpoints = [
      { range: { from: 1, to: 40 }, at: PERIOD_FROM, head: OTHER },
      { range: { from: 61, to: 100 }, at: PERIOD_TO, head: HEAD },
    ];
    gapCoverage.gaps = [{ from: 41, to: 60, reason: 'the process restarted without its sequence state' }];
    expect(produceRetentionAssessment(evidenceFor(coveredScope(), gapCoverage, 'not-met')).assessment.outcome).toBe(
      'not-met',
    );

    const noCheckpoint = coveredCoverage();
    noCheckpoint.checkpoints = [];
    expect(
      produceRetentionAssessment(evidenceFor(coveredScope(), noCheckpoint, 'indeterminate')).assessment.outcome,
    ).toBe('indeterminate');
  });

  it('refuses evidence the reader will not take at all, rather than emitting it', () => {
    // A checkpoint that claims a range the runs do not support is a layout fault, not a disagreement about the
    // outcome, and the producer surfaces the reader's own refusal rather than writing the document.
    const coverage = coveredCoverage();
    coverage.runs = [{ from: 1, to: 40 }];
    coverage.acknowledged = [{ from: 1, to: 40 }];
    coverage.observedHead = { sequence: 40, sha256: HEAD };
    expect(produced(() => produceRetentionAssessment(evidenceFor(coveredScope(), coverage, 'not-met')))).toBe(
      'NOT_RETENTION_ASSESSMENT',
    );
  });
});
