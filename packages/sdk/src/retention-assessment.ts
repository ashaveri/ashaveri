import { ReceiptError } from '@ashaveri/receipt';
import { SdkError, type SdkErrorCode } from './errors.js';

/**
 * The retention assessment, and the reading that decides what its evidence supports.
 *
 * A retention manifest states a window between the oldest record a store still holds and the instant the
 * manifest was written. That window is arithmetic, and the shipped reader refuses a manifest that states
 * it wrongly, but no subtraction can show that the store held every record across the period between the
 * two ends. A store that crashed, restored a backup, lost a suffix or acknowledged nothing for a week
 * still reports the same distance from its oldest survivor to now. This document is the shape that asks
 * the question the subtraction cannot answer, and the reading is public so that a party who does not
 * trust the writer can run it over the same bytes.
 *
 * The document carries three blocks. `scope` is what the deployment declares: who the assessment is
 * about, the article and period it takes itself to owe, the intake sequence range with an expected head
 * pinned outside the deployment, the checkpoint schedule, the clock the stamps rest on with its declared
 * uncertainty, and what the scope leaves out. `coverage` is what was observed: the intake sequence runs,
 * the ranges the store acknowledged, the checkpoint receipts, the observed head, a span where the only
 * evidence is a span, and the explicit disruptions. `assessment` is the deployment's own conclusion, in
 * the same spirit as a retention manifest's `duty.met`: a claim a reader recomputes rather than believes.
 *
 * Three properties arrange the reading.
 *
 * A span is not coverage. Where `coverage.span` states timestamps and no sequence run, the reading answers
 * `indeterminate` however long the span is and however cleanly its newest head matches the pin. The maximum
 * minus the minimum timestamp is not evidence that every record between them survived, and no member of
 * this layout gives that subtraction a path to `met`.
 *
 * An adverse observation is never a pass. A gap, a duplicate, a rollback, a lost suffix or a final
 * checkpoint head that is not the head the intake observed makes the assessment `not-met`, because the
 * evidence states that the period was not continuously held. A missing checkpoint, a checkpoint list that
 * does not tile the declared intake, an unacknowledged interval, a missing expected head or a head the
 * deployment asserted about itself makes it `indeterminate`, because the evidence cannot answer either way.
 *
 * The stated conclusion is recomputed. `assessment.outcome` is the writer's claim, and a reader that
 * computed another outcome refuses the document under `RETENTION_ASSESSMENT_DISAGREES`. A writer cannot
 * reach `met` by writing the word: the evidence has to support it.
 */

/** The one retention assessment version this module reads. A document names its own and never inherits this one. */
export const RETENTION_ASSESSMENT_FORMAT_VERSION = 1;

const IMPLEMENTED_RETENTION_ASSESSMENT_VERSIONS: readonly number[] = [RETENTION_ASSESSMENT_FORMAT_VERSION];

/**
 * The three duty labels a scope may declare, the closed set the retention manifest beside this family
 * already enumerates. The label is the deployment's own reading of the obligation and nothing here
 * interprets it.
 */
export const RETENTION_ASSESSMENT_ARTICLES = ['19(1)', '19(2)', '26(6)'] as const;

/** The labels above as a type. */
export type RetentionAssessmentArticle = (typeof RETENTION_ASSESSMENT_ARTICLES)[number];

/**
 * Who may pin the expected head, the whole closed set written once as a list.
 *
 * `customer` and `external-holder` are parties other than the subject, and a head one of them pinned is
 * independent of the intake that is being assessed. `subject` states honestly that the deployment pinned
 * the head about itself, and the reading weighs that declaration as self-assertion rather than as a pin.
 * `none` says nobody pinned one, and a reason has to stand beside it. A writer that names the intake, the
 * observation or the document as the pinning party is refused by the layout, because a head the intake
 * wrote beside its own observation is that observation repeated, and a reader that accepted it would let
 * the document attest itself.
 */
export const EXPECTED_HEAD_PINNERS = ['customer', 'external-holder', 'subject', 'none'] as const;

/** The pinning parties above as a type. */
export type ExpectedHeadPinner = (typeof EXPECTED_HEAD_PINNERS)[number];

/** The three outcomes a retention assessment can reach. Only one of them claims the period was covered. */
export const RETENTION_ASSESSMENT_OUTCOMES = ['met', 'not-met', 'indeterminate'] as const;

/** The outcomes above as a type. */
export type RetentionAssessmentOutcome = (typeof RETENTION_ASSESSMENT_OUTCOMES)[number];

/** The three results a coverage block can reach, before the retention outcome is decided. */
export const RETENTION_COVERAGE_RESULTS = ['covered', 'gap', 'indeterminate'] as const;

/** The coverage results above as a type. */
export type RetentionCoverageResult = (typeof RETENTION_COVERAGE_RESULTS)[number];

/** The highest interval a checkpoint schedule may declare, which is the hourly floor stated as a number. */
export const MAX_CHECKPOINT_INTERVAL_SECONDS = 3_600;

/**
 * The members each block of the layout defines, written once as lists because the published schema is the
 * second statement of the same sets. `test/retention-assessment.test.ts` reads both spellings and refuses a
 * disagreement in either direction, the way the capture and import suites hold their own member lists.
 */
export const RETENTION_ASSESSMENT_MEMBERS = ['v', 'scope', 'coverage', 'assessment'] as const;
export const RETENTION_SCOPE_MEMBERS = ['subject', 'duty', 'period', 'intake', 'checkpoint', 'timeBasis', 'excludes'] as const;
export const RETENTION_COVERAGE_MEMBERS = [
  'runs',
  'acknowledged',
  'checkpoints',
  'observedHead',
  'span',
  'gaps',
  'duplicates',
  'rollbacks',
  'suffixLoss',
] as const;

/** What the assessment is about, in the subject's own words: a deployment or a provider. */
export interface RetentionAssessmentSubject {
  readonly kind: 'deployment' | 'provider';
  readonly id: string;
}

/** The obligation the deployment declares, as its own statement rather than as this estate's reading. */
export interface RetentionAssessmentDuty {
  readonly article: RetentionAssessmentArticle;
  readonly requiredSeconds: number;
}

/** The period the assessment is about, in whole unix seconds, both ends inclusive. */
export interface RetentionAssessmentPeriod {
  readonly from: number;
  readonly to: number;
}

/**
 * The head the deployment expected at the last intake sequence, and who pinned it.
 *
 * A head with a `sha256` and a party other than the subject is the pin the reading compares against what
 * the intake observed. A null `sha256` names the absence of a pin and owes its reason; so does `none`.
 */
export interface RetentionAssessmentExpectedHead {
  readonly sha256: string | null;
  readonly pinnedBy: ExpectedHeadPinner;
  readonly reason: string | null;
}

/** The intake sequence range the scope is about, and the head expected at its end. */
export interface RetentionAssessmentIntake {
  readonly from: number;
  readonly to: number;
  readonly expectedHead: RetentionAssessmentExpectedHead;
}

/**
 * The checkpoint schedule the deployment declares: a customer holds the receipts, every completed batch
 * produces one, and no two are more than the stated interval apart.
 *
 * The layout refuses a weaker schedule rather than reading it as a different promise, because the
 * checkpoint is the only temporal witness this family carries and a period with no hourly witness is a
 * period whose continuity no reader can place.
 */
export interface RetentionAssessmentCheckpointSchedule {
  readonly holder: 'customer';
  readonly eachCompletedBatch: true;
  readonly maxIntervalSeconds: number;
}

/**
 * The clock basis every stamp in the document rests on, and how far that clock may stand from the instant
 * it names. A null uncertainty states that nobody measured the source, which is a statement and not a
 * bound of zero.
 *
 * This block is the named seam to a policy demand on the clock bound. This version carries the
 * declaration and the reading reports it beside the result; nothing here refuses a document because its
 * uncertainty is wide, because that demand belongs to a policy and not to this layout.
 */
export interface RetentionAssessmentTimeBasis {
  readonly source: string;
  readonly uncertaintySeconds: number | null;
}

/** The declared scope: who, what duty, which period and intake, which checkpoints, which clock, what is out. */
export interface RetentionAssessmentScope {
  readonly subject: RetentionAssessmentSubject;
  readonly duty: RetentionAssessmentDuty;
  readonly period: RetentionAssessmentPeriod;
  readonly intake: RetentionAssessmentIntake;
  readonly checkpoint: RetentionAssessmentCheckpointSchedule;
  readonly timeBasis: RetentionAssessmentTimeBasis;
  readonly excludes: readonly string[];
}

/** One inclusive range of intake sequence numbers. */
export interface RetentionSequenceRange {
  readonly from: number;
  readonly to: number;
}

/** One checkpoint receipt: the sequence range it covers, the instant it was taken and the head it names. */
export interface RetentionCheckpointReceipt {
  readonly range: RetentionSequenceRange;
  readonly at: number;
  readonly head: string;
}

/** The head the intake observed at the last sequence it saw. */
export interface RetentionObservedHead {
  readonly sequence: number;
  readonly sha256: string;
}

/**
 * The oldest and newest surviving records with their timestamps and heads.
 *
 * A span states what survived and when it was stamped. It says nothing about the sequences between the
 * two ends, which is the whole reason the span-only path exists: the reading can answer `indeterminate`
 * for it and can never answer `met`.
 */
export interface RetentionCoverageSpan {
  readonly from: number;
  readonly to: number;
  readonly oldestHead: string;
  readonly newestHead: string;
}

/** One observed stretch the intake did not carry, in sequence numbers. */
export interface RetentionCoverageGap extends RetentionSequenceRange {
  readonly reason: string;
}

/** One intake sequence that arrived more than once, and how many times the intake saw it. */
export interface RetentionCoverageDuplicate {
  readonly sequence: number;
  readonly count: number;
}

/** One observed rollback: the head the intake saw at a sequence, and the earlier head it restored. */
export interface RetentionCoverageRollback {
  readonly sequence: number;
  readonly observedHead: string;
  readonly restoredHead: string;
}

/** The tail of the declared range the intake never observed, against the head pinned at its end. */
export interface RetentionCoverageSuffixLoss extends RetentionSequenceRange {
  readonly reason: string;
}

/** What the intake observed, stated as runs, acknowledgments, checkpoints and explicit disruptions. */
export interface RetentionCoverage {
  readonly runs: readonly RetentionSequenceRange[];
  readonly acknowledged: readonly RetentionSequenceRange[];
  readonly checkpoints: readonly RetentionCheckpointReceipt[];
  readonly observedHead: RetentionObservedHead | null;
  readonly span: RetentionCoverageSpan | null;
  readonly gaps: readonly RetentionCoverageGap[];
  readonly duplicates: readonly RetentionCoverageDuplicate[];
  readonly rollbacks: readonly RetentionCoverageRollback[];
  readonly suffixLoss: RetentionCoverageSuffixLoss | null;
}

/** The deployment's own conclusion, which the reading recomputes rather than believes. */
export interface RetentionAssessmentClaim {
  readonly outcome: RetentionAssessmentOutcome;
}

/** The whole document: declared scope, observed coverage, and the deployment's conclusion. */
export interface RetentionAssessmentDocument {
  readonly v: number;
  readonly scope: RetentionAssessmentScope;
  readonly coverage: RetentionCoverage;
  readonly assessment: RetentionAssessmentClaim;
}

/**
 * What the reading concluded about coverage, in the basis its ranges are stated in.
 *
 * `sequence` ranges name intake sequence numbers; `time` ranges name unix seconds. A gap is always a
 * sequence finding, a missing checkpoint is always a time finding, and an unacknowledged interval is a
 * sequence finding. The reasons say what produced the result, one sentence each.
 */
export interface RetentionCoverageAssessment {
  readonly result: RetentionCoverageResult;
  readonly basis: 'sequence' | 'time';
  readonly ranges: readonly RetentionSequenceRange[];
  readonly reasons: readonly string[];
}

/** What the reading concluded, beside the scope it was asked about. */
export interface RetentionAssessmentResult {
  readonly outcome: RetentionAssessmentOutcome;
  readonly coverage: RetentionCoverageAssessment;
  readonly stated: {
    readonly subject: RetentionAssessmentSubject;
    readonly duty: RetentionAssessmentDuty;
    readonly period: RetentionAssessmentPeriod;
    readonly intake: RetentionAssessmentIntake;
    readonly checkpoint: RetentionAssessmentCheckpointSchedule;
    readonly timeBasis: RetentionAssessmentTimeBasis;
    readonly excludes: readonly string[];
  };
  /** One line each about what the outcome rests on, safe for a log. */
  readonly reasons: readonly string[];
}

const HEX64 = /^[0-9a-f]{64}$/;

function refused(code: SdkErrorCode, message: string): never {
  throw new SdkError(code, message);
}

function describe(value: unknown): string {
  if (typeof value === 'string') return `'${value}'`;
  if (value === undefined) return 'absent';
  if (value === null) return 'null';
  return `a ${Array.isArray(value) ? 'list' : typeof value}`;
}

function requireObject(value: unknown, where: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return refused('NOT_RETENTION_ASSESSMENT', `${where} is ${describe(value)}, which is not a member block of a retention assessment`);
  }
  return value as Record<string, unknown>;
}

/**
 * Closure, stated as the capture and import readers state it: a member the version does not define makes
 * the document invalid rather than a document read with the member dropped. A writer that stated a field
 * this reader does not know was answering a question the layout cannot ask, and dropping the answer
 * quietly would turn it into a silence.
 */
function requireKnownMembers(raw: Record<string, unknown>, allowed: readonly string[], where: string): void {
  for (const member of Object.keys(raw)) {
    if (!allowed.includes(member)) {
      refused(
        'NOT_RETENTION_ASSESSMENT',
        `${where} carries '${member}', which retention assessment version ${String(RETENTION_ASSESSMENT_FORMAT_VERSION)} does not define`,
      );
    }
  }
}

function requireText(raw: Record<string, unknown>, key: string, where: string): string {
  const value = raw[key];
  if (typeof value !== 'string' || value.length === 0) {
    refused('NOT_RETENTION_ASSESSMENT', `${where}.${key} is ${describe(value)}, and the document has to name it`);
  }
  return value;
}

function requireWhole(raw: Record<string, unknown>, key: string, where: string, what: string): number {
  const value = raw[key];
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    refused('NOT_RETENTION_ASSESSMENT', `${where}.${key} is ${describe(value)}, and ${what} is a non-negative whole number`);
  }
  return value;
}

function requirePositive(raw: Record<string, unknown>, key: string, where: string, what: string): number {
  const value = requireWhole(raw, key, where, what);
  if (value === 0) {
    refused('NOT_RETENTION_ASSESSMENT', `${where}.${key} is zero, and ${what} is a whole number of at least one`);
  }
  return value;
}

function requireOrNullWhole(raw: Record<string, unknown>, key: string, where: string, what: string): number | null {
  if (raw[key] === null) return null;
  return requireWhole(raw, key, where, what);
}

function requireBoolean(raw: Record<string, unknown>, key: string, where: string): boolean {
  const value = raw[key];
  if (typeof value !== 'boolean') {
    refused('NOT_RETENTION_ASSESSMENT', `${where}.${key} is ${describe(value)}: the document states it either way rather than leaving it out`);
  }
  return value;
}

function requireDigest(raw: Record<string, unknown>, key: string, where: string): string {
  const value = raw[key];
  if (typeof value !== 'string' || !HEX64.test(value)) {
    refused('NOT_RETENTION_ASSESSMENT', `${where}.${key} is ${describe(value)}, and a head is 64 lowercase hex characters`);
  }
  return value;
}

function requireDigestOrNull(raw: Record<string, unknown>, key: string, where: string): string | null {
  if (raw[key] === null) return null;
  return requireDigest(raw, key, where);
}

/**
 * The version the document names, against the versions this module reads. The element of the list is
 * returned rather than the number the document named, so the lookup is at once the refusal test and the
 * witness that what comes back is a version with rules behind it.
 */
function requireImplementedVersion(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value)) {
    throw new ReceiptError('UNSUPPORTED_VERSION', `retention assessment names ${describe(value)} where a version number belongs`);
  }
  const stated = IMPLEMENTED_RETENTION_ASSESSMENT_VERSIONS.find((each) => each === value);
  if (stated === undefined) {
    throw new ReceiptError(
      'UNSUPPORTED_VERSION',
      `retention assessment names version ${String(value)}, and this reader implements ${IMPLEMENTED_RETENTION_ASSESSMENT_VERSIONS.join(', ')} and does not read it as one of them`,
    );
  }
  return stated;
}

function readSubject(value: unknown): RetentionAssessmentSubject {
  const raw = requireObject(value, 'scope.subject');
  requireKnownMembers(raw, ['kind', 'id'], 'scope.subject');
  const kind = raw['kind'];
  if (kind !== 'deployment' && kind !== 'provider') {
    refused(
      'NOT_RETENTION_ASSESSMENT',
      `scope.subject.kind is ${describe(kind)}, and an assessment is about a deployment or a provider`,
    );
  }
  return { kind, id: requireText(raw, 'id', 'scope.subject') };
}

function readDuty(value: unknown): RetentionAssessmentDuty {
  const raw = requireObject(value, 'scope.duty');
  requireKnownMembers(raw, ['article', 'requiredSeconds'], 'scope.duty');
  const article = raw['article'];
  if (typeof article !== 'string' || !(RETENTION_ASSESSMENT_ARTICLES as readonly string[]).includes(article)) {
    refused(
      'NOT_RETENTION_ASSESSMENT',
      `scope.duty.article is ${describe(article)}, and the layout enumerates ${RETENTION_ASSESSMENT_ARTICLES.join(', ')}`,
    );
  }
  return {
    article: article as RetentionAssessmentArticle,
    requiredSeconds: requirePositive(raw, 'requiredSeconds', 'scope.duty', 'a declared period'),
  };
}

function readRange(value: unknown, where: string): RetentionSequenceRange {
  const raw = requireObject(value, where);
  requireKnownMembers(raw, ['from', 'to'], where);
  const from = requireWhole(raw, 'from', where, 'a sequence number');
  const to = requireWhole(raw, 'to', where, 'a sequence number');
  if (from > to) {
    refused(
      'NOT_RETENTION_ASSESSMENT',
      `${where} runs from ${String(from)} to ${String(to)}, which is not an ascending range of intake sequences`,
    );
  }
  return { from, to };
}

/**
 * An ordered list of inclusive sequence ranges, refused where the order is not ascending and refused again
 * where two ranges claim one sequence.
 *
 * The two refusals are separate sentences because they are separate faults in the intake: a range that
 * runs backwards is a non-monotonic observation, while two ranges that meet at or before an earlier end
 * are one sequence stated twice. A reader that folded either into the other would leave an operator
 * unable to tell a clock running backwards from a retry writing a record twice.
 */
function readOrderedRanges(value: unknown, where: string, declared: RetentionSequenceRange): RetentionSequenceRange[] {
  if (!Array.isArray(value)) {
    refused('NOT_RETENTION_ASSESSMENT', `${where} is ${describe(value)}, and the observed ranges are a list`);
  }
  const ranges = value.map((entry, index) => {
    const range = readRange(entry, `${where}[${String(index)}]`);
    if (range.from < declared.from || range.to > declared.to) {
      refused(
        'NOT_RETENTION_ASSESSMENT',
        `${where}[${String(index)}] covers ${String(range.from)} to ${String(range.to)}, outside the declared intake range ${String(declared.from)} to ${String(declared.to)}`,
      );
    }
    return range;
  });
  for (let index = 1; index < ranges.length; index += 1) {
    const range = ranges[index];
    const previous = ranges[index - 1];
    if (range === undefined || previous === undefined) continue;
    if (range.from < previous.from) {
      refused(
        'NOT_RETENTION_ASSESSMENT',
        `${where} lists a range beginning at ${String(range.from)} after one beginning at ${String(previous.from)}, so the intake sequence is not monotonic`,
      );
    }
    if (range.from <= previous.to) {
      refused(
        'NOT_RETENTION_ASSESSMENT',
        `${where} lists sequence ${String(range.from)} twice: one range ends at ${String(previous.to)} and the next begins at ${String(range.from)}`,
      );
    }
  }
  return ranges;
}

function readPeriod(value: unknown): RetentionAssessmentPeriod {
  const raw = requireObject(value, 'scope.period');
  requireKnownMembers(raw, ['from', 'to'], 'scope.period');
  const from = requireWhole(raw, 'from', 'scope.period', 'a unix time');
  const to = requireWhole(raw, 'to', 'scope.period', 'a unix time');
  if (from > to) {
    refused(
      'NOT_RETENTION_ASSESSMENT',
      `scope.period runs from ${String(from)} to ${String(to)}, which is not a period that runs forwards`,
    );
  }
  return { from, to };
}

function readExpectedHead(value: unknown): RetentionAssessmentExpectedHead {
  const raw = requireObject(value, 'scope.intake.expectedHead');
  requireKnownMembers(raw, ['sha256', 'pinnedBy', 'reason'], 'scope.intake.expectedHead');
  const sha256 = requireDigestOrNull(raw, 'sha256', 'scope.intake.expectedHead');
  const pinnedBy = raw['pinnedBy'];
  if (typeof pinnedBy !== 'string' || !(EXPECTED_HEAD_PINNERS as readonly string[]).includes(pinnedBy)) {
    const self = typeof pinnedBy === 'string' && ['self', 'intake', 'observation', 'document'].includes(pinnedBy);
    refused(
      'NOT_RETENTION_ASSESSMENT',
      self
        ? `scope.intake.expectedHead.pinnedBy is '${pinnedBy}', which names the intake rather than a party that could pin a head independently of it`
        : `scope.intake.expectedHead.pinnedBy is ${describe(pinnedBy)}, and the layout enumerates ${EXPECTED_HEAD_PINNERS.join(', ')}`,
    );
  }
  const reason = raw['reason'] === null ? null : requireText(raw, 'reason', 'scope.intake.expectedHead');
  if (sha256 === null && pinnedBy !== 'none') {
    refused(
      'NOT_RETENTION_ASSESSMENT',
      `scope.intake.expectedHead states no head and names '${pinnedBy}' as the party that pinned it, which is a party credited with a pin it did not make`,
    );
  }
  if (sha256 !== null && pinnedBy === 'none') {
    refused(
      'NOT_RETENTION_ASSESSMENT',
      'scope.intake.expectedHead states a head and names nobody as the party that pinned it',
    );
  }
  if ((sha256 === null || pinnedBy === 'none') && reason === null) {
    refused(
      'NOT_RETENTION_ASSESSMENT',
      'scope.intake.expectedHead states no independent pin and gives no reason, so the absence is silent',
    );
  }
  if (sha256 !== null && reason !== null) {
    refused(
      'NOT_RETENTION_ASSESSMENT',
      'scope.intake.expectedHead states a head and a reason for having none, so the block contradicts itself',
    );
  }
  return { sha256, pinnedBy: pinnedBy as ExpectedHeadPinner, reason };
}

function readIntake(value: unknown): RetentionAssessmentIntake {
  const raw = requireObject(value, 'scope.intake');
  requireKnownMembers(raw, ['from', 'to', 'expectedHead'], 'scope.intake');
  const from = requireWhole(raw, 'from', 'scope.intake', 'a sequence number');
  const to = requireWhole(raw, 'to', 'scope.intake', 'a sequence number');
  if (from > to) {
    refused(
      'NOT_RETENTION_ASSESSMENT',
      `scope.intake runs from ${String(from)} to ${String(to)}, which is not an ascending range of intake sequences`,
    );
  }
  return { from, to, expectedHead: readExpectedHead(raw['expectedHead']) };
}

function readCheckpointSchedule(value: unknown): RetentionAssessmentCheckpointSchedule {
  const raw = requireObject(value, 'scope.checkpoint');
  requireKnownMembers(raw, ['holder', 'eachCompletedBatch', 'maxIntervalSeconds'], 'scope.checkpoint');
  const holder = raw['holder'];
  if (holder !== 'customer') {
    refused(
      'NOT_RETENTION_ASSESSMENT',
      `scope.checkpoint.holder is ${describe(holder)}, and this layout defines a customer-held schedule only`,
    );
  }
  if (!requireBoolean(raw, 'eachCompletedBatch', 'scope.checkpoint')) {
    refused(
      'NOT_RETENTION_ASSESSMENT',
      'scope.checkpoint.eachCompletedBatch is false, and a schedule that skips completed batches is not the schedule this layout assesses',
    );
  }
  const maxIntervalSeconds = requirePositive(
    raw,
    'maxIntervalSeconds',
    'scope.checkpoint',
    'a checkpoint interval',
  );
  if (maxIntervalSeconds > MAX_CHECKPOINT_INTERVAL_SECONDS) {
    refused(
      'NOT_RETENTION_ASSESSMENT',
      `scope.checkpoint.maxIntervalSeconds is ${String(maxIntervalSeconds)}, above the ${String(MAX_CHECKPOINT_INTERVAL_SECONDS)} seconds this layout requires at most`,
    );
  }
  return { holder: 'customer', eachCompletedBatch: true, maxIntervalSeconds };
}

function readTimeBasis(value: unknown): RetentionAssessmentTimeBasis {
  const raw = requireObject(value, 'scope.timeBasis');
  requireKnownMembers(raw, ['source', 'uncertaintySeconds'], 'scope.timeBasis');
  return {
    source: requireText(raw, 'source', 'scope.timeBasis'),
    uncertaintySeconds: requireOrNullWhole(raw, 'uncertaintySeconds', 'scope.timeBasis', 'a bound in whole seconds'),
  };
}

function readExcludes(value: unknown): string[] {
  if (!Array.isArray(value)) {
    refused('NOT_RETENTION_ASSESSMENT', `scope.excludes is ${describe(value)}, and the exclusions are a list`);
  }
  return value.map((entry, index) => {
    if (typeof entry !== 'string' || entry.length === 0) {
      refused(
        'NOT_RETENTION_ASSESSMENT',
        `scope.excludes[${String(index)}] is ${describe(entry)}, and an exclusion is a sentence`,
      );
    }
    return entry;
  });
}

function readScope(value: unknown): RetentionAssessmentScope {
  const raw = requireObject(value, 'scope');
  requireKnownMembers(raw, RETENTION_SCOPE_MEMBERS, 'scope');
  return {
    subject: readSubject(raw['subject']),
    duty: readDuty(raw['duty']),
    period: readPeriod(raw['period']),
    intake: readIntake(raw['intake']),
    checkpoint: readCheckpointSchedule(raw['checkpoint']),
    timeBasis: readTimeBasis(raw['timeBasis']),
    excludes: readExcludes(raw['excludes']),
  };
}

/** Whether a sequence lies inside an inclusive range. */
function within(sequence: number, range: RetentionSequenceRange): boolean {
  return sequence >= range.from && sequence <= range.to;
}

/** Whether two inclusive ranges share a sequence. */
function overlaps(one: RetentionSequenceRange, other: RetentionSequenceRange): boolean {
  return one.from <= other.to && other.from <= one.to;
}

/** Whether every sequence of a range is covered by the runs beside it, which are ascending and disjoint. */
function supported(runs: readonly RetentionSequenceRange[], range: RetentionSequenceRange): boolean {
  let cursor = range.from;
  for (const run of runs) {
    if (run.to < cursor) continue;
    if (run.from > cursor) return false;
    cursor = Math.max(cursor, run.to + 1);
    if (cursor > range.to) return true;
  }
  return cursor > range.to;
}

function readCheckpoints(
  value: unknown,
  declared: RetentionSequenceRange,
  runs: readonly RetentionSequenceRange[],
): RetentionCheckpointReceipt[] {
  if (!Array.isArray(value)) {
    refused('NOT_RETENTION_ASSESSMENT', `coverage.checkpoints is ${describe(value)}, and checkpoint receipts are a list`);
  }
  const receipts = value.map((entry, index) => {
    const where = `coverage.checkpoints[${String(index)}]`;
    const raw = requireObject(entry, where);
    requireKnownMembers(raw, ['range', 'at', 'head'], where);
    const range = readRange(raw['range'], `${where}.range`);
    if (range.from < declared.from || range.to > declared.to) {
      refused(
        'NOT_RETENTION_ASSESSMENT',
        `${where}.range covers ${String(range.from)} to ${String(range.to)}, outside the declared intake range ${String(declared.from)} to ${String(declared.to)}`,
      );
    }
    if (!supported(runs, range)) {
      refused(
        'NOT_RETENTION_ASSESSMENT',
        `${where}.range claims ${String(range.from)} to ${String(range.to)}, which the observed intake runs do not support`,
      );
    }
    return {
      range,
      at: requireWhole(raw, 'at', where, 'a unix time'),
      head: requireDigest(raw, 'head', where),
    };
  });
  for (let index = 1; index < receipts.length; index += 1) {
    const receipt = receipts[index];
    const previous = receipts[index - 1];
    if (receipt === undefined || previous === undefined) continue;
    if (receipt.range.from <= previous.range.to) {
      refused(
        'NOT_RETENTION_ASSESSMENT',
        `coverage.checkpoints lists sequence ${String(receipt.range.from)} twice: one receipt ends at ${String(previous.range.to)} and the next begins at ${String(receipt.range.from)}`,
      );
    }
    if (receipt.at <= previous.at) {
      refused(
        'NOT_RETENTION_ASSESSMENT',
        `coverage.checkpoints stamps the receipt at ${String(receipt.at)} after one stamped at ${String(previous.at)}, so the checkpoint order is not monotonic`,
      );
    }
  }
  return receipts;
}

function readObservedHead(value: unknown, runs: readonly RetentionSequenceRange[]): RetentionObservedHead | null {
  if (value === null) {
    if (runs.length > 0) {
      refused(
        'NOT_RETENTION_ASSESSMENT',
        'coverage.observedHead is null while coverage.runs states an observation, so the document names no head for the run it holds',
      );
    }
    return null;
  }
  const raw = requireObject(value, 'coverage.observedHead');
  requireKnownMembers(raw, ['sequence', 'sha256'], 'coverage.observedHead');
  const sequence = requireWhole(raw, 'sequence', 'coverage.observedHead', 'a sequence number');
  const head: RetentionObservedHead = {
    sequence,
    sha256: requireDigest(raw, 'sha256', 'coverage.observedHead'),
  };
  if (runs.length === 0) {
    refused(
      'NOT_RETENTION_ASSESSMENT',
      `coverage.observedHead names sequence ${String(sequence)} while coverage.runs states nothing, so the observation has no run behind it`,
    );
  }
  const last = runs[runs.length - 1];
  if (last === undefined) {
    return refused('NOT_RETENTION_ASSESSMENT', 'coverage.observedHead stands beside no run this reader can reach');
  }
  if (sequence !== last.to) {
    refused(
      'NOT_RETENTION_ASSESSMENT',
      `coverage.observedHead names sequence ${String(sequence)} and the last observed run ends at ${String(last.to)}`,
    );
  }
  return head;
}

function readSpan(value: unknown): RetentionCoverageSpan | null {
  if (value === null) return null;
  const raw = requireObject(value, 'coverage.span');
  requireKnownMembers(raw, ['from', 'to', 'oldestHead', 'newestHead'], 'coverage.span');
  const from = requireWhole(raw, 'from', 'coverage.span', 'a unix time');
  const to = requireWhole(raw, 'to', 'coverage.span', 'a unix time');
  if (from > to) {
    refused(
      'NOT_RETENTION_ASSESSMENT',
      `coverage.span runs from ${String(from)} to ${String(to)}, which is not a span that runs forwards`,
    );
  }
  return {
    from,
    to,
    oldestHead: requireDigest(raw, 'oldestHead', 'coverage.span'),
    newestHead: requireDigest(raw, 'newestHead', 'coverage.span'),
  };
}

function readGaps(value: unknown, declared: RetentionSequenceRange, runs: readonly RetentionSequenceRange[]): RetentionCoverageGap[] {
  if (!Array.isArray(value)) {
    refused('NOT_RETENTION_ASSESSMENT', `coverage.gaps is ${describe(value)}, and the gaps are a list`);
  }
  const gaps = value.map((entry, index) => {
    const where = `coverage.gaps[${String(index)}]`;
    const raw = requireObject(entry, where);
    requireKnownMembers(raw, ['from', 'to', 'reason'], where);
    const range = {
      from: requireWhole(raw, 'from', where, 'a sequence number'),
      to: requireWhole(raw, 'to', where, 'a sequence number'),
    };
    if (range.from > range.to) {
      refused(
        'NOT_RETENTION_ASSESSMENT',
        `${where} runs from ${String(range.from)} to ${String(range.to)}, which is not an ascending range of intake sequences`,
      );
    }
    if (range.from < declared.from || range.to > declared.to) {
      refused(
        'NOT_RETENTION_ASSESSMENT',
        `${where} covers ${String(range.from)} to ${String(range.to)}, outside the declared intake range ${String(declared.from)} to ${String(declared.to)}`,
      );
    }
    if (runs.some((run) => overlaps(run, range))) {
      refused(
        'NOT_RETENTION_ASSESSMENT',
        `${where} states a gap over ${String(range.from)} to ${String(range.to)}, which a run beside it observed`,
      );
    }
    return { ...range, reason: requireText(raw, 'reason', where) };
  });
  for (let index = 1; index < gaps.length; index += 1) {
    const gap = gaps[index];
    const previous = gaps[index - 1];
    if (gap === undefined || previous === undefined) continue;
    if (overlaps(previous, gap)) {
      refused('NOT_RETENTION_ASSESSMENT', `coverage.gaps states sequence ${String(gap.from)} more than once`);
    }
  }
  return gaps;
}

function readDuplicates(value: unknown, declared: RetentionSequenceRange, runs: readonly RetentionSequenceRange[]): RetentionCoverageDuplicate[] {
  if (!Array.isArray(value)) {
    refused('NOT_RETENTION_ASSESSMENT', `coverage.duplicates is ${describe(value)}, and the duplicates are a list`);
  }
  const duplicates = value.map((entry, index) => {
    const where = `coverage.duplicates[${String(index)}]`;
    const raw = requireObject(entry, where);
    requireKnownMembers(raw, ['sequence', 'count'], where);
    const sequence = requireWhole(raw, 'sequence', where, 'a sequence number');
    if (!within(sequence, declared)) {
      refused(
        'NOT_RETENTION_ASSESSMENT',
        `${where}.sequence is ${String(sequence)}, outside the declared intake range ${String(declared.from)} to ${String(declared.to)}`,
      );
    }
    if (!runs.some((run) => within(sequence, run))) {
      refused(
        'NOT_RETENTION_ASSESSMENT',
        `${where} states a duplicate at sequence ${String(sequence)}, which no observed run reached`,
      );
    }
    const count = requireWhole(raw, 'count', where, 'a duplicate count');
    if (count < 2) {
      refused('NOT_RETENTION_ASSESSMENT', `${where}.count is ${String(count)}, and a sequence seen fewer than twice is not a duplicate`);
    }
    return { sequence, count };
  });
  for (let index = 1; index < duplicates.length; index += 1) {
    const duplicate = duplicates[index];
    const previous = duplicates[index - 1];
    if (duplicate === undefined || previous === undefined) continue;
    if (duplicate.sequence < previous.sequence) {
      refused('NOT_RETENTION_ASSESSMENT', 'coverage.duplicates is not in ascending sequence order');
    }
    if (duplicate.sequence === previous.sequence) {
      refused('NOT_RETENTION_ASSESSMENT', `coverage.duplicates names sequence ${String(duplicate.sequence)} twice`);
    }
  }
  return duplicates;
}

function readRollbacks(value: unknown, declared: RetentionSequenceRange, runs: readonly RetentionSequenceRange[]): RetentionCoverageRollback[] {
  if (!Array.isArray(value)) {
    refused('NOT_RETENTION_ASSESSMENT', `coverage.rollbacks is ${describe(value)}, and the rollbacks are a list`);
  }
  const rollbacks = value.map((entry, index) => {
    const where = `coverage.rollbacks[${String(index)}]`;
    const raw = requireObject(entry, where);
    requireKnownMembers(raw, ['sequence', 'observedHead', 'restoredHead'], where);
    const sequence = requireWhole(raw, 'sequence', where, 'a sequence number');
    if (!within(sequence, declared)) {
      refused(
        'NOT_RETENTION_ASSESSMENT',
        `${where}.sequence is ${String(sequence)}, outside the declared intake range ${String(declared.from)} to ${String(declared.to)}`,
      );
    }
    if (!runs.some((run) => within(sequence, run))) {
      refused(
        'NOT_RETENTION_ASSESSMENT',
        `${where} states a rollback at sequence ${String(sequence)}, which no observed run reached`,
      );
    }
    const observedHead = requireDigest(raw, 'observedHead', where);
    const restoredHead = requireDigest(raw, 'restoredHead', where);
    if (observedHead === restoredHead) {
      refused(
        'NOT_RETENTION_ASSESSMENT',
        `${where} names one head as both the observation and the restored head, so the block states no rollback`,
      );
    }
    return { sequence, observedHead, restoredHead };
  });
  for (let index = 1; index < rollbacks.length; index += 1) {
    const rollback = rollbacks[index];
    const previous = rollbacks[index - 1];
    if (rollback === undefined || previous === undefined) continue;
    if (rollback.sequence < previous.sequence) {
      refused('NOT_RETENTION_ASSESSMENT', 'coverage.rollbacks is not in ascending sequence order');
    }
    if (rollback.sequence === previous.sequence) {
      refused('NOT_RETENTION_ASSESSMENT', `coverage.rollbacks names sequence ${String(rollback.sequence)} twice`);
    }
  }
  return rollbacks;
}

function readSuffixLoss(
  value: unknown,
  declared: RetentionSequenceRange,
  runs: readonly RetentionSequenceRange[],
): RetentionCoverageSuffixLoss | null {
  if (value === null) return null;
  const raw = requireObject(value, 'coverage.suffixLoss');
  requireKnownMembers(raw, ['from', 'to', 'reason'], 'coverage.suffixLoss');
  const from = requireWhole(raw, 'from', 'coverage.suffixLoss', 'a sequence number');
  const to = requireWhole(raw, 'to', 'coverage.suffixLoss', 'a sequence number');
  if (from > to) {
    refused(
      'NOT_RETENTION_ASSESSMENT',
      `coverage.suffixLoss runs from ${String(from)} to ${String(to)}, which is not an ascending range`,
    );
  }
  if (from < declared.from || to > declared.to) {
    refused(
      'NOT_RETENTION_ASSESSMENT',
      `coverage.suffixLoss covers ${String(from)} to ${String(to)}, outside the declared intake range ${String(declared.from)} to ${String(declared.to)}`,
    );
  }
  if (to !== declared.to) {
    refused(
      'NOT_RETENTION_ASSESSMENT',
      `coverage.suffixLoss ends at ${String(to)} and the declared intake ends at ${String(declared.to)}, so the loss stated is not the suffix of the range`,
    );
  }
  const lastRun = runs[runs.length - 1];
  const lastObserved = lastRun === undefined ? declared.from - 1 : lastRun.to;
  if (from !== lastObserved + 1) {
    refused(
      'NOT_RETENTION_ASSESSMENT',
      `coverage.suffixLoss begins at ${String(from)} and the last observed sequence is ${String(lastObserved)}, so the loss stated is not the tail the runs leave`,
    );
  }
  if (runs.some((run) => overlaps(run, { from, to }))) {
    refused(
      'NOT_RETENTION_ASSESSMENT',
      `coverage.suffixLoss states a loss over ${String(from)} to ${String(to)}, which a run beside it observed`,
    );
  }
  return { from, to, reason: requireText(raw, 'reason', 'coverage.suffixLoss') };
}

function readCoverage(value: unknown, scope: RetentionAssessmentScope): RetentionCoverage {
  const raw = requireObject(value, 'coverage');
  requireKnownMembers(raw, RETENTION_COVERAGE_MEMBERS, 'coverage');
  const declared = { from: scope.intake.from, to: scope.intake.to };
  const runs = readOrderedRanges(raw['runs'], 'coverage.runs', declared);
  const acknowledged = readOrderedRanges(raw['acknowledged'], 'coverage.acknowledged', declared);
  const checkpoints = readCheckpoints(raw['checkpoints'], declared, runs);
  const observedHead = readObservedHead(raw['observedHead'], runs);
  const span = readSpan(raw['span']);
  const gaps = readGaps(raw['gaps'], declared, runs);
  const duplicates = readDuplicates(raw['duplicates'], declared, runs);
  const rollbacks = readRollbacks(raw['rollbacks'], declared, runs);
  const suffixLoss = readSuffixLoss(raw['suffixLoss'], declared, runs);
  if (span !== null) {
    if (
      runs.length > 0 ||
      acknowledged.length > 0 ||
      checkpoints.length > 0 ||
      observedHead !== null ||
      gaps.length > 0 ||
      duplicates.length > 0 ||
      rollbacks.length > 0 ||
      suffixLoss !== null
    ) {
      refused(
        'NOT_RETENTION_ASSESSMENT',
        'coverage.span stands beside other coverage evidence, so the document states two bases for one result and the reader cannot tell which produced it',
      );
    }
  }
  return { runs, acknowledged, checkpoints, observedHead, span, gaps, duplicates, rollbacks, suffixLoss };
}

function readAssessment(value: unknown): RetentionAssessmentClaim {
  const raw = requireObject(value, 'assessment');
  requireKnownMembers(raw, ['outcome'], 'assessment');
  const outcome = raw['outcome'];
  if (typeof outcome !== 'string' || !(RETENTION_ASSESSMENT_OUTCOMES as readonly string[]).includes(outcome)) {
    refused(
      'NOT_RETENTION_ASSESSMENT',
      `assessment.outcome is ${describe(outcome)}, and the layout enumerates ${RETENTION_ASSESSMENT_OUTCOMES.join(', ')}`,
    );
  }
  return { outcome: outcome as RetentionAssessmentOutcome };
}

/**
 * A retention assessment read out of whatever was handed over, refusing the shapes the layout cannot take.
 *
 * The order is the order the capture and import readers use. The version is decided first, because no
 * member can be named until the reader knows which rules the document is under. Structure follows, and the
 * checks between members come last: a checkpoint range is weighed against the runs it claims to speak
 * for, a gap is refused where a run beside it contradicts it, and a span is refused beside any other
 * coverage evidence. None of these is a verdict about the deployment; each is the document disagreeing
 * with itself, and the verdict is the reading's to reach.
 */
export function parseRetentionAssessment(value: unknown): RetentionAssessmentDocument {
  const root = requireObject(value, 'retention assessment');
  const version = requireImplementedVersion(root['v']);
  requireKnownMembers(root, RETENTION_ASSESSMENT_MEMBERS, 'retention assessment');
  const scope = readScope(root['scope']);
  const coverage = readCoverage(root['coverage'], scope);
  const assessment = readAssessment(root['assessment']);
  return { v: version, scope, coverage, assessment };
}

/** The sequences of a declared range that a list of runs does not cover, as ascending inclusive ranges. */
function uncovered(declared: RetentionSequenceRange, ranges: readonly RetentionSequenceRange[]): RetentionSequenceRange[] {
  const missing: RetentionSequenceRange[] = [];
  let cursor = declared.from;
  for (const range of ranges) {
    if (range.from > cursor) missing.push({ from: cursor, to: range.from - 1 });
    cursor = Math.max(cursor, range.to + 1);
  }
  if (cursor <= declared.to) missing.push({ from: cursor, to: declared.to });
  return missing;
}

/** One sentence per missing range, naming the range in the units its ends are in. */
function stateMissing(missing: readonly RetentionSequenceRange[], what: string): string[] {
  return missing.map(
    (range) => `${what} ${String(range.from)} to ${String(range.to)} is not covered, so there is a hole between those two ends`,
  );
}

/** The two ends of a list, or null where it has none, stated once so the callers can stay total. */
function endsOf<T>(list: readonly T[]): { readonly first: T; readonly last: T } | null {
  const first = list[0];
  const last = list[list.length - 1];
  return first === undefined || last === undefined ? null : { first, last };
}

/**
 * What a checkpoint list says about a period.
 *
 * The schedule is customer-held, one receipt per completed batch and no more than the declared interval
 * between two. The reading weighs the properties it can: the receipts tile the declared intake in order,
 * the first stands at or before the period opens, the last at or after it closes, and no interval between
 * consecutive receipts is wider than the declared maximum. A receipt list with a sequence gap is a
 * witness that does not place the intake, and a failure of any of the timing properties is an unwitnessed
 * interval; both answer `indeterminate` and never a pass. A range finding is stated in sequence numbers,
 * a timing finding in unix seconds, and the basis says which list the ranges beside the result are in.
 */
function checkpointFindings(
  checkpoints: readonly RetentionCheckpointReceipt[],
  declared: RetentionSequenceRange,
  period: RetentionAssessmentPeriod,
  maxIntervalSeconds: number,
): {
  readonly missing: readonly RetentionSequenceRange[];
  readonly reasons: readonly string[];
  readonly basis: 'sequence' | 'time';
} {
  const ends = endsOf(checkpoints);
  if (ends === null) {
    return {
      missing: [{ from: period.from, to: period.to }],
      reasons: ['no checkpoint receipt stands beside the period, so no instant in it is witnessed by the customer-held schedule'],
      basis: 'time',
    };
  }
  const { first, last } = ends;
  const missing: RetentionSequenceRange[] = [];
  const reasons: string[] = [];
  if (first.range.from > declared.from) {
    missing.push({ from: declared.from, to: first.range.from - 1 });
    reasons.push(
      `the first checkpoint covers sequences ${String(first.range.from)} to ${String(first.range.to)}, after the declared intake opens at ${String(declared.from)}, so the intake before it is unwitnessed`,
    );
  }
  for (let index = 1; index < checkpoints.length; index += 1) {
    const receipt = checkpoints[index];
    const previous = checkpoints[index - 1];
    if (receipt === undefined || previous === undefined) continue;
    if (receipt.range.from > previous.range.to + 1) {
      missing.push({ from: previous.range.to + 1, to: receipt.range.from - 1 });
      reasons.push(
        `checkpoints cover sequences ${String(previous.range.from)} to ${String(previous.range.to)} and ${String(receipt.range.from)} to ${String(receipt.range.to)}, leaving the intake between them unwitnessed`,
      );
    }
  }
  if (last.range.to < declared.to) {
    missing.push({ from: last.range.to + 1, to: declared.to });
    reasons.push(
      `the last checkpoint covers sequences ${String(last.range.from)} to ${String(last.range.to)}, before the declared intake closes at ${String(declared.to)}, so the intake after it is unwitnessed`,
    );
  }
  if (missing.length > 0) return { missing, reasons, basis: 'sequence' };
  if (first.at > period.from) {
    missing.push({ from: period.from, to: first.at - 1 });
    reasons.push(`the first checkpoint is stamped ${String(first.at)}, after the period opens at ${String(period.from)}, so the interval before it is unwitnessed`);
  }
  for (let index = 1; index < checkpoints.length; index += 1) {
    const receipt = checkpoints[index];
    const previous = checkpoints[index - 1];
    if (receipt === undefined || previous === undefined) continue;
    const distance = receipt.at - previous.at;
    if (distance > maxIntervalSeconds) {
      missing.push({ from: previous.at + 1, to: receipt.at - 1 });
      reasons.push(
        `checkpoints stamped ${String(previous.at)} and ${String(receipt.at)} stand ${String(distance)} seconds apart, more than the declared ${String(maxIntervalSeconds)}`,
      );
    }
  }
  if (last.at < period.to) {
    missing.push({ from: last.at + 1, to: period.to });
    reasons.push(`the last checkpoint is stamped ${String(last.at)}, before the period closes at ${String(period.to)}, so the interval after it is unwitnessed`);
  }
  return { missing, reasons, basis: 'time' };
}

/** One line for each range a finding list names, in the words of the finding it came from. */
function rangeReasons(gaps: readonly RetentionCoverageGap[], duplicates: readonly RetentionCoverageDuplicate[], rollbacks: readonly RetentionCoverageRollback[]): string[] {
  return [
    ...gaps.map((gap) => `the intake did not carry sequences ${String(gap.from)} to ${String(gap.to)}: ${gap.reason}`),
    ...duplicates.map((duplicate) => `the intake saw sequence ${String(duplicate.sequence)} ${String(duplicate.count)} times`),
    ...rollbacks.map(
      (rollback) =>
        `the intake rolled back at sequence ${String(rollback.sequence)} from ${rollback.observedHead} to ${rollback.restoredHead}`,
    ),
  ];
}

/**
 * Read a retention assessment, and say what its evidence supports.
 *
 * Pure: it takes a document and returns an outcome. It writes nothing, reads no clock and fetches nothing.
 * The stated outcome is recomputed and a disagreement is refused rather than answered with a correction,
 * because a document that claims one thing while its own evidence states another is not a document whose
 * other claims a reader can price.
 *
 * The order is the order the outcome turns on. A span-only input answers `indeterminate` before any head
 * is compared, which is what gives the maximum minus minimum timestamp no path to `met`. A sequence
 * shortfall or an explicit adverse finding answers `not-met`, because the evidence states that the period
 * was not held. A missing acknowledgment, a missing checkpoint, a checkpoint list that does not tile the
 * intake, a missing pin or a pin the deployment made about itself answers `indeterminate`, because the
 * evidence cannot answer either way. Only a period continuously covered in sequence, acknowledged across
 * its width, witnessed by customer-held checkpoints that tile the intake and close on the observed head,
 * and closed by a head an independent party pinned and the intake matched answers `met`.
 */
export function assessRetention(value: unknown): RetentionAssessmentResult {
  const document = parseRetentionAssessment(value);
  const { scope, coverage } = document;
  const declared: RetentionSequenceRange = { from: scope.intake.from, to: scope.intake.to };
  const reasons: string[] = [];
  const coverageReasons: string[] = [];
  let coverageResult: RetentionCoverageResult;
  let coverageBasis: 'sequence' | 'time' = 'sequence';
  let coverageRanges: RetentionSequenceRange[] = [];

  if (coverage.span !== null) {
    coverageResult = 'indeterminate';
    coverageBasis = 'time';
    coverageRanges = [{ from: coverage.span.from, to: coverage.span.to }];
    coverageReasons.push(
      'the only evidence is a span between the oldest and newest surviving record, and a span states no sequence between its ends',
    );
    coverageReasons.push(
      'the maximum minus the minimum timestamp is not evidence that every record in the period survived, so a span has no path to a covered result',
    );
  } else if (coverage.runs.length === 0) {
    coverageResult = 'indeterminate';
    coverageRanges = [declared];
    coverageReasons.push('no intake sequence run is stated, so the document carries no coverage evidence at all');
  } else {
    const missing = uncovered(declared, coverage.runs);
    const findings = rangeReasons(coverage.gaps, coverage.duplicates, coverage.rollbacks);
    const unacknowledged = uncovered(declared, coverage.acknowledged);
    const checkpoint = checkpointFindings(
      coverage.checkpoints,
      declared,
      scope.period,
      scope.checkpoint.maxIntervalSeconds,
    );
    const suffix = coverage.suffixLoss === null
      ? []
      : [`the intake lost the suffix from sequence ${String(coverage.suffixLoss.from)} to ${String(coverage.suffixLoss.to)}: ${coverage.suffixLoss.reason}`];

    if (missing.length > 0 || findings.length > 0 || suffix.length > 0) {
      coverageResult = 'gap';
      coverageRanges = [
        ...missing,
        ...coverage.gaps.map((gap) => ({ from: gap.from, to: gap.to })),
        ...(coverage.suffixLoss === null ? [] : [{ from: coverage.suffixLoss.from, to: coverage.suffixLoss.to }]),
      ];
      coverageReasons.push(...stateMissing(missing, 'the intake sequence'));
      coverageReasons.push(...findings);
      coverageReasons.push(...suffix);
      if (coverageRanges.length === 0) coverageRanges = [declared];
    } else if (unacknowledged.length > 0) {
      coverageResult = 'indeterminate';
      coverageRanges = unacknowledged;
      coverageReasons.push(...stateMissing(unacknowledged, 'the acknowledged sequence'));
      coverageReasons.push('the store acknowledged no range over that stretch, so the interval is unwitnessed rather than observed');
    } else if (checkpoint.reasons.length > 0) {
      coverageResult = 'indeterminate';
      coverageBasis = checkpoint.basis;
      coverageRanges = checkpoint.missing.length > 0 ? [...checkpoint.missing] : [{ from: scope.period.from, to: scope.period.to }];
      coverageReasons.push(...checkpoint.reasons);
    } else {
      coverageResult = 'covered';
      coverageRanges = [declared];
    }
  }

  let outcome: RetentionAssessmentOutcome;
  if (coverageResult === 'gap') {
    outcome = 'not-met';
    reasons.push('the coverage evidence states a period that was not continuously held, so the duty is not met');
  } else if (coverageResult === 'indeterminate') {
    outcome = 'indeterminate';
    reasons.push('the coverage evidence cannot answer whether the period was continuously held');
  } else if (coverage.span !== null) {
    // Unreachable: a span-only input sets a coverage result of indeterminate above. The branch is stated
    // rather than assumed away, because the span is the one input this function must never turn into met.
    outcome = 'indeterminate';
    reasons.push('a span is not continuous coverage');
  } else {
    const periodSeconds = scope.period.to - scope.period.from;
    const finalCheckpoint = coverage.checkpoints[coverage.checkpoints.length - 1];
    if (periodSeconds < scope.duty.requiredSeconds) {
      outcome = 'not-met';
      reasons.push(
        `the declared period is ${String(periodSeconds)} seconds and the declared duty requires ${String(scope.duty.requiredSeconds)}, so the period assessed is shorter than the duty`,
      );
    } else if (scope.intake.expectedHead.sha256 === null) {
      outcome = 'indeterminate';
      reasons.push('no expected head is pinned, so the observed head cannot be compared against anything independent');
    } else if (scope.intake.expectedHead.pinnedBy === 'subject') {
      outcome = 'indeterminate';
      reasons.push('the expected head is pinned by the subject itself, so it is the deployment attesting to its own intake');
    } else if (coverage.observedHead === null) {
      outcome = 'indeterminate';
      reasons.push('the document states no observed head, so the pinned head has nothing to match');
    } else if (coverage.observedHead.sequence < scope.intake.to) {
      outcome = 'not-met';
      reasons.push(
        `the observed head stands at sequence ${String(coverage.observedHead.sequence)} and the declared intake ends at ${String(scope.intake.to)}, so the tail was lost against the pinned head`,
      );
    } else if (coverage.observedHead.sha256 !== scope.intake.expectedHead.sha256) {
      outcome = 'not-met';
      reasons.push(
        `the observed head ${coverage.observedHead.sha256} is not the pinned head ${scope.intake.expectedHead.sha256}, so the pin catches a substitution or a rollback`,
      );
    } else if (finalCheckpoint === undefined) {
      // Unreachable: a covered result requires a receipt list that tiles the intake, and an empty list
      // answers indeterminate above. Stated rather than assumed away, because a pass with no final
      // witness is the shape this check exists to refuse.
      outcome = 'indeterminate';
      reasons.push('no final checkpoint receipt stands beside the intake, so no checkpoint witnesses the observed head');
    } else if (finalCheckpoint.head !== coverage.observedHead.sha256) {
      outcome = 'not-met';
      reasons.push(
        `the final checkpoint names the head ${finalCheckpoint.head} and the intake observed ${coverage.observedHead.sha256}, so the checkpoint does not witness the head the runs closed at`,
      );
    } else {
      outcome = 'met';
      reasons.push('the period is continuously covered, acknowledged across its width and witnessed by checkpoints that tile the intake and close on the observed head, and the observed head matches a head an independent party pinned');
    }
  }

  if (document.assessment.outcome !== outcome) {
    refused(
      'RETENTION_ASSESSMENT_DISAGREES',
      `assessment.outcome states '${document.assessment.outcome}' and the evidence in this document supports '${outcome}'`,
    );
  }

  return {
    outcome,
    coverage: {
      result: coverageResult,
      basis: coverageBasis,
      ranges: coverageRanges,
      reasons: coverageReasons,
    },
    stated: {
      subject: scope.subject,
      duty: scope.duty,
      period: scope.period,
      intake: scope.intake,
      checkpoint: scope.checkpoint,
      timeBasis: scope.timeBasis,
      excludes: scope.excludes,
    },
    reasons,
  };
}
