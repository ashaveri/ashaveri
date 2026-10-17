import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ReceiptError } from '@ashaveri/receipt';
import {
  assessRetention,
  MAX_CHECKPOINT_INTERVAL_SECONDS,
  parseRetentionAssessment,
  RETENTION_ASSESSMENT_FORMAT_VERSION,
  SdkError,
  type RetentionAssessmentResult,
} from '@ashaveri/sdk';

/**
 * The retention assessment vectors: whole documents, the outcome the published reading computes for each
 * one, and the refusals in between.
 *
 * Every accepted row is one edit to a covered document, and the row states the outcome the shipped
 * `assessRetention` reached when this file was written. The generator refuses to publish a row whose
 * stated outcome the reading does not reach, so a document whose evidence moved without the prose moving
 * stops the run rather than shipping. The two cases the suite exists for are checked here rather than
 * left to a reader: the span-only row is the one the old rule, the distance between its two stamps
 * against the declared period, would have called `met`, and it is `indeterminate` now; the covered row is
 * a period the sequence evidence genuinely covers. A script can tell the two apart by their outcomes.
 *
 * Nothing here writes a real deployment's state. The sequence numbers, heads and instants are fixtures,
 * and the document is published inline because it is read as a document rather than as bytes.
 */

const DATA = join(dirname(fileURLToPath(import.meta.url)), '..', 'data');

const HEAD = 'aa'.repeat(32);
const OTHER = 'bb'.repeat(32);
const RESTORED = 'cc'.repeat(32);
const PERIOD_FROM = 1_000_000;
const PERIOD_TO = PERIOD_FROM + 200;

type Block = Record<string, unknown>;

/** The covered document every other case is one edit away from. */
function covered(): Block {
  return {
    v: RETENTION_ASSESSMENT_FORMAT_VERSION,
    scope: {
      subject: { kind: 'deployment', id: 'fixture-deployment' },
      duty: { article: '19(1)', requiredSeconds: 200 },
      period: { from: PERIOD_FROM, to: PERIOD_TO },
      intake: {
        from: 1,
        to: 100,
        expectedHead: { sha256: HEAD, pinnedBy: 'customer', reason: null },
      },
      checkpoint: { holder: 'customer', eachCompletedBatch: true, maxIntervalSeconds: 3_600 },
      timeBasis: { source: 'fixture host clock', uncertaintySeconds: 1 },
      excludes: ['request bodies', 'model weights', 'the provider side of the intake'],
    },
    coverage: {
      runs: [{ from: 1, to: 100 }],
      acknowledged: [{ from: 1, to: 100 }],
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
    },
    assessment: { outcome: 'met' },
  };
}

function withEdit(edit: (document: Block) => void): Block {
  const document = covered();
  edit(document);
  return document;
}

function scopeOf(document: Block): Block {
  return document['scope'] as Block;
}

function coverageOf(document: Block): Block {
  return document['coverage'] as Block;
}

/** The span-only document: the oldest and newest survivors, no sequence evidence between them. */
function spanOnly(outcome: string): Block {
  return withEdit((document) => {
    document['coverage'] = {
      runs: [],
      acknowledged: [],
      checkpoints: [],
      observedHead: null,
      span: { from: PERIOD_FROM, to: PERIOD_TO, oldestHead: OTHER, newestHead: HEAD },
      gaps: [],
      duplicates: [],
      rollbacks: [],
      suffixLoss: null,
    };
    document['assessment'] = { outcome };
  });
}

/** A period whose intake skipped a stretch in the middle, with the checkpoints saying so. */
function interiorGap(outcome: string): Block {
  return withEdit((document) => {
    coverageOf(document)['runs'] = [
      { from: 1, to: 40 },
      { from: 61, to: 100 },
    ];
    coverageOf(document)['acknowledged'] = [
      { from: 1, to: 40 },
      { from: 61, to: 100 },
    ];
    coverageOf(document)['checkpoints'] = [
      { range: { from: 1, to: 40 }, at: PERIOD_FROM, head: OTHER },
      { range: { from: 61, to: 100 }, at: PERIOD_TO, head: HEAD },
    ];
    coverageOf(document)['gaps'] = [
      { from: 41, to: 60, reason: 'the intake process restarted without its sequence state' },
    ];
    document['assessment'] = { outcome };
  });
}

interface AssessmentRow {
  readonly name: string;
  readonly note: string;
  readonly document: Block;
}

const ASSESSMENT_ROWS: readonly AssessmentRow[] = [
  {
    name: 'continuous-coverage-met',
    note: 'A period the sequence evidence genuinely covers: one run across the declared intake range, the same range acknowledged by the store, three customer-held checkpoints from the period open to its close, and an observed head that matches a head the customer pinned. This is the case `met` exists for, and the evidence behind it is what the reader recomputes rather than what the document asserts.',
    document: covered(),
  },
  {
    name: 'span-only-would-have-met-under-the-span-rule',
    note: 'The oldest and newest surviving records, exactly one declared period apart, with the newest head equal to the pinned head. The old span rule, the distance between two stamps compared with the required period, would have called this met. It is indeterminate: a span states nothing about the sequences between its ends, and the reading gives the subtraction no path to a covered result.',
    document: spanOnly('indeterminate'),
  },
  {
    name: 'interior-gap-not-met',
    note: 'The intake carried sequences 1 through 40 and 61 through 100 and nothing between them, and the document states the gap rather than leaving it to be inferred. The store acknowledged the two runs, the checkpoints witness them, and the period is not continuously covered: a crash or a restart that loses the sequence state is a gap, never a silent pass.',
    document: interiorGap('not-met'),
  },
  {
    name: 'unstated-interior-gap-not-met',
    note: 'The intake observed sequences 1 through 40 and 61 through 100, the store acknowledged the whole declared range, and nothing states the missing stretch: no `gaps` row and no unacknowledged interval. The edges of the runs state it, and the reading derives the missing range from them and answers not met. Coverage is a property of the sequence the evidence supports, not of the findings a writer chose to list, which is the rule a `gaps` row cannot be the only witness for.',
    document: withEdit((document) => {
      coverageOf(document)['runs'] = [
        { from: 1, to: 40 },
        { from: 61, to: 100 },
      ];
      coverageOf(document)['acknowledged'] = [{ from: 1, to: 100 }];
      coverageOf(document)['checkpoints'] = [
        { range: { from: 1, to: 40 }, at: PERIOD_FROM, head: OTHER },
        { range: { from: 61, to: 100 }, at: PERIOD_TO, head: HEAD },
      ];
      document['assessment'] = { outcome: 'not-met' };
    }),
  },
  {
    name: 'suffix-loss-against-the-pinned-head-not-met',
    note: 'The intake observed sequences 1 through 90 against a declared range that ends at 100, and states the tail it lost. The observed head stands at 90 and the customer pinned a head for 100, so the suffix loss is visible against the pin rather than only against the runs. The answer is not met.',
    document: withEdit((document) => {
      coverageOf(document)['runs'] = [{ from: 1, to: 90 }];
      coverageOf(document)['acknowledged'] = [{ from: 1, to: 90 }];
      coverageOf(document)['checkpoints'] = [
        { range: { from: 1, to: 45 }, at: PERIOD_FROM, head: OTHER },
        { range: { from: 46, to: 90 }, at: PERIOD_TO, head: OTHER },
      ];
      coverageOf(document)['observedHead'] = { sequence: 90, sha256: OTHER };
      coverageOf(document)['suffixLoss'] = {
        from: 91,
        to: 100,
        reason: 'the volume lost its tail before the period closed',
      };
      document['assessment'] = { outcome: 'not-met' };
    }),
  },
  {
    name: 'rollback-against-the-pinned-head-not-met',
    note: 'The intake reached the pinned head at sequence 100 and then restored an earlier head at the same sequence. The rollback is stated rather than inferred, and it is a rollback against the pinned head because the head it left is the one the customer pinned. The answer is not met.',
    document: withEdit((document) => {
      coverageOf(document)['rollbacks'] = [
        { sequence: 100, observedHead: HEAD, restoredHead: RESTORED },
      ];
      document['assessment'] = { outcome: 'not-met' };
    }),
  },
  {
    name: 'duplicate-intake-sequence-not-met',
    note: 'The intake saw sequence 30 twice. A retry would leave this trace, and a document that stated it would be honest about the duplicate; the answer is still not met, because a record the intake saw twice is not a run it carried once. Duplicates inside the runs list are a different fault and are refused by the reader as a duplicate sequence.',
    document: withEdit((document) => {
      coverageOf(document)['duplicates'] = [{ sequence: 30, count: 2 }];
      document['assessment'] = { outcome: 'not-met' };
    }),
  },
  {
    name: 'missing-checkpoint-indeterminate',
    note: 'A continuously observed and acknowledged period with no checkpoint receipt beside it. Nothing states that the period was not held, and nothing witnesses it either: the answer is indeterminate, because the customer-held schedule is the only temporal witness this family carries.',
    document: withEdit((document) => {
      coverageOf(document)['checkpoints'] = [];
      document['assessment'] = { outcome: 'indeterminate' };
    }),
  },
  {
    name: 'checkpoint-interval-too-wide-indeterminate',
    note: 'Two checkpoints at the two ends of a period the declared schedule promises to witness every 100 seconds. The receipts are 200 seconds apart, so the middle of the period is unwitnessed. The answer is indeterminate rather than met, and rather than a gap: no evidence states that anything was lost.',
    document: withEdit((document) => {
      (scopeOf(document)['checkpoint'] as Block)['maxIntervalSeconds'] = 100;
      coverageOf(document)['checkpoints'] = [
        { range: { from: 1, to: 50 }, at: PERIOD_FROM, head: OTHER },
        { range: { from: 51, to: 100 }, at: PERIOD_TO, head: HEAD },
      ];
      document['assessment'] = { outcome: 'indeterminate' };
    }),
  },
  {
    name: 'unacknowledged-interval-indeterminate',
    note: 'The intake observed every sequence in the declared range and the store acknowledged only the two ends of it. Nothing states that the middle was lost, and no acknowledgment speaks for it. An unwitnessed interval is indeterminate and never a pass.',
    document: withEdit((document) => {
      coverageOf(document)['acknowledged'] = [
        { from: 1, to: 40 },
        { from: 61, to: 100 },
      ];
      document['assessment'] = { outcome: 'indeterminate' };
    }),
  },
  {
    name: 'missing-expected-head-indeterminate',
    note: 'The scope states that no customer held a head for this period and gives the reason. The coverage evidence is continuous, and the document cannot answer whether the head it observed is the head the customer expected. The absence is stated rather than inferred, and the answer is indeterminate.',
    document: withEdit((document) => {
      (scopeOf(document)['intake'] as Block)['expectedHead'] = {
        sha256: null,
        pinnedBy: 'none',
        reason: 'the customer held no head for this period',
      };
      document['assessment'] = { outcome: 'indeterminate' };
    }),
  },
  {
    name: 'self-asserted-expected-head-indeterminate',
    note: 'The deployment pinned the expected head about itself. The scope says so honestly, which is why the reader takes the document, and the reading weighs the declaration as self-assertion rather than as an independent pin. The answer is indeterminate; a head the subject pinned itself cannot close the period against the subject.',
    document: withEdit((document) => {
      (scopeOf(document)['intake'] as Block)['expectedHead'] = {
        sha256: HEAD,
        pinnedBy: 'subject',
        reason: null,
      };
      document['assessment'] = { outcome: 'indeterminate' };
    }),
  },
  {
    name: 'substituted-expected-head-not-met',
    note: 'Continuous runs, acknowledgments and checkpoints, and an observed head at sequence 100 that is not the head the customer pinned. The pin catches the substitution: every other member agrees, and the one comparison the coverage cannot make for itself is the one that fails. The answer is not met.',
    document: withEdit((document) => {
      coverageOf(document)['observedHead'] = { sequence: 100, sha256: OTHER };
      document['assessment'] = { outcome: 'not-met' };
    }),
  },
  {
    name: 'period-shorter-than-the-declared-duty-not-met',
    note: 'A period one second shorter than the duty the deployment declares. The coverage is continuous and the head matches, and the period assessed is not the period the duty requires: the answer is not met. This is the one figure the old span rule also treated as a failure, and it stays a failure here.',
    document: withEdit((document) => {
      (scopeOf(document)['period'] as Block)['to'] = PERIOD_FROM + 199;
      document['assessment'] = { outcome: 'not-met' };
    }),
  },
  {
    name: 'no-observation-indeterminate',
    note: 'A document that states neither a run nor a span: the intake observed nothing, and the document says so by leaving both lists empty. The answer is indeterminate rather than a pass over a period nothing witnessed.',
    document: withEdit((document) => {
      coverageOf(document)['runs'] = [];
      coverageOf(document)['acknowledged'] = [];
      coverageOf(document)['checkpoints'] = [];
      coverageOf(document)['observedHead'] = null;
      document['assessment'] = { outcome: 'indeterminate' };
    }),
  },
];

interface RefusalRow {
  readonly name: string;
  readonly note: string;
  readonly document: Block;
  readonly stage: 'layout' | 'reading';
  readonly code: string;
}

const REFUSALS: readonly RefusalRow[] = [
  {
    name: 'unknown-root-member',
    note: 'A document carrying `retainedAt`, a member no version of this layout defines. Closure holds here as it holds at every record of this estate: a writer that stated a field no reader knows was answering a question this document cannot ask, and dropping it quietly turns that answer into a silence.',
    document: withEdit((document) => {
      document['retainedAt'] = PERIOD_TO;
    }),
    stage: 'layout',
    code: 'NOT_RETENTION_ASSESSMENT',
  },
  {
    name: 'unknown-nested-member',
    note: 'A subject block carrying `region`, a member the layout does not define. The closure reaches every block, not only the root, so a nested field is refused at the position it sits on.',
    document: withEdit((document) => {
      (scopeOf(document)['subject'] as Block)['region'] = 'eu-west-1';
    }),
    stage: 'layout',
    code: 'NOT_RETENTION_ASSESSMENT',
  },
  {
    name: 'version-two',
    note: 'A document naming version 2. The version decides which members exist, so a reader with no rules for it refuses before one member is read, under the code the capture and import readers answer the same question with.',
    document: withEdit((document) => {
      document['v'] = 2;
    }),
    stage: 'layout',
    code: 'UNSUPPORTED_VERSION',
  },
  {
    name: 'non-monotonic-runs',
    note: 'Two observed runs whose sequence numbers run backwards: 10 through 20 followed by 5 through 8. A run that begins before the previous one began is a non-monotonic observation, which is a different fault from one sequence stated twice and gets its own sentence.',
    document: withEdit((document) => {
      coverageOf(document)['runs'] = [
        { from: 10, to: 20 },
        { from: 5, to: 8 },
      ];
    }),
    stage: 'layout',
    code: 'NOT_RETENTION_ASSESSMENT',
  },
  {
    name: 'duplicate-sequence-in-runs',
    note: 'Two observed runs that meet at sequence 50. One run ends there and the next begins there, so the document states one intake sequence twice. The reader refuses the pair rather than merging it into a longer run, because a merge would hide the duplicate the evidence recorded.',
    document: withEdit((document) => {
      coverageOf(document)['runs'] = [
        { from: 1, to: 50 },
        { from: 50, to: 100 },
      ];
    }),
    stage: 'layout',
    code: 'NOT_RETENTION_ASSESSMENT',
  },
  {
    name: 'self-asserted-pin-spelling',
    note: "A head pinned by `'self'`, a word that names the intake rather than a party that could pin a head independently of it. The layout enumerates the parties it can weigh and refuses the intake-side spellings by name, because a head the intake wrote beside its own observation is that observation repeated.",
    document: withEdit((document) => {
      ((scopeOf(document)['intake'] as Block)['expectedHead'] as Block)['pinnedBy'] = 'self';
    }),
    stage: 'layout',
    code: 'NOT_RETENTION_ASSESSMENT',
  },
  {
    name: 'checkpoint-claims-an-unsupported-range',
    note: 'A checkpoint receipt over sequences 41 through 60 while the observed runs cover 1 through 40 and 61 through 100. The receipt claims a range the intake does not support, which is the witness asserting a stretch nobody observed. It is refused rather than read as a checkpoint over the gap.',
    document: withEdit((document) => {
      coverageOf(document)['runs'] = [
        { from: 1, to: 40 },
        { from: 61, to: 100 },
      ];
      coverageOf(document)['acknowledged'] = [
        { from: 1, to: 40 },
        { from: 61, to: 100 },
      ];
      coverageOf(document)['checkpoints'] = [
        { range: { from: 41, to: 60 }, at: PERIOD_FROM, head: OTHER },
      ];
    }),
    stage: 'layout',
    code: 'NOT_RETENTION_ASSESSMENT',
  },
  {
    name: 'duplicate-checkpoint-sequence',
    note: 'Two checkpoint receipts over the same range. One sequence is witnessed twice by two receipts, which is a duplicate claim rather than two observations, and the reader refuses the pair. A checkpoint range that overlaps an earlier one by any amount is the same fault.',
    document: withEdit((document) => {
      coverageOf(document)['checkpoints'] = [
        { range: { from: 1, to: 34 }, at: PERIOD_FROM, head: OTHER },
        { range: { from: 1, to: 34 }, at: PERIOD_FROM + 100, head: HEAD },
      ];
    }),
    stage: 'layout',
    code: 'NOT_RETENTION_ASSESSMENT',
  },
  {
    name: 'span-beside-runs',
    note: 'A span stated beside the runs, acknowledgments and checkpoints. One coverage result cannot have two bases, and a reader that took both would have to choose which one produced the answer without saying so. The combination is refused.',
    document: withEdit((document) => {
      coverageOf(document)['span'] = {
        from: PERIOD_FROM,
        to: PERIOD_TO,
        oldestHead: OTHER,
        newestHead: HEAD,
      };
    }),
    stage: 'layout',
    code: 'NOT_RETENTION_ASSESSMENT',
  },
  {
    name: 'schedule-weaker-than-hourly',
    note: `A checkpoint schedule declaring ${String(MAX_CHECKPOINT_INTERVAL_SECONDS + 1)} seconds between receipts. The layout defines a customer-held schedule with at most an hour between two, and a document declaring a weaker one is refused rather than read as a different promise.`,
    document: withEdit((document) => {
      (scopeOf(document)['checkpoint'] as Block)['maxIntervalSeconds'] = MAX_CHECKPOINT_INTERVAL_SECONDS + 1;
    }),
    stage: 'layout',
    code: 'NOT_RETENTION_ASSESSMENT',
  },
  {
    name: 'suffix-loss-that-is-not-the-tail',
    note: 'A stated suffix loss over the last two sequences while the observed runs stop at 90. The loss the document states is not the tail its own runs leave, so the document disagrees with itself and is refused. The reading refuses the shape rather than choosing which of the two tails to believe.',
    document: withEdit((document) => {
      coverageOf(document)['runs'] = [{ from: 1, to: 90 }];
      coverageOf(document)['acknowledged'] = [{ from: 1, to: 90 }];
      coverageOf(document)['checkpoints'] = [
        { range: { from: 1, to: 45 }, at: PERIOD_FROM, head: OTHER },
        { range: { from: 46, to: 90 }, at: PERIOD_TO, head: OTHER },
      ];
      coverageOf(document)['observedHead'] = { sequence: 90, sha256: OTHER };
      coverageOf(document)['suffixLoss'] = { from: 99, to: 100, reason: 'the last two sequences are gone' };
      document['assessment'] = { outcome: 'not-met' };
    }),
    stage: 'layout',
    code: 'NOT_RETENTION_ASSESSMENT',
  },
  {
    name: 'duplicate-count-below-two',
    note: 'A duplicate row stating that the intake saw one sequence once. A sequence seen fewer than twice is not a duplicate, and the row is the writer stating a finding its own count does not support. The reader refuses it rather than dropping the row.',
    document: withEdit((document) => {
      coverageOf(document)['duplicates'] = [{ sequence: 30, count: 1 }];
    }),
    stage: 'layout',
    code: 'NOT_RETENTION_ASSESSMENT',
  },
  {
    name: 'span-only-claimed-met',
    note: 'The span-only document with its stated outcome changed to met. The layout takes the document and the evidence cannot support the claim: the stamps are one period apart and the newest head matches the pin, which is exactly the arithmetic the old rule read as fulfilment. The reading refuses the claim under its own code rather than silently returning indeterminate, because a document that says met and means indeterminate is not a document a reader can report on.',
    document: spanOnly('met'),
    stage: 'reading',
    code: 'RETENTION_ASSESSMENT_DISAGREES',
  },
  {
    name: 'interior-gap-claimed-met',
    note: 'The interior-gap document with its stated outcome changed to met. The document is whole, the gap is stated, and the two cannot both stand: the evidence states a period that was not continuously held. The reading refuses the claim under the disagreement code.',
    document: interiorGap('met'),
    stage: 'reading',
    code: 'RETENTION_ASSESSMENT_DISAGREES',
  },
  {
    name: 'covered-period-claimed-not-met',
    note: 'The covered document with its stated outcome changed to not-met. The evidence supports met, and the document states the opposite. The disagreement is refused in both directions: a reader cannot report a period as held when the document denies it, any more than it can report the reverse.',
    document: withEdit((document) => {
      document['assessment'] = { outcome: 'not-met' };
    }),
    stage: 'reading',
    code: 'RETENTION_ASSESSMENT_DISAGREES',
  },
];

/** What the shipped steps answered: the code and sentence, or `ok` where the step handed something back. */
function answeredBy(run: () => unknown): { readonly outcome: string; readonly message: string } {
  try {
    run();
    return { outcome: 'ok', message: '' };
  } catch (err) {
    if (err instanceof SdkError || err instanceof ReceiptError) return { outcome: err.code, message: err.message };
    throw new Error(`the shipped reader answered with something no registry declares: ${String(err)}`);
  }
}

/** The coverage and outcome the published reading reaches for one document, as the row states them. */
function readingOf(document: Block): RetentionAssessmentResult {
  return assessRetention(document);
}

function main(): void {
  const rows: Block[] = [];
  for (const row of ASSESSMENT_ROWS) {
    const parsed = answeredBy(() => parseRetentionAssessment(row.document));
    const reading = answeredBy(() => assessRetention(row.document));
    if (parsed.outcome !== 'ok') {
      throw new Error(`${row.name}: the layout refused a document this case states as taken (${parsed.outcome})`);
    }
    if (reading.outcome !== 'ok') {
      throw new Error(`${row.name}: the reading refused a document this case states as taken (${reading.outcome})`);
    }
    const assessment = readingOf(row.document);
    if (assessment.outcome !== (row.document['assessment'] as Block)['outcome']) {
      throw new Error(`${row.name}: the reading reached ${assessment.outcome} and the document states another outcome`);
    }
    rows.push({
      name: row.name,
      note: row.note,
      document: row.document,
      assessment: {
        outcome: assessment.outcome,
        coverage: assessment.coverage,
        reasons: assessment.reasons,
      },
    });
  }

  const refusals: Block[] = [];
  for (const row of REFUSALS) {
    const parsed = answeredBy(() => parseRetentionAssessment(row.document));
    const reading = answeredBy(() => assessRetention(row.document));
    if (row.stage === 'layout') {
      if (parsed.outcome !== row.code) {
        throw new Error(`${row.name}: the layout answers ${parsed.outcome}, not the ${row.code} this case states`);
      }
      if (reading.outcome !== row.code || reading.message !== parsed.message) {
        throw new Error(`${row.name}: the two published steps gave two answers for one fault`);
      }
      refusals.push({ name: row.name, note: row.note, document: row.document, stage: 'layout', code: reading.outcome, message: reading.message });
      continue;
    }
    if (parsed.outcome !== 'ok') {
      throw new Error(`${row.name}: the layout refused a document this case states the reading refuses`);
    }
    if (reading.outcome !== row.code) {
      throw new Error(`${row.name}: the reading answers ${reading.outcome}, not the ${row.code} this case states`);
    }
    refusals.push({ name: row.name, note: row.note, document: row.document, stage: 'reading', code: reading.outcome, message: reading.message });
  }

  const names = [...rows, ...refusals].map((row) => String(row['name']));
  if (new Set(names).size !== names.length) throw new Error('two cases of this suite share a name');
  if (rows.length < 8) throw new Error(`${String(rows.length)} assessment rows, and the outcomes and their refusals are more than that`);
  if (refusals.length < 8) throw new Error(`${String(refusals.length)} refusals, and the layout names more faults than that`);

  // The two rows this suite exists to keep apart: the span-only input the old rule would have called met,
  // and the covered input that is genuinely met. A script has to be able to tell them apart by outcome.
  const met = rows.find((row) => row['name'] === 'continuous-coverage-met');
  const span = rows.find((row) => row['name'] === 'span-only-would-have-met-under-the-span-rule');
  if (met === undefined || span === undefined) throw new Error('the suite lost one of the two rows its outcomes turn on');
  const metAssessment = met['assessment'] as Block;
  const spanAssessment = span['assessment'] as Block;
  if (metAssessment['outcome'] !== 'met') throw new Error('the covered period is not the row that reaches met');
  if (spanAssessment['outcome'] !== 'indeterminate') throw new Error('the span-only input did not answer indeterminate');
  const spanDocument = span['document'] as Block;
  const spanScope = scopeOf(spanDocument);
  const spanBlock = coverageOf(spanDocument)['span'] as Block;
  const required = (spanScope['duty'] as Block)['requiredSeconds'];
  const pinned = ((spanScope['intake'] as Block)['expectedHead'] as Block)['sha256'];
  if (typeof required !== 'number' || typeof pinned !== 'string') throw new Error('the span-only row lost its duty or its pin');
  if (Number(spanBlock['to']) - Number(spanBlock['from']) < required) {
    throw new Error('the span-only row is not a case the old span rule would have called met');
  }
  if (spanBlock['newestHead'] !== pinned) {
    throw new Error('the span-only row does not match the pinned head its old-rule reading turns on');
  }
  if ((metAssessment['coverage'] as Block)['result'] !== 'covered') {
    throw new Error('the row that reaches met does not record a covered result');
  }
  if ((spanAssessment['coverage'] as Block)['result'] !== 'indeterminate') {
    throw new Error('the span-only row does not record an indeterminate result');
  }

  const codeList = [...new Set(refusals.map((row) => String(row['code'])))].sort();
  mkdirSync(DATA, { recursive: true });
  writeFileSync(
    join(DATA, 'retention-assessment-v1.json'),
    `${JSON.stringify(
      {
        version: 1,
        description:
          "Retention assessments and the outcome the published reading computes for each one: a declared scope, the intake sequence runs and acknowledgments behind it, customer-held checkpoint receipts, the observed head, a span where a span is all there is, and the explicit gaps, duplicates, rollbacks and suffix loss. Every assessment row is a whole document and the outcome, coverage result, ranges and reasons `assessRetention` of `@ashaveri/sdk` reached for it when this file was written. The refused rows state the code and sentence, and which of the two published steps answered: `layout` where `parseRetentionAssessment` refused the document and `reading` where the layout took it and `assessRetention` refused the stated conclusion its own evidence did not support. The span-only row is the case the old span rule, the distance between the oldest and newest stamps compared with the required period, would have read as met; it is indeterminate here, and the covered row beside it is a period the sequence evidence genuinely covers, so the two outcomes are distinguishable by outcome alone.",
        layout: {
          format:
            'one closed v1 document with three blocks: the declared scope, the observed coverage and the deployment\'s stated conclusion, which the reading recomputes rather than believes',
          schema:
            'packages/sdk/schemas/retention-assessment-v1.schema.json, published as https://ashaveri.com/schemas/retention-assessment-v1.json, which is the layout a writer outside this repository builds against',
          reader:
            'parseRetentionAssessment in @ashaveri/sdk, which is the layout, and assessRetention, which parses and then recomputes the outcome from the evidence: continuous sequence coverage, acknowledgment across the declared width, checkpoints across the period, and an observed head matching a head an independent party pinned',
          codes: codeList,
          encodings: 'heads lowercase hex of 64 characters, instants unix seconds, sequence numbers non-negative whole numbers, and the document published inline as the object the reader is handed',
          keyMaterial:
            'none: the document carries no signature and no key. A retention assessment is the deployment\'s report about its own store, and what makes it evidence is the head an independent party pinned and the checkpoint receipts that party holds, not a key inside the document.',
          notChecked:
            'a document states one deployment\'s account of its own intake and store. Nothing here shows that the runs happened, that the acknowledgments came from a store, that the checkpoint receipts are the customer\'s, or that the clock the stamps rest on is bounded by the declared uncertainty. Those are the questions a reader answers with material it holds outside the file.',
        },
        vectors: rows,
        refusals,
      },
      null,
      2,
    )}\n`,
  );

  for (const row of rows) {
    const assessment = row['assessment'] as Block;
    console.log(`${String(row['name'])}: ${String(assessment['outcome'])} (${String((assessment['coverage'] as Block)['result'])})`);
  }
  for (const row of refusals) console.log(`${String(row['name'])}: ${String(row['stage'])} ${String(row['code'])}`);
}

main();
