import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { Ajv2020, type ValidateFunction } from 'ajv/dist/2020.js';
import { parseRetentionDocument, ReceiptError } from '@ashaveri/receipt';
import { describe, expect, it } from 'vitest';
import { SdkError } from '../src/errors.js';
import {
  assessRetention,
  EXPECTED_HEAD_PINNERS,
  MAX_CHECKPOINT_INTERVAL_SECONDS,
  parseRetentionAssessment,
  RETENTION_ASSESSMENT_ARTICLES,
  RETENTION_ASSESSMENT_FORMAT_VERSION,
  RETENTION_ASSESSMENT_MEMBERS,
  RETENTION_ASSESSMENT_OUTCOMES,
  RETENTION_COVERAGE_MEMBERS,
  RETENTION_SCOPE_MEMBERS,
} from '../src/retention-assessment.js';

/**
 * The retention assessment read as a document and as evidence.
 *
 * The base document below is a period that is genuinely covered: one run across the declared intake range,
 * the same range acknowledged by the store, three customer-held checkpoints from the period open to its
 * close, and an observed head that matches a head the customer pinned. Every other case is one edit to
 * that document, so a case that turns red names the rule it turns on rather than a fixture nobody can
 * reproduce. The span-only case is the one the old span rule would have read as met: its two stamps are
 * exactly as far apart as the declared period and its newest head is the pinned head, and it is
 * indeterminate because none of that says what happened between the two stamps.
 */

type Block = Record<string, unknown>;

const HEAD = 'aa'.repeat(32);
const OTHER = 'bb'.repeat(32);
const RESTORED = 'cc'.repeat(32);
const PERIOD_FROM = 1_000_000;
const PERIOD_TO = PERIOD_FROM + 200;
const RANGE = { from: 1, to: 100 };

const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;

const BASE: Block = {
  v: 1,
  scope: {
    subject: { kind: 'deployment', id: 'deployment-alpha' },
    duty: { article: '19(1)', requiredSeconds: 200 },
    period: { from: PERIOD_FROM, to: PERIOD_TO },
    intake: { from: 1, to: 100, expectedHead: { sha256: HEAD, pinnedBy: 'customer', reason: null } },
    checkpoint: { holder: 'customer', eachCompletedBatch: true, maxIntervalSeconds: 3_600 },
    timeBasis: { source: 'host clock', uncertaintySeconds: 1 },
    excludes: ['request bodies', 'model weights'],
  },
  coverage: {
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
  },
  assessment: { outcome: 'met' },
};

function documentFor(over: Block = {}): Block {
  const document = clone(BASE) as Block;
  for (const [member, value] of Object.entries(over)) document[member] = value;
  return document;
}

function scopeOf(document: Block): Block {
  return document['scope'] as Block;
}

function coverageOf(document: Block): Block {
  return document['coverage'] as Block;
}

function coded(run: () => unknown): { readonly code: string; readonly message: string } | null {
  try {
    run();
    return null;
  } catch (err) {
    if (err instanceof SdkError || err instanceof ReceiptError) return { code: err.code, message: err.message };
    throw err;
  }
}

function refusalOf(document: Block): { readonly code: string; readonly message: string } {
  const refused = coded(() => parseRetentionAssessment(document));
  if (refused === null) throw new Error('the reader took a document this case states as refused');
  return refused;
}

/** The span-only document, whose span and newest head are what the old span rule treated as fulfilment. */
function spanOnlyDocument(outcome = 'indeterminate'): Block {
  const document = documentFor();
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
  return document;
}

describe('parseRetentionAssessment', () => {
  it('takes the covered document and reads its members back', () => {
    const parsed = parseRetentionAssessment(documentFor());
    expect(parsed.v).toBe(RETENTION_ASSESSMENT_FORMAT_VERSION);
    expect(parsed.scope.intake.expectedHead.pinnedBy).toBe('customer');
    expect(parsed.coverage.runs).toEqual([RANGE]);
    expect(parsed.assessment.outcome).toBe('met');
    // The span-only document is a document the layout takes; what it supports is the reading's question.
    expect(() => parseRetentionAssessment(spanOnlyDocument())).not.toThrow();
  });

  it('refuses a member no version defines, at the root and inside a block', () => {
    expect(refusalOf({ ...documentFor(), retainedAt: PERIOD_TO }).code).toBe('NOT_RETENTION_ASSESSMENT');
    const nested = documentFor();
    (nested['coverage'] as Block)['retentionDuty'] = '19(1)';
    expect(refusalOf(nested).code).toBe('NOT_RETENTION_ASSESSMENT');
    const run = documentFor();
    (run['coverage'] as Block)['runs'] = [{ from: 1, to: 100, label: 'batch-a' }];
    expect(refusalOf(run).code).toBe('NOT_RETENTION_ASSESSMENT');
  });

  it('refuses a version it does not implement rather than reading it as its own', () => {
    expect(refusalOf({ ...documentFor(), v: 2 }).code).toBe('UNSUPPORTED_VERSION');
  });

  it('refuses a non-monotonic intake sequence', () => {
    const document = documentFor();
    (document['coverage'] as Block)['runs'] = [
      { from: 10, to: 20 },
      { from: 5, to: 8 },
    ];
    const refused = refusalOf(document);
    expect(refused.code).toBe('NOT_RETENTION_ASSESSMENT');
    expect(refused.message).toContain('not monotonic');
  });

  it('refuses a duplicate sequence number, in the runs and in the checkpoints', () => {
    const runs = documentFor();
    (runs['coverage'] as Block)['runs'] = [
      { from: 1, to: 50 },
      { from: 50, to: 100 },
    ];
    const runRefusal = refusalOf(runs);
    expect(runRefusal.code).toBe('NOT_RETENTION_ASSESSMENT');
    expect(runRefusal.message).toContain('twice');

    const checkpoints = documentFor();
    (checkpoints['coverage'] as Block)['checkpoints'] = [
      { range: { from: 1, to: 34 }, at: PERIOD_FROM, head: OTHER },
      { range: { from: 1, to: 34 }, at: PERIOD_FROM + 100, head: HEAD },
    ];
    const checkpointRefusal = refusalOf(checkpoints);
    expect(checkpointRefusal.code).toBe('NOT_RETENTION_ASSESSMENT');
    expect(checkpointRefusal.message).toContain('twice');
  });

  it('refuses a head the intake pinned about itself', () => {
    const document = documentFor();
    const expected = (scopeOf(document)['intake'] as Block)['expectedHead'] as Block;
    expected['pinnedBy'] = 'self';
    const refused = refusalOf(document);
    expect(refused.code).toBe('NOT_RETENTION_ASSESSMENT');
    expect(refused.message).toContain('intake rather than a party');
  });

  it('refuses a checkpoint that claims a range the intake does not support', () => {
    const document = documentFor();
    (document['coverage'] as Block)['runs'] = [
      { from: 1, to: 40 },
      { from: 61, to: 100 },
    ];
    (document['coverage'] as Block)['acknowledged'] = [
      { from: 1, to: 40 },
      { from: 61, to: 100 },
    ];
    (document['coverage'] as Block)['checkpoints'] = [{ range: { from: 41, to: 60 }, at: PERIOD_FROM, head: OTHER }];
    const refused = refusalOf(document);
    expect(refused.code).toBe('NOT_RETENTION_ASSESSMENT');
    expect(refused.message).toContain('do not support');
  });

  it('refuses a span beside other coverage evidence', () => {
    const document = documentFor();
    (document['coverage'] as Block)['span'] = {
      from: PERIOD_FROM,
      to: PERIOD_TO,
      oldestHead: OTHER,
      newestHead: HEAD,
    };
    expect(refusalOf(document).code).toBe('NOT_RETENTION_ASSESSMENT');
  });

  it('refuses a checkpoint schedule weaker than the layout states', () => {
    const document = documentFor();
    const checkpoint = scopeOf(document)['checkpoint'] as Block;
    checkpoint['maxIntervalSeconds'] = MAX_CHECKPOINT_INTERVAL_SECONDS + 1;
    expect(refusalOf(document).code).toBe('NOT_RETENTION_ASSESSMENT');
    const skipped = documentFor();
    (scopeOf(skipped)['checkpoint'] as Block)['eachCompletedBatch'] = false;
    expect(refusalOf(skipped).code).toBe('NOT_RETENTION_ASSESSMENT');
  });

  it('refuses a head that is not 64 lowercase hex characters, and a sequence that is not whole', () => {
    const digest = documentFor();
    (coverageOf(digest)['observedHead'] as Block)['sha256'] = 'zz'.repeat(32);
    expect(refusalOf(digest).code).toBe('NOT_RETENTION_ASSESSMENT');
    const fractional = documentFor();
    (coverageOf(fractional)['observedHead'] as Block)['sequence'] = 100.5;
    expect(refusalOf(fractional).code).toBe('NOT_RETENTION_ASSESSMENT');
    const negative = documentFor();
    (scopeOf(negative)['period'] as Block)['from'] = -1;
    expect(refusalOf(negative).code).toBe('NOT_RETENTION_ASSESSMENT');
  });
});

describe('assessRetention', () => {
  it('reaches met only from continuous coverage and a pinned matched head', () => {
    const assessment = assessRetention(documentFor());
    expect(assessment.outcome).toBe('met');
    expect(assessment.coverage.result).toBe('covered');
    expect(assessment.coverage.ranges).toEqual([RANGE]);
    expect(assessment.coverage.reasons).toEqual([]);
    expect(assessment.stated.duty.article).toBe('19(1)');
    // The shortest edit that removes the pin turns the same evidence into an indeterminate assessment.
    const unpinned = documentFor();
    (scopeOf(unpinned)['intake'] as Block)['expectedHead'] = {
      sha256: null,
      pinnedBy: 'none',
      reason: 'the customer held no head for this period',
    };
    unpinned['assessment'] = { outcome: 'indeterminate' };
    expect(assessRetention(unpinned).outcome).toBe('indeterminate');
  });

  it('answers indeterminate for a span-only input, however long the span and however clean the head', () => {
    const document = spanOnlyDocument();
    // This is the case the old span rule would have called met: the distance is the declared period and the
    // newest head is the pinned head. Neither says anything about the sequences between the two stamps.
    const span = coverageOf(document)['span'] as Block;
    expect(Number(span['to']) - Number(span['from'])).toBeGreaterThanOrEqual(200);
    expect(span['newestHead']).toBe(HEAD);
    const assessment = assessRetention(document);
    expect(assessment.outcome).toBe('indeterminate');
    expect(assessment.coverage.result).toBe('indeterminate');
    expect(assessment.coverage.basis).toBe('time');
    expect(assessment.coverage.reasons.join(' ')).toContain('span');
  });

  it('answers not-met for an interior gap', () => {
    const document = documentFor();
    (document['coverage'] as Block)['runs'] = [
      { from: 1, to: 40 },
      { from: 61, to: 100 },
    ];
    (document['coverage'] as Block)['acknowledged'] = [
      { from: 1, to: 40 },
      { from: 61, to: 100 },
    ];
    (document['coverage'] as Block)['checkpoints'] = [
      { range: { from: 1, to: 40 }, at: PERIOD_FROM, head: OTHER },
      { range: { from: 61, to: 100 }, at: PERIOD_TO, head: HEAD },
    ];
    (document['coverage'] as Block)['gaps'] = [
      { from: 41, to: 60, reason: 'the intake process restarted without its sequence state' },
    ];
    document['assessment'] = { outcome: 'not-met' };
    const assessment = assessRetention(document);
    expect(assessment.outcome).toBe('not-met');
    expect(assessment.coverage.result).toBe('gap');
    expect(assessment.coverage.ranges).toContainEqual({ from: 41, to: 60 });
  });

  it('answers not-met for an interior gap the document does not state', () => {
    // The runs' own edges state the hole and no `gaps` row repeats it. The store acknowledged the whole
    // range, so the continuity check is the only member this document's outcome turns on: remove it and
    // the checkpoint ranges, which cannot witness the hole, answer indeterminate instead.
    const document = documentFor();
    (document['coverage'] as Block)['runs'] = [
      { from: 1, to: 40 },
      { from: 61, to: 100 },
    ];
    (document['coverage'] as Block)['acknowledged'] = [{ from: 1, to: 100 }];
    (document['coverage'] as Block)['checkpoints'] = [
      { range: { from: 1, to: 40 }, at: PERIOD_FROM, head: OTHER },
      { range: { from: 61, to: 100 }, at: PERIOD_TO, head: HEAD },
    ];
    document['assessment'] = { outcome: 'not-met' };
    const assessment = assessRetention(document);
    expect(assessment.outcome).toBe('not-met');
    expect(assessment.coverage.result).toBe('gap');
    expect(assessment.coverage.ranges).toContainEqual({ from: 41, to: 60 });
    expect(assessment.coverage.reasons.join(' ')).toContain('41 to 60');
  });

  it('answers not-met for a suffix loss against the pinned head', () => {
    const document = documentFor();
    (document['coverage'] as Block)['runs'] = [{ from: 1, to: 90 }];
    (document['coverage'] as Block)['acknowledged'] = [{ from: 1, to: 90 }];
    (document['coverage'] as Block)['checkpoints'] = [
      { range: { from: 1, to: 45 }, at: PERIOD_FROM, head: OTHER },
      { range: { from: 46, to: 90 }, at: PERIOD_TO, head: OTHER },
    ];
    (document['coverage'] as Block)['observedHead'] = { sequence: 90, sha256: OTHER };
    (document['coverage'] as Block)['suffixLoss'] = {
      from: 91,
      to: 100,
      reason: 'the volume lost its tail before the period closed',
    };
    document['assessment'] = { outcome: 'not-met' };
    const assessment = assessRetention(document);
    expect(assessment.outcome).toBe('not-met');
    expect(assessment.coverage.result).toBe('gap');
    expect(assessment.coverage.ranges).toContainEqual({ from: 91, to: 100 });
  });

  it('answers not-met for a rollback', () => {
    const document = documentFor();
    (document['coverage'] as Block)['rollbacks'] = [
      { sequence: 50, observedHead: OTHER, restoredHead: RESTORED },
    ];
    document['assessment'] = { outcome: 'not-met' };
    const assessment = assessRetention(document);
    expect(assessment.outcome).toBe('not-met');
    expect(assessment.coverage.result).toBe('gap');
    expect(assessment.coverage.reasons.join(' ')).toContain('rolled back');
  });

  it('answers not-met for a duplicate intake sequence', () => {
    const document = documentFor();
    (document['coverage'] as Block)['duplicates'] = [{ sequence: 30, count: 2 }];
    document['assessment'] = { outcome: 'not-met' };
    const assessment = assessRetention(document);
    expect(assessment.outcome).toBe('not-met');
    expect(assessment.coverage.result).toBe('gap');
    expect(assessment.coverage.reasons.join(' ')).toContain('30');
  });

  it('answers indeterminate for a missing checkpoint', () => {
    const document = documentFor();
    (document['coverage'] as Block)['checkpoints'] = [];
    document['assessment'] = { outcome: 'indeterminate' };
    const assessment = assessRetention(document);
    expect(assessment.outcome).toBe('indeterminate');
    expect(assessment.coverage.result).toBe('indeterminate');
    expect(assessment.coverage.basis).toBe('time');
  });

  it('answers indeterminate for a checkpoint interval wider than the declared schedule', () => {
    const document = documentFor();
    // The period is 200 seconds and the schedule promises a receipt every 100, so two receipts at the two
    // ends of the period leave the middle unwitnessed.
    (scopeOf(document)['checkpoint'] as Block)['maxIntervalSeconds'] = 100;
    (document['coverage'] as Block)['checkpoints'] = [
      { range: { from: 1, to: 50 }, at: PERIOD_FROM, head: OTHER },
      { range: { from: 51, to: 100 }, at: PERIOD_TO, head: HEAD },
    ];
    document['assessment'] = { outcome: 'indeterminate' };
    const assessment = assessRetention(document);
    expect(assessment.outcome).toBe('indeterminate');
    expect(assessment.coverage.reasons.join(' ')).toContain('more than the declared');
  });

  it('answers indeterminate for checkpoints that do not tile the declared intake', () => {
    // Two receipts at the two ends of the period witness the instants and leave the middle of the intake
    // unwitnessed. The old gate read only the timing and answered met; a range gap is a witness that does
    // not place the intake, so the answer is indeterminate and the range is named in sequence numbers.
    const document = documentFor();
    (document['coverage'] as Block)['checkpoints'] = [
      { range: { from: 1, to: 10 }, at: PERIOD_FROM, head: OTHER },
      { range: { from: 91, to: 100 }, at: PERIOD_TO, head: HEAD },
    ];
    document['assessment'] = { outcome: 'indeterminate' };
    const assessment = assessRetention(document);
    expect(assessment.outcome).toBe('indeterminate');
    expect(assessment.coverage.result).toBe('indeterminate');
    expect(assessment.coverage.basis).toBe('sequence');
    expect(assessment.coverage.ranges).toContainEqual({ from: 11, to: 90 });
    expect(assessment.coverage.reasons.join(' ')).toContain('unwitnessed');
  });

  it('answers indeterminate when the first receipt starts late or the last stops early', () => {
    const lateStart = documentFor();
    (lateStart['coverage'] as Block)['checkpoints'] = [
      { range: { from: 11, to: 100 }, at: PERIOD_FROM, head: HEAD },
    ];
    lateStart['assessment'] = { outcome: 'indeterminate' };
    const started = assessRetention(lateStart);
    expect(started.outcome).toBe('indeterminate');
    expect(started.coverage.ranges).toContainEqual({ from: 1, to: 10 });

    const earlyStop = documentFor();
    (earlyStop['coverage'] as Block)['checkpoints'] = [
      { range: { from: 1, to: 90 }, at: PERIOD_FROM, head: HEAD },
    ];
    earlyStop['assessment'] = { outcome: 'indeterminate' };
    const stopped = assessRetention(earlyStop);
    expect(stopped.outcome).toBe('indeterminate');
    expect(stopped.coverage.ranges).toContainEqual({ from: 91, to: 100 });
  });

  it('answers not-met when the final checkpoint head is not the observed head', () => {
    // The receipts tile the intake, their stamps witness the period and the observed head matches the pin.
    // The final receipt names a head the intake did not observe, so the checkpoint does not witness the
    // head the runs closed at: the answer is not met rather than met on the strength of the other members.
    const document = documentFor();
    (document['coverage'] as Block)['checkpoints'] = [
      { range: { from: 1, to: 34 }, at: PERIOD_FROM, head: '11'.repeat(32) },
      { range: { from: 35, to: 67 }, at: PERIOD_FROM + 100, head: '22'.repeat(32) },
      { range: { from: 68, to: 100 }, at: PERIOD_TO, head: OTHER },
    ];
    document['assessment'] = { outcome: 'not-met' };
    const assessment = assessRetention(document);
    expect(assessment.outcome).toBe('not-met');
    expect(assessment.coverage.result).toBe('covered');
    expect(assessment.reasons.join(' ')).toContain('does not witness the head');
  });

  it('answers indeterminate for an unwitnessed interval the store never acknowledged', () => {
    const document = documentFor();
    (document['coverage'] as Block)['acknowledged'] = [
      { from: 1, to: 40 },
      { from: 61, to: 100 },
    ];
    document['assessment'] = { outcome: 'indeterminate' };
    const assessment = assessRetention(document);
    expect(assessment.outcome).toBe('indeterminate');
    expect(assessment.coverage.result).toBe('indeterminate');
    expect(assessment.coverage.basis).toBe('sequence');
    expect(assessment.coverage.ranges).toContainEqual({ from: 41, to: 60 });
  });

  it('answers indeterminate for a head the deployment pinned about itself', () => {
    const document = documentFor();
    (scopeOf(document)['intake'] as Block)['expectedHead'] = {
      sha256: HEAD,
      pinnedBy: 'subject',
      reason: null,
    };
    document['assessment'] = { outcome: 'indeterminate' };
    expect(assessRetention(document).outcome).toBe('indeterminate');
  });

  it('answers not-met when the observed head is not the pinned head', () => {
    const document = documentFor();
    // The receipts close on the same head the intake observed, so only the comparison with the pin fails.
    (document['coverage'] as Block)['checkpoints'] = [
      { range: { from: 1, to: 34 }, at: PERIOD_FROM, head: '11'.repeat(32) },
      { range: { from: 35, to: 67 }, at: PERIOD_FROM + 100, head: '22'.repeat(32) },
      { range: { from: 68, to: 100 }, at: PERIOD_TO, head: OTHER },
    ];
    (document['coverage'] as Block)['observedHead'] = { sequence: 100, sha256: OTHER };
    document['assessment'] = { outcome: 'not-met' };
    const assessment = assessRetention(document);
    expect(assessment.outcome).toBe('not-met');
    expect(assessment.reasons.join(' ')).toContain('not the pinned head');
  });

  it('answers not-met when the declared period is shorter than the declared duty', () => {
    const document = documentFor();
    (scopeOf(document)['period'] as Block)['to'] = PERIOD_FROM + 199;
    document['assessment'] = { outcome: 'not-met' };
    expect(assessRetention(document).outcome).toBe('not-met');
  });

  it('refuses a conclusion its own evidence does not support', () => {
    const spanClaim = coded(() => assessRetention(spanOnlyDocument('met')));
    expect(spanClaim?.code).toBe('RETENTION_ASSESSMENT_DISAGREES');

    const gap = documentFor();
    (gap['coverage'] as Block)['runs'] = [
      { from: 1, to: 40 },
      { from: 61, to: 100 },
    ];
    (gap['coverage'] as Block)['acknowledged'] = [
      { from: 1, to: 40 },
      { from: 61, to: 100 },
    ];
    (gap['coverage'] as Block)['checkpoints'] = [
      { range: { from: 1, to: 40 }, at: PERIOD_FROM, head: OTHER },
      { range: { from: 61, to: 100 }, at: PERIOD_TO, head: HEAD },
    ];
    (gap['coverage'] as Block)['gaps'] = [{ from: 41, to: 60, reason: 'restart' }];
    // The stated outcome is still met: the document says one thing and its evidence another.
    const gapClaim = coded(() => assessRetention(gap));
    expect(gapClaim?.code).toBe('RETENTION_ASSESSMENT_DISAGREES');

    const understated = documentFor();
    understated['assessment'] = { outcome: 'not-met' };
    expect(coded(() => assessRetention(understated))?.code).toBe('RETENTION_ASSESSMENT_DISAGREES');
  });
});

describe('the published schema and the reader decide the same documents', () => {
  const schemaPath = fileURLToPath(new URL('../schemas/retention-assessment-v1.schema.json', import.meta.url));
  const ajv = new Ajv2020({ strict: true });
  const schemaDocument = JSON.parse(readFileSync(schemaPath, 'utf8')) as {
    readonly $id: string;
    readonly required: readonly string[];
    readonly properties: {
      readonly v: { readonly const: number };
      readonly scope: {
        readonly required: readonly string[];
        readonly properties: {
          readonly duty: { readonly properties: { readonly article: { readonly enum: readonly string[] } } };
          readonly intake: {
            readonly properties: {
              readonly expectedHead: { readonly properties: { readonly pinnedBy: { readonly enum: readonly string[] } } };
            };
          };
        };
      };
      readonly coverage: { readonly required: readonly string[] };
      readonly assessment: { readonly properties: { readonly outcome: { readonly enum: readonly string[] } } };
    };
  };
  const validate = ajv.compile(schemaDocument) as ValidateFunction<unknown>;

  const accepted: readonly (readonly [string, Block])[] = [
    ['the covered document', documentFor()],
    ['the span-only document', spanOnlyDocument()],
    ['a document with an interior gap', (() => {
      const document = documentFor();
      (document['coverage'] as Block)['runs'] = [
        { from: 1, to: 40 },
        { from: 61, to: 100 },
      ];
      (document['coverage'] as Block)['acknowledged'] = [
        { from: 1, to: 40 },
        { from: 61, to: 100 },
      ];
      (document['coverage'] as Block)['checkpoints'] = [
        { range: { from: 1, to: 40 }, at: PERIOD_FROM, head: OTHER },
        { range: { from: 61, to: 100 }, at: PERIOD_TO, head: HEAD },
      ];
      (document['coverage'] as Block)['gaps'] = [{ from: 41, to: 60, reason: 'restart' }];
      document['assessment'] = { outcome: 'not-met' };
      return document;
    })()],
  ];

  for (const [name, document] of accepted) {
    it(`takes ${name} through the schema and through the reader`, () => {
      expect(validate(document), JSON.stringify(validate.errors)).toBe(true);
      expect(() => parseRetentionAssessment(document)).not.toThrow();
    });
  }

  const refused: readonly (readonly [string, Block])[] = [
    ['a member no version defines', { ...documentFor(), retainedAt: PERIOD_TO }],
    ['a version this reader does not implement', { ...documentFor(), v: 2 }],
    ['a pinning party outside the layout', (() => {
      const document = documentFor();
      ((scopeOf(document)['intake'] as Block)['expectedHead'] as Block)['pinnedBy'] = 'self';
      return document;
    })()],
    ['a schedule weaker than hourly', (() => {
      const document = documentFor();
      (scopeOf(document)['checkpoint'] as Block)['maxIntervalSeconds'] = MAX_CHECKPOINT_INTERVAL_SECONDS + 1;
      return document;
    })()],
    ['a head of the wrong width', (() => {
      const document = documentFor();
      (coverageOf(document)['observedHead'] as Block)['sha256'] = 'aa';
      return document;
    })()],
    ['an outcome outside the three', (() => {
      const document = documentFor();
      document['assessment'] = { outcome: 'discharged' };
      return document;
    })()],
  ];

  for (const [name, document] of refused) {
    it(`refuses ${name} through the schema and through the reader`, () => {
      expect(validate(document), 'the schema took a document the reader refuses').toBe(false);
      expect(() => parseRetentionAssessment(document)).toThrow();
    });
  }

  it('holds the schema enums and member lists to the reader\'s own, in both directions', () => {
    expect(schemaDocument.$id).toBe('https://ashaveri.com/schemas/retention-assessment-v1.json');
    expect(schemaDocument.properties.v.const).toBe(RETENTION_ASSESSMENT_FORMAT_VERSION);
    expect([...schemaDocument.required].sort()).toEqual([...RETENTION_ASSESSMENT_MEMBERS].sort());
    expect([...schemaDocument.properties.scope.required].sort()).toEqual([...RETENTION_SCOPE_MEMBERS].sort());
    expect([...schemaDocument.properties.coverage.required].sort()).toEqual([...RETENTION_COVERAGE_MEMBERS].sort());
    expect([...schemaDocument.properties.scope.properties.duty.properties.article.enum].sort()).toEqual(
      [...RETENTION_ASSESSMENT_ARTICLES].sort(),
    );
    expect([
      ...schemaDocument.properties.scope.properties.intake.properties.expectedHead.properties.pinnedBy.enum,
    ].sort()).toEqual([...EXPECTED_HEAD_PINNERS].sort());
    expect([...schemaDocument.properties.assessment.properties.outcome.enum].sort()).toEqual(
      [...RETENTION_ASSESSMENT_OUTCOMES].sort(),
    );
  });
});

describe('the retention manifest the assessment corrects', () => {
  const vectorsPath = fileURLToPath(new URL('../../fixtures/data/epoch-inventory-v1.json', import.meta.url));

  /**
   * Every published retention artifact in the inventory suite, decoded from the base64url byte string the
   * row hands the presence fold. The v1 artifacts are the ones whose duty arithmetic the assessment family
   * must leave exactly as it was: this test pins that the shipped v1 reader still takes them, and that the
   * two figures the old span rule turned on are the ones the documents still carry.
   */
  function publishedRetentionArtifacts(): { readonly version: number; readonly bytes: Uint8Array }[] {
    const file = JSON.parse(readFileSync(vectorsPath, 'utf8')) as {
      readonly vectors: readonly { readonly read?: { readonly presence?: readonly string[] } }[];
    };
    const artifacts: { version: number; bytes: Uint8Array }[] = [];
    for (const row of file.vectors) {
      for (const encoded of row.read?.presence ?? []) {
        const bytes = new Uint8Array(Buffer.from(encoded.replace(/-/gu, '+').replace(/_/gu, '/'), 'base64'));
        const version = (JSON.parse(Buffer.from(bytes).toString('utf8')) as { v: number }).v;
        artifacts.push({ version, bytes });
      }
    }
    return artifacts;
  }

  it('still reads every published retention v1 artifact and finds its duty arithmetic intact', () => {
    const artifacts = publishedRetentionArtifacts();
    const v1 = artifacts.filter((artifact) => artifact.version === 1);
    expect(v1.length, 'the published inventory suite carries no retention v1 artifact').toBeGreaterThan(0);
    for (const artifact of v1) {
      const manifest = parseRetentionDocument(artifact.bytes);
      const expectedHeld = manifest.retained.count === 0 ? 0 : manifest.at - manifest.retained.from;
      expect(manifest.duty.heldSeconds, 'heldSeconds is the distance from the oldest survivor to the stamp').toBe(expectedHeld);
      expect(manifest.duty.met, 'met is that span compared with the declared period').toBe(
        manifest.duty.heldSeconds >= manifest.duty.requiredSeconds,
      );
    }
  });
});
