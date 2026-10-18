import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  DEFAULT_RECEIPT_RECORD_KIND,
  openFileReceiptStore,
  readReceiptStoreCheckpoint,
  readRetentionEvidence,
  toHex,
} from '@ashaveri/signerd';
import { assessRetention, produceRetentionAssessment, SdkError } from '@ashaveri/sdk';

/**
 * The gateway-to-SDK evidence seam, exercised by one test against a real store.
 *
 * A store is opened through `openFileReceiptStore`, read as evidence through `readRetentionEvidence`, and that
 * evidence is fed straight into `produceRetentionAssessment` without a hand-restated shape in between, because
 * the seam this suite exists to guard is the one where a caller takes what the gateway answers and hands it to
 * the producer. `@ashaveri/fixtures` is the only in-repo package that already holds a dependency on both
 * `@ashaveri/signerd` and `@ashaveri/sdk`, so it is where the composition can be run end to end.
 *
 * Nothing here recomputes what the implementation computes. The assertions compare the produced document and
 * its reading against numbers read out of the store's own methods: the head `store.head()` recomputes, the
 * range and instant `readReceiptStoreCheckpoint` reports, and the clock `store.timeSource()` states. The
 * reader's outcome is read back, not derived from the rule, and the dishonest claim is shown refused rather
 * than restated as arithmetic. A drift in the gateway evidence shape would move one of those numbers or stop
 * the producer, which is what makes the case falsifiable.
 */

const RECEIPT = Uint8Array.from(Array.from({ length: 64 }, (_, i) => (i * 11) % 256));
const STAMP = 1_780_000_000;
const IDS = ['rcpt_01', 'rcpt_02', 'rcpt_03'];
const PERIOD = { from: STAMP, to: STAMP + 200 };
const NO_PIN = { sha256: null, pinnedBy: 'none', reason: 'the customer held no head for this assessment' } as const;

let created: string[] = [];

async function storeDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'ashaveri-retention-seam-'));
  created.push(dir);
  return dir;
}

/** Writes three receipts a minute apart with a maintained index, then reopens so the checkpoint is flushed. */
async function maintainedStore(dir: string): Promise<void> {
  const store = await openFileReceiptStore({ dir });
  for (const [i, id] of IDS.entries()) {
    await store.put(id, RECEIPT, STAMP + i * 60);
  }
  await openFileReceiptStore({ dir });
}

/** The declared scope the evidence reader is handed: a duty, a period, and no head pinned by anyone. */
function request(dir: string): Parameters<typeof readRetentionEvidence>[0] {
  return {
    dir,
    subject: { kind: 'deployment', id: 'seam-deployment' },
    duty: { article: '19(1)', requiredSeconds: 200 },
    period: PERIOD,
    expectedHead: NO_PIN,
    maxIntervalSeconds: 3_600,
  };
}

afterEach(async () => {
  const dirs = created;
  created = [];
  await Promise.all(dirs.map((dir) => rm(dir, { recursive: true, force: true })));
});

describe('store evidence composed into a produced assessment', () => {
  it('carries the head and checkpoint range the store states into the produced bytes', async () => {
    const dir = await storeDir();
    await maintainedStore(dir);

    const reference = await openFileReceiptStore({ dir });
    const headHex = toHex(await reference.head());
    const source = reference.timeSource();
    const checkpoint = await readReceiptStoreCheckpoint(dir, DEFAULT_RECEIPT_RECORD_KIND);
    expect(checkpoint.present).toBe(true);
    // The store agrees with itself: the head the index checkpoint names is the head the store recomputes.
    expect(checkpoint.head).toBe(headHex);

    const evidence = await readRetentionEvidence(request(dir));
    const produced = produceRetentionAssessment({ scope: evidence.scope, coverage: evidence.coverage, claim: 'indeterminate' });

    // The bytes the writer handed back re-read to the same assessment the writer's own round trip reached.
    const reread = assessRetention(JSON.parse(produced.bytes));
    expect(reread).toEqual(produced.assessment);

    // Every number the assessment rests on is the store's own, taken off its methods, not a figure computed here.
    expect(produced.document.coverage.observedHead).toEqual({ sequence: checkpoint.lastSequence, sha256: headHex });
    expect(produced.document.coverage.checkpoints).toEqual([
      { range: { from: checkpoint.firstSequence, to: checkpoint.lastSequence }, at: checkpoint.at, head: headHex },
    ]);
    expect(produced.document.coverage.runs).toEqual([{ from: checkpoint.firstSequence, to: checkpoint.lastSequence }]);
    expect(produced.document.scope.intake).toEqual({
      from: checkpoint.firstSequence,
      to: checkpoint.lastSequence,
      expectedHead: NO_PIN,
    });
    expect(produced.document.scope.timeBasis).toEqual({ source: source.name, uncertaintySeconds: source.uncertaintySeconds });

    // The outcome the shipped reader reaches over the produced bytes is the one the store state supports.
    expect(produced.assessment.outcome).toBe('indeterminate');
    expect(reread.coverage.result).toBe('indeterminate');
  });

  it('refuses to write the same store evidence up as met, because the store states one checkpoint and no pin', async () => {
    const dir = await storeDir();
    await maintainedStore(dir);
    const evidence = await readRetentionEvidence(request(dir));

    let failure: unknown = null;
    try {
      produceRetentionAssessment({ scope: evidence.scope, coverage: evidence.coverage, claim: 'met' });
    } catch (error) {
      failure = error;
    }
    expect(failure).toBeInstanceOf(SdkError);
    expect((failure as SdkError).code).toBe('RETENTION_ASSESSMENT_DISAGREES');
  });
});
