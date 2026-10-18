import { afterEach, describe, expect, it } from 'vitest';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { toHex } from '../src/digest.js';
import { openFileReceiptStore } from '../src/store.js';
import { readRetentionEvidence } from '../src/retention-evidence.js';

/**
 * Reading retention assessment evidence out of a store directory.
 *
 * The claim these cases hold is about the door, not the verdict: what a store states, this reader reports as
 * the evidence, and where a store states nothing the evidence says so rather than quietly inventing a witness.
 * Three store shapes exercise the whole branch a producer reads. A store that keeps its sidecar index states
 * a checkpoint, and the evidence carries one sequence run the store observed, that same range acknowledged, the
 * one checkpoint, and the head the store closed on. A store that declines its index states no checkpoint, and
 * the evidence offers only a span between the oldest and newest survivors and no observed head, which the
 * reader over a document built from it reads as indeterminate. A store that holds nothing offers no coverage at
 * all.
 *
 * Each case compares the evidence against the store's own answers, read straight off `openFileReceiptStore`:
 * the head the checkpoint names is the head the store reports, and the span's two ends are the window and the
 * chain endpoints the store holds. That is what keeps a reader from shipping a document its own store
 * contradicts.
 */

const RECEIPT = Uint8Array.from(Array.from({ length: 64 }, (_, i) => (i * 7) % 256));
const STAMP = 1_780_000_000;
const IDS = ['rcpt_01', 'rcpt_02', 'rcpt_03'];

const DECLARATION = {
  subject: { kind: 'deployment', id: 'evidence-deployment' },
  duty: { article: '19(1)', requiredSeconds: 10_000 },
  period: { from: STAMP, to: STAMP + 200 },
  expectedHead: { sha256: null, pinnedBy: 'none', reason: 'the customer held no head for this assessment' },
  maxIntervalSeconds: 3_600,
} as const;

let created: string[] = [];

async function emptyDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'ashaveri-retention-evidence-'));
  created.push(dir);
  return dir;
}

/** Writes `ids` receipts a minute apart with the sidecar choice the case names, then reopens once. */
async function fileWith(dir: string, ids: readonly string[], declined: boolean): Promise<void> {
  const store = await openFileReceiptStore({ dir, ...(declined ? { sidecarIndex: false } : {}) });
  for (const [i, id] of ids.entries()) {
    await store.put(id, RECEIPT, STAMP + i * 60);
  }
  await openFileReceiptStore({ dir, ...(declined ? { sidecarIndex: false } : {}) });
}

afterEach(async () => {
  const dirs = created;
  created = [];
  await Promise.all(dirs.map((dir) => rm(dir, { recursive: true, force: true })));
});

describe('readRetentionEvidence', () => {
  it('reads a maintained index as the checkpoint the store states, against the store head', async () => {
    const dir = await emptyDir();
    await fileWith(dir, IDS, false);
    const reference = await openFileReceiptStore({ dir });
    const head = toHex(await reference.head());

    const evidence = await readRetentionEvidence({ dir, ...DECLARATION });
    expect(evidence.coverage.checkpoints).toHaveLength(1);
    const receipt = evidence.coverage.checkpoints[0]!;
    expect(receipt.head).toBe(head);
    expect(receipt.range).toEqual({ from: 0, to: 2 });
    expect(receipt.at).toBe(STAMP + 120);
    expect(evidence.coverage.observedHead).toEqual({ sequence: 2, sha256: head });
    expect(evidence.coverage.runs).toEqual([{ from: 0, to: 2 }]);
    expect(evidence.coverage.acknowledged).toEqual([{ from: 0, to: 2 }]);
    expect(evidence.coverage.span).toBeNull();
    // The intake range is derived from what the store observed, and the scope is the deployment's declaration
    // with the store's own clock basis beside it.
    expect(evidence.scope.intake).toEqual({ from: 0, to: 2, expectedHead: DECLARATION.expectedHead });
    expect(evidence.scope.timeBasis).toEqual({ source: 'host clock', uncertaintySeconds: null });
    expect(evidence.scope.checkpoint).toEqual({ holder: 'customer', eachCompletedBatch: true, maxIntervalSeconds: 3_600 });
  });

  it('reads a declined index as no checkpoint, offering only a span', async () => {
    const dir = await emptyDir();
    await fileWith(dir, IDS, true);
    const reference = await openFileReceiptStore({ dir, sidecarIndex: false });
    const head = toHex(await reference.head());
    const anchor = toHex((await reference.chainState()).anchor);

    const evidence = await readRetentionEvidence({ dir, sidecarIndex: false, ...DECLARATION });
    expect(evidence.coverage.checkpoints).toEqual([]);
    expect(evidence.coverage.observedHead).toBeNull();
    expect(evidence.coverage.runs).toEqual([]);
    expect(evidence.coverage.span).toEqual({ from: STAMP, to: STAMP + 120, oldestHead: anchor, newestHead: head });
  });

  it('reads a store that holds nothing as no coverage at all', async () => {
    const dir = await emptyDir();
    // Opened and left empty: no append, so no record to state a checkpoint over and no span to draw.
    await openFileReceiptStore({ dir });

    const evidence = await readRetentionEvidence({ dir, ...DECLARATION });
    expect(evidence.coverage.runs).toEqual([]);
    expect(evidence.coverage.checkpoints).toEqual([]);
    expect(evidence.coverage.observedHead).toBeNull();
    expect(evidence.coverage.span).toBeNull();
  });

  it('honours a declared intake wider than the store observed', async () => {
    const dir = await emptyDir();
    await fileWith(dir, IDS, false);
    const evidence = await readRetentionEvidence({ dir, intake: { from: 0, to: 10 }, ...DECLARATION });
    expect(evidence.scope.intake.from).toBe(0);
    expect(evidence.scope.intake.to).toBe(10);
    // The store still states only what it holds: the observed run and head are the store's, not the claim.
    expect(evidence.coverage.observedHead).not.toBeNull();
    expect(evidence.coverage.observedHead!.sequence).toBe(2);
  });
});
