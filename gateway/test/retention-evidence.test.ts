import { afterEach, describe, expect, it } from 'vitest';
import { mkdtemp, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { toHex } from '../src/digest.js';
import { openFileReceiptStore, RECEIPT_SIDECAR_FILE, RECEIPT_STORE_FILE, type ReceiptRetention } from '../src/store.js';
import { readRetentionEvidence } from '../src/retention-evidence.js';
import { fixedClock } from './helpers.js';

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
 *
 * The second and third blocks hold the door to the two things it owes the directory it reads and the document
 * it hands back. It is a second opening of the operator's store, so the deployment's durability and serving
 * bounds go into that opening: an opening the gateway refuses at startup is refused here, and a window the
 * deployment would have pruned is not read as a window it holds. And a reader of evidence has no business
 * writing it, so the sidecar is declined unless the caller asks for it by name, which a listing taken before
 * and after a read is able to show. Where the caller gave the reader neither a period nor a count, the evidence
 * says so itself, because a span read from a file nobody bounded is not the deployment's own duty.
 */

const RECEIPT = Uint8Array.from(Array.from({ length: 64 }, (_, i) => (i * 7) % 256));
const STAMP = 1_780_000_000;
const IDS = ['rcpt_01', 'rcpt_02', 'rcpt_03'];
/** Ten receipts sharing one instant at a durability bound of ten: a store exactly at its bound. */
const BURST = Array.from({ length: 10 }, (_, i) => `rcpt_${String(i).padStart(3, '0')}`);

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

describe('the bounds the door opens under', () => {
  /**
   * The sorted names in a store directory, so a case can show what a read left behind.
   *
   * Sorted because a directory has no order an operating system owes a reader, and a listing that moved
   * between two runs of the same case would be a difference in the volume rather than in the door.
   */
  async function listing(dir: string): Promise<string[]> {
    return (await readdir(dir)).sort();
  }

  /** Writes `ids` receipts all at one instant under the retention the case names, keeping the index. */
  async function burstUnder(dir: string, ids: readonly string[], retention: ReceiptRetention): Promise<void> {
    const store = await openFileReceiptStore({ dir, retention });
    for (const id of ids) {
      await store.put(id, RECEIPT, STAMP);
    }
  }

  it('refuses the pairing the gateway refuses at startup, rather than assessing past it', async () => {
    // Ten receipts sharing one instant are a store exactly at its durability bound, and a two second
    // period takes more receipts at that traffic than the bound allows: the count is what cut the window
    // short. `openFileReceiptStore` refuses that pairing since the window derivation landed, and this door is a second opening
    // of the same directory, so the refusal it owes is the same one and not a wider span read as evidence.
    const dir = await emptyDir();
    const retention: ReceiptRetention = { maxAgeSeconds: 2, maxCount: 10, time: fixedClock(() => STAMP) };
    await burstUnder(dir, BURST, retention);

    await expect(readRetentionEvidence({ dir, retention, ...DECLARATION })).rejects.toMatchObject({
      code: 'RETENTION_WINDOW_UNHOLDABLE',
    });
  });

  it('reports the window the deployment retains, not the wider span still on the volume', async () => {
    // Three receipts a minute apart, and a deployment that keeps a period shorter than the gap between the
    // first two: the opening ages the oldest out of what it serves, and the evidence is of what the store
    // serves. The clock is injected because the window is a statement about an instant, and the host clock
    // would age all three out of the case rather than one.
    const dir = await emptyDir();
    const retention: ReceiptRetention = { maxAgeSeconds: 70, maxCount: 10, time: fixedClock(() => STAMP + 120) };
    await fileWith(dir, IDS, true);

    const evidence = await readRetentionEvidence({ dir, retention, ...DECLARATION });
    expect(evidence.coverage.span).toEqual({
      from: STAMP + 60,
      to: STAMP + 120,
      oldestHead: expect.any(String),
      newestHead: expect.any(String),
    });

    // The same directory read with no bound gives the wider span, which is the difference the case above
    // is for: the bytes are the same and the deployment's answer about them is not.
    const unbounded = await readRetentionEvidence({ dir, ...DECLARATION });
    expect(unbounded.coverage.span!.from).toBe(STAMP);
  });

  it('leaves no new file in the store directory when the caller did not ask for an index', async () => {
    // The store is written by openings that all declined the index, so the volume holds the log and nothing
    // else. A read of that directory is then asked to leave it as it found it: the index an opening would
    // bootstrap is a file in the operator's evidence directory, and a presentation command that writes one
    // has changed the thing it was asked to look at.
    const dir = await emptyDir();
    await fileWith(dir, IDS, true);
    const before = await listing(dir);
    expect(before).toEqual([RECEIPT_STORE_FILE]);

    const evidence = await readRetentionEvidence({ dir, ...DECLARATION });
    expect(await listing(dir)).toEqual(before);
    // Reading without the index is reading a store that states no checkpoint, which the evidence says so.
    expect(evidence.coverage.checkpoints).toEqual([]);
    expect(evidence.coverage.span).not.toBeNull();
  });

  it('writes the index only when the caller asks for it by name', async () => {
    // The other half of the default: a caller that wants the index names it, and the door then opens with
    // one and the volume gains it. A hard refusal to index would fail this case, and so would a default
    // that writes one for a reader that never asked.
    const dir = await emptyDir();
    await fileWith(dir, IDS, true);
    const before = await listing(dir);

    const evidence = await readRetentionEvidence({ dir, sidecarIndex: true, ...DECLARATION });
    expect(await listing(dir)).toEqual([...before, RECEIPT_SIDECAR_FILE].sort());
    expect(evidence.coverage.checkpoints).toHaveLength(1);
  });
});

describe('what the evidence states about the bound it was given', () => {
  it('states that no bound was given to the reader when the request named neither a period nor a count', async () => {
    const dir = await emptyDir();
    await fileWith(dir, IDS, false);

    const evidence = await readRetentionEvidence({ dir, ...DECLARATION });
    expect(evidence.readerBound).toEqual({
      stated: 'none',
      sentence: 'no bound was given to the reader',
    });
  });

  it('states that no bound was given when the request handed over an empty retention object', async () => {
    // Passing the object is not passing a bound: every field of `ReceiptRetention` is optional, and each
    // absent one is documented as nothing aging out or nothing shed by count. A reader given `{}` was given
    // a configuration that bounds nothing, and the evidence has to say so rather than let the object read
    // as an answer about what the deployment keeps.
    const dir = await emptyDir();
    await fileWith(dir, IDS, false);

    const evidence = await readRetentionEvidence({ dir, retention: {}, ...DECLARATION });
    expect(evidence.readerBound).toEqual({
      stated: 'none',
      sentence: 'no bound was given to the reader',
    });
  });

  it('names the period it was given and states that it was given no count', async () => {
    const dir = await emptyDir();
    await fileWith(dir, IDS, false);

    const evidence = await readRetentionEvidence({
      dir,
      retention: { maxAgeSeconds: 600, time: fixedClock(() => STAMP) },
      ...DECLARATION,
    });
    expect(evidence.readerBound).toEqual({ stated: 'given', maxAgeSeconds: 600, maxCount: null });
  });

  it('names the count it was given and states that it was given no period', async () => {
    // A count alone is a capacity number and covers no span of time, which is why the pairing the opening
    // refuses is a period beside a count and why this arm states the period it does not have.
    const dir = await emptyDir();
    await fileWith(dir, IDS, false);

    const evidence = await readRetentionEvidence({ dir, retention: { maxCount: 10_000 }, ...DECLARATION });
    expect(evidence.readerBound).toEqual({ stated: 'given', maxAgeSeconds: null, maxCount: 10_000 });
  });

  it('names both when the deployment configured both', async () => {
    const dir = await emptyDir();
    await fileWith(dir, IDS, false);

    const evidence = await readRetentionEvidence({
      dir,
      retention: { maxAgeSeconds: 600, maxCount: 10_000, time: fixedClock(() => STAMP) },
      serving: { maxServedReceipts: 500 },
      ...DECLARATION,
    });
    expect(evidence.readerBound).toEqual({ stated: 'given', maxAgeSeconds: 600, maxCount: 10_000 });
  });
});
