import { describe, expect, it } from 'vitest';
import { assessScope, PROBE_DEADLINE_MS, runCheckpointDrill, type Assessment, type DrillResult } from './support/checkpoint-drill.js';
import { bootBudget } from './support/served-gateway.js';

/**
 * The checkpoint and retention-evidence drill, run against a real deployment.
 *
 * One run of the drill is shared by every case below, because the run is the artifact: five hours of a
 * gateway serving completions into one volume on a disk, a second process opening that volume after the
 * server has stopped to take each checkpoint, a head pinned by a key the deployment never held, and then
 * twelve questions asked of the bytes the run left. A case here asserts a verdict the run reached; none of
 * them builds a store to reach it in.
 *
 * The control case is what makes the rest mean anything. A fold that answered `gap` to every question would
 * pass every arm below and prove nothing, so the scope declared as the run actually happened has to come
 * back `pass` first. An arm that came back `pass` where a gap was wanted is asserted as `pass`, with the
 * reason it is not caught stated here rather than left out.
 */

let started: Promise<DrillResult> | null = null;

function drill(): Promise<DrillResult> {
  started ??= runCheckpointDrill((line) => {
    process.stdout.write(`${line}\n`);
  });
  return started;
}

/** Five boots' patience, plus the twelve sealed readings a second process takes of the same volume. */
const DRILL_TIMEOUT = bootBudget(5) + 12 * PROBE_DEADLINE_MS;

function named(arms: readonly Assessment[], want: string): Assessment {
  const found = arms.find((each) => each.label.startsWith(want));
  if (found === undefined) throw new Error(`no arm named "${want}" ran`);
  return found;
}

function kinds(answer: Assessment): string[] {
  return answer.findings.map((each) => each.kind);
}

describe('the drill run', () => {
  it(
    'serves five hours of completions into one volume and reads each head back from the sealed bytes',
    async () => {
      const result = await drill();
      expect(result.served).toHaveLength(15);
      expect(result.checkpoints.map((each) => each.label)).toEqual(['A', 'B', 'C', 'D', 'E']);
      // The checkpoints a closed batch left each name a different head, and the batch that ended in the kill
      // names the volume's own end instead of a checkpoint's.
      const witnessed = result.checkpoints.filter((each) => each.at !== null);
      expect(witnessed).toHaveLength(4);
      expect(new Set(witnessed.map((each) => each.head?.sha256)).size).toBe(4);
      expect(result.checkpoints.at(-1)?.head?.sequence).toBe(14);
      // The stamps this run filed came from the source the operator named, not from the host's own claim.
      expect(result.clock.source).toBe('drill synchronisation');
      expect(result.clock.instants.at(1)! - result.clock.instants.at(0)!).toBe(3_600);
      expect(result.clock.instants.at(4)! - result.clock.instants.at(3)!).toBe(2 * 3_600);
      // Every completion is in the access log, and the manifest read is the line beside them.
      expect(result.access.lines).toBe(result.served.length + 1);
      expect(result.access.files.length).toBeGreaterThan(0);
    },
    DRILL_TIMEOUT,
  );

  it('takes each checkpoint from the sealed evidence rather than from the process that wrote it', async () => {
    const result = await drill();
    expect(result.sealedCheckpoints).toHaveLength(5);
    for (const each of result.sealedCheckpoints) {
      if (!each.sealed.present || each.volume === null) continue;
      // The index beside the volume never claims more than the receipts on it, whatever else it lags by.
      expect(each.sealed.lastSequence, `${each.label}: the index named a head past the volume`).toBeLessThanOrEqual(each.volume.sequence);
    }
    expect(result.sealedCheckpoints[0]?.volume?.sequence).toBe(3);
  });
});

describe('the five loss arms, asked of the live volume', () => {
  it('passes the scope declared as the run happened', async () => {
    const control = named((await drill()).arms, 'control:');
    expect(control.findings, JSON.stringify(control.findings)).toEqual([]);
    expect(control.verdict).toBe('pass');
    expect(control.coverageArm).toBe('checkpoint');
  });

  it('catches an acknowledged receipt rebuilt out of the volume', async () => {
    const omitted = named((await drill()).arms, 'omitted:');
    expect(omitted.verdict).not.toBe('pass');
    expect(kinds(omitted)).toContain('omitted-record');
    expect(kinds(omitted)).toContain('head-disagreement');
  });

  it('catches a receipt inside the scope that no client was issued', async () => {
    const extra = named((await drill()).arms, 'extra:');
    expect(extra.verdict).not.toBe('pass');
    expect(kinds(extra)).toContain('extra-record');
    expect(kinds(extra)).toContain('head-disagreement');
  });

  it('catches a checkpoint from an earlier hour offered for the whole scope', async () => {
    const stale = named((await drill()).arms, 'stale replay:');
    expect(stale.verdict).not.toBe('pass');
    expect(kinds(stale)).toEqual(['stale-replay']);
  });

  it('catches the same positions holding different bytes', async () => {
    const rollback = named((await drill()).arms, 'rollback:');
    expect(rollback.verdict).not.toBe('pass');
    expect(kinds(rollback)).toContain('head-disagreement');
    expect(kinds(rollback)).toContain('rollback');
  });

  it('catches the acknowledged tail gone from the volume', async () => {
    const suffix = named((await drill()).arms, 'suffix loss:');
    expect(suffix.verdict).not.toBe('pass');
    expect(kinds(suffix)).toContain('suffix-loss');
    expect(kinds(suffix)).toContain('omitted-record');
  });

  it('does not catch a receipt appended past the declared end, and says why', async () => {
    const beyond = named((await drill()).arms, 'beyond scope:');
    // The edge of the clause, stated rather than hidden. A head pinned at the end of a declared scope
    // witnesses that scope; a record added behind the end is outside it, and pinning a head that does not
    // exist yet is not a thing any scheme does. The arm is kept here so the boundary stays measured: if a
    // later reading of the same bytes starts calling this a gap, this case goes red and says so.
    expect(beyond.verdict).toBe('pass');
    expect(beyond.findings).toEqual([]);
  });

  it('answers an unpinned scope as indeterminate rather than as a pass', async () => {
    const unpinned = named((await drill()).arms, 'unpinned:');
    expect(unpinned.verdict).toBe('indeterminate');
    expect(kinds(unpinned)).toEqual(['no-independent-pin']);
  });

  it('answers a volume that states no checkpoint as indeterminate rather than as a pass', async () => {
    const declined = named((await drill()).arms, 'no index:');
    expect(declined.verdict).toBe('indeterminate');
    expect(kinds(declined)).toEqual(['no-checkpoint-witness']);
    expect(declined.coverageArm).toBe('span');
  });
});

describe('the crash, retry and restore legs', () => {
  it('says the batch that ended in the kill is unwitnessed, and never that it passed', async () => {
    const crash = named((await drill()).legs, 'crash:');
    expect(crash.verdict).toBe('gap');
    expect(kinds(crash)).toEqual(['unwitnessed-interval', 'interval-exceeded']);
  });

  it('keeps every durable acknowledgement across the kill', async () => {
    const crash = named((await drill()).legs, 'crash:');
    // What the crash costs is the checkpoint and not the bytes: every receipt the deployment acknowledged is
    // still on the volume after the restart, so the gap above is about an interval no witness reaches.
    expect(crash.observed?.sequence).toBe(14);
    expect(kinds(crash)).not.toContain('omitted-record');
    expect(kinds(crash)).not.toContain('suffix-loss');
  });

  it('shows a replayed proof of possession served again by the restarted process', async () => {
    const result = await drill();
    // The replay set lives in the process that served the first request, so a restart is shown a nonce it
    // never saw and answers it as a new intent. The receipt this files is the extra record the retry leg
    // below names; this case states what the run did rather than calling it right.
    expect(result.replay.status).toBe(200);
    expect(typeof result.replay.receiptId).toBe('string');
  });

  it('names the second receipt a retried intent filed as an extra record', async () => {
    const retry = named((await drill()).legs, 'retry:');
    expect(retry.verdict).not.toBe('pass');
    expect(kinds(retry)).toContain('extra-record');
  });

  it('catches a volume restored from an earlier hour beside the index that is not its own', async () => {
    const restore = named((await drill()).legs, 'restore:');
    expect(restore.verdict).toBe('gap');
    expect(kinds(restore)).toContain('suffix-loss');
    expect(kinds(restore)).toContain('omitted-record');
    // The stale index is not believed: the reader answers with the volume it can chain, not with the head
    // the index beside it was written for.
    expect(restore.observed?.sequence).toBe(3);
  });
});

describe('the pin', () => {
  it('refuses a pin signed by a key the issuance set names, and accepts the one held apart', async () => {
    const result = await drill();
    const [selfIssued, published, independent] = result.pins;
    expect(selfIssued?.refused, JSON.stringify(selfIssued)).toBe(true);
    expect(selfIssued?.code).toBe('PIN_SELF_ISSUED');
    expect(published?.refused, JSON.stringify(published)).toBe(true);
    expect(published?.code).toBe('PIN_SELF_ISSUED');
    expect(independent?.refused, JSON.stringify(independent)).toBe(false);
    expect(independent?.code).toBeNull();
    expect(independent?.head).toEqual(result.checkpoints.find((each) => each.label === 'C')?.head ?? null);
    // The two refusals rest on different facts, and the difference is kept visible.
    expect(selfIssued?.signatureByThisKey, 'a well-formed self-pin is refused on identity alone').toBe(true);
    expect(published?.signatureByThisKey, "no signature by this run's own receipt key exists in the artifact").toBe(false);
    expect(result.issuanceIdentities).toHaveLength(1);
    expect(result.holderKeyId).not.toBe(result.issuanceIdentities[0]);
    // The private half of the held-apart key is nowhere in the directory the deployment serves from.
    expect(result.volumeListing).not.toContain('head-pin-private.pem');
  });
});

describe('the fold beside the live run', () => {
  it('answers a store that will not say what it holds with the refusal it gave', async () => {
    const control = named((await drill()).arms, 'control:');
    const assessed = assessScope({
      declared: control.declared,
      probe: { ok: false, evidence: null, code: 'STORE_CHAIN_BROKEN', message: 'the record at 3 does not chain from 2' },
      volume: { records: [], endAt: 0, brokenAtSeq: null },
    });
    expect(assessed.verdict).toBe('refused');
    expect(kinds(assessed)).toEqual(['store-refusal']);
  });

  it('answers a volume that does not chain as refused rather than as a gap', async () => {
    const control = named((await drill()).arms, 'control:');
    expect(control.verdict, 'the live volume chained, so this synthetic one is the only broken thing here').toBe('pass');
    const assessed = assessScope({
      declared: control.declared,
      probe: { ok: true, evidence: null, code: null, message: null },
      volume: {
        records: [
          { seq: 0, at: control.declared.period.from, id: 'rcpt_zero', payload: Buffer.alloc(8, 1), digest: 'f'.repeat(64), prev: '0'.repeat(64), offset: 0, bytes: 100 },
          { seq: 1, at: control.declared.period.from + 1, id: 'rcpt_one', payload: Buffer.alloc(8, 2), digest: 'e'.repeat(64), prev: 'd'.repeat(64), offset: 100, bytes: 100 },
        ],
        endAt: 200,
        brokenAtSeq: 1,
      },
    });
    expect(assessed.verdict).toBe('refused');
    expect(kinds(assessed)).toEqual(['chain-disagreement']);
  });
});
