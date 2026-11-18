import { access, rm } from 'node:fs/promises';
import { dirname } from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import * as serving from './support/served-gateway.js';
import { assessScope, CHECKPOINT_READ_COUNT, DRILL_BOOT_COUNT, DRILL_SCENARIOS, PROBE_DEADLINE_MS, runCheckpointDrill, type Assessment, type DrillResult } from './support/checkpoint-drill.js';
import { bootBudget } from './support/served-gateway.js';
import { readPinEvidence } from './support/checkpoint-pin.js';

// Sharing one run keeps every assessment on the same captured evidence.

let started: Promise<DrillResult> | null = null;

function drill(): Promise<DrillResult> {
  started ??= runCheckpointDrill((line) => {
    process.stdout.write(`${line}\n`);
  });
  return started;
}

// Include checkpoint probes as well as the named scenario readings.
const DRILL_TIMEOUT = bootBudget(DRILL_BOOT_COUNT) + (DRILL_SCENARIOS.length + CHECKPOINT_READ_COUNT) * PROBE_DEADLINE_MS;

function named(arms: readonly Assessment[], want: string): Assessment {
  const found = arms.find((each) => each.label.startsWith(want));
  if (found === undefined) throw new Error(`no arm named "${want}" ran`);
  return found;
}

function kinds(answer: Assessment): string[] {
  return answer.findings.map((each) => each.kind);
}

describe('drill deployment cleanup', () => {
  it.each([
    { boot: 'A', failure: 'manifest' },
    { boot: 'B', failure: 'manifest' },
    { boot: 'C', failure: 'manifest' },
    { boot: 'D', failure: 'manifest' },
    { boot: 'E', failure: 'manifest' },
    { boot: 'D', failure: 'receipt' },
    { boot: 'A', failure: 'serving' },
  ])('stops boot $boot after $failure rejects, preserving the failure', async ({ boot, failure }) => {
    const originalBoot = serving.bootServing;
    const originalRead = serving.signedGetBytes;
    const originalComplete = serving.complete;
    const deployments: { served: serving.ServedGateway; root: string }[] = [];
    const bootCount = ['A', 'B', 'C', 'D', 'E'].indexOf(boot) + 1;
    const servingError = new Error('serving rejected after an HTTP refusal');
    let expectedError = servingError;
    let refusalStatus: number | undefined;
    let capturing = false;
    vi.spyOn(serving, 'bootServing').mockImplementation(async (args) => {
      const served = await originalBoot(args);
      deployments.push({ served, root: dirname(args[args.indexOf('--credentials-path') + 1]!) });
      return served;
    });
    vi.spyOn(serving, 'signedGetBytes').mockImplementation(async (served, pop, target) => {
      if (deployments.length === bootCount && target === '/v1/deployment-manifest') capturing = true;
      const selected = failure === 'manifest' ? target === '/v1/deployment-manifest' :
        failure === 'receipt' && capturing && target.startsWith('/v1/receipts/');
      if (deployments.length !== bootCount || !selected) return originalRead(served, pop, target);
      // The capture sees an actual HTTP 404, not a fabricated response.
      const response = await originalRead(served, pop, '/v1/receipts/missing-capture');
      refusalStatus = response.status;
      expectedError = new Error(failure === 'manifest'
        ? `manifest read failed for boot ${boot}: 404`
        : `receipt read failed for ${target.slice('/v1/receipts/'.length)}: 404`);
      return response;
    });
    vi.spyOn(serving, 'complete').mockImplementation(async (served, pop) => {
      if (failure !== 'serving') return originalComplete(served, pop);
      const response = await originalComplete(served, { ...pop, record: { id: 'unregistered-cleanup-holder' } });
      refusalStatus = response.status;
      throw servingError;
    });
    try {
      const error: unknown = await runCheckpointDrill().catch((caught: unknown) => caught);
      expect(refusalStatus).toBe(failure === 'serving' ? 401 : 404);
      expect(error).toEqual(expectedError);
      if (failure === 'serving') expect(error).toBe(servingError);
      expect(deployments).toHaveLength(bootCount);
      for (const { served, root } of deployments) {
        expect(await served.reached()).toMatch(/had gone with/u);
        await expect(fetch(`http://127.0.0.1:${String(served.port)}/v1/deployment-manifest`, {
          signal: AbortSignal.timeout(1_000),
        })).rejects.toMatchObject({ cause: { code: 'ECONNREFUSED' } });
        await expect(access(root)).rejects.toMatchObject({ code: 'ENOENT' });
      }
    } finally {
      vi.restoreAllMocks();
      // Red and mutation runs must not strand their intentionally unguarded children.
      for (const { served, root } of deployments) {
        await served.kill();
        await rm(root, { recursive: true, force: true });
      }
    }
  }, DRILL_TIMEOUT);
});

describe('drill cleanup rejection precedence', () => {
  it.each([
    { callback: 'rejects with an Error', rejects: true, error: new Error('capture rejected after child departure') },
    { callback: 'rejects with undefined', rejects: true, error: undefined },
    { callback: 'succeeds', rejects: false, error: undefined },
  ])('preserves precedence when the callback $callback and cleanup rejects', async ({ rejects, error: callbackError }) => {
    const originalBoot = serving.bootServing;
    const originalRead = serving.signedGetBytes;
    const deployments: { served: serving.ServedGateway; root: string }[] = [];
    let receiptReads = 0;
    let cleanupError: unknown;
    let cleanupSettled = false;
    vi.spyOn(serving, 'bootServing').mockImplementation(async (args) => {
      const served = await originalBoot(args);
      deployments.push({ served, root: dirname(args[args.indexOf('--credentials-path') + 1]!) });
      return {
        ...served,
        kill: async () => {
          try {
            await served.kill();
          } catch (error) {
            cleanupError = error;
            throw error;
          } finally {
            cleanupSettled = true;
          }
        },
      };
    });
    vi.spyOn(serving, 'signedGetBytes').mockImplementation(async (served, pop, target) => {
      const response = await originalRead(served, pop, target);
      if (!target.startsWith('/v1/receipts/') || ++receiptReads !== 4) return response;
      expect(response.status).toBe(200);
      // The last capture read can succeed even though its process has since departed.
      const pid = /started as pid ([1-9]\d*) /u.exec(await served.reached());
      expect(pid).not.toBeNull();
      process.kill(Number(pid![1]), 'SIGKILL');
      await expect.poll(() => served.reached(), { timeout: bootBudget(1) }).toContain('of its own accord');
      if (rejects) throw callbackError;
      return response;
    });
    try {
      const outcome = await runCheckpointDrill().then(
        () => ({ ok: true as const }),
        (error: unknown) => ({ ok: false as const, error }),
      );
      expect(cleanupSettled).toBe(true);
      expect(cleanupError).toBeInstanceOf(Error);
      expect(cleanupError).toMatchObject({
        message: expect.stringContaining('exited after it printed its listening line'),
      });
      expect(deployments).toHaveLength(1);
      for (const { served, root } of deployments) {
        expect(await served.reached()).toContain('of its own accord');
        await expect(fetch(`http://127.0.0.1:${String(served.port)}/v1/deployment-manifest`, {
          signal: AbortSignal.timeout(1_000),
        })).rejects.toMatchObject({ cause: { code: 'ECONNREFUSED' } });
        await expect(access(root)).rejects.toMatchObject({ code: 'ENOENT' });
      }
      expect(outcome.ok).toBe(false);
      if (outcome.ok) throw new Error('the drill resolved despite a cleanup rejection');
      expect(outcome.error).toBe(rejects ? callbackError : cleanupError);
    } finally {
      vi.restoreAllMocks();
      // Even red and mutation runs must release the actual child and owned directory.
      for (const { served, root } of deployments) {
        try {
          await served.kill();
        } catch (error) {
          expect(error).toMatchObject({
            message: expect.stringContaining('exited after it printed its listening line'),
          });
        } finally {
          await rm(root, { recursive: true, force: true });
        }
      }
    }
  }, DRILL_TIMEOUT);
});

describe('the drill run', () => {
  it(
    'serves five modeled hours across five boots and reads the sealed heads',
    async () => {
      const result = await drill();
      expect(result.served).toHaveLength(15);
      expect(result.checkpoints.map((each) => each.label)).toEqual(['A', 'B', 'C', 'D', 'E']);
      // The crashed batch has a volume end but no checkpoint.
      const witnessed = result.checkpoints.filter((each) => each.at !== null);
      expect(witnessed).toHaveLength(4);
      expect(new Set(witnessed.map((each) => each.head?.sha256)).size).toBe(4);
      expect(result.checkpoints.at(-1)?.head?.sequence).toBe(14);
      // The stamps this run filed came from the source the operator named, not from the host's own claim.
      expect(result.clock.source).toBe('drill synchronisation');
      expect(result.clock.instants.at(1)! - result.clock.instants.at(0)!).toBe(3_600);
      expect(result.clock.instants.at(4)! - result.clock.instants.at(3)!).toBe(2 * 3_600);
      expect(result.access.lines).toBe(result.served.length * 2 + result.captures.length + 1);
      expect(result.wallTimeMs).toBeGreaterThan(0);
      expect(result.clock.instants.at(-1)! - result.clock.instants[0]!).toBe(5 * 3_600);
      expect(result.arms.map((each) => each.label)).toEqual(DRILL_SCENARIOS.filter((each) => each.group === 'assessment').map((each) => each.label));
      expect(result.legs.map((each) => each.label)).toEqual(DRILL_SCENARIOS.filter((each) => each.group === 'recovery').map((each) => each.label));
      expect(result.receiptRead.status).toBe(200);
      expect(result.access.files.length).toBeGreaterThan(0);
    },
    DRILL_TIMEOUT,
  );

  it('takes each checkpoint from the sealed evidence rather than from the process that wrote it', async () => {
    const result = await drill();
    expect(result.sealedCheckpoints).toHaveLength(5);
    for (const each of result.sealedCheckpoints) {
      // A quiet skip would leave the head-versus-volume check unrun for a whole checkpoint.
      expect(each.sealed.present, `${each.label}: the sealed index stated no checkpoint`).toBe(true);
      expect(each.volume, `${each.label}: the sealed run left no volume head`).not.toBeNull();
      // The index beside the volume never claims more than the receipts on it, whatever else it lags by.
      expect(each.sealed.lastSequence, `${each.label}: the index named a head past the volume`).toBeLessThanOrEqual(each.volume!.sequence);
    }
    expect(result.sealedCheckpoints[0]?.volume?.sequence).toBe(3);
    expect(result.sealedCheckpoints.at(-1)?.sealed.lastSequence).toBe(12);
    expect(result.sealedCheckpoints.at(-1)?.volume?.sequence).toBe(14);
  });
});

describe('the nine assessment scenarios, asked of the live volume', () => {
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
    // A pinned head witnesses only the declared scope, not records appended beyond it.
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
    // The gap is an unwitnessed interval, not missing receipt bytes.
    expect(crash.observed?.sequence).toBe(14);
    expect(kinds(crash)).not.toContain('omitted-record');
    expect(kinds(crash)).not.toContain('suffix-loss');
  });

  it('shows a replayed proof of possession served again by the restarted process', async () => {
    const result = await drill();
    // Restart loses the replay set, so the repeated nonce files an extra receipt.
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
    // A stale index cannot override the readable volume chain.
    expect(restore.observed?.sequence).toBe(3);
  });
});

describe('the pin', () => {
  it('refuses the fixture issuer and accepts the local holder stand-in', async () => {
    const result = await drill();
    const [selfIssued, localHolder] = result.pins;
    expect(selfIssued?.refused, JSON.stringify(selfIssued)).toBe(true);
    expect(selfIssued?.code).toBe('PIN_SELF_ISSUED');
    expect(selfIssued?.signer).toBe(result.fixtureIssuerKeyId);
    expect(localHolder?.refused, JSON.stringify(localHolder)).toBe(false);
    expect(localHolder?.code).toBeNull();
    expect(localHolder?.head).toEqual(result.checkpoints.find((each) => each.label === 'C')?.head ?? null);
    expect(selfIssued?.signatureByThisKey, 'Node crypto verified the fixture self-pin before the guard').toBe(true);
    expect(localHolder?.signatureByThisKey).toBe(true);
    expect(result.issuanceIdentities).toHaveLength(DRILL_BOOT_COUNT);
    expect(result.issuanceIdentities).not.toContain(result.holderKeyId);
    // Separating files does not establish independent operator custody.
    expect(result.volumeListing).not.toContain('head-pin-private.pem');
  });
});

describe('per-boot captures', () => {
  it('retains every binary receipt and manifest with explicit TOFU provenance', async () => {
    const result = await drill();
    expect(result.captureLedger.map((boot) => boot.boot)).toEqual(['A', 'B', 'C', 'D', 'E']);
    expect(result.captureLedger.flatMap((boot) => boot.receipts.map((receipt) => receipt.id))).toEqual(result.served);
    expect(result.pinEvidence.boots.flatMap((boot) => boot.receipts.map((receipt) => receipt.id))).toEqual(result.served);
    for (const boot of result.pinEvidence.boots) {
      expect(boot.authentication).toMatchObject({ authenticated: false, demanded: false });
      expect(boot.authentication.advisory).toContain('trust-on-first-use');
      expect(boot.receipts.every((receipt) => receipt.epoch.ok && receipt.epoch.basis === 'current-epoch')).toBe(true);
    }
  });

  it('refuses omission of the last live boot or one live receipt against the original ledger', async () => {
    const result = await drill();
    const read = (captures: typeof result.captures) => readPinEvidence({ ledger: result.captureLedger, captures, trust: { mode: 'synthetic-tofu' } });
    expect(() => read(result.captures.slice(0, -1))).toThrow(/PIN_EVIDENCE/u);
    expect(() => read(result.captures.map((boot, index) => index === 4 ? { ...boot, receipts: boot.receipts.slice(1) } : boot))).toThrow(/PIN_EVIDENCE/u);
    expect(read(result.captures)).toEqual(result.pinEvidence);
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
