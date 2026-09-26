import { describe, expect, it } from 'vitest';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  CollateralError,
  appraiseCollateral,
  type CollateralOutcome,
  type CollateralRefusal,
  type CollateralTransport,
} from '../src/index.js';
import type { CollateralQuery } from '../src/types.js';
import { qeIdentity, secondsOf, signedDocument, tcbInfo, testVendor, type TestVendor } from './support/collateral-documents.js';

const FMSPC = '00906EA00000';
const CPU_TYPE = FMSPC.toLowerCase();
const LEVEL_DATE = '2026-09-01T00:00:00.000Z';
const NEXT_UPDATE = '2026-10-01T00:00:00.000Z';
const WITHIN = secondsOf('2026-09-15T00:00:00.000Z');
const AFTER = secondsOf('2026-11-15T00:00:00.000Z');
const OBSERVED = secondsOf('2026-09-15T06:00:00.000Z');

const vendor = testVendor();

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function query(over: Partial<CollateralQuery> = {}): CollateralQuery {
  return {
    origin: 'intel-tcb-info',
    platform: 'tdx',
    cpuType: CPU_TYPE,
    level: { by: 'tcb-date', value: LEVEL_DATE },
    appraisalAt: WITHIN,
    roots: [vendor.rootDer],
    retained: null,
    onAbsent: 'unassessed',
    ...over,
  };
}

function levelDocument(status = 'OK', signer: TestVendor = vendor): Uint8Array {
  return signedDocument(
    tcbInfo({
      fmspc: FMSPC,
      issueDate: LEVEL_DATE,
      nextUpdate: NEXT_UPDATE,
      levels: [{ tcbDate: LEVEL_DATE, tcbStatus: status }],
    }),
    signer,
  );
}

function identityDocument(status = 'OK'): Uint8Array {
  return signedDocument(qeIdentity({ issueDate: LEVEL_DATE, nextUpdate: NEXT_UPDATE, tcbStatus: status }), vendor);
}

/** A transport that answers with these bytes, and keeps the addresses it was asked. */
function serve(bytes: Uint8Array): { transport: CollateralTransport; asked: string[] } {
  const asked: string[] = [];
  const transport = async (input: string | URL | Request, _init: RequestInit = {}) => {
    asked.push(String(input));
    return new Response(bytes);
  };
  return { transport, asked };
}

/** The origin answering nothing, which is the only way a test here can be without a network. */
function silence(): CollateralTransport {
  return async () => {
    throw new Error('socket closed');
  };
}

function refusalOf(outcome: CollateralOutcome): CollateralRefusal {
  if ('refusal' in outcome) {
    return outcome.refusal;
  }
  throw new Error(`the answer was ${outcome.state}, which carries no refusal`);
}

async function ask(over: Partial<CollateralQuery> = {}, transport: CollateralTransport = silence()): Promise<CollateralOutcome> {
  return appraiseCollateral(query(over), { transport, clock: () => OBSERVED });
}

describe('the five answers', () => {
  it('says current only for bytes this run watched arrive inside the window the vendor signed', async () => {
    const bytes = levelDocument();
    const { transport, asked } = serve(bytes);
    const outcome = await appraiseCollateral(query(), { transport, clock: () => OBSERVED });
    expect(outcome.state).toBe('current');
    if (outcome.state !== 'current') throw new Error('unreachable');
    expect(asked).toHaveLength(1);
    expect(outcome.claim.reach).toBe('current-knowledge');
    expect(outcome.claim.observedAt).toBe(OBSERVED);
    expect(outcome.claim.appraisalAt).toBe(WITHIN);
    expect(outcome.claim.retainUntil).toBe(secondsOf(NEXT_UPDATE));
    expect(outcome.claim.cacheKey).toBe(`origin=intel-tcb-info|platform=tdx|cpuType=${CPU_TYPE}|level=tcb-date=${LEVEL_DATE}`);
    expect(outcome.collateral.classification.readAs).toBe('trusted');
    expect(outcome.collateral.digest).toBe(hex(sha256(bytes)));
    expect(outcome.collateral.anchorDigest).toBe(vendor.rootDigest);
    expect('refusal' in outcome).toBe(false);
  });

  it('says stale when the window the vendor signed does not reach the moment asked about', async () => {
    const { transport } = serve(levelDocument());
    const outcome = await appraiseCollateral(query({ appraisalAt: AFTER }), { transport, clock: () => OBSERVED });
    expect(outcome.state).toBe('stale');
    expect(refusalOf(outcome).code).toBe('COLLATERAL_WINDOW_CLOSED');
    expect(outcome.claim?.reach).toBe('historical-knowledge');
    expect(outcome.collateral?.classification.readAs).toBe('trusted');
  });

  it('refuses to read a current answer out of an archived one, and reads the same bytes as current live', async () => {
    const bytes = levelDocument();
    const archived = await ask({ retained: { bytes, observedAt: OBSERVED } });
    expect(archived.state).toBe('stale');
    expect(refusalOf(archived).code).toBe('COLLATERAL_NOT_OBSERVED');
    expect(archived.claim?.reach).toBe('historical-knowledge');
    expect(archived.claim?.observedAt).toBeNull();
    expect(archived.collateral?.digest).toBe(hex(sha256(bytes)));

    const { transport, asked } = serve(bytes);
    const live = await appraiseCollateral(query(), { transport, clock: () => OBSERVED });
    expect(live.state).toBe('current');
    expect(live.claim?.reach).toBe('current-knowledge');
    expect(asked).toHaveLength(1);
  });

  it('says revoked when the vendor no longer stands behind the level, and shows no softening of it', async () => {
    const { transport } = serve(levelDocument('OutOfDate'));
    const outcome = await appraiseCollateral(query(), { transport, clock: () => OBSERVED });
    expect(outcome.state).toBe('revoked');
    expect(refusalOf(outcome).code).toBe('COLLATERAL_REVOKED_BY_VENDOR');
    expect(outcome.collateral?.classification.readAs).toBe('revoked');
    expect(outcome.collateral?.blobs).toHaveLength(3);
    expect(outcome.claim?.reach).toBe('current-knowledge');
  });

  it('outranks a closed window with a revoked statement, and keeps the archived reach it has', async () => {
    const archived = await ask({
      appraisalAt: AFTER,
      retained: { bytes: levelDocument('Revoked'), observedAt: OBSERVED },
    });
    expect(archived.state).toBe('revoked');
    expect(refusalOf(archived).code).toBe('COLLATERAL_REVOKED_BY_VENDOR');
    expect(archived.claim?.reach).toBe('historical-knowledge');
  });

  it('refuses a status the declaration names no rule for instead of sorting it into the nearer one', async () => {
    const { transport } = serve(levelDocument('ConfigurationAndBIOSUpdateNeeded'));
    const outcome = await appraiseCollateral(query(), { transport, clock: () => OBSERVED });
    expect(outcome.state).toBe('unavailable');
    expect(refusalOf(outcome).code).toBe('COLLATERAL_STATUS_UNSUPPORTED');
    expect(refusalOf(outcome).detail).toContain('ConfigurationAndBIOSUpdateNeeded');
    expect(outcome.collateral).toBeNull();
  });

  it('says unavailable when the origin answers nothing, and carries nothing out of it', async () => {
    const outcome = await ask();
    expect(outcome.state).toBe('unavailable');
    expect(refusalOf(outcome).code).toBe('COLLATERAL_ORIGIN_UNREACHABLE');
    expect(refusalOf(outcome).verdict).toBe('retryable');
    expect(outcome.collateral).toBeNull();
    expect(outcome.claim).toBeNull();
  });

  it('says missing context when the question itself cannot be answered, and names the field', async () => {
    const cases: readonly { readonly over: Partial<CollateralQuery>; readonly code: string; readonly field: string }[] = [
      { over: { roots: [] }, code: 'COLLATERAL_ANCHOR_NOT_PINNED', field: 'roots' },
      { over: { appraisalAt: null }, code: 'COLLATERAL_INPUT_MISSING', field: 'appraisalAt' },
      { over: { level: null }, code: 'COLLATERAL_INPUT_MISSING', field: 'level' },
      { over: { cpuType: null }, code: 'COLLATERAL_INPUT_MISSING', field: 'cpuType' },
      {
        over: { retained: { bytes: new Uint8Array(0), observedAt: OBSERVED } },
        code: 'COLLATERAL_INPUT_MISSING',
        field: 'retained.bytes',
      },
      { over: { retained: { bytes: levelDocument(), observedAt: null } }, code: 'COLLATERAL_INPUT_MISSING', field: 'retained.observedAt' },
    ];
    for (const one of cases) {
      const outcome = await ask(one.over);
      expect(outcome.state, JSON.stringify(one.over)).toBe('missing-context');
      expect(refusalOf(outcome).code, one.field).toBe(one.code);
      expect(refusalOf(outcome).missing, one.field).toEqual([one.field]);
    }
  });

  it('answers an origin it does not read with the name that was asked, and never with a pass', async () => {
    const outcome = await ask({ origin: 'amd-kds' });
    expect(outcome.state).toBe('unavailable');
    expect(refusalOf(outcome).code).toBe('COLLATERAL_ORIGIN_UNSUPPORTED');
    expect(refusalOf(outcome).missing).toEqual(['origin']);
  });

  it('carries the QE identity to current with no level and no identity in its key', async () => {
    const { transport } = serve(identityDocument());
    const outcome = await appraiseCollateral(
      query({ origin: 'intel-qe-identity', cpuType: null, level: null }),
      { transport, clock: () => OBSERVED },
    );
    if (outcome.state !== 'current') {
      throw new Error(`the QE identity answered ${outcome.state}`);
    }
    expect(outcome.claim.cacheKey).toBe('origin=intel-qe-identity|platform=tdx');
    expect(outcome.collateral.declared.cpuType).toBeNull();
    expect(outcome.collateral.declared.vendorStatus).toBe('OK');
  });
});

describe('what an absent answer costs the caller', () => {
  it('throws under a policy that requires the collateral, naming the refusal it would otherwise return', async () => {
    const required = ask({ onAbsent: 'refuse' });
    await expect(required).rejects.toBeInstanceOf(CollateralError);
    const failure = await ask({ onAbsent: 'refuse' }).catch((error: unknown) => error);
    if (failure instanceof CollateralError) {
      expect(failure.code).toBe('COLLATERAL_ORIGIN_UNREACHABLE');
      expect(failure.refusal.missing).toEqual([]);
    } else {
      throw new Error('a required answer came back instead of throwing');
    }
  });

  it('throws for a question missing its root under one policy and reports it unassessed under the other', async () => {
    const required = await ask({ onAbsent: 'refuse', roots: [] }).catch((error: unknown) => error);
    if (required instanceof CollateralError) {
      expect(required.code).toBe('COLLATERAL_ANCHOR_NOT_PINNED');
    } else {
      throw new Error('a required root was answered instead of refused');
    }
    const reported = await ask({ roots: [] });
    expect(reported.state).toBe('missing-context');
    expect(reported.collateral).toBeNull();
  });

  it('does not throw for a document that is merely old or revoked, because it did answer', async () => {
    const closed = serve(levelDocument());
    const stale = await appraiseCollateral(
      query({ onAbsent: 'refuse', appraisalAt: AFTER }),
      { transport: closed.transport, clock: () => OBSERVED },
    );
    expect(stale.state).toBe('stale');
    const outOfDate = serve(levelDocument('OutOfDate'));
    const revoked = await appraiseCollateral(
      query({ onAbsent: 'refuse' }),
      { transport: outOfDate.transport, clock: () => OBSERVED },
    );
    expect(revoked.state).toBe('revoked');
  });

  it('hands no verdict to a caller that asks with nothing to believe', async () => {
    for (const over of [{ roots: [] }, { appraisalAt: null }, { level: null }, { cpuType: null }]) {
      const outcome = await ask(over);
      expect(outcome.collateral).toBeNull();
      expect(outcome.claim).toBeNull();
      expect(outcome.state).not.toBe('current');
    }
  });

  it('keeps a chain that reaches no pin out of every passing answer, and refuses it outright when required', async () => {
    const stranger = testVendor({ rootName: 'Unrelated Root', issuerName: 'Unrelated CA' });
    const { transport } = serve(levelDocument('OK', stranger));
    const reported = await appraiseCollateral(query(), { transport, clock: () => OBSERVED });
    expect(reported.state).toBe('unavailable');
    expect(reported.collateral).toBeNull();
    expect(reported.claim).toBeNull();
    const required = appraiseCollateral(query({ onAbsent: 'refuse' }), { transport, clock: () => OBSERVED });
    await expect(required).rejects.toBeInstanceOf(CollateralError);
  });
});
