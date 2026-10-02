import { describe, expect, it } from 'vitest';
import { sha256 } from '@noble/hashes/sha2.js';
import { qeIdentity, secondsOf, signedDocument, tcbInfo, testVendor, type TestVendor } from '@ashaveri/fixtures';
import {
  CollateralError,
  appraiseCarriedCollateral,
  appraiseCollateral,
  type CollateralOutcome,
  type CollateralQuery,
  type CollateralRefusal,
  type CollateralTransport,
} from '../src/index.js';

const FMSPC = '00906EA00000';
const CPU_TYPE = FMSPC.toLowerCase();
const LEVEL_DATE = '2026-09-01T00:00:00Z';
const NEXT_UPDATE = '2026-10-01T00:00:00Z';
const WITHIN = secondsOf('2026-09-15T00:00:00Z');
const AFTER = secondsOf('2026-11-15T00:00:00Z');
const OBSERVED = secondsOf('2026-09-15T06:00:00Z');

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

function levelDocument(status = 'UpToDate', signer: TestVendor = vendor): Uint8Array {
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

function identityDocument(status = 'UpToDate'): Uint8Array {
  return signedDocument(
    qeIdentity({
      issueDate: LEVEL_DATE,
      nextUpdate: NEXT_UPDATE,
      levels: [{ isvSvn: 0, tcbDate: LEVEL_DATE, tcbStatus: status }],
    }),
    vendor,
  );
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
    const archived = await ask({ retained: { bytes, chain: null, chainSha256: null, observedAt: OBSERVED } });
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
      retained: { bytes: levelDocument('Revoked'), chain: null, chainSha256: null, observedAt: OBSERVED },
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
        over: { retained: { bytes: new Uint8Array(0), chain: null, chainSha256: null, observedAt: OBSERVED } },
        code: 'COLLATERAL_INPUT_MISSING',
        field: 'retained.bytes',
      },
      {
        over: { retained: { bytes: levelDocument(), chain: null, chainSha256: null, observedAt: null } },
        code: 'COLLATERAL_INPUT_MISSING',
        field: 'retained.observedAt',
      },
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

  /**
   * The QE Identity body states its window and its statuses inside `enclaveIdentity`, and it states one
   * status per rung of `tcbLevels` rather than one for the document, so the rung is part of what a kept blob
   * answers and part of the key it belongs under.
   */
  it('carries the QE identity to current at the rung it states, and names no identity in its key', async () => {
    const { transport } = serve(identityDocument());
    const outcome = await appraiseCollateral(
      query({ origin: 'intel-qe-identity', cpuType: null }),
      { transport, clock: () => OBSERVED },
    );
    if (outcome.state !== 'current') {
      throw new Error(`the QE identity answered ${outcome.state}: ${'refusal' in outcome ? outcome.refusal.detail : ''}`);
    }
    expect(outcome.claim.cacheKey).toBe(`origin=intel-qe-identity|platform=tdx|level=tcb-date=${LEVEL_DATE}`);
    expect(outcome.collateral.declared.cpuType).toBeNull();
    expect(outcome.collateral.declared.vendorStatus).toBe('UpToDate');
  });

  it('refuses a QE identity question that names no rung, because the vendor states one status per rung', async () => {
    const { transport } = serve(identityDocument());
    const outcome = await appraiseCollateral(
      query({ origin: 'intel-qe-identity', cpuType: null, level: null }),
      { transport, clock: () => OBSERVED },
    );
    expect(outcome.state).toBe('missing-context');
    expect(refusalOf(outcome).missing).toEqual(['level']);
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
    const { transport } = serve(levelDocument('UpToDate', stranger));
    const reported = await appraiseCollateral(query(), { transport, clock: () => OBSERVED });
    expect(reported.state).toBe('unavailable');
    expect(reported.collateral).toBeNull();
    expect(reported.claim).toBeNull();
    const required = appraiseCollateral(query({ onAbsent: 'refuse' }), { transport, clock: () => OBSERVED });
    await expect(required).rejects.toBeInstanceOf(CollateralError);
  });
});

/**
 * Material that arrived inside a sealed container rather than from an origin, and the stamp question it settles.
 *
 * A container states no observation instant because nothing inside one watched an origin answer, so the instant
 * a caller hands is the one the record holding the material states: the moment a sealed receipt was chained at.
 * What that number buys is a read document, established under the root the caller pinned, and what it can never
 * buy is `current`, which is the reach a run makes by asking. The window the vendor signed is left where a
 * reader can weigh it against the instant it asks about, and these cases hold that apart from the code a carried
 * answer arrives with.
 */
describe('material that arrived inside a container', () => {
  /** An instant a sealed record could state: inside the window the vendor signed, and before this run. */
  const HELD_AT = secondsOf('2026-09-10T00:00:00Z');

  /** The same question with its material stated outside the query, which is where a carried appraisal states it. */
  function question(over: Partial<CollateralQuery> = {}): Omit<CollateralQuery, 'retained'> {
    const { retained: _notFromAStore, ...rest } = query(over);
    return rest;
  }

  it('weighs carried bytes under the root the caller pinned and asks the origin nothing', async () => {
    const bytes = levelDocument();
    const { transport, asked } = serve(bytes);
    const outcome = await appraiseCarriedCollateral(question(), { bytes, chain: null, chainSha256: null, heldAt: HELD_AT }, { transport, clock: () => OBSERVED });
    expect(asked, 'a carried appraisal asked the origin something').toEqual([]);
    expect(outcome.state).toBe('stale');
    // The bytes weighed are the bytes handed, and the anchor named is the pin the caller holds: a reader that
    // resolved a digest out of a container can see that the answer is about those exact bytes and no others.
    expect(outcome.collateral?.digest).toBe(hex(sha256(bytes)));
    expect(outcome.collateral?.anchorDigest).toBe(vendor.rootDigest);
    expect(outcome.collateral?.classification.window).toEqual({ from: secondsOf(LEVEL_DATE), until: secondsOf(NEXT_UPDATE) });
    expect(outcome.claim?.reach).toBe('historical-knowledge');
    expect(outcome.claim?.appraisalAt).toBe(WITHIN);
    expect(outcome.claim?.observedAt, 'the claim reports an observation this run never made').toBeNull();
    expect(refusalOf(outcome).code).toBe('COLLATERAL_NOT_OBSERVED');
    // The stamp's one visible effect: the instant the record states, in the sentence about bytes nobody fetched.
    expect(refusalOf(outcome).detail).toContain(new Date(HELD_AT * 1000).toISOString());
  });

  it('leaves the current answer to the run that asks the origin, whichever instant it hands', async () => {
    const bytes = levelDocument();
    const carried = await appraiseCarriedCollateral(
      question({ appraisalAt: HELD_AT }),
      { bytes, chain: null, chainSha256: null, heldAt: HELD_AT },
      { transport: silence() },
    );
    expect(carried.state).toBe('stale');
    expect(carried.claim?.reach).toBe('historical-knowledge');
    const { transport } = serve(bytes);
    const live = await appraiseCollateral(query({ appraisalAt: HELD_AT }), { transport, clock: () => OBSERVED });
    expect(live.state).toBe('current');
    expect(live.claim?.reach).toBe('current-knowledge');
  });

  it('keeps what the window check settled in the figures, because a carried run never asked', async () => {
    const outcome = await appraiseCarriedCollateral(
      question({ appraisalAt: AFTER }),
      { bytes: levelDocument(), chain: null, chainSha256: null, heldAt: HELD_AT },
      { transport: silence() },
    );
    expect(outcome.state).toBe('stale');
    // The vendor's window had closed on the moment asked and the answer still names the observation rather than
    // the window, because the window refusal is what a run that watched the document arrive reports. A reader
    // weighing the context one appraisal ran in reads the pair below, and no stamp moves either of them.
    expect(refusalOf(outcome).code).toBe('COLLATERAL_NOT_OBSERVED');
    expect(outcome.claim?.appraisalAt).toBe(AFTER);
    expect(outcome.collateral?.classification.window.until).toBeLessThanOrEqual(AFTER);
  });

  it('reads a vendor revocation out of carried bytes, because the statement does not depend on how they arrived', async () => {
    const outcome = await appraiseCarriedCollateral(
      question(),
      { bytes: levelDocument('Revoked'), chain: null, chainSha256: null, heldAt: HELD_AT },
      { transport: silence() },
    );
    expect(outcome.state).toBe('revoked');
    expect(refusalOf(outcome).code).toBe('COLLATERAL_REVOKED_BY_VENDOR');
    expect(outcome.collateral?.classification.readAs).toBe('revoked');
    expect(outcome.claim?.reach).toBe('historical-knowledge');
  });

  it('refuses a chain that reaches no root the caller pinned, and hands no bytes back from it', async () => {
    const stranger = testVendor({ rootName: 'Unrelated Root', issuerName: 'Unrelated CA' });
    const outcome = await appraiseCarriedCollateral(
      question(),
      { bytes: levelDocument('UpToDate', stranger), chain: null, chainSha256: null, heldAt: HELD_AT },
      { transport: silence() },
    );
    expect(outcome.state).toBe('unavailable');
    expect(refusalOf(outcome).code).toBe('COLLATERAL_ANCHOR_NOT_PINNED');
    expect(outcome.collateral).toBeNull();
    expect(outcome.claim).toBeNull();
  });

  it('refuses bytes that are not a document, and bytes that are none at all, at the position that names them', async () => {
    const unreadable = await appraiseCarriedCollateral(
      question(),
      { bytes: new TextEncoder().encode('not a document at all'), chain: null, chainSha256: null, heldAt: HELD_AT },
      { transport: silence() },
    );
    expect(unreadable.state).toBe('unavailable');
    expect(refusalOf(unreadable).code).toBe('COLLATERAL_BLOB_UNREADABLE');
    const empty = await appraiseCarriedCollateral(
      question(),
      { bytes: new Uint8Array(0), chain: null, chainSha256: null, heldAt: HELD_AT },
      { transport: silence() },
    );
    expect(empty.state).toBe('missing-context');
    expect(refusalOf(empty).code).toBe('COLLATERAL_INPUT_MISSING');
    expect(refusalOf(empty).missing).toEqual(['retained.bytes']);
  });

  it('throws for carried material a policy requires and this run cannot weigh', async () => {
    const stranger = testVendor({ rootName: 'Other Root', issuerName: 'Other CA' });
    const required = appraiseCarriedCollateral(
      question({ onAbsent: 'refuse' }),
      { bytes: levelDocument('UpToDate', stranger), chain: null, chainSha256: null, heldAt: HELD_AT },
      { transport: silence() },
    );
    await expect(required).rejects.toBeInstanceOf(CollateralError);
    const failure = await required.catch((error: unknown) => error);
    if (failure instanceof CollateralError) {
      expect(failure.code).toBe('COLLATERAL_ANCHOR_NOT_PINNED');
    } else {
      throw new Error('required carried material was answered instead of refused');
    }
  });
});
