import { describe, expect, it } from 'vitest';
import {
  INTEL_QE_IDENTITY,
  INTEL_TCB_INFO,
  appraiseCollateral,
  collateralCacheKey,
  fetchFromOrigin,
  readSignedCollateral,
  requestUrl,
  type CollateralErrorCode,
  type CollateralOutcome,
  type CollateralTransport,
  type OriginDeclaration,
} from '../src/index.js';
import type { CollateralQuery } from '../src/types.js';
import {
  foreignKey,
  secondsOf,
  signedDocument,
  tcbInfo,
  tcbInfoBody,
  testVendor,
  type TestVendor,
} from './support/collateral-documents.js';

const FMSPC = '00906EA00000';
const LEVEL_DATE = '2026-09-01T00:00:00.000Z';
const NEXT_UPDATE = '2026-10-01T00:00:00.000Z';
const WITHIN = secondsOf('2026-09-15T00:00:00.000Z');
const AFTER = secondsOf('2026-11-15T00:00:00.000Z');
const OBSERVED = secondsOf('2026-09-15T06:00:00.000Z');

const vendor = testVendor();

function query(over: Partial<CollateralQuery> = {}): CollateralQuery {
  return {
    origin: 'intel-tcb-info',
    platform: 'tdx',
    cpuType: FMSPC.toLowerCase(),
    level: { by: 'tcb-date', value: LEVEL_DATE },
    appraisalAt: WITHIN,
    roots: [vendor.rootDer],
    retained: null,
    onAbsent: 'unassessed',
    ...over,
  };
}

function levelDocument(signer: TestVendor = vendor, status = 'OK', fmspc = FMSPC): Uint8Array {
  return signedDocument(
    tcbInfo({
      fmspc,
      issueDate: LEVEL_DATE,
      nextUpdate: NEXT_UPDATE,
      levels: [{ tcbDate: LEVEL_DATE, tcbStatus: status }],
    }),
    signer,
  );
}

/** A document whose payload is bigger than any cap the path declares. */
function paddedDocument(signer: TestVendor = vendor): Uint8Array {
  return signedDocument(
    {
      ...tcbInfo({
        fmspc: FMSPC,
        issueDate: LEVEL_DATE,
        nextUpdate: NEXT_UPDATE,
        levels: [{ tcbDate: LEVEL_DATE, tcbStatus: 'OK' }],
      }),
      padding: 'x'.repeat(90000),
    },
    signer,
  );
}

function serve(bytes: Uint8Array): CollateralTransport {
  return async () => new Response(bytes);
}

function silence(): CollateralTransport {
  return async () => {
    throw new Error('socket closed');
  };
}

function recording(reply: () => Response): { transport: CollateralTransport; sent: { url: string; init: RequestInit }[] } {
  const sent: { url: string; init: RequestInit }[] = [];
  const transport = async (input: string | URL | Request, init: RequestInit = {}) => {
    sent.push({ url: String(input), init });
    return reply();
  };
  return { transport, sent };
}

async function ask(over: Partial<CollateralQuery>, transport: CollateralTransport): Promise<CollateralOutcome> {
  return appraiseCollateral(query(over), { transport, clock: () => OBSERVED });
}

function codeOf(outcome: CollateralOutcome): CollateralErrorCode {
  if ('refusal' in outcome) {
    return outcome.refusal.code;
  }
  throw new Error(`the answer was ${outcome.state}, which carries no refusal`);
}

/** Every failure the declaration names a code for, reached by a call that produces it. */
const failures: readonly { readonly slot: keyof OriginDeclaration['refusals']; readonly outcome: () => Promise<CollateralOutcome> }[] = [
  { slot: 'transport', outcome: () => ask({}, silence()) },
  { slot: 'status', outcome: () => ask({}, async () => new Response('gone', { status: 404 })) },
  { slot: 'oversize', outcome: () => ask({}, serve(paddedDocument())) },
  { slot: 'envelope', outcome: () => ask({}, serve(new TextEncoder().encode('not a jose message'))) },
  { slot: 'window', outcome: () => ask({ appraisalAt: AFTER }, serve(levelDocument())) },
  { slot: 'identity', outcome: () => ask({}, serve(levelDocument(vendor, 'OK', '00A0F0000000'))) },
  {
    slot: 'levels',
    outcome: () => ask({ level: { by: 'tcb-date', value: '2027-01-01T00:00:00.000Z' } }, serve(levelDocument())),
  },
  {
    slot: 'statusUnknown',
    outcome: () => ask({}, serve(levelDocument(vendor, 'ConfigurationAndBIOSUpdateNeeded'))),
  },
  { slot: 'signature', outcome: () => ask({}, serve(levelDocument({ ...vendor, signingKey: foreignKey() }))) },
  { slot: 'anchor', outcome: () => ask({ roots: [] }, serve(levelDocument())) },
];

describe('the declaration of the Intel retrieval path', () => {
  it('answers every failure of this path with the code the declaration names for it', async () => {
    expect(new Set(failures.map((one) => one.slot))).toEqual(new Set(Object.keys(INTEL_TCB_INFO.refusals)));
    for (const one of failures) {
      const outcome = await one.outcome();
      expect(outcome.state, one.slot).not.toBe('current');
      expect(codeOf(outcome), one.slot).toBe(INTEL_TCB_INFO.refusals[one.slot]);
    }
  });

  it('asks the address it spells, from the host it names and nowhere else', () => {
    const address = requestUrl(query(), INTEL_TCB_INFO);
    expect(typeof address === 'string' ? address : address.refusal.detail).toBe(
      `https://${INTEL_TCB_INFO.host}/tdx/certification/v4/tcb?fmspc=${FMSPC.toLowerCase()}`,
    );
    const spelled: OriginDeclaration = {
      ...INTEL_TCB_INFO,
      platformPath: () => '/tdx/certification/v9',
      cpuTypeMember: 'pcpu',
    };
    expect(requestUrl(query(), spelled)).toBe(`https://${INTEL_TCB_INFO.host}/tdx/certification/v9/tcb?pcpu=${FMSPC.toLowerCase()}`);
    const qe: OriginDeclaration = { ...INTEL_QE_IDENTITY, documentPath: 'qe/self' };
    expect(requestUrl(query({ origin: 'intel-qe-identity', cpuType: null, level: null }), qe)).toBe(
      `https://${INTEL_QE_IDENTITY.host}/tdx/certification/v4/qe/self`,
    );
  });

  it('refuses to ask another host at all, before a transport sees the address', async () => {
    const { transport, sent } = recording(() => new Response(levelDocument()));
    const elsewhere: OriginDeclaration = { ...INTEL_TCB_INFO, host: 'cache.example.com' };
    const address = requestUrl(query(), INTEL_TCB_INFO);
    if (typeof address !== 'string') throw new Error('the query was refused before an address');
    const outcome = await fetchFromOrigin(address, elsewhere, { transport });
    if (!('refusal' in outcome)) throw new Error('a foreign host was asked anyway');
    expect(outcome.refusal.code).toBe(elsewhere.refusals.envelope);
    expect(sent).toHaveLength(0);
  });

  it('sends the media type it states and nothing that identifies the caller', async () => {
    const { transport, sent } = recording(() => new Response(levelDocument()));
    const other: OriginDeclaration = { ...INTEL_TCB_INFO, signature: { ...INTEL_TCB_INFO.signature, mediaType: 'application/json' } };
    const address = requestUrl(query(), INTEL_TCB_INFO);
    if (typeof address !== 'string') throw new Error('the query was refused before an address');
    await fetchFromOrigin(address, other, { transport });
    const init = sent[0]?.init as RequestInit;
    const headers = new Headers(init.headers);
    expect(headers.get('accept')).toBe('application/json');
    expect([...headers.keys()]).toEqual(['accept']);
    expect(init.method).toBe('GET');
    expect(init.redirect).toBe('error');
  });

  it('waits the time it states and reads no more bytes than its cap', async () => {
    const address = requestUrl(query(), INTEL_TCB_INFO);
    if (typeof address !== 'string') throw new Error('the query was refused before an address');
    const patient: OriginDeclaration = { ...INTEL_TCB_INFO, timeoutMs: 25 };
    const waiting = await fetchFromOrigin(address, patient, {
      transport: (_input, init = {}) =>
        new Promise<Response>((_resolve, reject) => {
          const signal = init.signal;
          if (signal === undefined || signal === null) {
            reject(new Error('no signal was handed to wait on'));
            return;
          }
          signal.addEventListener('abort', () => reject(new Error('waiting was cut short')));
        }),
    });
    if (!('refusal' in waiting)) throw new Error('the declared wait was not kept');
    expect(waiting.refusal.code).toBe(patient.refusals.transport);
    expect(waiting.refusal.detail).toContain('25ms');

    const small: OriginDeclaration = { ...INTEL_TCB_INFO, maxResponseBytes: 64 };
    const oversize = await fetchFromOrigin(address, small, { transport: serve(levelDocument()) });
    if (!('refusal' in oversize)) throw new Error('an answer over the stated cap was kept');
    expect(oversize.refusal.code).toBe(small.refusals.oversize);
    expect(oversize.refusal.detail).toContain('64');
  });

  it('reads exactly the statuses it lists, and refuses the word it lists nowhere', async () => {
    for (const trusted of INTEL_TCB_INFO.status.trusted) {
      const outcome = await ask({}, serve(levelDocument(vendor, trusted)));
      expect(outcome.state, trusted).toBe('current');
      expect(outcome.collateral?.classification.readAs, trusted).toBe('trusted');
    }
    for (const revoked of INTEL_TCB_INFO.status.revoked) {
      const outcome = await ask({}, serve(levelDocument(vendor, revoked)));
      expect(outcome.state, revoked).toBe('revoked');
      expect(outcome.collateral?.classification.readAs, revoked).toBe('revoked');
      if ('refusal' in outcome) {
        expect(outcome.refusal.code, revoked).toBe('COLLATERAL_REVOKED_BY_VENDOR');
      }
    }
    const unlisted = await ask({}, serve(levelDocument(vendor, 'OutOfDateConfiguration')));
    expect(codeOf(unlisted)).toBe(INTEL_TCB_INFO.refusals.statusUnknown);
    expect(INTEL_TCB_INFO.status.trusted).toEqual(['OK']);
  });

  it('takes the member it names for the document rather than one it remembers', () => {
    const nested = signedDocument({ body: tcbInfoBody({
      fmspc: FMSPC,
      issueDate: LEVEL_DATE,
      nextUpdate: NEXT_UPDATE,
      levels: [{ tcbDate: LEVEL_DATE, tcbStatus: 'OK' }],
    }) }, vendor);
    const declared: OriginDeclaration = { ...INTEL_TCB_INFO, window: { ...INTEL_TCB_INFO.window, documentMember: 'body' } };
    const reading = { query: query(), declaration: declared, appraisalAt: WITHIN };
    const believed = readSignedCollateral(nested, reading);
    if ('refusal' in believed) throw new Error(`the declared member was not read: ${believed.refusal.detail}`);
    expect(believed.read.vendorStatus).toBe('OK');
    expect(believed.read.validUntil).toBe(secondsOf(NEXT_UPDATE));

    const asUsual = readSignedCollateral(nested, { query: query(), declaration: INTEL_TCB_INFO, appraisalAt: WITHIN });
    if (!('refusal' in asUsual)) throw new Error('a document outside the declared member was read anyway');
    expect(asUsual.refusal.code).toBe(INTEL_TCB_INFO.refusals.envelope);
  });

  it('keys a kept blob by the members it names, and by no instant', () => {
    expect(collateralCacheKey(query(), INTEL_TCB_INFO)).toBe(
      `origin=intel-tcb-info|platform=tdx|cpuType=${FMSPC.toLowerCase()}|level=tcb-date=${LEVEL_DATE}`,
    );
    expect(collateralCacheKey(query({ origin: 'intel-qe-identity', cpuType: null, level: null }), INTEL_QE_IDENTITY)).toBe(
      'origin=intel-qe-identity|platform=tdx',
    );
    const narrower: OriginDeclaration = {
      ...INTEL_TCB_INFO,
      cache: { ...INTEL_TCB_INFO.cache, keyMembers: ['origin', 'platform', 'cpuType'] },
    };
    expect(collateralCacheKey(query(), narrower)).toBe(`origin=intel-tcb-info|platform=tdx|cpuType=${FMSPC.toLowerCase()}`);
    expect(collateralCacheKey(query({ appraisalAt: AFTER }), INTEL_TCB_INFO)).toBe(collateralCacheKey(query(), INTEL_TCB_INFO));
    expect(INTEL_TCB_INFO.cache.keyMembers).toContain('level');
    expect(INTEL_QE_IDENTITY.cache.keyMembers).toEqual(['origin', 'platform']);
  });

  it('holds the cache rule it states: the vendor expires the record, and a kept blob never answers now', async () => {
    const bytes = levelDocument();
    const live = await ask({}, serve(bytes));
    expect(live.state).toBe('current');
    expect(live.claim?.retainUntil).toBe(secondsOf(NEXT_UPDATE));
    expect(live.claim?.observedAt).toBe(OBSERVED);

    const kept = await ask({ retained: { bytes, observedAt: OBSERVED } }, silence());
    expect(kept.state).toBe('stale');
    expect(kept.claim?.reach).toBe('historical-knowledge');
    expect(kept.claim?.observedAt).toBeNull();
    expect(kept.claim?.retainUntil).toBe(secondsOf(NEXT_UPDATE));
    expect(INTEL_TCB_INFO.cache.answersCurrentQuestions).toBe(false);
    expect(INTEL_TCB_INFO.cache.retainUntil).toBe('vendor-next-update');
    expect(INTEL_QE_IDENTITY.cache.answersCurrentQuestions).toBe(false);
  });

  it('states one envelope, one suite and one certificate member for both documents', () => {
    for (const declaration of [INTEL_TCB_INFO, INTEL_QE_IDENTITY]) {
      expect(declaration.signature.envelope).toBe('jws-compact');
      expect(declaration.signature.algorithm).toBe('ES256');
      expect(declaration.signature.certificateMember).toBe('x5c');
      expect(declaration.signature.mediaType).toBe('application/jose');
      expect(declaration.window.signedMember).toBe('issueDate');
      expect(declaration.window.nextUpdateMember).toBe('nextUpdate');
      expect(declaration.identity.statusMember).toBe('tcbStatus');
      expect(declaration.maxResponseBytes).toBe(65536);
      expect(declaration.timeoutMs).toBe(5000);
    }
    expect(INTEL_TCB_INFO.identity.levelsMember).toBe('tcb');
    expect(INTEL_TCB_INFO.window.documentMember).toBe('tcbInfo');
    expect(INTEL_QE_IDENTITY.identity.levelsMember).toBeNull();
    expect(INTEL_QE_IDENTITY.window.documentMember).toBeNull();
  });
});
