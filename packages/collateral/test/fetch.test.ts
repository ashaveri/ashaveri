import { describe, expect, it } from 'vitest';
import {
  INTEL_QE_IDENTITY,
  INTEL_TCB_INFO,
  collateralCacheKey,
  declarationFor,
  fetchFromOrigin,
  requestUrl,
  type OriginDeclaration,
} from '../src/index.js';
import type { CollateralQuery } from '../src/types.js';

const CPU_TYPE = '00906ea00000';

function query(over: Partial<CollateralQuery> = {}): CollateralQuery {
  return {
    origin: 'intel-tcb-info',
    platform: 'tdx',
    cpuType: CPU_TYPE,
    level: { by: 'tcb-date', value: '2026-09-01T00:00:00Z' },
    appraisalAt: 1790000000,
    roots: [new Uint8Array([1])],
    retained: null,
    onAbsent: 'unassessed',
    ...over,
  };
}

function url(over: Partial<CollateralQuery> = {}): string {
  const asked = requestUrl(query(over), INTEL_TCB_INFO);
  if (typeof asked === 'string') {
    return asked;
  }
  throw new Error(`the query was refused before a URL: ${asked.refusal.detail}`);
}

/** A transport that answers whatever the test needs answered, and keeps what it was asked with. */
function recorder(reply: (init: RequestInit) => Response | Promise<Response>) {
  const seen: { url: string; init: RequestInit }[] = [];
  const transport = async (input: string | URL | Request, init: RequestInit = {}) => {
    seen.push({ url: String(input), init });
    return reply(init);
  };
  return { transport, seen };
}

describe('the Intel retrieval path', () => {
  it('asks the declared address for the CPU type, in lower case hex', () => {
    expect(url()).toBe(`https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=${CPU_TYPE}`);
    expect(requestUrl(query({ cpuType: '00A0F0000000' }), INTEL_TCB_INFO)).toBe(
      'https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=00a0f0000000',
    );
  });

  it('asks the QE identity address with no identity in it', () => {
    expect(requestUrl(query({ origin: 'intel-qe-identity', cpuType: null, level: null }), INTEL_QE_IDENTITY)).toBe(
      'https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity',
    );
  });

  it('refuses a CPU type that cannot be an address, and names the field', () => {
    const asked = requestUrl(query({ cpuType: null }), INTEL_TCB_INFO);
    if (typeof asked !== 'string') {
      expect(asked.refusal.code).toBe('COLLATERAL_INPUT_MISSING');
      expect(asked.refusal.missing).toEqual(['cpuType']);
    } else {
      throw new Error('a query with no CPU type reached a URL');
    }
    const broken = requestUrl(query({ cpuType: 'not-a-fmspc' }), INTEL_TCB_INFO);
    if (typeof broken !== 'string') {
      expect(broken.refusal.missing).toEqual(['cpuType']);
    } else {
      throw new Error('a malformed CPU type reached an address');
    }
  });

  it('refuses an origin it does not read instead of guessing at one', () => {
    for (const origin of ['intel-pck-crl', 'amd-kds', 'nvidia-rim', 'ocsp'] as const) {
      const asked = declarationFor(origin);
      if ('refusal' in asked) {
        expect(asked.refusal.code, origin).toBe('COLLATERAL_ORIGIN_UNSUPPORTED');
        expect(asked.refusal.missing, origin).toEqual(['origin']);
      } else {
        throw new Error(`${origin} is served, which this package does not do`);
      }
    }
  });

  it('sends no credential and asks for the declared media type', async () => {
    const { transport, seen } = recorder(() => new Response('bytes'));
    const outcome = await fetchFromOrigin(url(), INTEL_TCB_INFO, { transport, clock: () => 1790000000 });
    expect('fetched' in outcome).toBe(true);
    const init = seen[0]?.init as RequestInit;
    const headers = new Headers(init.headers);
    expect(headers.get('accept')).toBe('application/jose');
    for (const forbidden of ['authorization', 'cookie', 'x-api-key', 'user-agent']) {
      expect(headers.has(forbidden), forbidden).toBe(false);
    }
    expect(init.method).toBe('GET');
    expect(init.redirect).toBe('error');
  });

  it('stamps the answer with the clock it was given, at the second the bytes landed', async () => {
    let clock = 1790000000;
    const { transport } = recorder(async () => {
      clock = 1790000007;
      return new Response('bytes');
    });
    const outcome = await fetchFromOrigin(url(), INTEL_TCB_INFO, { transport, clock: () => clock });
    if ('fetched' in outcome) {
      expect(outcome.fetched.observedAt).toBe(1790000007);
      expect(outcome.fetched.bytes).toEqual(new TextEncoder().encode('bytes'));
    } else {
      throw new Error(outcome.refusal.detail);
    }
  });

  it('refuses an address that names any host but the declared one, before asking it', async () => {
    const { transport, seen } = recorder(() => new Response('bytes'));
    for (const away of [
      'http://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=00906ea00000',
      'https://cache.example.com/tdx/certification/v4/tcb',
      'https://api.trustedservices.intel.com.evil.example/tdx/certification/v4/tcb',
    ]) {
      const outcome = await fetchFromOrigin(away, INTEL_TCB_INFO, { transport });
      if (!('refusal' in outcome)) {
        throw new Error(`${away} was asked of a transport`);
      }
      expect(outcome.refusal.code, away).toBe('COLLATERAL_BLOB_UNREADABLE');
    }
    expect(seen).toHaveLength(0);
  });

  it('answers a refusal when the origin will not answer, and calls it retryable', async () => {
    const unreachable = await fetchFromOrigin(url(), INTEL_TCB_INFO, {
      transport: async () => {
        throw new Error('socket closed');
      },
    });
    if (!('refusal' in unreachable)) throw new Error('a throwing transport was not refused');
    expect(unreachable.refusal.code).toBe('COLLATERAL_ORIGIN_UNREACHABLE');
    expect(unreachable.refusal.verdict).toBe('retryable');

    const refused = await fetchFromOrigin(url(), INTEL_TCB_INFO, { transport: async () => new Response('nope', { status: 404 }) });
    if (!('refusal' in refused)) throw new Error('a 404 was not refused');
    expect(refused.refusal.code).toBe('COLLATERAL_ORIGIN_REFUSED');
    expect(refused.refusal.detail).toContain('404');

    const empty = await fetchFromOrigin(url(), INTEL_TCB_INFO, { transport: async () => new Response('') });
    if (!('refusal' in empty)) throw new Error('an empty body was not refused');
    expect(empty.refusal.code).toBe('COLLATERAL_BLOB_UNREADABLE');
  });

  it('stops waiting at the declared timeout rather than at a default nobody wrote down', async () => {
    const patient: OriginDeclaration = { ...INTEL_TCB_INFO, timeoutMs: 20 };
    const outcome = await fetchFromOrigin(url(), patient, {
      transport: (_input, init = {}) =>
        new Promise<Response>((_resolve, reject) => {
          const signal = init.signal;
          if (signal === undefined || signal === null) {
            reject(new Error('no signal was given to wait on'));
            return;
          }
          signal.addEventListener('abort', () => reject(new Error('waiting was cut short')));
        }),
    });
    if (!('refusal' in outcome)) {
      throw new Error('an answer that never arrived was not refused');
    }
    expect(outcome.refusal.code).toBe('COLLATERAL_ORIGIN_UNREACHABLE');
    expect(outcome.refusal.detail).toContain('20ms');
  });

  it('refuses an answer bigger than the path declares, whether it said so or not', async () => {
    const announced = await fetchFromOrigin(url(), INTEL_TCB_INFO, {
      transport: async () => new Response('x'.repeat(10), { headers: { 'content-length': '999999' } }),
    });
    if (!('refusal' in announced)) throw new Error('an announced oversize body was read anyway');
    expect(announced.refusal.code).toBe('COLLATERAL_BLOB_UNREADABLE');
    expect(announced.refusal.detail).toContain('65536');

    const lying = await fetchFromOrigin(url(), { ...INTEL_TCB_INFO, maxResponseBytes: 4 }, {
      transport: async () => new Response('x'.repeat(10)),
    });
    if (!('refusal' in lying)) throw new Error('an unannounced oversize body was kept');
    expect(lying.refusal.code).toBe('COLLATERAL_BLOB_UNREADABLE');
  });

  it('keys a kept blob by what changes the answer, and by nothing else', () => {
    const base = collateralCacheKey(query(), INTEL_TCB_INFO);
    expect(base).toBe(`origin=intel-tcb-info|platform=tdx|cpuType=${CPU_TYPE}|level=tcb-date=2026-09-01T00:00:00Z`);
    const identity = { by: 'tcb-composition' as const, value: 'aabb0000000000000000000000000000' };
    for (const other of [
      query({ platform: 'sgx' }),
      query({ cpuType: '00a0f0000000' }),
      query({ level: identity }),
      query({ origin: 'intel-qe-identity' }),
    ]) {
      expect(collateralCacheKey(other, INTEL_TCB_INFO), 'a different identity is a different record').not.toBe(base);
    }
    for (const same of [query({ appraisalAt: 1 }), query({ onAbsent: 'refuse' }), query({ roots: [] }), query({ cpuType: CPU_TYPE.toUpperCase() })]) {
      expect(collateralCacheKey(same, INTEL_TCB_INFO), 'the same identity at another moment is the same record').toBe(base);
    }
  });

  it('names the inputs a key cannot be built without', () => {
    const asked = collateralCacheKey(query({ level: null }), INTEL_TCB_INFO);
    if (typeof asked === 'string') throw new Error('a key was built over a missing level');
    expect(asked.missing).toEqual(['level']);
    const qe = collateralCacheKey(query({ origin: 'intel-qe-identity', cpuType: null, level: null }), INTEL_QE_IDENTITY);
    expect(qe).toBe('origin=intel-qe-identity|platform=tdx');
  });
});
