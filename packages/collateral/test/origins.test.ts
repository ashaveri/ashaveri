import { describe, expect, it } from 'vitest';
import {
  INTEL_TCB_INFO,
  collateralCacheKey,
  fetchFromOrigin,
  readSignedCollateral,
  requestUrl,
  type CollateralQuery,
  type CollateralTransport,
  type DeclaredOriginDeclaration,
} from '../src/index.js';

const AT = 1790000000;

function query(over: Partial<CollateralQuery> = {}): CollateralQuery {
  return {
    origin: 'intel-pck-crl',
    platform: 'tdx',
    cpuType: null,
    level: null,
    appraisalAt: AT,
    roots: [new Uint8Array([1])],
    retained: null,
    onAbsent: 'unassessed',
    ...over,
  };
}

/**
 * A declared origin made here rather than taken from the package, so the general address, cache and
 * envelope branches are exercised before a real origin depends on them. The route and the shape are the
 * ones a DER list answers in; the bytes and the host are the test's own.
 */
const DECLARED: DeclaredOriginDeclaration = {
  name: 'intel-pck-crl',
  host: 'declared.example',
  method: 'GET',
  mediaType: 'application/pkix-crl',
  answer: 'der-crl',
  chainHeader: 'X-Declared-Chain',
  timeoutMs: 25,
  maxResponseBytes: 64,
  refusals: INTEL_TCB_INFO.refusals,
  reader: { as: 'declared-only', lacks: 'a DER CRL parser' },
  routes: [
    {
      name: 'list',
      path: '/list?ca={ca}&encoding=der',
      method: 'GET',
      mediaType: 'application/pkix-crl',
      answer: 'der-crl',
      knowledge: 'historical',
    },
  ],
  cache: null,
};

function bytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

function silent(): CollateralTransport {
  return async () => {
    throw new Error('a transport was asked');
  };
}

describe('a declared origin with no reader', () => {
  it('spells the route a query names, and stops where the query states no member for a placeholder', () => {
    expect(requestUrl(query({ ca: 'processor' }), DECLARED)).toBe('https://declared.example/list?ca=processor&encoding=der');
    const missing = requestUrl(query(), DECLARED);
    if (typeof missing === 'string') throw new Error('a route missing its CA scope was spelled anyway');
    expect(missing.refusal.code).toBe('COLLATERAL_INPUT_MISSING');
    expect(missing.refusal.missing).toEqual(['ca']);
  });

  it('names no record for a kept answer, and says why rather than returning an empty key', () => {
    const key = collateralCacheKey(query({ ca: 'processor' }), DECLARED);
    if (typeof key === 'string') throw new Error('a declared origin was keyed without a reader');
    expect(key.missing).toEqual([]);
    expect(key.why).toContain('no cache key yet');
  });

  it('refuses to weigh its answer with the reader that weighs a served JSON document', () => {
    const read = readSignedCollateral(bytes('30 82'), {
      query: query({ ca: 'processor' }),
      declaration: DECLARED,
      appraisalAt: AT,
    });
    if (!('refusal' in read)) throw new Error('a declared origin was read as a served document');
    expect(read.refusal.code).toBe('COLLATERAL_ORIGIN_UNSUPPORTED');
    expect(read.refusal.detail).toContain('der-crl');
  });

  it('refuses to ask a POST route rather than sending a GET it never published', async () => {
    const posted: DeclaredOriginDeclaration = {
      ...DECLARED,
      name: 'ocsp',
      method: 'POST',
      mediaType: 'application/ocsp-response',
      answer: 'der-ocsp-response',
      routes: [{ name: 'ocsp', path: '/', method: 'POST', mediaType: 'application/ocsp-response', answer: 'der-ocsp-response', knowledge: 'current' }],
    };
    const at = query({ ca: 'processor', ocspCertificate: new Uint8Array([1]), ocspIssuer: new Uint8Array([2]) });
    const asked = requestUrl(at, posted);
    if (typeof asked === 'string') throw new Error('a POST route was handed back as an address');
    expect(asked.refusal.code).toBe('COLLATERAL_ORIGIN_UNSUPPORTED');
    const outcome = await fetchFromOrigin('https://declared.example/', posted, { transport: silent() });
    if (!('refusal' in outcome)) throw new Error('a POST declaration was fetched with GET');
    expect(outcome.refusal.code).toBe('COLLATERAL_ORIGIN_UNSUPPORTED');
  });
});
