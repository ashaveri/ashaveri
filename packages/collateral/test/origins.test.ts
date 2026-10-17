import { describe, expect, it } from 'vitest';
import {
  AMD_KDS,
  CollateralError,
  INTEL_PCK_CRL,
  INTEL_TCB_INFO,
  appraiseCollateral,
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

function recorder(reply: (init: RequestInit) => Response | Promise<Response>): {
  readonly transport: CollateralTransport;
  readonly seen: { readonly url: string; readonly init: RequestInit }[];
} {
  const seen: { url: string; init: RequestInit }[] = [];
  const transport: CollateralTransport = async (input, init = {}) => {
    seen.push({ url: String(input), init });
    return reply(init);
  };
  return { transport, seen };
}

const CRL_URL = 'https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=processor&encoding=der';

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

  it('states the CRL route, media type and chain header measured for it, and the parser it lacks', () => {
    expect(INTEL_PCK_CRL.reader.as).toBe('declared-only');
    expect(INTEL_PCK_CRL.answer).toBe('der-crl');
    expect(INTEL_PCK_CRL.mediaType).toBe('application/pkix-crl');
    expect(INTEL_PCK_CRL.chainHeader).toBe('SGX-PCK-CRL-Issuer-Chain');
    expect(INTEL_PCK_CRL.routes[0]).toEqual({
      name: 'pck-crl',
      path: '/sgx/certification/v4/pckcrl?ca={ca}&encoding=der',
      method: 'GET',
      mediaType: 'application/pkix-crl',
      answer: 'der-crl',
      knowledge: 'historical',
    });
    if (INTEL_PCK_CRL.reader.as !== 'declared-only') throw new Error('the CRL was declared readable');
    expect(INTEL_PCK_CRL.reader.lacks).toBe('a DER CRL parser');
    expect(INTEL_PCK_CRL.cache).toBeNull();
  });

  it('spells the processor and platform CRL addresses, and stops when no authority scope is named', () => {
    expect(requestUrl(query({ ca: 'processor' }), INTEL_PCK_CRL)).toBe(CRL_URL);
    expect(requestUrl(query({ ca: 'platform' }), INTEL_PCK_CRL)).toBe(
      'https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform&encoding=der',
    );
    const missing = requestUrl(query(), INTEL_PCK_CRL);
    if (typeof missing === 'string') throw new Error('a CRL address was spelled without a CA scope');
    expect(missing.refusal.code).toBe('COLLATERAL_INPUT_MISSING');
    expect(missing.refusal.missing).toEqual(['ca']);
  });

  it('refuses an appraisal of the CRL with the parser it lacks, and names the origins it reads', async () => {
    const outcome = await appraiseCollateral(query({ origin: 'intel-pck-crl', ca: 'processor' }), { transport: silent() });
    expect(outcome.state).toBe('unavailable');
    if (!('refusal' in outcome)) throw new Error('an unread origin answered with a document');
    expect(outcome.refusal.code).toBe('COLLATERAL_ORIGIN_UNSUPPORTED');
    expect(outcome.refusal.missing).toEqual(['origin']);
    expect(outcome.refusal.detail).toContain('intel-pck-crl');
    expect(outcome.refusal.detail).toContain('DER CRL parser');
    expect(outcome.refusal.detail).toContain('intel-tcb-info and intel-qe-identity');

    const required = appraiseCollateral(query({ origin: 'intel-pck-crl', ca: 'processor', onAbsent: 'refuse' }), { transport: silent() });
    await expect(required).rejects.toBeInstanceOf(CollateralError);
  });

  it('keeps the fetch rules for the CRL: one host, no redirect, a bounded wait and a header kept as sent', async () => {
    const { transport, seen } = recorder(() => new Response(new Uint8Array([0x30, 0x82]), {
      headers: { [INTEL_PCK_CRL.chainHeader as string]: 'url-encoded-chain' },
    }));
    const outcome = await fetchFromOrigin(CRL_URL, INTEL_PCK_CRL, { transport, clock: () => AT });
    if (!('fetched' in outcome)) throw new Error(`the CRL answer was refused: ${outcome.refusal.detail}`);
    expect(new TextDecoder().decode(outcome.fetched.chain)).toBe('url-encoded-chain');
    expect(outcome.fetched.observedAt).toBe(AT);
    const init = seen[0]?.init as RequestInit;
    const headers = new Headers(init.headers);
    expect(headers.get('accept')).toBe('application/pkix-crl');
    expect([...headers.keys()]).toEqual(['accept']);
    expect(init.method).toBe('GET');
    expect(init.redirect).toBe('error');

    const away = await fetchFromOrigin('https://cache.example.com/pckcrl', INTEL_PCK_CRL, { transport: silent() });
    if (!('refusal' in away)) throw new Error('a foreign host was asked for the CRL');
    expect(away.refusal.code).toBe('COLLATERAL_BLOB_UNREADABLE');

    const refused = await fetchFromOrigin(CRL_URL, INTEL_PCK_CRL, { transport: async () => new Response('no', { status: 403 }) });
    if (!('refusal' in refused)) throw new Error('a 403 was read as a document');
    expect(refused.refusal.code).toBe('COLLATERAL_ORIGIN_REFUSED');

    const empty = await fetchFromOrigin(CRL_URL, INTEL_PCK_CRL, { transport: async () => new Response('') });
    if (!('refusal' in empty)) throw new Error('an empty body was read as a list');
    expect(empty.refusal.code).toBe('COLLATERAL_BLOB_UNREADABLE');

    const oversize = await fetchFromOrigin(CRL_URL, { ...INTEL_PCK_CRL, maxResponseBytes: 4 }, {
      transport: async () => new Response('x'.repeat(10)),
    });
    if (!('refusal' in oversize)) throw new Error('an oversize list was kept');
    expect(oversize.refusal.code).toBe('COLLATERAL_BLOB_UNREADABLE');

    const unreachable = await fetchFromOrigin(CRL_URL, INTEL_PCK_CRL, { transport: silent() });
    if (!('refusal' in unreachable)) throw new Error('an unreachable origin answered');
    expect(unreachable.refusal.code).toBe('COLLATERAL_ORIGIN_UNREACHABLE');
  });

  it('names no cache key for the CRL, because no reader states the list record', () => {
    const key = collateralCacheKey(query({ ca: 'processor' }), INTEL_PCK_CRL);
    if (typeof key === 'string') throw new Error('a CRL was keyed without a reader');
    expect(key.missing).toEqual([]);
    expect(key.why).toContain('no cache key yet');
  });

  it('states the two KDS routes and the chain shape measured beside them', () => {
    expect(AMD_KDS.host).toBe('kdsintf.amd.com');
    expect(AMD_KDS.mediaType).toBe('application/octet-stream');
    expect(AMD_KDS.answer).toBe('pem-certificate-chain');
    expect(AMD_KDS.chainHeader).toBeNull();
    expect(AMD_KDS.routes).toEqual([
      {
        name: 'vcek',
        path: '/vcek/v1/{product}/{hwid}',
        method: 'GET',
        mediaType: 'application/octet-stream',
        answer: 'der-certificate',
        knowledge: 'historical',
      },
      {
        name: 'cert-chain',
        path: '/vcek/v1/{product}/cert_chain',
        method: 'GET',
        mediaType: 'application/octet-stream',
        answer: 'pem-certificate-chain',
        knowledge: 'historical',
      },
    ]);
    if (AMD_KDS.reader.as !== 'declared-only') throw new Error('the KDS was declared readable');
    expect(AMD_KDS.reader.lacks).toContain('served VCEK sample');
    expect(AMD_KDS.reader.lacks).toContain('RSA/P-384 chain reader');
    expect(AMD_KDS.cache).toBeNull();
  });

  it('spells the chain and VCEK addresses, and names the member an address cannot be built without', () => {
    const hwid = 'ab'.repeat(32);
    expect(requestUrl(query({ origin: 'amd-kds', route: 'cert-chain', product: 'Milan' }), AMD_KDS)).toBe(
      'https://kdsintf.amd.com/vcek/v1/Milan/cert_chain',
    );
    expect(requestUrl(query({ origin: 'amd-kds', product: 'Milan', hwid: hwid.toUpperCase() }), AMD_KDS)).toBe(
      `https://kdsintf.amd.com/vcek/v1/Milan/${hwid}`,
    );
    const noProduct = requestUrl(query({ origin: 'amd-kds', route: 'cert-chain' }), AMD_KDS);
    if (typeof noProduct === 'string') throw new Error('a chain address was spelled without a product');
    expect(noProduct.refusal.missing).toEqual(['product']);

    const noHwid = requestUrl(query({ origin: 'amd-kds', product: 'Milan' }), AMD_KDS);
    if (typeof noHwid === 'string') throw new Error('a VCEK address was spelled without a chip id');
    expect(noHwid.refusal.missing).toEqual(['hwid']);

    const noRoute = requestUrl(query({ origin: 'amd-kds', route: 'crl', product: 'Milan' }), AMD_KDS);
    if (typeof noRoute === 'string') throw new Error('an undeclared route was spelled anyway');
    expect(noRoute.refusal.missing).toEqual(['route']);
  });

  it('refuses an appraisal of the KDS with the sample and reader it lacks', async () => {
    const outcome = await appraiseCollateral(
      query({ origin: 'amd-kds', product: 'Milan', hwid: 'ab'.repeat(32) }),
      { transport: silent() },
    );
    expect(outcome.state).toBe('unavailable');
    if (!('refusal' in outcome)) throw new Error('the KDS answered with a chain it never served');
    expect(outcome.refusal.code).toBe('COLLATERAL_ORIGIN_UNSUPPORTED');
    expect(outcome.refusal.detail).toContain('served VCEK sample');
    expect(outcome.refusal.detail).toContain('RSA/P-384 chain reader');
    expect(outcome.refusal.detail).toContain('intel-tcb-info and intel-qe-identity');
  });

  it('keeps the fetch rules for the KDS chain, and asks the media type it measured', async () => {
    const { transport, seen } = recorder(() => new Response('-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----'));
    const outcome = await fetchFromOrigin('https://kdsintf.amd.com/vcek/v1/Milan/cert_chain', AMD_KDS, { transport, clock: () => AT });
    if (!('fetched' in outcome)) throw new Error(`the chain answer was refused: ${outcome.refusal.detail}`);
    expect(new TextDecoder().decode(outcome.fetched.bytes)).toContain('BEGIN CERTIFICATE');
    expect(outcome.fetched.chain).toBeNull();
    const init = seen[0]?.init as RequestInit;
    const headers = new Headers(init.headers);
    expect(headers.get('accept')).toBe('application/octet-stream');
    expect([...headers.keys()]).toEqual(['accept']);
    expect(init.redirect).toBe('error');

    const refused = await fetchFromOrigin('https://kdsintf.amd.com/vcek/v1/Milan/cert_chain', AMD_KDS, {
      transport: async () => new Response('no', { status: 403 }),
    });
    if (!('refusal' in refused)) throw new Error('a 403 was read as a chain');
    expect(refused.refusal.code).toBe('COLLATERAL_ORIGIN_REFUSED');
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
