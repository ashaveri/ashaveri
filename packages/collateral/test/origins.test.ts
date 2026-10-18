import { describe, expect, it } from 'vitest';
import {
  AMD_KDS,
  CollateralError,
  DECLARED_ORIGINS,
  INTEL_PCK_CRL,
  INTEL_TCB_INFO,
  NVIDIA_OCSP,
  NVIDIA_RIM,
  ORIGIN_DECLARATIONS,
  SERVED_ORIGINS,
  appraiseCollateral,
  collateralCacheKey,
  declarationFor,
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

  it('states the CRL route, media type and chain header measured for it, and the reader it now carries', () => {
    expect(INTEL_PCK_CRL.reader.as).toBe('der-certificate-list');
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
    expect(INTEL_PCK_CRL.serialMember).toBe('certificateSerial');
    expect(INTEL_PCK_CRL.cache.keyMembers).toEqual(['origin', 'ca']);
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

  it('routes the CRL to its serial appraisal rather than reading it as a platform level', async () => {
    const outcome = await appraiseCollateral(
      query({ origin: 'intel-pck-crl', ca: 'processor', certificateSerial: 'ab' }),
      { transport: silent() },
    );
    expect(outcome.state).toBe('missing-context');
    if (!('refusal' in outcome)) throw new Error('a CRL was read as a platform level');
    expect(outcome.refusal.code).toBe('COLLATERAL_INPUT_MISSING');
    expect(outcome.refusal.missing).toEqual(['level']);
    expect(outcome.refusal.detail).toContain('appraisePckCrl');

    const required = appraiseCollateral(
      query({ origin: 'intel-pck-crl', ca: 'processor', certificateSerial: 'ab', onAbsent: 'refuse' }),
      { transport: silent() },
    );
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

  it('keys a kept CRL by the authority scope whose list it is', () => {
    expect(collateralCacheKey(query({ ca: 'processor' }), INTEL_PCK_CRL)).toBe('origin=intel-pck-crl|ca=processor');
    expect(collateralCacheKey(query({ ca: 'platform' }), INTEL_PCK_CRL)).toBe('origin=intel-pck-crl|ca=platform');
  });

  it('states the two KDS routes, the chain shape measured beside them and the reader that weighs them', () => {
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
    expect(AMD_KDS.reader.as).toBe('amd-vcek-chain');
    expect(AMD_KDS.cache.keyMembers).toEqual(['origin', 'product', 'hwid']);
  });

  it('spells the chain and VCEK addresses, and names the member an address cannot be built without', () => {
    const hwid = 'ab'.repeat(64);
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

    // The route answers 400 for a chip id spelled at half the length it states, so the shorter spelling is
    // refused here rather than sent to an address that has no answer for it.
    const halfHwid = requestUrl(query({ origin: 'amd-kds', product: 'Milan', hwid: 'ab'.repeat(32) }), AMD_KDS);
    if (typeof halfHwid === 'string') throw new Error('a half-length chip id reached an address');
    expect(halfHwid.refusal.missing).toEqual(['hwid']);

    const noRoute = requestUrl(query({ origin: 'amd-kds', route: 'crl', product: 'Milan' }), AMD_KDS);
    if (typeof noRoute === 'string') throw new Error('an undeclared route was spelled anyway');
    expect(noRoute.refusal.missing).toEqual(['route']);
  });

  it('keeps the KDS out of the platform-level appraisal now that it has a reader', async () => {
    const outcome = await appraiseCollateral(
      query({ origin: 'amd-kds', product: 'Milan', hwid: 'ab'.repeat(64) }),
      { transport: silent() },
    );
    expect(outcome.state).toBe('missing-context');
    if (!('refusal' in outcome)) throw new Error('the KDS was appraised as a platform level');
    expect(outcome.refusal.code).toBe('COLLATERAL_INPUT_MISSING');
    expect(outcome.refusal.detail).toContain('appraiseVcekChain');
  });

  it('keeps the fetch rules for the KDS, and asks the media type it measured', async () => {
    const pem = new TextEncoder().encode('-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----');
    const der = new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x07]);
    const { transport, seen } = recorder(() => new Response(pem));
    const chain = await fetchFromOrigin('https://kdsintf.amd.com/vcek/v1/Milan/cert_chain', AMD_KDS, { transport, clock: () => AT });
    if (!('fetched' in chain)) throw new Error(`the chain answer was refused: ${chain.refusal.detail}`);
    expect(new TextDecoder().decode(chain.fetched.bytes)).toContain('BEGIN CERTIFICATE');
    expect(chain.fetched.chain, 'the chain arrives in the body, and no header carries a second copy').toBeNull();

    const chip = await fetchFromOrigin('https://kdsintf.amd.com/vcek/v1/Milan/ab', { ...AMD_KDS, maxResponseBytes: 65536 }, {
      transport: async () => new Response(der),
      clock: () => AT,
    });
    if (!('fetched' in chip)) throw new Error(`the certificate answer was refused: ${chip.refusal.detail}`);
    expect(chip.fetched.bytes).toEqual(der);

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

    const away = await fetchFromOrigin('https://cache.example.com/vcek/v1/Milan/cert_chain', AMD_KDS, { transport: silent() });
    if (!('refusal' in away)) throw new Error('a foreign host was asked for the chain');
    expect(away.refusal.code).toBe('COLLATERAL_BLOB_UNREADABLE');

    const oversize = await fetchFromOrigin('https://kdsintf.amd.com/vcek/v1/Milan/cert_chain', { ...AMD_KDS, maxResponseBytes: 4 }, {
      transport: async () => new Response(pem),
    });
    if (!('refusal' in oversize)) throw new Error('an oversize chain was kept');
    expect(oversize.refusal.code).toBe('COLLATERAL_BLOB_UNREADABLE');
  });

  it('names every origin a query may carry once, and serves the four read here', () => {
    expect([...DECLARED_ORIGINS].sort()).toEqual([
      'amd-kds',
      'intel-pck-crl',
      'intel-qe-identity',
      'intel-tcb-info',
      'nvidia-rim',
      'ocsp',
    ]);
    expect(SERVED_ORIGINS).toEqual(['intel-tcb-info', 'intel-qe-identity', 'intel-pck-crl', 'amd-kds']);
    for (const name of DECLARED_ORIGINS) {
      expect(ORIGIN_DECLARATIONS[name]?.name, name).toBe(name);
    }
    for (const name of ['nvidia-rim', 'ocsp'] as const) {
      const asked = declarationFor(name);
      if (!('refusal' in asked)) throw new Error(`${name} was served without a reader`);
      expect(asked.refusal.code, name).toBe('COLLATERAL_ORIGIN_UNSUPPORTED');
      expect(asked.refusal.missing, name).toEqual(['origin']);
      expect(asked.refusal.detail, name).toContain('intel-tcb-info, intel-qe-identity, intel-pck-crl and amd-kds');
    }
    expect(declarationFor('intel-pck-crl')).toBe(INTEL_PCK_CRL);
    expect(declarationFor('amd-kds')).toBe(AMD_KDS);
  });

  it('states the RIM route and the signed reference shape NVIDIA publishes for it', () => {
    expect(NVIDIA_RIM.host).toBe('rim.attestation.nvidia.com');
    expect(NVIDIA_RIM.mediaType).toBe('application/json');
    expect(NVIDIA_RIM.answer).toBe('swid-rim');
    expect(NVIDIA_RIM.routes[0]).toEqual({
      name: 'rim',
      path: '/v1/rim/{rimId}',
      method: 'GET',
      mediaType: 'application/json',
      answer: 'swid-rim',
      knowledge: 'historical',
    });
    if (NVIDIA_RIM.reader.as !== 'declared-only') throw new Error('the RIM was declared readable');
    expect(NVIDIA_RIM.reader.lacks).toContain('served RIM body');
    expect(NVIDIA_RIM.reader.lacks).toContain('XML DSig reader');
    expect(NVIDIA_RIM.cache).toBeNull();
  });

  it('spells the RIM address from the id the evidence names, and stops when it names none', () => {
    expect(requestUrl(query({ origin: 'nvidia-rim', rimId: 'gpu-rim-0001' }), NVIDIA_RIM)).toBe(
      'https://rim.attestation.nvidia.com/v1/rim/gpu-rim-0001',
    );
    // No served answer pins the id's character set, so a stated id is carried percent-encoded rather
    // than refused as missing under a class nobody measured.
    expect(requestUrl(query({ origin: 'nvidia-rim', rimId: 'gpu rim/0001' }), NVIDIA_RIM)).toBe(
      'https://rim.attestation.nvidia.com/v1/rim/gpu%20rim%2F0001',
    );
    const missing = requestUrl(query({ origin: 'nvidia-rim' }), NVIDIA_RIM);
    if (typeof missing === 'string') throw new Error('a RIM address was spelled without an id');
    expect(missing.refusal.code).toBe('COLLATERAL_INPUT_MISSING');
    expect(missing.refusal.missing).toEqual(['rimId']);
  });

  it('refuses an appraisal of the RIM with the body and DSig reader it lacks', async () => {
    const outcome = await appraiseCollateral(
      query({ origin: 'nvidia-rim', rimId: 'gpu-rim-0001' }),
      { transport: silent() },
    );
    expect(outcome.state).toBe('unavailable');
    if (!('refusal' in outcome)) throw new Error('the RIM answered with a document it never served');
    expect(outcome.refusal.code).toBe('COLLATERAL_ORIGIN_UNSUPPORTED');
    expect(outcome.refusal.detail).toContain('served RIM body');
    expect(outcome.refusal.detail).toContain('XML DSig reader');
  });

  it('keeps the fetch rules for the RIM, including a credential-required refusal', async () => {
    const { transport, seen } = recorder(() => new Response('{}', { headers: { 'content-type': 'application/json' } }));
    const outcome = await fetchFromOrigin('https://rim.attestation.nvidia.com/v1/rim/gpu-rim-0001', NVIDIA_RIM, {
      transport,
      clock: () => AT,
    });
    if (!('fetched' in outcome)) throw new Error(`the RIM answer was refused: ${outcome.refusal.detail}`);
    const init = seen[0]?.init as RequestInit;
    const headers = new Headers(init.headers);
    expect(headers.get('accept')).toBe('application/json');
    expect([...headers.keys()]).toEqual(['accept']);
    expect(init.redirect).toBe('error');

    const refused = await fetchFromOrigin('https://rim.attestation.nvidia.com/v1/rim/gpu-rim-0001', NVIDIA_RIM, {
      transport: async () => new Response('{}', { status: 403, headers: { 'content-type': 'application/json' } }),
    });
    if (!('refusal' in refused)) throw new Error('a 403 was read as a manifest');
    expect(refused.refusal.code).toBe('COLLATERAL_ORIGIN_REFUSED');
    expect(refused.refusal.verdict).toBe('retryable');
  });

  it('states the OCSP endpoint as a POST route whose answer is current knowledge', () => {
    expect(NVIDIA_OCSP.host).toBe('ocsp.ndis.nvidia.com');
    expect(NVIDIA_OCSP.method).toBe('POST');
    expect(NVIDIA_OCSP.mediaType).toBe('application/ocsp-response');
    expect(NVIDIA_OCSP.answer).toBe('der-ocsp-response');
    expect(NVIDIA_OCSP.routes[0]?.knowledge).toBe('current');
    if (NVIDIA_OCSP.reader.as !== 'declared-only') throw new Error('the OCSP route was declared readable');
    expect(NVIDIA_OCSP.reader.lacks).toContain('served OCSP response');
    expect(NVIDIA_OCSP.reader.lacks).toContain('DER OCSP parser');
  });

  it('names the certificate and issuer an OCSP question states, and spells its address once both are given', () => {
    const missing = requestUrl(query({ origin: 'ocsp' }), NVIDIA_OCSP);
    if (typeof missing === 'string') throw new Error('an OCSP address was spelled with no question');
    expect(missing.refusal.code).toBe('COLLATERAL_INPUT_MISSING');
    expect(missing.refusal.missing).toEqual(['ocspCertificate', 'ocspIssuer']);

    const addressed = requestUrl(
      query({ origin: 'ocsp', ocspCertificate: new Uint8Array([1]), ocspIssuer: new Uint8Array([2]) }),
      NVIDIA_OCSP,
    );
    expect(addressed).toBe('https://ocsp.ndis.nvidia.com/');
  });

  it('refuses an OCSP appraisal and a POST fetch before either can read a response', async () => {
    const outcome = await appraiseCollateral(
      query({ origin: 'ocsp', ocspCertificate: new Uint8Array([1]), ocspIssuer: new Uint8Array([2]) }),
      { transport: silent() },
    );
    expect(outcome.state).toBe('unavailable');
    if (!('refusal' in outcome)) throw new Error('the OCSP origin answered with a response it never served');
    expect(outcome.refusal.code).toBe('COLLATERAL_ORIGIN_UNSUPPORTED');
    expect(outcome.refusal.detail).toContain('DER OCSP parser');

    const { transport, seen } = recorder(() => new Response('never'));
    const fetched = await fetchFromOrigin('https://ocsp.ndis.nvidia.com/', NVIDIA_OCSP, { transport });
    if (!('refusal' in fetched)) throw new Error('a POST declaration was fetched');
    expect(fetched.refusal.code).toBe('COLLATERAL_ORIGIN_UNSUPPORTED');
    expect(seen).toHaveLength(0);
  });

  it('reaches unavailable and missing context for every origin this package does not read, and no passing state', async () => {
    const states: string[] = [];
    for (const origin of ['nvidia-rim', 'ocsp'] as const) {
      const outcome = await appraiseCollateral(query({ origin }), { transport: silent() });
      states.push(outcome.state);
      expect(outcome.collateral, origin).toBeNull();
      expect(outcome.claim, origin).toBeNull();
    }
    expect(states).toEqual(['unavailable', 'unavailable']);

    const chain = await appraiseCollateral(
      query({ origin: 'amd-kds', product: 'Milan', hwid: 'ab'.repeat(64) }),
      { transport: silent() },
    );
    expect(chain.state).toBe('missing-context');
    expect(chain.collateral, 'the KDS entry point answers about a chip, not a level').toBeNull();
    expect(chain.claim).toBeNull();

    const crl = await appraiseCollateral(
      query({ origin: 'intel-pck-crl', ca: 'processor', certificateSerial: 'ab' }),
      { transport: silent() },
    );
    expect(crl.state).toBe('missing-context');
    expect(crl.collateral, 'the CRL entry point answers about a serial, not a level').toBeNull();
    expect(crl.claim).toBeNull();

    const rimWithoutId = requestUrl(query({ origin: 'nvidia-rim' }), NVIDIA_RIM);
    const ocspWithoutQuestion = requestUrl(query({ origin: 'ocsp' }), NVIDIA_OCSP);
    for (const missing of [rimWithoutId, ocspWithoutQuestion]) {
      if (typeof missing === 'string') throw new Error('a missing-context answer was spelled as an address');
      expect(missing.refusal.code).toBe('COLLATERAL_INPUT_MISSING');
    }
  });

  it('spells a POST address but refuses to fetch it rather than sending a GET it never published', async () => {
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
    if (typeof asked !== 'string') throw new Error(`a stated POST question was refused: ${asked.refusal.detail}`);
    expect(asked).toBe('https://declared.example/');
    const outcome = await fetchFromOrigin(asked, posted, { transport: silent() });
    if (!('refusal' in outcome)) throw new Error('a POST declaration was fetched with GET');
    expect(outcome.refusal.code).toBe('COLLATERAL_ORIGIN_UNSUPPORTED');
  });
});
