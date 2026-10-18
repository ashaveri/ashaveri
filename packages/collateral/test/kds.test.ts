import { describe, expect, it } from 'vitest';
import { sha256 } from '@noble/hashes/sha2.js';
import { parseCertificateChain } from '@ashaveri/attest-core';
import { secondsOf, testVendor } from '@ashaveri/fixtures';
import {
  AMD_KDS,
  INTEL_PCK_CRL,
  NVIDIA_RIM,
  SERVED_ORIGINS,
  appraiseCollateral,
  appraiseVcekChain,
  collateralCacheKey,
  declarationFor,
  readPckCrl,
  readSignedCollateral,
  readVcekChain,
  requestUrl,
  routesAnswerNow,
  type CollateralClaim,
  type CollateralRefusal,
  type CollateralTransport,
  type OriginDeclaration,
  type RevocationReadOutcome,
  type VcekChain,
  type VcekChainOutcome,
  type VcekChainQuery,
  type VcekChainReadOutcome,
} from '../src/index.js';
import { amdAsk, amdChain, amdRoot, amdVcek, hwidHex, hwidOf, rsaKeyPair, type AmdAuthority } from './kds-writer.js';

const PRODUCT = 'Milan';
const HWID = hwidOf('ashaveri-test-chip');
const HWID_HEX = hwidHex(HWID);
const VALID_FROM = secondsOf('2026-06-01T00:00:00Z');
const VALID_UNTIL = secondsOf('2033-06-01T00:00:00Z');
const WITHIN = secondsOf('2026-09-15T00:00:00Z');
const BEFORE = secondsOf('2024-01-01T00:00:00Z');
const OBSERVED = secondsOf('2026-09-15T06:00:00Z');
const VCEK_URL = `https://${AMD_KDS.host}/vcek/v1/${PRODUCT}/${HWID_HEX}`;
const CHAIN_URL = `https://${AMD_KDS.host}/vcek/v1/${PRODUCT}/cert_chain`;

const root = amdRoot();
const ask = amdAsk(root);
const chip = amdVcek(ask, { productName: 'Milan-B0', hwid: HWID, notBefore: VALID_FROM, notAfter: VALID_UNTIL });
const CHAIN = amdChain(ask.der, root.der);

function query(over: Partial<VcekChainQuery> = {}): VcekChainQuery {
  return {
    origin: 'amd-kds',
    platform: 'sgx',
    cpuType: null,
    level: null,
    product: PRODUCT,
    hwid: HWID_HEX,
    appraisalAt: WITHIN,
    roots: [root.der],
    retained: null,
    onAbsent: 'unassessed',
    ...over,
  };
}

/** The two answers one question is asked with, as the routes serve them. */
function pair(body: Uint8Array = chip.der, chain: Uint8Array = CHAIN): readonly [Uint8Array, Uint8Array] {
  return [body, chain];
}

function answering(body: Uint8Array, chain: Uint8Array): CollateralTransport {
  return async (input) => (String(input).endsWith('/cert_chain') ? new Response(chain) : new Response(body));
}

function recording(body: Uint8Array, chain: Uint8Array): {
  readonly transport: CollateralTransport;
  readonly seen: { readonly url: string; readonly init: RequestInit }[];
} {
  const seen: { url: string; init: RequestInit }[] = [];
  const transport: CollateralTransport = async (input, init = {}) => {
    seen.push({ url: String(input), init });
    return new Response(String(input).endsWith('/cert_chain') ? chain : body);
  };
  return { transport, seen };
}

function neverAsked(): CollateralTransport {
  return async () => {
    throw new Error('a pair this run did not fetch was read by asking the origin');
  };
}

async function askChain(transport: CollateralTransport, over: Partial<VcekChainQuery> = {}): Promise<VcekChainOutcome> {
  return appraiseVcekChain(query(over), { transport, clock: () => OBSERVED });
}

function read(body: Uint8Array, chain: Uint8Array | null, over: Partial<VcekChainQuery> = {}): VcekChain {
  const asked = query(over);
  const result = readVcekChain(body, chain, {
    query: asked,
    declaration: AMD_KDS,
    appraisalAt: asked.appraisalAt as number,
  });
  if ('read' in result) {
    return result.read;
  }
  throw new Error(`the pair was refused: ${result.refusal.code} ${result.refusal.detail}`);
}

/** The refusal an answer carries, whichever arm produced it. */
function refusalOf(
  answer: VcekChainOutcome | VcekChainReadOutcome | RevocationReadOutcome,
): CollateralRefusal {
  if ('refusal' in answer) {
    return answer.refusal;
  }
  throw new Error('the answer carried no refusal');
}

/** The chain and claim an answer carries, for a case that has already pinned which state it reached. */
function weighed(outcome: VcekChainOutcome): { readonly chain: VcekChain; readonly claim: CollateralClaim } {
  if (outcome.chain === null || outcome.claim === null) {
    throw new Error(`the answer was ${outcome.state} and carried no chain`);
  }
  return { chain: outcome.chain, claim: outcome.claim };
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (one) => one.toString(16).padStart(2, '0')).join('');
}

function reading(over: Partial<VcekChainQuery> = {}, declaration: OriginDeclaration = AMD_KDS) {
  const asked = query(over);
  return { query: asked, declaration, appraisalAt: asked.appraisalAt as number };
}

describe('the VCEK and the chain the KDS answers with', () => {
  it('reads the identity, the shared window and the bytes it weighed', () => {
    const weighedRead = read(chip.der, CHAIN);
    expect(weighedRead.productName).toBe('Milan-B0');
    expect(weighedRead.hwidHex).toBe(HWID_HEX);
    expect(weighedRead.serialHex).toBe('03');
    expect(weighedRead.window).toEqual({ from: VALID_FROM, until: VALID_UNTIL });
    expect(weighedRead.digest).toBe(hex(sha256(chip.der)));
    expect(weighedRead.anchorDigest).toBe(hex(sha256(root.der)));
    expect(weighedRead.blobs).toHaveLength(3);
    expect(weighedRead.blobs[0]).toEqual(chip.der);
    const presented = parseCertificateChain(CHAIN);
    expect(weighedRead.blobs[1]).toEqual(presented[0]?.raw);
    expect(weighedRead.blobs[2]).toEqual(presented[1]?.raw);
  });

  it('follows the issuer name rather than the order the chain arrived in', () => {
    expect(read(chip.der, amdChain(root.der, ask.der)).hwidHex).toBe(HWID_HEX);
  });

  it('answers issued for a pair this run fetched, and states its reach as historical', async () => {
    const [body, chain] = pair();
    const outcome = await askChain(answering(body, chain));
    expect(outcome.state).toBe('issued');
    expect('refusal' in outcome, 'a chain that stood at the moment asked carries no refusal').toBe(false);
    const { chain: readResult, claim } = weighed(outcome);
    expect(claim.reach).toBe('historical-knowledge');
    expect(claim.observedAt).toBe(OBSERVED);
    expect(claim.appraisalAt).toBe(WITHIN);
    expect(claim.retainUntil).toBe(readResult.window.until);
    expect(claim.retainUntil).toBe(VALID_UNTIL);
    expect(claim.cacheKey).toBe(`origin=amd-kds|product=${PRODUCT.toLowerCase()}|hwid=${HWID_HEX}`);
  });

  it('asks both published routes, named by the declaration rather than by its order', async () => {
    const [body, chain] = pair();
    const { transport, seen } = recording(body, chain);
    const outcome = await askChain(transport);
    expect(outcome.state).toBe('issued');
    expect(seen.map((one) => one.url)).toEqual([VCEK_URL, CHAIN_URL]);
    for (const one of seen) {
      const headers = new Headers(one.init.headers);
      expect(headers.get('accept')).toBe(AMD_KDS.mediaType);
      expect([...headers.keys()]).toEqual(['accept']);
      expect(one.init.method).toBe('GET');
      expect(one.init.redirect).toBe('error');
    }
  });

  it('answers NOT_OBSERVED for a retained pair, and reports no observation of its own', async () => {
    const [body, chain] = pair();
    const outcome = await askChain(neverAsked(), {
      retained: { bytes: body, chain, chainSha256: null, observedAt: OBSERVED },
    });
    expect(outcome.state).toBe('stale');
    expect(refusalOf(outcome).code).toBe('COLLATERAL_NOT_OBSERVED');
    const { claim } = weighed(outcome);
    expect(claim.reach).toBe('historical-knowledge');
    expect(claim.observedAt).toBeNull();
    expect(claim.cacheKey).toBe(`origin=amd-kds|product=${PRODUCT.toLowerCase()}|hwid=${HWID_HEX}`);
  });

  it('checks a retained chain against the digest the caller named beside it', async () => {
    const [body, chain] = pair();
    const outcome = await askChain(neverAsked(), {
      retained: { bytes: body, chain, chainSha256: sha256(new Uint8Array([1, 2, 3])), observedAt: OBSERVED },
    });
    expect(outcome.state).toBe('unavailable');
    expect(refusalOf(outcome).code).toBe('COLLATERAL_RETAINED_CHAIN_MISMATCH');
    expect(refusalOf(outcome).missing).toEqual(['retained.chain', 'retained.chainSha256']);
  });

  it('refuses a certificate that arrived with no chain beside it', async () => {
    const [body] = pair();
    expect(refusalOf(readVcekChain(body, null, reading())).code).toBe('COLLATERAL_ANCHOR_NOT_PINNED');
    expect(refusalOf(readVcekChain(body, null, reading())).detail).toContain(AMD_KDS.chainRoute);

    const kept = await askChain(neverAsked(), {
      retained: { bytes: body, chain: null, chainSha256: null, observedAt: OBSERVED },
    });
    expect(kept.state).toBe('unavailable');
    expect(refusalOf(kept).code).toBe('COLLATERAL_ANCHOR_NOT_PINNED');
  });

  it('refuses a chain that reaches no root the caller pinned', async () => {
    const stranger = amdRoot('Ashaveri Test AMD ARK Genoa');
    const foreignAsk = amdAsk(stranger, 'Ashaveri Test AMD ASK Genoa');
    const other = amdVcek(foreignAsk, { productName: 'Milan-B0', hwid: HWID, notBefore: VALID_FROM, notAfter: VALID_UNTIL });
    const outcome = await askChain(answering(other.der, amdChain(foreignAsk.der, stranger.der)));
    expect(outcome.state).toBe('unavailable');
    expect(refusalOf(outcome).code).toBe('COLLATERAL_ANCHOR_NOT_PINNED');
    expect(refusalOf(outcome).detail).toContain('MISSING_TRUST_ROOT');
  });

  it('refuses a chain whose root name is one the caller pinned under another key', async () => {
    const lookalikeRoot = amdRoot();
    const lookalikeAsk = amdAsk(lookalikeRoot);
    const other = amdVcek(lookalikeAsk, { productName: 'Milan-B0', hwid: HWID, notBefore: VALID_FROM, notAfter: VALID_UNTIL });
    const outcome = await askChain(answering(other.der, amdChain(lookalikeAsk.der, lookalikeRoot.der)));
    expect(outcome.state).toBe('unavailable');
    expect(refusalOf(outcome).code).toBe('COLLATERAL_SIGNATURE_UNVERIFIED');
    expect(refusalOf(outcome).detail).toContain('ASK signature does not verify');
  });

  it('refuses a chain whose intermediate signed the certificate with another key', async () => {
    const lookalike: AmdAuthority = { ...ask, key: rsaKeyPair() };
    const forged = amdVcek(lookalike, { productName: 'Milan-B0', hwid: HWID, notBefore: VALID_FROM, notAfter: VALID_UNTIL });
    const outcome = await askChain(answering(forged.der, CHAIN));
    expect(outcome.state).toBe('unavailable');
    expect(refusalOf(outcome).code).toBe('COLLATERAL_SIGNATURE_UNVERIFIED');
    expect(refusalOf(outcome).detail).toContain('VCEK signature does not verify');
  });
  it('refuses a certificate outside its own validity at the moment asked', async () => {
    const outcome = await askChain(answering(...pair()), { appraisalAt: BEFORE });
    expect(outcome.state).toBe('unavailable');
    expect(refusalOf(outcome).code).toBe('COLLATERAL_SIGNATURE_UNVERIFIED');
    expect(refusalOf(outcome).detail).toContain('CERT_EXPIRED');
  });

  it('refuses a believed chain whose certificates state no shared span', () => {
    const degenerate = amdVcek(ask, { productName: 'Milan-B0', hwid: HWID, notBefore: WITHIN, notAfter: WITHIN });
    const refused = readVcekChain(degenerate.der, CHAIN, reading());
    expect(refusalOf(refused).code).toBe('COLLATERAL_BLOB_UNREADABLE');
    expect(refusalOf(refused).detail).toContain('share no validity');
  });

  it('binds the certificate to the chip the question named', async () => {
    const other = hwidOf('ashaveri-test-another-chip');
    const neighbour = amdVcek(ask, { productName: 'Milan-B0', hwid: other, notBefore: VALID_FROM, notAfter: VALID_UNTIL });
    const outcome = await askChain(answering(neighbour.der, CHAIN));
    expect(outcome.state).toBe('unavailable');
    expect(refusalOf(outcome).code).toBe('COLLATERAL_IDENTITY_MISMATCH');
    expect(refusalOf(outcome).missing).toEqual(['hwid']);
    expect(refusalOf(outcome).detail).toContain(hwidHex(other));
  });

  it('binds the certificate to the product line the question named', async () => {
    const genoa = amdVcek(ask, { productName: 'Genoa-C0', hwid: HWID, notBefore: VALID_FROM, notAfter: VALID_UNTIL });
    const outcome = await askChain(answering(genoa.der, CHAIN));
    expect(outcome.state).toBe('unavailable');
    expect(refusalOf(outcome).code).toBe('COLLATERAL_IDENTITY_MISMATCH');
    expect(refusalOf(outcome).missing).toEqual(['product']);
    expect(refusalOf(outcome).detail).toContain('Genoa');
  });

  it('refuses a certificate that states no AMD identity extension as the wrong answer shape', () => {
    const refused = readVcekChain(ask.der, CHAIN, reading());
    expect(refusalOf(refused).code).toBe('COLLATERAL_SIGNATURE_UNVERIFIED');
    expect(refusalOf(refused).detail).toContain(AMD_KDS.suites.certificateKey);

    const keyless = amdVcek(ask, { hwid: HWID, notBefore: VALID_FROM, notAfter: VALID_UNTIL });
    const unstated = readVcekChain(keyless.der, CHAIN, reading());
    expect(refusalOf(unstated).code).toBe('COLLATERAL_BLOB_UNREADABLE');
    expect(refusalOf(unstated).detail).toContain('product name');

    const nameless = amdVcek(ask, { productName: 'Milan-B0', notBefore: VALID_FROM, notAfter: VALID_UNTIL });
    expect(refusalOf(readVcekChain(nameless.der, CHAIN, reading())).detail).toContain('HWID');
  });

  it('reads only the suites this origin publishes and names the one it met', async () => {
    const vendor = testVendor();
    const outcome = await askChain(answering(vendor.issuerDer, amdChain(vendor.issuerDer, vendor.rootDer)), {
      roots: [vendor.rootDer],
    });
    expect(outcome.state).toBe('unavailable');
    expect(refusalOf(outcome).code).toBe('COLLATERAL_SIGNATURE_UNVERIFIED');
    expect(refusalOf(outcome).detail).toContain('ecdsa-sha256');

    const widened: OriginDeclaration = {
      ...AMD_KDS,
      suites: { signature: 'ecdsa-sha384', authorityKey: 'ec-p384', certificateKey: 'ec-p384' },
    };
    const refused = readVcekChain(chip.der, CHAIN, reading({}, widened));
    expect(refusalOf(refused).code).toBe('COLLATERAL_SIGNATURE_UNVERIFIED');
    expect(refusalOf(refused).detail).toContain(AMD_KDS.suites.signature);
  });

  it('refuses a body holding two certificates, a chain holding none, and one issuer name carried twice', () => {
    const two = new Uint8Array(chip.der.byteLength + ask.der.byteLength);
    two.set(chip.der, 0);
    two.set(ask.der, chip.der.byteLength);
    expect(refusalOf(readVcekChain(two, CHAIN, reading())).detail).toContain('2 certificates');

    const noChain = readVcekChain(chip.der, new TextEncoder().encode('no certificate here'), reading());
    expect(refusalOf(noChain).code).toBe('COLLATERAL_BLOB_UNREADABLE');
    expect(refusalOf(noChain).detail).toContain(AMD_KDS.chainRoute);

    const twice = readVcekChain(chip.der, amdChain(ask.der, ask.der, root.der), reading());
    expect(refusalOf(twice).code).toBe('COLLATERAL_SIGNATURE_UNVERIFIED');
    expect(refusalOf(twice).detail).toContain('2 certificates');

    const noIssuer = readVcekChain(chip.der, amdChain(root.der), reading());
    expect(refusalOf(noIssuer).detail).toContain('no certificate');
  });

  it('holds its byte bound over each half of the answer, at the fetch and at the reader', async () => {
    const huge = new Uint8Array(AMD_KDS.maxResponseBytes + 1);
    const body = await askChain(answering(huge, CHAIN));
    expect(body.state).toBe('unavailable');
    expect(refusalOf(body).code).toBe('COLLATERAL_BLOB_UNREADABLE');
    expect(refusalOf(body).detail).toContain(String(huge.byteLength));

    const chain = await askChain(answering(chip.der, huge));
    expect(refusalOf(chain).code).toBe('COLLATERAL_BLOB_UNREADABLE');
    expect(refusalOf(chain).detail).toContain(CHAIN_URL);

    expect(refusalOf(readVcekChain(huge, CHAIN, reading())).detail).toContain(String(AMD_KDS.maxResponseBytes));
    expect(refusalOf(readVcekChain(huge, CHAIN, reading())).detail).toContain('certificate');
    expect(refusalOf(readVcekChain(chip.der, huge, reading())).detail).toContain('chain');
    expect(refusalOf(readVcekChain(new Uint8Array(), CHAIN, reading())).code).toBe('COLLATERAL_BLOB_UNREADABLE');
  });

  it('names the field a chip question cannot be asked without', async () => {
    const [body, chain] = pair();
    const transport = answering(body, chain);

    const noHwid = await askChain(transport, { hwid: '' });
    expect(noHwid.state).toBe('missing-context');
    expect(refusalOf(noHwid).missing).toEqual(['hwid']);

    const shortHwid = await askChain(transport, { hwid: HWID_HEX.slice(0, 64) });
    expect(refusalOf(shortHwid).missing).toEqual(['hwid']);

    const noProduct = await askChain(transport, { product: '' });
    expect(refusalOf(noProduct).missing).toEqual(['product']);

    const noRoots = await askChain(transport, { roots: [] });
    expect(refusalOf(noRoots).code).toBe('COLLATERAL_ANCHOR_NOT_PINNED');

    const noInstant = await askChain(transport, { appraisalAt: null });
    expect(refusalOf(noInstant).code).toBe('COLLATERAL_INPUT_MISSING');
    expect(refusalOf(noInstant).missing).toEqual(['appraisalAt']);

    const unreadPair = await askChain(neverAsked(), { retained: { bytes: body, chain, chainSha256: null, observedAt: null } });
    expect(refusalOf(unreadPair).missing).toEqual(['retained.observedAt']);

    const noStatedChip = readVcekChain(body, chain, { ...reading(), query: { ...query(), hwid: null } });
    expect(refusalOf(noStatedChip).code).toBe('COLLATERAL_INPUT_MISSING');
    expect(refusalOf(noStatedChip).missing).toEqual(['hwid']);
  });

  it('refuses an answer either route withheld rather than weighing half a question', async () => {
    const chainMissing = await askChain(async (input) =>
      String(input).endsWith('/cert_chain') ? new Response('gone', { status: 404 }) : new Response(chip.der));
    expect(chainMissing.state).toBe('unavailable');
    expect(refusalOf(chainMissing).code).toBe('COLLATERAL_ORIGIN_REFUSED');
    expect(refusalOf(chainMissing).detail).toContain('404');

    const bodyMissing = await askChain(async () => new Response('no', { status: 403 }));
    expect(refusalOf(bodyMissing).code).toBe('COLLATERAL_ORIGIN_REFUSED');

    const empty = await askChain(async (input) =>
      String(input).endsWith('/cert_chain') ? new Response(new Uint8Array()) : new Response(chip.der));
    expect(refusalOf(empty).code).toBe('COLLATERAL_BLOB_UNREADABLE');
  });

  it('throws for a required chip answer that could not be reached', async () => {
    await expect(appraiseVcekChain(
      query({ hwid: 'zz', onAbsent: 'refuse' }),
      { transport: neverAsked() },
    )).rejects.toMatchObject({ code: 'COLLATERAL_INPUT_MISSING' });
  });

  it('keeps the chain out of the platform-level appraisal and names the entry point that weighs it', async () => {
    const outcome = await appraiseCollateral(
      { ...query(), level: { by: 'tcb-date', value: '2026-09-01T00:00:00Z' } },
      { transport: neverAsked() },
    );
    expect(outcome.state).toBe('missing-context');
    if (!('refusal' in outcome)) throw new Error('a chip chain was appraised as a platform level');
    expect(outcome.refusal.code).toBe('COLLATERAL_INPUT_MISSING');
    expect(outcome.refusal.detail).toContain('appraiseVcekChain');
  });

  it('refuses the wrong arm rather than weighing a chain as a document', () => {
    const asJson = readSignedCollateral(chip.der, reading());
    if (!('refusal' in asJson)) throw new Error('a VCEK was read as a served JSON document');
    expect(asJson.refusal.code).toBe('COLLATERAL_BLOB_UNREADABLE');

    const asCrl = readPckCrl(chip.der, CHAIN, reading());
    expect(refusalOf(asCrl).code).toBe('COLLATERAL_BLOB_UNREADABLE');

    expect(refusalOf(readVcekChain(chip.der, CHAIN, reading({}, INTEL_PCK_CRL))).code)
      .toBe('COLLATERAL_BLOB_UNREADABLE');
    expect(refusalOf(readVcekChain(chip.der, CHAIN, reading({}, NVIDIA_RIM))).code)
      .toBe('COLLATERAL_ORIGIN_UNSUPPORTED');
  });
});

describe('the declaration the chain reader is wired through', () => {
  it('states the routes, the suites and the identity members the reader acts on', () => {
    expect(declarationFor('amd-kds')).toBe(AMD_KDS);
    expect(AMD_KDS.reader.as).toBe('amd-vcek-chain');
    expect(AMD_KDS.host).toBe('kdsintf.amd.com');
    expect(AMD_KDS.mediaType).toBe('application/octet-stream');
    expect(AMD_KDS.answer).toBe('pem-certificate-chain');
    expect(AMD_KDS.chainHeader).toBeNull();
    expect(AMD_KDS.timeoutMs).toBe(5000);
    expect(AMD_KDS.maxResponseBytes).toBe(65536);
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
    expect(AMD_KDS.certificateRoute).toBe('vcek');
    expect(AMD_KDS.chainRoute).toBe('cert-chain');
    expect(AMD_KDS.productMember).toBe('product');
    expect(AMD_KDS.hwidMember).toBe('hwid');
    expect(AMD_KDS.suites).toEqual({ signature: 'rsa-pss', authorityKey: 'rsa', certificateKey: 'ec-p384' });
    expect(AMD_KDS.cache.keyMembers).toEqual(['origin', 'product', 'hwid']);
    expect(AMD_KDS.cache.answersCurrentQuestions).toBe(false);
    expect(AMD_KDS.cache.retainUntil).toBe('certificate-not-after');
  });

  it('spells both addresses, and stops where the query states no member for a placeholder', () => {
    expect(requestUrl(query(), AMD_KDS)).toBe(VCEK_URL);
    expect(requestUrl({ ...query(), route: AMD_KDS.chainRoute }, AMD_KDS)).toBe(CHAIN_URL);
    expect(requestUrl({ ...query(), hwid: HWID_HEX.toUpperCase() }, AMD_KDS)).toBe(VCEK_URL);
    const noRoute = requestUrl({ ...query(), route: 'crl' }, AMD_KDS);
    if (typeof noRoute === 'string') throw new Error('an undeclared route was spelled anyway');
    expect(noRoute.refusal.missing).toEqual(['route']);
  });

  it('keys a kept pair by the chip it answers for, and reads the reach off the routes', () => {
    expect(SERVED_ORIGINS).toEqual(['intel-tcb-info', 'intel-qe-identity', 'intel-pck-crl', 'amd-kds']);
    expect(collateralCacheKey(query(), AMD_KDS)).toBe(`origin=amd-kds|product=milan|hwid=${HWID_HEX}`);
    expect(collateralCacheKey({ ...query(), appraisalAt: BEFORE }, AMD_KDS)).toBe(collateralCacheKey(query(), AMD_KDS));
    expect(routesAnswerNow(AMD_KDS)).toBe(false);
    expect(routesAnswerNow({
      ...AMD_KDS,
      routes: AMD_KDS.routes.map((one) => ({ ...one, knowledge: 'current' as const })),
    })).toBe(true);
    expect(routesAnswerNow({
      ...AMD_KDS,
      routes: AMD_KDS.routes.map((one) => (one.name === AMD_KDS.certificateRoute
        ? { ...one, knowledge: 'current' as const }
        : one)),
    })).toBe(false);
    expect(routesAnswerNow({
      ...AMD_KDS,
      routes: [...AMD_KDS.routes, {
        name: 'crl',
        path: '/vcek/v1/{product}/crl',
        method: 'GET' as const,
        mediaType: 'application/octet-stream',
        answer: 'der-crl' as const,
        knowledge: 'current' as const,
      }],
    })).toBe(false);
  });

  it('names the two origins still declared without a reader, and counts the four that are read', async () => {
    for (const name of ['nvidia-rim', 'ocsp'] as const) {
      const asked = declarationFor(name);
      if (!('refusal' in asked)) throw new Error(`${name} was served without a reader`);
      expect(asked.refusal.code, name).toBe('COLLATERAL_ORIGIN_UNSUPPORTED');
      expect(asked.refusal.missing, name).toEqual(['origin']);
      expect(asked.refusal.detail, name).toContain('intel-tcb-info, intel-qe-identity, intel-pck-crl and amd-kds');
    }
    const outcome = await appraiseCollateral(
      { ...query(), origin: 'nvidia-rim', rimId: 'gpu-rim-0001' },
      { transport: neverAsked() },
    );
    expect(outcome.state).toBe('unavailable');
    if (!('refusal' in outcome)) throw new Error('an unread origin answered');
    expect(outcome.refusal.detail).toContain('intel-pck-crl and amd-kds');
  });
});
