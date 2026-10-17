import { describe, expect, it } from 'vitest';
import { sha256 } from '@noble/hashes/sha2.js';
import { parseCertificateChain } from '@ashaveri/attest-core';
import {
  foreignKey,
  secondsOf,
  servedChain,
  testVendor,
  type TestVendor,
} from '@ashaveri/fixtures';
import {
  INTEL_PCK_CRL,
  INTEL_TCB_INFO,
  appraiseCollateral,
  appraisePckCrl,
  collateralCacheKey,
  declarationFor,
  readPckCrl,
  readSignedCollateral,
  requestUrl,
  type CollateralClaim,
  type CollateralRefusal,
  type CollateralTransport,
  type PckCrlQuery,
  type RevocationList,
  type RevocationOutcome,
  type RevocationReadOutcome,
} from '../src/index.js';
import { writeCrl } from './crl-writer.js';

const THIS = secondsOf('2026-09-01T00:00:00Z');
const NEXT = secondsOf('2026-10-01T00:00:00Z');
const WITHIN = secondsOf('2026-09-15T00:00:00Z');
const AFTER = secondsOf('2026-11-15T00:00:00Z');
const OBSERVED = secondsOf('2026-09-15T06:00:00Z');
const SERIAL = '5b0bf77b49c75aaba21cf76ad14224c0514fdcf4';
const OTHER = '0badc0de';
const HEADER = INTEL_PCK_CRL.chainHeader as string;

const vendor = testVendor();

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function query(over: Partial<PckCrlQuery> = {}): PckCrlQuery {
  return {
    origin: 'intel-pck-crl',
    platform: 'sgx',
    cpuType: null,
    level: null,
    ca: 'processor',
    certificateSerial: SERIAL,
    appraisalAt: WITHIN,
    roots: [vendor.rootDer],
    retained: null,
    onAbsent: 'unassessed',
    ...over,
  };
}

function listOf(input: {
  readonly revoked?: readonly { readonly serial: string; readonly revokedAt: number; readonly reason?: number }[];
  readonly signer?: TestVendor;
  readonly signingKey?: Uint8Array;
  readonly algorithmOid?: string;
  readonly omitNextUpdate?: boolean;
  readonly trailing?: Uint8Array;
} = {}): Uint8Array {
  return writeCrl({
    vendor: input.signer ?? vendor,
    thisUpdate: THIS,
    nextUpdate: NEXT,
    revoked: input.revoked,
    signingKey: input.signingKey,
    algorithmOid: input.algorithmOid,
    omitNextUpdate: input.omitNextUpdate,
    trailing: input.trailing,
  });
}

function answering(body: Uint8Array, chain: Uint8Array | null): CollateralTransport {
  return async () => new Response(body, chain === null ? {} : { headers: { [HEADER]: new TextDecoder().decode(chain) } });
}

function neverAsked(): CollateralTransport {
  return async () => {
    throw new Error('a list this run did not fetch was read by asking the origin');
  };
}

async function ask(transport: CollateralTransport, over: Partial<PckCrlQuery> = {}): Promise<RevocationOutcome> {
  return appraisePckCrl(query(over), { transport, clock: () => OBSERVED });
}

function read(body: Uint8Array, chain: Uint8Array | null, over: Partial<PckCrlQuery> = {}): RevocationList {
  const asked = query(over);
  const result = readPckCrl(body, chain, { query: asked, declaration: INTEL_PCK_CRL, appraisalAt: asked.appraisalAt as number });
  if ('read' in result) {
    return result.read;
  }
  throw new Error(`the list was refused: ${result.refusal.code} ${result.refusal.detail}`);
}

function refusalOf(result: RevocationOutcome | RevocationReadOutcome): CollateralRefusal {
  if ('refusal' in result) {
    return result.refusal;
  }
  throw new Error('the answer carried no refusal');
}

/** The list and claim an answer carries, for a case that has already pinned which state it reached. */
function weighed(outcome: RevocationOutcome): { readonly list: RevocationList; readonly claim: CollateralClaim } {
  if (outcome.list === null || outcome.claim === null) {
    throw new Error(`the answer was ${outcome.state} and carried no list`);
  }
  return { list: outcome.list, claim: outcome.claim };
}

describe('the DER certificate list the PCK route serves', () => {
  it('reads the version, suite, issuer, window and revoked serials, and keeps the bytes it weighed', () => {
    const body = listOf({
      revoked: [
        { serial: SERIAL, revokedAt: THIS, reason: 1 },
        { serial: OTHER, revokedAt: THIS },
      ],
    });
    const list = read(body, servedChain(vendor));
    expect(list.version).toBe(2);
    expect(list.signatureAlgorithm).toBe('ecdsa-with-SHA256');
    expect(list.window).toEqual({ from: THIS, until: NEXT });
    expect(list.revoked).toHaveLength(2);
    expect(list.revoked[0]?.serialHex).toBe(SERIAL);
    expect(list.revoked[0]?.reasonCode).toBe(1);
    expect(list.revoked[0]?.reason).toBe('keyCompromise');
    expect(list.revoked[1]?.serialHex).toBe(BigInt(`0x${OTHER}`).toString(16));
    expect(list.revoked[1]?.reasonCode).toBeNull();
    expect(list.revoked[1]?.reason).toBeNull();
    expect(list.digest).toBe(hex(sha256(body)));
    expect(list.anchorDigest).toBe(vendor.rootDigest);
    expect(list.blobs).toHaveLength(3);
    expect(list.blobs[0]).toEqual(body);
    expect(list.blobs[1]).toEqual(vendor.issuerDer);
    expect(list.blobs[2]).toEqual(vendor.rootDer);
    const signer = parseCertificateChain(vendor.issuerDer)[0];
    expect(list.issuer).toEqual(signer?.subject);
  });

  it('answers not-listed for a current list that does not name the serial, without calling it current', async () => {
    const outcome = await ask(answering(listOf({ revoked: [{ serial: OTHER, revokedAt: THIS, reason: 1 }] }), servedChain(vendor)));
    expect(outcome.state).toBe('not-listed');
    expect('refusal' in outcome, 'a list that does not name the serial is not a refusal').toBe(false);
    const { list, claim } = weighed(outcome);
    expect(claim.reach).toBe('current-knowledge');
    expect(claim.observedAt).toBe(OBSERVED);
    expect(claim.retainUntil).toBe(NEXT);
    expect(claim.cacheKey).toBe('origin=intel-pck-crl|ca=processor');
    expect(list.revoked.map((entry) => entry.serialHex)).not.toContain(SERIAL);
  });

  it('answers revoked under COLLATERAL_REVOKED_BY_VENDOR for a current list that names the serial', async () => {
    const outcome = await ask(answering(listOf({ revoked: [{ serial: SERIAL, revokedAt: THIS, reason: 1 }] }), servedChain(vendor)));
    expect(outcome.state).toBe('revoked');
    if (!('refusal' in outcome)) throw new Error('a revocation carried no refusal');
    expect(outcome.refusal.code).toBe('COLLATERAL_REVOKED_BY_VENDOR');
    expect(outcome.refusal.verdict).toBe('terminal');
    expect(outcome.refusal.detail).toContain(SERIAL);
    expect(outcome.refusal.detail).toContain('keyCompromise');
    expect(weighed(outcome).claim.reach).toBe('current-knowledge');
  });

  it('answers WINDOW_CLOSED outside the list window, and reads a named serial as revoked even then', async () => {
    const absent = listOf({ revoked: [{ serial: OTHER, revokedAt: THIS }] });
    const stale = await ask(answering(absent, servedChain(vendor)), { appraisalAt: AFTER });
    expect(stale.state).toBe('stale');
    if (!('refusal' in stale)) throw new Error('a closed window carried no refusal');
    expect(stale.refusal.code).toBe('COLLATERAL_WINDOW_CLOSED');
    expect(weighed(stale).claim.reach).toBe('historical-knowledge');
    expect(weighed(stale).list.window).toEqual({ from: THIS, until: NEXT });

    const named = listOf({ revoked: [{ serial: SERIAL, revokedAt: THIS }] });
    const revoked = await ask(answering(named, servedChain(vendor)), { appraisalAt: AFTER });
    expect(revoked.state).toBe('revoked');
    if (!('refusal' in revoked)) throw new Error('a revocation carried no refusal');
    expect(revoked.refusal.code).toBe('COLLATERAL_REVOKED_BY_VENDOR');
    expect(weighed(revoked).claim.reach).toBe('historical-knowledge');
  });

  it('answers NOT_OBSERVED for a retained list, and reports no observation of its own', async () => {
    const body = listOf({ revoked: [{ serial: OTHER, revokedAt: THIS }] });
    const outcome = await ask(neverAsked(), {
      retained: { bytes: body, chain: servedChain(vendor), chainSha256: null, observedAt: OBSERVED },
    });
    expect(outcome.state).toBe('stale');
    if (!('refusal' in outcome)) throw new Error('a retained list carried no refusal');
    expect(outcome.refusal.code).toBe('COLLATERAL_NOT_OBSERVED');
    const { claim } = weighed(outcome);
    expect(claim.reach).toBe('historical-knowledge');
    expect(claim.observedAt).toBeNull();
    expect(claim.retainUntil).toBe(NEXT);
  });

  it('keeps a retained revocation a revocation, with its reach stated as historical', async () => {
    const body = listOf({ revoked: [{ serial: SERIAL, revokedAt: THIS, reason: 1 }] });
    const outcome = await ask(neverAsked(), {
      retained: { bytes: body, chain: servedChain(vendor), chainSha256: null, observedAt: OBSERVED },
    });
    expect(outcome.state).toBe('revoked');
    if (!('refusal' in outcome)) throw new Error('a retained revocation carried no refusal');
    expect(outcome.refusal.code).toBe('COLLATERAL_REVOKED_BY_VENDOR');
    const { claim } = weighed(outcome);
    expect(claim.reach).toBe('historical-knowledge');
    expect(claim.observedAt).toBeNull();
  });

  it('answers ANCHOR_NOT_PINNED for a substituted root and names the walk that stopped', async () => {
    const stranger = testVendor({ rootName: 'Another Root CA', issuerName: 'Another Platform CA' });
    const body = listOf({ signer: stranger });
    const outcome = await ask(answering(body, servedChain(stranger)));
    expect(outcome.state).toBe('unavailable');
    if (!('refusal' in outcome)) throw new Error('a substituted root carried no refusal');
    expect(outcome.refusal.code).toBe('COLLATERAL_ANCHOR_NOT_PINNED');
    expect(outcome.refusal.detail).toContain('pinned nothing');
  });

  it('answers SIGNATURE_UNVERIFIED for a tampered signature and for a key the chain did not issue', async () => {
    const body = listOf({ revoked: [{ serial: SERIAL, revokedAt: THIS }] });
    const tampered = body.slice();
    tampered[tampered.length - 1] = (tampered[tampered.length - 1] as number) ^ 0x01;
    for (const [name, bytes] of [
      ['tampered', tampered],
      ['foreign key', listOf({ signingKey: foreignKey() })],
    ] as const) {
      const outcome = await ask(answering(bytes, servedChain(vendor)));
      expect(outcome.state, name).toBe('unavailable');
      if (!('refusal' in outcome)) throw new Error(`${name} carried no refusal`);
      expect(outcome.refusal.code, name).toBe('COLLATERAL_SIGNATURE_UNVERIFIED');
    }
  });

  it('refuses an empty body and an oversize body with the unreadable-blob code', async () => {
    const empty = await ask(async () => new Response(new Uint8Array()));
    expect(empty.state).toBe('unavailable');
    expect(refusalOf(empty).code).toBe('COLLATERAL_BLOB_UNREADABLE');

    const oversize = await ask(async () => new Response(new Uint8Array(INTEL_PCK_CRL.maxResponseBytes + 1)));
    expect(oversize.state).toBe('unavailable');
    expect(refusalOf(oversize).code).toBe('COLLATERAL_BLOB_UNREADABLE');
    expect(refusalOf(oversize).detail).toContain(String(INTEL_PCK_CRL.maxResponseBytes));

    expect(refusalOf(readPckCrl(new Uint8Array(), servedChain(vendor), { query: query(), declaration: INTEL_PCK_CRL, appraisalAt: WITHIN })).code)
      .toBe('COLLATERAL_BLOB_UNREADABLE');
    const huge = new Uint8Array(INTEL_PCK_CRL.maxResponseBytes + 1);
    expect(refusalOf(readPckCrl(huge, servedChain(vendor), { query: query(), declaration: INTEL_PCK_CRL, appraisalAt: WITHIN })).code)
      .toBe('COLLATERAL_BLOB_UNREADABLE');
  });

  it('names the input a CRL question cannot be asked without', async () => {
    const body = listOf();
    const noSerial = await ask(answering(body, servedChain(vendor)), { certificateSerial: '' });
    expect(noSerial.state).toBe('missing-context');
    expect(refusalOf(noSerial).code).toBe('COLLATERAL_INPUT_MISSING');
    expect(refusalOf(noSerial).missing).toEqual(['certificateSerial']);

    const notHex = await ask(answering(body, servedChain(vendor)), { certificateSerial: 'zz' });
    expect(notHex.state).toBe('missing-context');
    expect(refusalOf(notHex).missing).toEqual(['certificateSerial']);

    const noRoots = await ask(answering(body, servedChain(vendor)), { roots: [] });
    expect(refusalOf(noRoots).code).toBe('COLLATERAL_ANCHOR_NOT_PINNED');

    const noInstant = await ask(answering(body, servedChain(vendor)), { appraisalAt: null });
    expect(refusalOf(noInstant).code).toBe('COLLATERAL_INPUT_MISSING');
    expect(refusalOf(noInstant).missing).toEqual(['appraisalAt']);

    const noScope = requestUrl({ ...query(), ca: null }, INTEL_PCK_CRL);
    if (typeof noScope === 'string') throw new Error('a CRL address was spelled without an authority scope');
    expect(noScope.refusal.code).toBe('COLLATERAL_INPUT_MISSING');
    expect(noScope.refusal.missing).toEqual(['ca']);
  });

  it('throws for a required CRL answer that could not be reached', async () => {
    await expect(appraisePckCrl(
      query({ certificateSerial: '', onAbsent: 'refuse' }),
      { transport: neverAsked() },
    )).rejects.toMatchObject({ code: 'COLLATERAL_INPUT_MISSING' });
  });

  it('keeps the CRL out of the platform-level appraisal and names the entry point that weighs it', async () => {
    const outcome = await appraiseCollateral(
      {
        ...query(),
        certificateSerial: SERIAL,
      },
      { transport: neverAsked() },
    );
    expect(outcome.state).toBe('missing-context');
    if (!('refusal' in outcome)) throw new Error('a CRL was appraised as a platform level');
    expect(outcome.refusal.code).toBe('COLLATERAL_INPUT_MISSING');
    expect(outcome.refusal.detail).toContain('appraisePckCrl');
  });
});

describe('the checks the outcomes rest on', () => {
  it('changes the window answer when only the appraisal instant moves', async () => {
    const body = listOf({ revoked: [{ serial: OTHER, revokedAt: THIS }] });
    const inside = await ask(answering(body, servedChain(vendor)), { appraisalAt: WITHIN });
    const outside = await ask(answering(body, servedChain(vendor)), { appraisalAt: AFTER });
    expect(inside.state).toBe('not-listed');
    expect(outside.state).toBe('stale');
    expect(refusalOf(outside).code).toBe('COLLATERAL_WINDOW_CLOSED');
    expect(weighed(inside).list.digest, 'the same bytes were weighed twice').toBe(weighed(outside).list.digest);
  });

  it('changes the revocation answer when only the revoked set gains the serial', async () => {
    const absent = listOf({ revoked: [{ serial: OTHER, revokedAt: THIS }] });
    const present = listOf({
      revoked: [
        { serial: OTHER, revokedAt: THIS },
        { serial: SERIAL, revokedAt: THIS, reason: 1 },
      ],
    });
    const before = await ask(answering(absent, servedChain(vendor)));
    const after = await ask(answering(present, servedChain(vendor)));
    expect(before.state).toBe('not-listed');
    expect(after.state).toBe('revoked');
    expect(refusalOf(after).code).toBe('COLLATERAL_REVOKED_BY_VENDOR');
  });

  it('compares a serial as a number, so case and padding do not change the answer', async () => {
    const body = listOf({ revoked: [{ serial: SERIAL, revokedAt: THIS, reason: 1 }] });
    for (const spelling of [SERIAL.toUpperCase(), `00${SERIAL}`, `0000${SERIAL.toUpperCase()}`]) {
      const outcome = await ask(answering(body, servedChain(vendor)), { certificateSerial: spelling });
      expect(outcome.state, spelling).toBe('revoked');
    }
  });
});

describe('the DER shape this reader refuses', () => {
  it('refuses trailing bytes, a missing nextUpdate, and an unsupported signature suite', () => {
    const trailing = listOf({ trailing: new Uint8Array([0, 0]) });
    expect(refusalOf(readPckCrl(trailing, servedChain(vendor), { query: query(), declaration: INTEL_PCK_CRL, appraisalAt: WITHIN })).code)
      .toBe('COLLATERAL_BLOB_UNREADABLE');

    const open = listOf({ omitNextUpdate: true });
    const openRead = readPckCrl(open, servedChain(vendor), { query: query(), declaration: INTEL_PCK_CRL, appraisalAt: WITHIN });
    expect(refusalOf(openRead).code).toBe('COLLATERAL_BLOB_UNREADABLE');
    expect(refusalOf(openRead).detail).toContain('nextUpdate');

    const wrongSuite = listOf({ algorithmOid: '1.2.840.10045.4.3.3' });
    const wrongRead = readPckCrl(wrongSuite, servedChain(vendor), { query: query(), declaration: INTEL_PCK_CRL, appraisalAt: WITHIN });
    expect(refusalOf(wrongRead).code).toBe('COLLATERAL_BLOB_UNREADABLE');
    expect(refusalOf(wrongRead).detail).toContain('ecdsa-with-SHA384');
  });

  it('refuses an unknown critical entry extension and skips one that is not critical', () => {
    const critical = writeCrl({
      vendor,
      thisUpdate: THIS,
      nextUpdate: NEXT,
      revoked: [{ serial: SERIAL, revokedAt: THIS, unknownCriticalExtension: true }],
    });
    const refused = readPckCrl(critical, servedChain(vendor), { query: query(), declaration: INTEL_PCK_CRL, appraisalAt: WITHIN });
    expect(refusalOf(refused).code).toBe('COLLATERAL_BLOB_UNREADABLE');
    expect(refusalOf(refused).detail).toContain('critical extension');

    const tolerated = writeCrl({
      vendor,
      thisUpdate: THIS,
      nextUpdate: NEXT,
      revoked: [{ serial: SERIAL, revokedAt: THIS, unknownExtension: true }],
    });
    expect(read(tolerated, servedChain(vendor)).revoked[0]?.serialHex).toBe(SERIAL);
  });

  it('refuses a list that arrived without a chain and one whose issuer the chain does not carry', () => {
    const body = listOf();
    const noChain = readPckCrl(body, null, { query: query(), declaration: INTEL_PCK_CRL, appraisalAt: WITHIN });
    expect(refusalOf(noChain).code).toBe('COLLATERAL_ANCHOR_NOT_PINNED');
    expect(refusalOf(noChain).detail).toContain(HEADER);

    const stranger = testVendor({ rootName: 'Chain Root', issuerName: 'Chain Platform CA' });
    const wrongChain = readPckCrl(body, servedChain(stranger), { query: query(), declaration: INTEL_PCK_CRL, appraisalAt: WITHIN });
    expect(refusalOf(wrongChain).code).toBe('COLLATERAL_SIGNATURE_UNVERIFIED');
    expect(refusalOf(wrongChain).detail).toContain('no certificate');
  });

  it('refuses a chain header that is no URL-encoded certificate chain', () => {
    const body = listOf();
    for (const chain of [new TextEncoder().encode('%E0%A4%A'), new TextEncoder().encode('no certificates here')]) {
      const refused = readPckCrl(body, chain, { query: query(), declaration: INTEL_PCK_CRL, appraisalAt: WITHIN });
      expect(refusalOf(refused).code).toBe('COLLATERAL_BLOB_UNREADABLE');
      expect(refusalOf(refused).detail).toContain(HEADER);
    }
  });

  it('refuses a list whose issuer name is worn by a certificate another key signed', () => {
    const body = listOf();
    const lookalike = testVendor();
    const refused = readPckCrl(body, servedChain(lookalike), { query: query(), declaration: INTEL_PCK_CRL, appraisalAt: WITHIN });
    expect(refusalOf(refused).code).toBe('COLLATERAL_SIGNATURE_UNVERIFIED');
  });
});

describe('the declaration the reader is wired through', () => {
  it('refuses the wrong arm as an unreadable envelope rather than an origin no reader answers', () => {
    const asJson = readSignedCollateral(listOf(), { query: query(), declaration: INTEL_PCK_CRL, appraisalAt: WITHIN });
    if (!('refusal' in asJson)) throw new Error('a CRL was read as a served JSON document');
    expect(asJson.refusal.code).toBe('COLLATERAL_BLOB_UNREADABLE');

    const asCrl = readPckCrl(listOf(), servedChain(vendor), { query: query(), declaration: INTEL_TCB_INFO, appraisalAt: WITHIN });
    expect(refusalOf(asCrl).code).toBe('COLLATERAL_BLOB_UNREADABLE');
  });

  it('names the CRL as read, spells its address and keys the list by its authority scope', () => {
    expect(declarationFor('intel-pck-crl')).toBe(INTEL_PCK_CRL);
    expect(INTEL_PCK_CRL.reader.as).toBe('der-certificate-list');
    expect(requestUrl(query(), INTEL_PCK_CRL)).toBe(
      'https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=processor&encoding=der',
    );
    expect(requestUrl(query({ ca: 'platform' }), INTEL_PCK_CRL)).toBe(
      'https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform&encoding=der',
    );
    expect(collateralCacheKey(query(), INTEL_PCK_CRL)).toBe('origin=intel-pck-crl|ca=processor');
    expect(INTEL_PCK_CRL.serialMember).toBe('certificateSerial');
  });
});
