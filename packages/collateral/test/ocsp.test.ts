import { describe, expect, it } from 'vitest';
import { foreignKey, secondsOf, testVendor, type TestVendor } from '@ashaveri/fixtures';
import {
  CollateralError,
  INTEL_TCB_INFO,
  NVIDIA_OCSP,
  NVIDIA_RIM,
  ORIGIN_DECLARATIONS,
  appraiseCollateral,
  appraiseOcspResponse,
  buildOcspRequest,
  collateralCacheKey,
  readOcspResponse,
  requestUrl,
  routesAnswerNow,
  type CollateralClaim,
  type CollateralErrorCode,
  type CollateralQuery,
  type CollateralRefusal,
  type CollateralTransport,
  type OcspCollateral,
  type OcspOutcome,
  type OcspQuery,
  type OriginDeclaration,
} from '../src/index.js';
import { sha256Hex } from '../src/bytes.js';
import { readTlv } from '../src/der.js';
import type { Reading } from '../src/read.js';
import { derNameOf, issuerKeyHashOf, issuerNameHashOf, ocspDevice, writeOcspResponse, type OcspInput } from './ocsp-writer.js';

/**
 * The answers one certificate's revocation question reaches, and the refusals each failure reaches instead.
 *
 * Every answer is written by `ocsp-writer.ts` and signed by a key drawn in the run that asks for it; nobody's
 * responder bytes are in this repository, and no test reaches a network: the transport is handed the bytes a
 * case wrote. The five claim classes each draw their own vendor, because a root pinned in one case is a
 * decision that case made, and one key standing behind all five answers would let a pass in one state be the
 * reason another state looked right.
 *
 * What each state may say is asserted beside the state itself, because the row's acceptance is about reach
 * rather than about a figure: `current` is the one state that carries no refusal and the estate's only current
 * knowledge about a revocation, `stale` carries the answer's bytes with the refusal that says why they speak for
 * a moment other than now, `revoked` carries the standing and the instant it states, and the two absences carry
 * nothing at all. None of them says a platform is trusted: a responder answer names one certificate.
 */

const THIS_UPDATE = secondsOf('2026-09-01T00:00:00Z');
const NEXT_UPDATE = secondsOf('2026-10-01T00:00:00Z');
const PRODUCED_AT = secondsOf('2026-09-01T06:00:00Z');
const REVOKED_AT = secondsOf('2026-08-20T00:00:00Z');
const WITHIN = secondsOf('2026-09-15T00:00:00Z');
const AFTER = secondsOf('2026-11-15T00:00:00Z');
const OBSERVED = secondsOf('2026-09-15T06:00:00Z');
const ADDRESS = 'https://ocsp.ndis.nvidia.com/';

/** One vendor, a device certificate under its CA, and the CA a question names as the issuer. */
interface Fixture {
  readonly vendor: TestVendor;
  readonly device: Uint8Array;
  readonly serialHex: string;
}

function fixture(): Fixture {
  const vendor = testVendor();
  const device = ocspDevice(vendor.issuerDer, vendor.signingKey, 0x5b0bf77b);
  return { vendor, device: device.der, serialHex: device.serialHex };
}

function answer(one: Fixture, over: Partial<OcspInput> = {}): Uint8Array {
  return writeOcspResponse({
    responder: one.vendor,
    certificate: one.device,
    issuer: one.vendor.issuerDer,
    producedAt: PRODUCED_AT,
    thisUpdate: THIS_UPDATE,
    nextUpdate: NEXT_UPDATE,
    ...over,
  });
}

function queryOf(one: Fixture, over: Partial<OcspQuery> = {}): OcspQuery {
  return {
    origin: 'ocsp',
    platform: 'sgx',
    cpuType: null,
    level: null,
    ocspCertificate: one.device,
    ocspIssuer: one.vendor.issuerDer,
    appraisalAt: WITHIN,
    roots: [one.vendor.rootDer],
    retained: null,
    onAbsent: 'unassessed',
    ...over,
  };
}

function readingOf(one: Fixture, appraisalAt = WITHIN, over: Partial<OcspQuery> = {}): Reading {
  return { query: queryOf(one, over), declaration: NVIDIA_OCSP, appraisalAt };
}

function readOutcome(one: Fixture, body: Uint8Array, appraisalAt = WITHIN, over: Partial<OcspQuery> = {}) {
  return readOcspResponse(body, readingOf(one, appraisalAt, over));
}

/** A transport answering the one route with the bytes a case names, and nothing else about the caller. */
function serving(bytes: Uint8Array): CollateralTransport {
  return async () => new Response(bytes);
}

function silence(): CollateralTransport {
  return async () => {
    throw new Error('the test transport was asked');
  };
}

function recording(reply: () => Response): {
  readonly transport: CollateralTransport;
  readonly seen: { readonly url: string; readonly init: RequestInit }[];
} {
  const seen: { url: string; init: RequestInit }[] = [];
  const transport: CollateralTransport = async (input, init = {}) => {
    seen.push({ url: String(input), init });
    return reply();
  };
  return { transport, seen };
}

/**
 * The refusal a result carries, whichever of the two shapes it arrived in.
 *
 * A reader answers with the statement it believed or with the refusal that says why nothing was believed, and an
 * appraisal answers with a state beside one or the other, so both are read through these two helpers. `read` is
 * the reader's half and is named so the shape the case reached is the case's business, not the helper's.
 */
function refusalOf(
  result: { readonly refusal?: CollateralRefusal; readonly state?: string; readonly read?: unknown },
): CollateralRefusal {
  if (result.refusal === undefined) {
    throw new Error(`the answer was ${result.state ?? 'a read with no refusal beside it'}`);
  }
  return result.refusal;
}

function codeOf(result: { readonly refusal?: CollateralRefusal; readonly state?: string; readonly read?: unknown }): CollateralErrorCode {
  return refusalOf(result).code;
}

/** The collateral and claim an answer carries, for a case that has already pinned which state it reached. */
function weighed(outcome: OcspOutcome): { readonly collateral: OcspCollateral; readonly claim: CollateralClaim } {
  if (outcome.collateral === null || outcome.claim === null) {
    throw new Error(`the answer was ${outcome.state} and carried no bytes`);
  }
  return { collateral: outcome.collateral, claim: outcome.claim };
}

describe('the five answers one certificate question reaches', () => {
  it('reports current knowledge for an answer this run asked, inside its own window', async () => {
    const one = fixture();
    const body = answer(one);
    const outcome = await appraiseOcspResponse(queryOf(one), { transport: serving(body), clock: () => OBSERVED });
    expect(outcome.state).toBe('current');
    const { collateral, claim } = weighed(outcome);
    expect('refusal' in outcome).toBe(false);
    expect(claim.reach).toBe('current-knowledge');
    expect(claim.appraisalAt).toBe(WITHIN);
    expect(claim.observedAt).toBe(OBSERVED);
    expect(claim.retainUntil).toBe(NEXT_UPDATE);
    expect(claim.cacheKey).toBe(`origin=ocsp|ocspCertificate=${sha256Hex(one.device)}`);
    expect(collateral.certStatus).toBe('good');
    expect(collateral.serialHex).toBe(one.serialHex);
    expect(collateral.revokedAt).toBeNull();
    expect(collateral.reasonCode).toBeNull();
    expect(collateral.reason).toBeNull();
    expect(collateral.digest).toBe(sha256Hex(body));
    expect(collateral.anchorDigest).toBe(sha256Hex(one.vendor.rootDer));
    expect(collateral.classification.readAs).toBe('trusted');
    expect(collateral.classification.window).toEqual({ from: THIS_UPDATE, until: NEXT_UPDATE });
    expect(collateral.classification.signedAt).toBe(PRODUCED_AT);
    expect(collateral.declared).toEqual({ cpuType: null, vendorStatus: 'good' });
    expect(collateral.blobs[0]).toEqual(body);
  });

  it('reports current knowledge for a byKey responder identity, the other half of the same answer', async () => {
    const one = fixture();
    const outcome = await appraiseOcspResponse(queryOf(one), {
      transport: serving(answer(one, { responderBy: 'key' })),
      clock: () => OBSERVED,
    });
    expect(outcome.state).toBe('current');
    expect(weighed(outcome).collateral.anchorDigest).toBe(sha256Hex(one.vendor.rootDer));
  });

  it('closes the window rather than passing the certificate when the answer speaks for another moment', async () => {
    const one = fixture();
    const outcome = await appraiseOcspResponse(queryOf(one, { appraisalAt: AFTER }), {
      transport: serving(answer(one)),
      clock: () => OBSERVED,
    });
    expect(outcome.state).toBe('stale');
    const { collateral, claim } = weighed(outcome);
    expect(codeOf(outcome)).toBe('COLLATERAL_WINDOW_CLOSED');
    expect(claim.reach).toBe('historical-knowledge');
    expect(claim.observedAt).toBe(OBSERVED);
    expect(collateral.certStatus).toBe('good');
    expect(refusalOf(outcome).detail).toContain('2026-10-01T00:00:00.000Z');
  });

  it('refuses observation for bytes a store handed rather than an answer this run watched land', async () => {
    const one = fixture();
    const body = answer(one);
    const outcome = await appraiseOcspResponse(queryOf(one, {
      retained: { bytes: body, chain: null, chainSha256: null, observedAt: OBSERVED },
    }), { transport: silence(), clock: () => OBSERVED });
    expect(outcome.state).toBe('stale');
    const { collateral, claim } = weighed(outcome);
    expect(codeOf(outcome)).toBe('COLLATERAL_NOT_OBSERVED');
    expect(claim.reach).toBe('historical-knowledge');
    expect(claim.observedAt).toBeNull();
    expect(refusalOf(outcome).missing).toEqual(['retained']);
    expect(collateral.digest).toBe(sha256Hex(body));
  });

  it('states a revoked standing as current knowledge when this run asked, with the instant it carries', async () => {
    const one = fixture();
    const outcome = await appraiseOcspResponse(queryOf(one), {
      transport: serving(answer(one, { status: 'revoked', revokedAt: REVOKED_AT })),
      clock: () => OBSERVED,
    });
    expect(outcome.state).toBe('revoked');
    const { collateral, claim } = weighed(outcome);
    expect(codeOf(outcome)).toBe('COLLATERAL_REVOKED_BY_VENDOR');
    expect(claim.reach).toBe('current-knowledge');
    expect(collateral.certStatus).toBe('revoked');
    expect(collateral.classification.readAs).toBe('revoked');
    expect(collateral.revokedAt).toBe(REVOKED_AT);
    expect(refusalOf(outcome).detail).toContain(one.serialHex);
    expect(refusalOf(outcome).detail).toContain('2026-08-20T00:00:00.000Z');
  });

  it('keeps an archived revocation historical, because nobody here watched the bytes arrive', async () => {
    const one = fixture();
    const body = answer(one, { status: 'revoked', revokedAt: REVOKED_AT });
    const outcome = await appraiseOcspResponse(queryOf(one, {
      retained: { bytes: body, chain: null, chainSha256: null, observedAt: OBSERVED },
    }), { transport: silence(), clock: () => OBSERVED });
    expect(outcome.state).toBe('revoked');
    const { claim } = weighed(outcome);
    expect(codeOf(outcome)).toBe('COLLATERAL_REVOKED_BY_VENDOR');
    expect(claim.reach).toBe('historical-knowledge');
    expect(claim.observedAt).toBeNull();
  });

  it('reads a reason the package honours as the revocation it names, and carries it beside the answer', async () => {
    const one = fixture();
    const outcome = await appraiseOcspResponse(queryOf(one), {
      transport: serving(answer(one, { status: 'revoked', revokedAt: REVOKED_AT, revokedReason: 1 })),
      clock: () => OBSERVED,
    });
    expect(outcome.state).toBe('revoked');
    const { collateral } = weighed(outcome);
    expect(codeOf(outcome)).toBe('COLLATERAL_REVOKED_BY_VENDOR');
    expect(collateral.reasonCode).toBe(1);
    expect(collateral.reason).toBe('keyCompromise');
    expect(refusalOf(outcome).detail).toContain('keyCompromise');
  });

  it('refuses a removeFromCRL reason rather than reading a removal as a revocation', async () => {
    const one = fixture();
    const outcome = await appraiseOcspResponse(queryOf(one), {
      transport: serving(answer(one, { status: 'revoked', revokedAt: REVOKED_AT, revokedReason: 8 })),
      clock: () => OBSERVED,
    });
    expect(outcome.state).toBe('unavailable');
    expect(codeOf(outcome)).toBe('COLLATERAL_STATUS_UNSUPPORTED');
    expect(refusalOf(outcome).detail).toContain('removeFromCRL');
    expect(refusalOf(outcome).detail).toContain(one.serialHex);
    expect(outcome.collateral, 'a refusal of a removal keeps no answer and reads no revocation').toBeNull();
    expect(outcome.claim).toBeNull();

    const kept = await appraiseOcspResponse(queryOf(one, {
      retained: { bytes: answer(one, { status: 'revoked', revokedAt: REVOKED_AT, revokedReason: 8 }), chain: null, chainSha256: null, observedAt: OBSERVED },
    }), { transport: silence(), clock: () => OBSERVED });
    expect(kept.state).toBe('unavailable');
    expect(codeOf(kept)).toBe('COLLATERAL_STATUS_UNSUPPORTED');

    const asked = readOutcome(one, answer(one, { status: 'revoked', revokedAt: REVOKED_AT, revokedReason: 8 }));
    if ('read' in asked) {
      expect(asked.read.reasonCode).toBe(8);
      expect(asked.read.reason).toBe('removeFromCRL');
    } else {
      throw new Error('the reader refuses an answer the classification is the half that decides');
    }
  });

  it('names an unassigned reason code as the number it states rather than sorting it into a nearer reason', async () => {
    const one = fixture();
    const outcome = await appraiseOcspResponse(queryOf(one), {
      transport: serving(answer(one, { status: 'revoked', revokedAt: REVOKED_AT, revokedReason: 7 })),
      clock: () => OBSERVED,
    });
    expect(outcome.state).toBe('revoked');
    const { collateral } = weighed(outcome);
    expect(codeOf(outcome)).toBe('COLLATERAL_REVOKED_BY_VENDOR');
    expect(collateral.reasonCode).toBe(7);
    expect(collateral.reason).toBeNull();
    expect(refusalOf(outcome).detail).toContain('reason code 7');
  });

  it('answers a standing it has no rule for as absence, with no bytes and no claim beside it', async () => {
    const one = fixture();
    const outcome = await appraiseOcspResponse(queryOf(one), {
      transport: serving(answer(one, { status: 'unknown' })),
      clock: () => OBSERVED,
    });
    expect(outcome.state).toBe('unavailable');
    expect(codeOf(outcome)).toBe('COLLATERAL_STATUS_UNSUPPORTED');
    expect(outcome.collateral).toBeNull();
    expect(outcome.claim).toBeNull();
    expect(refusalOf(outcome).detail).toContain('unknown');
  });

  it('refuses outright when the appraisal requires the answer and the answer is absent', async () => {
    const one = fixture();
    const asked = appraiseOcspResponse(queryOf(one, { onAbsent: 'refuse' }), { transport: silence() });
    await expect(asked).rejects.toBeInstanceOf(CollateralError);
    await expect(asked).rejects.toMatchObject({ code: 'COLLATERAL_ORIGIN_UNREACHABLE' });
  });

  it('names the entry point that weighs an answer when the platform-level appraisal is asked instead', async () => {
    const one = fixture();
    const outcome = await appraiseCollateral(queryOf(one), { transport: silence() });
    expect(outcome.state).toBe('missing-context');
    expect(codeOf(outcome)).toBe('COLLATERAL_INPUT_MISSING');
    expect(refusalOf(outcome).detail).toContain('appraiseOcspResponse');
  });
});

describe('the missing context a certificate question can state', () => {
  it('refuses a verdict asked with no root pinned', async () => {
    const one = fixture();
    const outcome = await appraiseOcspResponse(queryOf(one, { roots: [] }), { transport: silence() });
    expect(outcome.state).toBe('missing-context');
    expect(codeOf(outcome)).toBe('COLLATERAL_ANCHOR_NOT_PINNED');
    expect(refusalOf(outcome).missing).toEqual(['roots']);
  });

  it('refuses a question that names no instant to appraise at', async () => {
    const one = fixture();
    const outcome = await appraiseOcspResponse(queryOf(one, { appraisalAt: null }), { transport: silence() });
    expect(outcome.state).toBe('missing-context');
    expect(codeOf(outcome)).toBe('COLLATERAL_INPUT_MISSING');
    expect(refusalOf(outcome).missing).toEqual(['appraisalAt']);
  });

  it('refuses empty bytes on either half of the pair, before the responder is asked', async () => {
    const one = fixture();
    for (const [member, over] of [['ocspCertificate', { ocspCertificate: new Uint8Array(0) }], ['ocspIssuer', { ocspIssuer: new Uint8Array(0) }]] as const) {
      const outcome = await appraiseOcspResponse(queryOf(one, over), { transport: silence() });
      expect(outcome.state, member).toBe('missing-context');
      expect(codeOf(outcome), member).toBe('COLLATERAL_INPUT_MISSING');
      expect(refusalOf(outcome).missing, member).toEqual([member]);
    }
    const kept = await appraiseOcspResponse(queryOf(one, {
      retained: { bytes: new Uint8Array(0), chain: null, chainSha256: null, observedAt: OBSERVED },
    }), { transport: silence() });
    expect(codeOf(kept)).toBe('COLLATERAL_INPUT_MISSING');
    expect(refusalOf(kept).missing).toEqual(['retained.bytes']);
  });

  it('names the certificate and issuer an address cannot be built without, and spells it once both are stated', () => {
    const one = fixture();
    const bare: CollateralQuery = { ...queryOf(one), ocspCertificate: null, ocspIssuer: null };
    const missing = requestUrl(bare, NVIDIA_OCSP);
    if (typeof missing === 'string') throw new Error('an OCSP address was spelled with no question');
    expect(missing.refusal.code).toBe('COLLATERAL_INPUT_MISSING');
    expect(missing.refusal.missing).toEqual(['ocspCertificate', 'ocspIssuer']);
    const asked = requestUrl({ ...bare, ocspCertificate: one.device, ocspIssuer: one.vendor.issuerDer }, NVIDIA_OCSP);
    expect(asked).toBe(ADDRESS);
  });

  it('keys a kept answer by the certificate it answers for, and never by the moment it was read', () => {
    const one = fixture();
    const key = collateralCacheKey(queryOf(one), NVIDIA_OCSP);
    expect(key).toBe(`origin=ocsp|ocspCertificate=${sha256Hex(one.device)}`);
    expect(collateralCacheKey({ ...queryOf(one), appraisalAt: AFTER }, NVIDIA_OCSP)).toBe(key);
    expect(NVIDIA_OCSP.cache.keyMembers).toEqual(['origin', 'ocspCertificate']);
    expect(NVIDIA_OCSP.cache.answersCurrentQuestions).toBe(false);
    expect(NVIDIA_OCSP.cache.retainUntil).toBe('vendor-next-update');
  });
});

describe('what the reader refuses before it believes anything', () => {
  const one = fixture();

  it('refuses an answer signed with a key the issuer chain did not issue', () => {
    expect(codeOf(readOutcome(one, answer(one, { signingKey: foreignKey() }))))
      .toBe('COLLATERAL_SIGNATURE_UNVERIFIED');
  });

  it('refuses a verdict whose pinned bytes hold no certificate, because nothing was pinned', () => {
    expect(codeOf(readOutcome(one, answer(one), WITHIN, { roots: [Uint8Array.from([1, 2, 3, 4])] })))
      .toBe('COLLATERAL_ANCHOR_NOT_PINNED');
  });

  /**
   * A second vendor drawn with the fixture's own default names is a chain wearing a trusted name over another
   * key, which is the one thing a walk must not read as an anchor. The refusal says the certificate above the
   * answer did not sign it, which is the truth of it and not a report that nothing was pinned.
   */
  it('refuses an answer whose chain reaches a name pinned under another key', () => {
    const other = testVendor();
    expect(codeOf(readOutcome(one, answer(one), WITHIN, { roots: [other.rootDer] })))
      .toBe('COLLATERAL_SIGNATURE_UNVERIFIED');
  });

  it('refuses an answer at a moment its own issuer does not stand at', () => {
    expect(codeOf(readOutcome(one, answer(one), secondsOf('2024-01-01T00:00:00Z'))))
      .toBe('COLLATERAL_SIGNATURE_UNVERIFIED');
  });

  it('refuses a responder identity that is not the issuer the question names, in either spelling', () => {
    // A vendor under its own names, because two vendors that share a distinguished name differ only by key and
    // a name hash taken over either is the same hash.
    const stranger = testVendor({ rootName: 'Ashaveri Test Stranger Root CA', issuerName: 'Ashaveri Test Stranger CA' });
    const named = codeOf(readOutcome(one, answer(one, { responderName: derNameOf(stranger.issuerDer) })));
    expect(named).toBe('COLLATERAL_SIGNATURE_UNVERIFIED');
    const keyed = codeOf(readOutcome(one, answer(one, { responderBy: 'key', responderHash: issuerKeyHashOf(stranger.issuerDer) })));
    expect(keyed).toBe('COLLATERAL_SIGNATURE_UNVERIFIED');
  });

  it('refuses a delegated responder certificate rather than believing an extension it does not read', () => {
    const delegated = testVendor();
    const outcome = readOutcome(one, answer(one, { presentCerts: [delegated.issuerDer] }));
    expect(codeOf(outcome)).toBe('COLLATERAL_SIGNATURE_UNVERIFIED');
    expect(refusalOf(outcome).detail).toContain('delegated by extension');
  });

  it('believes an answer that presents its own issuer byte for byte, and keeps those bytes beside it', () => {
    const body = answer(one, { presentCerts: [one.vendor.issuerDer] });
    const outcome = readOutcome(one, body);
    if ('refusal' in outcome) throw new Error(`the issuer's own certificate was refused: ${outcome.refusal.detail}`);
    expect(outcome.read.blobs).toEqual([body, one.vendor.issuerDer]);
  });

  it('refuses a suite this path weighs nowhere, and names the one it reads', () => {
    const outcome = readOutcome(one, answer(one, { suiteOid: '1.2.840.10045.4.3.3' }));
    expect(codeOf(outcome)).toBe('COLLATERAL_SIGNATURE_UNVERIFIED');
    expect(refusalOf(outcome).detail).toContain('ecdsa-sha256');
  });

  it('binds the answer to the certificate asked about, one member of the CertID at a time', () => {
    const stranger = testVendor({ rootName: 'Ashaveri Test Other Root CA', issuerName: 'Ashaveri Test Other CA' });
    const otherDevice = ocspDevice(stranger.issuerDer, stranger.signingKey, 0x0badc0de);
    const forged: readonly (readonly [string, Partial<OcspInput>])[] = [
      ['issuerNameHash', { nameHash: issuerNameHashOf(stranger.issuerDer) }],
      ['issuerKeyHash', { keyHash: issuerKeyHashOf(stranger.issuerDer) }],
      ['serialNumber', { serialHex: otherDevice.serialHex }],
    ];
    for (const [member, over] of forged) {
      const outcome = readOutcome(one, answer(one, over));
      expect(codeOf(outcome), member).toBe('COLLATERAL_IDENTITY_MISMATCH');
    }
  });

  it('refuses a pair the question states that cannot exist, before the responder is asked', async () => {
    const asked = fixture();
    const stranger = testVendor({ rootName: 'Ashaveri Test Unrelated Root CA', issuerName: 'Ashaveri Test Unrelated CA' });
    const outcome = await appraiseOcspResponse(queryOf(asked, { ocspIssuer: stranger.issuerDer }), { transport: silence() });
    expect(outcome.state).toBe('unavailable');
    expect(codeOf(outcome)).toBe('COLLATERAL_IDENTITY_MISMATCH');
    expect(refusalOf(outcome).missing).toEqual(['ocspIssuer']);
  });

  it('refuses a hash algorithm this path states no rule for comparing', () => {
    const outcome = readOutcome(one, answer(one, { hashOid: '2.16.840.1.101.3.4.2.1' }));
    expect(codeOf(outcome)).toBe('COLLATERAL_BLOB_UNREADABLE');
    expect(refusalOf(outcome).detail).toContain('2.16.840.1.101.3.4.2.1');
  });

  it('refuses a response type this path reads no rule for, and a version it has no reading for', () => {
    expect(codeOf(readOutcome(one, answer(one, { respTypeOid: '1.3.6.1.5.5.7.48.1.2' }))))
      .toBe('COLLATERAL_BLOB_UNREADABLE');
    expect(codeOf(readOutcome(one, answer(one, { version: 1 }))))
      .toBe('COLLATERAL_BLOB_UNREADABLE');
  });

  it('refuses an answer that speaks about more than the certificate asked about, or about none', () => {
    expect(codeOf(readOutcome(one, answer(one, { entries: 2 })))).toBe('COLLATERAL_BLOB_UNREADABLE');
    expect(codeOf(readOutcome(one, answer(one, { entries: 0 })))).toBe('COLLATERAL_BLOB_UNREADABLE');
  });

  it('refuses an answer that states no end to its own reach, or one that closes before it opens', () => {
    const none = readOutcome(one, answer(one, { nextUpdate: null }));
    expect(codeOf(none)).toBe('COLLATERAL_BLOB_UNREADABLE');
    expect(refusalOf(none).detail).toContain('nextUpdate');
    expect(codeOf(readOutcome(one, answer(one, { nextUpdate: THIS_UPDATE })))).toBe('COLLATERAL_BLOB_UNREADABLE');
  });

  it('refuses a critical extension it does not know, by the OID it carries', () => {
    const outcome = readOutcome(one, answer(one, { unknownCriticalExtension: true }));
    expect(codeOf(outcome)).toBe('COLLATERAL_BLOB_UNREADABLE');
    expect(refusalOf(outcome).detail).toContain('critical extension 1.2.3.4.5');
  });

  it('refuses a body that is not an answer, and one wider than the cap this path reads', () => {
    for (const body of [new Uint8Array(0), new TextEncoder().encode('not der'), Uint8Array.from([0x30, 0x03, 0x02, 0x01, 0x07])]) {
      expect(codeOf(readOutcome(one, body))).toBe('COLLATERAL_BLOB_UNREADABLE');
    }
    const oversized = new Uint8Array(NVIDIA_OCSP.maxResponseBytes + 1);
    oversized.set(answer(one));
    expect(codeOf(readOutcome(one, oversized))).toBe('COLLATERAL_BLOB_UNREADABLE');
  });

  it('refuses trailing bytes after the answer, and no answer at all beside a successful status', () => {
    expect(codeOf(readOutcome(one, answer(one, { trailing: Uint8Array.of(0x00) })))).toBe('COLLATERAL_BLOB_UNREADABLE');
    expect(codeOf(readOutcome(one, answer(one, { omitResponseBytes: true })))).toBe('COLLATERAL_BLOB_UNREADABLE');
  });

  it('refuses a standing carrying bytes where RFC 6960 states a NULL, in either of the two shapes', () => {
    const one = fixture();
    const good = readOutcome(one, answer(one, { standing: Uint8Array.of(0x80, 0x01, 0x00) }));
    expect(codeOf(good)).toBe('COLLATERAL_BLOB_UNREADABLE');
    expect(refusalOf(good).detail).toContain('certStatus');
    const unknown = readOutcome(one, answer(one, { standing: Uint8Array.of(0x82, 0x01, 0x00) }));
    expect(codeOf(unknown)).toBe('COLLATERAL_BLOB_UNREADABLE');
    expect(refusalOf(unknown).detail).toContain('certStatus');
  });

  it('refuses a revoked standing carrying more than the instant and the reason, and answers rather than throws', () => {
    const one = fixture();
    // The one member RFC 6960 puts after `revocationTime` is `revocationReason`, so a bytes-after-the-instant is
    // refused under the slot the standard states there; a trailing element beside a reason that slot has filled
    // is refused as the standing's own trailing data.
    const extra = readOutcome(one, answer(one, {
      status: 'revoked',
      revokedAt: REVOKED_AT,
      revokedExtra: Uint8Array.of(0x05, 0x00),
    }));
    expect(codeOf(extra)).toBe('COLLATERAL_BLOB_UNREADABLE');
    expect(refusalOf(extra).detail).toContain('revocationReason');

    const pastReason = readOutcome(one, answer(one, {
      status: 'revoked',
      revokedAt: REVOKED_AT,
      revokedReason: 1,
      revokedExtra: Uint8Array.of(0x05, 0x00),
    }));
    expect(codeOf(pastReason)).toBe('COLLATERAL_BLOB_UNREADABLE');
    expect(refusalOf(pastReason).detail).toContain('trailing data inside the revoked standing');
  });

  it('answers a status that is not successful with the origin refusal, and names which one it was', () => {
    const statuses: readonly (readonly [number, string])[] = [
      [1, 'malformedRequest'],
      [2, 'internalError'],
      [3, 'tryLater'],
      [5, 'sigRequired'],
      [6, 'unauthorized'],
    ];
    for (const [status, named] of statuses) {
      const outcome = readOutcome(one, answer(one, { responseStatus: status }));
      expect(codeOf(outcome), String(status)).toBe('COLLATERAL_ORIGIN_REFUSED');
      expect(refusalOf(outcome).detail, String(status)).toContain(named);
    }
    const figure = refusalOf(readOutcome(one, answer(one, { responseStatus: 42 }))).detail;
    expect(figure).toContain('status 42');
  });

  it('refuses the answer of an origin this reader has no arm for', () => {
    const body = answer(one);
    const served: readonly OriginDeclaration[] = [INTEL_TCB_INFO, ORIGIN_DECLARATIONS['amd-kds'], ORIGIN_DECLARATIONS['nvidia-rim']];
    for (const declaration of served) {
      const outcome = readOcspResponse(body, { ...readingOf(one), query: { ...queryOf(one), origin: declaration.name }, declaration });
      // An origin with a reader here is supported, so what this arm cannot weigh is the envelope, not the origin.
      expect(codeOf(outcome), declaration.name).toBe('COLLATERAL_BLOB_UNREADABLE');
      expect(refusalOf(outcome).detail, declaration.name).toContain(declaration.answer);
    }
    // The refusal for a declaration that states no reader at all is reachable only through a declaration of
    // that shape, because every origin this package declares now has an arm weighing some answer of it.
    const unread = readOcspResponse(body, {
      query: { ...queryOf(one), origin: 'nvidia-rim' },
      declaration: { ...NVIDIA_RIM, reader: { as: 'declared-only', lacks: 'an arm for a DER response' } },
      appraisalAt: WITHIN,
    });
    expect(codeOf(unread)).toBe('COLLATERAL_ORIGIN_UNSUPPORTED');
  });
});

describe('the question this path writes', () => {
  const one = fixture();

  it('posts the built question to the declared host with the two types RFC 6960 names apart', async () => {
    const { transport, seen } = recording(() => new Response(answer(one)));
    const outcome = await appraiseOcspResponse(queryOf(one), { transport, clock: () => OBSERVED });
    expect(outcome.state).toBe('current');
    const asked = seen[0] as { url: string; init: RequestInit };
    expect(asked.url).toBe(ADDRESS);
    expect(asked.init.method).toBe('POST');
    expect(asked.init.redirect).toBe('error');
    expect(asked.init.signal).toBeDefined();
    const headers = new Headers(asked.init.headers);
    expect(headers.get('content-type')).toBe(NVIDIA_OCSP.requestMediaType);
    expect(headers.get('accept')).toBe(NVIDIA_OCSP.mediaType);
    expect([...headers.keys()].sort()).toEqual(['accept', 'content-type']);
    const built = buildOcspRequest(one.device, one.vendor.issuerDer, NVIDIA_OCSP);
    if ('refusal' in built) throw new Error(`the question was refused: ${built.refusal.detail}`);
    expect(asked.init.body).toEqual(built);
  });

  /**
   * The question is read back here rather than compared against a stored sample: its `CertID` carries the same
   * two hashes and one serial the reader compares an answer against, so a writer and a reader that disagreed
   * would be asking and answering two different questions, and no stored bytes of anybody's responder are kept
   * to compare against in the first place.
   */
  it('writes the question as the nesting and the members RFC 6960 states', () => {
    const built = buildOcspRequest(one.device, one.vendor.issuerDer, NVIDIA_OCSP);
    if ('refusal' in built) throw new Error(`the question was refused: ${built.refusal.detail}`);
    const request = readTlv(built, 0, built.byteLength, 'OCSPRequest');
    expect(request.end).toBe(built.byteLength);
    const tbs = readTlv(built, request.contentStart, request.end, 'tbsRequest');
    const list = readTlv(built, tbs.contentStart, tbs.end, 'requestList');
    const single = readTlv(built, list.contentStart, list.end, 'Request');
    const certId = readTlv(built, single.contentStart, single.end, 'CertID');
    expect(certId.end).toBe(single.end);
    const algorithm = readTlv(built, certId.contentStart, certId.end, 'hashAlgorithm');
    const name = readTlv(built, algorithm.end, certId.end, 'issuerNameHash');
    const key = readTlv(built, name.end, certId.end, 'issuerKeyHash');
    const serial = readTlv(built, key.end, certId.end, 'serialNumber');
    expect(name.end - name.contentStart).toBe(20);
    expect(key.end - key.contentStart).toBe(20);
    expect(built.slice(name.contentStart, name.end)).toEqual(issuerNameHashOf(one.vendor.issuerDer));
    expect(built.slice(key.contentStart, key.end)).toEqual(issuerKeyHashOf(one.vendor.issuerDer));
    expect(serial.end).toBe(certId.end);
  });

  it('refuses to write a question for bytes that are not one certificate each', () => {
    const notDer = buildOcspRequest(new TextEncoder().encode('nope'), one.vendor.issuerDer, NVIDIA_OCSP);
    if (!('refusal' in notDer)) throw new Error('a question was built from bytes that do not parse');
    expect(notDer.refusal.code).toBe('COLLATERAL_BLOB_UNREADABLE');

    const doubled = new Uint8Array(one.device.byteLength * 2);
    doubled.set(one.device);
    doubled.set(one.device, one.device.byteLength);
    const pair = buildOcspRequest(doubled, one.vendor.issuerDer, NVIDIA_OCSP);
    if (!('refusal' in pair)) throw new Error('a question was built from two certificates at once');
    expect(pair.refusal.detail).toContain('holds 2 certificates');
  });

  it('reads the reach off the route, which is what makes an answer asked now a current one', () => {
    expect(routesAnswerNow(NVIDIA_OCSP)).toBe(true);
    expect(routesAnswerNow({
      ...NVIDIA_OCSP,
      routes: NVIDIA_OCSP.routes.map((route) => ({ ...route, knowledge: 'historical' as const })),
    })).toBe(false);
  });

  it('asks nothing when the origin does not answer, and reports a refusal rather than a pass', async () => {
    const unreachable = await appraiseOcspResponse(queryOf(one), { transport: silence() });
    expect(unreachable.state).toBe('unavailable');
    expect(codeOf(unreachable)).toBe('COLLATERAL_ORIGIN_UNREACHABLE');
    expect(unreachable.collateral).toBeNull();

    const refused = await appraiseOcspResponse(queryOf(one), { transport: async () => new Response('no', { status: 403 }) });
    expect(refused.state).toBe('unavailable');
    expect(codeOf(refused)).toBe('COLLATERAL_ORIGIN_REFUSED');
    expect(refusalOf(refused).verdict).toBe('retryable');
  });
});

/**
 * The five claim classes read as one list of pairs, because the acceptance names all five and the honest part of
 * each answer is the pair of figures it carries: the reach and the refusal that travels beside it. A state that
 * reported one without the other is the failure this case is written to catch, and each entry draws its own
 * vendor so no two of the five lean on the same pinned root.
 */
describe('what each state may say', () => {
  /** The state, its reach and its refusal as one line, so the five read against each other rather than past each other. */
  function shape(outcome: OcspOutcome): string {
    return `${outcome.state}:${outcome.claim?.reach ?? 'none'}:${'refusal' in outcome ? outcome.refusal.code : 'none'}`;
  }

  async function classify(
    one: Fixture,
    over: Partial<OcspQuery>,
    answerOver: Partial<OcspInput>,
    transport: (body: Uint8Array) => CollateralTransport,
  ): Promise<string> {
    const body = answer(one, answerOver);
    return shape(await appraiseOcspResponse(queryOf(one, over), { transport: transport(body), clock: () => OBSERVED }));
  }

  it('holds each state to the reach and the refusal it is allowed to carry', async () => {
    const reached = [
      await classify(fixture(), {}, {}, serving),
      await classify(fixture(), { appraisalAt: AFTER }, {}, serving),
      await classify(fixture(), {}, { status: 'revoked', revokedAt: REVOKED_AT }, serving),
      await classify(fixture(), {}, { status: 'unknown' }, serving),
      await classify(fixture(), { roots: [] }, {}, () => silence()),
    ];
    expect(reached).toEqual([
      'current:current-knowledge:none',
      'stale:historical-knowledge:COLLATERAL_WINDOW_CLOSED',
      'revoked:current-knowledge:COLLATERAL_REVOKED_BY_VENDOR',
      'unavailable:none:COLLATERAL_STATUS_UNSUPPORTED',
      'missing-context:none:COLLATERAL_ANCHOR_NOT_PINNED',
    ]);
  });

  it('keeps the same signed answer historical, and its refusal about the observation, when no origin was asked', async () => {
    const one = fixture();
    const body = answer(one);
    const kept = shape(await appraiseOcspResponse(queryOf(one, {
      retained: { bytes: body, chain: null, chainSha256: null, observedAt: OBSERVED },
    }), { transport: silence(), clock: () => OBSERVED }));
    expect(kept).toBe('stale:historical-knowledge:COLLATERAL_NOT_OBSERVED');
  });
});
