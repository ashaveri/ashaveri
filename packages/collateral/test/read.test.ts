import { describe, expect, it } from 'vitest';
import {
  INTEL_QE_IDENTITY,
  INTEL_TCB_INFO,
  readSignedCollateral,
  type CollateralRefusal,
  type OriginDeclaration,
  type ReadCollateral,
  type ReadOutcome,
} from '../src/index.js';
import type { CollateralQuery } from '../src/types.js';
import {
  foreignKey,
  mismatchedVendor,
  qeIdentity,
  secondsOf,
  signedDocument,
  tcbInfo,
  testVendor,
  type TestVendor,
} from './support/collateral-documents.js';

const FMSPC = '00906EA00000';
const CPU_TYPE = FMSPC.toLowerCase();
const LEVEL_DATE = '2026-09-01T00:00:00.000Z';
const NEXT_UPDATE = '2026-10-01T00:00:00.000Z';
const WITHIN = secondsOf('2026-09-15T00:00:00.000Z');

const vendor = testVendor();

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

function levelDocument(signer: TestVendor = vendor, status = 'OK', level = LEVEL_DATE, fmspc = FMSPC): Uint8Array {
  return signedDocument(
    tcbInfo({ fmspc, issueDate: level, nextUpdate: NEXT_UPDATE, levels: [{ tcbDate: level, tcbStatus: status }] }),
    signer,
  );
}

function outcome(
  bytes: Uint8Array,
  over: Partial<CollateralQuery> = {},
  declaration: OriginDeclaration = INTEL_TCB_INFO,
): ReadOutcome {
  const asked = query(over);
  return readSignedCollateral(bytes, {
    query: asked,
    declaration,
    appraisalAt: asked.appraisalAt === null ? WITHIN : asked.appraisalAt,
  });
}

function readOf(result: ReadOutcome): ReadCollateral {
  if ('read' in result) {
    return result.read;
  }
  throw new Error(`the document was refused: ${result.refusal.code} ${result.refusal.detail}`);
}

function refusalOf(result: ReadOutcome): CollateralRefusal {
  if ('refusal' in result) {
    return result.refusal;
  }
  throw new Error(`the document was read as ${result.read.vendorStatus}, but a refusal was expected`);
}

describe('the signed collateral document', () => {
  it('reads what the vendor signed once the chain reaches the root the caller pinned', () => {
    const read = readOf(outcome(levelDocument()));
    expect(read.vendorStatus).toBe('OK');
    expect(read.signedAt).toBe(secondsOf(LEVEL_DATE));
    expect(read.validUntil).toBe(secondsOf(NEXT_UPDATE));
    expect(read.declaredCpuType).toBe(FMSPC);
    expect(read.anchorDigest).toBe(vendor.rootDigest);
    expect(read.blobs).toHaveLength(3);
    expect(read.blobs[0]).toEqual(levelDocument());
  });

  it('reads the QE identity, which states one status and names no identity', () => {
    const bytes = signedDocument(
      qeIdentity({ issueDate: LEVEL_DATE, nextUpdate: NEXT_UPDATE, tcbStatus: 'OK' }),
      vendor,
    );
    const read = readOf(outcome(bytes, { origin: 'intel-qe-identity', cpuType: null, level: null }, INTEL_QE_IDENTITY));
    expect(read.vendorStatus).toBe('OK');
    expect(read.declaredCpuType).toBeNull();
    expect(read.anchorDigest).toBe(vendor.rootDigest);
  });

  it('refuses a chain borrowing the pinned root name over a key the pin does not hold', () => {
    // The same distinguished names over different keys: a chain that reads as the vendor's and is not.
    const refusal = refusalOf(outcome(levelDocument(testVendor())));
    expect(refusal.code).toBe('COLLATERAL_SIGNATURE_UNVERIFIED');
    expect(refusal.detail).toContain('pinned');
  });

  it('refuses a chain that reaches a self-signed certificate the caller pinned nothing for', () => {
    const stranger = testVendor({ rootName: 'Unrelated Root', issuerName: 'Unrelated CA' });
    expect(refusalOf(outcome(levelDocument(stranger))).code).toBe('COLLATERAL_ANCHOR_NOT_PINNED');
  });

  it('refuses a document the presented chain did not sign', () => {
    const bytes = signedDocument(
      tcbInfo({
        fmspc: FMSPC,
        issueDate: LEVEL_DATE,
        nextUpdate: NEXT_UPDATE,
        levels: [{ tcbDate: LEVEL_DATE, tcbStatus: 'OK' }],
      }),
      { ...vendor, signingKey: foreignKey() },
    );
    const refusal = refusalOf(outcome(bytes));
    expect(refusal.code).toBe('COLLATERAL_SIGNATURE_UNVERIFIED');
    expect(refusal.detail).toContain('does not hold');
  });

  it('refuses a pinned blob that holds no certificate, so it pins nothing', () => {
    expect(refusalOf(outcome(levelDocument(), { roots: [Uint8Array.from([1, 2, 3, 4])] })).code)
      .toBe('COLLATERAL_ANCHOR_NOT_PINNED');
  });

  it('refuses an answer that is not the envelope the origin declares', () => {
    for (const away of ['not a jose message', 'a.b', new Uint8Array([0xff, 0xfe, 0x00])]) {
      const bytes = typeof away === 'string' ? new TextEncoder().encode(away) : away;
      expect(refusalOf(outcome(bytes)).code, String(away)).toBe('COLLATERAL_BLOB_UNREADABLE');
    }
  });

  it('refuses a header naming another suite, presenting no certificates, or claiming a critical member', () => {
    const payload = tcbInfo({
      fmspc: FMSPC,
      issueDate: LEVEL_DATE,
      nextUpdate: NEXT_UPDATE,
      levels: [{ tcbDate: LEVEL_DATE, tcbStatus: 'OK' }],
    });
    const other = signedDocument(payload, vendor, { alg: 'RS256', x5c: ['MII'] });
    expect(refusalOf(outcome(other)).detail).toContain('RS256');
    expect(refusalOf(outcome(signedDocument(payload, vendor, { alg: 'ES256' }))).code)
      .toBe('COLLATERAL_BLOB_UNREADABLE');
    const critical = signedDocument(payload, vendor, { alg: 'ES256', crit: ['b64'], x5c: ['MII'] });
    expect(refusalOf(outcome(critical)).code).toBe('COLLATERAL_BLOB_UNREADABLE');
    const detached = signedDocument(payload, vendor, { alg: 'ES256', b64: false, x5c: ['MII'] });
    expect(refusalOf(outcome(detached)).code).toBe('COLLATERAL_BLOB_UNREADABLE');
  });

  it('refuses a document covering another identity than the one asked for', () => {
    const refusal = refusalOf(outcome(levelDocument(vendor, 'OK', LEVEL_DATE, '00A0F0000000')));
    expect(refusal.code).toBe('COLLATERAL_IDENTITY_MISMATCH');
    expect(refusal.missing).toEqual(['cpuType']);
  });

  it('refuses a level the signed list does not carry, and names the field that failed to match', () => {
    const refusal = refusalOf(outcome(levelDocument(), { level: { by: 'tcb-date', value: '2027-01-01T00:00:00.000Z' } }));
    expect(refusal.code).toBe('COLLATERAL_TCB_LEVEL_UNLISTED');
    expect(refusal.missing).toEqual(['level']);
  });

  it('refuses a certificate outside its own validity at the moment being appraised', () => {
    const expired = testVendor({
      notBefore: secondsOf('2025-01-01T00:00:00.000Z'),
      notAfter: secondsOf('2026-01-01T00:00:00.000Z'),
    });
    const refusal = refusalOf(outcome(levelDocument(expired)));
    expect(refusal.code).toBe('COLLATERAL_SIGNATURE_UNVERIFIED');
    expect(refusal.detail).toContain('validity');
  });

  it('refuses a chain naming a suite its key does not carry', () => {
    const refusal = refusalOf(outcome(levelDocument(mismatchedVendor())));
    expect(refusal.code).toBe('COLLATERAL_SIGNATURE_UNVERIFIED');
    expect(refusal.detail).toContain('ecdsa-sha384');
  });

  it('refuses a window that closes at or before the instant it opens', () => {
    const bytes = signedDocument(
      tcbInfo({
        fmspc: FMSPC,
        issueDate: LEVEL_DATE,
        nextUpdate: LEVEL_DATE,
        levels: [{ tcbDate: LEVEL_DATE, tcbStatus: 'OK' }],
      }),
      vendor,
    );
    expect(refusalOf(outcome(bytes)).code).toBe('COLLATERAL_BLOB_UNREADABLE');
  });

  it('refuses a document stating no window rather than assuming how long it stands', () => {
    const refusal = refusalOf(outcome(signedDocument({ tcbInfo: { fmspcid: FMSPC, tcb: [] } }, vendor)));
    expect(refusal.code).toBe('COLLATERAL_BLOB_UNREADABLE');
    expect(refusal.detail).toContain('window');
  });
});
