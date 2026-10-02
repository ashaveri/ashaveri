import { describe, expect, it } from 'vitest';
import {
  foreignKey,
  mismatchedVendor,
  qeIdentity,
  secondsOf,
  servedJsonBody,
  signedDocument,
  tcbInfo,
  tcbInfoBody,
  testVendor,
  type TestVendor,
} from '@ashaveri/fixtures';
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

const FMSPC = '00906EA00000';
const CPU_TYPE = FMSPC.toLowerCase();
/** The vendor writes its instants with no fraction, so the documents here do too. */
const LEVEL_DATE = '2026-09-01T00:00:00Z';
const NEXT_UPDATE = '2026-10-01T00:00:00Z';
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

function levelDocument(signer: TestVendor = vendor, status = 'UpToDate', level = LEVEL_DATE, fmspc = FMSPC): Uint8Array {
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
    expect(read.vendorStatus).toBe('UpToDate');
    expect(read.signedAt).toBe(secondsOf(LEVEL_DATE));
    expect(read.validUntil).toBe(secondsOf(NEXT_UPDATE));
    expect(read.declaredCpuType).toBe(FMSPC);
    expect(read.anchorDigest).toBe(vendor.rootDigest);
    expect(read.blobs).toHaveLength(3);
    expect(read.blobs[0]).toEqual(levelDocument());
  });

  it('reads the QE identity where the vendor nests it, and names no identity', () => {
    const bytes = signedDocument(
      qeIdentity({
        issueDate: LEVEL_DATE,
        nextUpdate: NEXT_UPDATE,
        levels: [{ isvSvn: 0, tcbDate: LEVEL_DATE, tcbStatus: 'UpToDate' }],
      }),
      vendor,
    );
    const read = readOf(outcome(bytes, { origin: 'intel-qe-identity', cpuType: null }, INTEL_QE_IDENTITY));
    expect(read.vendorStatus).toBe('UpToDate');
    expect(read.declaredCpuType).toBeNull();
    expect(read.signedAt).toBe(secondsOf(LEVEL_DATE));
    expect(read.anchorDigest).toBe(vendor.rootDigest);
  });

  /**
   * The QE Identity window and levels sit inside `enclaveIdentity`, which is the position the served body
   * states. Here they sit at the top of the payload, which is where this path used to read them, and where
   * the served answer states nothing at all but that wrapper and a signature.
   */
  it('refuses a QE identity whose window sits at the top of the payload instead of inside the wrapper', () => {
    const bytes = signedDocument({ issueDate: LEVEL_DATE, nextUpdate: NEXT_UPDATE, tcbLevels: [] }, vendor);
    const refusal = refusalOf(outcome(bytes, { origin: 'intel-qe-identity', cpuType: null }, INTEL_QE_IDENTITY));
    expect(refusal.code).toBe('COLLATERAL_BLOB_UNREADABLE');
    expect(refusal.detail).toContain('enclaveIdentity');
  });

  /**
   * A document laid out the way Intel lays a TCB Info out, read at each rung it lists. The composition is
   * the component numbers of an object, the advisories are named beside the rung that owes one, and the
   * words are the vendor's own. Nothing here is this repository's spelling of a vendor document.
   */
  it('reads a document laid out the way the vendor lays one out and reports the vendor words', () => {
    const bytes = signedDocument(
      tcbInfo({
        fmspc: FMSPC,
        issueDate: LEVEL_DATE,
        nextUpdate: NEXT_UPDATE,
        composition: 'tdx',
        levels: [
          {
            svns: [9, 9, 2, 2, 4, 1, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0],
            pceSvn: 11,
            tcbDate: LEVEL_DATE,
            tcbStatus: 'UpToDate',
            advisoryIDs: ['INTEL-TA0016'],
          },
          { tcbDate: '2025-04-01T00:00:00Z', tcbStatus: 'OutOfDate' },
        ],
      }),
      vendor,
    );
    const current = readOf(outcome(bytes));
    expect(current.vendorStatus).toBe('UpToDate');
    expect(current.declaredCpuType).toBe(FMSPC);
    expect(current.signedAt).toBe(secondsOf(LEVEL_DATE));
    expect(current.validUntil).toBe(secondsOf(NEXT_UPDATE));

    const older = readOf(outcome(bytes, { level: { by: 'tcb-date', value: '2025-04-01T00:00:00Z' } }));
    expect(older.vendorStatus, 'a second rung states its own status').toBe('OutOfDate');
  });

  /**
   * The levels hang under `tcbLevels` in every body fetched for the citation at `intel-origin.ts`. Spelled
   * `tcb`, which is what this package read until the list member was settled, the list is not there at all.
   */
  it('refuses a document that spells its level list the way this repository used to spell it', () => {
    const bytes = signedDocument(
      {
        tcbInfo: {
          issueDate: LEVEL_DATE,
          nextUpdate: NEXT_UPDATE,
          fmspc: FMSPC,
          tcb: [{ tcbDate: LEVEL_DATE, tcbStatus: 'UpToDate' }],
        },
      },
      vendor,
    );
    const refusal = refusalOf(outcome(bytes));
    expect(refusal.code).toBe('COLLATERAL_BLOB_UNREADABLE');
    expect(refusal.detail).toContain('tcbLevels');
  });

  it('refuses a level that states no status beside the composition the vendor states', () => {
    const bytes = signedDocument(
      {
        tcbInfo: {
          issueDate: LEVEL_DATE,
          nextUpdate: NEXT_UPDATE,
          fmspc: FMSPC,
          tcbLevels: [{ tcb: { sgxtcbcomponents: [{ svn: 9 }], pcesvn: 11 }, tcbDate: LEVEL_DATE }],
        },
      },
      vendor,
    );
    const refusal = refusalOf(outcome(bytes));
    expect(refusal.code).toBe('COLLATERAL_BLOB_UNREADABLE');
    expect(refusal.detail).toContain('the matched level states no tcbStatus');
  });

  /**
   * Both directions of the composition position. A served level states its composition as component
   * numbers, and a hex question has nothing to compare with: the refusal says that rather than blaming the
   * document for listing no rung. A level stating its composition as hex text is the shape this package
   * declared and no body serves, and asking it by composition finds a document that states no such numbers.
   */
  it('refuses a composition question by the shape the document actually states', () => {
    const composition = { by: 'tcb-composition', value: '09090202040100060000000000000000' } as const;
    const numbers = signedDocument(
      tcbInfo({
        fmspc: FMSPC,
        issueDate: LEVEL_DATE,
        nextUpdate: NEXT_UPDATE,
        levels: [{ svns: [9, 9, 2, 2, 4, 1, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0], pceSvn: 11, tcbDate: LEVEL_DATE, tcbStatus: 'UpToDate' }],
      }),
      vendor,
    );
    const metNumbers = refusalOf(outcome(numbers, { level: composition }));
    expect(metNumbers.code).toBe('COLLATERAL_TCB_LEVEL_UNLISTED');
    expect(metNumbers.detail).toContain('component numbers');

    const hexSpelled = signedDocument(
      {
        tcbInfo: {
          issueDate: LEVEL_DATE,
          nextUpdate: NEXT_UPDATE,
          fmspc: FMSPC,
          tcbLevels: [{ tcb: composition.value, tcbDate: LEVEL_DATE, tcbStatus: 'UpToDate' }],
        },
      },
      vendor,
    );
    const metHex = refusalOf(outcome(hexSpelled, { level: composition }));
    expect(metHex.code).toBe('COLLATERAL_TCB_LEVEL_UNLISTED');
    expect(metHex.detail).toContain('lists no level spelled');
  });

  /**
   * What the address returns is a JSON body carrying a hex `signature` member, with the issuer chain in
   * a response header named after the document. This path decodes three base64url parts and reads the
   * certificates from inside them, so the served body is refused at its envelope, before one member of it
   * is read. The refusal is pinned because the gap is real: material that arrives in a pack arrives alone,
   * and the chain is not inside the bytes.
   */
  it('refuses the body the vendor actually answers with, at the envelope', () => {
    const bytes = servedJsonBody(tcbInfo({
      fmspc: FMSPC,
      issueDate: LEVEL_DATE,
      nextUpdate: NEXT_UPDATE,
      levels: [{ tcbDate: LEVEL_DATE, tcbStatus: 'UpToDate' }],
    }));
    const refusal = refusalOf(outcome(bytes));
    expect(refusal.code).toBe('COLLATERAL_BLOB_UNREADABLE');
    expect(refusal.detail).toContain('not the three a JWS has');
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
        levels: [{ tcbDate: LEVEL_DATE, tcbStatus: 'UpToDate' }],
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
      levels: [{ tcbDate: LEVEL_DATE, tcbStatus: 'UpToDate' }],
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
    const refusal = refusalOf(outcome(levelDocument(vendor, 'UpToDate', LEVEL_DATE, '00A0F0000000')));
    expect(refusal.code).toBe('COLLATERAL_IDENTITY_MISMATCH');
    expect(refusal.missing).toEqual(['cpuType']);
  });

  /**
   * The guard reads the vendor's member and nothing else. Here the vendor's `fmspc` names a foreign
   * machine while `fmspcid`, a member no served document carries, vouches for the one asked about: a
   * reader that believed the second would hand back a true statement about somebody else's hardware.
   */
  it('refuses what the vendor member names even when another member vouches for the one asked about', () => {
    const bytes = signedDocument(
      {
        tcbInfo: {
          ...tcbInfoBody({
            fmspc: '00A0F0000000',
            issueDate: LEVEL_DATE,
            nextUpdate: NEXT_UPDATE,
            levels: [{ tcbDate: LEVEL_DATE, tcbStatus: 'UpToDate' }],
          }),
          fmspcid: FMSPC,
        },
      },
      vendor,
    );
    const refusal = refusalOf(outcome(bytes));
    expect(refusal.code).toBe('COLLATERAL_IDENTITY_MISMATCH');
    expect(refusal.detail).toContain('00A0F0000000');
  });

  it('refuses a document stating no identity member at all, and names the one it looked for', () => {
    const bytes = signedDocument(
      { tcbInfo: { issueDate: LEVEL_DATE, nextUpdate: NEXT_UPDATE, tcbLevels: [{ tcbDate: LEVEL_DATE, tcbStatus: 'UpToDate' }] } },
      vendor,
    );
    const refusal = refusalOf(outcome(bytes));
    expect(refusal.code).toBe('COLLATERAL_BLOB_UNREADABLE');
    expect(refusal.detail).toContain('fmspc');
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
        levels: [{ tcbDate: LEVEL_DATE, tcbStatus: 'UpToDate' }],
      }),
      vendor,
    );
    expect(refusalOf(outcome(bytes)).code).toBe('COLLATERAL_BLOB_UNREADABLE');
  });

  it('refuses a document stating no window rather than assuming how long it stands', () => {
    const refusal = refusalOf(outcome(signedDocument({ tcbInfo: { fmspc: FMSPC, tcbLevels: [] } }, vendor)));
    expect(refusal.code).toBe('COLLATERAL_BLOB_UNREADABLE');
    expect(refusal.detail).toContain('window');
  });
});
