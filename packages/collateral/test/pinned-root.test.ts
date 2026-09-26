import { describe, expect, it } from 'vitest';
import { sha256 } from '@noble/hashes/sha2.js';
import { DEFAULT_INTEL_SGX_ROOTS, INTEL_SGX_ROOT_CA_PEM, parseCertificateChain } from '@ashaveri/attest-core';
import { appraiseCollateral, type CollateralOutcome, type CollateralTransport } from '../src/index.js';
import type { CollateralQuery } from '../src/types.js';
import { secondsOf, signedDocument, tcbInfo, testVendor } from './support/collateral-documents.js';

const FMSPC = '00906EA00000';
const LEVEL_DATE = '2026-09-01T00:00:00.000Z';
const NEXT_UPDATE = '2026-10-01T00:00:00.000Z';
const WITHIN = secondsOf('2026-09-15T00:00:00.000Z');
const OBSERVED = secondsOf('2026-09-15T06:00:00.000Z');

/**
 * Intel's published provisioning root, held by `@ashaveri/attest-core` and digested here against the
 * fingerprint its fixture README records, so the pin in these cases is a root the caller can check
 * somewhere other than in the code that reads it.
 */
const INTEL_ROOT_SHA256 = '44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3';

const vendor = testVendor();

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function query(roots: readonly Uint8Array[]): CollateralQuery {
  return {
    origin: 'intel-tcb-info',
    platform: 'tdx',
    cpuType: FMSPC.toLowerCase(),
    level: { by: 'tcb-date', value: LEVEL_DATE },
    appraisalAt: WITHIN,
    roots,
    retained: null,
    onAbsent: 'unassessed',
  };
}

function serve(bytes: Uint8Array): CollateralTransport {
  return async () => new Response(bytes);
}

async function verdict(roots: readonly Uint8Array[]): Promise<CollateralOutcome> {
  const bytes = signedDocument(
    tcbInfo({
      fmspc: FMSPC,
      issueDate: LEVEL_DATE,
      nextUpdate: NEXT_UPDATE,
      levels: [{ tcbDate: LEVEL_DATE, tcbStatus: 'OK' }],
    }),
    vendor,
  );
  return appraiseCollateral(query(roots), { transport: serve(bytes), clock: () => OBSERVED });
}

describe('the root a verdict rests on', () => {
  it('holds a real vendor root whose digest the caller can check somewhere else', () => {
    const [root] = parseCertificateChain(new TextEncoder().encode(INTEL_SGX_ROOT_CA_PEM));
    if (root === undefined) {
      throw new Error('the published root does not parse');
    }
    expect(hex(sha256(root.raw))).toBe(INTEL_ROOT_SHA256);
    expect(root.publicKey.kind).toBe('ec-p256');
    expect(root.isCa).toBe(true);
  });

  it('reaches its verdict on the root the caller holds, not on the roots the library bundles', async () => {
    const own = await verdict([vendor.rootDer]);
    expect(own.state).toBe('current');
    expect(own.collateral?.anchorDigest).toBe(vendor.rootDigest);

    const bundled = await verdict(DEFAULT_INTEL_SGX_ROOTS);
    expect(bundled.state).toBe('unavailable');
    expect(bundled.collateral).toBeNull();
    if ('refusal' in bundled) {
      expect(bundled.refusal.code).toBe('COLLATERAL_ANCHOR_NOT_PINNED');
      expect(bundled.refusal.detail).toContain('pinned nothing');
    }

    const askedWithNothing = await verdict([]);
    expect(askedWithNothing.state).toBe('missing-context');
    if ('refusal' in askedWithNothing) {
      expect(askedWithNothing.refusal.code).toBe('COLLATERAL_ANCHOR_NOT_PINNED');
      expect(askedWithNothing.refusal.missing).toEqual(['roots']);
    }
  });

  it('names the root the chain actually reached when the caller holds two', async () => {
    const both = await verdict([new TextEncoder().encode(INTEL_SGX_ROOT_CA_PEM), vendor.rootDer]);
    expect(both.state).toBe('current');
    expect(both.collateral?.anchorDigest).toBe(vendor.rootDigest);
    expect(both.collateral?.anchorDigest).not.toBe(INTEL_ROOT_SHA256);
  });
});
