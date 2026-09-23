import { describe, expect, it } from 'vitest';
import {
  ReceiptError,
  generateSigningKey,
  issueReceipt,
  toBase64Url,
  toHex,
  type ReceiptPayload,
} from '@ashaveri/receipt';
import { sha256 } from '@noble/hashes/sha2.js';
import { assessCapture } from '../src/capture.js';
import { SdkError, type AshaveriPolicy } from '../src/index.js';
import { equalBytes } from '@ashaveri/receipt';

/**
 * The reader's verdict, and the three things it is not allowed to do: read a missing input as a pass,
 * read a stored digest as a checked one, or read custody as verification.
 *
 * The originals are `issueReceipt` output again, so the signature leg runs the format's real verifier
 * against a real key rather than against a stub.
 */

const KEY = generateSigningKey();
const OTHER = generateSigningKey();
const KID = toHex(KEY.kid);
const NOW = 1_800_000_000;
const TEXT = (value: string): Uint8Array => new TextEncoder().encode(value);
const ROOT = TEXT('a pinned vendor root');
const ROOT_DIGEST = toHex(sha256(ROOT));

function payload(version: 1 | 2, at: number): ReceiptPayload {
  const shared = {
    iss: 'ashaveri-test',
    ins: 'cvm-test-1',
    iat: at,
    nce: new Uint8Array(16).fill(7),
    req: sha256(TEXT('the canonical request bytes')),
    res: sha256(TEXT('the full response bytes')),
    mdl: 'test/model-1',
    wts: sha256(TEXT('the deployment manifest digest input')),
    meas: { tee: 'snp' as const, m: new Uint8Array(48).fill(3) },
    att: { d: sha256(TEXT('the evidence document')), ts: at - 5, url: 'https://gateway.test/evidence' },
    epk: 1,
    tok: { p: 11, c: 22 },
  };
  return version === 2 ? { v: 2, ...shared, mk: { sch: 'none' as const, d: sha256(TEXT('')) } } : { v: 1, ...shared };
}

const receiptV1 = issueReceipt(payload(1, NOW - 20), KEY);
const receiptV2 = issueReceipt(payload(2, NOW - 20), KEY);

const held = (bytes: Uint8Array): Record<string, unknown> => ({
  presence: 'held',
  bytes: toBase64Url(bytes),
  sha256: toHex(sha256(bytes)),
  byteCount: bytes.length,
});

const ABSENT_AT_SOURCE = { presence: 'absent-at-source', reason: 'the platform served no chain' };
const NOT_TAKEN_IN = { presence: 'not-taken-in', reason: 'the collector did not read the chain route' };

function record(
  original: Uint8Array,
  over: Record<string, unknown> = {},
  block: { readonly receiptFormatVersion?: 1 | 2; readonly context?: unknown; readonly originalBlock?: Record<string, unknown> } = {},
): Record<string, unknown> {
  return {
    v: 1,
    original: {
      sourceKind: 'receipt',
      sourceId: 'cvm-test-1',
      bytes: toBase64Url(original),
      sha256: toHex(sha256(original)),
      byteCount: original.length,
      signedBySource: true,
      signatureEmbedded: true,
      ...block.originalBlock,
    },
    acquired: { at: NOW, sourceStatedAt: NOW - 25 },
    manifests: { deployment: held(TEXT('{"v":1}')) },
    check: {
      policyVersion: 1,
      policyDigest: toHex(sha256(TEXT('the policy document'))),
      receiptFormatVersion: block.receiptFormatVersion ?? 1,
      verifierVersion: '0.1.0',
      appraisedAt: NOW,
    },
    context: block.context ?? { collateral: held(TEXT('the vendor chain')), validity: held(TEXT('the appraisal')) },
    trust: {
      roots: [{ family: 'amdArks', digest: ROOT_DIGEST }],
      limits: { maxReceiptAgeSeconds: 300, maxEvidenceAgeSeconds: 900 },
    },
    ...over,
  };
}

const PINNED: AshaveriPolicy = {
  keys: { [KID]: toBase64Url(KEY.publicKey) },
  issuers: ['ashaveri-test'],
  trustAnchors: { amdArks: [ROOT] },
};
const AT_NOW = { now: NOW * 1000 };

function statusOf(original: Uint8Array, params: { policy?: AshaveriPolicy } = {}): string {
  return assessCapture({ record: record(original), policy: params.policy, ...AT_NOW }).status;
}

function codes(fn: () => unknown): string | undefined {
  try {
    fn();
    return undefined;
  } catch (err) {
    if (err instanceof SdkError || err instanceof ReceiptError) return err.code;
    throw err;
  }
}

describe('a verdict keeps custody and verification apart', () => {
  it('reaches `repeated` only with every leg in place and the caller key pinned', () => {
    const verdict = assessCapture({ record: record(receiptV1), policy: PINNED, ...AT_NOW });
    expect(verdict.status).toBe('repeated');
    expect(verdict.absences).toEqual([]);
    expect(verdict.qualifications).toEqual([]);
  });

  it('returns the stored bytes, exactly, and recomputes the digest it reports', () => {
    const verdict = assessCapture({ record: record(receiptV1), policy: PINNED, ...AT_NOW });
    expect(equalBytes(verdict.repeated.originalBytes, receiptV1)).toBe(true);
    expect(verdict.repeated.sha256).toBe(toHex(sha256(receiptV1)));
    expect(verdict.custody.sha256).toBe(verdict.repeated.sha256);
    expect(verdict.custody.byteCount).toBe(receiptV1.length);
    expect(verdict.repeated.signatureVerifiedWithOwnPins).toBe(true);
    expect(verdict.repeated.signingKid).toBe(KID);
    expect(verdict.repeated.rootsMatched).toEqual(['amdArks']);
  });

  it('reports a signature the caller cannot repeat as unassessed, never as a pass', () => {
    const verdict = assessCapture({ record: record(receiptV1), ...AT_NOW });
    expect(verdict.status).toBe('unassessed');
    expect(verdict.repeated.signatureVerifiedWithOwnPins).toBe(false);
    // The claim of custody is still the record's, and the reader hands it back as a claim.
    expect(verdict.custody.assertsSignature).toBe(true);
    expect(verdict.qualifications.join(' ')).toContain(KID);
  });

  it('refuses a key the record kid does not describe, and pins nothing on somebody else', () => {
    const wrongKey: AshaveriPolicy = { ...PINNED, keys: { [KID]: toBase64Url(OTHER.publicKey) } };
    expect(codes(() => assessCapture({ record: record(receiptV1), policy: wrongKey, ...AT_NOW }))).toBe('KID_MISMATCH');
    const otherPinnedOnly: AshaveriPolicy = { ...PINNED, keys: { [toHex(OTHER.kid)]: toBase64Url(OTHER.publicKey) } };
    const verdict = assessCapture({ record: record(receiptV1), policy: otherPinnedOnly, ...AT_NOW });
    expect(verdict.status).toBe('unassessed');
    expect(verdict.qualifications.join(' ')).toContain(KID);
  });

  it('never calls a vendor chain it did not walk a verification', () => {
    const verdict = assessCapture({
      record: record(receiptV1, {}, { originalBlock: { sourceKind: 'device-evidence', sourceId: 'gpu-1' } }),
      policy: PINNED,
      ...AT_NOW,
    });
    expect(verdict.status).toBe('unassessed');
    expect(verdict.qualifications.join(' ')).toContain('verifyCompletionEvidence');
    expect(verdict.repeated.signatureVerifiedWithOwnPins).toBe(false);
  });

  it('says so when the record claims no signature at all', () => {
    const verdict = assessCapture({
      record: record(receiptV1, {}, { originalBlock: { signedBySource: false, signatureEmbedded: false } }),
      policy: PINNED,
      ...AT_NOW,
    });
    expect(verdict.custody.assertsSignature).toBe(false);
    expect(verdict.status).toBe('qualified');
    expect(verdict.qualifications.join(' ')).toContain('nothing to repeat');
  });
});

describe('missing context is never upgraded into a pass', () => {
  it('qualifies a verdict whose collateral the source never produced', () => {
    const verdict = assessCapture({
      record: record(receiptV1, {}, { context: { collateral: ABSENT_AT_SOURCE, validity: held(TEXT('the appraisal')) } }),
      policy: PINNED,
      ...AT_NOW,
    });
    expect(verdict.status).toBe('qualified');
    expect(verdict.absences).toEqual([{ slot: 'context.collateral', presence: 'absent-at-source', reason: 'the platform served no chain' }]);
    expect(verdict.repeated.signatureVerifiedWithOwnPins).toBe(true);
  });

  it('reports as unassessed a verdict whose collateral the collector failed to take in', () => {
    const verdict = assessCapture({
      record: record(receiptV1, {}, { context: { collateral: NOT_TAKEN_IN, validity: held(TEXT('the appraisal')) } }),
      policy: PINNED,
      ...AT_NOW,
    });
    expect(verdict.status).toBe('unassessed');
    expect(verdict.absences[0]?.presence).toBe('not-taken-in');
  });

  it('tells the source never had it apart from we did not look', () => {
    const neverHad = assessCapture({
      record: record(receiptV1, {}, { context: { collateral: ABSENT_AT_SOURCE, validity: held(TEXT('a')) } }),
      policy: PINNED,
      ...AT_NOW,
    });
    const didNotLook = assessCapture({
      record: record(receiptV1, {}, { context: { collateral: NOT_TAKEN_IN, validity: held(TEXT('a')) } }),
      policy: PINNED,
      ...AT_NOW,
    });
    expect(neverHad.status).not.toBe(didNotLook.status);
    expect(neverHad.absences[0]?.presence).toBe('absent-at-source');
    expect(didNotLook.absences[0]?.presence).toBe('not-taken-in');
    // The one thing neither reading is allowed to do is come back as a verdict that saw everything.
    expect(neverHad.status).not.toBe('repeated');
    expect(didNotLook.status).not.toBe('repeated');
  });

  it('refuses a record whose context is silently missing rather than declared absent', () => {
    const whole = record(receiptV1);
    const context = { ...(whole['context'] as Record<string, unknown>) };
    delete context['collateral'];
    expect(codes(() => assessCapture({ record: { ...whole, context }, policy: PINNED, ...AT_NOW }))).toBe('NOT_CAPTURE_RECORD');
  });

  it('refuses a record whose stated digest does not describe its own bytes', () => {
    const whole = record(receiptV1);
    const original = { ...(whole['original'] as Record<string, unknown>) };
    original['bytes'] = toBase64Url(receiptV2);
    expect(codes(() => assessCapture({ record: { ...whole, original }, policy: PINNED, ...AT_NOW }))).toBe(
      'EVIDENCE_DIGEST_MISMATCH',
    );
  });

  it('refuses a record that names a receipt version the bytes are not', () => {
    // The bytes are v2 and the record says it was checked against v1. The reader reads at the version the
    // record names, so the document the record cannot describe is refused rather than quietly re-read.
    expect(
      codes(() => assessCapture({ record: record(receiptV2), policy: PINNED, ...AT_NOW })),
    ).toBe('UNSUPPORTED_VERSION');
    expect(
      assessCapture({ record: record(receiptV2, {}, { receiptFormatVersion: 2 }), policy: PINNED, ...AT_NOW }).status,
    ).toBe('repeated');
  });
});

describe('the limits and the clock a verdict was reached under', () => {
  it('runs its own windows, and says when they differ from the record', () => {
    const stale = codes(() =>
      assessCapture({ record: record(receiptV1), policy: PINNED, now: (NOW + 10_000) * 1000 }),
    );
    expect(stale).toBe('STALE_RECEIPT');
    const archive: AshaveriPolicy = {
      ...PINNED,
      maxReceiptAgeSeconds: Number.POSITIVE_INFINITY,
      maxEvidenceAgeSeconds: Number.POSITIVE_INFINITY,
    };
    const verdict = assessCapture({ record: record(receiptV1), policy: archive, now: (NOW + 10_000) * 1000 });
    expect(verdict.status).toBe('qualified');
    expect(verdict.qualifications.join(' ')).toContain('never closes');
    expect(verdict.repeated.signatureVerifiedWithOwnPins).toBe(true);
  });

  it('refuses a record whose appraisal precedes its acquisition', () => {
    const verdict = assessCapture({
      record: record(receiptV1, { check: { ...(record(receiptV1).check as object), appraisedAt: NOW - 60 } }),
      policy: PINNED,
      ...AT_NOW,
    });
    expect(verdict.status).toBe('unassessed');
    expect(verdict.qualifications.join(' ')).toContain('ordering is unusable');
  });

  it('reports a source that dated its own bytes after they were collected', () => {
    const verdict = assessCapture({
      record: record(receiptV1, { acquired: { at: NOW, sourceStatedAt: NOW + 30 } }),
      policy: PINNED,
      ...AT_NOW,
    });
    expect(verdict.status).toBe('qualified');
    expect(verdict.custody.sourceStatedAt).toBe(NOW + 30);
    expect(verdict.custody.acquiredAt).toBe(NOW);
    expect(verdict.qualifications.join(' ')).toContain('the two clocks disagree');
  });

  it('measures a vendor root against the caller and never against a default', () => {
    const mismatched = { amdArks: [TEXT('a different root')] };
    expect(
      codes(() => assessCapture({ record: record(receiptV1), policy: PINNED, anchors: mismatched, ...AT_NOW })),
    ).toBe('EVIDENCE_VERIFICATION_FAILED');
    const matching = assessCapture({ record: record(receiptV1), policy: PINNED, anchors: { amdArks: [ROOT] }, ...AT_NOW });
    expect(matching.repeated.rootsMatched).toEqual(['amdArks']);
    const unpinned = assessCapture({ record: record(receiptV1), policy: PINNED, anchors: {}, ...AT_NOW });
    expect(unpinned.status).toBe('unassessed');
    expect(unpinned.qualifications.join(' ')).toContain(ROOT_DIGEST);
    const unnamed = assessCapture({
      record: record(receiptV1, { trust: { roots: [{ family: 'amdArks', digest: null }], limits: { maxReceiptAgeSeconds: 300, maxEvidenceAgeSeconds: 900 } } }),
      policy: PINNED,
      anchors: { amdArks: [ROOT] },
      ...AT_NOW,
    });
    expect(unnamed.status).toBe('unassessed');
    expect(unnamed.qualifications.join(' ')).toContain('unnamed root');
  });

  it('hands a caller the reasons, one line each, rather than only an outcome', () => {
    const verdict = assessCapture({ record: record(receiptV1), ...AT_NOW });
    expect(verdict.qualifications.length).toBeGreaterThan(0);
    for (const line of verdict.qualifications) {
      expect(line).not.toMatch(/[\r\n\u2028\u2029]/u);
      expect(line.length).toBeGreaterThan(20);
    }
    expect(statusOf(receiptV1, { policy: PINNED })).toBe('repeated');
  });
});
