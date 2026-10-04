import { tmpdir } from 'node:os';
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
import {
  DEFAULT_MAX_EVIDENCE_AGE_SECONDS,
  DEFAULT_MAX_RECEIPT_AGE_SECONDS,
  loadPolicyFromText,
  policyFileFromPolicy,
  policyFileToJson,
  SdkError,
  type AshaveriPolicy,
} from '../src/index.js';
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

function payload(at: number): ReceiptPayload {
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
  return {
    v: 1,
    ...shared,
    mk: { sch: 'none' as const, d: sha256(TEXT('')) },
    sd: { name: 'host clock', uncertaintySeconds: null },
    cva: {
      collateral: { presence: 'not-taken-in', reason: 'the collector did not read the chain route' },
      validity: { presence: 'not-taken-in', reason: 'the collector read no window' },
    },
    itm: [{ t: at, d: sha256(TEXT('the full response bytes')) }],
  };
}

const receiptV1 = issueReceipt(payload(NOW - 20), KEY);
const secondReceipt = issueReceipt(payload(NOW - 19), KEY);

const held = (bytes: Uint8Array): Record<string, unknown> => ({
  presence: 'held',
  bytes: toBase64Url(bytes),
  sha256: toHex(sha256(bytes)),
  byteCount: bytes.length,
});

const ABSENT_AT_SOURCE = { presence: 'absent-at-source', reason: 'the platform served no chain' };
const NOT_TAKEN_IN = { presence: 'not-taken-in', reason: 'the collector did not read the chain route' };

/**
 * A held collateral slot and everything it states about the answer: which source declaration the bytes
 * came under, where they were asked, what the answer names itself, when the last byte landed, how far the
 * clock behind that instant admits it can stand, which reading weighed the answer, the span the answer's
 * own signed statement reaches, and the key the answer was kept under. The header that carried the chain
 * arrives beside its digest.
 *
 * The address, the header it is asked at and the key's member names and order are what
 * `packages/collateral/src/intel-origin.ts` declares for this source, so the fixture states a route this
 * repository has named rather than one it invented, and no vendor byte is in it.
 */
function collateral(bytes: Uint8Array, over: Record<string, unknown> = {}): Record<string, unknown> {
  const header = TEXT('TCB-Info-Issuer-Chain: -----BEGIN CERTIFICATE-----');
  return {
    ...held(bytes),
    origin: 'intel-tcb-info',
    request: 'https://api.trustedservices.intel.com/sgx/certification/v4/tcb?fmspc=00906f000200',
    identity: { cpuType: '00906f000200', vendorStatus: 'UpToDate' },
    observedAt: NOW - 30,
    sourceUncertaintySeconds: 2,
    chainSha256: toHex(sha256(header)),
    chainBytes: toBase64Url(header),
    weighedBy: 'served',
    window: { from: 1_735_689_600, to: 1_798_761_600 },
    cacheKey: 'origin=intel-tcb-info|platform=sgx|cpuType=00906f000200|level=tcb-date=2024-05-15T00:00:00Z',
    ...over,
  };
}

function record(
  original: Uint8Array,
  over: Record<string, unknown> = {},
  block: { readonly receiptFormatVersion?: number; readonly context?: unknown; readonly originalBlock?: Record<string, unknown> } = {},
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
    context: block.context ?? { collateral: collateral(TEXT('the vendor chain')), validity: held(TEXT('the appraisal')) },
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
const AT_NOW = { nowMillis: NOW * 1000 };

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

  it('names the record\'s own claim `stated`, and carries no verdict field named for the keeping of bytes', () => {
    // The verdict's two halves are what the record says it held and what this reader established.
    // `stated` pairs with `repeated` and says whose claim it is, and the old name is refused here
    // rather than left as a second name for the same half.
    const verdict = assessCapture({ record: record(receiptV1), policy: PINNED, ...AT_NOW });
    expect(verdict).not.toHaveProperty('custody');
    expect(verdict.stated.sourceKind).toBe('receipt');
  });

  it('returns the stored bytes, exactly, and recomputes the digest it reports', () => {
    const verdict = assessCapture({ record: record(receiptV1), policy: PINNED, ...AT_NOW });
    expect(equalBytes(verdict.repeated.originalBytes, receiptV1)).toBe(true);
    expect(verdict.repeated.sha256).toBe(toHex(sha256(receiptV1)));
    expect(verdict.stated.sha256).toBe(verdict.repeated.sha256);
    expect(verdict.stated.byteCount).toBe(receiptV1.length);
    expect(verdict.repeated.signatureVerifiedWithOwnPins).toBe(true);
    expect(verdict.repeated.signingKid).toBe(KID);
    expect(verdict.repeated.rootsMatched).toEqual(['amdArks']);
  });

  it('reports a signature the caller cannot repeat as unassessed, never as a pass', () => {
    const verdict = assessCapture({ record: record(receiptV1), ...AT_NOW });
    expect(verdict.status).toBe('unassessed');
    expect(verdict.repeated.signatureVerifiedWithOwnPins).toBe(false);
    // The record's own claim about the bytes it held is still the record's, and the reader hands it
    // back as a claim.
    expect(verdict.stated.assertsSignature).toBe(true);
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
    expect(verdict.stated.assertsSignature).toBe(false);
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
    original['bytes'] = toBase64Url(secondReceipt);
    expect(codes(() => assessCapture({ record: { ...whole, original }, policy: PINNED, ...AT_NOW }))).toBe(
      'EVIDENCE_DIGEST_MISMATCH',
    );
  });

  it('refuses a record that names a receipt version this build has no reader for', () => {
    // One version is read, so a record naming any other number describes a document no reader of these
    // bytes can open. The reader answers the number the record named rather than re-reading the bytes at
    // a version the format does not declare, and the refusal says which number it would not take.
    for (const named of [0, 2, 3] as const) {
      expect(
        codes(() => assessCapture({ record: record(receiptV1, {}, { receiptFormatVersion: named }), policy: PINNED, ...AT_NOW })),
        `a record naming ${named}`,
      ).toBe('UNSUPPORTED_VERSION');
    }
    expect(
      assessCapture({ record: record(receiptV1, {}, { receiptFormatVersion: 1 }), policy: PINNED, ...AT_NOW }).status,
    ).toBe('repeated');
  });
});

describe('the observation a verdict hands back as the record\'s own claim', () => {
  it('accepts a slot stating every member, and hands the eight back on the verdict', () => {
    const header = TEXT('TCB-Info-Issuer-Chain: -----BEGIN CERTIFICATE-----');
    const verdict = assessCapture({ record: record(receiptV1), policy: PINNED, ...AT_NOW });
    expect(verdict.status).toBe('repeated');
    expect(verdict.stated.collateral).toEqual({
      origin: 'intel-tcb-info',
      request: 'https://api.trustedservices.intel.com/sgx/certification/v4/tcb?fmspc=00906f000200',
      identity: { cpuType: '00906f000200', vendorStatus: 'UpToDate' },
      observedAt: NOW - 30,
      sourceUncertaintySeconds: 2,
      chainSha256: toHex(sha256(header)),
      chainBytes: toBase64Url(header),
      weighedBy: 'served',
      window: { from: 1_735_689_600, to: 1_798_761_600 },
      cacheKey: 'origin=intel-tcb-info|platform=sgx|cpuType=00906f000200|level=tcb-date=2024-05-15T00:00:00Z',
    });
    // A chain the source served apart from the body is a pair, and a slot that states neither says so by
    // carrying neither: an empty string or a guess is not how this record writes "no header".
    const bare = collateral(TEXT('the vendor chain'));
    delete bare['chainSha256'];
    delete bare['chainBytes'];
    bare['weighedBy'] = 'embedded';
    const noChain = assessCapture({
      record: record(receiptV1, {}, {
        context: { collateral: bare, validity: held(TEXT('the appraisal')) },
      }),
      policy: PINNED,
      ...AT_NOW,
    });
    expect(noChain.stated.collateral).not.toHaveProperty('chainBytes');
    expect(noChain.stated.collateral).not.toHaveProperty('chainSha256');
    expect(noChain.stated.collateral?.weighedBy).toBe('embedded');
  });

  it('weighs the collateral slot\'s statement and no other slot\'s, whoever else states one', () => {
    // The role rule where it matters: the ten members are legal in any held slot, so a validity slot that
    // states a whole observation is a document this reader takes, assesses, and reports as nothing. Which
    // answer the record holds is the collateral slot's claim and the verdict carries that claim alone.
    const other = collateral(TEXT('the appraisal'), { origin: 'intel-qe-identity', cacheKey: 'origin=intel-qe-identity|platform=sgx|level=tcb-date=2024-05-15T00:00:00Z' });
    const verdict = assessCapture({
      record: record(receiptV1, {}, { context: { collateral: collateral(TEXT('the vendor chain')), validity: other } }),
      policy: PINNED,
      ...AT_NOW,
    });
    expect(verdict.status).toBe('repeated');
    expect(verdict.stated.collateral?.origin).toBe('intel-tcb-info');
    expect(verdict.stated.collateral?.cacheKey).toBe('origin=intel-tcb-info|platform=sgx|cpuType=00906f000200|level=tcb-date=2024-05-15T00:00:00Z');
    expect(JSON.stringify(verdict), 'a validity slot\'s observation reaching the verdict').not.toContain('intel-qe-identity');
  });

  it('keeps a record whose collateral slot is absent-at-source readable at every old member', () => {
    // Capture-v1 widened under its own number, and what that buys is that a
    // record stating an absence keeps every member it ever had, gains no obligation, and hands back no
    // observation it never made. The absence is still reported as the record's own state of the world.
    const verdict = assessCapture({
      record: record(receiptV1, {}, { context: { collateral: ABSENT_AT_SOURCE, validity: held(TEXT('the appraisal')) } }),
      policy: PINNED,
      ...AT_NOW,
    });
    expect(verdict.stated.collateral).toBeNull();
    expect(verdict.stated.sourceKind).toBe('receipt');
    expect(verdict.stated.sourceId).toBe('cvm-test-1');
    expect(verdict.stated.sha256).toBe(verdict.repeated.sha256);
    expect(verdict.stated.acquiredAt).toBe(NOW);
    expect(verdict.absences).toEqual([
      { slot: 'context.collateral', presence: 'absent-at-source', reason: 'the platform served no chain' },
    ]);
    expect(verdict.status).toBe('qualified');
  });
});

describe('the limits and the clock a verdict was reached under', () => {
  it('runs its own windows, and says when they differ from the record', () => {
    const stale = codes(() =>
      assessCapture({ record: record(receiptV1), policy: PINNED, nowMillis: (NOW + 10_000) * 1000 }),
    );
    expect(stale).toBe('STALE_RECEIPT');
    const archive: AshaveriPolicy = {
      ...PINNED,
      maxReceiptAgeSeconds: Number.POSITIVE_INFINITY,
      maxEvidenceAgeSeconds: Number.POSITIVE_INFINITY,
    };
    const verdict = assessCapture({ record: record(receiptV1), policy: archive, nowMillis: (NOW + 10_000) * 1000 });
    expect(verdict.status).toBe('qualified');
    expect(verdict.qualifications.join(' ')).toContain('never closes');
    expect(verdict.repeated.signatureVerifiedWithOwnPins).toBe(true);
  });

  it('applies the shipped windows to a reader whose document named neither of them', async () => {
    // A published document spells a window the policy never named as `null`, and the schema says that
    // names no window of the document's own. What a reader then runs is the shipped default beside each
    // number the record states, which is the sentence these two qualifications carry.
    const written = policyFileToJson(policyFileFromPolicy({ keys: PINNED.keys, issuers: PINNED.issuers }));
    expect(written).toContain('"maxReceiptAgeSeconds": null');
    expect(written).toContain('"maxEvidenceAgeSeconds": null');
    const loaded = await loadPolicyFromText(written, tmpdir());
    expect(loaded.policy.maxReceiptAgeSeconds, 'a window written as null loads as no number named').toBeUndefined();
    expect(loaded.policy.maxEvidenceAgeSeconds).toBeUndefined();
    const verdict = assessCapture({
      record: record(receiptV1, {
        trust: {
          roots: [{ family: 'amdArks', digest: ROOT_DIGEST }],
          limits: { maxReceiptAgeSeconds: 3_600, maxEvidenceAgeSeconds: 3_600 },
        },
      }),
      policy: loaded.policy,
      anchors: { amdArks: [ROOT] },
      ...AT_NOW,
    });
    const said = verdict.qualifications.join(' ');
    expect(said, 'the reader runs the receipt default, not no window').toContain(
      `this reader applied ${DEFAULT_MAX_RECEIPT_AGE_SECONDS}s`,
    );
    expect(said, 'and the evidence default beside it').toContain(
      `this reader applied ${DEFAULT_MAX_EVIDENCE_AGE_SECONDS}s`,
    );
  });

  it('says a record that names neither window named none, and not that its clock stayed open', () => {
    // The words this case pins are the whole point: a null in `trust.limits` is the record stating no
    // window of its own, which is one spelling short of a claim that the check ran with the clock
    // switched off. What the record left unnamed, this reader cannot recover, so the qualification says
    // what the record states and what this reader ran, and asserts no disagreement between them.
    const verdict = assessCapture({
      record: record(receiptV1, {
        trust: {
          roots: [{ family: 'amdArks', digest: ROOT_DIGEST }],
          limits: { maxReceiptAgeSeconds: null, maxEvidenceAgeSeconds: null },
        },
      }),
      policy: PINNED,
      anchors: { amdArks: [ROOT] },
      ...AT_NOW,
    });
    const said = verdict.qualifications.join(' ');
    expect(said).toContain(
      `the record states no window of its own for the receipt window while this reader applied ${DEFAULT_MAX_RECEIPT_AGE_SECONDS}s`,
    );
    expect(said).toContain(
      `the record states no window of its own for the evidence window while this reader applied ${DEFAULT_MAX_EVIDENCE_AGE_SECONDS}s`,
    );
    expect(said).not.toContain('no window while this reader applied');
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
    expect(verdict.stated.sourceStatedAt).toBe(NOW + 30);
    expect(verdict.stated.acquiredAt).toBe(NOW);
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
