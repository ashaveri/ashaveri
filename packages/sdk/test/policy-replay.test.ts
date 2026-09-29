import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { issueReceipt, signingKeyFromSeed, type ReceiptPayload } from '@ashaveri/receipt';
import {
  SdkError,
  loadPolicyFromText,
  parsePolicyFile,
  policyFileDigest,
  policyKeyByKid,
  toBase64Url,
  toHex,
  verifyCompletionReceipt,
  type AshaveriPolicy,
} from '../src/index.js';

/**
 * The proof that a policy document naming no `maxTimeUncertaintySeconds` still means what it meant
 * before that field existed, held as values rather than as a sentence about a run.
 *
 * `policyFileDigest` is defined over a canonical form, so "the field is additive" is a claim about
 * bytes, and a claim about bytes is worth only as much as the number attached to it. Every digest and
 * every verdict below was read off the policy reader of the commit this branch was cut from, by
 * replaying each document through that reader and through this tree's side by side. They are therefore
 * the numbers a policy that never made the demand carried before the demand could be made, and the
 * reader shipped here has to reproduce all of them. When one stops matching, either the canonical form
 * or the domain string moved, which moves every digest anyone has ever cited, or a document that names
 * no demand started reading as a different policy than the one it states.
 *
 * Two of the seven digests in the first table are the published vectors `policy-schema.test.ts` pins,
 * so this file's measurements are checked against numbers that exist outside it rather than only
 * against each other. The second table replays one real receipt against nine policies that differ only
 * in a pin, because the claim worth holding is not that a digest stood still but that no verdict moved
 * with it.
 */

const TEMP = mkdtempSync(join(tmpdir(), 'ashaveri-policy-replay-'));
afterAll(() => {
  rmSync(TEMP, { recursive: true, force: true });
});

const KID = 'a'.repeat(64);
const PUBKEY = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const SNP = '7f'.repeat(48);
const SHA = 'ab'.repeat(32);

/** Documents naming no time bound, in every shape the format reads. */
const CORPUS: ReadonlyArray<readonly [label: string, document: Record<string, unknown>, digest: string]> = [
  [
    'the published vector pinning one issuer',
    { v: 1, issuers: ['ashaveri-mock'] },
    'sha256:3329595b14993b16992a6577f332a05b34821e33454a53a24575a1c9902c91d6',
  ],
  [
    'the published vector pinning everything',
    {
      v: 1,
      issuers: ['ashaveri-prod'],
      instances: ['cvm-1'],
      keys: { [KID]: PUBKEY },
      measurements: { snp: [SNP] },
      maxReceiptAgeSeconds: 60,
      maxEvidenceAgeSeconds: null,
      trustAnchors: {
        amdArks: [{ path: 'roots/ark.pem', sha256: SHA }],
        intelSgxRoots: null,
        nvidiaRoots: [{ path: 'roots/device-ca.pem', sha256: 'cd'.repeat(32) }],
      },
    },
    'sha256:008742152d91f71b57ca1c63ddf29220d9b7b396cc77954e28575114a43cd373',
  ],
  [
    'a bare pin',
    { v: 1, issuers: ['a'] },
    'sha256:e2f17a62cb3fb36b5dbe73064df8c026517fe74648638fac24bcd32ffd2933f9',
  ],
  [
    'both windows named',
    { v: 1, issuers: ['a'], maxReceiptAgeSeconds: 60, maxEvidenceAgeSeconds: 120 },
    'sha256:4184b17e2c3e586e8ae9f6a3ecbff0baca35ffa5a9f59bb69d0e03cd72531552',
  ],
  [
    'an anchor path written with a backslash',
    {
      v: 1,
      issuers: ['ashaveri-prod'],
      trustAnchors: { nvidiaRoots: [{ path: 'roots\\device-ca.pem', sha256: SHA }] },
    },
    'sha256:92bfe108cd8725d495c6ff66646a271f4f9933548a0a99496028333ce4fc8a15',
  ],
  [
    'keys and measurements only',
    { v: 1, keys: { [KID]: PUBKEY }, measurements: { snp: [SNP] } },
    'sha256:5d2d88b6b4578ccd518183297f6d86f20ddffe32f5af9a76fda7626c9ed804bf',
  ],
  [
    'an unsorted set holding a duplicate',
    { v: 1, issuers: ['b', 'a', 'a'], measurements: { snp: [SNP] } },
    'sha256:177ced1f104767aaa660d6e8c21d11a942a7be7b73c9df9dc25a8ddca45740d9',
  ],
];

describe('a policy document that names no time bound', () => {
  it('hashes to the digest it carried before the field existed', () => {
    for (const [label, document, digest] of CORPUS) {
      const text = JSON.stringify(document);
      expect(text, `${label}: no demand in the document`).not.toContain('maxTimeUncertaintySeconds');
      expect(policyFileDigest(parsePolicyFile(text)), label).toBe(digest);
    }
  });
});

const KEY = signingKeyFromSeed(new Uint8Array(32).fill(7));
const SIGNING_KID = toHex(KEY.kid);
const PUBLIC_KEY = toBase64Url(KEY.publicKey);
/** A second key of the same width, standing in for one that was never the signer. */
const OTHER_PUBLIC_KEY = toBase64Url(new Uint8Array(32).fill(2));
const IAT = 1_772_000_000;
const NONCE = new Uint8Array(16).fill(3);
const REQUEST_HASH = new Uint8Array(32).fill(4);
const RESPONSE_HASH = new Uint8Array(32).fill(5);
const MEASUREMENT_HEX = toHex(new Uint8Array(48).fill(6));

const RECEIPT = issueReceipt(
  {
    v: 1,
    iss: 'ashaveri-prod',
    ins: 'cvm-1',
    iat: IAT,
    nce: NONCE,
    req: REQUEST_HASH,
    res: RESPONSE_HASH,
    mdl: 'mock-model-1',
    wts: new Uint8Array(32).fill(8),
    meas: { tee: 'snp', m: new Uint8Array(48).fill(6) },
    att: { d: new Uint8Array(32).fill(9), ts: IAT - 60, url: 'https://inference.ashaveri.com/v1/attestation' },
    epk: 0,
    tok: { p: 11, c: 5 },
  } satisfies ReceiptPayload,
  KEY,
);

/**
 * The verdict the shipped verifier reaches for the receipt above under one policy. The same reading
 * `policy-verdict.test.ts` makes, reproduced here rather than imported: this file is evidence about a
 * commit boundary, and evidence that depends on a fixture it cannot freeze can move with that fixture.
 */
function verdict(policy: AshaveriPolicy, atSeconds: number): string {
  const verifyKey = policyKeyByKid(policy, KEY.kid);
  if (verifyKey === undefined) return 'KEY_NOT_PINNED';
  try {
    verifyCompletionReceipt({
      receiptBytes: RECEIPT,
      nonce: NONCE,
      requestHash: REQUEST_HASH,
      responseHash: RESPONSE_HASH,
      responseBytes: new Uint8Array(0),
      verifyKey,
      policy,
      nowMillis: atSeconds * 1000,
    });
    return 'accept';
  } catch (err) {
    if (err instanceof SdkError) return err.code;
    const code = (err as { code?: string })?.code;
    return typeof code === 'string' ? `receipt:${code}` : `unexpected:${String(err)}`;
  }
}

/** One replay row: the document as the pre-change reader wrote it, and what it decided then. */
interface Replay {
  readonly label: string;
  readonly document: Record<string, unknown>;
  readonly digest: string;
  readonly at: number;
  readonly verdict: string;
}

function policyDocument(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    v: 1,
    issuers: ['ashaveri-prod'],
    instances: ['cvm-1'],
    keys: { [SIGNING_KID]: PUBLIC_KEY },
    measurements: { snp: [MEASUREMENT_HEX] },
    maxReceiptAgeSeconds: 3600,
    maxEvidenceAgeSeconds: 7200,
    trustAnchors: { amdArks: null, intelSgxRoots: null, nvidiaRoots: null },
    ...overrides,
  };
}

const REPLAYS: readonly Replay[] = [
  {
    label: 'every pin matches',
    document: policyDocument(),
    digest: 'sha256:26417f6336664fc064bffc772285abdb0b5b86af82f24ec15a7386346a9ad1e4',
    at: IAT + 60,
    verdict: 'accept',
  },
  {
    label: 'a stale receipt',
    document: policyDocument({ maxReceiptAgeSeconds: 30 }),
    digest: 'sha256:86e53c63389b157f76a09db14b13c3364e7536047b807699688f3c659f38696c',
    at: IAT + 3600,
    verdict: 'receipt:STALE_RECEIPT',
  },
  {
    label: 'a stale evidence window',
    document: policyDocument({ maxEvidenceAgeSeconds: 30 }),
    digest: 'sha256:b46beb08c66466ccb7d927b624c56182ca2662054f7887fd0dbbaf5fa66bb919',
    at: IAT + 3600,
    verdict: 'receipt:STALE_EVIDENCE',
  },
  {
    label: 'an issuer the receipt does not name',
    document: policyDocument({ issuers: ['ashaveri-other'] }),
    digest: 'sha256:b19aefbbabe0ce52a233f211eaad8c5adbd2d4c3eab6f8b1f81d19714130f98f',
    at: IAT + 60,
    verdict: 'ISSUER_NOT_ALLOWED',
  },
  {
    label: 'an instance the receipt does not name',
    document: policyDocument({ instances: ['cvm-9'] }),
    digest: 'sha256:6bb8c4fcde993475296390bc64e51c879da428dccc764666e6e3a74b665ebc73',
    at: IAT + 60,
    verdict: 'INSTANCE_NOT_ALLOWED',
  },
  {
    label: 'a measurement the receipt does not carry',
    document: policyDocument({ measurements: { snp: [`8${MEASUREMENT_HEX.slice(1)}`] } }),
    digest: 'sha256:b6bdc26a7f105ce4c0ad2228220f1082206ad04a2c2cc62aaebf34c153f5ea92',
    at: IAT + 60,
    verdict: 'MEASUREMENT_NOT_ALLOWED',
  },
  {
    label: 'a measurement pinned under the other kind',
    document: policyDocument({ measurements: { tdx: [MEASUREMENT_HEX] } }),
    digest: 'sha256:1bb657f03a18a91cc7004d2001db6743f108ebd072e834a19121b0291b5f8fe6',
    at: IAT + 60,
    verdict: 'accept',
  },
  {
    label: 'a key that is not the one that signed',
    document: policyDocument({ keys: { [SIGNING_KID]: OTHER_PUBLIC_KEY } }),
    digest: 'sha256:b1f8a91357bdf076d742788bf1314252b8a77944e9b5d9dffeefe5a4e271698f',
    at: IAT + 60,
    verdict: 'receipt:KID_MISMATCH',
  },
  {
    label: 'no key for this kid at all',
    document: policyDocument({ keys: { ['c'.repeat(64)]: PUBLIC_KEY } }),
    digest: 'sha256:10d78dbb018a08a2c194549a5d64662f0bf0dde30b63ccabfccbdac4bf0de7ec',
    at: IAT + 60,
    verdict: 'KEY_NOT_PINNED',
  },
];

describe('the same receipt under the replayed policies', () => {
  it('reaches the verdict each policy reached before the demand existed', async () => {
    for (const item of REPLAYS) {
      const loaded = await loadPolicyFromText(JSON.stringify(item.document), TEMP);
      expect(loaded.digest, `${item.label}: the document still hashes to what it hashed to`).toBe(item.digest);
      expect(
        loaded.policy.maxTimeUncertaintySeconds,
        `${item.label}: a document naming no demand loads as demanding none`,
      ).toBeUndefined();
      expect(verdict(loaded.policy, item.at), item.label).toBe(item.verdict);
    }
  });
});
