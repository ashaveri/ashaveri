import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { issueReceipt, signingKeyFromSeed, type ReceiptPayload } from '@ashaveri/receipt';
import {
  SdkError,
  loadPolicyFile,
  loadPolicyFromText,
  policyFileDigest,
  policyFileFromPolicy,
  policyFileToJson,
  policyKeyByKid,
  toBase64Url,
  toHex,
  verifyCompletionReceipt,
  type AshaveriPolicy,
} from '../src/index.js';

/**
 * The promise the file form exists to keep: a policy read out of a document reaches the same verdict
 * on the same receipt as the identical policy built in code. Everything below is one receipt, one
 * signing key, and a table of policies run through both routes.
 */

const TEMP = mkdtempSync(join(tmpdir(), 'ashaveri-policy-verdict-'));
afterAll(() => {
  rmSync(TEMP, { recursive: true, force: true });
});

const KEY = signingKeyFromSeed(new Uint8Array(32).fill(7));
const KID = toHex(KEY.kid);
const PUBLIC_KEY = toBase64Url(KEY.publicKey);
/** A second key of the same width, to stand in for one that was never pinned. */
const OTHER_PUBLIC_KEY = toBase64Url(new Uint8Array(32).fill(2));

const IAT = 1_772_000_000;
const NONCE = new Uint8Array(16).fill(3);
const REQUEST_HASH = new Uint8Array(32).fill(4);
const RESPONSE_HASH = new Uint8Array(32).fill(5);
const MEASUREMENT = new Uint8Array(48).fill(6);
const MEASUREMENT_HEX = toHex(MEASUREMENT);

const PAYLOAD: ReceiptPayload = {
  v: 1,
  iss: 'ashaveri-prod',
  ins: 'cvm-1',
  iat: IAT,
  nce: NONCE,
  req: REQUEST_HASH,
  res: RESPONSE_HASH,
  mdl: 'mock-model-1',
  wts: new Uint8Array(32).fill(8),
  meas: { tee: 'snp', m: MEASUREMENT },
  att: { d: new Uint8Array(32).fill(9), ts: IAT - 60, url: 'https://inference.ashaveri.com/v1/attestation' },
  epk: 0,
  tok: { p: 11, c: 5 },
};

const RECEIPT = issueReceipt(PAYLOAD, KEY);

/** One clock per case: the stale row needs a receipt that has aged, the rest have not. */
function verdict(policy: AshaveriPolicy, atSeconds: number): string {
  const verifyKey = policyKeyByKid(policy, KEY.kid);
  if (verifyKey === undefined) return 'KEY_NOT_PINNED';
  try {
    verifyCompletionReceipt({
      receiptBytes: RECEIPT,
      nonce: NONCE,
      requestHash: REQUEST_HASH,
      responseHash: RESPONSE_HASH,
      verifyKey,
      policy,
      now: atSeconds * 1000,
    });
    return 'accept';
  } catch (err) {
    if (err instanceof SdkError) return err.code;
    const code = (err as { code?: string })?.code;
    return typeof code === 'string' ? `receipt:${code}` : `unexpected:${String(err)}`;
  }
}

/** Every dimension the policy can pin, all of them matching the receipt above. */
const ACCEPTING: AshaveriPolicy = {
  issuers: ['ashaveri-prod'],
  instances: ['cvm-1'],
  keys: { [KID]: PUBLIC_KEY },
  measurements: { snp: [MEASUREMENT_HEX] },
  maxReceiptAgeSeconds: 3600,
  maxEvidenceAgeSeconds: 7200,
};

interface Case {
  readonly name: string;
  readonly policy: AshaveriPolicy;
  readonly at: number;
  readonly expect: string;
}

const CASES: readonly Case[] = [
  { name: 'every pin matches', policy: ACCEPTING, at: IAT + 60, expect: 'accept' },
  {
    name: 'a stale receipt',
    policy: { ...ACCEPTING, maxReceiptAgeSeconds: 30 },
    at: IAT + 3600,
    expect: 'receipt:STALE_RECEIPT',
  },
  {
    name: 'a stale evidence window',
    policy: { ...ACCEPTING, maxEvidenceAgeSeconds: 30 },
    at: IAT + 3600,
    expect: 'receipt:STALE_EVIDENCE',
  },
  {
    name: 'an issuer the receipt does not name',
    policy: { ...ACCEPTING, issuers: ['ashaveri-other'] },
    at: IAT + 60,
    expect: 'ISSUER_NOT_ALLOWED',
  },
  {
    name: 'an instance the receipt does not name',
    policy: { ...ACCEPTING, instances: ['cvm-9'] },
    at: IAT + 60,
    expect: 'INSTANCE_NOT_ALLOWED',
  },
  {
    name: 'a measurement the receipt does not carry',
    policy: { ...ACCEPTING, measurements: { snp: [`8${MEASUREMENT_HEX.slice(1)}`] } },
    at: IAT + 60,
    expect: 'MEASUREMENT_NOT_ALLOWED',
  },
  {
    name: 'a measurement pinned under the other kind',
    policy: { ...ACCEPTING, measurements: { tdx: [MEASUREMENT_HEX] } },
    at: IAT + 60,
    expect: 'accept',
  },
  {
    name: 'a key that is not the one that signed',
    policy: { ...ACCEPTING, keys: { [KID]: OTHER_PUBLIC_KEY } },
    at: IAT + 60,
    expect: 'receipt:KID_MISMATCH',
  },
  {
    name: 'no key for this kid at all',
    policy: { ...ACCEPTING, keys: { ['c'.repeat(64)]: PUBLIC_KEY } },
    at: IAT + 60,
    expect: 'KEY_NOT_PINNED',
  },
];

describe('a policy file and a policy object reach the same verdict', () => {
  it('accepts the matching receipt both ways round', async () => {
    const loaded = await loadPolicyFromText(policyFileToJson(policyFileFromPolicy(ACCEPTING)), TEMP);
    expect(verdict(ACCEPTING, IAT + 60)).toBe('accept');
    expect(verdict(loaded.policy, IAT + 60)).toBe('accept');
  });

  it('refuses on the same named code through either route', async () => {
    for (const item of CASES) {
      const throughObject = verdict(item.policy, item.at);
      const file = policyFileFromPolicy(item.policy);
      const loaded = await loadPolicyFromText(policyFileToJson(file), TEMP);
      expect(throughObject, item.name).toBe(item.expect);
      expect(verdict(loaded.policy, item.at), `${item.name} through the file`).toBe(item.expect);
      expect(loaded.policy.issuers, item.name).toEqual(item.policy.issuers);
      expect(loaded.policy.measurements, item.name).toEqual(item.policy.measurements);
      expect(loaded.policy.maxReceiptAgeSeconds ?? null, item.name).toEqual(file.maxReceiptAgeSeconds);
      expect(loaded.policy.maxEvidenceAgeSeconds ?? null, item.name).toEqual(file.maxEvidenceAgeSeconds);
    }
  });

  it('gives one digest to two differently formatted files, and refuses a third that adds a key', async () => {
    const file = policyFileFromPolicy(ACCEPTING);
    const written = join(TEMP, 'policy.json');
    const reformatted = join(TEMP, 'policy-reformatted.json');
    writeFileSync(written, policyFileToJson(file));
    // The same policy with its keys inserted in another order, another indentation and CRLF line
    // endings: three ways a formatter, an editor or a checkout changes a file's bytes.
    const reordered = {
      trustAnchors: { nvidiaRoots: null, intelSgxRoots: null, amdArks: null },
      measurements: { snp: [MEASUREMENT_HEX] },
      keys: { [KID]: PUBLIC_KEY },
      instances: ['cvm-1'],
      issuers: ['ashaveri-prod'],
      maxReceiptAgeSeconds: 3600,
      maxEvidenceAgeSeconds: 7200,
      v: 1,
    };
    writeFileSync(reformatted, `${JSON.stringify(reordered, null, 4).replace(/\n/gu, '\r\n')}\r\n`);

    const asRead = await loadPolicyFile(written);
    const asReformatted = await loadPolicyFile(reformatted);
    expect(readFileSync(written)).not.toEqual(readFileSync(reformatted));
    expect(asRead.digest).toBe(asReformatted.digest);
    expect(policyFileDigest(file)).toBe(asRead.digest);
    expect(asRead.digest).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(verdict(asRead.policy, IAT + 60)).toBe(verdict(asReformatted.policy, IAT + 60));

    // The same document with one key the format does not define. The object form has no equivalent to
    // disagree with, so the file has to refuse rather than read past it.
    const withExtraKey = join(TEMP, 'policy-unknown-key.json');
    writeFileSync(withExtraKey, JSON.stringify({ ...reordered, issuer: 'ashaveri-prod' }, null, 2));
    const err = await loadPolicyFile(withExtraKey).catch((cause: unknown) => cause);
    expect(err).toBeInstanceOf(SdkError);
    expect((err as SdkError).code).toBe('POLICY_FILE_INVALID');
    expect((err as SdkError).message).toContain("unknown key 'issuer'");
    // No digest is published for the refused document: the refusal happens while it is read, so no
    // identity ever attaches to a policy that dropped a field the operator wrote.
    expect(() => policyFileDigest(JSON.parse(JSON.stringify({ ...reordered, issuer: 'x' })) as never)).toThrow(
      /unknown key 'issuer'/u,
    );
  });

  it('changes the digest when the pin that decides the verdict changes', () => {
    const accepted = policyFileDigest(policyFileFromPolicy(ACCEPTING));
    const repointed = policyFileDigest(policyFileFromPolicy({ ...ACCEPTING, keys: { [KID]: OTHER_PUBLIC_KEY } }));
    const stale = policyFileDigest(policyFileFromPolicy({ ...ACCEPTING, maxReceiptAgeSeconds: 30 }));
    expect(new Set([accepted, repointed, stale]).size).toBe(3);
  });
});
