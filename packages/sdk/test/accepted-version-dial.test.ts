import { describe, expect, it } from 'vitest';
import { hashRequest, issueReceipt, signingKeyFromSeed, type ReceiptPayload } from '@ashaveri/receipt';
import { verifyCompletionReceipt } from '../src/index.js';

/**
 * The accepted-version set on the client verify entry point.
 *
 * `verifyReceipt` in the format package already read this set; the client path that wraps it is the entry a caller
 * reaches with a response in hand, so the dial has to travel through it. The cases are the four the setting owes at
 * every surface: a version 2 document refused when the caller names only `[1]`, the same document taken when the
 * caller names nothing, the same document taken when it names `[2]`, and the refusal naming both the caller's set and
 * the number the document states rather than only a code. The document is a complete and authentic one, so the
 * default and the `[2]` readings reach a verdict rather than stopping at the version gate.
 */

const KEY = signingKeyFromSeed(new Uint8Array(32).fill(11));
const IAT = 1_772_000_000;
const NONCE = new Uint8Array(16).fill(3);
const REQUEST_HASH = new Uint8Array(32).fill(4);
const EMPTY = new Uint8Array(0);
const RESPONSE_HASH = hashRequest(EMPTY);

const utf8 = (text: string): Uint8Array => new TextEncoder().encode(text);

const RECEIPT = issueReceipt(
  {
    v: 2,
    iss: 'dpl-9f2a41c3',
    ins: 'cvm-i-047f2a',
    iat: IAT,
    nce: NONCE,
    req: REQUEST_HASH,
    res: RESPONSE_HASH,
    mdl: 'mock-model-1',
    wts: new Uint8Array(32).fill(8),
    meas: { tee: 'snp' as const, m: new Uint8Array(48).fill(6) },
    att: { d: new Uint8Array(32).fill(9), ts: IAT - 60, url: 'https://inference.example/v1/attestation' },
    epk: 0,
    tok: { p: 1, c: 1 },
    mk: { sch: 'none' as const, d: RESPONSE_HASH },
    sd: { name: 'host clock', uncertaintySeconds: null },
    cva: {
      collateral: { presence: 'not-taken-in' as const, reason: 'this test signs no collateral into the record' },
      validity: { presence: 'not-taken-in' as const, reason: 'this test records no validity context' },
    },
    itm: [{ t: IAT - 1, d: hashRequest(utf8('the one item of a buffered body')) }],
    enc: { sch: 'none' as const },
  } satisfies ReceiptPayload,
  KEY,
);

function outcome(acceptedVersions?: readonly number[]): { readonly code: string; readonly message: string; readonly version?: number } {
  try {
    const verified = verifyCompletionReceipt({
      receiptBytes: RECEIPT,
      nonce: NONCE,
      requestHash: REQUEST_HASH,
      responseHash: RESPONSE_HASH,
      responseBytes: EMPTY,
      verifyKey: KEY.publicKey,
      nowMillis: IAT * 1000,
      ...(acceptedVersions === undefined ? {} : { acceptedVersions: acceptedVersions as readonly (1 | 2)[] }),
    });
    return { code: 'verify-ok', message: '', version: verified.payload.v };
  } catch (err) {
    const error = err as { code?: string; message?: string };
    return { code: error.code ?? 'unexpected', message: error.message ?? '' };
  }
}

describe('verifyCompletionReceipt accepted-version dial', () => {
  it('refuses a version 2 document the caller narrowed away, and takes it by default and at [2]', () => {
    expect(outcome().version).toBe(2);
    expect(outcome([2]).version).toBe(2);

    const refused = outcome([1]);
    expect(refused.code).toBe('UNSUPPORTED_VERSION');
    expect(refused.message).toContain('receipt payload version 2 is not in acceptedVersions [1]');
  });
});
