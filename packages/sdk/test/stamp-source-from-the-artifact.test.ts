import { describe, expect, it } from 'vitest';
import {
  hashRequest,
  issueReceipt,
  signingKeyFromSeed,
  type CollateralValidityAnchor,
  type ReceiptPayload,
  type StampDisclosure,
} from '@ashaveri/receipt';
import {
  loadPolicyFromText,
  SdkError,
  verifyCompletionReceipt,
  type AshaveriPolicy,
} from '../src/index.js';

/**
 * The stamp's disclosure read off the artifact, weighed by the shipped client path.
 *
 * A receipt states where its `iat` was read from and what that source declares about itself inside its own
 * signed payload, in `sd`. The demand a reviewer writes as `maxTimeUncertaintySeconds` is weighed against
 * that member by `verifyCompletionReceipt` itself, so every verdict below is reached by handing the client
 * nothing but bytes, a policy, and the digests the receipt names for itself: no call in this file states a
 * source, and a refusal that leaned on anything outside the document could not be produced here at all.
 * That is the reader half of the pair the design settled on: the statement is in the artifact, the check
 * reads it from the artifact, and the consequence is a refusal or a printed qualification, never a figure
 * this run invented beside the stamp.
 *
 * The verdicts are pinned as strings rather than compared between calls. A policy naming no demand must
 * answer exactly what the client answered before this demand could be stated at all, and a guard that
 * fired on the absent demand would agree with itself in two identical calls while moving every one of
 * those verdicts.
 */

const KEY = signingKeyFromSeed(new Uint8Array(32).fill(11));
const IAT = 1_772_000_000;
const NONCE = new Uint8Array(16).fill(3);
const REQUEST_HASH = new Uint8Array(32).fill(4);
const EMPTY = new Uint8Array(0);
const RESPONSE_HASH = hashRequest(EMPTY);
const MEASUREMENT = new Uint8Array(48).fill(6);

const utf8 = (text: string): Uint8Array => new TextEncoder().encode(text);

const held = (label: string) => ({ presence: 'held' as const, sha256: hashRequest(utf8(label)) });
const ANCHOR_HELD_BOTH: CollateralValidityAnchor = {
  collateral: held('collateral bytes'),
  validity: held('validity bytes'),
};
const ANCHOR_BOTH_ABSENT: CollateralValidityAnchor = {
  collateral: { presence: 'absent-at-source' as const, reason: 'the source published no chain' },
  validity: { presence: 'not-taken-in' as const, reason: 'this issuer records no validity context' },
};

/** A source measured to a bound, and a source stating nobody measured, as the two spell themselves. */
const BOUNDED_1: StampDisclosure = { name: 'ptp-disciplined host clock', uncertaintySeconds: 1 };
const BOUNDED_60: StampDisclosure = { name: 'gps disciplined clock', uncertaintySeconds: 60 };
const UNMEASURED: StampDisclosure = { name: 'host clock', uncertaintySeconds: null };

/**
 * One payload at the one version this format declares, its anchor held in both halves so nothing but the
 * disclosure decides, and its marking `none` over the empty response the call below hands.
 */
function payloadOver(sd: StampDisclosure, cva: CollateralValidityAnchor = ANCHOR_HELD_BOTH): ReceiptPayload {
  return {
    v: 1,
    iss: 'dpl-9f2a41c3',
    ins: 'cvm-i-047f2a',
    iat: IAT,
    nce: NONCE,
    req: REQUEST_HASH,
    res: RESPONSE_HASH,
    mdl: 'mock-model-1',
    wts: new Uint8Array(32).fill(8),
    meas: { tee: 'snp' as const, m: MEASUREMENT },
    att: { d: new Uint8Array(32).fill(9), ts: IAT - 60, url: 'https://inference.example/v1/attestation' },
    epk: 0,
    tok: { p: 1, c: 1 },
    mk: { sch: 'none' as const, d: RESPONSE_HASH },
    sd,
    cva,
    itm: [{ t: IAT - 1, d: hashRequest(utf8('the one item of a buffered body')) }],
  };
}

function receiptOver(sd: StampDisclosure, cva: CollateralValidityAnchor = ANCHOR_HELD_BOTH): Uint8Array {
  return issueReceipt(payloadOver(sd, cva), KEY);
}

/** One receipt handed to the shipped client path, answered with a string, at the instant it names. */
function verdict(receiptBytes: Uint8Array, policy: AshaveriPolicy | undefined): string {
  try {
    verifyCompletionReceipt({
      receiptBytes,
      nonce: NONCE,
      requestHash: REQUEST_HASH,
      responseHash: RESPONSE_HASH,
      responseBytes: EMPTY,
      verifyKey: KEY.publicKey,
      ...(policy === undefined ? {} : { policy }),
      nowMillis: IAT * 1000,
    });
    return 'verify-ok';
  } catch (err) {
    if (err instanceof SdkError) return err.code;
    const code = (err as { code?: string })?.code;
    return typeof code === 'string' ? `receipt:${code}` : `unexpected:${String(err)}`;
  }
}

/** The message a refusal carried, or the empty string where the call answered instead. */
function messageOf(receiptBytes: Uint8Array, policy: AshaveriPolicy): string {
  try {
    verifyCompletionReceipt({
      receiptBytes,
      nonce: NONCE,
      requestHash: REQUEST_HASH,
      responseHash: RESPONSE_HASH,
      responseBytes: EMPTY,
      verifyKey: KEY.publicKey,
      policy,
      nowMillis: IAT * 1000,
    });
    return '';
  } catch (err) {
    return err instanceof Error ? err.message : String(err);
  }
}

const NO_DEMAND: AshaveriPolicy = { issuers: ['dpl-9f2a41c3'] };
const demandOf = (seconds: number): AshaveriPolicy => ({ issuers: ['dpl-9f2a41c3'], maxTimeUncertaintySeconds: seconds });

const docWith = (over: Record<string, unknown>): string =>
  JSON.stringify({ v: 1, issuers: ['dpl-9f2a41c3'], instances: ['cvm-i-047f2a'], ...over });

describe('the disclosure a finished receipt states about its own stamp', () => {
  it('weighs the declared bound against the demand, at the boundary and on both sides of it', () => {
    const bounded = receiptOver(BOUNDED_1);
    expect(verdict(bounded, undefined)).toBe('verify-ok');
    expect(verdict(bounded, NO_DEMAND)).toBe('verify-ok');
    expect(verdict(bounded, demandOf(1))).toBe('verify-ok');
    expect(verdict(bounded, demandOf(2))).toBe('verify-ok');
    expect(verdict(bounded, demandOf(0))).toBe('STAMP_SOURCE_TOO_UNCERTAIN');
    const wide = receiptOver(BOUNDED_60);
    expect(verdict(wide, demandOf(60))).toBe('verify-ok');
    const refusal = messageOf(wide, demandOf(5));
    expect(refusal).toContain('gps disciplined clock');
    expect(refusal).toContain('60');
    expect(refusal).toContain('5');
  });

  it('refuses the unmeasured statement under every demand and reads it as nobody measured, not as zero', () => {
    const unmeasured = receiptOver(UNMEASURED);
    expect(verdict(unmeasured, undefined)).toBe('verify-ok');
    expect(verdict(unmeasured, NO_DEMAND)).toBe('verify-ok');
    for (const demanded of [0, 1, 3600]) {
      expect(verdict(unmeasured, demandOf(demanded)), String(demanded)).toBe('STAMP_SOURCE_TOO_UNCERTAIN');
    }
    const refusal = messageOf(unmeasured, demandOf(3600));
    expect(refusal).toContain('host clock');
    expect(refusal).toContain('no measured uncertainty');
    expect(refusal).toContain('3600');
  });

  it('reaches the verdict from the artifact alone: one policy, two documents, one disclosure apart', () => {
    // Nothing in either call names a source. The two receipts differ in one signed member, so the two
    // answers can differ for one reason only, and that reason is a field of the document.
    const policy = demandOf(1);
    expect(verdict(receiptOver(BOUNDED_1), policy)).toBe('verify-ok');
    expect(verdict(receiptOver(UNMEASURED), policy)).toBe('STAMP_SOURCE_TOO_UNCERTAIN');
    // And a demand of zero tells the two declared bounds apart by the number each states, which is the
    // reading no flattened figure could give: null and 0 are one answer only to a reader that threw the
    // difference away, and here they are two refusals and one acceptance.
    expect(verdict(receiptOver({ name: 'disciplined rtc', uncertaintySeconds: 0 }), demandOf(0))).toBe('verify-ok');
    expect(verdict(receiptOver(BOUNDED_1), demandOf(0))).toBe('STAMP_SOURCE_TOO_UNCERTAIN');
    expect(verdict(receiptOver(UNMEASURED), demandOf(0))).toBe('STAMP_SOURCE_TOO_UNCERTAIN');
  });

  it('weighs the disclosure after the pins and before the anchor demands', () => {
    // The refusal owed for the earlier reason is the one given: an issuer pin is decided before the
    // stamp's own statement, the stamp's statement before the anchor's, so a document failing two
    // demands is told the earlier one and the order is one rule read in one place.
    expect(
      verdict(receiptOver(UNMEASURED), { issuers: ['somebody-else'], maxTimeUncertaintySeconds: 1, minAnchorSlotsHeld: 1 }),
    ).toBe('ISSUER_NOT_ALLOWED');
    // The measurement pin, the case the brief names: a document whose measurement is unpinned and whose
    // disclosure fails a named demand alike is told the pin, because every pin is decided before the
    // stamp's own statement is weighed at all.
    expect(
      verdict(receiptOver(UNMEASURED), { ...NO_DEMAND, measurements: { snp: ['aa'.repeat(48)] }, maxTimeUncertaintySeconds: 1 }),
    ).toBe('MEASUREMENT_NOT_ALLOWED');
    expect(
      verdict(receiptOver(UNMEASURED, ANCHOR_BOTH_ABSENT), { ...NO_DEMAND, maxTimeUncertaintySeconds: 1, minAnchorSlotsHeld: 1 }),
    ).toBe('STAMP_SOURCE_TOO_UNCERTAIN');
    expect(
      verdict(receiptOver(BOUNDED_1, ANCHOR_BOTH_ABSENT), { ...NO_DEMAND, maxTimeUncertaintySeconds: 1, minAnchorSlotsHeld: 1 }),
    ).toBe('ANCHOR_SLOT_NOT_HELD');
  });

  it('answers the same under the demand an operator wrote in a document as under the object route', async () => {
    const loaded = await loadPolicyFromText(docWith({ maxTimeUncertaintySeconds: 1 }), '.');
    expect(loaded.policy.maxTimeUncertaintySeconds).toBe(1);
    expect(verdict(receiptOver(UNMEASURED), loaded.policy)).toBe('STAMP_SOURCE_TOO_UNCERTAIN');
    expect(verdict(receiptOver(BOUNDED_1), loaded.policy)).toBe('verify-ok');
    const nothing = await loadPolicyFromText(docWith({ maxTimeUncertaintySeconds: null }), '.');
    expect(nothing.policy.maxTimeUncertaintySeconds).toBeUndefined();
    expect(verdict(receiptOver(UNMEASURED), nothing.policy)).toBe('verify-ok');
  });

  it('names the source the document states, never one this run knew', () => {
    const named = receiptOver({ name: 'fixture clock', uncertaintySeconds: 7 });
    const refusal = messageOf(named, demandOf(3));
    expect(refusal).toContain("read from 'fixture clock'");
    expect(verdict(named, demandOf(7))).toBe('verify-ok');
  });
});
