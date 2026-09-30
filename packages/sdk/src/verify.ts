import {
  equalBytes,
  extractMarkedRegion,
  hashRequest,
  ReceiptError,
  verifyReceipt,
  type Marking,
  type VerifiedReceipt,
} from '@ashaveri/receipt';
import { toHex } from './b64.js';
import { SdkError } from './errors.js';
import type { AshaveriPolicy } from './policy.js';
import { assertAnchorHeldUnderPolicy } from './policy.js';
import { DEFAULT_MAX_EVIDENCE_AGE_SECONDS, DEFAULT_MAX_RECEIPT_AGE_SECONDS } from './policy.js';

export interface VerifyCompletionParams {
  readonly receiptBytes: Uint8Array;
  readonly nonce: Uint8Array;
  readonly requestHash: Uint8Array;
  readonly responseHash: Uint8Array;
  /**
   * The response bytes themselves, not only their digest. Required rather than optional so that a
   * live verification cannot be run in a shape that quietly skips the marking check: a receipt whose
   * payload names a marking attests a region inside these bytes, and the only way to honour that
   * claim is to read it off the bytes the caller received. Which payloads name one is a fact about the
   * `mk` member, not about a version number: `v: 1` names none, and every version that does is checked.
   *
   * The caller has to hand the same bytes it hashed into `responseHash`. That is checked rather than
   * assumed for a receipt that carries a marking claim, because a region lifted out of bytes the
   * receipt does not attest would be a verdict on the wrong document.
   */
  readonly responseBytes: Uint8Array;
  readonly verifyKey: Uint8Array;
  readonly policy?: AshaveriPolicy;
  /**
   * The instant the client read its answer, in whole milliseconds since the Unix epoch; defaults to
   * `Date.now`. It is the client's own clock, and the format's two windows are closed against it after
   * it has been turned into the seconds the stamps are counted in.
   *
   * A reading is refused by `CLIENT_CLOCK_OUT_OF_RANGE` when it is not a whole number of milliseconds
   * in the span this estate's instants are counted in. That is the argument's fault and not the
   * receipt's: a seconds figure in this parameter answers `STALE_RECEIPT` about an honest document,
   * which is a verdict nobody earned.
   */
  readonly nowMillis?: number;
}

/**
 * The two ends of the span a handed client clock is weighed in, in whole milliseconds. They are the
 * same two instants the format's reader states for its own seconds parameter, spelled in the unit this
 * one names: the first ten-digit Unix second times a thousand, and the last second a four-byte Unix
 * counter states before it rolls over, times a thousand.
 *
 * The lower end is what catches the mistake this refuses. A seconds figure handed into a milliseconds
 * parameter reads here as a day in 1970, and the divide below turns it into a stamp no receipt of this
 * estate is near, so every honest document would come back stale. A reading above the upper end is the
 * same class of misspelling at the other scale.
 */
const EARLIEST_CLOCK_MILLIS = 1_000_000_000_000;
const LATEST_CLOCK_MILLIS = 4_294_967_295_000;

/**
 * The one question asked of a handed clock, before a byte of the receipt is read.
 *
 * Nothing here decides which scale the number came from; the band does that by excluding the other
 * scale's magnitude for every instant this format can be asked about, so a caller handing a plausible
 * reading never meets a guess about what they meant to write.
 */
function assertClockMillis(handed: number): void {
  if (
    !Number.isSafeInteger(handed) ||
    handed < EARLIEST_CLOCK_MILLIS ||
    handed > LATEST_CLOCK_MILLIS
  ) {
    throw new SdkError(
      'CLIENT_CLOCK_OUT_OF_RANGE',
      `params.nowMillis of ${String(handed)} is not a whole number of milliseconds between ${String(
        EARLIEST_CLOCK_MILLIS,
      )} and ${String(LATEST_CLOCK_MILLIS)}: hand the instant in whole milliseconds, as Date.now spells it, or hand nothing and this client reads its own host clock`,
    );
  }
}

/**
 * Verifies a receipt against everything the client observed on the wire:
 * the signing key, the nonce it sent, and the exact request/response body
 * bytes it sent and received. Throws SdkError or ReceiptError on failure.
 *
 * The response bytes are checked twice, and the second check is the marking claim: a payload that
 * names a marking carries `mk.d`, the digest of one region inside the response, and it is verified
 * here rather than left to someone who kept the bytes and thought to look. The signature and the
 * payload checks come first, so this only ever runs over a document that is authentic.
 *
 * With a policy, this is where the two freshness windows close: the policy's own numbers if it
 * names them, the defaults in `policy.ts` if it does not. With no policy, no window runs.
 */
export function verifyCompletionReceipt(params: VerifyCompletionParams): VerifiedReceipt {
  // The client's clock is asked its question before a byte of the document is read, because a reading
  // that is not a count of milliseconds in this estate's span is the caller's argument to fix. Refusing
  // it here is what keeps the two windows below measuring the receipt rather than measuring the caller's
  // scale against the format's, which is the wrong verdict this entry met once already.
  const handed = params.nowMillis;
  if (handed !== undefined) assertClockMillis(handed);
  const nowSeconds = Math.floor((handed ?? Date.now()) / 1000);
  const policy = params.policy;
  // A policy carries these two windows whether its owner set them or not, and a policy is what
  // strict mode requires: a caller who pinned keys and measurements and never thought about the
  // clock is checked against the shipped defaults. `receipt` mode has no policy, so it gets no
  // window either, which is honest rather than a hole: what binds a receipt to the request being
  // verified there is the nonce the client chose for it.
  //
  // The rule is deliberately not pushed down into `verifyReceipt`. That package is the format
  // verifier an auditor runs on a receipt from last year with no policy in sight, and it refuses a
  // clock it was not handed; a default there would break the archiving promise the receipt spec
  // makes. The off switch beside that line is in this object, and it is a number: naming
  // `Number.POSITIVE_INFINITY` for one of the two leaves that one window open, which is a decision
  // written down rather than one left out. The document form spells no such reading, because a
  // version 1 document carries each window as a whole number of seconds or as `null`, and `null` on
  // either of those keys is the absent field above with the shipped default running.
  // `policyFileFromPolicy` refuses a non-finite window rather than writing one out as `null`.
  const receiptWindow =
    policy === undefined ? undefined : (policy.maxReceiptAgeSeconds ?? DEFAULT_MAX_RECEIPT_AGE_SECONDS);
  const evidenceWindow =
    policy === undefined ? undefined : (policy.maxEvidenceAgeSeconds ?? DEFAULT_MAX_EVIDENCE_AGE_SECONDS);
  const verified = verifyReceipt(params.receiptBytes, {
    publicKey: params.verifyKey,
    expectedNonce: params.nonce,
    nowSeconds,
    freshnessSeconds: receiptWindow,
    evidenceFreshnessSeconds: evidenceWindow,
  });
  const payload = verified.payload;
  if (!equalBytes(payload.req, params.requestHash)) {
    throw new SdkError(
      'REQUEST_HASH_MISMATCH',
      `receipt request hash ${toHex(payload.req)} does not match the request that was sent (${toHex(params.requestHash)})`,
    );
  }
  if (!equalBytes(payload.res, params.responseHash)) {
    throw new SdkError(
      'RESPONSE_HASH_MISMATCH',
      `receipt response hash ${toHex(payload.res)} does not match the response that was received (${toHex(params.responseHash)})`,
    );
  }
  // Every payload this format reads names `mk`, so the marking check is owed by every receipt that gets
  // this far rather than gated on which number a document claims. A condition spelled as
  // `payload.v === N` is a list of the versions someone thought of, and the gate that goes quiet about
  // the one document it was written for answers nothing wrong about the receipt it skipped.
  verifyMarkedRegion(payload, params.responseBytes);
  if (policy?.issuers !== undefined && !policy.issuers.includes(payload.iss)) {
    throw new SdkError('ISSUER_NOT_ALLOWED', `receipt issuer '${payload.iss}' is not pinned by the policy`);
  }
  if (policy?.instances !== undefined && !policy.instances.includes(payload.ins)) {
    throw new SdkError('INSTANCE_NOT_ALLOWED', `receipt instance '${payload.ins}' is not pinned by the policy`);
  }
  const allowedMeasurements = policy?.measurements?.[payload.meas.tee];
  if (allowedMeasurements !== undefined && !allowedMeasurements.includes(toHex(payload.meas.m))) {
    throw new SdkError(
      'MEASUREMENT_NOT_ALLOWED',
      `receipt measurement ${toHex(payload.meas.m)} (tee ${payload.meas.tee}) is not pinned by the policy`,
    );
  }
  // What the policy demands of an anchor, weighed last among the policy's own questions. The order is the
  // same one the pins keep: a receipt this policy would not trust an issuer or a measurement from is
  // refused for that reason before anybody reads its claims about what it took in, and a caller that
  // failed two of them is told the earlier one.
  //
  // Every payload this format reads names an anchor, so the demand is owed by every receipt that gets this
  // far, which is how the marking check above is owed, for the same reason: what makes this demand owed is
  // an anchor in the payload, and a condition spelled as a list of versions would be missing the next one
  // that carries the member while every gate stayed green. `policy.ts` says what the demand reaches at
  // `assertAnchorHeldUnderPolicy`, and the row this code earns in `docs/error-codes.md` is where a reader
  // learns which states it reaches and which it does not.
  assertAnchorHeldUnderPolicy(policy, payload.cva);
  return verified;
}

/**
 * The marking claim of a receipt that names one, read off the bytes this call was handed.
 *
 * Three checks in this order, and the order carries the meaning. The response digest is recomputed
 * over the bytes first, so a region taken from a document the receipt does not attest cannot become a
 * verdict: the `responseHash` check above proves the caller's digest matches the receipt, and this
 * proves the bytes it was handed are the bytes that digest was taken over. Two failures of that check
 * look alike to a caller and are not the same event, so the message names which side moved. The
 * region is then extracted by the rule its own label names, held by `@ashaveri/receipt` rather than
 * duplicated here, which is what makes the client's verdict and a third party's detector verdict
 * about the same bytes. Finally the region's digest is compared.
 *
 * The argument is the two members this check reads rather than the whole payload, so the check says what
 * it weighs and nothing else: a step typed against a version's payload shape is the list-of-versions
 * failure in another place, and the compiler would not catch it either.
 *
 * Every payload this reader opens names a marking, so there is no receipt for which this is not owed.
 *
 * The codes are the format package's. `MARK_MISMATCH` is what a reader needs in order to tell "the
 * marking does not match" apart from "the receipt is not authentic", which stays
 * `INVALID_SIGNATURE`'s meaning alone; the refusal of a label no verifier can interpret is
 * `UNSUPPORTED_SCHEME`, already raised by the parser before a payload reaches this point. Nothing
 * here adds to `SdkError`'s vocabulary beyond the response-digest refusal it already had.
 */
function verifyMarkedRegion(payload: { readonly res: Uint8Array; readonly mk: Marking }, responseBytes: Uint8Array): void {
  if (!equalBytes(hashRequest(responseBytes), payload.res)) {
    throw new SdkError(
      'RESPONSE_HASH_MISMATCH',
      `the response bytes handed for the marking check do not hash to the digest the receipt attests (${toHex(payload.res)})`,
    );
  }
  const region = extractMarkedRegion(payload.mk.sch, responseBytes);
  if (!equalBytes(hashRequest(region), payload.mk.d)) {
    throw new ReceiptError(
      'MARK_MISMATCH',
      `the ${payload.mk.sch} region of these bytes hashes to ${toHex(hashRequest(region))}, not to the ${toHex(payload.mk.d)} the receipt carries`,
    );
  }
}
