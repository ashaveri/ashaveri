import {
  equalBytes,
  extractMarkedRegion,
  hashRequest,
  ReceiptError,
  verifyReceipt,
  type ReceiptPayloadV2,
  type VerifiedReceipt,
} from '@ashaveri/receipt';
import { toHex } from './b64.js';
import { SdkError } from './errors.js';
import type { AshaveriPolicy } from './policy.js';
import { DEFAULT_MAX_EVIDENCE_AGE_SECONDS, DEFAULT_MAX_RECEIPT_AGE_SECONDS } from './policy.js';

export interface VerifyCompletionParams {
  readonly receiptBytes: Uint8Array;
  readonly nonce: Uint8Array;
  readonly requestHash: Uint8Array;
  readonly responseHash: Uint8Array;
  /**
   * The response bytes themselves, not only their digest. Required rather than optional so that a
   * live verification cannot be run in a shape that quietly skips the marking check: a v2 receipt
   * attests a region inside these bytes, and the only way to honour that claim is to read it off the
   * bytes the caller received.
   *
   * The caller has to hand the same bytes it hashed into `responseHash`. That is checked rather than
   * assumed for a receipt that carries a marking claim, because a region lifted out of bytes the
   * receipt does not attest would be a verdict on the wrong document.
   */
  readonly responseBytes: Uint8Array;
  readonly verifyKey: Uint8Array;
  readonly policy?: AshaveriPolicy;
  /** Wall clock in milliseconds since the epoch; defaults to Date.now. */
  readonly now?: number;
}

/**
 * Verifies a receipt against everything the client observed on the wire:
 * the signing key, the nonce it sent, and the exact request/response body
 * bytes it sent and received. Throws SdkError or ReceiptError on failure.
 *
 * The response bytes are checked twice, and the second check is the marking claim: a v2 receipt
 * carries `mk.d`, the digest of one region inside the response, and it is verified here rather than
 * left to someone who kept the bytes and thought to look. The signature and the payload checks come
 * first, so this only ever runs over a document that is authentic.
 *
 * With a policy, this is where the two freshness windows close: the policy's own numbers if it
 * names them, the defaults in `policy.ts` if it does not. With no policy, no window runs.
 */
export function verifyCompletionReceipt(params: VerifyCompletionParams): VerifiedReceipt {
  const now = Math.floor((params.now ?? Date.now()) / 1000);
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
  // makes. The only off switch on this side of that line is a policy that says
  // `Number.POSITIVE_INFINITY` for one of the two, which is a decision written down rather than
  // one left out.
  const receiptWindow =
    policy === undefined ? undefined : (policy.maxReceiptAgeSeconds ?? DEFAULT_MAX_RECEIPT_AGE_SECONDS);
  const evidenceWindow =
    policy === undefined ? undefined : (policy.maxEvidenceAgeSeconds ?? DEFAULT_MAX_EVIDENCE_AGE_SECONDS);
  const verified = verifyReceipt(params.receiptBytes, {
    publicKey: params.verifyKey,
    expectedNonce: params.nonce,
    now,
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
  if (payload.v === 2) {
    verifyMarkedRegion(payload, params.responseBytes);
  }
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
  return verified;
}

/**
 * The marking claim of a v2 receipt, read off the bytes this call was handed.
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
 * A v1 receipt never reaches this function, because it carries no `mk` and so makes no claim to
 * check. That asymmetry is the format's, not a relaxation added here.
 *
 * The codes are the format package's. `MARK_MISMATCH` is what a reader needs in order to tell "the
 * marking does not match" apart from "the receipt is not authentic", which stays
 * `INVALID_SIGNATURE`'s meaning alone; the refusal of a label no verifier can interpret is
 * `UNSUPPORTED_SCHEME`, already raised by the parser before a payload reaches this point. Nothing
 * here adds to `SdkError`'s vocabulary beyond the response-digest refusal it already had.
 */
function verifyMarkedRegion(payload: ReceiptPayloadV2, responseBytes: Uint8Array): void {
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
