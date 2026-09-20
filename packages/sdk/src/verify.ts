import { equalBytes, verifyReceipt, type VerifiedReceipt } from '@ashaveri/receipt';
import { toHex } from './b64.js';
import { SdkError } from './errors.js';
import type { AshaveriPolicy } from './policy.js';
import { DEFAULT_MAX_EVIDENCE_AGE_SECONDS, DEFAULT_MAX_RECEIPT_AGE_SECONDS } from './policy.js';

export interface VerifyCompletionParams {
  readonly receiptBytes: Uint8Array;
  readonly nonce: Uint8Array;
  readonly requestHash: Uint8Array;
  readonly responseHash: Uint8Array;
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
