import { equalBytes, verifyReceipt, type VerifiedReceipt } from '@ashaveri/receipt';
import { toHex } from './b64.js';
import { SdkError } from './errors.js';
import type { AshaveriPolicy } from './policy.js';

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
 */
export function verifyCompletionReceipt(params: VerifyCompletionParams): VerifiedReceipt {
  const now = Math.floor((params.now ?? Date.now()) / 1000);
  const policy = params.policy;
  const verified = verifyReceipt(params.receiptBytes, {
    publicKey: params.verifyKey,
    expectedNonce: params.nonce,
    now,
    freshnessSeconds: policy?.maxReceiptAgeSeconds,
    evidenceFreshnessSeconds: policy?.maxEvidenceAgeSeconds,
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
