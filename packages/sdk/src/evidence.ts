import {
  AttestationError,
  DEFAULT_AMD_ARKS,
  DEFAULT_INTEL_SGX_ROOTS,
  pinnedComposeHash,
  platformMeasurement,
  verifyAttestation,
  type RuntimeEvent,
  type VerificationResult,
} from '@ashaveri/attest-core';
import { MEASUREMENT_BYTES, equalBytes, type ReceiptPayload, type TeeKind } from '@ashaveri/receipt';
import { sha256 } from '@noble/hashes/sha2.js';
import { toHex } from './b64.js';
import { SdkError } from './errors.js';

/**
 * Pins for the vendor roots evidence must chain to. Omitting a family uses the
 * bundled default; setting it replaces the default outright, so an empty array
 * means "trust nothing in this family" and strict mode then refuses to guess.
 */
export interface EvidenceTrustAnchors {
  readonly amdArks?: readonly Uint8Array[];
  readonly intelSgxRoots?: readonly Uint8Array[];
}

export interface VerifyEvidenceParams {
  /** The `VersionedAttestation` document the gateway served for this request. */
  readonly document: Uint8Array;
  /** The digest the evidence had to be bound to: `evidenceReportData(nonce, requestHash)`. */
  readonly expectedReportData: Uint8Array;
  /** The already verified receipt payload, which the evidence must agree with. */
  readonly payload: ReceiptPayload;
  readonly anchors?: EvidenceTrustAnchors;
  /** Wall clock in milliseconds since the epoch; defaults to Date.now. */
  readonly now?: number;
}

export interface VerifiedEvidence {
  readonly tee: TeeKind;
  readonly platformKind: VerificationResult['platformKind'];
  /** The launch measurement the hardware attested to: SNP launch digest or TDX MRTD. */
  readonly measurement: Uint8Array;
  /** The compose hash the measured event log committed to, when the platform recorded one. */
  readonly composeHash: Uint8Array | null;
  readonly reportData: Uint8Array;
  readonly runtimeEvents: readonly RuntimeEvent[];
  readonly document: Uint8Array;
  /** True by construction: this type only exists once the platform signature verified. */
  readonly quoteSignatureVerified: true;
}

const PLATFORM_TEE_KINDS: Readonly<Record<VerificationResult['platformKind'], readonly TeeKind[]>> = {
  // SNP evidence attests the CPU launch digest only. A deployment labelled
  // 'snp+h100cc' also claims the H100 is in confidential-compute mode, which
  // this quote cannot show; the measurement pin is what binds the label to a
  // specific image either way.
  'sev-snp': ['snp', 'snp+h100cc'],
  tdx: ['tdx'],
};

/**
 * Refuses to look for hardware evidence where none can exist.
 *
 * Called before the fetch as well as during verification: a receipt that
 * declares `tee: 'software'` is a claim about the deployment, not about the
 * document, so no evidence endpoint could ever satisfy it and the request
 * would only add latency to a rejection we are already certain of.
 */
export function requireHardwareEvidence(tee: TeeKind): void {
  if (tee === 'software') {
    throw new SdkError(
      'EVIDENCE_NOT_HARDWARE',
      "strict mode requires platform evidence but the receipt declares tee 'software', which claims no hardware protection",
    );
  }
}

/**
 * The report data a gateway must attest to for one request.
 *
 * Mirrors the gateway's own rule (server.ts): the digest of the client nonce
 * joined with the hash of the exact request bytes. Recomputing it here rather
 * than trusting a value off the wire is what makes the evidence unforgeable and
 * non-replayable: only that instance, at that moment, could have quoted it.
 */
export function evidenceReportData(nonce: Uint8Array, requestHash: Uint8Array): Uint8Array {
  const bound = new Uint8Array(nonce.length + requestHash.length);
  bound.set(nonce, 0);
  bound.set(requestHash, nonce.length);
  return sha256(bound);
}

/**
 * Ties the hardware evidence to a verified receipt, and both to the request.
 *
 * Four independent facts have to line up: the bytes served hash to the `att.d`
 * the gateway signed into the receipt, the quote's report data is the digest of
 * this nonce and request, the platform signature chains to a pinned vendor root,
 * and the measurement the hardware reports equals the one the receipt claims.
 * The last of these is what stops a valid quote from an unrelated CVM from
 * satisfying a receipt for a deployment the client pinned.
 *
 * The byte checks run before signature verification so a mismatched document is
 * rejected without paying for the certificate chain.
 */
export function verifyCompletionEvidence(params: VerifyEvidenceParams): VerifiedEvidence {
  const { document, expectedReportData, payload } = params;
  const tee = payload.meas.tee;
  requireHardwareEvidence(tee);
  if (!equalBytes(sha256(document), payload.att.d)) {
    throw new SdkError(
      'EVIDENCE_DIGEST_MISMATCH',
      `sha256 of the served evidence is ${toHex(sha256(document))}, the receipt signed ${toHex(payload.att.d)}`,
    );
  }

  const anchors: EvidenceTrustAnchors = params.anchors ?? {};
  const trustedArks = anchors.amdArks ?? DEFAULT_AMD_ARKS;
  const trustedIntelRoots = anchors.intelSgxRoots ?? DEFAULT_INTEL_SGX_ROOTS;
  const requiredRoots = tee === 'tdx' ? trustedIntelRoots : trustedArks;
  if (requiredRoots.length === 0) {
    throw new SdkError(
      'EVIDENCE_NO_TRUST_ANCHORS',
      `no pinned root is configured for tee '${tee}', so the quote signature cannot be verified offline`,
    );
  }

  let result: VerificationResult;
  try {
    result = verifyAttestation(document, {
      trustedArks,
      trustedIntelRoots,
      now: params.now,
    });
  } catch (err) {
    if (err instanceof AttestationError) {
      throw new SdkError('EVIDENCE_VERIFICATION_FAILED', `${err.code}: ${err.message}`);
    }
    throw err;
  }

  if (!result.quoteSignatureVerified) {
    throw new SdkError(
      'EVIDENCE_NOT_VERIFIED',
      `the ${result.platformKind} quote was replayed but its own signature was not checked against a pinned root`,
    );
  }
  if (!equalBytes(result.reportData, expectedReportData)) {
    throw new SdkError(
      'EVIDENCE_REPORT_DATA_MISMATCH',
      `evidence is bound to report data ${toHex(result.reportData)}, this request expected ${toHex(expectedReportData)}`,
    );
  }
  if (!PLATFORM_TEE_KINDS[result.platformKind].includes(tee)) {
    throw new SdkError(
      'EVIDENCE_TEE_MISMATCH',
      `the receipt claims tee '${tee}' but the evidence is a ${result.platformKind} quote`,
    );
  }
  const measurement = platformMeasurement(result);
  if (measurement.length !== MEASUREMENT_BYTES[tee] || !equalBytes(measurement, payload.meas.m)) {
    throw new SdkError(
      'EVIDENCE_MEASUREMENT_MISMATCH',
      `the platform attests to measurement ${toHex(measurement)}, the receipt signed ${toHex(payload.meas.m)} (tee '${tee}')`,
    );
  }

  return {
    tee,
    platformKind: result.platformKind,
    measurement,
    composeHash: pinnedComposeHash(result),
    reportData: result.reportData,
    runtimeEvents: result.runtimeEvents,
    document,
    quoteSignatureVerified: true,
  };
}
