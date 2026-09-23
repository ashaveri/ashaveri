import { claimsConfidentialDevice, decodeReceipt, type VerifiedReceipt } from '@ashaveri/receipt';
import { fromBase64Url, toHex } from './b64.js';
import {
  deviceReports,
  evidenceReportData,
  requireHardwareEvidence,
  verifyCompletionEvidence,
  type EvidenceTrustAnchors,
  type VerifiedEvidence,
} from './evidence.js';
import { SdkError, type SdkErrorCode } from './errors.js';
import { adjudicateReceiptEpoch, type EpochVerdict, type ReceiptEpochClaim } from './epoch.js';
import { readDeploymentManifest, type ManifestAuthentication, type ReadManifestResult } from './manifest-auth.js';
import type { DeploymentManifest } from './manifest.js';
import type { AshaveriPolicy } from './policy.js';
import { verifyCompletionReceipt } from './verify.js';

const GATEWAY_FETCH_ATTEMPTS = 3;

export interface GatewaySessionOptions {
  readonly fetchImpl?: typeof fetch;
  readonly policy?: AshaveriPolicy;
}

export interface VerifyReceiptedParams {
  readonly receiptBytes: Uint8Array;
  readonly nonce: Uint8Array;
  readonly requestHash: Uint8Array;
  readonly responseHash: Uint8Array;
  /**
   * The response bytes themselves, which a v2 receipt's marking claim is read off. Required, because
   * an optional member is a route by which a live verification skips the mark without saying so: see
   * `VerifyCompletionParams.responseBytes`.
   */
  readonly responseBytes: Uint8Array;
  readonly now?: number;
}

export interface VerifyCompletionOptions extends VerifyReceiptedParams {
  /**
   * Also fetch and verify the platform evidence the receipt points at. This is
   * the step `strict` mode adds on top of receipt verification.
   */
  readonly verifyEvidence?: boolean;
  /** Vendor roots to chain to, overriding the policy's. */
  readonly anchors?: EvidenceTrustAnchors;
}

export interface VerifiedCompletion {
  readonly receipt: VerifiedReceipt;
  /** The verified evidence, or null when `verifyEvidence` was not requested. */
  readonly attestation: VerifiedEvidence | null;
}

/**
 * Tracks one gateway endpoint: caches its deployment manifest, resolves the
 * receipt signing key (pinned through the policy when one is set), and fetches
 * receipts and attestation documents with a short retry window for gateways
 * that publish them just after the response body finishes.
 */
export class GatewaySession {
  private manifestPromise: Promise<ReadManifestResult> | undefined;

  constructor(
    readonly baseUrl: string,
    private readonly options: GatewaySessionOptions = {},
  ) {}

  private get fetchImpl(): typeof fetch {
    return this.options.fetchImpl ?? globalThis.fetch;
  }

  /**
   * The deployment manifest, fetched once and cached.
   *
   * The bytes arrive in either of two shapes and both are read here: a sealed document is verified
   * before its contents are handed over, and a document this client cannot authenticate is handed
   * over anyway with its status stated, because the pins a manifest carries are ones a verifier checks
   * receipts against rather than facts it has to accept. What never happens is a seal that fails to
   * hold being read as a plain document: a body altered after it was signed is refused, not downgraded.
   */
  manifest(): Promise<DeploymentManifest> {
    return this.readManifest().then((read) => read.manifest);
  }

  /**
   * What this session concluded about the manifest it fetched, which is the advisory a caller reports
   * beside a verdict: whether a seal was served, whether it authenticated, and the sentence naming the
   * reason when it did not. It never throws for an absent seal, because "the deployment publishes no
   * signature and you designated no signing key" is a state of the world rather than a failure, and it
   * is the state a real deployment can be in.
   */
  manifestAuthentication(): Promise<ManifestAuthentication> {
    return this.readManifest().then((read) => read.authentication);
  }

  private readManifest(): Promise<ReadManifestResult> {
    this.manifestPromise ??= (async () => {
      let response: Response;
      try {
        response = await this.fetchImpl(`${this.baseUrl}/deployment-manifest`);
      } catch (err) {
        throw new SdkError('GATEWAY_ERROR', `cannot fetch deployment manifest: ${(err as Error).message}`);
      }
      if (!response.ok) {
        throw new SdkError('GATEWAY_ERROR', `deployment manifest request failed with status ${response.status}`);
      }
      return readDeploymentManifest(new Uint8Array(await response.arrayBuffer()), this.options.policy);
    })();
    return this.manifestPromise;
  }

  async receiptBytes(id: string): Promise<Uint8Array> {
    return this.fetchBytes(
      `${this.baseUrl}/receipts/${encodeURIComponent(id)}`,
      'receipt',
      'RECEIPT_NOT_FOUND',
      `for id ${id}`,
    );
  }

  /**
   * The attestation document bound to a report data value, as published on the
   * gateway's evidence endpoint.
   */
  async attestationBytes(reportData: Uint8Array): Promise<Uint8Array> {
    return this.fetchBytes(
      `${this.baseUrl}/attestation?report_data=${toHex(reportData)}`,
      'evidence',
      'EVIDENCE_NOT_FOUND',
      `for report data ${toHex(reportData)}`,
    );
  }

  /**
   * Device evidence for the same report data, from the route beside the platform one.
   *
   * Only a composite receipt sends a client here. These bytes are the vendor's own
   * array rather than a document the receipt commits to, so nothing anchors them but
   * the signature: what makes them this request's evidence is a genuine device having
   * signed this challenge, which is also why the URL is derived rather than read from
   * the receipt.
   */
  async deviceAttestationBytes(reportData: Uint8Array): Promise<Uint8Array> {
    return this.fetchBytes(
      `${this.baseUrl}/attestation/gpu?report_data=${toHex(reportData)}`,
      'device evidence',
      'EVIDENCE_NOT_FOUND',
      `for report data ${toHex(reportData)}`,
    );
  }

  async verifyReceipted(params: VerifyReceiptedParams): Promise<VerifiedReceipt> {
    const decoded = decodeReceipt(params.receiptBytes);
    const verifyKey = await this.resolveKey(decoded.header.kid, {
      kid: toHex(decoded.header.kid),
      epoch: decoded.payload.epk,
      issuedAt: decoded.payload.iat,
    });
    return verifyCompletionReceipt({
      receiptBytes: params.receiptBytes,
      nonce: params.nonce,
      requestHash: params.requestHash,
      responseHash: params.responseHash,
      responseBytes: params.responseBytes,
      verifyKey,
      policy: this.options.policy,
      now: params.now,
    });
  }

  /**
   * Verifies a completion: the receipt always, and in strict mode the platform
   * evidence the receipt commits to through `att.d`.
   *
   * The receipt comes first because it is the cheaper check and the reason the
   * evidence is worth fetching at all: its `tee` label alone can settle strict
   * mode, so a deployment claiming no hardware is rejected without a round trip.
   * The expected report data is recomputed from the client's own nonce and
   * request bytes rather than read from the gateway, so the gateway cannot point
   * the client at a quote for other work.
   *
   * A composite claim costs a second document. `att.d` covers only the platform
   * quote, so the device report arrives beside it and is believed on the strength
   * of its own signature over the same challenge; both legs are handed to
   * `verifyCompletionEvidence` together rather than judged apart, because the
   * claim is one sentence about one request.
   */
  async verifyCompletion(params: VerifyCompletionOptions): Promise<VerifiedCompletion> {
    const receipt = await this.verifyReceipted(params);
    if (params.verifyEvidence !== true) {
      return { receipt, attestation: null };
    }
    const tee = receipt.payload.meas.tee;
    requireHardwareEvidence(tee);
    const expectedReportData = evidenceReportData(params.nonce, params.requestHash);
    const document = await this.attestationBytes(expectedReportData);
    const gpuEvidence = claimsConfidentialDevice(tee)
      ? deviceReports(await this.deviceAttestationBytes(expectedReportData))
      : undefined;
    return {
      receipt,
      attestation: verifyCompletionEvidence({
        document,
        expectedReportData,
        gpuEvidence,
        payload: receipt.payload,
        anchors: params.anchors ?? this.options.policy?.trustAnchors,
        now: params.now,
      }),
    };
  }

  private async fetchBytes(
    url: string,
    what: string,
    notFound: SdkErrorCode,
    detail: string,
  ): Promise<Uint8Array> {
    for (let attempt = 1; attempt <= GATEWAY_FETCH_ATTEMPTS; attempt++) {
      let response: Response;
      try {
        response = await this.fetchImpl(url);
      } catch (err) {
        throw new SdkError('GATEWAY_ERROR', `cannot fetch ${what}: ${(err as Error).message}`);
      }
      if (response.ok) return new Uint8Array(await response.arrayBuffer());
      // Only a missing artifact is worth retrying: a receipt or quote the
      // gateway wrote a moment ago can briefly 404 while it is still landing.
      if (response.status !== 404) {
        throw new SdkError('GATEWAY_ERROR', `${what} request failed with status ${response.status}`);
      }
      if (attempt < GATEWAY_FETCH_ATTEMPTS) await delay(25 * attempt);
    }
    throw new SdkError(notFound, `no ${what} available ${detail}`);
  }

  /**
   * Adjudicate a receipt's claim about its own signing epoch against the deployment manifest.
   *
   * Public because the rule has exactly one copy and two callers: the line below that refuses a
   * receipt on it, and the offline reporter that prints the verdict it reached. A second statement of
   * what a superseded epoch means would be the same drift risk in two places that the client's answer
   * and an auditor's answer were written to remove.
   */
  async adjudicateEpoch(claim: ReceiptEpochClaim): Promise<EpochVerdict> {
    return adjudicateReceiptEpoch(await this.manifest(), claim);
  }

  private async resolveKey(kid: Uint8Array, claim: ReceiptEpochClaim): Promise<Uint8Array> {
    const keyBytes = await this.resolveSigningKey(kid);
    const verdict = await this.adjudicateEpoch(claim);
    if (!verdict.ok) {
      throw new SdkError(
        verdict.code,
        `receipt key ${claim.kid} claims epoch ${claim.epoch} signed at ${claim.issuedAt}, and the deployment manifest does not support that: ${verdict.detail}`,
      );
    }
    return keyBytes;
  }

  private async resolveSigningKey(kid: Uint8Array): Promise<Uint8Array> {
    const kidHex = toHex(kid);
    const manifest = await this.manifest();
    const declared = manifest.keys.find((entry) => entry.kid === kidHex);
    const policy = this.options.policy;
    if (policy === undefined) {
      if (declared === undefined) {
        throw new SdkError('BAD_MANIFEST', `receipt key ${kidHex} is not declared by the deployment manifest`);
      }
      return fromBase64Url(declared.publicKey);
    }
    const pinned = policy.keys?.[kidHex];
    if (pinned === undefined) {
      throw new SdkError('MANIFEST_KEY_NOT_PINNED', `receipt key ${kidHex} is not pinned by the policy`);
    }
    if (declared === undefined || declared.publicKey !== pinned) {
      throw new SdkError('MANIFEST_KEY_NOT_PINNED', `deployment manifest key ${kidHex} does not match the pinned key`);
    }
    return fromBase64Url(pinned);
  }
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}
