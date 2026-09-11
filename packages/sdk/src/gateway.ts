import { decodeReceipt, type VerifiedReceipt } from '@ashaveri/receipt';
import { fromBase64Url, toHex } from './b64.js';
import {
  evidenceReportData,
  requireHardwareEvidence,
  verifyCompletionEvidence,
  type EvidenceTrustAnchors,
  type VerifiedEvidence,
} from './evidence.js';
import { SdkError, type SdkErrorCode } from './errors.js';
import { parseManifest, type DeploymentManifest } from './manifest.js';
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
  private manifestPromise: Promise<DeploymentManifest> | undefined;

  constructor(
    readonly baseUrl: string,
    private readonly options: GatewaySessionOptions = {},
  ) {}

  private get fetchImpl(): typeof fetch {
    return this.options.fetchImpl ?? globalThis.fetch;
  }

  manifest(): Promise<DeploymentManifest> {
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
      try {
        return parseManifest(await response.json());
      } catch (err) {
        throw new SdkError('BAD_MANIFEST', (err as Error).message);
      }
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

  async verifyReceipted(params: VerifyReceiptedParams): Promise<VerifiedReceipt> {
    const kid = decodeReceipt(params.receiptBytes).header.kid;
    const verifyKey = await this.resolveKey(kid);
    return verifyCompletionReceipt({
      receiptBytes: params.receiptBytes,
      nonce: params.nonce,
      requestHash: params.requestHash,
      responseHash: params.responseHash,
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
   */
  async verifyCompletion(params: VerifyCompletionOptions): Promise<VerifiedCompletion> {
    const receipt = await this.verifyReceipted(params);
    if (params.verifyEvidence !== true) {
      return { receipt, attestation: null };
    }
    requireHardwareEvidence(receipt.payload.meas.tee);
    const expectedReportData = evidenceReportData(params.nonce, params.requestHash);
    const document = await this.attestationBytes(expectedReportData);
    return {
      receipt,
      attestation: verifyCompletionEvidence({
        document,
        expectedReportData,
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

  private async resolveKey(kid: Uint8Array): Promise<Uint8Array> {
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
