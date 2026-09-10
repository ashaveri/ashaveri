import { decodeReceipt, type VerifiedReceipt } from '@ashaveri/receipt';
import { fromBase64Url, toHex } from './b64.js';
import { SdkError } from './errors.js';
import { parseManifest, type DeploymentManifest } from './manifest.js';
import type { AshaveriPolicy } from './policy.js';
import { verifyCompletionReceipt } from './verify.js';

const RECEIPT_FETCH_ATTEMPTS = 3;

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

/**
 * Tracks one gateway endpoint: caches its deployment manifest, resolves the
 * receipt signing key (pinned through the policy when one is set), and fetches
 * receipts with a short retry window for gateways that issue them just after
 * the response body finishes.
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
    for (let attempt = 1; attempt <= RECEIPT_FETCH_ATTEMPTS; attempt++) {
      let response: Response;
      try {
        response = await this.fetchImpl(`${this.baseUrl}/receipts/${encodeURIComponent(id)}`);
      } catch (err) {
        throw new SdkError('GATEWAY_ERROR', `cannot fetch receipt: ${(err as Error).message}`);
      }
      if (response.status === 404 && attempt < RECEIPT_FETCH_ATTEMPTS) {
        await delay(25 * attempt);
        continue;
      }
      if (!response.ok) {
        throw new SdkError('GATEWAY_ERROR', `receipt request failed with status ${response.status}`);
      }
      return new Uint8Array(await response.arrayBuffer());
    }
    throw new SdkError('RECEIPT_NOT_FOUND', `no receipt available for id ${id}`);
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
