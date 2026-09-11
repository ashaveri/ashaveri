import { toHex } from './b64.js';
import { fromBase64Url } from './b64.js';
import type { EvidenceTrustAnchors } from './evidence.js';
import type { DeploymentManifest } from './manifest.js';

/**
 * Client-side pinning policy. `strict` verification requires one: it pins the
 * signing keys, measurements, issuers and instances the client is willing to
 * accept, so a compromised or repointed gateway cannot swap any of them.
 */
export interface AshaveriPolicy {
  readonly issuers?: readonly string[];
  readonly instances?: readonly string[];
  /** Ed25519 public keys by kid (hex). */
  readonly keys?: Readonly<Record<string, string>>;
  /** Allowed measurements (hex), keyed by environment kind. */
  readonly measurements?: Readonly<Record<string, readonly string[]>>;
  readonly maxReceiptAgeSeconds?: number;
  readonly maxEvidenceAgeSeconds?: number;
  /**
   * Vendor roots hardware evidence must chain to. Omit to accept the roots
   * bundled with `@ashaveri/attest-core`; set it to pin your own.
   */
  readonly trustAnchors?: EvidenceTrustAnchors;
}

export function policyFromManifest(manifest: DeploymentManifest): AshaveriPolicy {
  const keys: Record<string, string> = {};
  for (const key of manifest.keys) {
    keys[key.kid] = key.publicKey;
  }
  return {
    issuers: [manifest.iss],
    instances: [manifest.ins],
    keys,
    measurements: { [manifest.meas.tee]: [manifest.meas.m] },
  };
}

export function policyKeyByKid(policy: AshaveriPolicy, kid: Uint8Array): Uint8Array | undefined {
  const encoded = policy.keys?.[toHex(kid)];
  return encoded === undefined ? undefined : fromBase64Url(encoded);
}
