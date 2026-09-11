import { generateSigningKey, type SigningKey, type TeeKind } from '@ashaveri/receipt';
import { sha256 } from './digest.js';
import { DEFAULT_MOCK_MODEL } from './mock.js';

export type { TeeKind };

/** The kinds a live guest can attest to. `software` is what the mock deployment claims. */
export type HardwareTeeKind = Exclude<TeeKind, 'software'>;

export interface ModelInfo {
  readonly id: string;
  readonly wts: Uint8Array;
}

/**
 * Hardware evidence a client can re-verify on its own. The receipt binds
 * `att.d` to `sha256(document)`, so the served document must be byte-stable.
 */
export interface AttestationBundle {
  readonly document: Uint8Array;
  readonly timestamp: number;
  readonly url: string;
}

/** Everything a receipt signs about, and everything the manifest publishes. */
export interface Deployment {
  readonly issuer: string;
  readonly instance: string;
  readonly key: SigningKey;
  readonly epk: number;
  readonly tee: TeeKind;
  readonly measurement: Uint8Array;
  readonly models: readonly ModelInfo[];
  /**
   * Evidence for a receipt. `reportData` is the client nonce when the platform
   * can bind one, or null for the deployment's standing evidence.
   */
  attestation(reportData: Uint8Array | null): Promise<AttestationBundle>;
  /**
   * Device evidence for one request, present only when the deployment claims an
   * accelerator. `reportData` is the same value the platform quote carries, which is
   * the whole link between the two documents: it says a genuine device signed this
   * request, not that the device sits in the VM that served it.
   */
  deviceAttestation?(reportData: Uint8Array): Promise<AttestationBundle>;
}

export interface MockDeploymentOptions {
  readonly issuer?: string;
  readonly instance?: string;
  readonly key?: SigningKey;
  readonly model?: string;
}

const MOCK_EVIDENCE = new TextEncoder().encode('mock-attestation');

export function mockWeights(model: string): Uint8Array {
  return sha256(new TextEncoder().encode(`mock-weights:${model}`));
}

export function mockDeployment(options: MockDeploymentOptions = {}): Deployment {
  const model = options.model ?? DEFAULT_MOCK_MODEL;
  return {
    issuer: options.issuer ?? 'ashaveri-mock',
    instance: options.instance ?? 'mock-instance-1',
    key: options.key ?? generateSigningKey(),
    epk: 0,
    tee: 'software',
    measurement: sha256(new TextEncoder().encode('mock-measurement')),
    models: [{ id: model, wts: mockWeights(model) }],
    async attestation() {
      return {
        document: MOCK_EVIDENCE,
        timestamp: Math.floor(Date.now() / 1000),
        url: 'mock://attestation',
      };
    },
  };
}
