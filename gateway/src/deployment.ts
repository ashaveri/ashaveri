import { generateSigningKey, type SigningKey, type TeeKind } from '@ashaveri/receipt';
import { sha256 } from './digest.js';
import { DEFAULT_MOCK_MODEL } from './mock.js';
import { declarationOf, HOST_CLOCK_SOURCE, type StampDeclaration, type TimeSource } from './store.js';

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
  /**
   * The source `timestamp` was read from, named and bounded as that source declared itself.
   *
   * It travels inside this bundle rather than beside it because a collection instant without them is a
   * number nobody can weigh: `timestamp` is what a verifier's evidence window is measured from, and the
   * distance it can be wrong by is a fact about the clock the deployment wired, not about the platform
   * that signed the document.
   *
   * This is what the collecting process holds, and it is not in the receipt. Section 3 of
   * `docs/receipt-spec.md` spells `att` as the closed map `{ d, ts, url }`, so a label added here cannot
   * travel with a served record, and what a client checks about `att.ts` stays what the signed bytes
   * themselves carry: the instant, and nothing about whose it was.
   *
   * Nothing shipped reads it. The routes serve the bundle's `document`, and `issue` puts `d`, `ts` and
   * `url` into a payload; the only reader today is the test suite that checks a bundle names the source
   * it was built with. It stays required, because a bundle that cannot say where its instant came from
   * is the thing this field exists to make impossible, and a future reader is meant to find a label
   * rather than have to add one.
   */
  readonly stamped: StampDeclaration;
}

/** Everything a receipt signs about, and everything the manifest publishes. */
export interface Deployment {
  readonly issuer: string;
  readonly instance: string;
  readonly key: SigningKey;
  /**
   * The key that signs this deployment's manifest, when the operator has handed one over.
   *
   * It is not `key`, and the difference is the whole of what a signed manifest is worth: the manifest
   * is the document that states which keys sign receipts, so a receipt key that also signed it would
   * let one compromised signing key forge the record that was supposed to retire it. A client refuses
   * a wrapper verified that way, which is why this field names a second identity rather than an option
   * on the first.
   *
   * Absent is a state a real deployment can be in, and a served document then stays what it has always
   * been: plain JSON, which an honest client reads and reports as unauthenticated rather than
   * believing. Nothing here generates a key, embeds one, or decides which identity a deployment signs
   * with: this field carries one that somebody else handed to the process.
   */
  readonly manifestKey?: SigningKey;
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
  /** The key that seals the manifest this deployment serves. Absent leaves the document unsigned. */
  readonly manifestKey?: SigningKey;
  readonly model?: string;
  /**
   * Where this deployment's collection instants come from, named. Absent means `HOST_CLOCK_SOURCE`, so
   * an evidence stamp says it is this host's own clock at a bound nobody measured rather than pretending
   * to be a platform reading: a mock deployment has no attestable clock to name, and saying so is the
   * honest label.
   */
  readonly time?: TimeSource;
}

const MOCK_EVIDENCE = new TextEncoder().encode('mock-attestation');

export function mockWeights(model: string): Uint8Array {
  return sha256(new TextEncoder().encode(`mock-weights:${model}`));
}

export function mockDeployment(options: MockDeploymentOptions = {}): Deployment {
  const model = options.model ?? DEFAULT_MOCK_MODEL;
  const time = options.time ?? HOST_CLOCK_SOURCE;
  return {
    issuer: options.issuer ?? 'ashaveri-mock',
    instance: options.instance ?? 'mock-instance-1',
    key: options.key ?? generateSigningKey(),
    manifestKey: options.manifestKey,
    epk: 0,
    tee: 'software',
    measurement: sha256(new TextEncoder().encode('mock-measurement')),
    models: [{ id: model, wts: mockWeights(model) }],
    async attestation() {
      return {
        document: MOCK_EVIDENCE,
        timestamp: Math.floor(time.now()),
        url: 'mock://attestation',
        stamped: declarationOf(time),
      };
    },
  };
}
