import {
  AttestationError,
  decodeAttestation,
  equalBytes,
  parseNvidiaEvidenceBundle,
  parseSnpReport,
  parseTdxQuote,
  readNvidiaChallenge,
  reportDataBinds,
  type NvidiaEvidence,
  type RuntimeEvent,
} from '@ashaveri/attest-core';
import { claimsConfidentialDevice, signingKeyFromSeed } from '@ashaveri/receipt';
import { GuestClient, GuestError, type GuestApi, type GpuEvidenceBundle } from './guest.js';
import { sha256, toHex } from './digest.js';
import type { AttestationBundle, Deployment, HardwareTeeKind, ModelInfo, TeeKind } from './deployment.js';

/**
 * Live deployment: the signing key comes from the CVM's own key derivation and
 * every measurement claim comes from the guest's hardware evidence, so nothing
 * in a receipt is a hand-entered string.
 */

/** Evidence domain for the deployment's standing (non per-request) attestation. */
const DEPLOYMENT_EVIDENCE_DOMAIN = 'ashaveri:deployment-evidence:v1';

/** Quotes are ~12-20 KB each; 256 entries keeps the retention window under ~5 MB. */
const MAX_CACHED_EVIDENCE = 256;

const QUOTE_REPORT_DATA_BYTES = 64;

/** The only bundle format that answers a challenge this deployment chose; boot-time evidence answers one it never picked. */
const NVIDIA_ON_DEMAND_FORMAT = 'nvidia-nvattest-collect-evidence-json-v1';

export type DstackErrorCode =
  | 'EVIDENCE_UNDECODABLE'
  | 'UNSUPPORTED_PLATFORM'
  | 'TEE_MISMATCH'
  | 'IDENTITY_MISSING'
  | 'GUEST_EVIDENCE_UNBOUND'
  | 'GPU_EVIDENCE_UNSUPPORTED'
  | 'GPU_EVIDENCE_UNAVAILABLE'
  | 'GPU_EVIDENCE_UNBOUND';

export class DstackError extends Error {
  readonly code: DstackErrorCode;

  constructor(code: DstackErrorCode, detail: string) {
    super(`${code}: ${detail}`);
    this.name = 'DstackError';
    this.code = code;
  }
}

export interface DstackDeploymentOptions {
  /** Injectable for tests; defaults to the guest agent on the CVM's Unix socket. */
  readonly client?: GuestApi;
  /** Served models with the weight digest each receipt must carry. */
  readonly models: readonly ModelInfo[];
  /** Public origin of this gateway, without a trailing slash, e.g. https://inference.ashaveri.com/v1 */
  readonly evidenceBaseUrl: string;
  /** Guest key path. Rotating the key means changing this and bumping epk. */
  readonly keyPath?: string;
  readonly keyPurpose?: string;
  /**
   * A second guest key path, for signing this deployment's manifest. Absent leaves the manifest served
   * as plain JSON, which is a state a real deployment can be in rather than a defect: nothing here
   * derives a key nobody asked for, and the identity that signs a manifest is the operator's to choose.
   */
  readonly manifestKeyPath?: string;
  readonly manifestKeyPurpose?: string;
  readonly epk?: number;
  /** Overrides for the identity discovered from the event log. */
  readonly issuer?: string;
  readonly instance?: string;
  /** Fails startup if the platform's own evidence disagrees. */
  readonly tee?: HardwareTeeKind;
}

interface PlatformMeasurement {
  readonly tee: TeeKind;
  readonly measurement: Uint8Array;
  readonly events: readonly RuntimeEvent[];
}

function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

/**
 * The platform field is 64 bytes wide, so a document that quotes a shorter one
 * is not the evidence this deployment can serve. The binding rule itself lives in
 * attest-core so the client checking the same quote reaches the same verdict.
 */
function assertReportDataBound(reported: Uint8Array, requested: Uint8Array, context: string): void {
  if (reported.length !== QUOTE_REPORT_DATA_BYTES) {
    throw new DstackError('EVIDENCE_UNDECODABLE', `${context} carries ${reported.length} report bytes`);
  }
  if (!reportDataBinds(reported, requested)) {
    throw new DstackError(
      'GUEST_EVIDENCE_UNBOUND',
      `${context} is not bound to report data ${toHex(requested)}`,
    );
  }
}

function measureEvidence(document: Uint8Array, requestedReportData: Uint8Array): PlatformMeasurement {
  let attestation;
  try {
    attestation = decodeAttestation(document);
  } catch (error) {
    throw new DstackError('EVIDENCE_UNDECODABLE', error instanceof Error ? error.message : String(error));
  }
  assertReportDataBound(attestation.stack.reportData, requestedReportData, 'guest evidence');
  const platform = attestation.platform;
  if (platform.kind === 'tdx') {
    return {
      tee: 'tdx',
      measurement: parseTdxQuote(platform.quote).mrTd,
      events: attestation.stack.runtimeEvents,
    };
  }
  if (platform.kind === 'sev-snp') {
    return {
      tee: 'snp',
      measurement: parseSnpReport(platform.report).measurement,
      events: attestation.stack.runtimeEvents,
    };
  }
  throw new DstackError('UNSUPPORTED_PLATFORM', `no measurement is defined for platform kind '${platform.kind}'`);
}

function eventPayload(events: readonly RuntimeEvent[], name: string): Uint8Array | null {
  return events.find((event) => event.event === name)?.payload ?? null;
}

/**
 * The per-device reports inside one live bundle, in the shape @ashaveri/attest-core verifies.
 *
 * Only the on-demand format qualifies: boot-time evidence was collected against a nonce the
 * deployment never chose, so it answers this request no better than a photograph would. The
 * challenge is compared against the nonce inside each report's signed region rather than the
 * copy beside it in the JSON, because that is the value a client checks. Reading it is not a
 * verdict on the device; appraising the signature stays the client's job.
 */
export function nvidiaDeviceReports(bundle: GpuEvidenceBundle, challenge: Uint8Array): NvidiaEvidence[] {
  if (bundle.vendor !== 'nvidia' || bundle.format !== NVIDIA_ON_DEMAND_FORMAT) {
    throw new DstackError(
      'GPU_EVIDENCE_UNSUPPORTED',
      `device evidence is '${bundle.vendor}' in format '${bundle.format}', this deployment serves only 'nvidia' in format '${NVIDIA_ON_DEMAND_FORMAT}'`,
    );
  }
  let entries: NvidiaEvidence[];
  try {
    entries = parseNvidiaEvidenceBundle(bundle.evidence);
  } catch (error) {
    if (error instanceof AttestationError) {
      throw new DstackError('GPU_EVIDENCE_UNSUPPORTED', `device bundle: ${error.message}`);
    }
    throw error;
  }
  if (entries.length === 0) {
    throw new DstackError('GPU_EVIDENCE_UNAVAILABLE', 'the device bundle names no device, so nothing backs a GPU claim');
  }
  return entries.map((device, index) => {
    let signed: Uint8Array;
    try {
      signed = readNvidiaChallenge(device.report);
    } catch (error) {
      throw new DstackError(
        'GPU_EVIDENCE_UNSUPPORTED',
        `device ${index} report: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
    if (!equalBytes(signed, challenge)) {
      throw new DstackError(
        'GPU_EVIDENCE_UNBOUND',
        `device ${index} signed a report for challenge ${toHex(signed)}, this request's device challenge is ${toHex(challenge)}`,
      );
    }
    return device;
  });
}

/**
 * The platform a composite claim rests on.
 *
 * `snp+gpucc` and `tdx+gpucc` each add a device leg to an ordinary deployment
 * rather than naming a different kind of CPU, so the two halves are checked apart:
 * the launch digest comes from the platform quote and the accelerator has to answer
 * a challenge of its own. The label splits on its suffix instead of pairing
 * literals, so a composite cannot arrive without a platform to stand on.
 */
function platformHalf(tee: HardwareTeeKind): TeeKind {
  return claimsConfidentialDevice(tee) ? (tee.slice(0, tee.lastIndexOf('+')) as TeeKind) : tee;
}

export async function dstackDeployment(options: DstackDeploymentOptions): Promise<Deployment> {
  const client = options.client ?? new GuestClient();
  const keyPath = options.keyPath ?? '/ashaveri/receipt';
  const evidenceBaseUrl = options.evidenceBaseUrl.replace(/\/+$/, '');
  const standingReportData = sha256(utf8(DEPLOYMENT_EVIDENCE_DOMAIN));

  const { key: seed } = await client.getKey(keyPath, options.keyPurpose ?? '', 'ed25519');
  const key = signingKeyFromSeed(seed);

  // Two derivations at two paths, because the duties are two. The manifest is the document that states
  // which keys sign receipts, so a key that signs both would let one compromised signing key forge the
  // rotation record that was supposed to retire it, and a client reads a wrapper verified that way as a
  // manifest it cannot authenticate. Asking the guest for a second path is how an operator gets that
  // separation without this process holding or writing a secret: the same derivation, a different name.
  const manifestKey =
    options.manifestKeyPath === undefined
      ? undefined
      : signingKeyFromSeed(
          (await client.getKey(options.manifestKeyPath, options.manifestKeyPurpose ?? '', 'ed25519')).key,
        );
  if (manifestKey !== undefined && toHex(manifestKey.kid) === toHex(key.kid)) {
    // Not a coded refusal, because nothing can branch on it: a process that came back with one key for
    // two duties has been configured to serve a document no honest client will authenticate, and the one
    // useful answer is a line on stderr and a start-up that did not happen.
    throw new Error(
      `the guest derived the same key for ${keyPath} and ${String(options.manifestKeyPath)}, and one key cannot sign both the receipts and the manifest that lists them`,
    );
  }

  // Bounded so a long-running instance does not grow without limit; evidence is
  // re-fetchable only while it is retained, which is what the receipt's att.url promises.
  const cache = new Map<string, AttestationBundle>();
  const deviceCache = new Map<string, AttestationBundle>();
  const remember = (store: Map<string, AttestationBundle>, hex: string, bundle: AttestationBundle): AttestationBundle => {
    if (store.size >= MAX_CACHED_EVIDENCE) {
      const oldest = store.keys().next().value;
      if (oldest !== undefined) {
        store.delete(oldest);
      }
    }
    store.set(hex, bundle);
    return bundle;
  };

  const fetchEvidence = async (reportData: Uint8Array): Promise<AttestationBundle> => {
    const hex = toHex(reportData);
    const cached = cache.get(hex);
    if (cached !== undefined) {
      return cached;
    }
    const document = await client.attest(reportData);
    measureEvidence(document, reportData);
    return remember(cache, hex, {
      document,
      timestamp: Math.floor(Date.now() / 1000),
      url: `${evidenceBaseUrl}/attestation?report_data=${hex}`,
    });
  };

  /** Device bundles answering one challenge, or the reason this image cannot back a device claim. */
  const askDevices = (reportData: Uint8Array): Promise<readonly GpuEvidenceBundle[]> =>
    client.attestGpu(reportData).catch((error: unknown) => {
      if (error instanceof GuestError && error.code === 'GPU_ATTESTATION_UNAVAILABLE') {
        throw new DstackError(
          'GPU_EVIDENCE_UNAVAILABLE',
          `--tee ${options.tee} needs device evidence and this image gave none: ${error.detail}`,
        );
      }
      throw error;
    });

  // Collection costs a real device seconds, so one answer serves every read of its challenge.
  const fetchDeviceEvidence = async (reportData: Uint8Array): Promise<AttestationBundle> => {
    const hex = toHex(reportData);
    const cached = deviceCache.get(hex);
    if (cached !== undefined) {
      return cached;
    }
    const bundles = await askDevices(reportData);
    const [bundle] = bundles;
    // What gets served is the vendor's own array, unchanged, so a client can hand it to
    // NVIDIA's tool. Several bundles would have to be merged into something neither the
    // vendor nor @ashaveri/attest-core recognizes, and an empty answer backs no claim.
    if (bundle === undefined || bundles.length !== 1) {
      throw new DstackError(
        'GPU_EVIDENCE_UNSUPPORTED',
        `the device route answered with ${bundles.length} bundles and this deployment serves the one array nvattest wrote`,
      );
    }
    nvidiaDeviceReports(bundle, reportData);
    return remember(deviceCache, hex, {
      document: bundle.evidence,
      timestamp: Math.floor(Date.now() / 1000),
      url: `${evidenceBaseUrl}/attestation/gpu?report_data=${hex}`,
    });
  };

  const standing = await fetchEvidence(standingReportData);
  const platform = measureEvidence(standing.document, standingReportData);
  if (options.tee !== undefined && platformHalf(options.tee) !== platform.tee) {
    throw new DstackError('TEE_MISMATCH', `configured '${options.tee}' but the evidence shows '${platform.tee}'`);
  }

  // The CPU quote says nothing about the accelerator, so a composite label is never inferred
  // from hardware alone: the operator asks for it and a device has to answer the standing
  // challenge to confirm the claim. Collection is slow, so this runs once at startup rather
  // than on every receipt, and the result is discarded because each receipt asks for its own.
  let tee: TeeKind = platform.tee;
  if (options.tee !== undefined && claimsConfidentialDevice(options.tee)) {
    const devices = (await askDevices(standingReportData)).flatMap((bundle) =>
      nvidiaDeviceReports(bundle, standingReportData),
    );
    if (devices.length === 0) {
      throw new DstackError(
        'GPU_EVIDENCE_UNAVAILABLE',
        'no accelerator answered, so this deployment cannot claim a confidential GPU',
      );
    }
    tee = options.tee;
  }

  const composeHash = eventPayload(platform.events, 'compose-hash');
  const instanceId = eventPayload(platform.events, 'instance-id');
  const issuer = options.issuer ?? (composeHash === null ? null : `dstack-${toHex(composeHash).slice(0, 12)}`);
  const instance = options.instance ?? (instanceId === null ? null : toHex(instanceId));
  if (issuer === null || instance === null) {
    throw new DstackError(
      'IDENTITY_MISSING',
      'the event log carries no compose-hash or instance-id, so pass --issuer and --instance explicitly',
    );
  }

  return {
    issuer,
    instance,
    key,
    manifestKey,
    epk: options.epk ?? 0,
    tee,
    measurement: platform.measurement,
    models: options.models,
    async attestation(reportData: Uint8Array | null): Promise<AttestationBundle> {
      return fetchEvidence(reportData ?? standingReportData);
    },
    deviceAttestation: claimsConfidentialDevice(tee) ? fetchDeviceEvidence : undefined,
  };
}
