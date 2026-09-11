import {
  decodeAttestation,
  parseSnpReport,
  parseTdxQuote,
  reportDataBinds,
  type RuntimeEvent,
} from '@ashaveri/attest-core';
import { signingKeyFromSeed } from '@ashaveri/receipt';
import { GuestClient, type GuestApi } from './guest.js';
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

export type DstackErrorCode =
  | 'EVIDENCE_UNDECODABLE'
  | 'PLATFORM_UNSUPPORTED'
  | 'TEE_MISMATCH'
  | 'IDENTITY_MISSING'
  | 'EVIDENCE_REPORT_DATA_MISMATCH';

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
      'EVIDENCE_REPORT_DATA_MISMATCH',
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
  throw new DstackError('PLATFORM_UNSUPPORTED', `no measurement is defined for platform kind '${platform.kind}'`);
}

function eventPayload(events: readonly RuntimeEvent[], name: string): Uint8Array | null {
  return events.find((event) => event.event === name)?.payload ?? null;
}

export async function dstackDeployment(options: DstackDeploymentOptions): Promise<Deployment> {
  const client = options.client ?? new GuestClient();
  const keyPath = options.keyPath ?? '/ashaveri/receipt';
  const evidenceBaseUrl = options.evidenceBaseUrl.replace(/\/+$/, '');
  const standingReportData = sha256(utf8(DEPLOYMENT_EVIDENCE_DOMAIN));

  const { key: seed } = await client.getKey(keyPath, options.keyPurpose ?? '', 'ed25519');
  const key = signingKeyFromSeed(seed);

  // Bounded so a long-running instance does not grow without limit; evidence is
  // re-fetchable only while it is retained, which is what the receipt's att.url promises.
  const cache = new Map<string, AttestationBundle>();
  const fetchEvidence = async (reportData: Uint8Array): Promise<AttestationBundle> => {
    const hex = toHex(reportData);
    const cached = cache.get(hex);
    if (cached !== undefined) {
      return cached;
    }
    const document = await client.attest(reportData);
    measureEvidence(document, reportData);
    const bundle: AttestationBundle = {
      document,
      timestamp: Math.floor(Date.now() / 1000),
      url: `${evidenceBaseUrl}/attestation?report_data=${hex}`,
    };
    if (cache.size >= MAX_CACHED_EVIDENCE) {
      const oldest = cache.keys().next().value as string | undefined;
      if (oldest !== undefined) {
        cache.delete(oldest);
      }
    }
    cache.set(hex, bundle);
    return bundle;
  };

  const standing = await fetchEvidence(standingReportData);
  const platform = measureEvidence(standing.document, standingReportData);
  if (options.tee !== undefined && options.tee !== platform.tee) {
    throw new DstackError('TEE_MISMATCH', `configured '${options.tee}' but the evidence shows '${platform.tee}'`);
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
    epk: options.epk ?? 0,
    tee: platform.tee,
    measurement: platform.measurement,
    models: options.models,
    async attestation(reportData: Uint8Array | null): Promise<AttestationBundle> {
      return fetchEvidence(reportData ?? standingReportData);
    },
  };
}
