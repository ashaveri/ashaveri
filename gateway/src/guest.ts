import { existsSync } from 'node:fs';
import { request as httpRequest, type IncomingMessage, type RequestOptions } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { fromHex, toHex } from './digest.js';

/**
 * Client for the dstack guest agent, the only thing in this file that talks to
 * hardware. The agent serves a small JSON RPC over a Unix socket inside the CVM,
 * so no third-party SDK is needed and the gateway keeps no transitive dependency.
 */

const SOCKET_CANDIDATES = [
  '/var/run/dstack.sock',
  '/run/dstack.sock',
  '/var/run/dstack/dstack.sock',
  '/run/dstack/dstack.sock',
];

/** The agent quotes serially on the TDX driver, so a slow call can queue behind another. */
const DEFAULT_TIMEOUT_MS = 30_000;

/** Widest report_data the agent accepts; the platform field is 64 bytes and shorter values are zero padded. */
export const MAX_REPORT_DATA_BYTES = 64;

/** SPDM fixes the device challenge at 32 bytes; a longer digest must be taken by the caller. */
export const GPU_NONCE_BYTES = 32;

/**
 * Answers that say the route is not in this image, as opposed to this request having failed:
 * 501 for a build without nvattest, 404 and 405 for a guest agent too old to mount `v1`.
 */
const MISSING_ROUTE = new Set([404, 405, 501]);

/**
 * One accelerator's evidence as the guest agent ships it. `format` is the caller's
 * cue for which verifier applies, and an unrecognized value has no verifier.
 */
export interface GpuEvidenceBundle {
  readonly vendor: string;
  readonly format: string;
  readonly evidence: Uint8Array;
}

export type GuestErrorCode =
  | 'GUEST_ENDPOINT_MISSING'
  | 'GUEST_REQUEST_FAILED'
  | 'GUEST_RPC_ERROR'
  | 'GUEST_MALFORMED_RESPONSE'
  | 'GPU_ATTESTATION_UNAVAILABLE';

export class GuestError extends Error {
  readonly code: GuestErrorCode;
  /** The message without its code prefix, so a caller can re-wrap a failure without cutting prose out of a string. */
  readonly detail: string;
  /** The HTTP status behind the failure, or undefined when no response caused it. */
  readonly status: number | undefined;

  constructor(code: GuestErrorCode, detail: string, status?: number) {
    super(`${code}: ${detail}`);
    this.name = 'GuestError';
    this.code = code;
    this.detail = detail;
    this.status = status;
  }
}

export interface GuestClientOptions {
  /** Unix socket path, or an http(s) base URL for a simulator. Defaults to $DSTACK_SIMULATOR_ENDPOINT, then the first socket that exists. */
  readonly endpoint?: string;
  readonly timeoutMs?: number;
}

export interface GuestKey {
  readonly key: Uint8Array;
  readonly signatureChain: readonly Uint8Array[];
}

export interface GuestInfo {
  readonly tcbInfo: Record<string, unknown>;
  readonly raw: Record<string, unknown>;
}

/** The subset of the guest agent a deployment needs: a derived key, bound platform evidence, and device evidence. */
export interface GuestApi {
  getKey(path: string, purpose: string, algorithm: 'ed25519'): Promise<GuestKey>;
  attest(reportData: Uint8Array): Promise<Uint8Array>;
  attestGpu(nonce: Uint8Array): Promise<readonly GpuEvidenceBundle[]>;
}

export class GuestClient implements GuestApi {
  private readonly endpoint: string;
  private readonly timeoutMs: number;

  constructor(options: GuestClientOptions = {}) {
    this.endpoint = resolveEndpoint(options.endpoint);
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  }

  /** Deterministic key derivation: the same path and algorithm always yield the same key on the same deployment. */
  async getKey(path: string, purpose: string, algorithm: 'ed25519'): Promise<GuestKey> {
    const result = await this.post<Record<string, unknown>>('/GetKey', { path, purpose, algorithm });
    const key = requireHex(result['key'], 'key');
    const chain = requireStringArray(result['signature_chain'], 'signature_chain');
    return { key, signatureChain: chain.map((entry) => fromHex(entry)) };
  }

  /** Evidence bound to reportData. The returned bytes are the attestation document a client re-verifies. */
  async attest(reportData: Uint8Array): Promise<Uint8Array> {
    if (reportData.length === 0 || reportData.length > MAX_REPORT_DATA_BYTES) {
      throw new GuestError(
        'GUEST_MALFORMED_RESPONSE',
        `report_data must be 1 to ${MAX_REPORT_DATA_BYTES} bytes, got ${reportData.length}`,
      );
    }
    const result = await this.post<Record<string, unknown>>('/Attest', { report_data: toHex(reportData) });
    return requireHex(result['attestation'], 'attestation');
  }

  /**
   * Evidence collected from the accelerators now, against a challenge the caller picks.
   *
   * The agent hands the nonce to each device verbatim, so the answer is bound to this
   * moment and to no other. It binds the device, not the VM the device sits in; that
   * second link needs TDISP/TEE-IO, which this platform does not expose.
   */
  async attestGpu(nonce: Uint8Array): Promise<readonly GpuEvidenceBundle[]> {
    if (nonce.length !== GPU_NONCE_BYTES) {
      throw new GuestError(
        'GUEST_MALFORMED_RESPONSE',
        `nonce must be exactly ${GPU_NONCE_BYTES} bytes, got ${nonce.length}`,
      );
    }
    const result = await this.post<Record<string, unknown>>('/v1/AttestGpu', { nonce: toHex(nonce) }).catch((error: unknown) => {
      if (error instanceof GuestError && error.status !== undefined && MISSING_ROUTE.has(error.status)) {
        throw new GuestError(
          'GPU_ATTESTATION_UNAVAILABLE',
          `this image has no device attestation route (status ${error.status}), so it cannot produce GPU evidence. ${error.detail}`,
        );
      }
      throw error;
    });
    const bundles = result['bundles'];
    if (!Array.isArray(bundles)) {
      throw new GuestError('GUEST_MALFORMED_RESPONSE', 'bundles is not an array');
    }
    return bundles.map((entry, index) => {
      if (entry === null || typeof entry !== 'object') {
        throw new GuestError('GUEST_MALFORMED_RESPONSE', `bundles[${index}] is not an object`);
      }
      const bundle = entry as Record<string, unknown>;
      return {
        vendor: requireString(bundle['vendor'], `bundles[${index}].vendor`),
        format: requireString(bundle['format'], `bundles[${index}].format`),
        evidence: requireHex(bundle['evidence'], `bundles[${index}].evidence`),
      };
    });
  }

  async info(): Promise<GuestInfo> {
    const result = await this.post<Record<string, unknown>>('/Info', {});
    const tcbInfo = result['tcb_info'];
    if (typeof tcbInfo !== 'string') {
      throw new GuestError('GUEST_MALFORMED_RESPONSE', 'Info returned no tcb_info');
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(tcbInfo);
    } catch {
      throw new GuestError('GUEST_MALFORMED_RESPONSE', 'tcb_info is not valid JSON');
    }
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new GuestError('GUEST_MALFORMED_RESPONSE', 'tcb_info is not a JSON object');
    }
    return { tcbInfo: parsed as Record<string, unknown>, raw: result };
  }

  private post<T>(path: string, payload: unknown): Promise<T> {
    const body = JSON.stringify(payload);
    const url = /^https?:\/\//.test(this.endpoint) ? new URL(path, this.endpoint) : undefined;
    const options: RequestOptions = {
      ...(url === undefined
        ? { socketPath: this.endpoint, host: 'localhost' }
        : { protocol: url.protocol, hostname: url.hostname, port: url.port }),
      path: url?.pathname ?? path,
      method: 'POST',
      headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) },
    };
    return new Promise<T>((resolve, reject) => {
      const onResponse = (response: IncomingMessage): void => {
        const chunks: Buffer[] = [];
        response.on('data', (chunk: Buffer) => chunks.push(chunk));
        response.on('error', (err) => {
          reject(new GuestError('GUEST_REQUEST_FAILED', err.message));
        });
        response.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          const status = response.statusCode ?? 0;
          let parsed: unknown;
          try {
            parsed = JSON.parse(text);
          } catch {
            reject(
              new GuestError(
                'GUEST_MALFORMED_RESPONSE',
                `${path} returned status ${status} and a non-JSON body: ${text.slice(0, 200)}`,
                status,
              ),
            );
            return;
          }
          const remoteError =
            parsed !== null && typeof parsed === 'object' ? (parsed as Record<string, unknown>)['error'] : undefined;
          if (typeof remoteError === 'string') {
            reject(new GuestError('GUEST_RPC_ERROR', `${path}: ${remoteError}`, status));
            return;
          }
          resolve(parsed as T);
        });
      };
      const request =
        url?.protocol === 'https:' ? httpsRequest(options, onResponse) : httpRequest(options, onResponse);
      request.setTimeout(this.timeoutMs, () => {
        request.destroy(new Error(`guest agent did not answer ${path} within ${this.timeoutMs} ms`));
      });
      request.on('error', (err) => {
        reject(new GuestError('GUEST_REQUEST_FAILED', err.message));
      });
      request.write(body);
      request.end();
    });
  }
}

function resolveEndpoint(explicit: string | undefined): string {
  if (explicit !== undefined && explicit.length > 0) {
    return explicit;
  }
  const simulator = process.env['DSTACK_SIMULATOR_ENDPOINT'];
  if (simulator !== undefined && simulator.length > 0) {
    return simulator;
  }
  const present = SOCKET_CANDIDATES.find((candidate) => existsSync(candidate));
  if (present !== undefined) {
    return present;
  }
  throw new GuestError(
    'GUEST_ENDPOINT_MISSING',
    `no dstack guest socket at ${SOCKET_CANDIDATES.join(' or ')}; set DSTACK_SIMULATOR_ENDPOINT or --guest-socket`,
  );
}

function requireHex(value: unknown, field: string): Uint8Array {
  if (typeof value !== 'string') {
    throw new GuestError('GUEST_MALFORMED_RESPONSE', `${field} is not a hex string`);
  }
  try {
    return fromHex(value);
  } catch {
    throw new GuestError('GUEST_MALFORMED_RESPONSE', `${field} is not valid hex`);
  }
}

/**
 * A field the caller dispatches on. A bundle without its `vendor` and `format`
 * routes the evidence to no verifier at all, quietly, so it is refused here.
 */
function requireString(value: unknown, field: string): string {
  if (typeof value !== 'string') {
    throw new GuestError('GUEST_MALFORMED_RESPONSE', `${field} is not a string`);
  }
  return value;
}

// Array.isArray narrows to any[], which would leave every element to be cast again at
// the call site; filtering on the predicate is what actually produces a string[].
function requireStringArray(value: unknown, field: string): string[] {
  if (!Array.isArray(value)) {
    throw new GuestError('GUEST_MALFORMED_RESPONSE', `${field} is not an array of strings`);
  }
  const entries: unknown[] = value;
  const strings = entries.filter((entry): entry is string => typeof entry === 'string');
  if (strings.length !== entries.length) {
    throw new GuestError('GUEST_MALFORMED_RESPONSE', `${field} is not an array of strings`);
  }
  return strings;
}
