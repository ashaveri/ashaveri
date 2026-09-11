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

export type GuestErrorCode =
  | 'GUEST_ENDPOINT_MISSING'
  | 'GUEST_REQUEST_FAILED'
  | 'GUEST_RPC_ERROR'
  | 'GUEST_MALFORMED_RESPONSE';

export class GuestError extends Error {
  readonly code: GuestErrorCode;

  constructor(code: GuestErrorCode, detail: string) {
    super(`${code}: ${detail}`);
    this.name = 'GuestError';
    this.code = code;
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

/** The subset of the guest agent a deployment needs: a derived key and bound evidence. */
export interface GuestApi {
  getKey(path: string, purpose: string, algorithm: 'ed25519'): Promise<GuestKey>;
  attest(reportData: Uint8Array): Promise<Uint8Array>;
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
    const chain = result['signature_chain'];
    if (!Array.isArray(chain) || !chain.every((entry) => typeof entry === 'string')) {
      throw new GuestError('GUEST_MALFORMED_RESPONSE', 'signature_chain is not an array of hex strings');
    }
    return { key, signatureChain: chain.map((entry) => fromHex(entry as string)) };
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
        response.on('error', (err) => reject(new GuestError('GUEST_REQUEST_FAILED', err.message)));
        response.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let parsed: unknown;
          try {
            parsed = JSON.parse(text);
          } catch {
            const status = response.statusCode ?? 0;
            reject(
              new GuestError(
                'GUEST_MALFORMED_RESPONSE',
                `${path} returned status ${status} and a non-JSON body: ${text.slice(0, 200)}`,
              ),
            );
            return;
          }
          if (parsed !== null && typeof parsed === 'object' && typeof (parsed as Record<string, unknown>)['error'] === 'string') {
            reject(new GuestError('GUEST_RPC_ERROR', `${path}: ${(parsed as Record<string, unknown>)['error']}`));
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
      request.on('error', (err) => reject(new GuestError('GUEST_REQUEST_FAILED', err.message)));
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
