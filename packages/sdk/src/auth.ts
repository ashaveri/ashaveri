import {
  EMPTY_BODY_SHA256_HEX,
  POP_NONCE_BYTES,
  randomNonce,
  sha256Hex,
  signPopAuthorization,
  type PopFields,
} from '@ashaveri/receipt';
import { fromBase64Url, toBase64Url } from './b64.js';
import { SdkError } from './errors.js';

export type AshaveriCredential =
  | { readonly kind: 'pop'; readonly id: string; readonly privateKey: Uint8Array }
  | { readonly kind: 'bearer'; readonly secret: Uint8Array };

export const CREDENTIAL_ENV = {
  id: 'ASHAVERI_CREDENTIAL_ID',
  secret: 'ASHAVERI_CREDENTIAL_SECRET',
  kind: 'ASHAVERI_CREDENTIAL_KIND',
} as const;

export interface AuthOptions {
  readonly now?: () => number;
  readonly nonce?: () => Uint8Array;
}

// Spelled through `RequestInit` because `BodyInit` is not one of the fetch names `@types/node`
// declares as a global, so there is no such name to write here.
function bodyBytes(body: RequestInit['body'] | undefined): Uint8Array | null {
  if (body === null || body === undefined) return null;
  if (typeof body === 'string') return new TextEncoder().encode(body);
  if (body instanceof Uint8Array) return body;
  if (body instanceof ArrayBuffer) return new Uint8Array(body);
  throw new SdkError(
    'AUTH_CONFIG',
    'a proof-of-possession client must hash the exact request body, so pass a string or a Uint8Array, not a streaming or form request body',
  );
}

/**
 * The gateway signs and verifies against `request.url`, which is origin-form: the path
 * and the query, no host. Deriving it from the URL keeps a client that reaches the
 * gateway through a reverse proxy at a different prefix from having to know that the
 * proxy rewrote it, because the target it signs is the one on the wire.
 */
function requestTarget(url: string): string {
  const parsed = new URL(url);
  return `${parsed.pathname}${parsed.search}`;
}

function readNonceHeader(headers: Headers): Uint8Array | null {
  const raw = headers.get('x-ashaveri-nonce');
  if (raw === null) return null;
  const bytes = fromBase64Url(raw);
  if (bytes.length !== POP_NONCE_BYTES) {
    throw new SdkError('AUTH_CONFIG', `x-ashaveri-nonce must be ${String(POP_NONCE_BYTES)} bytes, got ${String(bytes.length)}`);
  }
  return bytes;
}

function applyCredential(credential: AshaveriCredential, url: string, init: RequestInit, options: AuthOptions): RequestInit {
  const headers = new Headers(init.headers);
  if (headers.has('authorization')) return init;
  if (credential.kind === 'bearer') {
    headers.set('authorization', `Bearer ${toBase64Url(credential.secret)}`);
    return { ...init, headers };
  }
  const nonce = readNonceHeader(headers) ?? options.nonce?.() ?? randomNonce();
  headers.set('x-ashaveri-nonce', toBase64Url(nonce));
  const body = bodyBytes(init.body);
  const fields: PopFields = {
    ts: Math.floor((options.now?.() ?? Date.now()) / 1000),
    nonce,
    method: (init.method ?? 'GET').toUpperCase(),
    target: requestTarget(url),
    bodyDigestHex: body === null ? EMPTY_BODY_SHA256_HEX : sha256Hex(body),
  };
  headers.set('authorization', signPopAuthorization(fields, credential.id, credential.privateKey));
  return { ...init, headers };
}

/**
 * Signing at the transport rather than in each request builder, because the session
 * layer makes four requests of its own (the manifest, a receipt, and the two evidence
 * documents) and a caller that wrapped the official client reaches the gateway
 * through a fetch this package never sees. One wrapper covers all three paths, and a
 * route added tomorrow is authenticated by the same line as the five that exist today.
 */
export function authorizedFetch(
  credential: AshaveriCredential | undefined,
  inner: typeof fetch,
  options: AuthOptions = {},
): typeof fetch {
  if (credential === undefined) return inner;
  return async (input, init) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    return inner(input, applyCredential(credential, url, init ?? {}, options));
  };
}

function decodeSecret(value: string, kind: 'pop' | 'bearer'): Uint8Array {
  const bytes = kind === 'pop' ? new Uint8Array(Buffer.from(value, 'hex')) : fromBase64Url(value);
  if (kind === 'pop' && bytes.length !== 32) {
    throw new SdkError('AUTH_CONFIG', `${CREDENTIAL_ENV.secret} must be 64 hex digits for a PoP credential, got ${String(bytes.length)} bytes`);
  }
  return bytes;
}

export function credentialFromEnv(env: Record<string, string | undefined>): AshaveriCredential | undefined {
  const id = env[CREDENTIAL_ENV.id];
  const secret = env[CREDENTIAL_ENV.secret];
  if (id === undefined || secret === undefined) return undefined;
  const kindRaw = env[CREDENTIAL_ENV.kind] ?? 'pop';
  if (kindRaw !== 'pop' && kindRaw !== 'bearer') {
    throw new SdkError('AUTH_CONFIG', `${CREDENTIAL_ENV.kind} must be pop or bearer, got ${kindRaw}`);
  }
  const secretBytes = decodeSecret(secret, kindRaw);
  return kindRaw === 'pop' ? { kind: 'pop', id, privateKey: secretBytes } : { kind: 'bearer', secret: secretBytes };
}
