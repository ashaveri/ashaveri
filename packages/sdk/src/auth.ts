import {
  EMPTY_BODY_SHA256_HEX,
  POP_NONCE_BYTES,
  randomNonce,
  sha256Hex,
  signPopAuthorization,
  type PopFields,
} from '@ashaveri/receipt';
import { fromBase64Url, fromHex, toBase64Url } from './b64.js';
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
 * The target signed is the target sent: this is the same origin-form path and query the
 * gateway reads off the request it received, so the two agree as long as nothing rewrites
 * the URL on the way. They do not agree through a proxy that changes the prefix, and the
 * answer there is `AUTH_SIGNATURE`, which is the honest one: a signature is a commitment
 * to the bytes this client sent, and a rewritten target is not those bytes.
 */
function requestTarget(url: string): string {
  const parsed = new URL(url);
  return `${parsed.pathname}${parsed.search}`;
}

function decode(value: string, name: string, format: 'hex' | 'base64url'): Uint8Array {
  try {
    return format === 'hex' ? fromHex(value) : fromBase64Url(value);
  } catch (err) {
    throw new SdkError('AUTH_CONFIG', `${name} must be ${format}: ${err instanceof Error ? err.message : String(err)}`);
  }
}

function readNonceHeader(headers: Headers): Uint8Array | null {
  const raw = headers.get('x-ashaveri-nonce');
  if (raw === null) return null;
  const bytes = decode(raw, 'x-ashaveri-nonce', 'base64url');
  if (bytes.length !== POP_NONCE_BYTES) {
    throw new SdkError('AUTH_CONFIG', `x-ashaveri-nonce must be ${String(POP_NONCE_BYTES)} bytes, got ${String(bytes.length)}`);
  }
  return bytes;
}

/**
 * One request as the signature sees it: where it is going, what the transport will send, the
 * bytes to hash. A `Request` input brings its own method and headers and `init` overrides only
 * the keys it names, so both are seeded here; signing always writes a header list, so an init
 * built from nothing would take the caller's method and unrelated headers off the wire. The
 * body is reported apart from that init, which never carries a `Request`'s stream: the transport
 * takes it from the `Request` itself and `bodyBytes` is what refuses it.
 */
interface Outgoing {
  readonly url: string;
  readonly init: RequestInit;
  readonly body: RequestInit['body'] | undefined;
}

function outgoing(input: string | URL | Request, init: RequestInit | undefined): Outgoing {
  if (!(input instanceof Request)) {
    return { url: typeof input === 'string' ? input : input.href, init: init ?? {}, body: init?.body };
  }
  return {
    url: input.url,
    init: { ...init, method: init?.method ?? input.method, headers: init?.headers ?? input.headers },
    body: init?.body ?? input.body ?? null,
  };
}

function applyCredential(credential: AshaveriCredential, request: Outgoing, options: AuthOptions): RequestInit {
  const init = request.init;
  const headers = new Headers(init.headers);
  if (headers.has('authorization')) return init;
  if (credential.kind === 'bearer') {
    headers.set('authorization', `Bearer ${toBase64Url(credential.secret)}`);
    return { ...init, headers };
  }
  const nonce = readNonceHeader(headers) ?? options.nonce?.() ?? randomNonce();
  headers.set('x-ashaveri-nonce', toBase64Url(nonce));
  const body = bodyBytes(request.body);
  const fields: PopFields = {
    ts: Math.floor((options.now?.() ?? Date.now()) / 1000),
    nonce,
    method: (init.method ?? 'GET').toUpperCase(),
    target: requestTarget(request.url),
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
  return async (input, init) => inner(input, applyCredential(credential, outgoing(input, init), options));
}

function decodeSecret(value: string, kind: 'pop' | 'bearer'): Uint8Array {
  const bytes = decode(value, CREDENTIAL_ENV.secret, kind === 'pop' ? 'hex' : 'base64url');
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
