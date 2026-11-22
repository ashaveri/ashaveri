import { hashRequest, randomNonce, type VerifiedReceipt } from '@ashaveri/receipt';
import { authorizedFetch, type AshaveriCredential } from './auth.js';
import { toBase64Url } from './b64.js';
import type { VerifyMode } from './client.js';
import { GatewaySession } from './gateway.js';
import { SdkError } from './errors.js';
import type { AshaveriPolicy } from './policy.js';

type FetchLike = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

export interface WrapOptions {
  /** Verification level. Default: 'receipt'. 'strict' requires a policy. */
  readonly verify?: VerifyMode;
  readonly policy?: AshaveriPolicy;
  /** Proof of possession or bearer credential. Omit to talk to a gateway that requires none. */
  readonly credential?: AshaveriCredential;
  /** Wall clock in milliseconds since the epoch; defaults to Date.now. */
  readonly nowMillis?: () => number;
  readonly onReceipt?: (receipt: VerifiedReceipt, id: string) => void;
}

export interface AshaveriTracker {
  /** Resolves (or awaits) the verified receipt for a completed response id. */
  readonly getReceipt: (id: string) => Promise<VerifiedReceipt>;
  readonly receiptIds: () => string[];
}

const CHAT_COMPLETIONS_MARKER = '/chat/completions';

/**
 * The bytes a wrapper can put under a digest, spelled the way `auth.ts` spells the set a proof-of-possession
 * signature accepts, so one body is never attestable to the signer and refused by the evidence. `undefined` is
 * the answer only for what no caller hands over: a `Request`, a stream or a form.
 */
function digestibleBody(body: RequestInit['body']): Uint8Array | undefined {
  if (typeof body === 'string') return new TextEncoder().encode(body);
  if (body instanceof Uint8Array) return body;
  if (body instanceof ArrayBuffer) return new Uint8Array(body);
  return undefined;
}

/**
 * Wraps an official `openai` client (v4+) so every chat completion against an
 * Ashaveri gateway is receipted and verified. The client's `fetch` is replaced
 * with one that injects the nonce header, hashes the exact request and
 * response bytes, fetches the receipt once the body completes, and verifies it
 * against the policy. With `verify: 'receipt'` or `'strict'`, a failed
 * verification rejects the completion promise (or errors the stream) instead
 * of silently returning the content.
 *
 * The digest is taken over bytes this call can name, which are a text body or a byte buffer, the same set a
 * proof-of-possession signature will accept. A `Request`, a stream or a form carries bytes no caller hands over:
 * `strict` refuses one before anything goes on the wire, because that level answers for the request as well as
 * for the answer, and `receipt` and `off` forward it and attest nothing about it. A caller presenting a
 * proof-of-possession credential meets `AUTH_CONFIG` at either of those two levels instead, because that
 * signature is computed over the body and there is nothing to compute it from. Section 5.1 of
 * `docs/receipt-spec.md` states the same rule where the three levels are defined.
 */
export function wrapOpenAI<T extends object>(client: T, options: WrapOptions = {}): T & { readonly ashaveri: AshaveriTracker } {
  const mode = options.verify ?? 'receipt';
  const holder = client as { fetch?: FetchLike };
  if (typeof holder.fetch !== 'function') {
    throw new SdkError('GATEWAY_ERROR', 'the client has no fetch function to wrap');
  }
  if (mode === 'strict' && options.policy === undefined) {
    throw new SdkError('NO_POLICY', "verify: 'strict' requires a policy pinning keys and measurements");
  }
  const original = holder.fetch.bind(undefined);
  const authed = authorizedFetch(options.credential, original, { nowMillis: options.nowMillis });
  const sessions = new Map<string, GatewaySession>();
  const tracked = new Map<string, Promise<VerifiedReceipt>>();

  const wrappedFetch: FetchLike = async (input, init) => {
    // The official client writes its own `Authorization` for a key this package never sees, and a
    // caller-set one wins over a credential: on this path the header is the wrapper's to own. A
    // `Request` input carries its headers on the request rather than in the init, so seeding from
    // the init alone would send an empty list and drop every header the caller had written.
    const prepared =
      options.credential === undefined
        ? init
        : { ...init, headers: withoutAuthorization(init?.headers ?? (input instanceof Request ? input.headers : undefined)) };
    // `off` asks nothing of a response, so it asks nothing of a request either: the caller's own bytes go
    // out with the credential and no nonce, whatever the body carries.
    if (mode === 'off') {
      return authed(input, prepared);
    }
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    const baseUrl = chatCompletionsBase(url);
    if (baseUrl === undefined) {
      return authed(input, prepared);
    }
    // Everything below digests bytes, and a body this call cannot name gives it nothing to digest. The readable
    // set is spelled the way `auth.ts` spells it for a signature, so a body is never attestable to one and
    // refused by the other. `strict` refuses the rest; `receipt` forwards it and claims nothing, unless the
    // caller presents a proof-of-possession credential, whose signature step refuses the request first.
    const digestBytes = prepared === undefined ? undefined : digestibleBody(prepared.body);
    if (digestBytes === undefined || prepared === undefined) {
      if (mode === 'strict') {
        throw new SdkError('REQUEST_BODY_NOT_DIGESTIBLE', notDigestibleDetail(prepared));
      }
      return authed(input, prepared);
    }
    const nonce = randomNonce();
    const headers = new Headers(prepared.headers);
    headers.set('x-ashaveri-nonce', toBase64Url(nonce));
    const response = await authed(input, { ...prepared, headers });
    const receiptId = response.headers.get('x-ashaveri-receipt-id');
    if (receiptId === null) {
      if (mode === 'strict') {
        throw new SdkError('NOT_RECEIPTED', 'the gateway did not provide a receipt for the response');
      }
      return response;
    }
    if (response.body === null) {
      return response;
    }
    const requestHash = hashRequest(digestBytes);
    const session = sessionFor(baseUrl);
    const [toClient, toHasher] = response.body.tee();
    const verification: Promise<VerifiedReceipt> = (async () => {
      // `responseBytes` is the whole body this branch of the tee read, which this call already held
      // in order to digest it. Keeping it costs no buffering and no latency; dropping it is what
      // would leave the marking claim unchecked on the path that runs the official client.
      const { responseBytes, responseHash } = await digestStream(toHasher);
      const receiptBytes = await session.receiptBytes(receiptId);
      const { receipt } = await session.verifyCompletion({
        receiptBytes,
        nonce,
        requestHash,
        responseHash,
        responseBytes,
        verifyEvidence: mode === 'strict',
        nowMillis: options.nowMillis?.(),
      });
      options.onReceipt?.(receipt, receiptId);
      return receipt;
    })();
    // Keep a handler on the promise so a response that is abandoned before
    // verification finishes never surfaces as an unhandled rejection.
    verification.catch(() => undefined);
    tracked.set(receiptId, verification);
    const guarded = toClient.pipeThrough(
      new TransformStream<Uint8Array, Uint8Array>({
        // Awaits verification before the stream closes, so a failed check
        // errors the stream the client is reading instead of passing silently.
        flush: async () => {
          await verification;
        },
      }),
    );
    return new Response(guarded, response);
  };

  holder.fetch = wrappedFetch;

  const ashaveri: AshaveriTracker = {
    getReceipt: (id) => {
      const pending = tracked.get(id);
      if (pending === undefined) {
        return Promise.reject(new SdkError('RECEIPT_NOT_FOUND', `no receipt is tracked for response id ${id}`));
      }
      return pending;
    },
    receiptIds: () => Array.from(tracked.keys()),
  };
  return Object.assign(client, { ashaveri });

  function sessionFor(base: string): GatewaySession {
    let session = sessions.get(base);
    if (session === undefined) {
      session = new GatewaySession(base, { fetchImpl: authed, policy: options.policy });
      sessions.set(base, session);
    }
    return session;
  }
}

/**
 * The refused request stated as what a caller can change: what this wrapper digests, which shapes give it
 * nothing, which level refused, and the ways out. A sentence naming only the refusal would leave a caller
 * sending the same request in the same shape.
 */
function notDigestibleDetail(prepared: RequestInit | undefined): string {
  const carried =
    prepared === undefined
      ? 'no request init at all'
      : prepared.body === null || prepared.body === undefined
        ? `no body (${typeof prepared.body})`
        : `a body this call cannot name (${Object.prototype.toString.call(prepared.body)})`;
  return (
    `this wrapper hashes the bytes it sends, and it cannot hash ${carried}: a Request, a stream, a form-data ` +
      `body and a missing body are that shape, so no nonce could be signed over the request and no receipt's req ` +
      `could be checked against it. verify is 'strict', the level that answers for the request it sends, so this ` +
      `request was refused here and nothing went on the wire. Send the body as text or as bytes, which is what ` +
      `the official client writes for a chat completion, or verify at 'receipt' or 'off', either of which ` +
      `forwards such a request and attests nothing about it unless a proof-of-possession credential is in use, ` +
      `whose signature is computed over the body and so refuses it either way`
  );
}

function withoutAuthorization(headers: RequestInit['headers']): Headers {
  const copy = new Headers(headers);
  copy.delete('authorization');
  return copy;
}

function chatCompletionsBase(url: string): string | undefined {
  if (!url.includes(CHAT_COMPLETIONS_MARKER)) {
    return undefined;
  }
  return url.slice(0, url.length - CHAT_COMPLETIONS_MARKER.length);
}

/**
 * Everything a verifier needs from a response body: the bytes themselves and their digest. The bytes
 * are the marked region's only witness, so a wrapper that hashed and discarded them could confirm a
 * signature over a response whose mark it never looked at.
 */
async function digestStream(
  stream: ReadableStream<Uint8Array>,
): Promise<{ readonly responseBytes: Uint8Array; readonly responseHash: Uint8Array }> {
  const reader = stream.getReader();
  const parts: Uint8Array[] = [];
  for (;;) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    parts.push(value);
  }
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return { responseBytes: out, responseHash: hashRequest(out) };
}
