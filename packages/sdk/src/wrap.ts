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
  readonly now?: () => number;
  readonly onReceipt?: (receipt: VerifiedReceipt, id: string) => void;
}

export interface AshaveriTracker {
  /** Resolves (or awaits) the verified receipt for a completed response id. */
  readonly getReceipt: (id: string) => Promise<VerifiedReceipt>;
  readonly receiptIds: () => string[];
}

const CHAT_COMPLETIONS_MARKER = '/chat/completions';

/**
 * Wraps an official `openai` client (v4+) so every chat completion against an
 * Ashaveri gateway is receipted and verified. The client's `fetch` is replaced
 * with one that injects the nonce header, hashes the exact request and
 * response bytes, fetches the receipt once the body completes, and verifies it
 * against the policy. With `verify: 'receipt'` or `'strict'`, a failed
 * verification rejects the completion promise (or errors the stream) instead
 * of silently returning the content.
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
  const authed = authorizedFetch(options.credential, original, { now: options.now });
  const sessions = new Map<string, GatewaySession>();
  const tracked = new Map<string, Promise<VerifiedReceipt>>();

  const wrappedFetch: FetchLike = async (input, init) => {
    if (mode === 'off' || typeof init?.body !== 'string') {
      return authed(input, init);
    }
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    const baseUrl = chatCompletionsBase(url);
    if (baseUrl === undefined) {
      return authed(input, init);
    }
    const nonce = randomNonce();
    const headers = new Headers(init.headers);
    headers.set('x-ashaveri-nonce', toBase64Url(nonce));
    const response = await authed(input, { ...init, headers });
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
    const requestHash = hashRequest(new TextEncoder().encode(init.body));
    const session = sessionFor(baseUrl);
    const [toClient, toHasher] = response.body.tee();
    const verification: Promise<VerifiedReceipt> = (async () => {
      const responseHash = await hashStream(toHasher);
      const receiptBytes = await session.receiptBytes(receiptId);
      const { receipt } = await session.verifyCompletion({
        receiptBytes,
        nonce,
        requestHash,
        responseHash,
        verifyEvidence: mode === 'strict',
        now: options.now?.(),
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

function chatCompletionsBase(url: string): string | undefined {
  if (!url.includes(CHAT_COMPLETIONS_MARKER)) {
    return undefined;
  }
  return url.slice(0, url.length - CHAT_COMPLETIONS_MARKER.length);
}

async function hashStream(stream: ReadableStream<Uint8Array>): Promise<Uint8Array> {
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
  return hashRequest(out);
}
