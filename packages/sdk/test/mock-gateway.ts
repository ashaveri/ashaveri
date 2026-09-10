import {
  generateSigningKey,
  hashRequest,
  issueReceipt,
  randomNonce,
  type ReceiptPayload,
  type SigningKey,
} from '@ashaveri/receipt';

export type ManifestKeyMode = 'real' | 'wrong' | 'none';

export interface FakeGatewayOptions {
  readonly issuer?: string;
  readonly instance?: string;
  readonly model?: string;
  /** Mutate the receipt payload before signing, simulating a lying gateway. */
  readonly mutatePayload?: (payload: ReceiptPayload) => ReceiptPayload;
  /** Mutate the response body after the receipt was computed. */
  readonly mutateResponseBody?: (body: string) => string;
  /** How the manifest declares the signing key. */
  readonly manifestKeys?: ManifestKeyMode;
  /** Serve the manifest with a failure status instead. */
  readonly manifestStatus?: number;
  /** Serve completions with a failure status instead. */
  readonly completionStatus?: number;
  /** Answer 404 for the first N receipt fetches. */
  readonly receiptAvailableAfterAttempts?: number;
  /** Deliver streamed bodies in slices of this many bytes. */
  readonly streamChunkBytes?: number;
  /** Omit the receipt id response header entirely. */
  readonly omitReceiptHeader?: boolean;
}

export interface RecordedRequest {
  readonly url: string;
  readonly method: string;
  readonly body?: string;
  readonly headers: Record<string, string>;
  readonly nonceHeader?: string;
}

export interface FakeGateway {
  readonly fetch: typeof fetch;
  readonly key: SigningKey;
  readonly baseUrl: string;
  readonly manifestJson: Record<string, unknown>;
  readonly requests: RecordedRequest[];
}

export const FAKE_BASE_URL = 'https://gateway.test/v1';
export const FAKE_RECEIPT_ID = 'chatcmpl-fake0001';
export const FAKE_CONTENT = 'Fake completion for 1 message(s).';
export const FAKE_PROMPT_TOKENS = 12;
export const FAKE_COMPLETION_TOKENS = 9;
export const FAKE_IAT = 1_700_000_000;
const FIXED_IAT = FAKE_IAT;

function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const b of bytes) {
    binary += String.fromCharCode(b);
  }
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

function fromBase64Url(value: string): Uint8Array {
  const padded = value.replaceAll('-', '+').replaceAll('_', '/');
  const binary = atob(padded.padEnd(Math.ceil(padded.length / 4) * 4, '='));
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

function chunkJson(id: string, created: number, model: string, delta: Record<string, unknown>, finishReason: string | null): string {
  return JSON.stringify({
    id,
    object: 'chat.completion.chunk',
    created,
    model,
    choices: [{ index: 0, delta, finish_reason: finishReason }],
  });
}

function sseBody(id: string, created: number, model: string, content: string): string {
  return (
    `data: ${chunkJson(id, created, model, { role: 'assistant', content: content.slice(0, 5) }, null)}\n\n` +
    `data: ${chunkJson(id, created, model, { content: content.slice(5, 12) }, null)}\n\n` +
    `data: ${chunkJson(id, created, model, { content: content.slice(12) }, null)}\n\n` +
    `data: ${chunkJson(id, created, model, {}, 'stop')}\n\n` +
    'data: [DONE]\n\n'
  );
}

function chunkedStream(text: string, sliceBytes: number): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder();
  return new ReadableStream<Uint8Array>({
    start(controller) {
      for (let i = 0; i < text.length; i += sliceBytes) {
        controller.enqueue(encoder.encode(text.slice(i, i + sliceBytes)));
      }
      controller.close();
    },
  });
}

export function createFakeGateway(options: FakeGatewayOptions = {}): FakeGateway {
  const issuer = options.issuer ?? 'fake-issuer';
  const instance = options.instance ?? 'fake-instance';
  const model = options.model ?? 'fake-model';
  const key = generateSigningKey();
  const receipts = new Map<string, Uint8Array>();
  const requests: RecordedRequest[] = [];
  let receiptCalls = 0;

  const manifestKeyEntry = () => {
    const declaredKey = options.manifestKeys === 'wrong' ? generateSigningKey() : key;
    return { kid: toHex(declaredKey.kid), alg: 'Ed25519', publicKey: toBase64Url(declaredKey.publicKey) };
  };
  const manifestJson: Record<string, unknown> = {
    v: 1,
    iss: issuer,
    ins: instance,
    epk: 0,
    keys: options.manifestKeys === 'none' ? [] : [manifestKeyEntry()],
    models: [{ id: model, wts: toHex(hashRequest(utf8(`weights:${model}`))) }],
    meas: { tee: 'snp', m: toHex(hashRequest(utf8('fake-measurement'))) },
  };

  const fetch: typeof fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    const method = (init?.method ?? 'GET').toUpperCase();
    const headers = new Headers(init?.headers);
    requests.push({
      url,
      method,
      body: typeof init?.body === 'string' ? init.body : undefined,
      headers: Object.fromEntries(headers.entries()),
      nonceHeader: headers.get('x-ashaveri-nonce') ?? undefined,
    });

    if (url === `${FAKE_BASE_URL}/deployment-manifest`) {
      if (options.manifestStatus !== undefined) {
        return new Response('manifest unavailable', { status: options.manifestStatus });
      }
      return Response.json(manifestJson);
    }

    const receiptMatch = /\/receipts\/([^/]+)$/.exec(url);
    if (receiptMatch !== null && method === 'GET') {
      receiptCalls += 1;
      const id = decodeURIComponent(receiptMatch[1]!);
      const bytes = receipts.get(id);
      if (bytes === undefined || (options.receiptAvailableAfterAttempts !== undefined && receiptCalls < options.receiptAvailableAfterAttempts)) {
        return new Response('not found', { status: 404 });
      }
      return new Response(bytes);
    }

    if (url === `${FAKE_BASE_URL}/chat/completions` && method === 'POST') {
      if (options.completionStatus !== undefined) {
        return new Response('gateway exploded', { status: options.completionStatus });
      }
      const body = init?.body;
      if (typeof body !== 'string') {
        return new Response('body must be a string', { status: 400 });
      }
      const parsed = JSON.parse(body) as { model?: string; messages?: unknown[]; stream?: boolean };
      const requestModel = parsed.model ?? model;
      const isStream = parsed.stream === true;
      const responseBody = isStream
        ? sseBody(FAKE_RECEIPT_ID, FIXED_IAT, requestModel, FAKE_CONTENT)
        : JSON.stringify({
            id: FAKE_RECEIPT_ID,
            object: 'chat.completion',
            created: FIXED_IAT,
            model: requestModel,
            choices: [
              {
                index: 0,
                message: { role: 'assistant', content: FAKE_CONTENT },
                finish_reason: 'stop',
              },
            ],
            usage: {
              prompt_tokens: FAKE_PROMPT_TOKENS,
              completion_tokens: FAKE_COMPLETION_TOKENS,
              total_tokens: FAKE_PROMPT_TOKENS + FAKE_COMPLETION_TOKENS,
            },
          });
      const nonceHeader = headers.get('x-ashaveri-nonce');
      const nonce = nonceHeader !== null ? fromBase64Url(nonceHeader) : randomNonce();
      let payload: ReceiptPayload = {
        v: 1,
        iss: issuer,
        ins: instance,
        iat: FIXED_IAT,
        nce: nonce,
        req: hashRequest(utf8(body)),
        res: hashRequest(utf8(responseBody)),
        mdl: requestModel,
        wts: hashRequest(utf8(`weights:${requestModel}`)),
        meas: { tee: 'snp', m: hashRequest(utf8('fake-measurement')) },
        att: { d: hashRequest(utf8('fake-attestation')), ts: FIXED_IAT, url: 'https://gateway.test/attestation' },
        epk: 0,
        tok: { p: FAKE_PROMPT_TOKENS, c: FAKE_COMPLETION_TOKENS },
      };
      payload = options.mutatePayload?.(payload) ?? payload;
      receipts.set(FAKE_RECEIPT_ID, issueReceipt(payload, key));
      const finalBody = options.mutateResponseBody?.(responseBody) ?? responseBody;
      const responseHeaders: Record<string, string> = {
        'content-type': isStream ? 'text/event-stream' : 'application/json',
      };
      if (!options.omitReceiptHeader) {
        responseHeaders['x-ashaveri-receipt-id'] = FAKE_RECEIPT_ID;
      }
      if (isStream && options.streamChunkBytes !== undefined) {
        return new Response(chunkedStream(finalBody, options.streamChunkBytes), { status: 200, headers: responseHeaders });
      }
      return new Response(finalBody, { status: 200, headers: responseHeaders });
    }

    return new Response('not found', { status: 404 });
  };

  return { fetch, key, baseUrl: FAKE_BASE_URL, manifestJson, requests };
}
