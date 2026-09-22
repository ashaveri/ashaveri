import {
  MARKING_MEMBER_NAME,
  emptyRegion,
  generateSigningKey,
  hashRequest,
  issueReceipt,
  provenanceV1Member,
  randomNonce,
  type Marking,
  type MarkingScheme,
  type ReceiptPayload,
  type ReceiptPayloadV1,
  type SigningKey,
} from '@ashaveri/receipt';
import { sha256 } from '@noble/hashes/sha2.js';

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
  /** Bytes the evidence endpoint serves. The receipt signs this document's digest. */
  readonly evidenceDocument?: Uint8Array;
  /** Bytes the device evidence endpoint serves. Absent means the route is not there. */
  readonly deviceEvidenceDocument?: Uint8Array;
  /** Answer 404 for evidence instead of serving a document. */
  readonly noEvidenceRoute?: boolean;
  /** Deliver streamed bodies in slices of this many bytes. */
  readonly streamChunkBytes?: number;
  /** Omit the receipt id response header entirely. */
  readonly omitReceiptHeader?: boolean;
  /**
   * Issue a v2 receipt, and mark the response under that scheme when one is named. Absent keeps the
   * double a v1 gateway, which is what the older suites here expect.
   *
   * This double writes the mark the way `gateway/src/marking.ts` does — the member spliced in ahead
   * of the closing brace of its own object, one chunk carrying an empty `choices` beside the member in
   * a stream — because both sides take the shape from `@ashaveri/receipt`'s published rule rather than
   * from each other. The client's verdict is only evidence if the bytes it read are bytes a real
   * gateway would have written.
   */
  readonly marking?: MarkingScheme;
  /** Write the frame ahead of the sentinel rather than after the last content chunk. */
  readonly markAfterSentinel?: boolean;
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

/**
 * The response as a marking gateway would have written it, with the attestation over the region it
 * added. `none` adds nothing and attests the empty region, which is a claim about the response rather
 * than an absence of one.
 */
function applyMarking(
  sch: MarkingScheme,
  body: string,
  model: string,
  isStream: boolean,
  afterSentinel: boolean,
): { readonly body: string; readonly marking: Marking } {
  if (sch === 'none') {
    return { body, marking: { sch: 'none', d: sha256(emptyRegion()) } };
  }
  if (!isStream) {
    const member = `"${MARKING_MEMBER_NAME}":${JSON.stringify(provenanceV1Member(FAKE_IAT))}`;
    const brace = body.lastIndexOf('}');
    const comma = body.slice(0, brace).trimEnd().endsWith('{') ? '' : ',';
    return {
      body: `${body.slice(0, brace)}${comma}${member}${body.slice(brace)}`,
      marking: { sch, d: sha256(utf8(member)) },
    };
  }
  const line = `data: ${JSON.stringify({
    id: FAKE_RECEIPT_ID,
    object: 'chat.completion.chunk',
    created: FAKE_IAT,
    model,
    choices: [],
    [MARKING_MEMBER_NAME]: provenanceV1Member(FAKE_IAT),
  })}`;
  const frame = `${line}\n\n`;
  const sentinelAt = body.indexOf('data: [DONE]');
  const marked =
    afterSentinel || sentinelAt < 0 ? `${body}${frame}` : `${body.slice(0, sentinelAt)}${frame}${body.slice(sentinelAt)}`;
  return { body: marked, marking: { sch, d: sha256(utf8(line)) } };
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
  const evidenceDocument = options.evidenceDocument ?? utf8('fake-attestation');
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
    meas: { tee: 'software', m: toHex(hashRequest(utf8('fake-measurement'))) },
  };

  /**
   * Whatever payload the caller handed the transport, as the text the receipt hashes. A `Request`
   * carries its body as a stream rather than as a field of an init, so this is where the double can
   * drain it; a payload in another shape stays unrecorded, as it always did.
   */
  const payloadOf = async (raw: RequestInit['body'] | undefined): Promise<string | undefined> => {
    if (typeof raw === 'string') {
      return raw;
    }
    if (raw instanceof ReadableStream) {
      return new Response(raw).text();
    }
    return undefined;
  };

  const fetch: typeof globalThis.fetch = async (input, init) => {
    const request = input instanceof Request ? input : undefined;
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    const method = (init?.method ?? request?.method ?? 'GET').toUpperCase();
    const headers = new Headers(init?.headers ?? request?.headers);
    const body = await payloadOf(init?.body ?? request?.body);
    requests.push({
      url,
      method,
      body,
      headers: Object.fromEntries(headers.entries()),
      nonceHeader: headers.get('x-ashaveri-nonce') ?? undefined,
    });

    if (url === `${FAKE_BASE_URL}/deployment-manifest`) {
      if (options.manifestStatus !== undefined) {
        return new Response('manifest unavailable', { status: options.manifestStatus });
      }
      return Response.json(manifestJson);
    }

    const deviceMatch = /\/attestation\/gpu\?report_data=([0-9a-fA-F]{64})$/.exec(url);
    if (deviceMatch !== null && method === 'GET') {
      if (options.deviceEvidenceDocument === undefined) {
        return new Response('not found', { status: 404 });
      }
      return new Response(options.deviceEvidenceDocument, { headers: { 'content-type': 'application/octet-stream' } });
    }

    const evidenceMatch = /\/attestation\?report_data=([0-9a-fA-F]{64})$/.exec(url);
    if (evidenceMatch !== null && method === 'GET') {
      if (options.noEvidenceRoute === true) {
        return new Response('not found', { status: 404 });
      }
      return new Response(evidenceDocument, { headers: { 'content-type': 'application/octet-stream' } });
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
      if (body === undefined) {
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
      const marked =
        options.marking === undefined
          ? undefined
          : applyMarking(options.marking, responseBody, requestModel, isStream, options.markAfterSentinel === true);
      const attestedBody = marked?.body ?? responseBody;
      const fields: Omit<ReceiptPayloadV1, 'v'> = {
        iss: issuer,
        ins: instance,
        iat: FIXED_IAT,
        nce: nonce,
        req: hashRequest(utf8(body)),
        res: hashRequest(utf8(attestedBody)),
        mdl: requestModel,
        wts: hashRequest(utf8(`weights:${requestModel}`)),
        meas: { tee: 'software', m: hashRequest(utf8('fake-measurement')) },
        att: { d: sha256(evidenceDocument), ts: FIXED_IAT, url: `${FAKE_BASE_URL}/attestation` },
        epk: 0,
        tok: { p: FAKE_PROMPT_TOKENS, c: FAKE_COMPLETION_TOKENS },
      };
      let payload: ReceiptPayload =
        marked === undefined
          ? { v: 1, ...fields }
          : { v: 2, ...fields, mk: marked.marking };
      payload = options.mutatePayload?.(payload) ?? payload;
      receipts.set(FAKE_RECEIPT_ID, issueReceipt(payload, key));
      const finalBody = options.mutateResponseBody?.(attestedBody) ?? attestedBody;
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
