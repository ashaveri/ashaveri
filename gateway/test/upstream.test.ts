import { describe, expect, it } from 'vitest';
import type { AddressInfo } from 'node:net';
import { decodeReceipt, hashRequest, toHex } from '@ashaveri/receipt';
import { buildGateway } from '../src/server.js';
import { mockDeployment } from '../src/deployment.js';
import { upstreamBackend } from '../src/upstream.js';
import { toBase64Url } from '../src/b64.js';

const MODEL = 'Qwen/Qwen2.5-0.5B-Instruct';
const NONCE = Uint8Array.from({ length: 16 }, (_, i) => i + 1);
const REQUEST_BODY = `{"model":"${MODEL}","messages":[{"role":"user","content":"hello"}]}`;
const STREAM_REQUEST_BODY = `{"model":"${MODEL}","messages":[{"role":"user","content":"hello"}],"stream":true}`;

interface Recorded {
  readonly body: Record<string, unknown>;
}

interface FakeUpstream {
  readonly fetchImpl: typeof fetch;
  readonly requests: Recorded[];
}

function event(chunk: Record<string, unknown>): string {
  return `data: ${JSON.stringify(chunk)}\n\n`;
}

const DONE = 'data: [DONE]\n\n';

function chunkStream(events: string[], delayMs = 0): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder();
  return new ReadableStream<Uint8Array>({
    async start(controller) {
      for (const item of events) {
        if (delayMs > 0) {
          await new Promise((resolve) => setTimeout(resolve, delayMs));
        }
        controller.enqueue(encoder.encode(item));
      }
      controller.close();
    },
  });
}

function streamResponse(events: string[], delayMs = 0): Response {
  return new Response(chunkStream(events, delayMs), {
    status: 200,
    headers: { 'content-type': 'text/event-stream' },
  });
}

function jsonResponse(body: string): Response {
  return new Response(body, { status: 200, headers: { 'content-type': 'application/json' } });
}

function fakeUpstream(make: (body: Record<string, unknown>) => Response | Promise<Response>): FakeUpstream {
  const requests: Recorded[] = [];
  return {
    requests,
    fetchImpl: (async (_input: unknown, init?: RequestInit) => {
      const raw = init?.body;
      const text = Buffer.isBuffer(raw) ? raw.toString('utf8') : String(raw ?? '');
      const body = JSON.parse(text) as Record<string, unknown>;
      requests.push({ body });
      return make(body);
    }) as typeof fetch,
  };
}

function gatewayWith(upstream: FakeUpstream) {
  const deployment = mockDeployment({ model: MODEL });
  const app = buildGateway({
    deployment,
    backend: upstreamBackend({ baseUrl: 'http://inference.test/v1', fetchImpl: upstream.fetchImpl }),
  });
  return { app, deployment };
}

function usageEvent(promptTokens: number, completionTokens: number): Record<string, unknown> {
  return {
    id: 'chatcmpl-live-1',
    object: 'chat.completion',
    created: 1_700_000_000,
    model: MODEL,
    choices: [],
    usage: { prompt_tokens: promptTokens, completion_tokens: completionTokens, total_tokens: promptTokens + completionTokens },
  };
}

async function receiptFor(app: ReturnType<typeof buildGateway>, id: string) {
  const res = await app.inject({ method: 'GET', url: `/v1/receipts/${id}` });
  expect(res.statusCode).toBe(200);
  return decodeReceipt(new Uint8Array(res.rawPayload)).payload;
}

describe('upstream backend: non-streaming', () => {
  it('forwards the upstream body verbatim and binds it', async () => {
    const body = JSON.stringify(usageEvent(11, 7));
    const upstream = fakeUpstream(() => jsonResponse(body));
    const { app } = gatewayWith(upstream);
    const res = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      headers: { 'content-type': 'application/json', 'x-ashaveri-nonce': toBase64Url(NONCE) },
      payload: REQUEST_BODY,
    });
    expect(res.statusCode).toBe(200);
    expect(res.payload).toBe(body);
    const payload = await receiptFor(app, res.headers['x-ashaveri-receipt-id'] as string);
    expect(toHex(payload.res)).toBe(toHex(hashRequest(new TextEncoder().encode(body))));
    expect(toHex(payload.req)).toBe(toHex(hashRequest(new TextEncoder().encode(REQUEST_BODY))));
    expect(payload.tok).toEqual({ p: 11, c: 7 });
    expect(payload.mdl).toBe(MODEL);
  });

  it('takes real token counts rather than estimating them', async () => {
    const upstream = fakeUpstream(() => jsonResponse(JSON.stringify(usageEvent(1234, 56))));
    const { app } = gatewayWith(upstream);
    const res = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      headers: { 'content-type': 'application/json' },
      payload: REQUEST_BODY,
    });
    const payload = await receiptFor(app, res.headers['x-ashaveri-receipt-id'] as string);
    expect(payload.tok.p).toBe(1234);
    expect(payload.tok.c).toBe(56);
  });

  it('passes an upstream error through without issuing a receipt', async () => {
    const upstream = fakeUpstream(() => new Response('{"error":{"message":"model not found"}}', { status: 404 }));
    const { app } = gatewayWith(upstream);
    const res = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      headers: { 'content-type': 'application/json' },
      payload: REQUEST_BODY,
    });
    expect(res.statusCode).toBe(404);
    expect(res.headers['x-ashaveri-receipt-id']).toBeUndefined();
  });

  it('refuses to sign when the upstream served a different model', async () => {
    const upstream = fakeUpstream(() => jsonResponse(JSON.stringify({ ...usageEvent(11, 7), model: 'other/model' })));
    const { app } = gatewayWith(upstream);
    const res = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      headers: { 'content-type': 'application/json' },
      payload: REQUEST_BODY,
    });
    expect(res.statusCode).toBe(502);
    expect(res.json()).toMatchObject({ error: { type: 'upstream_error' } });
  });
});

describe('upstream backend: streaming', () => {
  function streamEvents(): string[] {
    return [
      event({ id: 'chatcmpl-live-1', object: 'chat.completion.chunk', created: 1_700_000_000, model: MODEL, choices: [{ index: 0, delta: { role: 'assistant' }, finish_reason: null }] }),
      event({ id: 'chatcmpl-live-1', object: 'chat.completion.chunk', created: 1_700_000_000, model: MODEL, choices: [{ index: 0, delta: { content: 'Hel' }, finish_reason: null }] }),
      event({ id: 'chatcmpl-live-1', object: 'chat.completion.chunk', created: 1_700_000_000, model: MODEL, choices: [{ index: 0, delta: { content: 'lo' }, finish_reason: 'stop' }] }),
      event({ id: 'chatcmpl-live-1', object: 'chat.completion.chunk', created: 1_700_000_000, model: MODEL, choices: [], usage: { prompt_tokens: 9, completion_tokens: 4, total_tokens: 13 } }),
      DONE,
    ];
  }

  it('reassembles events that arrive split across network chunks', async () => {
    const events = streamEvents();
    const upstream = fakeUpstream(() => streamResponse(events));
    const { app } = gatewayWith(upstream);
    const res = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      headers: { 'content-type': 'application/json', 'x-ashaveri-nonce': toBase64Url(NONCE) },
      payload: STREAM_REQUEST_BODY,
    });
    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toContain('text/event-stream');
    expect(res.payload).toBe(events.join(''));
    const payload = await receiptFor(app, res.headers['x-ashaveri-receipt-id'] as string);
    expect(toHex(payload.res)).toBe(toHex(hashRequest(new TextEncoder().encode(events.join('')))));
    expect(payload.tok).toEqual({ p: 9, c: 4 });
  });

  it('asks the upstream for usage without changing the bytes the receipt binds', async () => {
    const upstream = fakeUpstream(() => streamResponse(streamEvents()));
    const { app } = gatewayWith(upstream);
    const res = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      headers: { 'content-type': 'application/json' },
      payload: STREAM_REQUEST_BODY,
    });
    expect(upstream.requests[0]?.body).toMatchObject({ stream: true, stream_options: { include_usage: true } });
    const payload = await receiptFor(app, res.headers['x-ashaveri-receipt-id'] as string);
    expect(toHex(payload.req)).toBe(toHex(hashRequest(new TextEncoder().encode(STREAM_REQUEST_BODY))));
  });

  it('issues no receipt when the client stops reading mid-stream', async () => {
    const upstream = fakeUpstream(
      () => streamResponse(streamEvents(), 40),
    );
    const { app } = gatewayWith(upstream);
    await app.listen({ port: 0, host: '127.0.0.1' });
    const port = (app.server.address() as AddressInfo).port;
    const controller = new AbortController();
    const res = await fetch(`http://127.0.0.1:${port}/v1/chat/completions`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: STREAM_REQUEST_BODY,
      signal: controller.signal,
    });
    const receiptId = res.headers.get('x-ashaveri-receipt-id');
    expect(typeof receiptId).toBe('string');
    const reader = res.body?.getReader();
    expect(reader).toBeDefined();
    await reader?.read();
    controller.abort();
    await new Promise((resolve) => setTimeout(resolve, 250));
    const receiptRes = await fetch(`http://127.0.0.1:${port}/v1/receipts/${receiptId as string}`);
    expect(receiptRes.status).toBe(404);
    await app.close();
  });
});

describe('deployment model guard', () => {
  it('rejects a model the deployment does not serve before contacting the upstream', async () => {
    const upstream = fakeUpstream(() => jsonResponse('{}'));
    const { app } = gatewayWith(upstream);
    const res = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      headers: { 'content-type': 'application/json' },
      payload: '{"model":"not-served","messages":[{"role":"user","content":"hi"}]}',
    });
    expect(res.statusCode).toBe(400);
    expect(res.json()).toMatchObject({ error: { message: "model 'not-served' is not served by this deployment" } });
    expect(upstream.requests).toHaveLength(0);
  });
});

describe('attestation route', () => {
  it('serves the deployment evidence document', async () => {
    const { app } = gatewayWith(fakeUpstream(() => jsonResponse('{}')));
    const res = await app.inject({ method: 'GET', url: '/v1/attestation' });
    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toContain('application/octet-stream');
    expect(res.payload).toBe('mock-attestation');
  });

  it('accepts a 32-byte hex report_data binding', async () => {
    const { app } = gatewayWith(fakeUpstream(() => jsonResponse('{}')));
    const good = await app.inject({ method: 'GET', url: `/v1/attestation?report_data=${'ab'.repeat(32)}` });
    expect(good.statusCode).toBe(200);
    const bad = await app.inject({ method: 'GET', url: '/v1/attestation?report_data=zz' });
    expect(bad.statusCode).toBe(400);
  });
});
