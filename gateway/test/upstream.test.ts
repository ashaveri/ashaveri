import { describe, expect, it } from 'vitest';
import type { AddressInfo } from 'node:net';
import type { HTTPMethods } from 'fastify';
import { decodeReceipt, hashRequest, toHex } from '@ashaveri/receipt';
import { mockDeployment } from '../src/deployment.js';
import { upstreamBackend } from '../src/upstream.js';
import { generated, harness, type Harness } from './helpers.js';

const MODEL = 'Qwen/Qwen2.5-0.5B-Instruct';
const CREDENTIAL = 'upstream';
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

async function gatewayWith(upstream: FakeUpstream): Promise<Harness> {
  return await harness({
    credentials: [generated(CREDENTIAL, ['complete', 'read'])],
    gateway: {
      deployment: mockDeployment({ model: MODEL }),
      backend: upstreamBackend({ baseUrl: 'http://inference.test/v1', fetchImpl: upstream.fetchImpl }),
    },
  });
}

/** The floor refuses what it cannot verify, so a request here signs the bytes it is about to send. */
async function send(h: Harness, method: HTTPMethods, target: string, body: string | null, nonce?: Uint8Array) {
  return await h.app.inject({
    // A literal method pins inject's awaitable Response overload; the HTTPMethods union selects
    // the chainable form, whose awaited value carries no statusCode or rawPayload.
    method: method as 'GET',
    url: target,
    headers: {
      ...(body === null ? {} : { 'content-type': 'application/json' }),
      ...h.signFor(CREDENTIAL, method, target, body, nonce === undefined ? undefined : { nonce }),
    },
    ...(body === null ? {} : { payload: body }),
  });
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

async function receiptFor(h: Harness, id: string) {
  const res = await send(h, 'GET', `/v1/receipts/${id}`, null);
  expect(res.statusCode).toBe(200);
  return decodeReceipt(new Uint8Array(res.rawPayload)).payload;
}

describe('upstream backend: non-streaming', () => {
  it('forwards the upstream body verbatim and binds it', async () => {
    const body = JSON.stringify(usageEvent(11, 7));
    const upstream = fakeUpstream(() => jsonResponse(body));
    const app = await gatewayWith(upstream);
    const res = await send(app, 'POST', '/v1/chat/completions', REQUEST_BODY, NONCE);
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
    const app = await gatewayWith(upstream);
    const res = await send(app, 'POST', '/v1/chat/completions', REQUEST_BODY);
    const payload = await receiptFor(app, res.headers['x-ashaveri-receipt-id'] as string);
    expect(payload.tok.p).toBe(1234);
    expect(payload.tok.c).toBe(56);
  });

  it('passes an upstream error through without issuing a receipt', async () => {
    const upstream = fakeUpstream(() => new Response('{"error":{"message":"model not found"}}', { status: 404 }));
    const app = await gatewayWith(upstream);
    const res = await send(app, 'POST', '/v1/chat/completions', REQUEST_BODY);
    expect(res.statusCode).toBe(404);
    expect(res.headers['x-ashaveri-receipt-id']).toBeUndefined();
  });

  it('refuses to sign when the upstream served a different model', async () => {
    const upstream = fakeUpstream(() => jsonResponse(JSON.stringify({ ...usageEvent(11, 7), model: 'other/model' })));
    const app = await gatewayWith(upstream);
    const res = await send(app, 'POST', '/v1/chat/completions', REQUEST_BODY);
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
    const app = await gatewayWith(upstream);
    const res = await send(app, 'POST', '/v1/chat/completions', STREAM_REQUEST_BODY, NONCE);
    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toContain('text/event-stream');
    expect(res.payload).toBe(events.join(''));
    const payload = await receiptFor(app, res.headers['x-ashaveri-receipt-id'] as string);
    expect(toHex(payload.res)).toBe(toHex(hashRequest(new TextEncoder().encode(events.join('')))));
    expect(payload.tok).toEqual({ p: 9, c: 4 });
  });

  it('asks the upstream for usage without changing the bytes the receipt binds', async () => {
    const upstream = fakeUpstream(() => streamResponse(streamEvents()));
    const app = await gatewayWith(upstream);
    const res = await send(app, 'POST', '/v1/chat/completions', STREAM_REQUEST_BODY);
    expect(upstream.requests[0]?.body).toMatchObject({ stream: true, stream_options: { include_usage: true } });
    const payload = await receiptFor(app, res.headers['x-ashaveri-receipt-id'] as string);
    expect(toHex(payload.req)).toBe(toHex(hashRequest(new TextEncoder().encode(STREAM_REQUEST_BODY))));
  });

  it('issues no receipt when the client stops reading mid-stream', async () => {
    const upstream = fakeUpstream(
      () => streamResponse(streamEvents(), 40),
    );
    const app = await gatewayWith(upstream);
    await app.app.listen({ port: 0, host: '127.0.0.1' });
    const port = (app.app.server.address() as AddressInfo).port;
    const controller = new AbortController();
    const res = await fetch(`http://127.0.0.1:${port}/v1/chat/completions`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...app.signFor(CREDENTIAL, 'POST', '/v1/chat/completions', STREAM_REQUEST_BODY),
      },
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
    const target = `/v1/receipts/${receiptId as string}`;
    const receiptRes = await fetch(`http://127.0.0.1:${port}${target}`, {
      headers: app.signFor(CREDENTIAL, 'GET', target, null),
    });
    expect(receiptRes.status).toBe(404);
    // The record of an aborted stream travels on the `close` event, since a hijacked
    // reply never emits `finish`: without this line that listener could be deleted and
    // every suite here would still pass.
    const streamed = app.log.entries().filter((each) => each.p === '/v1/chat/completions');
    expect(streamed).toMatchObject([{ cred: CREDENTIAL, auth: 'pop', st: 200, deny: null }]);
    await app.app.close();
  });
});

describe('deployment model guard', () => {
  it('rejects a model the deployment does not serve before contacting the upstream', async () => {
    const upstream = fakeUpstream(() => jsonResponse('{}'));
    const app = await gatewayWith(upstream);
    const res = await send(
      app,
      'POST',
      '/v1/chat/completions',
      '{"model":"not-served","messages":[{"role":"user","content":"hi"}]}',
    );
    expect(res.statusCode).toBe(400);
    expect(res.json()).toMatchObject({ error: { message: "model 'not-served' is not served by this deployment" } });
    expect(upstream.requests).toHaveLength(0);
  });
});

describe('attestation route', () => {
  it('serves the deployment evidence document', async () => {
    const app = await gatewayWith(fakeUpstream(() => jsonResponse('{}')));
    const res = await send(app, 'GET', '/v1/attestation', null);
    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toContain('application/octet-stream');
    expect(res.payload).toBe('mock-attestation');
  });

  it('accepts a 32-byte hex report_data binding', async () => {
    const app = await gatewayWith(fakeUpstream(() => jsonResponse('{}')));
    const good = await send(app, 'GET', `/v1/attestation?report_data=${'ab'.repeat(32)}`, null);
    expect(good.statusCode).toBe(200);
    const bad = await send(app, 'GET', '/v1/attestation?report_data=zz', null);
    expect(bad.statusCode).toBe(400);
  });
});
