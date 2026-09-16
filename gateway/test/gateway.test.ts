import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { HTTPMethods } from 'fastify';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { GatewayOptions } from '../src/server.js';
import { openFileReceiptStore, openMemoryReceiptStore } from '../src/store.js';
import { toBase64Url } from '../src/b64.js';
import { decodeReceipt, hashRequest, toHex } from '@ashaveri/receipt';
import { CLOCK_SECONDS, generated, harness, newBearerCredential, type Generated, type Harness } from './helpers.js';

const NONCE = Uint8Array.from({ length: 16 }, (_, i) => i + 1);
const REQUEST_BODY = '{"model":"mock-model-1","messages":[{"role":"user","content":"hello"}]}';
const STREAM_REQUEST_BODY =
  '{"model":"mock-model-1","messages":[{"role":"user","content":"hello"}],"stream":true}';

function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

/** The one credential this suite presents: enough scope for every route it calls. */
function credential(): Generated {
  return generated('gateway', ['complete', 'read']);
}

let session: Harness;

beforeEach(async () => {
  session = await harness({ credentials: [credential()] });
});

afterEach(async () => {
  await session.app.close();
});

/**
 * Nothing on this file's routes is answered to a request that proves nothing, so every call signs the
 * exact bytes it is about to send. `x-ashaveri-nonce` is the proof's nonce and the receipt's nonce at
 * once, which is why a test that wants a particular nonce in its receipt asks for it here rather than
 * setting a header the signature would not cover.
 */
async function send(h: Harness, method: HTTPMethods, target: string, body: string | null, nonce?: Uint8Array) {
  return await h.app.inject({
    // inject resolves its overload from a literal method; the HTTPMethods union selects the
    // chainable form, whose awaited value has no statusCode. A single literal pins the Response.
    method: method as 'GET',
    url: target,
    headers: {
      ...(body === null ? {} : { 'content-type': 'application/json' }),
      ...h.signFor('gateway', method, target, body, nonce === undefined ? undefined : { nonce }),
    },
    ...(body === null ? {} : { payload: body }),
  });
}

/**
 * A proof of possession carries its own nonce, so the route's answer to an absent or unreadable one is
 * reachable on the one admission that brings no nonce: a bearer credential on a deployment that asked
 * for them.
 */
async function sendBearer(
  h: Harness,
  secret: Uint8Array,
  method: HTTPMethods,
  target: string,
  body: string | null,
  nonceHeader?: string,
) {
  return await h.app.inject({
    method: method as 'GET',
    url: target,
    headers: {
      ...(body === null ? {} : { 'content-type': 'application/json' }),
      authorization: `Bearer ${toBase64Url(secret)}`,
      ...(nonceHeader === undefined ? {} : { 'x-ashaveri-nonce': nonceHeader }),
    },
    ...(body === null ? {} : { payload: body }),
  });
}

describe('deployment manifest', () => {
  it('describes the signing key, models, and measurement', async () => {
    const res = await session.inject({
      method: 'GET',
      url: '/v1/deployment-manifest',
      headers: session.signFor('gateway', 'GET', '/v1/deployment-manifest', null),
    });
    expect(res.statusCode).toBe(200);
    const manifest = res.json as {
      v: number;
      iss: string;
      ins: string;
      keys: { kid: string; alg: string; publicKey: string }[];
      models: { id: string }[];
      meas: { tee: string; m: string };
    };
    expect(manifest.v).toBe(1);
    expect(manifest.iss).toBe('ashaveri-mock');
    expect(manifest.ins).toBe('mock-instance-1');
    expect(manifest.keys).toHaveLength(1);
    expect(manifest.keys[0]!.alg).toBe('Ed25519');
    expect(manifest.keys[0]!.kid).toMatch(/^[0-9a-f]{64}$/);
    expect(manifest.keys[0]!.publicKey).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(manifest.models[0]!.id).toBe('mock-model-1');
    // The mock has no TEE behind it, and the protocol now has a kind that says so.
    expect(manifest.meas.tee).toBe('software');
    expect(manifest.meas.m).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('chat completions', () => {
  it('returns a JSON completion with a receipt id', async () => {
    const res = await send(session, 'POST', '/v1/chat/completions', REQUEST_BODY, NONCE);
    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toContain('application/json');
    const receiptId = res.headers['x-ashaveri-receipt-id'];
    expect(typeof receiptId).toBe('string');
    const body = res.json() as {
      id: string;
      object: string;
      model: string;
      choices: { message: { role: string; content: string } }[];
      usage: { prompt_tokens: number; completion_tokens: number };
    };
    expect(body.object).toBe('chat.completion');
    expect(body.model).toBe('mock-model-1');
    expect(body.choices[0]!.message.role).toBe('assistant');
    expect(typeof body.choices[0]!.message.content).toBe('string');
    expect(body.usage.prompt_tokens).toBeGreaterThan(0);
    expect(body.usage.completion_tokens).toBeGreaterThan(0);
  });

  it('returns an SSE stream terminated by [DONE]', async () => {
    const res = await send(session, 'POST', '/v1/chat/completions', STREAM_REQUEST_BODY, NONCE);
    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toContain('text/event-stream');
    expect(typeof res.headers['x-ashaveri-receipt-id']).toBe('string');
    expect(res.payload).toContain('data: ');
    expect(res.payload.trimEnd().endsWith('data: [DONE]')).toBe(true);
  });

  it('rejects an empty messages array', async () => {
    const res = await send(session, 'POST', '/v1/chat/completions', '{"messages":[]}');
    expect(res.statusCode).toBe(400);
    expect(res.json()).toMatchObject({ error: { message: 'messages must be a non-empty array' } });
  });

  it('rejects a malformed JSON body', async () => {
    const res = await send(session, 'POST', '/v1/chat/completions', '{not json');
    expect(res.statusCode).toBe(400);
    expect(res.json()).toMatchObject({ error: { message: 'request body is not valid JSON' } });
  });

  it('rejects a nonce that is not valid base64url', async () => {
    const bearer = newBearerCredential({ id: 'bearer', scopes: ['complete'], now: CLOCK_SECONDS });
    const h = await harness({ extra: [bearer.record], allowBearer: true });
    const res = await sendBearer(h, bearer.secret, 'POST', '/v1/chat/completions', REQUEST_BODY, '###');
    expect(res.statusCode).toBe(400);
    expect(res.json()).toMatchObject({
      error: { message: 'x-ashaveri-nonce is not valid base64url' },
    });
    await h.app.close();
  });

  it('rejects a nonce of the wrong length', async () => {
    const bearer = newBearerCredential({ id: 'bearer', scopes: ['complete'], now: CLOCK_SECONDS });
    const h = await harness({ extra: [bearer.record], allowBearer: true });
    const short = toBase64Url(Uint8Array.from({ length: 8 }, (_, i) => i + 1));
    const res = await sendBearer(h, bearer.secret, 'POST', '/v1/chat/completions', REQUEST_BODY, short);
    expect(res.statusCode).toBe(400);
    expect(res.json()).toMatchObject({
      error: { message: 'x-ashaveri-nonce must be 16 bytes' },
    });
    await h.app.close();
  });
});

describe('receipts', () => {
  it('binds the exact request and response bytes and the client nonce', async () => {
    const res = await send(session, 'POST', '/v1/chat/completions', REQUEST_BODY, NONCE);
    const receiptId = res.headers['x-ashaveri-receipt-id'] as string;
    const receiptRes = await send(session, 'GET', `/v1/receipts/${receiptId}`, null);
    expect(receiptRes.statusCode).toBe(200);
    expect(receiptRes.headers['content-type']).toBe('application/cbor');
    const payload = decodeReceipt(new Uint8Array(receiptRes.rawPayload)).payload;
    expect(toHex(payload.req)).toBe(toHex(hashRequest(utf8(REQUEST_BODY))));
    expect(toHex(payload.res)).toBe(toHex(hashRequest(utf8(res.payload))));
    expect(Array.from(payload.nce)).toEqual(Array.from(NONCE));
    expect(payload.mdl).toBe('mock-model-1');
    expect(payload.iss).toBe('ashaveri-mock');
    expect(payload.ins).toBe('mock-instance-1');
    expect(payload.tok.p).toBeGreaterThan(0);
    expect(payload.tok.c).toBeGreaterThan(0);
  });

  it('binds the exact SSE body for streamed completions', async () => {
    const res = await send(session, 'POST', '/v1/chat/completions', STREAM_REQUEST_BODY, NONCE);
    const receiptId = res.headers['x-ashaveri-receipt-id'] as string;
    const receiptRes = await send(session, 'GET', `/v1/receipts/${receiptId}`, null);
    const payload = decodeReceipt(new Uint8Array(receiptRes.rawPayload)).payload;
    expect(toHex(payload.res)).toBe(toHex(hashRequest(utf8(res.payload))));
  });

  it('generates a random nonce when the header is absent', async () => {
    const bearer = newBearerCredential({ id: 'bearer', scopes: ['complete'], now: CLOCK_SECONDS });
    const h = await harness({ extra: [bearer.record], allowBearer: true });
    const res = await sendBearer(h, bearer.secret, 'POST', '/v1/chat/completions', REQUEST_BODY);
    const receiptId = res.headers['x-ashaveri-receipt-id'] as string;
    const receiptRes = await sendBearer(h, bearer.secret, 'GET', `/v1/receipts/${receiptId}`, null);
    const payload = decodeReceipt(new Uint8Array(receiptRes.rawPayload)).payload;
    expect(payload.nce).toHaveLength(16);
    expect(Array.from(payload.nce)).not.toEqual(Array.from(NONCE));
    await h.app.close();
  });

  it('answers 404 for an unknown receipt id', async () => {
    const res = await send(session, 'GET', '/v1/receipts/does-not-exist', null);
    expect(res.statusCode).toBe(404);
  });

  it('binds the bytes sent, not an equivalent JSON serialization', async () => {
    const spaced = '{"model": "mock-model-1", "messages": [{"role": "user", "content": "hello"}]}';
    const first = await send(session, 'POST', '/v1/chat/completions', REQUEST_BODY);
    const second = await send(session, 'POST', '/v1/chat/completions', spaced);
    const firstReceipt = await send(session, 'GET', `/v1/receipts/${first.headers['x-ashaveri-receipt-id'] as string}`, null);
    const secondReceipt = await send(session, 'GET', `/v1/receipts/${second.headers['x-ashaveri-receipt-id'] as string}`, null);
    const firstReq = decodeReceipt(new Uint8Array(firstReceipt.rawPayload)).payload.req;
    const secondReq = decodeReceipt(new Uint8Array(secondReceipt.rawPayload)).payload.req;
    expect(toHex(firstReq)).not.toBe(toHex(secondReq));
    expect(toHex(secondReq)).toBe(toHex(hashRequest(utf8(spaced))));
  });
});

describe('durable receipts', () => {
  it('serves a receipt issued before the gateway restarted', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'ashaveri-gateway-'));
    try {
      const first = await harness({ credentials: [credential()], gateway: { store: await openFileReceiptStore({ dir }) } });
      const res = await send(first, 'POST', '/v1/chat/completions', REQUEST_BODY, NONCE);
      const receiptId = res.headers['x-ashaveri-receipt-id'] as string;
      await first.app.close();

      const second = await harness({ credentials: [credential()], gateway: { store: await openFileReceiptStore({ dir }) } });
      const fetched = await send(second, 'GET', `/v1/receipts/${receiptId}`, null);
      expect(fetched.statusCode).toBe(200);
      const payload = decodeReceipt(new Uint8Array(fetched.rawPayload)).payload;
      expect(toHex(payload.req)).toBe(toHex(hashRequest(utf8(REQUEST_BODY))));
      expect(toHex(payload.res)).toBe(toHex(hashRequest(utf8(res.payload))));
      await second.app.close();
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe('receipt retention', () => {
  async function complete(h: Harness, text: string): Promise<string> {
    const res = await send(h, 'POST', '/v1/chat/completions', `{"model":"mock-model-1","messages":[{"role":"user","content":"${text}"}]}`);
    return res.headers['x-ashaveri-receipt-id'] as string;
  }

  async function status(h: Harness, id: string): Promise<number> {
    return (await send(h, 'GET', `/v1/receipts/${id}`, null)).statusCode;
  }

  const boundedStore = (): Partial<GatewayOptions> => ({
    store: openMemoryReceiptStore({ retention: { maxCount: 2 } }),
  });

  it('drops the oldest receipt once the store is full', async () => {
    const bounded = await harness({ credentials: [credential()], gateway: boundedStore() });
    const ids = [await complete(bounded, 'first'), await complete(bounded, 'second')];
    expect(await status(bounded, ids[0]!)).toBe(200);
    await complete(bounded, 'third');
    expect(await status(bounded, ids[0]!)).toBe(404);
    expect(await status(bounded, ids[1]!)).toBe(200);
    await bounded.app.close();
  });

  it('forgets a receipt on capacity, not on the last fetch', async () => {
    const bounded = await harness({ credentials: [credential()], gateway: boundedStore() });
    const first = await complete(bounded, 'first');
    await complete(bounded, 'second');
    // Fetching keeps a receipt readable while it is retained, but does not make it
    // the newest entry, so the next completion is what evicts it.
    expect(await status(bounded, first)).toBe(200);
    await complete(bounded, 'third');
    expect(await status(bounded, first)).toBe(404);
    await bounded.app.close();
  });
});
