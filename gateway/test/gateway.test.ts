import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { buildGateway } from '../src/server.js';
import { toBase64Url } from '../src/b64.js';
import { decodeReceipt, hashRequest, toHex } from '@ashaveri/receipt';

const NONCE = Uint8Array.from({ length: 16 }, (_, i) => i + 1);
const REQUEST_BODY = '{"model":"mock-model-1","messages":[{"role":"user","content":"hello"}]}';
const STREAM_REQUEST_BODY =
  '{"model":"mock-model-1","messages":[{"role":"user","content":"hello"}],"stream":true}';

function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

let app: FastifyInstance;

beforeEach(() => {
  app = buildGateway();
});

afterEach(async () => {
  await app.close();
});

describe('deployment manifest', () => {
  it('describes the signing key, models, and measurement', async () => {
    const res = await app.inject({ method: 'GET', url: '/v1/deployment-manifest' });
    expect(res.statusCode).toBe(200);
    const manifest = res.json() as {
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
    expect(manifest.meas.tee).toBe('snp');
    expect(manifest.meas.m).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('chat completions', () => {
  it('returns a JSON completion with a receipt id', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      headers: { 'content-type': 'application/json', 'x-ashaveri-nonce': toBase64Url(NONCE) },
      payload: REQUEST_BODY,
    });
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
    const res = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      headers: { 'content-type': 'application/json', 'x-ashaveri-nonce': toBase64Url(NONCE) },
      payload: STREAM_REQUEST_BODY,
    });
    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toContain('text/event-stream');
    expect(typeof res.headers['x-ashaveri-receipt-id']).toBe('string');
    expect(res.payload).toContain('data: ');
    expect(res.payload.trimEnd().endsWith('data: [DONE]')).toBe(true);
  });

  it('rejects an empty messages array', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      headers: { 'content-type': 'application/json' },
      payload: '{"messages":[]}',
    });
    expect(res.statusCode).toBe(400);
    expect(res.json()).toMatchObject({ error: { message: 'messages must be a non-empty array' } });
  });

  it('rejects a malformed JSON body', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      headers: { 'content-type': 'application/json' },
      payload: '{not json',
    });
    expect(res.statusCode).toBe(400);
    expect(res.json()).toMatchObject({ error: { message: 'request body is not valid JSON' } });
  });

  it('rejects a nonce that is not valid base64url', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      headers: { 'content-type': 'application/json', 'x-ashaveri-nonce': '###' },
      payload: REQUEST_BODY,
    });
    expect(res.statusCode).toBe(400);
    expect(res.json()).toMatchObject({
      error: { message: 'x-ashaveri-nonce is not valid base64url' },
    });
  });

  it('rejects a nonce of the wrong length', async () => {
    const short = toBase64Url(Uint8Array.from({ length: 8 }, (_, i) => i + 1));
    const res = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      headers: { 'content-type': 'application/json', 'x-ashaveri-nonce': short },
      payload: REQUEST_BODY,
    });
    expect(res.statusCode).toBe(400);
    expect(res.json()).toMatchObject({
      error: { message: 'x-ashaveri-nonce must be 16 bytes' },
    });
  });
});

describe('receipts', () => {
  it('binds the exact request and response bytes and the client nonce', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      headers: { 'content-type': 'application/json', 'x-ashaveri-nonce': toBase64Url(NONCE) },
      payload: REQUEST_BODY,
    });
    const receiptId = res.headers['x-ashaveri-receipt-id'] as string;
    const receiptRes = await app.inject({ method: 'GET', url: `/v1/receipts/${receiptId}` });
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
    const res = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      headers: { 'content-type': 'application/json', 'x-ashaveri-nonce': toBase64Url(NONCE) },
      payload: STREAM_REQUEST_BODY,
    });
    const receiptId = res.headers['x-ashaveri-receipt-id'] as string;
    const receiptRes = await app.inject({ method: 'GET', url: `/v1/receipts/${receiptId}` });
    const payload = decodeReceipt(new Uint8Array(receiptRes.rawPayload)).payload;
    expect(toHex(payload.res)).toBe(toHex(hashRequest(utf8(res.payload))));
  });

  it('generates a random nonce when the header is absent', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      headers: { 'content-type': 'application/json' },
      payload: REQUEST_BODY,
    });
    const receiptId = res.headers['x-ashaveri-receipt-id'] as string;
    const receiptRes = await app.inject({ method: 'GET', url: `/v1/receipts/${receiptId}` });
    const payload = decodeReceipt(new Uint8Array(receiptRes.rawPayload)).payload;
    expect(payload.nce).toHaveLength(16);
    expect(Array.from(payload.nce)).not.toEqual(Array.from(NONCE));
  });

  it('answers 404 for an unknown receipt id', async () => {
    const res = await app.inject({ method: 'GET', url: '/v1/receipts/does-not-exist' });
    expect(res.statusCode).toBe(404);
  });

  it('binds the bytes sent, not an equivalent JSON serialization', async () => {
    const spaced = '{"model": "mock-model-1", "messages": [{"role": "user", "content": "hello"}]}';
    const first = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      headers: { 'content-type': 'application/json' },
      payload: REQUEST_BODY,
    });
    const second = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      headers: { 'content-type': 'application/json' },
      payload: spaced,
    });
    const firstReceipt = await app.inject({
      method: 'GET',
      url: `/v1/receipts/${first.headers['x-ashaveri-receipt-id'] as string}`,
    });
    const secondReceipt = await app.inject({
      method: 'GET',
      url: `/v1/receipts/${second.headers['x-ashaveri-receipt-id'] as string}`,
    });
    const firstReq = decodeReceipt(new Uint8Array(firstReceipt.rawPayload)).payload.req;
    const secondReq = decodeReceipt(new Uint8Array(secondReceipt.rawPayload)).payload.req;
    expect(toHex(firstReq)).not.toBe(toHex(secondReq));
    expect(toHex(secondReq)).toBe(toHex(hashRequest(utf8(spaced))));
  });
});
