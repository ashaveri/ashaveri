import { describe, expect, it } from 'vitest';
import OpenAI from 'openai';
import { parsePopAuthorization, sha256Hex, signingKeyFromSeed, verifyPopSignature } from '@ashaveri/receipt';
import { toBase64Url, wrapOpenAI, type AshaveriCredential } from '../src/index.js';
import {
  createFakeGateway,
  FAKE_BASE_URL,
  FAKE_CONTENT,
  FAKE_RECEIPT_ID,
} from './mock-gateway.js';

const CHAT_URL = `${FAKE_BASE_URL}/chat/completions`;
const REQUEST_BODY = JSON.stringify({ model: 'fake-model', messages: [{ role: 'user', content: 'hi' }] });
const POP_SEED = new Uint8Array(32).fill(11);
const POP_PUBLIC_KEY = signingKeyFromSeed(POP_SEED).publicKey;
const POP_CREDENTIAL: AshaveriCredential = { kind: 'pop', id: 'sdk-wrap-1', privateKey: POP_SEED };

/** Reads headers a capture transport stored from inside its own callback. The compiler cannot follow that assignment, so it needs a guard that names the case where nothing was captured. */
function captured(headers: Headers | null): Headers {
  if (headers === null) throw new Error('the transport captured no request headers');
  return headers;
}

function fakeOpenAiClient(gatewayOptions?: Parameters<typeof createFakeGateway>[0]) {
  const gateway = createFakeGateway(gatewayOptions);
  const client = { apiKey: 'test-key', fetch: gateway.fetch };
  return { gateway, client };
}

describe('wrapOpenAI', () => {
  it('injects the nonce header and verifies the response', async () => {
    const { gateway, client } = fakeOpenAiClient();
    const wrapped = wrapOpenAI(client);
    const response = await wrapped.fetch(CHAT_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer test-key' },
      body: REQUEST_BODY,
    });
    expect(response.status).toBe(200);
    expect(response.headers.get('x-ashaveri-receipt-id')).toBe(FAKE_RECEIPT_ID);
    const text = await response.text();
    expect(text).toContain(FAKE_CONTENT);
    // the original headers survived and the nonce was injected
    const recorded = gateway.requests[0]!;
    expect(recorded.headers['authorization']).toBe('Bearer test-key');
    expect(recorded.nonceHeader).toMatch(/^[A-Za-z0-9_-]{22}$/);
    const receipt = await wrapped.ashaveri.getReceipt(FAKE_RECEIPT_ID);
    expect(receipt.payload.mdl).toBe('fake-model');
    expect(wrapped.ashaveri.receiptIds()).toEqual([FAKE_RECEIPT_ID]);
  });

  it('verifies streamed responses and exposes their receipts', async () => {
    const { client } = fakeOpenAiClient();
    const wrapped = wrapOpenAI(client);
    const response = await wrapped.fetch(CHAT_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ model: 'fake-model', messages: [{ role: 'user', content: 'hi' }], stream: true }),
    });
    const text = await response.text();
    expect(text).toContain('data: ');
    expect(text.trimEnd().endsWith('data: [DONE]')).toBe(true);
    const receipt = await wrapped.ashaveri.getReceipt(FAKE_RECEIPT_ID);
    expect(receipt.payload.tok.c).toBe(9);
  });

  it('errors the body stream when verification fails', async () => {
    const { client } = fakeOpenAiClient({ mutateResponseBody: (body) => body.replace('Fake', 'Real') });
    const wrapped = wrapOpenAI(client);
    const response = await wrapped.fetch(CHAT_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: REQUEST_BODY,
    });
    await expect(response.text()).rejects.toThrow();
    await expect(wrapped.ashaveri.getReceipt(FAKE_RECEIPT_ID)).rejects.toMatchObject({
      code: 'RESPONSE_HASH_MISMATCH',
    });
  });

  it('passes through untouched in off mode', async () => {
    const { gateway, client } = fakeOpenAiClient();
    const wrapped = wrapOpenAI(client, { verify: 'off' });
    const response = await wrapped.fetch(CHAT_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: REQUEST_BODY,
    });
    expect(response.status).toBe(200);
    const text = await response.text();
    expect(text).toContain(FAKE_CONTENT);
    expect(gateway.requests[0]!.nonceHeader).toBeUndefined();
    expect(wrapped.ashaveri.receiptIds()).toEqual([]);
    await expect(wrapped.ashaveri.getReceipt(FAKE_RECEIPT_ID)).rejects.toMatchObject({
      code: 'RECEIPT_NOT_FOUND',
    });
  });

  it('passes through requests that are not chat completions', async () => {
    const { gateway, client } = fakeOpenAiClient();
    const wrapped = wrapOpenAI(client);
    const response = await wrapped.fetch(`${FAKE_BASE_URL}/models`, { method: 'GET' });
    expect(response.status).toBe(404);
    expect(gateway.requests[0]!.nonceHeader).toBeUndefined();
    expect(wrapped.ashaveri.receiptIds()).toEqual([]);
  });

  it('passes through requests without a string body', async () => {
    const { gateway, client } = fakeOpenAiClient();
    const wrapped = wrapOpenAI(client);
    const response = await wrapped.fetch(CHAT_URL, { method: 'POST' });
    expect(response.status).toBe(400);
    expect(gateway.requests[0]!.nonceHeader).toBeUndefined();
    expect(wrapped.ashaveri.receiptIds()).toEqual([]);
  });

  it('rejects a client without a fetch property', () => {
    expect(() => wrapOpenAI({} as object)).toThrow(/no fetch function/);
  });

  it('requires a policy in strict mode', () => {
    const { client } = fakeOpenAiClient();
    expect(() => wrapOpenAI(client, { verify: 'strict' })).toThrow(/requires a policy/);
  });

  it('rejects an unreceipted response in strict mode', async () => {
    const { client } = fakeOpenAiClient({ omitReceiptHeader: true });
    const wrapped = wrapOpenAI(client, { verify: 'strict', policy: {} });
    await expect(
      wrapped.fetch(CHAT_URL, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: REQUEST_BODY,
      }),
    ).rejects.toMatchObject({ code: 'NOT_RECEIPTED' });
  });

  // A hand-made holder proves what header shape the wrapper writes; the real client below proves
  // which header the wrapper wins when the official client has already written one.
  it('sends the credential through the wrapped transport', async () => {
    let seen: Headers | null = null;
    const fake = { fetch: (async (_input: string, init?: RequestInit) => {
      seen = new Headers(init?.headers);
      return new Response(JSON.stringify({ id: 'c1', object: 'chat.completion', created: 0, model: 'm', choices: [] }), { status: 200 });
    }) as unknown as typeof fetch };
    const wrapped = wrapOpenAI(fake, { credential: { kind: 'bearer', secret: new Uint8Array(32) } });
    await (wrapped as unknown as { fetch: typeof fetch }).fetch('https://gw.example/v1/chat/completions', { method: 'POST', body: '{}' });
    expect(captured(seen).get('authorization')).toBe(`Bearer ${toBase64Url(new Uint8Array(32))}`);
  });

  it('replaces the placeholder key an official client writes with the credential it was given', async () => {
    const seen: { headers: Headers; body: string | undefined }[] = [];
    const recorder = (async (_input: string | URL | Request, init?: RequestInit) => {
      seen.push({ headers: new Headers(init?.headers), body: typeof init?.body === 'string' ? init.body : undefined });
      return new Response(JSON.stringify({ id: 'c1', object: 'chat.completion', created: 0, model: 'fake-model', choices: [] }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }) as unknown as typeof fetch;
    const client = new OpenAI({ apiKey: 'placeholder-key', baseURL: 'https://gw.example/v1', fetch: recorder });
    const wrapped = wrapOpenAI(client, { credential: POP_CREDENTIAL });
    await wrapped.chat.completions.create({ model: 'fake-model', messages: [{ role: 'user', content: 'hi' }] });

    const { headers, body } = seen[0]!;
    const authorization = headers.get('authorization') as string;
    expect(authorization).toMatch(/^Ashaveri-PoP credential=sdk-wrap-1,/u);
    expect(authorization).not.toContain('placeholder-key');
    const nonce = Buffer.from(headers.get('x-ashaveri-nonce') as string, 'base64url');
    expect(nonce).toHaveLength(16);
    const parsed = parsePopAuthorization(authorization);
    expect(
      verifyPopSignature(
        {
          ts: parsed.ts,
          nonce: new Uint8Array(nonce),
          method: 'POST',
          target: '/v1/chat/completions',
          bodyDigestHex: sha256Hex(new TextEncoder().encode(body as string)),
        },
        parsed.signature,
        POP_PUBLIC_KEY,
      ),
    ).toBe(true);
  });
});
