import { describe, expect, it } from 'vitest';
import OpenAI from 'openai';
import { parsePopAuthorization, sha256Hex, signingKeyFromSeed, toHex, verifyPopSignature } from '@ashaveri/receipt';
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

  // The three cells below are the ruling on an undigestible body: `strict` refuses one by name, the two
  // levels that ask nothing of an unattestable answer still send it, and a text body is still digested
  // under every level, so the refusal cannot be a widening that switched verification off.
  it('refuses a body it cannot digest in strict mode, and sends nothing', async () => {
    const { gateway, client } = fakeOpenAiClient();
    const wrapped = wrapOpenAI(client, { verify: 'strict', policy: {} });
    await expect(
      wrapped.fetch(new Request(CHAT_URL, { method: 'POST', headers: { 'content-type': 'application/json' }, body: REQUEST_BODY })),
    ).rejects.toMatchObject({ code: 'REQUEST_BODY_NOT_DIGESTIBLE' });
    await expect(
      wrapped.fetch(new Request(CHAT_URL, { method: 'POST', body: REQUEST_BODY })),
    ).rejects.toThrow(/Send the body as text/u);
    expect(wrapped.ashaveri.receiptIds(), 'nothing was tracked because nothing was sent').toEqual([]);
    expect(gateway.requests, 'the refusal happened before the wire').toEqual([]);
  });

  it('sends a body it cannot digest under the two levels that promise nothing about it', async () => {
    for (const mode of ['receipt', 'off'] as const) {
      const { gateway, client } = fakeOpenAiClient();
      const wrapped = wrapOpenAI(client, { verify: mode });
      const response = await wrapped.fetch(
        new Request(CHAT_URL, { method: 'POST', headers: { 'content-type': 'application/json' }, body: REQUEST_BODY }),
      );
      expect(response.status, `${mode}: the request completes`).toBe(200);
      expect((await response.text()).includes(FAKE_CONTENT), `${mode}: the answer comes back whole}`).toBe(true);
      expect(gateway.requests[0]!.nonceHeader, `${mode}: no nonce of the client's own goes out`).toBeUndefined();
      expect(wrapped.ashaveri.receiptIds(), `${mode}: no receipt is claimed`).toEqual([]);
    }
  });

  it('digests a text body under every level, so the refusal is about the body and not the mode', async () => {
    for (const mode of ['off', 'receipt', 'strict'] as const) {
      const { gateway, client } = fakeOpenAiClient();
      // `strict` answers only for a deployment the caller named, so the level is reached with the double's own
      // key pinned. Its receipt instant and its evidence timestamp are fixed 2023 seconds, so both age bounds
      // are switched off rather than widened to arbitrary numbers: what this case measures is the digest, not
      // the freshness defaults.
      const policy = {
        keys: { [toHex(gateway.key.kid)]: toBase64Url(gateway.key.publicKey) },
        maxReceiptAgeSeconds: Number.POSITIVE_INFINITY,
        maxEvidenceAgeSeconds: Number.POSITIVE_INFINITY,
      };
      const wrapped = wrapOpenAI(client, mode === 'strict' ? { verify: mode, policy } : { verify: mode });
      const response = await wrapped.fetch(CHAT_URL, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: REQUEST_BODY,
      });
      expect(response.status, `${mode}: the completion is served`).toBe(200);
      if (mode === 'off') {
        // `off` digests nothing by definition, and what it must keep doing is sending the text unchanged.
        expect(gateway.requests[0]!.body, 'off still hands the gateway the bytes it was given').toBe(REQUEST_BODY);
        expect(wrapped.ashaveri.receiptIds()).toEqual([]);
        continue;
      }
      if (mode === 'strict') {
        // The point of this iteration is which refusal a text body does *not* draw. This double signs as a
        // software deployment, so the level that wants platform evidence refuses its answer for that reason;
        // what matters here is that a body readable as text was digested, signed a nonce over, and sent, and
        // never met the refusal the unreadable bodies meet.
        const sent = gateway.requests.find((one) => one.url.endsWith('/chat/completions'));
        expect(sent?.nonceHeader, 'strict hashed the body it was given and signed over it').toBeDefined();
        let refusal: { code?: string } = {};
        try {
          await wrapped.ashaveri.getReceipt(FAKE_RECEIPT_ID);
        } catch (error) {
          refusal = error as { code?: string };
        }
        expect(refusal.code, `strict refused for ${refusal.code ?? 'nothing'}, never for the body`).not.toBe(
          'REQUEST_BODY_NOT_DIGESTIBLE',
        );
        continue;
      }
      const receipt = await wrapped.ashaveri.getReceipt(FAKE_RECEIPT_ID);
      expect(receipt.payload.mdl, `${mode}: the text body was hashed and attested`).toBe('fake-model');
      expect(toHex(receipt.payload.req), `${mode}: the text body was hashed and attested`).toBe(
        sha256Hex(new TextEncoder().encode(REQUEST_BODY)),
      );
    }
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

  it('keeps the headers a Request input carries when it applies the credential', async () => {
    const { gateway, client } = fakeOpenAiClient();
    const secret = new Uint8Array(32);
    const wrapped = wrapOpenAI(client, { credential: { kind: 'bearer', secret } });
    const request = new Request(CHAT_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-request-id': 'call-1', authorization: 'Bearer stale-placeholder' },
      body: REQUEST_BODY,
    });
    const response = await wrapped.fetch(request);
    expect(response.status).toBe(200);
    const recorded = gateway.requests[0]!;
    // A `Request` brings its own method, headers and body, and the header the wrapper owns is
    // `authorization` alone: everything else the caller wrote has to reach the gateway with it.
    expect(recorded.method).toBe('POST');
    expect(recorded.body).toBe(REQUEST_BODY);
    expect(recorded.headers['content-type']).toBe('application/json');
    expect(recorded.headers['x-request-id']).toBe('call-1');
    expect(recorded.headers['authorization']).toBe(`Bearer ${toBase64Url(secret)}`);
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
