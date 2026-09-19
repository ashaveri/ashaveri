import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { HTTPMethods } from 'fastify';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { GatewayOptions } from '../src/server.js';
import { openFileReceiptStore, openMemoryReceiptStore } from '../src/store.js';
import { toBase64Url } from '../src/b64.js';
import { decodeReceipt, hashRequest, signingKeyFromSeed, toHex } from '@ashaveri/receipt';
import {
  parseCredentialFile,
  RECEIPT_ID,
  RECEIPT_ID_CHARS,
  RECEIPT_ID_TAG_HEX_CHARS,
  ReceiptNamespace,
  serializeCredentialFile,
} from '../src/access.js';
import {
  CLOCK_SECONDS,
  generated,
  harness,
  newBearerCredential,
  newPopCredential,
  type Generated,
  type Harness,
} from './helpers.js';

const NONCE = Uint8Array.from({ length: 16 }, (_, i) => i + 1);
const REQUEST_BODY = '{"model":"mock-model-1","messages":[{"role":"user","content":"hello"}]}';
const STREAM_REQUEST_BODY =
  '{"model":"mock-model-1","messages":[{"role":"user","content":"hello"}],"stream":true}';

function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

/**
 * One host key for the whole file, so a test can compute the tag the routes are expected to write,
 * and so two harnesses can stand for one gateway before and after a restart. The seed is a digest of
 * a readable phrase rather than a literal, because a tracked file in this repository holds no
 * key-shaped text and the secret scan reads it as history as well as a tree.
 */
const DEPLOYMENT_KEY = signingKeyFromSeed(hashRequest(utf8('ashaveri-gateway-test-host-key')));
const NAMESPACE = new ReceiptNamespace(DEPLOYMENT_KEY);

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

describe('receipt ids this gateway mints', () => {
  /**
   * A request signed as one named tenant. The file's own `send` signs for the single credential
   * every other cell presents, and the point of the two-tenant cells below is that two callers hold
   * the same route.
   */
  async function asTenant(
    h: Harness,
    credentialId: string,
    method: HTTPMethods,
    target: string,
    body: string | null,
  ) {
    return await h.app.inject({
      // A literal method pins inject's awaitable Response overload, as in `send`.
      method: method as 'GET',
      url: target,
      headers: {
        ...(body === null ? {} : { 'content-type': 'application/json' }),
        ...h.signFor(credentialId, method, target, body),
      },
      ...(body === null ? {} : { payload: body }),
    });
  }

  it('is a function of the credential id, and the same function across two loads of one file', () => {
    // Random ids from the factory, on purpose: a tag that only held for the ids this file happens to
    // hand-write would say nothing about the rule.
    const records = Array.from({ length: 5 }, () => newPopCredential({ scopes: ['read'] }).record);
    const text = serializeCredentialFile({ version: 1, credentials: records });
    const firstLoad = parseCredentialFile(text);
    const secondLoad = parseCredentialFile(text);
    // A namespace built a second time is what a restarted process holds: the same key in, the same
    // tags out, so the ids minted before the restart still carry a prefix this one computes.
    const rebuilt = new ReceiptNamespace(DEPLOYMENT_KEY);
    expect(firstLoad.credentials).toHaveLength(5);
    const tags: string[] = [];
    firstLoad.credentials.forEach((record, at) => {
      const tag = NAMESPACE.tagFor(record.id);
      expect(tag).toMatch(/^[0-9a-f]{16}$/u);
      expect(rebuilt.tagFor(secondLoad.credentials[at]!.id)).toBe(tag);
      tags.push(tag);
    });
    expect(new Set(tags).size).toBe(5);
  });

  it('namespaces the same credential id apart under two deployment keys', () => {
    // The tag is not computable from the id alone: without this deployment's seed, another gateway's
    // tag for the same name is nothing a caller can predict.
    const other = new ReceiptNamespace(
      signingKeyFromSeed(hashRequest(utf8('ashaveri-gateway-test-other-host-key'))),
    );
    const mine = NAMESPACE.tagFor('svc-shared');
    expect(other.tagFor('svc-shared')).not.toBe(mine);
    const id = NAMESPACE.mint(mine);
    expect(NAMESPACE.carries(id, mine)).toBe(true);
    expect(other.carries(id, other.tagFor('svc-shared'))).toBe(false);
  });

  it('derives the tag from the seed and not from the public half the manifest publishes', () => {
    // `deployment.key.publicKey` is in the manifest and in the COSE header of every receipt, so a tag
    // derived from it would be computable by anyone and every tenant's prefix would be public. These
    // two namespaces hold the same public key and different seeds, so only the secret can move the tag.
    const otherSeed = signingKeyFromSeed(hashRequest(utf8('ashaveri-gateway-test-secret-half')));
    const secretOnly = new ReceiptNamespace({ ...DEPLOYMENT_KEY, privateKey: otherSeed.privateKey });
    expect(secretOnly.tagFor('svc-shared')).not.toBe(NAMESPACE.tagFor('svc-shared'));
  });

  it('mints a fresh tagged id per completion, inside the route rule', () => {
    const tag = NAMESPACE.tagFor('svc-mint');
    const ids = [NAMESPACE.mint(tag), NAMESPACE.mint(tag)];
    for (const id of ids) {
      expect(id).toHaveLength(RECEIPT_ID_CHARS);
      expect(id.startsWith(tag)).toBe(true);
      expect(id).toMatch(/^[0-9a-f]+$/u);
      expect(RECEIPT_ID.test(id)).toBe(true);
    }
    expect(ids[0]).not.toBe(ids[1]);
  });

  it('addresses a completion by the minting credential, and leaves the upstream id in the body', async () => {
    const tenant = generated('tenant-a', ['complete', 'read']);
    const h = await harness({ credentials: [tenant], gateway: { key: DEPLOYMENT_KEY } });
    try {
      const res = await asTenant(h, 'tenant-a', 'POST', '/v1/chat/completions', REQUEST_BODY);
      const id = res.headers['x-ashaveri-receipt-id'] as string;
      expect(id.slice(0, RECEIPT_ID_TAG_HEX_CHARS)).toBe(NAMESPACE.tagFor('tenant-a'));
      // Two identifiers now: the body still carries whatever the backend called this completion, and
      // it is no longer the thing a receipt is fetched by.
      expect(id).not.toBe((res.json() as { id: string }).id);
      expect((await asTenant(h, 'tenant-a', 'GET', `/v1/receipts/${id}`, null)).statusCode).toBe(200);
      const second = await asTenant(h, 'tenant-a', 'POST', '/v1/chat/completions', REQUEST_BODY);
      expect(second.headers['x-ashaveri-receipt-id']).not.toBe(id);
    } finally {
      await h.app.close();
    }
  });

  it("answers another credential's receipt id as it answers one that never existed", async () => {
    const a = generated('tenant-a', ['complete', 'read']);
    const b = generated('tenant-b', ['complete', 'read']);
    const h = await harness({ credentials: [a, b], gateway: { key: DEPLOYMENT_KEY } });
    try {
      const res = await asTenant(h, 'tenant-a', 'POST', '/v1/chat/completions', REQUEST_BODY);
      const id = res.headers['x-ashaveri-receipt-id'] as string;
      const cross = await asTenant(h, 'tenant-b', 'GET', `/v1/receipts/${id}`, null);
      expect(cross.statusCode).toBe(404);
      // The same sentence, quoting the id it was asked for: a refusal that renamed the condition
      // would itself tell a prober that the bytes are there.
      expect(cross.json()).toEqual({ error: { message: `no receipt for id ${id}`, type: 'not_found' } });
      // An id carrying tenant-b's own tag that was never minted is indistinguishable from the one
      // above, which is what stops the route being walked.
      const absent = await asTenant(
        h,
        'tenant-b',
        'GET',
        `/v1/receipts/${NAMESPACE.mint(NAMESPACE.tagFor('tenant-b'))}`,
        null,
      );
      expect(absent.statusCode).toBe(cross.statusCode);
      // And the minting tenant still reads it, so the refusal above is the tag and not the store.
      expect((await asTenant(h, 'tenant-a', 'GET', `/v1/receipts/${id}`, null)).statusCode).toBe(200);
    } finally {
      await h.app.close();
    }
  });

  it("keeps a credential's history addressable when that credential's key rotates", async () => {
    // One store and one deployment key across both halves, so the only thing that moves is the
    // credential's own key pair. The id is tagged from the credential's *name*, which is why the
    // fetch below still lands.
    const store = openMemoryReceiptStore();
    const before = newPopCredential({ id: 'tenant-r', scopes: ['complete', 'read'], now: CLOCK_SECONDS });
    const first = await harness({
      credentials: [{ record: before.record, privateKey: before.privateKey }],
      gateway: { key: DEPLOYMENT_KEY, store },
    });
    try {
      const res = await asTenant(first, 'tenant-r', 'POST', '/v1/chat/completions', REQUEST_BODY);
      const id = res.headers['x-ashaveri-receipt-id'] as string;
      const after = newPopCredential({ id: 'tenant-r', scopes: ['complete', 'read'], now: CLOCK_SECONDS });
      expect(after.record.publicKey).not.toEqual(before.record.publicKey);
      const second = await harness({
        credentials: [{ record: after.record, privateKey: after.privateKey }],
        gateway: { key: DEPLOYMENT_KEY, store },
      });
      try {
        expect((await asTenant(second, 'tenant-r', 'GET', `/v1/receipts/${id}`, null)).statusCode).toBe(200);
      } finally {
        await second.app.close();
      }
    } finally {
      await first.app.close();
    }
  });
});

describe('durable receipts', () => {
  it('serves a receipt issued before the gateway restarted', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'ashaveri-gateway-'));
    try {
      // Both halves run on `DEPLOYMENT_KEY`, which is what a restart keeps in a real deployment: the
      // id in the header is tagged from that key's seed, so a second gateway holding a different one
      // would be a different deployment reading the first one's volume, not this process coming back.
      const first = await harness({
        credentials: [credential()],
        gateway: { key: DEPLOYMENT_KEY, store: await openFileReceiptStore({ dir }) },
      });
      const res = await send(first, 'POST', '/v1/chat/completions', REQUEST_BODY, NONCE);
      const receiptId = res.headers['x-ashaveri-receipt-id'] as string;
      await first.app.close();

      const second = await harness({
        credentials: [credential()],
        gateway: { key: DEPLOYMENT_KEY, store: await openFileReceiptStore({ dir }) },
      });
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
