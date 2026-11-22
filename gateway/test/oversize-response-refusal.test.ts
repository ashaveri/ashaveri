import { describe, expect, it } from 'vitest';
import type { HTTPMethods } from 'fastify';
import { decodeReceipt, hashRequest, toHex } from '@ashaveri/receipt';
import { mockDeployment } from '../src/deployment.js';
import { MAX_BUFFERED_BODY } from '../src/server.js';
import { upstreamBackend } from '../src/upstream.js';
import { generated, harness, type Harness } from './helpers.js';

/**
 * The bound on what this process will hold of one buffered completion, and the refusal it answers with.
 *
 * A buffered answer is collected whole before a byte of it reaches the client, because the digest the receipt
 * signs and the item it stamps are cut out of those bytes, so the bound is met while the answer is being read
 * and the refusal says what the gateway will not do rather than what the inference server did. That is the
 * difference this file exists to keep: the same event was reported as an upstream failure by an untyped error,
 * which a caller could not name and an operator read as a broken installation.
 *
 * The two boundary cells run at the shipped bound rather than at a smaller one, because the bound is shipped
 * and reached by no flag: the only way to show the refusal arrives at it and not before is to send the real
 * number of bytes, one either side.
 */

const MODEL = 'Qwen/Qwen2.5-0.5B-Instruct';
const CREDENTIAL = 'oversize-response';
const AT_THE_BOUND = MAX_BUFFERED_BODY;
const PAST_THE_BOUND = MAX_BUFFERED_BODY + 1;
const CHUNK_BYTES = 1024 * 1024;

interface Recorded {
  readonly raw: string;
}

/** A completion body of exactly `bytes`, whole and parseable, with a usage the route reads. */
function bufferedBody(bytes: number): string {
  const head =
    '{"usage":{"prompt_tokens":3,"completion_tokens":4,"total_tokens":7},"choices":[{"index":0,' +
    `"message":{"role":"assistant","content":"`;
  const tail = `"},"finish_reason":"stop"}],"model":"${MODEL}"}`;
  return head + 'a'.repeat(bytes - head.length - tail.length) + tail;
}

/** The same answer arriving in whole megabytes, which is how an upstream really sends one. */
function jsonStream(text: string): Response {
  const encoder = new TextEncoder();
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      for (let at = 0; at < text.length; at += CHUNK_BYTES) {
        controller.enqueue(encoder.encode(text.slice(at, at + CHUNK_BYTES)));
      }
      controller.close();
    },
  });
  return new Response(stream, { status: 200, headers: { 'content-type': 'application/json' } });
}

function servedBy(make: (request: Recorded) => Response | Promise<Response>): {
  readonly fetchImpl: typeof fetch;
  readonly requests: Recorded[];
} {
  const requests: Recorded[] = [];
  return {
    requests,
    fetchImpl: (async (_input: unknown, init?: RequestInit) => {
      const raw = init?.body;
      const record: Recorded = { raw: Buffer.isBuffer(raw) ? raw.toString('utf8') : String(raw ?? '') };
      requests.push(record);
      return make(record);
    }) as typeof fetch,
  };
}

async function gatewayWith(upstream: { readonly fetchImpl: typeof fetch }): Promise<Harness> {
  return await harness({
    credentials: [generated(CREDENTIAL, ['complete', 'read'])],
    gateway: {
      deployment: mockDeployment({ model: MODEL }),
      backend: upstreamBackend({ baseUrl: 'http://inference.test/v1', fetchImpl: upstream.fetchImpl }),
    },
  });
}

const REQUEST = `{"model":"${MODEL}","messages":[{"role":"user","content":"write it all"}]}`;

async function send(h: Harness): Promise<{
  statusCode: number;
  headers: Record<string, string | string[] | number | undefined>;
  payload: string;
  json: () => { error?: { message?: string; type?: string; code?: string } };
}> {
  const target = '/v1/chat/completions';
  const method: HTTPMethods = 'POST';
  const answer = await h.app.inject({
    method: method as 'POST',
    url: target,
    headers: { 'content-type': 'application/json', ...h.signFor(CREDENTIAL, 'POST', target, REQUEST) },
    payload: REQUEST,
  });
  return {
    statusCode: answer.statusCode,
    headers: answer.headers,
    payload: answer.payload,
    json: () => answer.json() as { error?: { message?: string; type?: string; code?: string } },
  };
}

describe('the bound on a collected completion', () => {
  it('holds an answer of exactly the bound, signs it, and digests the whole of it', async () => {
    const text = bufferedBody(AT_THE_BOUND);
    expect(text.length, 'the accepted arm is the bound, byte for byte').toBe(AT_THE_BOUND);
    const upstream = servedBy(() => jsonStream(text));
    const h = await gatewayWith(upstream);
    const answer = await send(h);
    expect(answer.statusCode, 'an answer at the bound is held, not refused').toBe(200);
    expect(answer.payload.length, 'and the caller is given the whole of it').toBe(AT_THE_BOUND);
    const id = answer.headers['x-ashaveri-receipt-id'];
    expect(typeof id, 'a completion this process collected is a completion it receipts').toBe('string');
    const target = `/v1/receipts/${String(id)}`;
    const fetched = await h.app.inject({
      method: 'GET',
      url: target,
      headers: h.signFor(CREDENTIAL, 'GET', target, null),
    });
    expect(fetched.statusCode).toBe(200);
    const payload = decodeReceipt(new Uint8Array(fetched.rawPayload)).payload;
    expect(toHex(payload.res), 'the receipt digests every byte that was sent').toBe(
      toHex(hashRequest(new TextEncoder().encode(text))),
    );
    expect(payload.tok, 'and the figures the body carried are the figures it states').toEqual({ p: 3, c: 4 });
    await h.app.close();
  });

  it('refuses the byte past the bound by name, and issues nothing for it', async () => {
    const text = bufferedBody(PAST_THE_BOUND);
    expect(text.length, 'the refused arm is one byte past the bound').toBe(PAST_THE_BOUND);
    const upstream = servedBy(() => jsonStream(text));
    const h = await gatewayWith(upstream);
    const answer = await send(h);
    expect(answer.statusCode, 'an answer past the bound this process will hold is refused').toBe(413);
    expect(answer.json().error?.type, 'and it is still an answer the upstream gave').toBe('upstream_error');
    expect(answer.json().error?.code, 'named by a code a caller can branch on').toBe('RESPONSE_TOO_LARGE');
    expect(
      answer.json().error?.message,
      'and by the number that moved, so the refusal is not read as a fault of the installation',
    ).toContain(String(MAX_BUFFERED_BODY));
    expect(
      answer.json().error?.message,
      'the refusal says to stream it, which is the shape no bound of this kind reaches',
    ).toContain('streamed');
    expect(answer.headers['x-ashaveri-receipt-id'], 'nothing was signed, so nothing is addressable').toBeUndefined();
    expect(answer.payload, 'and none of the upstream bytes reached the caller').not.toContain('aaa');
    expect(
      h.log.entries().filter((entry) => entry.p === '/v1/chat/completions'),
      'the access line carries the status this refusal answered with and no admission code',
    ).toMatchObject([{ cred: CREDENTIAL, st: 413, deny: null }]);
    await h.app.close();
  });

  it('hands back an upstream that fails while its answer is being read as the failure it is', async () => {
    // The named refusal is the one this process decides. A stream that dies mid-body is the upstream's
    // doing and keeps the untyped answer it has always had, so a handler written to answer every error
    // thrown while collecting would still leave this cell green only by hiding the first one.
    const upstream = servedBy(
      () =>
        new Response(
          new ReadableStream<Uint8Array>({
            start(controller) {
              controller.enqueue(new TextEncoder().encode('{"usage":'));
              controller.error(new Error('the inference server closed the connection mid-answer'));
            },
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        ),
    );
    const h = await gatewayWith(upstream);
    const answer = await send(h);
    expect(answer.statusCode, 'an upstream that dies mid-body is still an upstream failure').toBe(502);
    expect(answer.json().error?.type).toBe('upstream_error');
    expect(answer.json().error?.code, 'and carries no refusal code, because no bound was reached').toBeUndefined();
    expect(answer.json().error?.message, 'the sentence says what failed').toContain(
      'the inference server closed the connection mid-answer',
    );
    await h.app.close();
  });
});
