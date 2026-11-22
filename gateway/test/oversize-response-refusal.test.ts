import { describe, expect, it } from 'vitest';
import type { HTTPMethods } from 'fastify';
import { decodeReceipt, hashRequest, toHex } from '@ashaveri/receipt';
import { AccessError } from '../src/access.js';
import { mockDeployment } from '../src/deployment.js';
import { MAX_BUFFERED_BODY } from '../src/server.js';
import { upstreamBackend } from '../src/upstream.js';
import { generated, harness, type Harness } from './helpers.js';

/**
 * The bound on what this process will hold of one buffered answer, and the refusal it answers with.
 *
 * A buffered answer is collected whole before a byte of it reaches the client, because the digest the receipt
 * signs and the item it stamps are cut out of those bytes, so the bound is met while the answer is being read
 * and the refusal says what the gateway will not do rather than what the inference server did. That is the
 * difference this file exists to keep: the same event was reported as an upstream failure by an untyped error,
 * which a caller could not name and an operator read as a broken installation.
 *
 * Two answers cross this bound, and the cells below keep them apart. A completion is collected because it is
 * about to be attested, and the one change of shape that gets a caller past the bound is to ask for it
 * streamed. An upstream's own failure is collected because this gateway hands its bytes back and has no stream
 * arm for an answer it will not sign, so the advice a completion refusal carries would send a caller back with
 * the same request and the same failure, and the sentence says something else instead.
 *
 * The named refusal is also matched by its code rather than by its class at the route. A class here is the
 * vocabulary every credential refusal shares, so a handler written against the class would hand a caller the
 * status of a check that never ran, and every 5xx on that union is a credential-file refusal no request is
 * answered with.
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
/** The bound as one sentence states it twice: the byte count, and the mebibytes the prose names. */
const PAST_BOUND_TEXT = bufferedBody(PAST_THE_BOUND);

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
    const text = PAST_BOUND_TEXT;
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
    // The bound is stated twice in the one sentence, once as bytes and once in mebibytes, and both figures
    // are read from the constant rather than from a number copied into the prose: `docs/configured-values.md`
    // states the same figure in words, and the cell there holds that sentence to this declaration.
    expect(
      answer.json().error?.message,
      'the mebibyte spelling the refusal carries is the one the constant holds',
    ).toContain(`shipped at ${String(MAX_BUFFERED_BODY / (1024 * 1024))} MiB`);
    expect(
      answer.json().error?.message,
      'the refusal says to stream it, which is the shape no bound of this kind reaches',
    ).toContain('or asks for it streamed');
    expect(
      answer.json().error?.message,
      'and this answer was a completion, so it does not say the bytes were the upstream failing',
    ).not.toContain('this is not a completion');
    expect(answer.headers['x-ashaveri-receipt-id'], 'nothing was signed, so nothing is addressable').toBeUndefined();
    expect(answer.payload, 'and none of the upstream bytes reached the caller').not.toContain('aaa');
    expect(
      h.log.entries().filter((entry) => entry.p === '/v1/chat/completions'),
      'the access line carries the status this refusal answered with and no admission code',
    ).toMatchObject([{ cred: CREDENTIAL, st: 413, deny: null }]);
    await h.app.close();
  });

  it('refuses a past-bound failure without the advice that reaches nothing there', async () => {
    // `collect` reads both shapes of answer, and an upstream's failure is read whole whatever the request
    // asked for: there is no stream arm for bytes this gateway will not sign. Telling this caller to ask for
    // the completion streamed would send it back with the same request and the same refusal, so the sentence
    // says what the bytes were, that nothing was signed because nothing here was a completion, and which of
    // the two numbers moves.
    const upstream = servedBy(
      () =>
        new Response(new TextEncoder().encode(PAST_BOUND_TEXT), {
          status: 500,
          headers: { 'content-type': 'application/json' },
        }),
    );
    const h = await gatewayWith(upstream);
    const answer = await send(h);
    expect(answer.statusCode, 'the bound is the bound on either side of the exchange').toBe(413);
    expect(answer.json().error?.code, 'and the code a caller branches on is the same one').toBe('RESPONSE_TOO_LARGE');
    expect(
      answer.json().error?.message,
      'the sentence names the bytes it reached as the upstream failing',
    ).toContain("the inference server's own failure");
    expect(answer.json().error?.message, 'and says this answer was no completion').toContain(
      'this is not a completion',
    );
    expect(
      answer.json().error?.message,
      'while the advice it withholds is the advice that cannot work here',
    ).not.toContain('or asks for it streamed');
    expect(
      answer.json().error?.message,
      'and the streaming word it does carry states that reaching for it changes nothing',
    ).toContain('Asking for the completion streamed reaches nothing here');
    await h.app.close();
  });

  it('answers an AccessError that is not this bound with the upstream failure it is', async () => {
    // A credential refusal can stand in the same class as this one, and its status belongs to a check that
    // never ran on this request. Matching the class rather than the code would answer a completion with a
    // 500 carrying `BAD_CREDENTIAL_FILE`, which the two documents state no request is refused with, and would
    // read to an operator as a broken credential file behind a request that named none.
    const upstream = servedBy(
      () =>
        new Response(
          new ReadableStream<Uint8Array>({
            start(controller) {
              controller.enqueue(new TextEncoder().encode('{"usage":'));
              controller.error(
                new AccessError('BAD_CREDENTIAL_FILE', {
                  detail: 'the file a collector reached asked to open is gone',
                }),
              );
            },
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        ),
    );
    const h = await gatewayWith(upstream);
    const answer = await send(h);
    expect(answer.statusCode, 'no status from another check reaches this exchange').toBe(502);
    expect(answer.json().error?.type).toBe('upstream_error');
    expect(answer.json().error?.code, 'and no code that was not decided here is handed to the caller').toBeUndefined();
    expect(answer.json().error?.message, 'the sentence says what failed, in the words it arrived in').toContain(
      'the file a collector reached asked to open is gone',
    );
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
