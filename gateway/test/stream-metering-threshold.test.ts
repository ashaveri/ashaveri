import { describe, expect, it } from 'vitest';
import type { HTTPMethods } from 'fastify';
import { decodeReceipt, hashRequest, toHex } from '@ashaveri/receipt';
import { mockDeployment } from '../src/deployment.js';
import { upstreamBackend, STREAM_USAGE_INJECTION_MAX_BYTES } from '../src/upstream.js';
import { generated, harness, type Harness } from './helpers.js';

/**
 * The two arms of metering on a streamed request, and the bound that decides between them.
 *
 * Asking an inference server for its token figures costs a copy of the caller's own request: the injection
 * parses the body and writes it out again with one member added, and that copy is held while the response
 * streams. Above the bound the copy is declined, which is a decision about what a receipt can say as much
 * as about what it costs, so both arms are pinned here from either side of the number, and what the
 * declined arm gives up is pinned too.
 *
 * What it gives up is a measurement, and the receipt says so in the bytes it signs: the pair of figures goes
 * out as two absences where nothing was reported and as two counts where the upstream reported two counts,
 * which is the shape `packages/receipt` widened `v: 1` to admit. The pins below read the signed document
 * rather than `x-ashaveri-metering`, because a header stays with the response while a receipt is read long
 * after it, and a decoded pair of nulls is no proof that nulls are what went out.
 *
 * The size the existing witness in `gateway/test/upstream.test.ts` runs at is about two hundred bytes, far
 * under the bound, so that cell and these are the same arm; the cells below pin the boundary itself, the
 * byte for byte forwarding above it, and the two spellings the declined and the reported arms sign.
 */

const MODEL = 'Qwen/Qwen2.5-0.5B-Instruct';
const CREDENTIAL = 'metering';
/** Padded to sit one byte either side of the bound, which is where a `<=` and a `<` differ. */
const UNDER = STREAM_USAGE_INJECTION_MAX_BYTES;
const OVER = STREAM_USAGE_INJECTION_MAX_BYTES + 1;

interface Recorded {
  /** The exact bytes the gateway put on the wire to the inference server. */
  readonly raw: string;
  readonly parsed: Record<string, unknown>;
}

interface FakeUpstream {
  readonly fetchImpl: typeof fetch;
  readonly requests: Recorded[];
}

function event(chunk: Record<string, unknown>): string {
  return `data: ${JSON.stringify(chunk)}\n\n`;
}

const DONE = 'data: [DONE]\n\n';

/** One streamed completion, with or without the usage event a server only emits when it was asked. */
function streamEvents(withUsage: boolean): string[] {
  return streamEventsReporting(withUsage ? { prompt_tokens: 91, completion_tokens: 7 } : null);
}

/** The same completion carrying the figures an upstream reported, which may be two of nothing. */
function streamEventsReporting(usage: { prompt_tokens: number; completion_tokens: number } | null): string[] {
  const events = [
    event({
      id: 'chatcmpl-1',
      object: 'chat.completion.chunk',
      created: 1_700_000_000,
      model: MODEL,
      choices: [{ index: 0, delta: { content: 'Hello' }, finish_reason: null }],
    }),
    event({
      id: 'chatcmpl-1',
      object: 'chat.completion.chunk',
      created: 1_700_000_000,
      model: MODEL,
      choices: [{ index: 0, delta: {}, finish_reason: 'stop' }],
    }),
  ];
  if (usage !== null) {
    events.push(
      event({
        id: 'chatcmpl-1',
        object: 'chat.completion.chunk',
        created: 1_700_000_000,
        model: MODEL,
        choices: [],
        usage: { ...usage, total_tokens: usage.prompt_tokens + usage.completion_tokens },
      }),
    );
  }
  events.push(DONE);
  return events;
}

function streamResponse(events: string[]): Response {
  const encoder = new TextEncoder();
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      for (const item of events) controller.enqueue(encoder.encode(item));
      controller.close();
    },
  });
  return new Response(stream, { status: 200, headers: { 'content-type': 'text/event-stream' } });
}

function jsonResponse(body: string): Response {
  return new Response(body, { status: 200, headers: { 'content-type': 'application/json' } });
}

function fakeUpstream(make: () => Response): FakeUpstream {
  const requests: Recorded[] = [];
  return {
    requests,
    fetchImpl: (async (_input: unknown, init?: RequestInit) => {
      const raw = init?.body;
      const text = Buffer.isBuffer(raw) ? raw.toString('utf8') : String(raw ?? '');
      requests.push({ raw: text, parsed: JSON.parse(text) as Record<string, unknown> });
      return make();
    }) as typeof fetch,
  };
}

async function servedBy(upstream: FakeUpstream): Promise<Harness> {
  return await harness({
    credentials: [generated(CREDENTIAL, ['complete', 'read'])],
    gateway: {
      deployment: mockDeployment({ model: MODEL }),
      backend: upstreamBackend({ baseUrl: 'http://inference.test/v1', fetchImpl: upstream.fetchImpl }),
    },
  });
}

/**
 * A request of exactly `bytes` wire size, on the arm named, carrying a member the gateway reads nothing of.
 *
 * The padding is one inline file's worth of characters in a text part, which is the shape a large request
 * actually arrives in, and the claim beside it is the one `upstream.test.ts` pins: a member nobody parses
 * has to survive whatever this gateway does to the body.
 */
function bodyAt(bytes: number, stream: boolean): string {
  const head = `{"model":"${MODEL}","messages":[{"role":"user","content":[{"type":"text","text":"`;
  const tail =
    `"},{"type":"file","file":{"file_data":"${'A'.repeat(64)}"}}]}],` +
    `"ashaveri":{"file":{"sha256":"${'ab'.repeat(32)}","bytes":3,"media_type":"audio/wav"}},` +
    `"stream":${String(stream)}}`;
  const filler = 'x'.repeat(Math.max(0, bytes - head.length - tail.length));
  return head + filler + tail;
}

/** The streamed arm of the body above, which is the only arm the bound reaches. */
function streamedBodyAt(bytes: number): string {
  return bodyAt(bytes, true);
}

async function send(h: Harness, body: string): Promise<{
  statusCode: number;
  headers: Record<string, string | string[] | number | undefined>;
  payload: string;
  raw: Buffer;
}> {
  const target = '/v1/chat/completions';
  const method: HTTPMethods = 'POST';
  const answer = await h.app.inject({
    method: method as 'POST',
    url: target,
    headers: { 'content-type': 'application/json', ...h.signFor(CREDENTIAL, 'POST', target, body) },
    payload: body,
  });
  return {
    statusCode: answer.statusCode,
    headers: answer.headers,
    payload: answer.payload,
    raw: answer.rawPayload,
  };
}

/** The bytes a verifier is handed for this id: the document this issuance signed, as the store keeps it. */
async function signedReceipt(h: Harness, id: string): Promise<Uint8Array> {
  const target = `/v1/receipts/${id}`;
  const method: HTTPMethods = 'GET';
  const answer = await h.app.inject({
    method: method as 'GET',
    url: target,
    headers: h.signFor(CREDENTIAL, 'GET', target, null),
  });
  expect(answer.statusCode).toBe(200);
  return new Uint8Array(answer.rawPayload);
}

/** `toHex` of the signed document, for the pins that have to be about bytes rather than about a decode. */
async function signedHex(h: Harness, id: string): Promise<string> {
  return toHex(await signedReceipt(h, id));
}

async function receiptOf(h: Harness, id: string) {
  return decodeReceipt(await signedReceipt(h, id)).payload;
}

describe('the metering bound on a streamed request', () => {
  it('asks below the bound and declines above it, at the byte where the two differ', async () => {
    expect(streamedBodyAt(UNDER).length, 'the under arm is one byte inside the bound').toBe(UNDER);
    expect(streamedBodyAt(OVER).length, 'the over arm is one byte past it').toBe(OVER);

    const under = fakeUpstream(() => streamResponse(streamEvents(true)));
    const hUnder = await servedBy(under);
    const asked = await send(hUnder, streamedBodyAt(UNDER));
    expect(asked.statusCode).toBe(200);
    expect(under.requests[0]?.parsed['stream_options'], 'a body worth copying is copied').toMatchObject({
      include_usage: true,
    });
    expect(asked.headers['x-ashaveri-metering'], 'and nothing is declared about metering').toBeUndefined();
    await hUnder.app.close();

    const over = fakeUpstream(() => streamResponse(streamEvents(false)));
    const hOver = await servedBy(over);
    const declined = await send(hOver, streamedBodyAt(OVER));
    expect(declined.statusCode).toBe(200);
    expect(
      over.requests[0]?.parsed['stream_options'],
      'a body past the bound is not re-written for a count',
    ).toBeUndefined();
    expect(declined.headers['x-ashaveri-metering'], 'and the exception says so').toBe('declined');
    await hOver.app.close();
  });

  it('forwards the bytes that arrived, byte for byte, above the bound', async () => {
    const sent = streamedBodyAt(OVER);
    const upstream = fakeUpstream(() => streamResponse(streamEvents(false)));
    const h = await servedBy(upstream);
    const answer = await send(h, sent);
    expect(answer.statusCode).toBe(200);
    // The test of a copy is not that it parses the same: a re-serialisation does that too. It is that the
    // bytes on the wire are the bytes the caller wrote, member order, spacing and all.
    expect(upstream.requests[0]?.raw, 'no serialisation stands between the reader and the server').toBe(sent);
    const payload = await receiptOf(h, String(answer.headers['x-ashaveri-receipt-id']));
    expect(toHex(payload.req), 'and the receipt digests the bytes as they arrived').toBe(
      toHex(hashRequest(new TextEncoder().encode(sent))),
    );
    await h.app.close();
  });

  it('writes a different body below the bound, which is what makes the two arms tellable apart', async () => {
    const sent = streamedBodyAt(UNDER);
    const upstream = fakeUpstream(() => streamResponse(streamEvents(true)));
    const h = await servedBy(upstream);
    const answer = await send(h, sent);
    expect(answer.statusCode).toBe(200);
    expect(upstream.requests[0]?.raw, 'the asked arm re-wrote the body, and that is visible').not.toBe(sent);
    expect(upstream.requests[0]?.parsed, 'the member nobody reads still travelled through the rewrite').toMatchObject({
      stream: true,
      stream_options: { include_usage: true },
      ashaveri: { file: { sha256: 'ab'.repeat(32), bytes: 3, media_type: 'audio/wav' } },
    });
    await h.app.close();
  });

  it('signs two absences where it asked for nothing, as absences and not as measurements', async () => {
    const sent = streamedBodyAt(OVER);
    const upstream = fakeUpstream(() => streamResponse(streamEvents(false)));
    const h = await servedBy(upstream);
    const answer = await send(h, sent);
    const id = String(answer.headers['x-ashaveri-receipt-id']);
    // The pin is on the bytes first, because a decoded pair of nulls is also what a document that rendered
    // its zeros through one more round-trip hands back, and `x-ashaveri-metering` travels with no receipt.
    // `a2` is a map of two, `c` sorts before `p` by the bytewise order of their one-byte text keys, `f6` is
    // null and `00` the integer zero: the two runs `packages/receipt` proves distinct for this writer, read
    // off the document this gateway signed for these bytes.
    const signed = await signedHex(h, id);
    expect(signed, 'the signed pair is two absences').toContain('a26163f66170f6');
    expect(signed, 'and not two measurements of nothing').not.toContain('a2616300617000');
    const payload = await receiptOf(h, id);
    expect(payload.tok, 'the figures a declined copy left unasked are an absence').toEqual({ p: null, c: null });
    expect(
      String(answer.headers['x-ashaveri-metering']),
      'the header still names what this gateway did, and is no longer the only thing that says so',
    ).toBe('declined');
    // What this cell used to close with, a `data: [DONE]` test on the forwarded stream, was framing rather
    // than metering: no value of the bound and no spelling of `tok` could have moved it. The framing is
    // pinned where it belongs, by the `res` digest of the cell above and by `gateway/test/upstream.test.ts`.
    await h.app.close();
  });

  it('signs two zeros where the upstream reported two zeros, because that is a reading', async () => {
    const sent = streamedBodyAt(UNDER);
    const upstream = fakeUpstream(() =>
      streamResponse(streamEventsReporting({ prompt_tokens: 0, completion_tokens: 0 })),
    );
    const h = await servedBy(upstream);
    const answer = await send(h, sent);
    const id = String(answer.headers['x-ashaveri-receipt-id']);
    // The other half of the widening, in the same bytes: a reported zero is not the shape an absence takes,
    // so a producer that reached for the nulls by mistake would be caught here rather than in a decode that
    // cannot tell the two renderings apart.
    const signed = await signedHex(h, id);
    expect(signed, 'the signed pair is two measurements of nothing').toContain('a2616300617000');
    expect(signed, 'and not two absences').not.toContain('a26163f66170f6');
    expect((await receiptOf(h, id)).tok, 'a stack that served nothing says nothing').toEqual({ p: 0, c: 0 });
    expect(
      answer.headers['x-ashaveri-metering'],
      'and this gateway asked, so it has no exception to name',
    ).toBeUndefined();
    await h.app.close();
  });

  it('reads figures that arrive unasked, and still says the gateway did not ask for them', async () => {
    const sent = streamedBodyAt(OVER);
    const upstream = fakeUpstream(() => streamResponse(streamEvents(true)));
    const h = await servedBy(upstream);
    const answer = await send(h, sent);
    const payload = await receiptOf(h, String(answer.headers['x-ashaveri-receipt-id']));
    expect(payload.tok, 'a server that reports anyway is still read').toEqual({ p: 91, c: 7 });
    expect(answer.headers['x-ashaveri-metering'], 'and the header keeps saying what this gateway did').toBe(
      'declined',
    );
    await h.app.close();
  });

  it('re-writes no buffered request at either side of the bound, and states what its body reported', async () => {
    // The bound is consulted for a stream and for nothing else, so on this arm no reading of it changes an
    // observable: a buffered body is forwarded as it arrived because the injection is gated on the request's
    // own `stream` member, and its figures ride inside the answer. What can fail here is that gate, and it is
    // pinned at both sizes because an injection that reached a buffered body only when it was worth copying
    // would survive a cell that sent one size.
    //
    // The header this cell used to assert is gone rather than moved. It is written in the streamed branch of
    // the route and nowhere else, so on a buffered answer no value of `meteringDeclined` could have put it
    // on the response and its absence proved nothing. The figures below are the buffered arm's own statement.
    for (const [name, size] of [
      ['inside', UNDER],
      ['past', OVER],
    ] as const) {
      const sent = bodyAt(size, false);
      const upstream = fakeUpstream(() =>
        jsonResponse(
        JSON.stringify({ model: MODEL, usage: { prompt_tokens: 3, completion_tokens: 4, total_tokens: 7 } }),
      ),
      );
      const h = await servedBy(upstream);
      const answer = await send(h, sent);
      expect(answer.statusCode, `a buffered request ${name} the bound is served`).toBe(200);
      expect(upstream.requests[0]?.raw, `the body ${name} the bound reaches the server as the caller wrote it`).toBe(
        sent,
      );
      const payload = await receiptOf(h, String(answer.headers['x-ashaveri-receipt-id']));
      expect(
        payload.tok,
        `and its figures are the reading its body carried, ${name} the bound`,
      ).toEqual({ p: 3, c: 4 });
      await h.app.close();
    }
  });

  it('signs the absence of figures a buffered body never carried', async () => {
    // The same producer decision on the arm that pays no copy for it: a 200 whose JSON held no usage member
    // reported nothing, so its receipt states absence rather than two zeros that body never justified. The
    // size is the one under the bound, because this is a statement about the report and not about the ask.
    const sent = bodyAt(UNDER, false);
    const upstream = fakeUpstream(() => jsonResponse(JSON.stringify({ model: MODEL, choices: [] })));
    const h = await servedBy(upstream);
    const answer = await send(h, sent);
    const id = String(answer.headers['x-ashaveri-receipt-id']);
    const signed = await signedHex(h, id);
    expect(signed, 'the pair went out as two absences').toContain('a26163f66170f6');
    expect(signed, 'and not as two measurements of nothing').not.toContain('a2616300617000');
    expect((await receiptOf(h, id)).tok, 'no figures in the answer, no figures claimed').toEqual({ p: null, c: null });
    await h.app.close();
  });
});
