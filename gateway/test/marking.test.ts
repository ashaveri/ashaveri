import { afterEach, describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  MARKING_MEMBER_NAME,
  decodeReceipt,
  emptyRegion,
  extractMarkedRegion,
  hashRequest,
  sha256Hex,
  toHex,
  type MarkingScheme,
  type ReceiptPayloadV2,
} from '@ashaveri/receipt';
import { MarkedStreamTail, type BackendResponse, type CompletionBackend, type CompletionUsage } from '../src/index.js';
import { MARKING_CHUNK_ID } from '../src/marking.js';
import { sha256 } from '../src/digest.js';
import { CLOCK_SECONDS, generated, harness, type Generated, type Harness } from './helpers.js';

/**
 * The mark, seen from the side that writes it. Each cell below asks the same question of a response
 * this gateway built: are the bytes a client was handed the bytes `res` digests, and is the span
 * `mk.d` digests the span a reader of the published rule finds in them? The second half is the one
 * worth the test — a writer and a reader that each re-derived the region their own way would agree
 * with themselves and disagree with each other, and only a run through a real response catches that.
 */

const NONCE = Uint8Array.from({ length: 16 }, (_, i) => i + 1);
const REQUEST_BODY = '{"model":"mock-model-1","messages":[{"role":"user","content":"hello"}]}';
const STREAM_REQUEST_BODY = '{"model":"mock-model-1","messages":[{"role":"user","content":"hi"}],"stream":true}';
const MODEL = 'mock-model-1';
const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url));

function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function text(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

/** One of a stream's frames, in the spelling this gateway forwards. */
function frame(payload: Record<string, unknown>): string {
  return `data: ${JSON.stringify(payload)}\n\n`;
}

function contentChunk(content: string, finishReason: string | null): Record<string, unknown> {
  return {
    id: 'chatcmpl-upstream-1',
    object: 'chat.completion.chunk',
    created: CLOCK_SECONDS,
    model: MODEL,
    choices: [{ index: 0, delta: { content }, finish_reason: finishReason }],
  };
}

const SENTINEL = 'data: [DONE]\n\n';

const UPSTREAM_BUFFERED = JSON.stringify({
  id: 'chatcmpl-upstream-1',
  object: 'chat.completion',
  created: CLOCK_SECONDS,
  model: MODEL,
  choices: [
    {
      index: 0,
      message: { role: 'assistant', content: 'Mock reply: café ☕ served.' },
      finish_reason: 'stop',
    },
  ],
  usage: { prompt_tokens: 9, completion_tokens: 6, total_tokens: 15 },
});

const UPSTREAM_STREAM =
  frame(contentChunk('Mock reply: café ☕ served.', null)) + frame(contentChunk('', 'stop')) + SENTINEL;

/**
 * A backend whose bytes are given exactly, cut into the pieces a transport chooses rather than the
 * pieces a test would like. A completion id and a time never reach this gateway's decisions, so a
 * stub that wrote its own would hide the one thing worth checking: that the mark lands inside bytes
 * the upstream owns without editing them.
 */
function bodyBackend(body: string, contentType: string, splits: readonly number[] = []): CompletionBackend {
  const bytes = utf8(body);
  const pieces: Uint8Array[] = [];
  let cut = 0;
  for (const at of [...splits].sort((a, b) => a - b)) {
    if (at <= cut || at >= bytes.length) continue;
    pieces.push(bytes.subarray(cut, at));
    cut = at;
  }
  pieces.push(bytes.subarray(cut));
  const usage: Promise<CompletionUsage> = Promise.resolve({ model: MODEL, promptTokens: 9, completionTokens: 6 });
  return {
    async respond(): Promise<BackendResponse> {
      return {
        status: 200,
        contentType,
        chunks: (async function* (): AsyncGenerator<Uint8Array> {
          for (const piece of pieces) {
            yield piece;
          }
        })(),
        usage,
      };
    },
  };
}

function streamBackend(splits: readonly number[] = []): CompletionBackend {
  return bodyBackend(UPSTREAM_STREAM, 'text/event-stream', splits);
}

const credential: Generated = generated('marking', ['complete', 'read']);

let session: Harness | undefined;

async function open(gateway: { backend?: CompletionBackend; marking?: MarkingScheme } = {}): Promise<Harness> {
  await close();
  session = await harness({ credentials: [credential], gateway });
  return session;
}

async function close(): Promise<void> {
  if (session !== undefined) {
    const closing = session;
    session = undefined;
    await closing.app.close();
  }
}

afterEach(close);

async function send(h: Harness, target: string, body: string) {
  return await h.app.inject({
    // `inject` resolves its overload from a literal method, and the chainable form it picks for a
    // variable one has no `rawPayload` on; one literal pins the full response, as in the other suites.
    method: 'POST' as 'GET',
    url: target,
    headers: { 'content-type': 'application/json', ...h.signFor('marking', 'POST', target, body, { nonce: NONCE }) },
    payload: body,
  });
}

/** The receipt this response's id points at, decoded, narrowed to the version it always is. */
async function receiptFor(h: Harness, id: string): Promise<ReceiptPayloadV2> {
  const url = `/v1/receipts/${id}`;
  const res = await h.app.inject({ method: 'GET', url, headers: h.signFor('marking', 'GET', url, null) });
  expect(res.statusCode).toBe(200);
  const payload = decodeReceipt(new Uint8Array(res.rawPayload)).payload;
  if (payload.v !== 2) throw new Error(`expected a v2 payload, got version ${String(payload.v)}`);
  return payload;
}

function refusal(error: unknown): string {
  return String((error as { message?: string }).message ?? '');
}

describe('the marking flag', () => {
  it('ships off, and an off run adds no byte to a completion', async () => {
    const h = await open({ backend: bodyBackend(UPSTREAM_BUFFERED, 'application/json') });
    const res = await send(h, '/v1/chat/completions', REQUEST_BODY);
    expect(res.statusCode).toBe(200);
    // Byte for byte the upstream's own answer: with the flag off, nothing rides into a customer's
    // response unasked.
    expect(res.rawPayload.toString('utf8')).toBe(UPSTREAM_BUFFERED);
    const payload = await receiptFor(h, res.headers['x-ashaveri-receipt-id'] as string);
    expect(payload.mk.sch).toBe('none');
    expect(toHex(payload.mk.d)).toBe(sha256Hex(emptyRegion()));
    expect(toHex(payload.res)).toBe(sha256Hex(utf8(UPSTREAM_BUFFERED)));
    // And the declared absence is checkable against those bytes, which is what makes it a claim
    // rather than a hole: an unmarked response is what a `none` digest of the empty region verifies.
    expect(extractMarkedRegion('none', new Uint8Array(res.rawPayload))).toEqual(emptyRegion());
  });

  it('issues a v2 receipt whichever way the flag is set', async () => {
    for (const marking of [undefined, 'none', 'provenance-v1'] as const) {
      const h = await open({ backend: bodyBackend(UPSTREAM_BUFFERED, 'application/json'), marking });
      const res = await send(h, '/v1/chat/completions', REQUEST_BODY);
      const payload = await receiptFor(h, res.headers['x-ashaveri-receipt-id'] as string);
      expect([marking, payload.v, payload.mk.sch]).toEqual([
        marking,
        2,
        marking === 'provenance-v1' ? 'provenance-v1' : 'none',
      ]);
    }
  });

  it('refuses to start on a label the registry does not name', () => {
    // `provenance-v2` is the shape of a label a future registry row would add; the empty string is
    // what `--marking=` writes; `NONE` is the one a reader would not match. None of them is
    // startable, because a mark no extractor can read would be attested by a receipt and missed by
    // every detector.
    for (const given of ['provenance-v2', '', 'NONE']) {
      const out = runCli(['--mock', '--marking', given]);
      expect([given, out.status]).toEqual([given, 2]);
      expect(out.stderr).toContain('--marking must be one of none, provenance-v1');
    }
  });

  it('reports an off run on the banner, in the words the flag is documented in', () => {
    expect(runStoppedCli(['--mock']).find((line) => line.includes('marking:'))).toBe(
      '  marking: none, so no byte of a customer response is added here and every receipt says so',
    );
  });

  it('reports an on run, including whose duty the marking answers to', () => {
    const on = runStoppedCli(['--mock', '--marking', 'provenance-v1']).find((line) => line.includes('marking:'));
    expect(on).toContain('marking: provenance-v1');
    expect(on).toContain("any duty a marking answers to stays this deployment's own");
  });
});

describe('a marked buffered completion', () => {
  it('carries the member at the top level, and the receipt digests exactly its bytes', async () => {
    const h = await open({ backend: bodyBackend(UPSTREAM_BUFFERED, 'application/json'), marking: 'provenance-v1' });
    const res = await send(h, '/v1/chat/completions', REQUEST_BODY);
    expect(res.statusCode).toBe(200);
    const body = new Uint8Array(res.rawPayload);
    const payload = await receiptFor(h, res.headers['x-ashaveri-receipt-id'] as string);
    expect(payload.mk.sch).toBe('provenance-v1');

    // The completion the customer asked for is still there, and the member is the only addition: the
    // marking is one member at the top level, written last, and nothing else moved.
    const served = JSON.parse(text(body)) as Record<string, unknown>;
    expect(served['choices']).toEqual(JSON.parse(UPSTREAM_BUFFERED)['choices']);
    expect(Object.keys(served)).toEqual(['id', 'object', 'created', 'model', 'choices', 'usage', MARKING_MEMBER_NAME]);

    const region = extractMarkedRegion('provenance-v1', body);
    expect(text(region)).toMatch(new RegExp(`^"${MARKING_MEMBER_NAME}":\\{"marking":\\{"sch"`));
    // Writer and reader, meeting on one span: the digest the gateway took over the bytes it wrote,
    // recomputed by the published rule out of the bytes the client was handed.
    expect(toHex(sha256(region))).toBe(toHex(payload.mk.d));
    expect(toHex(hashRequest(body))).toBe(toHex(payload.res));
  });

  it('refuses an upstream body that cannot hold the member, and says which shape it met', async () => {
    for (const [body, why] of [
      ['not json at all', 'not JSON'],
      ['[{"id":"chatcmpl-1"}]', 'not one JSON object'],
      ['"a bare string"', 'not one JSON object'],
      ['null', 'not one JSON object'],
    ] as const) {
      const h = await open({ backend: bodyBackend(body, 'application/json'), marking: 'provenance-v1' });
      const res = await send(h, '/v1/chat/completions', REQUEST_BODY);
      expect(res.statusCode).toBe(502);
      expect(refusal(res.json()['error'])).toContain(why);
    }
  });

  it('serves that same unmarkable body while the flag is off', async () => {
    // The refusal belongs to the request for a mark and is not a new rule about upstreams: an off
    // deployment proxies what it was given, as it did before the member existed.
    const h = await open({ backend: bodyBackend('not json at all', 'application/json') });
    const res = await send(h, '/v1/chat/completions', REQUEST_BODY);
    expect(res.statusCode).toBe(200);
    expect(res.rawPayload.toString('utf8')).toBe('not json at all');
  });

  it('refuses a body whose upstream already wrote the member', async () => {
    const taken = JSON.stringify({
      ...JSON.parse(UPSTREAM_BUFFERED) as Record<string, unknown>,
      [MARKING_MEMBER_NAME]: { marking: { sch: 'ashaveri/provenance-v1', gen: 'ai', at: 1 } },
    });
    const h = await open({ backend: bodyBackend(taken, 'application/json'), marking: 'provenance-v1' });
    const res = await send(h, '/v1/chat/completions', REQUEST_BODY);
    expect(res.statusCode).toBe(502);
    expect(refusal(res.json()['error'])).toContain('already carries a');
  });

  it('leaves an upstream-written member to the client when the flag is off', async () => {
    // Off means this gateway vouches for the bytes it forwarded and declares that it marked nothing.
    // A backend that marked its own output is then refused by the reader holding both, which is the
    // only place injection bites a deployment that marks nothing: the streaming path never looks
    // inside a frame at all.
    const taken = JSON.stringify({
      ...JSON.parse(UPSTREAM_BUFFERED) as Record<string, unknown>,
      [MARKING_MEMBER_NAME]: { marking: { sch: 'ashaveri/provenance-v1', gen: 'ai', at: 1 } },
    });
    const h = await open({ backend: bodyBackend(taken, 'application/json') });
    const res = await send(h, '/v1/chat/completions', REQUEST_BODY);
    expect(res.statusCode).toBe(200);
    const payload = await receiptFor(h, res.headers['x-ashaveri-receipt-id'] as string);
    expect(payload.mk.sch).toBe('none');
    expect(() => extractMarkedRegion(payload.mk.sch, new Uint8Array(res.rawPayload))).toThrow(
      'carry 1 matching provenance-v1',
    );
  });
});

describe('a marked streamed completion', () => {
  it('writes one well-formed chunk holding the mark, inside the hash and before the sentinel', async () => {
    const h = await open({ backend: streamBackend(), marking: 'provenance-v1' });
    const res = await send(h, '/v1/chat/completions', STREAM_REQUEST_BODY);
    expect(res.statusCode).toBe(200);
    const body = new Uint8Array(res.rawPayload);
    const stream = text(body);
    const payload = await receiptFor(h, res.headers['x-ashaveri-receipt-id'] as string);

    const frames = stream.split('\n\n').filter((each) => each.length > 0);
    expect(frames.at(-1)).toBe('data: [DONE]');
    const mark = frames.at(-2) ?? '';
    const parsed = JSON.parse(mark.slice('data: '.length)) as Record<string, unknown>;
    // A chunk in every field a client reads, whose `choices` is empty: the shape measured to survive
    // an accumulator, where a frame that is neither a chunk nor the sentinel breaks one.
    expect({ id: parsed['id'], object: parsed['object'], choices: parsed['choices'], model: parsed['model'] }).toEqual(
      { id: MARKING_CHUNK_ID, object: 'chat.completion.chunk', choices: [], model: MODEL },
    );
    expect(Number.isInteger(parsed['created'])).toBe(true);
    expect(stream.indexOf('data: [DONE]')).toBeGreaterThan(stream.indexOf(`"${MARKING_MEMBER_NAME}"`));
    // The upstream's frames are still its own bytes, in its own order, with nothing edited.
    expect(stream.startsWith(UPSTREAM_STREAM.slice(0, UPSTREAM_STREAM.indexOf(SENTINEL)))).toBe(true);

    expect(toHex(sha256(extractMarkedRegion('provenance-v1', body)))).toBe(toHex(payload.mk.d));
    expect(toHex(hashRequest(body))).toBe(toHex(payload.res));
  });

  it('holds the mark ahead of the sentinel when the stream arrives in pieces', async () => {
    // Cut inside the sentinel's own letters, and inside a content frame, which is where a write
    // boundary actually falls: a client that stops reading at `[DONE]` never sees what came after it.
    const sentinelAt = UPSTREAM_STREAM.length - SENTINEL.length;
    const h = await open({
      backend: streamBackend([40, sentinelAt + 4, UPSTREAM_STREAM.length - 2]),
      marking: 'provenance-v1',
    });
    const res = await send(h, '/v1/chat/completions', STREAM_REQUEST_BODY);
    const stream = res.rawPayload.toString('utf8');
    const payload = await receiptFor(h, res.headers['x-ashaveri-receipt-id'] as string);
    const head = UPSTREAM_STREAM.slice(0, sentinelAt);
    const tailOfStream = stream.slice(head.length);
    expect(tailOfStream.startsWith(`data: {"id":"${MARKING_CHUNK_ID}"`)).toBe(true);
    expect(tailOfStream.endsWith(SENTINEL)).toBe(true);
    expect(stream.startsWith(head)).toBe(true);
    expect(toHex(sha256(extractMarkedRegion('provenance-v1', utf8(stream))))).toBe(toHex(payload.mk.d));
    expect(toHex(hashRequest(utf8(stream)))).toBe(toHex(payload.res));
  });

  it('adds nothing to a stream when the flag is off', async () => {
    const h = await open({ backend: streamBackend([37, 91]) });
    const res = await send(h, '/v1/chat/completions', STREAM_REQUEST_BODY);
    expect(res.rawPayload.toString('utf8')).toBe(UPSTREAM_STREAM);
    const payload = await receiptFor(h, res.headers['x-ashaveri-receipt-id'] as string);
    expect(toHex(payload.mk.d)).toBe(sha256Hex(emptyRegion()));
  });
});

describe('the tail a marked stream holds', () => {
  it('gives back the bytes it was handed, in order, with the mark inside the stream', () => {
    const pieces = ['data: {"a":1}\n\n', 'data: {"b', '":2}\n\ndata: [DO', 'NE]\n', '\n'];
    const tail = new MarkedStreamTail();
    let out = '';
    for (const piece of pieces) {
      out += text(tail.writable(utf8(piece)));
    }
    const mark = utf8(frame({ id: MARKING_CHUNK_ID, object: 'chat.completion.chunk', created: 1, model: MODEL, choices: [] }));
    for (const piece of tail.finishing(mark)) out += text(piece);
    expect(out).toBe(
      `data: {"a":1}\n\ndata: {"b":2}\n\n${new TextDecoder().decode(mark)}data: [DONE]\n\n`,
    );
  });

  it('writes the mark last when the stream has half a sentinel where its own should be', () => {
    const tail = new MarkedStreamTail();
    tail.writable(utf8('data: {"a":1}\n\ndata: [DO'));
    const out = tail.finishing(utf8('X')).map(text).join('');
    // Half a sentinel is not a sentinel, and splicing a chunk into the middle of a frame already on
    // its way is the worse error: the held bytes go out as they arrived, with the mark behind them.
    expect(out).toBe('data: [DOX');
  });

  it('holds nothing when there is no sentinel to wait for', () => {
    const tail = new MarkedStreamTail();
    expect(text(tail.writable(utf8('data: {"a":1}\n\n')))).toBe('data: {"a":1}\n\n');
    expect(tail.finishing(utf8('X')).map(text).join('')).toBe('X');
  });
});

function runCli(args: string[]): { status: number | null; stderr: string } {
  const env = { ...process.env };
  delete env['DSTACK_SIMULATOR_ENDPOINT'];
  const result = spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', env, timeout: 8000 });
  expect(result.error).toBeUndefined();
  return { status: result.status, stderr: result.stderr };
}

/** Boot, read the banner, and be stopped by the timeout: a serving process has no other ending. */
function runStoppedCli(args: string[]): string[] {
  const env = { ...process.env };
  delete env['DSTACK_SIMULATOR_ENDPOINT'];
  const result = spawnSync(process.execPath, [CLI, ...args, '--port', '0'], {
    encoding: 'utf8',
    env,
    timeout: 4000,
    killSignal: 'SIGKILL',
  });
  expect((result.error as (Error & { code?: string }) | undefined)?.code).toBe('ETIMEDOUT');
  return result.stdout.split('\n');
}
