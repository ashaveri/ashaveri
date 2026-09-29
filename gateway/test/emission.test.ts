import { afterEach, describe, expect, it } from 'vitest';
import type { AddressInfo } from 'node:net';
import {
  decodeReceipt,
  emptyRegion,
  extractMarkedRegion,
  frameResponse,
  sha256Hex,
  toHex,
  type ReceiptPayload,
} from '@ashaveri/receipt';
import {
  MARKING_CHUNK_ID,
  type BackendResponse,
  type CompletionBackend,
  type CompletionUsage,
  type TimeSource,
} from '../src/index.js';
import { StreamedItemStamps } from '../src/item-stamps.js';
import { sha256 } from '../src/digest.js';
import { CLOCK_SECONDS, fixedClock, generated, harness, type Generated, type Harness } from './helpers.js';

/**
 * What a gateway puts into a signed payload, and whether the bytes a client holds say the same thing.
 *
 * Every cell below asks one question in both directions: the gateway states a digest, and a reader that
 * was never party to the issuance recomputes it out of the bytes it was handed. That is the whole shape of
 * the hazard a digest stated inside a signed payload lives under. A payload's `res`, each of its item
 * digests, and the marked region `mk.d` names are three statements over one byte string, and any of the
 * three can be taken at a point where the bytes are still the upstream's rather than the client's. A test
 * that read the receipt back and compared it with what the gateway remembered would prove nothing about
 * that, because the gateway remembers the bytes it hashed, not the bytes a stranger received. So nothing
 * here reads the gateway's own bookkeeping: the response is taken as `rawPayload`, the items are framed
 * from it by the shipped `frameResponse`, and the payload has to agree.
 */

const NONCE = Uint8Array.from({ length: 16 }, (_, i) => i + 1);
const REQUEST_BODY = '{"model":"mock-model-1","messages":[{"role":"user","content":"hello"}]}';
const STREAM_REQUEST_BODY = '{"model":"mock-model-1","messages":[{"role":"user","content":"hi"}],"stream":true}';
const MODEL = 'mock-model-1';

const utf8 = (value: string): Uint8Array => new TextEncoder().encode(value);
const text = (bytes: Uint8Array): string => new TextDecoder().decode(bytes);

const frame = (payload: Record<string, unknown>): string => `data: ${JSON.stringify(payload)}\n\n`;
const SENTINEL = 'data: [DONE]\n\n';

const chunk = (content: string, finishReason: string | null): Record<string, unknown> => ({
  id: 'chatcmpl-upstream-1',
  object: 'chat.completion.chunk',
  created: CLOCK_SECONDS,
  model: MODEL,
  choices: [{ index: 0, delta: { content }, finish_reason: finishReason }],
});

const UPSTREAM_STREAM =
  frame(chunk('first piece', null)) + frame(chunk('second piece', null)) + frame(chunk('', 'stop')) + SENTINEL;

const UPSTREAM_BUFFERED = JSON.stringify({
  id: 'chatcmpl-upstream-1',
  object: 'chat.completion',
  created: CLOCK_SECONDS,
  model: MODEL,
  choices: [{ index: 0, message: { role: 'assistant', content: 'a buffered reply' }, finish_reason: 'stop' }],
  usage: { prompt_tokens: 9, completion_tokens: 6, total_tokens: 15 },
});

/** A body framed with carriage returns and no blank line, which is a second legal spelling of a stream. */
const CR_STREAM = 'data: {"a":1}\rdata: {"b":2}\rdata: [DONE]\r';

/** A stream whose last frame never got a terminator, so one item is settled only at the response's end. */
const OPEN_ENDED_STREAM = 'data: {"a":1}\n\ndata: {"b":2}';

/**
 * One body as the writes a transport was allowed to make, cut where this cell names.
 *
 * The splits are the point of the helper: a write boundary is a transport's choice and none of the digests
 * may depend on it, so the same body is run through several and every one has to issue the identical item
 * list.
 */
function piecesOf(body: string, splits: readonly number[]): Uint8Array[] {
  const bytes = utf8(body);
  const pieces: Uint8Array[] = [];
  let cut = 0;
  for (const at of [...splits].sort((a, b) => a - b)) {
    if (at <= cut || at >= bytes.length) continue;
    pieces.push(bytes.subarray(cut, at));
    cut = at;
  }
  pieces.push(bytes.subarray(cut));
  return pieces;
}

/** A backend that hands over these bytes in these pieces and nothing else. */
function bodyBackend(body: string, contentType: string, splits: readonly number[] = []): CompletionBackend {
  return streamBackend(contentType, piecesOf(body, splits));
}

/**
 * A backend over one response written in these pieces, which calls `passed` once the last of them has been
 * handed over and waits `pauseMs` after the first.
 *
 * `passed` is the cell's handle on the point past which a response has an id and no answer yet, which is
 * where a stamping failure reaches a client already holding that id. The pause is for a cell that reads the
 * response as a client does: bytes reach a reader when the socket chooses, and one that needs the headers to
 * have arrived before the failure has to give them time to get there.
 */
function pacedBackend(
  contentType: string,
  pieces: readonly Uint8Array[],
  options: { readonly passed?: () => void; readonly pauseMs?: number } = {},
): CompletionBackend {
  const { passed, pauseMs = 0 } = options;
  return streamBackend(contentType, pieces, async (at) => {
    if (at === 0 && pauseMs > 0) await new Promise((resolve) => setTimeout(resolve, pauseMs));
    if (at === pieces.length - 1) passed?.();
  });
}

/** The bytes of one completion, served with the usage a frame of it carries and this pacing between them. */
function streamBackend(
  contentType: string,
  pieces: readonly Uint8Array[],
  between?: (at: number) => Promise<void>,
): CompletionBackend {
  const usage: Promise<CompletionUsage> = Promise.resolve({
    model: MODEL,
    promptTokens: 9,
    completionTokens: 6,
  });
  return {
    async respond(): Promise<BackendResponse> {
      return {
        status: 200,
        contentType,
        chunks: (async function* (): AsyncGenerator<Uint8Array> {
          for (const [at, piece] of pieces.entries()) {
            yield piece;
            if (between !== undefined) await between(at);
          }
        })(),
        usage,
      };
    },
  };
}

/** Where each frame of the stream ends, which is where a write that closes one item can be made. */
function frameEnds(body: string): number[] {
  const at: number[] = [];
  for (let scan = body.indexOf('\n\n'); scan >= 0; scan = body.indexOf('\n\n', scan + 2)) {
    if (scan + 2 < body.length) at.push(scan + 2);
  }
  return at;
}

const credential: Generated = generated('emission', ['complete', 'read']);

let session: Harness | undefined;

async function open(
  gateway: { backend?: CompletionBackend; marking?: 'none' | 'provenance-v1'; time?: TimeSource } = {},
): Promise<Harness> {
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

interface Served {
  /** The bytes the client was handed, whole. Every digest below is checked against these. */
  readonly body: Uint8Array;
  readonly payload: ReceiptPayload;
  readonly status: number;
}

async function sendAndFetch(h: Harness, target: string, body: string): Promise<Served> {
  const res = await h.app.inject({
    method: 'POST' as 'GET',
    url: target,
    headers: { 'content-type': 'application/json', ...h.signFor('emission', 'POST', target, body, { nonce: NONCE }) },
    payload: body,
  });
  expect(res.statusCode).toBe(200);
  const id = res.headers['x-ashaveri-receipt-id'] as string;
  const receipt = await h.app.inject({
    method: 'GET',
    url: `/v1/receipts/${id}`,
    headers: h.signFor('emission', 'GET', `/v1/receipts/${id}`, null),
  });
  expect(receipt.statusCode).toBe(200);
  // Decoded by the shipped reader, which is the half of the proof a hand-built payload could not give:
  // a document this package cannot read back is not an artifact, whatever the writer remembered.
  return {
    body: new Uint8Array(res.rawPayload),
    payload: decodeReceipt(new Uint8Array(receipt.rawPayload)).payload,
    status: res.statusCode,
  };
}

/** A source that reads a second later every time it is asked, so a stamp per frame is a stamp apart. */
function steppingClock(start: number): TimeSource {
  let ticks = 0;
  return { name: 'stepping clock', uncertaintySeconds: 2, nowSeconds: () => start + (ticks += 1) };
}

/**
 * One body handed over at these write boundaries, with a source reading one second later every time it is
 * asked, as the list of `t` and `d` pairs the response would state.
 */
function stampedShape(body: Uint8Array, splits: readonly number[]): string[] {
  let ticks = 0;
  const stamps = new StreamedItemStamps(() => CLOCK_SECONDS + (ticks += 1));
  let cut = 0;
  for (const at of [...splits].sort((a, b) => a - b)) {
    if (at <= cut || at >= body.length) continue;
    stamps.written(body.subarray(cut, at));
    cut = at;
  }
  stamps.written(body.subarray(cut));
  const answer = stamps.answer();
  if (!answer.framed) throw new Error(`the split ${String(splits)} framed no items`);
  return answer.stamps.map((one) => `${String(one.t)}:${toHex(one.d)}`);
}

/** Whether no stamp in the list runs against the order its items were framed in. */
function runsInOrder(stamps: readonly number[]): boolean {
  let previous: number | undefined;
  for (const one of stamps) {
    if (previous !== undefined && one < previous) return false;
    previous = one;
  }
  return true;
}

/**
 * What a live `StreamedItemStamps` still owns of the response it read, reached by walking everything the
 * instance can hand back, and counted over every run of bytes that is not a 32-byte digest.
 *
 * A claim about retention is a claim about reachability, so this measures reachability and not a heap
 * figure: the digests the two readings state are 32 bytes apiece and are kept on purpose, and anything
 * wider than that is a response's own bytes. A payload of exactly 32 bytes would read here as a digest,
 * which is why the bodies below are framed from payloads of other widths. The companion claim, about the
 * reader in `packages/receipt` this one is built on, is at
 * `packages/receipt/test/response-items.test.ts`.
 */
function nonDigestBytesHeld(reader: object): number {
  const seen = new Set<unknown>();
  const stack: unknown[] = [reader];
  let held = 0;
  while (stack.length > 0) {
    const node = stack.pop();
    if (node === null || (typeof node !== 'object' && typeof node !== 'function') || seen.has(node)) continue;
    seen.add(node);
    if (ArrayBuffer.isView(node)) {
      if (node.byteLength !== 32) held += node.byteLength;
      continue;
    }
    for (const key of Object.keys(node)) stack.push((node as Record<string, unknown>)[key]);
  }
  return held;
}

/** The stamps of one body handed over at these boundaries, and the instance that took them. */
function drivenBy(body: Uint8Array, splits: readonly number[]): StreamedItemStamps {
  const stamps = new StreamedItemStamps(() => CLOCK_SECONDS);
  let cut = 0;
  for (const at of [...splits].sort((a, b) => a - b)) {
    if (at <= cut || at >= body.length) continue;
    stamps.written(body.subarray(cut, at));
    cut = at;
  }
  stamps.written(body.subarray(cut));
  return stamps;
}

describe('a v3 response, attested in the bytes a client holds', () => {
  it('frames a marked stream into items the reader rebuilds from the response it was handed', async () => {
    const h = await open({
      backend: bodyBackend(UPSTREAM_STREAM, 'text/event-stream', [40, UPSTREAM_STREAM.length - SENTINEL.length + 4]),
      marking: 'provenance-v1',
    });
    const served = await sendAndFetch(h, '/v1/chat/completions', STREAM_REQUEST_BODY);
    expect(served.payload.v).toBe(3);
    const payload = served.payload;
    if (!('itm' in payload)) throw new Error('a v3 payload carries no item list');

    // Recomputed by the published rule, out of the bytes this client holds and nothing else.
    const rebuilt = frameResponse('text/event-stream', served.body);
    if (!rebuilt.framed) throw new Error('the client bytes frame into no items');
    expect(payload.itm.map((one) => toHex(one.d))).toEqual(rebuilt.items.map((one) => toHex(one.d)));

    // The upstream sent three data frames and a sentinel; the client was handed a fourth frame, this
    // gateway's own mark, inside the sequence `res` digests. An item list taken before the mark was
    // written would be one entry short of the response a reader can walk.
    const upstreamItems = frameResponse('text/event-stream', utf8(UPSTREAM_STREAM));
    if (!upstreamItems.framed) throw new Error('the upstream body frames into no items');
    expect([upstreamItems.items.length, rebuilt.items.length]).toEqual([3, 4]);
    // An item's digest is of one frame's payload and none of the framing around it, so the line's own
    // `data: ` is not inside the bytes this entry hashes.
    const markLine = (text(served.body).split('\n\n').find((one) => one.includes(MARKING_CHUNK_ID)) ?? '')
      .slice('data: '.length);
    expect(payload.itm.map((one) => toHex(one.d))).toContain(toHex(sha256(utf8(markLine))));

    // The three digests of one byte string, agreeing on the same bytes.
    expect(toHex(payload.res)).toBe(sha256Hex(served.body));
    expect(toHex(sha256(extractMarkedRegion(payload.mk.sch, served.body)))).toBe(toHex(payload.mk.d));
    expect(payload.mk.sch).toBe('provenance-v1');
  });

  it('frames a stream the upstream stopped mid-line into a mark its own reader accepts', async () => {
    // The last frame of a completion that arrived with no terminator at all. What the client holds is the
    // upstream's bytes, the frame end the upstream owed, and this gateway's mark: three statements a reader
    // has to be able to check, because a receipt over a line two `data:` prefixes share attests bytes the
    // published rule then refuses under the scheme the same payload names.
    const unterminated = 'data: {"a":1}\n\ndata: {"b":2}';
    const h = await open({
      backend: bodyBackend(unterminated, 'text/event-stream', [14, unterminated.length - 1]),
      marking: 'provenance-v1',
    });
    const served = await sendAndFetch(h, '/v1/chat/completions', STREAM_REQUEST_BODY);
    expect(served.payload.v).toBe(3);
    const payload = served.payload;
    if (!('itm' in payload)) throw new Error('a v3 payload carries no item list');

    const rebuilt = frameResponse('text/event-stream', served.body);
    if (!rebuilt.framed) throw new Error('the client bytes frame into no items');
    expect(rebuilt.items.map((one) => text(one.bytes))).toEqual([
      '{"a":1}',
      '{"b":2}',
      text(extractMarkedRegion('provenance-v1', served.body)).slice('data: '.length),
    ]);
    expect(payload.itm.map((one) => toHex(one.d))).toEqual(rebuilt.items.map((one) => toHex(one.d)));

    // No line the client holds carries two frames, and the region the mark names is one of them.
    expect(text(served.body).split(/[\r\n]/).filter((line) => (line.match(/data:/g) ?? []).length > 1)).toEqual([]);
    expect(payload.mk.sch).toBe('provenance-v1');
    expect(toHex(sha256(extractMarkedRegion(payload.mk.sch, served.body)))).toBe(toHex(payload.mk.d));
    expect(toHex(payload.res)).toBe(sha256Hex(served.body));
  });

  it('frames the same stream identically whatever boundaries the transport chose', async () => {
    const body = UPSTREAM_STREAM;
    const cuts: number[][] = [
      [],
      [1, 2, 3],
      [body.indexOf(SENTINEL) + 3],
      [body.indexOf(SENTINEL) + 6],
      frameEnds(body),
      ...frameEnds(body).map((at) => [at]),
    ];
    let expected: string[] | undefined;
    for (const splits of cuts) {
      // A pinned source, because the mark frame this gateway writes carries an instant in the bytes the
      // items digest: on the host clock two runs of one body would differ by a frame, and the point of
      // this cell is that only the transport's boundaries vary.
      const h = await open({
        backend: bodyBackend(body, 'text/event-stream', splits),
        marking: 'provenance-v1',
        time: fixedClock(() => CLOCK_SECONDS),
      });
      const served = await sendAndFetch(h, '/v1/chat/completions', STREAM_REQUEST_BODY);
      if (!('itm' in served.payload)) throw new Error(`a split issued a payload with no item list: ${String(splits)}`);
      const digests = served.payload.itm.map((one) => toHex(one.d));
      // One body, one item list: the split moves nothing, because the frames are a property of the
      // bytes and not of how this process was allowed to hand them over.
      if (expected === undefined) expected = digests;
      expect([splits.length, digests]).toEqual([splits.length, expected]);
      expect(served.payload.v).toBe(3);
    }
  });

  it('issues one stamped list for one body whatever boundaries the transport chose', async () => {
    // A rising source, an unmarked stream, and the same body handed over in one piece, a frame at a time,
    // and in pieces that cut through frames: the list the signed document states is identical in all
    // three, because the readings a response consumes are its items and nothing else. A stamp that moved
    // with a write boundary would put a transport's accident inside a signed artifact, which is what a
    // published multi-item response vector cannot be allowed to freeze.
    const shapes: string[][] = [];
    for (const splits of [[], frameEnds(UPSTREAM_STREAM), [1, 20, 44, 96]]) {
      const h = await open({
        backend: bodyBackend(UPSTREAM_STREAM, 'text/event-stream', splits),
        time: steppingClock(CLOCK_SECONDS),
      });
      const served = await sendAndFetch(h, '/v1/chat/completions', STREAM_REQUEST_BODY);
      if (!('itm' in served.payload)) throw new Error('a v3 payload carries no item list');
      expect(served.payload.v).toBe(3);
      shapes.push(served.payload.itm.map((one) => `${String(one.t)}:${toHex(one.d)}`));
    }
    expect([shapes[1], shapes[2]]).toEqual([shapes[0] ?? [], shapes[0] ?? []]);
    // Distinct instants, so the equality above is an equality of a sequence and not of one number copied
    // across a list a frozen clock would have produced anyway.
    expect(new Set(shapes[0] ?? []).size).toBe((shapes[0] ?? []).length);
  });

  it('reads a stream framed by carriage returns as the two items its client reads', async () => {
    const h = await open({ backend: bodyBackend(CR_STREAM, 'text/event-stream', [9, 24]) });
    const served = await sendAndFetch(h, '/v1/chat/completions', STREAM_REQUEST_BODY);
    const rebuilt = frameResponse('text/event-stream', served.body);
    if (!rebuilt.framed || !('itm' in served.payload)) throw new Error('the carriage-returned body framed nothing');
    expect(rebuilt.items.length).toBe(2);
    expect(served.payload.itm.map((one) => toHex(one.d))).toEqual(rebuilt.items.map((one) => toHex(one.d)));
    expect(toHex(served.payload.res)).toBe(sha256Hex(served.body));
  });

  it('stamps each item as its frame passes, and keeps the list in the order the bytes were in', async () => {
    // One write per frame, so a source that moves reads a different instant for each item and the list
    // cannot be one number copied across it.
    const h = await open({
      backend: bodyBackend(UPSTREAM_STREAM, 'text/event-stream', frameEnds(UPSTREAM_STREAM)),
      time: steppingClock(CLOCK_SECONDS),
    });
    const served = await sendAndFetch(h, '/v1/chat/completions', STREAM_REQUEST_BODY);
    if (!('itm' in served.payload)) throw new Error('a v3 payload carries no item list');
    const stamps = served.payload.itm.map((one) => one.t);
    expect(runsInOrder(stamps)).toBe(true);
    // The clock here advances one second per reading and the frames were handed over in separate writes,
    // so an `iat` copied across the items would read as three equal values.
    expect(new Set(stamps).size).toBe(stamps.length);
  });

  it('keeps a stepped-back clock from issuing a list its own reader would refuse', async () => {
    // A source that steps backwards inside one response is the one way an item stamped after its
    // predecessor can carry an earlier instant, and the reader answers that document with
    // `ITEM_STAMP_OUT_OF_ORDER`. The gateway's answer is the largest instant this response has already
    // claimed, so the list stays readable and the disclosure beside it still names the bound the source
    // declared. `StreamedItemStamps` is tested against a clock that steps back directly below, where the
    // readings that decreased are visible; here the point is that the issued document survives the reader
    // it was signed for, and states no item after its own issuance. The reading falls every time it is
    // asked, which is the worst case for both claims: the response's first instant is its highest, and
    // the instant `iat` is taken from is its lowest.
    let reads = 0;
    const h = await open({
      backend: bodyBackend(UPSTREAM_STREAM, 'text/event-stream', frameEnds(UPSTREAM_STREAM)),
      time: {
        name: 'stepping back clock',
        uncertaintySeconds: null,
        nowSeconds: () => CLOCK_SECONDS - (reads += 1),
      },
    });
    const served = await sendAndFetch(h, '/v1/chat/completions', STREAM_REQUEST_BODY);
    if (!('itm' in served.payload)) throw new Error('a v3 payload carries no item list');
    const stamps = served.payload.itm.map((one) => one.t);
    // Reaching this line is half the witness: `sendAndFetch` decoded the document with `decodeReceipt`,
    // which is where `ITEM_STAMP_OUT_OF_ORDER` is raised, so a list running against its own order would
    // have failed the fetch rather than the assertion below.
    expect(runsInOrder(stamps)).toBe(true);
    // Every item passed before the receipt was signed, so no frame is dated after the document that
    // attests it. The clamp that keeps the list readable is a floor drawn from this response's own
    // readings, and a floor sits above a later reading when the source runs backwards, so the bound has
    // to be the instant the payload states.
    expect(stamps.every((one) => one <= served.payload.iat)).toBe(true);
    expect(served.payload.sd).toEqual({ name: 'stepping back clock', uncertaintySeconds: null });
  });

  it('attests a marked buffered body as the one item the client was handed', async () => {
    const h = await open({ backend: bodyBackend(UPSTREAM_BUFFERED, 'application/json'), marking: 'provenance-v1' });
    const served = await sendAndFetch(h, '/v1/chat/completions', REQUEST_BODY);
    expect(served.payload.v).toBe(3);
    if (!('itm' in served.payload)) throw new Error('a v3 payload carries no item list');
    const issued = served.payload.itm[0];
    // The whole body, mark member included, and nothing else: a buffered completion has no frames, so
    // its one item is the bytes `res` digests, which is why the two digests are equal here and unequal
    // on every stream.
    if (issued === undefined) throw new Error('a v3 payload states an item list with nothing in it');
    expect(served.payload.itm.length).toBe(1);
    expect(toHex(issued.d)).toBe(toHex(served.payload.res));
    const rebuilt = frameResponse('application/json', served.body);
    if (!rebuilt.framed) throw new Error('the client bytes framed into no items');
    const recomputed = rebuilt.items[0];
    if (recomputed === undefined) throw new Error('the client bytes framed no item');
    expect(toHex(recomputed.d)).toBe(toHex(issued.d));
    expect(toHex(sha256(extractMarkedRegion(served.payload.mk.sch, served.body)))).toBe(
      toHex(served.payload.mk.d),
    );
    expect(served.body.length).toBeGreaterThan(utf8(UPSTREAM_BUFFERED).length);
  });
});

describe('the fallback the bytes can reach', () => {
  it('issues v2 for a stream that sent no data frame, and v2 alone', async () => {
    // Frames, an event field and the sentinel, and not one `data:` line said: the response exists, its
    // bytes are hashed, and there is nothing for an item list to attest. The empty list is the format's
    // refusal, so the version that names no list is the one that can be signed truthfully.
    const body = 'event: message\n\n: a comment\n\ndata: [DONE]\n\n';
    const h = await open({ backend: bodyBackend(body, 'text/event-stream', [20]) });
    const served = await sendAndFetch(h, '/v1/chat/completions', STREAM_REQUEST_BODY);
    if (served.payload.v !== 2) throw new Error(`a stream of nothing issued a v${String(served.payload.v)} receipt`);
    // The three members are not present as empties, which is what a `v: 3` with a defaulted disclosure
    // would look like: a version that does not name them cannot carry them, and the closed map is what
    // makes that a fact of the bytes rather than an expectation about them.
    for (const member of ['itm', 'sd', 'cva']) {
      expect(Object.hasOwn(served.payload, member)).toBe(false);
    }
    // The reason the payload gives by falling back is the reason the shipped reader gives about the very
    // same bytes, which is the only statement of it a stranger can check.
    const rebuilt = frameResponse('text/event-stream', served.body);
    expect(rebuilt.framed).toBe(false);
    if (rebuilt.framed) throw new Error('the client bytes framed into items');
    expect(rebuilt.why).toContain('no data frame');
    // And the attestation the version can carry is still true of those bytes.
    expect(toHex(served.payload.res)).toBe(sha256Hex(served.body));
    expect(served.payload.mk.sch).toBe('none');
    expect(toHex(served.payload.mk.d)).toBe(sha256Hex(emptyRegion()));
  });

  it('issues v2 for a stream of nothing but an unterminated event field', async () => {
    const h = await open({ backend: bodyBackend('event: message', 'text/event-stream') });
    const served = await sendAndFetch(h, '/v1/chat/completions', STREAM_REQUEST_BODY);
    expect(served.payload.v).toBe(2);
    expect(toHex(served.payload.res)).toBe(sha256Hex(served.body));
  });
});

describe('the framing of one response, read off the bytes as they pass', () => {
  it('walks the same items the shipped reader walks, whatever the write boundaries were', () => {
    const body = utf8(UPSTREAM_STREAM);
    const expected = frameResponse('text/event-stream', body);
    if (!expected.framed) throw new Error('the body frames into no items');
    const splits: number[][] = [[], [1], frameEnds(UPSTREAM_STREAM), [40, 91, 130, body.length - 1]];
    for (const at of [...splits, splits.flat()]) {
      const stamps = new StreamedItemStamps(() => CLOCK_SECONDS);
      let cut = 0;
      for (const piece of [...at].sort((a, b) => a - b)) {
        if (piece <= cut || piece >= body.length) continue;
        stamps.written(body.subarray(cut, piece));
        cut = piece;
      }
      stamps.written(body.subarray(cut));
      const answer = stamps.answer();
      if (!answer.framed) throw new Error(`the split ${String(at)} framed no items`);
      expect([String(at), answer.stamps.map((one) => toHex(one.d))]).toEqual([
        String(at),
        expected.items.map((one) => toHex(one.d)),
      ]);
    }
  });

  it('holds no byte of a closed frame between its writes and its answer', () => {
    // The whole-response walk runs from a stream's first write to its last, so what it keeps of the bytes it
    // has read is kept until the receipt is signed. The two things this file takes from it are each item's
    // digest and how many there were, so nothing wider than a digest may be reachable once every frame has
    // arrived closed. The same body read by the verifier's own framing is the check that the digests stated
    // are the ones the bytes give: the retention claim and the answer claim are taken about one run.
    const body = utf8(UPSTREAM_STREAM);
    const stamps = drivenBy(body, frameEnds(UPSTREAM_STREAM));
    const answer = stamps.answer();
    if (!answer.framed) throw new Error('the stream framed no items');
    const expected = frameResponse('text/event-stream', body);
    if (!expected.framed) throw new Error('the whole body framed no items');
    expect(answer.stamps.map((one) => toHex(one.d))).toEqual(expected.items.map((one) => toHex(one.d)));
    expect(nonDigestBytesHeld(stamps)).toBe(0);

    // One frame the stream has not closed is the widest thing a live reader may own, and it is owned twice:
    // once by the walk that sees every byte, and once by this file's carry, which is by construction the same
    // value that walk holds internally. Every closed frame before it is gone from both.
    const open = `data: ${'y'.repeat(200)}`;
    const left = utf8(`data: {"a":1}\n\n${open}`);
    const midstream = drivenBy(left, []);
    expect(nonDigestBytesHeld(midstream)).toBe(open.length * 2);
    const settled = midstream.answer();
    if (!settled.framed) throw new Error('the unterminated frame was refused');
    const rebuilt = frameResponse('text/event-stream', left);
    if (!rebuilt.framed) throw new Error('the body with the open frame framed no items');
    expect(settled.stamps.map((one) => toHex(one.d))).toEqual(rebuilt.items.map((one) => toHex(one.d)));
  });

  it('reads one instant per item, so no write boundary is inside a stamp', () => {
    const body = utf8(UPSTREAM_STREAM);
    const expected = frameResponse('text/event-stream', body);
    if (!expected.framed) throw new Error('the body frames into no items');
    const whole = stampedShape(body, []);
    // The same body through one write, through one write per frame, and through boundaries that cut
    // inside frames: one list of instants and digests, because a stamp is a reading of a source taken for
    // one item and not a record of how many writes carried it. A reading taken once per write would answer
    // three equal instants for the whole body and three apart for the frames, and a published multi-item
    // vector would freeze one transport's boundaries into bytes every other implementation is asked to
    // reproduce.
    expect([whole, stampedShape(body, frameEnds(UPSTREAM_STREAM)), stampedShape(body, [1, 20, 44, 96])]).toEqual([
      whole,
      whole,
      whole,
    ]);
    // One reading per item, and the items are the whole of the count: a source that moves between two
    // frames shows between their stamps, and nothing put two items inside one reading here.
    expect([new Set(whole).size, whole.length]).toEqual([whole.length, expected.items.length]);
  });

  it('absorbs a clock that steps back between two frames into one readable order', () => {
    const read: number[] = [];
    const stamps = new StreamedItemStamps(() => {
      const previous = read.length === 0 ? CLOCK_SECONDS : (read[read.length - 1] ?? CLOCK_SECONDS);
      const next = previous - 1;
      read.push(next);
      return next;
    });
    for (const line of UPSTREAM_STREAM.split('\n\n')) {
      if (line.length > 0) stamps.written(utf8(`${line}\n\n`));
    }
    const answer = stamps.answer();
    if (!answer.framed) throw new Error('the body framed into no items');
    expect(read.length).toBeGreaterThan(1);
    // Every reading of this source is below the one before it, which is the worst case for the ordering
    // rule a reader enforces over signed bytes.
    expect(read.every((one, at) => at === 0 || (read[at - 1] ?? 0) > one)).toBe(true);
    const stampsOf = answer.stamps.map((one) => one.t);
    expect(runsInOrder(stampsOf)).toBe(true);
    // The list carries the largest instant this response has already claimed, which is a reading of the
    // source and not an invention: it is the first one, and no later item can be dated below it.
    expect(new Set(stampsOf).size).toBe(1);
    expect(stampsOf[0]).toBe(read[0]);
  });

  it('refuses a stream that sent no data frame, with the reason the shipped reader gives', () => {
    const stamps = new StreamedItemStamps(() => CLOCK_SECONDS);
    stamps.written(utf8('event: message\n\n: comment\n\ndata: [DONE]\n\n'));
    const answer = stamps.answer();
    expect(answer.framed).toBe(false);
    if (answer.framed) throw new Error('a sentinel framed an item');
    expect(answer.why).toContain('no data frame');
  });
});

describe('a stream whose stamps cannot be stated when the payload is built', () => {
  it('does not end the response as though it had attested it, and leaves the id it sent with nothing behind it', async () => {
    // This cell is about the outcome a client holds, and not about whether one of the three consistency
    // checks in `gateway/src/item-stamps.ts` fired. Those compare one gateway's two readings of one
    // response, both taken over the same bytes by the one walk, so no bytes a client can send put the two
    // readings apart, and no cell can hand them a disagreement to catch. What a cell can reach is the step
    // the checks stand at: `gateway/src/server.ts` writes `x-ashaveri-receipt-id` into the headers before
    // it has handed the client a byte of the body, so an `answer()` that does not return lands on a
    // response whose id the client has been handed. The source below stops answering at the one reading
    // `answer()` takes for a last frame the stream left unterminated, inside that method and after every
    // check it runs, so the failure reaches the client for a reason the client's own bytes cannot cause.
    // Which reason it was is not this cell's subject; the ending is.
    let passed = false;
    let missed = false;
    const first = 'data: {"a":1}\n\n';
    const h = await open({
      // Two writes of a body whose last frame has no terminator, with time after the first for the socket to
      // deliver the headers and the frame it carried: what a client holds before the failure is the thing
      // the decision has to be readable in.
      backend: pacedBackend('text/event-stream', piecesOf(OPEN_ENDED_STREAM, [first.length]), {
        pauseMs: 250,
        passed: () => {
          passed = true;
        },
      }),
      time: {
        name: 'a source that misses the last reading',
        uncertaintySeconds: null,
        nowSeconds: () => {
          if (passed && !missed) {
            missed = true;
            throw new Error('the wired source stopped answering');
          }
          // One reading missed and not a source gone: the access log stamps its own record off this same
          // source, and a forcing that outlived the response would be measured instead of the decision.
          return CLOCK_SECONDS;
        },
      },
    });

    await h.app.listen({ port: 0, host: '127.0.0.1' });
    const port = (h.app.server.address() as AddressInfo).port;
    const res = await fetch(`http://127.0.0.1:${port}/v1/chat/completions`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...h.signFor('emission', 'POST', '/v1/chat/completions', STREAM_REQUEST_BODY),
      },
      body: STREAM_REQUEST_BODY,
    });
    const id = res.headers.get('x-ashaveri-receipt-id');
    expect(typeof id).toBe('string');
    const reader = res.body?.getReader();
    if (reader === undefined) throw new Error('a completion that carried an id carried no body to read');

    const held: number[] = [];
    let short = false;
    try {
      for (;;) {
        const next = await reader.read();
        if (next.done === true) break;
        held.push(...next.value);
      }
    } catch {
      short = true;
    }
    // The client was handed the completion and the read still did not complete: the body is there and the
    // response is not, which is the one state a client cannot arrive at by accident. An ending that said
    // "done" over these bytes would be this gateway claiming it had attested them, and the id it advertised
    // would be a handle a client had no way to know was on nothing.
    expect([missed, short, new TextDecoder().decode(new Uint8Array(held)).startsWith(first)]).toEqual([
      true,
      true,
      true,
    ]);

    const target = `/v1/receipts/${id as string}`;
    const gone = await fetch(`http://127.0.0.1:${port}${target}`, {
      headers: h.signFor('emission', 'GET', target, null),
    });
    expect(gone.status).toBe(404);
    // Section 4.3 of `docs/receipt-spec.md` tells a client to retry briefly on a 404, so the answer this
    // decision leaves has to hold on the second try as it does on the first: no document arrives late for
    // this id. Minting an id records nothing, and only an issuance writes a document, so the second 404 is
    // the store saying that this handle was never attached to a response rather than saying that one is
    // still on its way. The retry is a fresh presentation, so it is signed afresh rather than replaying
    // the first one's nonce.
    await new Promise((resolve) => setTimeout(resolve, 250));
    const again = await fetch(`http://127.0.0.1:${port}${target}`, {
      headers: h.signFor('emission', 'GET', target, null),
    });
    expect(again.status).toBe(404);

    await h.app.close();
  });

  it('goes on attesting the deployments other responses after one could not be stated', async () => {
    // The failure is one response's. Its id is spent and nothing is filed under it, and the next completion
    // on the same gateway signs and files normally: a source that missed one reading costs a deployment the
    // receipt it could not state, and no more than that.
    let passed = false;
    let missed = false;
    const h = await open({
      backend: pacedBackend('text/event-stream', piecesOf(OPEN_ENDED_STREAM, []), {
        passed: () => {
          passed = true;
        },
      }),
      time: {
        name: 'a source that misses one reading',
        uncertaintySeconds: null,
        nowSeconds: () => {
          if (passed && !missed) {
            missed = true;
            throw new Error('the wired source stopped answering');
          }
          return CLOCK_SECONDS;
        },
      },
    });

    let reason = 'nothing reached the caller: the response was answered';
    await h.app
      .inject({
        method: 'POST' as 'GET',
        url: '/v1/chat/completions',
        headers: {
          'content-type': 'application/json',
          ...h.signFor('emission', 'POST', '/v1/chat/completions', STREAM_REQUEST_BODY),
        },
        payload: STREAM_REQUEST_BODY,
      })
      .catch((err: unknown) => {
        reason = err instanceof Error ? err.message : String(err);
      });
    // The reason leaves the process with the destroyed response, which is what says this ending was the
    // failed reading and not one of the refusals this route writes before its headers go out. A client on a
    // live socket is told only that the body stopped: it gets no completion, and the id it holds keeps
    // meaning no receipt. Nothing here claims the message reaches that client, because it does not.
    expect(reason).toContain('the wired source stopped answering');

    const served = await sendAndFetch(h, '/v1/chat/completions', STREAM_REQUEST_BODY);
    expect(served.payload.v).toBe(3);
  });
});

describe('the two disclosures a v3 payload states', () => {
  it('names the wired source and its bound, and defaults neither', async () => {
    const h = await open({
      backend: bodyBackend(UPSTREAM_BUFFERED, 'application/json'),
      time: { name: 'lab bench one', uncertaintySeconds: 3, nowSeconds: () => CLOCK_SECONDS },
    });
    const served = await sendAndFetch(h, '/v1/chat/completions', REQUEST_BODY);
    if (!('sd' in served.payload)) throw new Error('a v3 payload carries no stamp disclosure');
    expect(served.payload.sd).toEqual({ name: 'lab bench one', uncertaintySeconds: 3 });
    // Not the shipped host claim, and not a bound smoothed to zero: a deployment that measured its clock
    // has the measurement signed, and one that did not signs the absence of it.
    expect(served.payload.sd.name).not.toBe('host clock');
  });

  it('names the host clock and the uncertainty nobody measured when nothing was wired', async () => {
    const h = await open({ backend: bodyBackend(UPSTREAM_BUFFERED, 'application/json') });
    const served = await sendAndFetch(h, '/v1/chat/completions', REQUEST_BODY);
    if (!('sd' in served.payload)) throw new Error('a v3 payload carries no stamp disclosure');
    expect(served.payload.sd).toEqual({ name: 'host clock', uncertaintySeconds: null });
  });

  it('states that no appraisal context was taken in, in the words that say so', async () => {
    const h = await open({ backend: bodyBackend(UPSTREAM_BUFFERED, 'application/json') });
    const served = await sendAndFetch(h, '/v1/chat/completions', REQUEST_BODY);
    if (!('cva' in served.payload)) throw new Error('a v3 payload carries no validity anchor');
    const anchor = served.payload.cva;
    for (const slot of [anchor.collateral, anchor.validity]) {
      expect(slot.presence).toBe('not-taken-in');
      // A reason is required, and required to be the sentence this gateway can actually stand behind:
      // not a placeholder, and never a state that a reader could weigh as a pass.
      expect(slot.presence === 'not-taken-in' ? slot.reason.length : 0).toBeGreaterThan(20);
    }
    expect(anchor.collateral.presence === 'not-taken-in' ? anchor.collateral.reason : '').toContain(
      'this gateway takes no collateral',
    );
    expect(anchor.validity.presence === 'not-taken-in' ? anchor.validity.reason : '').toContain(
      'this gateway records no validity context',
    );
    // The two absences are two labels because one is a statement about the world and the other about the
    // collector, and a reason in the collector's slot that reported no window stood open would be an
    // appraisal this process never ran. What it may claim is what the record holds and what this gateway
    // looked at, which is what the sentence is now refused for saying otherwise.
    expect(anchor.validity.presence === 'not-taken-in' ? anchor.validity.reason : '').not.toMatch(
      /no window (?:stood|stands) open/,
    );
    // Both halves are stated, and the absence of one is never read in place of the other. The reader
    // hands them back under the names the format gives the slots, which is where `col` and `val` live.
    expect(Object.keys(anchor).sort()).toEqual(['collateral', 'validity']);
  });

  it('carries the three members of a v3 together, each named and none of them defaulted', async () => {
    const h = await open({
      backend: bodyBackend(UPSTREAM_STREAM, 'text/event-stream'),
      time: { name: 'wired at issuance', uncertaintySeconds: 0, nowSeconds: () => CLOCK_SECONDS },
    });
    const served = await sendAndFetch(h, '/v1/chat/completions', STREAM_REQUEST_BODY);
    expect(Object.keys(served.payload).sort()).toEqual(
      [
        'att', 'cva', 'epk', 'iat', 'ins', 'iss', 'itm', 'mdl', 'meas', 'mk', 'nce', 'req', 'res', 'sd',
        'tok', 'v', 'wts',
      ].sort(),
    );
    if (!('sd' in served.payload) || !('cva' in served.payload) || !('itm' in served.payload)) {
      throw new Error('a v3 payload is missing one of the three members that moved the version');
    }
    // A bound of zero is a source claiming it is right, and it is not the same document as the null the
    // host clock carries: the member is written either way, because an omitted bound reads as whichever
    // answer a reader prefers.
    expect(served.payload.sd).toEqual({ name: 'wired at issuance', uncertaintySeconds: 0 });
    expect(served.payload.itm.length).toBe(3);
  });
});
