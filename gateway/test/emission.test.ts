import { afterEach, describe, expect, it } from 'vitest';
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
 * was never party to the issuance recomputes it out of the bytes it was handed. That is the whole shape
 * of the hazard this unit lives in. A payload's `res`, each of its item digests, and the marked region
 * `mk.d` name are three statements over one byte string, and any of the three can be taken at a point
 * where the bytes are still the upstream's rather than the client's. A test that read the receipt back
 * and compared it with what the gateway remembered would prove nothing about that, because the gateway
 * remembers the bytes it hashed, not the bytes a stranger received. So nothing here reads the gateway's
 * own bookkeeping: the response is taken as `rawPayload`, the items are framed from it by the shipped
 * `frameResponse`, and the payload has to agree.
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

/**
 * A backend that hands over these exact bytes in these exact pieces. The splits are the point of the
 * helper: a write boundary is a transport's choice and none of the digests may depend on it, so the same
 * body is run through several and every one has to issue the identical item list.
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
          for (const piece of pieces) yield piece;
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
  return { name: 'stepping clock', uncertaintySeconds: 2, now: () => start + (ticks += 1) };
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
        now: () => CLOCK_SECONDS - (reads += 1),
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

describe('the two disclosures a v3 payload states', () => {
  it('names the wired source and its bound, and defaults neither', async () => {
    const h = await open({
      backend: bodyBackend(UPSTREAM_BUFFERED, 'application/json'),
      time: { name: 'lab bench one', uncertaintySeconds: 3, now: () => CLOCK_SECONDS },
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
    // Both halves are stated, and the absence of one is never read in place of the other. The reader
    // hands them back under the names the format gives the slots, which is where `col` and `val` live.
    expect(Object.keys(anchor).sort()).toEqual(['collateral', 'validity']);
  });

  it('carries the three members of a v3 together, each named and none of them defaulted', async () => {
    const h = await open({
      backend: bodyBackend(UPSTREAM_STREAM, 'text/event-stream'),
      time: { name: 'wired at issuance', uncertaintySeconds: 0, now: () => CLOCK_SECONDS },
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
