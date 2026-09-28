import { describe, expect, it } from 'vitest';
import { ResponseItemFramer, extractMarkedRegion, isEventStream } from '@ashaveri/receipt';
import type { ChatCompletionRequest } from '../src/mock.js';
import { upstreamBackend } from '../src/upstream.js';
import { MarkedStreamTail, markingFrame } from '../src/marking.js';

/**
 * One response body, read by every module in this estate that reads it, on the same bytes.
 *
 * Four modules walk the bytes of a streamed completion and each reaches a conclusion. The item framing in
 * `packages/receipt/src/response-items.ts` decides which spans are items and which frame is the sentinel,
 * because a `v: 3` payload digests them. The usage scan in `gateway/src/upstream.ts` decides which frames
 * carry a completion it has to meter. The extraction rule in `packages/receipt/src/marking.ts` decides
 * which span `mk.d` is the digest of. And `gateway/src/marking.ts` decides at which byte of the stream a
 * mark may go. They read one byte string, so on any body they have to agree about where its frames are: a
 * receipt that attests one reading while another counts frames differently is a document that disagrees
 * with itself about what was said. This file is where that agreement is measured rather than asserted.
 *
 * Two of the questions are not the same question, and the rows where they part say so in their own note:
 *
 * - The item framing reads a response a line at a time, so it attests a `data:` frame whose event was
 *   never dispatched, including the final frame of a body that ends mid-line. Those bytes were sent, `res`
 *   covers them, and section 3.1 of `docs/receipt-spec.md` publishes that reading.
 * - The usage scan reads a stream a dispatch at a time, because the JSON inside an event is knowable only
 *   once the blank line closes it. Its list is therefore shorter than the item list on exactly the rows
 *   where a body never wrote the blank line, which is `parsed: []` beside a list of items, and which the
 *   line feed row and the carriage return row of one shape state together so that the difference is on the
 *   model rather than on a terminator.
 *
 * The line endings are the part that is one question. A line feed, a carriage return, and that pair
 * together each end a line: section 3.1 states it, the item framing implements it, and a body framed with
 * carriage returns has to give every reader the frames it gives a client holding those bytes. The rows
 * whose separator is a bare carriage return are written to fail rather than to record, because a reader
 * that stops seeing frames when a terminator is not a line feed has stopped metering completions and
 * stopped finding its own mark.
 */

const LF = '\n';
const CRLF = '\r\n';
const CR = '\r';
const DONE = '[DONE]';
const STREAMED = 'text/event-stream';
const MARK_AT = 1772000000;
const MODEL = 'mock-model-1';

/** The frame a marked stream writes: the bytes on the wire, and the line inside them that `mk.d` digests. */
const MARK = markingFrame(MODEL, MARK_AT);
const MARK_TEXT = new TextDecoder().decode(MARK.frame);
const MARK_LINE = new TextDecoder().decode(MARK.line);
const MARK_PAYLOAD = MARK_LINE.slice('data: '.length);

/** The refusal the framing answers with for a stream that sent no data frame at all. */
const NO_FRAME = 'the response sent no data frame, so it states nothing for an item to attest';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** One `data:` frame of a body: its payload, what ends its line, and whether the space is written. */
interface Frame {
  readonly payload: string;
  readonly sep: string;
  /** `false` writes `data:{payload}`, the other spelling a conforming client reads as one field. */
  readonly space?: boolean;
}

interface ReaderCase {
  readonly name: string;
  /** What the row is for, and where the reading it expects is published. */
  readonly note: string;
  readonly frames: readonly Frame[];
  /** Byte offsets at which one write ended and the next began, to split a token or a terminator. */
  readonly cuts?: readonly number[];
  /** Reader 1, the item framing: each item's payload in order, or `null` for the refusal. */
  readonly items: readonly string[] | null;
  /** Reader 2, the usage scan: the 1-based indices of frames whose payload reaches `JSON.parse`. */
  readonly parsed: readonly number[];
  /** Reader 2's settled `completion_tokens`: the position of the first frame it metered, or 0 for none. */
  readonly metered: number;
  /** Reader 2 again: whether consuming the body as written threw, which is what a sentinel must never do. */
  readonly scanThrows: boolean;
  /** Reader 3, the extraction rule: how many marking-shaped `data:` lines the body holds. */
  readonly markLines: number;
  /** Reader 4, the marked tail: the byte of the response the mark frame is written at. */
  readonly markAt: number;
}

/** A body as its row renders it, optionally with other payloads in the same framing. */
function bodyOf(frames: readonly Frame[], payloads?: readonly string[]): string {
  return frames
    .map((frame, index) => `data:${frame.space === false ? '' : ' '}${payloads?.[index] ?? frame.payload}${frame.sep}`)
    .join('');
}

/** The same body, as the writes the row names hand it over. */
function piecesOf(body: string, cuts: readonly number[]): string[] {
  const out: string[] = [];
  let at = 0;
  for (const cut of [...cuts, body.length]) {
    out.push(body.slice(at, cut));
    at = cut;
  }
  return out;
}

function writesOf(body: string, cuts: readonly number[]): Uint8Array[] {
  return piecesOf(body, cuts).map((piece) => encoder.encode(piece));
}

/** The payload text of every frame in a row, so a note can speak of the sentinel frames it holds. */
function dataFrames(caseItem: ReaderCase): number {
  return caseItem.frames.filter((frame) => !frame.payload.startsWith(DONE)).length;
}

/**
 * Reader 1, the item framing, fed the row's writes in order.
 *
 * An item is named by its payload text and by the span of the body those bytes are, because "which bytes
 * belong to which frame" is one of the three questions this table asks and a payload text cannot answer it
 * on a body that says one thing twice.
 */
function readerItems(body: string, writes: readonly Uint8Array[]): string {
  const framer = new ResponseItemFramer(isEventStream(STREAMED));
  for (const write of writes) framer.feed(write);
  const outcome = framer.finish();
  if (!outcome.framed) return `refused: ${outcome.why}`;
  return JSON.stringify(spansOf(body, outcome.items.map((item) => decoder.decode(item.bytes))));
}

/** The same shape, built from a list of payload texts and the body's own bytes, with no framing in sight. */
function spansOf(body: string, payloads: readonly string[]): { text: string; at: number; width: number }[] {
  let cursor = 0;
  return payloads.map((text) => {
    const at = body.indexOf(text, cursor);
    if (at < 0) throw new Error(`${JSON.stringify(body)} holds no ${JSON.stringify(text)} at or after ${cursor}`);
    cursor = at + text.length;
    return { text, at, width: text.length };
  });
}

/** Every non-sentinel frame rewritten as a chunk carrying usage, numbered by the frame's own position. */
function meteringPayloads(caseItem: ReaderCase): string[] {
  return caseItem.frames.map((frame, index) =>
    frame.payload.startsWith(DONE)
      ? frame.payload
      : JSON.stringify({
          model: MODEL,
          choices: [{ index: 0, delta: { content: 'x' }, finish_reason: null }],
          usage: { prompt_tokens: 1, completion_tokens: index + 1 },
        }),
  );
}

interface ScanOutcome {
  readonly threw: boolean;
  readonly completionTokens: number;
  readonly forwardedWholeBody: boolean;
}

/** Reader 2, the usage scan, driven through its own backend over the row's bytes. */
async function runUpstream(body: string, writes: readonly Uint8Array[]): Promise<ScanOutcome> {
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      for (const write of writes) controller.enqueue(write);
      controller.close();
    },
  });
  const backend = upstreamBackend({
    baseUrl: 'http://inference.test/v1',
    fetchImpl: (async () =>
      new Response(stream, { status: 200, headers: { 'content-type': STREAMED } })) as typeof fetch,
  });
  const request: ChatCompletionRequest = { model: MODEL, messages: [{ role: 'user', content: 'hi' }], stream: true };
  try {
    const response = await backend.respond(Buffer.from(JSON.stringify({ model: MODEL })), request);
    let seen = new Uint8Array(0);
    for await (const chunk of response.chunks) seen = new Uint8Array([...seen, ...chunk]);
    const usage = await response.usage;
    return { threw: false, completionTokens: usage.completionTokens, forwardedWholeBody: decoder.decode(seen) === body };
  } catch {
    return { threw: true, completionTokens: 0, forwardedWholeBody: false };
  }
}

/**
 * What the usage scan makes of one frame, taken apart from what it makes of the others.
 *
 * A payload is the only part of a frame the scan parses, so the row's framing is kept byte for byte and
 * one frame at a time is rewritten as bytes no JSON parser accepts. That run throws exactly when the scan
 * reached the frame: a frame whose line a reader drops on the way, or whose event was never dispatched,
 * leaves the body consumable. The sentinel is read out of `scanThrows` instead, because reaching it is the
 * one outcome in which nothing throws.
 */
async function scanReaches(caseItem: ReaderCase, index: number): Promise<boolean> {
  const payloads = meteringPayloads(caseItem).map((payload, each) => (each === index ? '{unterminated' : payload));
  const body = bodyOf(caseItem.frames, payloads);
  return (await runUpstream(body, writesOf(body, caseItem.cuts ?? []))).threw;
}

/** Reader 3, the extraction rule, on a body whose every data frame carries the mark's shape. */
function readerRegions(caseItem: ReaderCase): { count: number; region: string | null } {
  const body = bodyOf(
    caseItem.frames,
    caseItem.frames.map((frame) => (frame.payload.startsWith(DONE) ? DONE : MARK_PAYLOAD)),
  );
  try {
    // One region is all a `provenance-v1` receipt answers with, so a body that carries the shape more than
    // once is counted through the `none` refusal, which states the number it found.
    return { count: 1, region: decoder.decode(extractMarkedRegion('provenance-v1', encoder.encode(body))) };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    const counted = /carries (\d+) regions matching provenance-v1/u.exec(message)?.[1];
    if (counted !== undefined) return { count: Number(counted), region: null };
    if (/carries no region matching/u.test(message)) return { count: 0, region: null };
    throw new Error(`the extraction rule answered with something this table cannot read: ${message}`);
  }
}

/**
 * Reader 4, the marked tail: the byte of the response at which the mark frame lands in what a client is
 * sent, and the whole body still there around it.
 *
 * The insertion offset is where that module's question is answered: it holds a stream back until it knows
 * whether these bytes end on the sentinel, and its purpose is to write the mark inside the stream rather
 * than after it. An offset equal to the body's length is the answer for a body that does not end on a
 * sentinel, which is the case section 3.1 settles: what follows a sentinel is still a response.
 */
function readerTail(body: string, cuts: readonly number[]): { at: number; lost: string | null } {
  const tail = new MarkedStreamTail();
  let sent = '';
  for (const write of writesOf(body, cuts)) sent += decoder.decode(tail.writable(write));
  const whole = sent + tail.finishing(MARK.frame).map((piece) => decoder.decode(piece)).join('');
  const at = whole.indexOf(MARK_TEXT);
  const rebuilt = whole.slice(0, at) + whole.slice(at + MARK_TEXT.length);
  return { at, lost: rebuilt === body ? null : `the client was sent ${JSON.stringify(rebuilt)}` };
}

const ROWS: readonly ReaderCase[] = [
  {
    name: 'line feeds only, three frames, the last of them the sentinel',
    note: 'the spelling this gateway writes, and the reading every other row is measured against',
    frames: [
      { payload: '{"a":1}', sep: `${LF}${LF}` },
      { payload: '{"b":2}', sep: `${LF}${LF}` },
      { payload: DONE, sep: `${LF}${LF}` },
    ],
    items: ['{"a":1}', '{"b":2}'],
    parsed: [1, 2, 3],
    metered: 1,
    scanThrows: false,
    markLines: 2,
    markAt: 30,
  },
  {
    name: 'carriage return line feed pairs only',
    note: 'the pair is one ending and not two, so this body holds the same three frames as the line feed row above',
    frames: [
      { payload: '{"a":1}', sep: `${CRLF}${CRLF}` },
      { payload: '{"b":2}', sep: `${CRLF}${CRLF}` },
      { payload: DONE, sep: `${CRLF}${CRLF}` },
    ],
    items: ['{"a":1}', '{"b":2}'],
    parsed: [1, 2, 3],
    metered: 1,
    scanThrows: false,
    markLines: 2,
    markAt: 34,
  },
  {
    name: 'bare carriage returns, and no blank line anywhere',
    note: 'the framing attests every line it was sent while the usage scan is still waiting for the dispatch this body never wrote, so `parsed` is empty by the stream model. Read beside the line feed row of this same shape, below.',
    frames: [
      { payload: '{"a":1}', sep: CR },
      { payload: '{"b":2}', sep: CR },
      { payload: DONE, sep: CR },
    ],
    items: ['{"a":1}', '{"b":2}'],
    parsed: [],
    metered: 0,
    scanThrows: false,
    markLines: 2,
    markAt: 28,
  },
  {
    name: 'line feeds, and no blank line anywhere',
    note: 'the companion row: one event whose dispatch never arrived, spelled in the terminator nobody disputes, so that the row above is about the model and not about a carriage return',
    frames: [
      { payload: '{"a":1}', sep: LF },
      { payload: '{"b":2}', sep: LF },
      { payload: DONE, sep: LF },
    ],
    items: ['{"a":1}', '{"b":2}'],
    parsed: [],
    metered: 0,
    scanThrows: false,
    markLines: 2,
    markAt: 28,
  },
  {
    name: 'bare carriage returns as frame endings and as blank lines',
    note: 'two carriage returns end an empty line, which dispatches the event above it, so every reader has to meter, attest and mark the same three frames the line feed body gives',
    frames: [
      { payload: '{"a":1}', sep: `${CR}${CR}` },
      { payload: '{"b":2}', sep: `${CR}${CR}` },
      { payload: DONE, sep: `${CR}${CR}` },
    ],
    items: ['{"a":1}', '{"b":2}'],
    parsed: [1, 2, 3],
    metered: 1,
    scanThrows: false,
    markLines: 2,
    markAt: 30,
  },
  {
    name: 'three terminator spellings in one body',
    note: 'a response may mix them frame by frame: a line feed and a carriage return, then the pair twice, then the pair again. A scan that reads line feeds alone and keeps a carriage return as content loses the frame written behind the ending it did not recognise.',
    frames: [
      { payload: '{"a":1}', sep: `${LF}${CR}` },
      { payload: '{"b":2}', sep: `${CRLF}${CRLF}` },
      { payload: DONE, sep: `${LF}${LF}` },
    ],
    items: ['{"a":1}', '{"b":2}'],
    parsed: [1, 2, 3],
    metered: 1,
    scanThrows: false,
    markLines: 2,
    markAt: 32,
  },
  {
    name: 'the sentinel mid-body, with a data frame after it',
    note: 'section 3.1 states that what follows a sentinel is still a response and one more item: the framing attests its bytes, the usage scan parses them, and the tail, whose question is whether the body ends on the sentinel, answers that it does not and writes its mark last',
    frames: [
      { payload: '{"a":1}', sep: `${LF}${LF}` },
      { payload: DONE, sep: `${LF}${LF}` },
      { payload: '{"b":2}', sep: `${LF}${LF}` },
    ],
    items: ['{"a":1}', '{"b":2}'],
    parsed: [1, 2, 3],
    metered: 1,
    scanThrows: false,
    markLines: 2,
    markAt: 44,
  },
  {
    name: 'the sentinel with a carriage return of its own before the pair',
    note: 'the carriage return ends the sentinel line, so `[DONE]` is what that frame said and nothing is left to parse. A scan that reads only line feeds hands `[DONE]` plus a carriage return to a JSON parser and takes the response down with it.',
    frames: [
      { payload: '{"a":1}', sep: `${LF}${LF}` },
      { payload: `${DONE}${CR}`, sep: `${CRLF}${CRLF}` },
    ],
    items: ['{"a":1}'],
    parsed: [1, 2],
    metered: 1,
    scanThrows: false,
    markLines: 1,
    markAt: 15,
  },
  {
    name: 'the sentinel ended by a bare carriage return and nothing after it',
    note: 'a response need not write a blank line after its last terminator for that terminator to have arrived, and a carriage return is the ending that says so',
    frames: [
      { payload: '{"a":1}', sep: CR },
      { payload: DONE, sep: CR },
    ],
    items: ['{"a":1}'],
    parsed: [],
    metered: 0,
    scanThrows: false,
    markLines: 1,
    markAt: 14,
  },
  {
    name: 'a stream that sent the sentinel and nothing else',
    note: 'the framing refuses rather than answering with an empty list, which is an answer, and the two scans and the tail each do their work on a stream that said nothing',
    frames: [{ payload: DONE, sep: `${LF}${LF}` }],
    items: null,
    parsed: [1],
    metered: 0,
    scanThrows: false,
    markLines: 0,
    markAt: 0,
  },
  {
    name: 'the sentinel split across two writes',
    note: 'a write boundary inside the six letters of `[DONE]` settles nothing until the line ending does, so all four readers answer as they do for the same bytes in one piece',
    frames: [
      { payload: '{"a":1}', sep: `${LF}${LF}` },
      { payload: DONE, sep: `${LF}${LF}` },
    ],
    cuts: [25],
    items: ['{"a":1}'],
    parsed: [1, 2],
    metered: 1,
    scanThrows: false,
    markLines: 1,
    markAt: 15,
  },
  {
    name: 'a frame terminator split across two writes',
    note: 'the blank line that dispatches an event may straddle a write, and a pair broken between its two line feeds is still one blank line',
    frames: [
      { payload: '{"a":1}', sep: `${LF}${LF}` },
      { payload: '{"b":2}', sep: `${LF}${LF}` },
      { payload: DONE, sep: `${LF}${LF}` },
    ],
    cuts: [14],
    items: ['{"a":1}', '{"b":2}'],
    parsed: [1, 2, 3],
    metered: 1,
    scanThrows: false,
    markLines: 2,
    markAt: 30,
  },
  {
    name: 'a carriage return line feed pair split across two writes',
    note: 'one write ends on the carriage return and the next begins with the line feed it belongs to. Read as two endings that is an empty line, which names no item and meters nothing new.',
    frames: [
      { payload: '{"a":1}', sep: `${CRLF}${CRLF}` },
      { payload: DONE, sep: `${CRLF}${CRLF}` },
    ],
    cuts: [14],
    items: ['{"a":1}'],
    parsed: [1, 2],
    metered: 1,
    scanThrows: false,
    markLines: 1,
    markAt: 17,
  },
  {
    name: 'the field name with no space after the colon',
    note: 'the one space is framing where it is written and content where it is not, and no reader takes the second spelling for a different frame',
    frames: [
      { payload: '{"a":1}', sep: `${LF}${LF}`, space: false },
      { payload: DONE, sep: `${LF}${LF}`, space: false },
    ],
    items: ['{"a":1}'],
    parsed: [1, 2],
    metered: 1,
    scanThrows: false,
    markLines: 1,
    markAt: 14,
  },
  {
    name: 'two data lines in one block, separated by a bare carriage return',
    note: 'one event holding two frames, which is the case where the endings between the lines matter as much as the one that dispatched them: a split that reads only line feeds hands the second line to the scan with a carriage return in front of it, and a line that starts with one is not a `data:` field at all',
    frames: [
      { payload: '{"a":1}', sep: CR },
      { payload: '{"b":2}', sep: `${CR}${CR}` },
    ],
    items: ['{"a":1}', '{"b":2}'],
    parsed: [1, 2],
    metered: 1,
    scanThrows: false,
    markLines: 2,
    markAt: 29,
  },
  {
    name: 'a final frame whose terminator never arrived',
    note: 'the bytes were sent, so the framing attests them and `res` covers them, while the usage scan is still waiting for an event that was never dispatched: this is the one row where the two lists differ by design, and section 3.1 states which of the two the receipt is built from',
    frames: [
      { payload: '{"a":1}', sep: `${LF}${LF}` },
      { payload: '{"b":2}', sep: '' },
    ],
    items: ['{"a":1}', '{"b":2}'],
    parsed: [1],
    metered: 1,
    scanThrows: false,
    markLines: 2,
    markAt: 28,
  },
];

describe('four readers of one response body, on the same bytes', () => {
  it('states an answer from every reader for every row, so the table cannot pass by silence', () => {
    // The guard against a table that agrees because nobody answered: each row carries a value for each of
    // the four readers, including the empty list, the zero and the body's own length, and each of those
    // values is checked here for being an answer at all before the four runs below compare it to a module.
    expect(ROWS).toHaveLength(16);
    for (const caseItem of ROWS) {
      const body = bodyOf(caseItem.frames);
      expect(caseItem.name.length, 'a row is named by what it is').toBeGreaterThan(12);
      expect(caseItem.note.length, `${caseItem.name}: a row says why it is here`).toBeGreaterThan(30);
      expect(caseItem.items === null || caseItem.items.length > 0, `${caseItem.name}: reader 1 answers`).toBe(true);
      expect(caseItem.parsed.length, `${caseItem.name}: reader 2 parses no phantom frame}`).toBeLessThanOrEqual(
        caseItem.frames.length,
      );
      expect(caseItem.metered === 0 || caseItem.parsed.length > 0, `${caseItem.name}: a metered frame is a parsed one`).toBe(
        true,
      );
      expect(caseItem.markLines, `${caseItem.name}: reader 3 counts no line the body does not hold}`).toBeLessThanOrEqual(
        dataFrames(caseItem),
      );
      expect(caseItem.markAt, `${caseItem.name}: reader 4 writes inside the body it was sent`).toBeLessThanOrEqual(
        body.length,
      );
      expect(body.length, `${caseItem.name}: the body is bytes`).toBeGreaterThan(0);
    }
  });

  for (const caseItem of ROWS) {
    describe(caseItem.name, () => {
      const body = bodyOf(caseItem.frames);
      const writes = writesOf(body, caseItem.cuts ?? []);

      it('renders the bytes the row names, in the writes the row names', () => {
        // Every answer below is about these bytes, so a row that rendered to other bytes than the ones its
        // expectations were written against would agree with the code by accident rather than by rule.
        const pieces = piecesOf(body, caseItem.cuts ?? []);
        expect(pieces).toHaveLength((caseItem.cuts ?? []).length + 1);
        expect(pieces.join('')).toBe(body);
        expect(writes.map((write) => decoder.decode(write))).toEqual(pieces);
        expect(writes.reduce((total, write) => total + write.length, 0)).toBe(body.length);
        for (const cut of caseItem.cuts ?? []) {
          expect(cut, 'a write boundary is inside the body').toBeGreaterThan(0);
          expect(cut, 'a write boundary is inside the body').toBeLessThan(body.length);
        }
      });

      it('reader 1, the item framing, attests these payloads at these offsets or refuses', () => {
        const expected =
          caseItem.items === null ? `refused: ${NO_FRAME}` : JSON.stringify(spansOf(body, caseItem.items));
        expect(readerItems(body, writes)).toBe(expected);
      });

      it('reader 2, the usage scan, parses exactly these frames and meters the first of them', async () => {
        const reached: number[] = [];
        for (let index = 0; index < caseItem.frames.length; index += 1) {
          if (await scanReaches(caseItem, index)) reached.push(index + 1);
        }
        expect(reached, 'frames whose payload reached JSON.parse').toEqual([...caseItem.parsed]);
        const metered = bodyOf(caseItem.frames, meteringPayloads(caseItem));
        const run = await runUpstream(metered, writesOf(metered, caseItem.cuts ?? []));
        expect(run.threw, 'a body of chunks a client can parse throws nothing').toBe(false);
        expect(run.completionTokens, 'the settled completion tokens name the frame metered').toBe(caseItem.metered);
        expect(run.forwardedWholeBody, 'the client is sent every byte of the response').toBe(true);
      });

      it('reader 2 again, on the bytes as a response wrote them, parses no terminator', async () => {
        // The same scan over the row's own payloads, which is where `[DONE]` is a token rather than a
        // document: a scan that keeps a carriage return inside the value it compares reaches `JSON.parse`
        // with `[DONE]` and a carriage return, and the failure is the whole stream and not one frame of it.
        const run = await runUpstream(body, writes);
        expect(run.threw).toBe(caseItem.scanThrows);
        expect(run.forwardedWholeBody, 'the client is sent every byte of the response').toBe(!caseItem.scanThrows);
      });

      it('reader 3, the extraction rule, counts these data lines and names the mark line', () => {
        const regions = readerRegions(caseItem);
        expect(regions.count, 'data lines the extraction rule counts').toBe(caseItem.markLines);
        if (caseItem.markLines === 1) {
          // The region is the whole field line, prefix included and terminator excluded, whichever
          // spelling of the terminator the response used: that span is what `mk.d` is a digest of.
          expect(regions.region, 'the region the rule names').toBe(
            `data:${caseItem.frames[0]?.space === false ? '' : ' '}${MARK_PAYLOAD}`,
          );
        }
      });

      it('reader 4, the marked tail, writes its mark at this byte and loses no byte of the response', () => {
        const tail = readerTail(body, caseItem.cuts ?? []);
        expect(tail.lost, 'the bytes a client is sent').toBeNull();
        expect(tail.at, 'where the mark frame was written').toBe(caseItem.markAt);
      });
    });
  }
});
