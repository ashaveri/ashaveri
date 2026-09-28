import { describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  EMPTY_BODY_SHA256_HEX,
  ReceiptError,
  ResponseItemDigestFramer,
  ResponseItemFramer,
  SSE_DATA_FIELD,
  SSE_DONE_VALUE,
  frameResponse,
  fromBase64Url,
  isEventStream,
  toHex,
  type ResponseItem,
  type ResponseItemDigestFraming,
  type ResponseItemFraming,
} from '../src/index.js';
import {
  FRAMED_LINE_SHA256_HEX,
  FRAME_CASES,
  NO_FRAME_REASON,
  PUBLISHED_FRAMING_BYTES,
  PUBLISHED_ITEM_SHA256_HEX,
  STREAMED,
  WHOLE_BODY_SHA256_HEX,
  itemDigestHex,
  framingText,
  type FrameCase,
} from './response-item-cases.js';

/**
 * What the framing of a response is, checked against bytes whose digests were written down away from
 * this code. See `response-item-cases.ts` for the material and for why its literals are external;
 * `response-items-split.test.ts` holds the companion claim, that none of this depends on how the bytes
 * were delivered.
 */

const vectorsPath = fileURLToPath(new URL('../../fixtures/data/res-v1.json', import.meta.url));
const markingSourcePath = fileURLToPath(new URL('../../../gateway/src/marking.ts', import.meta.url));

/** The escape sequences a source file spells out, turned back into the bytes they stand for. */
function unescapeSource(literal: string | undefined): string {
  if (literal === undefined) throw new Error('marking.ts no longer declares the frame end in a readable spelling');
  return literal.replace(/\\r/g, '\r').replace(/\\n/g, '\n');
}

function bytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

function textOf(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

/** sha256 from `node:crypto`: a second implementation, used only where a literal would be too long. */
function otherSha256Hex(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

function framed(caseItem: FrameCase): readonly ResponseItem[] {
  const outcome = frameResponse(caseItem.contentType, bytes(caseItem.body));
  if (!outcome.framed) throw new Error(`${caseItem.name}: refused where items were expected, "${outcome.why}"`);
  return outcome.items;
}

/** The answer for two frames, the second of them a payload no terminator closed, in one comparable string. */
const TWO_ITEMS = `${itemDigestHex('{"a":1}')}<{"a":1}>|${itemDigestHex('{"b":2}')}<{"b":2}>`;

/** The answer for one body that was never framed at all. */
const ONE_BUFFERED_ITEM = `${itemDigestHex('{"a":1}')}<{"a":1}>`;

function refusal(caseItem: FrameCase): string {
  const outcome = frameResponse(caseItem.contentType, bytes(caseItem.body));
  if (outcome.framed) {
    throw new Error(`${caseItem.name}: framed ${outcome.items.length} items where a refusal was expected`);
  }
  return outcome.why;
}

/** Where each item's bytes sit in the response, found by walking forward and never overlapping. */
function offsetsOf(body: Uint8Array, items: readonly ResponseItem[]): number[] {
  const offsets: number[] = [];
  let cursor = 0;
  for (const item of items) {
    let at = -1;
    for (let guess = cursor; guess + item.bytes.length <= body.length; guess += 1) {
      let same = true;
      for (let i = 0; i < item.bytes.length; i += 1) {
        if (body[guess + i] !== item.bytes[i]) {
          same = false;
          break;
        }
      }
      if (same) {
        at = guess;
        break;
      }
    }
    if (at < 0) throw new Error(`an item's bytes are not in the response they were framed from`);
    offsets.push(at);
    cursor = at + item.bytes.length;
  }
  return offsets;
}

describe('the framing rule', () => {
  for (const caseItem of FRAME_CASES.filter((one) => one.items.length > 0)) {
    it(`${caseItem.name}: ${caseItem.items.length} item${caseItem.items.length === 1 ? '' : 's'} with the payloads and digests written down for them`, () => {
      const items = framed(caseItem);
      expect(items.map((item) => textOf(item.bytes))).toEqual([...caseItem.items]);
      expect(items.map((item) => toHex(item.d))).toEqual(caseItem.items.map(itemDigestHex));
    });
  }

  for (const caseItem of FRAME_CASES.filter((one) => one.items.length === 0)) {
    it(`${caseItem.name}: a refusal that names its reason, and no list to be read as a claim`, () => {
      expect(refusal(caseItem)).toBe(NO_FRAME_REASON);
    });
  }

  it('refuses an empty stream once, rather than handing back a list a reader would have to trust', () => {
    const outcome = frameResponse(STREAMED, new Uint8Array(0));
    expect(outcome.framed).toBe(false);
    expect('items' in outcome).toBe(false);
  });

  it('reads the declared content type and not the shape of the bytes', () => {
    const looked = frameResponse('application/json', bytes('data: {"a":1}\n\ndata: [DONE]\n\n'));
    if (!looked.framed) throw new Error('a buffered body was refused');
    expect(looked.items).toHaveLength(1);
    expect(textOf(looked.items[0]!.bytes)).toBe('data: {"a":1}\n\ndata: [DONE]\n\n');

    expect(isEventStream('text/event-stream')).toBe(true);
    expect(isEventStream('text/event-stream; charset=utf-8')).toBe(true);
    expect(isEventStream('application/json')).toBe(false);
    expect(isEventStream('application/json; charset=utf-8')).toBe(false);
  });

  it('never refuses a buffered body, whatever it holds', () => {
    for (const body of ['', ' ', '{}']) {
      const outcome = frameResponse('application/json', bytes(body));
      if (!outcome.framed) throw new Error(`a buffered body of ${JSON.stringify(body)} was refused`);
      expect(outcome.items).toHaveLength(1);
      expect(textOf(outcome.items[0]!.bytes)).toBe(body);
    }
    const empty = frameResponse('application/json', new Uint8Array(0));
    if (!empty.framed) throw new Error('an empty buffered body was refused');
    expect(toHex(empty.items[0]!.d)).toBe(EMPTY_BODY_SHA256_HEX);
  });

  it('holds a frame open until its line ending arrives, so a sentinel split down its middle is still one', () => {
    // The byte at which a `[DONE]` happens to be complete is a transport fact. Here the token arrives
    // in two pieces and its frame is still the terminator rather than a payload, which leaves the
    // stream having said nothing, and nothing is the case this refuses rather than lists.
    const framer = new ResponseItemFramer(true);
    framer.feed(bytes('data: [DO'));
    framer.feed(bytes('NE]\n\n'));
    const outcome = framer.finish();
    expect(outcome).toEqual({ framed: false, why: NO_FRAME_REASON });
  });

  it('answers a second finish with the answer it gave the first, in both shapes of response', () => {
    // `finish()` reads what the buffer still holds: the last frame of a stream whose terminator never
    // arrived, and the whole of a buffered body. Asked twice, either reading taken again would add a fact
    // the response never said, a stream duplicating its last item and a buffered body stating a second
    // item beside the one that is all of it.
    const streamed = new ResponseItemFramer(true);
    streamed.feed(bytes('data: {"a":1}\n\ndata: {"b":2}'));
    const once = framingText(streamed.finish());
    expect(once).toBe(TWO_ITEMS);
    expect(framingText(streamed.finish())).toBe(once);

    const buffered = new ResponseItemFramer(false);
    buffered.feed(bytes('{"a":1}'));
    const firstBuffered = framingText(buffered.finish());
    expect(firstBuffered).toBe(ONE_BUFFERED_ITEM);
    expect(framingText(buffered.finish())).toBe(firstBuffered);
  });
});

describe('one framer answers one response', () => {
  /** Everything a caller can observe about an answer, taken before a refused chunk and again after it. */
  function shapeOf(outcome: ResponseItemFraming): string {
    if (!outcome.framed) return `refused: ${outcome.why}`;
    const decoder = new TextDecoder();
    return JSON.stringify({
      length: outcome.items.length,
      frozen: Object.isFrozen(outcome.items),
      items: outcome.items.map((item) => ({ payload: decoder.decode(item.bytes), d: toHex(item.d).slice(0, 12) })),
    });
  }

  /** The refusal a second response's bytes reach, taken apart from the error class it carries. */
  function refused(action: () => unknown): ReceiptError {
    try {
      action();
    } catch (err) {
      if (err instanceof ReceiptError) return err;
      throw new Error(`the call refused something this is not: ${String(err)}`);
    }
    throw new Error('a chunk after the answer was accepted, which is the failure this file exists to stop');
  }

  it('refuses a chunk fed after the answer, and the answer the caller holds does not change shape', () => {
    // The half the guard has to be witnessed by: one frame read, the answer taken, and then a second
    // response's two frames handed to the same instance. Without the refusal the caller's array grows from
    // one item to three, because `finish()` hands out the very list the framer appends to.
    const framer = new ResponseItemFramer(true);
    framer.feed(bytes('data: {"a":1}\n\n'));
    const answer = framer.finish();
    const before = shapeOf(answer);
    expect(before).toContain('"length":1');

    const err = refused(() => framer.feed(bytes('data: {"b":2}\n\ndata: [DONE]\n\n')));
    expect(err.code).toBe('FRAMER_REUSED');
    expect(shapeOf(answer)).toBe(before);
    expect(shapeOf(framer.finish())).toBe(before);
    expect(framer.finish()).toBe(answer);
  });

  it('refuses the same call on a buffered body, where the answer would not have moved', () => {
    // A buffered body is read whole at `finish()`, so a later chunk changes nothing observable about the
    // item already given: the single bytes of a buffered response stay the single bytes. The refusal is
    // about the instance's lifetime and not about which arm was hurt, so both arms answer the same way.
    const framer = new ResponseItemFramer(false);
    framer.feed(bytes('{"a":1}'));
    const answer = framer.finish();
    const before = shapeOf(answer);
    expect(before).toContain('"length":1');
    expect(refused(() => framer.feed(bytes('{"b":2}'))).code).toBe('FRAMER_REUSED');
    expect(shapeOf(answer)).toBe(before);
  });

  it('names the bytes it refused and the framer to use instead', () => {
    // The caller is a gateway deciding what to issue, and the sentence has to say which of its own calls
    // was wrong and what to do about it: a code with no fact in the message sends whoever reads the log
    // back to this file. The code itself is on the error, which is what a caller branches on.
    const framer = new ResponseItemFramer(true);
    framer.feed(bytes('data: {"a":1}\n\n'));
    framer.finish();
    const err = refused(() => framer.feed(bytes('data: {"b":2}\n\n')));
    expect(err.code).toBe('FRAMER_REUSED');
    expect(err.message).toContain('the response item framer was fed a chunk after its answer was taken');
    expect(err.message).toContain('15 bytes arrived');
    expect(err.message).toContain('finish()');
    expect(err.message).toContain('ResponseItemFramer');
  });

  it('closes the published list to whoever holds it, and states what the freeze cannot reach', () => {
    // The guard refuses this framer; the freeze refuses the array. A copy at `finish()` would have left
    // this instance's own list writable, so the answer a caller received would be a view of a list still
    // being written rather than a statement about the bytes that ended.
    const framer = new ResponseItemFramer(true);
    framer.feed(bytes('data: {"a":1}\n\n'));
    const answer = framer.finish();
    if (!answer.framed) throw new Error('a framed stream was refused');
    const items = answer.items as ResponseItem[];
    expect(Object.isFrozen(items)).toBe(true);
    expect(() => items.push(items[0]!)).toThrow(TypeError);
    expect(items).toHaveLength(1);
    // What the freeze does not reach is an item's own bytes: a typed array holding elements cannot be
    // frozen, so this writes over the copy the answer owns. The digest does not move with it, because an
    // item's `d` is the digest of the bytes that were framed and not a view recomputed on demand, so the
    // two parts of one item disagree in the open rather than the answer quietly becoming a statement
    // about bytes no response sent. That is the residual the decision was written against: a holder can
    // unmake its own reading, and no rule stops it, but an answer cannot change under one that never
    // touched it.
    items[0]!.bytes.fill(0x5a);
    expect(textOf(items[0]!.bytes)).toBe('ZZZZZZZ');
    expect(toHex(items[0]!.d)).toBe(itemDigestHex('{"a":1}'));
    expect(otherSha256Hex(items[0]!.bytes)).not.toBe(toHex(items[0]!.d));
  });

  it('frames a whole response in one call, which is the path that cannot reach the refusal', () => {
    // `frameResponse` builds a framer, feeds it once and answers from it, so the rule that a framer serves
    // one response holds of it by construction. This is the shape a verifier holding a body uses, and a
    // guard that fired here would refuse the reading of bytes that were never streamed.
    const outcome = frameResponse(STREAMED, bytes('data: {"a":1}\n\ndata: [DONE]\n\n'));
    if (!outcome.framed) throw new Error('a framed stream was refused');
    expect(outcome.items.map((item) => textOf(item.bytes))).toEqual(['{"a":1}']);
    expect(Object.isFrozen(outcome.items)).toBe(true);
  });
});

describe('what an item digest covers', () => {
  it('covers the payload alone: not the prefix, not the terminator, not the response', () => {
    const caseItem = FRAME_CASES[0]!;
    const items = framed(caseItem);
    expect(toHex(items[0]!.d)).toBe(itemDigestHex('{"a":1}'));
    expect(toHex(items[0]!.d)).not.toBe(FRAMED_LINE_SHA256_HEX);
    expect(toHex(items[0]!.d)).not.toBe(WHOLE_BODY_SHA256_HEX);
    expect(otherSha256Hex(bytes('data: {"a":1}'))).toBe(FRAMED_LINE_SHA256_HEX);
    expect(otherSha256Hex(bytes(caseItem.body))).toBe(WHOLE_BODY_SHA256_HEX);
  });

  it('is the digest of the bytes the item returns, on a second implementation as well', () => {
    for (const caseItem of FRAME_CASES.filter((one) => one.items.length > 0)) {
      for (const item of framed(caseItem)) {
        expect(otherSha256Hex(item.bytes)).toBe(toHex(item.d));
        expect(item.d).toHaveLength(32);
      }
    }
  });

  it('owns its bytes rather than pointing into the chunk they came in on', () => {
    // The gateway hands out Node `Buffer`s from a pooled allocation, so a view of one is only good
    // until that pool is reused. An item that outlives its chunk has to have its own copy.
    const chunk = bytes('data: {"a":1}\n\n');
    const framer = new ResponseItemFramer(true);
    framer.feed(chunk);
    chunk.fill(0x5a);
    const outcome = framer.finish();
    if (!outcome.framed) throw new Error('a fed stream was refused');
    expect(textOf(outcome.items[0]!.bytes)).toBe('{"a":1}');
    expect(toHex(outcome.items[0]!.d)).toBe(itemDigestHex('{"a":1}'));
  });

  it('owns the bytes of a frame that had not ended when the chunk did', () => {
    // What a drained chunk leaves behind is the start of the next frame, and it is left behind in the
    // caller's array: a pooled buffer refilled before the next read would rewrite the bytes the frame
    // after this one is framed from. The whole frame that ended is copied by `pushItem`; the fragment
    // that did not has to be copied too, or the two halves of one response own different bytes.
    const chunk = bytes('data: {"a":1}\n\ndata: {"b":2');
    const framer = new ResponseItemFramer(true);
    framer.feed(chunk);
    chunk.fill(0x5a);
    framer.feed(bytes('}\n\n'));
    expect(framingText(framer.finish())).toBe(TWO_ITEMS);
  });

  it('owns a buffered body from the chunk it arrived in, not from the caller', () => {
    // Nothing is framed as a buffered body arrives, so everything it holds is still unframed: the copy is
    // made when the chunk is taken in rather than left to the one `pushItem` makes at the end, because
    // the bytes hashed at the end would otherwise be whatever the caller wrote over them meanwhile.
    const chunk = bytes('{"a":1}');
    const framer = new ResponseItemFramer(false);
    framer.feed(chunk);
    chunk.fill(0x5a);
    expect(framingText(framer.finish())).toBe(ONE_BUFFERED_ITEM);
  });
});

/**
 * What a reader still owns of the bytes it read, reached by walking everything the instance can hand back.
 *
 * A claim about retention is a claim about reachability: the bytes are held if something the reader holds
 * points at them, and not otherwise. A digest is 32 bytes on both readers and is kept by both, so this
 * counts every reachable run of bytes that is not one: what is left is a response's own bytes, and the
 * difference between the two answers is exactly those. A payload of exactly 32 bytes would read here as a
 * digest, so the bodies below are framed from payloads of other widths. Own enumerable properties are what
 * a caller can reach, and both readers keep their state there.
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

/** The digest reader's answer for a body delivered in these pieces, as the digests it states. */
function digestsInPieces(pieces: readonly Uint8Array[], streamed: boolean): string {
  const framer = new ResponseItemDigestFramer(streamed);
  for (const piece of pieces) framer.feed(piece);
  return digestText(framer.finish());
}

/** An answer reduced to what both readers can state about it: each item's digest, or the refusal. */
function digestText(outcome: ResponseItemDigestFraming | ResponseItemFraming): string {
  if (!outcome.framed) return `refused: ${outcome.why}`;
  const list = 'items' in outcome ? outcome.items.map((item) => item.d) : outcome.digests;
  return list.map(toHex).join('|');
}

/** The same body, read by a caller that asked for each piece of it separately and by one that did not. */
function splitAt(body: Uint8Array, at: number): Uint8Array[] {
  return [body.subarray(0, at), body.subarray(at)];
}

describe('the two readers of these bytes, on one rule', () => {
  /** The refusal a second response's bytes reach on either reader, apart from the class it names. */
  function refused(action: () => unknown): ReceiptError {
    try {
      action();
    } catch (err) {
      if (err instanceof ReceiptError) return err;
      throw new Error(`the call refused something this is not: ${String(err)}`);
    }
    throw new Error('a chunk after the answer was accepted');
  }

  for (const caseItem of FRAME_CASES) {
    it(`${caseItem.name}: both readers answer the digests written down for it, and neither invents one`, () => {
      const body = bytes(caseItem.body);
      // The expectation is the case table's own literals: a published reading and a digest-only reading
      // agreeing with each other would also be true of two readings that both moved away from the rule, so
      // both halves are compared against the digests written down away from this code.
      const expected =
        caseItem.items.length === 0 ? `refused: ${NO_FRAME_REASON}` : caseItem.items.map(itemDigestHex).join('|');
      const published = frameResponse(caseItem.contentType, body);
      const digests = new ResponseItemDigestFramer(isEventStream(caseItem.contentType));
      digests.feed(body);
      expect([digestText(published), digestText(digests.finish())]).toEqual([expected, expected]);
    });
  }

  it('keeps no byte of any item it framed, where the published reader keeps every one of them', () => {
    const body = bytes('data: {"a":1}\n\ndata: {"b":2}\n\ndata: [DONE]\n\n');
    const digests = new ResponseItemDigestFramer(true);
    for (const piece of splitAt(body, 20)) digests.feed(piece);
    const published = new ResponseItemFramer(true);
    published.feed(body);
    const outcome = published.finish();
    if (!outcome.framed) throw new Error('the published framing refused a framed stream');
    const payloads = outcome.items.reduce((total, item) => total + item.bytes.length, 0);
    // The two payloads are the whole of what the framing reads out of this body, and the only thing the
    // digest reader holds beyond 32-byte digests is nothing at all: every frame here arrived closed.
    expect([payloads, nonDigestBytesHeld(digests), nonDigestBytesHeld(published)]).toEqual([14, 0, 14]);
    expect(digestText(digests.finish())).toBe(digestText(outcome));
  });

  it('holds back only the frame a stream has not closed, and gives it up when the frame ends', () => {
    // One frame of 4,000 bytes that no write terminated, then the two bytes that end it. What the walk
    // cannot do is decide whether such a run is one frame or half of one until a line ending arrives, so
    // that run is the widest thing either reader is allowed to hold, and the published reader keeps it as
    // an item's bytes as well as the frame before it.
    const open = `data: ${'x'.repeat(4000)}`;
    const digests = new ResponseItemDigestFramer(true);
    digests.feed(bytes(open));
    const heldOpen = nonDigestBytesHeld(digests);
    digests.feed(bytes('\n\n'));
    const answer = digests.finish();
    if (!answer.framed) throw new Error('the closed frame was refused');
    expect([heldOpen, nonDigestBytesHeld(digests), answer.digests.length]).toEqual([open.length, 0, 1]);

    const published = new ResponseItemFramer(true);
    published.feed(bytes(open));
    expect(nonDigestBytesHeld(published)).toBe(open.length);
    published.feed(bytes('\n\n'));
    // The payload the published answer keeps, and nothing else: the same frame, one copy wider than the
    // digest reader's, because that copy is the half a verifier of the bytes is given.
    expect(nonDigestBytesHeld(published)).toBe(4000);
    expect(digestText(published.finish())).toBe(digestText(answer));
  });

  it('answers digests and their count, and no bytes for a caller to read the rule out of', () => {
    const framer = new ResponseItemDigestFramer(true);
    framer.feed(bytes('data: {"a":1}\n\ndata: {"b":2}\n\ndata: [DONE]\n\n'));
    const answer = framer.finish();
    if (!answer.framed) throw new Error('a framed stream answered a refusal');
    expect(Object.keys(answer).sort()).toEqual(['digests', 'framed']);
    expect(Object.isFrozen(answer.digests)).toBe(true);
    expect(answer.digests.map((one) => one.length)).toEqual([32, 32]);
    // The count the answer states is the number of items the response framed, which is the second of the
    // two things a gateway needs from a walk and the one that keeps the two readings comparable.
    expect(answer.digests.length).toBe(2);
    expect(answer.digests.map(toHex)).toEqual([itemDigestHex('{"a":1}'), itemDigestHex('{"b":2}')]);
    const refusedAgain = refused(() => framer.feed(bytes('data: {"b":2}\n\n')));
    expect(refusedAgain.code).toBe('FRAMER_REUSED');
  });

  it('names the reader a second response needs, in the refusal each of the two gives', () => {
    // One rule and one lifetime for both readers, and the refusal sends the caller to the class it should
    // have taken: a message that named the other one would send a maintainer to the wrong contract.
    const digests = new ResponseItemDigestFramer(true);
    digests.feed(bytes('data: {"a":1}\n\n'));
    digests.finish();
    const late = bytes('data: {"b":2}\n\ndata: [DONE]\n\n');
    const err = refused(() => digests.feed(late));
    expect(err.code).toBe('FRAMER_REUSED');
    expect(err.message).toContain(`${String(late.length)} bytes arrived`);
    expect(err.message).toContain('ResponseItemDigestFramer');
    expect(err.message).not.toContain('own ResponseItemFramer');

    const published = new ResponseItemFramer(true);
    published.feed(bytes('data: {"a":1}\n\n'));
    published.finish();
    expect(refused(() => published.feed(bytes('data: {"b":2}\n\n'))).message).toContain('own ResponseItemFramer');
  });

  it('refuses a stream that sent no frame with the published reason, in both readings of it', () => {
    // The empty-list refusal decides which receipt version a gateway signs, so the two readers have to give
    // the same sentence for the same bytes and not merely the same shape of answer.
    for (const body of ['data: [DONE]\n\n', 'event: message\n\n: comment\n\n', '']) {
      const bytesOf = bytes(body);
      const expected = `refused: ${NO_FRAME_REASON}`;
      const whole = new ResponseItemDigestFramer(true);
      whole.feed(bytesOf);
      expect(digestText(whole.finish())).toBe(expected);
      expect(digestText(frameResponse(STREAMED, bytesOf))).toBe(expected);
      // And the same answer when the body arrives in pieces, which is how a gateway reads it.
      expect(digestsInPieces(splitAt(bytesOf, Math.ceil(bytesOf.length / 2)), true)).toBe(expected);
    }
  });
});

describe('the account a verifier can check', () => {
  /** Whether a leftover line is the field name and nothing else: one frame whose payload has no bytes. */
  function isFieldPrefix(line: string): boolean {
    return line === SSE_DATA_FIELD || line === `${SSE_DATA_FIELD} `;
  }

  /**
   * Whether one line of the bytes left over once the items are lifted out is framing and nothing else.
   *
   * A `data:` line that keeps its whole payload here is the failure this is looking for: the framing
   * dropped an item it should have attested, and `res` would still cover the bytes, so nothing else
   * would notice. A line that never was a `data:` line carries no item by the rule, so its bytes are
   * allowed to sit outside the list, and the sentinel is allowed because it ends a stream instead of
   * being said by one. The bare field name is not on this list, with or without its one space: both
   * spellings are a frame whose payload is empty, which is an item the list owes rather than framing the
   * rule can hand back. `checkAccount` takes those lines one item at a time, so a dropped zero-byte frame
   * leaves a prefix behind with nothing left to answer for it.
   */
  function isFramingOnly(line: string): boolean {
    if (line === '') return true;
    if (line === SSE_DONE_VALUE || line === `${SSE_DATA_FIELD}${SSE_DONE_VALUE}` || line === `${SSE_DATA_FIELD} ${SSE_DONE_VALUE}`) {
      return true;
    }
    return !line.startsWith(SSE_DATA_FIELD);
  }

  /** The accounting, for one body and the items framed out of it: positions, and what is left over. */
  function checkAccount(contentType: string, body: Uint8Array, items: readonly ResponseItem[]): void {
    const offsets = offsetsOf(body, items);
    let cursor = 0;
    let covered = 0;
    offsets.forEach((at, index) => {
      expect(at).toBeGreaterThanOrEqual(cursor);
      cursor = at + items[index]!.bytes.length;
      covered += items[index]!.bytes.length;
    });
    const taken = (index: number): boolean =>
      offsets.some((at, item) => at <= index && index < at + items[item]!.bytes.length);
    const outside = textOf(body.filter((_byte, index) => !taken(index)));
    // No payload of an item survives in what is left, which is the same claim as `res` being a hash of
    // these bytes with the items inside them rather than beside them. The leftover is read as lines the
    // way the framing reads them, so a carriage return splits it too: were it read only at line feeds, a
    // body framed with those would arrive here as one long line and be judged against the wrong spelling.
    let prefixes = 0;
    for (const line of outside.split(/[\r\n]/u)) {
      if (isFieldPrefix(line)) {
        prefixes += 1;
        continue;
      }
      expect(isFramingOnly(line), `leftover line ${JSON.stringify(line)} carries bytes no item attests`).toBe(true);
    }
    // Every framed item leaves its own field name outside itself and no other item's line, so the count of
    // those lines is the length of the list: a fact about the list and the body together, which no line of
    // the leftover can state on its own. A frame dropped from the list still leaves its prefix here, so the
    // counts part and this is where a zero-byte frame going missing is caught. A buffered body is one item
    // with no framing around it, so it leaves none.
    expect(prefixes, 'the framing outside the items names a different number of frames than the list holds').toBe(
      isEventStream(contentType) ? items.length : 0,
    );
    // The two counts add to the body only when no item's bytes were left out and none was read twice, which
    // the forward walk over the offsets above is the one thing that decides: as a claim about lengths this
    // is only as strong as that walk, and it is silent about a frame whose payload has no bytes to count.
    // That case belongs to the prefix count, and not to this line.
    expect(covered + outside.length).toBe(body.length);
  }

  it('lays the items over the response in order, and leaves only framing outside them', () => {
    for (const caseItem of FRAME_CASES) {
      // A refused case is walked too, against the empty list the table publishes for it: every byte of
      // such a response is then framing, which is the other half of why a refusal is the right answer.
      checkAccount(caseItem.contentType, bytes(caseItem.body), caseItem.items.length === 0 ? [] : framed(caseItem));
    }
  });

  it('frames the published stream into items whose digests, and whose `res`, are hashes of one byte string', () => {
    const suite = JSON.parse(readFileSync(vectorsPath, 'utf8')) as {
      vectors: Array<{
        name: string;
        contentType: string;
        responseBase64Url: string;
        responseByteLength: number;
        resHex: string;
      }>;
    };
    const streamed = suite.vectors.find((one) => one.name === 'streamed-frames');
    const unframed = suite.vectors.find((one) => one.name === 'streamed-payloads-without-framing');
    if (!streamed || !unframed) throw new Error('res-v1.json no longer carries the two streamed vectors');

    const body = fromBase64Url(streamed.responseBase64Url);
    expect(body.length).toBe(streamed.responseByteLength);
    // The published `res`, over the bytes as transmitted: what a verifier holding this response checks
    // against the same walk that gives them the items.
    expect(otherSha256Hex(body)).toBe(streamed.resHex);

    const outcome = frameResponse(streamed.contentType, body);
    if (!outcome.framed) throw new Error('the published streamed response was refused');
    expect(outcome.items.map((item) => toHex(item.d))).toEqual([...PUBLISHED_ITEM_SHA256_HEX]);
    checkAccount(streamed.contentType, body, outcome.items);

    // The framing accounts for every byte: the four payloads plus the prefix, terminator and sentinel
    // bytes of five frames are the whole body, and the payloads in order are the published response
    // stripped of its framing, which that vector exists to publish.
    const payloadBytes = outcome.items.reduce((total, item) => total + item.bytes.length, 0);
    expect(payloadBytes + PUBLISHED_FRAMING_BYTES).toBe(streamed.responseByteLength);
    const withoutSentinel = bytes(SSE_DONE_VALUE);
    const joined = new Uint8Array(payloadBytes);
    let at = 0;
    for (const item of outcome.items) {
      joined.set(item.bytes, at);
      at += item.bytes.length;
    }
    const publishedUnframed = fromBase64Url(unframed.responseBase64Url);
    expect(toHex(joined)).toBe(toHex(publishedUnframed.subarray(0, publishedUnframed.length - withoutSentinel.length)));
    expect(unframed.resHex).not.toBe(streamed.resHex);
  });

  it('names the field prefix and the sentinel once, and the marking path spells them the same way', () => {
    // `marking.ts` writes the frames and holds the sentinel back on the wire; this file reads them
    // apart again. The two agree byte for byte or a receipt attests a frame no client was sent, so the
    // agreement is read out of the writer's source rather than assumed from a shared understanding.
    const writer = readFileSync(markingSourcePath, 'utf8');
    const prefix = /export const SSE_FIELD_PREFIX = '([^']*)';/u.exec(writer)?.[1];
    const frameEnd = /export const SSE_FRAME_END = '([^']*)';/u.exec(writer)?.[1];
    const token = /const SENTINEL_TOKEN = new TextEncoder\(\)\.encode\('([^']*)'\);/u.exec(writer)?.[1];
    // The writer spells its two line feeds as escapes in source, so a read of its literal text has to
    // decode them before it can be compared with the bytes the framing reads.
    expect(unescapeSource(frameEnd)).toBe('\n\n');
    expect(prefix).toBe(SSE_DATA_FIELD + ' ');
    expect(token).toBe(SSE_DONE_VALUE);
    expect(SSE_DATA_FIELD).toBe('data:');
  });
});
