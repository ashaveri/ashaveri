import { describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  EMPTY_BODY_SHA256_HEX,
  ResponseItemFramer,
  SSE_DATA_FIELD,
  SSE_DONE_VALUE,
  frameResponse,
  fromBase64Url,
  isEventStream,
  toHex,
  type ResponseItem,
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
});

describe('the account a verifier can check', () => {
  /**
   * Whether one line of the bytes left over once the items are lifted out is framing and nothing else.
   *
   * A `data:` line that keeps its whole payload here is the failure this is looking for: the framing
   * dropped an item it should have attested, and `res` would still cover the bytes, so nothing else
   * would notice. A line that never was a `data:` line carries no item by the rule, so its bytes are
   * allowed to sit outside the list, and the sentinel is allowed because it ends a stream instead of
   * being said by one.
   */
  function isFramingOnly(line: string): boolean {
    if (line === '' || line === SSE_DATA_FIELD || line === `${SSE_DATA_FIELD} `) return true;
    if (line === SSE_DONE_VALUE || line === `${SSE_DATA_FIELD}${SSE_DONE_VALUE}` || line === `${SSE_DATA_FIELD} ${SSE_DONE_VALUE}`) {
      return true;
    }
    return !line.startsWith(SSE_DATA_FIELD);
  }

  /** The accounting, for one body and the items framed out of it: positions, and what is left over. */
  function checkAccount(body: Uint8Array, items: readonly ResponseItem[]): void {
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
    // these bytes with the items inside them rather than beside them.
    for (const line of outside.split(/\r?\n/u)) {
      expect(isFramingOnly(line), `leftover line ${JSON.stringify(line)} carries bytes no item attests`).toBe(true);
    }
    expect(covered + outside.length).toBe(body.length);
  }

  it('lays the items over the response in order, and leaves only framing outside them', () => {
    for (const caseItem of FRAME_CASES) {
      // A refused case is walked too, against the empty list the table publishes for it: every byte of
      // such a response is then framing, which is the other half of why a refusal is the right answer.
      checkAccount(bytes(caseItem.body), caseItem.items.length === 0 ? [] : framed(caseItem));
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
    checkAccount(body, outcome.items);

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
