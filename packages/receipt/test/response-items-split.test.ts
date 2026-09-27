import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { ResponseItemFramer, frameResponse, fromBase64Url, isEventStream, toHex } from '../src/index.js';
import {
  FRAME_CASES,
  PUBLISHED_ITEM_SHA256_HEX,
  STREAMED,
  expectedFramingText,
  framingText,
} from './response-item-cases.js';

/**
 * The framing of a response does not depend on how its bytes were delivered.
 *
 * This is the evidence for the claim that an item is a protocol frame and not a transport accident: one
 * body, fed in one piece, fed split at every position there is (which includes inside the six characters
 * of `[DONE]`, inside its field name, and between the two line feeds of a frame terminator), fed at
 * every pair of positions, fed one byte at a time, and fed in every fixed width, gives item for item the
 * same list with the same digests. A gateway that reads frames as they arrive, which is what a later
 * step will hand to `ResponseItemFramer`, therefore attests exactly what a verifier holding the whole
 * response rebuilds from it, and no part of the answer is a coincidence of where a write ended.
 *
 * The expectations come from `response-item-cases.ts`, digests included, so a framing that agreed with
 * itself at every split while disagreeing with the rule would still go red here rather than passing on
 * being internally consistent.
 */

const vectorsPath = fileURLToPath(new URL('../../fixtures/data/res-v1.json', import.meta.url));

function bytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

/** The framing of a stream whose bytes arrived as the pieces named. */
function framedInPieces(contentType: string, pieces: readonly Uint8Array[]): string {
  return framingText(feedAll(contentType, pieces).finish());
}

function feedAll(contentType: string, pieces: readonly Uint8Array[]): ResponseItemFramer {
  const framer = new ResponseItemFramer(isEventStream(contentType));
  for (const piece of pieces) framer.feed(piece);
  return framer;
}

/** The digests of the items, or an empty list when the framing refused. */
function digestsInPieces(contentType: string, pieces: readonly Uint8Array[]): string[] {
  const outcome = feedAll(contentType, pieces).finish();
  return outcome.framed ? outcome.items.map((item) => toHex(item.d)) : [];
}

function piecesAt(body: Uint8Array, cuts: readonly number[]): Uint8Array[] {
  const pieces: Uint8Array[] = [];
  let at = 0;
  for (const cut of [...cuts, body.length]) {
    pieces.push(body.subarray(at, cut));
    at = cut;
  }
  return pieces;
}

function oneByteEach(body: Uint8Array): Uint8Array[] {
  if (body.length === 0) return [body];
  const pieces: Uint8Array[] = [];
  for (let at = 0; at < body.length; at += 1) pieces.push(body.subarray(at, at + 1));
  return pieces;
}

function fixedWidths(body: Uint8Array, width: number): Uint8Array[] {
  const pieces: Uint8Array[] = [];
  for (let at = 0; at < body.length; at += width) pieces.push(body.subarray(at, at + width));
  return pieces.length === 0 ? [body] : pieces;
}

/** Every single cut of a body, which is where one write ended and the next began. */
function singleCuts(body: Uint8Array): number[][] {
  const cuts: number[][] = [];
  for (let at = 0; at <= body.length; at += 1) cuts.push([at]);
  return cuts;
}

/** Every pair of cuts, which is where two writes ended: only affordable on the small bodies. */
function cutPairs(body: Uint8Array): number[][] {
  const cuts: number[][] = [];
  for (let first = 0; first <= body.length; first += 1) {
    for (let second = first; second <= body.length; second += 1) cuts.push([first, second]);
  }
  return cuts;
}

interface PublishedStream {
  readonly name: string;
  readonly contentType: string;
  readonly body: Uint8Array;
  /** The write boundaries the vector was published with, as the transport chose them. */
  readonly chunks: Uint8Array[];
}

/**
 * The two streamed vectors of `res-v1.json` that hold one framed response: one written whole, one
 * written in two pieces that break inside a three-byte character. The suite's third `text/event-stream`
 * vector is the same payloads stripped of their framing, which is not a stream a framing can read frames
 * out of, so it is not swept here.
 */
const FRAMED_VECTORS = ['streamed-frames', 'streamed-frames-split-mid-character'] as const;

function publishedStream(name: string): PublishedStream {
  const suite = JSON.parse(readFileSync(vectorsPath, 'utf8')) as {
    vectors: Array<{
      name: string;
      contentType: string;
      responseBase64Url: string;
      chunksBase64Url: readonly string[];
    }>;
  };
  const one = suite.vectors.find((vector) => vector.name === name);
  if (!one) throw new Error(`res-v1.json no longer carries the ${name} vector`);
  const body = fromBase64Url(one.responseBase64Url);
  const chunks = one.chunksBase64Url.map((chunk) => fromBase64Url(chunk));
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  if (total !== body.length) throw new Error(`${name}: its chunks no longer add up to its body`);
  return { name: one.name, contentType: one.contentType, body, chunks };
}

describe('every delivery of one body frames the same items', () => {
  for (const caseItem of FRAME_CASES) {
    it(`${caseItem.name}: one piece, every cut, every pair of cuts, one byte at a time, every width`, () => {
      const body = bytes(caseItem.body);
      const expected = expectedFramingText(caseItem);
      expect(framingText(frameResponse(caseItem.contentType, body))).toBe(expected);
      for (const cuts of [...singleCuts(body), ...cutPairs(body)]) {
        expect(framedInPieces(caseItem.contentType, piecesAt(body, cuts)), `cuts ${String(cuts)}`).toBe(expected);
      }
      for (const width of [1, 2, 3, 5, 7, 11, 13, 16, 31, 64]) {
        expect(framedInPieces(caseItem.contentType, fixedWidths(body, width)), `width ${String(width)}`).toBe(expected);
      }
      expect(framedInPieces(caseItem.contentType, oneByteEach(body))).toBe(expected);
    });
  }

  it('holds its answer across the write boundaries the published vectors were sent with', () => {
    for (const name of FRAMED_VECTORS) {
      const stream = publishedStream(name);
      const baseline = framingText(frameResponse(stream.contentType, stream.body));
      expect(framedInPieces(stream.contentType, stream.chunks)).toBe(baseline);
      expect(framedInPieces(stream.contentType, oneByteEach(stream.body))).toBe(baseline);
      // Every position one write may have ended, which on a body this long is where a pair of cuts would
      // have to be a sample rather than a sweep; the named positions below and the pairs over the short
      // bodies carry the two-cut case.
      for (const cuts of singleCuts(stream.body)) {
        expect(framedInPieces(stream.contentType, piecesAt(stream.body, cuts)), `cuts ${String(cuts)}`).toBe(baseline);
      }
      // Anchored on the published payloads and not only on two runs agreeing with each other: both
      // vectors carry the same response, written by two different transports, so each is checked against
      // the four digests that response is known for.
      expect(digestsInPieces(stream.contentType, stream.chunks)).toEqual([...PUBLISHED_ITEM_SHA256_HEX]);
      expect(digestsInPieces(stream.contentType, oneByteEach(stream.body))).toEqual([...PUBLISHED_ITEM_SHA256_HEX]);
    }
  });

  it('cuts inside a frame terminator and inside the sentinel name, by position rather than by sweep', () => {
    // `data: {"a":1}\n\ndata: {"b":2}\n\ndata: [DONE]\n\n` is 44 bytes. The second frame's two line feeds
    // are at 28 and 29, the sentinel frame's field name runs from 30 to 35, `[DONE]` is 36 through 41,
    // and its own line feeds are 42 and 43. Every cut across that span is a place a socket may have
    // stopped, and none of them may change what the response attests.
    const caseItem = FRAME_CASES.find((one) => one.name === 'three frames, the last of them the sentinel');
    if (!caseItem) throw new Error('the cases file no longer carries the three-frame case');
    const body = bytes(caseItem.body);
    expect(body.length).toBe(44);
    const expected = expectedFramingText(caseItem);
    for (let at = 12; at <= 44; at += 1) {
      expect(framedInPieces(STREAMED, [body.subarray(0, at), body.subarray(at)]), `cut at ${String(at)}`).toBe(expected);
    }
  });

  it('takes an empty write for what it is, which is nothing at all', () => {
    for (const caseItem of FRAME_CASES) {
      const body = bytes(caseItem.body);
      const pieces: Uint8Array[] = [];
      for (const piece of oneByteEach(body)) pieces.push(new Uint8Array(0), piece);
      pieces.push(new Uint8Array(0));
      expect(framedInPieces(caseItem.contentType, pieces)).toBe(expectedFramingText(caseItem));
    }
  });

  it('answers the same refusal whichever piece the last bytes arrive in', () => {
    for (const caseItem of FRAME_CASES.filter((one) => one.items.length === 0)) {
      const body = bytes(caseItem.body);
      const expected = expectedFramingText(caseItem);
      for (const cuts of [...singleCuts(body), ...cutPairs(body)]) {
        expect(framedInPieces(caseItem.contentType, piecesAt(body, cuts))).toBe(expected);
      }
    }
  });
});
