import { sha256 } from '@noble/hashes/sha2.js';
import { utf8ToBytes } from '@noble/hashes/utils.js';
import { equalBytes } from './cose.js';
import { ReceiptError } from './errors.js';

/**
 * Which bytes of a gateway response are an item, and what each item's digest covers.
 *
 * The unit is a protocol item and not a transport accident. `gateway/src/marking.ts` states the reason
 * in the estate's own words: "a write boundary falls wherever the transport likes, including inside the
 * eight letters of `[DONE]`". A rule that read items off write boundaries would therefore attest a
 * different set of items for one response depending on how the socket chose to deliver it, and a
 * verifier holding the bytes it was handed could not reproduce the set. So the rule below is a function
 * of the response bytes alone: the same bytes give the same items and the same digests however they
 * were written or read, which is what makes an item's digest a claim a stranger can check.
 *
 * The rule, stated once and exported so nothing else has to restate it. An item is one `data:` frame of
 * a streamed response: the bytes after the field name, and after the one space that marking treats as
 * framing rather than content, up to the line ending that closes the frame. A line ending is a line feed,
 * a carriage return, or that pair together, which is how a stream of these frames is read at all: a rule
 * that took only the line feed would decode one item where a client reading the same bytes decodes two,
 * and a receipt that attests a per-item instant has to attest what a reader of the response receives. The
 * `[DONE]` value ends a stream instead of being said by it, so a frame carrying nothing but that token
 * contributes no item. A body that is not `text/event-stream` is one item holding all of it, because a
 * buffered completion has no frames and its body is the whole of what was said. A stream with no data
 * frame in it is a refusal and never an empty list, for the reason `pack.cddl` gives of its own item
 * list: a run of nothing states nothing, and zero digests give a reader nothing to hold the response
 * against.
 *
 * How this reader agrees with the estate's other readers of the same bytes, and where it answers another
 * question. The three endings above are one rule and everything that walks a response reads it: the
 * `dataLines` split and the event walk in `gateway/src/upstream.ts`, which meter the usage a completion
 * carried, and `frameLineSpans` in this package, which names the span `mk.d` digests, each break a line
 * at a carriage return as well as at a line feed, so a stream framed either way gives all of them the
 * same frames. `gateway/src/marking.ts` reads them from the other end: its `sentinelStart` steps back over
 * a trailing carriage return before it compares, so `data: [DONE]\r` is the sentinel there, here, and to a
 * client holding the bytes. The agreement is not a claim in a comment either, it is a table:
 * `gateway/test/response-frame-readers.test.ts` feeds one body through all four and states what each one
 * concludes about it.
 *
 * What is left between them is a difference of question and not of reading. This file walks lines, so it
 * attests a `data:` frame whose event was never dispatched, including the last frame of a body that ends
 * mid-line, because those bytes were sent and `res` covers them. The usage scan walks dispatches, because
 * what a completion says about its tokens is knowable only once a blank line has closed the event, and a
 * frame seen half way through is a frame it cannot parse at all. Section 3.1 of `docs/receipt-spec.md`
 * states which of the two the receipt is built from; the two rows of that table which part, one body
 * written in line feeds and the same body written in carriage returns with no blank line in either, are
 * there so the difference is read as the model and not as a terminator.
 *
 * How this relates to the digest a receipt already carries. `res` is sha256 over the response bytes
 * exactly as transmitted, framing included: section 3.1 of `docs/receipt-spec.md` publishes that, and
 * `packages/fixtures/data/res-v1.json` holds the bytes it was computed from for both shapes. The
 * framing above is a walk over those very same bytes. Every item's bytes are a slice of the response,
 * the slices come in the order the response put them in and overlap nothing, and every byte outside them
 * is framing this rule names: a `data:` prefix, the one optional space, a line ending, a blank line, the
 * sentinel frame, or a whole line that never was a data line, an `event:` or `id:` field or a comment. So
 * one verifier holding the response bytes rebuilds the items and hashes both them and the whole body in
 * the same pass, and `res` and each item's `d` are then two statements about one byte string rather than
 * two stories that cannot be compared. What is not true, and is worth saying plainly because the sentence
 * is easy to get backwards: the item digests alone do not reconstruct `res`, because the framing bytes
 * are outside every item by definition. `res` is what makes an item list need the response bytes beside
 * it, and `test/response-items.test.ts` holds both halves of that account open at once.
 *
 * What this module does not do. Nothing here takes an instant: no clock is read in this file, and the `t`
 * the `itm` entry puts beside each of these digests belongs to `gateway/src/item-stamps.ts`, which reads
 * it at the moment a frame passes the socket. What these digests are read by is that member: the table in
 * section 3.1 of `docs/receipt-spec.md` publishes an item's `d` as one item's bytes and none of the framing
 * around them, carried in `itm`, and the bytes this rule frames are the bytes that row means. The gateway
 * calls this file on both shapes it serves: a stream is walked as it leaves by `StreamedItemStamps`, which
 * feeds `ResponseItemDigestFramer` and so keeps no byte of any item it framed, and a buffered body is taken
 * whole by `stampedBufferedItem` through `frameResponse`, which is the reader a verifier of those bytes
 * runs. What neither reader does is stamp, digest the whole body, or settle what to issue: `res` and `mk.d`
 * are taken over these bytes elsewhere, by the process writing the socket, and `{framed: false}` is a value
 * handed to the caller that is deciding, not an answer about which action a refusal calls for.
 */

/** The field name whose value an item is, spelled as `gateway/src/marking.ts` writes it. */
export const SSE_DATA_FIELD = 'data:';

/** The value that ends a frame stream rather than being said by one, and so attests no item. */
export const SSE_DONE_VALUE = '[DONE]';

/** The content type whose bodies are read as frames; any other body is taken whole. */
const EVENT_STREAM_TYPE = 'text/event-stream';

const SPACE = 0x20;
const LF = 0x0a;
const CR = 0x0d;
const DATA_FIELD_BYTES = utf8ToBytes(SSE_DATA_FIELD);
const DONE_BYTES = utf8ToBytes(SSE_DONE_VALUE);

/**
 * One attested item: the bytes it was framed from, and their digest.
 *
 * `bytes` is what a caller hashes for itself and, later, what it hands to whoever has to reproduce
 * `res`; `d` is the half a receipt will name. Both are the framed payload and nothing else, which is
 * the whole content of the rule: a digest over the `data:` prefix and the terminator as well would be
 * a second, different framing of one response, and a verifier reading the item back from the bytes it
 * holds would have to guess which of the two it was given.
 */
export interface ResponseItem {
  readonly bytes: Uint8Array;
  /** sha256 of exactly `bytes`, 32 wide, in the same representation `mk.d` and `att.d` use. */
  readonly d: Uint8Array;
}

/**
 * The items of one response, or the reason that response attests no set of them at all.
 *
 * A refusal is a value and not an exception: the caller is deciding what to issue, and "this stream
 * said nothing" is an answer about the response rather than a fault in the code reading it.
 */
export type ResponseItemFraming =
  | { readonly framed: true; readonly items: readonly ResponseItem[] }
  | { readonly framed: false; readonly why: string };

/**
 * The items of one response as their digests alone, or the reason that response attests no set of them.
 *
 * The same two arms as `ResponseItemFraming`, the same refusal in the same words, and no bytes beside the
 * digests: what a reader of this answer can settle afterwards is which digests a response states and how
 * many of them it states, and `digests.length` is the count.
 */
export type ResponseItemDigestFraming =
  | { readonly framed: true; readonly digests: readonly Uint8Array[] }
  | { readonly framed: false; readonly why: string };

/** Whether a body of this content type is framed in `data:` lines rather than taken whole. */
export function isEventStream(contentType: string): boolean {
  return contentType.includes(EVENT_STREAM_TYPE);
}

/**
 * The framing of one response, read as a stream or as a whole body according to its content type.
 *
 * This is the rule applied to bytes that all arrived at once, and it is what `ResponseItemFramer`
 * agrees with at every split of the same bytes: a verifier holding a response body uses this, and a
 * gateway that saw the frames as they arrived uses the class below.
 */
export function frameResponse(contentType: string, body: Uint8Array): ResponseItemFraming {
  const framer = new ResponseItemFramer(isEventStream(contentType));
  framer.feed(body);
  return framer.finish();
}

/**
 * The reading both readers of these bytes take, walked once.
 *
 * One response's frames, as its bytes arrive: the walk holds back whatever no line ending has closed, ends
 * a line at a carriage return, a line feed, or that pair together, lifts the payload out of each `data:`
 * line it ends, passes the one framing space, hands back the sentinel as the terminator it is, and reads
 * what the buffer still holds as the last line the response sent. What is *kept* of a framed item is not
 * the walk's business: `take` is called with the item's bytes and the walk counts the item, which is the
 * whole difference between the two readers built on it. That is deliberate. A reader that answered the same
 * response differently from the published one would put two stories about one byte string inside one
 * document, and the difference the estate cannot afford is between bytes, not between two widths of the
 * same walk.
 */
class ResponseItemWalk {
  private buffer: Uint8Array = new Uint8Array(0);
  /** How many items `take` has been handed, which is the number a refusal is decided against. */
  private taken = 0;
  /** Whether the answer has been read, which is what ends this response. */
  private answered = false;

  /**
   * `reader` is the name the refusal of a late chunk quotes, so that the sentence sends a caller to the
   * class it should have taken rather than to whichever of the two this walk happens to serve.
   */
  constructor(
    private readonly streamed: boolean,
    private readonly reader: string,
    private readonly take: (bytes: Uint8Array) => void,
  ) {}

  /**
   * Take the next piece of the response, framing what of it is complete and holding the rest back.
   *
   * Refused once the answer has been read, which is the enforcement of one reader per response for both
   * readers built here: the framing a response produced is a statement about the bytes that produced it,
   * and a chunk of the next response's bytes belongs to a reading nobody has taken yet.
   */
  feed(chunk: Uint8Array): void {
    if (this.answered) {
      throw new ReceiptError(
        'FRAMER_REUSED',
        `${String(chunk.length)} bytes arrived after finish() answered this response; a chunk after the answer is another response's bytes, and a response takes its own ${this.reader}`,
      );
    }
    // The chunk is kept as it stands only when it is about to be scanned and what survives of it copied,
    // which is the streamed case. A buffered body is all of it unframed, so it is copied here instead:
    // nothing this instance holds between two calls is the caller's memory. See `pushItem` for the same
    // reason at the other end, where an item's bytes outlive the chunk they were framed from.
    this.buffer = this.buffer.length === 0 && this.streamed ? chunk : join(this.buffer, chunk);
    if (this.streamed) this.drainFrames();
  }

  /**
   * Read the answer: whatever the buffer still holds is the last line the response sent, and then whether
   * anything at all was framed. The caller's `take` has been handed every item by the time this returns.
   */
  read(): { readonly framed: true } | { readonly framed: false; readonly why: string } {
    this.answered = true;
    if (!this.streamed) {
      // One item, whatever it holds: a buffered body has no frames to be between, and an empty one is
      // still the whole of what was said about it. `res` covers these bytes, so the item is a statement
      // about them and not an omission of one.
      this.pushItem(this.buffer);
      return { framed: true };
    }
    // A final frame whose terminator never arrived is still a frame the response sent, and the bytes
    // a client hashed into `res` do not stop being one because the write ended first.
    this.takeLine(this.buffer);
    if (this.taken === 0) {
      return {
        framed: false,
        why: 'the response sent no data frame, so it states nothing for an item to attest',
      };
    }
    return { framed: true };
  }

  /**
   * Consume every complete line in the buffer, leaving any fragment of one that is still arriving.
   *
   * A carriage return, a line feed, and the two together each end a line. The pair counts as one ending so
   * that a CRLF body reads the same frame it always read; a lone carriage return ends the line before it,
   * which is the reading the stream model gives and the one a client holding these bytes applies.
   */
  private drainFrames(): void {
    let start = 0;
    for (;;) {
      const at = this.endingAt(start);
      if (at < 0) break;
      const width = this.buffer[at] === CR && this.buffer[at + 1] === LF ? 2 : 1;
      this.takeLine(this.buffer.subarray(start, at));
      start = at + width;
    }
    // Copied, not kept as a view of what was scanned: these are the bytes of a frame that has not ended
    // yet, and they are framed into an item later, by which time the chunk they arrived in may have been
    // refilled under the caller. `pushItem` copies what it emits for the same reason.
    this.buffer = this.buffer.subarray(start).slice();
  }

  /** The next byte at or after `start` that ends a line, or -1 when all that is left is one fragment. */
  private endingAt(start: number): number {
    const lineFeed = this.buffer.indexOf(LF, start);
    const carriage = this.buffer.indexOf(CR, start);
    if (lineFeed < 0) return carriage;
    if (carriage < 0) return lineFeed;
    return Math.min(lineFeed, carriage);
  }

  /**
   * One line of a frame stream. A line that is not a `data:` line is framing and not content: an
   * `event:` or `id:` field, a comment, the blank line that closes a frame. It carries no item, and
   * `res` still covers its bytes, so nothing about the response is hidden by the walk.
   */
  private takeLine(line: Uint8Array): void {
    if (!equalBytes(line.subarray(0, DATA_FIELD_BYTES.length), DATA_FIELD_BYTES)) return;
    const value = line.subarray(DATA_FIELD_BYTES.length);
    // The one space `data: ` writes is framing, exactly as `MarkedStreamTail` and upstream's scan
    // both read it. A second space is content, and so is a tab: the digest is of the bytes left.
    const payload = value[0] === SPACE ? value.subarray(1) : value;
    // The sentinel is a terminator wherever it sits, and an exact match cannot swallow content:
    // a chunk's payload here is JSON text, which no completion writes `[DONE]` as.
    if (equalBytes(payload, DONE_BYTES)) return;
    this.pushItem(payload);
  }

  private pushItem(bytes: Uint8Array): void {
    this.taken += 1;
    this.take(bytes);
  }
}

/**
 * The framing of a response that arrives in pieces.
 *
 * Feed the chunks in the order they were received and take the items from `finish()`; the instance is
 * good for one response, because items already emitted are the answer for the bytes that produced them
 * and appending a second response's bytes to them would be a different question. That is enforced at the
 * call that breaks it, in `feed()`, and the list an answer carries is frozen so that no holder of it can
 * extend it either.
 *
 * Boundary independence is structural rather than defended. A frame is emitted only once a byte that ends
 * a line has been seen, an ending is never read as content, and what is left over at `finish()` is read by
 * the same single rule that reads a complete line. So no decision depends on where a write ended: a
 * `[DONE]` split down its middle, a terminator split between its two line feeds, a carriage return split
 * from the line feed that follows it, and a body arriving one byte at a time all give the same list as the
 * same bytes in one piece. A carriage return separated this way ends an empty line, and an empty line
 * names no item, which is why the split cannot change the answer.
 *
 * This reader keeps an item's bytes beside its digest, because its answer is the one a verifier holding a
 * response body reads back: the digests and the bytes they were taken over have to travel together or the
 * verifier has nothing to compare its own walk against. A caller that has the bytes in hand for one instant
 * and needs no more than what each item digest is and how many there were takes
 * `ResponseItemDigestFramer`, which walks these same lines through the same `ResponseItemWalk`.
 */
export class ResponseItemFramer {
  private readonly items: ResponseItem[] = [];
  private readonly walk: ResponseItemWalk;
  /** What `finish()` answers, read the first time it is asked for and kept for every later one. */
  private answer: ResponseItemFraming | undefined;

  constructor(streamed: boolean) {
    this.walk = new ResponseItemWalk(streamed, 'ResponseItemFramer', (bytes) => {
      // Copied, because the buffer ahead of this may be a view of a pooled Node buffer the caller is
      // free to reuse; an item's bytes outlive the chunk they were framed from only if they own them.
      const owned = bytes.slice();
      this.items.push({ bytes: owned, d: sha256(owned) });
    });
  }

  /**
   * Take the next piece of the response, framing what of it is complete and holding the rest back.
   *
   * Refused once the answer has been taken, which is the enforcement of this file's second paragraph
   * rather than a restatement of it. The framing an answer holds is a statement about the bytes that
   * produced it, and `items` is that same array the caller was handed: a chunk read after the answer would
   * extend it in the caller's hands, so a response issued over two items would come to attest five. A
   * second response takes a second framer, which is what its own `res` and its own items are for.
   */
  feed(chunk: Uint8Array): void {
    this.walk.feed(chunk);
  }

  /**
   * The items of the whole response, or the refusal that there are none.
   *
   * Read once, and answered from that reading however many times it is asked: the items already emitted
   * belong to the bytes that produced them, so a second reading of what the buffer still held would attest
   * one frame twice, and a second push of a buffered body would state an item the response never made. A
   * chunk arriving after this answer belongs to another response, which needs its own framer, and `feed()`
   * refuses it now rather than leaving the rule to be remembered.
   *
   * The list an answer carries is frozen, which is the other half of the same sentence: the refusal stops
   * this framer extending it, and the freeze stops anyone holding the answer from doing so. A copy instead
   * would leave this instance's own array open, so the answer a caller received would be a snapshot of a
   * list that was still being written. What neither reaches is an item's own bytes: a typed array holding
   * elements cannot be frozen, so a caller that wrote over one would move the digest beside it. That is a
   * caller damaging its own reading rather than an answer changing under one that never touched it, which
   * is the failure the refusal and the frozen list are for, and the copy each item's bytes are made on is
   * what keeps this instance's memory out of the answer either way.
   */
  finish(): ResponseItemFraming {
    if (this.answer === undefined) {
      const outcome = this.walk.read();
      this.answer = outcome.framed ? { framed: true, items: Object.freeze(this.items) } : outcome;
    }
    return this.answer;
  }
}

/**
 * The digests of a response's items, without the items' bytes.
 *
 * A process that watches a stream as it leaves has each frame in hand for one instant. What it settles
 * afterwards is which digests that response states and how many of them it states, and a reader that keeps
 * nothing but those two answers holds none of the response: the bytes a frame was made of are digested and
 * dropped, and the only bytes a live instance still owns are the ones of the frame its last write did not
 * close, which is what the walk has to hold back to know where that frame ends. Holding the whole of a
 * stream instead, when the answer is a list of 32-byte digests, is a claim about the response that nobody
 * asked for.
 *
 * One `ResponseItemWalk`, one rule, so this cannot read a response differently from `ResponseItemFramer`:
 * the two answers differ in what they keep and not in what they see. `test/response-items.test.ts` holds
 * both readers against the same external table of payloads and their digests, refusal included, at every
 * split of the same bytes, so that agreement is measured rather than argued.
 *
 * The answer is a frozen list of 32-byte digests in the order the response put its items, or the same
 * refusal the published framing gives a stream that sent no `data:` frame. What is not here is an item's
 * bytes: a caller that needs them needs `ResponseItemFramer`, which is the reader a verifier of a response
 * body holds. One instance answers one response, and `feed()` refuses a chunk after the answer, as it does
 * there.
 */
export class ResponseItemDigestFramer {
  private readonly digests: Uint8Array[] = [];
  private readonly walk: ResponseItemWalk;
  /** What `finish()` answers, read the first time it is asked for and kept for every later one. */
  private answer: ResponseItemDigestFraming | undefined;

  constructor(streamed: boolean) {
    this.walk = new ResponseItemWalk(streamed, 'ResponseItemDigestFramer', (bytes) => {
      // No copy: `sha256` reads these bytes into its own state and returns a digest of its own, so
      // nothing outlives the call. The bytes here may be a view of the caller's chunk, and this is the
      // one answer that does not care, because the view is not kept.
      this.digests.push(sha256(bytes));
    });
  }

  /** The next piece of this response, as `ResponseItemFramer.feed` takes it. */
  feed(chunk: Uint8Array): void {
    this.walk.feed(chunk);
  }

  /**
   * The digests of the whole response, or the refusal that there are none.
   *
   * Read once and answered from that reading however many times it is asked, and the list frozen: the two
   * halves of the same lifetime rule `ResponseItemFramer.finish()` states. A digest is 32 bytes and is
   * itself never written over by this class, so the residual the published answer states about an item's
   * bytes does not arise here.
   */
  finish(): ResponseItemDigestFraming {
    if (this.answer === undefined) {
      const outcome = this.walk.read();
      this.answer = outcome.framed ? { framed: true, digests: Object.freeze(this.digests) } : outcome;
    }
    return this.answer;
  }
}

function join(held: Uint8Array, chunk: Uint8Array): Uint8Array {
  const out = new Uint8Array(held.length + chunk.length);
  out.set(held);
  out.set(chunk, held.length);
  return out;
}
