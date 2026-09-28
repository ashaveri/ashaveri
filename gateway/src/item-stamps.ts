import { ResponseItemFramer, equalBytes, frameResponse, type ItemStamp } from '@ashaveri/receipt';

/**
 * The per-item stamps a `v: 3` payload carries, taken at the moment each item's bytes are handed over.
 *
 * `itm`'s `d` is sha256 of one response item and `t` is the instant that item passed. The two halves
 * have different owners: the digests belong to `ResponseItemFramer`, which is the shipped reader of a
 * response body and the only code whose reading a client can reproduce from the bytes it holds, and the
 * instants belong to this file, because nobody but the process writing the socket knows when a byte left
 * it. So this module owns exactly one thing: it feeds the shipped framer with the bytes this gateway
 * hands to a client, and it reads the clock once per write, in the order the writes went out.
 *
 * Why the feed point is the write and not something upstream of it. `gateway/src/marking.ts` states the
 * rule this honours: the bytes marked are the bytes written, and section 3.3 of `docs/receipt-spec.md`
 * publishes which region that is. The same argument reaches every other digest in the payload, and the
 * three of them cover different spans of one byte string: `res` is sha256 over the whole response as
 * transmitted, framing and sentinels and this gateway's own mark frame included; each item's `d` is
 * sha256 over one `data:` frame's payload and none of the framing around it; `mk.d` is sha256 over the
 * marked region the published rule finds inside those same bytes. A feed point chosen anywhere before
 * the write would state digests over bytes a client never received: the upstream's chunks are not what
 * goes out on a marking deployment (a frame is inserted between the last chunk and the sentinel, and the
 * tail holds bytes back until their meaning is settled), and a buffered body is spliced with the marking
 * member after the upstream's bytes arrive. `res` and `mk.d` are already taken at the write, so an item
 * digest taken anywhere else would be the one member of the three that disagreed with the other two.
 *
 * Why a second, per-write reading of the same rule, when one framer already walks the bytes. The
 * shipped `ResponseItemFramer` answers once: `finish()` reads the answer, caches it, and `feed()`
 * refuses a chunk after that. An instant has to be attached while the response is still arriving, so
 * this file keeps one framer fed with every byte written, which is where the digests and the empty-list
 * refusal come from, and asks a fresh one how many items each write closed. The two readings cannot
 * disagree about which bytes are which item, because the prefix a write closes always ends on a line
 * ending, and a framer's own held bytes are, by its construction, exactly the bytes after the last line
 * ending it has seen. That is why the bytes carried over here are cut at the last line ending rather
 * than at any boundary a transport chose: the carry is the same value the authoritative framer holds
 * internally, so the two walks read one sequence of lines. `answer()` compares every digest the batches
 * produced against the authoritative list before returning it, so the claim is checked on the bytes of
 * every response rather than left to this paragraph.
 *
 * Why the stamps cannot run against the array order. Chain order is the item array's order and stamp
 * order is `t`, and the reader refuses a disagreement (`ITEM_STAMP_OUT_OF_ORDER`) on bytes that are
 * otherwise well-formed, which would be a signed receipt this gateway filed and nobody could open. The
 * batches are appended in write order and a clock is read once per batch, so the only way the list could
 * descend is a source that steps backwards inside one response. `stampFor` takes the largest reading
 * this response has already carried and never issues a smaller one, which is not a correction of the
 * clock but a bound drawn from this process's own readings: an item is never stamped earlier than the
 * item the response put before it. That bound is a floor, and a floor is no ceiling, so
 * `boundStampsAt` holds every stamp at the instant the payload states: the one reading taken after the
 * last frame passed is the latest instant this response may date any of its items with. A source that
 * steps back is a deployment's problem and it is stated by `sd`, whose bound and name travel with the
 * receipt; what this file refuses to do is answer a clock that jumped by signing a document its own
 * reader rejects, or one that dates an item of a response after the receipt attesting it.
 */

/** The items of one response with an instant beside each, or the reason the response has none. */
export type FramedItemStamps =
  | { readonly framed: true; readonly stamps: readonly ItemStamp[] }
  | { readonly framed: false; readonly why: string };

/** How many items one write closed, and the one instant all of them were handed over at. */
interface Batch {
  readonly at: number;
  readonly digests: readonly Uint8Array[];
}

const LINE_FEED = 0x0a;
const CARRIAGE_RETURN = 0x0d;

/**
 * Everything at or before the last line ending of these bytes, as an index one past it, or 0 when they
 * hold no ending at all.
 *
 * A line ending is a line feed or a carriage return, which is the pair `ResponseItemFramer` reads a
 * stream at; the two together end one line, and cutting after either of them leaves a prefix made only
 * of complete lines. Whether the byte after a carriage return is a line feed or the start of the next
 * line cannot change that: in the first case the pair ends the line already cut here, in the second the
 * line feed ends an empty line, which frames no item.
 */
function pastLastLineEnding(bytes: Uint8Array): number {
  for (let at = bytes.length - 1; at >= 0; at -= 1) {
    const one = bytes[at];
    if (one === LINE_FEED || one === CARRIAGE_RETURN) return at + 1;
  }
  return 0;
}

function join(held: Uint8Array, chunk: Uint8Array): Uint8Array {
  if (held.length === 0) return chunk;
  const out = new Uint8Array(held.length + chunk.length);
  out.set(held);
  out.set(chunk, held.length);
  return out;
}

/**
 * The item stamps of a stream, read off the bytes as they go out.
 *
 * One instance answers for one response, which is what its `res` and its `itm` are the digests of.
 */
export class StreamedItemStamps {
  /** Every byte written to the client, walked once by the shipped reader. */
  private readonly authoritative = new ResponseItemFramer(true);
  private readonly batches: Batch[] = [];
  /** The bytes written since the last line ending: the one frame this stream has not closed. */
  private carry: Uint8Array = new Uint8Array(0);
  private highest: number | undefined;

  /**
   * `readStamp` is the whole-second reading this process takes its `iat` from. It is called once per
   * write that closed a frame, and never for a write that closed none, so a stream that produces no item
   * produces no reading either.
   */
  constructor(private readonly readStamp: () => number) {}

  /**
   * Record that these bytes were handed to the client, in this order, and nothing else was.
   *
   * The caller's contract is the one `gateway/src/server.ts` keeps at its single write closure: every
   * byte that reaches the socket passes through here, including the marking frame this gateway writes
   * itself and the closing sentinel it forwards. A byte that reached the client without being recorded
   * here, or recorded here without reaching the client, puts an item digest out of step with `res`.
   */
  written(chunk: Uint8Array): void {
    this.authoritative.feed(chunk);
    const combined = join(this.carry, chunk);
    const closed = pastLastLineEnding(combined);
    if (closed === 0) {
      // Nothing this write delivered ends a line, so no item passed and no instant was read. The bytes
      // are held whole: they are the head of a frame a later write will close.
      this.carry = combined.slice();
      return;
    }
    const framing = new ResponseItemFramer(true);
    framing.feed(combined.subarray(0, closed));
    const answer = framing.finish();
    const digests = answer.framed ? answer.items.map((one) => one.d) : [];
    if (digests.length === 0) {
      // A write that closed no frame passed no item, so no instant was read for it: a stream of blank
      // lines and event fields costs this process no clock readings it has nothing to attest.
      this.carry = combined.slice(closed);
      return;
    }
    // One reading per write, taken once for the whole batch: the frames a single write closed left this
    // process together, and a per-item loop would invent distinctions the transport never made.
    this.batches.push({ at: this.stampFor(), digests });
    this.carry = combined.slice(closed);
  }

  /**
   * The stamped list, or the refusal.
   *
   * The list and its digests come from the framer that saw every byte, and the batches only decide which
   * instant each of those items carries; the two are compared first, because a batch that had framed an
   * item the whole-body walk does not hold would mean this file and the shipped reader disagree about one
   * response, and an unissued receipt beats a signed document resting on that disagreement.
   */
  answer(): FramedItemStamps {
    const framing = this.authoritative.finish();
    if (!framing.framed) {
      if (this.batches.length > 0) {
        throw new Error('the response framed no item and the per-write readings framed some; one of the two is wrong');
      }
      return { framed: false, why: framing.why };
    }
    const items = framing.items;
    const batched = this.flatBatches();
    if (batched.length > items.length) {
      throw new Error(
        `${String(batched.length)} items framed during the writes and ${String(items.length)} at the response's end`,
      );
    }
    const stamped: ItemStamp[] = [];
    for (const [index, one] of batched.entries()) {
      const item = items[index];
      if (item === undefined || !equalBytes(one.d, item.d)) {
        throw new Error(`item ${String(index)} was digested differently at its write and at the response's end`);
      }
      stamped.push({ t: one.at, d: item.d });
    }
    if (batched.length < items.length) {
      // The frame the stream left unterminated, if there is one. It is an item the response sent: the
      // shipped reader counts it at the end rather than dropping bytes a client hashed into `res`, and
      // the only instant it can be given is the one this process reads now.
      const at = this.stampFor();
      for (const item of items.slice(batched.length)) {
        stamped.push({ t: at, d: item.d });
      }
    }
    // The order `t` is in follows the order the bytes were in: the batches were appended in write order,
    // each carries one reading, and `stampFor` never returns below the one before it.
    return { framed: true, stamps: stamped };
  }

  /** The per-write readings and the digests each closed, in the order the writes went out. */
  private flatBatches(): { readonly at: number; readonly d: Uint8Array }[] {
    const flat: { at: number; d: Uint8Array }[] = [];
    for (const batch of this.batches) {
      for (const d of batch.digests) flat.push({ at: batch.at, d });
    }
    return flat;
  }

  /**
   * This response's next stamp: a fresh reading, never below one this response already carried. The floor
   * is here and the ceiling is not, because the instant a response is stamped with is read where the
   * payload is built: `boundStampsAt` applies it once that reading exists.
   */
  private stampFor(): number {
    const read = this.readStamp();
    this.highest = this.highest === undefined ? read : Math.max(this.highest, read);
    return this.highest;
  }
}

/**
 * The stamps of one framing, each bounded by the instant the payload that carries them states.
 *
 * `iat` is read when the document is signed, and every frame of the response passed before that reading,
 * so under a source that does not step back `t <= iat` is a fact about the order of two readings and
 * nothing has to enforce it. The clamp `stampFor` applies is a floor drawn from this response's own
 * readings, and a floor stands above a later reading when the source runs backwards: the list stays
 * readable and the receipt states items dated after its own issuance. Bounding each stamp at the instant
 * the payload names keeps both claims true of the signed bytes, because a minimum taken against one
 * constant preserves the order it is applied to, so no item is dated above the document attesting it and
 * none below its predecessor.
 *
 * The bound is a ceiling and not a correction of the clock. What the source read is what it read, and a
 * stamp held down to `iat` states only that this process will not date an item of its own response after
 * the instant it signed; the source and the bound it declares about itself stay beside the list in `sd`.
 */
export function boundStampsAt(framing: FramedItemStamps, iat: number): FramedItemStamps {
  if (!framing.framed) return framing;
  return { framed: true, stamps: framing.stamps.map((one) => ({ t: Math.min(one.t, iat), d: one.d })) };
}

/**
 * The stamped list of a response the gateway holds whole before it sends it.
 *
 * A buffered body is one item, and `frameResponse` is what a verifier of these bytes runs, so this is
 * the same reading from the same code with an instant attached. The instant is taken here, at the point
 * the body is complete and digested, which is the moment this response's one frame passed: a buffered
 * reply is hashed and signed before its first byte reaches the client, and there is no earlier reading
 * that speaks about bytes nobody has been handed yet.
 */
export function stampedBufferedItem(readStamp: () => number, contentType: string, body: Uint8Array): FramedItemStamps {
  const framing = frameResponse(contentType, body);
  if (!framing.framed) return { framed: false, why: framing.why };
  const at = readStamp();
  return { framed: true, stamps: framing.items.map((one) => ({ t: at, d: one.d })) };
}
