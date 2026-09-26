import {
  MARKING_MEMBER_NAME,
  emptyRegion,
  markingInsertionPoint,
  provenanceV1Member,
  type Marking,
} from '@ashaveri/receipt';
import { sha256 } from './digest.js';

/**
 * Writing the mark, which is one job done in two shapes and answered by one digest.
 *
 * The rule this module keeps is that the bytes marked are the bytes written: a member is added to a
 * buffered body before that body is hashed, and a frame goes through the same write closure the rest
 * of the stream took before the stream's digest is finalised. A receipt issued over bytes a client
 * never received is the failure this file exists to make impossible. What a reader looks for is
 * published in section 3.3 of `docs/receipt-spec.md` and read back by `extractMarkedRegion` in
 * `@ashaveri/receipt`, so a writer here and a reader there cannot drift without a vector disagreeing.
 */

/** How a completion is framed on its way to a client: one field line, then a blank line. */
export const SSE_FIELD_PREFIX = 'data: ';
export const SSE_FRAME_END = '\n\n';

/**
 * The id of the frame a marked stream writes. It is a fixed text rather than a copy of the upstream's
 * completion id for the reason `gateway/src/backend.ts` states: the streaming path puts a backend's
 * buffers straight into the hash and the socket without reading inside them, so the only identifier
 * this gateway holds for a response is one it minted. The frame is a chunk in every field a client
 * reads (`id`, `object`, `created`, `model`, `choices`) and its `choices` is empty because that is
 * the shape measured to survive an accumulator: a frame that is neither a chunk nor the sentinel is
 * delivered whole and then stops the accumulation, after content has already reached the caller.
 */
export const MARKING_CHUNK_ID = 'chatcmpl-ashaveri-marking';

/** The sentinel a stream ends with, in the two spellings of its field name that this holds back. */
const SENTINEL_TOKEN = new TextEncoder().encode('[DONE]');
const SENTINEL_FIELD = new TextEncoder().encode('data:');
/** The commonest spelling, which is the one worth holding a few bytes back for. */
const SENTINEL_FRAME = new TextEncoder().encode('data: [DONE]');
const SPACE = 0x20;
const LF = 0x0a;
const CR = 0x0d;

/** The marking attestation of a response this gateway added nothing to. */
export function unmarked(): Marking {
  return { sch: 'none', d: sha256(emptyRegion()) };
}

/** A buffered body either carries the mark, or the reason it cannot is what the caller is told. */
export type BufferedMarking =
  | { readonly marked: true; readonly body: Uint8Array; readonly marking: Marking }
  | { readonly marked: false; readonly why: string };

/**
 * The body to send, with the marking member added at the top level, and the digest of exactly the
 * bytes of that member.
 *
 * A body that cannot hold the member is refused rather than served unmarked: the flag on this path
 * said this deployment marks, and a receipt reading `none` afterwards would be an accurate statement
 * about a response nobody asked for. Two shapes cannot carry it, and each is refused with the fact
 * that says which: bytes that are not exactly one JSON object, and a body where the member name is
 * already taken, which is what an upstream that marks its own output writes.
 *
 * The member is spliced in rather than the body re-serialized, so the bytes ahead of it are the
 * upstream's own and the region `mk.d` names is a slice of what the client is sent. The writer takes
 * its insertion point from the same walk the reader takes its region from, in
 * `markingInsertionPoint`, which is the only way those two spans stay the same length.
 */
export function markBufferedBody(body: Uint8Array, at: number): BufferedMarking {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(body));
  } catch {
    return { marked: false, why: 'the upstream body is not JSON, so no marking member can be added to it' };
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return { marked: false, why: 'the upstream body is not one JSON object, so no marking member can be added to it' };
  }
  if (Object.hasOwn(parsed, MARKING_MEMBER_NAME)) {
    // Theirs or ours has to win, and a reader cannot be left to pick: a body with two members of one
    // name is read as whichever its parser likes, and the extraction rule counts two regions and
    // refuses. So the name being taken is a shape this gateway cannot mark.
    return { marked: false, why: `the upstream body already carries a ${MARKING_MEMBER_NAME} member` };
  }
  const insert = markingInsertionPoint(body);
  if (insert === null) {
    // Parses as an object with something after it, which is a body no reader settles on one reading
    // of: the member would go inside the first document and `res` would cover both.
    return { marked: false, why: 'the upstream body is one JSON object followed by other bytes, so no marking member can be added to it' };
  }
  const region = new TextEncoder().encode(`"${MARKING_MEMBER_NAME}":${JSON.stringify(provenanceV1Member(at))}`);
  return { marked: true, body: splice(body, insert, region), marking: { sch: 'provenance-v1', d: sha256(region) } };
}

/** The body with one member inserted at the point the shared walk named, and nothing else changed. */
function splice(body: Uint8Array, at: { readonly at: number; readonly comma: boolean }, region: Uint8Array): Uint8Array {
  const comma = at.comma ? new TextEncoder().encode(',') : new Uint8Array(0);
  const out = new Uint8Array(body.length + comma.length + region.length);
  out.set(body.subarray(0, at.at));
  out.set(comma, at.at);
  out.set(region, at.at + comma.length);
  out.set(body.subarray(at.at), at.at + comma.length + region.length);
  return out;
}

/** The frame a marked stream writes, and the digest of its line without the blank line after it. */
export function markingFrame(
  model: string,
  at: number,
): { readonly frame: Uint8Array; readonly line: Uint8Array; readonly marking: Marking } {
  const line = `${SSE_FIELD_PREFIX}${JSON.stringify({
    id: MARKING_CHUNK_ID,
    object: 'chat.completion.chunk',
    created: at,
    model,
    choices: [],
    [MARKING_MEMBER_NAME]: provenanceV1Member(at),
  })}`;
  return {
    line: new TextEncoder().encode(line),
    frame: new TextEncoder().encode(`${line}${SSE_FRAME_END}`),
    marking: { sch: 'provenance-v1', d: sha256(new TextEncoder().encode(line)) },
  };
}

/** Where the sentinel starts in these bytes, if they end with it and with nothing but line ends after. */
function sentinelStart(bytes: Uint8Array): number {
  let end = bytes.length;
  while (end > 0 && (bytes[end - 1] === LF || bytes[end - 1] === CR)) end -= 1;
  const tokenAt = end - SENTINEL_TOKEN.length;
  if (tokenAt < 0 || !equalsAt(bytes, tokenAt, SENTINEL_TOKEN)) return -1;
  let fieldAt = tokenAt;
  // One space between the field name and its value is framing rather than content, which is why it
  // is stepped over here and kept inside the region a marked frame carries.
  if (bytes[fieldAt - 1] === SPACE) fieldAt -= 1;
  fieldAt -= SENTINEL_FIELD.length;
  return fieldAt < 0 || !equalsAt(bytes, fieldAt, SENTINEL_FIELD) ? -1 : fieldAt;
}

function equalsAt(bytes: Uint8Array, at: number, token: Uint8Array): boolean {
  if (at < 0 || at + token.length > bytes.length) return false;
  for (let i = 0; i < token.length; i += 1) {
    if (bytes[at + i] !== token[i]) return false;
  }
  return true;
}

/**
 * How many of these bytes' last ones could still turn out to be the start of a sentinel. A write
 * boundary falls wherever the transport likes, including inside the eight letters of `[DONE]`, and
 * the only bytes this gateway may hold back are ones whose meaning is not settled yet. A stream that
 * ends mid-word is a truncated stream, and holding its bytes says nothing about it that its digest
 * does not already say.
 */
function unsettledSuffix(bytes: Uint8Array): number {
  for (let length = Math.min(bytes.length, SENTINEL_FRAME.length - 1); length > 0; length -= 1) {
    if (equalsAt(bytes, bytes.length - length, SENTINEL_FRAME.subarray(0, length))) return length;
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
 * The tail of a stream, held just long enough to write a mark inside the stream rather than after it.
 * A client that reads to the sentinel stops there, so a frame appended after it is inside the hash
 * and outside what that client hands its caller; the shape the design settles on is one frame ahead
 * of the sentinel, and this is what makes that true of a wire that arrives in pieces nobody chose.
 *
 * Nothing is buffered beyond what could still turn out to be the sentinel, so a completion whose
 * bytes all arrived in one write keeps everything ahead of that frame and loses no part of its
 * streaming. The one shape where the mark does land last is a stream that writes something *after*
 * its own sentinel: a client that stops early will not read the frame, and the bytes are still the
 * ones the receipt attests, which section 3.3 states rather than leaving to be inferred.
 */
export class MarkedStreamTail {
  private held: Uint8Array = new Uint8Array(0);

  /** The bytes this write makes safe to put on the socket now, which may be none of them. */
  writable(chunk: Uint8Array): Uint8Array {
    const combined = join(this.held, chunk);
    const at = sentinelStart(combined);
    if (at >= 0) {
      this.held = combined.subarray(at);
      return combined.subarray(0, at);
    }
    const keep = unsettledSuffix(combined);
    this.held = combined.subarray(combined.length - keep);
    return combined.subarray(0, combined.length - keep);
  }

  /** The pieces still owed to the client, in the order it should receive them. */
  finishing(frame: Uint8Array): Uint8Array[] {
    const at = sentinelStart(this.held);
    if (at === 0) return [frame, this.held];
    if (at > 0) return [this.held.subarray(0, at), frame, this.held.subarray(at)];
    // Held bytes that are not a sentinel go out as they arrived, with the mark behind them: the
    // alternative would splice a chunk into the middle of a frame that was already on its way.
    return this.held.length === 0 ? [frame] : [this.held, frame];
  }
}
