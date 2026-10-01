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
 * never received is the failure this file exists to make impossible. The streamed shape is written as a
 * frame, which is one field line and the blank line after it, and a frame is only a frame with the
 * frame before it closed: a mark set down on a line two `data:` prefixes share is a line no client's
 * parser makes a frame out of, so the terminator the upstream owed goes out first and the mark begins
 * its own. What a reader looks for is
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

/** The frame end, as bytes, which is what a stream that stopped mid-frame is owed ahead of a mark. */
const FRAME_END = new TextEncoder().encode(SSE_FRAME_END);

/**
 * How many of the bytes already written it takes to tell whether a frame is open. A blank line is two
 * line endings with nothing between them, the wider ending is the pair, so the last three bytes of what
 * was written answer it and nothing older is asked.
 */
const FRAME_WINDOW = 3;

/** The last bytes of one sequence, which is all `closesFrame` reads. */
function windowOf(bytes: Uint8Array): Uint8Array {
  return bytes.length <= FRAME_WINDOW ? bytes : bytes.subarray(bytes.length - FRAME_WINDOW);
}

/**
 * The width of the line ending that ends just before `at`: the pair once, a lone carriage return or line
 * feed once, and nothing otherwise. This is the ending section 3.1 of `docs/receipt-spec.md` publishes and
 * both shipped readers walk, so a frame closed by a carriage return is closed here too.
 */
function lineEndingBefore(bytes: Uint8Array, at: number): number {
  if (at <= 0) return 0;
  if (bytes[at - 1] === CR) return 1;
  if (bytes[at - 1] === LF) return bytes[at - 2] === CR ? 2 : 1;
  return 0;
}

/**
 * Whether these bytes close the frame they are in, which is a blank line: two line endings with nothing
 * between them. No bytes at all is the same answer, because the first frame of a body begins at the head
 * of the body and needs nothing ahead of it.
 *
 * This is a stronger test than "the last byte ended a line", and the strength is the point. A frame is one
 * field line and the blank line after it, so a mark written on a new line of an event the upstream never
 * closed is not a mark written as its own frame: a client that parses the response as server-sent events
 * concatenates the two `data:` fields it holds into one, and the completion it then reads is neither the
 * upstream's chunk nor this gateway's chunk. Measured against such a client, only the blank line makes the
 * mark a chunk of its own.
 */
function closesFrame(bytes: Uint8Array): boolean {
  if (bytes.length === 0) return true;
  const first = lineEndingBefore(bytes, bytes.length);
  return first > 0 && lineEndingBefore(bytes, bytes.length - first) > 0;
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
 * ones the receipt attests, which section 3.1 states rather than leaving to be inferred. That row is
 * measured of both readers here, in `gateway/test/response-frame-readers.test.ts`: the framing attests
 * the frame behind the sentinel as an item and this tail answers that the body does not end on a
 * sentinel, so its mark goes last.
 *
 * A mark is written as a frame: one field line and the blank line after it, with a closed frame ahead of
 * it. The upstream can stop mid-frame, with its last line carrying no terminator at all, or carrying a
 * line ending but never the blank line that dispatches it. Either way the terminator the upstream owed
 * is written before the mark, and the mark begins a frame of its own. Without that the client is handed one line
 * holding two `data:` prefixes, which is a line no conforming parser produces a frame from: the receipt
 * would then honestly attest bytes whose marked region the published rule refuses under the scheme the same
 * payload names. The bytes a completion is attested over are the bytes the upstream sent plus the frame end
 * it owed and the mark, in that order, and nothing in them is edited or moved.
 */
export class MarkedStreamTail {
  private held: Uint8Array = new Uint8Array(0);

  /**
   * The last bytes this tail put on the socket, kept only to tell whether the frame they are in was
   * closed. A blank line straddling a write boundary is still one blank line, so this is a window over
   * what was written rather than a reading of the last write.
   */
  private written: Uint8Array = new Uint8Array(0);

  /** The bytes this write makes safe to put on the socket now, which may be none of them. */
  writable(chunk: Uint8Array): Uint8Array {
    const combined = join(this.held, chunk);
    const at = sentinelStart(combined);
    const ready = at >= 0 ? combined.subarray(0, at) : combined.subarray(0, combined.length - unsettledSuffix(combined));
    this.held = at >= 0 ? combined.subarray(at) : combined.subarray(combined.length - unsettledSuffix(combined));
    this.noteWritten(ready);
    return ready;
  }

  /** The pieces still owed to the client, in the order it should receive them. */
  finishing(frame: Uint8Array): Uint8Array[] {
    const at = sentinelStart(this.held);
    // What goes out ahead of the mark: the held bytes that are not the sentinel, which is all of them
    // when these bytes are no sentinel at all and none of them when they begin with one.
    const before = at > 0 ? this.held.subarray(0, at) : at < 0 ? this.held : new Uint8Array(0);
    const after = at >= 0 ? this.held.subarray(at) : new Uint8Array(0);
    const owed = closesFrame(windowOf(join(this.written, before))) ? null : FRAME_END;
    // Half a sentinel is not a sentinel, and splicing a chunk into the middle of a frame that was
    // already on its way is the worse error: the held bytes go out as they arrived, the frame end the
    // upstream owed goes out after them, and the mark begins its own frame.
    return [before, owed, frame, after].filter((piece): piece is Uint8Array => piece !== null);
  }

  /** These bytes went to the socket, so they are what the next frame has to be separated from. */
  private noteWritten(bytes: Uint8Array): void {
    if (bytes.length === 0) return;
    this.written = windowOf(join(this.written, bytes));
  }
}
