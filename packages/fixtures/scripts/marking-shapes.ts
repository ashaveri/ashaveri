import { MARKING_MEMBER_NAME, provenanceV1Member } from '@ashaveri/receipt';

/**
 * The response shapes a `provenance-v1` mark is written into, built once here so the two generators
 * that publish them cannot come to describe them differently.
 *
 * Both shapes are the ones the published row in section 3.3 of `docs/receipt-spec.md` names: a member
 * of the top-level object in a buffered body, and one `data:` field line of a stream whose payload is
 * a chunk carrying an empty `choices`. In each the region is a substring of the response by
 * construction, which is the property the vectors are about: `mk.d` is a digest of bytes inside the
 * response, not of a value re-rendered from it.
 *
 * The content ahead of a region is deliberately not ASCII. A region is a span of *bytes*, so a body
 * whose text is multi-byte is the case that tells an implementation counting characters apart from one
 * counting bytes, and that difference is the whole of a matching digest versus one that never matches.
 */

const ID = 'chatcmpl-marking-1';
const MODEL = 'mock-model-1';
const CONTENT = 'Mock reply: café ☕ served.';
const PREFIX = 'data: ';
const SEPARATOR = '\n\n';
const TERMINATOR = 'data: [DONE]\n\n';

/** The marking time every published vector carries, so a digest is reproducible rather than recent. */
export const MARKING_AT = 1_772_000_000;

/**
 * The member as a writer serializes it: the name, the colon and the value, spelled exactly as the
 * body carries them, because that text is what `mk.d` hashes.
 */
export function memberText(at: number = MARKING_AT): string {
  return `${JSON.stringify(MARKING_MEMBER_NAME)}:${JSON.stringify(provenanceV1Member(at))}`;
}

/** The same member an hour later: one field of one number, and a region that hashes to something else. */
export function substitutedMember(): string {
  return memberText(MARKING_AT + 3_600);
}

/** One marked shape: the response as it goes on the wire, and the one region inside it. */
export interface MarkedShape {
  readonly response: string;
  readonly region: string;
}

/** A response carrying the shape more than once, which has no single region and so no digest. */
export interface AmbiguousShape {
  readonly response: string;
  readonly region: null;
}

function completionBody(): string {
  return JSON.stringify({
    id: ID,
    object: 'chat.completion',
    created: MARKING_AT,
    model: MODEL,
    choices: [{ index: 0, message: { role: 'assistant', content: CONTENT }, finish_reason: 'stop' }],
    usage: { prompt_tokens: 9, completion_tokens: 6, total_tokens: 15 },
  });
}

/** The chunk frames of a streamed completion, none of which carries a marking. */
function streamChunks(): string {
  const chunk = (delta: Record<string, unknown>, finishReason: string | null): string =>
    `${PREFIX}${JSON.stringify({
      id: ID,
      object: 'chat.completion.chunk',
      created: MARKING_AT,
      model: MODEL,
      choices: [{ index: 0, delta, finish_reason: finishReason }],
    })}${SEPARATOR}`;
  return (
    chunk({ role: 'assistant', content: CONTENT.slice(0, 11) }, null) +
    chunk({ content: CONTENT.slice(11, 18) }, null) +
    chunk({ content: CONTENT.slice(18) }, null) +
    chunk({}, 'stop')
  );
}

/**
 * One marking frame: a chunk in every field a client reads, whose `choices` is empty, with the member
 * beside it. The region is the field line as transmitted, the blank line after it excluded.
 */
function markingLine(member: string): string {
  const head = JSON.stringify({ id: ID, object: 'chat.completion.chunk', created: MARKING_AT, model: MODEL, choices: [] });
  return `${PREFIX}${head.slice(0, -1)},${member}}`;
}

/**
 * A buffered completion carrying one marking member, spliced in ahead of the brace that closes it. An
 * insertion rather than a re-serialization, which is what the gateway does: the bytes ahead of the
 * region stay the upstream's own, down to their spacing and their key order.
 */
export function markedBuffered(member: string = memberText()): MarkedShape {
  const body = completionBody();
  const brace = body.lastIndexOf('}');
  return { response: `${body.slice(0, brace)},${member}${body.slice(brace)}`, region: member };
}

/** A buffered completion carrying the member twice, which is two candidates and no verdict. */
export function bufferedWithTwoMembers(): AmbiguousShape {
  const body = completionBody();
  const brace = body.lastIndexOf('}');
  const pair = `${memberText()},${substitutedMember()}`;
  return { response: `${body.slice(0, brace)},${pair}${body.slice(brace)}`, region: null };
}

/** A stream carrying its mark ahead of the sentinel, inside the bytes the response digest covers. */
export function markedStreamed(member: string = memberText()): MarkedShape {
  return { response: `${streamChunks()}${markingLine(member)}${SEPARATOR}${TERMINATOR}`, region: markingLine(member) };
}

/** A stream whose backend marked itself as well, so the frames carry the shape twice. */
export function streamedWithTwoMarkingFrames(): AmbiguousShape {
  const first = markingLine(memberText());
  const second = markingLine(substitutedMember());
  return { response: `${streamChunks()}${first}${SEPARATOR}${second}${SEPARATOR}${TERMINATOR}`, region: null };
}

/** The completion of the buffered shape with no marking in it at all. */
export function unmarkedResponse(): string {
  return completionBody();
}

/** The stream of the streamed shape with no marking frame in it. */
export function unmarkedStream(): string {
  return `${streamChunks()}${TERMINATOR}`;
}
