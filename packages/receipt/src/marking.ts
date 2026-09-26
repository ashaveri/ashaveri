import { ReceiptError } from './errors.js';
import type { MarkingScheme } from './receipt.js';

/**
 * The extraction rule every `mk.sch` label names, held by the format package rather than by the
 * writer or by the client, because both of them are wrong the moment the two disagree and neither
 * disagreement is loud: a writer that digests one span and a reader that hashes another produces a
 * `MARK_MISMATCH` over bytes nobody edited. The published row for each label is
 * `docs/receipt-spec.md` section 3.3, and this file is where that row is executable.
 *
 * A label is bound to one byte shape for as long as it exists, so a shape change takes a new label
 * rather than quietly re-pointing an old one; a label this package does not name is refused by the
 * parser as `UNSUPPORTED_SCHEME` long before a rule here is asked about it.
 */

/** The top-level response member a marked completion carries, whichever shape it was served in. */
export const MARKING_MEMBER_NAME = 'ashaveri';

/**
 * The scheme label written *inside* the response member, which is the namespaced spelling of the
 * registry label `provenance-v1` written in `mk.sch`. The two are one scheme spelled for two
 * readers: the member is bytes of a transcript anyone may republish, where a name that travels needs
 * an owner, and `mk.sch` is a field of a document that already names its issuer.
 *
 * The rule does not read this text to *locate* a region, locating is structural, it reads it to
 * tell a marking apart from an unrelated member that happens to share the name, so a customer's own
 * `ashaveri` extension is not mistaken for something a receipt has an opinion about. Comparing a
 * fixed string is not looking a shape up from a label, which is the confusion `UNSUPPORTED_SCHEME`
 * exists to refuse.
 */
export const PROVENANCE_V1_MEMBER_SCHEME = 'ashaveri/provenance-v1';

/** The member a marked response carries: one `marking` object, and nothing else at that level. */
export interface ProvenanceV1Member {
  readonly marking: {
    readonly sch: typeof PROVENANCE_V1_MEMBER_SCHEME;
    readonly gen: 'ai';
    /** Unix seconds, whole: this text is hashed byte for byte as it is written. */
    readonly at: number;
  };
}

/**
 * The member a `provenance-v1` mark writes, built here so the writer and the rule read one
 * spelling. `at` is a whole number of seconds because the member is serialized as JSON text and
 * that text is what `mk.d` hashes: a fraction, or the negative zero a float keeps, would be baked
 * into the digest as a document no reader can reproduce from an integer.
 */
export function provenanceV1Member(at: number): ProvenanceV1Member {
  if (!Number.isSafeInteger(at) || at < 0) {
    throw new ReceiptError('BAD_PAYLOAD', `the marking time must be a non-negative integer of seconds, got ${String(at)}`);
  }
  return { marking: { sch: PROVENANCE_V1_MEMBER_SCHEME, gen: 'ai', at } };
}

/** The region `none` names, which is no bytes at all, so `mk.d` is sha256 over an empty input. */
export function emptyRegion(): Uint8Array {
  return new Uint8Array(0);
}

/** A byte span of a response, half-open: [start, end). */
interface Span {
  readonly start: number;
  readonly end: number;
}

const QUOTE = 0x22;
const BACKSLASH = 0x5c;
const COLON = 0x3a;
const COMMA = 0x2c;
const BRACE_OPEN = 0x7b;
const BRACE_CLOSE = 0x7d;
const BRACKET_OPEN = 0x5b;
const BRACKET_CLOSE = 0x5d;
const MINUS = 0x2d;
const PLUS = 0x2b;
const DOT = 0x2e;
const EXPONENT = [0x65, 0x45];
const ZERO = 0x30;
const NINE = 0x39;
const A_LOWER = 0x61;
const Z_LOWER = 0x7a;
const SPACE = 0x20;
const TAB = 0x09;
const LF = 0x0a;
const CR = 0x0d;
const DATA_PREFIX = 'data:';
const DONE_TOKEN = '[DONE]';

function isWhitespace(byte: number | undefined): boolean {
  return byte === SPACE || byte === TAB || byte === LF || byte === CR;
}

function isNumberByte(byte: number | undefined): boolean {
  if (byte === undefined) return false;
  return (byte >= ZERO && byte <= NINE) || byte === MINUS || byte === PLUS || byte === DOT || EXPONENT.includes(byte);
}

/**
 * Whether one decoded JSON value is the member this scheme names: an object carrying a `marking`
 * object whose `sch` is exactly the label above. Structural rather than textual, because the answer
 * decides how many regions a response carries, and a substring test would count the text of a
 * paragraph that merely mentions the shape.
 */
function isMarkingMemberValue(value: unknown): boolean {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const marking = (value as Record<string, unknown>)['marking'];
  if (typeof marking !== 'object' || marking === null || Array.isArray(marking)) return false;
  return (marking as Record<string, unknown>)['sch'] === PROVENANCE_V1_MEMBER_SCHEME;
}

/** Whether the JSON text of a member value is that member. `false` for text that does not parse. */
function isMarkingMemberText(text: string): boolean {
  try {
    return isMarkingMemberValue(JSON.parse(text) as unknown);
  } catch {
    return false;
  }
}

/**
 * One UTF-8 string token, starting at its opening quote. Only the ASCII bytes that delimit a token
 * are inspected, and no continuation byte of a multi-byte character can be one of them, so text in
 * any script passes through untouched and the offsets stay byte offsets rather than drifting into
 * character counts. Returns the offset just past the closing quote.
 */
function scanString(bytes: Uint8Array, at: number): number | null {
  if (bytes[at] !== QUOTE) return null;
  let i = at + 1;
  while (i < bytes.length) {
    const byte = bytes[i];
    if (byte === BACKSLASH) {
      i += 2;
      continue;
    }
    if (byte === QUOTE) return i + 1;
    i += 1;
  }
  return null;
}

function skipWhitespace(bytes: Uint8Array, at: number): number {
  let i = at;
  while (isWhitespace(bytes[i])) i += 1;
  return i;
}

/** The offset just past one JSON value, or null when the bytes are not a value from here. */
function scanValue(bytes: Uint8Array, at: number): number | null {
  const i = skipWhitespace(bytes, at);
  const first = bytes[i];
  if (first === undefined) return null;
  if (first === QUOTE) return scanString(bytes, i);
  if (first === BRACE_OPEN || first === BRACKET_OPEN) {
    const closesThis = first === BRACE_OPEN;
    let depth = 0;
    for (let j = i; j < bytes.length; j += 1) {
      const byte = bytes[j];
      if (byte === QUOTE) {
        const after = scanString(bytes, j);
        if (after === null) return null;
        j = after - 1;
        continue;
      }
      if (byte === BRACE_OPEN || byte === BRACKET_OPEN) {
        depth += 1;
        continue;
      }
      if (byte === BRACE_CLOSE || byte === BRACKET_CLOSE) {
        depth -= 1;
        if (depth === 0) return byte === (closesThis ? BRACE_CLOSE : BRACKET_CLOSE) ? j + 1 : null;
      }
    }
    return null;
  }
  if (isNumberByte(first)) {
    let j = i;
    while (isNumberByte(bytes[j])) j += 1;
    return j;
  }
  // `true`, `false`, `null`: a run of lower-case ASCII letters, and nothing else reaches here.
  let letters = 0;
  let j = i;
  for (;;) {
    const byte = bytes[j];
    if (byte === undefined || byte < A_LOWER || byte > Z_LOWER) break;
    j += 1;
    letters += 1;
  }
  return letters > 0 ? j : null;
}

/** The text of one string token, without its quotes, or null when the bytes are not one. */
function readStringToken(
  bytes: Uint8Array,
  at: number,
): { readonly text: string; readonly next: number } | null {
  if (bytes[at] !== QUOTE) return null;
  const after = scanString(bytes, at);
  if (after === null) return null;
  try {
    return { text: JSON.parse(new TextDecoder().decode(bytes.slice(at, after))) as string, next: after };
  } catch {
    return null;
  }
}

/** Where a body's one top-level JSON object sits, and whether it holds no members at all. */
interface ObjectSpan {
  readonly open: number;
  readonly close: number;
  readonly empty: boolean;
}

/**
 * The span of the single JSON object these bytes are, or null when they are not one object and
 * nothing else: trailing bytes other than whitespace belong to a second document, which is a body
 * this rule has no reading of: a stream pasted behind an object, or a response written twice. Neither
 * is read as whichever part happened to come first.
 *
 * This is the walk the marking member is added by and the walk the extraction rule reads, which is
 * the whole reason they are the same walk: a writer that found the closing brace one way and a reader
 * that found it another would agree with themselves and disagree with each other, and the only sign
 * of that is a digest that does not match.
 */
function objectSpan(bytes: Uint8Array): ObjectSpan | null {
  const open = skipWhitespace(bytes, 0);
  if (bytes[open] !== BRACE_OPEN) return null;
  let i = skipWhitespace(bytes, open + 1);
  const empty = bytes[i] === BRACE_CLOSE;
  const closed = (at: number): ObjectSpan | null =>
    skipWhitespace(bytes, at + 1) === bytes.length ? { open, close: at, empty } : null;
  for (;;) {
    i = skipWhitespace(bytes, i);
    if (bytes[i] === BRACE_CLOSE) return closed(i);
    const name = readStringToken(bytes, i);
    if (name === null) return null;
    let cursor = skipWhitespace(bytes, name.next);
    if (bytes[cursor] !== COLON) return null;
    const valueEnd = scanValue(bytes, skipWhitespace(bytes, cursor + 1));
    if (valueEnd === null) return null;
    cursor = skipWhitespace(bytes, valueEnd);
    if (bytes[cursor] === COMMA) {
      i = cursor + 1;
      continue;
    }
    if (bytes[cursor] !== BRACE_CLOSE) return null;
    return closed(cursor);
  }
}

/**
 * Where a marking member goes in a buffered body, and whether a comma has to precede it. `null` is
 * the answer for any body that is not exactly one JSON object, including a stream, whose frames are
 * marked a different way and by a different span.
 *
 * An insertion rather than a re-serialization: the bytes ahead of the member go on the wire as they
 * arrived, so the only difference between a marked completion and an unmarked one is the member and
 * the comma before it. A re-encode would have quietly rewritten the upstream's number spellings,
 * its escapes and its key order along the way, and every one of those is a different `res`.
 */
export function markingInsertionPoint(response: Uint8Array): { readonly at: number; readonly comma: boolean } | null {
  const span = objectSpan(response);
  return span === null ? null : { at: span.close, comma: !span.empty };
}

/**
 * The spans of every top-level `ashaveri` member of a body that is one JSON object, or null when the
 * body is not such an object, which is how a stream and a buffered body are told apart without
 * asking for a content type: a stream's bytes never read as one object, and an object's bytes never
 * read as a run of `data:` lines.
 *
 * Every member of the object is walked, so a response carrying the name twice reports two regions
 * rather than handing a reader the first or the last and letting that choice stand for a verdict.
 * Members nested below the top level are not candidates: the shape this scheme names is a member of
 * the completion, and a `marking` object that arrived inside somebody else's field is content `res`
 * covers as part of the transcript.
 */
function memberSpans(bytes: Uint8Array): Span[] {
  const span = objectSpan(bytes);
  if (span === null) return [];
  const found: Span[] = [];
  let i = span.open + 1;
  for (;;) {
    i = skipWhitespace(bytes, i);
    if (bytes[i] === BRACE_CLOSE) return found;
    const name = readStringToken(bytes, i);
    if (name === null) return found;
    const nameStart = i;
    const cursor = skipWhitespace(bytes, name.next);
    if (bytes[cursor] !== COLON) return found;
    const valueEnd = scanValue(bytes, skipWhitespace(bytes, cursor + 1));
    if (valueEnd === null) return found;
    if (name.text === MARKING_MEMBER_NAME && isMarkingMemberText(new TextDecoder().decode(bytes.slice(skipWhitespace(bytes, cursor + 1), valueEnd)))) {
      found.push({ start: nameStart, end: valueEnd });
    }
    const after = skipWhitespace(bytes, valueEnd);
    if (bytes[after] !== COMMA) return found;
    i = after + 1;
  }
}

/**
 * The candidate frames of a body written as server-sent events: each `data:` field line, its line
 * terminator excluded, whose payload is a completion chunk carrying no choices at all beside its
 * marking member. The empty `choices` is part of the shape rather than decoration: it is what makes
 * the frame a well-formed chunk to a client that accumulates a completion off a stream, which is
 * measured in `packages/sdk/test/unknown-response-members.test.ts`, and it is what keeps a mark out
 * of a frame that the same client hands to an accumulator un-parsed and then breaks.
 */
function frameLineSpans(bytes: Uint8Array): Span[] {
  const found: Span[] = [];
  const decoder = new TextDecoder();
  let lineStart = 0;
  for (let boundary = 0; boundary <= bytes.length; boundary += 1) {
    if (boundary !== bytes.length && bytes[boundary] !== LF) continue;
    let end = boundary;
    if (end > lineStart && bytes[end - 1] === CR) end -= 1;
    const start = lineStart;
    lineStart = boundary + 1;
    if (end - start < DATA_PREFIX.length) continue;
    const line = bytes.subarray(start, end);
    if (decoder.decode(line.subarray(0, DATA_PREFIX.length)) !== DATA_PREFIX) continue;
    let payloadAt = DATA_PREFIX.length;
    // One leading space belongs to the field's framing rather than to its value. The region below is
    // still the line exactly as transmitted, prefix and space included.
    if (line[payloadAt] === SPACE) payloadAt += 1;
    const text = decoder.decode(line.subarray(payloadAt));
    if (text === DONE_TOKEN) continue;
    let value: unknown;
    try {
      value = JSON.parse(text) as unknown;
    } catch {
      continue;
    }
    if (typeof value !== 'object' || value === null || Array.isArray(value)) continue;
    const record = value as Record<string, unknown>;
    const choices = record['choices'];
    if (!Array.isArray(choices) || choices.length !== 0) continue;
    if (isMarkingMemberValue(record[MARKING_MEMBER_NAME])) found.push({ start, end });
  }
  return found;
}

function regionsOf(response: Uint8Array): Span[] {
  return [...memberSpans(response), ...frameLineSpans(response)];
}

/** Which of the two ways a region fails to be exactly one, said in the refusal that names it. */
function whyNoSingleRegion(count: number, sch: MarkingScheme): string {
  if (sch === 'none') {
    return `a \`none\` receipt attests that no region of the response is marked, and these bytes carry ${String(
      count,
    )} matching provenance-v1`;
  }
  return count === 0
    ? 'the response carries no region matching the shape provenance-v1 names'
    : `the response carries ${String(count)} regions matching provenance-v1 and the rule names exactly one`;
}

/**
 * The bytes `mk.d` is the digest of, read off a response by the rule its scheme names.
 *
 * `none` answers with the empty region, and refuses a response that does carry a `provenance-v1`
 * region: the label declares that no region of *this response* is marked, which is a claim about
 * the bytes rather than only about what the gateway intended. It is also the only place the
 * upstream-injection case is caught on a deployment that marks nothing, since the streaming path
 * forwards a backend's bytes without reading inside them.
 *
 * No region and two regions are both `MARK_MISMATCH`, and the detail says which: what a reader is
 * owed is the fact that the marking does not match the attestation, and neither a response with
 * nothing to hash nor one with an ambiguous region is that fact by a different name. Neither is
 * `INVALID_SIGNATURE`, which stays the code for a receipt that is not authentic.
 */
export function extractMarkedRegion(sch: MarkingScheme, response: Uint8Array): Uint8Array {
  const regions = regionsOf(response);
  if (sch === 'none') {
    if (regions.length !== 0) throw new ReceiptError('MARK_MISMATCH', whyNoSingleRegion(regions.length, sch));
    return emptyRegion();
  }
  if (regions.length !== 1) throw new ReceiptError('MARK_MISMATCH', whyNoSingleRegion(regions.length, sch));
  const [only] = regions;
  if (only === undefined) throw new ReceiptError('MARK_MISMATCH', whyNoSingleRegion(0, sch));
  return response.slice(only.start, only.end);
}
