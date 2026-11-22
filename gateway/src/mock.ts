import { randomNonce } from '@ashaveri/receipt';
import { HOST_CLOCK_SOURCE, type TimeSource } from './store.js';

export const DEFAULT_MOCK_MODEL = 'mock-model-1';

export interface ChatMessage {
  readonly role: string;
  // One field naming both shapes, because a second one would leave a message free to state both or neither.
  /**
   * What this message carries, in whichever of the two shapes a client sends it: text on its own, or the
   * parts a request naming an image, an audio clip or a file sends in place of text. The parts are kept as
   * they arrived, because a parsed message is what the mock backend reads, and a part whose members were
   * dropped on the way in would make that backend's answer about a request nobody sent.
   */
  readonly content: string | readonly ContentPart[];
}

/**
 * One content part: only its `type` is read here, and every other member travels through unchanged, for
 * the reason section 1 of `docs/multimodal-admission.md` gives.
 */
export interface ContentPart {
  readonly type: string;
  readonly [member: string]: unknown;
}

export interface ChatCompletionRequest {
  readonly model: string;
  readonly messages: readonly ChatMessage[];
  readonly stream: boolean;
}

export interface MockCompletion {
  readonly id: string;
  readonly created: number;
  readonly model: string;
  readonly content: string;
  readonly promptTokens: number;
  readonly completionTokens: number;
}

/**
 * The sentences a request body is refused with. Both readers below state them out of this one list: the
 * parse that builds a message graph and the scan that reads a body's bytes answer one question about the
 * same grammar, and two spellings of the answer would let a request be refused one way by the route and
 * another by whoever later builds the graph the route did not need.
 */
const NOT_AN_OBJECT = 'request body must be a JSON object';
const NO_MESSAGES = 'messages must be a non-empty array';
const MESSAGE_NOT_OBJECT = 'each message must be an object';
const NO_ROLE = 'each message must have a non-empty string role';
const NO_CONTENT = 'each message must have a string content or an array of content parts';
const EMPTY_CONTENT_ARRAY = 'a content array must hold at least one content part';
const PART_NOT_OBJECT = 'each content part must be an object';
const PART_NO_TYPE = 'each content part must have a string type';
const BAD_MODEL = 'model must be a non-empty string';
const BAD_STREAM = 'stream must be a boolean';

export function parseChatCompletionRequest(raw: unknown): ChatCompletionRequest {
  if (typeof raw !== 'object' || raw === null) {
    throw new RequestError(NOT_AN_OBJECT);
  }
  const body = raw as Record<string, unknown>;
  const messagesRaw = body['messages'];
  if (!Array.isArray(messagesRaw) || messagesRaw.length === 0) {
    throw new RequestError(NO_MESSAGES);
  }
  const messages: ChatMessage[] = [];
  for (const message of messagesRaw) {
    if (typeof message !== 'object' || message === null) {
      throw new RequestError(MESSAGE_NOT_OBJECT);
    }
    const role = (message as Record<string, unknown>)['role'];
    const content = (message as Record<string, unknown>)['content'];
    if (typeof role !== 'string' || role.length === 0) {
      throw new RequestError(NO_ROLE);
    }
    messages.push({ role, content: parseContent(content) });
  }
  const modelRaw = body['model'];
  const model = modelRaw === undefined ? DEFAULT_MOCK_MODEL : modelRaw;
  if (typeof model !== 'string' || model.length === 0) {
    throw new RequestError(BAD_MODEL);
  }
  const streamRaw = body['stream'];
  const stream = streamRaw === undefined ? false : streamRaw;
  if (typeof stream !== 'boolean') {
    throw new RequestError(BAD_STREAM);
  }
  return { model, messages, stream };
}

export class RequestError extends Error {}

/**
 * The two shapes a message's content arrives in, admitted as the caller sent them. Only a part's `type`
 * is asked of it, for the reason section 1 of `docs/multimodal-admission.md` gives.
 */
function parseContent(raw: unknown): string | readonly ContentPart[] {
  if (typeof raw === 'string') {
    return raw;
  }
  if (!Array.isArray(raw)) {
    throw new RequestError(NO_CONTENT);
  }
  const listed = raw as readonly unknown[];
  if (listed.length === 0) {
    throw new RequestError(EMPTY_CONTENT_ARRAY);
  }
  const parts: ContentPart[] = [];
  for (const part of listed) {
    if (typeof part !== 'object' || part === null) {
      throw new RequestError(PART_NOT_OBJECT);
    }
    const type = (part as Record<string, unknown>)['type'];
    if (typeof type !== 'string') {
      throw new RequestError(PART_NO_TYPE);
    }
    parts.push(part as ContentPart);
  }
  return parts;
}

/**
 * The two members this gateway's routes read out of a request, and nothing else of it. `messages` is
 * decided about but never carried: the backend that forwards these bytes to an inference server asks the
 * same two questions of them, and a body whose bulk is one inline file would otherwise be held as a
 * string, as a graph, and as the copy made to add one metering member, for the whole of one completion.
 */
export interface ChatCompletionHead {
  readonly model: string;
  readonly stream: boolean;
}

// A JSON structural byte is always ASCII, and every byte of a multi-byte UTF-8 sequence is at or above
// 0x80, so a walk over the bytes settles on a quote, a comma or a brace without asking whether a
// character is still being read. That is what lets the scan below bound a token rather than decode it.
const SPACE = 0x20;
const TAB = 0x09;
const LINE_FEED = 0x0a;
const CARRIAGE_RETURN = 0x0d;
const QUOTE = 0x22;
const BACKSLASH = 0x5c;
const COLON = 0x3a;
const COMMA = 0x2c;
const CURLY_OPEN = 0x7b;
const CURLY_CLOSE = 0x7d;
const SQUARE_OPEN = 0x5b;
const SQUARE_CLOSE = 0x5d;
const MINUS = 0x2d;
const PLUS = 0x2b;
const DOT = 0x2e;
const SOLIDUS = 0x2f;
const DIGIT_ZERO = 0x30;
const DIGIT_NINE = 0x39;
const UPPER_A = 0x41;
const UPPER_F = 0x46;
const LOWER_E = 0x65;
const UPPER_E = 0x45;
const LOWER_A = 0x61;
const LOWER_B = 0x62;
const LOWER_F = 0x66;
const LOWER_N = 0x6e;
const LOWER_R = 0x72;
const LOWER_T = 0x74;
const LOWER_U = 0x75;

/**
 * The escapes that state one character on their own: the two quotes a token can carry without ending, the
 * solidus a caller may escape although it needs no escaping, and the four control characters JSON named.
 */
const SIMPLE_ESCAPES = new Set([QUOTE, BACKSLASH, SOLIDUS, LOWER_B, LOWER_F, LOWER_N, LOWER_R, LOWER_T]);
const TRUE_LITER = Uint8Array.from([0x74, 0x72, 0x75, 0x65]);
const FALSE_LITER = Uint8Array.from([0x66, 0x61, 0x6c, 0x73, 0x65]);
const NULL_LITER = Uint8Array.from([0x6e, 0x75, 0x6c, 0x6c]);

const decoder = new TextDecoder();

/** The half-open range of bytes one value, name or element holds. */
interface Span {
  readonly start: number;
  readonly end: number;
}

/** One member of an object: the name it was written under, and the range of the value beside it. */
interface MemberSpan extends Span {
  readonly name: string;
}

function isSpace(byte: number | undefined): boolean {
  return byte === SPACE || byte === TAB || byte === LINE_FEED || byte === CARRIAGE_RETURN;
}

function isDigit(byte: number | undefined): boolean {
  return byte !== undefined && byte >= DIGIT_ZERO && byte <= DIGIT_NINE;
}

function isHexDigit(byte: number | undefined): boolean {
  if (byte === undefined) return false;
  return (
    isDigit(byte) ||
    (byte >= LOWER_A && byte <= LOWER_F) ||
    (byte >= UPPER_A && byte <= UPPER_F)
  );
}

function pastSpace(bytes: Uint8Array, at: number): number {
  let i = at;
  while (isSpace(bytes[i])) i += 1;
  return i;
}

function startsWith(bytes: Uint8Array, at: number, liter: Uint8Array): boolean {
  for (let i = 0; i < liter.length; i += 1) {
    if (bytes[at + i] !== liter[i]) return false;
  }
  return true;
}

/** The string one token holds, quotes and escapes taken off the way the parse takes them off. */
function decodeToken(bytes: Uint8Array, span: Span): string {
  return JSON.parse(decoder.decode(bytes.subarray(span.start, span.end))) as string;
}

/**
 * The byte just past the escape sequence whose backslash sits at `at`, or null when these bytes do not hold
 * one. A backslash states a character, and only the eight bytes `SIMPLE_ESCAPES` names and a `u` followed
 * by four hexadecimal digits state one, so a backslash before anything else is not a token's character and
 * not the end of the token either: the parse refuses it, and so does this.
 */
function pastEscape(bytes: Uint8Array, at: number): number | null {
  const lead = bytes[at + 1];
  if (lead === undefined) return null;
  if (lead === LOWER_U) {
    for (let digit = at + 2; digit <= at + 5; digit += 1) {
      if (!isHexDigit(bytes[digit])) return null;
    }
    return at + 6;
  }
  return SIMPLE_ESCAPES.has(lead) ? at + 2 : null;
}

/**
 * The byte just past a string token opening at `at`, or null when these bytes never close one. An escape is
 * read rather than stepped over: the two bytes it is made of decide whether the token closes where the next
 * quote sits, and a backslash the grammar does not know is a token that never closes.
 */
function pastString(bytes: Uint8Array, at: number): number | null {
  if (bytes[at] !== QUOTE) return null;
  let i = at + 1;
  for (;;) {
    const byte = bytes[i];
    if (byte === undefined) return null;
    // A control byte inside a token is not what JSON writes there, and the parse refuses it; so does this.
    if (byte < SPACE) return null;
    if (byte === BACKSLASH) {
      const escaped = pastEscape(bytes, i);
      if (escaped === null) return null;
      i = escaped;
      continue;
    }
    if (byte === QUOTE) return i + 1;
    i += 1;
  }
}

/** The byte just past one number, or null when these bytes do not hold one. */
function pastNumber(bytes: Uint8Array, at: number): number | null {
  let i = bytes[at] === MINUS ? at + 1 : at;
  const lead = bytes[i];
  if (lead === DIGIT_ZERO) {
    i += 1;
  } else if (isDigit(lead)) {
    do i += 1; while (isDigit(bytes[i]));
  } else {
    return null;
  }
  if (bytes[i] === DOT) {
    i += 1;
    if (!isDigit(bytes[i])) return null;
    do i += 1; while (isDigit(bytes[i]));
  }
  if (bytes[i] === LOWER_E || bytes[i] === UPPER_E) {
    i += 1;
    if (bytes[i] === PLUS || bytes[i] === MINUS) i += 1;
    if (!isDigit(bytes[i])) return null;
    do i += 1; while (isDigit(bytes[i]));
  }
  return i;
}

/** The byte just past one value of any kind, or null when the bytes at `at` are not a value. */
function pastValue(bytes: Uint8Array, at: number): number | null {
  const start = pastSpace(bytes, at);
  const byte = bytes[start];
  if (byte === QUOTE) return pastString(bytes, start);
  if (byte === MINUS || isDigit(byte)) return pastNumber(bytes, start);
  if (byte === CURLY_OPEN) return readObject(bytes, start)?.end ?? null;
  if (byte === SQUARE_OPEN) return readArray(bytes, start)?.end ?? null;
  if (startsWith(bytes, start, TRUE_LITER)) return start + TRUE_LITER.length;
  if (startsWith(bytes, start, FALSE_LITER)) return start + FALSE_LITER.length;
  if (startsWith(bytes, start, NULL_LITER)) return start + NULL_LITER.length;
  return null;
}

/** The members of the object whose `{` sits at `at`, and the byte past its `}`, or null if it is not one. */
function readObject(bytes: Uint8Array, at: number): { readonly members: MemberSpan[]; readonly end: number } | null {
  const opening = pastSpace(bytes, at);
  if (bytes[opening] !== CURLY_OPEN) return null;
  const members: MemberSpan[] = [];
  let i = pastSpace(bytes, opening + 1);
  if (bytes[i] === CURLY_CLOSE) return { members, end: i + 1 };
  for (;;) {
    const nameEnd = pastString(bytes, i);
    if (nameEnd === null) return null;
    const name = decodeToken(bytes, { start: i, end: nameEnd });
    i = pastSpace(bytes, nameEnd);
    if (bytes[i] !== COLON) return null;
    const start = pastSpace(bytes, i + 1);
    const end = pastValue(bytes, start);
    if (end === null) return null;
    members.push({ name, start, end });
    i = pastSpace(bytes, end);
    if (bytes[i] === COMMA) {
      i = pastSpace(bytes, i + 1);
      continue;
    }
    return bytes[i] === CURLY_CLOSE ? { members, end: i + 1 } : null;
  }
}

/** The span of every element of the array whose `[` sits at `at`, and the byte past its `]`. */
function readArray(bytes: Uint8Array, at: number): { readonly elements: Span[]; readonly end: number } | null {
  const opening = pastSpace(bytes, at);
  if (bytes[opening] !== SQUARE_OPEN) return null;
  const elements: Span[] = [];
  let i = pastSpace(bytes, opening + 1);
  if (bytes[i] === SQUARE_CLOSE) return { elements, end: i + 1 };
  for (;;) {
    const start = pastSpace(bytes, i);
    const end = pastValue(bytes, start);
    if (end === null) return null;
    elements.push({ start, end });
    i = pastSpace(bytes, end);
    if (bytes[i] === COMMA) {
      i = pastSpace(bytes, i + 1);
      continue;
    }
    return bytes[i] === SQUARE_CLOSE ? { elements, end: i + 1 } : null;
  }
}

/** The last member written under `name`, because a document that repeats a key is read as its last value. */
function lastNamed(members: readonly MemberSpan[], name: string): MemberSpan | undefined {
  let found: MemberSpan | undefined;
  for (const member of members) {
    if (member.name === name) found = member;
  }
  return found;
}

/**
 * The members of a value the walk over the whole body has already accepted. An array carries none, which is
 * what the parse asks too: `typeof` answers the object question of a list, and the member the caller then
 * looks for on it is absent, exactly as it was once a graph stood there.
 */
function membersOfValue(bytes: Uint8Array, span: Span): readonly MemberSpan[] {
  if (bytes[span.start] === SQUARE_OPEN) return [];
  const read = readObject(bytes, span.start);
  // The invariant is the walk's own: a span it bounded as an object re-reads as one, since both reads take
  // the same bytes under the same rules. Landing here means the two stopped agreeing about these bytes, and
  // what a caller then reads is the route's sentence for a body that is not one JSON value.
  if (read === null) throw new SyntaxError('an object the walk read is read again');
  return read.members;
}

/**
 * The spans of a content stated as parts, nothing for a content stated as text, and null for a value that
 * is neither. Only the bytes of a part are bounded here: the media a part carries is the bulk of a large
 * request, and it is read as a length rather than as a string, because nothing this gateway does with it
 * needs its text.
 */
function partsOf(bytes: Uint8Array, content: Span): Span[] | null {
  if (bytes[content.start] === QUOTE) return [];
  const read = readArray(bytes, content.start);
  if (read === null) return null;
  if (read.elements.length === 0) throw new RequestError(EMPTY_CONTENT_ARRAY);
  return read.elements;
}

/**
 * The grammar a request body has to hold, read off its bytes.
 *
 * The refusals are the parse's own, in the parse's own order: the message list first, then `model`, then
 * `stream`. A body that is not one JSON value is answered with a `SyntaxError`, which is what the route
 * already turns into its sentence about invalid JSON, and a body that is one but shaped wrong is answered
 * with the `RequestError` the route prints. `JSON.parse` is asked of a member's bytes only where the
 * member's text is what is being weighed, so a token holding an inline file is bounded and never decoded.
 */
export function readChatCompletionHead(raw: Uint8Array): ChatCompletionHead {
  const opening = pastSpace(raw, 0);
  if (raw[opening] !== CURLY_OPEN) {
    const end = pastValue(raw, opening);
    if (end === null || pastSpace(raw, end) < raw.length) throw new SyntaxError('the request bytes are not one JSON value');
    // A list is an object to `typeof` and holds no `messages` member, so it meets the sentence the member
    // is refused with rather than the sentence a number or a bare word meets.
    throw new RequestError(raw[opening] === SQUARE_OPEN ? NO_MESSAGES : NOT_AN_OBJECT);
  }
  const body = readObject(raw, opening);
  if (body === null || pastSpace(raw, body.end) < raw.length) {
    throw new SyntaxError('the request bytes are not one JSON object');
  }

  const messages = lastNamed(body.members, 'messages');
  if (messages === undefined) throw new RequestError(NO_MESSAGES);
  const list = readArray(raw, messages.start);
  if (list === null || list.elements.length === 0) throw new RequestError(NO_MESSAGES);
  for (const message of list.elements) {
    const kind = raw[message.start];
    if (kind !== CURLY_OPEN && kind !== SQUARE_OPEN) throw new RequestError(MESSAGE_NOT_OBJECT);
    const fields = membersOfValue(raw, message);
    const role = lastNamed(fields, 'role');
    // An empty token is two bytes and nothing decodes to fewer, so the quotes settle whether a role was
    // written without this line reaching for the text between them.
    if (role === undefined || raw[role.start] !== QUOTE || role.end - role.start <= 2) {
      throw new RequestError(NO_ROLE);
    }
    const content = lastNamed(fields, 'content');
    if (content === undefined) throw new RequestError(NO_CONTENT);
    const parts = partsOf(raw, content);
    if (parts === null) throw new RequestError(NO_CONTENT);
    for (const part of parts) {
      const partKind = raw[part.start];
      if (partKind !== CURLY_OPEN && partKind !== SQUARE_OPEN) throw new RequestError(PART_NOT_OBJECT);
      const type = lastNamed(membersOfValue(raw, part), 'type');
      if (type === undefined || raw[type.start] !== QUOTE) throw new RequestError(PART_NO_TYPE);
    }
  }

  const model = lastNamed(body.members, 'model');
  let modelName = DEFAULT_MOCK_MODEL;
  if (model !== undefined) {
    if (raw[model.start] !== QUOTE) throw new RequestError(BAD_MODEL);
    modelName = decodeToken(raw, model);
    if (modelName.length === 0) throw new RequestError(BAD_MODEL);
  }

  const stream = lastNamed(body.members, 'stream');
  if (stream === undefined) return { model: modelName, stream: false };
  if (stream.end - stream.start === TRUE_LITER.length && startsWith(raw, stream.start, TRUE_LITER)) {
    return { model: modelName, stream: true };
  }
  if (stream.end - stream.start === FALSE_LITER.length && startsWith(raw, stream.start, FALSE_LITER)) {
    return { model: modelName, stream: false };
  }
  throw new RequestError(BAD_STREAM);
}

function responseId(): string {
  return `chatcmpl-${b64Id(randomNonce())}`;
}

function b64Id(bytes: Uint8Array): string {
  let binary = '';
  for (const b of bytes) {
    binary += String.fromCharCode(b);
  }
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

/** The text one part states. A part naming anything else states no text, so this reads none out of it. */
function partText(part: ContentPart): string {
  const value = part['text'];
  return part.type === 'text' && typeof value === 'string' ? value : '';
}

/**
 * The characters one message offers as text: a string is all of it, and an array only what its text
 * parts state, because the bytes of an image, an audio clip or a file are not characters this code can
 * read, and a figure drawn from their length would be a measurement of nothing.
 */
function textCharacters(content: string | readonly ContentPart[]): number {
  if (typeof content === 'string') {
    return content.length;
  }
  return content.reduce((sum, part) => sum + partText(part).length, 0);
}

/**
 * The clause naming what the mock read of one message. Both shapes answer in characters of text, and a
 * parts message states its part counts beside them, so the figure names what it counted and what it left
 * out rather than reading as a metering of every byte the caller sent.
 */
function describeContent(content: string | readonly ContentPart[]): string {
  if (typeof content === 'string') {
    return `with ${content.length} characters`;
  }
  const text = content.filter((part) => part.type === 'text').length;
  return (
    `with ${textCharacters(content)} characters in ${text} text part(s) ` +
    `beside ${content.length - text} part(s) naming something else`
  );
}

export function mockCompletion(
  request: ChatCompletionRequest,
  options: {
    /**
     * Where this completion's creation instant comes from, named. Absent means `HOST_CLOCK_SOURCE`: the
     * mock backend has no platform to read a time from, so the honest answer is this host's own clock at
     * the bound nobody measured, and a deployment that wired a source of its own should hand that same
     * source here rather than let the body carry an unlabelled reading.
     */
    readonly time?: TimeSource;
  } = {},
): MockCompletion {
  const time = options.time ?? HOST_CLOCK_SOURCE;
  const last = request.messages[request.messages.length - 1] as ChatMessage;
  const totalChars = request.messages.reduce((sum, message) => sum + textCharacters(message.content), 0);
  const content =
    `This is a mock completion from signerd --mock. ` +
    `Your request contained ${request.messages.length} message(s); ` +
    `the last message role was "${last.role}" ${describeContent(last.content)}.`;
  return {
    id: responseId(),
    created: Math.floor(time.nowSeconds()),
    model: request.model,
    content,
    promptTokens: Math.ceil(totalChars / 4),
    completionTokens: Math.ceil(content.length / 4),
  };
}

export function completionJson(completion: MockCompletion): string {
  return JSON.stringify({
    id: completion.id,
    object: 'chat.completion',
    created: completion.created,
    model: completion.model,
    choices: [
      {
        index: 0,
        message: { role: 'assistant', content: completion.content },
        finish_reason: 'stop',
      },
    ],
    usage: {
      prompt_tokens: completion.promptTokens,
      completion_tokens: completion.completionTokens,
      total_tokens: completion.promptTokens + completion.completionTokens,
    },
  });
}

export function completionSse(completion: MockCompletion): string {
  const chunkCount = 3;
  const pieceLength = Math.ceil(completion.content.length / chunkCount);
  const pieces: string[] = [];
  for (let i = 0; i < completion.content.length; i += pieceLength) {
    pieces.push(completion.content.slice(i, i + pieceLength));
  }
  if (pieces.length === 0) {
    pieces.push('');
  }
  const chunk = (delta: Record<string, unknown>, finishReason: string | null): string =>
    JSON.stringify({
      id: completion.id,
      object: 'chat.completion.chunk',
      created: completion.created,
      model: completion.model,
      choices: [{ index: 0, delta, finish_reason: finishReason }],
    });
  let out = '';
  out += `data: ${chunk({ role: 'assistant', content: pieces[0] }, null)}\n\n`;
  for (const piece of pieces.slice(1)) {
    out += `data: ${chunk({ content: piece }, null)}\n\n`;
  }
  out += `data: ${chunk({}, 'stop')}\n\n`;
  out += 'data: [DONE]\n\n';
  return out;
}
