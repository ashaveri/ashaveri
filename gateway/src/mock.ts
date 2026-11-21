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
 * One content part: only its `type` is read here, and every other member travels through unchanged,
 * because the grammar of a part is the provider's to define and a gateway that checked it would be
 * answering a well-formed request with this code's opinion of another vendor's field names.
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

export function parseChatCompletionRequest(raw: unknown): ChatCompletionRequest {
  if (typeof raw !== 'object' || raw === null) {
    throw new RequestError('request body must be a JSON object');
  }
  const body = raw as Record<string, unknown>;
  const messagesRaw = body['messages'];
  if (!Array.isArray(messagesRaw) || messagesRaw.length === 0) {
    throw new RequestError('messages must be a non-empty array');
  }
  const messages: ChatMessage[] = [];
  for (const message of messagesRaw) {
    if (typeof message !== 'object' || message === null) {
      throw new RequestError('each message must be an object');
    }
    const role = (message as Record<string, unknown>)['role'];
    const content = (message as Record<string, unknown>)['content'];
    if (typeof role !== 'string' || role.length === 0) {
      throw new RequestError('each message must have a non-empty string role');
    }
    messages.push({ role, content: parseContent(content) });
  }
  const modelRaw = body['model'];
  const model = modelRaw === undefined ? DEFAULT_MOCK_MODEL : modelRaw;
  if (typeof model !== 'string' || model.length === 0) {
    throw new RequestError('model must be a non-empty string');
  }
  const streamRaw = body['stream'];
  const stream = streamRaw === undefined ? false : streamRaw;
  if (typeof stream !== 'boolean') {
    throw new RequestError('stream must be a boolean');
  }
  return { model, messages, stream };
}

export class RequestError extends Error {}

/**
 * The two shapes a message's content arrives in, admitted as the caller sent them. Only a part's `type`
 * is asked of it, so a content member this code has never seen is served rather than ending as a refusal
 * over a field name.
 */
function parseContent(raw: unknown): string | readonly ContentPart[] {
  if (typeof raw === 'string') {
    return raw;
  }
  if (!Array.isArray(raw)) {
    throw new RequestError('each message must have a string content or an array of content parts');
  }
  const listed = raw as readonly unknown[];
  if (listed.length === 0) {
    throw new RequestError('a content array must hold at least one content part');
  }
  const parts: ContentPart[] = [];
  for (const part of listed) {
    if (typeof part !== 'object' || part === null) {
      throw new RequestError('each content part must be an object');
    }
    const type = (part as Record<string, unknown>)['type'];
    if (typeof type !== 'string') {
      throw new RequestError('each content part must have a string type');
    }
    parts.push(part as ContentPart);
  }
  return parts;
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
