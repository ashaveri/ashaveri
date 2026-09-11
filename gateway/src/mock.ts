import { randomNonce } from '@ashaveri/receipt';

export const DEFAULT_MOCK_MODEL = 'mock-model-1';

export interface ChatMessage {
  readonly role: string;
  readonly content: string;
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
    if (typeof content !== 'string') {
      throw new RequestError('each message must have a string content');
    }
    messages.push({ role, content });
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

export function mockCompletion(request: ChatCompletionRequest): MockCompletion {
  const last = request.messages[request.messages.length - 1] as ChatMessage;
  const totalChars = request.messages.reduce((sum, message) => sum + message.content.length, 0);
  const content =
    `This is a mock completion from signerd --mock. ` +
    `Your request contained ${request.messages.length} message(s); ` +
    `the last message role was "${last.role}" with ${last.content.length} characters.`;
  return {
    id: responseId(),
    created: Math.floor(Date.now() / 1000),
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
