import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { once } from 'node:events';
import OpenAI, { OpenAIError } from 'openai';
import { AshaveriClient, SdkError } from '../src/index.js';

/**
 * Response shapes served by the local listener below. The names say what the response carries, not
 * what a caller asked for: `unseen-member` responses hold one top-level member that no chat
 * completion schema declares, and `unrecognised-frame` is a streamed data frame that is neither a
 * completion chunk nor the `[DONE]` sentinel.
 */
type Shape = 'buffered' | 'buffered-unseen-member' | 'stream-unseen-member' | 'stream-unrecognised-frame';

const PROBE_MEMBER = 'probe_extension';
const PROBE_VALUE: Record<string, unknown> = { note: 'a member no chat completion declares', seq: 7 };
const UNRECOGNISED_OBJECT = 'unrecognised.response';
const COMPLETION_ID = 'chatcmpl-response-shapes-1';
const MODEL = 'response-shape-model';
const CREATED = 1_700_000_000;
const CONTENT = 'measured content';
const COMPLETION_KEYS = ['id', 'object', 'created', 'model', 'choices', 'usage'];
const CHUNK_KEYS = ['id', 'object', 'created', 'model', 'choices'];
const MESSAGES = [{ role: 'user' as const, content: 'hi' }];

function completionBody(withProbeMember: boolean): Record<string, unknown> {
  const body: Record<string, unknown> = {
    id: COMPLETION_ID,
    object: 'chat.completion',
    created: CREATED,
    model: MODEL,
    choices: [{ index: 0, message: { role: 'assistant', content: CONTENT }, finish_reason: 'stop' }],
    usage: { prompt_tokens: 11, completion_tokens: 5, total_tokens: 16 },
  };
  if (withProbeMember) {
    body[PROBE_MEMBER] = PROBE_VALUE;
  }
  return body;
}

function chunkBody(delta: Record<string, unknown>, finishReason: string | null): Record<string, unknown> {
  return {
    id: COMPLETION_ID,
    object: 'chat.completion.chunk',
    created: CREATED,
    model: MODEL,
    choices: [{ index: 0, delta, finish_reason: finishReason }],
  };
}

/** The frames of a streamed response, in the order the listener writes them. */
function streamFrames(shape: Shape): Record<string, unknown>[] {
  const chunks = [
    chunkBody({ role: 'assistant', content: 'meas' }, null),
    chunkBody({ content: 'ured co' }, null),
    chunkBody({ content: 'ntent' }, null),
    chunkBody({}, 'stop'),
  ];
  if (shape === 'stream-unseen-member') {
    // The tail chunk carries content for nobody: `choices` is empty and the member is the payload.
    return [...chunks, { id: COMPLETION_ID, object: 'chat.completion.chunk', created: CREATED, model: MODEL, choices: [], [PROBE_MEMBER]: PROBE_VALUE }];
  }
  if (shape === 'stream-unrecognised-frame') {
    return [...chunks, { object: UNRECOGNISED_OBJECT, [PROBE_MEMBER]: PROBE_VALUE }];
  }
  return chunks;
}

function responseFrames(shape: Shape): string[] {
  if (shape === 'buffered' || shape === 'buffered-unseen-member') {
    return [JSON.stringify(completionBody(shape === 'buffered-unseen-member'))];
  }
  return [...streamFrames(shape).map((frame) => `data: ${JSON.stringify(frame)}\n\n`), 'data: [DONE]\n\n'];
}

const SHAPES: readonly Shape[] = ['buffered', 'buffered-unseen-member', 'stream-unseen-member', 'stream-unrecognised-frame'];

/**
 * A member read off a response object as plain data, because neither consumer's declared type names
 * a member its schema never heard of.
 */
function memberOf(value: unknown, name: string): unknown {
  return typeof value === 'object' && value !== null ? (value as Record<string, unknown>)[name] : undefined;
}

function ownMembersOf(value: unknown): string[] {
  return Object.keys(value as object);
}

function choiceCount(value: unknown): number {
  const choices = memberOf(value, 'choices');
  return Array.isArray(choices) ? choices.length : -1;
}

function bufferedText(completion: unknown): string {
  const choices = memberOf(completion, 'choices');
  const first = Array.isArray(choices) ? choices[0] : undefined;
  return String(memberOf(memberOf(first, 'message'), 'content'));
}

function streamedText(chunks: readonly unknown[]): string {
  return chunks
    .map((chunk) => {
      const choices = memberOf(chunk, 'choices');
      const first = Array.isArray(choices) ? choices[0] : undefined;
      const content = memberOf(memberOf(first, 'delta'), 'content');
      return typeof content === 'string' ? content : '';
    })
    .join('');
}

let server: Server | null = null;
let baseUrl = '';

beforeAll(async () => {
  server = createServer((request, response) => {
    const path = request.url ?? '';
    const shape = SHAPES.find((candidate) => path.startsWith(`/${candidate}/`));
    const chunks: Buffer[] = [];
    request.on('data', (chunk: Buffer) => chunks.push(chunk));
    request.on('end', () => {
      if (shape === undefined) {
        response.statusCode = 404;
        response.end('no such response shape');
        return;
      }
      const streamed = !shape.startsWith('buffered');
      response.statusCode = 200;
      response.setHeader('content-type', streamed ? 'text/event-stream' : 'application/json');
      for (const frame of responseFrames(shape)) {
        response.write(frame);
      }
      response.end();
    });
  });
  // Port 0 asks the operating system for a free port and the address is read back once the listener
  // is up, because a port picked by hand can land inside a range Windows reserves.
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(async () => {
  // Both consumers hold their connection open for reuse, so closing the listener alone would wait
  // on sockets nobody is going to use again.
  const listening = server;
  if (listening !== null) {
    listening.closeAllConnections();
    listening.close();
    await once(listening, 'close');
  }
});

function officialClient(shape: Shape): OpenAI {
  return new OpenAI({ apiKey: 'response-shape-key', baseURL: `${baseUrl}/${shape}/v1`, maxRetries: 0 });
}

/**
 * The SDK's own client, in the mode that asks for nothing but the response: `off` sends no nonce and
 * fetches no receipt, so what these tests read is the parser rather than a verification outcome.
 */
function sdkClient(shape: Shape): AshaveriClient {
  return new AshaveriClient({ baseUrl: `${baseUrl}/${shape}/v1`, verify: 'off' });
}

async function collectOfficialChunks(client: OpenAI): Promise<unknown[]> {
  const stream = await client.chat.completions.create({ model: MODEL, messages: MESSAGES, stream: true });
  const chunks: unknown[] = [];
  for await (const chunk of stream) {
    chunks.push(chunk);
  }
  return chunks;
}

async function collectSdkChunks(client: AshaveriClient): Promise<{ chunks: unknown[]; error: unknown }> {
  const stream = await client.chat.completions.stream({ model: MODEL, messages: MESSAGES });
  const chunks: unknown[] = [];
  try {
    for await (const chunk of stream) {
      chunks.push(chunk);
    }
  } catch (error) {
    return { chunks, error };
  }
  return { chunks, error: null };
}

describe('a buffered chat completion response', () => {
  it('hands both consumers the members the response carried, and nothing else', async () => {
    const completion = await officialClient('buffered').chat.completions.create({ model: MODEL, messages: MESSAGES });
    expect(bufferedText(completion)).toBe(CONTENT);
    expect(ownMembersOf(completion)).toEqual(COMPLETION_KEYS);
    expect(memberOf(completion, PROBE_MEMBER)).toBeUndefined();

    const result = await sdkClient('buffered').chat.completions.create({ model: MODEL, messages: MESSAGES });
    expect(result.completion.choices[0]?.message.content).toBe(CONTENT);
    expect(ownMembersOf(result.completion)).toEqual(COMPLETION_KEYS);
    expect(memberOf(result.completion, PROBE_MEMBER)).toBeUndefined();
  });

  it('keeps an unseen top-level member on the object the official client returns', async () => {
    const completion = await officialClient('buffered-unseen-member').chat.completions.create({ model: MODEL, messages: MESSAGES });
    expect(bufferedText(completion)).toBe(CONTENT);
    expect(ownMembersOf(completion)).toEqual([...COMPLETION_KEYS, PROBE_MEMBER]);
    expect(memberOf(completion, PROBE_MEMBER)).toEqual(PROBE_VALUE);
    // Re-serialising the object the client returned still carries the member, so nothing was
    // dropped on the way out of the transport either.
    expect(JSON.stringify(completion)).toContain(JSON.stringify(PROBE_VALUE));
  });

  it('keeps an unseen top-level member on the completion the SDK returns', async () => {
    const result = await sdkClient('buffered-unseen-member').chat.completions.create({ model: MODEL, messages: MESSAGES });
    expect(result.completion.choices[0]?.message.content).toBe(CONTENT);
    expect(ownMembersOf(result.completion)).toEqual([...COMPLETION_KEYS, PROBE_MEMBER]);
    expect(memberOf(result.completion, PROBE_MEMBER)).toEqual(PROBE_VALUE);
  });
});

describe('a streamed chat completion whose last chunk has no choices and carries an unseen member', () => {
  it('is walked to its last chunk by the official client, which passes that chunk through', async () => {
    const chunks = await collectOfficialChunks(officialClient('stream-unseen-member'));
    expect(chunks).toHaveLength(5);
    expect(streamedText(chunks)).toBe(CONTENT);
    expect(chunks.slice(0, 4).map((chunk) => ownMembersOf(chunk))).toEqual([CHUNK_KEYS, CHUNK_KEYS, CHUNK_KEYS, CHUNK_KEYS]);
    const tail = chunks[4];
    expect(ownMembersOf(tail)).toEqual([...CHUNK_KEYS, PROBE_MEMBER]);
    expect(choiceCount(tail)).toBe(0);
    expect(memberOf(tail, PROBE_MEMBER)).toEqual(PROBE_VALUE);
  });

  it('reaches the accumulation helper too, whose finished completion carries the member', async () => {
    const stream = officialClient('stream-unseen-member').chat.completions.stream({ model: MODEL, messages: MESSAGES });
    const chunks: unknown[] = [];
    for await (const chunk of stream) {
      chunks.push(chunk);
    }
    expect(streamedText(chunks)).toBe(CONTENT);
    const finished = await stream.finalChatCompletion();
    expect(bufferedText(finished)).toBe(CONTENT);
    expect(ownMembersOf(finished)).toEqual(['object', PROBE_MEMBER, 'id', 'choices', 'created', 'model']);
    expect(memberOf(finished, PROBE_MEMBER)).toEqual(PROBE_VALUE);
  });

  it('is walked to its last chunk by the SDK, which yields that chunk as a chunk', async () => {
    const { chunks, error } = await collectSdkChunks(sdkClient('stream-unseen-member'));
    expect(error).toBeNull();
    expect(chunks).toHaveLength(5);
    expect(streamedText(chunks)).toBe(CONTENT);
    const tail = chunks[4];
    expect(ownMembersOf(tail)).toEqual([...CHUNK_KEYS, PROBE_MEMBER]);
    expect(choiceCount(tail)).toBe(0);
    expect(memberOf(tail, PROBE_MEMBER)).toEqual(PROBE_VALUE);
  });
});

describe('a streamed response carrying a frame that is neither a chunk nor the sentinel', () => {
  it('is delivered whole by the official client, which does not read the frame', async () => {
    const chunks = await collectOfficialChunks(officialClient('stream-unrecognised-frame'));
    expect(chunks).toHaveLength(5);
    expect(streamedText(chunks)).toBe(CONTENT);
    const odd = chunks[4];
    expect(ownMembersOf(odd)).toEqual(['object', PROBE_MEMBER]);
    expect(memberOf(odd, 'object')).toBe(UNRECOGNISED_OBJECT);
    expect(memberOf(odd, 'id')).toBeUndefined();
    expect(memberOf(odd, 'choices')).toBeUndefined();
    expect(memberOf(odd, PROBE_MEMBER)).toEqual(PROBE_VALUE);
  });

  it('stops the official client once it has to add the frame up', async () => {
    const stream = officialClient('stream-unrecognised-frame').chat.completions.stream({ model: MODEL, messages: MESSAGES });
    const chunks: unknown[] = [];
    let error: unknown = null;
    try {
      for await (const chunk of stream) {
        chunks.push(chunk);
      }
      await stream.finalChatCompletion();
    } catch (err) {
      error = err;
    }
    // The four content chunks arrive before the failure, so a consumer that already showed them has
    // a half-read stream rather than an untouched response.
    expect(chunks).toHaveLength(4);
    expect(streamedText(chunks)).toBe(CONTENT);
    expect(error).toBeInstanceOf(OpenAIError);
    expect((error as Error).message).toBe('chunk.choices is not iterable');
  });

  it('is refused by the SDK parser, which names it a chunk that is not one', async () => {
    const { chunks, error } = await collectSdkChunks(sdkClient('stream-unrecognised-frame'));
    expect(chunks).toHaveLength(4);
    expect(streamedText(chunks)).toBe(CONTENT);
    expect(error).toBeInstanceOf(SdkError);
    expect((error as SdkError).code).toBe('GATEWAY_ERROR');
    expect((error as Error).message).toBe('stream chunk is not a chat completion chunk');
  });
});
