import {
  completionJson,
  completionSse,
  mockCompletion,
  type ChatCompletionRequest,
} from './mock.js';

export interface CompletionUsage {
  readonly model: string;
  readonly promptTokens: number;
  readonly completionTokens: number;
}

/**
 * A completed upstream exchange, described in terms the receipt layer needs.
 * `chunks` must yield exactly the bytes the client receives, because `res` is
 * the hash of that stream rather than of a re-serialization. The upstream's own
 * completion id is not part of this contract: it names nothing the gateway looks
 * up, because a receipt is addressed by the id this gateway mints for the
 * credential that asked.
 */
export interface BackendResponse {
  readonly status: number;
  readonly contentType: string;
  readonly chunks: AsyncIterable<Uint8Array>;
  /** Resolves after `chunks` is exhausted. Rejected only if the exchange failed mid-body. */
  readonly usage: Promise<CompletionUsage>;
}

export interface CompletionBackend {
  respond(rawRequest: Buffer, request: ChatCompletionRequest): Promise<BackendResponse>;
}

async function* oneShot(bytes: Uint8Array): AsyncGenerator<Uint8Array> {
  yield bytes;
}

export function mockBackend(): CompletionBackend {
  return {
    async respond(_rawRequest, request) {
      const completion = mockCompletion(request);
      const body = new TextEncoder().encode(
        request.stream ? completionSse(completion) : completionJson(completion),
      );
      return {
        status: 200,
        contentType: request.stream ? 'text/event-stream' : 'application/json',
        chunks: oneShot(body),
        usage: Promise.resolve({
          model: completion.model,
          promptTokens: completion.promptTokens,
          completionTokens: completion.completionTokens,
        }),
      };
    },
  };
}
