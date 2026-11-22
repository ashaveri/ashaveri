import {
  completionJson,
  completionSse,
  mockCompletion,
  type ChatCompletionRequest,
} from './mock.js';
import type { TimeSource } from './store.js';

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
  /**
   * Set by a backend that gave up on metering this exchange rather than pay for it, and by nothing else.
   *
   * Absent means the figures were asked for, which is what a hand-written backend that never considered
   * the question does. The member exists because the receipt cannot say any of this itself: `tok` is a
   * required map of two non-negative integers in the published format, so a completion whose token figures
   * were never obtained still has to state two of them, and a reader left with `0` and `0` cannot tell a
   * measured nothing from an unmeasured something. This is the half the response can carry, and the route
   * writes it as `x-ashaveri-metering`.
   */
  readonly meteringDeclined?: boolean;
}

export interface CompletionBackend {
  respond(rawRequest: Buffer, request: ChatCompletionRequest): Promise<BackendResponse>;
}

async function* oneShot(bytes: Uint8Array): AsyncGenerator<Uint8Array> {
  yield bytes;
}

export function mockBackend(options: {
  /**
   * The source the completions this backend serves are dated by, handed to `mockCompletion` as that
   * function's own `time` option rather than as this bag. Absent means that function's own default,
   * which is `HOST_CLOCK_SOURCE` and names itself as such.
   */
  readonly time?: TimeSource;
} = {}): CompletionBackend {
  return {
    async respond(_rawRequest, request) {
      const completion = mockCompletion(request, { time: options.time });
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
