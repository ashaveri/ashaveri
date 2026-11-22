import {
  completionJson,
  completionSse,
  mockCompletion,
  type ChatCompletionRequest,
} from './mock.js';
import type { TimeSource } from './store.js';

/**
 * What the serving stack reported of one completion, as one pair.
 *
 * The two figures are one value rather than two members that happen to carry numbers, which is the rule
 * the receipt format already states: an upstream's usage event carries both together, so a count beside
 * an absence is a metering state no producer can be in and the writer refuses to sign one. The absence
 * arm exists because a producer that never got an answer has something true to say about it, and a zero
 * is not that thing.
 */
export type CompletionUsage =
  | {
      readonly model: string;
      readonly promptTokens: number;
      readonly completionTokens: number;
    }
  | {
      readonly model: string;
      readonly promptTokens: null;
      readonly completionTokens: null;
    };

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
   * the question does. The member is not the statement that a completion went unmeasured: the format
   * admits `tok` as either two non-negative integers or two nulls that nothing reported them, and a
   * producer that asked for nothing states the nulls, so the signed document says for itself which of the
   * two it holds. What this names is the gateway's own act, that it declined the copy the ask costs, and
   * the route writes it as `x-ashaveri-metering` on a streamed answer before the body ends. That moment is
   * the reason it is still carried: it is the only place a caller is told before it holds a receipt, and a
   * deployment that reads only the header learns what this gateway did rather than what arrived.
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
