import { isEventStream } from '@ashaveri/receipt';
import type { CompletionBackend, CompletionUsage } from './backend.js';

export interface UpstreamOptions {
  /** Root of an OpenAI-compatible server, without the trailing /chat/completions. */
  readonly baseUrl: string;
  readonly fetchImpl?: typeof fetch;
}

interface Deferred<T> {
  readonly promise: Promise<T>;
  readonly resolve: (value: T) => void;
  readonly reject: (error: unknown) => void;
}

function deferred<T>(): Deferred<T> {
  let resolve: (value: T) => void = () => undefined;
  let reject: (error: unknown) => void = () => undefined;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

/**
 * Token metering needs usage on streamed responses, which vLLM only emits when
 * asked. The usage-only event is still forwarded verbatim, so `res` keeps
 * binding exactly the bytes the client received.
 */
function requestForUpstream(raw: Buffer): Buffer {
  try {
    const body = JSON.parse(raw.toString('utf8')) as Record<string, unknown>;
    const existing = body['stream_options'];
    const options = typeof existing === 'object' && existing !== null ? (existing as Record<string, unknown>) : {};
    if (options['include_usage'] === true) {
      return raw;
    }
    body['stream_options'] = { ...options, include_usage: true };
    return Buffer.from(JSON.stringify(body), 'utf8');
  } catch {
    return raw;
  }
}

interface CompletionEvent {
  readonly model?: unknown;
  readonly usage?: { prompt_tokens?: unknown; completion_tokens?: unknown } | null;
}

function toFields(value: unknown): CompletionEvent | null {
  return typeof value === 'object' && value !== null ? value : null;
}

function usageOf(event: CompletionEvent): { promptTokens: number; completionTokens: number } | null {
  const usage = event.usage;
  if (typeof usage !== 'object' || usage === null) {
    return null;
  }
  const prompt = usage.prompt_tokens;
  const completion = usage.completion_tokens;
  if (typeof prompt !== 'number' || typeof completion !== 'number') {
    return null;
  }
  return { promptTokens: prompt, completionTokens: completion };
}

/**
 * The width of the line ending at `at`: a carriage return and the line feed after it are one ending,
 * either alone is one, and anything else is none.
 *
 * Section 3.1 of `docs/receipt-spec.md` publishes these three, and `ResponseItemFramer` in
 * `@ashaveri/receipt` reads a response by them. This scan reads the same bytes for a different answer, the
 * usage a completion carried, and it has to agree about where the frames are to give one: a carriage
 * return left unread is worse than an ending missed, because it becomes the first byte of the line behind
 * it and that line stops being a `data:` field at all.
 */
function endingWidth(text: string, at: number): number {
  const char = text[at];
  if (char === '\r') return text[at + 1] === '\n' ? 2 : 1;
  return char === '\n' ? 1 : 0;
}

/** Where the next event ends: the offset of two line endings written one after another, and their width. */
function dispatchedAt(text: string): { readonly at: number; readonly width: number } | null {
  for (let at = 0; at < text.length; ) {
    const first = endingWidth(text, at);
    if (first === 0) {
      at += 1;
      continue;
    }
    const second = endingWidth(text, at + first);
    if (second === 0) {
      at += first;
      continue;
    }
    return { at, width: first + second };
  }
  return null;
}

/** The payload of every `data:` line of one event, with the field name and its one space taken off. */
function dataLines(event: string): string[] {
  const out: string[] = [];
  for (const line of event.split(/\r\n|\r|\n/)) {
    if (line.startsWith('data:')) {
      out.push(line.slice(5).replace(/^ /, ''));
    }
  }
  return out;
}

export function upstreamBackend(options: UpstreamOptions): CompletionBackend {
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  const base = options.baseUrl.replace(/\/$/, '');

  return {
    async respond(rawRequest, request) {
      const upstream = await fetchImpl(`${base}/chat/completions`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: request.stream ? requestForUpstream(rawRequest) : rawRequest,
      });

      if (!upstream.ok || upstream.body === null) {
        const body = new Uint8Array(await upstream.arrayBuffer());
        return {
          status: upstream.status,
          contentType: upstream.headers.get('content-type') ?? 'application/json',
          chunks: (async function* () {
            yield body;
          })(),
          usage: Promise.resolve({ model: request.model, promptTokens: 0, completionTokens: 0 }),
        };
      }

      const contentType =
        upstream.headers.get('content-type') ?? (request.stream ? 'text/event-stream' : 'application/json');
      // fetch types the body as ReadableStream<any>, so the element type has to be named
      // here or every chunk read below arrives untyped.
      const stream: ReadableStream<Uint8Array> = upstream.body;
      // The question this scan asks is the question the route asks before it decides what to attest, so it
      // is asked of the same predicate and not of a literal spelled out here. The scan answers it to find a
      // usage line, and the framing answers it to decide whether a body is frames or one whole item; two
      // spellings would let a body be metered as a stream and attested as a single item, or the other way
      // round, with each half internally consistent and the pair stating two different responses.
      const streaming = isEventStream(contentType);
      const usageSlot = deferred<CompletionUsage>();
      // An aborted client stops consuming before this settles, and an awaited
      // promise nobody settles would surface as an unhandled rejection.
      usageSlot.promise.catch(() => undefined);

      const seen = { usage: false };
      let model = '';
      // The scan reads the model and the usage out of the stream and nothing else. The completion
      // id every event carries is forwarded to the client untouched, but it names no receipt: an id
      // chosen by the inference server is a lookup key only as long as that server is unguessable,
      // and this gateway mints its own instead.
      const remember = (event: CompletionEvent): void => {
        if (typeof event.model === 'string' && event.model.length > 0) {
          model = event.model;
        }
        const usage = usageOf(event);
        if (usage !== null && !seen.usage) {
          seen.usage = true;
          usageSlot.resolve({ model, ...usage });
        }
      };

      const chunks = (async function* (): AsyncGenerator<Uint8Array> {
        const reader = stream.getReader();
        const decoder = new TextDecoder();
        let pending = '';
        try {
          for (;;) {
            const next = await reader.read();
            if (next.done) {
              break;
            }
            const value = next.value;
            // Scan before yielding so the usage is known the moment the server takes the
            // chunk, and forward verbatim so the receipt hashes exactly what the client sees.
            pending += decoder.decode(value, { stream: true });
            if (streaming) {
              let event = dispatchedAt(pending);
              while (event !== null) {
                for (const data of dataLines(pending.slice(0, event.at))) {
                  if (data !== '[DONE]') {
                    remember(toFields(JSON.parse(data)) ?? {});
                  }
                }
                pending = pending.slice(event.at + event.width);
                event = dispatchedAt(pending);
              }
            }
            yield value;
          }
          pending += decoder.decode();
          if (!streaming && pending.length > 0) {
            remember(toFields(JSON.parse(pending)) ?? {});
          }
          if (!seen.usage) {
            usageSlot.resolve({ model, promptTokens: 0, completionTokens: 0 });
          }
        } catch (error) {
          if (!seen.usage) {
            usageSlot.reject(error);
          }
          throw error;
        } finally {
          reader.releaseLock();
        }
      })();

      return { status: upstream.status, contentType, chunks, usage: usageSlot.promise };
    },
  };
}
