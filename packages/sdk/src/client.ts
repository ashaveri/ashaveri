import { hashRequest, randomNonce, type VerifiedReceipt } from '@ashaveri/receipt';
import { toBase64Url } from './b64.js';
import { GatewaySession, type VerifiedCompletion } from './gateway.js';
import { SdkError } from './errors.js';
import type { VerifiedEvidence } from './evidence.js';
import type { AshaveriPolicy } from './policy.js';

export type VerifyMode = 'off' | 'receipt' | 'strict';

/** What one completion check yields; both fields are null when verification is off. */
export interface VerificationOutcome {
  readonly receipt: VerifiedReceipt | null;
  readonly attestation: VerifiedEvidence | null;
}

export interface AshaveriClientOptions {
  /** Gateway base URL without a trailing slash, e.g. http://127.0.0.1:7173/v1 */
  readonly baseUrl: string;
  /** Verification level. Default: 'receipt'. 'strict' requires a policy. */
  readonly verify?: VerifyMode;
  readonly policy?: AshaveriPolicy;
  readonly fetch?: typeof fetch;
  /** Wall clock in milliseconds since the epoch; defaults to Date.now. */
  readonly now?: () => number;
}

export interface ChatCompletionMessageParam {
  readonly role: string;
  readonly content: string;
}

export interface ChatCompletionParams {
  readonly model?: string;
  readonly messages: readonly ChatCompletionMessageParam[];
  readonly stream?: boolean;
  readonly [key: string]: unknown;
}

export interface ChatCompletionChoice {
  readonly index: number;
  readonly message: { readonly role: string; readonly content: string };
  readonly finish_reason: string | null;
}

export interface ChatCompletionUsage {
  readonly prompt_tokens: number;
  readonly completion_tokens: number;
  readonly total_tokens: number;
}

export interface ChatCompletion {
  readonly id: string;
  readonly object: string;
  readonly created: number;
  readonly model: string;
  readonly choices: readonly ChatCompletionChoice[];
  readonly usage?: ChatCompletionUsage;
}

export interface ChatCompletionChunkChoice {
  readonly index: number;
  readonly delta: Readonly<Record<string, unknown>>;
  readonly finish_reason: string | null;
}

export interface ChatCompletionChunk {
  readonly id: string;
  readonly object: string;
  readonly created: number;
  readonly model: string;
  readonly choices: readonly ChatCompletionChunkChoice[];
}

export interface CompletionResult extends VerificationOutcome {
  readonly completion: ChatCompletion;
}

export interface ChunkStream extends AsyncIterable<ChatCompletionChunk> {
  readonly receipt: Promise<VerifiedReceipt | null>;
  /** The verified evidence in strict mode and nothing otherwise, or the verification failure. */
  readonly attestation: Promise<VerifiedEvidence | null>;
}

function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function concatBytes(parts: readonly Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

async function readAll(body: ReadableStream<Uint8Array> | null): Promise<Uint8Array> {
  if (body === null) {
    return new Uint8Array(0);
  }
  const reader = body.getReader();
  const parts: Uint8Array[] = [];
  for (;;) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    parts.push(value);
  }
  return concatBytes(parts);
}

function parseCompletion(bytes: Uint8Array): ChatCompletion {
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw new SdkError('GATEWAY_ERROR', 'response body is not valid JSON');
  }
  if (
    typeof value !== 'object' ||
    value === null ||
    typeof (value as Record<string, unknown>)['id'] !== 'string' ||
    !Array.isArray((value as Record<string, unknown>)['choices'])
  ) {
    throw new SdkError('GATEWAY_ERROR', 'response body is not a chat completion');
  }
  return value as ChatCompletion;
}

function parseChunk(value: unknown): ChatCompletionChunk {
  if (
    typeof value !== 'object' ||
    value === null ||
    typeof (value as Record<string, unknown>)['id'] !== 'string' ||
    !Array.isArray((value as Record<string, unknown>)['choices'])
  ) {
    throw new SdkError('GATEWAY_ERROR', 'stream chunk is not a chat completion chunk');
  }
  return value as ChatCompletionChunk;
}

export class AshaveriClient {
  private readonly mode: VerifyMode;
  private readonly session: GatewaySession;
  private readonly fetchImpl: typeof fetch;
  private readonly now?: () => number;
  readonly chat: {
    readonly completions: {
      readonly create: (params: ChatCompletionParams) => Promise<CompletionResult>;
      readonly stream: (params: ChatCompletionParams) => Promise<ChunkStream>;
    };
  };

  constructor(options: AshaveriClientOptions) {
    const baseUrl = options.baseUrl.replace(/\/+$/, '');
    this.mode = options.verify ?? 'receipt';
    if (this.mode === 'strict' && options.policy === undefined) {
      throw new SdkError('NO_POLICY', "verify: 'strict' requires a policy pinning keys and measurements");
    }
    this.fetchImpl = options.fetch ?? globalThis.fetch;
    this.session = new GatewaySession(baseUrl, { fetchImpl: this.fetchImpl, policy: options.policy });
    this.now = options.now;
    this.chat = {
      completions: {
        create: (params) => this.create(params),
        stream: (params) => this.stream(params),
      },
    };
  }

  private async post(body: string, nonce: Uint8Array): Promise<Response> {
    let response: Response;
    try {
      response = await this.fetchImpl(`${this.session.baseUrl}/chat/completions`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-ashaveri-nonce': toBase64Url(nonce),
        },
        body,
      });
    } catch (err) {
      throw new SdkError('GATEWAY_ERROR', `request to the gateway failed: ${(err as Error).message}`);
    }
    if (!response.ok) {
      const text = await response.text();
      throw new SdkError('GATEWAY_ERROR', `gateway returned status ${response.status}: ${text}`);
    }
    return response;
  }

  private async verify(
    receiptId: string,
    nonce: Uint8Array,
    requestHash: Uint8Array,
    responseHash: Uint8Array,
  ): Promise<VerifiedCompletion> {
    const receiptBytes = await this.session.receiptBytes(receiptId);
    return this.session.verifyCompletion({
      receiptBytes,
      nonce,
      requestHash,
      responseHash,
      verifyEvidence: this.mode === 'strict',
      now: this.now?.(),
    });
  }

  async create(params: ChatCompletionParams): Promise<CompletionResult> {
    if (params.stream === true) {
      throw new TypeError('use chat.completions.stream() for streaming requests');
    }
    const body = JSON.stringify(params);
    const nonce = randomNonce();
    const response = await this.post(body, nonce);
    const receiptId = response.headers.get('x-ashaveri-receipt-id');
    const bytes = await readAll(response.body);
    const completion = parseCompletion(bytes);
    if (this.mode === 'off') {
      return { completion, receipt: null, attestation: null };
    }
    if (receiptId === null) {
      if (this.mode === 'strict') {
        throw new SdkError('NOT_RECEIPTED', 'the gateway did not provide a receipt for the response');
      }
      return { completion, receipt: null, attestation: null };
    }
    const { receipt, attestation } = await this.verify(
      receiptId,
      nonce,
      hashRequest(utf8(body)),
      hashRequest(bytes),
    );
    return { completion, receipt, attestation };
  }

  async stream(params: ChatCompletionParams): Promise<ChunkStream> {
    const body = JSON.stringify({ ...params, stream: true });
    const nonce = randomNonce();
    const response = await this.post(body, nonce);
    if (response.body === null) {
      throw new SdkError('GATEWAY_ERROR', 'streaming response has no body');
    }
    const receiptId = response.headers.get('x-ashaveri-receipt-id');
    const requestHash = hashRequest(utf8(body));
    const decoder = new TextDecoder();
    const parts: Uint8Array[] = [];
    let buffer = '';
    let settleVerification: (outcome: VerificationOutcome) => void = () => {};
    let failVerification: (err: unknown) => void = () => {};
    const verification = new Promise<VerificationOutcome>((resolve, reject) => {
      settleVerification = resolve;
      failVerification = reject;
    });

    const client = this;
    const iterator = async function* (): AsyncGenerator<ChatCompletionChunk> {
      const reader = response.body!.getReader();
      try {
        for (;;) {
          const { done, value } = await reader.read();
          if (done) {
            break;
          }
          parts.push(value);
          buffer += decoder.decode(value, { stream: true });
          let match = /\r?\n\r?\n/.exec(buffer);
          while (match !== null) {
            const event = buffer.slice(0, match.index);
            buffer = buffer.slice(match.index + match[0].length);
            for (const chunk of parseEvent(event)) {
              yield chunk;
            }
            match = /\r?\n\r?\n/.exec(buffer);
          }
        }
        buffer += decoder.decode();
        for (const chunk of parseEvent(buffer)) {
          yield chunk;
        }
        if (client.mode === 'off') {
          settleVerification({ receipt: null, attestation: null });
          return;
        }
        if (receiptId === null) {
          if (client.mode === 'strict') {
            const err = new SdkError('NOT_RECEIPTED', 'the gateway did not provide a receipt for the response');
            failVerification(err);
            throw err;
          }
          settleVerification({ receipt: null, attestation: null });
          return;
        }
        const outcome = await client
          .verify(receiptId, nonce, requestHash, hashRequest(concatBytes(parts)))
          .catch((err: unknown) => {
            failVerification(err);
            throw err;
          });
        settleVerification(outcome);
      } finally {
        reader.releaseLock();
      }
    };

    const receipt = verification.then((outcome) => outcome.receipt);
    const attestation = verification.then((outcome) => outcome.attestation);
    // Keep a handler on both so a stream abandoned before verification settles
    // never surfaces as an unhandled rejection.
    receipt.catch(() => undefined);
    attestation.catch(() => undefined);

    return {
      [Symbol.asyncIterator]: iterator,
      receipt,
      attestation,
    };
  }
}

function parseEvent(event: string): ChatCompletionChunk[] {
  const chunks: ChatCompletionChunk[] = [];
  for (const line of event.split(/\r?\n/)) {
    if (!line.startsWith('data:')) {
      continue;
    }
    const data = line.slice('data:'.length).replace(/^ /, '');
    if (data === '[DONE]') {
      continue;
    }
    try {
      chunks.push(parseChunk(JSON.parse(data)));
    } catch (err) {
      if (err instanceof SdkError) {
        throw err;
      }
      throw new SdkError('GATEWAY_ERROR', 'stream data line is not valid JSON');
    }
  }
  return chunks;
}
