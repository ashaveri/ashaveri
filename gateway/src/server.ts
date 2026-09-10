import Fastify, { type FastifyInstance } from 'fastify';
import {
  generateSigningKey,
  hashRequest,
  issueReceipt,
  randomNonce,
  type ReceiptPayload,
  type SigningKey,
} from '@ashaveri/receipt';
import { fromBase64Url } from './b64.js';
import {
  DEFAULT_MOCK_MODEL,
  completionJson,
  completionSse,
  mockCompletion,
  parseChatCompletionRequest,
  RequestError,
  type MockCompletion,
} from './mock.js';

const NONCE_BYTES = 16;

export interface GatewayOptions {
  readonly issuer?: string;
  readonly instance?: string;
  readonly key?: SigningKey;
}

export interface ManifestJson {
  readonly v: 1;
  readonly iss: string;
  readonly ins: string;
  readonly epk: number;
  readonly keys: readonly { kid: string; alg: 'Ed25519'; publicKey: string }[];
  readonly models: readonly { id: string; wts: string }[];
  readonly meas: { tee: 'snp' | 'snp+h100cc' | 'tdx'; m: string };
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const b of bytes) {
    binary += String.fromCharCode(b);
  }
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

export function buildGateway(options: GatewayOptions = {}): FastifyInstance {
  const issuer = options.issuer ?? 'ashaveri-mock';
  const instance = options.instance ?? 'mock-instance-1';
  const key = options.key ?? generateSigningKey();
  const weightsDigest = hashRequest(new TextEncoder().encode(`mock-weights:${DEFAULT_MOCK_MODEL}`));
  const measurement = hashRequest(new TextEncoder().encode('mock-measurement'));
  const attestationDigest = hashRequest(new TextEncoder().encode('mock-attestation'));
  const receipts = new Map<string, Uint8Array>();

  const app = Fastify({ bodyLimit: 16 * 1024 * 1024, logger: false });
  // The receipt binds the exact bytes the client sent, so the body is kept raw
  // instead of being parsed into a JS object first.
  app.addContentTypeParser('application/json', { parseAs: 'buffer' }, (_request, body, done) => {
    done(null, body);
  });

  const manifest: ManifestJson = {
    v: 1,
    iss: issuer,
    ins: instance,
    epk: 0,
    keys: [{ kid: toHex(key.kid), alg: 'Ed25519', publicKey: toBase64Url(key.publicKey) }],
    models: [{ id: DEFAULT_MOCK_MODEL, wts: toHex(weightsDigest) }],
    meas: { tee: 'snp', m: toHex(measurement) },
  };

  function issueFor(completion: MockCompletion, nonce: Uint8Array, requestBody: Buffer, responseBody: string): Uint8Array {
    const iat = Math.floor(Date.now() / 1000);
    const payload: ReceiptPayload = {
      v: 1,
      iss: issuer,
      ins: instance,
      iat,
      nce: nonce,
      req: hashRequest(requestBody),
      res: hashRequest(new TextEncoder().encode(responseBody)),
      mdl: completion.model,
      wts: hashRequest(new TextEncoder().encode(`mock-weights:${completion.model}`)),
      meas: { tee: 'snp', m: measurement },
      att: { d: attestationDigest, ts: iat, url: 'mock://attestation' },
      epk: 0,
      tok: { p: completion.promptTokens, c: completion.completionTokens },
    };
    const bytes = issueReceipt(payload, key);
    receipts.set(completion.id, bytes);
    return bytes;
  }

  app.get('/v1/deployment-manifest', async () => manifest);

  app.get('/v1/receipts/:id', async (request, reply) => {
    const id = (request.params as { id: string }).id;
    const bytes = receipts.get(id);
    if (!bytes) {
      reply.code(404).send({ error: { message: `no receipt for id ${id}`, type: 'not_found' } });
      return;
    }
    reply.header('content-type', 'application/cbor');
    reply.send(Buffer.from(bytes));
  });

  app.post('/v1/chat/completions', async (request, reply) => {
    if (!(request.body instanceof Buffer)) {
      reply.code(400).send({ error: { message: 'request body must be application/json', type: 'invalid_request_error' } });
      return;
    }
    let chatRequest;
    try {
      chatRequest = parseChatCompletionRequest(JSON.parse(request.body.toString('utf8')));
    } catch (err) {
      const message = err instanceof RequestError ? err.message : 'request body is not valid JSON';
      reply.code(400).send({ error: { message, type: 'invalid_request_error' } });
      return;
    }
    let nonce: Uint8Array;
    const rawNonceHeader = request.headers['x-ashaveri-nonce'];
    const nonceHeader = Array.isArray(rawNonceHeader) ? rawNonceHeader[0] : rawNonceHeader;
    if (nonceHeader !== undefined) {
      try {
        nonce = fromBase64Url(nonceHeader);
      } catch {
        reply.code(400).send({ error: { message: 'x-ashaveri-nonce is not valid base64url', type: 'invalid_request_error' } });
        return;
      }
      if (nonce.length !== NONCE_BYTES) {
        reply.code(400).send({ error: { message: `x-ashaveri-nonce must be ${NONCE_BYTES} bytes`, type: 'invalid_request_error' } });
        return;
      }
    } else {
      nonce = randomNonce();
    }
    const completion = mockCompletion(chatRequest);
    reply.header('x-ashaveri-receipt-id', completion.id);
    if (chatRequest.stream) {
      const body = completionSse(completion);
      issueFor(completion, nonce, request.body, body);
      reply.header('content-type', 'text/event-stream');
      reply.send(body);
    } else {
      const body = completionJson(completion);
      issueFor(completion, nonce, request.body, body);
      reply.header('content-type', 'application/json');
      reply.send(body);
    }
  });

  return app;
}
