import { describe, expect, it } from 'vitest';
import { hashRequest, randomNonce } from '@ashaveri/receipt';
import {
  AshaveriClient,
  parseManifest,
  policyFromManifest,
  SdkError,
  type AshaveriPolicy,
} from '../src/index.js';
import {
  createFakeGateway,
  FAKE_BASE_URL,
  FAKE_COMPLETION_TOKENS,
  FAKE_CONTENT,
  FAKE_IAT,
  FAKE_PROMPT_TOKENS,
  FAKE_RECEIPT_ID,
} from './mock-gateway.js';

const MESSAGES = [{ role: 'user', content: 'hi' }];

interface ClientOptions {
  readonly verify?: 'off' | 'receipt' | 'strict';
  readonly policy?: AshaveriPolicy;
  readonly now?: () => number;
}

function clientWith(gatewayOptions?: Parameters<typeof createFakeGateway>[0], buildClientOptions: (policy: AshaveriPolicy) => ClientOptions = () => ({})) {
  const gateway = createFakeGateway(gatewayOptions);
  const policy = policyFromManifest(parseManifest(gateway.manifestJson));
  const client = new AshaveriClient({
    baseUrl: FAKE_BASE_URL,
    fetch: gateway.fetch,
    ...buildClientOptions(policy),
  });
  return { gateway, client, policy };
}

describe('AshaveriClient.create', () => {
  it('verifies the receipt by default', async () => {
    const { gateway, client } = clientWith();
    const { completion, receipt } = await client.chat.completions.create({ messages: MESSAGES });
    expect(completion.id).toBe(FAKE_RECEIPT_ID);
    expect(completion.choices[0]!.message.content).toBe(FAKE_CONTENT);
    expect(completion.usage!.prompt_tokens).toBe(FAKE_PROMPT_TOKENS);
    expect(receipt).not.toBeNull();
    expect(receipt!.payload.mdl).toBe('fake-model');
    expect(receipt!.payload.iss).toBe('fake-issuer');
    expect(receipt!.payload.tok.p).toBe(FAKE_PROMPT_TOKENS);
    expect(receipt!.payload.tok.c).toBe(FAKE_COMPLETION_TOKENS);
    const nonceHeader = gateway.requests[0]!.nonceHeader;
    expect(nonceHeader).toMatch(/^[A-Za-z0-9_-]{22}$/);
  });

  it('uses a fresh nonce per request', async () => {
    const { gateway, client } = clientWith();
    await client.chat.completions.create({ messages: MESSAGES });
    await client.chat.completions.create({ messages: MESSAGES });
    const completions = gateway.requests.filter((request) => request.url.endsWith('/chat/completions'));
    expect(completions).toHaveLength(2);
    expect(completions[0]!.nonceHeader).toBeDefined();
    expect(completions[1]!.nonceHeader).toBeDefined();
    expect(completions[0]!.nonceHeader).not.toBe(completions[1]!.nonceHeader);
  });

  it('skips verification entirely in off mode', async () => {
    const { gateway, client } = clientWith({}, () => ({ verify: 'off' as const }));
    const { completion, receipt } = await client.chat.completions.create({ messages: MESSAGES });
    expect(completion.id).toBe(FAKE_RECEIPT_ID);
    expect(receipt).toBeNull();
    // only the completion request happened: no manifest or receipt fetches
    expect(gateway.requests).toHaveLength(1);
  });

  it('rejects a response body modified after signing', async () => {
    const { client } = clientWith({ mutateResponseBody: (body) => body.replace('Fake', 'Real') });
    await expect(client.chat.completions.create({ messages: MESSAGES })).rejects.toMatchObject({
      code: 'RESPONSE_HASH_MISMATCH',
    });
  });

  it('rejects a receipt whose request hash does not match the sent bytes', async () => {
    const { client } = clientWith({
      mutatePayload: (payload) => ({ ...payload, req: hashRequest(new TextEncoder().encode('other bytes')) }),
    });
    await expect(client.chat.completions.create({ messages: MESSAGES })).rejects.toMatchObject({
      code: 'REQUEST_HASH_MISMATCH',
    });
  });

  it('rejects a receipt signed over a different nonce', async () => {
    const { client } = clientWith({ mutatePayload: (payload) => ({ ...payload, nce: randomNonce() }) });
    await expect(client.chat.completions.create({ messages: MESSAGES })).rejects.toMatchObject({
      code: 'NONCE_MISMATCH',
    });
  });

  it('rejects a receipt signed by a key the manifest does not declare', async () => {
    const { client } = clientWith({ manifestKeys: 'wrong' });
    await expect(client.chat.completions.create({ messages: MESSAGES })).rejects.toMatchObject({
      code: 'BAD_MANIFEST',
    });
  });

  it('wraps completion failures as GATEWAY_ERROR', async () => {
    const { client } = clientWith({ completionStatus: 503 });
    await expect(client.chat.completions.create({ messages: MESSAGES })).rejects.toMatchObject({
      code: 'GATEWAY_ERROR',
    });
  });

  it('wraps manifest failures as GATEWAY_ERROR', async () => {
    const { client } = clientWith({ manifestStatus: 500 });
    await expect(client.chat.completions.create({ messages: MESSAGES })).rejects.toMatchObject({
      code: 'GATEWAY_ERROR',
    });
  });

  it('retries when the receipt is not available yet', async () => {
    const { client } = clientWith({ receiptAvailableAfterAttempts: 2 });
    const { receipt } = await client.chat.completions.create({ messages: MESSAGES });
    expect(receipt).not.toBeNull();
    expect(receipt!.payload.tok.p).toBe(FAKE_PROMPT_TOKENS);
  });

  it('throws a TypeError when called with stream: true', async () => {
    const { client } = clientWith();
    await expect(client.chat.completions.create({ messages: MESSAGES, stream: true })).rejects.toBeInstanceOf(
      TypeError,
    );
  });
});

describe('AshaveriClient.stream', () => {
  it('yields chunks and verifies the receipt', async () => {
    const { client } = clientWith();
    const stream = await client.chat.completions.stream({ messages: MESSAGES });
    const chunks = [];
    for await (const chunk of stream) {
      chunks.push(chunk);
    }
    expect(chunks).toHaveLength(4);
    expect(chunks[0]!.choices[0]!.delta.role).toBe('assistant');
    const content = chunks
      .map((chunk) => (typeof chunk.choices[0]!.delta.content === 'string' ? chunk.choices[0]!.delta.content : ''))
      .join('');
    expect(content).toBe(FAKE_CONTENT);
    const receipt = await stream.receipt;
    expect(receipt).not.toBeNull();
    expect(receipt!.payload.mdl).toBe('fake-model');
  });

  it('parses events split across arbitrary delivery boundaries', async () => {
    const { client } = clientWith({ streamChunkBytes: 7 });
    const stream = await client.chat.completions.stream({ messages: MESSAGES });
    const chunks = [];
    for await (const chunk of stream) {
      chunks.push(chunk);
    }
    expect(chunks).toHaveLength(4);
    const content = chunks
      .map((chunk) => (typeof chunk.choices[0]!.delta.content === 'string' ? chunk.choices[0]!.delta.content : ''))
      .join('');
    expect(content).toBe(FAKE_CONTENT);
    await expect(stream.receipt).resolves.not.toBeNull();
  });

  it('errors the iterator and the receipt when the body was modified', async () => {
    const { client } = clientWith({ mutateResponseBody: (body) => body.replace('Fake', 'Real') });
    const stream = await client.chat.completions.stream({ messages: MESSAGES });
    await expect(
      (async () => {
        for await (const _chunk of stream) {
          // drain
        }
      })(),
    ).rejects.toMatchObject({ code: 'RESPONSE_HASH_MISMATCH' });
    await expect(stream.receipt).rejects.toMatchObject({ code: 'RESPONSE_HASH_MISMATCH' });
  });

  it('settles the receipt to null in off mode', async () => {
    const { client } = clientWith({}, () => ({ verify: 'off' as const }));
    const stream = await client.chat.completions.stream({ messages: MESSAGES });
    for await (const _chunk of stream) {
      // drain
    }
    await expect(stream.receipt).resolves.toBeNull();
  });
});

describe('strict mode', () => {
  it('requires a policy', () => {
    const gateway = createFakeGateway();
    expect(() => new AshaveriClient({ baseUrl: FAKE_BASE_URL, fetch: gateway.fetch, verify: 'strict' })).toThrow(
      SdkError,
    );
  });

  it('accepts a deployment pinned by a policy built from its manifest', async () => {
    const { gateway, client } = clientWith({}, (policy) => ({ verify: 'strict' as const, policy }));
    const { receipt } = await client.chat.completions.create({ messages: MESSAGES });
    expect(receipt).not.toBeNull();
    expect(gateway.requests.length).toBeGreaterThanOrEqual(2);
  });

  it('rejects an issuer the policy does not pin', async () => {
    const { client } = clientWith({}, (policy) => ({
      verify: 'strict' as const,
      policy: { ...policy, issuers: ['someone-else'] },
    }));
    await expect(client.chat.completions.create({ messages: MESSAGES })).rejects.toMatchObject({
      code: 'ISSUER_NOT_ALLOWED',
    });
  });

  it('rejects an instance the policy does not pin', async () => {
    const { client } = clientWith({}, (policy) => ({
      verify: 'strict' as const,
      policy: { ...policy, instances: ['other-instance'] },
    }));
    await expect(client.chat.completions.create({ messages: MESSAGES })).rejects.toMatchObject({
      code: 'INSTANCE_NOT_ALLOWED',
    });
  });

  it('rejects a measurement the policy does not pin', async () => {
    const { client } = clientWith({}, (policy) => ({
      verify: 'strict' as const,
      policy: { ...policy, measurements: { software: ['00'.repeat(32)] } },
    }));
    await expect(client.chat.completions.create({ messages: MESSAGES })).rejects.toMatchObject({
      code: 'MEASUREMENT_NOT_ALLOWED',
    });
  });

  it('rejects a signing key the policy does not pin', async () => {
    const { client } = clientWith({}, () => ({
      verify: 'strict' as const,
      policy: {},
    }));
    await expect(client.chat.completions.create({ messages: MESSAGES })).rejects.toMatchObject({
      code: 'MANIFEST_KEY_NOT_PINNED',
    });
  });

  it('rejects an unreceipted response in strict mode', async () => {
    const { client } = clientWith({ omitReceiptHeader: true }, (policy) => ({
      verify: 'strict' as const,
      policy,
    }));
    await expect(client.chat.completions.create({ messages: MESSAGES })).rejects.toMatchObject({
      code: 'NOT_RECEIPTED',
    });
  });

  it('rejects an unreceipted stream in strict mode', async () => {
    const { client } = clientWith({ omitReceiptHeader: true }, (policy) => ({
      verify: 'strict' as const,
      policy,
    }));
    const stream = await client.chat.completions.stream({ messages: MESSAGES });
    await expect(
      (async () => {
        for await (const _chunk of stream) {
          // drain
        }
      })(),
    ).rejects.toMatchObject({ code: 'NOT_RECEIPTED' });
    await expect(stream.receipt).rejects.toMatchObject({ code: 'NOT_RECEIPTED' });
  });

  it('rejects a receipt that is too old for the policy clock', async () => {
    const { client } = clientWith({}, (policy) => ({
      verify: 'strict' as const,
      policy: { ...policy, maxReceiptAgeSeconds: 60 },
      now: () => (FAKE_IAT + 600) * 1000,
    }));
    await expect(client.chat.completions.create({ messages: MESSAGES })).rejects.toMatchObject({
      code: 'STALE_RECEIPT',
    });
  });

  it('accepts an old-dated receipt when the policy clock says it is fresh', async () => {
    const { client } = clientWith({}, (policy) => ({
      verify: 'strict' as const,
      policy: { ...policy, maxReceiptAgeSeconds: 60 },
      now: () => (FAKE_IAT + 30) * 1000,
    }));
    const { receipt } = await client.chat.completions.create({ messages: MESSAGES });
    expect(receipt).not.toBeNull();
  });
});
