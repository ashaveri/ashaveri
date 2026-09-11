import { describe, expect, it } from 'vitest';
import { hashRequest, randomNonce } from '@ashaveri/receipt';
import {
  AshaveriClient,
  evidenceReportData,
  fromBase64Url,
  parseManifest,
  policyFromManifest,
  SdkError,
  toHex,
  type AshaveriPolicy,
  type ReceiptPayload,
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

  it('reports a receipt that never arrives as missing, not as a gateway failure', async () => {
    const { gateway, client } = clientWith({ receiptAvailableAfterAttempts: 99 });
    await expect(client.chat.completions.create({ messages: MESSAGES })).rejects.toMatchObject({
      code: 'RECEIPT_NOT_FOUND',
    });
    expect(gateway.requests.filter((req) => req.url.includes('/receipts/'))).toHaveLength(3);
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

  // The fake gateway is a software deployment. Relabelling its receipt is what
  // lets a client get as far as the evidence stage.
  const hardwareTee = (payload: ReceiptPayload): ReceiptPayload => ({
    ...payload,
    meas: { tee: 'tdx', m: new Uint8Array(48) },
  });

  it('refuses a deployment whose receipt claims no hardware', async () => {
    const { gateway, client } = clientWith({}, (policy) => ({ verify: 'strict' as const, policy }));
    await expect(client.chat.completions.create({ messages: MESSAGES })).rejects.toMatchObject({
      code: 'EVIDENCE_NOT_HARDWARE',
    });
    // The receipt verifies first, so nothing is fetched before it is refused.
    expect(gateway.requests.some((request) => request.url.includes('/attestation'))).toBe(false);
  });

  it('never fetches evidence below strict mode', async () => {
    const { gateway, client } = clientWith({ mutatePayload: hardwareTee });
    const { receipt } = await client.chat.completions.create({ messages: MESSAGES });
    expect(receipt).not.toBeNull();
    expect(gateway.requests.some((request) => request.url.includes('/attestation'))).toBe(false);
  });

  it('asks for the evidence bound to the nonce and request it sent', async () => {
    const { gateway, client } = clientWith({ mutatePayload: hardwareTee, noEvidenceRoute: true }, (policy) => ({
      verify: 'strict' as const,
      policy,
    }));
    await expect(client.chat.completions.create({ messages: MESSAGES })).rejects.toMatchObject({
      code: 'EVIDENCE_NOT_FOUND',
    });
    const completion = gateway.requests.find((request) => request.url.endsWith('/chat/completions'))!;
    const expected = toHex(
      evidenceReportData(
        fromBase64Url(completion.nonceHeader!),
        hashRequest(new TextEncoder().encode(completion.body!)),
      ),
    );
    const evidence = gateway.requests.filter((request) => request.url.includes('/attestation'));
    expect(evidence).toHaveLength(3);
    expect(evidence[0]!.url).toBe(`${FAKE_BASE_URL}/attestation?report_data=${expected}`);
  });

  it('rejects evidence that is not a platform document', async () => {
    const { client } = clientWith({ mutatePayload: hardwareTee }, (policy) => ({
      verify: 'strict' as const,
      policy,
    }));
    await expect(client.chat.completions.create({ messages: MESSAGES })).rejects.toMatchObject({
      code: 'EVIDENCE_VERIFICATION_FAILED',
    });
  });

  it('refuses to verify against roots the policy did not pin', async () => {
    const { gateway, client } = clientWith({ mutatePayload: hardwareTee }, (policy) => ({
      verify: 'strict' as const,
      policy: { ...policy, trustAnchors: { intelSgxRoots: [] } },
    }));
    await expect(client.chat.completions.create({ messages: MESSAGES })).rejects.toMatchObject({
      code: 'EVIDENCE_NO_TRUST_ANCHORS',
    });
    expect(gateway.requests.filter((request) => request.url.includes('/attestation'))).toHaveLength(1);
  });

  // A composite receipt claims an accelerator beside the CPU, so the platform quote
  // alone cannot settle strict mode. The fake gateway is a software deployment whose
  // evidence route serves bytes no parser accepts, so every case below still ends in
  // a refusal; what these pin is that the device route is consulted at all, with this
  // request's own challenge, and that its answer is read before a verdict. The
  // accepted pairing, where both documents are genuine, is exercised on live hardware.
  const compositeTee = (payload: ReceiptPayload): ReceiptPayload => ({
    ...payload,
    meas: { tee: 'snp+h100cc', m: new Uint8Array(48) },
  });
  const gpuBundle = (devices: number): Uint8Array =>
    new TextEncoder().encode(
      JSON.stringify(
        Array.from({ length: devices }, () => ({ evidence: 'AAAA', certificate: 'AAAA' })),
      ),
    );

  /** The report data strict mode had to ask both routes for. */
  async function compositeChallenge(gatewayOptions: Parameters<typeof createFakeGateway>[0]) {
    const { gateway, client } = clientWith(gatewayOptions, (policy) => ({
      verify: 'strict' as const,
      policy,
    }));
    const failure = client.chat.completions.create({ messages: MESSAGES });
    await expect(failure).rejects.toBeInstanceOf(SdkError);
    const completion = gateway.requests.find((request) => request.url.endsWith('/chat/completions'))!;
    return {
      gateway,
      challenge: toHex(
        evidenceReportData(
          fromBase64Url(completion.nonceHeader!),
          hashRequest(new TextEncoder().encode(completion.body!)),
        ),
      ),
    };
  }

  it('asks the device route for the same challenge as the platform route', async () => {
    const { gateway, challenge } = await compositeChallenge({
      mutatePayload: compositeTee,
      deviceEvidenceDocument: gpuBundle(1),
    });
    expect(gateway.requests.filter((request) => request.url === `${FAKE_BASE_URL}/attestation?report_data=${challenge}`)).toHaveLength(1);
    expect(
      gateway.requests.filter((request) => request.url === `${FAKE_BASE_URL}/attestation/gpu?report_data=${challenge}`),
    ).toHaveLength(1);
  });

  it('rejects a device document that is not the bundle nvattest writes', async () => {
    const { client } = clientWith(
      { mutatePayload: compositeTee, deviceEvidenceDocument: new TextEncoder().encode('not a bundle') },
      (policy) => ({ verify: 'strict' as const, policy }),
    );
    await expect(client.chat.completions.create({ messages: MESSAGES })).rejects.toThrow(/MALFORMED_GPU_BUNDLE/);
  });

  it('holds the device route to the same retry window as the receipt', async () => {
    const { gateway } = await compositeChallenge({ mutatePayload: compositeTee });
    expect(gateway.requests.filter((request) => request.url.includes('/attestation/gpu'))).toHaveLength(3);
  });

  it('never asks the device route for a receipt that claims no device', async () => {
    const { gateway } = await compositeChallenge({ mutatePayload: hardwareTee });
    expect(gateway.requests.some((request) => request.url.includes('/attestation/gpu'))).toBe(false);
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
      verify: 'receipt' as const,
      policy: { ...policy, maxReceiptAgeSeconds: 60 },
      now: () => (FAKE_IAT + 30) * 1000,
    }));
    const { receipt } = await client.chat.completions.create({ messages: MESSAGES });
    expect(receipt).not.toBeNull();
  });
});
