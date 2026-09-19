import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildGateway, CredentialStore, newPopCredential, openMemoryAccessLog } from '@ashaveri/signerd';
import {
  AshaveriClient,
  authorizedFetch,
  parseManifest,
  policyFromManifest,
  type AshaveriCredential,
} from '../src/index.js';

// This suite has to reach a listening socket rather than Fastify's in-process injector, so it cannot
// use the gateway test harness. One credential stands in for whatever `--credentials-path` would
// load: the gateway is given its public half, every client below is given its private half.
const issued = newPopCredential({ id: 'e2e', scopes: ['read', 'complete'] });
const credential: AshaveriCredential = { kind: 'pop', id: 'e2e', privateKey: issued.privateKey };

// Signing the transport rather than the call keeps the header set identical to the one the client
// puts on its own requests, and the inline arrow is what keeps `fetch` bound to the global.
const signedFetch = authorizedFetch(credential, (input, init) => fetch(input, init));

// Derived from the factory rather than named from fastify, which this package does not depend on.
type Gateway = Awaited<ReturnType<typeof buildGateway>>;

let app: Gateway;
let base: string;

beforeAll(async () => {
  app = buildGateway({
    access: new CredentialStore({ file: { version: 1, credentials: [issued.record] } }),
    accessLog: openMemoryAccessLog(),
  });
  await app.listen({ port: 0, host: '127.0.0.1' });
  const address = app.addresses()[0]!;
  base = `http://127.0.0.1:${address.port}/v1`;
});

afterAll(async () => {
  await app.close();
});

const MESSAGES = [{ role: 'user', content: 'hello ashaveri' }];

describe('sdk against a signerd --mock gateway', () => {
  it('verifies a non-streaming completion end to end', async () => {
    const client = new AshaveriClient({ baseUrl: base, credential });
    const { completion, receipt } = await client.chat.completions.create({ messages: MESSAGES });
    expect(completion.object).toBe('chat.completion');
    expect(completion.model).toBe('mock-model-1');
    expect(completion.choices[0]!.message.content).toContain('1 message(s)');
    expect(receipt).not.toBeNull();
    expect(receipt!.payload.iss).toBe('ashaveri-mock');
    expect(receipt!.payload.ins).toBe('mock-instance-1');
    expect(receipt!.payload.mdl).toBe('mock-model-1');
    expect(receipt!.payload.meas.tee).toBe('software');
    expect(receipt!.payload.tok.p).toBe(completion.usage!.prompt_tokens);
    expect(receipt!.payload.tok.c).toBe(completion.usage!.completion_tokens);
  });

  it('verifies a streaming completion end to end', async () => {
    const client = new AshaveriClient({ baseUrl: base, credential });
    const stream = await client.chat.completions.stream({ messages: MESSAGES });
    const chunks = [];
    for await (const chunk of stream) {
      chunks.push(chunk);
    }
    expect(chunks.length).toBeGreaterThan(1);
    expect(chunks[0]!.choices[0]!.delta.role).toBe('assistant');
    const content = chunks
      .map((chunk) => (typeof chunk.choices[0]!.delta.content === 'string' ? chunk.choices[0]!.delta.content : ''))
      .join('');
    expect(content).toContain('1 message(s)');
    const receipt = await stream.receipt;
    expect(receipt).not.toBeNull();
    expect(receipt!.payload.tok.c).toBeGreaterThan(0);
  });

  it('accepts the deployment in receipt mode with a policy built from its manifest', async () => {
    const manifest = parseManifest(await (await signedFetch(`${base}/deployment-manifest`)).json());
    const client = new AshaveriClient({
      baseUrl: base,
      credential,
      verify: 'receipt',
      policy: policyFromManifest(manifest),
    });
    const { receipt } = await client.chat.completions.create({ messages: MESSAGES });
    expect(receipt).not.toBeNull();
    expect(receipt!.payload.ins).toBe('mock-instance-1');
  });

  it('refuses the mock deployment in strict mode: it attests no hardware', async () => {
    const manifest = parseManifest(await (await signedFetch(`${base}/deployment-manifest`)).json());
    const client = new AshaveriClient({
      baseUrl: base,
      credential,
      verify: 'strict',
      policy: policyFromManifest(manifest),
    });
    await expect(client.chat.completions.create({ messages: MESSAGES })).rejects.toMatchObject({
      code: 'EVIDENCE_NOT_HARDWARE',
    });
  });

  it('detects a response body modified in transit', async () => {
    const mitm: typeof fetch = async (input, init) => {
      const response = await fetch(input, init);
      const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
      if (url.endsWith('/chat/completions')) {
        const text = await response.text();
        return new Response(text.replace('mock completion', 'hacked completion'), response);
      }
      return response;
    };
    const client = new AshaveriClient({ baseUrl: base, credential, fetch: mitm });
    await expect(client.chat.completions.create({ messages: MESSAGES })).rejects.toMatchObject({
      code: 'RESPONSE_HASH_MISMATCH',
    });
  });
});
