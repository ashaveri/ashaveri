import { describe, expect, it } from 'vitest';
import {
  EMPTY_BODY_SHA256_HEX,
  POP_NONCE_BYTES,
  parsePopAuthorization,
  sha256Hex,
  signingKeyFromSeed,
  verifyPopSignature,
} from '@ashaveri/receipt';
import { SdkError } from '../src/errors.js';
import { CREDENTIAL_ENV, authorizedFetch, credentialFromEnv, type AshaveriCredential } from '../src/auth.js';
import { AshaveriClient } from '../src/client.js';

const SEED = new Uint8Array(32).fill(11);
const CREDENTIAL: AshaveriCredential = { kind: 'pop', id: 'sdk-test-1', privateKey: SEED };
const PUBLIC_KEY = signingKeyFromSeed(SEED).publicKey;
const BASE = 'https://gw.example/v1';
const NOW_MS = 1_772_000_000_000;

/** Records what the wrapper handed the transport, and answers with an empty response. */
function transport() {
  const seen: { url: string; init: RequestInit }[] = [];
  const inner = (async (input: RequestInfo | URL, init?: RequestInit) => {
    seen.push({ url: String(input), init: init ?? {} });
    return new Response('{}', { status: 200 });
  }) as unknown as typeof fetch;
  return { inner, seen, call: () => seen[seen.length - 1] };
}

function header(call: { init: RequestInit }, name: string): string | undefined {
  const headers = new Headers(call.init.headers);
  return headers.get(name) ?? undefined;
}

describe('authorizedFetch, proof of possession', () => {
  it('signs the origin-form request target and the body digest', async () => {
    const { inner, call } = transport();
    const fetchImpl = authorizedFetch(CREDENTIAL, inner, { now: () => NOW_MS });
    const body = '{"model":"m","messages":[]}';
    await fetchImpl(`${BASE}/chat/completions`, { method: 'POST', body });
    const presented = call();
    const authorization = header(presented, 'authorization');
    expect(authorization).toBeDefined();
    const parsed = parsePopAuthorization(authorization as string);
    const nonce = new Headers(presented.init.headers).get('x-ashaveri-nonce');
    expect(nonce).toHaveLength(22);
    expect(
      verifyPopSignature(
        {
          ts: parsed.ts,
          nonce: new Uint8Array(Buffer.from(nonce as string, 'base64url')),
          method: 'POST',
          target: '/v1/chat/completions',
          bodyDigestHex: sha256Hex(new TextEncoder().encode(body)),
        },
        parsed.signature,
        PUBLIC_KEY,
      ),
    ).toBe(true);
  });

  it('keeps the nonce the caller already set, so the receipt still echoes the signed value', async () => {
    const { inner, call } = transport();
    const fetchImpl = authorizedFetch(CREDENTIAL, inner, { now: () => NOW_MS });
    const nonce = new Uint8Array(POP_NONCE_BYTES).fill(0x5a);
    await fetchImpl(`${BASE}/chat/completions`, {
      method: 'POST',
      body: '{}',
      headers: { 'x-ashaveri-nonce': Buffer.from(nonce).toString('base64url') },
    });
    const presented = call();
    const authorization = header(presented, 'authorization');
    const parsed = parsePopAuthorization(authorization as string);
    expect(new Uint8Array(Buffer.from(new Headers(presented.init.headers).get('x-ashaveri-nonce') as string, 'base64url'))).toEqual(nonce);
    expect(
      verifyPopSignature(
        { ts: parsed.ts, nonce, method: 'POST', target: '/v1/chat/completions', bodyDigestHex: sha256Hex(new TextEncoder().encode('{}')) },
        parsed.signature,
        PUBLIC_KEY,
      ),
    ).toBe(true);
  });

  it('signs a bodyless GET against the empty-body digest, query included', async () => {
    const { inner, call } = transport();
    const fetchImpl = authorizedFetch(CREDENTIAL, inner, { now: () => NOW_MS });
    await fetchImpl(`${BASE}/attestation?report_data=${'ab'.repeat(32)}`);
    const presented = call();
    const parsed = parsePopAuthorization(header(presented, 'authorization') as string);
    const nonce = Buffer.from(new Headers(presented.init.headers).get('x-ashaveri-nonce') as string, 'base64url');
    expect(
      verifyPopSignature(
        { ts: parsed.ts, nonce: new Uint8Array(nonce), method: 'GET', target: `/v1/attestation?report_data=${'ab'.repeat(32)}`, bodyDigestHex: EMPTY_BODY_SHA256_HEX },
        parsed.signature,
        PUBLIC_KEY,
      ),
    ).toBe(true);
  });

  it('generates a fresh nonce per request when the caller set none', async () => {
    const { inner, seen } = transport();
    const fetchImpl = authorizedFetch(CREDENTIAL, inner, { now: () => NOW_MS });
    await fetchImpl(`${BASE}/deployment-manifest`);
    await fetchImpl(`${BASE}/deployment-manifest`);
    const nonces = seen.map((entry) => new Headers(entry.init.headers).get('x-ashaveri-nonce'));
    expect(nonces[0]).not.toBe(nonces[1]);
  });

  it('leaves a caller-set Authorization header alone', async () => {
    const { inner, call } = transport();
    const fetchImpl = authorizedFetch(CREDENTIAL, inner, { now: () => NOW_MS });
    await fetchImpl(`${BASE}/deployment-manifest`, { headers: { authorization: 'Bearer theirs' } });
    expect(header(call(), 'authorization')).toBe('Bearer theirs');
  });

  it('refuses a body form it cannot hash instead of signing the wrong bytes', async () => {
    const { inner } = transport();
    const fetchImpl = authorizedFetch(CREDENTIAL, inner, { now: () => NOW_MS });
    await expect(
      fetchImpl(`${BASE}/chat/completions`, { method: 'POST', body: new ReadableStream<Uint8Array>() }),
    ).rejects.toMatchObject({ code: 'AUTH_CONFIG' });
  });

  it('returns the transport unchanged when no credential is configured', async () => {
    const { inner, seen } = transport();
    const fetchImpl = authorizedFetch(undefined, inner);
    expect(fetchImpl).toBe(inner);
    await fetchImpl(`${BASE}/deployment-manifest`);
    expect(header(callOf(seen), 'authorization')).toBeUndefined();

    function callOf(entries: { init: RequestInit }[]) {
      return entries[entries.length - 1] as { init: RequestInit };
    }
  });
});

describe('authorizedFetch, bearer mode', () => {
  it('presents the secret and sends no nonce header', async () => {
    const { inner, call } = transport();
    const fetchImpl = authorizedFetch({ kind: 'bearer', secret: new Uint8Array(32).fill(4) }, inner);
    await fetchImpl(`${BASE}/deployment-manifest`);
    const headers = new Headers(call().init.headers);
    expect(headers.get('authorization')).toBe(`Bearer ${Buffer.from(new Uint8Array(32).fill(4)).toString('base64url')}`);
    expect(headers.get('x-ashaveri-nonce')).toBeNull();
  });
});

describe('credentialFromEnv', () => {
  it('reads a PoP credential from a hex private key', () => {
    const env = {
      [CREDENTIAL_ENV.id]: 'env-1',
      [CREDENTIAL_ENV.secret]: Buffer.from(SEED).toString('hex'),
      [CREDENTIAL_ENV.kind]: 'pop',
    };
    const parsed = credentialFromEnv(env);
    expect(parsed).toMatchObject({ kind: 'pop', id: 'env-1' });
    expect(parsed?.kind === 'pop' ? Buffer.from(parsed.privateKey).equals(SEED) : false).toBe(true);
  });

  it('reads a bearer credential, and defaults the kind to pop', () => {
    const env = { [CREDENTIAL_ENV.id]: 'env-2', [CREDENTIAL_ENV.secret]: 'c2VjcmV0c2VjcmV0c2VjcmV0c2Vj' };
    expect(credentialFromEnv({ ...env, [CREDENTIAL_ENV.kind]: 'bearer' })).toMatchObject({ kind: 'bearer' });
    expect(credentialFromEnv({ [CREDENTIAL_ENV.secret]: 'c2VjcmV0c2VjcmV0c2VjcmV0c2Vj' })).toBeUndefined();
  });

  it('is undefined with nothing set, so the unauthenticated default survives', () => {
    expect(credentialFromEnv({})).toBeUndefined();
  });

  it('refuses a PoP key that is not 32 bytes', () => {
    const env = { [CREDENTIAL_ENV.id]: 'env-3', [CREDENTIAL_ENV.secret]: 'aa', [CREDENTIAL_ENV.kind]: 'pop' };
    try {
      credentialFromEnv(env);
      throw new Error('expected an SdkError');
    } catch (err) {
      expect(err).toBeInstanceOf(SdkError);
      expect((err as SdkError).code).toBe('AUTH_CONFIG');
    }
  });
});

const CLIENT_SEED = new Uint8Array(32).fill(7);

describe('AshaveriClient transport', () => {
  it('signs with the credential it was built with, before the gateway is involved', async () => {
    let seen: Headers | null = null;
    const capture: typeof fetch = async (_input, init) => {
      seen = new Headers(init?.headers);
      return new Response(JSON.stringify({ error: { message: 'the transport stops here' } }), { status: 500 });
    };
    const client = new AshaveriClient({
      baseUrl: 'https://gw.example/v1',
      fetch: capture,
      credential: { kind: 'pop', id: 'svc-1', privateKey: CLIENT_SEED },
    });
    await expect(client.chat.completions.create({ messages: [{ role: 'user', content: 'hi' }] })).rejects.toThrow();
    expect(seen?.get('authorization')).toMatch(/^Ashaveri-PoP credential=svc-1,/u);
    expect(seen?.get('x-ashaveri-nonce')).toMatch(/^[A-Za-z0-9_-]{22}$/u);
  });

  it('sends nothing that looks like a credential when none is configured', async () => {
    let seen: Headers | null = null;
    const capture: typeof fetch = async (_input, init) => {
      seen = new Headers(init?.headers);
      return new Response(JSON.stringify({ error: { message: 'the transport stops here' } }), { status: 500 });
    };
    const client = new AshaveriClient({ baseUrl: 'https://gw.example/v1', fetch: capture });
    await expect(client.chat.completions.create({ messages: [{ role: 'user', content: 'hi' }] })).rejects.toThrow();
    expect(seen?.get('authorization')).toBeNull();
  });
});
