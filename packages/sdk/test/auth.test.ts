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
import { buildGateway, CredentialStore, newPopCredential, openMemoryAccessLog } from '@ashaveri/signerd';

const SEED = new Uint8Array(32).fill(11);
const CREDENTIAL: AshaveriCredential = { kind: 'pop', id: 'sdk-test-1', privateKey: SEED };
const PUBLIC_KEY = signingKeyFromSeed(SEED).publicKey;
const BASE = 'https://gw.example/v1';
const NOW_MS = 1_772_000_000_000;

/** Records what the wrapper handed the transport, and answers with an empty response. */
function transport() {
  const seen: { url: string; init: RequestInit }[] = [];
  const inner = (async (input: string | URL | Request, init?: RequestInit) => {
    seen.push({ url: String(input), init: init ?? {} });
    return new Response('{}', { status: 200 });
  }) as unknown as typeof fetch;
  return {
    inner,
    seen,
    /** The last request the SDK sent. An empty `seen` is a broken test, so it says so by name rather than handing back `undefined`. */
    call: () => {
      const last = seen[seen.length - 1];
      if (last === undefined) throw new Error('the SDK sent no request');
      return last;
    },
  };
}

function header(call: { init: RequestInit }, name: string): string | undefined {
  const headers = new Headers(call.init.headers);
  return headers.get(name) ?? undefined;
}

/** Runs something expected to refuse, and hands back the error so a case can name its code. */
function refusal(body: () => unknown): SdkError {
  try {
    body();
  } catch (err) {
    expect(err).toBeInstanceOf(SdkError);
    return err as SdkError;
  }
  throw new Error('expected an SdkError');
}

function nonceOf(call: { init: RequestInit }): Uint8Array {
  return new Uint8Array(Buffer.from(new Headers(call.init.headers).get('x-ashaveri-nonce') as string, 'base64url'));
}

/** Reads headers a capture transport stored from inside its own callback. The compiler cannot follow that assignment, so it needs a guard that names the case where nothing was captured. */
function captured(headers: Headers | null): Headers {
  if (headers === null) throw new Error('the transport captured no request headers');
  return headers;
}

describe('authorizedFetch, proof of possession', () => {
  it('signs the origin-form request target and the body digest', async () => {
    const text = '{"model":"m","messages":[]}';
    const encoded = new TextEncoder().encode(text);
    // The digest is of the bytes, so every form that carries these same bytes signs the same way.
    for (const body of [text, encoded, encoded.buffer as ArrayBuffer]) {
      const { inner, call } = transport();
      const fetchImpl = authorizedFetch(CREDENTIAL, inner, { now: () => NOW_MS });
      await fetchImpl(`${BASE}/chat/completions`, { method: 'POST', body });
      const presented = call();
      const authorization = header(presented, 'authorization');
      expect(authorization).toBeDefined();
      const parsed = parsePopAuthorization(authorization as string);
      expect(header(presented, 'x-ashaveri-nonce')).toHaveLength(22);
      expect(
        verifyPopSignature(
          {
            ts: parsed.ts,
            nonce: nonceOf(presented),
            method: 'POST',
            target: '/v1/chat/completions',
            bodyDigestHex: sha256Hex(encoded),
          },
          parsed.signature,
          PUBLIC_KEY,
        ),
      ).toBe(true);
    }
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

  it('signs with the nonce the options supply, so a fixed vector is reproducible', async () => {
    const { inner, call } = transport();
    const nonce = new Uint8Array(POP_NONCE_BYTES).fill(0x33);
    const fetchImpl = authorizedFetch(CREDENTIAL, inner, { now: () => NOW_MS, nonce: () => nonce });
    await fetchImpl(`${BASE}/deployment-manifest`);
    const presented = call();
    expect(nonceOf(presented)).toEqual(nonce);
    const parsed = parsePopAuthorization(header(presented, 'authorization') as string);
    expect(
      verifyPopSignature(
        { ts: parsed.ts, nonce, method: 'GET', target: '/v1/deployment-manifest', bodyDigestHex: EMPTY_BODY_SHA256_HEX },
        parsed.signature,
        PUBLIC_KEY,
      ),
    ).toBe(true);
  });

  it('refuses a caller-set nonce of the wrong width', async () => {
    const { inner } = transport();
    const fetchImpl = authorizedFetch(CREDENTIAL, inner, { now: () => NOW_MS });
    const short = Buffer.from(new Uint8Array(POP_NONCE_BYTES - 1)).toString('base64url');
    await expect(
      fetchImpl(`${BASE}/chat/completions`, { method: 'POST', body: '{}', headers: { 'x-ashaveri-nonce': short } }),
    ).rejects.toMatchObject({ code: 'AUTH_CONFIG' });
  });

  it('refuses a caller-set nonce that is not base64url as a configuration error', async () => {
    const { inner } = transport();
    const fetchImpl = authorizedFetch(CREDENTIAL, inner, { now: () => NOW_MS });
    await expect(
      fetchImpl(`${BASE}/chat/completions`, { method: 'POST', body: '{}', headers: { 'x-ashaveri-nonce': 'not base64url!' } }),
    ).rejects.toMatchObject({ code: 'AUTH_CONFIG' });
  });

  it('signs the method a Request input carries, not the GET an empty init would give', async () => {
    const { inner, call } = transport();
    const fetchImpl = authorizedFetch(CREDENTIAL, inner, { now: () => NOW_MS });
    await fetchImpl(new Request(`${BASE}/chat/completions`, { method: 'POST' }));
    const presented = call();
    expect(presented.init.method).toBe('POST');
    const parsed = parsePopAuthorization(header(presented, 'authorization') as string);
    expect(
      verifyPopSignature(
        { ts: parsed.ts, nonce: nonceOf(presented), method: 'POST', target: '/v1/chat/completions', bodyDigestHex: EMPTY_BODY_SHA256_HEX },
        parsed.signature,
        PUBLIC_KEY,
      ),
    ).toBe(true);
  });

  it('keeps the headers a Request input carries, and its caller-set authorization still wins', async () => {
    const { inner, call } = transport();
    const fetchImpl = authorizedFetch(CREDENTIAL, inner, { now: () => NOW_MS });
    await fetchImpl(new Request(`${BASE}/deployment-manifest`, { headers: { 'x-keep-me': 'kept', 'content-type': 'application/json' } }));
    expect(header(call(), 'x-keep-me')).toBe('kept');
    expect(header(call(), 'content-type')).toBe('application/json');

    const kept = transport();
    const bearer = authorizedFetch({ kind: 'bearer', secret: new Uint8Array(32).fill(4) }, kept.inner);
    await bearer(new Request(`${BASE}/deployment-manifest`, { headers: { authorization: 'Bearer theirs' } }));
    expect(header(kept.call(), 'authorization')).toBe('Bearer theirs');
  });

  it('refuses a Request input whose body is a stream it cannot hash', async () => {
    const { inner } = transport();
    const fetchImpl = authorizedFetch(CREDENTIAL, inner, { now: () => NOW_MS });
    await expect(fetchImpl(new Request(`${BASE}/chat/completions`, { method: 'POST', body: '{}' }))).rejects.toMatchObject({
      code: 'AUTH_CONFIG',
    });
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
    expect(refusal(() => credentialFromEnv(env)).code).toBe('AUTH_CONFIG');
  });

  it('refuses a credential kind that is neither pop nor bearer', () => {
    const env = { [CREDENTIAL_ENV.id]: 'env-4', [CREDENTIAL_ENV.secret]: 'aa'.repeat(32), [CREDENTIAL_ENV.kind]: 'mtls' };
    expect(refusal(() => credentialFromEnv(env)).code).toBe('AUTH_CONFIG');
  });

  it('refuses a PoP key that is hex but the wrong width, and says so by name', () => {
    const env = { [CREDENTIAL_ENV.id]: 'env-5', [CREDENTIAL_ENV.secret]: 'aa'.repeat(31), [CREDENTIAL_ENV.kind]: 'pop' };
    const err = refusal(() => credentialFromEnv(env));
    expect(err.code).toBe('AUTH_CONFIG');
    expect(err.message).toContain(CREDENTIAL_ENV.secret);
  });

  it('refuses a PoP key with a corrupt tail instead of signing with a truncated one', () => {
    // 64 hex digits plus two characters outside the alphabet: the 32 bytes before them would
    // otherwise have become a key nobody was told about.
    const env = { [CREDENTIAL_ENV.id]: 'env-6', [CREDENTIAL_ENV.secret]: `${'aa'.repeat(32)}zz`, [CREDENTIAL_ENV.kind]: 'pop' };
    expect(refusal(() => credentialFromEnv(env)).code).toBe('AUTH_CONFIG');
  });

  it('refuses a PoP key of an odd length instead of dropping the last digit', () => {
    // 65 digits: a lenient decoder stops after the 64th and hands back exactly the 32 bytes a PoP
    // key needs, so the width check below it never fires and the lost digit is never mentioned.
    const env = { [CREDENTIAL_ENV.id]: 'env-7', [CREDENTIAL_ENV.secret]: `${'aa'.repeat(32)}a`, [CREDENTIAL_ENV.kind]: 'pop' };
    expect(refusal(() => credentialFromEnv(env)).code).toBe('AUTH_CONFIG');
  });

  it('refuses a bearer secret that is not base64url as a configuration error', () => {
    const env = { [CREDENTIAL_ENV.id]: 'env-8', [CREDENTIAL_ENV.secret]: 'not base64url!', [CREDENTIAL_ENV.kind]: 'bearer' };
    expect(refusal(() => credentialFromEnv(env)).code).toBe('AUTH_CONFIG');
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
    expect(captured(seen).get('authorization')).toMatch(/^Ashaveri-PoP credential=svc-1,/u);
    expect(captured(seen).get('x-ashaveri-nonce')).toMatch(/^[A-Za-z0-9_-]{22}$/u);
  });

  it('sends nothing that looks like a credential when none is configured', async () => {
    let seen: Headers | null = null;
    const capture: typeof fetch = async (_input, init) => {
      seen = new Headers(init?.headers);
      return new Response(JSON.stringify({ error: { message: 'the transport stops here' } }), { status: 500 });
    };
    const client = new AshaveriClient({ baseUrl: 'https://gw.example/v1', fetch: capture });
    await expect(client.chat.completions.create({ messages: [{ role: 'user', content: 'hi' }] })).rejects.toThrow();
    expect(captured(seen).get('authorization')).toBeNull();
  });
});

describe('AshaveriClient against a credentialed gateway', () => {
  it('completes, and the gateway records one proof-of-possession admission', async () => {
    const credential = newPopCredential({ id: 'client-test', scopes: ['complete', 'read'] });
    const log = openMemoryAccessLog();
    const app = buildGateway({
      access: new CredentialStore({ file: { version: 1, credentials: [credential.record] } }),
      accessLog: log,
    });
    await app.listen({ port: 0, host: '127.0.0.1' });
    const address = app.server.address();
    if (address === null || typeof address === 'string') throw new Error('the gateway did not bind a port');
    const base = `http://127.0.0.1:${String(address.port)}/v1`;
    const client = new AshaveriClient({
      baseUrl: base,
      credential: { kind: 'pop', id: 'client-test', privateKey: credential.privateKey },
    });
    const { completion } = await client.chat.completions.create({ messages: [{ role: 'user', content: 'hi' }] });
    expect(completion.object).toBe('chat.completion');
    await app.close();
    expect(log.entries().filter((entry) => entry.p === '/v1/chat/completions')).toMatchObject([
      { cred: 'client-test', auth: 'pop', st: 200, deny: null },
    ]);
  });

  it('surfaces the gateway refusal, with its code, through the client', async () => {
    const credential = newPopCredential({ id: 'client-test', scopes: ['read'] });
    const app = buildGateway({
      access: new CredentialStore({ file: { version: 1, credentials: [credential.record] } }),
      accessLog: openMemoryAccessLog(),
    });
    await app.listen({ port: 0, host: '127.0.0.1' });
    const address = app.server.address();
    if (address === null || typeof address === 'string') throw new Error('the gateway did not bind a port');
    const client = new AshaveriClient({
      baseUrl: `http://127.0.0.1:${String(address.port)}/v1`,
      credential: { kind: 'pop', id: 'client-test', privateKey: credential.privateKey },
    });
    await expect(client.chat.completions.create({ messages: [] })).rejects.toThrow(/SCOPE_DENIED/u);
    await app.close();
  });
});
