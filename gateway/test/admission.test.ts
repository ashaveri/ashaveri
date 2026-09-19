import { describe, expect, it } from 'vitest';
import { mkdtemp, rm, utimes, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  EMPTY_BODY_SHA256_HEX,
  fromBase64Url,
  sha256Hex,
  signPopAuthorization,
  signingKeyFromSeed,
  toBase64Url,
  type PopFields,
} from '@ashaveri/receipt';
import {
  AccessError,
  accessStatus,
  CredentialStore,
  DEFAULT_RATE,
  REPLAY_WINDOW_SECONDS,
  TokenBucket,
  newBearerCredential,
  newPopCredential,
  parseCredentialFile,
  serializeCredentialFile,
  type AdmissionInput,
  type CredentialFile,
  type CredentialRecord,
  type Scope,
} from '../src/access.js';

const KEY_SEED = new Uint8Array(32).fill(3);
const NOW = 1_772_000_000;

function record(id: string, scopes: Scope[], extra: Partial<CredentialRecord> = {}) {
  const generated = newPopCredential({ id, scopes, now: NOW });
  const publicKey = signingKeyFromSeed(KEY_SEED).publicKey;
  return {
    record: { ...generated.record, publicKey, ...extra } satisfies CredentialRecord,
    privateKey: KEY_SEED,
  };
}

function store(records: CredentialRecord[], options: { allowBearer?: boolean; toleranceSeconds?: number } = {}) {
  const file: CredentialFile = { version: 1, credentials: records };
  return new CredentialStore({ file, allowBearer: options.allowBearer, toleranceSeconds: options.toleranceSeconds });
}

interface Signed {
  id: string;
  privateKey: Uint8Array;
  method?: string;
  target?: string;
  body?: string | null;
  ts?: number;
  nonce?: Uint8Array;
  /** Set false to present a signature whose nonce header is missing. */
  withNonceHeader?: boolean;
}

/**
 * One builder for every case, because a bodyless GET has to sign the empty-body
 * digest and a test that hand-assembled the difference would be asserting its own
 * arithmetic rather than the gateway's.
 */
function signed(options: Signed): AdmissionInput {
  const method = options.method ?? 'POST';
  const target = options.target ?? '/v1/chat/completions';
  const text = options.body ?? (method === 'POST' ? '{"model":"m","messages":[]}' : '');
  const body = text.length === 0 ? null : new TextEncoder().encode(text);
  const nonce = options.nonce ?? new Uint8Array(16).fill(1);
  const fields: PopFields = {
    ts: options.ts ?? NOW,
    nonce,
    method,
    target,
    bodyDigestHex: body === null ? EMPTY_BODY_SHA256_HEX : sha256Hex(body),
  };
  const headers: Record<string, string> = {
    authorization: signPopAuthorization(fields, options.id, options.privateKey),
  };
  if (options.withNonceHeader !== false) {
    headers['x-ashaveri-nonce'] = toBase64Url(nonce);
  }
  return { method, url: target, headers, body, nowSeconds: NOW };
}

function code(fn: () => unknown): string {
  try {
    fn();
    return 'no-error';
  } catch (err) {
    return err instanceof AccessError ? err.code : `non-AccessError: ${String(err)}`;
  }
}

interface Refusal {
  code: string;
  logCode: string;
  status: number;
  credentialId: string | null;
  message: string;
}

/**
 * What a store answered one presentation, with every field a caller and the access log can each see.
 * An admission reports `no-error` and nothing else, because the rest of the shape is a property of a
 * refusal. `at` is the nonce byte, so two presentations of one store are never also a replay.
 */
function refusal(s: CredentialStore, id: string, privateKey: Uint8Array, at: number): Refusal {
  try {
    s.admit(signed({ id, privateKey, nonce: new Uint8Array(16).fill(at) }));
    return { code: 'no-error', logCode: 'no-error', status: 0, credentialId: null, message: '' };
  } catch (err) {
    if (!(err instanceof AccessError)) throw err;
    return {
      code: err.code,
      logCode: err.logCode,
      status: err.status,
      credentialId: err.credentialId ?? null,
      message: err.message,
    };
  }
}

describe('CredentialStore.admit, the five checks in order', () => {
  it('admits a valid proof of possession and reports what it granted', () => {
    const generated = record('svc-1', ['complete']);
    const admission = store([generated.record]).admit(signed({ id: 'svc-1', privateKey: generated.privateKey }));
    expect(admission).toMatchObject({ credentialId: 'svc-1', scope: 'complete', auth: 'pop' });
    expect(admission.nonce).toHaveLength(16);
  });

  it('answers a name this file does not carry with the refusal a failed signature gets', () => {
    const generated = record('svc-1', ['complete']);
    const wrongKey = new Uint8Array(32).fill(9);
    const s = store([generated.record]);
    // Both halves sign with a key no record in this file holds, so neither has proved it holds the key
    // its own header names, and neither is owed an answer about the file. The two refusals are one
    // answer in one sentence, and the sentence names only what the caller wrote: which names this
    // store carries is not a question a request gets to ask.
    const named = refusal(s, 'svc-1', wrongKey, 1);
    const unclaimed = refusal(s, 'nobody', wrongKey, 2);
    expect(named).toMatchObject({ code: 'AUTH_SIGNATURE', logCode: 'AUTH_SIGNATURE', status: 401 });
    expect(unclaimed).toMatchObject({ code: 'AUTH_SIGNATURE', status: 401 });
    expect(unclaimed.message).toBe('the proof of possession signature did not verify: nobody');
  });

  it('tells the log the reason a collapsed refusal was given, and the caller only that it did not verify', () => {
    const generated = record('svc-1', ['complete']);
    const bearer = newBearerCredential({ id: 'ops-1', now: NOW });
    const s = store([generated.record, bearer.record], { allowBearer: true });
    const wrongKey = new Uint8Array(32).fill(9);
    // A client pointing a proof of possession at a bearer key and a client naming an id that was never
    // issued are the same thing to the caller and two different things to the operator reading a spike
    // of them, so the codes differ exactly once and the answers do not.
    expect(refusal(s, 'ops-1', wrongKey, 3)).toMatchObject({
      code: 'AUTH_SIGNATURE',
      logCode: 'AUTH_SCHEME',
      status: 401,
      credentialId: 'ops-1',
    });
    expect(refusal(s, 'nobody', wrongKey, 4)).toMatchObject({
      code: 'AUTH_SIGNATURE',
      logCode: 'AUTH_UNKNOWN',
      status: 401,
      credentialId: 'nobody',
    });
    expect(refusal(s, 'svc-1', wrongKey, 5).code).toBe('AUTH_SIGNATURE');
    expect(refusal(s, 'svc-1', generated.privateKey, 6).code).toBe('no-error');
  });

  it('refuses a revoked credential only to a caller that proves the key it names', () => {
    const generated = record('svc-1', ['complete'], { revokedAt: NOW - 1 });
    const s = store([generated.record]);
    // Presented with a key that could never verify, this is a caller that has proved nothing, so it is
    // told that and nothing else: the withdrawal is the record's own answer, and the record's own key
    // is what makes it entitled to it.
    expect(code(() => s.admit(signed({ id: 'svc-1', privateKey: new Uint8Array(32).fill(9), nonce: new Uint8Array(16).fill(4) })))).toBe(
      'AUTH_SIGNATURE',
    );
    expect(code(() => s.admit(signed({ id: 'svc-1', privateKey: generated.privateKey, nonce: new Uint8Array(16).fill(5) })))).toBe(
      'AUTH_REVOKED',
    );
  });

  it('refuses a timestamp outside the tolerance and names the clock', () => {
    const generated = record('svc-1', ['complete']);
    const s = store([generated.record]);
    const stale = signed({ id: 'svc-1', privateKey: generated.privateKey, ts: NOW - 121 });
    try {
      s.admit(stale);
      throw new Error('expected a refusal');
    } catch (err) {
      expect(err).toBeInstanceOf(AccessError);
      expect((err as AccessError).code).toBe('AUTH_STALE');
      // The record's `cred` is filled from this field, so a refusal raised after the lookup has to
      // carry the name out with it or the line logs no credential for a known one.
      expect((err as AccessError).credentialId).toBe('svc-1');
      expect((err as AccessError).message.toLowerCase()).toContain('clock');
    }
    expect(code(() => s.admit(signed({ id: 'svc-1', privateKey: generated.privateKey, ts: NOW + 121 })))).toBe('AUTH_STALE');
    expect(code(() => s.admit(signed({ id: 'svc-1', privateKey: generated.privateKey, ts: NOW + 119 })))).toBe('no-error');
  });

  it('honours a configured tolerance', () => {
    const generated = record('svc-1', ['complete']);
    const s = store([generated.record], { toleranceSeconds: 600 });
    expect(code(() => s.admit(signed({ id: 'svc-1', privateKey: generated.privateKey, ts: NOW - 500 })))).toBe('no-error');
  });

  it('refuses the same nonce from the same credential twice, and allows a different credential to reuse it', () => {
    const a = record('svc-a', ['complete']);
    const b = record('svc-b', ['complete']);
    const s = store([a.record, b.record]);
    const nonce = new Uint8Array(16).fill(0x42);
    const first = signed({ id: 'svc-a', privateKey: a.privateKey, nonce });
    expect(code(() => s.admit(first))).toBe('no-error');
    expect(code(() => s.admit(first))).toBe('NONCE_SEEN');
    expect(code(() => s.admit(signed({ id: 'svc-b', privateKey: b.privateKey, nonce })))).toBe('no-error');
  });

  it('refuses a scope miss before the bucket is touched', () => {
    const generated = record('read-only', ['read'], { rate: { perMinute: 1, burst: 1 } });
    const s = store([generated.record]);
    const denied = (at: number): AdmissionInput =>
      signed({ id: 'read-only', privateKey: generated.privateKey, nonce: new Uint8Array(16).fill(at) });
    const entitled = (at: number): AdmissionInput =>
      signed({
        id: 'read-only',
        privateKey: generated.privateKey,
        method: 'GET',
        target: '/v1/deployment-manifest',
        nonce: new Uint8Array(16).fill(at),
      });
    // The scope miss is presented twice around a one-token budget. The second time the bucket is
    // already empty, so a pipeline that charged it before testing scope would report RATE_LIMITED
    // for a request that was never going to use it, and the GET between them shows it spent none.
    expect(code(() => s.admit(denied(1)))).toBe('SCOPE_DENIED');
    expect(code(() => s.admit(entitled(2)))).toBe('no-error');
    expect(code(() => s.admit(denied(3)))).toBe('SCOPE_DENIED');
  });

  it('refuses either shape of a scope miss with the budget whole', () => {
    const generated = record('read-only', ['read'], { rate: { perMinute: 1, burst: 1 } });
    const s = store([generated.record]);
    const miss = (target: string, at: number): AdmissionInput =>
      signed({ id: 'read-only', privateKey: generated.privateKey, target, nonce: new Uint8Array(16).fill(at) });
    const entitled = (at: number): AdmissionInput =>
      signed({
        id: 'read-only',
        privateKey: generated.privateKey,
        method: 'GET',
        target: '/v1/deployment-manifest',
        nonce: new Uint8Array(16).fill(at),
      });
    // The two refusals come from different halves of one condition: the table names
    // `/v1/chat/completions` and asks `complete` of it, which this `read` grant does not satisfy,
    // and it names `/v1/completions` not at all. Both arrive ahead of the single token this record
    // holds, and the GET after them is what says neither spent it.
    expect(code(() => s.admit(miss('/v1/chat/completions', 1)))).toBe('SCOPE_DENIED');
    expect(code(() => s.admit(miss('/v1/completions', 2)))).toBe('SCOPE_DENIED');
    expect(code(() => s.admit(entitled(3)))).toBe('no-error');
  });

  it('refuses a rate-exhausted credential with a retry hint', () => {
    const generated = record('svc-1', ['complete'], { rate: { perMinute: 1, burst: 1 } });
    const s = store([generated.record]);
    let seen = 'no-error';
    for (let i = 0; i < 3; i++) {
      const attempt = signed({ id: 'svc-1', privateKey: generated.privateKey, nonce: new Uint8Array(16).fill(i) });
      try {
        s.admit(attempt);
      } catch (err) {
        seen = err instanceof AccessError ? err.code : 'other';
        if (seen === 'RATE_LIMITED' && err instanceof AccessError) {
          expect(err.retryAfterSeconds).toBeGreaterThan(0);
        }
      }
    }
    expect(seen).toBe('RATE_LIMITED');
  });

  it('refuses a missing header, a foreign scheme, and a signature with no nonce header', () => {
    const generated = record('svc-1', ['complete']);
    const s = store([generated.record]);
    const completion = { method: 'POST', url: '/v1/chat/completions', body: null };
    expect(code(() => s.admit({ ...completion, headers: {} }))).toBe('AUTH_MALFORMED');
    expect(code(() => s.admit({ ...completion, headers: { authorization: 'Bearer x' } }))).toBe('AUTH_SCHEME');
    const noNonce = signed({ id: 'svc-1', privateKey: generated.privateKey, withNonceHeader: false });
    expect(code(() => s.admit(noNonce))).toBe('AUTH_NONCE_MISSING');
  });

  it('refuses a nonce header that contradicts the signed nonce', () => {
    const generated = record('svc-1', ['complete']);
    const request = signed({ id: 'svc-1', privateKey: generated.privateKey });
    const swapped: AdmissionInput = {
      ...request,
      headers: { ...request.headers, 'x-ashaveri-nonce': toBase64Url(new Uint8Array(16).fill(0x77)) },
    };
    // There is no separate comparison for this: the nonce is a signing-string
    // component, so a header that disagrees with the signature fails the signature.
    expect(code(() => store([generated.record]).admit(swapped))).toBe('AUTH_SIGNATURE');
  });
});

describe('bearer mode', () => {
  it('is off by default and refuses a bearer record outright', () => {
    const bearer = newBearerCredential({ id: 'ops-1', now: NOW });
    const s = store([bearer.record]);
    expect(
      code(() => s.admit({ method: 'GET', url: '/v1/deployment-manifest', headers: { authorization: `Bearer ${Buffer.from(bearer.secret).toString('base64url')}` }, body: null })),
    ).toBe('AUTH_SCHEME');
  });

  it('admits a correct secret when enabled, and labels the admission bearer', () => {
    const bearer = newBearerCredential({ id: 'ops-1', now: NOW });
    const s = store([bearer.record], { allowBearer: true });
    const secret = Buffer.from(bearer.secret).toString('base64url');
    const admission = s.admit({
      method: 'GET',
      url: '/v1/deployment-manifest',
      headers: { authorization: `Bearer ${secret}` },
      body: null,
    });
    expect(admission).toMatchObject({ credentialId: 'ops-1', auth: 'bearer', nonce: null });
    expect(
      code(() => s.admit({ method: 'GET', url: '/v1/deployment-manifest', headers: { authorization: 'Bearer wrong' }, body: null })),
    ).toBe('AUTH_UNKNOWN');
  });

  it('still applies scope and rate in bearer mode', () => {
    const bearer = newBearerCredential({ id: 'ops-1', scopes: ['read'], now: NOW });
    const s = store([bearer.record], { allowBearer: true });
    const secret = Buffer.from(bearer.secret).toString('base64url');
    expect(
      code(() => s.admit({ method: 'POST', url: '/v1/chat/completions', headers: { authorization: `Bearer ${secret}` }, body: null })),
    ).toBe('SCOPE_DENIED');
    // A target outside the table is refused the same way once a secret has matched, and a secret
    // that matches nothing there gets the refusal a wrong secret always gets.
    expect(
      code(() => s.admit({ method: 'GET', url: '/v1/not-a-route', headers: { authorization: `Bearer ${secret}` }, body: null })),
    ).toBe('SCOPE_DENIED');
    expect(
      code(() => s.admit({ method: 'GET', url: '/v1/not-a-route', headers: { authorization: 'Bearer wrong' }, body: null })),
    ).toBe('AUTH_UNKNOWN');
  });

  it('refuses a bearer scope miss twice on a credential with one token to spend', () => {
    const bearer = newBearerCredential({ id: 'ops-1', scopes: ['read'], now: NOW });
    const tight: CredentialRecord = { ...bearer.record, rate: { perMinute: 1, burst: 1 } };
    const s = store([tight], { allowBearer: true });
    const secret = Buffer.from(bearer.secret).toString('base64url');
    // Built fresh each time rather than reused, because a bearer request carries no nonce and no
    // timestamp: the bucket is the only state two identical presentations could differ over.
    const completion = (): AdmissionInput => ({
      method: 'POST',
      url: '/v1/chat/completions',
      headers: { authorization: `Bearer ${secret}` },
      body: null,
    });
    // The second refusal is the one that says a scope miss never spends budget. The first answers
    // SCOPE_DENIED under either ordering, since the token is still there when it arrives.
    expect(code(() => s.admit(completion()))).toBe('SCOPE_DENIED');
    expect(code(() => s.admit(completion()))).toBe('SCOPE_DENIED');
  });

  it('refuses either shape of a bearer scope miss with the budget whole', () => {
    const bearer = newBearerCredential({ id: 'ops-1', scopes: ['read'], now: NOW });
    const tight: CredentialRecord = { ...bearer.record, rate: { perMinute: 1, burst: 1 } };
    const s = store([tight], { allowBearer: true });
    const secret = Buffer.from(bearer.secret).toString('base64url');
    const miss = (target: string): AdmissionInput => ({
      method: 'POST',
      url: target,
      headers: { authorization: `Bearer ${secret}` },
      body: null,
    });
    // A bearer request presents no nonce, so the two refusals differ only by target, and the GET
    // after them is what shows a refusal spent nothing: the record holds one token, and it is still
    // there for the route this credential may use.
    expect(code(() => s.admit(miss('/v1/chat/completions')))).toBe('SCOPE_DENIED');
    expect(code(() => s.admit(miss('/v1/completions')))).toBe('SCOPE_DENIED');
    expect(
      code(() =>
        s.admit({ method: 'GET', url: '/v1/deployment-manifest', headers: { authorization: `Bearer ${secret}` }, body: null }),
      ),
    ).toBe('no-error');
  });

  it('refuses a bearer record whose stored hash is malformed', () => {
    const bearer = newBearerCredential({ id: 'ops-1', now: NOW });
    const broken: CredentialRecord = { ...bearer.record, secretHash: new Uint8Array(31) };
    const s = store([broken], { allowBearer: true });
    expect(
      code(() => s.admit({ method: 'GET', url: '/v1/deployment-manifest', headers: { authorization: 'Bearer anything' }, body: null })),
    ).toBe('AUTH_UNKNOWN');
  });
});

describe('GET routes sign the empty body digest', () => {
  it('accepts a bodyless request whose signing string used the published constant', () => {
    const generated = record('svc-1', ['read']);
    const nonce = new Uint8Array(16).fill(5);
    const header = signPopAuthorization(
      { ts: NOW, nonce, method: 'GET', target: '/v1/attestation?report_data=aa', bodyDigestHex: EMPTY_BODY_SHA256_HEX },
      'svc-1',
      generated.privateKey,
    );
    const admission = store([generated.record]).admit({
      method: 'GET',
      url: '/v1/attestation?report_data=aa',
      headers: { authorization: header, 'x-ashaveri-nonce': toBase64Url(nonce) },
      body: null,
      nowSeconds: NOW,
    });
    expect(admission.scope).toBe('read');
  });

  it('refuses the same credential replayed onto another target', () => {
    const generated = record('svc-1', ['read']);
    const nonce = new Uint8Array(16).fill(6);
    const header = signPopAuthorization(
      { ts: NOW, nonce, method: 'GET', target: '/v1/attestation?report_data=aa', bodyDigestHex: EMPTY_BODY_SHA256_HEX },
      'svc-1',
      generated.privateKey,
    );
    expect(
      code(() =>
        store([generated.record]).admit({
          method: 'GET',
          url: '/v1/attestation?report_data=bb',
          headers: { authorization: header, 'x-ashaveri-nonce': toBase64Url(nonce) },
          body: null,
          nowSeconds: NOW,
        }),
      ),
    ).toBe('AUTH_SIGNATURE');
  });
});

describe('TokenBucket', () => {
  it('refills at the configured rate and never above burst', () => {
    const bucket = new TokenBucket();
    const rate = { perMinute: 60, burst: 2 };
    let clock = 1_000;
    expect(bucket.take('a', rate, clock).allowed).toBe(true);
    expect(bucket.take('a', rate, clock).allowed).toBe(true);
    expect(bucket.take('a', rate, clock).allowed).toBe(false);
    clock += 60_000;
    expect(bucket.take('a', rate, clock).allowed).toBe(true);
    expect(bucket.take('a', rate, clock).allowed).toBe(true);
    expect(bucket.take('a', rate, clock).allowed).toBe(false);
  });

  it('refills nothing for time that has not passed when the clock steps backwards', () => {
    const bucket = new TokenBucket();
    const rate = { perMinute: 60, burst: 3 };
    expect(bucket.take('a', rate, 60_000).allowed).toBe(true);
    expect(bucket.take('a', rate, 60_000).allowed).toBe(true);
    // One token of three is left, and thirty seconds that have already been counted would
    // otherwise read as a debt: a step backwards may not spend tokens nobody took.
    expect(bucket.take('a', rate, 30_000).allowed).toBe(true);
    expect(bucket.take('a', rate, 30_000).allowed).toBe(false);
  });

  it('grants a clock that wobbles no more than the same stamps without the wobble', () => {
    const rate = { perMinute: 60, burst: 2 };
    const admitted = (stamps: number[]): number => {
      const bucket = new TokenBucket();
      return stamps.filter((stamp) => bucket.take('a', rate, stamp).allowed).length;
    };
    // Two backwards steps, each followed by a forward one that re-crosses the stamp it fell from.
    // A bucket that records the lower stamp as its base pays that interval out a second time, so
    // the wobbly run buys more than the run whose backwards steps never happened.
    const wobbly = [2_000, 1_000, 2_000, 1_500, 2_500];
    const forwardOnly = wobbly.filter((stamp, index) => index === 0 || stamp >= (wobbly[index - 1] ?? 0));
    expect(forwardOnly.length).toBeLessThan(wobbly.length);
    expect(admitted(wobbly)).toBeLessThanOrEqual(admitted(forwardOnly));
  });

  it('keeps one bucket per credential', () => {
    const bucket = new TokenBucket();
    const rate = { perMinute: 1, burst: 1 };
    expect(bucket.take('a', rate, 0).allowed).toBe(true);
    expect(bucket.take('b', rate, 0).allowed).toBe(true);
    expect(bucket.take('a', rate, 0).allowed).toBe(false);
  });

  it('says how long to wait, in whole seconds of at least one', () => {
    const bucket = new TokenBucket();
    bucket.take('a', { perMinute: 6, burst: 1 }, 0);
    const second = bucket.take('a', { perMinute: 6, burst: 1 }, 0);
    expect(second.allowed).toBe(false);
    expect(second.retryAfterSeconds).toBeGreaterThanOrEqual(1);
    expect(Number.isInteger(second.retryAfterSeconds)).toBe(true);
  });

  it('keeps the hint a number for a rate that can never refill', () => {
    const bucket = new TokenBucket();
    const dead = { perMinute: 0, burst: 1 };
    expect(bucket.take('a', dead, 0).allowed).toBe(true);
    const denied = bucket.take('a', dead, 0);
    expect(denied.allowed).toBe(false);
    expect(Number.isFinite(denied.retryAfterSeconds)).toBe(true);
    expect(Number.isInteger(denied.retryAfterSeconds)).toBe(true);
  });

  it('exports the default the design chose and the replay window', () => {
    expect(DEFAULT_RATE).toEqual({ perMinute: 60, burst: 120 });
    expect(REPLAY_WINDOW_SECONDS).toBe(900);
  });
});

describe('the refusals that come from the gateway side of the door', () => {
  it('refuses a target the route table does not name, rather than inventing a scope for it', () => {
    const generated = record('svc-1', ['read', 'complete']);
    const gone = record('svc-gone', ['read', 'complete'], { revokedAt: NOW - 1 });
    const s = store([generated.record, gone.record]);
    const unlisted = (id: string, privateKey: Uint8Array, at: number): AdmissionInput =>
      signed({ id, privateKey, method: 'GET', target: '/v1/not-a-route', nonce: new Uint8Array(16).fill(at) });
    // An unscoped target is a scope requirement, so it answers through the credential that
    // presented it: a refusal the table alone could give would let anyone probe which paths a
    // deployment has scoped.
    expect(code(() => s.admit({ method: 'GET', url: '/v1/not-a-route', headers: {}, body: null }))).toBe('AUTH_MALFORMED');
    expect(code(() => s.admit(unlisted('svc-1', generated.privateKey, 1)))).toBe('SCOPE_DENIED');
    expect(accessStatus('SCOPE_DENIED')).toBe(403);
    expect(code(() => s.admit(unlisted('nobody', generated.privateKey, 2)))).toBe('AUTH_SIGNATURE');
    expect(code(() => s.admit(unlisted('svc-gone', gone.privateKey, 3)))).toBe('AUTH_REVOKED');
  });

  it('keys the replay set on the nonce bytes, so a re-spelled header is the same nonce', () => {
    const generated = record('svc-1', ['complete']);
    const s = store([generated.record]);
    const nonce = new Uint8Array(16);
    const canonical = toBase64Url(nonce);
    // The last character of an unpadded base64url nonce carries spare bits no byte depends on, so
    // this twin decodes to the same 16 bytes and signs to the same signature. Only a set keyed on
    // the decoded bytes can see the two presentations as one request.
    const respelled = `${canonical.slice(0, -1)}B`;
    expect(fromBase64Url(respelled)).toEqual(nonce);
    expect(respelled).not.toBe(canonical);
    const first = signed({ id: 'svc-1', privateKey: generated.privateKey, nonce });
    expect(code(() => s.admit(first))).toBe('no-error');
    expect(code(() => s.admit({ ...first, headers: { ...first.headers, 'x-ashaveri-nonce': respelled } }))).toBe('NONCE_SEEN');
  });
});

/** A `pop` record carrying the field only a bearer record has a use for. */
function strayKeyed(pop: CredentialRecord): CredentialRecord {
  return { ...pop, secretHash: new Uint8Array(32) };
}

/** A `pop` record whose key is a byte short of the width the verifier needs. */
function narrowKeyed(pop: CredentialRecord): CredentialRecord {
  return { ...pop, publicKey: new Uint8Array(31) };
}

/** The `AccessError` a call refuses with, so its code, its status and its sentence can each be read. */
function thrownBy(run: () => unknown): AccessError {
  let caught: unknown;
  try {
    run();
  } catch (err) {
    caught = err;
  }
  expect(caught, 'the call was expected to refuse').toBeInstanceOf(AccessError);
  return caught as AccessError;
}

/**
 * What the store does with a record whose shape is wrong, which is where the collapse's last
 * name-dependent 500 used to live. A record that offers no key its kind can be verified against was
 * answered `BAD_CREDENTIAL_RECORD` at the moment a request named it: 500 for one id and 401 for
 * another, which is a probe of the credential file wearing a server-fault face. Both routes into the
 * store now settle that before a request arrives, and they settle it the way the parser already did -
 * one field dropped because the parser never reads it, one record refused because the parser refuses
 * it - so this is two paths agreeing rather than a rule neither of them had.
 */
describe('the shape of a record, checked where records enter', () => {
  it('serves a proof-of-possession record that arrived carrying a secret hash', () => {
    const generated = record('svc-1', ['read', 'complete']);
    const handed = strayKeyed(generated.record);
    const s = store([handed]);
    // `parseRecord` reaches for `secretHash` on one branch, and a `pop` record does not take it, so
    // these same bytes in a file on disk become the record with no such field on it. The in-memory
    // constructor is the route that never passes the parser, and clearing the field there is the
    // agreement, not a repair: the record it holds is the one the other route would have produced.
    const asParsed = parseCredentialFile(serializeCredentialFile({ version: 1, credentials: [handed] }));
    expect(s.credentials()).toEqual(asParsed.credentials);
    expect(s.credentials()[0]?.secretHash).toBeUndefined();
    // Which is what took this state off the request path: the record has a key, so the request that
    // proves it is served and the refusal that used to answer 500 for it is not on the way to anyone.
    expect(code(() => s.admit(signed({ id: 'svc-1', privateKey: generated.privateKey })))).toBe('no-error');
    // The store's record is a copy. `--mock` and every harness here keep reading the records they
    // handed in, and a store that edited them would leave a caller holding something its own file
    // never said.
    expect(handed.secretHash).toBeInstanceOf(Uint8Array);
  });

  it('refuses to take a proof-of-possession record with no key of the width its kind needs', () => {
    const generated = record('svc-narrow', ['read', 'complete']);
    const refusal = thrownBy(() => store([narrowKeyed(generated.record)]));
    expect(refusal.code).toBe('BAD_CREDENTIAL_RECORD');
    expect(refusal.status).toBe(500);
    // Named, because a refusal that never reaches a caller is worth having exactly when the one who
    // can fix the file reads which record to fix. `access-file.test.ts` pins the parser refusing the
    // same bytes on disk, and that is where this rule came from.
    expect(refusal.message).toContain("'svc-narrow'");
    expect(refusal.message).toMatch(/31-byte publicKey/u);
    expect(refusal.message).toMatch(/not the 32 bytes/u);
    // Width is the whole check: a 32-byte key the library will not accept is a record the store holds
    // and the verifier refuses, which is `access-order.test.ts`'s `small-order-key`.
    expect(() => store([{ ...generated.record, publicKey: new Uint8Array(32) }])).not.toThrow();
  });
});

describe('a store that reads its credential file from disk', () => {
  const dirOf = async (): Promise<{
    dir: string;
    path: string;
    write: (text: string) => Promise<void>;
    file: (records: CredentialRecord[]) => string;
  }> => {
    const dir = await mkdtemp(join(tmpdir(), 'ashaveri-admission-'));
    const path = join(dir, 'credentials.json');
    let tick = 1_772_000_000_000;
    const write = async (text: string): Promise<void> => {
      // An explicit mtime, so what the reload reacts to is the file moving and not this test
      // happening to write it in a later clock tick than the one before.
      tick += 60_000;
      const when = new Date(tick);
      await writeFile(path, text, 'utf8');
      await utimes(path, when, when);
    };
    const file = (records: CredentialRecord[]): string => serializeCredentialFile({ version: 1, credentials: records });
    return { dir, path, write, file };
  };

  it('admits nobody until it has read, and re-reads when the file moves', async () => {
    const { dir, path, write, file } = await dirOf();
    // The coherent pair, not `complete` alone: this cell is about the reload, and a record that
    // completes without reading is refused at load, so an incoherent list here would test the pairing
    // rule from a cell that means to test something else.
    const generated = newPopCredential({ id: 'svc-1', scopes: ['read', 'complete'], now: NOW });
    try {
      await write(file([generated.record]));
      const s = new CredentialStore({ path });
      expect(s.credentials()).toEqual([]);
      expect(code(() => s.admit(signed({ id: 'svc-1', privateKey: generated.privateKey })))).toBe('AUTH_SIGNATURE');

      await s.reloadIfNeeded();
      expect(s.credentials().map((entry) => entry.id)).toEqual(['svc-1']);
      const fresh = (at: number): AdmissionInput =>
        signed({ id: 'svc-1', privateKey: generated.privateKey, nonce: new Uint8Array(16).fill(at) });
      expect(code(() => s.admit(fresh(7)))).toBe('no-error');

      // The operator's revocation takes effect on the next read, not on the next restart.
      await write(file([{ ...generated.record, revokedAt: NOW }]));
      await s.reloadIfNeeded();
      expect(code(() => s.admit(fresh(8)))).toBe('AUTH_REVOKED');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('keeps the records it has while the file on disk does not parse, and recovers after', async () => {
    const { dir, path, write, file } = await dirOf();
    // The coherent pair, not `complete` alone: this cell is about the reload, and a record that
    // completes without reading is refused at load, so an incoherent list here would test the pairing
    // rule from a cell that means to test something else.
    const generated = newPopCredential({ id: 'svc-1', scopes: ['read', 'complete'], now: NOW });
    try {
      await write(file([generated.record]));
      const s = new CredentialStore({ path });
      await s.reloadIfNeeded();
      await write('{oops');
      await expect(s.reloadIfNeeded()).rejects.toMatchObject({ code: 'BAD_CREDENTIAL_FILE', status: 500 });
      expect(s.credentials().map((entry) => entry.id)).toEqual(['svc-1']);
      expect(code(() => s.admit(signed({ id: 'svc-1', privateKey: generated.privateKey })))).toBe('no-error');

      // The failed read recorded no mtime, so a file the operator has finished writing is picked up
      // by the next reload rather than needing the process restarted.
      await write(file([generated.record]));
      await s.reloadIfNeeded();
      expect(
        code(() => s.admit(signed({ id: 'svc-1', privateKey: generated.privateKey, nonce: new Uint8Array(16).fill(3) }))),
      ).toBe('no-error');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('keeps the records it has while a replacement file names a key nobody can verify', async () => {
    const { dir, path, write, file } = await dirOf();
    const good = newPopCredential({ id: 'svc-1', scopes: ['read', 'complete'], now: NOW });
    const typo = newPopCredential({ id: 'svc-typo', scopes: ['read', 'complete'], now: NOW });
    try {
      await write(file([good.record]));
      const s = new CredentialStore({ path });
      await s.reloadIfNeeded();
      expect(s.credentials()).toHaveLength(1);

      // The second record's key has had a byte off the end of it, which is the edit this test is
      // about: the store refuses the record, on this route through the parser rather than through
      // ingest, because a file is read only after it has been checked.
      await write(file([good.record, { ...typo.record, publicKey: new Uint8Array(31) }]));
      const failure = await s.reloadIfNeeded().then(() => undefined, (err: unknown) => err);
      expect(failure).toBeInstanceOf(AccessError);
      expect((failure as AccessError).code).toBe('BAD_CREDENTIAL_RECORD');
      expect((failure as AccessError).status).toBe(500);
      // Both halves of the policy in one read: the failure is reported, with the file it came from
      // named, and it is the operator's typo rather than an outage. The records that had loaded are
      // still the records served, so the reload that could not land did not take the ones that had.
      const message = (failure as AccessError).message;
      expect(message).toContain(path);
      expect(message).toMatch(/publicKey is 31 bytes, not 32/u);
      expect(s.credentials().map((each) => each.id)).toEqual(['svc-1']);
      expect(code(() => s.admit(signed({ id: 'svc-1', privateKey: good.privateKey, nonce: new Uint8Array(16).fill(5) })))).toBe('no-error');

      // Fixed, and the next reload lands. No mtime was recorded for a file that refused, so a
      // finished edit is picked up without a restart.
      await write(file([good.record, typo.record]));
      await s.reloadIfNeeded();
      expect(s.credentials().map((each) => each.id)).toEqual(['svc-1', 'svc-typo']);
      expect(code(() => s.admit(signed({ id: 'svc-typo', privateKey: typo.privateKey, nonce: new Uint8Array(16).fill(6) })))).toBe('no-error');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('takes either a path or an in-memory file, never both and never neither', () => {
    expect(code(() => new CredentialStore({}))).toBe('BAD_CREDENTIAL_FILE');
    expect(code(() => new CredentialStore({ path: '/nonexistent/credentials.json', file: { version: 1, credentials: [] } }))).toBe('BAD_CREDENTIAL_FILE');
  });
});
