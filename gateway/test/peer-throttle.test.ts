import { describe, expect, it } from 'vitest';
import {
  EMPTY_BODY_SHA256_HEX,
  POP_NONCE_BYTES,
  POP_TIMESTAMP_TOLERANCE_SECONDS,
  signPopAuthorization,
  signingKeyFromSeed,
  toBase64Url,
  type PopFields,
} from '@ashaveri/receipt';
import {
  AccessError,
  CredentialStore,
  DEFAULT_PEER_RATE,
  TokenBucket,
  newBearerCredential,
  newPopCredential,
  type AdmissionInput,
  type CredentialRate,
  type CredentialRecord,
} from '../src/access.js';
import { ACCESS_RECORD_FIELDS } from '../src/aclog.js';
import { harness } from './helpers.js';

/**
 * The request bound a connection is held to before this gateway spends any crypto on it.
 *
 * It exists because of what the collapse bought: a name the credential file does not carry is now
 * answered by performing one Ed25519 verification against a key that is in no file, so an
 * unauthenticated guess costs a verification where it used to cost a map lookup. The per-credential
 * bucket cannot bound that, because a guess holds no credential to charge, so the charge goes on the
 * address of the connection and is taken ahead of the header being read at all.
 *
 * Two halves of that are pinned here: that a guessing loop stops being answered by the crypto, counted
 * rather than timed, and that the refusal it gets says the same words in a store that holds the name it
 * typed and one that does not.
 */

const NOW_SECONDS = 1_772_000_000;
/** One frozen millisecond clock, so no request in a burst can refill the bucket the burst is counted against. */
const CLOCK_MS = NOW_SECONDS * 1000;

const WORK_ROUTE = { method: 'GET', url: '/v1/deployment-manifest' } as const;

const HELD_SEED = new Uint8Array(32).fill(0x31);
/** A key no record in any store here carries the public half of: every signature made with it fails. */
const FOREIGN_SECRET = new Uint8Array(32).fill(0x32);
const HELD_NAME = 'edge-svc';
/** The name no file carries, which is the one a prober types. */
const GUESSED_NAME = 'probe-svc';
/** The address the storm comes from, and the one a paying customer does. */
const STORM = '203.0.113.7';
const CUSTOMER = '198.51.100.4';

function heldRecord(rate: CredentialRate): CredentialRecord {
  const generated = newPopCredential({ id: HELD_NAME, scopes: ['read', 'complete'], now: NOW_SECONDS });
  return { ...generated.record, publicKey: signingKeyFromSeed(HELD_SEED).publicKey, rate };
}

/** A nonce per presentation, so no cell's answer is ever the replay set's. */
function nonceAt(at: number): Uint8Array {
  const nonce = new Uint8Array(POP_NONCE_BYTES).fill(0x77, 0, POP_NONCE_BYTES - 4);
  nonce[POP_NONCE_BYTES - 4] = (at >>> 24) & 0xff;
  nonce[POP_NONCE_BYTES - 3] = (at >>> 16) & 0xff;
  nonce[POP_NONCE_BYTES - 2] = (at >>> 8) & 0xff;
  nonce[POP_NONCE_BYTES - 1] = at & 0xff;
  return nonce;
}

interface AskOptions {
  /** The key these bytes are signed with: the foreign one is a guess, the held one is a real client. */
  readonly key?: Uint8Array;
  readonly peer?: string;
  readonly stamp?: 'fresh' | 'stale';
  readonly withNonceHeader?: boolean;
}

/**
 * A proof-of-possession request built the way a client builds one, differing from an admission only in
 * the key that signed it. `stamp` and `withNonceHeader` let one builder stand for the header-shaped
 * refusals too, because the ordering claims below are about a shed peer never reaching them.
 */
function guess(name: string, at: number, options: AskOptions = {}): AdmissionInput {
  const nonce = nonceAt(at);
  const ts = options.stamp === 'stale' ? NOW_SECONDS - POP_TIMESTAMP_TOLERANCE_SECONDS - 1 : NOW_SECONDS;
  const fields: PopFields = {
    ts,
    nonce,
    method: WORK_ROUTE.method,
    target: WORK_ROUTE.url,
    bodyDigestHex: EMPTY_BODY_SHA256_HEX,
  };
  const headers: Record<string, string> = { authorization: signPopAuthorization(fields, name, options.key ?? FOREIGN_SECRET) };
  if (options.withNonceHeader !== false) headers['x-ashaveri-nonce'] = toBase64Url(nonce);
  return {
    method: WORK_ROUTE.method,
    url: WORK_ROUTE.url,
    headers,
    body: null,
    nowSeconds: NOW_SECONDS,
    peerAddress: options.peer ?? STORM,
  };
}

function bearerInput(secret: Uint8Array, peer: string): AdmissionInput {
  return {
    method: WORK_ROUTE.method,
    url: WORK_ROUTE.url,
    headers: { authorization: `Bearer ${Buffer.from(secret).toString('base64url')}` },
    body: null,
    nowSeconds: NOW_SECONDS,
    peerAddress: peer,
  };
}

/** A request with no `Authorization` header at all, which is the cheapest refusal there is. */
function headerless(peer: string): AdmissionInput {
  return { method: WORK_ROUTE.method, url: WORK_ROUTE.url, headers: {}, body: null, nowSeconds: NOW_SECONDS, peerAddress: peer };
}

interface Answer {
  readonly code: string;
  /** What the access log would record for this refusal, which differs from `code` only where a refusal is collapsed. */
  readonly logCode: string;
  readonly status: number;
  readonly message: string;
  readonly retryAfterSeconds: number | undefined;
  readonly credentialId: string | null;
}

function answer(store: CredentialStore, input: AdmissionInput): Answer {
  try {
    const granted = store.admit(input);
    return {
      code: 'no-error',
      logCode: 'no-error',
      status: 0,
      message: `served as ${granted.credentialId}`,
      retryAfterSeconds: undefined,
      credentialId: granted.credentialId,
    };
  } catch (err) {
    if (!(err instanceof AccessError)) throw err;
    return {
      code: err.code,
      logCode: err.logCode,
      status: err.status,
      message: err.message,
      retryAfterSeconds: err.retryAfterSeconds,
      credentialId: err.credentialId ?? null,
    };
  }
}

/** Everything a caller can observe about one answer, and nothing the access log keeps. */
function observable(a: Answer): string {
  return `${a.code} ${a.status} "${a.message}"`;
}

function fills(count: number, value: string): string[] {
  return new Array<string>(count).fill(value);
}

/** A store with its peer bound set, its clock frozen, and a counter on every verification it performs. */
function watchedStore(
  credentials: CredentialRecord[],
  peerRate: CredentialRate,
  options: { allowBearer?: boolean } = {},
): { store: CredentialStore; verifications(): number } {
  let verifications = 0;
  const store = new CredentialStore({
    file: { version: 1, credentials },
    allowBearer: options.allowBearer ?? false,
    peerRate,
    now: () => CLOCK_MS,
    countVerification: () => {
      verifications += 1;
    },
  });
  return { store, verifications: () => verifications };
}

describe('the request bound a connection meets ahead of the crypto', () => {
  it('refuses a burst of well-formed guesses and spends no verification on the ones it sheds', () => {
    const burst = 5;
    const guesses = 40;
    const { store, verifications } = watchedStore([heldRecord({ perMinute: 60, burst: 60 })], { perMinute: 60, burst });

    const codes: string[] = [];
    const sheds: Answer[] = [];
    for (let at = 0; at < guesses; at++) {
      // Well-formed in every way a guess can be: a fresh stamp, a real 16-byte nonce header, a
      // 64-byte signature of the right width. Only the bytes themselves are somebody else's.
      const reply = answer(store, guess(GUESSED_NAME, at));
      codes.push(reply.code);
      if (reply.code === 'RATE_LIMITED') sheds.push(reply);
    }

    // Ahead of the bound: the collapse's answer, one verification each. Behind it: the throttle, and the
    // counter says the verifier was not asked again. Timing could show none of this, which is why the
    // seam counts calls; and `burst` rather than `burst + 1`, because the token the request that opens a
    // fresh bucket spends is charged to it.
    expect(codes.slice(0, burst)).toEqual(fills(burst, 'AUTH_SIGNATURE'));
    expect(codes.slice(burst)).toEqual(fills(guesses - burst, 'RATE_LIMITED'));
    expect(verifications()).toBe(burst);

    for (const shed of sheds) {
      expect(shed.status, 'a throttle is a 429 on every one of its refusals').toBe(429);
      expect(shed.retryAfterSeconds).toBeGreaterThanOrEqual(1);
      expect(Number.isInteger(shed.retryAfterSeconds)).toBe(true);
    }
    expect(sheds).toHaveLength(guesses - burst);
    process.stdout.write(
      `peer-throttle: ${String(guesses)} well-formed guesses from one address, ${String(verifications())} reached ` +
        `the verifier and ${String(guesses - burst)} were refused ahead of it\n`,
    );
  });

  it('sheds a peer before it reads the header, the stamp or the nonce', () => {
    // One token per peer, so the first request from an address is answered on its own merits and every
    // later one is the throttle's. Each shape gets its own address, which is also what makes the two
    // halves of this case independent of each other.
    const { store, verifications } = watchedStore([heldRecord({ perMinute: 60, burst: 60 })], { perMinute: 60, burst: 1 });
    const enrolled = newBearerCredential({ id: 'ops-1', scopes: ['read', 'complete'], now: NOW_SECONDS });

    const shapes: AdmissionInput[] = [
      headerless('192.0.2.1'),
      {
        method: WORK_ROUTE.method,
        url: WORK_ROUTE.url,
        headers: { authorization: 'Ashaveri-PoP' },
        body: null,
        nowSeconds: NOW_SECONDS,
        peerAddress: '192.0.2.2',
      },
      { ...guess(GUESSED_NAME, 3, { stamp: 'stale' }), peerAddress: '192.0.2.3' },
      { ...guess(GUESSED_NAME, 4, { withNonceHeader: false }), peerAddress: '192.0.2.4' },
      bearerInput(enrolled.secret, '192.0.2.5'),
      { ...guess(GUESSED_NAME, 6), peerAddress: '192.0.2.6' },
      { ...guess(HELD_NAME, 7, { key: HELD_SEED }), peerAddress: '192.0.2.7' },
    ];

    const first = shapes.map((input) => answer(store, input).code);
    const then = shapes.map((input) => answer(store, input).code);
    expect(verifications()).toBe(2);

    // Unthrottled, each of these is refused for something it wrote itself - or, for the last two,
    // answered. Throttled, they are one answer, and the counter says none of them was verified.
    expect(first).toEqual([
      'AUTH_MALFORMED',
      'AUTH_MALFORMED',
      'AUTH_STALE',
      'AUTH_NONCE_MISSING',
      'AUTH_SCHEME',
      'AUTH_SIGNATURE',
      'no-error',
    ]);
    expect(then).toEqual(fills(shapes.length, 'RATE_LIMITED'));
  });

  it('tells a throttled peer the same words whether or not the file holds the name it wrote', () => {
    const rate: CredentialRate = { perMinute: 60, burst: 3 };
    const holds = watchedStore([heldRecord({ perMinute: 60, burst: 60 })], rate);
    const lacks = watchedStore([], rate);
    const enrolled = newBearerCredential({ id: 'ops-1', scopes: ['read', 'complete'], now: NOW_SECONDS });

    // Every shape here proves nothing, which is what makes it fair to demand the same answer from both
    // stores: the request that carries a valid proof of possession is legitimately answered out of the
    // file, and that exception belongs to the collapse rather than to this bucket.
    const shapes: AdmissionInput[] = [
      guess(GUESSED_NAME, 11),
      guess(HELD_NAME, 12),
      { ...guess(GUESSED_NAME, 13), peerAddress: STORM },
      bearerInput(enrolled.secret, STORM),
      headerless(STORM),
    ];

    let shed = 0;
    shapes.forEach((shape, index) => {
      const holdsAnswer = observable(answer(holds.store, shape));
      const lacksAnswer = observable(answer(lacks.store, shape));
      expect(lacksAnswer, `shape ${String(index)} answers differently in the two stores`).toBe(holdsAnswer);
      if (holdsAnswer.startsWith('RATE_LIMITED')) shed += 1;
    });
    expect(shed, 'the pair never reached the throttle, so it proved nothing about it').toBeGreaterThan(0);

    // Unlike the collapsed refusal, the throttle needs no split between the code logged and the code
    // returned: nothing about it depends on a name, and it names none.
    const last = answer(holds.store, guess(GUESSED_NAME, 99));
    expect(last.code).toBe('RATE_LIMITED');
    expect(last.logCode).toBe('RATE_LIMITED');
    expect(last.credentialId, 'a shed request names no credential, so the line cannot carry one').toBeNull();
    expect(observable(last)).not.toContain(GUESSED_NAME);
    expect(observable(last)).not.toContain(HELD_NAME);
    expect(observable(last)).not.toContain(STORM);
  });

  it('takes nothing from a credential the guesses named', () => {
    const credentialBurst = 4;
    const { store, verifications } = watchedStore([heldRecord({ perMinute: 60, burst: credentialBurst })], {
      perMinute: 60,
      burst: 10,
    });

    // Forty guesses about a name this store does hold, from one address, until it is refused.
    for (let at = 0; at < 40; at++) answer(store, guess(HELD_NAME, at));
    expect(verifications()).toBe(10);

    // A real client on another address then finds the credential's whole budget intact: the guesses
    // spent none of it, because none of them reached the check that spends it.
    const codes: string[] = [];
    for (let at = 0; at < credentialBurst + 2; at++) {
      codes.push(answer(store, guess(HELD_NAME, 100 + at, { key: HELD_SEED, peer: CUSTOMER })).code);
    }
    expect(codes).toEqual([...fills(credentialBurst, 'no-error'), 'RATE_LIMITED', 'RATE_LIMITED']);
    const credentialThrottle = answer(store, guess(HELD_NAME, 200, { key: HELD_SEED, peer: CUSTOMER }));
    expect(credentialThrottle.message).not.toContain('per connection address');
  });

  it('bounds one connection and not another', () => {
    const { store } = watchedStore([heldRecord({ perMinute: 60, burst: 60 })], { perMinute: 60, burst: 3 });
    for (let at = 0; at < 3; at++) expect(answer(store, guess(GUESSED_NAME, at)).code).toBe('AUTH_SIGNATURE');
    for (let at = 3; at < 6; at++) expect(answer(store, guess(GUESSED_NAME, at)).code).toBe('RATE_LIMITED');
    // A second address is a second bucket, which is the whole reason the key is the socket's own peer
    // rather than anything a caller writes.
    expect(answer(store, guess(GUESSED_NAME, 21, { peer: CUSTOMER })).code).toBe('AUTH_SIGNATURE');
  });

  it('charges no peer for a request no transport placed', () => {
    const { store } = watchedStore([heldRecord({ perMinute: 60, burst: 60 })], { perMinute: 1, burst: 1 });
    const codes = new Set<string>();
    for (let at = 0; at < 30; at++) codes.add(answer(store, { ...guess(GUESSED_NAME, at), peerAddress: undefined }).code);
    // `undefined` is a store handed requests directly - a test, or `--mock` - and there is no address to
    // charge. That the gateway's own transport never sends one is the next case's subject.
    expect([...codes]).toEqual(['AUTH_SIGNATURE']);
  });

  it('is filled by the gateway from the socket, and by no header', async () => {
    const h = await harness({
      extra: [heldRecord({ perMinute: 60, burst: 60 })],
      // A route-level harness is one socket address, so every injected request here shares one bucket.
      peerRate: { perMinute: 60, burst: 3 },
    });
    const codes: Array<string | undefined> = [];
    const statuses: number[] = [];
    for (let at = 0; at < 8; at++) {
      const response = await h.app.inject({
        method: 'GET',
        url: WORK_ROUTE.url,
        headers: {
          // A different claimed origin on every request. If any header supplied the key, no request here
          // would ever be refused for the address it came from.
          'x-forwarded-for': `203.0.113.${String(100 + at)}`,
          forwarded: `for=198.51.100.${String(100 + at)}`,
          'client-ip': `192.0.2.${String(100 + at)}`,
          ...h.signFor(GUESSED_NAME, 'GET', WORK_ROUTE.url, null, { key: FOREIGN_SECRET }),
        },
      });
      statuses.push(response.statusCode);
      codes.push((JSON.parse(response.payload) as { error?: { code?: string } }).error?.code);
    }
    expect(codes.slice(0, 3)).toEqual(fills(3, 'AUTH_SIGNATURE'));
    expect(codes.slice(3)).toEqual(fills(5, 'RATE_LIMITED'));
    expect(statuses.slice(3)).toEqual(new Array<number>(5).fill(429));

    // A request with no header at all meets the same bound, which is what "every request meets it" has
    // to mean, and is answered with the hint this code already carries.
    const refused = await h.app.inject({ method: 'GET', url: WORK_ROUTE.url });
    expect(refused.statusCode).toBe(429);
    expect(Number(refused.headers['retry-after'])).toBeGreaterThanOrEqual(1);

    const entries = h.log.entries();
    expect(entries).toHaveLength(9);
    expect(entries.at(-1)).toMatchObject({ deny: 'RATE_LIMITED', cred: null, st: 429 });
    // The bound is not a recorded field and cannot become one: the allowlist is closed, so nothing in
    // this process says which peers were shed.
    expect(Object.keys(entries.at(-1) ?? {}).sort()).toEqual([...ACCESS_RECORD_FIELDS].sort());
    expect(JSON.stringify(entries)).not.toContain('203.0.113.');
    expect(JSON.stringify(entries)).not.toContain('198.51.100.');
    expect(JSON.stringify(entries)).not.toContain('127.0.0.1');
    await h.app.close();
  });
});

describe('the bound itself', () => {
  it('is a number a guessing loop reaches and a client does not', () => {
    // Pinned, because the size is the design decision: loose enough that no honest client meets it,
    // tight enough that a loop does long before it has spent a second of crypto. At the ~183 microseconds
    // one forged verification measures on this workspace's library, the burst is ~55ms of the process and
    // the refill fifteen verifications a second, against the ~5,500 a second an unbounded loop asks for.
    expect(DEFAULT_PEER_RATE).toEqual({ perMinute: 900, burst: 300 });
  });

  it('caps how many addresses it remembers, and gives an evicted peer a fresh bucket', () => {
    // The keys are whoever connects, which nothing else bounds, so an uncapped map would trade a control
    // on what a request costs for a door onto memory.
    const bucket = new TokenBucket(2);
    const rate = { perMinute: 60, burst: 2 };
    expect(bucket.take('a', rate, CLOCK_MS).allowed).toBe(true);
    expect(bucket.take('b', rate, CLOCK_MS).allowed).toBe(true);
    // Presenting `a` again moves it to the back, so the next arrival gives up on `b`, the quietest key.
    expect(bucket.take('a', rate, CLOCK_MS).allowed).toBe(true);
    expect(bucket.take('a', rate, CLOCK_MS).allowed).toBe(false);
    expect(bucket.take('c', rate, CLOCK_MS).allowed).toBe(true);
    expect(bucket.take('a', rate, CLOCK_MS).allowed).toBe(false);
    // `b` was evicted rather than refused, and comes back holding a whole bucket: the cap bounds memory,
    // not the number of peers willing to be polite.
    expect(bucket.take('b', rate, CLOCK_MS).allowed).toBe(true);
  });

  it('says which of the two buckets fired, because the two answers are different fixes', () => {
    // A credential with five tokens in hand and a connection allowed one request: the same code and
    // status then arrives from two different places, and a caller that cannot tell them apart rotates a
    // credential that was never the problem.
    const { store, verifications } = watchedStore([heldRecord({ perMinute: 60, burst: 5 })], {
      perMinute: 60,
      burst: 1,
    });
    const admitted = answer(store, guess(HELD_NAME, 1, { key: HELD_SEED, peer: CUSTOMER }));
    const peerThrottle = answer(store, guess(HELD_NAME, 2, { key: HELD_SEED, peer: CUSTOMER }));
    expect([admitted.code, peerThrottle.code]).toEqual(['no-error', 'RATE_LIMITED']);
    expect(peerThrottle.status).toBe(429);
    expect(peerThrottle.retryAfterSeconds).toBeGreaterThanOrEqual(1);
    expect(peerThrottle.message).toContain('per connection address');
    expect(verifications()).toBe(1);

    // Four more addresses spend the credential's remaining tokens, and the next one meets the other
    // bucket: after the signature, as it always was, and in the credential's own words.
    for (let at = 0; at < 4; at++) {
      expect(answer(store, guess(HELD_NAME, 10 + at, { key: HELD_SEED, peer: `192.0.2.${String(at)}` })).code).toBe(
        'no-error',
      );
    }
    const credentialThrottle = answer(store, guess(HELD_NAME, 20, { key: HELD_SEED, peer: '192.0.2.9' }));
    expect(credentialThrottle.code).toBe('RATE_LIMITED');
    expect(credentialThrottle.status).toBe(429);
    expect(credentialThrottle.message).not.toContain('per connection address');
    expect(credentialThrottle.message).toContain(HELD_NAME);
    // One verification for each of the six requests that reached the signature check, and none for the
    // two the peer bound refused.
    expect(verifications()).toBe(6);
  });
});
