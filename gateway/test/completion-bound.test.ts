import { describe, expect, it } from 'vitest';
import type { CompletionBackend } from '../src/backend.js';
import { mockBackend } from '../src/backend.js';
import { DEFAULT_COMPLETION_RATE, type DeploymentCompletionBound, type ReceiptIntakeGuard } from '../src/server.js';
import { DEFAULT_PEER_RATE } from '../src/access.js';
import { openMemoryReceiptStore, type ReceiptRetention, type ReceiptStore } from '../src/store.js';
import { fixedClock, generated, harness, type Harness } from './helpers.js';

/**
 * The deployment-wide bound on the completions one process admits. `gateway/src/access.ts` holds what one
 * connection address may ask for and what one credential may spend, and both are bounds on what a caller
 * does; this is a bound on what this process can write, so it is read at admission, on the one route that
 * issues a receipt, and it answers the same way whoever sent the request. These cases are the shape the
 * durability guard is already proved in: a counted upstream, a status, a sentence, and a log line.
 */

const REQUEST_BODY = '{"model":"mock-model-1","messages":[{"role":"user","content":"hello"}]}';
/** One instant for every stamp a fixture writes, so a retained set spans no seconds. */
const STAMP = 1_780_000_000;
/** A period long enough that nothing ages out of it, so only a count ever decides the guard. */
const TEN_YEARS_SECONDS = 10 * 365 * 24 * 60 * 60;

/** The credential every completion here signs with, held to a rate no case in this file reaches. */
function credential(): ReturnType<typeof generated> {
  return generated('bound', ['complete', 'read'], { rate: { perMinute: 100_000, burst: 100_000 } });
}

/** The upstream is the thing this bound is placed ahead of, so its calls are counted, not assumed. */
function countingBackend(): { backend: CompletionBackend; calls(): number } {
  const inner = mockBackend();
  let calls = 0;
  return {
    calls: () => calls,
    backend: {
      async respond(raw, request) {
        calls += 1;
        return inner.respond(raw, request);
      },
    },
  };
}

interface Serving {
  readonly h: Harness;
  readonly upstream: { calls(): number };
  readonly store: ReceiptStore;
  /** One completion, with the four things a caller can observe about it. */
  complete(text: string): Promise<{
    statusCode: number;
    receiptId: string | null;
    retryAfter: string | undefined;
    error: Record<string, unknown>;
  }>;
  /** Any request, signed the same way, for the routes that keep serving. */
  ask(method: string, target: string, body: string | null): Promise<{ statusCode: number; headers: Record<string, string | undefined> }>;
}

async function serving(
  bound: DeploymentCompletionBound,
  options: { store?: ReceiptStore; guard?: ReceiptIntakeGuard } = {},
): Promise<Serving> {
  const upstream = countingBackend();
  const store = options.store ?? openMemoryReceiptStore();
  const h = await harness({
    credentials: [credential()],
    gateway: {
      // The gateway's clock is pinned so a retained set's span is a fact of this fixture; the bound's own
      // clock comes from `completionBound.nowMillis` below and is pinned separately, because a case about
      // a refill cannot wait for real seconds to pass.
      time: fixedClock(() => STAMP),
      backend: upstream.backend,
      store,
      completionBound: bound,
      ...(options.guard === undefined ? {} : { receiptIntakeGuard: options.guard }),
    },
  });
  async function ask(method: string, target: string, body: string | null) {
    const response = await h.app.inject({
      method: method as 'GET',
      url: target,
      headers: {
        ...(body === null ? {} : { 'content-type': 'application/json' }),
        ...h.signFor('bound', method, target, body),
      },
      ...(body === null ? {} : { payload: body }),
    });
    return {
      statusCode: response.statusCode,
      headers: response.headers as Record<string, string | undefined>,
      payload: response.payload,
    };
  }
  return {
    h,
    upstream,
    store,
    ask,
    async complete(text: string) {
      const response = await ask('POST', '/v1/chat/completions', REQUEST_BODY.replace('hello', text));
      return {
        statusCode: response.statusCode,
        receiptId: response.headers['x-ashaveri-receipt-id'] ?? null,
        retryAfter: response.headers['retry-after'],
        error:
          response.statusCode === 200
            ? {}
            : ((response.payload.length === 0 ? {} : JSON.parse(response.payload)) as { error?: Record<string, unknown> })
                .error ?? {},
      };
    },
  };
}

/** A bound of `n` taken at once, refilling at one a minute, which is the pair every case here drives. */
function boundAt(burst: number, perMinute = 60, atMillis: () => number = () => 0): DeploymentCompletionBound {
  return { rate: { perMinute, burst }, nowMillis: atMillis };
}

describe('the bound a deployment that configures nothing runs at', () => {
  it('is this build\'s write ceiling, derived from its two measured costs and stated as a rate', () => {
    // The figure is not chosen for a banner. One receipt costs 447.6 microseconds to sign and 3.951
    // milliseconds to append at 20,000 retained, which is 4.40 milliseconds together, and that sum divided
    // into 60,000 and 1,000 is both halves of the pair, so a change to either cost moves both numbers or
    // this case fails rather than let a shipped default drift from the costs it was computed from.
    const derivedMillisPerReceipt = 4.4;
    expect(DEFAULT_COMPLETION_RATE).toEqual({
      perMinute: Math.floor(60_000 / derivedMillisPerReceipt),
      burst: Math.floor(1_000 / derivedMillisPerReceipt),
    });
    expect(DEFAULT_COMPLETION_RATE.perMinute).toBe(13_636);
    expect(DEFAULT_COMPLETION_RATE.burst).toBe(227);
  });

  it('is stated in the unit the per-address bound is stated in, and says how many addresses it holds', () => {
    // Comparability is the reason the shape is `{ perMinute, burst }` rather than a count in seconds: an
    // operator reads one number against the other and sees the deployment's own traffic in both.
    expect(DEFAULT_COMPLETION_RATE.perMinute / DEFAULT_PEER_RATE.perMinute).toBeCloseTo(2.273, 3);
    // A refill is steady, so a minute of the shipped burst is a minute of the same rate.
    expect(DEFAULT_COMPLETION_RATE.perMinute / 60).toBeCloseTo(DEFAULT_COMPLETION_RATE.burst, 0);
  });

  it('is a bound and not an unlimited sentinel', () => {
    // A deployment that wired nothing would otherwise be the one that refused nothing, which is the state
    // this exists to close. The shipped number is a count a request can be refused against, and the case
    // below drives it through a real gateway to show that it does refuse.
    expect(DEFAULT_COMPLETION_RATE.perMinute).toBeGreaterThan(0);
    expect(DEFAULT_COMPLETION_RATE.burst).toBeGreaterThan(0);
    expect(DEFAULT_COMPLETION_RATE.perMinute).toBeLessThan(Number.MAX_SAFE_INTEGER);
  });
});

describe('a gateway running a completion bound', () => {
  it('refuses the completion past the bound with DEPLOYMENT_RATE_LIMITED and a 429', async () => {
    const s = await serving(boundAt(2));
    try {
      expect((await s.complete('first')).statusCode).toBe(200);
      expect((await s.complete('second')).statusCode).toBe(200);
      const refused = await s.complete('third');
      expect(refused.statusCode).toBe(429);
      expect(refused.error.code).toBe('DEPLOYMENT_RATE_LIMITED');
    } finally {
      await s.h.app.close();
    }
  });

  it('names the quantity and the configured value in the sentence a caller is handed', async () => {
    const s = await serving(boundAt(2));
    try {
      await s.complete('first');
      await s.complete('second');
      const message = String((await s.complete('third')).error.message);
      expect(message).toContain('this deployment admits no completion past the rate it sets for itself');
      expect(message).toContain('admits 60 completions a minute across the whole deployment');
      expect(message).toContain('2 of them at once');
      expect(message).toContain('refused before any inference is run');
      expect(message).toContain('--completion-rate');
    } finally {
      await s.h.app.close();
    }
  });

  it('never reaches the upstream for a refused completion, and reaches it once for a served one', async () => {
    // Evidence from the code path rather than from the status: the bound is read in the pre-handler, so a
    // refusal that spent an inference would show here as a call.
    const s = await serving(boundAt(2));
    try {
      await s.complete('first');
      await s.complete('second');
      expect(s.upstream.calls(), 'both served completions called the upstream').toBe(2);
      expect((await s.complete('third')).statusCode).toBe(429);
      expect(s.upstream.calls(), 'the refused one called it no further').toBe(2);
    } finally {
      await s.h.app.close();
    }
  });

  it('files no receipt for a refused completion and keeps serving the ones already filed', async () => {
    const s = await serving(boundAt(1));
    try {
      const served = await s.complete('first');
      expect(served.statusCode).toBe(200);
      const refused = await s.complete('second');
      expect(refused.receiptId, 'a refusal mints no id').toBeNull();
      expect((await s.ask('GET', `/v1/receipts/${String(served.receiptId)}`, null)).statusCode).toBe(200);
      expect((await s.ask('GET', '/v1/deployment-manifest', null)).statusCode).toBe(200);
      expect((await s.ask('GET', '/v1/attestation', null)).statusCode).toBe(200);
    } finally {
      await s.h.app.close();
    }
  });

  it('holds one counter for the whole deployment, not one per credential', async () => {
    // Two credentials, one bucket: the second caller is refused on the first request it makes, which is
    // the difference between a bound on this process and a bound on each of its callers.
    const others = generated('other', ['complete', 'read'], { rate: { perMinute: 100_000, burst: 100_000 } });
    const upstream = countingBackend();
    const h = await harness({
      credentials: [credential(), others],
      gateway: { backend: upstream.backend, completionBound: boundAt(1) },
    });
    try {
      const first = await h.app.inject({
        method: 'POST',
        url: '/v1/chat/completions',
        headers: { 'content-type': 'application/json', ...h.signFor('bound', 'POST', '/v1/chat/completions', REQUEST_BODY) },
        payload: REQUEST_BODY,
      });
      expect(first.statusCode).toBe(200);
      const second = await h.app.inject({
        method: 'POST',
        url: '/v1/chat/completions',
        headers: {
          'content-type': 'application/json',
          ...h.signFor('other', 'POST', '/v1/chat/completions', REQUEST_BODY),
        },
        payload: REQUEST_BODY,
      });
      expect(second.statusCode, 'the other credential spent the same bucket').toBe(429);
      expect((second.json() as { error?: { code?: string } }).error?.code).toBe('DEPLOYMENT_RATE_LIMITED');
    } finally {
      await h.app.close();
    }
  });

  it('counts only the route that issues a receipt, and sheds no read', async () => {
    const s = await serving(boundAt(1));
    try {
      const served = await s.complete('first');
      const receiptId = String(served.receiptId);
      expect(served.statusCode).toBe(200);
      for (const [method, target] of [
        ['GET', `/v1/receipts/${receiptId}`],
        ['GET', '/v1/attestation'],
        ['GET', '/v1/deployment-manifest'],
        ['GET', '/v1/attestation/gpu'],
      ] as const) {
        const route = `${method} ${target}`;
        expect((await s.ask(method, target, null)).statusCode, `${route} is never refused for a rate`).not.toBe(429);
      }
      // A second completion is still refused, so the reads above did not refill the bucket they shared.
      expect((await s.complete('second')).statusCode).toBe(429);
    } finally {
      await s.h.app.close();
    }
  });

  it('answers with the wait to the next token, because this condition is a bucket', async () => {
    const s = await serving(boundAt(1));
    try {
      await s.complete('first');
      const refused = await s.complete('second');
      expect(refused.retryAfter, 'a refill has a time, so the answer states it').toBeDefined();
      expect(Number(refused.retryAfter)).toBeGreaterThanOrEqual(1);
      expect(String(refused.error.message)).toContain('a token appears in');
    } finally {
      await s.h.app.close();
    }
  });

  it('refills at the rate the bound states, and admits again when a token appears', async () => {
    // One token every second at `perMinute: 60`, so the same request is refused at one instant and served
    // at the next: the bound is a rate and not a count of a process's life.
    let at = 0;
    const s = await serving(boundAt(1, 60, () => at));
    try {
      expect((await s.complete('first')).statusCode).toBe(200);
      expect((await s.complete('second')).statusCode, 'no elapsed time, no refill').toBe(429);
      at = 1_000;
      expect((await s.complete('third')).statusCode, 'one second bought one token').toBe(200);
      expect((await s.complete('fourth')).statusCode).toBe(429);
    } finally {
      await s.h.app.close();
    }
  });

  it('serves every completion a deployment under its own bound sends', async () => {
    const s = await serving(boundAt(10));
    try {
      for (let i = 0; i < 10; i++) {
        expect((await s.complete(`fill ${String(i)}`)).statusCode).toBe(200);
      }
      expect(s.upstream.calls()).toBe(10);
      expect((await s.complete('past it')).statusCode).toBe(429);
    } finally {
      await s.h.app.close();
    }
  });

  it('refuses nobody who was not admitted first', async () => {
    // The bound sits behind the five checks, so a deployment running at its ceiling discloses nothing to a
    // caller that has proved nothing: the earlier check answers.
    const s = await serving(boundAt(1));
    try {
      await s.complete('first');
      const anonymous = await s.h.app.inject({
        method: 'POST',
        url: '/v1/chat/completions',
        headers: { 'content-type': 'application/json' },
        payload: REQUEST_BODY,
      });
      expect(anonymous.statusCode).toBe(401);
      expect((anonymous.json() as { error: { code: string } }).error.code).toBe('AUTH_MALFORMED');
    } finally {
      await s.h.app.close();
    }
  });

  it('writes the refusal to the access log as its own reason, naming the credential it refused', async () => {
    const s = await serving(boundAt(1));
    try {
      await s.complete('first');
      expect((await s.complete('second')).statusCode).toBe(429);
      const line = s.h.log.entries().at(-1);
      expect(line, 'one line per refusal').toMatchObject({
        deny: 'DEPLOYMENT_RATE_LIMITED',
        st: 429,
        cred: 'bound',
        auth: null,
        scope: null,
        p: '/v1/chat/completions',
      });
    } finally {
      await s.h.app.close();
    }
  });

  it('lets the durability guard answer while both conditions hold', async () => {
    // The guard is read ahead of this bound, so a completion the store could not have kept is refused for
    // the reason that says so, and the ordering rule that a request reporting two failures reports the
    // earlier one holds for the seventh check as it does for the sixth.
    const retention: ReceiptRetention = {
      maxAgeSeconds: TEN_YEARS_SECONDS,
      maxCount: 4,
      time: fixedClock(() => STAMP + 60),
    };
    const store = openMemoryReceiptStore({ retention });
    for (let i = 0; i < 3; i++) {
      await store.put(`rcpt_${String(i)}`, Uint8Array.from([i]), STAMP);
    }
    // One token, so the served completion spends the last of it and the next request meets both conditions.
    const s = await serving(boundAt(1), { store, guard: { retention } });
    try {
      expect((await s.complete('fourth')).statusCode, 'the store is not yet at its bound').toBe(200);
      const refused = await s.complete('fifth');
      expect(refused.statusCode).toBe(429);
      expect(refused.error.code).toBe('RECEIPT_WINDOW_UNHOLDABLE');
      expect(s.upstream.calls(), 'neither refusal computed anything').toBe(1);
    } finally {
      await s.h.app.close();
    }
  });

  it('runs the shipped ceiling for a deployment that named no rate, and refuses past it', async () => {
    // The rate is the constant, so it is driven to the burst and one past it. Only the bucket's clock is
    // pinned here, because a refill measured against the wall clock would let this case pass by running
    // slowly, and the claim is about the count, not about how fast the fixture was.
    const s = await serving({ nowMillis: () => 0 });
    try {
      for (let i = 0; i < DEFAULT_COMPLETION_RATE.burst; i++) {
        expect((await s.complete(`fill ${String(i)}`)).statusCode, `the ${String(i)}th completion`).toBe(200);
      }
      const refused = await s.complete('past the ceiling');
      expect(refused.statusCode).toBe(429);
      expect(String(refused.error.message)).toContain('admits 13636 completions a minute');
      expect(s.upstream.calls(), 'every refusal was refused before the inference').toBe(
        DEFAULT_COMPLETION_RATE.burst,
      );
    } finally {
      await s.h.app.close();
    }
  });
});

/**
 * A store with room it will never run out of, so the only bound a case below can meet is the one under
 * test: the durability guard is silent about a volume this far from its bound, and a completion is still
 * refused, because this bound is about what one process writes and not about what a file can hold.
 */
describe('the bound against a store that has kept everything it was asked to', () => {
  it('refuses a completion the volume could have kept', async () => {
    const retention: ReceiptRetention = { maxAgeSeconds: 184 * 24 * 60 * 60, maxCount: 10_000, time: fixedClock(() => STAMP) };
    const store = openMemoryReceiptStore({ retention });
    const s = await serving(boundAt(1, 60), { store, guard: { retention } });
    try {
      expect((await s.complete('first')).statusCode).toBe(200);
      const refused = await s.complete('second');
      expect(refused.error.code, 'the guard is silent two receipts short of ten thousand').toBe(
        'DEPLOYMENT_RATE_LIMITED',
      );
      expect((await store.window()).count, 'and the refusal filed nothing').toBe(1);
    } finally {
      await s.h.app.close();
    }
  });
});
