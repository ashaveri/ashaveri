import { describe, expect, it } from 'vitest';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { CompletionBackend } from '../src/backend.js';
import { mockBackend } from '../src/backend.js';
import {
  DEFAULT_INTAKE_GUARD_FRACTION,
  intakeGuardRefusal,
  type IntakeGuardFigures,
  type ReceiptIntakeGuard,
} from '../src/server.js';
import {
  openFileReceiptStore,
  openMemoryReceiptStore,
  receiptsNeededForWindow,
  type ReceiptRetention,
  type RetainedWindow,
} from '../src/store.js';
import type { CredentialRate } from '../src/access.js';
import { generated, harness, type Generated, type Harness } from './helpers.js';

/**
 * The guard reads a store's retained set, so every case here is a count and two stamps rather than a
 * file: `gateway/src/store.ts` is where the rate comes from, and this suite asks only whether the
 * reading is acted on. `receiptsNeededForWindow` is the function the opening refusal refuses by, so
 * the figures below are derived by the same rule the store applies and written out beside each
 * expectation the way `store.test.ts` writes its own out.
 */

/** The durability bound every fixture store is opened with. */
const BOUND = 4;
/** A period long enough that no fixture receipt ever ages out of it, so only the count decides. */
const TEN_YEARS_SECONDS = 10 * 365 * 24 * 60 * 60;
/** One instant for every stamp a fixture writes, so a retained set spans no seconds at all. */
const STAMP = 1_780_000_000;

/** A retained set of `count` receipts, all stamped at `STAMP`. */
function held(count: number): RetainedWindow {
  return count === 0 ? { from: 0, to: 0, count: 0 } : { from: STAMP, to: STAMP, count };
}

/** The policy a fixture store was opened with, and which its guard is handed. */
const retention: ReceiptRetention = {
  maxAgeSeconds: TEN_YEARS_SECONDS,
  maxCount: BOUND,
  now: () => STAMP + 60,
};

/** The guard a deployment that configures nothing but the two bounds runs. */
const atTheBound: ReceiptIntakeGuard = { retention };

describe('the intake guard, as arithmetic', () => {
  it('refuses at the durability bound when the retained stamps cannot span the period', () => {
    // Four receipts at a bound of four, every one of them stamped at the same instant, which is the
    // fastest traffic a file can report: the span is read as one second, so the period takes
    // ceil(3 * 315360000 / 1) + 1 = 946080001 receipts and the bound holds four.
    const refusal = intakeGuardRefusal(atTheBound, held(BOUND));
    expect(refusal).toEqual({
      retained: 4,
      refusesAt: 4,
      bound: 4,
      spanSeconds: 0,
      periodSeconds: TEN_YEARS_SECONDS,
      needed: 946_080_001,
    });
    // The derived figure is the store's own arithmetic, not a copy of it.
    expect(receiptsNeededForWindow(TEN_YEARS_SECONDS, held(BOUND))).toBe(refusal?.needed);
  });

  it('serves below the durability bound, where nothing is being shed', () => {
    // Three of four: the next completion retires nothing yet, and the opening refuses this pairing
    // never, because a set short of its count is keeping everything its period asked of it.
    expect(intakeGuardRefusal(atTheBound, held(BOUND - 1))).toBeNull();
  });

  it('serves a store at its bound whose stamps already span the period', () => {
    // The state the opening lets through and this must let through too: at the bound, but the four
    // retained receipts cover the configured period between their own two end stamps, so the count
    // reconciles with the period and the next retirement falls outside it.
    const spans = { from: STAMP, to: STAMP + TEN_YEARS_SECONDS, count: BOUND };
    expect(receiptsNeededForWindow(TEN_YEARS_SECONDS, spans)).toBe(BOUND);
    expect(intakeGuardRefusal(atTheBound, spans)).toBeNull();
  });

  it('never asks a policy bounded on one side only, in either shape', () => {
    // One bound is not a pairing. A count with no period retires nothing that a period covers, and a
    // period with no count sheds nothing on capacity, so neither half can be the short one.
    const countOnly: ReceiptIntakeGuard = { retention: { maxCount: BOUND, now: retention.now } };
    const periodOnly: ReceiptIntakeGuard = { retention: { maxAgeSeconds: TEN_YEARS_SECONDS, now: retention.now } };
    expect(intakeGuardRefusal(countOnly, held(BOUND))).toBeNull();
    expect(intakeGuardRefusal(periodOnly, held(BOUND))).toBeNull();
    expect(intakeGuardRefusal({}, held(BOUND))).toBeNull();
  });

  it('serves a store that has measured no rate of its own', () => {
    // Fewer than two receipts is no measurement, in either direction of the arithmetic, and a period
    // that is not a positive number of seconds is no period to hold.
    expect(intakeGuardRefusal(atTheBound, held(0))).toBeNull();
    expect(intakeGuardRefusal(atTheBound, held(1))).toBeNull();
    expect(intakeGuardRefusal({ retention: { maxAgeSeconds: 0, maxCount: BOUND } }, held(BOUND))).toBeNull();
  });

  it('refuses from the configured fraction of the bound, not only from the bound itself', () => {
    // Half of four is two, and two receipts stamped at one instant already say the period cannot be
    // held at this rate: the point of the threshold being a fraction is to meet that reading while
    // there is still room, rather than at the last receipt the bound keeps.
    const atHalf: ReceiptIntakeGuard = { retention, refusesAtFraction: 0.5 };
    expect(intakeGuardRefusal(atHalf, held(1))).toBeNull();
    expect(intakeGuardRefusal(atHalf, held(2))).toMatchObject({ retained: 2, refusesAt: 2, bound: 4 });
  });

  it('rounds a fraction up to a whole receipt, and never past the bound', () => {
    // A threshold is a count of receipts, so a fraction that does not land on one is read at the next
    // receipt above it: 60% of four is 2.4, and two receipts is not yet 60% of the bound.
    expect(intakeGuardRefusal({ retention, refusesAtFraction: 0.6 }, held(2))).toBeNull();
    expect(intakeGuardRefusal({ retention, refusesAtFraction: 0.6 }, held(3))?.refusesAt).toBe(3);
    // Nothing sits above the bound: a retained set never exceeds the count that retires it, so a
    // threshold wider than one reads as the bound and not as a guard that can never fire. Turning the
    // guard off is a named decision, and the two cases below hold it.
    expect(intakeGuardRefusal({ retention, refusesAtFraction: 3 }, held(BOUND))?.refusesAt).toBe(BOUND);
    expect(intakeGuardRefusal({ retention, refusesAtFraction: Number.NaN }, held(BOUND))?.refusesAt).toBe(BOUND);
    expect(intakeGuardRefusal({ retention, refusesAtFraction: 0 }, held(BOUND))?.refusesAt).toBe(BOUND);
  });

  it('takes the opt-in to grow past the guard ahead of every other figure', () => {
    // The state that refuses with everything else in place, and then the same state with the opt-in
    // set. Nothing about the arithmetic changes: the opt-in is read first, because a deployment that
    // took it has already made this decision and is not being asked to make it again per request.
    expect(intakeGuardRefusal(atTheBound, held(BOUND))?.needed).toBeGreaterThan(BOUND);
    expect(intakeGuardRefusal({ ...atTheBound, growPastGuard: true }, held(BOUND))).toBeNull();
  });

  it('defaults to the bound itself, which is the state a store refuses to open at', async () => {
    // The claim that a deployment setting nothing sees no change is a claim about two code paths, so
    // it is checked against the real one rather than argued. Five receipts at one instant into a store
    // bounded at three: the retained set sits at its bound and its span is no seconds, which is the
    // signature the opening refuses by.
    const dir = await mkdtemp(join(tmpdir(), 'ashaveri-intake-guard-'));
    try {
      const tight: ReceiptRetention = { maxAgeSeconds: TEN_YEARS_SECONDS, maxCount: 3, now: () => STAMP + 60 };
      const written = await openFileReceiptStore({ dir, retention: tight });
      for (let i = 0; i < 5; i++) {
        await written.put(`rcpt_${String(i)}`, Uint8Array.from([i]), STAMP);
      }
      const window = await written.window();
      expect(window).toEqual({ from: STAMP, to: STAMP, count: 3 });

      // Both readings at the refusing pairing: the store will not open, and the guard would refuse.
      await expect(openFileReceiptStore({ dir, retention: tight })).rejects.toMatchObject({
        code: 'RETENTION_WINDOW_UNHOLDABLE',
      });
      expect(intakeGuardRefusal({ retention: tight }, window)).not.toBeNull();

      // And both at the same file under a bound that holds it: the store opens, the guard is silent.
      // One file, two configurations, so the only thing that moves is whether the retained set reaches
      // the state the two readings agree is a shortfall. The wider store keeps all five records the run
      // wrote, so it is read from its own window rather than from the narrower store's.
      const wide: ReceiptRetention = { ...tight, maxCount: 6 };
      const reopened = await openFileReceiptStore({ dir, retention: wide });
      expect(await reopened.window()).toEqual({ from: STAMP, to: STAMP, count: 5 });
      expect(intakeGuardRefusal({ retention: wide }, await reopened.window())).toBeNull();
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('ships the default fraction as the bound itself, in the units the guard takes', () => {
    // `1` is a whole fraction of the bound rather than a sentinel, which is what makes the default and
    // the state a store refuses at one and the same arithmetic instead of two lists kept in step.
    expect(DEFAULT_INTAKE_GUARD_FRACTION).toBe(1);
    expect(intakeGuardRefusal(atTheBound, held(BOUND))).toEqual(
      intakeGuardRefusal({ retention, refusesAtFraction: DEFAULT_INTAKE_GUARD_FRACTION }, held(BOUND)),
    );
  });
});

// ---------------------------------------------------------------------------
// The same rule read off a serving gateway.
// ---------------------------------------------------------------------------

const REQUEST_BODY = '{"model":"mock-model-1","messages":[{"role":"user","content":"hello"}]}';

/** Every completion this test suite sends, and the credential that signs for them. */
function credential(rate?: CredentialRate): Generated {
  return generated('intake', ['complete', 'read'], rate === undefined ? {} : { rate });
}

/** The upstream is the thing the guard is placed ahead of, so its calls are counted, not assumed. */
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
  /** One completion, as the credential above signs it, with the three things a caller can observe. */
  complete(text: string): Promise<{
    statusCode: number;
    receiptId: string | null;
    retryAfter: string | undefined;
    /** The error envelope, for a refusal; empty for a served completion. */
    error: Record<string, unknown>;
  }>;
  /** Any request, signed the same way, for the routes that keep serving. */
  ask(method: string, target: string, body: string | null): Promise<{ statusCode: number; headers: Record<string, string | undefined> }>;
}

async function serving(
  guard: ReceiptIntakeGuard,
  options: { rate?: CredentialRate } = {},
): Promise<Serving> {
  const upstream = countingBackend();
  const h = await harness({
    // The credential's own bucket, when a case is about a second 429 beside this one. The connection's
    // bound is left at the harness default, because every request a fixture injects shares one address.
    credentials: [credential(options.rate)],
    gateway: {
      // The gateway's own clock and the store's retention clock are pinned to the same instant, so a
      // retained set's span is a fact of this fixture rather than of how long the run took.
      now: () => STAMP * 1000,
      backend: upstream.backend,
      store: openMemoryReceiptStore({ retention }),
      receiptIntakeGuard: guard,
    },
  });
  async function ask(method: string, target: string, body: string | null) {
    const response = await h.app.inject({
      method: method as 'GET',
      url: target,
      headers: {
        ...(body === null ? {} : { 'content-type': 'application/json' }),
        ...h.signFor('intake', method, target, body),
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

describe('a gateway whose store has reached the durability guard', () => {
  it('refuses a completion at the bound with RECEIPT_WINDOW_UNHOLDABLE and a 429', async () => {
    const s = await serving(atTheBound);
    try {
      for (let i = 0; i < BOUND; i++) {
        expect((await s.complete(`fill ${String(i)}`)).statusCode, `the run up to the bound`).toBe(200);
      }
      const refused = await s.complete('past the bound');
      expect(refused.statusCode).toBe(429);
      expect(refused.error.code).toBe('RECEIPT_WINDOW_UNHOLDABLE');
      // The four numbers an operator acts on, in the sentence the caller is handed: the retained set,
      // the bound it reached, the period configured beside it, and the count that period takes.
      const message = String(refused.error.message);
      expect(message).toContain('the store holds 4 of the 4 receipts its durability bound allows');
      expect(message).toContain(`${String(TEN_YEARS_SECONDS)} seconds`);
      expect(message).toContain('946080001 receipts');
      expect(message).toContain('which is 946079997 more than the bound holds');
      expect(message).toContain('refusing from 4 of them');
    } finally {
      await s.h.app.close();
    }
  });

  it('never reaches the upstream for a refused completion, and reaches it once for a served one', async () => {
    // Evidence from the code path rather than from the status: the guard is in the pre-handler, so a
    // refusal that spent an inference would show here as a call. The count is read either side of the
    // same request to make the difference a fact about this guard rather than about the run.
    const s = await serving(atTheBound);
    try {
      for (let i = 0; i < BOUND; i++) {
        await s.complete(`fill ${String(i)}`);
      }
      expect(s.upstream.calls(), 'every served completion called the upstream').toBe(BOUND);
      expect((await s.complete('refused')).statusCode).toBe(429);
      expect(s.upstream.calls(), 'a refused completion called it no further').toBe(BOUND);
    } finally {
      await s.h.app.close();
    }
  });

  it('answers a retryable status with no wait figure, because no wait is known', async () => {
    // 429 says the condition clears; naming seconds would say this process knows when the traffic on
    // the volume falls under the rate the bound cannot hold, which it does not.
    const s = await serving(atTheBound);
    try {
      for (let i = 0; i < BOUND; i++) {
        await s.complete(`fill ${String(i)}`);
      }
      expect((await s.complete('refused')).retryAfter).toBeUndefined();
    } finally {
      await s.h.app.close();
    }
  });

  it('files no receipt for a refused completion and keeps serving the ones already filed', async () => {
    // The reading, the verification and the handover routes are all served from what the store kept,
    // which is the whole reason this refusal is placed at intake rather than at the store: the receipt
    // that cannot be kept going forward is refused, and the ones that exist are not touched.
    const s = await serving(atTheBound);
    try {
      const ids: string[] = [];
      for (let i = 0; i < BOUND; i++) {
        const answered = await s.complete(`fill ${String(i)}`);
        ids.push(String(answered.receiptId));
      }
      const refused = await s.complete('refused');
      expect(refused.receiptId, 'a refusal mints no id').toBeNull();

      expect((await s.ask('GET', `/v1/receipts/${ids[0]}`, null)).statusCode, 'the oldest filed receipt').toBe(200);
      expect((await s.ask('GET', '/v1/deployment-manifest', null)).statusCode).toBe(200);
      expect((await s.ask('GET', '/v1/attestation', null)).statusCode).toBe(200);
    } finally {
      await s.h.app.close();
    }
  });

  it('serves a quiet store exactly as it did before the guard was read', async () => {
    // The two states a quiet deployment is in: nothing filed yet, and a store short of its bound.
    // Neither is refused whatever the period says, because neither is shedding a receipt.
    const s = await serving(atTheBound);
    try {
      expect((await s.complete('first')).statusCode).toBe(200);
      expect((await s.complete('second')).statusCode).toBe(200);
      expect(s.upstream.calls()).toBe(2);
    } finally {
      await s.h.app.close();
    }
  });

  it('refuses from the configured fraction of the bound, two receipts earlier', async () => {
    const s = await serving({ retention, refusesAtFraction: 0.5 });
    try {
      expect((await s.complete('first')).statusCode).toBe(200);
      expect((await s.complete('second')).statusCode).toBe(200);
      expect((await s.complete('third')).statusCode, 'two of four is the half of the bound').toBe(429);
      expect(s.upstream.calls(), 'the third completion was refused before it was computed').toBe(2);
    } finally {
      await s.h.app.close();
    }
  });

  it('keeps issuing past the bound when the opt-in is set, and retires inside the period', async () => {
    // The opt-in is the behaviour that existed before this guard, so it is held to what that behaviour
    // actually costs: the answer is served, a receipt is filed, and the oldest receipt in the same
    // volume is gone because the bound had to make room for the new one. The window the deployment
    // advertised is the one the count reaches, and this is where that reads as a shorter one.
    const s = await serving({ retention, growPastGuard: true });
    try {
      const ids: string[] = [];
      for (let i = 0; i < BOUND + 1; i++) {
        const answered = await s.complete(`fill ${String(i)}`);
        expect(answered.statusCode, `the opt-in refuses nothing`).toBe(200);
        ids.push(String(answered.receiptId));
      }
      expect(s.upstream.calls()).toBe(BOUND + 1);
      expect((await s.ask('GET', `/v1/receipts/${ids[0]}`, null)).statusCode, 'retired by the bound').toBe(404);
      expect((await s.ask('GET', `/v1/receipts/${ids[1]}`, null)).statusCode).toBe(200);
    } finally {
      await s.h.app.close();
    }
  });

  it('refuses nobody who was not admitted first', async () => {
    // The guard is the sixth check and not the first: an unauthenticated completion is still answered
    // about its credential, so a deployment running at its guard discloses nothing to a caller that has
    // proved nothing, and the five documented checks keep reporting the earlier failure.
    const s = await serving(atTheBound);
    try {
      for (let i = 0; i < BOUND; i++) {
        await s.complete(`fill ${String(i)}`);
      }
      const anonymous = await s.h.app.inject({
        method: 'POST',
        url: '/v1/chat/completions',
        headers: { 'content-type': 'application/json' },
        payload: REQUEST_BODY,
      });
      expect(anonymous.statusCode).toBe(401);
      expect((JSON.parse(anonymous.payload) as { error: { code: string } }).error.code).toBe('AUTH_MALFORMED');
      expect(s.upstream.calls(), 'a refusal of the credential called it no further than the fills did').toBe(BOUND);
    } finally {
      await s.h.app.close();
    }
  });

  it('writes the refusal to the access log as a reason a rate limit is not', async () => {
    // Two 429s out of one gateway, separated where they have to be. The credential's bucket is five
    // tokens and the four fills spend four: the guard refusal takes the fifth and then refuses, so the
    // request behind it is answered by the empty bucket ahead of ever reaching the guard. Same status,
    // different code, different reason on the line, and the guard's own line still names the credential
    // it refused while leaving `auth` and `scope` null, because what it declined is the issuing.
    const s = await serving(atTheBound, { rate: { perMinute: 5, burst: 5 } });
    try {
      for (let i = 0; i < BOUND; i++) {
        await s.complete(`fill ${String(i)}`);
      }
      const guard = await s.complete('guard');
      const rate = await s.complete('rate');
      expect([guard.statusCode, rate.statusCode]).toEqual([429, 429]);
      expect([guard.error.code, rate.error.code]).toEqual(['RECEIPT_WINDOW_UNHOLDABLE', 'RATE_LIMITED']);

      const entries = s.h.log.entries();
      expect(entries.at(-2), 'the guard, as the log records it').toMatchObject({
        deny: 'RECEIPT_WINDOW_UNHOLDABLE',
        st: 429,
        cred: 'intake',
        auth: null,
        scope: null,
        p: '/v1/chat/completions',
      });
      expect(entries.at(-1), 'the bucket, as the log records it').toMatchObject({
        deny: 'RATE_LIMITED',
        st: 429,
        cred: 'intake',
      });
      expect(
        entries.filter((each) => each.deny === 'RECEIPT_WINDOW_UNHOLDABLE'),
        'one line per guard refusal, and none of them a rate limit',
      ).toHaveLength(1);
    } finally {
      await s.h.app.close();
    }
  });
});

/**
 * The store this case ends on is the one the guard is read from, so the file it writes is the evidence
 * the refusal rests on: ten durable appends is what the suite in `store.test.ts` measured as the point
 * where a case here would otherwise reach the runner's default, and this one opens that file once
 * rather than three times.
 */
const FILE_CASE_TIMEOUT = 15_000;

describe('a refusal against a volume a real store wrote', () => {
  it(
    'reads the guard off the window the file reports, not off a number the plan chose',
    { timeout: FILE_CASE_TIMEOUT },
    async () => {
      const dir = await mkdtemp(join(tmpdir(), 'ashaveri-intake-guard-file-'));
      try {
        const bound: ReceiptRetention = { maxAgeSeconds: TEN_YEARS_SECONDS, maxCount: 2, now: () => STAMP + 60 };
        const written = await openFileReceiptStore({ dir, retention: bound });
        for (let i = 0; i < 4; i++) {
          await written.put(`rcpt_${String(i)}`, Uint8Array.from([i, 1, 2, 3]), STAMP);
        }
        const window = await written.window();
        expect(window.count, 'the bound retired everything above it').toBe(2);
        const refusal: IntakeGuardFigures | null = intakeGuardRefusal({ retention: bound }, window);
        expect(refusal).toMatchObject({ retained: 2, bound: 2, refusesAt: 2, spanSeconds: 0 });
        // 2 receipts at one instant: ceil(1 * 315360000 / 1) + 1.
        expect(refusal?.needed).toBe(315_360_001);
        expect(receiptsNeededForWindow(TEN_YEARS_SECONDS, window)).toBe(refusal?.needed);
      } finally {
        await rm(dir, { recursive: true, force: true });
      }
    },
  );
});

/** A guard handed a store it has no policy for, which is what an embedding caller that set nothing gets. */
describe('a gateway with no intake guard configured', () => {
  it('issues past its durability bound exactly as it did before the guard was read', async () => {
    const s = await serving({});
    try {
      for (let i = 0; i < BOUND + 2; i++) {
        expect((await s.complete(`fill ${String(i)}`)).statusCode).toBe(200);
      }
      expect(s.upstream.calls()).toBe(BOUND + 2);
    } finally {
      await s.h.app.close();
    }
  });
});
