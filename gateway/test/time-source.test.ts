import { afterEach, describe, expect, it } from 'vitest';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import fc from 'fast-check';
import {
  HOST_CLOCK_SOURCE,
  measurableSpanSeconds,
  openFileReceiptStore,
  openMemoryReceiptStore,
  receiptsNeededForWindow,
  readingsApart,
  RECEIPT_STORE_FILE,
  type ReceiptRetention,
  type ReceiptStore,
  type RetainedWindow,
  type TimeSource,
  type WindowClaim,
} from '../src/store.js';
import { fixedClock } from './helpers.js';

/**
 * What a declared uncertainty does to a verdict, measured against a substituted source rather than
 * against the mock gateway.
 *
 * Three questions, one per group below. Whether two readings of one source are a difference: that is
 * `readingsApart`, and the answer is the same at a window's edges as in its arithmetic, because both
 * weigh a distance against the one resolution the source declares. Whether a stamp counts as inside
 * the window it was served out of: that is `WindowClaim`, and its cases are drawn over substituted
 * sources and real windows rather than over one hand-written instant. Whether the bound a record was
 * issued under comes back with the record: it comes back through the store that reads it, and the last
 * group states where that stops short, which is a finding about the record layout rather than a detail
 * of this file.
 */

/** Set from the environment so a red run replays exactly: `FC_SEED=1234` on the package's test run. */
const SEED = Number(process.env['FC_SEED'] ?? '20260918');
/** Bounded by the file cases below, not by this: a store walk is a map lookup and a dozen comparisons. */
const RUNS = Number(process.env['FC_RUNS'] ?? '400');
/** The file-backed cases reopen a volume, which is the slow part of a case on a shared host. */
const FILE_CASE_TIMEOUT = 15_000;

/** Twice the bound: the most two readings of one source can lean apart from each other. */
const resolution = (bound: number): number => 2 * bound;

const created: string[] = [];

afterEach(async () => {
  const dirs = created.splice(0, created.length);
  await Promise.all(dirs.map((dir) => rm(dir, { recursive: true, force: true })));
});

async function emptyDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'ashaveri-time-source-'));
  created.push(dir);
  return dir;
}

/** The margin a stamp has before a half-open window's nearer edge, in the units the claim counts in. */
function marginOf(iat: number, from: number, to: number): number {
  return Math.min(iat - from + 1, to - iat);
}

async function claimOf(store: ReceiptStore, from: number, to: number): Promise<WindowClaim> {
  const seen: WindowClaim[] = [];
  for await (const item of store.range(from, to)) {
    seen.push(item.claim);
  }
  expect(seen).toHaveLength(1);
  return seen[0]!;
}

describe('two readings of one source', () => {
  it('calls a pair no wider than the resolution the same reading, and a wider pair a difference', () => {
    // The boundary is the resolution itself rather than one less than it, which is what lets a span
    // used for arithmetic and a distance reported to an operator be the same comparison.
    const measured = fixedClock(() => 0, 5);
    expect(readingsApart(measured, 0, resolution(5)).state).toBe('indistinguishable');
    expect(readingsApart(measured, 0, resolution(5) + 1).state).toBe('apart');
    // A source that claims it is exact can tell two consecutive seconds apart.
    const exact = fixedClock(() => 0, 0);
    expect(readingsApart(exact, 0, 0).state).toBe('indistinguishable');
    expect(readingsApart(exact, 0, 1).state).toBe('apart');
  });

  it('states no resolution for a source nobody measured, whatever the two readings are', () => {
    const apart = readingsApart(HOST_CLOCK_SOURCE, 1_000, 2_000);
    expect(apart.state).toBe('unmeasured');
    // The absence is the whole point of the third state: a reader cannot take a distance across an
    // unmeasured source and write it down as if the source had bounded it.
    expect('resolutionSeconds' in apart).toBe(false);
    expect('uncertaintySeconds' in apart).toBe(false);
  });

  it('agrees with the distance the readings print, over drawn bounds and pairs', () => {
    fc.assert(
      fc.property(fc.nat(3_600), fc.nat(200_000), fc.nat(200_000), (bound, first, second) => {
        const apart = readingsApart(fixedClock(() => first, bound), first, second);
        const distance = Math.abs(first - second);
        return (
          apart.state === (distance <= resolution(bound) ? 'indistinguishable' : 'apart') &&
          apart.apartSeconds === distance &&
          apart.resolutionSeconds === resolution(bound) &&
          apart.uncertaintySeconds === bound &&
          apart.source === 'fixture clock'
        );
      }),
      { numRuns: RUNS, seed: SEED },
    );
  });
});

describe('a stamp read against the window it was served out of', () => {
  it('keeps an unmeasured source from reporting a satisfied membership', async () => {
    // Ten seconds deep inside a wide window by any clock in the world, and the store still has no
    // bound to weigh it with, which is the state this lane must not let read as accuracy.
    const store = openMemoryReceiptStore();
    await store.put('rcpt_01', Uint8Array.from([1, 2, 3]), 1_010);
    expect(store.timeSource()).toEqual({ name: 'host clock', uncertaintySeconds: null });
    expect(await claimOf(store, 1_000, 2_000)).toEqual({
      state: 'bound-unknown',
      stamped: { name: 'host clock', uncertaintySeconds: null },
    });
  });

  it('draws the line at the same distance the pair comparison draws it', async () => {
    // A source bounded at 10 seconds resolves nothing closer than 20, so a stamp 20 seconds clear of
    // an edge is still at it and one second further is inside. Counted from the edge itself, because
    // the older edge belongs to the window: the stamp sitting on `from` has one second of margin.
    const source = fixedClock(() => 1_500, 10);
    const probe = async (iat: number): Promise<WindowClaim> => {
      const store = openMemoryReceiptStore({ retention: { time: source } });
      await store.put('rcpt_01', Uint8Array.from([iat % 256]), iat);
      return claimOf(store, 1_000, 2_000);
    };
    await expect(probe(1_000)).resolves.toMatchObject({ state: 'at-edge', marginSeconds: 1 });
    await expect(probe(1_019)).resolves.toMatchObject({ state: 'at-edge', marginSeconds: 20 });
    await expect(probe(1_020)).resolves.toMatchObject({ state: 'inside-window' });
    // The newer edge is excluded, so one second below it is the closest a served stamp can sit.
    await expect(probe(1_999)).resolves.toMatchObject({ state: 'at-edge', marginSeconds: 1 });
    await expect(probe(1_979)).resolves.toMatchObject({ state: 'inside-window' });
  });

  it('reports every stamp a source that claims exactness wrote as inside its own window', async () => {
    // The degenerate bound is the one that says a reading is the instant: no stamp the store served
    // can be outside a window it was matched into, so hedging an edge here would be a false unknown.
    const store = openMemoryReceiptStore({ retention: { time: fixedClock(() => 1_000, 0) } });
    await store.put('rcpt_01', Uint8Array.from([9]), 1_000);
    expect(await claimOf(store, 1_000, 1_001)).toEqual({
      state: 'inside-window',
      stamped: { name: 'fixture clock', uncertaintySeconds: 0 },
    });
  });

  it('states the same verdict for a stamp, a window and a bound, however they are drawn', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.option(fc.nat(300), { nil: null }),
        fc.nat(5_000),
        fc.integer({ min: 2, max: 2_000 }),
        fc.nat(),
        async (bound, from, width, drawn) => {
          const to = from + width;
          const iat = from + (drawn % width);
          const store = openMemoryReceiptStore({ retention: { time: fixedClock(() => iat, bound) } });
          await store.put('rcpt_01', Uint8Array.from([1]), iat);
          const claim = await claimOf(store, from, to);
          if (claim.state === 'bound-unknown') {
            return bound === null && claim.stamped.uncertaintySeconds === null;
          }
          if (bound === null) {
            return false;
          }
          const source = fixedClock(() => iat, bound);
          const margin = claim.state === 'at-edge' ? claim.marginSeconds : marginOf(iat, from, to);
          if (claim.state !== (margin > resolution(bound) ? 'inside-window' : 'at-edge')) {
            return false;
          }
          // The same resolution weighs both, and the two edges take it one second apart from each
          // other because `from` is inside the window and `to` is not: a stamp exactly one resolution
          // above the older edge cannot have been meant for anywhere outside, and a stamp exactly one
          // resolution below the newer edge could have. A stamp reported at an edge is never a
          // difference from the nearer of them, which is the comparison `readingsApart` makes.
          const older = iat - from;
          const newer = to - iat;
          if (claim.state === 'inside-window') {
            return older >= resolution(bound) && newer > resolution(bound);
          }
          const nearerEdge = older <= newer ? from : to;
          return readingsApart(source, iat, nearerEdge).state === 'indistinguishable';
        },
      ),
      { numRuns: RUNS, seed: SEED },
    );
  });
});

describe('the bound a record was issued under', () => {
  it('comes back beside the record through a restart that declares the same source', { timeout: FILE_CASE_TIMEOUT }, async () => {
    const dir = await emptyDir();
    const retention: ReceiptRetention = { time: fixedClock(() => 1_500, 10) };
    const written = await openFileReceiptStore({ dir, retention });
    await written.put('rcpt_01', Uint8Array.from([1, 2, 3]), 1_020);
    const reopened = await openFileReceiptStore({ dir, retention });
    expect(reopened.timeSource()).toEqual({ name: 'fixture clock', uncertaintySeconds: 10 });
    expect(await claimOf(reopened, 1_000, 2_000)).toEqual({
      state: 'inside-window',
      stamped: { name: 'fixture clock', uncertaintySeconds: 10 },
    });
  });

  it('follows the declaration the store was opened with, because no record byte holds it', { timeout: FILE_CASE_TIMEOUT }, async () => {
    const dir = await emptyDir();
    const written = await openFileReceiptStore({ dir, retention: { time: fixedClock(() => 1_500, 1) } });
    await written.put('rcpt_01', Uint8Array.from([1, 2, 3]), 1_020);
    expect((await claimOf(written, 1_000, 2_000)).state).toBe('inside-window');

    // A second opening that declares a wider bound reads the same stamp as sitting at an edge. The
    // record's own bytes are untouched by that, which is the finding this case pins rather than fixes:
    // the bound travels with the deployment's declaration and not with the record.
    const widened = await openFileReceiptStore({ dir, retention: { time: fixedClock(() => 1_500, 30) } });
    expect(await claimOf(widened, 1_000, 2_000)).toEqual({
      state: 'at-edge',
      marginSeconds: 21,
      stamped: { name: 'fixture clock', uncertaintySeconds: 30 },
    });
    const image = await readFile(join(dir, RECEIPT_STORE_FILE));
    expect(image.includes(Buffer.from('fixture clock', 'utf8'))).toBe(false);
    expect(image.includes(Buffer.from('host clock', 'utf8'))).toBe(false);
  });
});

describe('the rate a window is derived at', () => {
  const ends = (from: number, to: number, count: number): RetainedWindow => ({ from, to, count });

  it('takes more receipts for one period when the source declares a bound', () => {
    // Five receipts over four seconds at a one-year period: exact readings give a quarter of a receipt
    // per second, and a source that resolves nothing inside 20 seconds cannot claim four seconds of
    // span at all, so it is read over the one second its floor allows.
    const period = 31_536_000;
    expect(receiptsNeededForWindow(period, ends(1_000, 1_004, 5), fixedClock(() => 0, 0))).toBe(31_536_001);
    expect(receiptsNeededForWindow(period, ends(1_000, 1_004, 5), fixedClock(() => 0, 3))).toBe(126_144_001);
    // The shipped default declares nothing, which is the same arithmetic as the exact source over the
    // printed span: an unmeasured source narrows nothing, and says so rather than claiming accuracy.
    expect(receiptsNeededForWindow(period, ends(1_000, 1_004, 5))).toBe(31_536_001);
    expect(receiptsNeededForWindow(period, ends(1_000, 1_004, 5), HOST_CLOCK_SOURCE)).toBe(31_536_001);
  });

  it('never reads a span the source cannot resolve as no seconds at all', () => {
    expect(measurableSpanSeconds(ends(1_000, 1_004, 5), fixedClock(() => 0, 3))).toBe(1);
    expect(measurableSpanSeconds(ends(1_000, 1_004, 5), fixedClock(() => 0, 1))).toBe(2);
    expect(measurableSpanSeconds(ends(1_000, 1_000, 5), fixedClock(() => 0, 1))).toBe(1);
    expect(measurableSpanSeconds(ends(1_000, 1_004, 5), HOST_CLOCK_SOURCE)).toBe(4);
    // A store that measured nothing of its own traffic asks no rate question.
    expect(receiptsNeededForWindow(1_000, ends(1_000, 1_004, 1), fixedClock(() => 0, 3))).toBeNull();
    expect(receiptsNeededForWindow(0, ends(1_000, 1_004, 5), fixedClock(() => 0, 3))).toBeNull();
  });

  it('names the source it derived the count under in the refusal an operator reads', { timeout: FILE_CASE_TIMEOUT }, async () => {
    const refusal = async (time: TimeSource): Promise<string> => {
      const dir = await emptyDir();
      const retention: ReceiptRetention = { maxAgeSeconds: 2, maxCount: 10, time };
      const store = await openFileReceiptStore({ dir, retention });
      for (let i = 0; i < 10; i++) {
        await store.put(`rcpt_${String(i)}`, Uint8Array.from([i]), 1_000);
      }
      return openFileReceiptStore({ dir, retention }).then(
        () => 'opened, no refusal',
        (error: unknown) => (error as Error).message,
      );
    };
    // Ten receipts sharing one instant is the fastest traffic a file can report, so both readings
    // refuse over the same one-second floor. What differs is the sentence: an operator raising the
    // bound has to know which source the number was worked out under.
    const measured = await refusal(fixedClock(() => 1_000, 4));
    expect(measured).toContain('RETENTION_WINDOW_UNHOLDABLE');
    expect(measured).toContain('as read from the source named fixture clock');
    expect(measured).toContain('resolve no distance above 8 seconds');
    expect(measured).toContain('which leaves 1 of those seconds');
    const unmeasured = await refusal(fixedClock(() => 1_000));
    expect(unmeasured).toContain('as read from the source named fixture clock');
    expect(unmeasured).toContain('on which nobody measured an uncertainty');
    expect(unmeasured).not.toContain('resolve no distance above');
  });
});
