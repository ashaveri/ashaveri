import { afterEach, describe, expect, it } from 'vitest';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtemp, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decodeReceipt } from '@ashaveri/receipt';
import {
  HOST_CLOCK_SOURCE,
  openMemoryReceiptStore,
  type ReceiptStore,
  type TimeSource,
} from '../src/store.js';
import {
  MAX_TIME_SOURCE_STATE_REFRESH_SECONDS,
  MIN_TIME_SOURCE_STATE_REFRESH_SECONDS,
  TIME_SOURCE_STATE_PLAUSIBILITY_BAND_SECONDS,
  TIME_SOURCE_STATE_FILE_VERSION,
  openTimeSourceState,
  parseTimeSourceState,
  refreshSecondsFor,
  stalenessCeilingSeconds,
  TimeSourceStateError,
  type TimeSourceStateHandle,
} from '../src/time-source-state.js';
import { generated, harness, type Harness } from './helpers.js';
import { noteSpawn, spawnCeilingForCalls } from './support/spawn-budget.js';

/**
 * A deployment's stamps read from a state file, through the reader that holds it in memory.
 *
 * The promise this file keeps is narrow and worth stating before the groups: the name and the bound a
 * receipt signs inside `sd` have to be the name and the bound of the source that read the stamp, even when
 * that source is a file somebody else maintains, and even when the file stops being maintained.
 * `gateway/test/time-source.test.ts` holds what a declared bound does to a verdict once a source is wired,
 * and the store has accepted a source at its seam all along. What these cases hold beside it is the route a
 * shipped process takes to a source at all, which is the half that can go wrong silently: an
 * unreadable document answered by the host clock would put a sentence inside a signed artifact that the
 * process knew was false.
 *
 * Four groups, one per way that promise breaks. The first reads the document, because every later answer is
 * arithmetic on what it states, and a member this reader drops is a claim the artifact stops making. The
 * second is refusal at the start, since a fallback there is the defect the route exists to avoid. The third
 * is the live rule: an age, a ceiling derived from the bound the file itself states, a stamp refused rather
 * than extrapolated, and the two shapes a step of the host clock must never reach, which are a stamp moved
 * and a bound quietly widened. The fourth runs the shipped binary, because a route that exists only for a
 * caller of the library is not a route an operator has.
 *
 * The monotonic and wall clocks are injected where a case is about the arithmetic they feed, so an age of a
 * hundred seconds costs no run a hundred seconds of waiting. Where a case is about the reading of a file it
 * is given no seam at all: it opens the real reader over the real file system and counts the reads.
 */

/** The instant the fixtures state, far from any host clock, so a stamp matching it was not read off one. */
const BASE = 1_772_000_000;
/** The source name the fixtures write, and the one every refusal and every `sd` below quotes. */
const SOURCE = 'disciplined ntp source';
/** The completion body one issuance is asked for, on the model a default mock deployment declares. */
const REQUEST_BODY = '{"model":"mock-model-1","messages":[{"role":"user","content":"state file"}]}';
/** The two deadlines `gateway/test/cli.test.ts` owns for the children this file also starts. */
const SPAWN_DEADLINE_MS = 8_000;
const BOOT_DEADLINE_MS = 10_000;

const created: string[] = [];
const started: TimeSourceStateHandle[] = [];

afterEach(async () => {
  for (const handle of started.splice(0, started.length)) {
    handle.stop();
  }
  const dirs = created.splice(0, created.length);
  await Promise.all(dirs.map((dir) => rm(dir, { recursive: true, force: true })));
});

async function emptyDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'ashaveri-time-source-state-'));
  created.push(dir);
  return dir;
}

/** One state document, spelled as the operator's synchronisation writes it, with the members a case moves. */
function stateDocument(fields: Record<string, unknown> = {}): string {
  return JSON.stringify({
    version: TIME_SOURCE_STATE_FILE_VERSION,
    source: SOURCE,
    uncertaintySeconds: 3,
    measuredAtSeconds: BASE,
    ...fields,
  });
}

/** A monotonic clock a case moves by whole seconds, which is what makes an age cost nothing to reach. */
function monotonicFixture(): { readonly seconds: () => number; readonly advance: (seconds: number) => void } {
  let at = 0;
  return {
    seconds: () => at,
    advance: (seconds: number) => {
      at += seconds;
    },
  };
}

/**
 * One open, with the seams a case needs and nothing else: the wall clock pinned to the fixture instant, so
 * the start band weighs a document naming an instant in 2026 against a host claiming the same thing.
 */
async function openFixture(
  path: string,
  clocks: { readonly mono?: ReturnType<typeof monotonicFixture> } = {},
): Promise<TimeSourceStateHandle> {
  const handle = await openTimeSourceState({
    path,
    monotonicSeconds: clocks.mono?.seconds,
    wallSeconds: () => BASE,
  });
  started.push(handle);
  return handle;
}

/**
 * The message a source raised instead of answering, or this file's own failure.
 *
 * Written once because four cases ask the same question, and a case that reads a refusal by catching any
 * exception at all can pass on a fault its own harness raised: this names the instant that answered where
 * a refusal was owed, so a green here is a refusal and not a coincidence.
 */
function refusalOf(source: TimeSource): string {
  let held: number;
  try {
    held = source.nowSeconds();
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
  throw new Error(`the state answered ${String(held)} where the case owes a refusal`);
}

/** The message a refused open handed back, or this file's own failure for the same reason. */
async function refusalOfOpen(path: string): Promise<string> {
  return openTimeSourceState({ path, wallSeconds: () => BASE }).then(
    () => 'opened a source from a document that was refused',
    (error: unknown) => (error as Error).message,
  );
}

describe('the state document, read whole or not at all', () => {
  it('adopts the name, the bound and the instant it states, and no others', async () => {
    const dir = await emptyDir();
    const path = join(dir, 'clock-state.json');
    await writeFile(path, stateDocument({ uncertaintySeconds: 7, measuredAtSeconds: BASE + 12 }), 'utf8');
    const handle = await openFixture(path);
    expect(handle.source.name).toBe(SOURCE);
    expect(handle.source.uncertaintySeconds).toBe(7);
    expect(handle.source.nowSeconds()).toBe(BASE + 12);
    expect(handle.path).toBe(path);
  });

  it('keeps a bound of zero as a claim of exactness and a null as the sentence that nobody measured', async () => {
    const dir = await emptyDir();
    const zero = join(dir, 'zero.json');
    await writeFile(zero, stateDocument({ uncertaintySeconds: 0 }), 'utf8');
    expect((await openFixture(zero)).source.uncertaintySeconds).toBe(0);
    const none = join(dir, 'none.json');
    await writeFile(none, stateDocument({ uncertaintySeconds: null }), 'utf8');
    const unmeasured = await openFixture(none);
    // Neither absence is read as the other, and neither is read as the shipped host claim: a null here is a
    // source the deployment named and nobody bounded, which is a different document from no source at all.
    expect(unmeasured.source.uncertaintySeconds).toBeNull();
    expect(unmeasured.source.name).toBe(SOURCE);
    expect(unmeasured.source.name).not.toBe(HOST_CLOCK_SOURCE.name);
  });

  it('refuses a member this reader has no name for and keeps the reading already adopted in force', async () => {
    const dir = await emptyDir();
    const path = join(dir, 'clock-state.json');
    await writeFile(path, stateDocument({ uncertaintySeconds: 4, measuredAtSeconds: BASE + 20 }), 'utf8');
    const handle = await openFixture(path, { mono: monotonicFixture() });
    expect(handle.source.uncertaintySeconds).toBe(4);
    const before = handle.source.nowSeconds();

    // A document stating a second bound beside the one this reader knows would have the tighter claim
    // dropped, and the artifact would go on naming the wider number: that is the drift a reader of a signed
    // disclosure cannot afford, so the member is refused by name and every field of the reading in force
    // stands exactly as it was, including the bound the refused document tried to replace.
    await writeFile(path, stateDocument({ uncertaintySeconds: 1, tighterBoundSeconds: 1 }), 'utf8');
    await expect(handle.refresh()).rejects.toThrow(/tighterBoundSeconds/u);
    expect(handle.source.name).toBe(SOURCE);
    expect(handle.source.uncertaintySeconds).toBe(4);
    expect(handle.source.nowSeconds()).toBe(before);
  });

  it('refuses a document cut in the middle and adopts one written then renamed over the path', async () => {
    const dir = await emptyDir();
    const path = join(dir, 'clock-state.json');
    const good = stateDocument({ measuredAtSeconds: BASE + 30 });
    await writeFile(path, good, 'utf8');
    const mono = monotonicFixture();
    const handle = await openFixture(path, { mono });
    mono.advance(2);

    // The half-written file is what a writer that does not rename leaves behind, so this is the witness that
    // a partial document cannot half-update a source: it is refused as a whole, and the instant held before
    // it keeps advancing off the base it was adopted with rather than a blend taken from both documents.
    await writeFile(path, good.slice(0, good.length - 12), 'utf8');
    await expect(handle.refresh()).rejects.toThrow(/not readable as JSON/u);
    expect(handle.source.uncertaintySeconds).toBe(3);
    expect(handle.source.nowSeconds()).toBe(BASE + 32);

    // The writer this module expects replaces the file by rename, and the reader adopts it whole: a new name
    // and a new bound are in force at the next stamp, which is the one pair of fields a receipt reports.
    const replaced = join(dir, 'clock-state.next.json');
    await writeFile(
      replaced,
      stateDocument({ source: 'replaced source', uncertaintySeconds: 9, measuredAtSeconds: BASE + 40 }),
      'utf8',
    );
    await rename(replaced, path);
    await handle.refresh();
    expect(handle.source.name).toBe('replaced source');
    expect(handle.source.uncertaintySeconds).toBe(9);
    expect(handle.source.nowSeconds()).toBe(BASE + 40);
  });

  it('refuses every spelling that states no measurement, and names the file in each refusal', () => {
    const path = join('volumes', 'clock-state.json');
    const bytes = (text: string): Uint8Array => new TextEncoder().encode(text);
    const refusals: readonly (readonly [string, string])[] = [
      ['no instant at all', JSON.stringify({ version: 1, source: SOURCE, uncertaintySeconds: 3 })],
      ['no source', JSON.stringify({ version: 1, uncertaintySeconds: 3, measuredAtSeconds: BASE })],
      ['no bound stated either way', JSON.stringify({ version: 1, source: SOURCE, measuredAtSeconds: BASE })],
      [
        'no version',
        JSON.stringify({ source: SOURCE, uncertaintySeconds: 3, measuredAtSeconds: BASE }),
      ],
      [
        'a version this reader does not have',
        JSON.stringify({ version: 2, source: SOURCE, uncertaintySeconds: 3, measuredAtSeconds: BASE }),
      ],
      ['a fractional instant', JSON.stringify({ version: 1, source: SOURCE, uncertaintySeconds: 3, measuredAtSeconds: BASE + 0.5 })],
      ['an instant that is not a number', JSON.stringify({ version: 1, source: SOURCE, uncertaintySeconds: 3, measuredAtSeconds: 'now' })],
      ['an instant below zero', JSON.stringify({ version: 1, source: SOURCE, uncertaintySeconds: 3, measuredAtSeconds: -1 })],
      ['a bound of negative one', JSON.stringify({ version: 1, source: SOURCE, uncertaintySeconds: -1, measuredAtSeconds: BASE })],
      ['a bound that is not a number', JSON.stringify({ version: 1, source: SOURCE, uncertaintySeconds: 'three', measuredAtSeconds: BASE })],
      ['a fractional bound', JSON.stringify({ version: 1, source: SOURCE, uncertaintySeconds: 0.5, measuredAtSeconds: BASE })],
      ['a bound wider than any instant this route can place', JSON.stringify({ version: 1, source: SOURCE, uncertaintySeconds: TIME_SOURCE_STATE_PLAUSIBILITY_BAND_SECONDS + 1, measuredAtSeconds: BASE })],
      ['no name for the source', JSON.stringify({ version: 1, source: '   ', uncertaintySeconds: 3, measuredAtSeconds: BASE })],
      ['a source that is not text', JSON.stringify({ version: 1, source: 7, uncertaintySeconds: 3, measuredAtSeconds: BASE })],
      ['a list rather than an object', '[1,2,3]'],
      ['a number rather than a document', '17'],
      ['nothing at all', ''],
    ];
    for (const [what, text] of refusals) {
      // Each refusal names the file, because the path is the one thing an operator can act on, and none of
      // these is read past: a document this reader cannot quote back to its author is not a source it may
      // name inside a signed receipt.
      expect(() => parseTimeSourceState(bytes(text), path), what).toThrow(TimeSourceStateError);
      expect(() => parseTimeSourceState(bytes(text), path), what).toThrow(path);
    }
  });

  it('reads back the whole of a document one synchronisation would write', async () => {
    const dir = await emptyDir();
    const path = join(dir, 'clock-state.json');
    await writeFile(path, stateDocument({ uncertaintySeconds: 2, measuredAtSeconds: BASE + 6 }), 'utf8');
    const bytes = new Uint8Array(await readFile(path));
    expect(parseTimeSourceState(bytes, path)).toEqual({
      source: SOURCE,
      uncertaintySeconds: 2,
      measuredAtSeconds: BASE + 6,
    });
  });
});

describe('a state file that cannot be read stops the run', () => {
  it('refuses to open over a file that is not there, naming the path and the reason', async () => {
    const dir = await emptyDir();
    const path = join(dir, 'absent.json');
    const refusal = await refusalOfOpen(path);
    expect(refusal).toContain(path);
    expect(refusal).toContain('could not be read');
  });

  it('refuses a document whose instant no reading can place, and says what it was weighed against', async () => {
    const dir = await emptyDir();
    const path = join(dir, 'clock-state.json');
    await writeFile(
      path,
      stateDocument({ measuredAtSeconds: BASE - TIME_SOURCE_STATE_PLAUSIBILITY_BAND_SECONDS - 1 }),
      'utf8',
    );
    const refusal = await refusalOfOpen(path);
    expect(refusal).toContain(path);
    expect(refusal).toContain(String(TIME_SOURCE_STATE_PLAUSIBILITY_BAND_SECONDS));
    expect(refusal).toContain('refuses to sign receipts from it');
    // An hour away is inside the band and the run takes the document's word for it: the band is a refusal of
    // a file that names no instant anybody can reach, and never a claim that a day of difference is accurate.
    await writeFile(path, stateDocument({ measuredAtSeconds: BASE + 3600 }), 'utf8');
    expect((await openFixture(path)).source.nowSeconds()).toBe(BASE + 3600);
  });

  it('refuses an instant spelled in milliseconds, which is the one mistake a clock file can make twice', async () => {
    const dir = await emptyDir();
    const path = join(dir, 'clock-state.json');
    await writeFile(path, stateDocument({ measuredAtSeconds: BASE * 1000 }), 'utf8');
    // A whole number in a wider unit parses as a number and is refused as an instant: this estate stamps,
    // compares and retires in whole Unix seconds, and a reading a thousand times past the second it names
    // would be signed into every receipt as the deployment's own clock.
    const refusal = await refusalOfOpen(path);
    expect(refusal).toContain(path);
    expect(refusal).toContain(String(BASE * 1000));
  });

  it('hands a caller no source at all when the document is refused', async () => {
    const dir = await emptyDir();
    const path = join(dir, 'clock-state.json');
    await writeFile(path, stateDocument({ extraMember: true }), 'utf8');
    // Nothing is returned on a refusal, so there is no object left to wire and no name a receipt could
    // carry that the process knew it had not read.
    await expect(openFixture(path)).rejects.toBeInstanceOf(TimeSourceStateError);
  });
});

describe('the live rule: a state older than its own bound stops signing', () => {
  it('refuses a stamp once the file sits past the ceiling its bound allows, naming age, bound and file', async () => {
    const dir = await emptyDir();
    const path = join(dir, 'clock-state.json');
    await writeFile(path, stateDocument({ uncertaintySeconds: 3, measuredAtSeconds: BASE }), 'utf8');
    const mono = monotonicFixture();
    const handle = await openFixture(path, { mono });
    // Three seconds of bound takes the reader to its one-second floor and to a ceiling of five: an age of
    // seven is a file that stopped being a measurement and became a number this process is wearing.
    expect(handle.policy()).toEqual({ refreshSeconds: 1, stalenessCeilingSeconds: 5 });
    mono.advance(4);
    expect(handle.source.nowSeconds()).toBe(BASE + 4);
    mono.advance(3);
    const refusal = refusalOf(handle.source);
    expect(refusal).toContain(path);
    expect(refusal).toContain(SOURCE);
    expect(refusal).toContain('7 seconds behind');
    expect(refusal).toContain('bounded at 3 seconds');
    expect(refusal).toContain('5 seconds this route allows');

    // The same file moving forward again is the whole of the recovery: the rule weighs the state's age, so a
    // synchronisation that comes back resumes the stamps without a restart and without a second document.
    await writeFile(path, stateDocument({ uncertaintySeconds: 3, measuredAtSeconds: BASE + 10 }), 'utf8');
    await handle.refresh();
    expect(handle.source.nowSeconds()).toBe(BASE + 10);
  });

  it('weighs an unbounded state on liveness alone, at the intervals this reader counts', async () => {
    const dir = await emptyDir();
    const path = join(dir, 'clock-state.json');
    await writeFile(path, stateDocument({ uncertaintySeconds: null }), 'utf8');
    const mono = monotonicFixture();
    const handle = await openFixture(path, { mono });
    // Nothing was measured, so nothing bounds an age but this reader's own timers: the cadence falls to the
    // widest interval, the ceiling is twice it, and the refusal says nobody measured rather than inventing a
    // zero for an age to be weighed against.
    expect(handle.policy()).toEqual({
      refreshSeconds: MAX_TIME_SOURCE_STATE_REFRESH_SECONDS,
      stalenessCeilingSeconds: 2 * MAX_TIME_SOURCE_STATE_REFRESH_SECONDS,
    });
    mono.advance(2 * MAX_TIME_SOURCE_STATE_REFRESH_SECONDS);
    expect(handle.source.nowSeconds()).toBe(BASE + 120);
    mono.advance(1);
    const refusal = refusalOf(handle.source);
    expect(refusal).toContain(path);
    expect(refusal).toContain('121 seconds behind');
    expect(refusal).toContain('nobody measured an uncertainty');
    expect(refusal).not.toContain('bounded at');
  });

  it('carries the file through an issuance, so a lapsed state costs a receipt and not a silent date', async () => {
    const dir = await emptyDir();
    const path = join(dir, 'clock-state.json');
    await writeFile(path, stateDocument({ uncertaintySeconds: 3, measuredAtSeconds: BASE }), 'utf8');
    const mono = monotonicFixture();
    const handle = await openFixture(path, { mono });
    const credential = generated('time-source-state', ['complete', 'read']);
    const app: Harness = await harness({ credentials: [credential], gateway: { time: handle.source } });
    try {
      const served = await app.app.inject({
        method: 'POST' as 'GET',
        url: '/v1/chat/completions',
        headers: {
          'content-type': 'application/json',
          ...app.signFor('time-source-state', 'POST', '/v1/chat/completions', REQUEST_BODY),
        },
        payload: REQUEST_BODY,
      });
      expect(served.statusCode).toBe(200);
      const receiptId = served.headers['x-ashaveri-receipt-id'] as string;
      const fetched = await app.app.inject({
        method: 'GET',
        url: `/v1/receipts/${receiptId}`,
        headers: app.signFor('time-source-state', 'GET', `/v1/receipts/${receiptId}`, null),
      });
      const payload = decodeReceipt(new Uint8Array(fetched.rawPayload)).payload;
      // The signed document names the file's source with the file's bound, which is the sentence the whole
      // route is for: a client weighing `maxTimeUncertaintySeconds` reads the deployment's own measurement
      // rather than the claim of whatever host the process happens to stand on.
      expect(payload.sd).toEqual({ name: SOURCE, uncertaintySeconds: 3 });
      expect(payload.sd.name).not.toBe(HOST_CLOCK_SOURCE.name);
      expect(payload.iat).toBe(BASE);

      // And once the state lapses the same gateway answers no receipt: the issuance is refused with the file
      // named in it, rather than dated by a clock the document never mentioned.
      mono.advance(3_600);
      const lapsed = await app.app.inject({
        method: 'POST' as 'GET',
        url: '/v1/chat/completions',
        headers: {
          'content-type': 'application/json',
          ...app.signFor('time-source-state', 'POST', '/v1/chat/completions', REQUEST_BODY),
        },
        payload: REQUEST_BODY,
      });
      expect(lapsed.statusCode).toBeGreaterThanOrEqual(500);
      // The answer is a JSON document, so the path reaches it escaped: this is the same text the refusal
      // names, spelled the way the wire spells it.
      expect(lapsed.body).toContain(JSON.stringify(path).slice(1, -1));
      expect(lapsed.body).toContain('3600 seconds behind');
      expect(lapsed.body).toContain('bounded at 3 seconds');
    } finally {
      await app.app.close();
    }
  });
});

describe('what the cached source answers between reads', () => {
  it('performs no file read on the path that stamps a receipt', async () => {
    const dir = await emptyDir();
    const path = join(dir, 'clock-state.json');
    // A wide bound, so the ceiling is nowhere near any stall this machine could cause, and no seam at all:
    // this is the real reader over the real file system, which is the only pair a per-stamp read could hide
    // from, and the counter is what a hot path that read the file would break.
    await writeFile(
      path,
      stateDocument({ uncertaintySeconds: 600, measuredAtSeconds: Math.floor(Date.now() / 1000) }),
      'utf8',
    );
    const handle = await openTimeSourceState({ path });
    started.push(handle);
    handle.stop();
    expect(handle.stateReads()).toBe(1);
    let last = -1;
    for (let at = 0; at < 10_000; at += 1) {
      const stamp = handle.source.nowSeconds();
      // Whole seconds, and never one below the last: the unit every stamp, comparison and retirement in this
      // estate is written in, and the ordering a receipt chain rests on.
      expect(Number.isInteger(stamp)).toBe(true);
      expect(stamp).toBeGreaterThanOrEqual(last);
      last = stamp;
    }
    expect(handle.stateReads()).toBe(1);
  });

  it('moves no stamp when the host clock is stepped backwards and then forwards', async () => {
    const dir = await emptyDir();
    const path = join(dir, 'clock-state.json');
    const wall = Math.floor(Date.now() / 1000);
    await writeFile(path, stateDocument({ uncertaintySeconds: 600, measuredAtSeconds: wall }), 'utf8');
    const handle = await openTimeSourceState({ path });
    started.push(handle);
    handle.stop();
    const before = handle.source.nowSeconds();
    // One hour off the host's own claim in one direction and a day in the other: the stamp is the file's
    // instant advanced on a base that counts time since this process started, so neither step reaches it, and
    // a receipt already signed stays where it was signed. A source advanced off `Date.now` reddens here.
    const realNow = Date.now;
    try {
      Date.now = () => realNow.call(Date) - 3_600_000;
      expect(handle.source.nowSeconds()).toBe(before);
      Date.now = () => realNow.call(Date) + 86_400_000;
      expect(handle.source.nowSeconds()).toBe(before);
    } finally {
      Date.now = realNow;
    }
  });

  it('refuses rather than rewinds when a later document states an instant behind the one it stamped', async () => {
    const dir = await emptyDir();
    const path = join(dir, 'clock-state.json');
    await writeFile(path, stateDocument({ uncertaintySeconds: 3, measuredAtSeconds: BASE + 100 }), 'utf8');
    const mono = monotonicFixture();
    const handle = await openFixture(path, { mono });
    mono.advance(1);
    expect(handle.source.nowSeconds()).toBe(BASE + 101);

    // A writer reporting an instant behind the one already stamped cannot pull a stamp back: the base holds,
    // and the file's word stays what an age is weighed against, so the widening gap is refused as a state
    // that no longer bounds this process's own arithmetic. A source that quietly returned the older instant
    // would hand a reader two stamps out of order under one name, which is what `sd` cannot survive.
    await writeFile(path, stateDocument({ uncertaintySeconds: 3, measuredAtSeconds: BASE + 40 }), 'utf8');
    await handle.refresh();
    const refusal = refusalOf(handle.source);
    expect(refusal).toContain('61 seconds behind');
    expect(refusal).toContain(path);
    expect(handle.source.name).toBe(SOURCE);
  });

  it('derives its cadence from the bound the document states and holds it inside the estate resolution', () => {
    // Half the bound, floored at one second and capped at the widest interval: a source bounded at an hour is
    // not read every second, and a source bounded at a second is not read once a minute.
    expect(refreshSecondsFor(null)).toBe(MAX_TIME_SOURCE_STATE_REFRESH_SECONDS);
    expect(refreshSecondsFor(0)).toBe(MIN_TIME_SOURCE_STATE_REFRESH_SECONDS);
    expect(refreshSecondsFor(1)).toBe(MIN_TIME_SOURCE_STATE_REFRESH_SECONDS);
    expect(refreshSecondsFor(10)).toBe(5);
    expect(refreshSecondsFor(1000)).toBe(MAX_TIME_SOURCE_STATE_REFRESH_SECONDS);
    // From two seconds of bound up the ceiling stays inside twice the bound the file states, which is the
    // distance `readingsApart` already refuses to call a difference between two readings of one source.
    for (const bound of [2, 3, 10, 61, 600, 1000, 86_400]) {
      expect(stalenessCeilingSeconds(bound, refreshSecondsFor(bound)), `bound ${String(bound)}`).toBeLessThanOrEqual(
        2 * bound,
      );
    }
    expect(stalenessCeilingSeconds(null, refreshSecondsFor(null))).toBe(
      2 * MAX_TIME_SOURCE_STATE_REFRESH_SECONDS,
    );
  });

  it('travels through a store as the declaration the store states about itself', async () => {
    const dir = await emptyDir();
    const path = join(dir, 'clock-state.json');
    await writeFile(path, stateDocument({ uncertaintySeconds: 12, measuredAtSeconds: BASE }), 'utf8');
    const handle = await openFixture(path, { mono: monotonicFixture() });
    const stamp = handle.source.nowSeconds();
    const store: ReceiptStore = openMemoryReceiptStore({ retention: { time: handle.source } });
    await store.put('rcpt_01', Uint8Array.from([1, 2, 3]), stamp);
    // The same two fields `declarationOf` puts into a payload's `sd`, read off the store that filed the record.
    expect(store.timeSource()).toEqual({ name: SOURCE, uncertaintySeconds: 12 });
    const seen: number[] = [];
    for await (const record of store.range(BASE, BASE + 10)) {
      seen.push(record.iat);
    }
    expect(seen).toEqual([BASE]);
  });

  it('reads the file again when the timer runs, and reports once when it cannot', async () => {
    const dir = await emptyDir();
    const path = join(dir, 'clock-state.json');
    await writeFile(path, stateDocument({ uncertaintySeconds: 600 }), 'utf8');
    const lines: string[] = [];
    const handle = await openTimeSourceState({
      path,
      refreshSeconds: MIN_TIME_SOURCE_STATE_REFRESH_SECONDS,
      wallSeconds: () => BASE,
      report: (line: string) => {
        lines.push(line);
      },
    });
    started.push(handle);
    // The cadence this case waits on is one second, and the bytes behind it come off the file rather than
    // being handed in, which is the only way a case can show that the timer itself adopted something.
    await writeFile(path, stateDocument({ uncertaintySeconds: 600, source: 'advanced by the timer' }), 'utf8');
    await new Promise((resolve) => setTimeout(resolve, 1_400));
    expect(handle.source.name).toBe('advanced by the timer');
    expect(handle.stateReads()).toBeGreaterThan(1);

    await rm(path, { force: true });
    await new Promise((resolve) => setTimeout(resolve, 2_600));
    // One line for a fault that goes on faulting: the timer keeps trying, and an operator reading a log gets
    // the file named once rather than the same sentence every interval.
    expect(lines.filter((line) => line.includes(path))).toHaveLength(1);
    // The cached reading still answers while its own age is inside the ceiling, because a file that cannot be
    // read is not yet a state that has lapsed: the age rule decides, and it decides the same way whether the
    // file stopped moving or stopped existing.
    expect(handle.source.nowSeconds()).toBeGreaterThanOrEqual(BASE + 3);
    handle.stop();
  });
});

describe('the route on the shipped binary', () => {
  const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url));

  /** One CLI child that exits, with its code and both of its streams. */
  function runCli(...args: string[]): { status: number | null; stdout: string; stderr: string } {
    noteSpawn(SPAWN_DEADLINE_MS);
    const env = { ...process.env };
    delete env['DSTACK_SIMULATOR_ENDPOINT'];
    const result = spawnSync(process.execPath, [CLI, ...args], {
      encoding: 'utf8',
      env,
      timeout: SPAWN_DEADLINE_MS,
      killSignal: 'SIGKILL',
    });
    expect(result.error, `the CLI child did not run: ${String(result.error)}`).toBeUndefined();
    return { status: result.status, stdout: result.stdout, stderr: result.stderr };
  }

  /** One CLI child that serves, read as far as its banner and stopped, on the deadline a boot is given. */
  async function bootBanner(...args: string[]): Promise<string> {
    noteSpawn(BOOT_DEADLINE_MS);
    const env = { ...process.env };
    delete env['DSTACK_SIMULATOR_ENDPOINT'];
    const child = spawn(process.execPath, [CLI, ...args], { env, stdio: ['ignore', 'pipe', 'pipe'] });
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    let out = '';
    let err = '';
    child.stderr.on('data', (chunk: string) => {
      err += chunk;
    });
    const stopped = new Promise<void>((resolve) => child.once('exit', () => resolve()));
    try {
      return await new Promise<string>((resolve, reject) => {
        const deadline = setTimeout(
          () => reject(new Error(`no listening line within ${String(BOOT_DEADLINE_MS / 1000)}s; stderr held ${JSON.stringify(err)}`)),
          BOOT_DEADLINE_MS,
        );
        child.once('exit', (code) =>
          reject(new Error(`the gateway exited with ${String(code)} before it listened; stderr held ${JSON.stringify(err)}`)),
        );
        child.stdout.on('data', (chunk: string) => {
          out += chunk;
          // The whole banner is one write, so the chunk that carries the listening line carries every line
          // behind it, and a case reads the report rather than a prefix of it.
          if (/^signerd \(mock\) listening on http:\/\/127\.0\.0\.1:[1-9]\d*\n/u.test(out)) {
            clearTimeout(deadline);
            resolve(out);
          }
        });
      });
    } finally {
      child.kill('SIGKILL');
      await stopped;
    }
  }

  it(
    'names the flag, the bound it leaves to the document, and the absence of a fallback',
    { timeout: spawnCeilingForCalls(1, SPAWN_DEADLINE_MS) },
    () => {
      const help = runCli('--help');
      expect(help.status).toBe(0);
      const folded = help.stdout.replace(/\s+/gu, ' ');
      expect(folded).toContain('--time-source-state <file>');
      expect(folded).toContain('no flag here names a bound');
      expect(folded).toContain('this route never falls back to the host clock');
      expect(folded).toContain('moved on between reads by a monotonic');
      expect(folded).toContain('Default: this host');
    },
  );

  it(
    'refuses a run whose state file is not there, on the exit no flag answers, naming the path',
    { timeout: spawnCeilingForCalls(2, SPAWN_DEADLINE_MS) },
    async () => {
      const dir = await emptyDir();
      const path = join(dir, 'absent.json');
      const result = runCli('--mock', '--port', '0', '--time-source-state', path);
      expect(result.status, result.stderr).toBe(1);
      expect(result.stderr).toContain(path);
      expect(result.stderr).toContain('could not be read');
      // Nothing listened and nothing was stamped: the run that could not read its source is the run that
      // never started, and no usage hint sends an operator to a flag for a fact about a file.
      expect(result.stdout).toBe('');
      const second = runCli('--mock', '--port', '0', '--time-source-state', join(dir, 'also-absent.json'));
      expect(second.stderr).not.toContain("Try 'signerd --help'");
      expect(second.stderr).toContain('also-absent.json');
    },
  );

  it(
    'refuses a state document the binary cannot read, and does not stamp under the host clock instead',
    { timeout: spawnCeilingForCalls(2, SPAWN_DEADLINE_MS) },
    async () => {
      const dir = await emptyDir();
      const path = join(dir, 'clock-state.json');
      await writeFile(path, stateDocument({ measuredAtSeconds: undefined }), 'utf8');
      const missing = runCli('--mock', '--port', '0', '--time-source-state', path);
      expect(missing.status, missing.stderr).toBe(1);
      expect(missing.stderr).toContain('measuredAtSeconds');
      expect(missing.stdout).toBe('');

      await writeFile(path, stateDocument({ rootHash: 'nothing this reader knows' }), 'utf8');
      const unknown = runCli('--mock', '--port', '0', '--time-source-state', path);
      expect(unknown.status, unknown.stderr).toBe(1);
      expect(unknown.stderr).toContain('rootHash');
      expect(unknown.stderr).toContain(`version ${String(TIME_SOURCE_STATE_FILE_VERSION)}`);
      expect(unknown.stdout).toBe('');
    },
  );

  it(
    'starts on a readable file, prints the source it reads and how often it reads it',
    { timeout: spawnCeilingForCalls(1, BOOT_DEADLINE_MS) },
    async () => {
      const dir = await emptyDir();
      const path = join(dir, 'clock-state.json');
      // The instant a real run has to state is the host's own second, since the start band weighs the
      // document against it: this is the file an operator's synchronisation would be writing.
      await writeFile(
        path,
        stateDocument({ uncertaintySeconds: 600, measuredAtSeconds: Math.floor(Date.now() / 1000) }),
        'utf8',
      );
      const banner = await bootBanner('--mock', '--port', '0', '--time-source-state', path);
      const folded = banner.replace(/\s+/gu, ' ');
      expect(folded).toContain(`${SOURCE}, whose readings are bounded at 600 seconds`);
      expect(folded).toContain(`time source state: ${path}`);
      expect(folded).toContain('every 60 seconds');
      expect(folded).toContain('more than 720 seconds behind');
      // The name the run reports is the file's, and the shipped claim is gone from the banner: whoever reads
      // a start-up log can tell which source this process was holding from those two lines.
      expect(folded).not.toContain('read from host clock');
    },
  );
});
