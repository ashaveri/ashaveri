import { describe, expect, it } from 'vitest';
import { foldProvableHorizon, horizonFault } from '../src/horizon.js';

/**
 * The fold that answers how far back a deployment can prove it held receipts.
 *
 * The two sources are the ones a deployment actually has: a sealed run of packs, whose windows the epoch
 * inventory states in the pack's framing (from included, to excluded), and the live store's retained set,
 * which the store reports in its own framing (both ends inclusive). The fold is where those two framings
 * meet, so every case below pins numbers that come out differently if one of the two ends is converted
 * wrongly, and none of them asks for a figure the evidence cannot carry.
 *
 * Five years is stated as 1,825 days of 86,400 seconds rather than a calendar walk, because a horizon this
 * wide is a duration and the fold reads no calendar.
 */
const DAY = 86_400;
const FIVE_YEARS = 1_825 * DAY;
const START = 1_700_000_000;

const run = (from: number, toExclusive: number) => ({ window: { from, to: toExclusive } });
const live = (from: number, to: number) => ({ from, to });

describe('the provable horizon, folded from a sealed run and a live store', () => {
  it('reads a run sealed back five years as the five years it reaches', () => {
    // The store has shed everything older than the last month, and the run carries the years before it. A
    // reading that stopped at the live window would tell this deployment it holds 30 days of evidence.
    const horizon = foldProvableHorizon({
      run: run(START, START + FIVE_YEARS),
      live: live(START + FIVE_YEARS - 30 * DAY, START + FIVE_YEARS + 2 * DAY - 1),
    });

    expect(horizon?.from).toBe(START);
    expect(horizon?.toExclusive).toBe(START + FIVE_YEARS + 2 * DAY);
    expect(horizon?.seconds, 'the two sources overlap by 30 days, so the reach is not the sum of their lengths')
      .toBe(FIVE_YEARS + 2 * DAY);
    expect(horizon?.continuous).toBe(true);
    expect(horizon?.gaps).toEqual([]);
    expect(horizon?.segments.map((one) => one.source)).toEqual(['sealed-run', 'live-window']);
  });

  it('reads a live window alone as the window it states, and nothing wider', () => {
    // 184 days is the shipped default age bound, so a deployment that has sealed nothing can state 184 days
    // and no more. The conversion is the whole risk here: the store's newest stamp is inclusive, and reading
    // it as exclusive loses a day from every horizon this fold has ever stated.
    const horizon = foldProvableHorizon({
      live: live(START, START + 184 * DAY - 1),
    });

    expect(horizon?.seconds).toBe(184 * DAY);
    expect(horizon?.toExclusive).toBe(START + 184 * DAY);
    expect(horizon?.segments).toHaveLength(1);
    expect(horizon?.segments[0]?.source).toBe('live-window');
  });

  it('reads a sealed run with no live window beside it as the run it is', () => {
    const horizon = foldProvableHorizon({ run: run(START, START + FIVE_YEARS) });

    expect(horizon?.seconds).toBe(FIVE_YEARS);
    expect(horizon?.segments.map((one) => one.source)).toEqual(['sealed-run']);
  });

  it('answers a declared duty against the reach and names both figures when it falls short', () => {
    // The duty is the caller's declaration, so the verdict is the subtraction beside it: 184 days held, five
    // years required, short by the difference. The words go with the numbers because an operator reads the
    // line, not the arithmetic.
    const horizon = foldProvableHorizon({
      live: live(START, START + 184 * DAY - 1),
      duty: { article: '19(1)', requiredSeconds: FIVE_YEARS },
    });

    expect(horizon?.duty).not.toBeNull();
    expect(horizon?.duty?.met).toBe(false);
    expect(horizon?.duty?.heldSeconds).toBe(184 * DAY);
    expect(horizon?.duty?.requiredSeconds).toBe(FIVE_YEARS);
    expect(horizon?.because.join('\n')).toContain(`${String(184 * DAY)} seconds`);
    expect(horizon?.because.join('\n')).toContain(String(FIVE_YEARS));
  });

  it('answers a declared duty met once the reach covers it', () => {
    const horizon = foldProvableHorizon({
      run: run(START, START + FIVE_YEARS),
      duty: { article: '19(1)', requiredSeconds: FIVE_YEARS },
    });

    expect(horizon?.duty?.met).toBe(true);
    expect(horizon?.duty?.heldSeconds).toBe(FIVE_YEARS);
  });

  it('states no verdict at all when the deployment declares no duty', () => {
    // The reach is a fact about the evidence and the period is a reading of a law, so a fold that paired them
    // without being asked would be this package answering which article the deployment owes.
    const horizon = foldProvableHorizon({ run: run(START, START + FIVE_YEARS) });

    expect(horizon?.duty).toBeNull();
    expect(horizon?.because).toEqual([]);
    expect(horizon?.seconds, 'the reach is still stated, because it is what the evidence carries').toBe(FIVE_YEARS);
  });

  it('refuses to call a stretch the evidence does not cover part of one horizon', () => {
    // The run stops at START + FIVE_YEARS and the store begins 10 days later: the decade between the two
    // starts is not evidence of anything, so the reach is the longer of the two continuous stretches and the
    // gap is named rather than smoothed.
    const horizon = foldProvableHorizon({
      run: run(START, START + FIVE_YEARS),
      live: live(START + FIVE_YEARS + 10 * DAY, START + FIVE_YEARS + 40 * DAY - 1),
    });

    expect(horizon?.continuous).toBe(false);
    expect(horizon?.gaps).toEqual([{ from: START + FIVE_YEARS, toExclusive: START + FIVE_YEARS + 10 * DAY }]);
    expect(horizon?.seconds, 'the run reaches five years and the live window 30 days').toBe(FIVE_YEARS);
    expect(horizon?.from).toBe(START);
    expect(horizon?.toExclusive).toBe(START + FIVE_YEARS);
  });

  it('refuses a store whose zero window says it holds nothing', () => {
    // An empty store reports from 0 and to 0. Read as a window that would start the horizon at the epoch and
    // state more than half a century of reach, which is the shape this fault exists to refuse.
    const fault = horizonFault({ live: live(0, 0) });

    expect(fault).not.toBeNull();
    expect(fault).toContain('zero window');
    expect(foldProvableHorizon({ live: live(0, 0) })).toBeNull();
  });

  it('refuses a reading with no evidence source at all', () => {
    expect(horizonFault({})).toContain('no sealed run and no live window');
    expect(foldProvableHorizon({})).toBeNull();
  });

  it('refuses a window that does not run forwards rather than stating a negative reach', () => {
    expect(horizonFault({ live: live(START, START - DAY) })).toContain('runs backwards');
    expect(horizonFault({ run: run(START + DAY, START) })).toContain('runs backwards');
    expect(foldProvableHorizon({ live: live(START, START - DAY) })).toBeNull();
  });

  it('takes the later stretch as the reach when it is the longer of the two', () => {
    // A deployment that sealed a month and has been running live for five years since. The two stretches do
    // not touch, so the answer is the live one, and a fold that merged the runs it opened with and then forgot
    // to carry the next one would report the month.
    const horizon = foldProvableHorizon({
      run: run(START, START + 30 * DAY),
      live: live(START + 40 * DAY, START + FIVE_YEARS),
    });

    expect(horizon?.continuous).toBe(false);
    expect(horizon?.gaps).toEqual([{ from: START + 30 * DAY, toExclusive: START + 40 * DAY }]);
    expect(horizon?.from).toBe(START + 40 * DAY);
    expect(horizon?.toExclusive).toBe(START + FIVE_YEARS + 1);
    expect(horizon?.seconds).toBe(FIVE_YEARS + 1 - 40 * DAY);
  });

  it('carries the run and the live window as two segments in the order the evidence falls', () => {
    // The segments are what a reviewer reads to see which part of the reach came from which artifact: the
    // sealed run states its own half-open window, and the live store's inclusive end is converted here
    // rather than left for the reader to guess.
    const horizon = foldProvableHorizon({
      run: run(START, START + FIVE_YEARS),
      live: live(START + FIVE_YEARS, START + FIVE_YEARS + 6 * DAY - 1),
    });

    expect(horizon?.segments).toEqual([
      { source: 'sealed-run', from: START, toExclusive: START + FIVE_YEARS },
      { source: 'live-window', from: START + FIVE_YEARS, toExclusive: START + FIVE_YEARS + 6 * DAY },
    ]);
    expect(horizon?.continuous, 'the store opens exactly where the run closes').toBe(true);
  });
});
