import { describe, expect, it } from 'vitest';
import { MINIMUM_RETENTION_DAYS } from '../src/aclog.js';
import {
  ACCESS_LOG_EDGE,
  RECEIPTS_EDGE,
  daysToSeconds,
  decideDutyWindow,
  holdWindowNote,
  judgeWindow,
} from '../src/duty-window.js';
import type { CustomerInstructionRecord } from '../src/instruction-record.js';

/**
 * The one place that answers whether a window can hold the period a deployment states it owes.
 *
 * `gateway/src/duty-window.ts` owns the comparison and the one sentence the record-facing edges share, so
 * these cases weigh pairings of numbers and read the sentence back: which pairs come with no gap, which
 * come short and by how much, and what each edge's refusal names as the thing to raise. What a record is
 * made of, and what a run prints, live in `gateway/test/instruction-record.test.ts` and
 * `gateway/test/cli.test.ts` beside it; nothing here reads a file or boots a process.
 *
 * One shape is refused over and over because it is the one this unit exists to keep out: a floor. A stated
 * period of one second is weighed exactly as a stated period of fifty years is, because a window that
 * holds it is honourable and this repository is not the hand that names what a deployment owes.
 */
const path = 'ashaveri-instruction-record.json';

/** A record's two facts, with one of them changed per case and no reader between the case and the judge. */
function record(over: Partial<Omit<CustomerInstructionRecord, 'path' | 'digestHex'>> = {}): CustomerInstructionRecord {
  return {
    path,
    digestHex: 'ab'.repeat(32),
    statedRetentionDays: 184,
    acceptsMinimumFloor: false,
    ...over,
  };
}

describe('the one decision', () => {
  it('calls a window that holds the stated period honourable, on either side of equality', () => {
    expect(decideDutyWindow(daysToSeconds(184), daysToSeconds(184))).toBeNull();
    expect(decideDutyWindow(daysToSeconds(730), daysToSeconds(184))).toBeNull();
    expect(decideDutyWindow(0, 1)).toEqual({ windowSeconds: 0, statedSeconds: 1, shortBySeconds: 1 });
  });

  it('names the shortfall rather than a floor, and never refuses a short period on its own', () => {
    // A stated period of one second is as honourable as one of fifty years: this answers a pairing,
    // not a question about what the law requires.
    expect(decideDutyWindow(daysToSeconds(1), daysToSeconds(1))).toBeNull();
    expect(decideDutyWindow(daysToSeconds(3650), daysToSeconds(1))).toBeNull();
  });

  it('states the shortfall as the difference of the two numbers it was handed', () => {
    // The gap travels with the verdict so an edge can quote it without doing its own arithmetic; a second
    // copy of the subtraction is a second chance to answer one pairing two ways.
    expect(decideDutyWindow(daysToSeconds(100), daysToSeconds(184))).toEqual({
      windowSeconds: daysToSeconds(100),
      statedSeconds: daysToSeconds(184),
      shortBySeconds: daysToSeconds(84),
    });
  });

  it('refuses a receipts window shorter than the record, naming the flag it wants raised', () => {
    const verdict = judgeWindow(RECEIPTS_EDGE, 90, record({}), MINIMUM_RETENTION_DAYS);
    if (!verdict.refused) throw new Error('a receipts window shorter than the stated period was not refused');
    expect(verdict.answeredBy).toBe('the flags this run names');
    expect(verdict.message).toContain('--receipts-days gives the receipts store 90 days');
    expect(verdict.message).toContain('name --receipts-days 184 or more');
  });
});

describe('a window weighed against the record the deployment wrote', () => {
  it('refuses a window shorter than the period the record states, naming both numbers and both sources', () => {
    const judge = judgeWindow(
      ACCESS_LOG_EDGE,
      30,
      record({ statedRetentionDays: 184, acceptsMinimumFloor: false }),
      MINIMUM_RETENTION_DAYS,
    );
    if (!judge.refused) throw new Error('a window shorter than the stated period was not refused');
    expect(judge.message).toContain('--access-log-days gives this run 30 days');
    expect(judge.message).toContain(`${path} states 184 days as the period this deployment owes`);
    expect(judge.message).toContain('name --access-log-days 184 or more');
    expect(judge.answeredBy).toBe('the flags this run names');
  });

  it('obeys the window a record states and a longer one, and refuses one day short', () => {
    expect(
      judgeWindow(ACCESS_LOG_EDGE, 184, record({ statedRetentionDays: 184, acceptsMinimumFloor: false }), MINIMUM_RETENTION_DAYS)
        .refused,
    ).toBe(false);
    expect(
      judgeWindow(ACCESS_LOG_EDGE, 400, record({ statedRetentionDays: 184, acceptsMinimumFloor: false }), MINIMUM_RETENTION_DAYS)
        .refused,
    ).toBe(false);
    expect(
      judgeWindow(ACCESS_LOG_EDGE, 183, record({ statedRetentionDays: 184, acceptsMinimumFloor: false }), MINIMUM_RETENTION_DAYS)
        .refused,
    ).toBe(true);
  });

  it('obeys a period shorter than the floor when the record states it and declines the floor', () => {
    // The whole reason the record exists: a deployment that states its own shorter duty period is
    // enforcing what it wrote down, and nothing in here argues with the number it stated.
    expect(judgeWindow(ACCESS_LOG_EDGE, 45, record({ statedRetentionDays: 45 }), MINIMUM_RETENTION_DAYS)).toEqual({
      refused: false,
    });
  });

  it('refuses a record that accepts the floor while stating less than it, and names the record as what changes', () => {
    const judge = judgeWindow(
      ACCESS_LOG_EDGE,
      90,
      record({ statedRetentionDays: 90, acceptsMinimumFloor: true }),
      MINIMUM_RETENTION_DAYS,
    );
    if (!judge.refused) throw new Error('a record accepting a floor it states less than was not refused');
    expect(judge.answeredBy).toBe('the record itself');
    expect(judge.message).toContain(`accepts the ${MINIMUM_RETENTION_DAYS}-day floor as this deployment's own`);
    expect(judge.message).toContain('and states 90 days');
    expect(judge.message).toContain('the record contradicts itself');
  });

  it('weighs the window against the record and not against the floor, where the record states longer than the floor', () => {
    // A record that accepts the floor and states two years leaves a window of two hundred days refused
    // on the period it states, which is the number that deployment wrote; the floor is not the yardstick
    // this check holds, and a message that named it would quote the wrong figure back.
    const judge = judgeWindow(
      ACCESS_LOG_EDGE,
      200,
      record({ statedRetentionDays: 730, acceptsMinimumFloor: true }),
      MINIMUM_RETENTION_DAYS,
    );
    if (!judge.refused) throw new Error('a window shorter than a stated two years was not refused');
    expect(judge.message).toContain('states 730 days as the period this deployment owes');
    expect(judge.message).not.toContain(`${MINIMUM_RETENTION_DAYS} days as the period`);
  });
});

/**
 * The hold note one edge prints beside its judgement.
 *
 * A hold is a deployment's instruction to keep, and a window is a deployment's instruction about how
 * long it keeps: the two are stated apart and this file weighs only one pairing of numbers, so what a
 * hold may add to an edge is a sentence beside the verdict and nothing inside it. These cases hold the
 * sentence's own wording and the fact that the verdict does not move, which is the half of the contract
 * that says a hold never silently extends a period a deployment stated and never answers a shortfall.
 */
describe('the hold note beside a window', () => {
  const held = { path: 'hold-incident-7.json', digestHex: 'cd'.repeat(32) };

  it('states that held records are kept past the window named, and that neither number moves', () => {
    // The sentence is pinned whole rather than searched for fragments: the wording is the claim, and an
    // edit that folded the shortfall away or widened the stated period would still leave every fragment
    // this case could match on.
    expect(holdWindowNote(held, daysToSeconds(90))).toBe(
      `records under the hold at ${held.path} sha256 ${held.digestHex} are kept past the ${String(
        daysToSeconds(90),
      )} seconds this run configures while that hold is in force, and the hold changes neither that window ` +
        'nor the period this deployment stated: it answers no shortfall',
    );
  });

  it('names nothing when no hold is in force', () => {
    expect(holdWindowNote(null, daysToSeconds(90))).toBeNull();
  });

  it('names one record per call, so a caller handed two in-force records says two sentences', () => {
    // The sentence is about one hold's bytes and one window, which is what lets it be honest about both.
    // A deployment running two matters suspends that window twice, so the enumeration belongs to the
    // caller: neither of these two lines names the other, and a line that named only one of two would
    // read to an operator who handed both as the whole answer.
    const other = { path: 'hold-incident-8.json', digestHex: 'ef'.repeat(32) };
    const first = holdWindowNote(held, daysToSeconds(90)) ?? 'nothing';
    const second = holdWindowNote(other, daysToSeconds(90)) ?? 'nothing';
    expect(first).toContain(held.path);
    expect(first).not.toContain(other.path);
    expect(second).toContain(other.path);
    expect(second).not.toContain(held.path);
    expect(second).not.toBe(first);
    // Asked twice, and still only beside the pairing: two notes move neither number.
    expect(judgeWindow(RECEIPTS_EDGE, 90, record({}), MINIMUM_RETENTION_DAYS).refused).toBe(true);
  });

  it('leaves a window shorter than the stated period refused with the identical sentence beside an active hold', () => {
    // The note is asked before the pairing, so what a row can fail is a note that reaches the verdict. The
    // refusal is pinned whole, because "identical" here means the sentence this edge has always said: the
    // same shortfall and the same remedy, whichever hand holds a hold record. What the note may not do is
    // quote the stated period as though it had been met, which the two absences below measure. That a hold
    // moves no number inside the verdict is the `judgeWindow` rows above, weighed with no note asked at
    // all, and repeating that call twice here would compare one pure reading with itself.
    const note = holdWindowNote(held, daysToSeconds(90));
    if (note === null) throw new Error('an active hold handed the edge produced no note');
    const judge = judgeWindow(RECEIPTS_EDGE, 90, record({}), MINIMUM_RETENTION_DAYS);
    if (!judge.refused) throw new Error('a receipts window shorter than the stated period was not refused');
    expect(judge.message).toBe(
      `--receipts-days gives the receipts store 90 days and ${path} states 184 days as the period this ` +
        'deployment owes, so the window named at start-up is shorter than the period its own instruction ' +
        'record states; name --receipts-days 184 or more, or point --instruction-record at the record this ' +
        'deployment wrote',
    );
    expect(note).not.toContain('184');
    expect(note).not.toContain('so the shortfall is answered');
  });
});
