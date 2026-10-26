import { describe, expect, it } from 'vitest';
import { MINIMUM_RETENTION_DAYS } from '../src/aclog.js';
import {
  ACCESS_LOG_EDGE,
  RECEIPTS_EDGE,
  daysToSeconds,
  decideDutyWindow,
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
