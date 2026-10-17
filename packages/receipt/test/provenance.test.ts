import { describe, expect, it } from 'vitest';
import { PROVENANCES, isProvenance, reduceProvenance, type Provenance } from '../src/provenance.js';

/**
 * The provenance vocabulary and its reduction, held as the matrix the design states rather than as three
 * sentences that agree.
 *
 * The rule "live software never becomes hardware evidence; a captured original can retain valid hardware
 * evidence" is a statement about combinations, so the cases below walk combinations: every pair of the
 * three values with its weakened result written out, the three-item corners, and a sweep over all
 * twenty-seven combinations of a three-item container asserting the properties the rule names. The
 * pack's reader and the fixtures generator call the same function this file asks, so a case here is a
 * case about both of them at once.
 */

/** The three values as this file spells them, written out rather than read from the constant under test. */
const LIVE: Provenance = 'live';
const CAPTURED: Provenance = 'captured';
const FIXTURE: Provenance = 'fixture';

describe('the provenance vocabulary', () => {
  it('is the three values in the order the formats write them, strongest first', () => {
    expect([...PROVENANCES]).toEqual([LIVE, CAPTURED, FIXTURE]);
  });

  it('guards the values and refuses everything else, case and spelling alike', () => {
    for (const one of PROVENANCES) expect(isProvenance(one), `${one} is refused by its own guard`).toBe(true);
    for (const one of ['Live', ' live', 'live ', 'replayed', 'synthetic', 'captured-v2', '', 1, null, undefined]) {
      expect(isProvenance(one), `${String(one)} is read as a value`).toBe(false);
    }
  });
});

describe('the provenance reduction', () => {
  /**
   * Every pair, with the weakest value written out per row: the two same-value rows keep that value, a
   * fixture beside anything makes the fixture, and live beside captured is captured because the weakest
   * value wins and a captured original retains its value among live items.
   */
  const PAIRS: ReadonlyArray<readonly [Provenance, Provenance, Provenance]> = [
    [LIVE, LIVE, LIVE],
    [CAPTURED, CAPTURED, CAPTURED],
    [FIXTURE, FIXTURE, FIXTURE],
    [LIVE, CAPTURED, CAPTURED],
    [LIVE, FIXTURE, FIXTURE],
    [CAPTURED, FIXTURE, FIXTURE],
    [CAPTURED, LIVE, CAPTURED],
    [FIXTURE, LIVE, FIXTURE],
    [FIXTURE, CAPTURED, FIXTURE],
  ];

  it('reduces every pair to the weakest of the two, in either order', () => {
    for (const [first, second, weakest] of PAIRS) {
      expect(reduceProvenance([first, second]), `${first} and ${second} reduce to ${weakest}`).toBe(weakest);
    }
  });

  it('keeps a lone value as the reduction of a one-item run', () => {
    for (const one of PROVENANCES) expect(reduceProvenance([one])).toBe(one);
  });

  it('reduces the three-item corners the design names', () => {
    // Live software never becomes hardware evidence: a run of live items reduces to live, never to
    // captured, so no combination without a captured item can state hardware evidence.
    expect(reduceProvenance([LIVE, LIVE, LIVE])).toBe(LIVE);
    // A captured original retains valid hardware evidence: one captured item beside live ones keeps the
    // captured value rather than being washed down to live.
    expect(reduceProvenance([LIVE, CAPTURED, LIVE])).toBe(CAPTURED);
    // A fixture beside either weaker claim makes the whole fixture, which is the value a fixture-derived
    // container has to state inside itself.
    expect(reduceProvenance([CAPTURED, FIXTURE, LIVE])).toBe(FIXTURE);
    expect(reduceProvenance([FIXTURE, LIVE, LIVE])).toBe(FIXTURE);
  });

  it('is the weakest of every combination of three, and never a value the items did not carry', () => {
    // All twenty-seven combinations. The properties are the rule read three ways: the result is one of the
    // items' values, every item's value is at least as strong as the result, and the result is fixture
    // exactly when some item is, captured exactly when none is a fixture but some item is captured, and
    // live exactly when every item is.
    for (const first of PROVENANCES) {
      for (const second of PROVENANCES) {
        for (const third of PROVENANCES) {
          const items = [first, second, third];
          const label = items.join(', ');
          const reduced = reduceProvenance(items);
          expect(items, `${label} reduced to a value none of its items carried`).toContain(reduced);
          for (const one of items) {
            expect(
              PROVENANCES.indexOf(reduced),
              `${label} reduced to ${reduced}, stronger than the item ${one}`,
            ).toBeGreaterThanOrEqual(PROVENANCES.indexOf(one));
          }
          const expected = items.includes(FIXTURE) ? FIXTURE : items.includes(CAPTURED) ? CAPTURED : LIVE;
          expect(reduced, `${label}`).toBe(expected);
        }
      }
    }
  });

  it('refuses a reduction over no items rather than inventing a value for nothing', () => {
    // A container that carries no material states no provenance, which is why neither format asks this
    // question about an empty list: the pack and the two export arms that carry material each refuse an
    // empty array of items before a reduction is reached.
    expect(() => reduceProvenance([])).toThrow(/no weakest value/u);
  });
});
