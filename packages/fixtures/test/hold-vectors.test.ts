import { describe, expect, it } from 'vitest';
import {
  HOLD_RECORD_LIMITS,
  HOLD_RECORD_TEXT_MAX_UNITS,
  HOLD_RECORD_V1_MEMBERS,
  HOLD_RECORD_VERSIONS,
  HOLD_RECORD_WINDOW_MEMBERS,
  ReceiptError,
  encodeHoldRecord,
  fromBase64Url,
  holdActiveAt,
  holdCoversStamp,
  holdRecordBytes,
  parseHoldRecord,
  refuseErasureUnderHold,
  toBase64Url,
  type HoldRecord,
} from '@ashaveri/receipt';
import { loadHoldVectors, type HoldConsultationVector } from '../src/index.js';

/**
 * The published hold vectors, replayed the way a port replays them: decode the record bytes, hand them to
 * the shipped reader, and answer the verdict the row promises. The accepted rows are written back through
 * the shipped writer too, so the bytes a port holds are the bytes this repository's own writer produces for
 * the record they parse to. The consultation rows are replayed at the door their `door` column names, over
 * the holds their row publishes as bytes rather than over any record assembled beside the file.
 *
 * Nothing here restates a rule. Every answer is what `parseHoldRecord`, `holdActiveAt`, `holdCoversStamp`
 * or `refuseErasureUnderHold` gave when the run reached it, which is what makes a hand-edited vector fail:
 * the published word is the only claim, and the shipped door is the only witness.
 */

const file = loadHoldVectors();

const decoded = (bytes: Uint8Array): string => new TextDecoder().decode(bytes);

function verdictOf(bytes: Uint8Array): string {
  try {
    parseHoldRecord(bytes);
    return 'verify-ok';
  } catch (err) {
    if (err instanceof ReceiptError) return err.code;
    throw err;
  }
}

const HONEST = file.vectors.find((one) => one.name === 'hold-fixture-v1');
if (HONEST === undefined) throw new Error('the family publishes no hold-fixture-v1 row to replay the others against');
const HONEST_BYTES = fromBase64Url(HONEST.recordBase64Url);

/** The holds one consultation row publishes, read back through the shipped reader as a caller would hand them. */
function holdsOf(one: HoldConsultationVector) {
  return one.holdsBase64Url.map((bytes) => parseHoldRecord(fromBase64Url(bytes)));
}

/** What the door this row names answers, computed here rather than read from beside it. */
function answerOf(one: HoldConsultationVector): string {
  const holds = holdsOf(one);
  if (one.door === 'erasure') {
    if (one.call.credential === undefined) throw new Error(`${one.name}: an erasure row states no credential`);
    try {
      refuseErasureUnderHold(holds, one.call.credential, one.call.at);
      return 'verify-ok';
    } catch (err) {
      if (err instanceof ReceiptError && err.code === 'HOLD_ERASURE_REFUSED') return err.code;
      throw err;
    }
  }
  const [only] = holds;
  if (holds.length !== 1 || only === undefined) {
    const stated = String(holds.length);
    throw new Error(`${one.name}: a ${one.door} row is answered by one hold, and this publishes ${stated}`);
  }
  if (one.door === 'active') return holdActiveAt(only, one.call.at) ? 'active' : 'inactive';
  if (one.call.iat === undefined) throw new Error(`${one.name}: a coverage row states no record stamp`);
  return holdCoversStamp(only, one.call.iat, one.call.at) ? 'covers' : 'does-not-cover';
}

function rowNamed(name: string): HoldConsultationVector {
  const found = file.consultations.find((one) => one.name === name);
  if (found === undefined) throw new Error(`the family publishes no consultation row named ${name}`);
  return found;
}

/** One layout row by name, and the record it publishes read back through the shipped reader. */
function layoutNamed(name: string): HoldRecord {
  const found = file.vectors.find((one) => one.name === name);
  if (found === undefined) throw new Error(`the family publishes no layout row named ${name}`);
  return parseHoldRecord(fromBase64Url(found.recordBase64Url));
}

/** The credential the honest record names first, read out of its own bytes rather than typed beside them. */
const HELD_CREDENTIAL = parseHoldRecord(HONEST_BYTES).credentials![0]!;

describe('the hold family states the shipped rule', () => {
  it('publishes the versions, members, limits and text bound the package declares', () => {
    expect(file.rule.versions).toEqual([...HOLD_RECORD_VERSIONS]);
    expect(file.rule.members).toEqual([...HOLD_RECORD_V1_MEMBERS]);
    expect(file.rule.windowMembers).toEqual([...HOLD_RECORD_WINDOW_MEMBERS]);
    expect(file.rule.limits).toBe(HOLD_RECORD_LIMITS);
    expect(file.rule.textMaxUnits).toBe(HOLD_RECORD_TEXT_MAX_UNITS);
    expect(file.rule.reader).toBe('parseHoldRecord in @ashaveri/receipt');
    expect(file.rule.writer).toBe('holdRecordBytes in @ashaveri/receipt');
  });

  it('names the three doors, and every row answers at one of them', () => {
    expect(file.rule.consultations).toEqual({
      active: 'holdActiveAt in @ashaveri/receipt',
      coverage: 'holdCoversStamp in @ashaveri/receipt',
      erasure: 'refuseErasureUnderHold in @ashaveri/receipt',
    });
    const doors = new Set(file.consultations.map((one) => one.door));
    expect([...doors].sort()).toEqual(['active', 'coverage', 'erasure']);
    expect(file.consultations.length).toBeGreaterThan(0);
  });

  it('publishes no key material, because the record carries no signature', () => {
    // The check is on the members a file would carry key material under, not on the word: this family's
    // prose says out loud that the record is unsigned, and a test that read that as a secret would refuse
    // the very sentence that tells a port not to look for one.
    const members = new Set<string>();
    const walk = (value: unknown): void => {
      if (Array.isArray(value)) {
        for (const item of value) walk(item);
        return;
      }
      if (value !== null && typeof value === 'object') {
        for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
          members.add(key);
          walk(item);
        }
      }
    };
    walk(file);
    const keyMaterial = [
      'publicKey',
      'publicKeyBase64Url',
      'publicKeyHex',
      'privateKey',
      'seed',
      'kid',
      'kidHex',
      'signature',
    ];
    for (const member of keyMaterial) {
      expect(members.has(member), `the family publishes ${member}, and a hold record is unsigned`).toBe(false);
    }
    expect(file.rule.unsigned).toContain('no signature');
  });

  it('states its instants beside the window the records carry', () => {
    const honest = parseHoldRecord(HONEST_BYTES);
    expect(file.rule.instants.issue).toBe(honest.at);
    expect(file.rule.instants.windowFrom).toBe(honest.window.from);
    expect(file.rule.instants.windowTo).toBe(honest.window.to);
    expect(file.rule.instants.receiptFixtureStamp).toBe(honest.at);
    expect(file.rule.instants.released).toBe(layoutNamed('hold-released-v1').released);
  });
});

describe('the hold layout rows replay', () => {
  for (const one of file.vectors) {
    it(`${one.name} answers ${one.expected}`, () => {
      const bytes = fromBase64Url(one.recordBase64Url);
      expect(bytes.length).toBe(one.recordByteLength);
      expect(verdictOf(bytes)).toBe(one.expected);
      if (one.expected !== 'verify-ok') return;
      const parsed = parseHoldRecord(bytes);
      expect(encodeHoldRecord(parsed)).toEqual(bytes);
      expect(holdRecordBytes(parsed)).toEqual(bytes);
      expect(parsed.prov).toBe('fixture');
      expect(parsed.limits).toBe(HOLD_RECORD_LIMITS);
    });
  }

  it('writes the accepted record in the member order the layout declares', () => {
    const document = JSON.parse(decoded(HONEST_BYTES)) as Record<string, unknown>;
    expect(Object.keys(document)).toEqual([...HOLD_RECORD_V1_MEMBERS]);
    expect(Object.keys(document['window'] as object)).toEqual([...HOLD_RECORD_WINDOW_MEMBERS]);
  });

  it('refuses with one of the two codes this layout can answer, and names where', () => {
    // The layout names no pointer registry, so a document is refused for its version or for its shape and
    // for nothing else. A row naming any other code is a row about a rule this reader does not have.
    const refusals = file.vectors.filter((one) => one.expected !== 'verify-ok');
    expect(refusals.length).toBeGreaterThan(0);
    const codes = ['HOLD_RECORD_UNSUPPORTED_VERSION', 'HOLD_RECORD_BAD_DOCUMENT'];
    for (const one of refusals) {
      expect(codes, `${one.name} names ${one.expected}`).toContain(one.expected);
      expect(one.fault, `${one.name} states no fault block`).toBeDefined();
      expect(fromBase64Url(one.recordBase64Url)).not.toEqual(HONEST_BYTES);
    }
    expect(refusals.filter((one) => one.expected === 'HOLD_RECORD_UNSUPPORTED_VERSION').length).toBe(1);
  });

  it('measures the authored-text bound at the unit either side of the ceiling', () => {
    const at = layoutNamed('hold-reason-at-width-limit-v1');
    const wide = file.vectors.find((one) => one.name === 'hold-reason-one-unit-wide-v1');
    expect(wide, 'the family publishes no row one unit past the ceiling').toBeDefined();
    expect(at.reason.length).toBe(HOLD_RECORD_TEXT_MAX_UNITS);
    const wideDocument = JSON.parse(decoded(fromBase64Url(wide!.recordBase64Url))) as { reason: string };
    expect(wideDocument.reason.length).toBe(HOLD_RECORD_TEXT_MAX_UNITS + 1);
    expect(verdictOf(fromBase64Url(wide!.recordBase64Url))).toBe('HOLD_RECORD_BAD_DOCUMENT');
  });

  it('pins the open hold to the two absences its name claims', () => {
    // The row is named for what it leaves out, and nothing in the published bytes says so: an accepted row
    // whose content could be swapped for the two-credential record would keep every verdict above green
    // while its name and its note became false. Absence is read here as the record's own statement, the way
    // the consultation rows read it, so the omission is a fact of the bytes rather than a word beside them.
    const open = layoutNamed('hold-covers-every-credential-v1');
    expect(open.credentials, 'the row that covers every credential names some').toBeUndefined();
    expect(open.window.to, 'the row with an open window end states one').toBeNull();
    expect('credentials' in open, 'the parsed record carries the member the layout lets a record leave off').toBe(
      false,
    );
  });
});

describe('the hold consultation rows replay', () => {
  for (const one of file.consultations) {
    it(`${one.name} answers ${one.expected} at the ${one.door} door`, () => {
      expect(answerOf(one)).toBe(one.expected);
      for (const bytes of one.holdsBase64Url) {
        const hold = parseHoldRecord(fromBase64Url(bytes));
        // A published hold is a fixture record and the writer reproduces its own bytes, so no row is
        // answered by a document this repository's writer would not emit.
        expect(toBase64Url(holdRecordBytes(hold))).toBe(bytes);
      }
    });
  }

  it('refuses an erasure by naming the credential and the hold that suspends it', () => {
    for (const one of file.consultations) {
      if (one.expected !== 'HOLD_ERASURE_REFUSED') continue;
      const held = one.call.credential;
      expect(held, `${one.name} is an erasure row stating no credential`).toBeDefined();
      let caught: unknown;
      try {
        refuseErasureUnderHold(holdsOf(one), held!, one.call.at);
      } catch (err) {
        caught = err;
      }
      expect(caught).toBeInstanceOf(ReceiptError);
      const message = (caught as ReceiptError).message;
      expect(message).toContain(held!);
      // The issue stamp and the author a refusal quotes are read out of the published holds themselves, so
      // the sentence points at an instruction a reviewer can find rather than at a number typed beside it.
      const suspends = (hold: HoldRecord): boolean =>
        holdActiveAt(hold, one.call.at) && (hold.credentials === undefined || hold.credentials.includes(held!));
      const named = holdsOf(one).filter(suspends);
      expect(named.length).toBeGreaterThan(0);
      expect(message).toContain(String(named[0]!.at));
      expect(message).toContain(named[0]!.by);
    }
  });

  it('draws each boundary at one instant, with the same bytes on both sides', () => {
    // Four pairs, each two rows over one hold whose only difference is the instant in the call: the moment
    // the erasure is weighed at, or the stamp a coverage call asks about. A boundary is a fact about one
    // second, and a row published alone states a value rather than a bound: these are the pairs that refuse
    // a reader who moves a comparison by one step in either direction.
    const pairs: readonly [string, string][] = [
      ['erasure-one-second-before-issue-allowed', 'erasure-at-issue-instant-refused'],
      ['erasure-one-second-before-release-refused', 'erasure-at-release-instant-allowed'],
      ['active-one-second-before-release-active', 'active-at-release-instant-inactive'],
      ['coverage-last-instant-inside-window-covers', 'coverage-window-end-exclusive-does-not-cover'],
    ];
    for (const [before, after] of pairs) {
      const one = rowNamed(before);
      const other = rowNamed(after);
      expect(one.door, `${before} and ${after} are meant to be the same door`).toBe(other.door);
      expect(other.holdsBase64Url, `${before} and ${after} are meant to read one hold`).toEqual(one.holdsBase64Url);
      expect(other.call, `${before} and ${after} state no call to differ at`).not.toEqual(one.call);
      expect(other.expected, `${before} and ${after} answer the same way, so one boundary is misstated`).not.toBe(
        one.expected,
      );
    }
  });

  it('weighs the window at the coverage door and declines to weigh it at the erasure door', () => {
    // One record, two doors, two answers. This is the pair the module's comment states and the only shape
    // that shows a port which arm read the window: an erasure of a credential a hold names is suspended
    // however far the call's instant sits outside the window, because an erasure takes the whole of a
    // credential's material at once.
    const erasure = rowNamed('erasure-window-not-weighed-refused');
    const coverage = rowNamed('coverage-past-window-does-not-cover');
    expect(coverage.holdsBase64Url).toEqual(erasure.holdsBase64Url);
    expect(erasure.expected).toBe('HOLD_ERASURE_REFUSED');
    expect(coverage.expected).toBe('does-not-cover');
    const [hold] = holdsOf(coverage);
    expect(holdCoversStamp(hold!, coverage.call.iat!, coverage.call.at)).toBe(false);
    expect(holdActiveAt(hold!, erasure.call.at)).toBe(true);
  });

  it('scans every hold a caller is handed rather than the first one it meets', () => {
    const two = rowNamed('erasure-second-hold-of-the-list-names-it-refused');
    expect(two.holdsBase64Url.length).toBe(2);
    const holds = holdsOf(two);
    const [first, second] = holds;
    expect(holdActiveAt(first!, two.call.at)).toBe(true);
    expect(first!.credentials).not.toContain(two.call.credential!);
    expect(second!.credentials).toContain(two.call.credential!);
    expect(() => refuseErasureUnderHold([first!], two.call.credential!, two.call.at)).not.toThrow();
    expect(() => refuseErasureUnderHold(holds, two.call.credential!, two.call.at)).toThrow(
      expect.objectContaining({ code: 'HOLD_ERASURE_REFUSED' }),
    );
  });

  it('reads an omitted credentials member as every credential and an empty list as no document', () => {
    const open = rowNamed('erasure-open-hold-covers-every-credential-refused');
    const [hold] = holdsOf(open);
    expect(hold!.credentials).toBeUndefined();
    expect(open.call.credential).not.toBe(HELD_CREDENTIAL);
    const emptyList = file.vectors.find((one) => one.name === 'hold-empty-credentials-v1');
    expect(verdictOf(fromBase64Url(emptyList!.recordBase64Url))).toBe('HOLD_RECORD_BAD_DOCUMENT');
  });

  it('lifts a suspension with the record alone, and never by editing one', () => {
    // The released rows answer for one pair of bytes: the only thing that moved is the instant. A port that
    // needs a rewritten record to let an erasure through has not implemented the release at all.
    const released = rowNamed('erasure-at-release-instant-allowed');
    const [hold] = holdsOf(released);
    expect(hold!.released).toBe(file.rule.instants.released);
    expect(released.holdsBase64Url).toEqual(rowNamed('erasure-one-second-before-release-refused').holdsBase64Url);
    expect(answerOf(released)).toBe('verify-ok');
  });
});
