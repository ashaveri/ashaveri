import { afterAll, describe, expect, it } from 'vitest';
import fc from 'fast-check';
import net, { type AddressInfo } from 'node:net';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { newBearerCredential } from '../src/access.js';
import {
  ACCESS_RECORD_FIELDS,
  MAX_ACCESS_FILE_BYTES,
  openFileAccessLog,
  parseAccessLine,
  renderAccessLine,
  type AccessRecord,
  type AccessWindow,
} from '../src/aclog.js';
import { generated, harness } from './helpers.js';

/**
 * What one line of the access log is, in both directions, and what keeps a refusal to one line on the way
 * out. `renderAccessLine` writes the twelve allowlisted fields through `JSON.stringify` and appends a line
 * feed; `parseAccessLine` reads them back and refuses anything else; `window()` reads a whole day file and
 * counts the lines it can parse. `aclog.test.ts` already pins the field allowlist from the bytes and
 * round-trips one fixed record, so nothing here repeats that. These walk the shapes between the two, then
 * ask the same question of the two surfaces that put a refusal in front of a client.
 */

/** Set from the environment so a red run replays exactly: `FC_SEED=1234` on the package's test run. */
const SEED = Number(process.env['FC_SEED'] ?? '20260918');

/** Kept low enough that the file runs in seconds; the pinned examples carry the named edges. */
const RUNS = Number(process.env['FC_RUNS'] ?? '300');

/**
 * The field length that stands for as wide as a caller can hand the writer. The writer has no cap, so the
 * widest case worth drawing is wider than the file rotation trigger, which is the number that says a
 * rotation limit does not bound a read. `FC_BIG_FIELD=1000` makes the gates that use it cheap.
 */
const BIG_FIELD = Number(process.env['FC_BIG_FIELD'] ?? '34000000');

/** How deep a non-record this file hands the reader before it asks what that cost. */
const NEST_DEPTH = Number(process.env['FC_NEST_DEPTH'] ?? '20000');

const STARTED_AT = performance.now();
let propertyCalls = 0;
let predicateCalls = 0;

/** What this file measured rather than argued, printed once by `afterAll` so a log line stays greppable. */
const measured: string[] = [];

function measure(text: string): void {
  measured.push(text);
}

/**
 * `fc.assert` fires the predicate `runs` times in total, and the pinned examples are the first
 * `examples.length` of those firings rather than extra runs on top of them. Measured on 4.10.1 at two
 * seeds: 10 runs with 3 examples is 10 firings, and 0 runs with 1 example is no firing at all. So this
 * counter is the call count, and adding the examples to it would double count every pinned case.
 */
function check<T>(arbitrary: fc.Arbitrary<T>, examples: readonly T[], predicate: (value: T) => boolean, runs: number = RUNS): void {
  propertyCalls += 1;
  predicateCalls += runs;
  fc.assert(fc.property(arbitrary, predicate), {
    numRuns: runs,
    seed: SEED,
    examples: examples.map((each) => [each] as [T]),
  });
}

const LF = '\n';
const CR = '\r';
/**
 * Named by code point rather than spelled into the file, so the bytes of this test source cannot depend on
 * how a checkout decoded them.
 */
const LINE_SEPARATOR = String.fromCharCode(0x2028);
const PARAGRAPH_SEPARATOR = String.fromCharCode(0x2029);
const DEL = String.fromCharCode(0x7f);
const ACCENT = String.fromCharCode(0xe9);
const SNOWMAN = String.fromCodePoint(0x1f300);
const ZERO_WIDTH_SPACE = String.fromCharCode(0x200b);
const BOM = String.fromCharCode(0xfeff);

/**
 * The definition every one-line claim here is written against: four characters, not two. A JSON escaper
 * folds the first pair and leaves the second pair raw, and that difference is the subject of the last
 * section of this file, so all four are counted everywhere.
 */
const ANY_LINE = new RegExp('[\\n\\r\\u2028\\u2029]', 'u');

function linesOf(text: string): number {
  return text.split(ANY_LINE).length;
}

/** How many line breaks of any of the four kinds the text holds, counted by occurrence rather than by kind. */
function breaksOf(text: string): number {
  return text.split(ANY_LINE).length - 1;
}

/**
 * The two the writer cannot escape. `JSON.stringify` folds a line feed and a carriage return into a
 * two-character escape and writes the pair below as the bytes they are, so this is the only half of the
 * definition a drawn field value can move.
 */
function rawSeparatorsOf(text: string): number {
  return text.split(LINE_SEPARATOR).length - 1 + text.split(PARAGRAPH_SEPARATOR).length - 1;
}

const T0 = 1_772_000_000_000;
const DAY = new Date(T0).toISOString().slice(0, 10);

function entry(overrides: Partial<AccessRecord> = {}): AccessRecord {
  return {
    t: T0,
    rid: 'req-1',
    cred: 'svc-1',
    auth: 'pop',
    scope: 'complete',
    m: 'POST',
    p: '/v1/chat/completions',
    rcp: null,
    nce: 'AAAAAAAAAAAAAAAAAAAAAA',
    st: 200,
    dur: 12,
    deny: null,
    ...overrides,
  };
}

async function tempDir(): Promise<string> {
  return mkdtemp(join(tmpdir(), 'ashaveri-access-line-'));
}

function partName(day: string, part: number): string {
  return `access-${day}-${String(part).padStart(3, '0')}.jsonl`;
}

/**
 * What `window()` answers for a day file holding exactly these bytes. The log is opened and closed around
 * the read and never written to, so the sweep behind a `record()` cannot be what a count here depends on.
 */
async function windowOver(contents: string): Promise<AccessWindow> {
  const dir = await tempDir();
  await writeFile(join(dir, partName(DAY, 0)), contents, 'utf8');
  const log = await openFileAccessLog({ dir, days: 184, now: () => T0 });
  const seen = await log.window();
  await log.close();
  await rm(dir, { recursive: true, force: true });
  return seen;
}

/** The twelve fields, compared by name so a failing draw says which one moved. */
function differences(written: AccessRecord, read: AccessRecord): string[] {
  const moved: string[] = [];
  for (const field of ACCESS_RECORD_FIELDS) {
    if (written[field] !== read[field]) moved.push(field);
  }
  return moved;
}

/**
 * The reader's own idea of a whole record, rebuilt here rather than borrowed from the parser, so a gate
 * can say that what came back was a record without asking the thing that produced it. A returned value
 * that fails this is a partial record in a caller's hands, which is the defect the refusal half is
 * looking for.
 */
const NUMBER_FIELDS: readonly string[] = ['t', 'st', 'dur'];
const STRING_FIELDS: readonly string[] = ['rid', 'm', 'p'];
const NULLABLE_FIELDS: readonly string[] = ['cred', 'scope', 'rcp', 'nce', 'deny'];

function wholeRecord(value: unknown): boolean {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const raw = value as Record<string, unknown>;
  if (Object.keys(raw).length !== ACCESS_RECORD_FIELDS.length) return false;
  for (const field of ACCESS_RECORD_FIELDS) {
    const held: unknown = raw[field];
    if (NUMBER_FIELDS.includes(field)) {
      if (typeof held !== 'number') return false;
    } else if (STRING_FIELDS.includes(field)) {
      if (typeof held !== 'string') return false;
    } else if (field === 'auth') {
      if (held !== null && held !== 'pop' && held !== 'bearer') return false;
    } else if (NULLABLE_FIELDS.includes(field)) {
      if (typeof held !== 'string' && held !== null) return false;
    } else {
      return false;
    }
  }
  return true;
}

interface Outcome {
  threw: boolean;
  value: unknown;
  message: string;
}

/** Parse, and keep what the reader answered instead of letting a throw end the case. */
function tryParse(text: string): Outcome {
  try {
    return { threw: false, value: parseAccessLine(text), message: '' };
  } catch (err) {
    return { threw: true, value: undefined, message: err instanceof Error ? err.message : String(err) };
  }
}

/** Text a caller may hand a field: line endings, JSON metacharacters, controls and astral pairs. */
const HOSTILE_UNIT = fc.constantFrom(
  ...[...'abzAZ019-_./"\\=?&#: %', '\t', '\0', DEL, ACCENT, ZERO_WIDTH_SPACE, BOM, SNOWMAN, LF, CR, LINE_SEPARATOR, PARAGRAPH_SEPARATOR],
);

const hostileText = fc.array(HOSTILE_UNIT, { maxLength: 24 }).map((parts) => parts.join(''));

/** Every field type the parser reads: a number, a string, and a string that may be null. */
const drawnNumber = fc.oneof(
  fc.integer({ min: -2_147_483_648, max: 4_102_444_800_000 }),
  fc.integer({ min: 0, max: 1_000_000 }).map((each) => each / 4),
  fc.constantFrom(0, 1, -1, 9_007_199_254_740_991, 1e21, 5e-324, Number.MAX_VALUE, -Number.MAX_VALUE, 0.1),
);

const drawnText = fc.oneof(fc.constant(''), hostileText, fc.array(fc.constantFrom(...[...'abc/:-_']), { maxLength: 40 }).map((parts) => parts.join('')));

const drawnNullable = fc.oneof(fc.constant<string | null>(null), drawnText);

const drawnAuth = fc.oneof(fc.constant<'pop' | 'bearer' | null>(null), fc.constant<'pop' | 'bearer' | null>('pop'), fc.constant<'pop' | 'bearer' | null>('bearer'));

const recordArbitrary: fc.Arbitrary<AccessRecord> = fc.record({
  t: drawnNumber,
  rid: drawnText,
  cred: drawnNullable,
  auth: drawnAuth,
  scope: drawnNullable,
  m: drawnText,
  p: drawnText,
  rcp: drawnNullable,
  nce: drawnNullable,
  st: drawnNumber,
  dur: drawnNumber,
  deny: drawnNullable,
});

/** The record with the widest field a caller can hand the writer, which has no cap to reach. */
function widestEntry(): AccessRecord {
  return entry({ p: 'x'.repeat(BIG_FIELD), rid: 'y'.repeat(BIG_FIELD), deny: LINE_SEPARATOR + 'z'.repeat(1_024) });
}

/**
 * One value per oracle that is *not* the kind the field reads for. `1.5` is deliberately absent from the
 * number row: the reader checks the kind, not integrality, and a fractional number is the kind it asks
 * for. The gate below this block pins that as a choice rather than an oversight.
 */
const NOT_A_NUMBER = fc.constantFrom<unknown>('0', true, null, [], {});
const NOT_A_STRING = fc.constantFrom<unknown>(0, true, null, [], {}, 1.5);
const NOT_A_STRING_OR_NULL = fc.constantFrom<unknown>(0, true, [], {}, 1.5);
const NOT_POP_OR_BEARER_OR_NULL = fc.constantFrom<unknown>('pop ', 'PoP', 'POP', 'unpop', `pop${LF}`, '', 0, [], true, {});

function wrongTypeFor(field: string): fc.Arbitrary<unknown> {
  if (NUMBER_FIELDS.includes(field)) return NOT_A_NUMBER;
  if (STRING_FIELDS.includes(field)) return NOT_A_STRING;
  if (field === 'auth') return NOT_POP_OR_BEARER_OR_NULL;
  return NOT_A_STRING_OR_NULL;
}

/**
 * One of the three ways a line stops being a record: a name the allowlist does not carry, a name it does
 * carry that went missing, and a name whose value is the wrong kind, which for `auth` includes a string
 * that is neither pop, nor bearer, nor null. The mutations run on the bytes the writer produced, so a case
 * cannot pass by never having been a record in the first place.
 */
type Shape = { readonly kind: 'extra' | 'missing' | 'wrong-type'; readonly field: string; readonly value?: unknown };

const shapeArbitrary: fc.Arbitrary<Shape> = fc.oneof(
  fc.record({ kind: fc.constant<'extra'>('extra'), field: hostileText.filter((each) => !ACCESS_RECORD_FIELDS.includes(each as keyof AccessRecord)) }),
  fc.record({ kind: fc.constant<'missing'>('missing'), field: fc.constantFrom(...ACCESS_RECORD_FIELDS) }),
  fc.constantFrom(...ACCESS_RECORD_FIELDS).chain((field) => wrongTypeFor(field).map((value) => ({ kind: 'wrong-type' as const, field, value }))),
);

function lineFor(shape: Shape): string {
  const written = JSON.parse(renderAccessLine(entry())) as Record<string, unknown>;
  if (shape.kind === 'extra') {
    written[shape.field] = 1;
  } else if (shape.kind === 'missing') {
    delete written[shape.field];
  } else {
    written[shape.field] = shape.value;
  }
  return JSON.stringify(written);
}

/** Which sentence a refusal owes for which shape, and the name it has to put in that sentence. */
function refusalSays(shape: Shape, message: string): boolean {
  if (shape.kind === 'extra') {
    return message.includes('unknown field') && (shape.field.length === 0 || message.includes(shape.field));
  }
  if (shape.kind === 'missing') {
    return message.includes('missing field') && message.includes(shape.field);
  }
  if (shape.field === 'auth') {
    return message.includes('auth') && /neither a string nor null|neither pop, bearer, nor null/u.test(message);
  }
  return message.includes(shape.field) && /is not a number|is not a string|neither a string nor null/u.test(message);
}

describe('what a written line reads back as', () => {
  it('reads back every record the writer can produce', () => {
    check(recordArbitrary, [entry(), { ...entry(), cred: null, auth: null, scope: null, rcp: null, nce: null, deny: null }, { ...entry(), rid: '', cred: '', scope: '', m: '', p: '', nce: '', deny: '' }, widestEntry()], (written) => {
      const text = renderAccessLine(written);
      const read = parseAccessLine(text);
      // The empty-string record is the one an allowlist read out of a caller could turn into a null, and
      // the widest field is the one a length cap nobody wrote would have refused: both are in the draws.
      return differences(written, read).length === 0 && Object.keys(read).length === ACCESS_RECORD_FIELDS.length;
    });
  });

  it('refuses a shape that is not a record, and hands the caller nothing to read', () => {
    check(shapeArbitrary, [], (shape) => {
      const answered = tryParse(lineFor(shape));
      // A refusal is a throw with a sentence naming what moved, and never a returned object with holes in
      // it: a caller that got a value back got a record.
      if (!answered.threw) return false;
      return answered.value === undefined && refusalSays(shape, answered.message);
    });
  });

  it('takes a number field on its kind, not its integrality, and says so for every shape', () => {
    // The reader asks `typeof value === 'number'` and stops there, so a fractional duration reads back as
    // the fraction it was written as. That is the rule this file now pins instead of tripping over: an
    // integer-only reader would refuse a line that is merely odd, and a line the reader refuses is a line
    // `window()` counts as corruption, which is the state the scrub treats as a reason not to delete. The
    // check buys nothing against a caller who can write a fraction and could as easily write an integer,
    // while it can cost a real deployment an unparseable day.
    const fractions = [1.5, 0.1, -0.5, 5e-324, 1e21, Number.MAX_VALUE, -Number.MAX_VALUE] as const;
    for (const field of ['t', 'st', 'dur'] as const) {
      for (const value of fractions) {
        const written = entry({ [field]: value });
        const text = renderAccessLine(written);
        const read = parseAccessLine(text);
        expect(Object.is(read[field], value), `${field}=${String(value)}`).toBe(true);
        expect(differences(written, read), `${field}=${String(value)}`).toEqual([]);
      }
      for (const value of ['0', true, null, [], {}] as const) {
        const answered = tryParse(lineFor({ kind: 'wrong-type', field, value }));
        expect(answered.threw, `${field}=${String(value)}`).toBe(true);
      }
    }
    measure('parseAccessLine checks a number field by kind: every finite double round-trips exactly, and only a non-number is refused');
  });

  it('returns a whole record or nothing at all, whatever JSON text it is handed', () => {
    const jsonText = fc.oneof(
      fc.array(HOSTILE_UNIT, { maxLength: 60 }).map((parts) => parts.join('')),
      fc.constantFrom(
        'null',
        'true',
        '0',
        '-1',
        '""',
        '"pop"',
        '[]',
        '{}',
        '[1,2,3]',
        '[[[[[[1]]]]]]',
        '{"a":1}',
        '{"t":1}',
        '{"__proto__":{"polluted":true}}',
        renderAccessLine(entry()).trimEnd(),
        renderAccessLine(entry()).trimEnd().slice(0, 40),
        '   ',
        '',
      ),
    );
    check(jsonText, [], (text) => {
      const answered = tryParse(text);
      // Either the reader threw, or what it gave back is a complete record: there is no third answer,
      // which is the whole of "refusal without a partial record" stated from the bytes.
      if (answered.threw) return true;
      return wholeRecord(answered.value);
    });
  });

  it('refuses a number the writer cannot spell and blames the field, not the line', () => {
    for (const field of NUMBER_FIELDS) {
      for (const unusable of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
        const written = { ...entry(), [field]: unusable } as AccessRecord;
        const text = renderAccessLine(written);
        const answered = tryParse(text.trimEnd());
        // `JSON.stringify` writes null for all three, so the reader is right to say the field is not a
        // number rather than hand back a record with a null where a timestamp belongs.
        expect(answered.threw, `${field}=${String(unusable)}`).toBe(true);
        expect(answered.message, `${field}=${String(unusable)}`).toContain(field);
        expect(answered.message).toMatch(/is not a number/u);
      }
    }
    // Minus zero is the one number that survives the writer as a different number: it is spelled "0".
    const signed = renderAccessLine({ ...entry(), st: -0 } as AccessRecord);
    expect(signed).toContain('"st":0');
    expect(parseAccessLine(signed).st).toBe(0);
    expect(Object.is(parseAccessLine(signed).st, -0)).toBe(false);
  });

  it('keeps a duplicated field on the side JSON.parse decided, and a hostile name out of the prototype', () => {
    const twice = '{"t":1,"rid":"a","cred":null,"auth":null,"scope":null,"m":"GET","p":"/x","rcp":null,"nce":null,"st":2,"dur":3,"deny":null,"t":999}';
    expect(parseAccessLine(twice).t).toBe(999);
    const polluted = '{"t":1,"rid":"a","cred":null,"auth":null,"scope":null,"m":"GET","p":"/x","rcp":null,"nce":null,"st":2,"dur":3,"deny":null,"__proto__":{"crept":true}}';
    const answered = tryParse(polluted);
    expect(answered.threw).toBe(true);
    expect(answered.message).toContain('unknown field');
    expect(({} as Record<string, unknown>)['crept']).toBeUndefined();
  });
});

const GOOD = renderAccessLine(entry()).trimEnd();
const LATER = renderAccessLine(entry({ t: T0 + 60_000, rid: 'req-2' })).trimEnd();

/**
 * A zero-length piece and an unreadable one leave the count where it was by two different rules in the
 * reader: one is tested before the parse, the other is the `catch` that swallows every failure. These
 * gates hand the reader bytes and report what the count says, because that is the only thing a caller of
 * `window()` can see.
 */
describe('what the reader answers for a file of bytes', () => {
  it('counts a final line that carries no newline exactly as one that does', async () => {
    expect(await windowOver(GOOD + LF)).toEqual({ from: T0, to: T0, count: 1 });
    expect(await windowOver(GOOD)).toEqual({ from: T0, to: T0, count: 1 });
    expect(await windowOver(GOOD + LF + LATER + LF)).toEqual({ from: T0, to: T0 + 60_000, count: 2 });
    expect(await windowOver(GOOD + LF + LATER)).toEqual({ from: T0, to: T0 + 60_000, count: 2 });
    // The terminator is what the writer appends, not what the reader asks for: a file truncated between
    // two writes and a file the writer left clean are told apart by nothing here.
    expect(await windowOver(LF + GOOD + LF + LF + LF + LATER + LF + LF)).toEqual({ from: T0, to: T0 + 60_000, count: 2 });
  });

  it('leaves the count where it was for a blank line and for a line it cannot read', async () => {
    // '' is empty, so the reader tests it before parsing. The rest are not empty, so each one reaches
    // `JSON.parse`, throws, and is dropped: the count cannot tell the two rules apart.
    for (const blank of ['', ' ', '\t', 'x', '{', 'null', '[]', GOOD.slice(0, 30)]) {
      expect(await windowOver(GOOD + LF + blank + LF + LATER + LF), JSON.stringify(blank)).toEqual({
        from: T0,
        to: T0 + 60_000,
        count: 2,
      });
    }
  });

  it('answers a torn final line and a corrupt middle line with the same report', async () => {
    const whole = { from: T0, to: T0, count: 1 };
    for (const cut of [1, 2, 8, 40, GOOD.length - 40, GOOD.length - 8, GOOD.length - 2, GOOD.length - 1]) {
      const torn = GOOD.slice(0, cut);
      // Same bytes, same reader, same answer, whichever side of the good record the unreadable piece sits
      // on. A window that lost a line and a window whose file ends mid-write are not distinguishable.
      expect(await windowOver(torn + LF + GOOD + LF), `middle ${cut}`).toEqual(whole);
      expect(await windowOver(GOOD + LF + torn), `final ${cut}`).toEqual(whole);
    }
  });

  it('loses a record split across two lines instead of counting it twice or handing back half', async () => {
    const split = GOOD.length - 40;
    expect(await windowOver(GOOD.slice(0, split) + LF + GOOD.slice(split) + LF)).toEqual({ from: null, to: null, count: 0 });
    expect(await windowOver(GOOD.slice(0, split) + LF + GOOD.slice(split))).toEqual({ from: null, to: null, count: 0 });
  });

  it('gives a caller nothing beyond two timestamps and a count to reason from', async () => {
    const seen = await windowOver(GOOD + LF + 'not json' + LF);
    expect(Object.keys(seen).sort()).toEqual(['count', 'from', 'to']);
    expect(JSON.stringify(seen)).toBe('{"from":1772000000000,"to":1772000000000,"count":1}');
  });

  it('reads back through the window what the writer was asked to record', async () => {
    const dir = await tempDir();
    const log = await openFileAccessLog({ dir, days: 184, now: () => T0 });
    await log.record(entry({ t: T0 + 120_000, rid: 'req-3' }));
    await log.record(entry({ t: T0, rid: 'req-1' }));
    await log.record(entry({ t: T0 + 60_000, rid: 'req-2', deny: null }));
    await log.drain();
    const seen = await log.window();
    const parts = await log.files();
    await log.close();
    await rm(dir, { recursive: true, force: true });
    // The writer terminates every line, so the window sees all three, and the range is over the field,
    // not over the order the records arrived in.
    expect(seen).toEqual({ from: T0, to: T0 + 120_000, count: 3 });
    expect(parts).toHaveLength(1);
  });

  it('takes a line longer than the rotation trigger whole, and says what that cost', async () => {
    const wide = bigEntry(BIG_FIELD);
    const line = renderAccessLine(wide);
    if (BIG_FIELD > MAX_ACCESS_FILE_BYTES) {
      expect(Buffer.byteLength(line)).toBeGreaterThan(MAX_ACCESS_FILE_BYTES);
    } else {
      // Under `FC_BIG_FIELD` the drawn line is not wider than the trigger, so the claim this half makes is
      // not available to the run. Say so in the log rather than let a cheap run read as the full one.
      measure(`FC_BIG_FIELD=${String(BIG_FIELD)} is under the ${String(MAX_ACCESS_FILE_BYTES)}-byte trigger, so the oversized claim did not run`);
    }
    const dir = await tempDir();
    const log = await openFileAccessLog({ dir, days: 184, now: () => T0 });
    const beganAt = performance.now();
    await log.record(wide);
    await log.drain();
    const wroteIn = performance.now() - beganAt;
    const readAt = performance.now();
    const seen = await log.window();
    const readIn = performance.now() - readAt;
    const parts = await log.files();
    await log.close();
    await rm(dir, { recursive: true, force: true });
    // `MAX_ACCESS_FILE_BYTES` chooses which file the next line goes to; it bounds neither a line nor a
    // part, so the oversized record stands alone in its own file and reads back whole.
    expect(seen).toEqual({ from: T0, to: T0, count: 1 });
    expect(parts).toHaveLength(1);
    measure(`one line of ${Buffer.byteLength(line)} bytes: wrote in ${wroteIn.toFixed(0)} ms, windowed in ${readIn.toFixed(0)} ms, accepted`);
  });

  it('hands a deeply nested non-record to the reader, and reports which way it answered', async () => {
    const blob = nestBlob(NEST_DEPTH);
    const answer = tryParse(blob);
    const beganAt = performance.now();
    const seen = await windowOver(blob + LF + GOOD);
    const readIn = performance.now() - beganAt;
    // Both halves are measured, not argued: the parse either threw or it did not, and the reader either
    // counted the good record or it lost it. Nothing here adds a depth limit to the ones that do exist.
    measure(`nested ${NEST_DEPTH} deep: parse ${answer.threw ? `refused (${answer.message.slice(0, 60)})` : 'accepted'}, windowed in ${readIn.toFixed(0)} ms`);
    expect(answer.threw, 'a non-record is not a record').toBe(true);
    expect(seen).toEqual({ from: T0, to: T0, count: 1 });
  });
});

function bigEntry(size: number): AccessRecord {
  return entry({ p: 'x'.repeat(size), rid: '', cred: null, auth: null, scope: null, rcp: null, nce: null, deny: null });
}

function nestBlob(depth: number): string {
  return '['.repeat(depth) + ']'.repeat(depth);
}

/**
 * A line is `\n`, `\r`, U+2028 or U+2029. The writer escapes the first pair into the text of a JSON string
 * and leaves the second pair standing where they were, so the two claims below are checked against
 * different halves of that definition: one is about what the file's own reader can be fooled by, the other
 * is about what any other reader of the same bytes sees.
 */
describe('what a written line is against each of the four', () => {
  it('keeps a newline and a carriage return out of a line whatever a field holds', () => {
    check(recordArbitrary, [widestEntry(), entry({ deny: LF + CR + 'tail' }), entry({ p: LF.repeat(3) })], (written) => {
      const text = renderAccessLine(written);
      const body = text.slice(0, -1);
      return text.endsWith(LF) && !body.includes(LF) && !body.includes(CR);
    });
  });

  it('leaves the two separators JSON does not spell raw, and counts them honestly', () => {
    const withSeparators = fc.record({
      deny: fc.oneof(fc.constant<string | null>(null), hostileText, fc.constant(LINE_SEPARATOR), fc.constant(PARAGRAPH_SEPARATOR), fc.constant(LINE_SEPARATOR + PARAGRAPH_SEPARATOR + LINE_SEPARATOR)),
    });
    check(withSeparators, [{ deny: LINE_SEPARATOR }, { deny: PARAGRAPH_SEPARATOR }, { deny: LINE_SEPARATOR + LF + PARAGRAPH_SEPARATOR }], (chosen) => {
      const written = entry({ ...chosen });
      const text = renderAccessLine(written);
      // Exactly the drawn raw separators survive: `JSON.stringify` is silent on both, and the writer adds
      // the one terminator of its own. A line feed or a carriage return in the drawn value is counted at
      // zero, because the escaper turned it into two characters that no reader splits on. So the line the
      // writer counts as one is two, four, or seven by the definition this file is written against, and
      // `window()` agrees with the writer because it splits on `\n` alone.
      const raw = rawSeparatorsOf(written.deny ?? '');
      return breaksOf(text) === raw + 1 && linesOf(text) === raw + 2;
    });
    measure('renderAccessLine escapes \\n and \\r only: U+2028 and U+2029 reach the file raw');
  });
});

async function popGet(credId: string, target: string, mutate?: (header: string) => string): Promise<{ statusCode: number; payload: string; headers: Record<string, string> }> {
  const signed = await harness({ credentials: [generated(credId, ['read'])] });
  try {
    const header = signed.signFor(credId, 'GET', target, null);
    const entries = Object.entries(header);
    const named = entries.find(([, value]) => value.includes('Ashaveri-PoP'));
    const sent: Record<string, string> = Object.fromEntries(
      named === undefined || mutate === undefined ? entries : entries.map(([key, value]) => (key === named[0] ? [key, mutate(value)] : [key, value])),
    );
    const response = await signed.app.inject({ method: 'GET', url: target, headers: sent });
    return {
      statusCode: response.statusCode,
      payload: response.payload,
      headers: Object.fromEntries(Object.entries(response.headers ?? {}).map(([key, value]) => [key, String(value)])),
    };
  } finally {
    await signed.app.close();
  }
}

/**
 * Bytes on a real socket, answered in bytes. `app.inject` parses the url it is handed and never runs the
 * HTTP parser, so a request line this gateway has to see as text can only be asked of a socket. Resolves
 * with the whole answer once its header block is complete; a refused request closes without one, and the
 * caller reads whatever arrived.
 */
function rawRequest(port: number, bytes: string): Promise<string> {
  return new Promise((resolve) => {
    const socket = net.connect(port, '127.0.0.1', () => socket.write(Buffer.from(bytes, 'utf8')));
    let got = '';
    socket.setEncoding('utf8');
    socket.on('data', (chunk: string) => {
      got += chunk;
      if (got.includes('\r\n\r\n')) {
        socket.destroy();
        resolve(got);
      }
    });
    socket.on('close', () => resolve(got));
    socket.on('error', () => resolve(got));
  });
}

/** Both request-shaped inputs the plan called clean by rule, attacked from the wire side instead. */
describe('what a refusal reaching a client looks like', () => {
  it('refuses a credential id the rule has no room for, and keeps the answer to one line', async () => {
    for (const [name, hostile] of [
      ['line feed', LF],
      ['carriage return', CR],
      ['line separator', LINE_SEPARATOR],
      ['paragraph separator', PARAGRAPH_SEPARATOR],
      ['space', ' '],
      ['too long', 'a'.repeat(65)],
      ['punctuation', '../etc/passwd'],
    ] as const) {
      const answered = await popGet('svc-pop', '/v1/receipts/abc', (header) => header.replace(/credential=[^,]*/u, `credential=ab${hostile}cd`));
      // Nothing about an id the credential rule refuses travels into a message: this pins the reply, and
      // the refusal itself, rather than trusting the regular expression. `app.inject` does not run the
      // socket parser, so this half says what the gateway answers to a header it was handed, not what a
      // socket would have accepted.
      expect(answered.statusCode, name).toBe(401);
      expect(linesOf(answered.payload), name).toBe(1);
      expect(linesOf(JSON.stringify(answered.headers)), name).toBe(1);
      expect(answered.payload, name).not.toContain(`ab${hostile}cd`);
      expect(answered.payload, name).not.toMatch(ANY_LINE);
    }
  });

  it('reads a separator a request target carries as the percent-encoded spelling, in both directions', async () => {
    // The target is the one message input this gateway quotes back with no character rule in front of it:
    // `no scope row for GET <target>` names the path as it arrived. It cannot arrive raw. `app.inject`
    // re-encodes the url before the router sees it, so admission reads `%E2%80%A8` and quotes that back.
    // Both halves of that are pinned, because the encoding is what the signature has to have covered: a
    // client that signed the target it meant is refused, and one that signed the target the gateway read is
    // answered without a break anywhere.
    const raw = `/v1/receipts/abc${LINE_SEPARATOR}`;
    const encoded = '/v1/receipts/abc%E2%80%A8';
    const signed = await harness({ credentials: [generated('svc-target', ['read'])] });
    let refused: { statusCode: number; payload: string };
    let answered: { statusCode: number; payload: string };
    let logged: AccessRecord[];
    try {
      const first = await signed.app.inject({
        method: 'GET',
        url: raw,
        headers: signed.signFor('svc-target', 'GET', raw, null),
      });
      refused = { statusCode: first.statusCode, payload: first.payload };
      const second = await signed.app.inject({
        method: 'GET',
        url: raw,
        headers: signed.signFor('svc-target', 'GET', encoded, null),
      });
      answered = { statusCode: second.statusCode, payload: second.payload };
      logged = signed.log.entries();
    } finally {
      await signed.app.close();
    }
    // The target travels only inside the signature input, never in the header, so a client that signs one
    // spelling and is read as the other is refused for the reason that is true from the gateway's side.
    expect(refused.statusCode).toBe(401);
    expect(refused.payload).toContain('AUTH_SIGNATURE');
    expect(linesOf(refused.payload)).toBe(1);
    expect(refused.payload).not.toMatch(ANY_LINE);
    expect(answered.statusCode).toBe(403);
    expect(answered.payload).toContain(`no scope row for GET ${encoded}`);
    expect(answered.payload).not.toContain(LINE_SEPARATOR);
    expect(linesOf(answered.payload)).toBe(1);
    expect(answered.payload).not.toMatch(ANY_LINE);
    // The same text reaches the log through `p`, which is filled from that same url. The writer escapes a
    // line feed and a carriage return and is silent on this one, so what keeps the second line out of the
    // file is the encoding, not the writer.
    expect(logged).toHaveLength(2);
    for (const record of logged) {
      expect(record.p).toBe(encoded);
      expect(breaksOf(renderAccessLine(record))).toBe(1);
    }
  });

  it('refuses a request line carrying a raw separator, before a route runs or a line is written', async () => {
    // The half the gate above cannot ask, because `app.inject` never runs the socket parser. This is a real
    // socket and a real request line, and the answer is the HTTP parser's: the separator is not a character
    // a target may hold, so the request is refused as malformed. It is refused before this process has a
    // route, a credential or a request state, which is why the count this leaves behind is the same count
    // the control request left. A control request on the same path, differing only in the separator, is
    // served and logged, so the 400 is the separator's doing and not the socket's.
    const bear = newBearerCredential({ id: 'svc-socket', scopes: ['read'] });
    const opened = await harness({ extra: [bear.record], allowBearer: true });
    const secret = Buffer.from(bear.secret).toString('base64url');
    try {
      await opened.app.listen({ port: 0, host: '127.0.0.1' });
      const port = (opened.app.server.address() as AddressInfo).port;
      const line = (target: string): string =>
        `GET ${target} HTTP/1.1\r\nHost: ashaveri.test\r\nAuthorization: Bearer ${secret}\r\nConnection: close\r\n\r\n`;
      const control = await rawRequest(port, line('/v1/receipts/absent-1'));
      expect(control).toContain('404');
      expect(control).toContain('no receipt for id absent-1');
      expect(control).not.toContain(LINE_SEPARATOR);
      expect(opened.log.entries()).toHaveLength(1);
      const hostile = await rawRequest(port, line(`/v1/receipts/absent-1${LINE_SEPARATOR}`));
      expect(hostile).toContain('400');
      // Nothing here is this gateway's answer: no route ran, so no admission code and no handler text.
      expect(hostile).not.toContain('no receipt for id');
      expect(hostile).not.toContain('authentication_error');
      expect(hostile).not.toContain(LINE_SEPARATOR);
      expect(opened.log.entries()).toHaveLength(1);
    } finally {
      await opened.app.close();
    }
  });

  it('keeps a decoded path parameter out of the message that quotes an id, and answers in one line either way', async () => {
    // The router percent-decodes a path parameter, so the reply could have been handed a separator the
    // request line never carried as a raw byte. It is not: admission reads the raw target and `matchesPath`
    // tests the id segment against the receipt-id rule, so `%` fails it, the route is unlisted, and the
    // answer is admission's, not the handler's. This is the rule that keeps `no receipt for id` clean, and
    // it is pinned rather than trusted, because the rule lives in another file.
    const encoded = await popGet('svc-id', '/v1/receipts/a%e2%80%a8b');
    expect(encoded.statusCode).toBe(403);
    expect(linesOf(encoded.payload)).toBe(1);
    expect(encoded.payload).not.toContain(LINE_SEPARATOR);
    expect(encoded.payload).not.toContain('no receipt for id');
    // The reachable form: an id the rule admits and no receipt answers for. Every character the message
    // can quote is one the rule allows, so no separator can reach a reply from this site at all.
    const missing = await popGet('svc-id', '/v1/receipts/absent-1');
    expect(missing.statusCode).toBe(404);
    expect(missing.payload).toContain('no receipt for id absent-1');
    expect(linesOf(missing.payload)).toBe(1);
  });

  it('replies to an unnamed model in one line, whatever the body chose to call it', async () => {
    const body = JSON.stringify({ model: `q${LINE_SEPARATOR}w${PARAGRAPH_SEPARATOR}e${LF}r`, messages: [{ role: 'user', content: 'x' }] });
    const signed = await harness({ credentials: [generated('svc-chat', ['complete'])] });
    let answered: { statusCode: number; payload: string; headers: Record<string, string> };
    let logged: AccessRecord[];
    try {
      const response = await signed.app.inject({
        method: 'POST',
        url: '/v1/chat/completions',
        headers: { ...signed.signFor('svc-chat', 'POST', '/v1/chat/completions', body), 'content-type': 'application/json' },
        payload: body,
      });
      answered = {
        statusCode: response.statusCode,
        payload: response.payload,
        headers: Object.fromEntries(Object.entries(response.headers ?? {}).map(([key, value]) => [key, String(value)])),
      };
      logged = signed.log.entries();
    } finally {
      await signed.app.close();
    }
    // The body is parsed by `JSON.parse`, which takes both separators raw inside a string, so the model
    // name the gateway quotes back is the widest text a caller can put on one line of a reply.
    expect(answered.statusCode).toBe(400);
    expect(answered.payload).toContain('is not served by this deployment');
    expect(linesOf(answered.payload)).toBe(1);
    expect(answered.payload).not.toMatch(ANY_LINE);
    expect(linesOf(JSON.stringify(answered.headers))).toBe(1);
    // The record this request leaves behind carries the target the router saw, with the query stripped,
    // and never the body text: the field that could hold request-chosen characters is the one the log
    // fills from `request.url`, which stays percent-encoded.
    expect(logged).toHaveLength(1);
    const [record] = logged;
    if (record === undefined) throw new Error('the request left no access record behind');
    for (const field of ACCESS_RECORD_FIELDS) {
      const held = record[field];
      expect(linesOf(String(held)), field).toBe(1);
      expect(String(held)).not.toContain(`q${LINE_SEPARATOR}w`);
    }
    expect(record.p).toBe('/v1/chat/completions');
    expect(record.st).toBe(400);
  });
});

afterAll(() => {
  for (const line of measured) console.log(`access-line: ${line}`);
  console.log(
    `access-line: seed ${String(SEED)}, ${String(propertyCalls)} properties, ${String(predicateCalls)} predicate calls, ` +
      `big field ${String(BIG_FIELD)}, nest depth ${String(NEST_DEPTH)}, wall clock ${((performance.now() - STARTED_AT) / 1000).toFixed(1)}s`,
  );
});

