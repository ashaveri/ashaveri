import { describe, expect, it } from 'vitest';
import { equalBytes } from '@ashaveri/receipt';
import { SdkError } from '../src/errors.js';
import {
  IMPORT_TRANSFORMATION,
  NORMALIZATION_RULES,
  NORMALIZATION_RULE_NAMES,
  normalizeCompletions,
  normalizeExportId,
  normalizeIssuedAt,
  normalizeModel,
  normalizeProvider,
  normalizeProviderExport,
} from '../src/import-normalize.js';

/**
 * The normalization rules over their matrix, and the report over the positions that fall out of it.
 *
 * Each rule is asked for the three states a provider can put it in: the export states a value, the export
 * states nothing, and the export states something the rule does not read. The first two are the rule's
 * work and the driver's report; the third is a refusal, and the tests below read the sentence back
 * because the sentence is what a deterministic report is made of.
 *
 * The driver's tests hold the two claims the import contract rests on. One: the report is a function of
 * the bytes, so the same export yields the same rows and the same sentence in the same order, whichever
 * spelling of one JSON object arrives. Two: the normalized document is a function of the export and the
 * table, so its members are written in the table's order and a re-run over the same bytes is the same
 * bytes rather than a re-rendering that happens to agree.
 */

const TEXT = (value: string): Uint8Array => new TextEncoder().encode(value);
const DIGEST_A = 'ab'.repeat(32);
const DIGEST_B = 'cd'.repeat(32);

/** One entry of the synthetic provider's `completions`, in the export's own spelling. */
function entry(over: Record<string, unknown> = {}): Record<string, unknown> {
  return { ref: 'c-0001', sha256: DIGEST_A, at: 1_759_276_701, ...over };
}

/** The export every case below is one edit of: every field a rule reads, two whole entries, nothing else. */
function baseExport(): Record<string, unknown> {
  return {
    provider: 'synthhub',
    export_id: 'EXP-2026-10-01-0001',
    issued: 1_759_276_800,
    model: 'synth-model-1',
    completions: [entry(), entry({ ref: 'c-0002', sha256: DIGEST_B, at: 1_759_276_752 })],
  };
}

const bytesOf = (exported: Record<string, unknown>): Uint8Array => TEXT(JSON.stringify(exported));

/** The same object with members left out, which is how the export states nothing at a position. */
function without(exported: Record<string, unknown>, ...members: readonly string[]): Record<string, unknown> {
  const out = { ...exported };
  for (const member of members) delete out[member];
  return out;
}

/** The refusal one run answers with, as the code and the sentence a reader branches on. */
function refusalOf(run: () => unknown): { readonly code: string; readonly message: string } {
  try {
    run();
  } catch (err) {
    if (err instanceof SdkError) return { code: err.code, message: err.message };
    throw err;
  }
  throw new Error('the run answered with a value where this case states a refusal');
}

describe('the rule table', () => {
  it('states five rules whose names are the published list, in one order', () => {
    expect(NORMALIZATION_RULES.map((rule) => rule.name)).toEqual([...NORMALIZATION_RULE_NAMES]);
  });

  it('gives every rule its own export field and its own normalized member', () => {
    const fields = NORMALIZATION_RULES.map((rule) => rule.field);
    const members = NORMALIZATION_RULES.map((rule) => rule.member);
    expect(new Set(fields).size).toBe(fields.length);
    expect(new Set(members).size).toBe(members.length);
    for (const rule of NORMALIZATION_RULES) expect(typeof rule.read).toBe('function');
  });

  it('cites the transformation a derived representation names', () => {
    expect(IMPORT_TRANSFORMATION).toBe('normalizeProviderExport');
  });

  it('exports every rule as a named function, so the list above is the source and not a copy of it', () => {
    for (const read of [normalizeProvider, normalizeExportId, normalizeIssuedAt, normalizeModel, normalizeCompletions]) {
      expect(typeof read, 'a rule named in the published list is not a function').toBe('function');
    }
  });
});

describe('each rule over its matrix', () => {
  it('reads the provider name, or nothing, and refuses a value that is not a name', () => {
    expect(normalizeProvider(baseExport())).toBe('synthhub');
    expect(normalizeProvider(without(baseExport(), 'provider'))).toBeNull();
    const refused = refusalOf(() => normalizeProvider({ provider: 7 }));
    expect(refused.code).toBe('NOT_IMPORT_ENVELOPE');
    expect(refused.message).toContain("'provider'");
  });

  it('reads the export id, or nothing, and refuses a value that is not a name', () => {
    expect(normalizeExportId(baseExport())).toBe('EXP-2026-10-01-0001');
    expect(normalizeExportId(without(baseExport(), 'export_id'))).toBeNull();
    expect(refusalOf(() => normalizeExportId({ export_id: '' })).code).toBe('NOT_IMPORT_ENVELOPE');
  });

  it('reads the issued instant, or nothing, and refuses every shape that is not a whole instant', () => {
    expect(normalizeIssuedAt(baseExport())).toBe(1_759_276_800);
    expect(normalizeIssuedAt(without(baseExport(), 'issued'))).toBeNull();
    for (const value of ['yesterday', 1.5, -1, null, 9_007_199_254_740_992]) {
      const refused = refusalOf(() => normalizeIssuedAt({ issued: value }));
      expect(refused.code, `issued ${String(value)}`).toBe('NOT_IMPORT_ENVELOPE');
      expect(refused.message).toContain("'issued'");
      expect(refused.message).toContain('whole number of unix seconds');
    }
  });

  it('reads the model name, or nothing, and refuses a value that is not a name', () => {
    expect(normalizeModel(baseExport())).toBe('synth-model-1');
    expect(normalizeModel(without(baseExport(), 'model'))).toBeNull();
    expect(refusalOf(() => normalizeModel({ model: ['synth-model-1'] })).code).toBe('NOT_IMPORT_ENVELOPE');
  });

  it('reads the completion entries, or nothing, keeping only entries whose three members are readable', () => {
    expect(normalizeCompletions(baseExport())).toEqual([
      { id: 'c-0001', sha256: DIGEST_A, at: 1_759_276_701 },
      { id: 'c-0002', sha256: DIGEST_B, at: 1_759_276_752 },
    ]);
    expect(normalizeCompletions(without(baseExport(), 'completions'))).toBeNull();
    expect(normalizeCompletions({ completions: [] })).toEqual([]);
    // An entry missing one member falls out whole; its readable members are not carried half-stated.
    expect(normalizeCompletions({ completions: [entry(), without(entry(), 'sha256')] })).toEqual([
      { id: 'c-0001', sha256: DIGEST_A, at: 1_759_276_701 },
    ]);
  });

  it('refuses every shape of the completions list that is not a list of entry objects', () => {
    for (const value of ['two completions', { ref: 'c-0001' }, [7], [null]]) {
      const refused = refusalOf(() => normalizeCompletions({ completions: value }));
      expect(refused.code, `completions ${JSON.stringify(value)}`).toBe('NOT_IMPORT_ENVELOPE');
      expect(refused.message).toContain("'completions");
    }
  });

  it('refuses an entry member of a shape no reading of that member takes', () => {
    const cases: readonly [Record<string, unknown>, string][] = [
      [entry({ ref: 7 }), "'completions[0].ref'"],
      [entry({ sha256: 'AB'.repeat(32) }), "'completions[0].sha256'"],
      [entry({ at: -1 }), "'completions[0].at'"],
    ];
    for (const [withBad, where] of cases) {
      const refused = refusalOf(() => normalizeCompletions({ completions: [withBad] }));
      expect(refused.code).toBe('NOT_IMPORT_ENVELOPE');
      expect(refused.message, `the refusal does not name ${where}`).toContain(where);
    }
  });
});

describe('the driver over an export', () => {
  it('folds the whole export into one document, members in the table order, and reports nothing', () => {
    const seen = normalizeProviderExport(bytesOf(baseExport()));
    expect(JSON.parse(new TextDecoder().decode(seen.bytes)) as unknown).toEqual({
      v: 1,
      provider: 'synthhub',
      exportId: 'EXP-2026-10-01-0001',
      issuedAt: 1_759_276_800,
      model: 'synth-model-1',
      items: [
        { id: 'c-0001', sha256: DIGEST_A, at: 1_759_276_701 },
        { id: 'c-0002', sha256: DIGEST_B, at: 1_759_276_752 },
      ],
    });
    expect(new TextDecoder().decode(seen.bytes)).toBe(
      '{"v":1,"provider":"synthhub","exportId":"EXP-2026-10-01-0001","issuedAt":1759276800,' +
        '"model":"synth-model-1","items":[{"id":"c-0001","sha256":"' +
        DIGEST_A +
        '","at":1759276701},{"id":"c-0002","sha256":"' +
        DIGEST_B +
        '","at":1759276752}]}',
    );
    expect(seen.report).toEqual([]);
  });

  it('is a function of the bytes: one export yields one document and one report, however it is spelled', () => {
    const once = normalizeProviderExport(bytesOf(baseExport()));
    const again = normalizeProviderExport(bytesOf(baseExport()));
    expect(equalBytes(once.bytes, again.bytes)).toBe(true);
    expect(again.report).toEqual(once.report);
    // The member order of the export's text is not the reading's order: one object spelled two ways is
    // one import, one document and one report.
    const reordered = baseExport();
    const flipped: Record<string, unknown> = {};
    for (const member of Object.keys(reordered).sort().reverse()) flipped[member] = reordered[member];
    const other = normalizeProviderExport(bytesOf(flipped));
    expect(equalBytes(other.bytes, once.bytes)).toBe(true);
    expect(other.report).toEqual(once.report);
  });

  it('reports a field no rule reads, with one sentence for that field every time', () => {
    const seen = normalizeProviderExport(bytesOf({ ...baseExport(), region: 'eu-west-1' }));
    expect(seen.report).toEqual([
      {
        kind: 'unsupported-field',
        field: 'region',
        states: "the export carries 'region', which no normalization rule of import version 1 reads",
      },
    ]);
    expect(normalizeProviderExport(bytesOf({ ...baseExport(), region: 'us-east-1' })).report).toEqual(seen.report);
  });

  it('reports a field a rule reads that the export states nothing at, and leaves it out of the document', () => {
    const seen = normalizeProviderExport(bytesOf(without(baseExport(), 'model')));
    expect(seen.report).toEqual([
      {
        kind: 'missing-field',
        field: 'model',
        states: "the export carries nothing at 'model', which normalization rule 'normalizeModel' reads",
      },
    ]);
    expect(JSON.parse(new TextDecoder().decode(seen.bytes)) as unknown).toEqual({
      v: 1,
      provider: 'synthhub',
      exportId: 'EXP-2026-10-01-0001',
      issuedAt: 1_759_276_800,
      items: [
        { id: 'c-0001', sha256: DIGEST_A, at: 1_759_276_701 },
        { id: 'c-0002', sha256: DIGEST_B, at: 1_759_276_752 },
      ],
    });
  });

  it('keeps the two kinds apart on one input, and orders the rows by position rather than by arrival', () => {
    const seen = normalizeProviderExport(
      bytesOf({
        ...without(baseExport(), 'model'),
        region: 'eu-west-1',
        completions: [entry({ cost_micros: 42 }), without(entry({ ref: 'c-0002' }), 'sha256')],
      }),
    );
    expect(seen.report.map((row) => [row.kind, row.field])).toEqual([
      ['unsupported-field', 'completions[0].cost_micros'],
      ['missing-field', 'completions[1].sha256'],
      ['missing-field', 'model'],
      ['unsupported-field', 'region'],
    ]);
    expect(seen.report.map((row) => row.states)).toEqual([
      "the export carries 'completions[0].cost_micros', which no normalization rule of import version 1 reads",
      "the export carries nothing at 'completions[1].sha256', which normalization rule 'normalizeCompletions' reads",
      "the export carries nothing at 'model', which normalization rule 'normalizeModel' reads",
      "the export carries 'region', which no normalization rule of import version 1 reads",
    ]);
    // The entry missing its digest falls out whole, and the entry carrying the unread member stays: the
    // two outcomes are one report and two different pieces of the document.
    expect(JSON.parse(new TextDecoder().decode(seen.bytes)) as unknown).toMatchObject({
      items: [{ id: 'c-0001', sha256: DIGEST_A, at: 1_759_276_701 }],
    });
  });

  it('refuses bytes that are no JSON object, each with the code every refusal of this reading carries', () => {
    for (const bytes of [TEXT('[1, 2]'), TEXT('not json at all'), TEXT('"a string"'), Uint8Array.from([0xff, 0xfe, 0x00])]) {
      const refused = refusalOf(() => normalizeProviderExport(bytes));
      expect(refused.code).toBe('NOT_IMPORT_ENVELOPE');
      expect(refused.message.length).toBeGreaterThan(40);
    }
    const nested = refusalOf(() => normalizeProviderExport(bytesOf({ ...baseExport(), issued: 'yesterday' })));
    expect(nested.code).toBe('NOT_IMPORT_ENVELOPE');
    expect(nested.message).toContain("'issued'");
  });
});
