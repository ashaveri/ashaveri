import { describe, expect, it } from 'vitest';
import { readSourceFile, sectionBody, tableRows, unionMembers } from './doc-contract.js';

/**
 * docs/error-codes.md is where a caller looks up what to do with a code it has caught. A table
 * like that goes stale the moment a union changes, so this suite makes the change fail CI:
 * it reads every code out of the declarations and every row out of the document, and requires
 * them to agree in both directions, including the counts the opening paragraph states.
 *
 * The unions are parsed from source rather than imported. Importing them all would make this
 * package depend on every other one, and the document keys its rows by union name anyway, so
 * the name is the thing under test.
 */
const UNION_SOURCES: ReadonlyArray<readonly [union: string, file: string]> = [
  ['ReceiptErrorCode', '../../receipt/src/errors.ts'],
  ['SdkErrorCode', '../../sdk/src/errors.ts'],
  ['AttestationErrorCode', '../../attest-core/src/errors.ts'],
  ['GuestErrorCode', '../../../gateway/src/guest.ts'],
  ['DstackErrorCode', '../../../gateway/src/dstack.ts'],
  ['StoreErrorCode', '../../../gateway/src/store.ts'],
  ['AccessErrorCode', '../../../gateway/src/access.ts'],
  ['CollateralErrorCode', '../../collateral/src/errors.ts'],
];

const DOC_PATH = '../../../docs/error-codes.md';

/** The header every union table carries, so a wrapped row can be written out the way the file spells one. */
const CODE_TABLE = '| Code | Union | Raised when | What the caller does | Verdict |';

interface Row {
  readonly code: string;
  readonly union: string;
}

/** Rows of each `## \`XErrorCode\`` table, keyed by the heading's union name. */
function documentedSections(markdown: string): Map<string, Row[]> {
  const sections = new Map<string, Row[]>();
  let current: Row[] | undefined;
  let tableOpen = false;
  for (const line of markdown.split('\n')) {
    // A markdown table closes at the first blank line, and a cell wrapped onto a physical line of its
    // own closes it too while rendering as a paragraph outside the table. The reading below skips every
    // line it does not recognise as a row, which is how a row lost to that wrap would pass unnoticed
    // here and read as a missing code somewhere else, so a table broken anywhere but on a blank line is
    // refused rather than read short.
    if (tableOpen && line.trim().length > 0 && !line.startsWith('|')) {
      throw new Error(
        `a table row runs onto the line ${JSON.stringify(line.slice(0, 60))}, which ends the table: ` +
          'one row per physical line',
      );
    }
    tableOpen = line.startsWith('|---') || (tableOpen && line.startsWith('|'));
    const heading = /^## `([A-Za-z]+ErrorCode)`$/u.exec(line);
    if (heading) {
      current = [];
      sections.set(heading[1]!, current);
      continue;
    }
    if (line.startsWith('## ')) current = undefined;
    if (!current || !line.startsWith('| `')) continue;
    const cells = line.split('|').map((cell) => cell.trim().replace(/`/gu, ''));
    const code = cells[1];
    const union = cells[2];
    if (code === undefined || union === undefined) throw new Error(`table row has fewer than two cells: ${line}`);
    current.push({ code, union });
  }
  return sections;
}

const sections = documentedSections(readSourceFile(DOC_PATH));
const declared = new Map(UNION_SOURCES.map(([union, file]) => [union, unionMembers(union, file)]));
const allCodes = [...declared.values()].flat();
const distinctCodes = new Set(allCodes);

describe('docs/error-codes.md', () => {
  it('covers one section per union this workspace declares', () => {
    expect([...sections.keys()].sort()).toEqual([...declared.keys()].sort());
  });

  it('gives exactly one row to each declared code, and no row to an undeclared one', () => {
    for (const [union, codes] of declared) {
      const rows = sections.get(union) ?? [];
      expect(rows.map((row) => row.code).sort(), `${union} rows`).toEqual([...codes].sort());
    }
  });

  it('states the owning union in every row', () => {
    for (const [union, rows] of sections) {
      for (const row of rows) {
        expect(`${row.code} -> ${row.union}`, `row under the ${union} heading`).toBe(`${row.code} -> ${union}`);
      }
    }
  });

  /**
   * The two readers above refuse a row whose cell runs onto a second physical line rather than reading
   * short around it, and a refusal nothing exercises is a branch. So the check is a document written
   * for the purpose, with the shape GitHub-flavoured markdown actually gives: the table closes at the
   * continuation line, the continuation renders as a paragraph, and the row behind it renders outside
   * any table. A reader that skipped the line would still return every code above the break, and one
   * that stopped there would return none of the codes below it.
   */
  it('refuses a row that continues onto a line which is not a row', () => {
    const wrapped = [
      '## `StoreErrorCode`',
      '',
      CODE_TABLE,
      '|---|---|---|---|---|',
      '| `A_CODE` | `StoreErrorCode` | The rule, and',
      '`the rest of its sentence` | What to do | terminal |',
      '| `ANOTHER_CODE` | `StoreErrorCode` | The row behind the wrap | What to do | terminal |',
      '',
    ].join('\n');
    expect(() => documentedSections(wrapped)).toThrow(/one row per physical line/u);
    expect(() => tableRows(wrapped, CODE_TABLE)).toThrow(/one row per physical line/u);
    // The shipped document passes through both readings, which is what makes the two refusals above
    // about a reader rather than about a shape no document of this estate can be written in.
    expect(documentedSections(readSourceFile(DOC_PATH)).size).toBe(UNION_SOURCES.length);
    expect(
      tableRows(sectionBody(readSourceFile(DOC_PATH), '## `StoreErrorCode`'), CODE_TABLE).length,
      'the store table, which is the one that grew a wrapped row and lost the rows behind it',
    ).toBe(6);
  });

  it('states the real counts in the opening paragraph', () => {
    const stated = /There are (\d+) declarations across \w+ unions, resolving to (\d+) distinct strings/u.exec(
      readSourceFile(DOC_PATH),
    );
    expect(stated, 'the opening paragraph must give both counts as digits').not.toBeNull();
    expect([Number(stated?.[1]), Number(stated?.[2])], 'declared, distinct').toEqual([
      allCodes.length,
      distinctCodes.size,
    ]);
  });

  it('keeps the shared strings down to the ones the document explains', () => {
    const shared = [...distinctCodes].filter((code) => allCodes.filter((each) => each === code).length > 1);
    expect([...shared].sort()).toEqual(['UNSUPPORTED_PLATFORM', 'UNSUPPORTED_VERSION']);
  });
});
