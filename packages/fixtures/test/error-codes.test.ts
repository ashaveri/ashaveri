import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

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
];

const DOC_PATH = '../../../docs/error-codes.md';

function read(file: string): string {
  return readFileSync(fileURLToPath(new URL(file, import.meta.url)), 'utf8');
}

/** The members of `export type <union> = ... ;`, in declaration order. */
function declaredCodes(union: string, file: string): string[] {
  const source = read(file);
  const marker = `export type ${union} =`;
  const start = source.indexOf(marker);
  if (start < 0) throw new Error(`${union} is not declared in ${file}`);
  const rest = source.slice(start + marker.length);
  const end = rest.indexOf(';');
  if (end < 0) throw new Error(`${union} in ${file} has no terminating semicolon`);
  // The pattern carries exactly one capture group, so group 1 is present in every match it yields.
  return [...rest.slice(0, end).matchAll(/'([A-Z0-9_]+)'/g)].map((found) => found[1]!);
}

interface Row {
  readonly code: string;
  readonly union: string;
}

/** Rows of each `## \`XErrorCode\`` table, keyed by the heading's union name. */
function documentedSections(markdown: string): Map<string, Row[]> {
  const sections = new Map<string, Row[]>();
  let current: Row[] | undefined;
  for (const line of markdown.split('\n')) {
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

const sections = documentedSections(read(DOC_PATH));
const declared = new Map(UNION_SOURCES.map(([union, file]) => [union, declaredCodes(union, file)]));
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

  it('states the real counts in the opening paragraph', () => {
    const stated = /There are (\d+) declarations across \w+ unions, resolving to (\d+) distinct strings/u.exec(
      read(DOC_PATH),
    );
    expect(stated, 'the opening paragraph must give both counts as digits').not.toBeNull();
    expect([Number(stated?.[1]), Number(stated?.[2])], 'declared, distinct').toEqual([
      allCodes.length,
      distinctCodes.size,
    ]);
  });

  it('keeps the shared string down to the one the document explains', () => {
    const shared = [...distinctCodes].filter((code) => allCodes.filter((each) => each === code).length > 1);
    expect(shared).toEqual(['UNSUPPORTED_PLATFORM']);
  });
});
