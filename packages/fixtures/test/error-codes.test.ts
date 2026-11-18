import { randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { readSourceFile, sectionBody, tableRows } from './doc-contract.js';
import { discoverCodeFamilies } from './error-code-discovery.js';

const DOC_PATH = '../../../docs/error-codes.md';
const CODE_TABLE = '| Code | Union | Raised when | What the caller does | Verdict |';
const ROSTER_TABLE = '| Union | Package | Owns |';

interface Row {
  readonly code: string;
  readonly union: string;
}

function documentedSections(markdown: string): Map<string, Row[]> {
  const sections = new Map<string, Row[]>();
  for (const line of markdown.split('\n')) {
    const heading = /^## `([^`]+)`$/u.exec(line);
    if (!heading) continue;
    const name = heading[1]!;
    if (sections.has(name)) throw new Error(`duplicate code-section heading ${name}`);
    const rows = tableRows(sectionBody(markdown, line), CODE_TABLE).map((cells) => {
      if (cells.length !== 7) throw new Error(`malformed code row under ${name}`);
      return { code: codeCell(cells[1]!), union: codeCell(cells[2]!) };
    });
    sections.set(name, rows);
  }
  return sections;
}

function codeCell(cell: string): string {
  const match = /^`([^`]+)`$/u.exec(cell);
  if (!match) throw new Error(`expected a single named code cell: ${cell}`);
  return match[1]!;
}

function assertErrorDocument(markdown: string, families: ReadonlyMap<string, readonly string[]>): void {
  const found = documentedSections(markdown);
  const names = [...families.keys()].sort();
  expect([...found.keys()].sort(), 'code-section roster').toEqual(names);
  const roster = tableRows(markdown, ROSTER_TABLE).map((cells) => codeCell(cells[1]!));
  expect(roster.sort(), 'introductory union roster').toEqual(names);
  const introduction = markdown.split(/^## /mu)[0]!;
  const stated = [...introduction.matchAll(/There are (\d+) declarations across (\d+) unions, resolving to (\d+) distinct strings/gu)];
  expect(stated.length, 'one introductory sentence with all three counts as digits').toBe(1);
  const codes = [...families.values()].flat();
  expect(stated[0]!.slice(1).map(Number), 'declaration, union and distinct counts')
    .toEqual([codes.length, families.size, new Set(codes).size]);
  for (const [union, codes] of families) {
    const rows = found.get(union) ?? [];
    expect(rows.map((row) => row.code).sort(), `${union} rows`).toEqual([...codes].sort());
    for (const row of rows) expect(row.union, `${union} row owner`).toBe(union);
  }
}

function withShippedSource(source: string, check: () => void): void {
  const file = fileURLToPath(new URL(`../../../gateway/src/doc-discovery-${randomUUID()}.ts`, import.meta.url));
  writeFileSync(file, source, { flag: 'wx' });
  try {
    check();
  } finally {
    unlinkSync(file);
  }
}

const markdown = readSourceFile(DOC_PATH);
const declared = discoverCodeFamilies();

const REFUSAL_SECTION = [
  '## `DiscoveryRefusalCode`',
  '',
  CODE_TABLE,
  '|---|---|---|---|---|',
  '| `DISCOVERY_ONE` | `DiscoveryRefusalCode` | First refusal | Stop | terminal |',
  '| `DISCOVERY_TWO` | `DiscoveryRefusalCode` | Second refusal | Stop | terminal |',
  '',
].join('\n');

function withDiscoveryDocumentation(document: string): string {
  return document
    .replace(/There are (\d+) declarations across (\d+) unions, resolving to (\d+) distinct strings/u,
      (_sentence, declarations: string, unions: string, distinct: string) =>
        `There are ${Number(declarations) + 2} declarations across ${Number(unions) + 1} unions, ` +
        `resolving to ${Number(distinct) + 2} distinct strings`)
    .replace(ROSTER_TABLE + '\n|---|---|---|', ROSTER_TABLE + '\n|---|---|---|\n' +
      '| `DiscoveryRefusalCode` | `fixture` | Discovery witness |') + '\n' + REFUSAL_SECTION;
}

// These independently written counts and rows must agree with source, not a generated document.
const SMALL_DOCUMENT = [
  'There are 4 declarations across 2 unions, resolving to 2 distinct strings;',
  '',
  ROSTER_TABLE,
  '|---|---|---|',
  '| `FirstErrorCode` | `fixture` | First layer |',
  '| `SecondErrorCode` | `fixture` | Second layer |',
  '',
  '## `FirstErrorCode`',
  '',
  CODE_TABLE,
  '|---|---|---|---|---|',
  '| `ONE` | `FirstErrorCode` | First refusal | Stop | terminal |',
  '| `TWO` | `FirstErrorCode` | Second refusal | Stop | terminal |',
  '',
  '## `SecondErrorCode`',
  '',
  CODE_TABLE,
  '|---|---|---|---|---|',
  '| `ONE` | `SecondErrorCode` | First refusal | Stop | terminal |',
  '| `TWO` | `SecondErrorCode` | Second refusal | Stop | terminal |',
  '',
].join('\n');
const SMALL_FAMILIES = new Map([
  ['FirstErrorCode', ['ONE', 'TWO']],
  ['SecondErrorCode', ['ONE', 'TWO']],
]);

function withoutLine(document: string, prefix: string): string {
  return document.split('\n').filter((line) => !line.startsWith(prefix)).join('\n');
}

function withoutSection(document: string, heading: string): string {
  return document.replace(`${heading}\n${sectionBody(document, heading)}`, '');
}

describe('docs/error-codes.md', () => {
  it('covers the discovered shipped families', () => {
    assertErrorDocument(markdown, declared);
  });

  it('rejects missing docs for a freshly created shipped RefusalCode family and accepts matching docs', () => {
    withShippedSource(
      "export type DiscoveryRefusalCode = 'DISCOVERY_ONE' | 'DISCOVERY_TWO';\n" +
      "export class DiscoveryError extends Error { readonly code: DiscoveryRefusalCode = 'DISCOVERY_ONE'; }\n",
      () => {
        const fresh = discoverCodeFamilies();
        expect(() => assertErrorDocument(markdown, fresh)).toThrow(/roster/u);
        expect(fresh.get('DiscoveryRefusalCode')).toEqual(['DISCOVERY_ONE', 'DISCOVERY_TWO']);
        assertErrorDocument(withDiscoveryDocumentation(markdown), fresh);
      },
    );
  });

  it.each([
    ['ExpressionDecision', 'export const Expression = class extends Error { declare code: ExpressionDecision; };'],
    ['GenericDecision', 'class Base<T> extends Error { declare value: T; }\n' +
      'export class Child extends Base<string> { declare code: GenericDecision; }'],
  ])('discovers the exclusive %s family and requires its documentation', (family, source) => {
    withShippedSource(`type ${family} = 'EXCLUSIVE_ONE' | 'EXCLUSIVE_TWO';\n${source}`, () => {
      const fresh = discoverCodeFamilies();
      expect(fresh.get(family)).toEqual(['EXCLUSIVE_ONE', 'EXCLUSIVE_TWO']);
      expect(() => assertErrorDocument(markdown, fresh)).toThrow(/roster/u);
    });
  });

  it('resolves getters, renamed imports, transparent aliases and inherited constructor codes from source', () => {
    const directory = mkdtempSync(fileURLToPath(new URL('../src/doc-discovery-', import.meta.url)));
    try {
      writeFileSync(join(directory, 'families.ts'), [
        "export type Decision_7 = 'ONE' | // 'COMMENT_ONLY'; not a member",
        "  'TWO'",
        "export type OtherDecision = 'ONE' | 'TWO'",
        'export type Transparent = (Decision_7)',
      ].join('\n'), { flag: 'wx' });
      writeFileSync(join(directory, 'errors.ts'), [
        "import type { Transparent as Renamed, OtherDecision } from './families.js';",
        "import { ReceiptError as Parent, type ReceiptErrorCode as Imported } from '@ashaveri/receipt';",
        'type AnotherAlias = Renamed;',
        "export class GetterBase extends Error { get code(): AnotherAlias { return 'ONE'; } }",
        'export class Indirect extends GetterBase {}',
        'export class ParameterBase extends TypeError { constructor(readonly code: OtherDecision) { super(); } }',
        'export class InheritedParameter extends ParameterBase {}',
        'export class FromWorkspace extends Parent { declare readonly code: Imported; }',
        'export const Expression = class extends Error { declare code: OtherDecision; };',
        'export class CodeLess extends Error {}',
        "export class LogOnly extends Error { logCode = 'NOT_AN_INSTANCE_CODE'; }",
        "export class StaticOnly extends Error { static code = 'NOT_AN_INSTANCE_CODE'; }",
        "export class Structural { name = ''; message = ''; code = 123; }",
        '{ class Error {} class Pretender extends Error { code = 123; } }',
      ].join('\n'), { flag: 'wx' });
      const fresh = discoverCodeFamilies();
      expect([...fresh.keys()].filter((name) => !declared.has(name)).sort()).toEqual(['Decision_7', 'OtherDecision']);
      expect(fresh.get('Decision_7')).toEqual(['ONE', 'TWO']);
      expect(fresh.get('OtherDecision')).toEqual(['ONE', 'TWO']);
      expect(fresh.get('ReceiptErrorCode')).toEqual(declared.get('ReceiptErrorCode'));
      const independent = SMALL_DOCUMENT.replaceAll('FirstErrorCode', 'Decision_7').replaceAll('SecondErrorCode', 'OtherDecision');
      assertErrorDocument(independent, new Map([
        ['Decision_7', fresh.get('Decision_7')!], ['OtherDecision', fresh.get('OtherDecision')!],
      ]));
    } finally {
      rmSync(directory, { recursive: true });
    }
  });

  it('diagnoses every code-bearing unsupported shape instead of silently dropping a family', () => {
    withShippedSource([
      'type Broad = string; class BroadError extends Error { declare code: Broad; }',
      'type Unsafe = any; class AnyError extends Error { declare code: Unsafe; }',
      'type Empty = never; class NeverError extends Error { declare code: Empty; }',
      'type Numeric = 1 | 2; class NumericError extends Error { declare code: Numeric; }',
      "type Mixed = 'ONE' | 2; class MixedError extends Error { declare code: Mixed; }",
      'type Unknown = unknown; class UnknownError extends Error { declare code: Unknown; }',
      "type Optional = 'ONE' | 'TWO'; class OptionalError extends Error { declare code?: Optional; }",
      "class InlineError extends Error { declare code: 'ONE' | 'TWO'; }",
      "class InferredError extends Error { code = 'ONE'; }",
      "type Left = 'ONE'; type Right = 'TWO'; class AmbiguousError extends Error { declare code: Left | Right; }",
      'type Generic<T> = T; class GenericError extends Error { declare code: Generic<Left>; }',
      'type Missing = NotDeclared; class UnresolvedError extends Error { declare code: Missing; }',
      "type Vanishing = 'ONE' | never; class VanishingError extends Error { declare code: Vanishing; }",
      "{ type Duplicate = 'ONE'; class First extends Error { declare code: Duplicate; } }",
      "{ type Duplicate = 'TWO'; class Second extends Error { declare code: Duplicate; } }",
      "import { UnresolvedBase } from './doc-discovery-missing.js';",
      'class BrokenBaseError extends UnresolvedBase { declare code: Left; }',
      'class BrokenGenericBase<T> extends UnresolvedBase { declare value: T; }',
      'class BrokenGenericError extends BrokenGenericBase<string> { declare code: Left; }',
      'const BrokenExpression = class BrokenExpressionError extends UnresolvedBase { declare code: Left; };',
    ].join('\n'), () => {
      let diagnostic = '';
      try {
        discoverCodeFamilies();
      } catch (error) {
        if (!(error instanceof Error)) throw error;
        diagnostic = error.message;
      }
      for (const name of [
        'BroadError', 'AnyError', 'NeverError', 'NumericError', 'MixedError', 'UnknownError', 'OptionalError',
        'InlineError', 'InferredError', 'AmbiguousError', 'GenericError', 'UnresolvedError', 'VanishingError', 'BrokenBaseError',
        'BrokenGenericError', 'BrokenExpressionError',
      ]) expect(diagnostic, `${name} must not disappear`).toContain(`${name}.code:`);
      expect(diagnostic).toContain('duplicate documentation name Duplicate');
      expect(diagnostic).toContain('finite string literals');
    });
  });

  it('accepts independently handwritten matching documentation', () => {
    assertErrorDocument(SMALL_DOCUMENT, SMALL_FAMILIES);
  });

  it('augments existing correct document counts without tying the witness to current totals', () => {
    const expanded = SMALL_DOCUMENT
      .replace('4 declarations across 2 unions, resolving to 2 distinct strings',
        '6 declarations across 2 unions, resolving to 4 distinct strings')
      .replace('| `TWO` | `FirstErrorCode` |',
        '| `FIRST_EXTRA` | `FirstErrorCode` | Extra refusal | Stop | terminal |\n| `TWO` | `FirstErrorCode` |')
      .replace('| `TWO` | `SecondErrorCode` |',
        '| `SECOND_EXTRA` | `SecondErrorCode` | Extra refusal | Stop | terminal |\n| `TWO` | `SecondErrorCode` |');
    const expandedFamilies = new Map([
      ['FirstErrorCode', ['ONE', 'TWO', 'FIRST_EXTRA']],
      ['SecondErrorCode', ['ONE', 'TWO', 'SECOND_EXTRA']],
    ]);
    for (const [document, families] of [[SMALL_DOCUMENT, SMALL_FAMILIES], [expanded, expandedFamilies]] as const) {
      assertErrorDocument(document, families);
      assertErrorDocument(withDiscoveryDocumentation(document), new Map([
        ...families, ['DiscoveryRefusalCode', ['DISCOVERY_ONE', 'DISCOVERY_TWO']],
      ]));
    }
  });

  it.each([
    ['introductory union omitted', withoutLine(SMALL_DOCUMENT, '| `SecondErrorCode` | `fixture`')],
    ['introductory union duplicated', SMALL_DOCUMENT.replace('| `FirstErrorCode` | `fixture` | First layer |',
      '| `FirstErrorCode` | `fixture` | First layer |\n| `FirstErrorCode` | `fixture` | First layer |')],
    ['section duplicated', SMALL_DOCUMENT + '\n## `FirstErrorCode`\n' + sectionBody(SMALL_DOCUMENT, '## `FirstErrorCode`')],
    ['union count changed', SMALL_DOCUMENT.replace('across 2 unions', 'across 3 unions')],
    ['declaration count changed', SMALL_DOCUMENT.replace('4 declarations', '5 declarations')],
    ['distinct count changed', SMALL_DOCUMENT.replace('2 distinct strings', '3 distinct strings')],
    ['code row duplicated', SMALL_DOCUMENT.replace('| `ONE` | `FirstErrorCode` | First refusal | Stop | terminal |',
      '| `ONE` | `FirstErrorCode` | First refusal | Stop | terminal |\n| `ONE` | `FirstErrorCode` | First refusal | Stop | terminal |')],
    ['wrong owning union', SMALL_DOCUMENT.replace('| `ONE` | `FirstErrorCode`', '| `ONE` | `SecondErrorCode`')],
    ['existing row removed', withoutLine(markdown, '| `MALFORMED_CBOR` |')],
    ['whole existing union removed', withoutSection(withoutLine(markdown, '| `StoreErrorCode` |'), '## `StoreErrorCode`')],
  ])('refuses %s', (name, document) => {
    expect(() => assertErrorDocument(document, name.includes('existing') ? declared : SMALL_FAMILIES)).toThrow();
  });

  it('refuses a row that continues onto a line which is not a row', () => {
    const wrapped = [
      '## `StoreErrorCode`', '', CODE_TABLE, '|---|---|---|---|---|',
      '| `A_CODE` | `StoreErrorCode` | The rule, and',
      '`the rest of its sentence` | What to do | terminal |',
      '| `ANOTHER_CODE` | `StoreErrorCode` | Behind the wrap | What to do | terminal |', '',
    ].join('\n');
    expect(() => documentedSections(wrapped)).toThrow(/one row per physical line/u);
    expect(() => tableRows(wrapped, CODE_TABLE)).toThrow(/one row per physical line/u);
    expect(tableRows(sectionBody(markdown, '## `StoreErrorCode`'), CODE_TABLE).length)
      .toBe(declared.get('StoreErrorCode')?.length);
  });

  it('keeps the shared strings down to the ones the document explains', () => {
    const codes = [...declared.values()].flat();
    const shared = [...new Set(codes)].filter((code) => codes.filter((each) => each === code).length > 1);
    expect(shared.sort()).toEqual(['UNSUPPORTED_PLATFORM', 'UNSUPPORTED_VERSION']);
  });
});
