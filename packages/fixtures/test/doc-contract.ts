import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { expect } from 'vitest';

/**
 * The readers the document tests share. Both kinds of input are text this repository owns: a
 * TypeScript declaration, and a markdown table. Neither is imported as code.
 *
 * A document test is the only place the shape of a shipped artefact and the shape of the prose
 * about it meet, so the parsers here are deliberately narrow: they find one declaration, or one
 * table with one exact header, and refuse to guess when either is missing or doubled. A table the
 * test could not find has to fail the run loudly, because a silently empty row list reads as a
 * document that stopped claiming anything.
 *
 * One check is here too, because five published suites state a column roster and a reviewer copies
 * it out of their file: `assertRowRoster`. It is the equality, written once, that each of those
 * suite tests holds its own file to.
 */

/** A workspace file, spelled the way the calling test spells it, relative to this directory. */
export function readSourceFile(specifier: string): string {
  return readFileSync(fileURLToPath(new URL(specifier, import.meta.url)), 'utf8');
}

/** The members of `export type <union> = ... ;`, in declaration order. */
export function unionMembers(union: string, file: string): string[] {
  const source = readSourceFile(file);
  const marker = `export type ${union} =`;
  const start = source.indexOf(marker);
  if (start < 0) throw new Error(`${union} is not declared in ${file}`);
  const rest = source.slice(start + marker.length);
  const end = rest.indexOf(';');
  if (end < 0) throw new Error(`${union} in ${file} has no terminating semicolon`);
  // The pattern carries exactly one capture group, so group 1 is present in every match it yields.
  return [...rest.slice(0, end).matchAll(/'([A-Z0-9_]+)'/gu)].map((found) => found[1]!);
}

export interface LiteralEntry {
  readonly key: string;
  readonly value: string;
}

/**
 * The `KEY: value` pairs of a `const <name> ... = { ... };` literal, in source order, with the
 * values still as written. Comment lines between the entries carry no `KEY:` and are skipped, which
 * is what lets a map keep the paragraph explaining one of its rows.
 */
export function literalEntries(name: string, file: string): LiteralEntry[] {
  const source = readSourceFile(file);
  const start = source.indexOf(`const ${name}`);
  if (start < 0) throw new Error(`${name} is not declared in ${file}`);
  const open = source.indexOf('{', start);
  const close = open < 0 ? -1 : source.indexOf('\n};', open);
  if (open < 0 || close < 0) throw new Error(`${name} in ${file} is not a braced object literal`);
  const entries: LiteralEntry[] = [];
  for (const line of source.slice(open + 1, close).split('\n')) {
    const found = /^\s+([A-Z][A-Z0-9_]*)\s*:\s*(.+)$/u.exec(line);
    if (found) entries.push({ key: found[1]!, value: found[2]!.trim().replace(/,$/u, '') });
  }
  if (entries.length === 0) throw new Error(`${name} in ${file} carries no entries this reader can parse`);
  return entries;
}

/**
 * The rows below one table header, as trimmed cells including the leading empty one. The header has
 * to appear exactly once: a document that grew a second copy of a table would otherwise have its
 * rows read out of whichever one came first.
 */
export function tableRows(markdown: string, header: string): string[][] {
  const lines = markdown.split('\n');
  const headers = lines.map((line, at) => (line === header ? at : -1)).filter((at) => at >= 0);
  if (headers.length !== 1) {
    throw new Error(`the table headed ${header} appears ${headers.length} times, and this reads exactly one`);
  }
  const rows: string[][] = [];
  for (const line of lines.slice(headers[0]! + 1)) {
    if (!line.startsWith('| `')) {
      if (line.startsWith('|---')) continue;
      break;
    }
    rows.push(line.split('|').map((cell) => cell.trim()));
  }
  if (rows.length === 0) throw new Error(`the table headed ${header} has no rows`);
  return rows;
}

/** The body of a `## <heading>` section, up to the next `## ` heading of any kind. */
export function sectionBody(markdown: string, heading: string): string {
  const lines = markdown.split('\n');
  const start = lines.indexOf(heading);
  if (start < 0) throw new Error(`${heading} is not a section heading in the document`);
  const rest = lines.slice(start + 1);
  const end = rest.findIndex((line) => line.startsWith('## '));
  return (end < 0 ? rest : rest.slice(0, end)).join('\n');
}

/**
 * Counts the documents write as words rather than digits. Reading one is a check that the sentence
 * still agrees with the thing it counts, which a document that only ever restated the number in a
 * table could not make.
 */
const NUMBER_WORDS: readonly string[] = [
  'zero',
  'one',
  'two',
  'three',
  'four',
  'five',
  'six',
  'seven',
  'eight',
  'nine',
  'ten',
  'eleven',
  'twelve',
  'thirteen',
  'fourteen',
  'fifteen',
  'sixteen',
  'seventeen',
  'eighteen',
  'nineteen',
  'twenty',
];

export function spelledNumber(word: string): number {
  const at = NUMBER_WORDS.indexOf(word.toLowerCase());
  if (at < 0) throw new Error(`${word} is not a number word a document here uses, and this reads up to twenty`);
  return at;
}

/**
 * The five columns every published row carries because they say which row and which document it is,
 * and nothing about whether a reader accepts it. `epoch-inventory-v1.json` publishes the same five as
 * `layout.rowNamingFields`, and that test hands the file's own list to `assertRowRoster`; the four
 * suites that publish only their answer columns have no such member to hand, so their tests hand this
 * one. Writing them out again inside a suite test is how one of those tests came to allow columns the
 * published file never declared: the list the test allowed and the list the file declares were two
 * different things, and only one of them was published.
 */
export const ROW_NAMING_FIELDS: readonly string[] = [
  'name',
  'note',
  'documentBase64Url',
  'documentByteLength',
  'read',
];

/** A published suite, read as far as its roster check reaches: its declared columns and its rows. */
export interface RosterFile {
  readonly layout: { readonly verdictFields: readonly string[] };
  readonly vectors: readonly object[];
}

/**
 * The equality a published suite's column roster is held to, in the one order that makes a copy of it
 * trustworthy: first that no column is stated twice, inside either list or across the two of them,
 * then that the columns actually on the rows are exactly the declared list plus the naming list, and
 * last that a row count somebody states out loud is the count of the rows rather than a number carried
 * along beside them.
 *
 * A permission check could not do the second half: a list of fields a row may carry lets a column no
 * declaration names sit on a row unnoticed, which is how a reviewer copying the roster out of a
 * published file came to be handed a list that does not describe the data, and how a port that refuses
 * an undeclared column refuses rows the suite stands behind. So both directions are compared here,
 * and each refusal names what it found rather than a count the reader has to diff by hand.
 *
 * Where a suite's roster is a different shape, that is data in the arguments rather than a branch here:
 * a suite publishes its naming columns, or its test passes the shared list, and a suite whose rows are
 * counted in a document passes that number. A column some rows carry and others do not needs no special
 * case, because the comparison is over the columns the rows carry between them.
 */
export function assertRowRoster(
  file: RosterFile,
  naming: readonly string[],
  statedRowCount?: number,
): void {
  const roster = file.layout.verdictFields;
  const twiceInRoster = roster.filter((one, at) => roster.indexOf(one) !== at);
  expect(twiceInRoster, `the roster declares ${twiceInRoster.join(', ')} more than once`).toEqual([]);
  const twiceInNaming = naming.filter((one, at) => naming.indexOf(one) !== at);
  expect(twiceInNaming, `the naming list states ${twiceInNaming.join(', ')} more than once`).toEqual([]);
  const onBoth = roster.filter((one) => naming.includes(one));
  expect(onBoth, `${onBoth.join(', ')} is on the roster and on the naming list`).toEqual([]);
  const declared = [...roster, ...naming].sort();
  const carried = [...new Set(file.vectors.flatMap((one) => Object.keys(one)))].sort();
  const undeclared = carried.filter((one) => !declared.includes(one));
  const uncarried = declared.filter((one) => !carried.includes(one));
  expect(
    carried,
    `the rows carry ${undeclared.join(', ') || 'nothing the lists name'}, and the lists declare ` +
      `${uncarried.join(', ') || 'nothing a row carries'}`,
  ).toEqual(declared);
  if (statedRowCount !== undefined) {
    expect(
      file.vectors.length,
      `a sentence counts ${String(statedRowCount)} rows and the file publishes ${String(file.vectors.length)}`,
    ).toBe(statedRowCount);
  }
}
