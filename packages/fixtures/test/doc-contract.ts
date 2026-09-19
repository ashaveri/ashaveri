import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

/**
 * The readers the document tests share. Both kinds of input are text this repository owns: a
 * TypeScript declaration, and a markdown table. Neither is imported as code.
 *
 * A document test is the only place the shape of a shipped artefact and the shape of the prose
 * about it meet, so the parsers here are deliberately narrow: they find one declaration, or one
 * table with one exact header, and refuse to guess when either is missing or doubled. A table the
 * test could not find has to fail the run loudly, because a silently empty row list reads as a
 * document that stopped claiming anything.
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
