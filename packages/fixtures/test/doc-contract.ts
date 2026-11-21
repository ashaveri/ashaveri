import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { expect } from 'vitest';

/**
 * The readers the document tests share. Every input is text this repository owns, read as text and never
 * imported as code: a TypeScript declaration, a markdown table, a package manifest, a declared version.
 *
 * A document test is the only place the shape of a shipped artefact and the shape of the prose
 * about it meet, so the parsers here are deliberately narrow: they find one declaration, or one
 * table with one exact header, and refuse to guess when either is missing or doubled. A table the
 * test could not find has to fail the run loudly, because a silently empty row list reads as a
 * document that does not claim anything.
 *
 * One check is here too, because five published suites state a column roster and a reviewer copies
 * it out of their file: `assertRowRoster`. It is the equality, written once, that each of those
 * suite tests holds its own file to.
 *
 * The publishability rule and the range reader are here for the same reason the roster is. Two tests
 * hold the published manifests to one statement each of them, a rule written in one of the two drifts
 * from the other, and the drift reads as two passing suites that mean different things. `pinned-node`
 * and `installed-artifacts` therefore ask one question of one reader, and
 * `publish-manifests` and `installed-artifacts` filter one list.
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
 *
 * A table ends at a blank line, and so does the reading here. What is refused rather than skipped is a
 * line inside a table that carries no pipe: markdown closes the table at it and renders the rest as a
 * paragraph, and a reader that stopped there would hand back the rows above the break as if the table
 * still had them all.
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
      if (line.trim().length === 0 || line.startsWith('|')) break;
      throw new Error(
        `a table row runs onto the line ${JSON.stringify(line.slice(0, 60))}, which ends the table: ` +
          'one row per physical line, or the rows behind it render outside the table and no reader reaches them',
      );
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
 * The members of a `const <name> = [ ... ];` declaration in a source file, read as the numbers the source
 * writes.
 *
 * Two document tests need the payload's version set, and neither imports it: `PARSED_VERSIONS` is
 * deliberately kept off the receipt package's index, and a cross-package source import does not sit inside
 * this package's `rootDir`. A reading written twice is a reading that can disagree with itself, so it lives
 * here beside the other two, and it refuses to guess: a declaration that cannot be found, or that holds no
 * number, stops the run rather than handing back an empty set a claim would pass on nothing.
 */
export function declaredVersions(name: string, file: string): number[] {
  const source = readSourceFile(file);
  const declared = new RegExp(`const ${name}(?::[^=]+)? = \\[([^\\]]*)\\]`, 'u').exec(source);
  if (declared === null) throw new Error(`${name} is not a bracketed list this reader can find in ${file}`);
  const cells = (declared[1] ?? '')
    .split(',')
    .map((cell) => cell.trim())
    .filter((cell) => cell.length > 0);
  if (cells.length === 0) throw new Error(`${name} in ${file} declares no versions, so there is nothing to hold a document to`);
  return cells.map((cell) => {
    if (!/^[0-9]+$/u.test(cell)) throw new Error(`${name} in ${file} carries ${cell}, which is not a version number`);
    return Number(cell);
  });
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

/** The scope every package in this workspace publishes under. */
export const PACKAGE_SCOPE = '@ashaveri/';

/**
 * One workspace package manifest, read once: the directory it sits in, spelled the way the caller
 * spells it, because one test writes `packages/receipt` in a message and the other needs the path it
 * can hand to a packer; the name; the version a publish would file the tarball under; and every field.
 */
export interface PackageManifest {
  readonly dir: string;
  readonly name: string;
  readonly version: string;
  readonly fields: Record<string, unknown>;
}

/**
 * The scoped manifests among the files read, in name order. Which directories a caller reads is left to
 * that caller, because the two that ask do not ask the same question: one holds the whole workspace to
 * its fields, including the gateway, and the other installs the packages a consumer is offered. What is
 * written once here is which manifest counts as one, and the refusal a caller must not talk itself out
 * of: a package of this scope that states no version has nothing to publish, so the run stops rather
 * than packing `undefined`.
 */
export function scopedManifests(reads: Iterable<{ dir: string; text: string }>): PackageManifest[] {
  const found: PackageManifest[] = [];
  for (const one of reads) {
    const raw = JSON.parse(one.text) as Record<string, unknown>;
    const name = raw['name'];
    if (typeof name !== 'string' || !name.startsWith(PACKAGE_SCOPE)) continue;
    const version = raw['version'];
    if (typeof version !== 'string') {
      throw new Error(`${one.dir}/package.json names ${name} with no version string`);
    }
    found.push({ dir: one.dir, name, version, fields: raw });
  }
  return found.sort((a, b) => a.name.localeCompare(b.name));
}

/**
 * Whether a manifest a publish would upload. `private: true` is the only statement a package can make
 * that holds it back, so a manifest spelling the flag `false` belongs here whether or not this
 * workspace ever writes it that way.
 */
export function isPublishable(fields: Record<string, unknown>): boolean {
  return fields['private'] !== true;
}

/**
 * Every path a manifest names as a way in: `main`, `types`, each `bin` target, and every target of the
 * nested `exports` map. These are the fields a consumer's resolver reads and the ones a `files` list has
 * to cover, so both the manifest test and the tarball test need the same list out of the same shapes.
 */
export function entryPoints(fields: Record<string, unknown>): string[] {
  const listed: string[] = [];
  for (const key of ['main', 'types']) {
    const value = fields[key];
    if (typeof value === 'string') listed.push(value);
  }
  const bin = fields['bin'];
  if (typeof bin === 'string') listed.push(bin);
  else if (typeof bin === 'object' && bin !== null) {
    for (const value of Object.values(bin as Record<string, unknown>)) {
      if (typeof value === 'string') listed.push(value);
    }
  }
  // `exports` nests, so the targets are collected by walking rather than by reading one shape.
  const walk = (value: unknown): void => {
    if (typeof value === 'string') {
      listed.push(value);
      return;
    }
    if (typeof value === 'object' && value !== null) {
      for (const nested of Object.values(value as Record<string, unknown>)) walk(nested);
    }
  };
  walk(fields['exports']);
  return listed;
}

/**
 * A version as a declared range names it: three numbers, and the text they were read out of so a failure
 * can quote the file rather than a reconstruction of it.
 */
export interface Version {
  readonly major: number;
  readonly minor: number;
  readonly patch: number;
  readonly text: string;
}

/** An exact `X.Y.Z`, or the reason the file holding it cannot be read here. */
export function parseVersion(text: string, where: string): Version {
  // The pattern carries exactly three capture groups, so each is present in every match it yields.
  const found = /^(\d+)\.(\d+)\.(\d+)$/u.exec(text);
  if (found === null) {
    throw new Error(`${where} states ${text}, which is not an exact X.Y.Z version`);
  }
  return { major: Number(found[1]), minor: Number(found[2]), patch: Number(found[3]), text };
}

/** Negative below, zero equal, positive above. */
export function compareVersions(a: Version, b: Version): number {
  return a.major - b.major || a.minor - b.minor || a.patch - b.patch;
}

export type BoundOperator = '>=' | '>' | '<=' | '<';

export interface Comparator {
  readonly op: BoundOperator;
  readonly version: Version;
}

/** What each operator asks of the ordering between a version and its bound. */
const HOLDS: Record<BoundOperator, (order: number) => boolean> = {
  '>=': (order) => order >= 0,
  '>': (order) => order > 0,
  '<=': (order) => order <= 0,
  '<': (order) => order < 0,
};

/** An exclusive bound admits less than the inclusive one on the same version. */
const STRICTER: Record<BoundOperator, number> = { '>=': 0, '>': 1, '<=': 0, '<': 1 };

/**
 * The comparators of a declared range. A short bound (`<25`) is filled out to `<25.0.0`, which is what a
 * range means by it, and the space inside `>= 26.13.0` is taken out before the bounds are split, because
 * that spacing states the same bound as `>=26.13.0`.
 *
 * The reader is deliberately narrow, accepting only a whitespace-separated list of `>=`, `>`, `<=` and
 * `<` comparators with numeric versions, so a range in any other form is reported rather than read as
 * agreement. Nothing in this package's dependency tree can parse a range from a test: `semver` sits in
 * the store several links deep, unreachable from here and with no types installed, so a reader is
 * written rather than a package added for one assertion.
 */
export function parseRange(range: string, where: string): Comparator[] {
  const unreadable =
    `${where} declares "${range}", which cannot be read here: this understands a `
    + 'whitespace-separated list of >=, >, <= and < comparators with numeric versions, and nothing else';
  const comparators: Comparator[] = [];
  for (const token of range.trim().replace(/([<>]=?)[ \t]+/gu, '$1').split(/\s+/u)) {
    const found = /^(>=|<=|>|<)(\d+(?:\.\d+){0,2})$/u.exec(token);
    const op = found?.[1];
    const stated = found?.[2];
    if (op !== '>=' && op !== '>' && op !== '<=' && op !== '<') throw new Error(unreadable);
    if (stated === undefined) throw new Error(unreadable);
    const [major = '0', minor = '0', patch = '0'] = stated.split('.');
    comparators.push({ op, version: parseVersion(`${major}.${minor}.${patch}`, `${where} comparator ${token}`) });
  }
  if (comparators.length === 0) throw new Error(unreadable);
  return comparators;
}

/** Whether one version holds every comparator of a read range. */
export function admitted(version: Version, comparators: Comparator[]): boolean {
  return comparators.every((comparator) => HOLDS[comparator.op](compareVersions(version, comparator.version)));
}

/** The bound on one side that a range's admitted set turns on: the highest lower one, the lowest upper. */
function tightest(comparators: Comparator[], side: 'lower' | 'upper'): Comparator | undefined {
  let best: Comparator | undefined;
  for (const one of comparators) {
    const isLower = one.op === '>=' || one.op === '>';
    if (isLower !== (side === 'lower')) continue;
    if (best === undefined) {
      best = one;
      continue;
    }
    const order = compareVersions(one.version, best.version);
    const furtherIn = side === 'lower' ? order > 0 : order < 0;
    if (order === 0 ? STRICTER[one.op] > STRICTER[best.op] : furtherIn) best = one;
  }
  return best;
}

/** The lowest version a range admits: the floor a pin has to sit on exactly. */
export function floorOf(comparators: Comparator[], where: string): Version {
  const lower = tightest(comparators, 'lower');
  if (lower === undefined) throw new Error(`${where} sets no lower bound, so it admits every release`);
  return lower.version;
}

/** Whether two comparators cut the same set of versions off on their side. */
function sameBound(left: Comparator | undefined, right: Comparator | undefined): boolean {
  if (left === undefined || right === undefined) return left === right;
  return left.op === right.op && compareVersions(left.version, right.version) === 0;
}

/**
 * Whether two read ranges state one promise. A range in this language is a list of bounds a version has
 * to hold at once, so what it admits turns on the tightest bound on each side: `>=26.13.0 <27`,
 * `>= 26.13.0 <27` and `>=26.13.0 <27.0.0` are one promise written three ways, while `>=26.0.0` admits
 * releases none of them do. Matching the text reddens the first pair as a re-spacing and lets a quietly
 * widened floor pass, which is the failure this reader exists to refuse.
 */
export function rangesAgree(left: Comparator[], right: Comparator[]): boolean {
  return (
    sameBound(tightest(left, 'lower'), tightest(right, 'lower')) &&
    sameBound(tightest(left, 'upper'), tightest(right, 'upper'))
  );
}
