import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { basename, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { DATA } from '../src/index.js';
import { sectionBody, spelledNumber } from './doc-contract.js';

/**
 * The suite inventory in `docs/vectors.md` is the index a port starts from: it names the file of each
 * published suite and the version field that file carries. Both are copies of facts that live in
 * `data/`, and a copy is how a document comes to state something the artefacts stopped carrying. This
 * reads the table as data and checks it against them. The prose around the rows is reviewed by the
 * people who write it, with one exception: a sentence that states a count of what the published files
 * carry is read for that count, and the rows it counts are taken out of the file the table names for
 * that suite, because the number belongs to the artefact and a reader typing it from memory is the
 * drift this refuses to be.
 */

const DOC = fileURLToPath(new URL('../../../docs/vectors.md', import.meta.url));
const PKG = fileURLToPath(new URL('../', import.meta.url));
const ROOT = fileURLToPath(new URL('../../../', import.meta.url));
/** The header of the one table that lists the published suites, one row per suite. */
const SUITES_TABLE = '| Suite | File | What it pins | Version field |';

/** The backticked spans of a cell, which is how this document spells a name it means literally. */
function named(cell: string): string[] {
  return [...cell.matchAll(/`([^`]+)`/gu)].map((found) => found[1]!);
}

/** The paths a cell names: backticked, and spelled with a separator rather than as a bare word. */
function paths(cell: string): string[] {
  return named(cell).filter((each) => each.includes('/'));
}

interface SuiteRow {
  readonly suite: string;
  /** The paths the File column names, as written. */
  readonly files: string[];
  /** The Version field column, still as written. */
  readonly versionCell: string;
}

/**
 * The inventory's rows. Read here rather than through `tableRows` in `doc-contract.ts`, because that
 * reader only accepts rows opening on a backtick and these open on a suite's name.
 */
function suiteRows(): SuiteRow[] {
  const lines = readFileSync(DOC, 'utf8').split('\n');
  const header = lines.indexOf(SUITES_TABLE);
  if (header < 0) throw new Error(`${SUITES_TABLE} is not a table header in docs/vectors.md`);
  const rows: SuiteRow[] = [];
  for (const line of lines.slice(header + 1)) {
    if (!line.startsWith('|')) break;
    if (line.startsWith('|---')) continue;
    const cells = line.split('|').map((cell) => cell.trim());
    rows.push({ suite: cells[1] ?? '', files: paths(cells[2] ?? ''), versionCell: cells[4] ?? '' });
  }
  if (rows.length < 2) {
    throw new Error(`the suite inventory has ${String(rows.length)} readable rows, and two is the least a pattern is`);
  }
  return rows;
}

/**
 * A path the document names, found at the repository root or under the package holding it, since the
 * table spells some paths from the repository and one from the package. `null` when neither is there,
 * so a row naming a file that has moved reports itself rather than throwing on the way to it.
 */
function resolve(named: string): string | null {
  for (const base of [ROOT, PKG]) {
    const found = join(base, named);
    if (existsSync(found)) return found;
  }
  return null;
}

/** The version values a row states outright, in the `version: 1` form. */
function stated(cell: string): number[] {
  return [...cell.matchAll(/`version:\s*(\d+)`/gu)].map((found) => Number(found[1]));
}

/** The top-level `version` field of a JSON file the inventory names. */
function versionOf(path: string): number {
  const found = resolve(path);
  if (found === null) throw new Error(`${path} is named by the inventory and is not there to read`);
  const parsed = JSON.parse(readFileSync(found, 'utf8')) as { version?: unknown };
  if (typeof parsed.version !== 'number') {
    throw new Error(`${path} carries no numeric version to compare against the row`);
  }
  return parsed.version;
}

/** The JSON files at the top of `data/`, which is where one published suite is one file. */
function publishedSuites(): string[] {
  return readdirSync(DATA)
    .filter((each) => each.endsWith('.json'))
    .sort();
}

/**
 * The verdict and code of every row one suite states a verdict on, read out of the file rather than
 * from the prose. Each shape is written out because the eleven suites do not agree on where a verdict
 * lives: four keep the refusing cases in an array beside the accepted ones and name a code on each row,
 * and seven give every case one word that is either the accepted verdict or the code of the refusal. A
 * suite whose file gains a shape no one recognised has to be named here, which is what stops this
 * reading an empty list as a suite with no refusals.
 */
function verdictsOf(basename: string): { verdict: string; code: string | null }[] {
  const found = resolve(`packages/fixtures/data/${basename}`) ?? resolve(`data/${basename}`);
  if (found === null) throw new Error(`${basename} is named by the inventory and is not there to read`);
  const parsed = JSON.parse(readFileSync(found, 'utf8')) as Record<string, unknown>;
  const rows = (key: string): Record<string, unknown>[] =>
    Array.isArray(parsed[key]) ? (parsed[key] as Record<string, unknown>[]) : [];
  const field = (row: Record<string, unknown>, key: string): string => {
    const value = row[key];
    if (typeof value !== 'string') throw new Error(`${basename} has a row with no ${key} this reader can use`);
    return value;
  };
  switch (basename) {
    case 'manifest.json':
      return rows('fixtures').map((row) => ({ verdict: field(row, 'expected'), code: null }));
    case 'marking-v1.json':
      return rows('vectors').map((row) => ({ verdict: field(row, 'expected'), code: null }));
    case 'export-v1.json':
    case 'manifest-v1.json':
    case 'pack-v1.json':
    case 'redaction-v1.json':
    case 'epoch-inventory-v1.json':
      return rows('vectors').map((row) => ({ verdict: field(row, 'verdict'), code: null }));
    case 'pop-v1.json':
    case 'req-v1.json':
    case 'res-v1.json':
    case 'chain-v1.json':
      return rows('refusals').map((row) => ({ verdict: 'refused', code: field(row, 'code') }));
    default:
      throw new Error(`${basename} states verdicts in a shape this reader does not know`);
  }
}

/** Every code `docs/error-codes.md` gives a row, read off its union sections. */
function documentedCodes(): Set<string> {
  const markdown = readFileSync(fileURLToPath(new URL('../../../docs/error-codes.md', import.meta.url)), 'utf8');
  const codes = new Set<string>();
  let inTable = false;
  for (const line of markdown.split('\n')) {
    if (line.startsWith('## ')) {
      inTable = /^## `[A-Za-z]+ErrorCode`$/u.test(line);
      continue;
    }
    if (!inTable || !line.startsWith('| `')) continue;
    const code = /^\|\s*`([^`]+)`/u.exec(line)?.[1];
    if (code !== undefined) codes.add(code);
  }
  if (codes.size < 20) throw new Error(`${codes.size} codes read from docs/error-codes.md, which lists more`);
  return codes;
}

/**
 * The section that speaks for every suite in the table, read as one run of prose because its sentences
 * are wrapped across several lines. The one number in it is the count of the table's rows, and a count
 * written down by hand is a claim that outlives the rows it was taken from, so it is read out of the
 * section and compared rather than trusted.
 */
function refusalSection(): string {
  return sectionBody(readFileSync(DOC, 'utf8'), '## Every suite refuses something').replace(/\n\s*/gu, ' ');
}

/**
 * The two bullets `docs/vectors.md` gives the epoch inventory, read as one run of prose because the
 * sentences in them are wrapped across several lines. Both state a count of the published rows in words
 * rather than as digits, and both counts belong to the rows rather than to the memory of whoever wrote
 * the sentence.
 */
function epochInventoryProse(): string {
  const doc = readFileSync(DOC, 'utf8');
  const start = doc.indexOf('\n- **Epoch inventory.');
  if (start < 0) throw new Error('docs/vectors.md states no Epoch inventory bullet to read');
  const rest = doc.slice(start);
  const end = rest.indexOf('\n## ');
  return (end < 0 ? rest : rest.slice(0, end)).replace(/\n\s*/gu, ' ');
}

/**
 * One of the counts those bullets state about the published rows, taken back out of the sentence that
 * states it. A document that stopped claiming a count fails as a missing sentence rather than reading as
 * a claim of nothing, which is the shape an empty match would have.
 */
function countStatedByTheDocument(states: RegExp, what: string): string {
  const stated = states.exec(epochInventoryProse());
  if (stated === null) throw new Error(`the Epoch inventory bullets state no count of ${what}`);
  return stated[1]!;
}

/** One published row of the inventory suite, as the file itself spells its members. */
type InventoryRow = Record<string, unknown>;

/** The two orders an inventory row publishes beside the folded list it names, where it publishes them. */
interface InventoryReadback {
  readonly runFiles?: string[];
  readonly breakFiles?: string[];
  readonly shortFiles?: string[];
}

/**
 * The rows of the suite the table calls `Epoch inventory`, read out of the file that row names. These are
 * the rows the two bullets count, so the path comes from the document rather than from a path typed in
 * beside it.
 */
function inventoryRows(): InventoryRow[] {
  const row = rows.find((each) => each.suite === 'Epoch inventory');
  if (row === undefined) throw new Error('the suite table lists no Epoch inventory row to read the file from');
  const files = row.files.filter((each) => each.endsWith('.json'));
  if (files.length !== 1) {
    throw new Error(`the Epoch inventory row names ${String(files.length)} files, and this reads the one`);
  }
  const named = files[0]!;
  const found = resolve(named);
  if (found === null) throw new Error(`${named} is named by the Epoch inventory row and is not there to read`);
  const parsed = JSON.parse(readFileSync(found, 'utf8')) as { vectors?: unknown };
  if (!Array.isArray(parsed.vectors)) throw new Error(`${named} publishes no vectors array to read`);
  return parsed.vectors as InventoryRow[];
}

/**
 * Whether one published inventory row states one of the two folded lists in the reverse of the order the
 * run puts its packs in. The file carries both orders on the rows that state them: `site` names which of
 * the two lists the row speaks about, and the `readback` beside it carries `runFiles`, the run the
 * entries' own figures put back into order, and that list as the document states it. A list of one entry
 * states no order for this to call the reverse of, so a row carrying one entry is not one of these.
 */
function statesAReversedList(row: InventoryRow): boolean {
  const site = row.site;
  if (site !== 'chain.breaks' && site !== 'duty.short') return false;
  const readback = row.readback as InventoryReadback | undefined;
  if (readback === undefined) return false;
  const run = readback.runFiles;
  const stated = site === 'chain.breaks' ? readback.breakFiles : readback.shortFiles;
  if (!Array.isArray(run) || !Array.isArray(stated) || stated.length < 2) return false;
  const inRunOrder = run.filter((one) => stated.includes(one));
  if (inRunOrder.length !== stated.length) return false;
  return stated.every((one, at) => one === inRunOrder[inRunOrder.length - 1 - at]);
}

const rows = suiteRows();

describe('docs/vectors.md suite inventory', () => {
  it('names a file for every suite, and every file it names is there', () => {
    for (const row of rows) {
      expect(row.files.length, `${row.suite} names no file`).toBeGreaterThan(0);
      for (const path of row.files) {
        const found = resolve(path);
        expect(found, `${row.suite} names ${path}, which does not exist`).not.toBeNull();
        if (found === null) continue;
        const stat = statSync(found);
        if (path.endsWith('/')) {
          expect(stat.isDirectory(), `${row.suite} names ${path}, which is not a directory`).toBe(true);
        } else {
          expect(stat.isFile(), `${row.suite} names ${path}, which is not a file`).toBe(true);
        }
      }
    }
  });

  it('names the published suites and nothing else', () => {
    // The other direction, which is the one a new suite drifts through: a file added to `data/`
    // without a row leaves a port reading the document and never meeting it, and a row outliving its
    // file says a suite is published when it is gone.
    const named = new Set(
      rows.flatMap((row) => row.files).filter((each) => each.endsWith('.json')).map((each) => basename(each)),
    );
    const published = publishedSuites();
    for (const file of published) {
      expect(named, `${file} is published but no row names it`).toContain(file);
    }
    for (const file of named) {
      expect(published, `${file} is named by a row and is not published in data/`).toContain(file);
    }
  });

  it('states a version each file it names carries', () => {
    for (const row of rows) {
      const values = stated(row.versionCell);
      const jsons = row.files.filter((each) => each.endsWith('.json'));
      const pointedAt = named(row.versionCell).filter((each) => each.endsWith('.json')).map((each) => basename(each));
      expect(
        values.length + pointedAt.length,
        `${row.suite} states a version neither as a value nor as the file it belongs to`,
      ).toBeGreaterThan(0);
      for (const path of jsons) {
        const version = versionOf(path);
        if (values.length > 0) {
          expect(values.length, `${row.suite} states one version for more than one file`).toBe(1);
          expect(`${row.suite}: ${basename(path)} is at version ${String(version)}`).toBe(
            `${row.suite}: ${basename(path)} is at version ${String(values[0])}`,
          );
        } else {
          // The row gives no number: it says which file the version belongs to, and all this can ask
          // is that the answer is a whole version of that file rather than a field of something else.
          expect(pointedAt, `${row.suite} states the version of a file the row does not name`).toContain(
            basename(path),
          );
          expect(Number.isInteger(version), `${path} carries a whole version`).toBe(true);
          expect(version, `${path} carries a version above zero`).toBeGreaterThan(0);
        }
      }
    }
  });

  it('gives a rule in prose to the suites that state their version as a value', () => {
    // What the document's sentence about `description` is scoped to: a generated suite states its
    // version as a value and its rule in prose, and the manifest, which lists artefacts instead of
    // stating a rule, carries neither. A file that gained a stated version without the description
    // the same sentence promises is the shape of defect that sentence exists to be true of.
    for (const row of rows) {
      if (stated(row.versionCell).length === 0) continue;
      for (const path of row.files.filter((each) => each.endsWith('.json'))) {
        const found = resolve(path);
        if (found === null) throw new Error(`${path} is named by the inventory and is not there to read`);
        const parsed = JSON.parse(readFileSync(found, 'utf8')) as { description?: unknown };
        expect(
          typeof parsed.description === 'string' && parsed.description.length > 0,
          `${row.suite} states a version value, so ${basename(path)} has to carry the description the document promises`,
        ).toBe(true);
      }
    }
  });

  it('publishes a refusal with a listed code in every suite it tabulates', () => {
    // The sentence this guards is the section above the rows: each suite carries at least one case whose
    // verdict is a refusal, and every code those cases name is one the error-code document lists. Both
    // halves are read off the files, because a suite that lost its negative rows would keep a table that
    // still looked right, and a row that named a code no union declares would be a word nobody answers.
    const codes = documentedCodes();
    // The sentence's opening word counts the suites it speaks for, and what it counts is the table's rows, so
    // the word is read back out of the section and held against them: a table that gained a suite row, or lost
    // one, would otherwise keep a sentence claiming a number the document no longer matches.
    const stated = /Each of the ([a-z]+) suites the table above lists/u.exec(refusalSection());
    expect(stated, 'the section stopped counting the suites it speaks for').not.toBeNull();
    expect(spelledNumber(stated?.[1] ?? ''), 'and the count it states is not the count of rows').toBe(rows.length);
    for (const row of rows) {
      const files = row.files.filter((each) => each.endsWith('.json')).map((each) => basename(each));
      expect(files.length, `${row.suite} names no file to read verdicts out of`).toBeGreaterThan(0);
      const verdicts = files.flatMap((each) => verdictsOf(each));
      expect(verdicts.length, `${row.suite} states no verdicts at all`).toBeGreaterThan(0);
      const refused = verdicts.filter((each) => each.verdict !== 'verify-ok');
      expect(refused.length, `${row.suite} publishes no case whose verdict is a refusal`).toBeGreaterThan(0);
      for (const each of refused) {
        const code = each.code ?? each.verdict;
        expect(code, `${row.suite} has a refusal naming nothing`).toMatch(/^[A-Z][A-Z0-9_]*$/u);
        expect(codes.has(code), `${row.suite} refuses with ${code}, which error-codes.md does not list`).toBe(
          true,
        );
      }
    }
  });

  it('states how many inventory rows carry an edit block, and the rows agree', () => {
    // The sentence counts the rows stating an `edit` block, and that count is a fact of the published file:
    // a row gaining or losing its block moves one of the two sides of this comparison. What the same
    // sentence says about the two it counts, that they are the honest span replaced with a longer run
    // label and differ by one byte at one position, one accepted and one refused, is held row by row by the
    // inventory's own width-pair case in `epoch-inventory-vectors.test.ts`. What nothing held was the
    // number standing in the document.
    const stating = inventoryRows().filter((one) => one.edit !== undefined);
    expect(
      spelledNumber(
        countStatedByTheDocument(/([A-Za-z]+) rows state an `edit` block/u, 'the rows stating an edit block'),
      ),
      'the document counts a different number of rows stating an edit block than the rows do',
    ).toBe(stating.length);
  });

  it('states that the inventory rows reversing a folded list are acceptances', () => {
    // Two claims in one sentence, both read off the rows: that the count of rows stating one of the two
    // folded lists in the reverse of the order the run puts those packs in is the count the sentence states,
    // and that every one of them is an acceptance rather than an oversight. The keying the sentence appeals
    // to is why a reversal is accepted at all, so a row that turned from an acceptance into a refusal, or a
    // reversal the suite gained or lost, is refused here rather than left standing in prose.
    const reversed = inventoryRows().filter(statesAReversedList);
    expect(
      spelledNumber(
        countStatedByTheDocument(
          /the ([a-z]+) rows stating a reversed list are acceptances/u,
          'the rows stating a reversed list',
        ),
      ),
      'the document counts a different number of rows stating a reversed list than the rows do',
    ).toBe(reversed.length);
    for (const one of reversed) {
      expect(
        one.verdict,
        `${String(one.name)} states a folded list in the other order and is not an acceptance`,
      ).toBe('verify-ok');
    }
  });
});
