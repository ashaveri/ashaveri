import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { basename, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { DATA } from '../src/index.js';

/**
 * The suite inventory in `docs/vectors.md` is the index a port starts from: it names the file of each
 * published suite and the version field that file carries. Both are copies of facts that live in
 * `data/`, and a copy is how a document comes to state something the artefacts stopped carrying. This
 * reads the table as data and checks it against them, which is the whole of what it does — the prose
 * around the rows is reviewed by the people who write it, not parsed here.
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
});
