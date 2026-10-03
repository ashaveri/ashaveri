import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  ANCHOR_LEDGER_FILES,
  ANCHOR_LICENCE_CLASSES,
  parseAnchorLedger,
  type AnchorLicenceClass,
} from '../src/anchor-ledger.js';
import { fixture } from './helpers.js';

/**
 * `docs/trust-anchors.md` is the prose a reader meets before the artifact: it projects the ledger's
 * provenance half into a table, and the half it projects is exactly the half no computation reaches,
 * so nothing else in this package holds it to anything. A row whose source, day or licence class
 * drifts between the document and the ledger is a repository stating two different provenances for
 * one file, and the reader of the document has no way to tell which one the bytes arrived under.
 *
 * The comparison is in both directions and in the ledger's own order, because a table that dropped a
 * row and one that added a row are both a document disagreeing with the artifact, and an order that
 * moves is a table a reviewer cannot line up against the file it describes. The arithmetic half of a
 * row is not read here: `test/anchor-ledger.test.ts` holds that to the bytes, one case per file, and
 * a document that copied a digest would only add a place for it to go stale.
 *
 * The tables are parsed rather than imported, the way every document test in this workspace parses:
 * the shape on the page is the thing under test, and a reader that guessed at a row it could not find
 * would report a document that stopped claiming anything as one that agrees.
 */

const DOC_PATH = new URL('../../../docs/trust-anchors.md', import.meta.url);
const LEDGER_PATH = new URL('../data/anchor-provenance-v1.cbor', import.meta.url);

/** The header of each table this suite reads, spelled the way the document spells it. */
const ROW_TABLE = '| Family | File | Taken | Licence | Source |';
const CLASS_TABLE = '| Class | Rows | What it means here |';

const FIXTURE_PREFIX = 'test/fixtures/';

/** Every tracked fixture under the name a row gives it, since only the embedded three resolve from source. */
const SHIPPED: ReadonlyMap<string, Uint8Array> = new Map<string, Uint8Array>(
  ANCHOR_LEDGER_FILES.filter((file) => file.startsWith(FIXTURE_PREFIX)).map((file) => [
    file,
    fixture(file.slice(FIXTURE_PREFIX.length)),
  ]),
);

const document = parseAnchorLedger(new Uint8Array(readFileSync(LEDGER_PATH)), { shipped: SHIPPED });
const markdown = readFileSync(DOC_PATH, 'utf8');

/** The day a row states, which is the first second of a UTC day in the ledger and a date on the page. */
function utcDay(seconds: number): string {
  return new Date(seconds * 1000).toISOString().slice(0, 10);
}

/** How many times a phrase appears, so a claim stated twice is a finding rather than a pass. */
function occurrences(haystack: string, phrase: string): number {
  return haystack.split(phrase).length - 1;
}

/**
 * The rows below one table header, as trimmed cells including the leading and trailing empty ones a
 * split on the pipe leaves behind. The header has to appear exactly once, and a row that runs onto a
 * second physical line is refused rather than skipped: markdown closes the table at that line and
 * renders the rest as a paragraph, so a reader that stopped there would hand back the rows above the
 * break as if the table still held them all.
 */
function tableRows(text: string, header: string): string[][] {
  const lines = text.split('\n');
  const headers = lines.map((line, at) => (line === header ? at : -1)).filter((at) => at >= 0);
  if (headers.length !== 1) {
    throw new Error(`the table headed ${header} appears ${String(headers.length)} times, and this reads exactly one`);
  }
  const rows: string[][] = [];
  for (const line of lines.slice(headers[0]! + 1)) {
    if (!line.startsWith('| `')) {
      if (line.startsWith('|---')) continue;
      if (line.trim().length === 0 || line.startsWith('|')) break;
      throw new Error(
        `a row of the table headed ${header} runs onto the line ${JSON.stringify(line.slice(0, 60))}, ` +
          'which ends the table: one row per physical line, or the rows behind it render outside the table',
      );
    }
    rows.push(line.split('|').map((cell) => cell.trim()));
  }
  if (rows.length === 0) throw new Error(`the table headed ${header} has no rows`);
  return rows;
}

/** One documented row, its cells unbacked, from a table that carries exactly the five columns. */
function documentedRows(text: string): string[][] {
  return tableRows(text, ROW_TABLE).map((cells) => {
    if (cells.length !== 7) {
      throw new Error(`a row of the row table carries ${String(cells.length - 2)} cells and this reads five: ${cells.join('|')}`);
    }
    return cells.slice(1, 6).map((cell) => cell.replace(/`/gu, ''));
  });
}

/** What the ledger states for one row, in the five columns the document prints. */
function ledgerRow(file: string): string[] {
  const row = document.rows.find((one) => one.file === file);
  if (row === undefined) throw new Error(`the committed ledger names no row for ${file}`);
  return [row.family, row.file, utcDay(row.takenAt), row.licence, row.origin];
}

describe('docs/trust-anchors.md', () => {
  it('gives one row to each row of the committed ledger, in the ledger order', () => {
    expect(documentedRows(markdown)).toEqual(ANCHOR_LEDGER_FILES.map((file) => ledgerRow(file)));
  });

  it('states the counts the ledger holds, in the sentence that carries them', () => {
    const stated =
      /There are (\d+) rows, in the ledger's own\s+order: (\d+) embedded anchors and then (\d+) tracked files/u.exec(
        markdown,
      );
    expect(stated, 'the opening paragraph must give all three counts as digits').not.toBeNull();
    const embedded = ANCHOR_LEDGER_FILES.filter((file) => !file.startsWith(FIXTURE_PREFIX)).length;
    expect([Number(stated?.[1]), Number(stated?.[2]), Number(stated?.[3])], 'rows, embedded, tracked').toEqual([
      document.rows.length,
      embedded,
      ANCHOR_LEDGER_FILES.length - embedded,
    ]);
    expect(document.rows.length, 'and the ledger covers every file the roster names').toBe(
      ANCHOR_LEDGER_FILES.length,
    );
  });

  it('counts each licence class the way the ledger does, over the four the format declares', () => {
    const classes = tableRows(markdown, CLASS_TABLE).map((cells) => {
      if (cells.length !== 5) throw new Error(`a class row carries ${String(cells.length - 2)} cells and this reads three`);
      return { name: cells[1]!.replace(/`/gu, ''), rows: Number(cells[2]) };
    });
    expect(classes.map((one) => one.name), 'the classes the document explains').toEqual([
      ...ANCHOR_LICENCE_CLASSES,
    ]);
    for (const one of classes) {
      const counted = document.rows.filter((row) => row.licence === (one.name as AnchorLicenceClass)).length;
      expect(one.rows, `rows the document counts as ${one.name}`).toBe(counted);
    }
    expect(
      classes.reduce((total, one) => total + one.rows, 0),
      'the class counts sum to the row count',
    ).toBe(document.rows.length);
  });

  it('states the one licence note the ledger carries, once', () => {
    const noted = document.rows.filter((row) => row.licenceNote !== undefined);
    expect(noted.map((row) => row.file), 'the rows carrying a note').toEqual(['test/fixtures/tdx-quote-v4.bin']);
    const note = noted[0]?.licenceNote;
    expect(note, 'the note itself').toBeDefined();
    expect(occurrences(markdown, note as string), 'the note on the page').toBe(1);
  });

  it('names the suite that holds it to the artifact', () => {
    expect(markdown).toContain('packages/attest-core/test/trust-anchors-doc.test.ts');
  });

  /**
   * The refusal above is a branch nothing else exercises, so it is exercised on a document written for
   * the purpose, in the shape GitHub-flavoured markdown actually gives: the table closes at the
   * continuation line, the continuation renders as a paragraph, and the row behind it renders outside
   * any table. A reader that skipped the line would still return every row above the break, and one
   * that stopped there would return none of the rows below it, and either way the shipped table would
   * have looked shorter than it is rather than broken.
   */
  it('refuses a row that continues onto a line which is not a row', () => {
    const wrapped = [
      ROW_TABLE,
      '|---|---|---|---|---|',
      '| `intel` | `test/fixtures/intel-sgx-root-ca.pem` | 2026-09-11 | `none-stated` | https://example/',
      'root.pem |',
      '| `amd` | `test/fixtures/sev-snp-ask.pem` | 2026-06-17 | `none-stated` | https://example/kds |',
      '',
    ].join('\n');
    expect(() => tableRows(wrapped, ROW_TABLE)).toThrow(/one row per physical line/u);
    // The shipped table passes through the same reader, which is what makes the refusal about a reader
    // rather than about a shape no document of this estate can be written in.
    expect(documentedRows(markdown)).toHaveLength(document.rows.length);
  });
});
