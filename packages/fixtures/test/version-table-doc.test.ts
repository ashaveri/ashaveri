import { describe, expect, it } from 'vitest';
import { declaredVersions, readSourceFile, sectionBody } from './doc-contract.js';

/**
 * Section 7 of `docs/receipt-spec.md` is the promise a published version makes about the bytes it can
 * read: one row per document family, the package that ships the reader, the entry points a consumer calls,
 * and the format versions that reader parses. Every one of those four cells is a fact about the source, and
 * before this file no test read any of them, so the branch's published claim about which family admits which
 * versions rested on a document nobody checked.
 *
 * Three properties the reading has to hold, and why each is here.
 *
 *   A row that cannot be parsed fails the run, and the failure says which rows were read. The trap in a
 *   table of version sets is a reader that truncates a cell: `1; 2` read up to the semicolon is `1`, which is
 *   what the source says, so the family keeps a row that agrees and the disagreement hides in the half of the
 *   cell nobody looked at. Worse, a reader that stops at a line it does not recognise reports the families
 *   above the stop and stays silent about the ones below, and a family whose row went unread then looks exactly
 *   like a family that has no row. So each cell here is read against one exact spelling and anything else is
 *   named and refused, and the family roster below is compared in both directions against the rows that were
 *   actually parsed.
 *
 *   `doc-contract.ts` holds the shared table reader, and this file does not use it. Every table that reader
 *   holds opens in a backticked cell, and every row of this one opens in a plain family name, so it closes the
 *   table at its first data line and reports the table as holding no rows. The refusal a document test most
 *   needs is the one that tells an unread row apart from an absent one, and at the scale of a whole table that
 *   is the distinction lost. The section reader is shared, and so is the version-list reader; what is written
 *   here is the two cell readers this table's shape needs, and they keep the property the shared one was written
 *   for: a cell carrying anything other than the one spelling this understands is named and refused, never
 *   skipped.
 *
 *   A disagreement is named by family. The table states nothing about which module holds a family's version
 *   set, so the roster below carries that pairing, which is the one place this file restates a claim rather
 *   than reading it: the sets themselves come out of the source, and a roster entry that stops resolving is a
 *   thrown error rather than a skipped family.
 *
 * What this reaches, stated as a limit: the version set a family's own module declares, the package the table
 * ships it under, and the entry points it names. It does not weigh the vendor paragraph's version figures,
 * because those numbers belong to their issuers and one of them is spelled `1.1`, which the shared version
 * reader refuses as a number; what is held of that paragraph is that the readers it names exist in the package
 * it names, and that the families it excludes are absent from the table.
 */

const RECEIPT_SPEC = '../../../docs/receipt-spec.md';
const SPEC_SECTION = '## 7. Published compatibility';
const FAMILIES_TABLE = '| Document family | Ships in | Reader a consumer calls | Versions parsed |';
const VENDOR_PARAGRAPH_MARKER = 'Documents whose layout a vendor defines';

/** The index a consumer resolves through, for each package the table ships a reader in. */
const PACKAGE_INDEX: Record<string, string> = {
  '@ashaveri/receipt': '../../receipt/src/index.ts',
  '@ashaveri/sdk': '../../sdk/src/index.ts',
  '@ashaveri/attest-core': '../../attest-core/src/index.ts',
};

/**
 * Where one family's accepted versions are written in the source that ships its reader. The three shapes are
 * the three the published readers use: a declared list, a single declared version, and a version tested
 * against a literal at the refusal.
 */
type DeclaredSet =
  | { readonly kind: 'list'; readonly name: string }
  | { readonly kind: 'scalar'; readonly name: string }
  | { readonly kind: 'guard'; readonly marker: string };

interface FamilySource {
  readonly family: string;
  readonly pkg: string;
  readonly file: string;
  readonly declared: DeclaredSet;
}

/** The seventeen families section 7's table is kept for, and the module holding each set. */
const FAMILY_SOURCES: readonly FamilySource[] = [
  { family: 'Receipt payload', pkg: '@ashaveri/receipt', file: '../../receipt/src/receipt.ts', declared: { kind: 'list', name: 'PARSED_VERSIONS' } },
  { family: 'Evidence pack manifest', pkg: '@ashaveri/receipt', file: '../../receipt/src/pack.ts', declared: { kind: 'guard', marker: 'PACK_UNSUPPORTED_VERSION' } },
  { family: 'Technical export manifest', pkg: '@ashaveri/receipt', file: '../../receipt/src/export.ts', declared: { kind: 'guard', marker: 'EXPORT_UNSUPPORTED_VERSION' } },
  { family: 'Redaction manifest', pkg: '@ashaveri/receipt', file: '../../receipt/src/redaction.ts', declared: { kind: 'guard', marker: 'REDACTION_UNSUPPORTED_VERSION' } },
  { family: 'Epoch inventory', pkg: '@ashaveri/receipt', file: '../../receipt/src/epoch-inventory.ts', declared: { kind: 'guard', marker: 'EPOCH_INVENTORY_UNSUPPORTED_VERSION' } },
  { family: 'Destruction receipt', pkg: '@ashaveri/receipt', file: '../../receipt/src/destruction-receipt.ts', declared: { kind: 'guard', marker: 'DESTRUCTION_RECEIPT_UNSUPPORTED_VERSION' } },
  { family: 'Retention manifest', pkg: '@ashaveri/receipt', file: '../../receipt/src/retention.ts', declared: { kind: 'list', name: 'RETENTION_FORMAT_VERSIONS' } },
  { family: 'Disclosure record', pkg: '@ashaveri/receipt', file: '../../receipt/src/disclosure-record.ts', declared: { kind: 'list', name: 'DISCLOSURE_RECORD_VERSIONS' } },
  { family: 'Model inventory record', pkg: '@ashaveri/receipt', file: '../../receipt/src/model-inventory.ts', declared: { kind: 'list', name: 'MODEL_INVENTORY_VERSIONS' } },
  { family: 'Hold record', pkg: '@ashaveri/receipt', file: '../../receipt/src/hold.ts', declared: { kind: 'list', name: 'HOLD_RECORD_VERSIONS' } },
  { family: 'Incident preservation bundle', pkg: '@ashaveri/receipt', file: '../../receipt/src/incident-bundle.ts', declared: { kind: 'list', name: 'INCIDENT_BUNDLE_VERSIONS' } },
  { family: 'Deployment manifest', pkg: '@ashaveri/sdk', file: '../../sdk/src/manifest.ts', declared: { kind: 'guard', marker: 'v must be 1' } },
  { family: 'Capture record', pkg: '@ashaveri/sdk', file: '../../sdk/src/capture.ts', declared: { kind: 'scalar', name: 'CAPTURE_FORMAT_VERSION' } },
  { family: 'Import envelope', pkg: '@ashaveri/sdk', file: '../../sdk/src/import-envelope.ts', declared: { kind: 'scalar', name: 'IMPORT_FORMAT_VERSION' } },
  { family: 'Retention assessment', pkg: '@ashaveri/sdk', file: '../../sdk/src/retention-assessment.ts', declared: { kind: 'scalar', name: 'RETENTION_ASSESSMENT_FORMAT_VERSION' } },
  { family: 'Verification policy file', pkg: '@ashaveri/sdk', file: '../../sdk/src/policy-file.ts', declared: { kind: 'scalar', name: 'POLICY_FORMAT_VERSION' } },
  { family: 'Anchor provenance ledger', pkg: '@ashaveri/attest-core', file: '../../attest-core/src/anchor-ledger.ts', declared: { kind: 'scalar', name: 'ANCHOR_LEDGER_FORMAT_VERSION' } },
];

/** The vendor families the paragraph below the table says are read but not listed, and the readers it names. */
const VENDOR_READERS: readonly (readonly [reader: string, named: string])[] = [
  ['decodeAttestation', 'dStack'],
  ['parseSnpReport', 'AMD SEV-SNP'],
  ['verifyTdxQuote', 'Intel TDX'],
  ['parseNvidiaEvidenceBundle', 'NVIDIA'],
];

/** One parsed row: the four cells, the two of them read as values, and the line they came from. */
interface Row {
  readonly family: string;
  readonly pkg: string;
  readonly readers: readonly string[];
  readonly versions: readonly number[];
  readonly statedVersions: string;
  readonly line: string;
}

interface Unread {
  readonly line: string;
  readonly why: string;
}

function specSection(): string {
  return sectionBody(readSourceFile(RECEIPT_SPEC), SPEC_SECTION);
}

/** A file spelled the way a reader looks for it in a failure: from the repository root, not from this test. */
function shown(specifier: string): string {
  return specifier.replace(/^\.\.\/\.\.\/\.\.\//u, '').replace(/^\.\.\/\.\.\//u, 'packages/');
}

/** The package one row ships its reader in, read from the cell the table states it in. */
function rowPackage(cell: string): string {
  const found = /^`(@ashaveri\/[a-z0-9-]+)`$/u.exec(cell);
  const name = found?.[1];
  if (name === undefined) {
    throw new Error(`the "Ships in" cell spells ${JSON.stringify(cell)}, which is not one backticked package name`);
  }
  if (!(name in PACKAGE_INDEX)) {
    throw new Error(`the table ships a reader in ${name}, and this file holds no published index to read it from`);
  }
  return name;
}

/**
 * The entry points one row names: backticked, comma separated, and nothing else. The cell is rebuilt from what
 * was read and compared to what was written, so a spelling this does not model, including a semicolon standing
 * where a separator belongs, is reported instead of read as the tail of a name.
 */
function rowReaders(cell: string): string[] {
  const names = [...cell.matchAll(/`([A-Za-z][A-Za-z0-9]*)`/gu)].map((found) => String(found[1]));
  if (names.length === 0) {
    throw new Error(`the "Reader a consumer calls" cell spells ${JSON.stringify(cell)}, which names no backticked function`);
  }
  const rebuilt = names.map((one) => `\`${one}\``).join(', ');
  if (rebuilt !== cell) {
    throw new Error(`the "Reader a consumer calls" cell spells ${JSON.stringify(cell)}, which is not ${JSON.stringify(rebuilt)}`);
  }
  return names;
}

/**
 * The versions one row states: whole numbers joined by commas and one final "and". Every token has to be a
 * number on its own, so `1; 2` is refused here rather than read as `1`.
 */
function rowVersions(cell: string): number[] {
  const tokens = cell.split(/\s*,\s*|\s+and\s+/u).map((token) => token.trim()).filter((token) => token.length > 0);
  if (tokens.length === 0) {
    throw new Error(`the "Versions parsed" cell spells ${JSON.stringify(cell)}, which states no version`);
  }
  const numbers = tokens.map((token) => {
    if (!/^[0-9]+$/u.test(token)) {
      throw new Error(`the "Versions parsed" cell spells ${JSON.stringify(cell)}, and ${JSON.stringify(token)} inside it is not a version number`);
    }
    return Number(token);
  });
  if (new Set(numbers).size !== numbers.length) {
    throw new Error(`the "Versions parsed" cell states ${cell}, which names one version twice`);
  }
  return numbers.sort((a, b) => a - b);
}

/** The table, as far as it can be read: the rows that parsed, and every line that did not. */
function readFamiliesTable(): { rows: Row[]; unread: Unread[]; abandoned: Unread[] } {
  const lines = specSection().split('\n');
  const heads = lines.map((line, at) => (line === FAMILIES_TABLE ? at : -1)).filter((at) => at >= 0);
  if (heads.length !== 1) {
    throw new Error(
      `the family table header ${JSON.stringify(FAMILIES_TABLE)} appears ${String(heads.length)} times in ` +
        `${SPEC_SECTION} of ${shown(RECEIPT_SPEC)}, and this reads exactly one`,
    );
  }
  const rows: Row[] = [];
  const unread: Unread[] = [];
  const abandoned: Unread[] = [];
  let closed = false;
  for (const line of lines.slice((heads[0] ?? 0) + 1)) {
    if (line.startsWith('|---')) continue;
    if (closed) {
      if (line.startsWith('|')) {
        abandoned.push({
          line,
          why: 'it sits below a line that closed the table, so it renders outside the table and no consumer of it is reached',
        });
      }
      continue;
    }
    if (line.trim().length === 0 || !line.startsWith('|')) {
      closed = true;
      continue;
    }
    const cells = line.split('|').map((cell) => cell.trim());
    if (cells.length !== 6) {
      unread.push({
        line,
        why: `it carries ${String(cells.length - 2)} cells rather than the four the table header declares`,
      });
      continue;
    }
    const family = cells[1] ?? '';
    if (family.length === 0) {
      unread.push({ line, why: 'its first cell names no document family' });
      continue;
    }
    try {
      rows.push({
        family,
        pkg: rowPackage(cells[2] ?? ''),
        readers: rowReaders(cells[3] ?? ''),
        versions: rowVersions(cells[4] ?? ''),
        statedVersions: cells[4] ?? '',
        line,
      });
    } catch (error) {
      unread.push({ line, why: (error as Error).message });
    }
  }
  return { rows, unread, abandoned };
}

/**
 * The rows, or the reason there are not the rows. Nothing unread is left to be discovered later: every line the
 * table holds that did not turn into a claim is named, and the families that did parse are listed so a reader
 * can see how far the reading reached.
 */
function familyRows(): Row[] {
  const { rows, unread, abandoned } = readFamiliesTable();
  const complaints = [
    ...unread.map((one) => `a row was not read: ${one.why}\n  ${one.line}`),
    ...abandoned.map((one) => `a row was left behind: ${one.why}\n  ${one.line}`),
  ];
  const twice = rows
    .map((row) => row.family)
    .filter((family, at, all) => all.indexOf(family) !== at);
  if (twice.length > 0) {
    complaints.push(`the table states ${[...new Set(twice)].join(', ')} in more than one row, so one family has two promises`);
  }
  if (complaints.length > 0) {
    throw new Error(
      `${shown(RECEIPT_SPEC)} ${SPEC_SECTION} was refused rather than read:\n${complaints.join('\n')}\n` +
        `${String(rows.length)} of the table's rows were read: ${rows.map((row) => row.family).join(', ')}`,
    );
  }
  return rows;
}

/**
 * The names an index exports, separated into the ones a caller can invoke and the ones that exist only at
 * compile time. The index is walked as statements rather than by finding the ones that match, so an export this
 * cannot resolve is reported: a reader that matched some of an index and returned those names as the whole
 * roster is how a real entry point came to be reported as missing, and the same silence would wave through a
 * name that no longer exists. A star re-export or a rename on the way out leaves no complete list to read, so
 * both are thrown rather than guessed at.
 */
function exportedNames(index: string): { values: string[]; types: string[] } {
  const source = readSourceFile(index);
  const statements: string[] = [];
  let open: string[] = [];
  for (const line of source.split('\n')) {
    if (open.length === 0 && !/^export\b/u.test(line)) continue;
    open.push(line);
    if (line.includes(';')) {
      statements.push(open.join('\n').trim());
      open = [];
    }
  }
  if (open.length > 0) {
    throw new Error(`${shown(index)} ends inside an export statement, so its roster cannot be read to the end`);
  }
  if (statements.length === 0) {
    throw new Error(`${shown(index)} carries no export statement, so an entry point named in the table could not be checked`);
  }
  const values: string[] = [];
  const types: string[] = [];
  for (const statement of statements) {
    const found = /^export( type)? \{([^}]*)\} from '[^']+';$/su.exec(statement);
    if (found === null) {
      throw new Error(`${shown(index)} exports through ${JSON.stringify(statement.slice(0, 64))}, which this cannot resolve into names`);
    }
    const names = (found[2] ?? '')
      .split(',')
      .map((entry) => entry.trim())
      .filter((entry) => entry.length > 0);
    if (names.length === 0) {
      throw new Error(`${shown(index)} has an export statement naming nothing: ${JSON.stringify(statement.slice(0, 64))}`);
    }
    (found[1] === ' type' ? types : values).push(...names);
  }
  if (values.length === 0) {
    throw new Error(`${shown(index)} exports no value at all, so no entry point a consumer calls could be read from it`);
  }
  return { values, types };
}

/** The one version a scalar constant declares, read where it is declared rather than where it is used. */
function scalarVersion(name: string, file: string): number[] {
  const source = readSourceFile(file);
  const found = [...source.matchAll(new RegExp(`\\bconst ${name}\\b[^=\\n]*=\\s*([^;\\n]+)`, 'gu'))];
  if (found.length !== 1) {
    throw new Error(`${name} is declared ${String(found.length)} times in ${shown(file)}, and this reads the set from exactly one declaration`);
  }
  const stated = (found[0]?.[1] ?? '').trim();
  if (!/^[0-9]+$/u.test(stated)) {
    throw new Error(`${name} in ${shown(file)} is declared as ${JSON.stringify(stated)}, which is not one version number`);
  }
  return [Number(stated)];
}

/**
 * The version a reader tests for at the refusal that names it. The refusal line is found by the code or message
 * it carries, and the test above it is read from the nearest line holding one integer equality: a family whose
 * set is not one literal, or whose refusal this cannot locate, is reported rather than read as agreeing.
 */
function guardVersion(marker: string, file: string): number[] {
  const lines = readSourceFile(file).split('\n');
  const thrown = lines.map((line, at) => (line.includes(`'${marker}'`) ? at : -1)).filter((at) => at >= 0);
  if (thrown.length !== 1) {
    throw new Error(`${marker} is raised ${String(thrown.length)} times in ${shown(file)}, and this reads the version test above exactly one of them`);
  }
  for (let at = thrown[0] ?? 0; at >= Math.max(0, (thrown[0] ?? 0) - 10); at -= 1) {
    const tests = [...(lines[at] ?? '').matchAll(/(!==|===)\s*([0-9]+)/gu)];
    if (tests.length === 0) continue;
    if (tests.length > 1) {
      throw new Error(
        `the version test above ${marker} in ${shown(file)} reads ${JSON.stringify((lines[at] ?? '').trim())}, ` +
          'which holds more than one integer equality, so this cannot say which set the reader parses',
      );
    }
    const stated = (tests[0]?.[2] ?? '').trim();
    if ((tests[0]?.[1] ?? '') !== '!==') {
      throw new Error(`the version test above ${marker} in ${shown(file)} reads ${JSON.stringify((lines[at] ?? '').trim())}, which admits one version and refuses every other`);
    }
    return [Number(stated)];
  }
  throw new Error(`nothing within ten lines above ${marker} in ${shown(file)} tests a version against a number`);
}

/** The set the owning module states, read through whichever of the three shapes that module writes it in. */
function sourceVersions(source: FamilySource): number[] {
  const declared = source.declared;
  const versions =
    declared.kind === 'list'
      ? declaredVersions(declared.name, source.file)
      : declared.kind === 'scalar'
        ? scalarVersion(declared.name, source.file)
        : guardVersion(declared.marker, source.file);
  if (versions.length === 0) {
    throw new Error(`${shown(source.file)} declares no version for ${source.family}, so there is nothing to hold the table to`);
  }
  return [...new Set(versions)].sort((a, b) => a - b);
}

function sourceFor(family: string): FamilySource | undefined {
  return FAMILY_SOURCES.find((one) => one.family === family);
}

describe('the published compatibility table states the version sets its readers hold', () => {
  it('reads one row for every document family the table is kept for', () => {
    const rows = familyRows();
    const stated = rows.map((row) => row.family).sort();
    const kept = FAMILY_SOURCES.map((one) => one.family).sort();
    expect(
      stated,
      `the table's rows were read as ${stated.join(', ')}; the families this holds a reader for are ` +
        `${kept.join(', ')}; a row that was not read and a row this has no source for both land here`,
    ).toEqual(kept);
    expect(
      rows.map((row) => `${row.family} ships in ${row.pkg}`).sort(),
      'the table ships a reader in a package other than the one this reads that family in its source from',
    ).toEqual(FAMILY_SOURCES.map((one) => `${one.family} ships in ${one.pkg}`).sort());
  });

  it('states each family version set as the owning reader declares it', () => {
    const offenders: string[] = [];
    for (const row of familyRows()) {
      const source = sourceFor(row.family);
      if (source === undefined) {
        offenders.push(`${row.family} has a row and no source this reads, so its stated set was compared against nothing`);
        continue;
      }
      const declared = sourceVersions(source);
      if (row.versions.join(', ') !== declared.join(', ')) {
        offenders.push(
          `${row.family}: ${shown(RECEIPT_SPEC)} states versions parsed as "${row.statedVersions}" ` +
            `and ${shown(source.file)} reads ${declared.map((one) => String(one)).join(', ')}`,
        );
      }
    }
    expect(offenders, 'the table states a version set a reader does not parse').toEqual([]);
  });

  it('names a reader the shipping package exports', () => {
    const offenders: string[] = [];
    for (const row of familyRows()) {
      const exported = exportedNames(PACKAGE_INDEX[row.pkg] ?? '');
      for (const reader of row.readers) {
        if (!exported.values.includes(reader)) {
          const where = exported.types.includes(reader) ? 'it is exported as a type, so no consumer calls it' : 'it is in no export block of that index';
          offenders.push(`${row.family}: ${shown(RECEIPT_SPEC)} names ${reader} as the entry point a consumer calls, and ${row.pkg} does not export it (${where})`);
        }
      }
    }
    expect(offenders, 'the table names a reader a consumer cannot import').toEqual([]);
  });

  it('keeps the vendor families out of the table and their readers in the package that reads them', () => {
    const section = specSection();
    const paragraphs = section
      .split(/\n\n+/u)
      .filter((paragraph) => paragraph.includes(VENDOR_PARAGRAPH_MARKER));
    if (paragraphs.length !== 1) {
      throw new Error(
        `"${VENDOR_PARAGRAPH_MARKER}" opens ${String(paragraphs.length)} paragraphs of ${shown(RECEIPT_SPEC)} ` +
        `${SPEC_SECTION}, and the vendor claims are read from exactly one`,
      );
    }
    const paragraph = paragraphs[0] ?? '';
    const exported = exportedNames(PACKAGE_INDEX['@ashaveri/attest-core'] ?? '');
    const offenders: string[] = [];
    for (const [reader, named] of VENDOR_READERS) {
      if (!paragraph.includes(`\`${reader}\``)) {
        offenders.push(`${named}: the vendor paragraph no longer names ${reader} as the reader it weighs`);
      }
      if (!exported.values.includes(reader)) {
        offenders.push(`${named}: the vendor paragraph names ${reader}, and @ashaveri/attest-core exports no such value`);
      }
    }
    for (const row of familyRows()) {
      const vendor = VENDOR_READERS.filter(([reader, named]) => row.family.includes(named) || row.readers.includes(reader));
      if (vendor.length > 0) {
        offenders.push(
          `${row.family}: the vendor paragraph says these families are not in the table, and the table states a row for it`,
        );
      }
    }
    expect(offenders, 'the vendor paragraph and the family table no longer agree about what is listed').toEqual([]);
  });
});
