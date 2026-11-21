import { describe, expect, it } from 'vitest';
import { existsSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  declaredVersions,
  isPublishable,
  readSourceFile,
  scopedManifests,
  sectionBody,
  spelledNumber,
} from './doc-contract.js';

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
 * What this reaches: the version set a family's own module declares, the package the table ships it under, the
 * entry points it names, the four figures the vendor paragraph states for the layouts a vendor owns, and the
 * sentence counting the published packages that add no family of their own. The two paragraphs at the end are
 * read from the same section, so a figure that moved alone in one of them lands here rather than in a review.
 *
 * The vendor figures are read the way the rows are, against the refusal that states them, with one addition:
 * they are not all whole numbers. `1.1` is how SPDM writes a two-part version, and the source holds it as the
 * byte `0x11`, so a byte is spelled back into the dotted form the document uses and a byte whose halves are not
 * both digits is refused rather than rounded. Nothing is coerced between `1` and `1.1`: two version numbers
 * written in different shapes are two sets, and the paragraph that states one while the reader refuses at the
 * other is wrong in a way a consumer publishes.
 */

const RECEIPT_SPEC = '../../../docs/receipt-spec.md';
const SPEC_SECTION = '## 7. Published compatibility';
const FAMILIES_TABLE = '| Document family | Ships in | Reader a consumer calls | Versions parsed |';
const VENDOR_PARAGRAPH_MARKER = 'Documents whose layout a vendor defines';
const NO_FAMILY_MARKER = 'add no document family of their own:';

/** Where the workspace keeps its packages: one directory each, plus the gateway beside them. */
const PACKAGES_PARENT = '../../';
const GATEWAY_DIR = '../../../gateway';

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

/**
 * The vendor families the paragraph below the table says are read but not listed. Four things are held of each:
 * the reader the paragraph names exists and is exported by the package it names, the family stays out of the
 * table, the version figure the paragraph states is the set the module refuses everything else at, and the code
 * the paragraph answers with is the code that refusal raises.
 *
 * `marker` is a phrase only that refusal's own message carries, because a published reader can raise one code
 * for several reasons: `UNSUPPORTED_VERSION` answers a legacy envelope tag, a platform variant and the version
 * field, and only the third of them is the figure the paragraph states. The phrase locates the refusal, the
 * refusal locates the guard above it, and the guard is what states the set.
 */
interface VendorFamily {
  readonly named: string;
  readonly reader: string;
  readonly file: string;
  readonly marker: string;
}

const VENDOR_FAMILIES: readonly VendorFamily[] = [
  { named: 'dStack', reader: 'decodeAttestation', file: '../../attest-core/src/decode.ts', marker: 'envelope version field' },
  { named: 'AMD SEV-SNP', reader: 'parseSnpReport', file: '../../attest-core/src/sev-snp.ts', marker: 'report version' },
  { named: 'Intel TDX', reader: 'verifyTdxQuote', file: '../../attest-core/src/tdx-dcap.ts', marker: 'quote version' },
  { named: 'NVIDIA', reader: 'parseNvidiaEvidenceBundle', file: '../../attest-core/src/nvidia.ts', marker: 'declares SPDM version' },
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

/** What the one declaration of a constant sets it to, still spelled as the source spells it. */
function declaredValue(name: string, file: string): string {
  const source = readSourceFile(file);
  const found = [...source.matchAll(new RegExp(`\\bconst ${name}\\b[^=\\n]*=\\s*([^;\\n]+)`, 'gu'))];
  if (found.length !== 1) {
    throw new Error(`${name} is declared ${String(found.length)} times in ${shown(file)}, and this reads the set from exactly one declaration`);
  }
  return (found[0]?.[1] ?? '').trim();
}

/** The one version a scalar constant declares, read where it is declared rather than where it is used. */
function scalarVersion(name: string, file: string): number[] {
  const stated = declaredValue(name, file);
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

/**
 * The paragraph below the table that states what is read but not listed. Both of the claims held here are in
 * this one paragraph, so both are read from it, and the refusal is the same shape the rows use: a paragraph
 * that grew a second copy, or lost the one it had, is reported rather than read out of whichever is nearest.
 */
function vendorParagraph(): string {
  const paragraphs = specSection()
    .split(/\n\n+/u)
    .filter((paragraph) => paragraph.includes(VENDOR_PARAGRAPH_MARKER));
  if (paragraphs.length !== 1) {
    throw new Error(
      `"${VENDOR_PARAGRAPH_MARKER}" opens ${String(paragraphs.length)} paragraphs of ${shown(RECEIPT_SPEC)} ` +
        `${SPEC_SECTION}, and the vendor claims are read from exactly one`,
    );
  }
  return paragraphs[0] ?? '';
}

/** The paragraph broken where it breaks its own claims: at its sentences, then at the semicolons inside them. */
function paragraphClauses(paragraph: string): string[] {
  const clauses: string[] = [];
  for (const sentence of paragraph.split(/(?<=\.)\s+/u)) clauses.push(...sentence.split(';'));
  return clauses;
}

/** The one clause naming this reader, or the reason its claim is not stated exactly once. */
function vendorClause(clauses: readonly string[], family: VendorFamily): string {
  const stated = clauses.filter((clause) => clause.includes(`\`${family.reader}\``));
  if (stated.length !== 1) {
    throw new Error(
      `the vendor paragraph of ${shown(RECEIPT_SPEC)} ${SPEC_SECTION} names ${family.reader} in ` +
        `${String(stated.length)} clauses, and its figure is read from exactly one`,
    );
  }
  return (stated[0] ?? '').trim();
}

const VERSION_TOKEN = /^[0-9]+(?:\.[0-9]+)?$/u;

/** Two version spellings ordered: a dotted pair sits above the whole number it grows out of. */
function compareVersionTokens(a: string, b: string): number {
  const [leftMajor = 0, leftMinor = 0] = a.split('.').map((part) => Number(part));
  const [rightMajor = 0, rightMinor = 0] = b.split('.').map((part) => Number(part));
  return leftMajor - rightMajor || leftMinor - rightMinor;
}

/**
 * What the clause says about the reader: everything after the name it names it by. The sentence introducing the
 * claims argues about versions in general before any of them is stated, so a figure, a code or a direction read
 * out of the wrong half of a sentence is a disagreement a published document could carry without noticing.
 */
function claimTail(clause: string, family: VendorFamily): string {
  const named = clause.indexOf(`\`${family.reader}\``);
  if (named < 0) {
    throw new Error(`the clause this was asked to read names neither ${family.reader} nor anything else it could follow`);
  }
  return clause.slice(named + family.reader.length + 2);
}

const VERSION_RUN = /^\s*(?<list>\d+(?:\.\d+)?(?:\s*(?:,|and)\s*\d+(?:\.\d+)?)*)(?=\s|$)/u;

/**
 * The figure the clause states, read from the run of version numbers written right after the one word `version`
 * following the reader's name. The run takes everything joined to the first number by a comma or by "and" and
 * stops where the next joiner does not lead to another number, so "must state version 1 and is answered" states
 * `1` and "accepts versions 2, 3 and 4 and refuses any other" states `2, 3, 4`: the "and" that ends a run joins
 * verbs, not versions, and a figure that runs onto it is read no further than the numbers.
 */
function clauseFigure(clause: string, family: VendorFamily): string[] {
  const tail = claimTail(clause, family);
  const uses = [...tail.matchAll(/\bvers(?:ion|ions)\b/gu)];
  if (uses.length !== 1) {
    throw new Error(
      `the clause naming ${family.reader} states the word version ${String(uses.length)} times after it, and ` +
        `${JSON.stringify(tail.trim())} is not a figure this could take once`,
    );
  }
  const after = tail.slice((uses[0]?.index ?? 0) + (uses[0]?.[0]?.length ?? 0));
  const stated = VERSION_RUN.exec(after)?.groups?.['list'];
  if (stated === undefined) {
    throw new Error(`the clause naming ${family.reader} states no version after the word version: ${JSON.stringify(after.trim())}`);
  }
  const figure = [...stated.matchAll(/\d+(?:\.\d+)?/gu)].map((found) => String(found[0]));
  if (new Set(figure).size !== figure.length) {
    throw new Error(`the clause naming ${family.reader} states ${figure.join(', ')}, which names one version twice`);
  }
  return figure.sort(compareVersionTokens);
}

/** The code the clause answers a refused version with, or nothing where it names none. */
function clauseCode(clause: string, family: VendorFamily): string | null {
  const codes = [
    ...new Set([...claimTail(clause, family).matchAll(/`([A-Z][A-Z0-9_]+)`/gu)].map((found) => String(found[1]))),
  ];
  if (codes.length > 1) {
    throw new Error(
      `the clause naming ${family.reader} answers with ${codes.join(', ')}, and a figure is weighed against ` +
        'the one refusal that states it',
    );
  }
  return codes[0] ?? null;
}

/**
 * How often the clause says the reader refuses. Most readers refuse at one place; a two-way exchange refuses
 * at both ends of it, which the paragraph claims in words, and a guard quietly dropped from one end of that
 * exchange leaves the claim false and the remaining guard true.
 */
function clauseSites(clause: string, family: VendorFamily): number {
  const directions = [...claimTail(clause, family).matchAll(/\b(both|[0-9]+|the two|all) directions\b/gu)];
  if (directions.length === 0) return 1;
  if (directions.length > 1) {
    throw new Error(`the clause naming ${family.reader} states an exchange shape ${String(directions.length)} times`);
  }
  const stated = directions[0]?.[1] ?? '';
  if (stated !== 'both') {
    throw new Error(
      `the clause naming ${family.reader} states ${JSON.stringify(stated)} directions, which this reads only as "both"`,
    );
  }
  return 2;
}

/** Every comparison operator, and one comparison with both of its sides named. */
const OPERATORS = /(===|!==|==|!=|<=|>=|<|>)/gu;
const COMPARISON = /([A-Za-z_$][A-Za-z0-9_$]*(?:\[[0-9]+\])?)\s*(===|!==|==|!=|<=|>=|<|>)\s*([^\s(),]+)/gu;

/** The version one side of a comparison names, spelled as a document would spell it. */
function versionTerm(term: string, family: VendorFamily): string {
  if (VERSION_TOKEN.test(term)) return term;
  if (!/^[A-Z][A-Z0-9_]*$/u.test(term)) {
    throw new Error(
      `${term} is compared beside the refusal of ${shown(family.file)} that states ${family.reader}'s set, ` +
        'and this reads a version from a number or from a declared constant',
    );
  }
  const declared = declaredValue(term, family.file);
  if (/^[0-9]+$/u.test(declared)) return declared;
  const byte = /^0x([0-9a-fA-F]{2})$/u.exec(declared);
  if (byte === null) {
    throw new Error(
      `${term} in ${shown(family.file)} is declared as ${JSON.stringify(declared)}, which is neither a version ` +
        'number nor the byte that carries one',
    );
  }
  const halves = (byte[1] ?? '').split('').map((digit) => Number.parseInt(digit, 16));
  const [high = 0, low = 0] = halves;
  if (high > 9 || low > 9) {
    throw new Error(
      `${term} in ${shown(family.file)} is the byte ${declared}, whose halves ${String(high)} and ` +
        `${String(low)} are not both single digits, so no document could state it as a dotted version`,
    );
  }
  return `${String(high)}.${String(low)}`;
}

/** The guard a refusal sits under: the nearest line above it that compares anything. */
function guardAbove(lines: readonly string[], at: number, family: VendorFamily): string {
  for (let scan = at - 1; scan >= Math.max(0, at - 10); scan -= 1) {
    const line = lines[scan] ?? '';
    if ([...line.matchAll(OPERATORS)].length > 0) return line;
  }
  throw new Error(
    `nothing within ten lines above the ${JSON.stringify(family.marker)} refusal in ${shown(family.file)} ` +
      `compares a value, so the set ${family.reader} accepts is not stated where this reads it`,
  );
}

/**
 * The set one guard admits: the values it refuses everything else at. A guard spelled `version !== 2 &&
 * version !== 3` admits two, and one that compares anything else, or compares two different things, or
 * compares against a value this cannot name, is reported rather than read as a set.
 */
function guardVersions(line: string, family: VendorFamily): string[] {
  const terms = [...line.matchAll(COMPARISON)];
  const operators = [...line.matchAll(OPERATORS)];
  if (terms.length !== operators.length) {
    throw new Error(
      `the guard above ${family.reader}'s refusal in ${shown(family.file)} reads ${JSON.stringify(line.trim())}, ` +
        'which holds a comparison this cannot take both sides of',
    );
  }
  for (const term of terms) {
    if (term[2] !== '!==') {
      throw new Error(
        `the guard above ${family.reader}'s refusal in ${shown(family.file)} reads ${JSON.stringify(line.trim())}, ` +
          `which uses ${String(term[2])} rather than refusing every version but the ones it names`,
      );
    }
  }
  const compared = [...new Set(terms.map((term) => String(term[1])))];
  if (compared.length !== 1) {
    throw new Error(
      `the guard above ${family.reader}'s refusal in ${shown(family.file)} compares ${compared.join(', ')}, ` +
        'two different values, so this cannot read one set off it',
    );
  }
  return [...new Set(terms.map((term) => versionTerm(String(term[3]), family)))].sort(compareVersionTokens);
}

/** One refusal this read, as the site that states the version set. */
interface RefusalSite {
  readonly code: string;
  readonly versions: string[];
}

/** The refusals carrying this family's marker, each read as the site that states the set it admits. */
function refusalSites(family: VendorFamily): RefusalSite[] {
  const lines = readSourceFile(family.file).split('\n');
  const found = lines
    .map((line, at) => ({ line, at }))
    .filter((one) => one.line.includes('fail(') && one.line.includes(family.marker));
  if (found.length === 0) {
    throw new Error(
      `nothing in ${shown(family.file)} refuses with ${JSON.stringify(family.marker)} in a fail call, so ` +
        `${family.reader} states its version set nowhere this reads`,
    );
  }
  return found.map((site) => {
    const code = /^\s*fail\('([A-Z][A-Z0-9_]+)'[,)]/u.exec(site.line)?.[1];
    if (code === undefined) {
      throw new Error(
        `${shown(family.file)} raises ${JSON.stringify(site.line.trim())}, which is not a fail('CODE', ...) call ` +
          `this can read ${family.reader}'s refusal code out of`,
      );
    }
    return { code, versions: guardVersions(guardAbove(lines, site.at, family), family) };
  });
}

/** The set the module admits, read over every site that refuses for it, and the refusal they all answer with. */
function sourceFigure(family: VendorFamily): { code: string; versions: string[]; sites: number } {
  const sites = refusalSites(family);
  const codes = [...new Set(sites.map((one) => one.code))];
  if (codes.length !== 1) {
    throw new Error(
      `${family.reader} is refused under ${codes.join(', ')} in ${shown(family.file)}, and a figure is weighed ` +
        'against the one code that states it',
    );
  }
  const sets = [...new Set(sites.map((one) => one.versions.join(', ')))];
  if (sets.length !== 1) {
    throw new Error(
      `${family.reader} refuses at ${String(sites.length)} sites in ${shown(family.file)} admitting ` +
        `${sets.join(' and ')}, so this cannot say which set ${family.named} is read under`,
    );
  }
  return { code: String(codes[0]), versions: sites[0]?.versions ?? [], sites: sites.length };
}

/** The packages a publish would upload, read off the workspace rather than listed here. */
function publishSet(): string[] {
  const specs = readdirSync(fileURLToPath(new URL(PACKAGES_PARENT, import.meta.url)), { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => `${PACKAGES_PARENT}${entry.name}`)
    .concat(GATEWAY_DIR)
    .filter((spec) => existsSync(fileURLToPath(new URL(`${spec}/package.json`, import.meta.url))));
  const found = scopedManifests(specs.map((spec) => ({ dir: shown(spec), text: readSourceFile(`${spec}/package.json`) })));
  const names = found.filter((manifest) => isPublishable(manifest.fields)).map((manifest) => manifest.name).sort();
  if (names.length === 0) {
    throw new Error(
      'no publishable @ashaveri/* manifest is in the workspace, so the paragraph counting the packages ' +
        'that add no family had no set to be weighed against',
    );
  }
  return names;
}

/**
 * The sentence counting the packages that add no document family, read as its count and as the names it
 * enumerates. The count is a word and the names are backticked, so both halves are refused rather than
 * guessed at: a number written as a digit is a count this cannot read, and a name with nothing said after it
 * is not an enumeration of the set the sentence claims.
 */
function noFamilyClaim(): { count: number; names: string[] } {
  const paragraphs = specSection()
    .split(/\n\n+/u)
    .filter((paragraph) => paragraph.includes(NO_FAMILY_MARKER));
  if (paragraphs.length !== 1) {
    throw new Error(
      `"${NO_FAMILY_MARKER}" sits in ${String(paragraphs.length)} paragraphs of ${shown(RECEIPT_SPEC)} ` +
        `${SPEC_SECTION}, and the count is read from exactly one`,
    );
  }
  const sentences = (paragraphs[0] ?? '')
    .replace(/\s+/gu, ' ')
    .split(/(?<=\.)\s+/u)
    .filter((sentence) => sentence.includes(NO_FAMILY_MARKER));
  if (sentences.length !== 1) {
    throw new Error(
      `${shown(RECEIPT_SPEC)} states "${NO_FAMILY_MARKER}" in ${String(sentences.length)} sentences of that ` +
        'paragraph, and the count is read from exactly one',
    );
  }
  const sentence = sentences[0] ?? '';
  const stated = /^(?<count>[A-Za-z]+) published packages add no document family of their own: (?<rest>.*)\.$/u.exec(sentence);
  const word = stated?.groups?.['count'];
  const rest = stated?.groups?.['rest'];
  if (word === undefined || rest === undefined) {
    throw new Error(
      `${shown(RECEIPT_SPEC)} states ${JSON.stringify(sentence.slice(0, 72))}, which is not "<count> published ` +
        'packages add no document family of their own: <the names>',
    );
  }
  const names = [...rest.matchAll(/`(@ashaveri\/[a-z0-9-]+)`/gu)].map((found) => String(found[1]));
  if (names.length === 0) {
    throw new Error(`${shown(RECEIPT_SPEC)} enumerates no backticked package name after the count ${word}`);
  }
  const doubled = names.filter((one, at) => names.indexOf(one) !== at);
  if (doubled.length > 0) {
    throw new Error(`${shown(RECEIPT_SPEC)} enumerates ${[...new Set(doubled)].join(', ')} more than once`);
  }
  const described = rest.split(/`@ashaveri\/[a-z0-9-]+`/u).filter((part) => part.trim().length > 0);
  if (described.length !== names.length) {
    throw new Error(
      `${shown(RECEIPT_SPEC)} enumerates ${String(names.length)} package names and ${String(described.length)} ` +
        'statements about them, so one of the two lists is not this sentence\'s',
    );
  }
  return { count: spelledNumber(word), names };
}

/** The packages that ship no reader of their own: the publish set with the table's packages taken out of it. */
function noFamilySet(rows: readonly Row[]): string[] {
  const shipping = [...new Set(rows.map((row) => row.pkg))].sort();
  const publishing = publishSet();
  const outside = shipping.filter((name) => !publishing.includes(name));
  if (outside.length > 0) {
    throw new Error(
      `the table ships a reader in ${outside.join(', ')}, which no publishable manifest claims, so taking the ` +
        "table's packages out of the publish set would say nothing about what is left",
    );
  }
  return publishing.filter((name) => !shipping.includes(name)).sort();
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
    const paragraph = vendorParagraph();
    const exported = exportedNames(PACKAGE_INDEX['@ashaveri/attest-core'] ?? '');
    const offenders: string[] = [];
    for (const family of VENDOR_FAMILIES) {
      if (!paragraph.includes(`\`${family.reader}\``)) {
        offenders.push(`${family.named}: the vendor paragraph no longer names ${family.reader} as the reader it weighs`);
      }
      if (!exported.values.includes(family.reader)) {
        offenders.push(`${family.named}: the vendor paragraph names ${family.reader}, and @ashaveri/attest-core exports no such value`);
      }
    }
    for (const row of familyRows()) {
      const vendor = VENDOR_FAMILIES.filter((family) => row.family.includes(family.named) || row.readers.includes(family.reader));
      if (vendor.length > 0) {
        offenders.push(
          `${row.family}: the vendor paragraph says these families are not in the table, and the table states a row for it`,
        );
      }
    }
    expect(offenders, 'the vendor paragraph and the family table no longer agree about what is listed').toEqual([]);
  });

  it("weighs the vendor paragraph's four figures against the refusals that state them", () => {
    const clauses = paragraphClauses(vendorParagraph());
    const offenders: string[] = [];
    for (const family of VENDOR_FAMILIES) {
      let claim: { figure: string[]; code: string | null; sites: number };
      try {
        const clause = vendorClause(clauses, family);
        claim = { figure: clauseFigure(clause, family), code: clauseCode(clause, family), sites: clauseSites(clause, family) };
      } catch (error) {
        offenders.push(`${family.named}: the figure went unread, and an unread figure is not an agreement: ${(error as Error).message}`);
        continue;
      }
      let source: { code: string; versions: string[]; sites: number };
      try {
        source = sourceFigure(family);
      } catch (error) {
        offenders.push(`${family.named}: the set its reader accepts went unread, and this does not pass on a guess: ${(error as Error).message}`);
        continue;
      }
      if (claim.figure.join(', ') !== source.versions.join(', ')) {
        offenders.push(
          `${family.named}: ${shown(RECEIPT_SPEC)} states ${family.reader} accepting ` +
            `${claim.figure.join(' and ')} and ${shown(family.file)} refuses every version but ` +
            `${source.versions.join(' and ')}`,
        );
      }
      if (claim.code !== null && claim.code !== source.code) {
        offenders.push(
          `${family.named}: ${shown(RECEIPT_SPEC)} answers a version outside the set with ${claim.code} and ` +
            `${shown(family.file)} answers it with ${source.code}`,
        );
      }
      if (claim.sites !== source.sites) {
        offenders.push(
          `${family.named}: ${shown(RECEIPT_SPEC)} states ${family.reader} refusing at ${String(claim.sites)} ` +
            `place${claim.sites === 1 ? '' : 's'} and ${shown(family.file)} refuses at ${String(source.sites)}`,
        );
      }
    }
    expect(offenders, 'the vendor paragraph states a version figure its readers do not refuse at').toEqual([]);
  });

  it('holds the packages that add no family of their own to the table and to the publish set', () => {
    const rows = familyRows();
    let claim: { count: number; names: string[] };
    try {
      claim = noFamilyClaim();
    } catch (error) {
      throw new Error(`the sentence counting the packages that add no document family went unread, and an unread count is not an agreement: ${(error as Error).message}`);
    }
    const derived = noFamilySet(rows);
    const offenders: string[] = [];
    if (claim.names.slice().sort().join(', ') !== derived.join(', ')) {
      offenders.push(
        `${shown(RECEIPT_SPEC)} states ${claim.names.join(', ')} add no document family and the publish set ` +
          `leaves ${derived.join(', ')} once the packages the table ships readers in are taken out of it`,
      );
    }
    if (claim.count !== claim.names.length) {
      offenders.push(
        `${shown(RECEIPT_SPEC)} counts ${String(claim.count)} packages and enumerates ${String(claim.names.length)}: ` +
          `${claim.names.join(', ')}`,
      );
    }
    expect(offenders, 'the packages stated to add no family are not the packages that add none').toEqual([]);
  });
});
