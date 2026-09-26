import { readdirSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

/**
 * The readers that hold `docs/configured-values.md` to the code it describes.
 *
 * The document makes a membership claim about three sets: the flags one block declares, the constants
 * the source reads when an operator named nothing, and the environment variables shipped code reads or
 * substitutes. Each set is therefore enumerated from the file text that declares it, never from a list
 * copied here, because a copy would drift with the document, and the point of this file is to find out
 * what the document says when it stops being true.
 *
 * Where `doc-contract.ts` has a reader for a shape it is used: the tables, and the workspace files they
 * are read against. It has none for a `parseArgs` block, for a directory's worth of fallback sites, or
 * for a shell substitution, so those three are read by the narrowest pattern that names the construct.
 * Each refuses an empty or missing block rather than returning nothing, since a set that came out blank
 * would let the document be measured against nothing and pass.
 *
 * `doc-contract.ts` is read from its own path at run time rather than imported, because this package's
 * test project roots at `gateway/` and a static import of a file in another package is a source outside
 * that root: the typecheck refuses it, and widening a root is a package's own decision rather than a
 * document test's. The shape is written out below and every call still goes into the shared reader, so a
 * change to how narrowly it finds a table lands here the moment it lands anywhere else.
 */
interface DocContract {
  readSourceFile(specifier: string): string;
  tableRows(markdown: string, header: string): string[][];
}

const contract = (await import(
  new URL('../../packages/fixtures/test/doc-contract.ts', import.meta.url).href
)) as DocContract;
const { readSourceFile, tableRows } = contract;

/** The inventory, spelled from this file's package. */
const DOCUMENT = '../../../docs/configured-values.md';
/** Where the flags are declared, and where the two receipt bounds the CLI hands the store are named. */
const CLI_SOURCE = '../../../gateway/src/cli.ts';
const COMPOSE = '../../../enclave/docker-compose.yaml';
const ENTRYPOINT = '../../../enclave/docker-entrypoint.sh';
const SDK_AUTH = '../../../packages/sdk/src/auth.ts';
/** The gateway's own source directory, from which the fallback sites are read file by file. */
const GATEWAY_SRC = new URL('../src/', import.meta.url);
/** How a workspace path in a table cell becomes a specifier `readSourceFile` takes. */
const FROM_FIXTURES = '../../../';

/** The table of every flag the CLI's option block accepts. */
const FLAG_TABLE = '| Flag | What it governs | Bound or shape | Default this process runs | Class | Declared in |';
/** The table of every constant the code reads in a defaulting position. */
const DEFAULT_TABLE = '| Name | Value as source | What it governs | Class | Declared in |';
/** The table of environment variables that carry a setting. */
const SETTING_TABLE = '| Variable | What it governs | Shape | Class | Declared in |';
/** The table of the environment variable that carries key material. */
const SECRET_TABLE = '| Variable | What it governs | Shape | Class | Read from |';
/** The paragraph that states what the default table leaves out. */
const OUTSIDE_THE_TABLE = 'Bounds shipped in the same source';

interface TableSpec {
  readonly header: string;
  /** Which cell of that table's rows carries the class the table was written for. */
  readonly classCell: number;
  /** Which cell names the file the rows are read from. */
  readonly fileCell: number;
  readonly className: string;
}

/** The four tables, with the two columns this file reads out of each. */
const TABLES: readonly TableSpec[] = [
  { header: FLAG_TABLE, classCell: 5, fileCell: 6, className: "the operator's to declare" },
  { header: DEFAULT_TABLE, classCell: 4, fileCell: 5, className: 'shipped default' },
  { header: SETTING_TABLE, classCell: 4, fileCell: 5, className: "the operator's to declare" },
  { header: SECRET_TABLE, classCell: 4, fileCell: 5, className: 'never in a commit or a log' },
];

interface DocRow {
  /** The row's subject, with its backticks and a flag's leading dashes removed. */
  readonly name: string;
  /** Every cell as written, including the empty ones the surrounding pipes leave. */
  readonly cells: readonly string[];
}

function documentText(): string {
  return readSourceFile(DOCUMENT);
}

/** One table's rows, with cell 1 read as the row's subject. */
function rows(header: string): DocRow[] {
  return tableRows(documentText(), header).map((cells) => ({
    name: unbacktick(cells[1] ?? '').replace(/^--/u, ''),
    cells,
  }));
}

function unbacktick(cell: string): string {
  return cell.replace(/`/gu, '');
}

/** Every gateway source file, keyed by the specifier that reads it back. */
function gatewaySources(): Map<string, string> {
  const out = new Map<string, string>();
  for (const entry of readdirSync(GATEWAY_SRC).sort()) {
    if (!entry.endsWith('.ts')) continue;
    const specifier = `../../../gateway/src/${entry}`;
    out.set(specifier, readSourceFile(specifier));
  }
  if (out.size === 0) throw new Error(`${GATEWAY_SRC.pathname} holds no TypeScript source to read fallbacks from`);
  return out;
}

/**
 * A file's text without the lines a comment owns. A fallback site is something the code runs, so a
 * sentence that merely names a constant must not put it in an enumeration, and a comment quoting a
 * literal must not make a default the source no longer holds read as true.
 */
function codeLines(source: string): string {
  return source
    .split('\n')
    .filter((line) => !/^\s*(?:\/\/|\/?\*)/u.test(line))
    .join('\n');
}

interface FlagDeclaration {
  readonly name: string;
  /** The literal the block itself names, for the few flags whose default is spelled at the declaration. */
  readonly literalDefault: string | undefined;
}

/**
 * The `parseArgs` option block, as flag names and the defaults written beside them. The block is the
 * only place a flag exists, so an operator who adds one without a row in the document meets this
 * enumeration rather than a reviewer's memory.
 */
function flagsTheCodeAccepts(): FlagDeclaration[] {
  const source = readSourceFile(CLI_SOURCE);
  const start = source.indexOf('options: {');
  if (start < 0) throw new Error(`${CLI_SOURCE} holds no parseArgs options block`);
  const end = source.indexOf('\n    },', start);
  if (end < 0) throw new Error('the parseArgs options block does not close at the indentation it opened at');
  const flags: FlagDeclaration[] = [];
  for (const line of source.slice(start + 'options: {'.length, end).split('\n')) {
    const declared = /^\s*'?([a-z][a-z0-9-]*)'?:\s*\{[^}]*\}/u.exec(line);
    if (!declared) continue;
    flags.push({ name: declared[1]!, literalDefault: /default:\s*'([^']*)'/u.exec(line)?.[1] });
  }
  if (flags.length === 0) throw new Error('the parseArgs options block yielded no flag to compare the tables against');
  return flags;
}

/** Names standing on the right of a `??`, on a parameter's own default, or in a whole-number fallback. */
function constantsReadInDefaultingPositions(): Set<string> {
  const found = new Set<string>();
  for (const source of gatewaySources().values()) {
    const code = codeLines(source);
    for (const fallback of code.matchAll(/\?\?\s+([A-Z][A-Z0-9_]+)\b/gu)) found.add(fallback[1]!);
    for (const param of code.matchAll(/\w+\s*:\s*(?:number|string)\s*=\s*([A-Z][A-Z0-9_]+)\s*[,)]/gu)) {
      found.add(param[1]!);
    }
    // The CLI's own defaulting helper takes the fallback last, so a bare constant name in that slot is
    // precisely what the run uses when the operator named nothing.
    for (const call of code.matchAll(/wholeNumber\(([^)]*)\)/gu)) {
      const fallback = call[1]!
        .split(',')
        .map((arg) => arg.trim())
        .filter((arg) => arg.length > 0)
        .at(-1);
      if (fallback !== undefined && /^[A-Z][A-Z0-9_]+$/u.test(fallback)) found.add(fallback);
    }
  }
  if (found.size === 0) throw new Error('gateway/src reads no constant in a defaulting position, so the table could not be measured');
  return found;
}

/**
 * Literals standing in a defaulting position in the gateway's source: a block default, the left of a
 * `??`, or the arm taken when a value is absent. A row may quote one of these as a flag's default and
 * nothing else, which is what keeps a number nobody changed in source from reading as a fact.
 */
function literalsHeldInDefaultingPositions(): Set<string> {
  const found = new Set<string>();
  for (const source of gatewaySources().values()) {
    const code = codeLines(source);
    for (const literal of code.matchAll(/default:\s*'([^']*)'/gu)) found.add(literal[1]!);
    for (const literal of code.matchAll(/\?\?\s*'([^']*)'/gu)) found.add(literal[1]!);
    for (const literal of code.matchAll(/=== undefined \?\s*(?:'([^']*)'|(\d+))\s*:/gu)) {
      found.add(literal[1] ?? literal[2]!);
    }
  }
  if (found.size === 0) throw new Error('gateway/src holds no literal in a defaulting position for a row to quote');
  return found;
}

/** The right-hand side of a module-level `const`, as written. */
function valueDeclaredIn(name: string, specifier: string): string {
  const line = readSourceFile(specifier)
    .split('\n')
    .find((candidate) => new RegExp(`^(?:export )?const ${name}\\b[^=]*=`, 'u').test(candidate));
  if (line === undefined) throw new Error(`${name} is not declared at module level in ${specifier}`);
  const value = line.slice(line.indexOf('=') + 1).replace(/;$/u, '').trim();
  if (value.length === 0) throw new Error(`${name} in ${specifier} has no value on its declaration line`);
  return value;
}

/**
 * Both spellings of a value reduced to one. The document quotes source, so a claim that drifts from the
 * declaration fails on comparison rather than on formatting: underscores are how source groups long
 * numbers, and quotes are how source spells a string.
 */
function asSpelled(value: string): string {
  return unbacktick(value).replace(/'/gu, '').replace(/_/gu, '').replace(/\s+/gu, '');
}

/** Every `ASHAVERI_*` name the two container files substitute or assign. */
function namesTheContainerReads(): Set<string> {
  const found = new Set<string>();
  for (const file of [COMPOSE, ENTRYPOINT]) {
    for (const name of readSourceFile(file).matchAll(/\b(ASHAVERI_[A-Z0-9_]+)\b/gu)) found.add(name[1]!);
  }
  if (found.size === 0) throw new Error('the container files substitute no ASHAVERI_ variable for the tables to name');
  return found;
}

/** Every name shipped gateway code reads out of `process.env`. */
function namesTheGatewayReads(): Set<string> {
  const found = new Set<string>();
  for (const source of gatewaySources().values()) {
    for (const name of codeLines(source).matchAll(/process\.env\[?\s*['"]([A-Z0-9_]+)['"]/gu)) found.add(name[1]!);
  }
  if (found.size === 0) throw new Error('gateway/src reads no environment variable, so the tables could not be measured against it');
  return found;
}

/** What `CREDENTIAL_ENV` holds: the three names a client is configured by, and the one of them a key. */
function namesTheCredentialCarries(): { readonly all: Set<string>; readonly secret: string } {
  const source = readSourceFile(SDK_AUTH);
  const start = source.indexOf('const CREDENTIAL_ENV');
  if (start < 0) throw new Error(`${SDK_AUTH} declares no CREDENTIAL_ENV`);
  const block = source.slice(start, source.indexOf('} as const', start));
  const all = new Set<string>();
  for (const name of block.matchAll(/'(ASHAVERI_[A-Z0-9_]+)'/gu)) all.add(name[1]!);
  const secret = /\bsecret:\s*'(ASHAVERI_[A-Z0-9_]+)'/u.exec(block)?.[1];
  if (all.size === 0 || secret === undefined) {
    throw new Error('CREDENTIAL_ENV holds no credential name and no secret entry for the tables to be read against');
  }
  return { all, secret };
}

/** The whole environment surface, as the union of the three readings of it. */
function environmentVariables(): Set<string> {
  return new Set([
    ...namesTheContainerReads(),
    ...namesTheGatewayReads(),
    ...namesTheCredentialCarries().all,
  ]);
}

/** Backticked tokens in a cell, which is how the document spells a name or a literal. */
function backticked(cell: string | undefined): string[] {
  return [...(cell ?? '').matchAll(/`([^`]+)`/gu)].map((found) => found[1]!);
}

/** The constants the paragraph outside the default table names, read as one wrapped paragraph. */
function namesOutsideTheTable(): string[] {
  const lines = documentText().split('\n');
  const start = lines.findIndex((line) => line.startsWith(OUTSIDE_THE_TABLE));
  if (start < 0) throw new Error(`the document no longer states what the default table leaves out: ${OUTSIDE_THE_TABLE}`);
  const paragraph: string[] = [];
  for (const line of lines.slice(start)) {
    if (line.trim().length === 0) break;
    paragraph.push(line);
  }
  return [...paragraph.join(' ').matchAll(/`([A-Z][A-Z0-9_]+)`/gu)].map((found) => found[1]!);
}

const fallbackConstants = constantsReadInDefaultingPositions();
const environment = environmentVariables();
const codeFlags = flagsTheCodeAccepts();
const flagRows = rows(FLAG_TABLE);
const defaultRows = rows(DEFAULT_TABLE);
const settingRows = rows(SETTING_TABLE);
const secretRows = rows(SECRET_TABLE);

describe('docs/configured-values.md against the flags gateway/src/cli.ts accepts', () => {
  it('names every flag the option block declares', () => {
    const named = new Set(flagRows.map((row) => row.name));
    const missing = codeFlags.filter((flag) => !named.has(flag.name)).map((flag) => `--${flag.name}`);
    expect(missing, 'a flag an operator can pass and the inventory does not name').toEqual([]);
  });

  it('names no flag the option block does not declare', () => {
    const accepted = new Set(codeFlags.map((flag) => flag.name));
    const extra = flagRows.filter((row) => !accepted.has(row.name)).map((row) => row.name);
    expect(extra, 'a row in the inventory behind which no flag exists').toEqual([]);
  });

  it('states the counts the enumerations recompute', () => {
    // The sentence is prose and will be rewrapped, so whitespace is folded before the numbers are read
    // out of it. The numbers themselves are digits rather than words because a count above twenty is
    // what these tables carry, and the reader a document here shares stops at twenty on purpose.
    const prose = documentText().replace(/\s+/gu, ' ');
    const claim =
      /(\d+) flag rows, (\d+) shipped defaults, and (\d+) environment variables, of which (\d+) are settings and (\d+) carries credential material\. (\d+) flags name their default in the block that declares them/u.exec(
        prose,
      );
    expect(claim, 'the opening paragraph states a count for each table').not.toBeNull();
    const [flagCount, defaultCount, variableCount, settingCount, secretCount, blockDefaultCount] = (claim ?? [])
      .slice(1)
      .map((stated) => Number(stated));
    expect(flagCount, 'the flags the table carries against the option block').toBe(codeFlags.length);
    expect(defaultCount, 'the shipped defaults the table carries against the fallback sites').toBe(fallbackConstants.size);
    expect(variableCount, 'the environment variables the two tables carry against the code').toBe(environment.size);
    expect(settingCount, 'the settings counted above against the rows that carry one').toBe(settingRows.length);
    expect(secretCount, 'the credential material counted above against the rows that carry it').toBe(secretRows.length);
    expect(settingCount! + secretCount!, 'the two environment tables hold the whole set between them').toBe(variableCount);
    expect(
      blockDefaultCount,
      'the flags whose default is written at the declaration against the block that writes one',
    ).toBe(codeFlags.filter((flag) => flag.literalDefault !== undefined).length);
  });

  it('carries each row in the class its table was written for, and names a file for it', () => {
    for (const table of TABLES) {
      for (const row of rows(table.header)) {
        expect(row.cells[table.classCell], `${row.name} states the class of its own table`).toBe(table.className);
        const file = unbacktick(row.cells[table.fileCell] ?? '');
        expect(file.length, `${row.name} names the file it is read from`).toBeGreaterThan(0);
        expect(readSourceFile(`${FROM_FIXTURES}${file}`).includes(row.name), `${row.name} appears in ${file}`).toBe(true);
      }
    }
  });

  it('writes the default the block itself carries, for exactly the flags that have one', () => {
    const withDefaults = codeFlags.filter((flag) => flag.literalDefault !== undefined);
    expect(withDefaults.length, 'the block spells at least one default beside a declaration').toBeGreaterThan(0);
    const stated = new Map(flagRows.map((row) => [row.name, backticked(row.cells[4])]));
    for (const flag of withDefaults) {
      expect(stated.get(flag.name) ?? [], `--${flag.name} states the default written beside its declaration`).toEqual([
        flag.literalDefault,
      ]);
    }
  });

  it('quotes as a default only a name a table carries or a literal the code holds in a defaulting position', () => {
    const literals = literalsHeldInDefaultingPositions();
    const names = new Set([...fallbackConstants, ...environment]);
    for (const row of flagRows) {
      for (const token of backticked(row.cells[4])) {
        const backed = /^[A-Z][A-Z0-9_]+$/u.test(token) ? names.has(token) : literals.has(token);
        expect(backed, `--${row.name} states a default the source backs: ${token}`).toBe(true);
      }
    }
  });
});

describe('the shipped defaults against the source that declares them', () => {
  it('names every constant read in a defaulting position', () => {
    const named = new Set(defaultRows.map((row) => row.name));
    const missing = [...fallbackConstants].filter((name) => !named.has(name));
    expect(missing, 'a fallback the code reads and the inventory does not name').toEqual([]);
  });

  it('names no constant the code does not read in a defaulting position', () => {
    const extra = defaultRows.filter((row) => !fallbackConstants.has(row.name)).map((row) => row.name);
    expect(extra, 'a row above which no fallback site in gateway/src reads a constant').toEqual([]);
  });

  it('states each value as the file it names spells it', () => {
    for (const row of defaultRows) {
      const source = valueDeclaredIn(row.name, `${FROM_FIXTURES}${unbacktick(row.cells[5] ?? '')}`);
      expect(asSpelled(row.cells[2] ?? ''), `${row.name}: the value the table states against the declaration`).toBe(
        asSpelled(source),
      );
    }
  });

  it('keeps the bounds no flag reaches outside the table, and names constants that are still there', () => {
    // The paragraph after the table is the document's own limit on it, so it is read as well: a name
    // there that no longer exists is a sentence about nothing, and a name that has since gained a
    // fallback site belongs in the table instead of the exception.
    const outside = namesOutsideTheTable();
    expect(outside.length, 'the paragraph outside the table names the bounds it excludes').toBeGreaterThan(0);
    for (const name of outside) {
      expect(fallbackConstants.has(name), `${name} is read in a defaulting position, so it belongs in the table`).toBe(false);
      expect(
        [...gatewaySources().keys()].filter((specifier) => {
          try {
            valueDeclaredIn(name, specifier);
            return true;
          } catch {
            return false;
          }
        }).length,
        `${name} is declared at module level in exactly one gateway source file`,
      ).toBe(1);
    }
  });
});

describe('the environment variables against the code that reads them', () => {
  it('names every variable shipped code reads or substitutes', () => {
    const named = new Set([...settingRows, ...secretRows].map((row) => row.name));
    const missing = [...environment].filter((name) => !named.has(name));
    expect(missing, 'a variable the shipped code reads and the inventory does not name').toEqual([]);
  });

  it('names no variable shipped code does not read or substitute', () => {
    const extra = [...settingRows, ...secretRows]
      .filter((row) => !environment.has(row.name))
      .map((row) => row.name);
    expect(extra, 'a row for a variable no shipped file reads').toEqual([]);
  });

  it('keeps the three readings apart, so the total the paragraph states is a count and not a coincidence', () => {
    const credential = namesTheCredentialCarries();
    const container = namesTheContainerReads();
    const gateway = namesTheGatewayReads();
    expect(
      [...credential.all].filter((name) => container.has(name) || gateway.has(name)),
      'a credential name that a container file or the gateway also reads, which would count twice',
    ).toEqual([]);
    expect(
      container.size + gateway.size + credential.all.size,
      'the three readings add up to the set the tables carry',
    ).toBe(environment.size);
  });

  it('puts exactly the key material in the class nothing may record', () => {
    const credential = namesTheCredentialCarries();
    expect(
      secretRows.map((row) => row.name),
      'the table nothing may hold names the entry the SDK decodes into a signing key',
    ).toEqual([credential.secret]);
    expect(
      settingRows
        .map((row) => row.name)
        .filter((name) => credential.all.has(name)),
      "the settings table carries the credential's name and kind, which are public, and not its key",
    ).toEqual(['ASHAVERI_CREDENTIAL_ID', 'ASHAVERI_CREDENTIAL_KIND']);
  });
});
