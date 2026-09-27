import { describe, expect, it } from 'vitest';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  EPOCH_INVENTORY_CONTENT_TYPE,
  EPOCH_INVENTORY_PACK_FILE,
  EPOCH_INVENTORY_PACKS_DIRECTORY,
  EPOCH_INVENTORY_RETENTION_FILE,
} from '@ashaveri/receipt';
import { readSourceFile, spelledNumber, tableRows, unionMembers } from './doc-contract.js';

/**
 * The epoch inventory document and the epoch inventory schema are two statements of one layout, and the document
 * is the one a reimplementer reads first. Two statements of one shape are how one comes to disagree with the
 * other, and a schema that gained a member in silence would leave the prose describing a container nobody can
 * build and a reader checking a layout it was never told about.
 *
 * So the table is read as data and the layout as data, and they are compared in both directions: every row
 * resolves to a member the layout defines, with the type and the required-ness the layout gives it, and every
 * member the layout defines appears as a row. The pair is enumerated out of the layout rather than written twice,
 * which is the only way this file can notice a widening: a test that restated the member list would have to be
 * edited alongside the schema, and would pass either way.
 *
 * No layout here chooses between arms, so a block is named by its own definition name and every row key is that
 * name plus the member. The one position the layout spells two ways is the window: `pack.span` and `window` are
 * both the `span` definition, which is why the table carries two rows for it and no more.
 *
 * The signed header is the one block of the layout the field table carries no rows for, because its members are
 * numbered rather than named, and the document lays those three out in a table of their own. That table is held
 * against the same definition. The refusals the document lists are held against the reader that raises them and
 * the registry that declares them, in both directions, so a code that arrives in one of the three cannot go
 * missing from the other two unnoticed.
 */

const DOC = '../../../docs/epoch-inventory-v1.md';
const SCHEMA = '../../../packages/receipt/schemas/epoch-inventory-v1.schema.json';
const CDDL = '../../../packages/receipt/epoch-inventory.cddl';
const ERRORS = '../../../packages/receipt/src/errors.ts';
const READER = '../../../packages/receipt/src/epoch-inventory.ts';
const LAYOUT_TABLE = '| Member | Type | Required | What it states |';
const REFUSAL_TABLE = '| Code | The fault |';
const LABEL_TABLE = '| Label | Name | Value |';
/** The prefix this container's own refusals carry, which is what separates them from the shared envelope's. */
const PREFIX = 'EPOCH_INVENTORY_';

interface JsonSchema {
  $defs?: Record<string, JsonSchema>;
  $id?: unknown;
  $ref?: unknown;
  const?: unknown;
  description?: string;
  items?: JsonSchema;
  minItems?: unknown;
  pattern?: unknown;
  properties?: Record<string, JsonSchema>;
  required?: readonly string[];
  type?: unknown;
}

interface Declared {
  readonly path: string;
  readonly type: string;
  readonly required: boolean;
  /** The layout's own node for this member, with a `$ref` already resolved. */
  readonly node: JsonSchema;
}

interface Row {
  readonly path: string;
  readonly type: string;
  readonly required: boolean;
  readonly states: string;
}

const schema = JSON.parse(readSourceFile(SCHEMA)) as JsonSchema;
const defs = schema.$defs ?? {};

function section(): string {
  return readSourceFile(DOC);
}

/** The document as one line, so a check pins a sentence rather than the place a paragraph was wrapped. */
function prose(): string {
  return section().replace(/\s+/gu, ' ');
}

/** A `$ref` becomes the definition it points at; anything else is already the node. */
function deref(node: JsonSchema | undefined): JsonSchema {
  if (node === undefined) throw new Error('the layout references a block it does not define');
  if (typeof node.$ref === 'string') {
    return definition(/^#\/\$defs\/(.+)$/u.exec(node.$ref)?.[1] ?? '');
  }
  return node;
}

function definition(name: string): JsonSchema {
  const found = defs[name];
  if (found === undefined) throw new Error(`${name} names no definition in the published layout`);
  return found;
}

/** The type token the table spells for a node: its declared type, or its constant value. */
function typeToken(node: JsonSchema, path: string): string {
  if ('const' in node) return String(node.const);
  switch (node.type) {
    case 'array':
      return 'array';
    case 'object':
      return 'object';
    case 'string':
      return 'string';
    case 'integer':
      return 'integer';
    case 'boolean':
      return 'boolean';
    default:
      throw new Error(`${path} carries a type ${String(node.type)} this reader has no table cell for`);
  }
}

/** The block a row key belongs to, with the top of the table written as the empty string. */
function blockOf(path: string): string {
  return path.slice(0, path.lastIndexOf('.') + 1);
}

/** The member a row key ends with. */
function leafOf(path: string): string {
  return path.slice(path.lastIndexOf('.') + 1);
}

/**
 * Every member the layout defines, keyed the way the table keys it. The envelope's three positions and the
 * document's own seven are bare, and each member below them is prefixed by the definition that holds it. A
 * definition that states one byte shape rather than a map names no member of its own and so contributes no row.
 */
function declaredRows(): Declared[] {
  const out: Declared[] = [];
  const membersOf = (block: string, def: JsonSchema): void => {
    const required = def.required ?? [];
    for (const [name, child] of Object.entries(def.properties ?? {})) {
      const path = block === '' ? name : `${block}.${name}`;
      const node = deref(child);
      out.push({ path, type: typeToken(node, path), required: required.includes(name), node });
    }
  };
  membersOf('', schema);
  membersOf('', definition('manifest'));
  for (const [key, def] of Object.entries(defs)) {
    if (key === 'manifest' || def.properties === undefined) continue;
    membersOf(key, def);
  }
  return out;
}

function parseRows(header: string): Row[] {
  return tableRows(section(), header).map((cells) => ({
    path: cells[1]?.replace(/`/gu, '').trim() ?? '',
    type: cells[2]?.replace(/`/gu, '').trim() ?? '',
    required: (cells[3] ?? '').trim() === 'yes',
    states: cells[4] ?? '',
  }));
}

function rows(): Row[] {
  return parseRows(LAYOUT_TABLE);
}

function refusalRows(): string[] {
  return tableRows(section(), REFUSAL_TABLE).map((cells) => cells[1]?.replace(/`/gu, '').trim() ?? '');
}

/** The three signed parameters as the document lays them out, one row per COSE label. */
function labelRows(): Array<{ label: string; name: string; value: string }> {
  const lines = section().split('\n');
  const at = lines.indexOf(LABEL_TABLE);
  if (at < 0) throw new Error(`${LABEL_TABLE} is not a table in the epoch inventory document`);
  const out: Array<{ label: string; name: string; value: string }> = [];
  for (const line of lines.slice(at + 1)) {
    if (line.startsWith('|---')) continue;
    if (!line.startsWith('| ')) break;
    const cells = line.split('|').map((cell) => cell.trim().replace(/`/gu, ''));
    out.push({ label: cells[1] ?? '', name: cells[2] ?? '', value: cells[3] ?? '' });
  }
  if (out.length === 0) throw new Error('the table of signed header parameters has no rows');
  return out;
}

/** Every code the receipt registry declares, in the order it declares them. */
function registryCodes(): string[] {
  return unionMembers('ReceiptErrorCode', ERRORS);
}

/** The codes of the receipt union this container's reader names, read out of the reader's own source. */
function readerCodes(): string[] {
  const source = readSourceFile(READER);
  return registryCodes().filter((code) => source.includes(`'${code}'`));
}

/**
 * Every workspace file the document names: the artifacts it points at by path from the root, and the documents
 * beside it, which a link spells by bare name because the reader of the link is already in `docs`.
 */
function namedArtifacts(): string[] {
  const body = section();
  const paths = [...body.matchAll(/(?:packages|docs)\/[A-Za-z0-9_./-]+/gu)].map((found) => found[0]);
  const siblings = [...body.matchAll(/\]\(([A-Za-z0-9_-]+\.md)\)/gu)].map((found) => `docs/${found[1] ?? ''}`);
  return [...new Set([...paths, ...siblings])];
}

/**
 * Every ceiling keyword anywhere in the layout. The document states that a byte ceiling belongs to the format
 * file and that this projection carries floors only, so this list has to stay empty for that sentence to be
 * true, and an added bound on the far side of a floor is exactly the edit that would otherwise leave the two
 * statements of one shape disagreeing in silence.
 */
function ceilingKeywords(node: JsonSchema): string[] {
  const found: string[] = [];
  const walk = (value: unknown): void => {
    if (Array.isArray(value)) {
      for (const one of value) walk(one);
      return;
    }
    if (value === null || typeof value !== 'object') return;
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      if (['maxLength', 'maxItems', 'maximum', 'exclusiveMaximum'].includes(key)) found.push(key);
      walk(child);
    }
  };
  walk(node);
  return found;
}

const declared = declaredRows();
const byPath = new Map(declared.map((one) => [one.path, one]));
const headerDef = schema.properties?.protectedHeader ?? {};

describe('docs/epoch-inventory-v1.md layout', () => {
  it('names every member the layout declares, and no member it does not', () => {
    // Order-insensitive on purpose: which block of the table comes first is a choice of prose, and the case
    // below is what pins order. What this case owes the reader is that the two statements name one set.
    const paths = rows().map((row) => row.path);
    expect(new Set(paths).size, 'one row key appears twice, so a member is both invented and missing').toBe(paths.length);
    expect([...paths].sort(), 'the table and the layout do not name the same members').toEqual(
      declared.map((one) => one.path).sort(),
    );
  });

  it('gives each member the type and the required-ness the layout gives it', () => {
    for (const row of rows()) {
      const want = byPath.get(row.path);
      if (want === undefined) throw new Error(`${row.path} is a row the published layout has no member for`);
      expect(row.type, `${row.path} is typed as the layout types it`).toBe(want.type);
      expect(row.required, `${row.path} is required exactly where the layout requires it`).toBe(want.required);
    }
    // The one position of the whole projection that may be absent is the envelope's signature, and the row says
    // why: a display of an unsigned document still shows. Nothing below the envelope is optional.
    const optional = rows().filter((row) => !row.required).map((row) => row.path);
    expect(optional, 'the layout leaves more than the projection of a signature open').toEqual(['signature']);
  });

  it('keeps each block of the table together, in the order the layout declares its members', () => {
    // A row that belongs to one block and lands inside another reads as a member that moved, and a block split
    // down the table is how a reimplementer starts seeing a shape that is not there.
    const blocks = rows().map((row) => blockOf(row.path));
    const seen: string[] = [];
    for (const block of blocks) {
      if (seen[seen.length - 1] !== block) seen.push(block);
    }
    expect(seen.length, 'a block of the table is not contiguous').toBe(new Set(seen).size);
    const grouped = new Map<string, string[]>();
    for (const one of declared) {
      const list = grouped.get(blockOf(one.path)) ?? [];
      list.push(one.path);
      grouped.set(blockOf(one.path), list);
    }
    for (const [block, paths] of grouped) {
      const inTable = rows().filter((row) => blockOf(row.path) === block).map((row) => leafOf(row.path));
      expect(inTable, `${block === '' ? 'the top of the table' : block} is not in the order the layout declares it`).toEqual(
        paths.map((one) => leafOf(one)),
      );
    }
  });

  it('lays the signed header out with exactly the parameters the layout projects', () => {
    const names = Object.keys(headerDef.properties ?? {});
    const laid = labelRows();
    expect(laid.map((one) => one.name).sort(), 'the header table and the layout name different parameters').toEqual(
      [...names].sort(),
    );
    for (const one of laid) {
      expect(one.label, `${one.name} is named by something that is not a COSE label number`).toMatch(/^\d+$/u);
    }
    expect(new Set(laid.map((one) => one.label)).size, 'two signed parameters share one label').toBe(laid.length);
    // The sentence above the table counts the parameters in words, and the count is the layout's.
    const stated = /contains exactly ([a-z]+) parameters/u.exec(prose());
    expect(stated, 'the document stopped counting the signed parameters').not.toBeNull();
    expect(spelledNumber(stated?.[1] ?? ''), 'and the count it states').toBe(names.length);
    const valueOf = (parameter: string): string => laid.find((one) => one.name === parameter)?.value ?? '';
    expect(valueOf('typ'), 'the header table states a content type the layout does not fix').toContain(
      String(headerDef.properties?.typ?.const),
    );
    expect(valueOf('alg'), 'the header table names no algorithm the layout fixes').toContain('-8');
    expect(valueOf('kid'), 'the header table states a key id of another width').toContain('32-byte');
    expect(deref(headerDef.properties?.kid).pattern, 'the layout no longer projects the kid as thirty-two bytes of hex').toContain('{64}');
  });

  it('states the floors the layout states, and claims no ceiling it does not carry', () => {
    // A floor is a fact a reader enforces, so the row beside it has to say it, and a row that promises a floor
    // the layout never gave is the same defect pointed the other way. The two lists the run states about itself
    // carry no floor, and the rows say so, because an empty one of those is a statement rather than an absence.
    for (const one of declared) {
      if (one.node.type !== 'array') continue;
      const row = rows().find((each) => each.path === one.path);
      if (one.node.minItems === 1) {
        expect(row?.states ?? '', `${one.path} has a floor the row beside it does not state`).toMatch(/at least one/iu);
        continue;
      }
      expect(one.node.minItems, `${one.path} grew a floor this reader has no sentence for`).toBeUndefined();
      expect(row?.states ?? '', `${one.path} is a list whose emptiness the row does not state`).toContain('no floor');
    }
    expect(ceilingKeywords(schema), 'the layout grew a ceiling the document says belongs to the format').toEqual([]);
    expect(prose()).toContain('A byte ceiling belongs to the CDDL');
  });

  it('files the entries where the layout files them', () => {
    // The path is a claim a reader checks against the entry's own digest, and the two file names are the layout.
    const body = prose();
    for (const named of [
      `${EPOCH_INVENTORY_PACKS_DIRECTORY}/<digest>/${EPOCH_INVENTORY_PACK_FILE}`,
      `${EPOCH_INVENTORY_PACKS_DIRECTORY}/<digest>/${EPOCH_INVENTORY_RETENTION_FILE}`,
    ]) {
      expect(body, `the document stopped naming ${named}`).toContain(named);
    }
    const cddl = readSourceFile(CDDL);
    expect(cddl).toContain(`"${EPOCH_INVENTORY_CONTENT_TYPE}"`);
  });

  it('names every refusal the reader answers with, and no refusal it never raises', () => {
    const named = refusalRows();
    expect(new Set(named).size, 'one refusal is named by two rows').toBe(named.length);
    expect([...named].sort(), 'the refusals table and the reader do not answer with the same codes').toEqual(
      readerCodes().sort(),
    );
    const registry = registryCodes();
    for (const code of named) {
      expect(registry, `${code} is named by the document and declared nowhere`).toContain(code);
    }
    for (const code of registry.filter((one) => one.startsWith(PREFIX))) {
      expect(named, `${code} is declared for this container and named by no row`).toContain(code);
    }
    // And the document says which answers a caller must not merge, because they are about the document, about
    // two parts of one document, about a row's subject, and about the reader's own hands.
    const body = prose();
    for (const phrase of [
      'is one document contradicting itself at a position',
      'is one document contradicting itself across its entries',
      'is a row about something the document does not describe',
      'is a reader that was handed too little',
    ]) {
      expect(body, `the document stopped telling a caller that this refusal ${phrase}`).toContain(phrase);
    }
  });

  it('states the identity of the schema file it restates', () => {
    const body = prose();
    expect(schema.$id, 'the schema carries no identity for the document to state').toBe(
      'https://ashaveri.com/schemas/epoch-inventory-v1.json',
    );
    expect(body).toContain(String(schema.$id));
    expect(body).toContain('packages/receipt/schemas/epoch-inventory-v1.schema.json');
    expect(body).toContain('packages/receipt/epoch-inventory.cddl');
    expect(body, 'the document points at the test that holds this table to the schema').toContain(
      'packages/fixtures/test/epoch-inventory-doc.test.ts',
    );
  });

  it('names only artifacts that are in the tree', () => {
    const artifacts = namedArtifacts();
    // The floor is against a sweep that silently matched nothing, which would make this case green while the
    // document named files that had moved.
    expect(artifacts.length, 'the document names almost no workspace file').toBeGreaterThanOrEqual(6);
    for (const one of artifacts) {
      expect(existsSync(fileURLToPath(new URL(`../../../${one}`, import.meta.url))), `${one} is named by the document and is not in the tree`).toBe(
        true,
      );
    }
  });

  it('is a standalone statement of the container', () => {
    // The document is the first thing a reimplementer opens, so it names the facts a second file would otherwise
    // have to supply: the content type, the label it sits at, the tag around the envelope, the structure the
    // signature covers, the encoding, and the two rules of the JSON reading.
    const body = prose();
    expect(body).toContain('ashaveri/epoch-inventory');
    expect(body).toContain('label 3');
    expect(body).toContain('Signature1');
    expect(body).toContain('tag 18');
    expect(body).toContain('Core Deterministic Encoding');
    expect(body).toContain('lowercase hex');
    expect(body).toContain('signed byte for byte');
    expect(body).toContain('No member name appears twice');
    expect(body).toContain('Every number is written as an integer');
    expect(body, 'the document cites a line number, which is a fact about a file that edits itself').not.toMatch(
      /line \d+/u,
    );
  });

  it('says what a verified inventory does not establish', () => {
    const body = prose();
    for (const phrase of [
      'It is not a claim that the packs exist',
      'It is not a claim that the run is complete',
      'It is not a statement about a duty, a lawful basis or a request',
      'It is not a claim about freshness',
    ]) {
      expect(body, `the document stopped saying that a verified inventory ${phrase.toLowerCase()}`).toContain(phrase);
    }
    expect(body, 'the document lets a reader of one document claim a check on the packs').not.toMatch(
      /\bverifies the pack/u,
    );
    expect(body).toContain('The reader is handed this document and nothing else');
    expect(body).toContain('Position in `packs` bears nothing');
  });
});
