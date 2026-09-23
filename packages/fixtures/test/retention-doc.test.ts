import { describe, expect, it } from 'vitest';
import { readSourceFile, sectionBody, tableRows } from './doc-contract.js';

/**
 * The retention manifest layout exists twice: as a JSON Schema a reader can run, and as the field table in
 * `docs/receipt-spec.md` that a reader actually reads first. Two statements of one shape are how one comes
 * to disagree with the other, and a schema that gained a member in silence would leave the prose describing
 * a document nobody writes and a reader checking a layout they were never told about.
 *
 * So this reads the section as data and the schema as data, and compares them in both directions: every row
 * of the table has to resolve to a member the layout defines, with the type and the required-ness the layout
 * gives it, and every member the layout defines has to appear in the table, in the order the schema declares
 * them. The pair is enumerated out of the schema rather than written twice, which is the one way this file
 * can notice a widening: a test that restated the member list would have to be edited alongside the schema
 * and would pass either way.
 *
 * The default age bound this estate publishes is checked against the constant that sets it, in
 * `gateway/src/store.ts`, because the section names the number in seconds and the store is where it lives.
 * A prose figure agreeing with its own source code by accident is the failure this catches. The schema is
 * asserted to hold no such number, so this check cannot quietly become a second way of enforcing a legal
 * floor the layout has decided not to enforce.
 */

const DOC = '../../../docs/receipt-spec.md';
const SCHEMA = '../../../packages/receipt/schemas/retention-v1.schema.json';
const STORE = '../../../gateway/src/store.ts';
/** The one subsection this test reads, matched by its full heading line. */
const SECTION = '### 5.3 Retention manifest layout';
/** Header of the layout table: one row per member the published shape names. */
const LAYOUT_TABLE = '| Member | Type | Required | What it states |';

interface JsonSchema {
  $defs?: Record<string, JsonSchema>;
  $ref?: unknown;
  const?: unknown;
  enum?: readonly unknown[];
  if?: JsonSchema;
  items?: JsonSchema;
  minimum?: unknown;
  properties?: Record<string, JsonSchema>;
  required?: readonly string[];
  then?: JsonSchema;
  type?: unknown;
}

interface Declared {
  readonly type: string;
  readonly required: boolean;
}

const schema = JSON.parse(readSourceFile(SCHEMA)) as JsonSchema;

function section(): string {
  return sectionBody(readSourceFile(DOC), SECTION);
}

/** The section as one line, so a check pins a sentence rather than the place a paragraph was wrapped. */
function prose(): string {
  return section().replace(/\s+/gu, ' ');
}

/** A `$ref` becomes the definition it points at; anything else is already the node. */
function deref(node: JsonSchema | undefined): JsonSchema {
  if (node === undefined) throw new Error('the layout references a block it does not define');
  if (typeof node.$ref === 'string') {
    const name = /^#\/\$defs\/(.+)$/u.exec(node.$ref)?.[1] ?? '';
    const found = schema.$defs?.[name];
    if (found === undefined) throw new Error(`${node.$ref} names no definition in the published layout`);
    return found;
  }
  return node;
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

/**
 * Every member the layout declares, as `block.leaf` paths with the array element written `[*]`, in the
 * order the schema writes them. That order is the order the writer serializes, so the table is compared
 * against it rather than sorted out of the way.
 */
function declared(path: string, node: JsonSchema, out: [string, Declared][]): [string, Declared][] {
  const required = node.required ?? [];
  for (const [key, child] of Object.entries(node.properties ?? {})) {
    const member = path === '' ? key : `${path}.${key}`;
    const target = deref(child);
    out.push([member, { type: typeToken(target, member), required: required.includes(key) }]);
    if (target.properties !== undefined) declared(member, target, out);
    if (target.items !== undefined) declared(`${member}[*]`, deref(target.items), out);
  }
  return out;
}

/** The one member a table path names, with the required-ness of the object that holds it. */
function resolve(path: string): Declared {
  let holder: JsonSchema = deref(schema);
  let found: JsonSchema = holder;
  let heldBy: readonly string[] = holder.required ?? [];
  let key = '';
  for (const segment of path.split('.')) {
    const isArray = segment.endsWith('[*]');
    key = isArray ? segment.slice(0, -3) : segment;
    const child = holder.properties?.[key];
    if (child === undefined) throw new Error(`${path}: ${key} is not a member the layout declares`);
    heldBy = holder.required ?? [];
    found = deref(child);
    holder = isArray ? deref(found.items) : found;
  }
  return { type: typeToken(found, path), required: heldBy.includes(key) };
}

interface Row extends Declared {
  readonly path: string;
  readonly states: string;
}

function tableRowsParsed(): Row[] {
  return tableRows(section(), LAYOUT_TABLE).map((cells) => ({
    path: cells[1]?.replace(/`/gu, '').trim() ?? '',
    type: cells[2]?.replace(/`/gu, '').trim() ?? '',
    required: (cells[3] ?? '').trim() === 'yes',
    states: cells[4] ?? '',
  }));
}

/** The seconds `gateway/src/store.ts` publishes as its default age bound. */
function publishedDefault(): number {
  const found = /export const MINIMUM_RETENTION_SECONDS\s*=\s*([\d\s*]+);/u.exec(readSourceFile(STORE));
  if (!found) throw new Error('MINIMUM_RETENTION_SECONDS is not a product of whole numbers in gateway/src/store.ts');
  return (found[1] ?? '').split('*').reduce((total, part) => {
    const factor = Number(part.trim());
    if (!Number.isInteger(factor) || factor <= 0) throw new Error(`${part} is not a whole factor`);
    return total * factor;
  }, 1);
}

const declaredMembers = declared('', deref(schema), []);

describe('docs/receipt-spec.md retention manifest layout (5.3)', () => {
  it('names every member the schema declares, in the order it declares them', () => {
    const rows = tableRowsParsed();
    expect(rows.map((row) => row.path), 'the table and the schema name the same members in the same order').toEqual(
      declaredMembers.map(([path]) => path),
    );
  });

  it('states no member the schema does not define', () => {
    const known = new Set(declaredMembers.map(([path]) => path));
    for (const row of tableRowsParsed()) {
      expect(known.has(row.path), `the table names ${row.path}, which the published layout does not`).toBe(true);
    }
  });

  it('gives each member the type and the required-ness the layout gives it', () => {
    for (const row of tableRowsParsed()) {
      const want = resolve(row.path);
      expect(row.type, `${row.path} is typed as the schema types it`).toBe(want.type);
      expect(row.required, `${row.path} is required exactly where the schema requires it`).toBe(want.required);
    }
  });

  it('keeps the two optional bounds optional in both blocks that carry them', () => {
    const rows = new Map(tableRowsParsed().map((row) => [row.path, row]));
    for (const path of [
      'policy.maxAgeSeconds',
      'policy.maxCount',
      'retired.trims[*].under.maxAgeSeconds',
      'retired.trims[*].under.maxCount',
    ]) {
      expect(rows.get(path)?.required, `${path} is absent to mean no bound, not to mean zero`).toBe(false);
    }
    expect(rows.get('policy')?.required, 'the policy block itself always travels with the document').toBe(true);
  });

  it('cites the schema file it restates, and says what the artifact is not', () => {
    const body = prose();
    expect(body, 'the section names the file a reader should hold it against').toContain(
      'packages/receipt/schemas/retention-v1.schema.json',
    );
    expect(body).toContain('carries no signature');
    expect(body, 'the section does not let a reader think something here writes the document').toContain(
      'nothing here writes or reads',
    );
    expect(body, 'and it names the test that holds the two statements together').toContain(
      'packages/fixtures/test/retention-doc.test.ts',
    );
  });

  it('names the three duty labels the layout enumerates', () => {
    const labels = deref(schema.$defs?.duty).properties?.article?.enum ?? [];
    expect(labels.length, 'the layout enumerates the duty labels').toBe(3);
    const row = tableRowsParsed().find((each) => each.path === 'duty.article');
    expect(row, 'the table carries a duty.article row').toBeDefined();
    for (const label of labels) {
      expect(row?.states ?? '', `the duty.article row names the label ${String(label)}`).toContain(String(label));
    }
  });

  it('holds the store default named in the section against the constant that sets it', () => {
    const seconds = publishedDefault();
    expect(seconds, 'the store publishes its default as a product of whole factors').toBeGreaterThan(0);
    expect(prose(), 'and the section states that many seconds').toContain(String(seconds));
    const duty = deref(schema.$defs?.duty);
    expect(duty.if, 'while the layout conditions on no article').toBeUndefined();
    expect(duty.then, 'so the number lives in the store and the prose, not in a bound').toBeUndefined();
    expect(duty.properties?.requiredSeconds?.minimum, 'and a stated period is still a period').toBe(1);
  });
});
