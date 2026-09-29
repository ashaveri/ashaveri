import { describe, expect, it } from 'vitest';
import { readSourceFile, sectionBody, tableRows } from './doc-contract.js';

/**
 * The retention manifest layout exists twice in two statements of it: as a JSON Schema a reader can run, and as
 * the field table in `docs/receipt-spec.md` that a reader actually reads first. Two statements of one shape are
 * how one comes to disagree with the other, and a schema that gained a member in silence would leave the prose
 * describing a document nobody writes and a reader checking a layout they were never told about.
 *
 * So each section is read as data and its own schema as data, and the pair is compared in both directions: every
 * row of the table has to resolve to a member the layout defines, with the type and the required-ness the layout
 * gives it, and every member the layout defines has to appear in the table, in the order the schema declares
 * them. The pair is enumerated out of the schema rather than written twice, which is the one way this file can
 * notice a widening: a test that restated the member list would have to be edited alongside the schema and would
 * pass either way.
 *
 * Both layouts are held this way rather than one, because version two is the case the check exists for. A second
 * section of prose added beside a second schema is exactly the pair that can drift apart in silence, and the one
 * member that differs between them, `presence`, is the member an inventory folds. The two tables are also held
 * against each other: the version two list is the version one list plus the members under `presence` and nothing
 * else, which is what a version bump that changes only one member states, and the section that carries it states
 * which half of a reader's question each of the two artifacts answers.
 *
 * The default age bound this estate publishes is checked against the constant that sets it, in
 * `gateway/src/store.ts`, because section 5.3 names the number in seconds and the store is where it lives. A
 * prose figure agreeing with its own source code by accident is the failure this catches. The schema is asserted
 * to hold no such number, so this check cannot quietly become a second way of enforcing a legal floor the layout
 * has decided not to enforce.
 */

const DOC = '../../../docs/receipt-spec.md';
const STORE = '../../../gateway/src/store.ts';
/** Header of a layout table: one row per member the published shape names. */
const LAYOUT_TABLE = '| Member | Type | Required | What it states |';

interface Layout {
  /** The heading of the section that states this layout, matched whole. */
  readonly section: string;
  /** The schema file that is the normative statement of it. */
  readonly file: string;
  /** The version the section is written for, which is what the sentences below are asked of. */
  readonly version: 1 | 2;
}

const LAYOUTS: readonly Layout[] = [
  { section: '### 5.3 Retention manifest layout', file: '../../../packages/receipt/schemas/retention-v1.schema.json', version: 1 },
  {
    section: '### 5.4 Retention manifest layout, version 2',
    file: '../../../packages/receipt/schemas/retention-v2.schema.json',
    version: 2,
  },
];

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

interface Row extends Declared {
  readonly path: string;
  readonly states: string;
}

const document = readSourceFile(DOC);

/**
 * The body of one `### ` subsection: from its heading to the next heading of either level. `sectionBody` runs to
 * the next level two heading, which for the last section of a level is what a reader means and for the first of
 * two subsections is not, so the slice is narrowed here rather than in the shared helper every other suite in
 * this directory reads.
 */
function subsection(layout: Layout): string {
  const body = sectionBody(document, layout.section);
  const rest = body.split('\n');
  const end = rest.findIndex((line) => line.startsWith('### '));
  return (end < 0 ? rest : rest.slice(0, end)).join('\n');
}

function proseOf(layout: Layout): string {
  return subsection(layout).replace(/\s+/gu, ' ');
}

function schemaOf(layout: Layout): JsonSchema {
  return JSON.parse(readSourceFile(layout.file)) as JsonSchema;
}

/** A `$ref` becomes the definition it points at; anything else is already the node. */
function deref(schema: JsonSchema, node: JsonSchema | undefined): JsonSchema {
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
 * Every member the layout declares, as `block.leaf` paths with the array element written `[*]`, in the order the
 * schema writes them. That order is the order the writer serializes, so the table is compared against it rather
 * than sorted out of the way.
 */
function declared(schema: JsonSchema, path: string, node: JsonSchema, out: [string, Declared][]): [string, Declared][] {
  const required = node.required ?? [];
  for (const [key, child] of Object.entries(node.properties ?? {})) {
    const member = path === '' ? key : `${path}.${key}`;
    const target = deref(schema, child);
    out.push([member, { type: typeToken(target, member), required: required.includes(key) }]);
    if (target.properties !== undefined) declared(schema, member, target, out);
    if (target.items !== undefined) declared(schema, `${member}[*]`, deref(schema, target.items), out);
  }
  return out;
}

/** The one member a table path names, with the required-ness of the object that holds it. */
function resolve(schema: JsonSchema, path: string): Declared {
  let holder: JsonSchema = deref(schema, schema);
  let found: JsonSchema = holder;
  let heldBy: readonly string[] = holder.required ?? [];
  let key = '';
  for (const segment of path.split('.')) {
    const isArray = segment.endsWith('[*]');
    key = isArray ? segment.slice(0, -3) : segment;
    const child = holder.properties?.[key];
    if (child === undefined) throw new Error(`${path}: ${key} is not a member the layout declares`);
    heldBy = holder.required ?? [];
    found = deref(schema, child);
    holder = isArray ? deref(schema, found.items) : found;
  }
  return { type: typeToken(found, path), required: heldBy.includes(key) };
}

function rows(layout: Layout): Row[] {
  return tableRows(subsection(layout), LAYOUT_TABLE).map((cells) => ({
    path: cells[1]?.replace(/`/gu, '').trim() ?? '',
    type: cells[2]?.replace(/`/gu, '').trim() ?? '',
    required: (cells[3] ?? '').trim() === 'yes',
    states: cells[4] ?? '',
  }));
}

function declaredPaths(layout: Layout): string[] {
  const schema = schemaOf(layout);
  return declared(schema, '', schema, []).map(([path]) => path);
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

for (const layout of LAYOUTS) {
  const schema = schemaOf(layout);
  const members = declared(schema, '', schema, []);

  describe(`docs/receipt-spec.md retention manifest layout (${String(layout.version)})`, () => {
    it('names every member the schema declares, in the order it declares them', () => {
      const parsed = rows(layout);
      expect(parsed.map((row) => row.path), 'the table and the schema name the same members in the same order').toEqual(
        members.map(([path]) => path),
      );
    });

    it('states no member the schema does not define', () => {
      const known = new Set(members.map(([path]) => path));
      for (const row of rows(layout)) {
        expect(known.has(row.path), `the table names ${row.path}, which the published layout does not`).toBe(true);
      }
    });

    it('gives each member the type and the required-ness the layout gives it', () => {
      for (const row of rows(layout)) {
        const want = resolve(schema, row.path);
        expect(row.type, `${row.path} is typed as the schema types it`).toBe(want.type);
        expect(row.required, `${row.path} is required exactly where the schema requires it`).toBe(want.required);
      }
    });

    it('keeps the two optional bounds optional in both blocks that carry them', () => {
      const parsed = new Map(rows(layout).map((row) => [row.path, row]));
      for (const path of [
        'policy.maxAgeSeconds',
        'policy.maxCount',
        'retired.trims[*].under.maxAgeSeconds',
        'retired.trims[*].under.maxCount',
      ]) {
        expect(parsed.get(path)?.required, `${path} is absent to mean no bound, not to mean zero`).toBe(false);
      }
      expect(parsed.get('policy')?.required, 'the policy block itself always travels with the document').toBe(true);
    });

    it('cites the schema file it restates, and says what the artifact is not', () => {
      const body = proseOf(layout);
      const named = layout.file.replace('../../../', '');
      expect(body, 'the section names the file a reader should hold it against').toContain(named);
      expect(
        body,
        'and it names the test that holds the two statements together',
      ).toContain('packages/fixtures/test/retention-doc.test.ts');
      expect(
        body,
        'the section does not let a reader think the program that fills the fields is public',
      ).toContain('not part of this repository');
    });

    it('names the three duty labels the layout enumerates', () => {
      const labels = deref(schema, schema.$defs?.duty).properties?.article?.enum ?? [];
      expect(labels.length, 'the layout enumerates the duty labels').toBe(3);
      const row = rows(layout).find((each) => each.path === 'duty.article');
      expect(row, 'the table carries a duty.article row').toBeDefined();
      for (const label of labels) {
        expect(row?.states ?? '', `the duty.article row names the label ${String(label)}`).toContain(String(label));
      }
    });
  });
}

describe('docs/receipt-spec.md retention manifest layout (the two versions together)', () => {
  it('adds the presence members to version two and changes no other row', () => {
    const [first, second] = LAYOUTS;
    if (first === undefined || second === undefined) throw new Error('the two layouts are not both stated here');
    const one = declaredPaths(first);
    const two = declaredPaths(second);
    expect(two.slice(0, one.length), 'the version two table is not the version one table with a block appended').toEqual(
      one,
    );
    const added = two.slice(one.length);
    expect(added.length, 'version two adds more members than the one block it exists to carry').toBeGreaterThan(1);
    expect(
      added.every((path) => path === 'presence' || path.startsWith('presence.')),
      'a version two row sits outside the presence block, which is the one thing this bump is',
    ).toBe(true);
    const oneRows = new Map(rows(first).map((row) => [row.path, row]));
    for (const row of rows(second).filter((each) => each.path !== 'v' && oneRows.has(each.path))) {
      const before = oneRows.get(row.path);
      expect(
        { type: row.type, required: row.required },
        `${row.path} is a member one version spells differently from the other`,
      ).toEqual({ type: before?.type, required: before?.required });
    }
    expect(
      rows(second).find((row) => row.path === 'v')?.type,
      'the version row of each table states its own version, which is the point of the bump',
    ).toBe('2');
    expect(rows(first).find((row) => row.path === 'v')?.type).toBe('1');
  });

  it('says in both sections which half each artifact carries and which it does not', () => {
    const [first, second] = LAYOUTS;
    if (first === undefined || second === undefined) throw new Error('the two layouts are not both stated here');
    const one = proseOf(first);
    const two = proseOf(second);
    expect(one, 'section 5.3 names what signs the manifest').toContain('packs[].retentionSha256');
    expect(one, 'and says a manifest alone is a report rather than evidence').toContain(
      'a manifest handed over on its own is a report',
    );
    expect(two, 'the version two section states the split rather than leaving it implied').toContain(
      'Neither statement replaces the other',
    );
    expect(two, 'and names the inventory as the source of the reach this artifact cannot state').toContain(
      'packages/receipt/epoch-inventory.cddl',
    );
    expect(two, 'it says the observation claims nothing forward').toContain('no member here is forward-looking');
    expect(
      two,
      'and it tells a reader what the fold refuses, so the two halves are not read as one verdict',
    ).toContain('EPOCH_INVENTORY_PRESENCE_GAP');
    expect(two).not.toMatch(/will be available|will remain|guarantees? that .* is available/iu);
    expect(two, 'no compliance claim rides on the observation').not.toMatch(/compliant|discharged|lawful duty/iu);
    expect(one, 'the version one section makes no presence claim it cannot support').not.toContain('presence');
  });

  it('holds the store default named in the section against the constant that sets it', () => {
    const [first] = LAYOUTS;
    if (first === undefined) throw new Error('the version one layout is not stated here');
    const schema = schemaOf(first);
    const seconds = publishedDefault();
    expect(seconds, 'the store publishes its default as a product of whole factors').toBeGreaterThan(0);
    expect(proseOf(first), 'and the section states that many seconds').toContain(String(seconds));
    const duty = deref(schema, schema.$defs?.duty);
    expect(duty.if, 'while the layout conditions on no article').toBeUndefined();
    expect(duty.then, 'so the number lives in the store and the prose, not in a bound').toBeUndefined();
    expect(duty.properties?.requiredSeconds?.minimum, 'and a stated period is still a period').toBe(1);
  });
});
