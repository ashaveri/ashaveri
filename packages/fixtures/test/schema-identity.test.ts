import { describe, expect, it } from 'vitest';
import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

/**
 * Every published schema URI names the version it describes.
 *
 * The rule exists because two documents already share one format family: the receipt spec defines payload
 * `v: 1` and `v: 2`, and a reader is told to refuse a version it does not implement. An identity like
 * `schemas/receipt.json` cannot stand for one of those two, so the next version would either reuse a URI
 * that already meant something else or leave the old file named as though it were the only one. Carrying
 * the number in the identity is what makes a second version an addition rather than a redefinition.
 *
 * The directory is walked rather than a list written down, because a fifth schema added on its own terms is
 * exactly the case this catches, and a list would have to be edited to notice. Both schema directories are
 * read, and each has to yield at least one file, since a path that quietly stopped resolving would leave
 * every assertion below true of nothing.
 */

const HOST = 'https://ashaveri.com/schemas/';

const SCHEMA_DIRS: readonly (readonly [label: string, href: string])[] = [
  ['packages/receipt/schemas', '../../receipt/schemas'],
  ['packages/sdk/schemas', '../../sdk/schemas'],
];

interface Shape {
  $id?: unknown;
  properties?: Record<string, { const?: unknown }>;
  required?: readonly string[];
}

function schemasIn(label: string, href: string): [where: string, shape: Shape][] {
  const dir = fileURLToPath(new URL(href, import.meta.url));
  const names = readdirSync(dir, { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith('.schema.json'))
    .map((entry) => entry.name)
    .sort();
  expect(names.length, `${label} yielded no schema files, so the checks below would pass on nothing`).toBeGreaterThan(
    0,
  );
  return names.map((name) => [`${label}/${name}`, JSON.parse(readFileSync(`${dir}/${name}`, 'utf8')) as Shape]);
}

const all = SCHEMA_DIRS.flatMap(([label, href]) => schemasIn(label, href));

describe('published schema identities', () => {
  it('gives every schema a versioned identity that matches its file name', () => {
    expect(all.length, 'at least one schema was read from each directory').toBeGreaterThanOrEqual(2);
    for (const [where, shape] of all) {
      const file = where.slice(where.lastIndexOf('/') + 1);
      const match = /^(.+)-v(\d+)\.schema\.json$/u.exec(file);
      expect(match, `${where} is not named <thing>-vN.schema.json`).not.toBeNull();
      const [, thing, digits] = match ?? [];
      expect(shape.$id, `${where} carries no identity at all`).toBeDefined();
      expect(
        shape.$id,
        `${where} is named for ${thing} version ${digits}, so its identity has to say the same`,
      ).toBe(`${HOST}${thing}-v${digits}.json`);
    }
  });

  it('keeps the version in the identity and the version member inside the document equal', () => {
    for (const [where, shape] of all) {
      const digits = /-v(\d+)\.schema\.json$/u.exec(where)?.[1] ?? '';
      const declared = shape.properties?.v?.const;
      if (declared === undefined) continue;
      expect(
        String(declared),
        `${where} names version ${String(declared)} inside a document whose identity says v${digits}`,
      ).toBe(digits);
      expect(shape.required ?? [], `${where} declares a version member it does not require`).toContain('v');
    }
  });

  it('holds no two schemas to the same identity', () => {
    const ids = all.map(([, shape]) => String(shape.$id));
    expect(new Set(ids).size, 'two schema files share one identity').toBe(ids.length);
  });
});
