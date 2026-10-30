import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { SdkError } from '../src/errors.js';
import {
  EXPECTED_HEAD_PINNERS,
  MAX_CHECKPOINT_INTERVAL_SECONDS,
  RETENTION_ASSESSMENT_ARTICLES,
  RETENTION_ASSESSMENT_FORMAT_VERSION,
  RETENTION_ASSESSMENT_MEMBERS,
  RETENTION_ASSESSMENT_OUTCOMES,
  RETENTION_COVERAGE_MEMBERS,
  RETENTION_SCOPE_MEMBERS,
  parseRetentionAssessment,
} from '../src/retention-assessment.js';

/**
 * The prose layout page against the layout that decides.
 *
 * `docs/retention-assessment-v1.md` exists because the member sets were readable only from TypeScript, and a page
 * nobody checks goes false quietly: this repository has already carried a document quoting a document that was
 * flatly wrong for days, and a suite that reads only code cannot see that. So the page states its lists in a form a
 * test can parse, and this file compares them, in both directions, against the JSON Schema a writer builds against
 * and the closed sets the reader enforces. A member added to one and not the others is a red suite, not a silent
 * divergence.
 *
 * The parse cases below are the page's other half: the four refusals it describes are run against a document taken
 * from the published vectors, so a claim that the layout refuses a shape is checked by the reader rather than by the
 * paragraph that says it.
 */

const docPath = fileURLToPath(new URL('../../../docs/retention-assessment-v1.md', import.meta.url));
const schemaPath = fileURLToPath(new URL('../schemas/retention-assessment-v1.schema.json', import.meta.url));
const vectorsPath = fileURLToPath(new URL('../../fixtures/data/retention-assessment-v1.json', import.meta.url));

/** A JSON Schema node of the shape this layout uses: nested objects, arrays whose `items` carry the row shape. */
interface SchemaNode {
  required?: string[];
  properties?: Record<string, SchemaNode>;
  enum?: (string | number)[];
  const?: string | number | boolean;
  items?: SchemaNode;
  type?: string;
}

/** The page's parsed `members(...)`, `enum(...)`, `bound(...)` and `version` lines, keyed by the path they name. */
interface Stated {
  members: Map<string, string[]>;
  enums: Map<string, string[]>;
  bound: number | undefined;
  version: number | undefined;
}

/** Walk the schema the way the page enumerates it: an array's row shape is named by the array's own path. */
function schemaRequired(node: SchemaNode, path = 'top'): Map<string, string[]> {
  const found = new Map<string, string[]>();
  if (node.required !== undefined) {
    found.set(path, [...node.required].sort());
  }
  for (const [key, child] of Object.entries(node.properties ?? {})) {
    for (const [nested, members] of schemaRequired(child, path === 'top' ? key : `${path}.${key}`)) {
      found.set(nested, members);
    }
  }
  if (node.items !== undefined) {
    for (const [nested, members] of schemaRequired(node.items, path)) {
      if (!found.has(nested)) {
        found.set(nested, members);
      }
    }
  }
  return found;
}

function schemaEnums(node: SchemaNode, path = 'top'): Map<string, string[]> {
  const found = new Map<string, string[]>();
  if (node.enum !== undefined) {
    found.set(path, node.enum.map(String));
  }
  for (const [key, child] of Object.entries(node.properties ?? {})) {
    for (const [nested, values] of schemaEnums(child, path === 'top' ? key : `${path}.${key}`)) {
      found.set(nested, values);
    }
  }
  if (node.items !== undefined) {
    for (const [nested, values] of schemaEnums(node.items, path)) {
      if (!found.has(nested)) {
        found.set(nested, values);
      }
    }
  }
  return found;
}

function readPage(): Stated {
  const stated: Stated = { members: new Map(), enums: new Map(), bound: undefined, version: undefined };
  const split = (value: string | undefined): string[] => (value ?? '').split(',').map((one) => one.trim());
  for (const raw of readFileSync(docPath, 'utf8').split('\n')) {
    const line = raw.trim();
    const members = /^members\((.+)\): (.+)$/.exec(line);
    if (members !== null) {
      const [, path, value] = members;
      if (path !== undefined && value !== undefined) {
        stated.members.set(path, split(value).sort());
      }
      continue;
    }
    const enumeration = /^enum\((.+)\): (.+)$/.exec(line);
    if (enumeration !== null) {
      const [, path, value] = enumeration;
      if (path !== undefined && value !== undefined) {
        stated.enums.set(path, split(value));
      }
      continue;
    }
    const bound = /^bound\(.+\): (\d+)$/.exec(line);
    if (bound?.[1] !== undefined) {
      stated.bound = Number(bound[1]);
      continue;
    }
    const version = /^version: (\d+)$/.exec(line);
    if (version?.[1] !== undefined) {
      stated.version = Number(version[1]);
    }
  }
  return stated;
}

/** One code, so a page that drops a refusal says so in the suite rather than in a review comment. */
function refusalCodeOf(document: unknown): string {
  try {
    parseRetentionAssessment(document);
  } catch (error) {
    return error instanceof SdkError ? error.code : `not-an-SdkError: ${String(error)}`;
  }
  return 'accepted';
}

/** The published vectors' first assessed case: a period genuinely covered, so the base reads and the edits refuse. */
function honestDocument(): Record<string, unknown> {
  const vectors = JSON.parse(readFileSync(vectorsPath, 'utf8')) as { vectors: { document: Record<string, unknown> }[] };
  const document = vectors.vectors[0]?.document;
  if (document === undefined) {
    throw new Error('the published vectors carry no assessed case to read');
  }
  return structuredClone(document);
}

function pinOf(document: Record<string, unknown>): Record<string, unknown> {
  const scope = document['scope'] as Record<string, unknown>;
  const intake = scope['intake'] as Record<string, unknown>;
  return intake['expectedHead'] as Record<string, unknown>;
}

describe('docs/retention-assessment-v1.md states the layout the schema enforces', () => {
  const page = readPage();
  const schema = JSON.parse(readFileSync(schemaPath, 'utf8')) as SchemaNode;

  it('names every block the schema closes, and no block it does not', () => {
    const enforced = schemaRequired(schema);
    expect([...page.members.keys()].sort()).toEqual([...enforced.keys()].sort());
    for (const [path, members] of enforced) {
      expect(page.members.get(path), `the page names different members for ${path}`).toEqual(members);
    }
  });

  it('names every enumeration the schema fixes, in the order the schema states it', () => {
    const enforced = schemaEnums(schema);
    expect([...page.enums.keys()].sort()).toEqual([...enforced.keys()].sort());
    for (const [path, values] of enforced) {
      expect(page.enums.get(path), `the page names different values for ${path}`).toEqual(values);
    }
  });

  it('agrees with the sets and the bound the reader exports', () => {
    expect(page.members.get('top')).toEqual([...RETENTION_ASSESSMENT_MEMBERS].sort());
    expect(page.members.get('scope')).toEqual([...RETENTION_SCOPE_MEMBERS].sort());
    expect(page.members.get('coverage')).toEqual([...RETENTION_COVERAGE_MEMBERS].sort());
    expect(page.enums.get('scope.duty.article')).toEqual([...RETENTION_ASSESSMENT_ARTICLES]);
    expect(page.enums.get('scope.intake.expectedHead.pinnedBy')).toEqual([...EXPECTED_HEAD_PINNERS]);
    expect(page.enums.get('assessment.outcome')).toEqual([...RETENTION_ASSESSMENT_OUTCOMES]);
    expect(page.bound).toBe(MAX_CHECKPOINT_INTERVAL_SECONDS);
    expect(page.version).toBe(RETENTION_ASSESSMENT_FORMAT_VERSION);
  });

  it('carries both refusal codes on the page that explains them', () => {
    const prose = readFileSync(docPath, 'utf8');
    expect(prose).toContain('NOT_RETENTION_ASSESSMENT');
    expect(prose).toContain('RETENTION_ASSESSMENT_DISAGREES');
    expect(prose).toContain('parseRetentionAssessment');
    expect(prose).toContain('assessRetention');
  });
});

describe('the pin refusals the page describes are the ones the reader runs', () => {
  it('reads the honest case the page describes before refusing anything', () => {
    expect(refusalCodeOf(honestDocument())).toBe('accepted');
  });

  it('refuses a head with no party credited with pinning it', () => {
    const document = honestDocument();
    pinOf(document)['pinnedBy'] = 'none';
    expect(refusalCodeOf(document)).toBe('NOT_RETENTION_ASSESSMENT');
  });

  it('refuses no head while naming a party that gave one', () => {
    const document = honestDocument();
    Object.assign(pinOf(document), { sha256: null, pinnedBy: 'customer' });
    expect(refusalCodeOf(document)).toBe('NOT_RETENTION_ASSESSMENT');
  });

  it('refuses a silent absence: no head, no party, no reason', () => {
    const document = honestDocument();
    Object.assign(pinOf(document), { sha256: null, pinnedBy: 'none', reason: null });
    expect(refusalCodeOf(document)).toBe('NOT_RETENTION_ASSESSMENT');
  });

  it('refuses a head stated beside a reason for having none', () => {
    const document = honestDocument();
    pinOf(document)['reason'] = 'the store could not reach its pinning service';
    expect(refusalCodeOf(document)).toBe('NOT_RETENTION_ASSESSMENT');
  });

  it('refuses a member the version does not define, which is why the lists above are closed', () => {
    const document = honestDocument();
    pinOf(document)['signerKey'] = 'anything';
    expect(refusalCodeOf(document)).toBe('NOT_RETENTION_ASSESSMENT');
  });
});
