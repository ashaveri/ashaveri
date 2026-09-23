import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { Ajv2020, type ValidateFunction } from 'ajv/dist/2020.js';

/**
 * Holds the published retention manifest layout to itself.
 *
 * The layout is public and the program that writes it is not, so nothing here can be derived from a
 * writer in this repository: what this file can do is refuse a silent widening. Every member the
 * artifact names, whether each is required, and how each nested block closes are asserted as written
 * lists rather than read back out of the schema and compared with itself, because a test that derives
 * both sides passes whatever the schema says and notices nothing.
 *
 * Two claims are executable rather than merely structural, and they are the two that matter to a
 * reader. The document compiles as a schema, so the published layout is a statement a verifier can
 * run rather than prose with braces in it. And the line the layout draws between a shape and a legal
 * reading is enforced in the permissive direction: a stated period has to be a period, while no
 * article's value is bounded, because Article 19(1) yields to other Union or national law and a
 * refusal here would overrule a reading this estate does not own. The conditional floor that once sat
 * on the duty block is therefore asserted absent, which is a claim a test can hold rather than a
 * sentence a reader has to trust.
 */

const schemaPath = fileURLToPath(new URL('../schemas/retention-v1.schema.json', import.meta.url));
const schemaText = readFileSync(schemaPath, 'utf8');

interface JsonSchema {
  $defs?: Record<string, JsonSchema>;
  $id?: unknown;
  $ref?: unknown;
  additionalProperties?: unknown;
  const?: unknown;
  description?: unknown;
  enum?: readonly unknown[];
  if?: JsonSchema;
  items?: JsonSchema;
  minItems?: unknown;
  minimum?: unknown;
  pattern?: unknown;
  properties?: Record<string, JsonSchema>;
  required?: readonly string[];
  then?: JsonSchema;
  type?: unknown;
}

const schema = JSON.parse(schemaText) as JsonSchema;

function descriptionOf(text: string): string {
  const node = text === 'root' ? schema : (schema.$defs?.[text] ?? {});
  return typeof node.description === 'string' ? node.description : '';
}

/** A named definition, or a failure that names the one that went missing. */
function def(name: string): JsonSchema {
  const node = schema.$defs?.[name];
  if (node === undefined) throw new Error(`$defs.${name} is not part of the published layout`);
  return node;
}

/** The members of a block, keyed by name. */
function members(name: string): Record<string, JsonSchema> {
  const block = name === 'root' ? schema : def(name);
  if (block.properties === undefined) throw new Error(`${name} names no members`);
  return block.properties;
}

function prop(name: string, key: string): JsonSchema {
  const node = members(name)[key];
  if (node === undefined) throw new Error(`${name}.${key} is not part of the published layout`);
  return node;
}

function requiredOf(name: string): readonly string[] {
  const block = name === 'root' ? schema : def(name);
  if (block.required === undefined) throw new Error(`${name} states no required list`);
  return block.required;
}

/** A whole manifest in the layout's own members, with one block replaced by a test's variant. */
function manifest(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    v: 1,
    at: 1_800_000_000,
    policy: { maxAgeSeconds: 15_897_600, maxCount: 100_000 },
    retained: { from: 1_790_000_000, to: 1_799_999_999, count: 42 },
    retired: {
      byAge: 7,
      byCount: 3,
      trims: [{ at: 1_795_000_000, byAge: 7, byCount: 3, under: { maxAgeSeconds: 15_897_600 } }],
    },
    chain: {
      anchor: '00'.repeat(32),
      head: 'ab'.repeat(32),
    },
    duty: { article: '19(1)', requiredSeconds: 15_897_600, heldSeconds: 10_000_000, met: false },
    ...overrides,
  };
}

/** The published layout compiled as a schema, in ajv's strict mode, so a misspelling is a failure here. */
function compile(s: object): ValidateFunction<unknown> {
  const ajv = new Ajv2020({ strict: true });
  return ajv.compile(s);
}

const validate = compile(schema);

describe('retention-v1.schema.json published layout', () => {
  it('names the seven top level members and nothing else', () => {
    expect(schema.$id, 'the layout carries an identity').toBe('https://ashaveri.com/schemas/retention.json');
    expect(schema.type, 'the artifact is a JSON object').toBe('object');
    expect(schema.additionalProperties, 'the top level map is closed').toBe(false);
    expect(requiredOf('root'), 'the required members are the seven the writer always emits').toEqual([
      'v',
      'at',
      'policy',
      'retained',
      'retired',
      'chain',
      'duty',
    ]);
    expect(Object.keys(members('root')).sort(), 'no optional top level member hides beside them').toEqual(
      [...requiredOf('root')].sort(),
    );
  });

  it('keeps every version one constant rather than a discriminant', () => {
    expect(prop('root', 'v').const, 'exactly one format version is defined').toBe(1);
    expect(prop('root', 'v').type, 'a version is not a number somebody can write as a fraction').toBeUndefined();
  });

  it('states the instants and counts as whole non-negative integers', () => {
    const integerFields: readonly (readonly [string, string])[] = [
      ['root', 'at'],
      ['window', 'from'],
      ['window', 'to'],
      ['window', 'count'],
      ['retired', 'byAge'],
      ['retired', 'byCount'],
      ['trimEvent', 'at'],
      ['trimEvent', 'byAge'],
      ['trimEvent', 'byCount'],
      ['duty', 'heldSeconds'],
    ];
    for (const [name, key] of integerFields) {
      const node = prop(name, key);
      expect(node.type, `${name}.${key} counts whole units`).toBe('integer');
      expect(node.minimum, `${name}.${key} is never negative`).toBe(0);
    }
    expect(prop('policyState', 'maxAgeSeconds').type, 'an age bound is whole seconds').toBe('integer');
    expect(prop('policyState', 'maxCount').type, 'a count bound is a whole number of receipts').toBe('integer');
    expect(prop('duty', 'requiredSeconds').minimum, 'a required period of zero seconds is not a period').toBe(1);
  });

  it('declares the two policy bounds optional in both places they appear', () => {
    const policy = def('policyState');
    expect(policy.additionalProperties, 'a policy block closes').toBe(false);
    expect(requiredOf('policyState'), 'an absent bound means no cap rather than zero').toEqual([]);
    expect(prop('root', 'policy').$ref, 'the configured policy is a policy block').toBe('#/$defs/policyState');
    expect(prop('trimEvent', 'under').$ref, 'a trim carries the same shape, read off its own record').toBe(
      '#/$defs/policyState',
    );
  });

  it('keeps the retirement history whole and its events in order of writing', () => {
    expect(requiredOf('retired')).toEqual(['byAge', 'byCount', 'trims']);
    expect(def('retired').additionalProperties, 'the retirement block closes').toBe(false);
    const trims = prop('retired', 'trims');
    expect(trims.type, 'the events are an array').toBe('array');
    expect(trims.$ref ?? trims.items?.$ref, 'each entry is a trim event').toBe('#/$defs/trimEvent');
    expect(trims.minItems, 'a store that has compacted nothing states an empty history').toBeUndefined();
    expect(requiredOf('trimEvent')).toEqual(['at', 'byAge', 'byCount', 'under']);
    expect(def('trimEvent').additionalProperties, 'a trim event closes').toBe(false);
  });

  it('publishes the two chain endpoints as lowercase digests of thirty-two bytes', () => {
    expect(requiredOf('chain'), 'both endpoints are required here').toEqual(['anchor', 'head']);
    expect(def('chain').additionalProperties, 'the chain block closes').toBe(false);
    for (const key of ['anchor', 'head']) {
      const node = prop('chain', key);
      expect(node.type, `chain.${key} is text`).toBe('string');
      expect(node.pattern, `chain.${key} is sixty-four lowercase hex characters`).toBe('^[0-9a-f]{64}$');
    }
    expect(requiredOf('root'), 'the manifest repeats the endpoints rather than deferring to a pack').toContain('chain');
    expect(descriptionOf('root'), 'and the file says so where a reader will meet it').toContain(
      'repeats the anchor and the head here',
    );
  });

  it('names the duty, its three labels, and the arithmetic beside them', () => {
    expect(requiredOf('duty')).toEqual(['article', 'requiredSeconds', 'heldSeconds', 'met']);
    expect(def('duty').additionalProperties, 'the duty block closes').toBe(false);
    expect(prop('duty', 'article').enum, 'the labels the shipped writer can name').toEqual(['19(1)', '19(2)', '26(6)']);
    expect(prop('duty', 'met').type, 'the comparison is a stated value a reader recomputes').toBe('boolean');
    expect(descriptionOf('duty')).not.toContain('compliance');
    expect(descriptionOf('root'), 'the artifact says it is not signed').toContain('this document is not signed');
    expect(descriptionOf('root'), 'and that nothing here writes it').toContain(
      'Nothing in this repository writes or reads this document today',
    );
  });

  it('bounds no article period and still refuses a value that is not a period', () => {
    const sixMonths = 15_897_600;
    expect(prop('duty', 'requiredSeconds').minimum, 'a stated period is a period').toBe(1);
    expect(def('duty').if, 'no conditional sits on the duty block').toBeUndefined();
    expect(def('duty').then, 'so no article carries an enforced floor').toBeUndefined();
    expect(
      validate(manifest({ duty: { article: '19(1)', requiredSeconds: sixMonths - 86_400, heldSeconds: 0, met: false } })),
      'a 19(1) period under six months is a deployment reading, not a malformed document',
    ).toBe(true);
    expect(
      validate(manifest({ duty: { article: '26(6)', requiredSeconds: sixMonths - 86_400, heldSeconds: 0, met: false } })),
      'and the routed articles were never bounded either',
    ).toBe(true);
    expect(
      validate(manifest({ duty: { article: '19(1)', requiredSeconds: 0, heldSeconds: 0, met: false } })),
      'zero seconds is not a period under any article',
    ).toBe(false);
  });

  it('refuses what the layout does not define, at every level it closes', () => {
    expect(validate(manifest()), 'the reference manifest validates').toBe(true);
    expect(validate(manifest({ window: 1 })), 'an unnamed top level member is a refusal').toBe(false);
    expect(validate(manifest({ retained: { from: 1, to: 2 } })), 'a window with no count is a refusal').toBe(false);
    expect(validate(manifest({ chain: { anchor: '00'.repeat(32) } })), 'a head of nothing is a refusal').toBe(false);
    expect(
      validate(manifest({ chain: { anchor: 'AB'.repeat(32), head: 'ab'.repeat(32) } })),
      'an uppercase digest is not the published spelling',
    ).toBe(false);
    expect(
      validate(manifest({ policy: { maxAgeSeconds: 100, keepEverything: true } })),
      'a configured bound cannot grow a private companion',
    ).toBe(false);
    expect(
      validate(
        manifest({
          retired: {
            byAge: 0,
            byCount: 0,
            trims: [{ at: 1, byAge: 0, byCount: 0, under: {}, seam: 'ab'.repeat(32) }],
          },
        }),
      ),
      'a trim event carries no seam of its own',
    ).toBe(false);
    expect(validate(manifest({ v: 2 })), 'a second version is a different document').toBe(false);
    expect(validate(manifest({ at: 1.5 })), 'an instant somebody reached for a fraction of is refused').toBe(false);
    expect(validate({ ...manifest(), duty: { article: '99(9)', requiredSeconds: 15_897_600, heldSeconds: 0, met: false } }), 'an unknown label is refused').toBe(
      false,
    );
  });
});
