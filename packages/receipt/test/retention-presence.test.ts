import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { Ajv2020, type ValidateFunction } from 'ajv/dist/2020.js';
import { ReceiptError } from '../src/errors.js';
import {
  RETENTION_CHAIN_MEMBERS,
  RETENTION_DUTY_MEMBERS,
  RETENTION_FILE_NAMES,
  RETENTION_FORMAT_VERSIONS,
  RETENTION_HELD_MEMBERS,
  RETENTION_FAMILY_MEMBERS,
  RETENTION_POLICY_MEMBERS,
  RETENTION_PRESENCE_MEMBERS,
  RETENTION_RETIRED_MEMBERS,
  RETENTION_TRIM_MEMBERS,
  RETENTION_UNDER_KINDS,
  RETENTION_UNDER_MEMBERS,
  RETENTION_V1_MEMBERS,
  RETENTION_V2_MEMBERS,
  RETENTION_WINDOW_MEMBERS,
  encodeRetentionDocument,
  parseRetentionDocument,
  retentionDocumentBytes,
  type RetentionManifest,
  type RetentionManifestV1,
  type RetentionManifestV2,
} from '../src/retention.js';

/**
 * Version two of the retention manifest, and the reader and writer that read and write both versions.
 *
 * This is the change that goes quietest when it is done wrong. A reader keyed on one version literal skips the
 * work for the next version rather than failing at it, and every gate in a repository stays green while it does:
 * the case written for `v: 1` passes, the case that would have named `v: 2` was never written, and a deployment
 * whose artifacts moved to the new layout is folded as though it stated nothing. So three things are held here
 * rather than assumed. The member lists the reader closes are compared with the member lists each published
 * schema requires, in both directions and in order, so widening one statement of the layout without the others
 * is a failure rather than a passing build. The version is asked of `RETENTION_FORMAT_VERSIONS`, the set, and the
 * set is compared with the constants the two schema files declare, so a third layout cannot arrive unread. And
 * the round trip runs at both versions, because a writer that emitted a caller's key order would hand two
 * deployments holding the same store state two digests, and an inventory seals one of them.
 *
 * What the reader refuses is the layout and the arithmetic between two stated members: a presence count that is
 * not the length of its own list, one digest named twice inside one family, `met` beside the two integers it
 * compares, `heldSeconds` beside the instant and the window it is measured from, a trim event stamped after its
 * own manifest, and the whole presence block beside a version one document. What it never refuses is a number
 * this estate would disagree with, which is the same line the version one layout draws and for the same reason.
 */

interface JsonSchema {
  $defs?: Record<string, JsonSchema>;
  $id?: unknown;
  $ref?: unknown;
  additionalProperties?: unknown;
  const?: unknown;
  description?: unknown;
  enum?: readonly unknown[];
  items?: JsonSchema;
  minItems?: unknown;
  minimum?: unknown;
  pattern?: unknown;
  properties?: Record<string, JsonSchema>;
  required?: readonly string[];
  type?: unknown;
}

const onePath = fileURLToPath(new URL('../schemas/retention-v1.schema.json', import.meta.url));
const twoPath = fileURLToPath(new URL('../schemas/retention-v2.schema.json', import.meta.url));
const one = JSON.parse(readFileSync(onePath, 'utf8')) as JsonSchema;
const two = JSON.parse(readFileSync(twoPath, 'utf8')) as JsonSchema;

function compile(node: JsonSchema): ValidateFunction<unknown> {
  return new Ajv2020({ strict: true }).compile(node as object);
}

const validateOne = compile(one);
const validateTwo = compile(two);

function member(node: JsonSchema, name: string, key: string): JsonSchema {
  const block = name === 'root' ? node : (node.$defs?.[name] ?? {});
  const found = block.properties?.[key];
  if (found === undefined) throw new Error(`${name}.${key} is not part of a published retention layout`);
  return found;
}

function required(node: JsonSchema, name: string): readonly string[] {
  const block = name === 'root' ? node : (node.$defs?.[name] ?? {});
  if (block.required === undefined) throw new Error(`${name} states no required list`);
  return block.required;
}

function closed(node: JsonSchema, name: string): unknown {
  return (name === 'root' ? node : (node.$defs?.[name] ?? {})).additionalProperties;
}

/** The code a call answered with, or the fact that it answered with none. */
function thrownCode(run: () => unknown): string {
  try {
    run();
  } catch (err) {
    return err instanceof ReceiptError ? err.code : `UNCODED ${String(err)}`;
  }
  return 'accepted';
}

/** The whole message a refusal carried, which is what separates two faults sharing one code. */
function refusal(run: () => unknown): string {
  try {
    run();
  } catch (err) {
    return err instanceof ReceiptError ? err.message : `UNCODED ${String(err)}`;
  }
  return 'accepted';
}

/** The bytes of a document written as text, which is how both layouts arrive. */
function textOf(source: string): Uint8Array {
  return new TextEncoder().encode(source);
}

/** One family of the appraisal context, in the shape the writer is asked for. */
function family(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    count: 2,
    held: [
      { sha256: 'ab'.repeat(32), under: { kind: 'root', value: 'cd'.repeat(32) } },
      { sha256: 'ef'.repeat(32), under: { kind: 'chain', value: '01'.repeat(32) } },
    ],
    ...overrides,
  };
}

/** The whole presence block, both families, with one family moved at a time. */
function both(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return { collateral: family(), validity: family(), ...overrides };
}

/** A version one manifest, whole under its own layout. */
function manifestOne(overrides: Record<string, unknown> = {}): Record<string, unknown> {
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
    chain: { anchor: '00'.repeat(32), head: 'ab'.repeat(32) },
    duty: { article: '19(1)', requiredSeconds: 15_897_600, heldSeconds: 10_000_000, met: false },
    ...overrides,
  };
}

/** A version two manifest: the seven members version one states, plus the observation. */
function manifestTwo(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return { ...manifestOne(), v: 2, presence: both(), ...overrides };
}

function asOne(document: Record<string, unknown>): RetentionManifestV1 {
  return document as unknown as RetentionManifestV1;
}

function asTwo(document: Record<string, unknown>): RetentionManifestV2 {
  return document as unknown as RetentionManifestV2;
}

/** The duty the reference document states, so a case can move one figure at a time. */
const REFERENCE_DUTY = { article: '19(1)', requiredSeconds: 15_897_600, heldSeconds: 10_000_000, met: false } as const;

/** The reference version two document with `at` stated twice, which is what a parser settles silently. */
function doubledAt(): string {
  const source = JSON.stringify(manifestTwo());
  const at = source.indexOf('"at":');
  return `${source.slice(0, at)}"at": 2, ${source.slice(at)}`;
}

/** One held document, so the cases that move a digest or a belief stay one line long. */
function held(sha256: string, kind: string, value: string): Record<string, unknown> {
  return { sha256, under: { kind, value } };
}

describe('retention-v2.schema.json published layout', () => {
  it('adds one member to the version one list and changes nothing else', () => {
    expect(two.$id, 'the version two identity carries the version two number').toBe(
      'https://ashaveri.com/schemas/retention-v2.json',
    );
    expect(member(two, 'root', 'v').const, 'exactly one version is defined by this file').toBe(2);
    expect(required(two, 'root'), 'the required members are version one seven plus the observation').toEqual([
      ...RETENTION_V1_MEMBERS,
      'presence',
    ]);
    expect(
      [...RETENTION_V1_MEMBERS, ...RETENTION_V2_MEMBERS.slice(RETENTION_V1_MEMBERS.length)],
      'the two reader-side lists differ by exactly the members version two adds',
    ).toEqual([...RETENTION_V2_MEMBERS]);
    expect(
      Object.keys(two.properties ?? {}).sort(),
      'no optional member hides beside the eight',
    ).toEqual([...RETENTION_V2_MEMBERS].sort());
    expect(closed(two, 'root'), 'the top level map stays closed').toBe(false);
    expect(required(two, 'root').length, 'and the block that makes this version is required, not optional').toBe(8);
  });

  it('states the seven inherited members as version one states them', () => {
    for (const key of RETENTION_V1_MEMBERS.filter((each) => each !== 'v')) {
      expect(member(two, 'root', key).$ref, `${key} is a reference the two layouts spell differently`).toBe(
        member(one, 'root', key).$ref,
      );
    }
    for (const name of ['policyState', 'window', 'retired', 'trimEvent', 'chain', 'duty']) {
      expect(
        JSON.stringify(two.$defs?.[name] ?? null),
        `${name} is a block the two versions spell differently, which adding one member does not license`,
      ).toBe(JSON.stringify(one.$defs?.[name] ?? null));
    }
    expect(
      String(member(two, 'root', 'at').description),
      'the observation is made at the instant the document already carries',
    ).toContain('presence');
  });

  it('requires the presence block and both families beside it', () => {
    expect(required(two, 'presence'), 'neither family is optional and the block names no third').toEqual([
      ...RETENTION_PRESENCE_MEMBERS,
    ]);
    expect(closed(two, 'presence'), 'the presence block closes').toBe(false);
    expect(member(two, 'presence', 'collateral').$ref, 'both families are one shape').toBe(
      member(two, 'presence', 'validity').$ref,
    );
    expect(required(two, 'presenceFamily'), 'a family states its count and its list').toEqual([
      ...RETENTION_FAMILY_MEMBERS,
    ]);
    expect(closed(two, 'presenceFamily'), 'the family closes').toBe(false);
    expect(member(two, 'presenceFamily', 'count').type, 'the count is a whole number').toBe('integer');
    expect(member(two, 'presenceFamily', 'count').minimum, 'a count of nothing is zero and not an absence').toBe(0);
    expect(member(two, 'presenceFamily', 'held').type, 'the documents are a list').toBe('array');
    expect(
      member(two, 'presenceFamily', 'held').minItems,
      'an empty list is the statement that nothing was held, so the list carries no floor',
    ).toBeUndefined();
    expect(member(two, 'presenceFamily', 'held').items?.$ref, 'each entry is a held document').toBe(
      '#/$defs/presenceHeld',
    );
  });

  it('names each held document and the value it was believed under', () => {
    expect(required(two, 'presenceHeld'), 'a digest with no value beside it is not a statement').toEqual([
      ...RETENTION_HELD_MEMBERS,
    ]);
    expect(closed(two, 'presenceHeld'), 'the held entry closes').toBe(false);
    expect(required(two, 'presenceUnder'), 'the belief is a label and a digest').toEqual([...RETENTION_UNDER_MEMBERS]);
    expect(closed(two, 'presenceUnder'), 'the belief closes').toBe(false);
    expect(
      member(two, 'presenceUnder', 'kind').enum,
      'a document is held under a root or a chain, and no third thing',
    ).toEqual([...RETENTION_UNDER_KINDS]);
    for (const [name, key] of [
      ['presenceHeld', 'sha256'],
      ['presenceUnder', 'value'],
    ] as const) {
      expect(member(two, name, key).pattern, `${name}.${key} is sixty-four lowercase hex characters`).toBe(
        '^[0-9a-f]{64}$',
      );
    }
    expect(member(two, 'root', 'presence').$ref, 'the block is a definition the map opens').toBe('#/$defs/presence');
  });

  it('accepts the shape and refuses what the layout does not define', () => {
    expect(validateTwo(manifestTwo()), 'the reference version two manifest validates').toBe(true);
    expect(
      validateTwo(manifestTwo({ presence: both({ collateral: family({ count: 5 }) }) })),
      'a count that is not the length of its list is the readers refusal, and no keyword this layout carries',
    ).toBe(true);
    expect(
      validateTwo({ ...manifestTwo(), presence: { collateral: family() } }),
      'a block naming one family is a refusal rather than a family that held nothing',
    ).toBe(false);
    expect(validateTwo(manifestTwo({ presence: both({ extra: 1 }) })), 'the presence block closes').toBe(false);
    expect(validateTwo(manifestTwo({ v: 1 })), 'a version one document is not this layout').toBe(false);
    expect(
      validateTwo(manifestTwo({ presence: both({ collateral: family({ held: [{ sha256: 'ab'.repeat(32) }] }) }) })),
      'a held document names what it was believed under',
    ).toBe(false);
    expect(
      validateTwo(
        manifestTwo({ presence: both({ collateral: family({ held: [held('AB'.repeat(32), 'root', 'cd'.repeat(32))] }) }) }),
      ),
      'an uppercase digest is not the published spelling',
    ).toBe(false);
    expect(
      validateTwo(
        manifestTwo({ presence: both({ collateral: family({ held: [held('ab'.repeat(32), 'pinned', 'cd'.repeat(32))] }) }) }),
      ),
      'a belief outside the two kinds is refused',
    ).toBe(false);
    expect(
      validateTwo(manifestTwo({ presence: both({ collateral: family({ count: -1 }) }) })),
      'a count is never negative',
    ).toBe(false);
    expect(validateTwo(manifestTwo({ presence: both({ extra: {} }) })), 'the block names no third family').toBe(false);
    expect(
      validateOne(manifestTwo()),
      'the presence block beside a version one document is a different layout entirely',
    ).toBe(false);
  });
});

describe('the two layouts, the reader and the writer are one answer', () => {
  it('gives each version the member list its reader closes over', () => {
    expect([...required(one, 'root')], 'the version one reader list and the version one schema are two answers').toEqual([
      ...RETENTION_V1_MEMBERS,
    ]);
    expect([...required(two, 'root')], 'the version two reader list and the version two schema are two answers').toEqual([
      ...RETENTION_V2_MEMBERS,
    ]);
    const blocks: readonly (readonly [string, JsonSchema, readonly string[]])[] = [
      ['policyState', one, RETENTION_POLICY_MEMBERS],
      ['window', one, RETENTION_WINDOW_MEMBERS],
      ['retired', one, RETENTION_RETIRED_MEMBERS],
      ['trimEvent', one, RETENTION_TRIM_MEMBERS],
      ['chain', one, RETENTION_CHAIN_MEMBERS],
      ['duty', one, RETENTION_DUTY_MEMBERS],
      ['presence', two, RETENTION_PRESENCE_MEMBERS],
      ['presenceFamily', two, RETENTION_FAMILY_MEMBERS],
      ['presenceHeld', two, RETENTION_HELD_MEMBERS],
      ['presenceUnder', two, RETENTION_UNDER_MEMBERS],
    ];
    for (const [name, node, listed] of blocks) {
      const wants = [...required(node, name)].sort();
      if (name === 'policyState') {
        // The two bounds are optional in both layouts and at both positions, which is the one place a retention
        // map leaves a member open on purpose, so the reader's list is wider than the required list by design.
        expect(wants, `${name} requires what its reader says is optional`).toEqual([]);
        continue;
      }
      expect([...listed].sort(), `${name} is a member list the schema of its own version does not require`).toEqual(
        wants,
      );
    }
  });

  it('asks the version of a set rather than of a literal, and files each version under its own name', () => {
    const declared = [one, two].map((node) => {
      const constant = member(node, 'root', 'v').const;
      if (typeof constant !== 'number') throw new Error('a published layout declares no version constant');
      return constant;
    });
    expect([...RETENTION_FORMAT_VERSIONS].sort(), 'the reader version set and the published layouts differ').toEqual(
      [...declared].sort(),
    );
    expect(RETENTION_FORMAT_VERSIONS.length, 'the set does not hold one entry per published layout').toBe(
      declared.length,
    );
    for (const [version, name] of Object.entries(RETENTION_FILE_NAMES)) {
      expect(name, `version ${version} is filed under a name that does not carry its version`).toBe(
        `retention-v${version}.json`,
      );
    }
    expect(thrownCode(() => parseRetentionDocument(textOf('{"v": 3}\n')))).toBe('RETENTION_UNSUPPORTED_VERSION');
    expect(thrownCode(() => parseRetentionDocument(textOf('{"v": "2"}\n')))).toBe('RETENTION_BAD_DOCUMENT');
    expect(thrownCode(() => parseRetentionDocument(textOf('{"v": 2}\n')))).toBe('RETENTION_BAD_DOCUMENT');
    expect(thrownCode(() => parseRetentionDocument(textOf('{"v": 1}\n')))).toBe('RETENTION_BAD_DOCUMENT');
  });

  it('reads what it writes, at both versions, in the order the layout declares', () => {
    const oneBytes = encodeRetentionDocument(asOne(manifestOne()));
    expect(Object.keys(JSON.parse(new TextDecoder().decode(oneBytes)) as Record<string, unknown>)).toEqual([
      ...RETENTION_V1_MEMBERS,
    ]);
    expect(parseRetentionDocument(oneBytes).v).toBe(1);
    expect('presence' in parseRetentionDocument(oneBytes), 'a version one document states no observation').toBe(false);

    const twoBytes = retentionDocumentBytes(asTwo(manifestTwo()));
    expect(Object.keys(JSON.parse(new TextDecoder().decode(twoBytes)) as Record<string, unknown>)).toEqual([
      ...RETENTION_V2_MEMBERS,
    ]);
    const written = new TextDecoder().decode(twoBytes);
    expect(written).toBe(`${JSON.stringify(JSON.parse(written), null, 2)}\n`);
    const read = parseRetentionDocument(twoBytes);
    expect(read.v).toBe(2);
    if (read.v !== 2) throw new Error('the version two round trip did not read a version two document');
    expect(read.presence.collateral.held[0]?.under.kind).toBe('root');
    expect(read.presence.collateral.count).toBe(2);
    expect(read.presence.validity.held[1]?.sha256).toBe('ef'.repeat(32));
    expect(
      new TextDecoder().decode(encodeRetentionDocument(read)),
      'a document read back writes the bytes it arrived as',
    ).toBe(written);

    const optionalOnly = new TextDecoder().decode(
      encodeRetentionDocument(asOne({ ...manifestOne(), policy: { maxAgeSeconds: 10 } })),
    );
    const parsed = JSON.parse(optionalOnly) as { policy: Record<string, unknown> };
    expect(Object.keys(parsed.policy), 'an absent bound is left out rather than written as null').toEqual([
      'maxAgeSeconds',
    ]);
    expect(optionalOnly, 'and a null never stands in for the absence a layout reads as no bound').not.toContain('null');
  });

  it('refuses the arithmetic between members that no keyword carries', () => {
    expect(
      thrownCode(() =>
        parseRetentionDocument(
          encodeRetentionDocument(asTwo(manifestTwo({ presence: both({ collateral: family({ count: 3 }) }) }))),
        ),
      ),
      'a family whose count is not the length of its list is a document disagreeing with itself',
    ).toBe('RETENTION_BAD_DOCUMENT');
    expect(
      thrownCode(() =>
        parseRetentionDocument(
          encodeRetentionDocument(
            asTwo(
              manifestTwo({
                presence: both({
                  collateral: family({
                    held: [held('ab'.repeat(32), 'root', 'cd'.repeat(32)), held('ab'.repeat(32), 'chain', '01'.repeat(32))],
                  }),
                }),
              }),
            ),
          ),
        ),
      ),
      'one digest named twice inside one family is refused rather than folded twice',
    ).toBe('RETENTION_BAD_DOCUMENT');
    expect(
      thrownCode(() =>
        parseRetentionDocument(encodeRetentionDocument(asTwo(manifestTwo({ duty: { ...REFERENCE_DUTY, met: true } })))),
      ),
      'met beside the two integers it compares is arithmetic a reader recomputes',
    ).toBe('RETENTION_BAD_DOCUMENT');
    expect(
      thrownCode(() =>
        parseRetentionDocument(encodeRetentionDocument(asTwo(manifestTwo({ retained: { from: 1, to: 1, count: 1 } })))),
      ),
      'heldSeconds beside the instant and the window it is measured from is arithmetic too',
    ).toBe('RETENTION_BAD_DOCUMENT');
    expect(
      thrownCode(() =>
        parseRetentionDocument(
          encodeRetentionDocument(
            asTwo(manifestTwo({ retired: { byAge: 0, byCount: 0, trims: [{ at: 2_000_000_000, byAge: 0, byCount: 0, under: {} }] } })),
          ),
        ),
      ),
      'a trim stamped after the manifest carrying it is a contradiction inside one document',
    ).toBe('RETENTION_BAD_DOCUMENT');
    expect(
      thrownCode(() => parseRetentionDocument(textOf(`${JSON.stringify(manifestOne({ presence: both() }))}\n`))),
      'the presence block beside a version one document is refused, not dropped',
    ).toBe('RETENTION_BAD_DOCUMENT');
    expect(
      thrownCode(() => parseRetentionDocument(textOf(`${JSON.stringify({ ...manifestTwo(), at: 1_800_000_000.5 })}\n`))),
      'a float wearing an instant is refused while the characters still distinguish it',
    ).toBe('RETENTION_BAD_DOCUMENT');
    expect(
      thrownCode(() => parseRetentionDocument(textOf(doubledAt()))),
      'a member named twice settles into one value in a parser and two values in the hashed bytes',
    ).toBe('RETENTION_BAD_DOCUMENT');
    expect(
      parseRetentionDocument(
        encodeRetentionDocument(
          asTwo(
            manifestTwo({
              retained: { from: 0, to: 0, count: 0 },
              duty: { article: '19(1)', requiredSeconds: 1, heldSeconds: 0, met: false },
              presence: both({ collateral: family({ count: 0, held: [] }), validity: family({ count: 0, held: [] }) }),
            }),
          ),
        ),
      ),
      'an empty store and an empty family are statements rather than absences',
    ).toMatchObject({ presence: { collateral: { count: 0 }, validity: { count: 0 } } });
    expect(
      parseRetentionDocument(
        encodeRetentionDocument(asOne(manifestOne({ duty: { article: '26(6)', requiredSeconds: 1, heldSeconds: 10_000_000, met: true } }))),
      ),
      'a period this estate would not have chosen is a whole document',
    ).toBeDefined();
  });

  it('names which fault it reached rather than letting one code carry three', () => {
    const head = 'retention manifest does not match the layout its declared version defines: '.length;
    const messages = [
      refusal(() =>
        parseRetentionDocument(
          encodeRetentionDocument(asTwo(manifestTwo({ presence: both({ collateral: family({ count: 5 }) }) }))),
        ),
      ),
      refusal(() =>
        parseRetentionDocument(
          encodeRetentionDocument(
            asTwo(
              manifestTwo({
                presence: both({
                  validity: family({
                    held: [held('ab'.repeat(32), 'root', 'cd'.repeat(32)), held('ab'.repeat(32), 'chain', '01'.repeat(32))],
                  }),
                }),
              }),
            ),
          ),
        ),
      ),
      refusal(() => parseRetentionDocument(encodeRetentionDocument(asTwo(manifestTwo({ duty: { ...REFERENCE_DUTY, met: true } }))))),
      refusal(() => parseRetentionDocument(encodeRetentionDocument(asTwo(manifestTwo({ retained: { from: 1, to: 1, count: 1 } }))))),
      refusal(() =>
        parseRetentionDocument(
          encodeRetentionDocument(
            asTwo(manifestTwo({ retired: { byAge: 0, byCount: 0, trims: [{ at: 2_000_000_000, byAge: 0, byCount: 0, under: {} }] } })),
          ),
        ),
      ),
      refusal(() => parseRetentionDocument(textOf(`${JSON.stringify(manifestOne({ presence: both() }))}\n`))),
      refusal(() => parseRetentionDocument(textOf('{"v": 9}\n'))),
    ];
    const readable: string[] = [];
    for (const [index, message] of messages.entries()) {
      expect(message, `case ${String(index)} was accepted and so names no fault`).not.toBe('accepted');
      readable.push(message.slice(head, head + 90));
    }
    expect(new Set(readable).size, 'two refusals of one code read as one sentence to a reader').toBe(readable.length);
  });

  it('leaves a document of either version unreadable only by a refusal, never by silence', () => {
    const manifests: readonly RetentionManifest[] = [asOne(manifestOne()), asTwo(manifestTwo())];
    expect(manifests.length, 'the round trip covers fewer layouts than the version set names').toBe(
      RETENTION_FORMAT_VERSIONS.length,
    );
    for (const document of manifests) {
      const bytes = retentionDocumentBytes(document);
      expect(
        thrownCode(() => parseRetentionDocument(bytes.slice(0, bytes.length - 12))),
        `a version ${String(document.v)} document cut short was not refused`,
      ).toBe('RETENTION_BAD_DOCUMENT');
      expect(
        thrownCode(() => parseRetentionDocument(new Uint8Array([0xff, 0xfe, 0x00]))),
        'bytes that are not text were not refused',
      ).toBe('RETENTION_BAD_DOCUMENT');
    }
  });
});
