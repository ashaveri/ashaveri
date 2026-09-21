import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { Ajv2020, type ValidateFunction } from 'ajv/dist/2020.js';
import {
  MEASUREMENT_BYTES,
  receiptToJson,
  toHex,
  type Marking,
  type Measurement,
  type ReceiptPayload,
  type ReceiptPayloadV1,
  type ReceiptPayloadV2,
} from '../src/index.js';
import * as receiptParser from '../src/receipt.js';

const schemaPath = fileURLToPath(new URL('../schemas/receipt-v1.schema.json', import.meta.url));
const cddlPath = fileURLToPath(new URL('../receipt.cddl', import.meta.url));
const specPath = fileURLToPath(new URL('../../../docs/receipt-spec.md', import.meta.url));
const schema = JSON.parse(readFileSync(schemaPath, 'utf8')) as object;

/** An object schema of the kind this file nests under `properties`. */
interface ObjectSchema {
  additionalProperties?: unknown;
  properties?: Record<string, unknown>;
}

/**
 * The parts of this schema the agreement test below reads: one branch per payload version, the
 * descriptions that say which members each of them names, and the four definitions nested below the
 * payload map.
 */
interface SchemaShape {
  description: string;
  $defs: {
    payloadFields: { properties: Record<string, ObjectSchema> };
    payloadV1: { properties: Record<string, unknown>; description: string };
    payloadV2: { properties: Record<string, ObjectSchema>; description: string };
  };
}

const shape = schema as SchemaShape;

/** The nested members a document can carry, which is `mk` on v2 and the other three on either. */
const NESTED_KEYS = ['meas', 'att', 'tok', 'mk'] as const;
type NestedKey = (typeof NESTED_KEYS)[number];

/**
 * The definition one nested member points at, wherever this file happens to hold it. `mk` is a v2
 * member, so its definition sits on that branch; the other three are shared and sit under
 * `payloadFields`, which both branches reach through their `allOf`.
 */
function nestedDefinition(key: NestedKey): ObjectSchema {
  return key === 'mk' ? shape.$defs.payloadV2.properties.mk! : shape.$defs.payloadFields.properties[key]!;
}

/**
 * The text of one CDDL rule, from its opening brace to the first line that closes it. A rule the
 * reader could not find has to fail the run rather than hand back an empty string, because an empty
 * block reads as a format that stopped declaring any members.
 */
function cddlRule(cddl: string, rule: string): string {
  const start = cddl.indexOf(`${rule} = {`);
  if (start < 0) throw new Error(`${rule} is not declared in ${cddlPath}`);
  const end = cddl.indexOf('\n}', start);
  if (end < 0) throw new Error(`${rule} in ${cddlPath} never closes`);
  return cddl.slice(start, end);
}

/**
 * The members one CDDL block declares, in the order it declares them: comments stripped, then every
 * `name:` read off the commas that separate the members. The order is not decoration: v2's block
 * puts `mk` after the thirteen, and the twin and the parser both claim that list as theirs.
 *
 * A block that names nothing by label comes back empty rather than throwing, because the reader of
 * every map in the file has to be able to tell `Ashaveri-Protected-Header`, whose keys are the COSE
 * registry's integers, apart from a map that has lost its members.
 */
function labeledMembers(block: string): string[] {
  const members: string[] = [];
  for (const line of block.split('\n').slice(1)) {
    for (const piece of line.split(';')[0]!.split(',')) {
      const found = /^\s*([a-z][a-z0-9_]*)\s*:/u.exec(piece);
      if (found) members.push(found[1]!);
    }
  }
  return members;
}

function cddlMembers(cddl: string, rule: string): string[] {
  const members = labeledMembers(cddlRule(cddl, rule));
  if (members.length === 0) throw new Error(`the ${rule} block declares no members`);
  return members;
}

/**
 * The names of every rule the file opens as a map: `Name = {` at the start of a line. Read off the
 * text so that a map added to the format later is in this set the day it lands, rather than a name
 * somebody has to remember to write down a second time.
 */
function cddlMapRuleNames(cddl: string): string[] {
  const names: string[] = [];
  for (const line of cddl.split('\n')) {
    const found = /^([A-Za-z][A-Za-z0-9_-]*) = \{/u.exec(line);
    if (found) names.push(found[1]!);
  }
  if (names.length === 0) throw new Error(`no map rule is declared in ${cddlPath}`);
  return names;
}

/**
 * The blocks of a rule written as a map, or a choice between maps. `Measurement` is two blocks that
 * name the same members at different widths, and the second one is invisible to `cddlRule`, which
 * stops at the first closing brace: a member arriving in one arm alone would be a map no list stands
 * behind. A block that never closes throws rather than reading as an empty one.
 */
function cddlRuleArms(cddl: string, rule: string): string[] {
  const start = cddl.indexOf(`${rule} = {`);
  if (start < 0) throw new Error(`${rule} is not declared in ${cddlPath}`);
  const arms: string[] = [];
  let current: string[] = [];
  for (const line of cddl.slice(start).split('\n')) {
    if (line === '} / {') {
      arms.push(current.join('\n'));
      current = [line];
      continue;
    }
    if (line === '}') {
      arms.push(current.join('\n'));
      return arms;
    }
    current.push(line);
  }
  throw new Error(`${rule} in ${cddlPath} never closes`);
}

/** A value a test cannot go on without: the name rides along, because a bare `!` hides which lookup
 * failed. */
function required<T>(value: T | undefined, detail: string): T {
  if (value === undefined) throw new Error(detail);
  return value;
}

/**
 * One string for a whole document's worth of line breaks: a sentence in these files spans the lines it
 * wrapped at, so a check that pins a sentence has to read the prose rather than the wrapping. An edit
 * that reflows a paragraph then leaves the assertion alone, and an edit that rewords it does not.
 */
function flat(text: string): string {
  return text.replace(/\s+/gu, ' ').trim();
}

/**
 * The CDDL's full-line comments as prose. A trailing comment sits next to a type expression and
 * belongs to that member; these are the file's paragraphs, and they are what a stranger reading the
 * format definition actually reads.
 */
function cddlProse(cddl: string): string {
  return flat(cddl.split('\n').filter((line) => line.startsWith(';')).map((line) => line.slice(1)).join('\n'));
}

/**
 * `where` says `phrase` exactly once: zero is a document that stopped stating the rule, two is one
 * that started stating it in two voices. The name and the phrase ride along in the failure because a
 * bare length assertion cannot say which of the four texts went quiet.
 */
function saidOnce(where: string, text: string, phrase: string): void {
  const hits = text.split(phrase).length - 1;
  expect(hits, `${where} says "${phrase}" ${hits} times, not once`).toBe(1);
}

/**
 * The body of one `## ` section of a markdown document, from its heading to the next `## ` heading: a
 * `### ` subsection belongs to its section and stays inside the body, which is what the sentence
 * count below wants — a subsection repeating section 6's rule is the second voice the check is there
 * to catch.
 */
function sectionBody(markdown: string, heading: string): string {
  const lines = markdown.split('\n');
  const start = lines.indexOf(heading);
  if (start < 0) throw new Error(`${heading} is not a heading in ${specPath}`);
  const rest = lines.slice(start + 1);
  const end = rest.findIndex((line) => line.startsWith('## '));
  return (end < 0 ? rest : rest.slice(0, end)).join('\n');
}

/**
 * Compiles a receipt schema with Ajv's strict mode on, so a keyword this schema does not
 * define fails at compile time instead of being ignored.
 *
 * `uri` is given a validator that accepts everything. The schema's only format is a label on
 * `att.url`, and it is the patterns in `$defs` and under `meas` that carry the constraints a
 * reimplementer has to match, not the formats: nothing here reads the URL's shape, and a real
 * uri validator would add a rule the signed payload does not commit to.
 *
 * `strictTypes` is at its default, so a subschema that is looser than the `$ref` it narrows is a
 * compile error rather than a log line: the two `then` branches at
 * `$defs.payloadFields/properties/meas/allOf/0` and `/1` each declare `type: "string"` next to their
 * `pattern`.
 */
function compile(s: object): ValidateFunction<unknown> {
  const acceptsAnything = () => true;
  const ajv = new Ajv2020({ strict: true, formats: { uri: acceptsAnything } });
  return ajv.compile(s);
}

const validate = compile(schema);

const DIGEST = new Uint8Array(32).fill(2);

/**
 * The projection the schema describes, with only the measurement varying per case. The signature and
 * kid are placeholders here: this suite checks the schema against the same kind-to-width table the
 * codec enforces, and the schema only constrains their shape.
 */
function v1(tee: string, m: Uint8Array): ReceiptPayloadV1 {
  return {
    v: 1,
    iss: 'ashaveri-schema',
    ins: 'cvm-schema-1',
    iat: 1_772_000_000,
    nce: new Uint8Array(16).fill(1),
    req: DIGEST,
    res: DIGEST,
    mdl: 'mock-model-1',
    wts: DIGEST,
    meas: { tee, m } as Measurement,
    att: { d: DIGEST, ts: 1_772_000_000 - 60, url: 'https://inference.ashaveri.com/v1/attestation' },
    epk: 0,
    tok: { p: 1, c: 1 },
  };
}

/** v2 is v1's fields and one member, so the marked document is the same payload with `mk` on it. */
function v2(mk: Marking): ReceiptPayloadV2 {
  return { ...v1('software', new Uint8Array(32).fill(4)), v: 2, mk };
}

function twin(payload: ReceiptPayload): unknown {
  return receiptToJson(payload, new Uint8Array(64).fill(3), new Uint8Array(32).fill(4));
}

/**
 * A twin rewritten through its JSON text, because the negative cases are about a member the
 * projection does not produce: the codec will not hand out a v2 payload with no `mk`, and that is
 * exactly the document a schema has to refuse.
 */
function rewritten(payload: ReceiptPayload, edit: (members: Record<string, unknown>) => void): unknown {
  const document = JSON.parse(JSON.stringify(twin(payload))) as { payload: Record<string, unknown> };
  edit(document.payload);
  return document;
}

/**
 * The same rewrite one level down, because the maps nested inside the payload are the ones this
 * schema now closes there too. The document handed to `validate` is one the projection itself
 * produced, with the edit applied inside one of its maps and nowhere else.
 */
function rewrittenNested(
  payload: ReceiptPayload,
  owner: NestedKey,
  edit: (members: Record<string, unknown>) => void,
): unknown {
  const document = JSON.parse(JSON.stringify(twin(payload))) as {
    payload: Record<string, Record<string, unknown>>;
  };
  edit(document.payload[owner]!);
  return document;
}

function outcome(value: unknown): string | null {
  return validate(value) ? null : JSON.stringify(validate.errors);
}

describe('the receipt JSON Schema', () => {
  it('accepts every kind at the width the codec requires', () => {
    for (const [tee, bytes] of Object.entries(MEASUREMENT_BYTES)) {
      expect(outcome(twin(v1(tee, new Uint8Array(bytes).fill(1)))), `tee ${tee} with ${bytes} bytes`).toBeNull();
    }
  });

  it("rejects a measurement at another kind's width", () => {
    for (const [tee, bytes] of Object.entries(MEASUREMENT_BYTES)) {
      const wrong = bytes === 32 ? 48 : 32;
      expect(outcome(twin(v1(tee, new Uint8Array(wrong).fill(1)))), `tee ${tee} with ${wrong} bytes`).not.toBeNull();
    }
  });

  it('rejects an unknown environment kind', () => {
    expect(outcome(twin(v1('sgx', new Uint8Array(48).fill(1))))).not.toBeNull();
  });

  it('accepts a marked payload and requires its mk', () => {
    expect(outcome(twin(v2({ sch: 'provenance-v1', d: DIGEST })))).toBeNull();
    expect(outcome(rewritten(v2({ sch: 'provenance-v1', d: DIGEST }), (members) => { delete members.mk; }))).not.toBeNull();
  });

  it('holds a v1 payload to its thirteen members and a v2 payload to its fourteen', () => {
    // Both halves of the discriminant, now that the branches are closed: a v1 document rewritten to
    // `v: 2` is missing a member it now needs, and a v1 document that keeps its thirteen and adds
    // the marking attestation is a document no version defines. The twin refuses both, which is what
    // makes "v: 1 carries no mk" something the schema states rather than something a reader hopes.
    expect(outcome(rewritten(v1('software', DIGEST), (members) => { members.v = 2; }))).not.toBeNull();
    expect(outcome(rewritten(v1('software', DIGEST), (members) => { members.mk = { sch: 'none', d: toHex(DIGEST) }; }))).not.toBeNull();
    expect(outcome(rewritten(v2({ sch: 'none', d: DIGEST }), (members) => { members.not_a_member = 'x'; }))).not.toBeNull();
  });

  it('refuses an undefined member inside each nested map, where the keyword is the only thing that does', () => {
    // Every case is a pair. The unedited document validates and the edited one does not, and the only
    // difference is a member no map names, so a refusal here cannot have arrived for any other
    // reason. Delete a nested `additionalProperties` and the second half of each pair goes red; the
    // first half keeps green, which is the point: the case tests the keyword, not the document.
    const cases: Array<[ReceiptPayload, NestedKey]> = [
      [v2({ sch: 'none', d: DIGEST }), 'meas'],
      [v2({ sch: 'none', d: DIGEST }), 'att'],
      [v2({ sch: 'none', d: DIGEST }), 'tok'],
      [v2({ sch: 'none', d: DIGEST }), 'mk'],
      // `meas`, `att` and `tok` are declared once and shared by both branches through their `allOf`,
      // so the same definition is asked for on the branch that never sees `mk`.
      [v1('software', DIGEST), 'tok'],
    ];
    for (const [payload, key] of cases) {
      expect(outcome(twin(payload)), `${key} on a document that names only what the format does`).toBeNull();
      expect(
        outcome(rewrittenNested(payload, key, (members) => { members.surprise = 'x'; })),
        `${key} carrying a member the format does not name`,
      ).not.toBeNull();
    }
  });

  it('closes every map the format defines, in the twin, the CDDL and the spec alike', () => {
    // The rule is one rule, written down four times: the parser, this schema, the normative CDDL
    // and the specification. A reader porting the format reads the last two, so a document that
    // stopped saying it would leave the port to guess, which is how an open map comes back.
    const cddl = readFileSync(cddlPath, 'utf8');
    const membersPerVersion: Record<1 | 2, string[]> = {
      1: cddlMembers(cddl, 'Ashaveri-Receipt-Payload-v1'),
      2: cddlMembers(cddl, 'Ashaveri-Receipt-Payload-v2'),
    };
    expect(membersPerVersion[1].length).toBe(13);
    expect(membersPerVersion[2]).toEqual([...membersPerVersion[1], 'mk']);
    const twinMembers = (branch: 'payloadV1' | 'payloadV2'): string[] => [
      ...Object.keys(shape.$defs.payloadFields.properties),
      ...Object.keys(shape.$defs[branch].properties),
    ];
    expect(twinMembers('payloadV1').sort()).toEqual([...membersPerVersion[1]].sort());
    expect(twinMembers('payloadV2').sort()).toEqual([...membersPerVersion[2]].sort());

    // The CDDL's closure is the absence of `...` in the two payload blocks, said out loud so a port
    // need not decide whether the absence was a rule or an oversight. The pin is the sentence rather
    // than the word "closed": a comment saying the opposite still contains that word.
    const prose = cddlProse(cddl);
    saidOnce('the CDDL payload note', prose, 'A payload map is closed at both versions');
    saidOnce('the CDDL payload note', prose, 'the absence of `...` in the two blocks below is that rule rather than an oversight');
    expect(cddlRule(cddl, 'Ashaveri-Receipt-Payload-v1').includes('...')).toBe(false);
    expect(cddlRule(cddl, 'Ashaveri-Receipt-Payload-v2').includes('...')).toBe(false);

    // One level down the same two things have to hold, and neither is shown by a type expression.
    // Each block carries no `...`, which is the format saying it closes, and the twin declares the
    // same member names the block does: a twin that named a member the block does not would validate
    // a document the format refuses, and one that dropped a name would refuse a document the format
    // admits. Either drift is invisible to a case built out of the twin's own members, which is why
    // the list below is read out of the CDDL rather than written a second time here.
    const blockPerKey: Record<NestedKey, string> = {
      meas: 'Measurement',
      att: 'EvidenceRef',
      tok: 'TokenMetering',
      mk: 'Marking',
    };
    for (const key of NESTED_KEYS) {
      expect(cddlRule(cddl, blockPerKey[key]).includes('...'), `${blockPerKey[key]} closes`).toBe(false);
      expect(
        Object.keys(nestedDefinition(key).properties ?? {}),
        `the twin's ${key} members`,
      ).toEqual(cddlMembers(cddl, blockPerKey[key]));
      // That the closing keyword sits there is the assertion; that it binds is the case earlier in
      // this file, which hands `validate` the same document with one unnamed member added. A keyword
      // this schema did not define would have failed to compile at all, which is the other guard.
      expect(nestedDefinition(key).additionalProperties, `${key} names its members as the whole of it`).toBe(false);
    }

    // The note that used to record the divergence now records the rule reaching there, and the
    // sentence that said it stopped has to stay gone: a comment restored would put this file back
    // into reading as a format with two levels of strictness.
    saidOnce('the CDDL closure note', prose, "That rule is the format's, not one map's");
    saidOnce('the CDDL closure note', prose, 'below carry no `...` either');
    saidOnce('the CDDL closure note', prose, 'The parser and the JSON twin refuse it at that level');
    saidOnce('the CDDL closure note', prose, 'every map this file defines closes');
    for (const block of ['Marking', 'Measurement', 'EvidenceRef', 'TokenMetering']) {
      expect(prose.includes(`\`${block}\``), `the CDDL names ${block}`).toBe(true);
    }
    expect(prose).not.toMatch(/\bare open\b/u);
    expect(prose).not.toContain('stops at the payload map');

    // And the specification states the refusal once in the field table and once in section 6, which
    // is the pair a reader of the prose gets. Zero occurrences means the sentence was edited away;
    // more than the one each means the document started saying the same thing in two voices.
    const spec = readFileSync(specPath, 'utf8');
    const versionRow = spec.split('\n').filter((line) => line.startsWith('| `v` | int |'));
    expect(versionRow).toHaveLength(1);
    expect(versionRow[0]!.split(' does not define')).toHaveLength(2);
    const section = sectionBody(spec, '## 6. Versioning');
    expect(section.split('does not define')).toHaveLength(2);

    // Section 6 says the same thing the CDDL note does, named by the four keys a reader of the field
    // table has, and pointing at the file that decides it instead of at itself.
    const specProse = flat(section);
    saidOnce('section 6', specProse, "The rule is not the payload map's alone");
    saidOnce('section 6', specProse, 'the four maps nested inside it, `meas`, `att`, `tok` and `mk`');
    saidOnce('section 6', specProse, 'carry no `...` in the normative CDDL either');
    saidOnce('section 6', specProse, 'refuses an undefined member of any of them');
    expect(specProse).not.toMatch(/\bare open\b/u);
    expect(specProse).not.toContain('stops at the payload map');

    // The twin says the same thing. The root description is the one place that speaks below the
    // payload map, and it names all four nested keys and says which keyword closes each level; the
    // two branch descriptions close their own map and name nothing inside it, so a reader never takes
    // a claim about one level from a sentence about another.
    saidOnce('the twin', shape.description, 'Each branch is closed');
    saidOnce('the twin', shape.description, 'Closure is not one level');
    saidOnce('the twin', shape.description, 'the four nested inside it');
    saidOnce('the twin', shape.description, 'the nested definitions through `additionalProperties`');
    for (const key of NESTED_KEYS) {
      expect(shape.description.includes(`\`${key}\``), `the twin names ${key}`).toBe(true);
    }
    for (const branch of ['payloadV1', 'payloadV2'] as const) {
      const doc = shape.$defs[branch].description;
      saidOnce(`the twin's ${branch} description`, doc, 'The map is closed');
      for (const key of NESTED_KEYS) {
        expect(doc.includes(`\`${key}\``), `the twin's ${branch} description stops at its own map`).toBe(false);
      }
    }
  });

  it('describes the mark as a label and a 32-byte digest', () => {
    const missingLabel = (members: Record<string, unknown>): void => {
      members.mk = { d: toHex(DIGEST) };
    };
    const wrongWidth = (members: Record<string, unknown>): void => {
      members.mk = { sch: 'provenance-v1', d: toHex(new Uint8Array(31).fill(1)) };
    };
    expect(outcome(rewritten(v2({ sch: 'none', d: DIGEST }), missingLabel))).not.toBeNull();
    expect(outcome(rewritten(v2({ sch: 'none', d: DIGEST }), wrongWidth))).not.toBeNull();
  });

  it('refuses to compile a keyword this schema does not define', () => {
    // The same text with `strict: false` compiled and silently dropped the keyword, so this
    // is the case that shows strict mode is on.
    const misspelled = JSON.parse(readFileSync(schemaPath, 'utf8')) as {
      $defs: { hex16: Record<string, unknown> };
    };
    misspelled.$defs.hex16.patterntypo = misspelled.$defs.hex16.pattern;
    delete misspelled.$defs.hex16.pattern;
    expect(() => compile(misspelled)).toThrow(/unknown keyword/);
    expect(() => compile(JSON.parse(readFileSync(schemaPath, 'utf8')) as object)).not.toThrow();
  });
});

/**
 * The parser's member lists, read off the module that enforces them rather than written out again
 * here: every export named `..._MEMBERS` is a list the closure walk checks. A list added to
 * `receipt.ts` therefore arrives in this set on its own, and one that answers for no map below fails
 * rather than going unread.
 */
function parserMemberLists(): Map<string, readonly string[]> {
  const lists = new Map<string, readonly string[]>();
  for (const [name, value] of Object.entries(receiptParser)) {
    if (!name.endsWith('_MEMBERS')) continue;
    if (!Array.isArray(value) || value.some((member) => typeof member !== 'string')) {
      throw new Error(`${name} is exported from src/receipt.ts but is not a list of member names`);
    }
    lists.set(name, value as readonly string[]);
  }
  if (lists.size === 0) throw new Error('src/receipt.ts exports no member list to bind to the CDDL');
  return lists;
}

/** One map the CDDL defines, the list that stands behind it, and what the rule adds to that list. */
interface ListBinding {
  readonly map: string;
  readonly list: string;
  readonly adds?: readonly string[];
}

/**
 * Which list stands behind which map. There is one `adds` in this format: v2 is v1's members plus
 * `mk`, so both payload blocks bind to the one shared list and the version pair stays a row rather
 * than becoming a second copy of every assertion below. `MARKING_MEMBERS` stands behind the map `mk`'s
 * value is, which is why it appears once and not inside the payload's list.
 */
const LIST_FOR_MAP: readonly ListBinding[] = [
  { map: 'Ashaveri-Receipt-Payload-v1', list: 'SHARED_MEMBERS' },
  { map: 'Ashaveri-Receipt-Payload-v2', list: 'SHARED_MEMBERS', adds: ['mk'] },
  { map: 'Marking', list: 'MARKING_MEMBERS' },
  { map: 'Measurement', list: 'MEASUREMENT_MEMBERS' },
  { map: 'EvidenceRef', list: 'EVIDENCE_REF_MEMBERS' },
  { map: 'TokenMetering', list: 'TOKEN_METERING_MEMBERS' },
];

describe("the parser's member lists", () => {
  it('answer for every map the CDDL defines, and for no map it does not define', () => {
    const cddl = readFileSync(cddlPath, 'utf8');
    const lists = parserMemberLists();

    // The format's side of the pairing, read out of the file: the maps that name their members by
    // label, which is the kind of map the closure walk speaks of. `Ashaveri-Protected-Header` is a
    // map and is not one of these, because its keys are the COSE registry's integers and a document
    // whose key is not a label is refused for not being one rather than matched against a list.
    const maps = new Map<string, string[]>();
    for (const rule of cddlMapRuleNames(cddl)) {
      const arms = cddlRuleArms(cddl, rule).map((arm) => labeledMembers(arm));
      const first = required(arms[0], `${rule} declares no block`);
      if (first.length === 0) continue;
      // A rule written as a choice between maps is one list's job only while the arms name the same
      // members. `Measurement` differs in the width `m` carries, which is a value rule and not a
      // member rule; a name that arrived in one arm alone would be a second map standing unbound.
      for (const [index, arm] of arms.entries()) {
        expect(arm, `${rule} arm ${index + 1} of ${arms.length} names members its first arm does not`).toEqual(first);
      }
      maps.set(rule, first);
    }

    // Both directions of the pairing, which is the point of deriving the format's side instead of
    // typing it. A map with no list behind it is a parser that refuses a member the format defines,
    // and a list bound to a rule nothing defines is a check that can rot where nobody looks; neither
    // is visible in the other's failure, and a sixth map added next month lands in `maps` by itself.
    const boundMaps = LIST_FOR_MAP.map((binding) => binding.map);
    expect(new Set(boundMaps).size, 'one map is bound to a parser list twice').toBe(boundMaps.length);
    expect([...maps.keys()].sort(), 'maps the CDDL defines with no parser list bound to them').toEqual([...boundMaps].sort());
    const boundLists = [...new Set(LIST_FOR_MAP.map((binding) => binding.list))];
    expect([...lists.keys()].sort(), 'parser lists bound to no map the CDDL defines').toEqual([...boundLists].sort());

    for (const binding of LIST_FOR_MAP) {
      const list = required(lists.get(binding.list), `${binding.list} is not an export of src/receipt.ts`);
      const defined = cddlMembers(cddl, binding.map);
      const enforced = [...list, ...(binding.adds ?? [])];
      // A name the format defines and the list drops is refused as an undefined member by the parser
      // that reads it; a name the list carries and the format does not define buys a document
      // acceptance no version of the format grants. Either one alone passes a subset check pointed at
      // random, so the two diffs are named separately.
      const refused = defined.filter((member) => !enforced.includes(member));
      expect(refused, `${binding.list} does not enforce ${binding.map}'s member(s): ${refused.join(', ')}`).toEqual([]);
      const invented = enforced.filter((member) => !defined.includes(member));
      expect(invented, `${binding.list} names member(s) ${binding.map} does not define: ${invented.join(', ')}`).toEqual([]);
      // Order bears on nothing here, but `SHARED_MEMBERS` and the twin both say they list members in
      // the order the CDDL writes them. Once the two sides agree on which names, that claim gets its
      // own line, so a reordering that leaves the set intact says so instead of going unmentioned.
      expect(enforced, `${binding.list} is in another order than ${binding.map}: ${enforced.join(', ')} against ${defined.join(', ')}`).toEqual(defined);
    }

    // What this cannot see, said plainly rather than implied: a list exported under a name that does
    // not end in `_MEMBERS`, or one the closure walk never reads, is a fact about `receipt.ts` and
    // not about a map the format gained.
  });
});
