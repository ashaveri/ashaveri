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
import * as coseCodec from '../src/cose.js';

const schemaPath = fileURLToPath(new URL('../schemas/receipt-v1.schema.json', import.meta.url));
const cddlPath = fileURLToPath(new URL('../receipt.cddl', import.meta.url));
const specPath = fileURLToPath(new URL('../../../docs/receipt-spec.md', import.meta.url));
const schema = JSON.parse(readFileSync(schemaPath, 'utf8')) as object;

/** An object schema of the kind this file nests under `properties`. */
interface ObjectSchema {
  additionalProperties?: unknown;
  properties?: Record<string, unknown>;
  type?: unknown;
}

/**
 * The parts of this schema the agreement test below reads: one branch per payload version, the
 * descriptions that say which members each of them names, and the definitions nested below the
 * payload map.
 */
interface SchemaShape {
  description: string;
  properties: { protectedHeader: ObjectSchema };
  $defs: {
    payloadFields: { properties: Record<string, ObjectSchema> };
    payloadV1: { properties: Record<string, ObjectSchema>; description: string };
    payloadV2: { properties: Record<string, ObjectSchema>; description: string };
  };
}

const shape = schema as SchemaShape;

/** The maps the closure walk enforces, read off the module that walks them rather than restated. */
const definedMaps = receiptParser.DEFINED_MAPS;

/**
 * The nested members a document can carry, which is `mk` on v2 and the other three on either. This is
 * the roster every matrix below sweeps, so it is read out of the structure the parser walks rather
 * than typed here: a roster of this file's own would go on asking the twin about a map the walk had
 * stopped entering, and the lists the parser exports would still match the CDDL rule by rule.
 */
const NESTED_KEYS: string[] = [...new Set(
  Object.values(definedMaps).flatMap((defined) => Object.keys(defined.nested ?? {})),
)];

/**
 * The definition one nested member points at, wherever this file happens to hold it. A member only
 * one branch names, such as `mk`, has its definition on that branch; the members both branches share
 * sit under `payloadFields`, which each of them reaches through their `allOf`. Searched rather than
 * switched on by name, so a map the format gains is looked for in the same two places without an
 * edit here.
 */
function nestedDefinition(key: string): ObjectSchema {
  return required(
    shape.$defs.payloadV2.properties[key] ?? shape.$defs.payloadFields.properties[key],
    `the twin declares no definition for the nested member ${key}`,
  );
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
 * The integer labels one CDDL block declares its members by, which is how `Ashaveri-Protected-Header`
 * spells them and why `labeledMembers` reads none of them: COSE names header parameters from its own
 * registry rather than after the format carrying them. A block that names no integer is a header that
 * declared nothing, so it stops the run instead of reading as an empty one.
 *
 * A label's sign is part of it, because RFC 9052 section 3.1 makes a header key a negative integer as
 * legal a thing as an unsigned one ("we use text strings, negative integers, and unsigned integers as
 * map keys"), and a reader matching unsigned digits derived `[1, 3, 4]` from a block that declared a
 * fourth member by a negative label: the set the tie compares stayed equal, the run went green, and the
 * parser refused a label the format declares. The same reasoning closes the second blind spot: a line
 * this reader cannot parse has to stop the run rather than be walked past, because a label spelled in a
 * shape the tie does not understand is the same hole in another shape, and two declarations on one line
 * hand back a set that is short by however many it dropped.
 */
function cddlIntegerLabels(block: string): number[] {
  const labels: number[] = [];
  for (const line of block.split('\n').slice(1)) {
    // `;` opens a comment to the end of the line in CDDL, so what is left is the declaration. A line
    // that is blank once the comment is gone declares nothing and is skipped; one that declares
    // something the reader cannot spell out as one integer-labelled member throws.
    const declaration = line.split(';')[0]!;
    if (declaration.trim() === '') continue;
    const found = /^\s*(-?\d+)\s*:\s*[^,\s][^,]*,?\s*$/u.exec(declaration);
    if (!found) {
      throw new Error(
        `this reader takes one member per line, labelled by an integer, and cannot read "${declaration.trim()}" from ${cddlPath}`,
      );
    }
    labels.push(Number(found[1]));
  }
  if (labels.length === 0) throw new Error('the block declares no member by integer label');
  return labels;
}

/**
 * Which rule a nested member's value is, read off the payload blocks that name it: `meas` is a
 * `Measurement`. Derived rather than written out beside the member, because adding a member to a
 * payload block is the only way a new map reaches this format, and a table of rule names kept by hand
 * here would let that map arrive in the CDDL and in the parser while the twin-side assertions went
 * on sweeping the maps before it. Two payload blocks naming one member two different rules is the
 * format describing one member as two maps, so it stops the run rather than settling for one.
 */
function nestedRuleNames(cddl: string): Map<string, string> {
  const rules = new Map<string, string>();
  for (const binding of LIST_FOR_MAP.filter((row) => row.map.startsWith('Ashaveri-Receipt-Payload-v'))) {
    for (const line of cddlRule(cddl, binding.map).split('\n').slice(1)) {
      for (const piece of line.split(';')[0]!.split(',')) {
        const found = /^\s*([a-z][a-z0-9_]*)\s*:\s*([A-Z][A-Za-z0-9_-]*)\s*$/u.exec(piece);
        if (!found) continue;
        const known = rules.get(found[1]!);
        if (known !== undefined && known !== found[2]) {
          throw new Error(`${found[1]} is a ${known} in one payload block and a ${found[2]} in the other`);
        }
        rules.set(found[1]!, found[2]!);
      }
    }
  }
  if (rules.size === 0) throw new Error(`no payload member is bound to a rule in ${cddlPath}`);
  return rules;
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

/**
 * The twin's side of one payload version the parser reads: the branch that describes it and the
 * document this file builds for it. Both are looked up off the version the walk names rather than
 * beside a roster typed out here, so a version the walk gains has to be answered for in this file
 * before a matrix below can quietly test one document fewer.
 */
function twinForVersion(version: string): { branch: 'payloadV1' | 'payloadV2'; document: ReceiptPayload } {
  if (version === '1') return { branch: 'payloadV1', document: v1('software', DIGEST) };
  if (version === '2') return { branch: 'payloadV2', document: v2({ sch: 'none', d: DIGEST }) };
  throw new Error(`this file has no branch or document for payload version ${version}`);
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
  owner: string,
  edit: (members: Record<string, unknown>) => void,
): unknown {
  const document = JSON.parse(JSON.stringify(twin(payload))) as {
    payload: Record<string, Record<string, unknown>>;
  };
  edit(required(document.payload[owner], `the projection carries no ${owner} map to edit`));
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
    //
    // One case per map per version, read off the structure the walk enforces: `meas`, `att` and `tok`
    // are declared once and shared by both branches through their `allOf`, so each is asked for on the
    // branch that never sees `mk` as well as the one that does.
    const cases: Array<[ReceiptPayload, string]> = Object.entries(definedMaps).flatMap(
      ([version, defined]) =>
        Object.keys(defined.nested ?? {}).map(
          (key): [ReceiptPayload, string] => [twinForVersion(version).document, key],
        ),
    );
    for (const [payload, key] of cases) {
      expect(outcome(twin(payload)), `${key} on a document that names only what the format does`).toBeNull();
      expect(
        outcome(rewrittenNested(payload, key, (members) => { members.surprise = 'x'; })),
        `${key} carrying a member the format does not name`,
      ).not.toBeNull();
    }
  });

  it('closes every map the signature covers, in the twin, the CDDL and the spec alike', () => {
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
    // the maps here are the ones the walk enters and each one's rule name is read off the payload
    // block that names the member, neither of them written a second time in this file.
    const rulePerKey = nestedRuleNames(cddl);
    for (const key of NESTED_KEYS) {
      const rule = required(
        rulePerKey.get(key),
        `the walk enters a map at ${key} that no payload block names a rule for`,
      );
      expect(cddlRule(cddl, rule).includes('...'), `${rule} closes`).toBe(false);
      expect(
        Object.keys(nestedDefinition(key).properties ?? {}),
        `the twin's ${key} members`,
      ).toEqual(cddlMembers(cddl, rule));
      // That the closing keyword sits there is the assertion; that it binds is the case earlier in
      // this file, which hands `validate` the same document with one unnamed member added. A keyword
      // this schema did not define would have failed to compile at all, which is the other guard.
      expect(nestedDefinition(key).additionalProperties, `${key} names its members as the whole of it`).toBe(false);
    }

    saidOnce('the CDDL closure note', prose, "That rule is the format's, not one map's");
    saidOnce('the CDDL closure note', prose, 'below carry no `...` either');
    saidOnce('the CDDL closure note', prose, 'The parser and the JSON twin refuse it at that level');
    // The note that used to record the divergence now records the rule reaching the signed half of
    // it, and each header is named for what the format says of it now. A reader of the format takes
    // this boundary from the comment and not from the source: `Ashaveri-Protected-Header` closes under
    // the same rule as the payload, for the stronger reason that its bytes are what the signature
    // hashes, and the unprotected map is the single one a signer fills at will because no claim can
    // travel through it. Either sentence sliding back into a claim about every map the file defines,
    // or back into exempting the protected header, is one the parser contradicts on its first read.
    saidOnce('the CDDL closure note', prose, 'so the payload map and every map nested inside it close, at both versions');
    saidOnce('the CDDL closure note', prose, '`Ashaveri-Protected-Header` closes with them');
    saidOnce('the CDDL closure note', prose, 'The parser refuses the unknown label by number');
    saidOnce('the CDDL closure note', prose, 'One map this file leaves a signer free to fill, and that is a decision rather than a gap');
    saidOnce('the CDDL closure note', prose, 'What the format declares of it is therefore only that it carries no claim');
    // Two phrasings held out of the note by name. The first exempted the signed header from the closure
    // rule, which is now the rule the parser refuses a label by; the second described the unprotected map
    // as a divergence between what the format writes and what a reader takes, which the widened type on
    // its own line says out loud instead. Either returning is the format file stating something the code
    // no longer does, and a reader of the definition has nothing but the code to check it against.
    expect(prose).not.toContain('sit outside that rule');
    expect(prose).not.toContain('takes any map at all where the format writes');
    // The header's closure is the absence of `...` in its block, as the payload's is, and the
    // unprotected widening is the type on its line rather than a paragraph about it: `{}` declared an
    // empty map no code required, so the format now names the map a verifier accepts.
    expect(cddlRule(cddl, 'Ashaveri-Protected-Header').includes('...'), 'the protected header closes').toBe(false);
    expect(cddl).toContain('unprotected: { * any => any }');
    expect(cddl).not.toMatch(/unprotected: \{\}/u);
    for (const rule of new Set(rulePerKey.values())) {
      expect(prose.includes(`\`${rule}\``), `the CDDL names ${rule}`).toBe(true);
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
    // The signed header's projection says of itself that no keyword closes it, and that is the one claim
    // in that paragraph a keyword could not carry: what closes that map is the parser refusing a label by
    // number, which happens upstream of anything this file describes. The two assertions below hold the
    // sentence and the artifact against each other, so the prose cannot drift into naming a keyword that
    // is not there, and an `additionalProperties` added to the definition has to arrive with the sentence
    // rewritten rather than quietly contradicting it.
    expect(
      shape.properties.protectedHeader.additionalProperties,
      'the projection of the signed header carries an `additionalProperties`, which its description says it does not',
    ).toBeUndefined();
    saidOnce('the twin', shape.description, 'this definition carries no closure keyword');
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
    // label, which is the kind of map the closure walk in `receipt.ts` speaks of. This file's two
    // header maps are outside that pairing because they are outside that walk, which enters a payload
    // and the maps below it and never a header. Neither header is therefore unenforced: the signed one
    // closes against the integer labels `receipt.cddl` names, in `cose.ts`, and the case after this
    // one binds those labels to the block. `Ashaveri-Protected-Header` spells its members as the COSE
    // registry's integers, so the reader below skips it and the assertion after this loop says that the
    // one skipped name is that header rather than a map whose members were spelled some other way.
    // `unprotected` is not a rule this reader can find at all, only `{ * any => any }` written inside
    // `COSE_Sign1-COSE`, which is the format saying out loud that it declares nothing about it.
    const maps = new Map<string, string[]>();
    const unlabeled: string[] = [];
    for (const rule of cddlMapRuleNames(cddl)) {
      const arms = cddlRuleArms(cddl, rule).map((arm) => labeledMembers(arm));
      const first = required(arms[0], `${rule} declares no block`);
      if (first.length === 0) {
        unlabeled.push(rule);
        continue;
      }
      // A rule written as a choice between maps is one list's job only while the arms name the same
      // members. `Measurement` differs in the width `m` carries, which is a value rule and not a
      // member rule; a name carried by one arm alone would be a second map standing unbound, which
      // ever way the difference fell.
      for (const [index, arm] of arms.entries()) {
        const added = arm.filter((member) => !first.includes(member));
        const dropped = first.filter((member) => !arm.includes(member));
        expect(
          arm,
          `${rule} arm ${index + 1} of ${arms.length} names a different set of members than its first arm, carrying ${added.join(', ') || 'nothing'} the first arm does not and lacking ${dropped.join(', ') || 'nothing'} it does`,
        ).toEqual(first);
      }
      maps.set(rule, first);
    }

    // The exemption, stated rather than inferred. Skipping a rule with no labelled members is what
    // takes the protected header out of the derived side above, and a rule whose members are spelled
    // any way but `[a-z][a-z0-9_]*` is legal CDDL that arrives at the same skip. Naming the skipped
    // set answers which of the two happened, and a second name landing here is a map to read rather
    // than a map to miss.
    expect(unlabeled, 'CDDL map rules whose members this reader does not read as labels').toEqual([
      'Ashaveri-Protected-Header',
    ]);

    // Both directions of the pairing, which is the point of deriving the format's side instead of
    // typing it. A map with no list behind it is a parser that refuses a member the format defines,
    // and a list bound to a rule nothing defines is a check that can rot where nobody looks; neither
    // is visible in the other's failure. A map the format gains reaches `maps` on its own only as far
    // as this reader reaches, which is to say when it spells its members as the six here do, and a
    // rule spelled otherwise is caught by the exemption above instead.
    const boundMaps = LIST_FOR_MAP.map((binding) => binding.map);
    expect(new Set(boundMaps).size, 'one map is bound to a parser list twice').toBe(boundMaps.length);
    expect([...maps.keys()].sort(), 'maps the CDDL defines with no parser list bound to them').toEqual([...boundMaps].sort());
    const boundLists = [...new Set(LIST_FOR_MAP.map((binding) => binding.list))];
    expect([...lists.keys()].sort(), 'parser lists bound to no map the CDDL defines').toEqual([...boundLists].sort());

    // The structure the walk reads, which no export can vouch for. Two faults sit here and neither
    // shows above. An entry spelled out inline beside the list it copies is as correct as that list
    // until the day the list is edited, so what follows is identity and not equality. A version that
    // lost its `nested` altogether still binds every exported list to its rule, so the maps each
    // version enters are compared with the payload members this schema makes into maps, which is the
    // one roster every matrix in this file and in receipt.test.ts reads.
    const rulePerKey = nestedRuleNames(cddl);
    const readers = new Map<string, Array<{ version: string; key: string; members: readonly string[] }>>();
    for (const [version, defined] of Object.entries(definedMaps)) {
      const nested = required(defined.nested, `the closure walk enters no map below a version ${version} payload`);
      const twinMaps = [
        ...Object.entries(shape.$defs.payloadFields.properties),
        ...Object.entries(shape.$defs[twinForVersion(version).branch].properties),
      ]
        .filter(([, definition]) => definition.type === 'object')
        .map(([key]) => key);
      expect(
        [...Object.keys(nested)].sort(),
        `the maps version ${version} enters are not the payload members the twin declares as maps`,
      ).toEqual([...twinMaps].sort());
      for (const [key, map] of Object.entries(nested)) {
        const rule = required(rulePerKey.get(key), `no payload block names a rule for the map version ${version} enters at ${key}`);
        readers.set(rule, [...(readers.get(rule) ?? []), { version, key, members: map.members }]);
      }
    }

    for (const binding of LIST_FOR_MAP) {
      const list = required(lists.get(binding.list), `${binding.list} is not an export of src/receipt.ts`);
      const defined = cddlMembers(cddl, binding.map);
      const enforced = [...list, ...(binding.adds ?? [])];
      // A name the format defines and the list drops is refused as an undefined member by the parser
      // that reads it; a name the list carries and the format does not define buys a document
      // acceptance no version of the format grants. Either one alone passes a subset check pointed at
      // random, so the two diffs are named separately.
      const missing = defined.filter((member) => !enforced.includes(member));
      expect(missing, `${binding.list} does not enforce ${binding.map}'s member(s): ${missing.join(', ')}`).toEqual([]);
      const extra = enforced.filter((member) => !defined.includes(member));
      expect(extra, `${binding.list} names member(s) ${binding.map} does not define: ${extra.join(', ')}`).toEqual([]);
      // Order bears on nothing here, but `SHARED_MEMBERS` and the twin both say they list members in
      // the order the CDDL writes them. Once the two sides agree on which names, that claim gets its
      // own line, so a reordering that leaves the set intact says so instead of going unmentioned.
      expect(enforced, `${binding.list} is in another order than ${binding.map}: ${enforced.join(', ')} against ${defined.join(', ')}`).toEqual(defined);
      // And the walk reads this very array wherever that rule sits below a payload, which is the
      // half of the fact the export cannot carry: the list and the CDDL agreeing is no help once the
      // parser is comparing a document against a copy of the thing it agreed to.
      for (const reader of readers.get(binding.map) ?? []) {
        expect(
          reader.members,
          `version ${reader.version} reads ${reader.key} against a list that is not the exported ${binding.list} itself`,
        ).toBe(list);
      }
    }

    // What this cannot see, said plainly rather than implied: a list exported under a name that does
    // not end in `_MEMBERS` is a fact about `receipt.ts` and not about a map the format gained, and
    // the payload level's own member list is read through its export rather than against the walk,
    // because the v2 entry is built from the shared list plus one name and is a copy on purpose. The
    // signed header's list is the one the case below reads, because no rule here reaches it.
    //
    // Neither reaches which label holds which parameter, and that is the third thing this cannot see.
    // `COSE_HEADER_ALG` and `COSE_HEADER_CONTENT_TYPE` are `1` and `3`; exchanging the two numbers
    // leaves both sides of the header tie at [1, 3, 4], and leaves every case in this package green,
    // because a signed header is written from those constants and read back through them, and the
    // hand-built control in `receipt.test.ts` builds its map from the same two names. What reads the
    // assignment instead of the set is a document whose bytes were fixed before the read: the four
    // stored vectors under `packages/fixtures/data/receipts`, regenerated by no test and read back
    // through `verifyReceipt` by `packages/fixtures/test/fixtures.test.ts`, each carry `-8` at label 1
    // and `"ashaveri/receipt"` at label 3, and `cose.ts` requires a number where it reads `alg`, so a
    // module that moved the two constants answers `UNSUPPORTED_ALG` against bytes no issuer moved. That
    // is a check on the vectors, and no comparison of two sets in this file can stand in for it.
  });

  it('binds the labels a protected header may carry to the block that declares them', () => {
    // The pairing above reaches every map whose members are text labels, and the signed header is the
    // one map whose are not, so nothing there could see which labels it closes against. The parser
    // refuses a label the block does not name by number, before it reads any declared one, so the set it
    // refuses everything else with is compared with the block rather than with a second copy in this
    // file. Both directions bear: a label the format declares and the parser refuses rejects receipts an
    // issuer legitimately signs, and a label the parser takes that the format does not declare is an
    // authenticated parameter no version of this format granted. What makes the comparison worth running
    // is that the reader of the block can lose a declaration without noticing, so it reads a signed label
    // as signed, and a line it cannot parse stops the run: an equality between a set derived by a partial
    // reader and a set the parser wrote is agreement about nothing.
    const cddl = readFileSync(cddlPath, 'utf8');
    const declared = cddlIntegerLabels(cddlRule(cddl, 'Ashaveri-Protected-Header'));
    const accepted = [...coseCodec.DECLARED_PROTECTED_LABELS];
    expect(
      accepted.slice().sort((a, b) => a - b),
      `src/cose.ts accepts labels ${accepted.join(', ')} and the CDDL declares ${declared.join(', ')}`,
    ).toEqual(declared.slice().sort((a, b) => a - b));
    // And the block itself still names the three the COSE registry fixes, so an equality between two
    // sides that both lost a label cannot pass for agreement. A fourth declaration of either sign, or of
    // any shape this reader will not spell, is refused above or by the reader throwing.
    expect(declared.slice().sort((a, b) => a - b)).toEqual([1, 3, 4]);
  });
});
