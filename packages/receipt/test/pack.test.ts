import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { Ajv2020, type ValidateFunction } from 'ajv/dist/2020.js';
import { cddlRule, cddlRuleArms, labeledMembers, memberDeclarations, readCddl, required } from './cddl.js';

/**
 * Holds `pack.cddl` to its own JSON twin.
 *
 * Every claim here is derivation, because a member set written down in a test and in the format is
 * edited in one of the two places and stays plausible in the other. Which members each map of the
 * pack format declares is read out of `pack.cddl`; which definition of the twin stands behind each of
 * them is read out of the twin's own `$ref`s; and the document every negative case runs against is
 * built from those declarations rather than copied from a projection that does not exist yet. Nothing
 * assembles a pack today, so there is no writer here to agree with and no bytes to paste: what a pack
 * must hold is the CDDL's business, and this file's business is to notice the day the two public
 * statements of it stop being one statement.
 *
 * `test/cddl.ts` supplies the block readers, which take a rule name and the text of any file and so
 * serve a second CDDL without change. What it does not supply is a path to it: `readCddl` and the
 * failures of `cddlRule` name `receipt.cddl`, so a rule missing from *this* format would be reported
 * as missing from that one. `packRule` and `packArms` below are the thin wrappers that fix the name in
 * the message. `integerLabels`, `flat`, `saidOnce` and `cddlProse` are defined here rather than
 * imported because `schema.test.ts` keeps them to itself, a test file exports nothing, and moving prose
 * helpers out of a file another suite owns is a change to that file rather than to this one.
 */
const packCddlPath = fileURLToPath(new URL('../pack.cddl', import.meta.url));
const packSchemaPath = fileURLToPath(new URL('../schemas/pack-v1.schema.json', import.meta.url));

function readPackCddl(): string {
  return readFileSync(packCddlPath, 'utf8');
}

/** An object schema of the kind the twin nests under `properties` and `$defs`. */
interface ObjectSchema {
  $ref?: unknown;
  additionalProperties?: unknown;
  const?: unknown;
  description?: string;
  items?: ObjectSchema;
  minItems?: unknown;
  pattern?: unknown;
  properties?: Record<string, ObjectSchema>;
  required?: readonly string[];
  type?: unknown;
}

/** The parts of the twin this file reads: the root prose, the envelope, and every definition. */
interface PackSchemaShape {
  additionalProperties?: unknown;
  description: string;
  properties: { protectedHeader: ObjectSchema; payload: ObjectSchema; signature: ObjectSchema };
  required?: string[];
  $defs: Record<string, ObjectSchema>;
}

const shape = JSON.parse(readFileSync(packSchemaPath, 'utf8')) as PackSchemaShape;

/** One string for a whole document's worth of line breaks, so a check pins a sentence and not a wrapping. */
function flat(text: string): string {
  return text.replace(/\s+/gu, ' ').trim();
}

/** The CDDL's full-line comments as prose, which is what a stranger reading the format actually reads. */
function cddlProse(cddl: string): string {
  return flat(cddl.split('\n').filter((line) => line.startsWith(';')).map((line) => line.slice(1)).join('\n'));
}

/**
 * `where` says `phrase` exactly once: zero is a document that stopped stating the rule, two is one
 * that started stating it in two voices. The name and the phrase ride along in the failure because a
 * bare length assertion cannot say which of the two texts went quiet.
 */
function saidOnce(where: string, text: string, phrase: string): void {
  const hits = text.split(phrase).length - 1;
  expect(hits, `${where} says "${phrase}" ${hits} times, not once`).toBe(1);
}

/** The map block one rule opens, with the path named when the rule is not there. */
function packRule(cddl: string, rule: string): string {
  if (!cddl.includes(`${rule} = {`)) throw new Error(`${rule} is not declared in ${packCddlPath}`);
  return cddlRule(cddl, rule);
}

/** Every block of a rule written as a map, or a choice between maps, with the same fix to the name. */
function packArms(cddl: string, rule: string): string[] {
  if (!cddl.includes(`${rule} = {`)) throw new Error(`${rule} is not declared in ${packCddlPath}`);
  return cddlRuleArms(cddl, rule);
}

/**
 * The members one block declares, and the run stops on a block that names none. The signed header is
 * the one rule whose members are not spelled this way, so a caller sweeping every map asks for this
 * and answers for the exemption itself.
 */
function packMembers(cddl: string, rule: string): string[] {
  const members = labeledMembers(packRule(cddl, rule));
  if (members.length === 0) throw new Error(`the ${rule} block declares no members`);
  return members;
}

/**
 * The integer labels one block declares its members by, sign included, because RFC 9052 makes a
 * negative header key as legal a thing as an unsigned one and a reader that lost the sign would tie
 * against a set the format does not declare. One member per line, and a line this reader cannot spell
 * out stops the run rather than being walked past.
 */
function integerLabels(block: string): number[] {
  const labels: number[] = [];
  for (const line of block.split('\n').slice(1)) {
    const declaration = line.split(';')[0]!;
    if (declaration.trim() === '') continue;
    const found = /^\s*(-?\d+)\s*:\s*[^,\s][^,]*,?\s*$/u.exec(declaration);
    if (!found) {
      throw new Error(`this reader takes one member per line, labelled by an integer, and cannot read "${declaration.trim()}"`);
    }
    labels.push(Number(found[1]));
  }
  if (labels.length === 0) throw new Error('the block declares no member by integer label');
  return labels;
}

/** The quoted value one integer label carries, which is how a content type is read out of a header. */
function labeledLiteral(block: string, label: number): string {
  const found = new RegExp(`^\\s*${label}\\s*:\\s*"([^"]*)"`, 'mu').exec(block);
  if (!found) throw new Error(`the block carries no quoted value at label ${label}`);
  return found[1]!;
}

/** Every rule the file opens as a map, read off the text so a map added later is swept the day it lands. */
function packMapRuleNames(cddl: string): string[] {
  const names: string[] = [];
  for (const line of cddl.split('\n')) {
    const found = /^([A-Za-z][A-Za-z0-9_-]*) = \{/u.exec(line);
    if (found) names.push(found[1]!);
  }
  if (names.length === 0) throw new Error(`no map rule is declared in ${packCddlPath}`);
  return names;
}

/** The rule one manifest member is, and whether the member is an array of it rather than one of it. */
interface NestedRule {
  readonly member: string;
  readonly rule: string;
  readonly array: boolean;
}

/**
 * Which rules the manifest opens, read off its own member declarations: a bare `PackChain` is one
 * value of that rule, and `[+ PackItem]` is an array of them. Anything else about a member — a choice
 * between two rules, a type expression this reader does not read — stops the run, because a member
 * quietly skipped would be a map the twin could drift away from with nothing asked of it.
 */
function manifestNestedRules(cddl: string): NestedRule[] {
  const nested: NestedRule[] = [];
  for (const member of memberDeclarations(packRule(cddl, 'Ashaveri-Pack-Manifest'))) {
    const one = /^([A-Z][A-Za-z0-9_-]*)$/u.exec(member.type);
    if (one) {
      nested.push({ member: member.name, rule: one[1]!, array: false });
      continue;
    }
    const many = /^\[\+\s+([A-Z][A-Za-z0-9_-]*)\]$/u.exec(member.type);
    if (many) {
      nested.push({ member: member.name, rule: many[1]!, array: true });
      continue;
    }
    if (/^(?:int|tstr|bstr\b|-?\d+)/u.test(member.type)) continue;
    throw new Error(`${member.name} is declared as "${member.type}", which this reader does not read as one rule`);
  }
  if (nested.length === 0) throw new Error(`the manifest of ${packCddlPath} opens no map`);
  return nested;
}

/** The definition a `$ref` reaches, and the name it reaches it under. */
function referenced(schema: ObjectSchema, where: string): { name: string; def: ObjectSchema } {
  const ref = required(schema.$ref, `${where} is not a reference, so it binds to no definition`);
  if (typeof ref !== 'string') throw new Error(`${where} carries a $ref that is not text`);
  const name = required(/#\/\$defs\/(.+)$/u.exec(ref)?.[1], `${where} references ${ref}, which is not a pointer into $defs`);
  return { name, def: required(shape.$defs[name], `the twin has no ${name} definition to be found`) };
}

/** The manifest's own definition, which every other one is reached through. */
const manifestDef = referenced(shape.properties.payload, 'the pack payload').def;

/** The twin side of one manifest member: the definition it points at, and under which name. */
function memberDefinition(nested: NestedRule): { name: string; def: ObjectSchema } {
  const property = required(
    manifestDef.properties?.[nested.member],
    `the twin declares no ${nested.member} beside the manifest's ${nested.rule}`,
  );
  const target = nested.array
    ? required(property.items, `the CDDL makes ${nested.member} an array of ${nested.rule} and the twin gives it no element schema`)
    : property;
  return referenced(target, `the manifest member ${nested.member}`);
}

/** The manifest definition and each one the manifest opens, with the CDDL rule behind it. */
function definitionsByRule(cddl: string): Array<{ rule: string; name: string; def: ObjectSchema }> {
  return [
    { rule: 'Ashaveri-Pack-Manifest', name: 'manifest', def: manifestDef },
    ...manifestNestedRules(cddl).map((nested) => ({ rule: nested.rule, ...memberDefinition(nested) })),
  ];
}

/** A number of bytes, as this estate's projections write a byte string: lowercase hex. */
function hexOf(bytes: number): string {
  return 'ab'.repeat(bytes);
}

/**
 * One declared byte width against the hex pattern the twin writes for the same position. The comparison
 * is of the numbers, so a width moving in either document reddens the tie by naming both figures: a
 * digest growing from thirty-two bytes to forty-eight is caught here as a tie that no longer holds, and
 * not only downstream where a built document fails a pattern for reasons of its own.
 */
function widthTie(bytes: number, pattern: unknown, position: string): void {
  expect(
    pattern,
    `${position} is ${String(bytes)} bytes in the format, so the twin's pattern is ${String(bytes * 2)} hex digits`,
  ).toBe(`^[0-9a-f]{${String(bytes * 2)}}$`);
}

/** The integer a sweep of positions reads back as itself, and no position is asked to be zero. */
const AN_INT = 1_772_000_000;

/**
 * A value of the type expression one member declares, which is how the document every case below runs
 * against is built out of the format rather than out of a projection. An expression this reader cannot
 * fill stops the run: a member silently left out of the built document would be a member the twin
 * never had to answer for, and the whole point of building the document is that it cannot be quiet
 * about a position the format gained.
 */
function valueForType(cddl: string, type: string): unknown {
  const literal = /^(-?\d+)$/u.exec(type);
  if (literal) return Number(literal[1]);
  if (type === 'int') return AN_INT;
  const many = /^\[\+\s+([A-Z][A-Za-z0-9_-]*)\]$/u.exec(type);
  if (many) return [instanceOfRule(cddl, many[1]!)];
  const one = /^([A-Z][A-Za-z0-9_-]*)$/u.exec(type);
  if (one) return instanceOfRule(cddl, one[1]!);
  const sized = /^bstr \.size (\d+)$/u.exec(type);
  if (sized) return hexOf(Number(sized[1]));
  if (/^bstr \.cbor [A-Z][A-Za-z0-9_-]*$/u.test(type)) return hexOf(4);
  if (/^tstr \.size \(\d+\.\.\d+\)$/u.test(type)) return 'an-id';
  if (type === 'tstr') return 'a-label';
  throw new Error(`this builder fills no value of the type expression "${type}"`);
}

/** A document of the shape one rule declares, at every width and no deeper than the format goes. */
function instanceOfRule(cddl: string, rule: string): Record<string, unknown> {
  const arms = packArms(cddl, rule);
  if (arms.length !== 1) {
    throw new Error(`${rule} is written as a choice between ${arms.length} blocks and this builder takes one map per rule`);
  }
  const members = memberDeclarations(arms[0]!);
  if (members.length === 0) throw new Error(`${rule} declares no member to build a value of`);
  const out: Record<string, unknown> = {};
  for (const member of members) out[member.name] = valueForType(cddl, member.type);
  return out;
}

/**
 * The envelope half of the document, read off the twin rather than written out: three members, two of
 * them fixed values and one a keyed digest. Deriving it from the schema weakens nothing that matters,
 * because the payload this file builds comes from the CDDL and what the header holds is the COSE
 * registry's names for three parameters this format did not choose.
 */
function headerDocument(): Record<string, unknown> {
  const header = shape.properties.protectedHeader;
  const out: Record<string, unknown> = {};
  for (const key of required(header.required, 'the projection of the signed header names no required members')) {
    const definition = required(header.properties?.[key], `the projection names ${key} and does not define it`);
    if ('const' in definition) out[key] = definition.const;
    else if (typeof definition.pattern === 'string') out[key] = hexOf(32);
    else throw new Error(`this builder fills no value for the header member ${key}`);
  }
  return out;
}

function packDocument(cddl: string): Record<string, unknown> {
  return {
    protectedHeader: headerDocument(),
    payload: instanceOfRule(cddl, 'Ashaveri-Pack-Manifest'),
    signature: hexOf(64),
  };
}

/**
 * Compiles the twin with Ajv's strict mode on, so a keyword this schema does not define fails at
 * compile time instead of being ignored. No `format` appears anywhere in this file, so unlike the
 * receipt's twin there is nothing here to give a validator that accepts everything.
 */
function compile(s: object): ValidateFunction<unknown> {
  const ajv = new Ajv2020({ strict: true });
  return ajv.compile(s);
}

const validate = compile(shape);

function outcome(value: unknown): string | null {
  return validate(value) ? null : JSON.stringify(validate.errors);
}

/** The map at one path inside a built document, so a case can add a member where it means to. */
function mapAt(root: unknown, path: readonly (string | number)[]): Record<string, unknown> {
  let cursor: unknown = root;
  for (const step of path) {
    cursor = Array.isArray(cursor)
      ? required(cursor[Number(step)], `the built document has no element at ${String(step)}`)
      : required((cursor as Record<string, unknown>)[String(step)], `the built document has no member ${String(step)}`);
  }
  if (typeof cursor !== 'object' || cursor === null || Array.isArray(cursor)) {
    throw new Error(`the path ${path.join('.')} does not reach a map to edit`);
  }
  return cursor as Record<string, unknown>;
}

/** Where each closed map sits in the document this file builds, read off the CDDL's own nesting. */
function closedLevels(cddl: string): Array<{ rule: string; path: (string | number)[] }> {
  const levels: Array<{ rule: string; path: (string | number)[] }> = [
    { rule: 'Ashaveri-Pack-Manifest', path: ['payload'] },
  ];
  for (const nested of manifestNestedRules(cddl)) {
    levels.push({
      rule: nested.rule,
      path: nested.array ? ['payload', nested.member, 0] : ['payload', nested.member],
    });
  }
  return levels;
}

/** The type expression the format writes for a position that is not left to a reader's judgement. */
const INTEGER_TYPE = /^(?:int|-?\d+)$/u;

/**
 * Every position the format types as an integer, with the dotted name a reader of a pack uses: `at` at
 * the manifest level, `span.from` one map down, `items.iat` inside an element of an array. The rule
 * that refuses a float reaches all of them alike, so a sweep holding the format to it has to be asked
 * about every position the format has rather than about a roster somebody remembered. A member that
 * opens a map is expanded into it, so a map gaining an integer arrives here with no edit below.
 */
function integerPositions(cddl: string): string[] {
  const nested = new Map(manifestNestedRules(cddl).map((row) => [row.member, row.rule]));
  const positions: string[] = [];
  for (const member of memberDeclarations(packRule(cddl, 'Ashaveri-Pack-Manifest'))) {
    if (INTEGER_TYPE.test(member.type)) {
      positions.push(member.name);
      continue;
    }
    const rule = nested.get(member.name);
    if (rule === undefined) continue;
    for (const inner of memberDeclarations(packRule(cddl, rule))) {
      if (INTEGER_TYPE.test(inner.type)) positions.push(`${member.name}.${inner.name}`);
    }
  }
  if (positions.length === 0) throw new Error(`no position of ${packCddlPath} is typed as an integer`);
  return positions;
}

const CDDL = readPackCddl();
const INTEGER_POSITIONS = integerPositions(CDDL);

describe('the pack CDDL and its JSON twin', () => {
  it('closes every map the format declares, and names the one it leaves free', () => {
    // Closedness is the absence of `...` in a block, and the sweep that matters runs over the rules the
    // file has rather than a list of them kept here: a map added to the format is asked about the day
    // it lands, which is the only way a second open map is caught rather than shipped.
    const labeled: string[] = [];
    const unlabeled: string[] = [];
    for (const rule of packMapRuleNames(CDDL)) {
      expect(packRule(CDDL, rule).includes('...'), `${rule} carries an open member`).toBe(false);
      if (labeledMembers(packRule(CDDL, rule)).length === 0) unlabeled.push(rule);
      else labeled.push(rule);
    }
    // The exemption, stated rather than inferred: the signed header spells its members by the COSE
    // registry's integers, so a reader of text labels sees none of them. A second name here would be a
    // map whose members are spelled some other way and a sweep that quietly passed over it.
    expect(unlabeled, 'rules whose members this reader does not read as labels').toEqual(['Ashaveri-Pack-Protected-Header']);
    expect(labeled.sort(), 'the maps the format closes').toEqual(
      ['Ashaveri-Pack-Manifest', 'PackChain', 'PackDuty', 'PackItem', 'PackSpan'].sort(),
    );

    // The header closes against labels rather than against members, and one map of the container a
    // signer fills at will because nothing written in it can travel as a claim. `{ * any => any }` is
    // the format saying that out loud; `{}` would claim an emptiness no code enforces.
    expect(integerLabels(packRule(CDDL, 'Ashaveri-Pack-Protected-Header')).slice().sort((a, b) => a - b)).toEqual([1, 3, 4]);
    expect(CDDL).toContain('unprotected: { * any => any }');
    expect(CDDL).not.toMatch(/unprotected: \{\}/u);

    // The twin closes where the CDDL does, with the keyword that applies where the members are named
    // in the same object, and says nothing about a header no keyword reaches.
    for (const { rule, def } of definitionsByRule(CDDL)) {
      expect(def.additionalProperties, `${rule} in the twin does not name its members as the whole of it`).toBe(false);
    }
    expect(
      shape.properties.protectedHeader.additionalProperties,
      'the projection of the signed header carries an `additionalProperties`, which its description says it does not',
    ).toBeUndefined();
  });

  it('declares the members the twin names, at every map the manifest opens', () => {
    // Both directions, per map: a name the CDDL declares and the twin drops is a member a projection
    // would refuse to show, and a name the twin carries and the CDDL does not is a field no signature
    // covers. Order is compared too, because the CDDL writes its members in one and a projection is a
    // document somebody reads in sequence.
    for (const { rule, def } of definitionsByRule(CDDL)) {
      const declared = packMembers(CDDL, rule);
      const projected = Object.keys(required(def.properties, `${rule} in the twin declares no properties`));
      expect(projected, `the twin's ${rule} members are not the ones ${rule} declares`).toEqual(declared);
      // Every member of this format is required: no position is optional and none carries a default,
      // so a reader never has to work out what an omitted field meant. A twin that let one be absent
      // would be a projection of a document the format refuses.
      expect(def.required, `${rule} in the twin does not require every member it names`).toEqual(projected);
      // And the kinds and widths agree with what the CDDL writes beside each member, rather than with a
      // table of them kept in this file: a fixed byte width is read as a number off the type expression
      // and matched against the digits in the twin's pattern, so the tie holds the width and not a name.
      for (const member of memberDeclarations(packRule(CDDL, rule))) {
        const definition = required(def.properties?.[member.name], `${rule}.${member.name} is declared and not projected`);
        if (INTEGER_TYPE.test(member.type)) {
          if (member.name === 'v') {
            expect(definition.const, `${rule}.v is not fixed at ${member.type} in the twin`).toBe(Number(member.type));
          } else {
            expect(definition.type, `${rule}.${member.name} is not an integer in the twin`).toBe('integer');
          }
        }
        const declaredWidth = /^bstr \.size (\d+)$/u.exec(member.type);
        if (declaredWidth) {
          // The width the format declares is compared to the digits in the pattern the twin reaches, so
          // neither side can move without the tie naming both figures. The definition's own name is in
          // the message rather than in the assertion: `hex32` is the twin's business, the count of hex
          // digits is the format's.
          const bytes = Number(declaredWidth[1]);
          const target =
            typeof definition.$ref === 'string'
              ? referenced(definition, `${rule}.${member.name}`)
              : { name: `${rule}.${member.name}`, def: definition };
          widthTie(bytes, required(target.def.pattern, `${target.name} carries no pattern to tie to the format`), `${rule}.${member.name} through ${target.name}`);
        }
        if (/^\[\+\s+[A-Z]/u.test(member.type)) {
          expect(definition.type, `${rule}.${member.name} is not an array in the twin`).toBe('array');
          expect(definition.minItems, `${rule}.${member.name} does not require an element`).toBe(1);
        }
      }
    }

    // No object definition stands orphaned: one the manifest never opens is a map the format stopped
    // declaring while the projection went on describing it, and nothing above would notice.
    const objectDefs = Object.keys(shape.$defs)
      .filter((name) => shape.$defs[name]?.type === 'object')
      .sort();
    expect(objectDefs, 'the twin carries object definitions no manifest member opens').toEqual(
      definitionsByRule(CDDL).map(({ name }) => name).sort(),
    );
    // And every name under `$defs` is reached from the document: by the manifest, by one of its
    // members, or by a member of a map a member opens. A helper left behind is a second answer to a
    // width the format no longer states, and it is invisible to an assertion that only walks down.
    const reached = new Set<string>(definitionsByRule(CDDL).map(({ name }) => name));
    for (const { def } of definitionsByRule(CDDL)) {
      for (const member of Object.values(required(def.properties, 'a definition with no properties'))) {
        if (typeof member.$ref === 'string') reached.add(/#\/\$defs\/(.+)$/u.exec(member.$ref)?.[1] ?? member.$ref);
        const element = member.items?.$ref;
        if (typeof element === 'string') reached.add(/#\/\$defs\/(.+)$/u.exec(element)?.[1] ?? element);
      }
    }
    expect([...reached].sort(), 'the twin declares a definition no member reaches').toEqual(Object.keys(shape.$defs).sort());
  });

  it('accepts the document the format declares and refuses one member more at every level', () => {
    const document = packDocument(CDDL);
    expect(outcome(document), 'a pack built from the declared members is refused').toBeNull();
    // Each case is a pair, so a refusal cannot have arrived for any other reason than a member no map
    // names. Delete an `additionalProperties` from the twin and only the second half of each pair goes
    // red, which is the point: the case tests the keyword and not the document.
    for (const { rule, path } of closedLevels(CDDL)) {
      const edited = JSON.parse(JSON.stringify(document)) as Record<string, unknown>;
      const target = mapAt(edited, path);
      expect(
        Object.keys(target).length,
        `${rule} is reached by no path this file can build, so its case tested nothing`,
      ).toBeGreaterThan(0);
      target.surprise = 'x';
      expect(outcome(edited), `${rule} carrying a member the format does not name`).not.toBeNull();
    }
    // The array of items is closed at both ends: an element is a map the format names, and a count of
    // them is a claim, so an empty one is refused rather than read as a span that held nothing.
    const emptied = JSON.parse(JSON.stringify(document)) as { payload: { items: unknown[] } };
    emptied.payload.items = [];
    expect(outcome(emptied), 'a pack carrying no receipts is accepted').not.toBeNull();
  });

  it('carries no member that states the deployment’s own verdict', () => {
    // `met` is the member a retention manifest signs and this container does not, and the difference
    // is a decision. A sweep over every declared member of every closed map is what holds it, because
    // a name added to one map would otherwise be a conclusion signed beside the evidence for it.
    const declared: string[] = [];
    for (const { rule } of closedLevels(CDDL)) declared.push(...packMembers(CDDL, rule));
    expect(declared.filter((member) => member === 'met'), 'the format declares a verdict member').toEqual([]);
    expect(
      required(shape.$defs.duty?.properties, 'the twin declares no duty members').met,
      'the twin projects a verdict the CDDL does not declare',
    ).toBeUndefined();
    saidOnce('the CDDL', cddlProse(CDDL), '`met` is absent on purpose');
    saidOnce('the twin', shape.description, 'No member states whether the duty was met');
  });

  it('types every number it declares as an integer, and says the rule once', () => {
    const prose = cddlProse(CDDL);
    saidOnce('the CDDL', prose, 'is a CBOR integer, major type 0 or 1, and no other major type carries one');
    saidOnce('the CDDL', prose, 'where no floating-point number may appear, in a value and in a key alike');
    // The roster is derived above and pinned here as a fact about the file, because a format that
    // gained a position either way has to make somebody look at it: two at the manifest level, three
    // below the duty map, two below the span, and one inside an item.
    expect(INTEGER_POSITIONS).toEqual([
      'v',
      'at',
      'span.from',
      'span.to',
      'duty.rev',
      'duty.required',
      'duty.held',
      'items.iat',
    ]);
    // The declarations and nothing else: the word "float" belongs in this file's prose, where it
    // explains what a reader must not accept, and would not belong in a type expression. CDDL gives a
    // number position four spellings beside `int`, and the format uses none of them.
    const declarations = CDDL.split('\n')
      .filter((line) => !line.startsWith(';'))
      .join('\n');
    expect(declarations).not.toMatch(/\b(?:uint\d*|nint|biguint|bigint|float\d*)\b/u);
    // The receipt's own test file keeps that file's prose from carrying a copy of its roster because
    // two other documents enumerate it and are tied to the format. Nothing enumerates this format's
    // list yet, so the pin here is the narrower one that is not vacuous: the prose explains single
    // positions at length, which it does for `rev`, `required` and `held`, and carries no dotted name,
    // which is the shape a second copy of the roster would take.
    expect(prose).not.toContain('The positions are');
    for (const position of INTEGER_POSITIONS.filter((each) => each.includes('.'))) {
      expect(prose, `the CDDL's prose carries ${position}, a copy of the roster the blocks already state`).not.toContain(
        `\`${position}\``,
      );
    }
    // JSON has one number type, so a projection cannot state this rule and does not pretend to.
    expect(shape.description).not.toMatch(/float/iu);
  });

  it('reuses the receipt’s envelope rather than restating it', () => {
    const receipt = readCddl();
    const packTag = required(/^Ashaveri-Pack = #6\.(\d+)\(/mu.exec(CDDL)?.[1], 'the pack declares no COSE tag');
    const receiptTag = required(/^Ashaveri-Receipt = #6\.(\d+)\(/mu.exec(receipt)?.[1], 'the receipt declares no COSE tag');
    expect(packTag, 'a pack is no longer a tagged COSE_Sign1').toBe(receiptTag);
    const packSignature = required(/signature: bstr \.size (\d+)/u.exec(CDDL)?.[1], 'the pack states no signature width');
    const receiptSignature = required(/signature: bstr \.size (\d+)/u.exec(receipt)?.[1], 'the receipt states no signature width');
    expect(packSignature, 'the two documents no longer sign with one curve').toBe(receiptSignature);
    expect(
      integerLabels(packRule(CDDL, 'Ashaveri-Pack-Protected-Header')).slice().sort((a, b) => a - b),
      'the two signed headers no longer carry the same three labels',
    ).toEqual(integerLabels(cddlRule(receipt, 'Ashaveri-Protected-Header')).slice().sort((a, b) => a - b));
    // And the one thing the two headers have to disagree about: the content type, which is how a reader
    // holding one signed document knows which of the two they are reading.
    const packTyp = labeledLiteral(packRule(CDDL, 'Ashaveri-Pack-Protected-Header'), 3);
    const receiptTyp = labeledLiteral(cddlRule(receipt, 'Ashaveri-Protected-Header'), 3);
    expect(receiptTyp, "the receipt's own type moved, and this file does not own it").toBe('ashaveri/receipt');
    expect(packTyp, 'the pack no longer says what it is').toBe('ashaveri/pack');
    expect(
      required(shape.properties.protectedHeader.properties?.typ, 'the twin projects no typ').const,
      'the twin writes a typ the CDDL does not declare',
    ).toBe(packTyp);
    expect(CDDL).not.toContain(receiptTyp);
    // The tag is one of the things a JSON projection cannot carry, and the projection says where a reader
    // learns it. The number is tied to the format rather than repeated here, so a tag moving in the
    // CDDL reddens the projection's sentence about it instead of leaving it confidently wrong.
    expect(
      shape.description,
      `the projection names no tag, or names one the format does not declare, which is ${packTag}`,
    ).toContain(`tag ${packTag}`);
    // The two envelope positions the twin writes as hex and the format writes as byte counts are tied
    // by the same numbers the map sweep uses. The envelope is an array and its header is numbered, so
    // the widths come off the text rather than off a member list, and the signature's own regex is the
    // one this case already reads for the two documents sharing a curve.
    widthTie(Number(packSignature), required(shape.properties.signature.pattern, 'the twin projects no signature'), 'the pack signature');
    const kidWidth = required(
      /4:\s*bstr \.size (\d+)/u.exec(packRule(CDDL, 'Ashaveri-Pack-Protected-Header'))?.[1],
      'the signed header declares no kid width',
    );
    widthTie(
      Number(kidWidth),
      required(shape.properties.protectedHeader.properties?.kid?.pattern, 'the twin projects no kid'),
      'the kid',
    );
  });

  it('leaves the envelope as open as it says it is, and refuses what the format does not', () => {
    // The looseness is a stated choice, so it is pinned from both ends: the projection requires two
    // members of an envelope the format builds from four, and the sentence in its own description is
    // what that gap answers to. Neither half is a discovery — remove the clause and the case that names
    // it goes red, and close the root or require the signature and the clause stops being true.
    const envelope = packDocument(CDDL);
    expect(outcome(envelope), 'a pack envelope with everything the format requires is refused').toBeNull();
    const unsigned = packDocument(CDDL);
    delete unsigned.signature;
    expect(outcome(unsigned), 'a projection that refuses an unsigned pack contradicts its own description').toBeNull();
    expect(
      required(shape.required, 'the projection names no required members at its root').slice().sort(),
      'the projection requires more of an envelope than it says it does',
    ).toEqual(['payload', 'protectedHeader']);
    expect(
      shape.additionalProperties,
      'the projection closes a root its own description says it leaves open',
    ).toBeUndefined();
    // And the format, which is the other half of the sentence: four elements, sixty-four bytes of
    // signature, a tag around the whole of it.
    const start = CDDL.indexOf('COSE_Sign1-Pack-COSE = [');
    if (start < 0) throw new Error(`the signed envelope is not declared in ${packCddlPath}`);
    const block = CDDL.slice(start, CDDL.indexOf('\n]', start));
    expect(
      block.split('\n').filter((line) => /^\s+\w+:/u.test(line)).length,
      'the signed envelope no longer carries four elements',
    ).toBe(4);
    expect(block).toContain('signature: bstr .size 64');
  });

  it('says each rule it states in one place', () => {
    const prose = cddlProse(CDDL);
    // The format's own claims, each said once: that the layout is ahead of any generator, that a
    // member has to earn its place against the receipts inside the container, that the walk rather than
    // the array orders them, and that a period the deployer states has no default behind it.
    saidOnce('the CDDL', prose, 'Nothing in this repository assembles a pack today');
    saidOnce('the CDDL', prose, 'the container is public whether or not the tool that fills it is');
    saidOnce('the CDDL', prose, 'Each member passed one test: a reader of the pack needs it, and no receipt inside the container carries it');
    saidOnce('the CDDL', prose, '`v` is the one member no walk consumes');
    saidOnce('the CDDL', prose, 'Order in the array bears nothing');
    saidOnce('the CDDL', prose, 'A pack of nothing has no first node');
    saidOnce('the CDDL', prose, 'Closure is one rule across this file and not a rule about one map');
    saidOnce('the CDDL', prose, 'One map a signer fills at will, and that is a decision rather than a gap');
    saidOnce('the CDDL', prose, 'this format supplies no default for it');
    saidOnce('the CDDL', prose, 'they are the authority and this file is wrong');
    // The relations between two members, said once in the format and named once in the projection as
    // belonging to the format. A rule the projection also states in its own words is a second voice for
    // a rule no JSON Schema keyword can check, and two voices is how the two files stop agreeing.
    saidOnce('the CDDL', prose, 'the rule is `at` never before `to`');
    saidOnce('the CDDL', prose, 'Both bounds bind the items');
    saidOnce('the CDDL', prose, '`held` is a count of seconds measured at `at`');
    saidOnce('the CDDL', prose, '`rev` is never after `at`');
    saidOnce('the CDDL', prose, 'No two items in a pack carry the same `id`');
    saidOnce('the CDDL', prose, 'is a rule a conforming reader enforces and this container cannot');
    saidOnce('the CDDL', prose, 'every instant this file names is a unix time no earlier than the epoch');
    // Two phrasings a later edit must not bring back: a pack whose items were ordered by their
    // position in the array, and a manifest that restated what the store's own window reports.
    expect(prose).not.toContain('in the order they appear in the array');
    expect(prose).not.toMatch(/\bis open\b/u);
    // The framing belongs to section 5.2 and to the published images, and the assertion here is only
    // that the format cites both by name. The format does restate the framing beside `PackItem` — the
    // field order for a verifier reading one file, and two widths the members themselves carry — so the
    // claim is not that the copy is absent. It is that the copy is tied: `pack-framing.test.ts` reads
    // the declared `prev` width and `id` ceiling out of the blocks below and rebuilds frames with them,
    // and the images those rebuilds answer to are byte-checked in
    // `packages/fixtures/test/chain-vectors.test.ts`, which is where a disagreement about an offset is
    // caught rather than here.
    expect(prose).toContain('section 5.2');
    expect(prose).toContain('packages/fixtures/data/chain-v1.json');

    const twin = shape.description;
    saidOnce(
      'the twin',
      twin,
      'The rules that hold between two members are not spelled out here because no keyword reaches them',
    );
    saidOnce('the twin', twin, 'The envelope above it is projected more loosely than the format writes it, and that is a decision rather than a gap');
    saidOnce('the twin', twin, 'Display-only projection of the signed COSE_Sign1 pack container');
    saidOnce('the twin', twin, "Closure is not the manifest's alone");
    saidOnce('the twin', twin, 'this definition carries no closure keyword');
    saidOnce('the twin', twin, "because the retention-duty registry is a reader's question rather than this file's");
    saidOnce('the twin', twin, 'Nothing in this repository assembles or reads a pack today');
    for (const nested of manifestNestedRules(CDDL)) {
      expect(twin.includes(`\`${nested.member}\``), `the twin names no ${nested.member}`).toBe(true);
    }
    saidOnce('the manifest definition', required(manifestDef.description, 'the manifest definition says nothing'), 'A pack manifest and nothing else');
    for (const { rule, def } of definitionsByRule(CDDL)) {
      if (rule === 'Ashaveri-Pack-Manifest') continue;
      expect(
        required(def.description, `${rule} in the twin says nothing about itself`),
        `${rule}'s own description reaches above its level`,
      ).not.toMatch(/additionalProperties|unevaluatedProperties/u);
    }
    // The keyword claim is made once, at the root, which is the one place that speaks below the
    // manifest map. A nested description repeating it is the second voice this file has seen the
    // receipt's twin have to be held out of.
    expect(twin).toContain('additionalProperties');
  });

  it('refuses to compile a keyword this schema does not define', () => {
    // The same text with `strict: false` compiles and silently drops the keyword, so this is the case
    // that shows strict mode is on.
    const misspelled = JSON.parse(readFileSync(packSchemaPath, 'utf8')) as { $defs: { hex32: Record<string, unknown> } };
    misspelled.$defs.hex32.patterntypo = misspelled.$defs.hex32.pattern;
    delete misspelled.$defs.hex32.pattern;
    expect(() => compile(misspelled)).toThrow(/unknown keyword/);
    expect(() => compile(JSON.parse(readFileSync(packSchemaPath, 'utf8')) as object)).not.toThrow();
  });
});
