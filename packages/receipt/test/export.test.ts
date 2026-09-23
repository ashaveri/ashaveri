import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha2.js';
import { Tag } from 'cbor2';
import { Ajv2020, type ValidateFunction } from 'ajv/dist/2020.js';
import { cddlRule, labeledMembers, memberDeclarations, readCddl, required } from './cddl.js';
import { COSE_HEADER_ALG, COSE_HEADER_CONTENT_TYPE, COSE_HEADER_KID } from '../src/cose.js';
import {
  DECLARED_EXPORT_PROTECTED_LABELS,
  EXPORT_ANCHORED_MEMBERS,
  EXPORT_ASSESSMENT_MEMBERS,
  EXPORT_CHAINED_ITEM_MEMBERS,
  EXPORT_CLAIM_MEMBERS,
  EXPORT_COMPANION_MEMBERS,
  EXPORT_CONTENT_TYPE,
  EXPORT_INLINE_MEMBERS,
  EXPORT_ITEM_MEMBERS,
  EXPORT_MANIFEST_MEMBERS,
  EXPORT_PLAIN_MEMBERS,
  EXPORT_VOID_MEMBERS,
  type ExportRead,
  decodeExport,
  encodeExportManifest,
  encodeExportProtectedHeader,
  exportRecordDigest,
  exportSigStructure,
  sealExport,
  signExport,
  verifyExport,
  type ExportAnchoredCollection,
  type ExportChainedItem,
  type ExportCollection,
  type ExportItem,
  type ExportManifest,
} from '../src/export.js';
import { ReceiptError } from '../src/errors.js';
import { decodeCanonical, encodeCanonical, signCoseSign1, signingKeyFromSeed, toHex, type SigningKey } from '../src/index.js';
import type { ReceiptErrorCode } from '../src/errors.js';

/**
 * The export contract held together: `export.cddl`, its JSON twin, and the reader in `src/export.ts`.
 *
 * Three statements of one layout, so three pairs of agreements, and every claim here is derivation. Which
 * members each map declares is read out of the CDDL; which definition of the twin stands behind each of
 * them is read out of the twin's own `$ref`s and `oneOf`s; and what the reader answers for a position is
 * asked of it with a document built out of the first two, never pasted from a projection that might itself
 * be wrong. A roster typed out in this file would keep passing the day the format gained a member, which is
 * the exact failure the sweeps exist to prevent.
 *
 * The reader's refusals are each reached by editing one position of one honest document and re-sealing it,
 * so the fault a case reports can only be the edit: an unsigned mutant would answer `INVALID_SIGNATURE` for
 * every position in the file, and the suite would be measuring the signature instead of the layout.
 *
 * `test/cddl.ts` supplies the block readers, which take a rule name and the text of any file and so serve a
 * third CDDL without change. What it does not supply is a path to it, so `exportRule` and its companions
 * below fix the file name in the message, and read the choice rules `cddlRule` cannot see.
 */
const exportCddlPath = fileURLToPath(new URL('../export.cddl', import.meta.url));
const exportSchemaPath = fileURLToPath(new URL('../schemas/export-v1.schema.json', import.meta.url));
const packSchemaPath = fileURLToPath(new URL('../schemas/pack-v1.schema.json', import.meta.url));
const packCddlPath = fileURLToPath(new URL('../pack.cddl', import.meta.url));

const CDDL = readFileSync(exportCddlPath, 'utf8');

/** The rosters `export.ts` claims, keyed by the name the bindings below use to look them up. */
const ROSTERS: Record<string, readonly string[]> = {
  MANIFEST_MEMBERS: EXPORT_MANIFEST_MEMBERS,
  ASSESSMENT_MEMBERS: EXPORT_ASSESSMENT_MEMBERS,
  CLAIM_MEMBERS: EXPORT_CLAIM_MEMBERS,
  ANCHORED_MEMBERS: EXPORT_ANCHORED_MEMBERS,
  PLAIN_MEMBERS: EXPORT_PLAIN_MEMBERS,
  VOID_MEMBERS: EXPORT_VOID_MEMBERS,
  ITEM_MEMBERS: EXPORT_ITEM_MEMBERS,
  CHAINED_ITEM_MEMBERS: EXPORT_CHAINED_ITEM_MEMBERS,
  INLINE_MEMBERS: EXPORT_INLINE_MEMBERS,
  COMPANION_MEMBERS: EXPORT_COMPANION_MEMBERS,
};

/** One map the format defines, the constant that claims its roster, and nothing else. */
interface MapBinding {
  readonly rule: string;
  readonly constant: string;
}

const CLOSED_MAPS: readonly MapBinding[] = [
  { rule: 'Ashaveri-Export-Manifest', constant: 'MANIFEST_MEMBERS' },
  { rule: 'ExportAssessment', constant: 'ASSESSMENT_MEMBERS' },
  { rule: 'ExportClaim', constant: 'CLAIM_MEMBERS' },
  { rule: 'ExportAnchoredCollection', constant: 'ANCHORED_MEMBERS' },
  { rule: 'ExportPlainCollection', constant: 'PLAIN_MEMBERS' },
  { rule: 'ExportVoidCollection', constant: 'VOID_MEMBERS' },
  { rule: 'ExportItem', constant: 'ITEM_MEMBERS' },
  { rule: 'ExportChainedItem', constant: 'CHAINED_ITEM_MEMBERS' },
  { rule: 'ExportInlineOriginal', constant: 'INLINE_MEMBERS' },
  { rule: 'ExportCompanionOriginal', constant: 'COMPANION_MEMBERS' },
];

/** One rule the CDDL opens as a map, with the file named when the rule is not there. */
function exportRule(cddl: string, rule: string): string {
  if (!cddl.includes(`${rule} = {`)) throw new Error(`${rule} is not declared in ${exportCddlPath}`);
  return cddlRule(cddl, rule);
}

/** The arms of a rule written as a choice between rules, which is how a shape is picked by its `k`. */
function exportChoiceArms(cddl: string, rule: string): string[] {
  const found = new RegExp(`^${rule} = ([A-Z][^\\n]+)$`, 'mu').exec(cddl);
  if (!found) throw new Error(`${rule} is not declared as a choice in ${exportCddlPath}`);
  const arms = found[1]!.split('/').map((arm) => arm.trim());
  if (arms.length < 2) throw new Error(`${rule} is a choice of ${String(arms.length)} rules, which is not a choice`);
  return arms;
}

function isChoiceRule(cddl: string, rule: string): boolean {
  return new RegExp(`^${rule} = [A-Z][^\\n]* /`, 'mu').test(cddl);
}

/** The `k` value one arm rule states, which is the label a document answers with. */
function armLabel(cddl: string, rule: string): string {
  const found = /^\s*k\s*:\s*"([^"]+)"/mu.exec(exportRule(cddl, rule));
  if (!found) throw new Error(`${rule} declares no arm label at k`);
  return found[1]!;
}

/** Which rule declares the arm a label names, so a twin arm and a CDDL block meet by name. */
function ruleForArmLabel(cddl: string, label: string): string {
  const hits = exportMapRuleNames(cddl).filter((rule) => {
    if (!cddl.includes(`${rule} = {`)) return false;
    return /^\s*k\s*:\s*"([^"]+)"/mu.exec(exportRule(cddl, rule))?.[1] === label;
  });
  if (hits.length !== 1) {
    throw new Error(`${String(hits.length)} rules of ${exportCddlPath} declare the arm label "${label}", and one is the only useful answer`);
  }
  return hits[0]!;
}

/** The labels one member's type expression enumerates, or null when it does not enumerate. */
function labelChoices(type: string): string[] | null {
  if (!/^\s*"[^"]+"(?:\s*\/\s*"[^"]+")*\s*$/.test(type)) return null;
  return type.split('/').map((piece) => piece.trim().replace(/^"|"$/gu, ''));
}

/** The members one block declares, and the run stops on a block that names none. */
function exportMembers(cddl: string, rule: string): string[] {
  const members = labeledMembers(exportRule(cddl, rule));
  if (members.length === 0) throw new Error(`the ${rule} block declares no members`);
  return members;
}

/** Every rule the file opens as a map, read off the text so a map added later is swept the day it lands. */
function exportMapRuleNames(cddl: string): string[] {
  const names: string[] = [];
  for (const line of cddl.split('\n')) {
    const found = /^([A-Za-z][A-Za-z0-9_-]*) = \{/u.exec(line);
    if (found) names.push(found[1]!);
  }
  if (names.length === 0) throw new Error(`no map rule is declared in ${exportCddlPath}`);
  return names;
}

/** The integer labels one block declares its members by, sign included. */
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
  const found = new RegExp(`^\\s*${String(label)}\\s*:\\s*"([^"]*)"`, 'mu').exec(block);
  if (!found) throw new Error(`the block carries no quoted value at label ${String(label)}`);
  return found[1]!;
}

/** One string for a whole document's line breaks, so a check pins a sentence and not a wrapping. */
function flat(text: string): string {
  return text.replace(/\s+/gu, ' ').trim();
}

/** The CDDL's full-line comments as prose, which is what a stranger reading the format actually reads. */
function cddlProse(cddl: string): string {
  return flat(cddl.split('\n').filter((line) => line.startsWith(';')).map((line) => line.slice(1)).join('\n'));
}

/**
 * `where` says `phrase` exactly once: zero is a document that stopped stating the rule, two is one that
 * started stating it in two voices. The name and the phrase ride along in the failure because a bare length
 * assertion cannot say which of the two texts went quiet.
 */
function saidOnce(where: string, text: string, phrase: string): void {
  const hits = text.split(phrase).length - 1;
  expect(hits, `${where} says "${phrase}" ${String(hits)} times, not once`).toBe(1);
}

interface ObjectSchema {
  $ref?: unknown;
  additionalProperties?: unknown;
  const?: unknown;
  description?: string;
  enum?: readonly unknown[];
  items?: ObjectSchema;
  minLength?: unknown;
  minItems?: unknown;
  oneOf?: ObjectSchema[];
  pattern?: unknown;
  properties?: Record<string, ObjectSchema>;
  required?: readonly string[];
  type?: unknown;
}

interface ExportSchemaShape {
  additionalProperties?: unknown;
  description: string;
  properties: { protectedHeader: ObjectSchema; payload: ObjectSchema; signature: ObjectSchema };
  required?: string[];
  $defs: Record<string, ObjectSchema>;
}

const shape = JSON.parse(readFileSync(exportSchemaPath, 'utf8')) as ExportSchemaShape;

/** The definition a `$ref` reaches, and the name it reaches it under. */
function referenced(schema: ObjectSchema, where: string): { name: string; def: ObjectSchema } {
  const ref = required(schema.$ref, `${where} is not a reference, so it binds to no definition`);
  if (typeof ref !== 'string') throw new Error(`${where} carries a $ref that is not text`);
  const name = required(/#\/\$defs\/(.+)$/u.exec(ref)?.[1], `${where} references ${ref}, which is not a pointer into $defs`);
  return { name, def: required(shape.$defs[name], `the twin has no ${name} definition to be found`) };
}

/** The arms of a twin choice, each resolved to the definition it points at and the name it uses. */
function choiceArmsOf(node: ObjectSchema, where: string): Array<{ name: string; def: ObjectSchema }> {
  const arms = required(node.oneOf, `${where} carries no oneOf, so a choice of the format has no twin`);
  return arms.map((arm) => referenced(arm, where));
}

const manifestDef = referenced(shape.properties.payload, 'the export payload').def;

/** The three collection arms and the two original arms, CDDL rule matched to twin definition. */
function armsOf(cddl: string, choiceRule: string, twinDefName: string): Array<{ rule: string; label: string; name: string; def: ObjectSchema }> {
  const rules = exportChoiceArms(cddl, choiceRule);
  const defs = choiceArmsOf(required(cdef(twinDefName), `the twin's ${twinDefName}`), `the ${twinDefName}`);
  expect(defs.length, `the twin offers a different number of ${choiceRule} arms than the format does`).toBe(rules.length);
  return rules.map((rule, index) => ({ rule, label: armLabel(cddl, rule), name: defs[index]!.name, def: defs[index]!.def }));
}

function cdef(name: string): ObjectSchema | undefined {
  return shape.$defs[name];
}

/** Which arm a choice position takes in a document this file builds. */
interface Arms {
  readonly collection: string;
  readonly original: string;
}

const COLLECTION_ARMS = exportChoiceArms(CDDL, 'ExportCollection').map((rule) => armLabel(CDDL, rule));
const ORIGINAL_ARMS = exportChoiceArms(CDDL, 'ExportOriginal').map((rule) => armLabel(CDDL, rule));

/** Every combination of the two choices, including the two a void collection never reaches. */
const ALL_COMBINATIONS: Arms[] = COLLECTION_ARMS.flatMap((collection) =>
  collection === 'void' ? [{ collection, original: 'inline' }] : ORIGINAL_ARMS.map((original) => ({ collection, original })),
);

/** Every closed map of this format with the definition of the twin that stands behind it. */
function definitionsByRule(cddl: string): Array<{ rule: string; name: string; def: ObjectSchema }> {
  const arms = armsOf(cddl, 'ExportCollection', 'collection');
  const items: Array<{ rule: string; armName: string }> = [];
  for (const arm of arms) {
    if (arm.rule === 'ExportVoidCollection') continue;
    const rule = elementRule(cddl, arm.rule);
    if (!items.some((one) => one.rule === rule)) items.push({ rule, armName: arm.name });
  }
  return [
    { rule: 'Ashaveri-Export-Manifest', name: 'manifest', def: manifestDef },
    { rule: 'ExportAssessment', ...referenced(required(manifestDef.properties?.assessment, 'the twin projects no assessment'), 'the manifest member assessment') },
    { rule: 'ExportClaim', ...referenced(required(manifestDef.properties?.claim, 'the twin projects no claim'), 'the manifest member claim') },
    ...arms.map((arm) => ({ rule: arm.rule, name: arm.name, def: arm.def })),
    ...items.map((one) => ({ rule: one.rule, ...elementSchemaOf(one.armName) })),
    ...armsOf(cddl, 'ExportOriginal', 'original').map((arm) => ({ rule: arm.rule, name: arm.name, def: arm.def })),
  ];
}

/** The element definition behind one collection arm's `items`. */
function elementSchemaOf(armName: string): { name: string; def: ObjectSchema } {
  const arm = required(shape.$defs[armName], `the twin has no ${armName} definition`);
  const items = required(arm.properties?.items, `${armName} declares no items`);
  return referenced(required(items.items, `${armName} gives its items no element schema`), `the ${armName} items`);
}

/** The CDDL rule one collection arm names behind its `items` member. */
function elementRule(cddl: string, collectionRule: string): string {
  for (const declared of memberDeclarations(exportRule(cddl, collectionRule))) {
    if (declared.name !== 'items') continue;
    const found = /^\[\+\s+([A-Z][A-Za-z0-9_-]*)\]$/u.exec(declared.type);
    if (found) return found[1]!;
    throw new Error(`${collectionRule}.items is declared as "${declared.type}", which is not an array of one rule`);
  }
  throw new Error(`${collectionRule} declares no items member`);
}

/** A number of bytes, as this estate's projections write a byte string: lowercase hex. */
function hexOf(bytes: number): string {
  return 'ab'.repeat(bytes);
}

/** One one-byte value for a whole number, which no position of this format may be. */
const AN_INT = 1_772_000_000;

/** The type `export.cddl` writes for a number position that is not left to a reader's judgement. */
const INTEGER_TYPE = /^(?:int|-?\d+)$/u;

/**
 * A value of the type expression one member declares. An expression this builder cannot fill stops the
 * run: a member quietly left out of the built document would be a member the twin never had to answer for,
 * and the point of building the document out of the format is that it cannot be quiet about a position the
 * format gained.
 */
function valueForType(cddl: string, type: string, arms: Arms, position: string): unknown {
  const literal = /^(-?\d+)$/u.exec(type);
  if (literal) return Number(literal[1]);
  if (type === 'int') return AN_INT;
  const labels = labelChoices(type);
  if (labels !== null) return labels[0];
  const many = /^\[\+\s+([A-Z][A-Za-z0-9_-]*)\]$/u.exec(type);
  if (many) return [instanceOfRule(cddl, many[1]!, arms, `${position}[*]`)];
  const one = /^([A-Z][A-Za-z0-9_-]*)$/u.exec(type);
  if (one) {
    const rule = one[1]!;
    if (isChoiceRule(cddl, rule)) {
      const wanted = rule === 'ExportCollection' ? arms.collection : arms.original;
      return instanceOfRule(cddl, ruleForArmLabel(cddl, wanted), arms, position);
    }
    return instanceOfRule(cddl, rule, arms, position);
  }
  const sized = /^bstr \.size (\d+)$/u.exec(type);
  if (sized) return hexOf(Number(sized[1]));
  if (/^bstr \.cbor [A-Z][A-Za-z0-9_-]*$/u.test(type)) return hexOf(4);
  if (type === 'bstr') return hexOf(4);
  if (/^tstr \.size \(\d+\.\.\d+\)$/u.test(type)) return 'a-name';
  if (type === 'tstr') return 'a-label';
  throw new Error(`this builder fills no value of the type expression "${type}" at ${position}`);
}

/** A map the format declares, built member by member out of its own declarations. */
function instanceOfRule(cddl: string, rule: string, arms: Arms, position: string): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const member of memberDeclarations(exportRule(cddl, rule))) {
    out[member.name] = valueForType(cddl, member.type, arms, position === '' ? member.name : `${position}.${member.name}`);
  }
  if (Object.keys(out).length === 0) throw new Error(`${rule} declares no member to build a value of`);
  return out;
}

/**
 * The envelope half of the document, read off the twin rather than written out: three members, two of them
 * fixed values and one a keyed digest. Deriving it weakens nothing that matters, because the payload comes
 * from the CDDL and the header holds the COSE registry's names for three parameters this format did not
 * choose.
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

function exportDocument(arms: Arms): Record<string, unknown> {
  return {
    protectedHeader: headerDocument(),
    payload: instanceOfRule(CDDL, 'Ashaveri-Export-Manifest', arms, ''),
    signature: hexOf(64),
  };
}

/**
 * Compiles a twin with Ajv's strict mode on, so a keyword the schema does not define fails at compile time
 * instead of being ignored. No `format` appears in either file, so there is nothing here to give a
 * validator that accepts everything.
 */
function compile(s: object): ValidateFunction<unknown> {
  const ajv = new Ajv2020({ strict: true });
  return ajv.compile(s);
}

const validate = compile(shape);
const validatePack = compile(JSON.parse(readFileSync(packSchemaPath, 'utf8')) as object);

function outcome(value: unknown, check: ValidateFunction<unknown> = validate): string | null {
  return check(value) ? null : JSON.stringify(check.errors);
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

/** Where each closed map sits in a document of the given arms, derived from the CDDL's own nesting. */
function closedLevels(arms: Arms): Array<{ rule: string; path: (string | number)[] }> {
  const collectionRule = ruleForArmLabel(CDDL, arms.collection);
  const levels: Array<{ rule: string; path: (string | number)[] }> = [
    { rule: 'Ashaveri-Export-Manifest', path: ['payload'] },
    { rule: 'ExportAssessment', path: ['payload', 'assessment'] },
    { rule: 'ExportClaim', path: ['payload', 'claim'] },
    { rule: collectionRule, path: ['payload', 'collection'] },
  ];
  if (arms.collection === 'void') return levels;
    const itemsRule = elementRule(CDDL, collectionRule);
  levels.push({ rule: itemsRule, path: ['payload', 'collection', 'items', 0] });
  levels.push({ rule: ruleForArmLabel(CDDL, arms.original), path: ['payload', 'collection', 'items', 0, 'orig'] });
  return levels;
}

/** The rules one member's type expression reaches, through an array of them or a choice between them. */
function referencedRules(cddl: string, type: string): string[] {
  const array = /^\[\+\s+([A-Z][A-Za-z0-9_-]*)\]$/u.exec(type);
  if (array) return [array[1]!];
  if (/^[A-Z][A-Za-z0-9_-]*$/u.test(type)) {
    return isChoiceRule(cddl, type) ? exportChoiceArms(cddl, type) : [type];
  }
  return [];
}

/**
 * Every position the format types as an integer, with the dotted name a reader of a document uses. The
 * expansion follows the CDDL's own members, so a map gaining an integer arrives in this list with no edit
 * below, and the sweep that holds the format and the reader to the rule is asked about every position the
 * format has rather than about a roster somebody remembered.
 */
function integerPositions(cddl: string): string[] {
  const positions: string[] = [];
  const walk = (rule: string, prefix: string, depth: number): void => {
    if (depth > 5) throw new Error(`${rule} is nested deeper than this reader expands`);
    for (const member of memberDeclarations(exportRule(cddl, rule))) {
      const path = prefix === '' ? member.name : `${prefix}.${member.name}`;
      if (INTEGER_TYPE.test(member.type)) {
        if (!positions.includes(path)) positions.push(path);
        continue;
      }
      for (const inner of referencedRules(cddl, member.type)) walk(inner, path, depth + 1);
    }
  };
  walk('Ashaveri-Export-Manifest', '', 0);
  if (positions.length === 0) throw new Error(`no position of ${exportCddlPath} is typed as an integer`);
  return positions;
}

/**
 * The byte ceilings the format writes beside each text position, read off the declarations rather than kept
 * beside the reader, so the constants in `export.ts` are tied to the file that states them.
 */
function textCeilings(cddl: string): Array<{ rule: string; member: string; max: number }> {
  const out: Array<{ rule: string; member: string; max: number }> = [];
  for (const rule of exportMapRuleNames(cddl)) {
    for (const member of memberDeclarations(exportRule(cddl, rule))) {
      const found = /^tstr \.size \((\d+)\.\.(\d+)\)$/u.exec(member.type);
      if (!found) continue;
      out.push({ rule, member: member.name, max: Number(found[2]) });
    }
  }
  if (out.length === 0) throw new Error(`no text position of ${exportCddlPath} states a byte ceiling`);
  return out;
}

const INTEGER_POSITIONS = integerPositions(CDDL);
const CEILINGS = textCeilings(CDDL);
const PROSE = cddlProse(CDDL);

describe('the export CDDL and its JSON twin', () => {
  it('closes every map the format declares, and names the one map it leaves free', () => {
    const labeled: string[] = [];
    const unlabeled: string[] = [];
    for (const rule of exportMapRuleNames(CDDL)) {
      expect(exportRule(CDDL, rule).includes('...'), `${rule} carries an open member`).toBe(false);
      if (labeledMembers(exportRule(CDDL, rule)).length === 0) unlabeled.push(rule);
      else labeled.push(rule);
    }
    // The exemption, stated rather than inferred: the signed header spells its members by the COSE
    // registry's integers, so a reader of text labels sees none of them.
    expect(unlabeled, 'rules whose members this reader does not read as labels').toEqual(['Ashaveri-Export-Protected-Header']);
    expect(labeled.sort(), 'the maps the format closes').toEqual(CLOSED_MAPS.map((one) => one.rule).sort());

    // The reader's own rosters, held against the blocks they claim to be: a constant that kept an old name
    // or dropped a new one is the second voice this file exists to silence.
    for (const binding of CLOSED_MAPS) {
      expect([...required(ROSTERS[binding.constant], `no roster is claimed under ${binding.constant}`)], `export.ts's EXPORT_${binding.constant} is not the ${binding.rule} roster`).toEqual(exportMembers(CDDL, binding.rule));
    }

    expect(integerLabels(exportRule(CDDL, 'Ashaveri-Export-Protected-Header')).slice().sort((a, b) => a - b)).toEqual([1, 3, 4]);
    expect([...DECLARED_EXPORT_PROTECTED_LABELS].sort((a, b) => a - b)).toEqual([COSE_HEADER_ALG, COSE_HEADER_CONTENT_TYPE, COSE_HEADER_KID]);
    expect(CDDL).toContain('unprotected: { * any => any }');
    expect(CDDL).not.toMatch(/unprotected: \{\}/u);

    for (const { rule, def } of definitionsByRule(CDDL)) {
      expect(def.additionalProperties, `${rule} in the twin does not name its members as the whole of it`).toBe(false);
    }
    // The two choice definitions close through their arms and carry no members of their own, which is where
    // a `k` that landed in the wrong arm would otherwise be read and dropped.
    for (const name of ['collection', 'original']) {
      const choice = required(cdef(name), `the twin has no ${name} definition`);
      expect(choice.properties, `${name} names members above the arms that carry them`).toBeUndefined();
      expect(choice.additionalProperties, `${name} carries a closure keyword no arm needs`).toBeUndefined();
      for (const arm of choiceArmsOf(choice, `the ${name}`)) {
        expect(arm.def.additionalProperties, `${arm.name} does not close`).toBe(false);
      }
    }
    expect(
      shape.properties.protectedHeader.additionalProperties,
      'the projection of the signed header carries an `additionalProperties`, which its description says it does not',
    ).toBeUndefined();
  });

  it('declares the members the twin names, at every map and every arm', () => {
    for (const { rule, def } of definitionsByRule(CDDL)) {
      const declared = exportMembers(CDDL, rule);
      const projected = Object.keys(required(def.properties, `${rule} in the twin declares no properties`));
      expect(projected, `the twin's ${rule} members are not the ones ${rule} declares`).toEqual(declared);
      // Every member of this format is required by the arm that carries it: no position is optional, none
      // carries a default, and a reader never has to work out what an omitted field meant.
      expect(def.required, `${rule} in the twin does not require every member it names`).toEqual(projected);
      for (const member of memberDeclarations(exportRule(CDDL, rule))) {
        const definition = required(def.properties?.[member.name], `${rule}.${member.name} is declared and not projected`);
        if (INTEGER_TYPE.test(member.type)) {
          if (member.name === 'v') {
            expect(definition.const, `${rule}.v is not fixed at ${member.type} in the twin`).toBe(Number(member.type));
          } else {
            expect(definition.type, `${rule}.${member.name} is not an integer in the twin`).toBe('integer');
          }
        }
        const labels = labelChoices(member.type);
        if (labels !== null) {
          // The claim's two kinds are one enum, and every other label position fixes a `const` per arm,
          // which is what makes a `k` a shape and not a value.
          if (labels.length > 1) {
            expect(definition.enum, `${rule}.${member.name} is a label choice the twin does not enumerate`).toEqual(labels);
          } else {
            expect(definition.const, `${rule}.${member.name} is not fixed at ${String(labels[0])} in the twin`).toBe(labels[0]);
          }
        }
        const declaredWidth = /^bstr \.size (\d+)$/u.exec(member.type);
        if (declaredWidth) {
          const bytes = Number(declaredWidth[1]);
          const target = typeof definition.$ref === 'string' ? referenced(definition, `${rule}.${member.name}`) : { name: `${rule}.${member.name}`, def: definition };
          widthTie(bytes, required(target.def.pattern, `${target.name} carries no pattern to tie to the format`), `${rule}.${member.name} through ${target.name}`);
        }
        const ceiling = /^tstr \.size \((\d+)\.\.(\d+)\)$/u.exec(member.type);
        if (ceiling) {
          expect(definition.minLength, `${rule}.${member.name} does not state the floor the format gives it`).toBe(Number(ceiling[1]));
        }
        if (/^\[\+\s+[A-Z]/u.test(member.type)) {
          expect(definition.type, `${rule}.${member.name} is not an array in the twin`).toBe('array');
          expect(definition.minItems, `${rule}.${member.name} does not require an element`).toBe(1);
        }
        if (member.type === 'bstr') {
          const target = referenced(definition, `${rule}.${member.name}`);
          expect(target.def.pattern, `${rule}.${member.name} is projected as something other than byte strings`).toBe('^([0-9a-f]{2})+$');
        }
        if (member.type === 'tstr') {
          expect(definition.type, `${rule}.${member.name} is not a string in the twin`).toBe('string');
        }
      }
    }

    // The twin's objects with members are exactly the maps the format's rules are, arms included, and the
    // rest are the two choices and the two hex helpers, named here rather than inferred.
    const withMembers = Object.keys(shape.$defs)
      .filter((name) => cdef(name)?.properties !== undefined)
      .sort();
    expect(withMembers, 'the twin and the format do not name the same maps').toEqual(definitionsByRule(CDDL).map(({ name }) => name).sort());
    expect(
      Object.keys(shape.$defs).filter((name) => cdef(name)?.oneOf !== undefined).sort(),
      'the choices of the twin are not the two the format writes',
    ).toEqual(['collection', 'original']);
    expect(
      Object.keys(shape.$defs).filter((name) => cdef(name)?.oneOf === undefined && cdef(name)?.properties === undefined).sort(),
      'the twin carries a helper definition no arm of this list explains',
    ).toEqual(['hex32', 'hexBytes']);

    const reached = new Set<string>(withMembers);
    for (const { def } of definitionsByRule(CDDL)) {
      for (const member of Object.values(required(def.properties, 'a definition with no properties'))) {
        if (typeof member.$ref === 'string') reached.add(/#\/\$defs\/(.+)$/u.exec(member.$ref)?.[1] ?? member.$ref);
        if (typeof member.items?.$ref === 'string') reached.add(/#\/\$defs\/(.+)$/u.exec(member.items.$ref)?.[1] ?? member.items.$ref);
      }
    }
    for (const name of ['collection', 'original']) {
      for (const arm of choiceArmsOf(required(cdef(name), name), name)) reached.add(arm.name);
    }
    expect([...reached].sort(), 'the twin declares a definition no member reaches').toEqual(Object.keys(shape.$defs).sort());
  });

  it('accepts the document every arm declares and refuses one member more at every level', () => {
    for (const arms of ALL_COMBINATIONS) {
      const document = exportDocument(arms);
      const label = `${arms.collection} collection, ${arms.original} original`;
      expect(outcome(document), `an export built from the declared members is refused (${label})`).toBeNull();
      // Each case adds one member to one map and nothing else, so a refusal cannot have arrived for any
      // other reason. Delete an `additionalProperties` from the twin and only the second half of each pair
      // goes red, which is the point: the case tests the keyword and not the document.
      for (const { rule, path } of closedLevels(arms)) {
        const edited = structuredClone(document);
        mapAt(edited, path).surprise = 'x';
        expect(outcome(edited), `${rule} carrying a member the format does not name (${label})`).not.toBeNull();
      }
    }
    // The item array is closed at both ends: an element is a map the format names, and a count of them is a
    // claim, so an empty one is refused under the arms that carry material.
    for (const label of ['anchored', 'plain']) {
      const document = exportDocument({ collection: label, original: 'inline' });
      mapAt(document, ['payload', 'collection']).items = [];
      expect(outcome(document), `an export under ${label} carrying no items is accepted`).not.toBeNull();
    }
    // And the two arms are exclusive, which is what a `k` is for: a document holding both an endpoint pair
    // and no items array is neither shape.
    const mixed = exportDocument({ collection: 'anchored', original: 'inline' });
    delete mapAt(mixed, ['payload', 'collection']).items;
    expect(outcome(mixed), 'one arm of a choice accepted a document from another').not.toBeNull();
  });

  it('defines no legal category anywhere, and says the assessment is the only statement', () => {
    // The names are the substance of the promise: a member called `duty`, `article`, `required`, `held`,
    // `met`, `qualification` or `period` would be this format answering the question it says it does not.
    const declared: string[] = [];
    for (const { rule } of definitionsByRule(CDDL)) declared.push(...exportMembers(CDDL, rule));
    for (const name of ['duty', 'article', 'law', 'required', 'held', 'met', 'qualification', 'period', 'category', 'mapping']) {
      expect(declared, `the format declares a member named ${name}`).not.toContain(name);
    }
    // The only enumeration in the twin, and it is not a legal label; the assessment's one statement is a
    // const per arm, not an enum, so a later version adds an arm rather than widening a list in place.
    const enums = Object.entries(shape.$defs)
      .flatMap(([name, def]) => Object.entries(def.properties ?? {}).filter(([, child]) => child.enum !== undefined).map(([key]) => `${name}.${key}`))
      .sort();
    expect(enums, 'the twin enumerates a label position beyond the claim kind').toEqual(['claim.kind']);
    expect(shape.$defs.claim?.properties?.kind?.enum).toEqual(['provenance', 'custody']);
    expect(shape.$defs.assessment?.properties?.k?.const).toBe('none');
    expect(shape.$defs.assessment?.properties?.states?.minLength, 'the statement may be empty, which is the silence this block refuses').toBe(1);
    expect(required(shape.$defs.assessment?.description, 'the assessment says nothing about itself')).toContain('no legal vocabulary');
    saidOnce('the twin', shape.description, 'No legal vocabulary is defined in it');

    saidOnce('the CDDL', PROSE, 'No legal vocabulary is defined here');
    saidOnce('the CDDL', PROSE, 'its kind is chosen from two labels');
    saidOnce('the CDDL', PROSE, 'Nothing here is a legal category');
    // Two phrasings a later edit must not bring back: an assessment stated by leaving something out, and a
    // claim about the material that the signature was made to establish.
    expect(PROSE).not.toContain('an absent assessment');
    expect(PROSE).not.toContain('proves the material is lawful');
  });

  it('types every number it declares as an integer, and says the rule once', () => {
    saidOnce('the CDDL', PROSE, 'is a CBOR integer, major type 0 or 1, and no other major type carries one');
    saidOnce('the CDDL', PROSE, 'in a value and in a key alike');
    // Two at the manifest level, one inside an item of either arm, and one below the claim: the version and
    // the stamps are the whole of what this format types as a number, in the order the blocks reach them.
    expect(INTEGER_POSITIONS).toEqual(['v', 'at', 'collection.items.iat', 'claim.made']);
    const declarations = CDDL.split('\n')
      .filter((line) => !line.startsWith(';'))
      .join('\n');
    expect(declarations).not.toMatch(/\b(?:uint\d*|nint|biguint|bigint|float\d*)\b/u);
    expect(PROSE).not.toContain('The positions are');
    for (const position of INTEGER_POSITIONS.filter((each) => each.includes('.'))) {
      expect(PROSE, `the CDDL's prose carries ${position}, a copy of the roster the blocks state`).not.toContain(`\`${position}\``);
    }
    // JSON has one number type, so a projection cannot state this rule and does not pretend to.
    expect(shape.description).not.toMatch(/float/iu);
  });

  it('reuses the envelope the receipt and the pack use, and differs on the content type', () => {
    const receipt = readCddl();
    const pack = readFileSync(packCddlPath, 'utf8');
    const exportTag = required(/^Ashaveri-Export = #6\.(\d+)\(/mu.exec(CDDL)?.[1], 'the export declares no COSE tag');
    expect(exportTag, 'an export is no longer a tagged COSE_Sign1').toBe(required(/^Ashaveri-Receipt = #6\.(\d+)\(/mu.exec(receipt)?.[1], 'the receipt declares no tag'));
    expect(exportTag).toBe(required(/^Ashaveri-Pack = #6\.(\d+)\(/mu.exec(pack)?.[1], 'the pack declares no tag'));
    const exportSignature = required(/signature: bstr \.size (\d+)/u.exec(CDDL)?.[1], 'the export states no signature width');
    expect(exportSignature, 'the three documents no longer sign with one curve').toBe(required(/signature: bstr \.size (\d+)/u.exec(receipt)?.[1], 'the receipt states none'));
    expect(
      integerLabels(exportRule(CDDL, 'Ashaveri-Export-Protected-Header')).slice().sort((a, b) => a - b),
      'the three signed headers no longer carry the same three labels',
    ).toEqual(integerLabels(cddlRule(receipt, 'Ashaveri-Protected-Header')).slice().sort((a, b) => a - b));

    const exportTyp = labeledLiteral(exportRule(CDDL, 'Ashaveri-Export-Protected-Header'), 3);
    const packTyp = labeledLiteral(cddlRule(pack, 'Ashaveri-Pack-Protected-Header'), 3);
    const receiptTyp = labeledLiteral(cddlRule(receipt, 'Ashaveri-Protected-Header'), 3);
    expect(exportTyp, 'the export no longer says what it is').toBe('ashaveri/export');
    expect(exportTyp).toBe(EXPORT_CONTENT_TYPE);
    expect(new Set([exportTyp, packTyp, receiptTyp]).size, 'two of the three containers now share a content type').toBe(3);
    expect(
      required(shape.properties.protectedHeader.properties?.typ, 'the twin projects no typ').const,
      'the twin writes a typ the CDDL does not declare',
    ).toBe(exportTyp);
    expect(CDDL).not.toContain(receiptTyp);
    expect(CDDL).not.toContain(packTyp);

    // The signed envelope is an array of four and a sixty-four byte signature, as the other two files write
    // it, and the projection is looser than the format on purpose.
    const start = CDDL.indexOf('COSE_Sign1-Export-COSE = [');
    if (start < 0) throw new Error(`the signed envelope is not declared in ${exportCddlPath}`);
    const block = CDDL.slice(start, CDDL.indexOf('\n]', start));
    expect(block.split('\n').filter((line) => /^\s+\w+:/u.test(line)).length, 'the signed envelope no longer carries four elements').toBe(4);
    expect(block).toContain('signature: bstr .size 64');
    widthTie(Number(exportSignature), required(shape.properties.signature.pattern, 'the twin projects no signature'), 'the export signature');
    const kidWidth = required(/4:\s*bstr \.size (\d+)/u.exec(exportRule(CDDL, 'Ashaveri-Export-Protected-Header'))?.[1], 'the signed header declares no kid width');
    widthTie(Number(kidWidth), required(shape.properties.protectedHeader.properties?.kid?.pattern, 'the twin projects no kid'), 'the kid');
    const unsigned = exportDocument({ collection: 'anchored', original: 'inline' });
    delete unsigned.signature;
    expect(outcome(unsigned), 'a projection that refuses an unsigned export contradicts its own description').toBeNull();
    expect(required(shape.required, 'the projection names no required members at its root').slice().sort()).toEqual(['payload', 'protectedHeader']);
    expect(shape.additionalProperties, 'the projection closes a root its own description says it leaves open').toBeUndefined();
  });

  it('separates the two item rules by exactly the predecessor, and the arms by their labels', () => {
    const plain = exportMembers(CDDL, 'ExportItem');
    const chained = exportMembers(CDDL, 'ExportChainedItem');
    expect(chained.filter((name) => !plain.includes(name)), 'the anchored item adds a position').toEqual(['p']);
    expect(plain.filter((name) => !chained.includes(name)), 'the plain item has a position the anchored one lacks').toEqual([]);
    expect(chained.filter((name) => plain.includes(name)), 'the shared positions changed order between the two rules').toEqual(plain);
    // The same is true of the twin, so neither file can move a roster without the other noticing.
    const chainedProjected = Object.keys(required(cdef('chainedItem'), 'the twin has no chained item').properties ?? {});
    const plainProjected = Object.keys(required(cdef('item'), 'the twin has no item').properties ?? {});
    expect(chainedProjected.filter((name) => !plainProjected.includes(name)), 'the chained item of the twin adds a position of its own').toEqual(['p']);
    expect(chainedProjected.filter((name) => plainProjected.includes(name)), 'the shared positions moved order in the twin').toEqual(plainProjected);

    const arms = armsOf(CDDL, 'ExportCollection', 'collection');
    expect(arms.map((one) => one.label)).toEqual(COLLECTION_ARMS);
    // Only the anchored arm carries the two endpoints, and no other arm can reach them.
    expect(arms.map((one) => Object.keys(one.def.properties ?? {}))).toEqual([
      ['k', 'anchor', 'head', 'items'],
      ['k', 'items'],
      ['k', 'states'],
    ]);
    expect(COLLECTION_ARMS).toEqual(['anchored', 'plain', 'void']);
    expect(ORIGINAL_ARMS).toEqual(['inline', 'companion']);
  });

  it('states the framing it reuses, the walk it bounds, and each rule once', () => {
    saidOnce('the CDDL', PROSE, 'is section 5.2 of');
    expect(PROSE).toContain('packages/fixtures/data/chain-v1.json');
    saidOnce('the CDDL', PROSE, 'What a completed walk does not establish');
    saidOnce('the CDDL', PROSE, 'It is not proof that the source is complete');
    saidOnce('the CDDL', PROSE, 'not proof of freshness');
    saidOnce('the CDDL', PROSE, 'not a verification of the receipts inside it');
    saidOnce('the CDDL', PROSE, 'An empty collection has an explicit outcome');
    saidOnce('the CDDL', PROSE, 'the opposite of pack v1');
    saidOnce('the CDDL', PROSE, 'Closure is one rule across this file and not a rule about one map');
    saidOnce('the CDDL', PROSE, 'One map a signer fills at will, and that is a decision rather than a gap');
    saidOnce('the CDDL', PROSE, 'Two differences make a new pack version the wrong instrument');
    saidOnce('the CDDL', PROSE, 'nothing a reader verifies');
    expect(PROSE).not.toMatch(/\bis open\b/u);
    // The twin hands the between-member rules to the format, once, and the format carries them.
    saidOnce('the twin', shape.description, 'The rules that hold between two members are not spelled out here because no keyword reaches them');
    saidOnce('the twin', shape.description, 'The envelope above it is projected more loosely than the format writes it, and that is a decision rather than a gap');
    saidOnce('the twin', shape.description, 'Display-only projection of the signed COSE_Sign1 export container');
    saidOnce('the twin', shape.description, "Closure is not the manifest's alone");
    saidOnce('the twin', shape.description, 'this definition carries no closure keyword');
    for (const nested of ['assessment', 'collection', 'claim']) {
      expect(shape.description.includes(`\`${nested}\``), `the twin names no ${nested}`).toBe(true);
    }
    for (const { rule, def } of definitionsByRule(CDDL)) {
      if (rule === 'Ashaveri-Export-Manifest') continue;
      expect(required(def.description, `${rule} in the twin says nothing about itself`), `${rule}'s own description reaches above its level`).not.toMatch(/additionalProperties|unevaluatedProperties/u);
    }
    expect(shape.description).toContain('additionalProperties');
    expect(shape.description).toContain('export.cddl');
  });

  it('refuses to compile a keyword this schema does not define', () => {
    // The same text with `strict: false` compiles and silently drops the keyword, so this is the case that
    // shows strict mode is on.
    const misspelled = JSON.parse(readFileSync(exportSchemaPath, 'utf8')) as { $defs: { hex32: Record<string, unknown> } };
    misspelled.$defs.hex32.patterntypo = misspelled.$defs.hex32.pattern;
    delete misspelled.$defs.hex32.pattern;
    expect(() => compile(misspelled)).toThrow(/unknown keyword/u);
    expect(() => compile(JSON.parse(readFileSync(exportSchemaPath, 'utf8')) as object)).not.toThrow();
  });
});

function widthTie(bytes: number, pattern: unknown, position: string): void {
  expect(pattern, `${position} is ${String(bytes)} bytes in the format, so the twin's pattern is ${String(bytes * 2)} hex digits`).toBe(`^[0-9a-f]{${String(bytes * 2)}}$`);
}

/* -------------------------------------------------------------------------- */
/* The documents every reader case edits by one position.                       */
/* -------------------------------------------------------------------------- */

const KEY = signingKeyFromSeed(new Uint8Array(32).fill(11));
const CLOCK = AN_INT;

function bytesOf(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

function manifest(over: Partial<ExportManifest> = {}): ExportManifest {
  return {
    v: 1,
    at: CLOCK,
    assessment: { k: 'none', states: 'no legal assessment was made of this material' },
    collection: plainCollection('inline'),
    claim: { made: CLOCK - 60, by: 'Amir, on the record', kind: 'provenance', states: 'gathered from one store and copied by hand' },
    ...over,
  };
}

function inlineItem(id: string, iat: number, text: string): ExportItem {
  const bytes = bytesOf(text);
  return { id, iat, d: sha256(bytes), orig: { k: 'inline', bytes } };
}

/** The companion names this file builds, and the bytes a reader would be handed for each. */
const COMPANIONS: ReadonlyMap<string, string> = new Map([
  ['contract.pdf', 'contract text'],
  ['screenshot.png', 'ticket image'],
]);

function companionItem(id: string, iat: number, name: string): ExportItem {
  const text = COMPANIONS.get(name);
  if (text === undefined) throw new Error(`no companion named ${name} is built by this file`);
  return { id, iat, d: sha256(bytesOf(text)), orig: { k: 'companion', name } };
}

function plainCollection(arm: string): ExportCollection {
  const items = arm === 'inline' ? [inlineItem('item-0', CLOCK - 30, 'contract text'), inlineItem('item-1', CLOCK - 20, 'ticket image')] : [companionItem('item-0', CLOCK - 30, 'contract.pdf'), companionItem('item-1', CLOCK - 20, 'screenshot.png')];
  return { k: 'plain', items };
}

/** The framing's own byte layout, rebuilt here so the reader's function is compared against a second source. */
function framingInput(id: string, iat: number, prev: Uint8Array, payload: Uint8Array): Uint8Array {
  const name = new TextEncoder().encode(id);
  const out = new Uint8Array(1 + 32 + 8 + 2 + name.length + payload.length);
  const view = new DataView(out.buffer);
  out[0] = 0;
  out.set(prev, 1);
  view.setBigUint64(9, BigInt(iat));
  view.setUint16(17, name.length);
  out.set(name, 19);
  out.set(payload, 19 + name.length);
  return out;
}

/** Three records chained in order from an empty anchor, with the head the last of them hashes to. */
function anchoredCollection(): ExportAnchoredCollection {
  const texts = ['first receipt', 'second receipt', 'third receipt'];
  let prev: Uint8Array = new Uint8Array(32);
  const items: ExportChainedItem[] = texts.map((text, index) => {
    const bytes = bytesOf(text);
    const one: ExportChainedItem = { id: `r-${String(index)}`, iat: CLOCK + index, d: sha256(bytes), p: prev, orig: { k: 'inline', bytes } };
    prev = exportRecordDigest({ id: one.id, iat: one.iat, p: one.p, bytes });
    return one;
  });
  return { k: 'anchored', anchor: new Uint8Array(32), head: prev, items };
}

function sealedManifest(arms: string, original = 'inline'): Uint8Array {
  return signExport(manifest({ collection: collectionFor(arms, original) }), KEY);
}

function collectionFor(arms: string, original: string): ExportCollection {
  if (arms === 'void') return { k: 'void', states: 'nothing was carried out of the store' };
  if (arms === 'anchored') return anchoredCollection();
  return plainCollection(original);
}

/**
 * The manifest map of a sealed document, edited, re-encoded and re-signed: one fault, which is the edit,
 * with nothing else moved and the signature still good. Without the re-seal every structural case below
 * would be answered `INVALID_SIGNATURE` and the suite would measure the signature instead of the layout.
 */
function editSealed(bytes: Uint8Array, mutate: (root: Map<unknown, unknown>) => void): Uint8Array {
  const root = decodeCanonical(payloadOf(bytes));
  if (!(root instanceof Map)) throw new Error('the document this file builds has no manifest map to edit');
  mutate(root);
  return sealWithKey(encodeCanonical(root), KEY);
}

function sealWithKey(payloadBytes: Uint8Array, key: SigningKey): Uint8Array {
  const header = encodeExportProtectedHeader(key.kid);
  return sealExport(header, payloadBytes, ed25519.sign(exportSigStructure(header, payloadBytes), key.privateKey));
}

/** The four elements of a sealed envelope, read back for the cases that rebuild one around a piece. */
function elementsOf(bytes: Uint8Array): unknown[] {
  const top = decodeCanonical(bytes);
  const contents = (top as { contents?: unknown }).contents;
  if (!Array.isArray(contents)) throw new Error('the document this file builds is not a four-element envelope');
  return contents;
}

function payloadOf(bytes: Uint8Array): Uint8Array {
  return elementsOf(bytes)[2] as Uint8Array;
}

function child(value: unknown, key: string | number): unknown {
  if (value instanceof Map) return value.get(key);
  if (Array.isArray(value)) return value[Number(key)];
  throw new Error(`${String(key)} is not a member of anything this case edits`);
}

function itemOf(root: Map<unknown, unknown>, index: number): Map<unknown, unknown> {
  const items = child(child(root, 'collection'), 'items');
  const one = Array.isArray(items) ? items[index] : undefined;
  if (!(one instanceof Map)) throw new Error(`the built document carries no item at ${String(index)}`);
  return one;
}

function mapOf(value: unknown, position: string): Map<unknown, unknown> {
  if (!(value instanceof Map)) throw new Error(`${position} is not a map in the document this case builds`);
  return value;
}

/**
 * Where one position of the format lives in a document of the arms given, which is how the ceiling sweep
 * edits a position that only one arm carries.
 */
function positionFor(arms: Arms, rule: string, member: string, root: Map<unknown, unknown>): Map<unknown, unknown> {
  const collection = mapOf(child(root, 'collection'), 'collection');
  const maps: Record<string, () => Map<unknown, unknown>> = {
    'Ashaveri-Export-Manifest': () => root,
    ExportAssessment: () => mapOf(child(root, 'assessment'), 'assessment'),
    ExportClaim: () => mapOf(child(root, 'claim'), 'claim'),
    ExportAnchoredCollection: () => collection,
    ExportPlainCollection: () => collection,
    ExportVoidCollection: () => collection,
    ExportItem: () => itemOf(root, 0),
    ExportChainedItem: () => itemOf(root, 0),
    ExportInlineOriginal: () => mapOf(child(itemOf(root, 0), 'orig'), 'orig'),
    ExportCompanionOriginal: () => mapOf(child(itemOf(root, 0), 'orig'), 'orig'),
  };
  const wanted = maps[rule];
  if (wanted === undefined) throw new Error(`this case builds no document position for ${rule}`);
  const reached = wanted();
  if (!reached.has(member)) {
    throw new Error(`${rule}.${member} is not a position of a ${arms.collection} collection with a ${arms.original} original`);
  }
  return reached;
}

/** The arms a document must take for one rule's positions to be in it. */
function armsFor(rule: string): Arms {
  if (rule === 'ExportAnchoredCollection' || rule === 'ExportChainedItem') return { collection: 'anchored', original: 'inline' };
  if (rule === 'ExportVoidCollection') return { collection: 'void', original: 'inline' };
  if (rule === 'ExportCompanionOriginal') return { collection: 'plain', original: 'companion' };
  return { collection: 'plain', original: 'inline' };
}

function thrownByDecode(bytes: Uint8Array): unknown {
  try {
    decodeExport(bytes);
    return null;
  } catch (err) {
    return err;
  }
}

function thrownByVerify(bytes: Uint8Array, key: SigningKey = KEY, options?: Parameters<typeof verifyExport>[2]): unknown {
  try {
    verifyExport(bytes, key.publicKey, options);
    return null;
  } catch (err) {
    return err;
  }
}

function codeOf(thrown: unknown): string {
  if (thrown instanceof ReceiptError) return thrown.code;
  return thrown instanceof Error ? `UNCODED:${thrown.message}` : `THREW:${String(thrown)}`;
}

/** The arm a read result reports, named by the case that asks for it and by nothing else. */
function armOf<W extends ExportRead['kind']>(want: W, read: ExportRead): Extract<ExportRead, { kind: W }> {
  if (read.kind !== want) throw new Error(`the reader reported ${read.kind} where this case expects ${want}`);
  return read as Extract<ExportRead, { kind: W }>;
}

describe('the export reader', () => {
  it('reads each of the three collection arms and reports the arm it read', () => {
    const voided = verifyExport(sealedManifest('void'), KEY.publicKey);
    const voidOutcome = armOf('void', voided.outcome);
    expect('items' in voidOutcome, 'a void outcome carries items to count').toBe(false);
    expect(voidOutcome.states).toBe('nothing was carried out of the store');
    expect(voided.manifest.assessment).toEqual({ k: 'none', states: 'no legal assessment was made of this material' });
    expect(voided.header.contentType).toBe(EXPORT_CONTENT_TYPE);

    const plain = verifyExport(sealedManifest('plain'), KEY.publicKey);
    expect(armOf('plain', plain.outcome).items).toHaveLength(2);
    expect(plain.manifest.claim.kind).toBe('provenance');
    expect(plain.manifest.claim.by).toBe('Amir, on the record');

    const anchored = verifyExport(sealedManifest('anchored'), KEY.publicKey);
    expect(armOf('anchored', anchored.outcome).walked.map((one) => one.id)).toEqual(['r-0', 'r-1', 'r-2']);
    expect(armOf('anchored', anchored.outcome).items).toHaveLength(3);
  });

  it('orders an anchored read by the links and not by the array', () => {
    const collection = anchoredCollection();
    const shuffled: ExportAnchoredCollection = { ...collection, items: [collection.items[2]!, collection.items[0]!, collection.items[1]!] };
    const verified = verifyExport(signExport(manifest({ collection: shuffled }), KEY), KEY.publicKey);
    expect(armOf('anchored', verified.outcome).walked.map((one) => one.id)).toEqual(['r-0', 'r-1', 'r-2']);
  });

  it('is deterministic from a manifest through the bytes and back', () => {
    for (const [name, collection] of [
      ['anchored', anchoredCollection()],
      ['plain', plainCollection('companion')],
      ['void', { k: 'void', states: 'nothing' } as ExportCollection],
    ] as Array<[string, ExportCollection]>) {
      const value = manifest({ collection });
      const first = encodeExportManifest(value);
      const round = encodeExportManifest(decodeExport(sealWithKey(first, KEY)).manifest);
      expect(toHex(round), `re-encoding what the reader decoded moves a byte (${name})`).toBe(toHex(first));
      expect(toHex(sealWithKey(first, KEY))).toBe(toHex(signExport(value, KEY)));
      const decoded = decodeExport(signExport(value, KEY));
      expect(decoded.envelope.unprotected.size, 'the unprotected map the format leaves free was read as something else').toBe(0);
      expect(elementsOf(signExport(value, KEY))).toHaveLength(4);
    }
  });

  it('will not sign what it would refuse, so no writer ships an unreadable export', () => {
    const whole = manifest({ collection: anchoredCollection() });
    expect(() => signExport(whole, KEY)).not.toThrow();
    const collection = whole.collection as ExportAnchoredCollection;
    const cases: Array<[string, ExportManifest, string, ReceiptErrorCode]> = [
      ['an empty items array', { ...whole, collection: { k: 'plain', items: [] } }, 'declares a non-empty', 'EXPORT_BAD_MANIFEST'],
      ['a claim stamped after the assembly', { ...whole, claim: { ...whole.claim, made: CLOCK + 1 } }, 'postdates the assembly', 'EXPORT_BAD_MANIFEST'],
      ['an assessment label of its own invention', { ...whole, assessment: { k: 'partial', states: 'a later version says so' } as unknown as ExportManifest['assessment'] }, 'is not the label this version defines', 'EXPORT_UNSUPPORTED_LABEL'],
      ['a digest of the wrong width', { ...whole, collection: { ...collection, items: [{ ...collection.items[0]!, d: new Uint8Array(31) }, collection.items[1]!, collection.items[2]!] } }, 'must be a 32-byte bstr', 'EXPORT_BAD_MANIFEST'],
      ['a companion name that is a path', { ...whole, collection: { k: 'plain', items: [{ id: 'item-0', iat: CLOCK, d: sha256(bytesOf('contract text')), orig: { k: 'companion', name: '../outside' } }] } }, 'not a path or a location', 'EXPORT_BAD_MANIFEST'],
    ];
    for (const [name, value, phrase, code] of cases) {
      let caught: unknown;
      try {
        signExport(value, KEY);
      } catch (err) {
        caught = err;
      }
      expect(caught, `signExport accepted ${name}`).toBeInstanceOf(ReceiptError);
      expect((caught as Error).message, name).toContain(phrase);
      expect(codeOf(caught), `${name} answered another code`).toBe(code);
    }
  });

  it('refuses an envelope that is not one, whatever it holds', () => {
    expect(codeOf(thrownByDecode(new Uint8Array([0xff])))).toBe('EXPORT_MALFORMED_CBOR');
    expect((thrownByDecode(encodeCanonical([1, 2, 3])) as Error).message).toMatch(/tag 18/u);
    const good = signExport(manifest(), KEY);
    const [prot, , payload] = elementsOf(good);
    expect(codeOf(thrownByDecode(encodeCanonical(new Tag(18, [prot, new Map(), payload]))))).toBe('NOT_COSE_SIGN1');
    expect((thrownByDecode(sealExport(prot as Uint8Array, payload as Uint8Array, new Uint8Array(63))) as Error).message).toMatch(/64-byte bstr/u);
    const algSwapped = encodeCanonical(new Map<number, unknown>([[COSE_HEADER_ALG, -7], [COSE_HEADER_CONTENT_TYPE, EXPORT_CONTENT_TYPE], [COSE_HEADER_KID, KEY.kid]]));
    expect((thrownByDecode(sealExport(algSwapped, payload as Uint8Array, new Uint8Array(64))) as Error).message).toMatch(/alg=-7/u);
    const fourthLabel = encodeCanonical(new Map<number, unknown>([[COSE_HEADER_ALG, -8], [COSE_HEADER_CONTENT_TYPE, EXPORT_CONTENT_TYPE], [COSE_HEADER_KID, KEY.kid], [5, 'what']]));
    expect((thrownByDecode(sealExport(fourthLabel, payload as Uint8Array, new Uint8Array(64))) as Error).message).toMatch(/does not define: the numeric key 5/u);
  });

  it('refuses a document that is not an export, in both directions', () => {
    const payload = encodeExportManifest(manifest({ collection: anchoredCollection() }));
    // A receipt's envelope around an export's manifest: one key signs both, so the typ is the only thing
    // that keeps a reader from reporting a handover as an attestation about one response.
    expect((thrownByDecode(signCoseSign1(payload, KEY)) as Error).message).toMatch(/typ=ashaveri\/receipt/u);
    const packHeader = encodeExportProtectedHeader(KEY.kid, 'ashaveri/pack');
    expect(codeOf(thrownByDecode(sealExport(packHeader, payload, ed25519.sign(exportSigStructure(packHeader, payload), KEY.privateKey))))).toBe('EXPORT_BAD_HEADER');
    // The other direction, which no reader of this container performs and the pack's own projection does:
    // an export manifest is not a pack manifest, because the six members a pack requires are not the five
    // this one carries and both maps are closed.
    expect(outcome(exportDocument({ collection: 'anchored', original: 'inline' }).payload, validatePack), 'a pack projection accepted an export manifest').not.toBeNull();
    // And a reader of this container is not a reader of that one: the pack's twin names the type it
    // projects, and it is not this one.
    expect(shape.properties.protectedHeader.properties?.typ?.const).not.toBe('ashaveri/pack');
  });

  it('refuses every structural fault by name, one position at a time', () => {
    const atCollection = (root: Map<unknown, unknown>) => mapOf(child(root, 'collection'), 'collection');
    const cases: Array<[string, Arms, (root: Map<unknown, unknown>) => void, string, RegExp]> = [
      ['an undefined member of the manifest', { collection: 'plain', original: 'inline' }, (root) => root.set('surprise', 'x'), 'EXPORT_BAD_MANIFEST', /member this version does not define: 'surprise'/u],
      ['an undefined member of the claim', { collection: 'plain', original: 'inline' }, (root) => mapOf(child(root, 'claim'), 'claim').set('witness', 'x'), 'EXPORT_BAD_MANIFEST', /claim carries a member this version does not define: 'witness'/u],
      ['an undefined member of an item', { collection: 'plain', original: 'inline' }, (root) => itemOf(root, 0).set('where', 'x'), 'EXPORT_BAD_MANIFEST', /collection\.items\[0\] carries a member/u],
      ['an undefined member of an anchored item', { collection: 'anchored', original: 'inline' }, (root) => itemOf(root, 0).set('where', 'x'), 'EXPORT_BAD_MANIFEST', /carries a member this version does not define: 'where'/u],
      ['an undefined member of a companion original', { collection: 'plain', original: 'companion' }, (root) => mapOf(child(itemOf(root, 0), 'orig'), 'orig').set('url', 'x'), 'EXPORT_BAD_MANIFEST', /orig \(companion\) carries a member/u],
      ['an undefined member of an inline original', { collection: 'plain', original: 'inline' }, (root) => mapOf(child(itemOf(root, 0), 'orig'), 'orig').set('url', 'x'), 'EXPORT_BAD_MANIFEST', /orig \(inline\) carries a member/u],
      ['an undefined member of the collection', { collection: 'plain', original: 'inline' }, (root) => { atCollection(root).set('surprise', 'x'); }, 'EXPORT_BAD_MANIFEST', /collection carries a member this version does not define: 'surprise'/u],
      ['an absent assessment', { collection: 'plain', original: 'inline' }, (root) => root.delete('assessment'), 'EXPORT_BAD_MANIFEST', /assessment must be a map/u],
      ['an absent claim', { collection: 'plain', original: 'inline' }, (root) => root.delete('claim'), 'EXPORT_BAD_MANIFEST', /claim must be a map/u],
      ['a version this package cannot read', { collection: 'plain', original: 'inline' }, (root) => root.set('v', 2), 'EXPORT_UNSUPPORTED_VERSION', /version 2 is not a format/u],
      ['a version that is not an integer', { collection: 'plain', original: 'inline' }, (root) => root.set('v', '1'), 'EXPORT_BAD_MANIFEST', /v must be an integer/u],
      ['a negative assembly stamp', { collection: 'plain', original: 'inline' }, (root) => root.set('at', -1), 'EXPORT_BAD_MANIFEST', /non-negative integer of seconds/u],
      ['a claim stamped after the assembly', { collection: 'plain', original: 'inline' }, (root) => mapOf(child(root, 'claim'), 'claim').set('made', CLOCK + 1), 'EXPORT_BAD_MANIFEST', /claim\.made/u],
      ['a path where a file name belongs', { collection: 'plain', original: 'companion' }, (root) => mapOf(child(itemOf(root, 0), 'orig'), 'orig').set('name', '../outside'), 'EXPORT_BAD_MANIFEST', /must be a file name and not a path/u],
      ['an empty id', { collection: 'plain', original: 'inline' }, (root) => itemOf(root, 0).set('id', ''), 'EXPORT_BAD_MANIFEST', /must be between 1 and/u],
      ['a digest of another width', { collection: 'plain', original: 'inline' }, (root) => itemOf(root, 0).set('d', new Uint8Array(31)), 'EXPORT_BAD_MANIFEST', /d must be a 32-byte bstr/u],
      ['an empty array under the plain arm', { collection: 'plain', original: 'inline' }, (root) => atCollection(root).set('items', []), 'EXPORT_BAD_MANIFEST', /declares a non-empty/u],
      ['an empty array under the anchored arm', { collection: 'anchored', original: 'inline' }, (root) => atCollection(root).set('items', []), 'EXPORT_BAD_MANIFEST', /the anchored arm declares a non-empty/u],
      ['a predecessor inside a collection that claims no chain', { collection: 'plain', original: 'inline' }, (root) => itemOf(root, 0).set('p', new Uint8Array(32)), 'EXPORT_BAD_MANIFEST', /names a predecessor in a collection that claims no chain/u],
      ['a missing predecessor in an anchored collection', { collection: 'anchored', original: 'inline' }, (root) => itemOf(root, 0).delete('p'), 'EXPORT_BAD_MANIFEST', /names no predecessor in a collection that claims one/u],
      ['an assessment label of another version', { collection: 'plain', original: 'inline' }, (root) => mapOf(child(root, 'assessment'), 'assessment').set('k', 'partial'), 'EXPORT_UNSUPPORTED_LABEL', /is not the label this version defines/u],
      ['a collection arm of another version', { collection: 'plain', original: 'inline' }, (root) => atCollection(root).set('k', 'sealed'), 'EXPORT_UNSUPPORTED_LABEL', /is not one of anchored, plain, void/u],
      ['an original arm of another version', { collection: 'plain', original: 'inline' }, (root) => mapOf(child(itemOf(root, 0), 'orig'), 'orig').set('k', 'remote'), 'EXPORT_UNSUPPORTED_LABEL', /is not one of inline, companion/u],
      ['a claim kind outside the two', { collection: 'plain', original: 'inline' }, (root) => mapOf(child(root, 'claim'), 'claim').set('kind', 'chain-of-custody'), 'EXPORT_UNSUPPORTED_LABEL', /claim\.kind='chain-of-custody'/u],
      ['a floating-point number in a closed map', { collection: 'plain', original: 'inline' }, (root) => root.set('at', 1.5), 'EXPORT_BAD_MANIFEST', /./u],
      ['a floating-point number as a map key', { collection: 'plain', original: 'inline' }, (root) => root.set(2.5, 'at'), 'EXPORT_BAD_MANIFEST', /./u],
    ];
    for (const [name, arms, mutate, code, pattern] of cases) {
      const bytes = editSealed(sealedManifest(arms.collection, arms.original), mutate);
      const thrown = thrownByDecode(bytes);
      expect(thrown, `${name} was accepted`).toBeInstanceOf(Error);
      expect((thrown as Error).message, name).toMatch(pattern);
      expect(codeOf(thrown), `${name} answered the wrong code`).toBe(code);
      // A structural fault is a fault of the document, so a reader with no key at all hears it too.
      expect(codeOf(thrownByVerify(bytes)), `${name} answered differently once verified`).toBe(code);
    }
  });

  it('refuses two items answering to one name, which is a name and not a link', () => {
    const collided = editSealed(sealedManifest('plain'), (root) => {
      const items = child(child(root, 'collection'), 'items');
      if (Array.isArray(items)) items.push(mapOf(structuredClone(items[0]), 'clone'));
    });
    expect(codeOf(thrownByDecode(collided))).toBe('EXPORT_DUPLICATE_ID');
    // Chained honestly, so every digest is the one the next record names: nothing about a link says two
    // items share a name, because the name sits inside the hash and both spellings hash perfectly. This
    // document is assembled past the writer, which refuses to sign it, because the question is what a
    // reader answers for bytes a deployment did sign.
    const collection = anchoredCollection();
    const twin: ExportAnchoredCollection = { ...collection, items: [...collection.items, { ...collection.items[1]!, id: collection.items[0]!.id }] };
    expect(codeOf(thrownByVerify(sealWithKey(encodeExportManifest(manifest({ collection: twin })), KEY)))).toBe('EXPORT_DUPLICATE_ID');
  });

  it('refuses a gap, a fork, an unreachable head and an item the walk never reaches', () => {
    const good = anchoredCollection();
    // A record lifted out of the middle: what remains is whole by its own digest, and the walk stops short.
    const gap: ExportAnchoredCollection = { ...good, items: [good.items[0]!, good.items[2]!] };
    const broken = thrownByVerify(signExport(manifest({ collection: gap }), KEY));
    expect(codeOf(broken)).toBe('EXPORT_CHAIN_BROKEN');
    expect((broken as Error).message).toMatch(/stopped at a digest that is not the head/u);
    // The same omission with the hole closed by re-chaining, which is the forgery the signed head exists to
    // defeat: the links are perfect and the run is still short of the endpoint the writer signed.
    const closed: ExportAnchoredCollection = { ...good, items: rechain([good.items[0]!, good.items[2]!]) };
    expect(codeOf(thrownByVerify(signExport(manifest({ collection: closed }), KEY)))).toBe('EXPORT_CHAIN_BROKEN');
    // Two items claiming one predecessor: the walk would take whichever it met first, so a fork is refused
    // rather than resolved by arrival order.
    const rival: ExportAnchoredCollection = { ...good, items: [forked(good), ...good.items] };
    expect(codeOf(thrownByVerify(signExport(manifest({ collection: rival }), KEY)))).toBe('EXPORT_CHAIN_BROKEN');
    // A record parked beside a run it is not part of reaches the head exactly as the honest ones do, so the
    // second half of the rule is the only one with eyes for it.
    const parked: ExportAnchoredCollection = { ...good, items: [...good.items, parkedItem(good)] };
    const unreached = thrownByVerify(signExport(manifest({ collection: parked }), KEY));
    expect(codeOf(unreached)).toBe('EXPORT_ITEM_UNREACHED');
    expect((unreached as Error).message).toMatch(/parked/u);
    // The controls: the same run with nothing parked and nothing lifted walks, and a single record chained
    // from an anchor to its own digest is a whole run of one.
    expect(() => verifyExport(signExport(manifest({ collection: good }), KEY), KEY.publicKey)).not.toThrow();
    const single = rechain([good.items[0]!]);
    expect(() => verifyExport(signExport(manifest({ collection: { k: 'anchored', anchor: good.anchor, head: exportRecordDigest({ id: single[0]!.id, iat: single[0]!.iat, p: single[0]!.p, bytes: (single[0]!.orig as { bytes: Uint8Array }).bytes }), items: single } }), KEY), KEY.publicKey)).not.toThrow();
  });

  it('checks each digest, and refuses to guess about a companion it was not handed', () => {
    expect(() => verifyExport(sealedManifest('plain'), KEY.publicKey)).not.toThrow();
    const edited = editSealed(sealedManifest('plain'), (root) => {
      mapOf(child(itemOf(root, 0), 'orig'), 'orig').set('bytes', bytesOf('one byte of a different contract'));
    });
    const mismatch = thrownByVerify(edited);
    expect(codeOf(mismatch)).toBe('EXPORT_DIGEST_MISMATCH');
    expect((mismatch as Error).message).toMatch(/item-0/u);

    const companion = sealedManifest('plain', 'companion');
    const absent = thrownByVerify(companion);
    expect(codeOf(absent)).toBe('EXPORT_ORIGINAL_UNAVAILABLE');
    expect((absent as Error).message).toMatch(/names contract\.pdf/u);
    const handed = new Map<string, Uint8Array>([...COMPANIONS].map(([name, text]) => [name, bytesOf(text)]));
    expect(() => verifyExport(companion, KEY.publicKey, { companions: handed })).not.toThrow();
    handed.set('contract.pdf', bytesOf('a substituted contract'));
    expect(codeOf(thrownByVerify(companion, KEY, { companions: handed }))).toBe('EXPORT_DIGEST_MISMATCH');
    // A companion is a name and not a location, so an anchored collection can chain over companion bytes
    // too, which is what a reader handed the originals beside the document gets.
    const chained = anchoredCollection();
    expect(chained.items[0]!.orig.k).toBe('inline');
  });

  it('compares the endpoints a caller already holds, and never leaves a pin unused', () => {
    const collection = anchoredCollection();
    const bytes = signExport(manifest({ collection }), KEY);
    expect(() => verifyExport(bytes, KEY.publicKey, { expectedHead: collection.head, expectedAnchor: collection.anchor })).not.toThrow();
    const other = sha256(bytesOf('a head from another handover'));
    expect((thrownByVerify(bytes, KEY, { expectedHead: other }) as Error).message).toMatch(/head=/u);
    expect(codeOf(thrownByVerify(bytes, KEY, { expectedHead: other }))).toBe('EXPORT_ENDPOINT_MISMATCH');
    expect(codeOf(thrownByVerify(bytes, KEY, { expectedAnchor: other }))).toBe('EXPORT_ENDPOINT_MISMATCH');
    // A collection that states no endpoints cannot be the run the reader expected, and passing it because
    // there was nothing to compare would be the silent pin.
    expect(codeOf(thrownByVerify(sealedManifest('plain'), KEY, { expectedHead: other }))).toBe('EXPORT_ENDPOINT_MISMATCH');
    expect(codeOf(thrownByVerify(sealedManifest('void'), KEY, { expectedAnchor: other }))).toBe('EXPORT_ENDPOINT_MISMATCH');
  });

  it('refuses one byte changed anywhere in the payload, whatever the structure says', () => {
    const bytes = sealedManifest('anchored');
    const flipped = new Uint8Array(bytes);
    const at = flipped.length - 70;
    flipped[at] = (flipped[at] ?? 0) ^ 0x01;
    // The signature is checked before the manifest is read, so a mutated byte is a refusal about the bytes
    // and never a structural answer the document did not earn.
    expect(codeOf(thrownByVerify(flipped))).toBe('INVALID_SIGNATURE');
    expect(codeOf(thrownByVerify(bytes, signingKeyFromSeed(new Uint8Array(32).fill(9))))).toBe('EXPORT_KID_MISMATCH');
  });

  it('enforces the byte ceilings the format writes beside each text position', () => {
    for (const { rule, member, max } of CEILINGS) {
      const arms = armsFor(rule);
      const fill = (text: string) => (root: Map<unknown, unknown>): void => {
        positionFor(arms, rule, member, root).set(member, text);
      };
      // The decoder is the consumer of a width rule: a ceiling is a property of the document, so no
      // signature, digest or walk has anything to do with the answer.
      expect(() => decodeExport(editSealed(sealedManifest(arms.collection, arms.original), fill('a'.repeat(max)))), `${rule}.${member} at ${String(max)} bytes is refused`).not.toThrow();
      const over = codeOf(thrownByDecode(editSealed(sealedManifest(arms.collection, arms.original), fill('a'.repeat(max + 1)))));
      expect(over, `${rule}.${member} accepted ${String(max + 1)} bytes`).toBe('EXPORT_BAD_MANIFEST');
    }
  });

  it('frames a chained record the way the specification publishes it, and no other way', () => {
    const first = anchoredCollection().items[0]!;
    const bytes = (first.orig as { bytes: Uint8Array }).bytes;
    const honest = exportRecordDigest({ id: first.id, iat: first.iat, p: first.p, bytes });
    expect(toHex(sha256(framingInput(first.id, first.iat, first.p, bytes)))).toBe(toHex(honest));
    expect(honest.length).toBe(32);
    const input = framingInput(first.id, first.iat, first.p, bytes);
    expect(input[0]).toBe(0);
    expect(input.length).toBe(1 + 32 + 8 + 2 + new TextEncoder().encode(first.id).length + bytes.length);
    for (const [name, moved] of [
      ['the predecessor', exportRecordDigest({ id: first.id, iat: first.iat, p: sha256(bytesOf('elsewhere')), bytes })],
      ['the stamp', exportRecordDigest({ id: first.id, iat: first.iat + 1, p: first.p, bytes })],
      ['the name', exportRecordDigest({ id: `${first.id}x`, iat: first.iat, p: first.p, bytes })],
      ['the bytes', exportRecordDigest({ id: first.id, iat: first.iat, p: first.p, bytes: bytesOf('other') })],
    ] as Array<[string, Uint8Array]>) {
      expect(toHex(moved), `moving ${name} left the record digest alone`).not.toBe(toHex(honest));
    }
    // Big-endian and unsigned, which the stamp's eight bytes show: a value one past 2^32 moves the fourth
    // byte from the left and nothing after it.
    expect([...framingInput('a', 2 ** 32, new Uint8Array(32), new Uint8Array(0)).slice(9, 17)]).toEqual([0, 0, 0, 1, 0, 0, 0, 0]);
    expect(() => exportRecordDigest({ id: 'a', iat: 1, p: new Uint8Array(31), bytes: new Uint8Array(0) })).toThrow(/predecessor of 31 bytes/u);
    expect(() => exportRecordDigest({ id: '', iat: 1, p: new Uint8Array(32), bytes: new Uint8Array(0) })).toThrow(/an id of 0 bytes/u);
  });

  it('returns what it read and never a verdict of its own', () => {
    const verified = verifyExport(sealedManifest('anchored'), KEY.publicKey);
    // The report is the manifest, the header and the envelope. No field of it is a conclusion about a duty,
    // a period, a comparison, or whether the source still holds anything else.
    expect(Object.keys(verified).sort()).toEqual(['envelope', 'header', 'manifest', 'outcome']);
    expect(Object.keys(verified.manifest).sort()).toEqual(['assessment', 'at', 'claim', 'collection', 'v']);
    expect(Object.keys(verified.manifest.claim).sort()).toEqual(['by', 'kind', 'made', 'states']);
    const printed = JSON.stringify(verified, (_key, value: unknown) => (value instanceof Uint8Array ? 'bytes' : value)).toLowerCase();
    for (const word of ['duty', 'article', '"met"', 'required', 'qualification', 'complete', 'fresh', 'law']) {
      expect(printed, `the reader's own report carries ${word}`).not.toContain(word);
    }
    // And the code names this container refuses with say nothing about a duty either: a caller that read a
    // refusal as a legal finding would be reading a sentence that never uses the word.
    const codes: readonly ReceiptErrorCode[] = ['EXPORT_BAD_MANIFEST', 'EXPORT_CHAIN_BROKEN', 'EXPORT_UNSUPPORTED_LABEL', 'EXPORT_ENDPOINT_MISMATCH'];
    for (const code of codes) {
      expect(new ReceiptError(code).message.toLowerCase(), `${code} names a duty`).not.toMatch(/duty|law|legal/u);
    }
  });
});

/** The same three records, re-chained from the anchor in the order given. */
function rechain(items: readonly ExportChainedItem[]): ExportChainedItem[] {
  let prev: Uint8Array = new Uint8Array(32);
  return items.map((one) => {
    const bytes = one.orig.k === 'inline' ? one.orig.bytes : new Uint8Array(0);
    const next: ExportChainedItem = { ...one, p: prev };
    prev = exportRecordDigest({ id: next.id, iat: next.iat, p: prev, bytes });
    return next;
  });
}

/** A second item claiming the anchor as its predecessor, which is where a run would have to choose. */
function forked(collection: ExportAnchoredCollection): ExportChainedItem {
  const bytes = bytesOf('a rival first record');
  return { id: 'rival', iat: collection.items[0]!.iat, d: sha256(bytes), p: collection.anchor, orig: { k: 'inline', bytes } };
}

/** An item named by nobody's predecessor and naming a predecessor from another chain entirely. */
function parkedItem(collection: ExportAnchoredCollection): ExportChainedItem {
  const bytes = bytesOf('a parked record');
  return { id: 'parked', iat: collection.items[0]!.iat, d: sha256(bytes), p: sha256(bytesOf('another chain entirely')), orig: { k: 'inline', bytes } };
}
