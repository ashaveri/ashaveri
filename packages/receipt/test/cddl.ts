import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

/**
 * The readers of `receipt.cddl` that more than one test file needs.
 *
 * `schema.test.ts` holds the rest of them, and does the binding between the normative definition and
 * the parser's member lists. What lives here is the smaller set the two sweeps share: which members a
 * block declares, which rule a member's value is, and which of those members the format types as an
 * integer. Those three answers are read out of the CDDL rather than written down again because a list
 * a document and a test both state has to be held by the test that reads the source of truth: a roster
 * typed out in either place keeps passing the day the format gains a member, and the whole point of
 * the sweeps is to be asked about every position the format has.
 *
 * A second reader file inside this package would be the same duplication this one exists to avoid, and
 * importing these from another package is not on offer: the two packages do not read each other's test
 * directories, because a relative import that walks out of a package works in this workspace and
 * breaks the moment either one is published on its own.
 */
const moduleDir = fileURLToPath(new URL('.', import.meta.url));

/** The normative definition, next to the source it describes. */
export const cddlPath = `${moduleDir}../receipt.cddl`;

/** The whole file, read once per call so a test that edits nothing in it still reads what is there. */
export function readCddl(): string {
  return readFileSync(cddlPath, 'utf8');
}

/** A value a test cannot go on without: the name rides along, because a bare `!` hides which lookup
 * failed. */
export function required<T>(value: T | undefined, detail: string): T {
  if (value === undefined) throw new Error(detail);
  return value;
}

/**
 * The text of one CDDL rule, from its opening brace to the first line that closes it. A rule the
 * reader could not find has to fail the run rather than hand back an empty string, because an empty
 * block reads as a format that stopped declaring any members.
 */
export function cddlRule(cddl: string, rule: string): string {
  const start = cddl.indexOf(`${rule} = {`);
  if (start < 0) throw new Error(`${rule} is not declared in ${cddlPath}`);
  const end = cddl.indexOf('\n}', start);
  if (end < 0) throw new Error(`${rule} in ${cddlPath} never closes`);
  return cddl.slice(start, end);
}

/**
 * The members one CDDL block declares, each with the type expression written beside it, in the order
 * the block declares them: comments stripped, then every `name:` read off the commas that separate the
 * members. The order is not decoration: v2's block puts `mk` after the thirteen, and the twin and the
 * parser both claim that list as theirs. The type rides along for the same reason the name does: which
 * of these positions the format makes an integer is the CDDL's answer, and a test that asks for it has
 * to read it here rather than remember it.
 *
 * A member name this reader takes is a text label, `[a-z][a-z0-9_]*`, so the labels
 * `Ashaveri-Protected-Header` spells as integers are outside it and belong to `cddlIntegerLabels`.
 */
export function memberDeclarations(block: string): Array<{ name: string; type: string }> {
  const members: Array<{ name: string; type: string }> = [];
  for (const line of block.split('\n').slice(1)) {
    for (const piece of line.split(';')[0]!.split(',')) {
      const found = /^\s*([a-z][a-z0-9_]*)\s*:\s*(.*?)\s*$/u.exec(piece);
      if (found) members.push({ name: found[1]!, type: found[2]! });
    }
  }
  return members;
}

/**
 * The members one block declares, names only. A block that names nothing by label comes back empty
 * rather than throwing, because the reader of every map in the file has to be able to tell
 * `Ashaveri-Protected-Header`, whose keys are the COSE registry's integers, apart from a map that has
 * lost its members.
 */
export function labeledMembers(block: string): string[] {
  return memberDeclarations(block).map((member) => member.name);
}

/**
 * The blocks of a rule written as a map, or a choice between maps. `Measurement` is two blocks that
 * name the same members at different widths, and the second one is invisible to `cddlRule`, which
 * stops at the first closing brace: a member arriving in one arm alone would be a map no list stands
 * behind. A block that never closes throws rather than reading as an empty one.
 */
export function cddlRuleArms(cddl: string, rule: string): string[] {
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

/** One map the CDDL defines, the list that stands behind it, and what the rule adds to that list. */
export interface ListBinding {
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
export const LIST_FOR_MAP: readonly ListBinding[] = [
  { map: 'Ashaveri-Receipt-Payload-v1', list: 'SHARED_MEMBERS' },
  { map: 'Ashaveri-Receipt-Payload-v2', list: 'SHARED_MEMBERS', adds: ['mk'] },
  { map: 'Marking', list: 'MARKING_MEMBERS' },
  { map: 'Measurement', list: 'MEASUREMENT_MEMBERS' },
  { map: 'EvidenceRef', list: 'EVIDENCE_REF_MEMBERS' },
  { map: 'TokenMetering', list: 'TOKEN_METERING_MEMBERS' },
];

/**
 * The payload members whose value is another map the file defines, each bound to the rule it is:
 * `meas` is a `Measurement`. Derived rather than written out beside the member, because adding a member
 * to a payload block is the only way a new map reaches this format, and a table of rule names kept by
 * hand here would let that map arrive in the CDDL and in the parser while the twin-side assertions
 * went on sweeping the maps before it. Two payload blocks naming one member two different rules is the
 * format describing one member as two maps, so it stops the run rather than settling for one.
 */
export function nestedRuleNames(cddl: string): Map<string, string> {
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
 * The type `receipt.cddl` writes for a number position that is not left to a reader's judgement: the
 * bare `int`, and the integer literal that fixes a version. Both are the format typing a position as
 * an integer, which is why both belong to the sweeps and neither to the other.
 */
const INTEGER_TYPE = /^(?:int|-?\d+)$/u;

/**
 * Every position the format types as an integer, in the order the payload blocks reach them, with the
 * dotted name a reader of a payload uses: `iat` at the payload level and `att.ts` one map down.
 *
 * `att`, `tok` and `meas` expand into the rules they are, because a member of `EvidenceRef` is a
 * position of the payload document that carries it, and the rule that refuses a float at `att.ts` is
 * the same rule that refuses one at `iat`. `mk` expands too, and contributes nothing: `Marking` types
 * its two members as a label and a digest. Nothing is filtered out at the end — a name bound to a rule
 * is expanded even when the rule holds no integer, so a position gaining one in the CDDL arrives in
 * this list with no edit here.
 *
 * Both payload blocks are read, which is how a position that only one version carries would still be
 * found; a name the two blocks list twice is reported once.
 */
export function cddlIntegerPositions(cddl: string): string[] {
  const rules = nestedRuleNames(cddl);
  const positions: string[] = [];
  const push = (name: string): void => {
    if (!positions.includes(name)) positions.push(name);
  };
  for (const binding of LIST_FOR_MAP.filter((row) => row.map.startsWith('Ashaveri-Receipt-Payload-v'))) {
    for (const member of memberDeclarations(cddlRule(cddl, binding.map))) {
      const rule = rules.get(member.name);
      if (rule === undefined) {
        if (INTEGER_TYPE.test(member.type)) push(member.name);
        continue;
      }
      for (const arm of cddlRuleArms(cddl, rule)) {
        for (const inner of memberDeclarations(arm)) {
          if (INTEGER_TYPE.test(inner.type)) push(`${member.name}.${inner.name}`);
        }
      }
    }
  }
  if (positions.length === 0) throw new Error(`no position of ${cddlPath} is typed as an integer`);
  return positions;
}
