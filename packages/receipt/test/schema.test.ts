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

const schemaPath = fileURLToPath(new URL('../schemas/receipt-v1.schema.json', import.meta.url));
const cddlPath = fileURLToPath(new URL('../receipt.cddl', import.meta.url));
const specPath = fileURLToPath(new URL('../../../docs/receipt-spec.md', import.meta.url));
const schema = JSON.parse(readFileSync(schemaPath, 'utf8')) as object;

/**
 * The parts of this schema the agreement test below reads: one branch per payload version, and the
 * three descriptions that say which level each of them closes.
 */
interface SchemaShape {
  description: string;
  $defs: {
    payloadFields: { properties: Record<string, unknown> };
    payloadV1: { properties: Record<string, unknown>; description: string };
    payloadV2: { properties: Record<string, unknown>; description: string };
  };
}

const shape = schema as SchemaShape;

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
 * The members one payload block declares, in the order it declares them: comments stripped, then
 * every `name:` read off the commas that separate the members. The order is not decoration — v2's
 * block puts `mk` after the thirteen, and the twin and the parser both claim that list as theirs.
 */
function cddlMembers(cddl: string, version: 1 | 2): string[] {
  const members: string[] = [];
  for (const line of cddlRule(cddl, `Ashaveri-Receipt-Payload-v${version}`).split('\n').slice(1)) {
    for (const piece of line.split(';')[0]!.split(',')) {
      const found = /^\s*([a-z][a-z0-9_]*)\s*:/u.exec(piece);
      if (found) members.push(found[1]!);
    }
  }
  if (members.length === 0) throw new Error(`the payload v${version} block declares no members`);
  return members;
}

/**
 * One string for a whole document's worth of line breaks: a sentence in these files spans the lines it
 * wrapped at, so a leg that pins a sentence has to read the prose rather than the wrapping. An edit
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
 * count below wants — a subsection repeating section 6's rule is the second voice that leg is there
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

  it('closes the payload map in the twin, the CDDL and the spec alike', () => {
    // The rule is one rule, written down four times: the parser, this schema, the normative CDDL
    // and the specification. A reader porting the format reads the last two, so a document that
    // stopped saying it would leave the port to guess, which is how an open map comes back.
    const cddl = readFileSync(cddlPath, 'utf8');
    const membersPerVersion: Record<1 | 2, string[]> = { 1: cddlMembers(cddl, 1), 2: cddlMembers(cddl, 2) };
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

    // Where that rule stops is a boundary no type expression shows. The four nested blocks omit the
    // marker too, so the file reads as closed at that level, and the parser and the twin are the ones
    // that do not enforce it there. The note has to name that divergence rather than the leniency: a
    // port that believes these blocks are open by the format builds a verifier laxer than the
    // normative text, which is the one mistake this file exists to prevent.
    saidOnce('the CDDL boundary note', prose, 'Closedness stops at the payload map');
    saidOnce('the CDDL boundary note', prose, 'below carry no `...` either');
    saidOnce('the CDDL boundary note', prose, 'the parser and the JSON twin do not enforce it there');
    for (const block of ['Marking', 'Measurement', 'EvidenceRef', 'TokenMetering']) {
      expect(prose.includes(`\`${block}\``), `the CDDL names ${block}`).toBe(true);
    }
    expect(prose).not.toMatch(/\bare open\b/u);

    // And the specification states the refusal once in the field table and once in section 6, which
    // is the pair a reader of the prose gets. Zero occurrences means the sentence was edited away;
    // more than the one each means the document started saying the same thing in two voices.
    const spec = readFileSync(specPath, 'utf8');
    const versionRow = spec.split('\n').filter((line) => line.startsWith('| `v` | int |'));
    expect(versionRow).toHaveLength(1);
    expect(versionRow[0]!.split(' does not define')).toHaveLength(2);
    const section = sectionBody(spec, '## 6. Versioning');
    expect(section.split('does not define')).toHaveLength(2);

    // Section 6 carries the same boundary in the same direction, named by the four keys a reader of
    // the field table has, and pointing at the file that decides it instead of at itself.
    const specProse = flat(section);
    saidOnce('section 6', specProse, 'The rule stops at the payload map');
    saidOnce('section 6', specProse, 'the four maps nested inside it, `meas`, `att`, `tok` and `mk`');
    saidOnce('section 6', specProse, 'carry no `...` in the normative CDDL either');
    saidOnce('section 6', specProse, 'reads what it names there and drops the rest rather than refusing the document');
    expect(specProse).not.toMatch(/\bare open\b/u);

    // The twin says the same thing, and its three closedness descriptions have to agree on the level.
    // The root is the only one that speaks below the payload map, and it names all four nested keys
    // and says the keyword is absent there; each branch description closes its own map and names
    // nothing inside it, so neither can be read as constraining a level this schema does not.
    saidOnce('the twin', shape.description, 'Each branch is closed');
    saidOnce('the twin', shape.description, 'Closure is at that one level');
    saidOnce('the twin', shape.description, 'carry no such keyword');
    for (const key of ['meas', 'att', 'tok', 'mk']) {
      expect(shape.description.includes(`\`${key}\``), `the twin names ${key}`).toBe(true);
    }
    for (const branch of ['payloadV1', 'payloadV2'] as const) {
      const doc = shape.$defs[branch].description;
      saidOnce(`the twin's ${branch} description`, doc, 'The map is closed');
      for (const key of ['meas', 'att', 'tok', 'mk']) {
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
