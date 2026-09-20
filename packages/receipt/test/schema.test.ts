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

/** The parts of this schema the agreement test below reads: one branch per payload version. */
interface SchemaShape {
  $defs: {
    payloadFields: { properties: Record<string, unknown> };
    payloadV1: { properties: Record<string, unknown> };
    payloadV2: { properties: Record<string, unknown> };
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

/** The body of one `## ` section of a markdown document, up to the next heading of any level. */
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
    // need not decide whether the absence was a rule or an oversight.
    expect(cddl).toMatch(/;[^\n]*\bclosed\b/iu);
    expect(cddlRule(cddl, 'Ashaveri-Receipt-Payload-v1').includes('...')).toBe(false);
    expect(cddlRule(cddl, 'Ashaveri-Receipt-Payload-v2').includes('...')).toBe(false);

    // And the specification states the refusal once in the field table and once in section 6, which
    // is the pair a reader of the prose gets. Zero occurrences means the sentence was edited away;
    // more than the one each means the document started saying the same thing in two voices.
    const spec = readFileSync(specPath, 'utf8');
    const versionRow = spec.split('\n').filter((line) => line.startsWith('| `v` | int |'));
    expect(versionRow).toHaveLength(1);
    expect(versionRow[0]!.split(' does not define')).toHaveLength(2);
    const section = sectionBody(spec, '## 6. Versioning');
    expect(section.split('does not define')).toHaveLength(2);
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
