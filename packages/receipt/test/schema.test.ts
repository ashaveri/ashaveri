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
const schema = JSON.parse(readFileSync(schemaPath, 'utf8')) as object;

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
 * `$defs.payloadV1/properties/meas/allOf/0` and `/1` each declare `type: "string"` next to their
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

  it('holds a v1 payload to thirteen members and a v2 payload to fourteen', () => {
    // The branches are exclusive on `v`, which is what makes the version a discriminant rather
    // than a hint: neither of these is a document, and neither reads as the other.
    expect(outcome(rewritten(v1('software', DIGEST), (members) => { members.v = 2; }))).not.toBeNull();
    expect(outcome(rewritten(v1('software', DIGEST), (members) => { members.mk = { sch: 'none', d: toHex(DIGEST) }; }))).toBeNull();
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
