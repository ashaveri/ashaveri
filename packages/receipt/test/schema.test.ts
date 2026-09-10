import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';
import {
  MEASUREMENT_BYTES,
  receiptToJson,
  type Measurement,
  type ReceiptPayload,
} from '../src/index.js';

const schemaPath = fileURLToPath(new URL('../schemas/receipt-v1.schema.json', import.meta.url));
const schema = JSON.parse(readFileSync(schemaPath, 'utf8')) as object;
// strict:false because no format validator is registered for "uri". The patterns in the
// schema, not the formats, carry the constraints a reimplementer has to match.
const validate = new Ajv2020({ strict: false }).compile(schema) as (value: unknown) => boolean;

const DIGEST = new Uint8Array(32).fill(2);

/** The projection the schema describes, with only the measurement varying per case. */
function twin(tee: string, m: Uint8Array): unknown {
  const payload: ReceiptPayload = {
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
  // Signature and kid are placeholders here: this suite checks the schema against the same
  // kind-to-width table the codec enforces, and the schema only constrains their shape.
  return receiptToJson(payload, new Uint8Array(64).fill(3), new Uint8Array(32).fill(4));
}

function outcome(tee: string, bytes: number): string | null {
  const value = twin(tee, new Uint8Array(bytes).fill(1));
  return validate(value) ? null : JSON.stringify(validate.errors);
}

describe('receipt-v1 JSON Schema', () => {
  it('accepts every kind at the width the codec requires', () => {
    for (const [tee, bytes] of Object.entries(MEASUREMENT_BYTES)) {
      expect(outcome(tee, bytes), `tee ${tee} with ${bytes} bytes`).toBeNull();
    }
  });

  it("rejects a measurement at another kind's width", () => {
    for (const [tee, bytes] of Object.entries(MEASUREMENT_BYTES)) {
      const wrong = bytes === 32 ? 48 : 32;
      expect(outcome(tee, wrong), `tee ${tee} with ${wrong} bytes`).not.toBeNull();
    }
  });

  it('rejects an unknown environment kind', () => {
    expect(outcome('sgx', 48)).not.toBeNull();
  });
});
