import { describe, expect, it } from 'vitest';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  MODEL_INVENTORY_ASSERTED_MODEL_FIELDS,
  MODEL_INVENTORY_BOUND_MODEL_FIELDS,
  MODEL_INVENTORY_LIMITS,
  MODEL_INVENTORY_MANIFEST_MEMBERS,
  MODEL_INVENTORY_MODEL_MEMBERS,
  MODEL_INVENTORY_POINTERS,
  MODEL_INVENTORY_POINTER_CITATIONS,
  MODEL_INVENTORY_REVIEW_MEMBERS,
  MODEL_INVENTORY_V1_MEMBERS,
  ReceiptError,
  encodeModelInventory,
  modelInventoryBytes,
  parseModelInventory,
  sealDeploymentManifest,
  signingKeyFromSeed,
  toBase64Url,
  toHex,
  verifyModelInventory,
  type ModelInventoryRecord,
} from '../src/index.js';

/**
 * The model inventory's strict reader, driven over the bytes of a file rather than over objects, and
 * the bound/asserted split driven over a manifest the reader is handed beside the record. The refusal
 * cases are one edit of the writer's own bytes at the position each fault names, so a row tests the
 * rule it states rather than a document assembled out of junk.
 */

const encoded = (text: string): Uint8Array => new TextEncoder().encode(text);
const decoded = (bytes: Uint8Array): string => new TextDecoder().decode(bytes);

const MANIFEST_KEY = signingKeyFromSeed(sha256(encoded('ashaveri-test/model-inventory/manifest')));
const MODEL_ID = 'test-model/one';
const WTS = toHex(sha256(encoded('test weights')));
const AT = 1_772_000_000;

const MANIFEST_DOCUMENT = {
  v: 1,
  iss: 'dpl-test-inventory',
  ins: 'ins-test-inventory',
  epk: 1,
  keys: [
    {
      kid: toHex(MANIFEST_KEY.kid),
      alg: 'Ed25519',
      publicKey: toBase64Url(MANIFEST_KEY.publicKey),
    },
  ],
  models: [{ id: MODEL_ID, wts: WTS }],
  meas: { tee: 'software', m: toHex(sha256(encoded('test measurement'))) },
};

const SEALED_MANIFEST = sealDeploymentManifest(encoded(JSON.stringify(MANIFEST_DOCUMENT)), MANIFEST_KEY);
const MANIFEST_SHA256 = toHex(sha256(SEALED_MANIFEST));

function record(): ModelInventoryRecord {
  return {
    v: 1,
    prov: 'fixture',
    at: AT,
    scope: 'Fixture extract over the test deployment this suite seals its own manifest for.',
    manifest: { sha256: MANIFEST_SHA256, iss: MANIFEST_DOCUMENT.iss, ins: MANIFEST_DOCUMENT.ins },
    models: [
      {
        bound: { id: MODEL_ID, wts: WTS },
        asserted: {
          version: 'one',
          purpose: 'Demonstrating the inventory layout over fixture material.',
          risk: 'fixture',
          reviews: [{ at: AT, by: 'the fixture deployer' }],
        },
      },
    ],
    pointers: [...MODEL_INVENTORY_POINTERS],
    limits: MODEL_INVENTORY_LIMITS,
  };
}

/** One edit of the writer's bytes, every other byte left as the writer wrote it. */
function edited(base: ModelInventoryRecord, mutate: (document: Record<string, unknown>) => void): Uint8Array {
  const document = JSON.parse(decoded(encodeModelInventory(base))) as Record<string, unknown>;
  mutate(document);
  return encoded(`${JSON.stringify(document, null, 2)}\n`);
}

function codeOf(run: () => unknown): string {
  try {
    run();
  } catch (err) {
    if (err instanceof ReceiptError) return err.code;
    throw err;
  }
  throw new Error('the reader accepted a document this case states it refuses');
}

describe('the model inventory layout', () => {
  it('round-trips a record through the writer and the reader', () => {
    const base = record();
    const bytes = modelInventoryBytes(base);
    expect(parseModelInventory(bytes)).toEqual(base);
    expect(encoded(`${JSON.stringify(JSON.parse(decoded(bytes)), null, 2)}\n`)).toEqual(bytes);
  });

  it('groups each model entry into the bound and asserted fields the layout fixes', () => {
    const parsed = parseModelInventory(modelInventoryBytes(record()));
    const [model] = parsed.models;
    expect(Object.keys(model!.bound)).toEqual([...MODEL_INVENTORY_BOUND_MODEL_FIELDS]);
    expect(Object.keys(model!.asserted)).toEqual([...MODEL_INVENTORY_ASSERTED_MODEL_FIELDS]);
    expect(model!.bound.id).toBe(MODEL_ID);
    expect(model!.asserted.purpose).toBe('Demonstrating the inventory layout over fixture material.');
  });

  it('declares the member lists the wire closes over', () => {
    const document = JSON.parse(decoded(encodeModelInventory(record()))) as Record<string, unknown>;
    expect(Object.keys(document)).toEqual([...MODEL_INVENTORY_V1_MEMBERS]);
    expect(Object.keys(document['manifest'] as object)).toEqual([...MODEL_INVENTORY_MANIFEST_MEMBERS]);
    const [model] = document['models'] as Array<Record<string, unknown>>;
    expect(Object.keys(model!)).toEqual([...MODEL_INVENTORY_MODEL_MEMBERS]);
    const [review] = model!['reviews'] as Array<Record<string, unknown>>;
    expect(Object.keys(review!)).toEqual([...MODEL_INVENTORY_REVIEW_MEMBERS]);
  });

  it('gives every pointer a citation', () => {
    for (const pointer of MODEL_INVENTORY_POINTERS) {
      expect(MODEL_INVENTORY_POINTER_CITATIONS[pointer].length).toBeGreaterThan(0);
    }
  });
});

describe('the model inventory reader refuses', () => {
  it('a document that is not one JSON object', () => {
    expect(codeOf(() => parseModelInventory(encoded('not json')))).toBe('MODEL_INVENTORY_BAD_DOCUMENT');
    expect(codeOf(() => parseModelInventory(encoded('[]')))).toBe('MODEL_INVENTORY_BAD_DOCUMENT');
  });

  it('a member named twice, while the bytes carry both', () => {
    const bytes = encoded(decoded(encodeModelInventory(record())).replace('"v": 1,', '"v": 1,\n  "v": 1,'));
    expect(codeOf(() => parseModelInventory(bytes))).toBe('MODEL_INVENTORY_BAD_DOCUMENT');
  });

  it('a float wearing an integer', () => {
    const bytes = encodeModelInventory(record());
    const spelled = encoded(decoded(bytes).replace(`"at": ${AT}`, `"at": ${AT}.0`));
    expect(codeOf(() => parseModelInventory(spelled))).toBe('MODEL_INVENTORY_BAD_DOCUMENT');
  });

  it('a version no layout reads', () => {
    const bytes = edited(record(), (document) => {
      document['v'] = 2;
    });
    expect(codeOf(() => parseModelInventory(bytes))).toBe('MODEL_INVENTORY_UNSUPPORTED_VERSION');
  });

  it('a member the top level does not define', () => {
    const bytes = edited(record(), (document) => {
      document['future'] = 'a member no version names';
    });
    expect(codeOf(() => parseModelInventory(bytes))).toBe('MODEL_INVENTORY_BAD_DOCUMENT');
  });

  it('a critical member of a model entry the layout does not define', () => {
    const bytes = edited(record(), (document) => {
      const [model] = document['models'] as Array<Record<string, unknown>>;
      model!['weightsFile'] = 'a path no member of this layout holds';
    });
    expect(codeOf(() => parseModelInventory(bytes))).toBe('MODEL_INVENTORY_BAD_DOCUMENT');
  });

  it('a member of the manifest block the layout does not define', () => {
    const bytes = edited(record(), (document) => {
      const manifest = document['manifest'] as Record<string, unknown>;
      manifest['epk'] = 1;
    });
    expect(codeOf(() => parseModelInventory(bytes))).toBe('MODEL_INVENTORY_BAD_DOCUMENT');
  });

  it('an absent member', () => {
    const bytes = edited(record(), (document) => {
      delete document['scope'];
    });
    expect(codeOf(() => parseModelInventory(bytes))).toBe('MODEL_INVENTORY_BAD_DOCUMENT');
  });

  it('a limits member wording its own limits', () => {
    const bytes = edited(record(), (document) => {
      document['limits'] = 'This record has no limits.';
    });
    expect(codeOf(() => parseModelInventory(bytes))).toBe('MODEL_INVENTORY_BAD_DOCUMENT');
  });

  it('a pointer outside the registry', () => {
    const bytes = edited(record(), (document) => {
      document['pointers'] = ['app-1-7'];
    });
    expect(codeOf(() => parseModelInventory(bytes))).toBe('MODEL_INVENTORY_UNKNOWN_POINTER');
  });

  it('an empty models list, an empty reviews list and an empty pointers list', () => {
    expect(
      codeOf(() =>
        parseModelInventory(
          edited(record(), (document) => {
            document['models'] = [];
          }),
        ),
      ),
    ).toBe('MODEL_INVENTORY_BAD_DOCUMENT');
    expect(
      codeOf(() =>
        parseModelInventory(
          edited(record(), (document) => {
            const [model] = document['models'] as Array<Record<string, unknown>>;
            model!['reviews'] = [];
          }),
        ),
      ),
    ).toBe('MODEL_INVENTORY_BAD_DOCUMENT');
    expect(
      codeOf(() =>
        parseModelInventory(
          edited(record(), (document) => {
            document['pointers'] = [];
          }),
        ),
      ),
    ).toBe('MODEL_INVENTORY_BAD_DOCUMENT');
  });

  it('one model named twice', () => {
    const bytes = edited(record(), (document) => {
      const models = document['models'] as Array<Record<string, unknown>>;
      models.push({ ...models[0] });
    });
    expect(codeOf(() => parseModelInventory(bytes))).toBe('MODEL_INVENTORY_BAD_DOCUMENT');
  });

  it('a review stamped after the extract that carries it', () => {
    const bytes = edited(record(), (document) => {
      const [model] = document['models'] as Array<Record<string, unknown>>;
      const [review] = model!['reviews'] as Array<Record<string, unknown>>;
      review!['at'] = AT + 1;
    });
    expect(codeOf(() => parseModelInventory(bytes))).toBe('MODEL_INVENTORY_BAD_DOCUMENT');
  });

  it('a weights digest in uppercase hex', () => {
    const bytes = edited(record(), (document) => {
      const [model] = document['models'] as Array<Record<string, unknown>>;
      model!['wts'] = WTS.toUpperCase();
    });
    expect(codeOf(() => parseModelInventory(bytes))).toBe('MODEL_INVENTORY_BAD_DOCUMENT');
  });

  it('a provenance outside the vocabulary', () => {
    const bytes = edited(record(), (document) => {
      document['prov'] = 'synthetic';
    });
    expect(codeOf(() => parseModelInventory(bytes))).toBe('MODEL_INVENTORY_BAD_DOCUMENT');
  });

  it('a record whose writer state the reader would refuse', () => {
    const base = record();
    const broken: ModelInventoryRecord = { ...base, limits: 'worded by the writer' };
    expect(codeOf(() => modelInventoryBytes(broken))).toBe('MODEL_INVENTORY_BAD_DOCUMENT');
  });
});

describe('the bound and asserted split, over the manifest the record designates', () => {
  it('verifies an honest record against its sealed manifest, authenticated under the designated key', () => {
    const verified = verifyModelInventory(modelInventoryBytes(record()), {
      manifestBytes: SEALED_MANIFEST,
      manifestPublicKey: MANIFEST_KEY.publicKey,
    });
    expect(verified.record).toEqual(record());
    expect(verified.manifest).toEqual({ sealed: true, authenticated: true });
  });

  it('reads a sealed manifest without a key and reports the authentication it did not do', () => {
    const verified = verifyModelInventory(modelInventoryBytes(record()), { manifestBytes: SEALED_MANIFEST });
    expect(verified.manifest).toEqual({ sealed: true, authenticated: false });
  });

  it('reads the plain payload bytes when those are what the record designates', () => {
    const plain = encoded(JSON.stringify(MANIFEST_DOCUMENT));
    const base = record();
    const designating: ModelInventoryRecord = {
      ...base,
      manifest: { ...base.manifest, sha256: toHex(sha256(plain)) },
    };
    const verified = verifyModelInventory(modelInventoryBytes(designating), { manifestBytes: plain });
    expect(verified.manifest).toEqual({ sealed: false, authenticated: false });
  });

  it('refuses a designated key beside a plain manifest', () => {
    const plain = encoded(JSON.stringify(MANIFEST_DOCUMENT));
    const base = record();
    const designating: ModelInventoryRecord = {
      ...base,
      manifest: { ...base.manifest, sha256: toHex(sha256(plain)) },
    };
    expect(
      codeOf(() =>
        verifyModelInventory(modelInventoryBytes(designating), {
          manifestBytes: plain,
          manifestPublicKey: MANIFEST_KEY.publicKey,
        }),
      ),
    ).toBe('MODEL_INVENTORY_MANIFEST_UNSEALED');
  });

  it('refuses manifest bytes that are not the ones the record designates', () => {
    const other = sealDeploymentManifest(
      encoded(JSON.stringify({ ...MANIFEST_DOCUMENT, ins: 'another-instance' })),
      MANIFEST_KEY,
    );
    expect(
      codeOf(() => verifyModelInventory(modelInventoryBytes(record()), { manifestBytes: other })),
    ).toBe('MODEL_INVENTORY_MANIFEST_MISMATCH');
  });

  it('refuses a designated manifest that states no models to bind against', () => {
    const { models: _models, ...withoutModels } = MANIFEST_DOCUMENT;
    const sealed = sealDeploymentManifest(encoded(JSON.stringify(withoutModels)), MANIFEST_KEY);
    const base = record();
    const designating: ModelInventoryRecord = {
      ...base,
      manifest: { ...base.manifest, sha256: toHex(sha256(sealed)) },
    };
    expect(
      codeOf(() => verifyModelInventory(modelInventoryBytes(designating), { manifestBytes: sealed })),
    ).toBe('MODEL_INVENTORY_MANIFEST_UNREADABLE');
  });

  it('accepts a mutation of an asserted field, which stays asserted', () => {
    const bytes = edited(record(), (document) => {
      const [model] = document['models'] as Array<Record<string, unknown>>;
      model!['purpose'] = 'A purpose the deployment stated after assembly.';
    });
    const verified = verifyModelInventory(bytes, {
      manifestBytes: SEALED_MANIFEST,
      manifestPublicKey: MANIFEST_KEY.publicKey,
    });
    expect(verified.record.models[0]!.asserted.purpose).toBe('A purpose the deployment stated after assembly.');
    expect(verified.record.models[0]!.bound).toEqual({ id: MODEL_ID, wts: WTS });
  });

  it('refuses a mutation of a bound model id, with the two values named', () => {
    const bytes = edited(record(), (document) => {
      const [model] = document['models'] as Array<Record<string, unknown>>;
      model!['id'] = 'test-model/two';
    });
    expect(
      codeOf(() => verifyModelInventory(bytes, { manifestBytes: SEALED_MANIFEST })),
    ).toBe('MODEL_INVENTORY_BOUND_DISAGREES');
  });

  it('refuses a mutation of a bound weights digest', () => {
    const bytes = edited(record(), (document) => {
      const [model] = document['models'] as Array<Record<string, unknown>>;
      model!['wts'] = toHex(sha256(encoded('other weights')));
    });
    expect(
      codeOf(() => verifyModelInventory(bytes, { manifestBytes: SEALED_MANIFEST })),
    ).toBe('MODEL_INVENTORY_BOUND_DISAGREES');
  });

  it('refuses a mutation of the bound issuer', () => {
    const bytes = edited(record(), (document) => {
      const manifest = document['manifest'] as Record<string, unknown>;
      manifest['iss'] = 'dpl-someone-else';
    });
    expect(
      codeOf(() => verifyModelInventory(bytes, { manifestBytes: SEALED_MANIFEST })),
    ).toBe('MODEL_INVENTORY_BOUND_DISAGREES');
  });

  it('refuses a model the designated manifest does not declare', () => {
    const bytes = edited(record(), (document) => {
      const [model] = document['models'] as Array<Record<string, unknown>>;
      model!['id'] = 'test-model/undeclared';
      model!['wts'] = WTS;
    });
    expect(
      codeOf(() => verifyModelInventory(bytes, { manifestBytes: SEALED_MANIFEST })),
    ).toBe('MODEL_INVENTORY_BOUND_DISAGREES');
  });
});