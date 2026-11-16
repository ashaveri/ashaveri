import { describe, expect, it } from 'vitest';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  MODEL_INVENTORY_ASSERTED_MODEL_FIELDS,
  MODEL_INVENTORY_BOUND_MODEL_FIELDS,
  MODEL_INVENTORY_LIMITS,
  MODEL_INVENTORY_POINTERS,
  MODEL_INVENTORY_POINTER_CITATIONS,
  ReceiptError,
  decodeSealedDeploymentManifest,
  encodeModelInventory,
  fromBase64Url,
  modelInventoryBytes,
  parseModelInventory,
  toHex,
  verifyExport,
  verifyModelInventory,
} from '@ashaveri/receipt';
import { loadModelInventoryVectors } from '../src/index.js';

/**
 * The published model inventory vectors, replayed the way a port replays them: read the record bytes,
 * hand them to the shipped reader, and answer the verdict the row promises. The accepted rows are also
 * written back through the shipped writer, so the bytes a port holds are the bytes this repository's
 * own writer produces for the record they parse to. The bound cases are replayed as pairs, the record
 * beside the manifest bytes the case carries, through the verifying door rather than the parsing one.
 *
 * The bound fields of the accepted record are also re-derived here from the manifest payload itself,
 * read out of the seal the family publishes, so the agreement the verifying door reports is witnessed
 * against the manifest's own statement rather than against the reader's report of it.
 */

const file = loadModelInventoryVectors();

const decoded = (bytes: Uint8Array): string => new TextDecoder().decode(bytes);

function verdictOf(bytes: Uint8Array): string {
  try {
    parseModelInventory(bytes);
    return 'verify-ok';
  } catch (err) {
    if (err instanceof ReceiptError) return err.code;
    throw err;
  }
}

const ACCEPTED = file.vectors.find((one) => one.expected === 'verify-ok');
if (ACCEPTED === undefined) throw new Error('the family publishes no accepted record to replay the ride from');
const ACCEPTED_BYTES = fromBase64Url(ACCEPTED.recordBase64Url);
const MANIFEST_BYTES = fromBase64Url(file.rule.manifest.documentBase64Url);
const MANIFEST_KEY = fromBase64Url(file.rule.manifest.publicKeyBase64Url);

describe('the model inventory family states the shipped rule', () => {
  it('enumerates the pointers, citations, limits and field split the package publishes', () => {
    expect(file.rule.pointers).toEqual([...MODEL_INVENTORY_POINTERS]);
    expect(file.rule.pointerCitations).toEqual({ ...MODEL_INVENTORY_POINTER_CITATIONS });
    expect(file.rule.limits).toBe(MODEL_INVENTORY_LIMITS);
    expect(file.rule.boundModelFields).toEqual([...MODEL_INVENTORY_BOUND_MODEL_FIELDS]);
    expect(file.rule.assertedModelFields).toEqual([...MODEL_INVENTORY_ASSERTED_MODEL_FIELDS]);
  });

  it('publishes the manifest row it names, byte for byte', () => {
    expect(file.rule.manifest.row).toBe('manifest-v1.json#paired-with-the-published-receipt-family');
    const seal = decodeSealedDeploymentManifest(MANIFEST_BYTES);
    expect(toHex(sha256(MANIFEST_BYTES))).toBe(parseModelInventory(ACCEPTED_BYTES).manifest.sha256);
    expect(seal.header.contentType).toBe('ashaveri/deployment-manifest');
  });
});

describe('the model inventory parse rows replay', () => {
  for (const one of file.vectors) {
    it(`${one.name} answers ${one.expected}`, () => {
      const bytes = fromBase64Url(one.recordBase64Url);
      expect(bytes.length).toBe(one.recordByteLength);
      expect(verdictOf(bytes)).toBe(one.expected);
      if (one.expected !== 'verify-ok') return;
      const parsed = parseModelInventory(bytes);
      expect(encodeModelInventory(parsed)).toEqual(bytes);
      expect(modelInventoryBytes(parsed)).toEqual(bytes);
      expect(parsed.prov).toBe('fixture');
    });
  }

  it('refuses a record whose fault block names a position the bytes do not carry', () => {
    // The fault blocks are claims about the rows beside them, and a row whose edit moved nothing would
    // keep its refusal while testing a different rule. Each refusing row's bytes differ from the
    // accepted record's bytes, which is the least the edit has to do.
    for (const one of file.vectors) {
      if (one.expected === 'verify-ok') continue;
      expect(one.fault, `${one.name} states no fault block`).toBeDefined();
      expect(fromBase64Url(one.recordBase64Url)).not.toEqual(ACCEPTED_BYTES);
    }
  });
});

describe('the model inventory bound cases replay', () => {
  for (const one of file.boundCases) {
    it(`${one.name} answers ${one.expected}`, () => {
      const recordBytes = fromBase64Url(one.recordBase64Url);
      const manifestBytes = fromBase64Url(one.manifestBase64Url);
      const options =
        one.publicKeyBase64Url === undefined
          ? { manifestBytes }
          : { manifestBytes, manifestPublicKey: fromBase64Url(one.publicKeyBase64Url) };
      if (one.expected !== 'verify-ok') {
        expect(() => verifyModelInventory(recordBytes, options)).toThrow(
          expect.objectContaining({ code: one.expected }),
        );
        return;
      }
      const verified = verifyModelInventory(recordBytes, options);
      if (one.sealed !== undefined) expect(verified.manifest.sealed).toBe(one.sealed);
      if (one.authenticated !== undefined) expect(verified.manifest.authenticated).toBe(one.authenticated);
    });
  }

  it('witnesses the split: the bound mutation pair differs in outcome, the asserted mutation reads', () => {
    const refused = file.boundCases.filter((one) => one.expected === 'MODEL_INVENTORY_BOUND_DISAGREES');
    expect(refused.length).toBeGreaterThanOrEqual(3);
    const accepted = file.boundCases.find((one) => one.name === 'bound-asserted-mutation-accepted');
    expect(accepted?.expected).toBe('verify-ok');
    const asserted = parseModelInventory(fromBase64Url(accepted!.recordBase64Url));
    const honest = parseModelInventory(ACCEPTED_BYTES);
    expect(asserted.models[0]!.bound).toEqual(honest.models[0]!.bound);
    expect(asserted.models[0]!.asserted.purpose).not.toBe(honest.models[0]!.asserted.purpose);
  });
});

describe('the accepted record binds to the manifest payload, re-derived here', () => {
  it('copies the model id, weights digest, issuer and instance out of the signed payload', () => {
    const payload = JSON.parse(decoded(decodeSealedDeploymentManifest(MANIFEST_BYTES).payloadBytes)) as {
      iss: string;
      ins: string;
      models: Array<{ id: string; wts: string }>;
    };
    const record = parseModelInventory(ACCEPTED_BYTES);
    expect(record.manifest.iss).toBe(payload.iss);
    expect(record.manifest.ins).toBe(payload.ins);
    expect(record.models.length).toBe(payload.models.length);
    for (const [index, model] of record.models.entries()) {
      expect(model.bound.id).toBe(payload.models[index]!.id);
      expect(model.bound.wts).toBe(payload.models[index]!.wts);
    }
  });
});

describe('the export ride replays through the published export contract', () => {
  it('verifies the export, reads the item back through both inventory doors, and moves no export member', () => {
    const exportBytes = fromBase64Url(file.rule.exportRide.exportBase64Url);
    const exportKey = fromBase64Url(file.rule.exportRide.publicKeyBase64Url);
    const verified = verifyExport(exportBytes, exportKey);
    expect(verified.manifest.collection.k).toBe('plain');
    if (verified.outcome.kind !== 'plain') throw new Error('the ride is not the plain arm');
    const item = verified.outcome.items.find((one) => one.id === file.rule.exportRide.itemId);
    expect(item, 'the export carries the item the ride names').toBeDefined();
    expect(item!.prov).toBe('fixture');
    expect(item!.orig.k).toBe('inline');
    if (item!.orig.k !== 'inline') throw new Error('the ride item is not inline');
    expect(item!.orig.bytes).toEqual(ACCEPTED_BYTES);
    expect(parseModelInventory(item!.orig.bytes)).toEqual(parseModelInventory(ACCEPTED_BYTES));
    const bound = verifyModelInventory(item!.orig.bytes, {
      manifestBytes: MANIFEST_BYTES,
      manifestPublicKey: MANIFEST_KEY,
    });
    expect(bound.manifest).toEqual({ sealed: true, authenticated: true });
  });
});