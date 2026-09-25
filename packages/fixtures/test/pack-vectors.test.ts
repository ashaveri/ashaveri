import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  PACK_CONTENT_TYPE,
  ReceiptError,
  decodePack,
  packRecordDigest,
  toHex,
  verifyPack,
  type PackManifest,
  type PackVerifyOptions,
  type VerifiedPack,
} from '@ashaveri/receipt';
import { loadPackVectors, type PackVector } from '../src/index.js';
import { unionMembers } from './doc-contract.js';

/**
 * The published pack vectors, replayed the way a port replays them: take the document out of the file, hand
 * the reader the designation the file states beside it, and compare the answer with the verdict the file
 * states. Nothing here computes an expected value from the reader. The walk order, the ordering findings, the
 * named items and both verdict columns are data in `data/pack-v1.json`, and the only question asked of the
 * code is whether it answers as the file says it does.
 *
 * Three more things are checked on the way, because a suite of chained documents is only as good as the chain.
 * The record table the file publishes beside its honest run is recomputed from the document's own items, so a
 * framing that only this implementation's writer produces shows up as a disagreement rather than as a silent
 * convention. Every code of the pack family in the registry is required to be reached by a committed document,
 * which is the only way a refusal added to `errors.ts` without a case cannot pass unnoticed. And the two
 * columns are required to disagree where they are said to, because the pair is the substance of a reader that
 * keeps "these bytes are whole" apart from "this caller can attribute them".
 *
 * The client half of this reading lives in `packages/cli/test/vector-conformance.test.ts`, which drives the
 * same rows through the paths a shipped verifier takes; what is here is the format package's own reader, the
 * one every verdict in this file was witnessed with when the generator wrote it.
 */

const file = loadPackVectors();
const ERRORS = '../../../packages/receipt/src/errors.ts';

const bytes = (base64url: string): Uint8Array => new Uint8Array(Buffer.from(base64url, 'base64url'));

/** The options a row's designation builds, which are the reader's two shapes and no third. */
function optionsFor(one: PackVector): PackVerifyOptions {
  if (one.read.pinned !== undefined) return { publicKey: bytes(one.read.pinned) };
  if (one.read.retained === undefined) return {};
  const byKid = new Map(one.read.retained.map((one2) => [one2.kid, one2.publicKeyBase64Url]));
  return {
    resolveKey: (kid) => {
      const found = byKid.get(toHex(kid));
      return found === undefined ? undefined : bytes(found);
    },
  };
}

/** What the shipped reader answers for a row, and the reading whenever it returned one. */
function read(one: PackVector): { verdict: string; result: VerifiedPack | null } {
  try {
    return { verdict: 'verify-ok', result: verifyPack(bytes(one.documentBase64Url), optionsFor(one)) };
  } catch (err) {
    if (err instanceof ReceiptError) return { verdict: err.code, result: null };
    throw err;
  }
}

/** What the keyless half answers for the same bytes. */
function structural(one: PackVector): string {
  try {
    decodePack(bytes(one.documentBase64Url));
    return 'verify-ok';
  } catch (err) {
    if (err instanceof ReceiptError) return err.code;
    throw err;
  }
}

const publishedIds = new Set(file.layout.keyMaterial.map((one) => one.kidHex));
const honest = file.vectors.find((one) => one.name === 'well-formed-three-items');

describe('the evidence pack vectors', () => {
  it('are a suite the format, its twin and its writer all still describe', () => {
    expect(file.version).toBe(1);
    expect(file.description.length).toBeGreaterThan(0);
    expect(file.layout.contentType).toBe(PACK_CONTENT_TYPE);
    expect(file.layout.headerLabels).toEqual({ alg: 1, typ: 3, kid: 4 });
    // Every path the file names is a file, and the format and the twin still carry the content type this
    // suite is about: a port pointed at a document that no longer states the type would compare the wrong pair.
    for (const path of [file.layout.format, file.layout.twin, file.layout.prose.split(' ')[0] ?? '']) {
      expect(existsSync(fileURLToPath(new URL(`../../../${path}`, import.meta.url))), `${path} is named by the suite and is not there`).toBe(true);
    }
    const cddl = readFileSync(fileURLToPath(new URL(`../../../${file.layout.format}`, import.meta.url)), 'utf8');
    expect(cddl).toContain(`"${PACK_CONTENT_TYPE}"`);
    const twin = JSON.parse(readFileSync(fileURLToPath(new URL(`../../../${file.layout.twin}`, import.meta.url)), 'utf8')) as {
      properties?: { protectedHeader?: { properties?: { typ?: { const?: unknown } } } };
    };
    expect(twin.properties?.protectedHeader?.properties?.typ?.const).toBe(PACK_CONTENT_TYPE);
    // The writer the file names is reachable from the package entry, which is the half that makes these bytes
    // rather than only describing them.
    for (const name of ['signPack', 'encodePackManifest', 'sealPack']) {
      expect(file.layout.writer, `the suite names no ${name} as the code that made these documents`).toContain(name);
    }
  });

  it('publishes a record framing that comes back out of the document it sits beside', () => {
    expect(honest, 'the suite publishes no honest run').toBeDefined();
    if (honest === undefined) return;
    const manifest = decodePack(bytes(honest.documentBase64Url)).manifest;
    expect(file.layout.records.map((one) => one.id)).toEqual(manifest.items.map((one) => one.id));
    for (const [index, row] of file.layout.records.entries()) {
      const item = manifest.items[index]!;
      expect(row.position, `record ${row.id}`).toBe(index);
      expect(row.id).toBe(item.id);
      expect(row.iat).toBe(item.iat);
      expect(row.prevHex).toBe(toHex(item.prev));
      expect(row.receiptByteLength).toBe(item.receipt.length);
      // The digest is recomputed from the bytes the item carries, which is what a reader does to walk: a
      // framing that moved in the writer and not here would show up as this disagreement.
      expect(toHex(packRecordDigest(item)), `${row.id} digest`).toBe(row.digestHex);
    }
    // And the table describes a run that closes: the first predecessor is the signed anchor and the last
    // digest is the signed head, which is the pair the walk is between.
    expect(file.layout.records[0]!.prevHex).toBe(toHex(manifest.chain.anchor));
    expect(file.layout.records[file.layout.records.length - 1]!.digestHex).toBe(toHex(manifest.chain.head));
  });

  it('designates only keys it publishes, and publishes keys that resolve', () => {
    for (const one of file.layout.keyMaterial) {
      const publicKey = bytes(one.publicKeyBase64Url);
      expect(toHex(sha256(publicKey)), `${one.id} kid`).toBe(one.kidHex);
      expect(one.publicKeyHex).toBe(toHex(publicKey));
    }
    for (const one of file.vectors) {
      expect(bytes(one.documentBase64Url)).toHaveLength(one.documentByteLength);
      for (const pin of one.read.retained ?? []) {
        expect(publishedIds.has(pin.kid), `${one.name} retains ${pin.kid}, which the suite publishes no key for`).toBe(true);
      }
      if (one.read.pinned !== undefined) {
        const pinned = bytes(one.read.pinned);
        const kid = toHex(sha256(pinned));
        expect(publishedIds.has(kid), `${one.name} pins a key the suite publishes no kid for`).toBe(true);
      }
    }
    // A whole sealed pack names the kid that made its signature, and this suite publishes it, so a port can
    // reproduce a seal rather than only check one.
    for (const one of file.vectors) {
      const documentBytes = bytes(one.documentBase64Url);
      let kid: string;
      try {
        kid = toHex(decodePack(documentBytes).header.kid);
      } catch {
        continue;
      }
      expect(publishedIds.has(kid), `${one.name} is sealed under a kid the suite does not publish`).toBe(true);
    }
  });

  it('carries no field a row is not told about and no code no registry declares', () => {
    const allowed = new Set(['name', 'note', 'documentBase64Url', 'documentByteLength', 'read', 'verdict', 'structural', ...file.layout.verdictFields]);
    for (const one of file.vectors) {
      for (const field of Object.keys(one)) {
        expect(allowed.has(field), `${one.name} carries ${field}, which the suite describes no field of`).toBe(true);
      }
    }
    const declared = new Set(unionMembers('ReceiptErrorCode', ERRORS));
    for (const one of file.vectors) {
      if (one.verdict === 'verify-ok') continue;
      expect(declared.has(one.verdict), `${one.name} answers ${one.verdict}, which no registry declares`).toBe(true);
    }
    for (const one of file.vectors) {
      if (one.structural === 'verify-ok') continue;
      expect(declared.has(one.structural), `${one.name} is structurally ${one.structural}, which no registry declares`).toBe(true);
    }
    // The file's own roster is exactly the set its rows answer with, so a verdict that left the suite is caught
    // from both ends of one list.
    expect([...file.layout.codes].sort()).toEqual([...new Set(file.vectors.map((one) => one.verdict))].sort());
  });

  it('gives every row the verdict and the reading its file states', () => {
    const observed = file.vectors.map((one) => `${one.name}: ${read(one).verdict}`);
    expect(observed).toEqual(file.vectors.map((one) => `${one.name}: ${one.verdict}`));
    expect(file.vectors.map(structural)).toEqual(file.vectors.map((one) => one.structural));
    // The accepted rows carry more than a word, and each of those is the reader's own answer: the order the
    // links reached, the steps where the stamps disagree, and the window the manifest states.
    for (const one of file.vectors.filter((each) => each.verdict === 'verify-ok')) {
      const result = read(one).result;
      expect(result, one.name).not.toBeNull();
      if (result === null) continue;
      expect(result.outcome.walked.map((each) => each.item.id), one.name).toEqual(one.walk);
      expect(result.outcome.ordering, one.name).toEqual(one.ordering ?? []);
      if (one.span !== undefined) expect(result.outcome.span, one.name).toEqual(one.span);
      for (const each of result.outcome.walked) {
        // The equality is part of the walk, so a suite that published a run would be incomplete without
        // stating that each original attests the stamp its record was hashed with.
        expect(each.receipt.payload.iat, `${one.name} ${each.item.id}`).toBe(each.item.iat);
      }
    }
  });

  it('accepts the pack whose two orders disagree and reports the step', () => {
    // The row is the substance of the format's decision: a store chains under whatever stamp it was handed, so
    // a clock correction inside a span produces lawful bytes, and a reader that refused them would be refusing
    // a deployment for a fact its own format states no rule against.
    const disagreeing = file.vectors.filter((one) => (one.ordering?.length ?? 0) > 0);
    expect(disagreeing.length, 'no published pack carries an ordering finding').toBeGreaterThanOrEqual(1);
    for (const one of disagreeing) {
      expect(one.verdict, `${one.name}: a disagreement was refused rather than reported`).toBe('verify-ok');
      const result = read(one).result;
      expect(result?.outcome.ordering, one.name).toEqual(one.ordering);
      for (const finding of result?.outcome.ordering ?? []) {
        expect(finding.kind, one.name).toBe('stamp-runs-backwards');
        expect(finding.toIat, one.name).toBeLessThan(finding.fromIat);
        // The pair is in chain order, so the finding names the step and not a pair of names sorted by spelling.
        const walked = (result?.outcome.walked ?? []).map((each) => each.item.id);
        expect(walked.indexOf(finding.from) + 1, one.name).toBe(walked.indexOf(finding.to));
      }
    }
    // Equality of two stamps is not a disagreement, and the row saying so is accepted with nothing reported.
    const tied = file.vectors.find((one) => one.name === 'two-records-under-one-stamp');
    expect(tied?.verdict).toBe('verify-ok');
    expect(tied?.ordering).toEqual([]);
  });

  it('publishes both halves of the chain rule, and the walk alone does not refuse the parked row', () => {
    // `pack.cddl` states a conforming reader's check in two halves. Both arrive as codes here, so a port that
    // implemented only the walk has to answer the parked row with a word it does not have.
    const parked = file.vectors.find((one) => one.verdict === 'PACK_ITEM_UNREACHED');
    expect(parked, 'the suite publishes no pack that reaches its head with an item left over').toBeDefined();
    const broken = file.vectors.filter((one) => one.verdict === 'PACK_CHAIN_BROKEN');
    expect(broken.length, 'the suite publishes no broken run').toBeGreaterThanOrEqual(2);
    // The parked row's whole structure holds and the honest run it was cut from is accepted, which is what
    // makes the count the thing that refuses rather than the shape of the document.
    expect(parked?.structural).toBe('verify-ok');
    expect(parked?.item, 'the refusal names no item').toBeTypeOf('string');
  });

  it('keeps a whole document refused for a key apart from one refused for its bytes', () => {
    // The two columns are the reason this suite publishes two words per row. A row that decodes and then is
    // refused is a caller holding too few keys or a signature that does not hold, and a row refused by
    // `decodePack` is a manifest contradicting itself whoever signed it.
    const attributed = ['PACK_KID_MISMATCH', 'PACK_UNKNOWN_KEY', 'PACK_RECEIPT_INVALID', 'PACK_RECEIPT_STAMP_MISMATCH'];
    const afterAKey = file.vectors.filter((one) => one.structural === 'verify-ok' && attributed.includes(one.verdict));
    expect(afterAKey.length).toBeGreaterThanOrEqual(4);
    const tampering = file.vectors.filter((one) => one.verdict === 'INVALID_SIGNATURE');
    expect(tampering.length).toBeGreaterThanOrEqual(2);
    for (const one of tampering) {
      expect(one.structural, `${one.name}: a signature failure answered as a document fault`).toBe('verify-ok');
    }
    const selfContradicting = file.vectors.filter((one) => one.verdict === 'PACK_BAD_MANIFEST');
    expect(selfContradicting.length).toBeGreaterThanOrEqual(6);
    for (const one of selfContradicting) {
      expect(one.structural, `${one.name}: a malformed manifest reached a key`).toBe('PACK_BAD_MANIFEST');
    }
  });

  it('reaches every code the format registry declares for this container', () => {
    const declared = unionMembers('ReceiptErrorCode', ERRORS).filter((code) => code.startsWith('PACK_'));
    expect(declared.length).toBeGreaterThanOrEqual(11);
    const reached = new Set([...file.vectors.map((one) => one.verdict), ...file.vectors.map((one) => one.structural)]);
    for (const code of declared) {
      expect(reached.has(code), `${code} is declared and no published row reaches it`).toBe(true);
    }
  });

  it('refuses a pack document at the export reader it is handed to', () => {
    // The pair that keeps the two containers apart, published from this file. One key signs both documents and
    // either verifies under it, so the only thing that tells a reader which claim it is holding is the type.
    expect(file.crossReading.cases.length).toBeGreaterThanOrEqual(1);
    for (const one of file.crossReading.cases) {
      const documentBytes = bytes(one.documentBase64Url);
      let manifest: PackManifest | null = null;
      try {
        manifest = decodePack(documentBytes).manifest;
      } catch {
        manifest = null;
      }
      expect(manifest, `${one.name}: the cross-reading case is not a pack document`).not.toBeNull();
      expect(one.expected, `${one.name}: the export reader accepted a pack`).not.toBe('verify-ok');
    }
  });
});
