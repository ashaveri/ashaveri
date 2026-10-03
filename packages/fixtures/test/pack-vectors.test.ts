import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  PACK_CONTENT_TYPE,
  CARRIED_MAX_BYTES,
  CUSTODY_SLOTS_PER_ITEM,
  ReceiptError,
  decodePack,
  packRecordDigest,
  resolveAttached,
  toHex,
  verifyPack,
  type PackManifest,
  type PackVerifyOptions,
  type VerifiedPack,
} from '@ashaveri/receipt';
import { loadPackVectors, type PackVector } from '../src/index.js';
import { assertRowRoster, ROW_NAMING_FIELDS, unionMembers } from './doc-contract.js';

/**
 * The published pack vectors, replayed the way a port replays them: take the document out of the file, hand
 * the reader the designation the file states beside it, and compare the answer with the verdict the file
 * states. Nothing here computes an expected value from the reader. The walk order, the ordering findings, the
 * named items and both verdict columns are data in `data/pack-v1.json`, and the only question asked of the
 * code is whether it answers as the file says it does.
 *
 * Three more things are checked on the way, because a suite of chained documents is only as good as the chain.
 * The record tables the file publishes beside its two framed runs are recomputed from those documents' own
 * items, so a framing that only this implementation's writer produces shows up as a disagreement rather than as
 * a silent convention. Every code of the pack family in the registry is required to be reached by a committed
 * document, which is the only way a refusal added to `errors.ts` without a case cannot pass unnoticed. And the
 * two columns are required to disagree where they are said to, because the pair is the substance of a reader
 * that keeps "these bytes are whole" apart from "this caller can attribute them".
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

describe('the evidence pack vectors', () => {
  it('are a suite the format, its twin and its writer all still describe', () => {
    expect(file.version).toBe(1);
    expect(file.description.length).toBeGreaterThan(0);
    expect(file.layout.contentType).toBe(PACK_CONTENT_TYPE);
    expect(file.layout.headerLabels).toEqual({ alg: 1, typ: 3, kid: 4 });
    // Every path the file names is a file, and the format and the twin still carry the content type this
    // suite is about: a port pointed at a document that no longer states the type would compare the wrong pair.
    for (const path of [
      file.layout.format,
      file.layout.twin,
      file.layout.document,
      file.layout.prose.split(' ')[0] ?? '',
    ]) {
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
    // Two runs are framed here, and both tables are read the same way: out of the sealed bytes of the row each
    // one sits beside. The pair is what the framing rule states, so the rule and the two table members are held
    // to the same two rows rather than to a name written into this file.
    const tables = [
      { rows: file.layout.records, vector: 'well-formed-three-items' },
      { rows: file.layout.attachedRecords, vector: 'held-slots-referred-to-by-name' },
    ] as const;
    const rule = file.layout.framingRule;
    expect(typeof rule, 'the suite publishes no framing rule').toBe('string');
    if (typeof rule === 'string') {
      for (const one of tables) {
        expect(rule, `the framing rule stopped naming the table of ${one.vector}`).toContain(one.vector);
      }
    }
    for (const one of tables) {
      const row = file.vectors.find((each) => each.name === one.vector);
      expect(row, `the suite frames a run no published row carries: ${one.vector}`).toBeDefined();
      if (row === undefined) continue;
      const manifest = decodePack(bytes(row.documentBase64Url)).manifest;
      expect(one.rows.map((each) => each.id), one.vector).toEqual(manifest.items.map((each) => each.id));
      for (const [index, record] of one.rows.entries()) {
        const item = manifest.items[index]!;
        expect(record.position, `${one.vector} record ${record.id}`).toBe(index);
        expect(record.id, one.vector).toBe(item.id);
        expect(record.iat, one.vector).toBe(item.iat);
        expect(record.prevHex, one.vector).toBe(toHex(item.prev));
        expect(record.receiptByteLength, one.vector).toBe(item.receipt.length);
        // The digest is recomputed from the bytes the item carries, which is what a reader does to walk: a
        // framing that moved in the writer and not here would show up as this disagreement.
        expect(toHex(packRecordDigest(item)), `${one.vector} ${record.id} digest`).toBe(record.digestHex);
      }
      // And each table describes a run that closes: the first predecessor is the signed anchor and the last
      // digest is the signed head, which is the pair the walk is between.
      expect(one.rows[0]!.prevHex, one.vector).toBe(toHex(manifest.chain.anchor));
      expect(one.rows[one.rows.length - 1]!.digestHex, one.vector).toBe(toHex(manifest.chain.head));
    }
    // The two runs are the same three names and stamps, and their receipts differ: the referred-to one seals
    // receipts whose anchor slots state `held`, so its frames are wider. A table that had been copied from the
    // other run would agree on ids and stamps and fail here.
    expect(file.layout.records.map((one) => one.id)).toEqual(file.layout.attachedRecords.map((one) => one.id));
    expect(
      file.layout.attachedRecords.some((one, index) => one.receiptByteLength !== file.layout.records[index]?.receiptByteLength),
      'the framed runs hold the same receipt bytes, so one table was copied from the other',
    ).toBe(true);
  });

  it('states the two ceilings as the figures the reader enforces', () => {
    // A ceiling spelled as a word in this sentence would be a claim that stays true when the number under it
    // moves. The generator reads the two figures out of `packages/receipt/src/pack.ts`, so what the published
    // rule prints is the figure the reader refuses on, and this case is what notices if the prose and the
    // constants part.
    const rule = file.layout.custodyRule;
    expect(typeof rule, 'the suite publishes no custody rule').toBe('string');
    if (typeof rule !== 'string') return;
    expect(rule, 'the byte ceiling the rule states is not the one the reader enforces').toContain(
      `${String(CARRIED_MAX_BYTES)} bytes`,
    );
    expect(rule, 'the slot ceiling the rule states is not the one the reader counts against').toContain(
      `${String(CUSTODY_SLOTS_PER_ITEM)} slots`,
    );
  });

  it('fills the arm of one accepted pack and the references beside it answer for it', () => {
    // The byte arm is permitted by the layout and filled by one published document, whose every attached object
    // resolves to a reference the same pack signs for. The pack that refers to material and attaches no copy of it
    // is still the ordinary case, and the refusal a caller meets at the lookup is no document's answer, so this case
    // is where the suite reaches it, out of the same bytes the file publishes rather than from a manifest invented
    // for it.
    const accepted = file.vectors.filter((one) => one.verdict === 'verify-ok');
    expect(accepted.length).toBeGreaterThanOrEqual(6);
    const attaching = accepted.filter((one) => decodePack(bytes(one.documentBase64Url)).manifest.attached.length > 0);
    expect(attaching.length, 'no accepted pack of this suite attaches the material its references name').toBe(1);
    for (const one of attaching) {
      const manifest = decodePack(bytes(one.documentBase64Url)).manifest;
      for (const [index, entry] of manifest.attached.entries()) {
        const reached = resolveAttached(manifest, entry.sha256);
        expect(toHex(reached.custody.b), `${one.name} attached[${String(index)}]`).toBe(toHex(entry.sha256));
        const carried = entry.chain === null ? null : toHex(sha256(entry.chain));
        expect(
          entry.chainSha256 === null ? null : toHex(entry.chainSha256),
          `${one.name} attached[${String(index)}] states a header digest its own bytes disagree with`,
        ).toBe(carried);
      }
      // The served half, asked of the published bytes and not of a manifest this file invented: the header the arm
      // carries is the one the reference for that body states, which is the pair the row exists to publish.
      const served = manifest.attached[0]!;
      expect(served.chain, `${one.name} attaches a body with no header beside it`).not.toBeNull();
      const servedReference = manifest.custody.find((each) => toHex(each.b) === toHex(served.sha256));
      expect(servedReference, `${one.name} attaches an object no reference of this pack states`).toBeDefined();
      expect(toHex(servedReference!.c!)).toBe(toHex(served.chainSha256!));
    }
    const referring = accepted.find((one) => one.name === 'held-slots-referred-to-by-name');
    expect(referring, 'the suite publishes no accepted pack whose held slots are answered by name').toBeDefined();
    if (referring === undefined) return;
    const manifest = decodePack(bytes(referring.documentBase64Url)).manifest;
    expect(manifest.attached, 'the pack that refers to material by name attaches something after all').toEqual([]);
    expect(manifest.custody.length, 'the accepted pack signs a reference for every held slot it seals').toBeGreaterThanOrEqual(1);
    const first = manifest.custody[0]!;
    const thrown = (() => {
      try {
        resolveAttached(manifest, first.b);
        return null;
      } catch (err) {
        return err;
      }
    })();
    expect(thrown, 'the lookup answered a digest this pack attaches nothing for with no refusal at all').toBeInstanceOf(ReceiptError);
    expect((thrown as ReceiptError).code).toBe('PACK_ATTACHED_UNRESOLVED');
    expect((thrown as ReceiptError).message).toContain(first.k.item);
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
    // The published roster is the whole set of columns a row may carry, so it is held as an equality over the
    // columns the rows actually carry, in the one check every suite with a roster is wired to. Reading it as a
    // list of allowances, as this case did, cannot see a column a row carries and the file never declares.
    assertRowRoster(file, ROW_NAMING_FIELDS);
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
    // One declared code is the lookup's and no document's, because the arm may be empty: a held slot the arm
    // attaches nothing for is a caller reaching past what the pack undertook, and neither `decodePack` nor
    // `verifyPack` resolves a slot for a caller. It is refused by name in the case above, out of the bytes this
    // file publishes as whole, which is the only place a port can be shown both halves of that distinction.
    const byADocument = declared.filter((one) => one !== 'PACK_ATTACHED_UNRESOLVED');
    for (const code of byADocument) {
      expect(reached.has(code), `${code} is declared and no published row reaches it`).toBe(true);
    }
    expect(reached.has('PACK_ATTACHED_UNRESOLVED'), 'a document answered with the lookup-only code').toBe(false);
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
