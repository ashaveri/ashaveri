import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  REDACTION_CONTENT_TYPE,
  ReceiptError,
  decodePack,
  decodeRedaction,
  packRecordDigest,
  toHex,
  verifyPack,
  verifyRedaction,
  type PackItem,
  type PackVerifyOptions,
  type RedactionVerifyOptions,
  type VerifiedRedaction,
} from '@ashaveri/receipt';
import { loadPackVectors, loadRedactionVectors, type RedactionVector } from '../src/index.js';
import { unionMembers } from './doc-contract.js';

/**
 * The published redaction vectors, replayed the way a port replays them: take the redaction out of the file,
 * take the pack it names out of the file beside it, hand the reader both, and compare the answer with the
 * verdict the file states. Nothing here computes an expected value from the reader. The survivor run, the two
 * chain heads, the named items and both verdict columns are data in `data/redaction-v1.json`, and the only
 * question asked of the code is whether it answers as the file says it does.
 *
 * Three more things are checked on the way, because a suite about a pair of documents is only as good as the
 * pairing. The pack each row names is required to be the document `pack-v1.json` publishes under that name, so
 * this suite redacts evidence the repository already stands behind rather than a rebuild that happens to look
 * the same. The reduced chain is recomputed *here*, by walking the pack's own links and folding
 * `packRecordDigest` over the survivors, so a construction that only this repository's writer produces shows up
 * as a disagreement rather than as a silent convention. And every accepted row is required to state two heads
 * that differ, because the sentence this container exists to make unproducible is that a pack's chain head still
 * holds after one of its records is gone.
 *
 * The client half of this reading lives in `packages/cli/test/vector-conformance.test.ts`, which drives the same
 * rows through the paths a shipped verifier takes; what is here is the format package's own reader, the one
 * every verdict in this file was witnessed with when the generator wrote it.
 */

const file = loadRedactionVectors();
const packFile = loadPackVectors();
const ERRORS = '../../../packages/receipt/src/errors.ts';

const bytes = (base64url: string): Uint8Array => new Uint8Array(Buffer.from(base64url, 'base64url'));
const fromHex = (hex: string): Uint8Array => new Uint8Array(Buffer.from(hex, 'hex'));

/** The options a row's designation builds, beside the pack the row hands, which are the reader's own shapes. */
function optionsFor(one: RedactionVector): RedactionVerifyOptions {
  let keys: PackVerifyOptions = {};
  if (one.read.pinned !== undefined) keys = { publicKey: bytes(one.read.pinned) };
  else if (one.read.retained !== undefined) {
    const byKid = new Map((one.read.retained ?? []).map((each) => [each.kid, each.publicKeyBase64Url]));
    keys = {
      resolveKey: (kid: Uint8Array) => {
        const found = byKid.get(toHex(kid));
        return found === undefined ? undefined : bytes(found);
      },
    };
  }
  return {
    ...keys,
    packBytes: one.packBase64Url === undefined ? (undefined as unknown as Uint8Array) : bytes(one.packBase64Url),
  };
}

/** What the shipped reader answers for a row, and the reading whenever it returned one. */
function read(one: RedactionVector): { verdict: string; result: VerifiedRedaction | null } {
  try {
    return { verdict: 'verify-ok', result: verifyRedaction(bytes(one.documentBase64Url), optionsFor(one)) };
  } catch (err) {
    if (err instanceof ReceiptError) return { verdict: err.code, result: null };
    throw err;
  }
}

/** What the keyless half answers for the same bytes. */
function structural(one: RedactionVector): string {
  try {
    decodeRedaction(bytes(one.documentBase64Url));
    return 'verify-ok';
  } catch (err) {
    if (err instanceof ReceiptError) return err.code;
    throw err;
  }
}

/** The pack's records in the order its links fix them, walked here rather than taken from the array. */
function walked(packBytes: Uint8Array) {
  const manifest = decodePack(packBytes).manifest;
  const visited = new Set<string>();
  const reached: PackItem[] = [];
  let cursor = manifest.chain.anchor;
  for (;;) {
    const next = manifest.items.find((one) => !visited.has(one.id) && toHex(one.prev) === toHex(cursor));
    if (next === undefined) break;
    visited.add(next.id);
    reached.push(next);
    cursor = packRecordDigest(next);
  }
  return { manifest, reached };
}

/**
 * The reduced chain, recomputed in this file from the pack's own bytes: walk the links for the order, drop the
 * named records, and fold `packRecordDigest` from the pack's anchor. This is the reading a port takes from
 * `redaction.cddl` and from section 5.2, and it is deliberately not a call to the published fold.
 */
function reducedChainFromPack(packBytes: Uint8Array, removed: readonly string[]): string {
  const { manifest, reached } = walked(packBytes);
  const dropped = new Set(removed);
  let prev = manifest.chain.anchor;
  for (const one of reached) {
    if (dropped.has(one.id)) continue;
    prev = packRecordDigest({ id: one.id, iat: one.iat, prev, receipt: one.receipt });
  }
  return toHex(prev);
}

const publishedIds = new Set(file.layout.keyMaterial.map((one) => one.kidHex));
const packRows = new Map(packFile.vectors.map((one) => [one.name, one]));
const FIRST_KEY = file.layout.keyMaterial[0]!;

describe('the redaction manifest vectors', () => {
  it('are a suite the format, its twin and its writer all still describe', () => {
    expect(file.version).toBe(1);
    expect(file.description.length).toBeGreaterThan(0);
    expect(file.layout.contentType).toBe(REDACTION_CONTENT_TYPE);
    expect(file.layout.headerLabels).toEqual({ alg: 1, typ: 3, kid: 4 });
    // Every path the file names is a file, and the format and the twin still carry the content type this suite
    // is about: a port pointed at a document that no longer states the type would compare the wrong pair.
    const prose = file.layout.prose.split(' ')[0] ?? '';
    for (const path of [file.layout.format, file.layout.twin, prose]) {
      expect(
        existsSync(fileURLToPath(new URL(`../../../${path}`, import.meta.url))),
        `${path} is named by the suite and is not there`,
      ).toBe(true);
    }
    const cddl = readFileSync(fileURLToPath(new URL(`../../../${file.layout.format}`, import.meta.url)), 'utf8');
    expect(cddl).toContain(`"${REDACTION_CONTENT_TYPE}"`);
    const twin = JSON.parse(readFileSync(fileURLToPath(new URL(`../../../${file.layout.twin}`, import.meta.url)), 'utf8')) as {
      properties?: { protectedHeader?: { properties?: { typ?: { const?: unknown } } } };
    };
    expect(twin.properties?.protectedHeader?.properties?.typ?.const).toBe(REDACTION_CONTENT_TYPE);
    // The writer the file names is reachable from the package entry, which is the half that makes these bytes
    // rather than only describing them.
    for (const name of ['signRedaction', 'encodeRedactionManifest', 'sealRedaction']) {
      expect(file.layout.writer, `the suite names no ${name} as the code that made these documents`).toContain(name);
    }
    // The reader column names the two entry points and the pack reader between them, so a port is pointed at
    // the shipped pair rather than at a reimplementation of the walk.
    expect(file.layout.reader).toContain('verifyRedaction');
    expect(file.layout.reader).toContain('verifyPack');
    expect(file.layout.reader).toContain('decodeRedaction');
  });

  it('names a pack this repository already publishes, byte for byte', () => {
    for (const one of file.vectors) {
      if (one.packOf === undefined) {
        expect(one.packBase64Url, `${one.name} states no pack row and still carries pack bytes`).toBeUndefined();
        continue;
      }
      const found = packRows.get(one.packOf);
      expect(found, `${one.name} names ${one.packOf}, which pack-v1.json publishes no such document`).toBeDefined();
      if (found === undefined) continue;
      const packBytes = bytes(one.packBase64Url ?? '');
      expect(packBytes, `${one.name} pack length`).toHaveLength(one.packByteLength ?? 0);
      if (one.packEdited === undefined) {
        expect(toHex(packBytes), `${one.name} is not handed the bytes ${one.packOf} publishes`).toBe(
          toHex(bytes(found.documentBase64Url)),
        );
        continue;
      }
      // The one departure from handing over a published document is a row that says which position it moved,
      // and the two byte strings differ by those bytes and by their length alone.
      const published = bytes(found.documentBase64Url);
      expect(packBytes, `${one.name} states an edit and carries the published bytes unchanged`).not.toEqual(published);
      expect(packBytes.length, `${one.name}: the edit moved the length as well as the byte`).toBe(published.length);
      let differences = 0;
      for (let index = 0; index < published.length; index += 1) {
        if (published[index] !== packBytes[index]) differences += 1;
      }
      expect(differences, `${one.name}: ${one.packEdited} moved more than one byte`).toBe(1);
    }
    // The row that hands no pack is the one that states the refusal for it, and no other row may omit a pack.
    const lacking = file.vectors.filter((one) => one.packOf === undefined);
    expect(lacking.length, 'no row states the reader that was handed one document of the pair').toBeGreaterThanOrEqual(1);
    for (const one of lacking) {
      expect(one.verdict, `${one.name}: a row with no pack answered with something else`).toBe('REDACTION_PACK_UNAVAILABLE');
    }
  });

  it('designates only keys it publishes, and publishes keys that resolve', () => {
    for (const one of file.layout.keyMaterial) {
      const publicKey = bytes(one.publicKeyBase64Url);
      expect(toHex(sha256(publicKey)), `${one.id} kid`).toBe(one.kidHex);
      expect(one.publicKeyHex).toBe(toHex(publicKey));
      // Every kid this suite signs with is one the pack suite publishes, so these redactions speak about the
      // evidence of the same deployment rather than about a second family of the same shape.
      expect(packFile.layout.keyMaterial.map((each) => each.kidHex), `${one.kidHex} is outside the pack suite`).toContain(
        one.kidHex,
      );
    }
    for (const one of file.vectors) {
      expect(bytes(one.documentBase64Url)).toHaveLength(one.documentByteLength);
      for (const pin of one.read.retained ?? []) {
        expect(publishedIds.has(pin.kid), `${one.name} retains ${pin.kid}, which the suite publishes no key for`).toBe(true);
      }
      if (one.read.pinned !== undefined) {
        const pinned = bytes(one.read.pinned);
        expect(publishedIds.has(toHex(sha256(pinned))), `${one.name} pins a key the suite publishes no kid for`).toBe(true);
      }
    }
    // A whole sealed redaction names the kid that made its signature, and this suite publishes it, so a port can
    // reproduce a seal rather than only check one. A row refused at its header names none that resolves.
    for (const one of file.vectors) {
      const documentBytes = bytes(one.documentBase64Url);
      let kid: string;
      try {
        kid = toHex(decodeRedaction(documentBytes).header.kid);
      } catch {
        continue;
      }
      expect(publishedIds.has(kid), `${one.name} is sealed under a kid the suite does not publish`).toBe(true);
    }
  });

  it('carries no field a row is not told about and no code no registry declares', () => {
    const allowed = new Set([
      'name',
      'note',
      'documentBase64Url',
      'documentByteLength',
      'packOf',
      'packEdited',
      'packBase64Url',
      'packByteLength',
      'read',
      'verdict',
      'structural',
      ...file.layout.verdictFields,
    ]);
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
      expect(declared.has(one.structural), `${one.name} is structurally ${one.structural}, which no registry declares`).toBe(
        true,
      );
    }
    // The file's own roster is exactly the set its rows answer with, so a verdict that left the suite is caught
    // from both ends of one list.
    expect([...file.layout.codes].sort()).toEqual([...new Set(file.vectors.map((one) => one.verdict))].sort());
  });

  it('gives every row the verdict and the reading its file states', () => {
    const observed = file.vectors.map((one) => `${one.name}: ${read(one).verdict}`);
    expect(observed).toEqual(file.vectors.map((one) => `${one.name}: ${one.verdict}`));
    expect(file.vectors.map(structural)).toEqual(file.vectors.map((one) => one.structural));
    // The accepted rows carry more than a word, and each of those is the reader's own answer: the run that
    // remains, the head over it, and the pack's head.
    for (const one of file.vectors.filter((each) => each.verdict === 'verify-ok')) {
      const result = read(one).result;
      expect(result, one.name).not.toBeNull();
      if (result === null) continue;
      expect(result.outcome.survivors.map((each) => each.item.id), one.name).toEqual(one.survivors);
      expect(toHex(result.outcome.reduced), one.name).toBe(one.reducedHex);
      expect(toHex(result.outcome.originalHead), one.name).toBe(one.originalHeadHex);
      // The originals the pack carries are the records the survivor run is made of, each attesting the stamp
      // its record was hashed with, which is the equality the pack reader holds and this one inherits.
      for (const each of result.outcome.survivors) {
        expect(each.receipt.payload.iat, `${one.name} ${each.item.id}`).toBe(each.item.iat);
      }
    }
  });

  it('recomputes the survivor chain from the pack it was handed, not from a writer', () => {
    const accepted = file.vectors.filter((one) => one.verdict === 'verify-ok');
    expect(accepted.length, 'the suite publishes too few accepted pairs').toBeGreaterThanOrEqual(8);
    for (const one of accepted) {
      const packBytes = bytes(one.packBase64Url ?? '');
      const manifest = decodeRedaction(bytes(one.documentBase64Url)).manifest;
      expect(reducedChainFromPack(packBytes, manifest.removed), `${one.name}: the reduced head is not what the pack's own bytes fold to`).toBe(
        one.reducedHex,
      );
      // The head that survives is never the head the pack signed, which is the property the whole container
      // exists to keep a reader from merging.
      expect(one.reducedHex, `${one.name}: a redaction stated the pack's own head after a removal`).not.toBe(
        one.originalHeadHex,
      );
      expect(toHex(manifest.pack), `${one.name}: the designation is not the sha256 of the pack handed`).toBe(
        toHex(sha256(packBytes)),
      );
      expect(toHex(manifest.reduced), `${one.name}: the fold did not reach the head the document carries}`).toBe(
        one.reducedHex,
      );
    }
  });

  it("publishes the run and the survivor tables the pack's own bytes reproduce", () => {
    const packBytes = bytes(packRows.get('well-formed-three-items')!.documentBase64Url);
    const { manifest, reached } = walked(packBytes);
    expect(file.layout.run.map((one) => one.id)).toEqual(reached.map((one) => one.id));
    for (const [index, row] of file.layout.run.entries()) {
      const item = reached[index]!;
      expect(row.position).toBe(index);
      expect(row.id).toBe(item.id);
      expect(row.iat).toBe(item.iat);
      expect(row.prevHex).toBe(toHex(item.prev));
      expect(row.digestHex, `${row.id} digest`).toBe(toHex(packRecordDigest(item)));
    }
    // The run closes: the first predecessor is the signed anchor and the last digest the signed head.
    expect(file.layout.run[0]!.prevHex).toBe(toHex(manifest.chain.anchor));
    expect(file.layout.run[file.layout.run.length - 1]!.digestHex).toBe(toHex(manifest.chain.head));
    expect(file.layout.run.filter((one) => one.namedForRemoval).map((one) => one.id)).toEqual(['receipt-1']);

    // The survivor table is that run with the named record dropped, and each row states both the predecessor
    // its record carries in the pack and the predecessor the reduced chain used.
    const items = new Map(manifest.items.map((one) => [one.id, one]));
    const survivors = file.layout.run.filter((one) => !one.namedForRemoval);
    expect(file.layout.records.map((one) => one.id)).toEqual(survivors.map((one) => one.id));
    for (const row of file.layout.records) {
      const item = items.get(row.id)!;
      expect(row.iat).toBe(item.iat);
      expect(row.prevInPackHex).toBe(toHex(item.prev));
      expect(row.digestHex, `${row.id} reduced digest`).toBe(
        toHex(packRecordDigest({ id: item.id, iat: item.iat, prev: fromHex(row.relinkedFromHex), receipt: item.receipt })),
      );
    }
    // The first survivor's relinking is a no-op and every later one is not, which is the difference between a
    // chain over the survivors and the pack's own run read from the middle. The last digest of this table is
    // the head the accepted row publishes.
    expect(file.layout.records[0]!.relinkedFromHex).toBe(file.layout.records[0]!.prevInPackHex);
    for (const row of file.layout.records.slice(1)) {
      expect(row.relinkedFromHex, `${row.id}: a survivor kept the predecessor of a record named gone`).not.toBe(
        row.prevInPackHex,
      );
    }
    expect(file.layout.records[file.layout.records.length - 1]!.digestHex).toBe(
      file.vectors.find((one) => one.name === 'removed-middle-record')?.reducedHex,
    );
  });

  it('states the wrong half of a pair, and the wrong construction of a chain, as separate refusals', () => {
    // Four rows refuse because of what the reader was handed rather than what the writer wrote, which is the
    // distinction a port is most likely to lose: too little, the wrong pack, and a pair that cannot both be true.
    const handed = file.vectors.filter((one) =>
      ['REDACTION_PACK_UNAVAILABLE', 'REDACTION_PACK_MISMATCH', 'REDACTION_PACK_DISAGREES'].includes(one.verdict),
    );
    expect(handed.length).toBeGreaterThanOrEqual(4);
    for (const one of handed) {
      // Each of them is whole as a document: the refusal is reached with a pack and a key in hand.
      expect(one.structural, `${one.name}: a pairing refusal answered as a manifest fault`).toBe('verify-ok');
    }
    // Three wrong constructions of the survivor chain, each one a document that reads as a chain claim, and
    // each a different position, so a port cannot pass two of them with one wrong rule.
    const chains = file.vectors.filter((one) => one.verdict === 'REDACTION_SURVIVOR_CHAIN_MISMATCH');
    expect(chains.length).toBeGreaterThanOrEqual(3);
    expect(new Set(chains.map((one) => one.edited ?? '')).size, 'the chain refusals state the same edit').toBe(chains.length);
    for (const one of chains) {
      expect(one.edited, `${one.name}: a chain refusal states no position to look at`).toBeDefined();
      expect(one.structural, `${one.name}: a chain refusal answered as a manifest fault`).toBe('verify-ok');
    }
    // The claim the format exists to make unproducible, published as a row that is refused rather than as a
    // sentence a reader is asked to trust.
    const headRestated = file.vectors.find((one) => one.name === 'claiming-the-packs-own-head-still-holds');
    expect(headRestated?.verdict).toBe('REDACTION_SURVIVOR_CHAIN_MISMATCH');
    expect(headRestated?.edited).toContain('the head the pack signs for its own run');
  });

  it('keeps a whole document refused for a pack apart from one refused for its bytes', () => {
    // The two columns are the reason this suite publishes two words per row. A row that decodes and then is
    // refused is a caller with too few keys, the wrong pack, or a signature that does not hold, and a row
    // refused by `decodeRedaction` is a manifest contradicting itself whoever signed it.
    const attributed = [
      'REDACTION_KID_MISMATCH',
      'REDACTION_UNKNOWN_KEY',
      'REDACTION_PACK_UNAVAILABLE',
      'REDACTION_PACK_MISMATCH',
      'REDACTION_PACK_DISAGREES',
      'REDACTION_ITEM_ABSENT',
      'REDACTION_SURVIVORS_EMPTY',
      'REDACTION_SURVIVOR_CHAIN_MISMATCH',
    ];
    const afterAKey = file.vectors.filter((one) => one.structural === 'verify-ok' && attributed.includes(one.verdict));
    expect(afterAKey.length).toBeGreaterThanOrEqual(8);
    const tampering = file.vectors.filter((one) => one.verdict === 'INVALID_SIGNATURE');
    expect(tampering.length).toBeGreaterThanOrEqual(2);
    for (const one of tampering) {
      expect(one.structural, `${one.name}: a signature failure answered as a document fault`).toBe('verify-ok');
    }
    const selfContradicting = file.vectors.filter((one) => one.verdict === 'REDACTION_BAD_MANIFEST');
    expect(selfContradicting.length).toBeGreaterThanOrEqual(5);
    for (const one of selfContradicting) {
      expect(one.structural, `${one.name}: a malformed manifest reached a key`).toBe('REDACTION_BAD_MANIFEST');
    }
    // A refusal that belongs to the pack keeps the pack's code, because a pack's sentence says pack, and the
    // redaction half of such a row is whole.
    const packCodes = file.vectors.filter((one) => one.verdict.startsWith('PACK_'));
    expect(packCodes.length, 'no row inherits a refusal from the pack it names').toBeGreaterThanOrEqual(2);
    for (const one of packCodes) {
      expect(one.structural, `${one.name}: a pack refusal answered as a redaction fault`).toBe('verify-ok');
    }
  });

  it('reaches every code the format registry declares for this container', () => {
    const declared = unionMembers('ReceiptErrorCode', ERRORS).filter((code) => code.startsWith('REDACTION_'));
    expect(declared.length).toBeGreaterThanOrEqual(13);
    const reached = new Set([...file.vectors.map((one) => one.verdict), ...file.vectors.map((one) => one.structural)]);
    for (const code of declared) {
      expect(reached.has(code), `${code} is declared and no published row reaches it`).toBe(true);
    }
  });

  it('refuses a redaction document at the pack reader it is handed to', () => {
    // The pair that keeps the containers apart, published from this file. One key signs both documents and
    // either verifies under it, so the only thing that tells a reader which claim it is holding is the type.
    expect(file.crossReading.cases.length).toBeGreaterThanOrEqual(1);
    for (const one of file.crossReading.cases) {
      const documentBytes = bytes(one.documentBase64Url);
      expect(one.expected, `${one.name}: the pack reader accepted a redaction`).not.toBe('verify-ok');
      // The stated answer is the pack reader's own, witnessed here rather than copied.
      let observed = 'verify-ok';
      try {
        verifyPack(documentBytes, { publicKey: bytes(FIRST_KEY.publicKeyBase64Url) });
      } catch (err) {
        observed = err instanceof ReceiptError ? err.code : 'uncoded';
      }
      expect(observed, one.name).toBe(one.expected);
      // And the document is a whole redaction sealed by a key this suite publishes, so the refusal is about
      // which container it is and not about these bytes being broken.
      expect(toHex(decodeRedaction(documentBytes).header.kid), `${one.name} is not sealed by a published key`).toBe(
        FIRST_KEY.kidHex,
      );
    }
  });
});
