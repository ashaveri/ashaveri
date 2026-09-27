import { describe, expect, it } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  EPOCH_INVENTORY_CONTENT_TYPE,
  ReceiptError,
  decodeCanonical,
  decodeEpochInventory,
  epochInventorySigStructure,
  sealEpochInventory,
  toBase64Url,
  toHex,
  verifyEpochInventory,
  type EpochInventoryVerifyOptions,
} from '@ashaveri/receipt';
import { loadEpochInventoryVectors, type EpochInventoryVector } from '../src/index.js';
import { unionMembers } from './doc-contract.js';

/**
 * The published epoch inventory vectors, replayed the way a port replays them: take the document out of the
 * file, hand the reader the designation the file states beside it, and compare the answer with the verdict the
 * file states. Nothing here computes an expected value from the reader. The run order, the summaries, the
 * refusal sentences and both verdict columns are data in `data/epoch-inventory-v1.json`, and the only question
 * asked of the code is whether it answers as the file says it does.
 *
 * Four more things are checked on the way, because a suite of one-document artifacts is only as good as the
 * claims it can be read for. The honest envelope is rebuilt here from the three pieces the file publishes
 * beside it, by the shipped seal function rather than by the signing writer or the generator's case list,
 * and required to be byte-identical to
 * the published document, so the framing the file states is the framing the bytes carry. The two run-label
 * rows are required to differ by one inserted byte at one position, which is what makes the ceiling they straddle
 * a width rule rather than two unrelated documents. Every code of the inventory family in the registry is
 * required to be reached by a committed row, which is the only way a refusal added to `errors.ts` without a
 * case cannot pass unnoticed. And the two folded lists are required to vector the same guards, every refusing
 * row at a site naming the guard of that site it reaches,
 * because their guards are twins: a suite that vectored one site or one guard and not its twin would let a
 * port that keyed or compared only the other pass every row here.
 *
 * The client half of this reading is not wired yet: `packages/cli/test/vector-conformance.test.ts` drives the
 * other suites through the paths a shipped verifier takes, and these rows go there next. What is here is the
 * format package's own reader, the one every verdict in this file was witnessed with when the generator wrote
 * it.
 */

const file = loadEpochInventoryVectors();
const ERRORS = '../../../packages/receipt/src/errors.ts';

const bytes = (base64url: string): Uint8Array => new Uint8Array(Buffer.from(base64url, 'base64url'));

/** The options a row's designation builds, which are the reader's two shapes and no third. */
function optionsFor(one: EpochInventoryVector): EpochInventoryVerifyOptions {
  if (one.read.pinned !== undefined) return { publicKey: bytes(one.read.pinned) };
  if (one.read.retained !== undefined) {
    const held = one.read.retained;
    return {
      resolveKey: (kid: Uint8Array): Uint8Array | undefined => {
        const found = held[toHex(kid)];
        return found === undefined ? undefined : bytes(found);
      },
    };
  }
  return {};
}

/** What one reader answered, in the shape the file states its verdicts in. */
function answer(run: () => unknown): { code: string; message: string } {
  try {
    run();
    return { code: 'verify-ok', message: '' };
  } catch (err) {
    if (err instanceof ReceiptError) return { code: err.code, message: err.message };
    throw err;
  }
}

const verdictOf = (one: EpochInventoryVector): { code: string; message: string } =>
  answer(() => verifyEpochInventory(bytes(one.documentBase64Url), optionsFor(one)));
const structuralOf = (one: EpochInventoryVector): string =>
  answer(() => decodeEpochInventory(bytes(one.documentBase64Url))).code;

/** The payload of a sealed document, which is the JSON text the signature covers. */
function payloadText(one: EpochInventoryVector): string {
  const contents = (decodeCanonical(bytes(one.documentBase64Url)) as { contents?: unknown }).contents;
  if (!Array.isArray(contents) || !(contents[2] instanceof Uint8Array)) {
    throw new Error(`${one.name} is not a four-element envelope with a byte payload`);
  }
  return new TextDecoder().decode(contents[2]);
}

/** The signature element of a sealed document, which is the fourth element of the envelope. */
function signatureOf(one: EpochInventoryVector): Uint8Array {
  const contents = (decodeCanonical(bytes(one.documentBase64Url)) as { contents?: unknown }).contents;
  if (!Array.isArray(contents) || !(contents[3] instanceof Uint8Array)) {
    throw new Error(`${one.name} is not a four-element envelope with a byte signature`);
  }
  return contents[3];
}

const honest = file.vectors.find((one) => one.name === 'honest-run-of-three');
if (honest === undefined) throw new Error('the suite publishes no honest row to read the framing from');
const reveal = honest.reveal;
if (reveal === undefined) throw new Error('the honest row publishes no reveal block to rebuild the envelope from');

/** The `kid` a published protected header carries. */
function declaredKid(header: Uint8Array): Uint8Array {
  const decoded = decodeCanonical(header);
  if (!(decoded instanceof Map)) throw new Error('a published protected header is not a map');
  const kid = decoded.get(4);
  if (!(kid instanceof Uint8Array)) throw new Error('a published protected header carries no kid');
  return kid;
}

describe('the published epoch inventory vectors', () => {
  it('states a rule in prose and a layout a reader can hold', () => {
    expect(file.version).toBe(1);
    expect(file.description.length).toBeGreaterThan(80);
    expect(file.layout.format).toBe('packages/receipt/epoch-inventory.cddl');
    expect(file.layout.prose).toBe('docs/epoch-inventory-v1.md');
    expect(file.layout.contentType).toBe(EPOCH_INVENTORY_CONTENT_TYPE);
    expect(file.layout.twin).toBe('packages/receipt/schemas/epoch-inventory-v1.schema.json');
    expect(file.vectors.length).toBeGreaterThanOrEqual(20);
  });

  it('is answered by both readers exactly as the file says, on every row', () => {
    for (const one of file.vectors) {
      const structure = structuralOf(one);
      expect(structure, `${one.name} is structurally ${structure}`).toBe(one.structural);
      const read = verdictOf(one);
      expect(read.code, `${one.name} answers ${read.code}`).toBe(one.verdict);
      if (one.verdict === 'verify-ok') {
        expect(one.message, `${one.name} is accepted and carries a refusal sentence`).toBeUndefined();
      } else {
        expect(read.message, `${one.name} is refused in other words than the file states`).toBe(one.message);
      }
    }
  });

  it('hands back the run the reader recomputed and the document it parsed', () => {
    const accepted = file.vectors.filter((one) => one.verdict === 'verify-ok');
    expect(accepted.length).toBeGreaterThanOrEqual(8);
    for (const one of accepted) {
      const read = verifyEpochInventory(bytes(one.documentBase64Url), optionsFor(one));
      const stated = one.readback;
      if (stated === undefined) throw new Error(`${one.name} is accepted and states no readback`);
      // The one recomputation the accepted rows pin: the run in the order the entries' own figures put them,
      // which is what makes `entries-listed-backwards` a witness rather than a restatement.
      expect(read.outcome.packs.map((each) => each.file)).toEqual(stated.runFiles);
      // The remaining columns are the reader echoing the row's own document text back, so they are published
      // as data and asserted once, as a single parse echo rather than as six silent recomputations.
      expect({
        statedFiles: read.manifest.packs.map((each) => each.file),
        window: read.manifest.window,
        continuous: read.manifest.chain.continuous,
        breakFiles: read.manifest.chain.breaks.map((each) => each.file),
        carried: read.manifest.duty.carried,
        shortFiles: read.manifest.duty.short.map((each) => each.file),
      }).toEqual({
        statedFiles: stated.statedFiles,
        window: stated.window,
        continuous: stated.continuous,
        breakFiles: stated.breakFiles,
        carried: stated.carried,
        shortFiles: stated.shortFiles,
      });
    }
    // The order a row is listed in bears nothing, so at least one accepted row has to show the reader putting a
    // run back into the order its figures state rather than repeating the array it was handed.
    expect(accepted.some((one) => one.readback?.runFiles.join(' ') !== one.readback?.statedFiles.join(' '))).toBe(
      true,
    );
  });

  it('rebuilds the honest envelope from the pieces the file publishes', () => {
    // The shipped seal function over three published byte strings: not the signing writer, which never sees
    // the pieces taken apart, and not the generator's case list, which sealed them. This is the proof
    // the framing the file states is the framing the bytes carry, and it is what a port with no access to this
    // repository's writer has to check its own encoder against.
    const header = bytes(String(reveal['protectedHeaderBase64Url']));
    const payload = bytes(String(reveal['payloadBase64Url']));
    const signature = new Uint8Array(Buffer.from(String(reveal['signatureHex']), 'hex'));
    const published = file.layout.keyMaterial.find((one) => one.kidHex === toHex(declaredKid(header)));
    if (published === undefined) throw new Error('the honest header names a kid the suite publishes no key for');
    const publicKey = bytes(published.publicKeyBase64Url);
    expect(toBase64Url(header)).toBe(String(reveal['protectedHeaderBase64Url']));
    expect(toHex(sha256(payload))).toBe(String(reveal['payloadSha256Hex']));
    const rebuilt = sealEpochInventory(header, payload, signature);
    expect(toHex(rebuilt)).toBe(toHex(bytes(honest.documentBase64Url)));
    expect(rebuilt.length).toBe(honest.documentByteLength);
    expect(toHex(epochInventorySigStructure(header, payload))).toBe(String(reveal['sigStructureHex']));
    expect(
      ed25519.verify(signature, epochInventorySigStructure(header, payload), publicKey, { zip215: false }),
    ).toBe(true);
    expect(String(reveal['contextString'])).toBe('Signature1');
    expect(String(reveal['externalAadBase64Url'])).toBe(toBase64Url(new Uint8Array(0)));
    // And the rebuilt bytes answer the same verdict as the published ones, which is the only thing a framing
    // proof is for.
    expect(verifyEpochInventory(rebuilt, { publicKey }).manifest.epoch).toBe('quarter-one');
  });

  it('straddles the one width ceiling with a pair differing by one byte', () => {
    const within = file.vectors.find((one) => one.name === 'run-label-at-the-printed-width');
    const past = file.vectors.find((one) => one.name === 'run-label-one-byte-past-the-printed-width');
    if (within === undefined || past === undefined) throw new Error('the suite lost one row of its label pair');
    const honestPayload = payloadText(honest);
    for (const one of [within, past]) {
      const edit = one.edit;
      if (edit === undefined) throw new Error(`${one.name} states no edit to rebuild it from`);
      expect(edit.of, `${one.name} edits a row this suite does not publish`).toBe(honest.name);
      const payload = payloadText(one);
      expect(payload).toBe(honestPayload.replace(edit.from, edit.to));
      expect(one.edited).toContain('epoch');
    }
    // The two rows are the same document to within one inserted byte, which is what makes the ceiling a width
    // rule and the two refusals one rule met at both sides of it.
    const short = payloadText(within);
    const long = payloadText(past);
    expect(long.length - short.length).toBe(1);
    let at = 0;
    while (at < short.length && short[at] === long[at]) at += 1;
    expect(short.slice(at)).toBe(long.slice(at + 1));
    // The one inserted payload byte moves two things outside the text: the length prefix of the payload
    // bstr, the only difference in the two documents before the payload itself, and the signature, which
    // covers the bytes and so answers afresh on every one of its 64.
    const withinDoc = bytes(within.documentBase64Url);
    const pastDoc = bytes(past.documentBase64Url);
    expect(pastDoc.length - withinDoc.length).toBe(1);
    expect(withinDoc.slice(0, 72)).toEqual(pastDoc.slice(0, 72));
    expect(withinDoc[72]).toBe(0x4e);
    expect(pastDoc[72]).toBe(0x4f);
    const withinSig = signatureOf(within);
    const pastSig = signatureOf(past);
    expect(withinSig.length).toBe(64);
    expect(pastSig.length).toBe(64);
    let differing = 0;
    for (let i = 0; i < 64; i += 1) if (withinSig[i] !== pastSig[i]) differing += 1;
    expect(differing).toBe(64);
    expect(within.verdict).toBe('verify-ok');
    expect(past.verdict).toBe('EPOCH_INVENTORY_BAD_DOCUMENT');
    expect(past.message).toContain('201');
  });

  it('reaches every code the inventory family declares', () => {
    const declared = unionMembers('ReceiptErrorCode', ERRORS).filter((code) => code.startsWith('EPOCH_INVENTORY_'));
    expect(declared.length).toBeGreaterThanOrEqual(12);
    const reached = new Set([...file.vectors.map((one) => one.verdict), ...file.vectors.map((one) => one.structural)]);
    for (const code of declared) {
      expect(reached.has(code), `${code} is declared and no published row reaches it`).toBe(true);
    }
    // The file's own roster is exactly the set its rows answer with, so a verdict that left the suite is caught
    // from both ends of one list.
    expect([...file.layout.codes].sort()).toEqual([...new Set(file.vectors.map((one) => one.verdict))].sort());
    for (const one of file.vectors) {
      if (one.verdict === 'verify-ok') continue;
      expect(declared.includes(one.verdict) || ['NOT_COSE_SIGN1', 'UNSUPPORTED_ALG', 'INVALID_SIGNATURE'].includes(one.verdict), `${one.name} answers ${one.verdict}`).toBe(
        true,
      );
    }
  });

  it('vectors both folded lists guard for guard', () => {
    const atBreaks = file.vectors.filter((one) => one.site === 'chain.breaks');
    const atShortfall = file.vectors.filter((one) => one.site === 'duty.short');
    expect(atBreaks.length).toBeGreaterThanOrEqual(5);
    expect(atBreaks.length).toBe(atShortfall.length);
    // Every refusal the reader reaches inside a folded list names its site and the guard of that site it
    // reaches, and no row carries a guard at no site: a row that lost its site would otherwise hide one half
    // of the twins from this file, which counted 6 and 6 while one flag guard went unvectored.
    for (const one of file.vectors) {
      if (one.guard !== undefined) {
        expect(one.site, `${one.name} names the ${one.guard} guard at no site`).toBeDefined();
      }
      if (one.verdict === 'EPOCH_INVENTORY_PACK_UNNAMED') {
        expect(one.site, `${one.name} is a folded-list refusal and names no site`).toBeDefined();
      }
    }
    // Each site carries every fault its list can hold: the claim contradicted by the list beside it, the
    // count too high, the count too low, two rows naming one pack, a name the run does not hold, a row
    // naming a held pack with no such finding in it, and a row whose own figures are not the pair's or the
    // pack's, which is two rows, one per moved position. The codes cannot tell a flag refusal from a count
    // refusal, so the guard names are what let this check see its own asymmetry.
    const guardsAt = (rows: EpochInventoryVector[]): string[] =>
      rows.filter((one) => one.verdict !== 'verify-ok').map((one) => one.guard ?? '').sort();
    const atEachSite = ['claim', 'count', 'count', 'figures', 'figures', 'repeat', 'unheld', 'without-finding'];
    expect(guardsAt(atBreaks)).toEqual(atEachSite);
    expect(guardsAt(atShortfall)).toEqual(atEachSite);
    // The twins answer their guards with the same codes, and each site vectors the reversed-list acceptance.
    const codesAt = (rows: EpochInventoryVector[]): string[] =>
      rows.filter((one) => one.verdict !== 'verify-ok').map((one) => one.verdict).sort();
    expect(codesAt(atShortfall)).toEqual(codesAt(atBreaks));
    expect(atBreaks.filter((one) => one.verdict === 'verify-ok').length).toBe(1);
    expect(atShortfall.filter((one) => one.verdict === 'verify-ok').length).toBe(1);
  });

  it('keeps a refusal that is about a run apart from one about a shape', () => {
    // The two columns exist because the container has two entry points, and every arithmetic refusal has to show
    // up only in the one that holds the run: a row refused by both is a document that never got as far as an
    // arithmetic, and a port that merged the columns cannot tell the two apart.
    const arithmetic = ['EPOCH_INVENTORY_RUN_NOT_CONTIGUOUS', 'EPOCH_INVENTORY_SUMMARY_DISAGREES', 'EPOCH_INVENTORY_PACK_UNNAMED'];
    const atArithmetic = file.vectors.filter((one) => arithmetic.includes(one.verdict));
    expect(atArithmetic.length).toBeGreaterThanOrEqual(10);
    for (const one of atArithmetic) {
      expect(one.structural, `${one.name} is refused by the shape reader too, so it vectors no arithmetic`).toBe(
        'verify-ok',
      );
    }
    for (const one of file.vectors) {
      if (one.verdict === one.structural) continue;
      expect(one.verdict, `${one.name} agrees at the shape and disagrees the other way round`).not.toBe('verify-ok');
    }
  });
});
