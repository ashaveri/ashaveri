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
 * beside it, by a path that is neither the writer's nor the generator's, and required to be byte-identical to
 * the published document, so the framing the file states is the framing the bytes carry. The two run-label
 * rows are required to differ by one inserted byte at one position, which is what makes the ceiling they straddle
 * a width rule rather than two unrelated documents. Every code of the inventory family in the registry is
 * required to be reached by a committed row, which is the only way a refusal added to `errors.ts` without a
 * case cannot pass unnoticed. And the two folded lists are required to carry the same number of rows each,
 * because their guards are twins: a suite that vectored only one of them would let a port that keyed only the
 * other pass every row here.
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

const honest = file.vectors.find((one) => one.name === 'honest-run-of-three');
if (honest === undefined) throw new Error('the suite publishes no honest row to read the framing from');
const reveal = honest.reveal;
if (reveal === undefined) throw new Error('the honest row publishes no reveal block to rebuild the envelope from');

/** The three published pieces of the honest document, and the key the file publishes for the kid they name. */
function revealed(): { header: Uint8Array; payload: Uint8Array; signature: Uint8Array; publicKey: Uint8Array } {
  const header = bytes(String(reveal['protectedHeaderBase64Url']));
  const published = file.layout.keyMaterial.find((one) => toHex(declaredKid(header)) === one.kidHex);
  if (published === undefined) throw new Error('the honest header names a kid the suite publishes no key for');
  return {
    header,
    payload: bytes(String(reveal['payloadBase64Url'])),
    signature: new Uint8Array(Buffer.from(String(reveal['signatureHex']), 'hex')),
    publicKey: bytes(published.publicKeyBase64Url),
  };
}

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

  it('hands back the run and the summaries the accepted rows state', () => {
    const accepted = file.vectors.filter((one) => one.verdict === 'verify-ok');
    expect(accepted.length).toBeGreaterThanOrEqual(8);
    for (const one of accepted) {
      const read = verifyEpochInventory(bytes(one.documentBase64Url), optionsFor(one));
      const stated = one.readback;
      if (stated === undefined) throw new Error(`${one.name} is accepted and states no readback`);
      expect(read.outcome.packs.map((each) => each.file)).toEqual(stated.runFiles);
      expect(read.manifest.packs.map((each) => each.file)).toEqual(stated.statedFiles);
      expect(read.manifest.window).toEqual(stated.window);
      expect(read.manifest.chain.continuous).toBe(stated.continuous);
      expect(read.manifest.chain.breaks.map((each) => each.file)).toEqual(stated.breakFiles);
      expect(read.manifest.duty.carried).toBe(stated.carried);
      expect(read.manifest.duty.short.map((each) => each.file)).toEqual(stated.shortFiles);
    }
    // The order a row is listed in bears nothing, so at least one accepted row has to show the reader putting a
    // run back into the order its figures state rather than repeating the array it was handed.
    expect(accepted.some((one) => one.readback?.runFiles.join(' ') !== one.readback?.statedFiles.join(' '))).toBe(
      true,
    );
  });

  it('rebuilds the honest envelope from the pieces the file publishes', () => {
    // Neither the writer nor the generator: three published byte strings put back together. This is the proof
    // the framing the file states is the framing the bytes carry, and it is what a port with no access to this
    // repository's writer has to check its own encoder against.
    const { header, payload, signature, publicKey } = revealed();
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
    expect(short.slice(0, at)).toBe(long.slice(0, at));
    expect(short.slice(at)).toBe(long.slice(at + 1));
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

  it('vectors both folded lists the same number of times', () => {
    const atBreaks = file.vectors.filter((one) => one.site === 'chain.breaks');
    const atShortfall = file.vectors.filter((one) => one.site === 'duty.short');
    expect(atBreaks.length).toBeGreaterThanOrEqual(5);
    expect(atBreaks.length).toBe(atShortfall.length);
    // Each site carries the same fault shapes: a name the run does not hold, a count too high, a count too low,
    // two rows naming one pack, a row naming a held pack with no such finding, and the reversed list, which is
    // an acceptance rather than a refusal. The codes are the readable form of that list, and the two sites are
    // guarded by twins rather than by one routine, so a suite missing either half is a suite missing both.
    const codesAt = (rows: EpochInventoryVector[]): string[] =>
      rows.filter((one) => one.verdict !== 'verify-ok').map((one) => one.verdict).sort();
    expect(codesAt(atBreaks)).toEqual([
      'EPOCH_INVENTORY_PACK_UNNAMED',
      'EPOCH_INVENTORY_PACK_UNNAMED',
      'EPOCH_INVENTORY_SUMMARY_DISAGREES',
      'EPOCH_INVENTORY_SUMMARY_DISAGREES',
      'EPOCH_INVENTORY_SUMMARY_DISAGREES',
    ]);
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
