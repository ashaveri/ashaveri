import { describe, expect, it } from 'vitest';
import { sha256, sha384 } from '@noble/hashes/sha2.js';
import {
  EPOCH_INVENTORY_LABEL_MAX_BYTES,
  ReceiptError,
  decodeEpochInventory,
  encodePayload,
  generateSigningKey,
  issueReceipt,
  verifyEpochInventory,
} from '../src/index.js';
import type { EpochInventoryManifest, ReceiptPayload } from '../src/index.js';
import { buildRun, FOLD_HONEST, HELD as foldHeld, sealFoldDocument, sealOf, FOLD_KEY } from './presence-run.js';

/**
 * The printed-line character class has one owner (`src/line-text.ts`) and three consumers in this package: the
 * receipt writer refuses it at the attested text members of a payload (`src/receipt.ts`), the epoch inventory
 * refuses it at the five text positions it prints, the run label and the two deployment ids and the two duty
 * labels it copies (`src/epoch-inventory.ts`), and `src/errors.ts` escapes every one of them out of a message.
 * This file drives one set of characters through all of them and holds them to one membership, because two prose
 * comments saying that two classes are deliberately different is drift waiting to happen, and this estate has
 * already had one guard notice a character that a second guard let through (`packages/cli/src/usage.ts` states that
 * history beside its own copy of the ranges).
 *
 * Two facts are asserted per character and they are not the same fact. Each site's verdict is held to what this
 * file expects of the character, stated below as data rather than read out of the owner, so a test can disagree
 * with its producer rather than borrow its pattern; and the refusal sites are then held to each other, which is
 * the claim of one owner. A site that narrowed its own scan while the owner stayed put fails both halves, and a
 * site that widened past the class fails the first.
 *
 * What stays site-owned is asserted beside it, because sharing a class is not merging two refusals: the byte
 * ceiling belongs to the label alone and reaches no copied position, and so do the position a refusal names, the
 * sentence it gives, and the code a caller branches on. The reader half of that is asked twice over here, at the
 * label and at each copied position, because a rule held at one member of a container and dropped at four is the
 * defect this file exists to catch.
 */

/** The class restated here for the same reason the escaping suites restate it: disagreement has to be possible. */
const FORGES_A_LINE = /[\p{Cc}\p{Cf}\u{2028}\u{2029}\u{e0000}-\u{e007f}]/u;

/**
 * One row per character the two scans of this package answer for, per kind of character the class is made
 * of, and per shape outside it. The soft hyphen, the zero width space, the zero width joiner, the
 * right-to-left override and the tag-block rows are here by name so a reader of this file can see the seam
 * rather than infer it from a range.
 */
const ROSTER: ReadonlyArray<{ readonly name: string; readonly character: string; readonly inClass: boolean }> = [
  { name: 'NUL', character: '\u0000', inClass: true },
  { name: 'line feed', character: '\n', inClass: true },
  { name: 'carriage return', character: '\r', inClass: true },
  { name: 'tab', character: '\t', inClass: true },
  { name: 'escape', character: '\u001b', inClass: true },
  { name: 'information separator four', character: '\u001c', inClass: true },
  { name: 'delete', character: '\u007f', inClass: true },
  { name: 'next line', character: '\u0085', inClass: true },
  { name: 'application program command', character: '\u009f', inClass: true },
  { name: 'soft hyphen', character: '\u00ad', inClass: true },
  { name: 'Arabic number sign', character: '\u0600', inClass: true },
  { name: 'Arabic letter mark', character: '\u061c', inClass: true },
  { name: 'Arabic end of ayah', character: '\u06dd', inClass: true },
  { name: 'Syriac abbreviation mark', character: '\u070f', inClass: true },
  { name: 'Mongolian vowel separator', character: '\u180e', inClass: true },
  { name: 'zero width space', character: '\u200b', inClass: true },
  { name: 'zero width non-joiner', character: '\u200c', inClass: true },
  { name: 'zero width joiner', character: '\u200d', inClass: true },
  { name: 'left-to-right mark', character: '\u200e', inClass: true },
  { name: 'right-to-left mark', character: '\u200f', inClass: true },
  { name: 'line separator', character: '\u2028', inClass: true },
  { name: 'paragraph separator', character: '\u2029', inClass: true },
  { name: 'left-to-right embedding', character: '\u202a', inClass: true },
  { name: 'left-to-right override', character: '\u202d', inClass: true },
  { name: 'right-to-left override', character: '\u202e', inClass: true },
  { name: 'word joiner', character: '\u2060', inClass: true },
  { name: 'function application', character: '\u2061', inClass: true },
  { name: 'left-to-right isolate', character: '\u2066', inClass: true },
  { name: 'pop directional isolate', character: '\u2069', inClass: true },
  { name: 'byte order mark', character: '\ufeff', inClass: true },
  { name: 'interlinear annotation anchor', character: '\ufff9', inClass: true },
  { name: 'language tag', character: '\u{e0000}', inClass: true },
  { name: 'tag space', character: '\u{e0020}', inClass: true },
  { name: 'cancelled tag', character: '\u{e007f}', inClass: true },
  { name: 'a Latin letter', character: 'a', inClass: false },
  { name: 'a space', character: ' ', inClass: false },
  { name: 'a no-break space', character: '\u00a0', inClass: false },
  { name: 'an accented Latin letter', character: 'é', inClass: false },
  { name: 'a CJK ideograph', character: '漢', inClass: false },
  { name: 'a check mark', character: '✓', inClass: false },
  { name: 'a four-per-em space', character: '\u2005', inClass: false },
  { name: 'an astral math letter', character: '\u{1d400}', inClass: false },
  { name: 'an astral emoji', character: '\u{1f600}', inClass: false },
];

/**
 * The ranges the class is argued about, swept whole rather than sampled, each with what a reimplementer who read
 * only the CDDL would expect. Every code point of the tag block is refused because the block is spelled out in the
 * class for that reason; the C0 and C1 ranges are refused as controls; the bidi and zero-width neighbourhood of
 * `U+2000..U+206F` is the mixed one, where spaces, dashes, quotation marks and operators sit between the format
 * characters and only the format characters are refused; and the astral letters and emoji are text a line is made
 * of. The expectation for each is this file's own reading of the ranges, and no site is consulted for it.
 */
const SWEEPS: ReadonlyArray<{ readonly name: string; readonly from: number; readonly to: number }> = [
  { name: 'C0 and C1', from: 0x0000, to: 0x00ff },
  { name: 'the general punctuation block', from: 0x2000, to: 0x206f },
  { name: 'the tag block', from: 0xe0000, to: 0xe007f },
  { name: 'astral Latin letters', from: 0x1d400, to: 0x1d41f },
  { name: 'a run of emoji', from: 0x1f600, to: 0x1f61f },
  { name: 'the combining diacritical marks', from: 0x0300, to: 0x036f },
];

/** A whole document, so the only thing a case moves is the text the class is asked about. */
function payloadV1(overrides: Partial<ReceiptPayload> = {}): ReceiptPayload {
  const at = 1_772_000_000;
  return {
    v: 1,
    iss: 'dpl-9f2a41',
    ins: 'cvm-i-047f',
    iat: at,
    nce: new Uint8Array(16).fill(0xab),
    req: sha256(new TextEncoder().encode('{"model":"m","messages":[]}')),
    res: sha256(new TextEncoder().encode('{"choices":[]}')),
    mdl: 'meta-llama/Llama-3.1-8B-Instruct',
    wts: sha256(new TextEncoder().encode('manifest')),
    meas: { tee: 'snp+gpucc', m: sha384(new TextEncoder().encode('launch-digest')) },
    att: { d: sha256(new Uint8Array(64).fill(2)), ts: at - 60, url: 'https://inference.ashaveri.com/v1/attestation' },
    epk: 3,
    tok: { p: 128, c: 64 },
    mk: { sch: 'none', d: sha256(new Uint8Array(0)) },
    sd: { name: 'host clock', uncertaintySeconds: null },
    cva: {
      collateral: { presence: 'not-taken-in', reason: 'this test took no collateral in' },
      validity: { presence: 'not-taken-in', reason: 'this test recorded no validity context' },
    },
    itm: [{ t: at, d: sha256(new Uint8Array(0)) }],
    ...overrides,
  };
}

/**
 * Two writer positions, one top-level member and one inside a nested map, because which positions a site applies
 * the class to is the site's own fact and the sweep should reach both shapes it holds them in. All eight attested
 * positions are swept against the class in `receipt.test.ts`; this file is about membership.
 */
const WRITER_POSITIONS: ReadonlyArray<{ readonly name: string; readonly carrying: (text: string) => ReceiptPayload }> = [
  { name: 'iss', carrying: (text) => payloadV1({ iss: text }) },
  {
    name: 'att.url',
    carrying: (text) => {
      const base = payloadV1();
      return { ...base, att: { ...base.att, url: text } };
    },
  },
];

interface Verdict {
  readonly refused: boolean;
  readonly code: string;
  readonly message: string;
}

/** A refusal is a `ReceiptError`; anything else is a crash, and this file says so rather than reads a verdict. */
function verdictOf(run: () => unknown): Verdict {
  try {
    run();
    return { refused: false, code: 'accepted', message: '' };
  } catch (err) {
    if (!(err instanceof ReceiptError)) throw new Error(`a site answered with something that is not a refusal: ${String(err)}`);
    return { refused: true, code: err.code, message: err.message };
  }
}

/** What the receipt writer says about one value at one attested position. */
function atWriter(position: { readonly name: string; readonly carrying: (text: string) => ReceiptPayload }, text: string): Verdict {
  return verdictOf(() => encodePayload(position.carrying(text)));
}

/** What the inventory reader says about one run label, over a document whole in every other position. */
function atReader(text: string): Verdict {
  return verdictOf(() => decodeEpochInventory(sealFoldDocument({ ...FOLD_HONEST.manifest, epoch: text })));
}

/** The hex both sites spell a code point in: lowercase, unpadded. */
function hexOf(character: string): string {
  return (character.codePointAt(0) ?? 0).toString(16);
}

/** A value carrying one character and no pad, so the padding rule answers for neither site. */
function carrying(character: string): string {
  return `a${character}b`;
}

/**
 * The four positions an inventory copies out of a deployment manifest and a pack, each with the edit that puts one
 * value at it. They are asked beside the run label because the label is the position the class has always reached
 * and these four are the ones it now reaches too, and a rule held at one member of a container and dropped at four
 * is the defect this file is for.
 *
 * The run they edit is the presence fold's own, with its middle entry short of the period that entry states it
 * owed, because `duty.short[0].art` exists only where a shortfall is stated: a case that wrote the row by hand
 * would be asking the position of a document the fold refuses for another reason, and the refusal a reader would
 * then meet is the summary's and not the text's.
 */
interface CopiedPosition {
  readonly name: string;
  readonly at: (manifest: EpochInventoryManifest, value: string) => EpochInventoryManifest;
}

const SHORT_RUN = buildRun(3, foldHeld, (index, one) =>
  index === 1 ? { ...one, duty: { ...one.duty, required: 500, held: 100 } } : one,
);

const COPIED_POSITIONS: readonly CopiedPosition[] = [
  {
    name: 'manifest.iss',
    at: (one, value) => ({ ...one, manifest: { ...one.manifest, iss: value } }),
  },
  {
    name: 'manifest.ins',
    at: (one, value) => ({ ...one, manifest: { ...one.manifest, ins: value } }),
  },
  {
    name: 'packs[0].duty.art',
    at: (one, value) => ({
      ...one,
      packs: one.packs.map((each, index) => (index === 0 ? { ...each, duty: { ...each.duty, art: value } } : each)),
    }),
  },
  {
    name: 'duty.short[0].art',
    at: (one, value) => ({
      ...one,
      duty: { carried: one.duty.carried, short: one.duty.short.map((each, index) => (index === 0 ? { ...each, art: value } : each)) },
    }),
  },
];

/** What the inventory reader says about one value at one copied position, at the shape half, where the text is read. */
function atCopied(position: CopiedPosition, value: string): Verdict {
  return verdictOf(() => decodeEpochInventory(sealFoldDocument(position.at(SHORT_RUN.manifest, value))));
}

/** What the inventory writer says about the same value, at the step that signs, which parses before it seals. */
function atCopiedWriter(position: CopiedPosition, value: string): Verdict {
  return verdictOf(() => sealOf({ manifest: position.at(SHORT_RUN.manifest, value), artifacts: SHORT_RUN.artifacts }));
}

describe('the printed-line character class has one owner', () => {
  it('holds the roster to a sweep of the class and not a token sample', () => {
    // A roster that quietly stopped covering the class would let all three sites agree on a subset of it, and a
    // roster whose rows were typed on a mistake would let them agree on a wrong answer. Both are refused here, in
    // front of the site checks.
    const refused = ROSTER.filter((one) => one.inClass);
    const admitted = ROSTER.filter((one) => !one.inClass);
    expect(refused.length, 'the roster names almost nothing the class refuses').toBeGreaterThanOrEqual(30);
    expect(admitted.length, 'the roster names almost nothing the class admits').toBeGreaterThanOrEqual(8);
    expect(new Set(ROSTER.map((one) => one.character)).size, 'one character appears twice under two memberships').toBe(ROSTER.length);
    for (const named of ['\u00ad', '\u200b', '\u200d', '\u202e', '\u{e0020}', '\u{e007f}', '\u2028', '\u2029', '\ufeff', '\u180e']) {
      expect(refused.some((one) => one.character === named), `the roster carries no ${hexOf(named)}`).toBe(true);
    }
    for (const one of ROSTER) {
      expect(FORGES_A_LINE.test(one.character), `${one.name} as this file reads the class`).toBe(one.inClass);
    }
  });

  it('refuses and admits the same characters at the writer and at the inventory reader', () => {
    for (const one of ROSTER) {
      const text = carrying(one.character);
      const reader = atReader(text);
      expect(reader.refused, `the run label carrying ${one.name}`).toBe(one.inClass);
      for (const position of WRITER_POSITIONS) {
        const writer = atWriter(position, text);
        expect(writer.refused, `${position.name} carrying ${one.name}`).toBe(one.inClass);
        expect(reader.refused, `${one.name} refused at one site and not the other`).toBe(writer.refused);
      }
    }
  });

  it('holds every copied position to the membership the run label is held to', () => {
    // One roster, four positions, and the label beside them. `inClass` is this file's own reading of the ranges,
    // so a reader that refused the line-enders and let the zero width and directional ones through would fail here
    // at the position that let one, by name, rather than in a sentence about which positions the rule reaches.
    for (const one of ROSTER) {
      const value = carrying(one.character);
      const label = atReader(value);
      for (const position of COPIED_POSITIONS) {
        const copied = atCopied(position, value);
        expect(copied.refused, `${position.name} carrying ${one.name}`).toBe(one.inClass);
        expect(copied.code, `${position.name} carrying ${one.name} answered under another code`).toBe(
          one.inClass ? 'EPOCH_INVENTORY_BAD_DOCUMENT' : 'accepted',
        );
        if (one.inClass) {
          expect(copied.message, `${one.name} refused at ${position.name} without naming the position`).toContain(
            `${position.name} carries the code point ${hexOf(one.character)}, which is not printable text`,
          );
          expect(copied.message, `${one.name} refused with the writer's sentence at ${position.name}`).not.toContain(
            'forge a line',
          );
        }
        expect(copied.refused, `${one.name} refused at ${position.name} and not at the run label`).toBe(label.refused);
      }
    }
  });

  it('refuses the same characters at the copied positions before it seals one', () => {
    // The symmetry the estate asks of a stricter reader: the writer parses what it signs, so a document whose
    // reader refuses a copied value cannot be made through this package's own seal. Each refusal names the
    // position and the code point, which is the half that shows the guard is the one answering rather than some
    // earlier shape complaint about the same document.
    for (const position of COPIED_POSITIONS) {
      for (const one of ROSTER.filter((each) => each.inClass)) {
        const answer = atCopiedWriter(position, carrying(one.character));
        expect(answer.code, `${position.name} carrying ${one.name} was signed`).toBe('EPOCH_INVENTORY_BAD_DOCUMENT');
        expect(answer.message, `${position.name} carrying ${one.name} named another position at the writer`).toContain(
          `${position.name} carries the code point ${hexOf(one.character)}`,
        );
      }
    }
    expect(verdictOf(() => sealOf(SHORT_RUN)).code, 'the run these cases start from does not seal').toBe('accepted');
  });

  it('copies a clean value of any length and any text outside the class, unchanged', () => {
    // The other half of both directions, and the half that keeps the widening honest: no ceiling arrives at a
    // copied position with the class, so a figure as long as a deployment manifest states and as foreign as the
    // document that supplied it reads back byte for byte.
    const clean = ['dpl-47f', `dpl-${'x'.repeat(300)}`, 'cvm-é漢', 'a b', '19(1)\u00a0\u2005\u0301', 'ins-\u{1f600}'];
    for (const position of COPIED_POSITIONS) {
      for (const value of clean) {
        expect(atCopied(position, value).code, `${position.name} carrying ${JSON.stringify(value)} was refused`).toBe(
          'accepted',
        );
      }
    }
    const long = `dpl-${'x'.repeat(300)}-é漢\u{1f600}`;
    const sealed = sealOf({ manifest: COPIED_POSITIONS[0]!.at(SHORT_RUN.manifest, long), artifacts: SHORT_RUN.artifacts });
    const read = verifyEpochInventory(sealed, { publicKey: FOLD_KEY.publicKey, presence: SHORT_RUN.artifacts });
    expect(read.manifest.manifest.iss, 'the value that came back is the value that went in').toBe(long);
    expect(read.outcome.presence, 'the fold stopped answering for a document with a wide issuer').toBeDefined();
  });

  it('answers the class before the width at the label', () => {
    // The label's own scan is the function the copied positions share, and the order this position answers its
    // three questions in is that scan's: emptiness, class, width, padding. Pinned rather than left to the reading
    // order, because a label that is both too wide and unprintable is a document two refusals could name.
    const joiner = String.fromCodePoint(0x200d);
    const past = `${'x'.repeat(EPOCH_INVENTORY_LABEL_MAX_BYTES)}${joiner}`;
    const answer = atReader(past);
    expect(answer.code).toBe('EPOCH_INVENTORY_BAD_DOCUMENT');
    expect(answer.message, 'the width answered before the class').toContain('epoch carries the code point 200d');
    expect(answer.message).not.toContain('must be at most');
    expect(atReader('x'.repeat(EPOCH_INVENTORY_LABEL_MAX_BYTES + 1)).message, 'a wide label with no class member').toContain(
      'must be at most',
    );
  });

  it('agrees with one reading of the ranges at both sites, code point by code point', () => {
    // The roster is read by name; this is the whole of the ranges it stands for, so an owner that dropped the tag
    // block or started refusing astral letters fails here rather than in a sentence. Both sites are asked, and the
    // oracle is the class as this file states it.
    let refused = 0;
    let admitted = 0;
    for (const sweep of SWEEPS) {
      for (let code = sweep.from; code <= sweep.to; code += 1) {
        // Lone surrogates are not code points a `tstr` can hold, and both sites walk by code point.
        if (code >= 0xd800 && code <= 0xdfff) continue;
        const character = String.fromCodePoint(code);
        const refusedHere = FORGES_A_LINE.test(character);
        const text = carrying(character);
        const reader = atReader(text);
        expect(reader.refused, `U+${code.toString(16)} as a run label`).toBe(refusedHere);
        const writer = atWriter(WRITER_POSITIONS[0]!, text);
        expect(writer.refused, `U+${code.toString(16)} as an attested text member`).toBe(refusedHere);
        expect(reader.refused, `U+${code.toString(16)} refused at one site and not the other`).toBe(writer.refused);
        if (refusedHere) refused += 1;
        else admitted += 1;
      }
    }
    expect(refused, 'the sweep refused almost nothing').toBeGreaterThanOrEqual(200);
    expect(admitted, 'the sweep admitted almost nothing').toBeGreaterThanOrEqual(400);
  });

  it('keeps the two refusal sites each on its own sentence, position name, code and ceiling', () => {
    const softHyphen = carrying('\u00ad');
    const writer = atWriter(WRITER_POSITIONS[0]!, softHyphen);
    const nested = atWriter(WRITER_POSITIONS[1]!, softHyphen);
    const reader = atReader(softHyphen);

    // Two codes, because one is a payload this package was handed to sign and the other is somebody else's
    // document, and a caller branches on them apart.
    expect(writer.code, 'the writer answers under its own code').toBe('BAD_PAYLOAD');
    expect(nested.code, 'a nested position answers under the writer code too').toBe('BAD_PAYLOAD');
    expect(reader.code, 'the reader answers under its own code').toBe('EPOCH_INVENTORY_BAD_DOCUMENT');

    // Two sentences, because what each refusal is about differs even though the characters do not.
    expect(writer.message).toContain('iss carries the code point ad, which would forge a line this document never wrote');
    expect(nested.message).toContain('att.url carries the code point ad, which would forge a line this document never wrote');
    expect(reader.message).toContain('epoch carries the code point ad, which is not printable text');
    expect(reader.message).not.toContain('forge a line');

    // One ceiling, the label's, which is not the writer's to take and not the class's to give.
    expect(atReader('x'.repeat(EPOCH_INVENTORY_LABEL_MAX_BYTES)).refused, 'the label at the last byte the format allows').toBe(false);
    const pastIt = atReader('x'.repeat(EPOCH_INVENTORY_LABEL_MAX_BYTES + 1));
    expect(pastIt.code, 'the label one byte past it').toBe('EPOCH_INVENTORY_BAD_DOCUMENT');
    expect(pastIt.message, 'and the ceiling answered for, not the class').toContain('must be at most');
    expect(atWriter(WRITER_POSITIONS[0]!, 'x'.repeat(4096)).refused, 'a long clean value is text a line is made of').toBe(false);
  });

  it('escapes the same class out of every message this package raises', () => {
    // The third consumer. A message about a value is printed by whoever caught the error, so the promise that a
    // `ReceiptError` is one line of visible text is the same class asked at a third site, and it is asked here of
    // every character the roster names rather than of the line feeds an earlier suite thought of.
    for (const one of ROSTER) {
      const message = new ReceiptError('BAD_PAYLOAD', carrying(one.character)).message;
      expect(FORGES_A_LINE.test(message), `a message still carrying ${one.name} raw`).toBe(false);
      if (one.inClass) expect(message, `${one.name} escaped rather than dropped`).not.toContain(one.character);
      else expect(message, `${one.name} kept as written`).toContain(carrying(one.character));
    }
  });

  it('refuses at the step that signs, not only at the encoder a test calls', () => {
    // `issueReceipt` is the call a receipt is made through, and `signEpochInventory` parses a run label before it
    // seals one: the shared class has to reach the paths that produce bytes, or it is a claim about a helper
    // rather than about a document. The inventory half of this is also what keeps the widening honest, because a
    // writer that runs the same scan before it signs cannot produce a document its own reader newly refuses.
    const key = generateSigningKey();
    for (const one of ROSTER.filter((each) => each.inClass)) {
      const text = carrying(one.character);
      expect(verdictOf(() => issueReceipt(payloadV1({ iss: text }), key)).code, `iss carrying ${one.name}`).toBe('BAD_PAYLOAD');
      expect(verdictOf(() => issueReceipt(payloadV1({ mdl: text }), key)).code, `mdl carrying ${one.name}`).toBe('BAD_PAYLOAD');
      expect(
        verdictOf(() => sealOf({ ...FOLD_HONEST, manifest: { ...FOLD_HONEST.manifest, epoch: text } })).code,
        `a run label carrying ${one.name} at the inventory writer`,
      ).toBe('EPOCH_INVENTORY_BAD_DOCUMENT');
    }
    expect(verdictOf(() => sealOf(FOLD_HONEST)).code, 'the honest run still seals').toBe('accepted');
    expect(verdictOf(() => issueReceipt(payloadV1({ iss: 'dpl-9f2a41' }), key)).refused, 'a clean value still signs').toBe(false);
  });
});
