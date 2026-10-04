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
import { assertRowRoster, literalEntries, readSourceFile, ROW_NAMING_FIELDS, unionMembers } from './doc-contract.js';

/**
 * The published epoch inventory vectors, replayed the way a port replays them: take the document out of the
 * file, hand the reader the designation the file states beside it, and compare the answer with the verdict the
 * file states. Nothing here computes an expected value from the reader. The run order, the summaries, the
 * refusal sentences and both verdict columns are data in `data/epoch-inventory-v1.json`, and the only question
 * asked of the code is whether it answers as the file says it does.
 *
 * Seven more things are checked on the way, because a suite of one-document artifacts is only as good as the
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
 * A fifth holds the file's own two lists of row columns, the roster of answer columns and the naming columns
 * published beside it, against the columns its published rows carry, in both directions, through the one check
 * every suite with a roster is wired to in `doc-contract.ts`. The sibling suites read that roster as the list
 * of fields a row may add, and a verifier written from the published pattern does the same here, so a column
 * carried by a row and missing from both lists is a compliant row refused, and a column in either list and
 * carried by no row is a field the file promises and the suite withholds. The naming columns are read out of
 * the file rather than repeated here, and a column stated twice in either list or on both is refused, because
 * the equality compares sets and would otherwise pass a roster that lies about a row. The shared naming list
 * those four siblings are handed is held equal to this file's own here, because the two are one list written in
 * two places and this is the case that reads both.
 *
 * A sixth and a seventh hold the published refusals apart at the width a reader actually prints. Three
 * findings share `EPOCH_INVENTORY_RUN_NOT_CONTIGUOUS`, the other codes of this family that more than one
 * published row answers with share a fixed sentence too, and a detail reaches an operator up to a bound: words
 * naming the finding past the cut are a refusal that reads as every other refusal of its code. The bound and
 * the fixed sentences are read out of `packages/receipt/src/errors.ts` rather than repeated here, so the
 * measurement is taken at the width the registry applies and not at one this file remembers.
 *
 * The client half of this reading lives in `packages/cli/test/vector-conformance.test.ts`, which drives the
 * same rows through the two exported inventory readers, and the command half in
 * `packages/cli/test/epoch-inventory-at-the-command-edge.test.ts`, which replays every published row through
 * `ashaveri verify-handover` and holds the pinned `ashaveri verify-epoch-inventory` answer against that one on
 * the rows it names. What is here is the format package's own reader, the one every verdict in this file was
 * witnessed with when the generator wrote it.
 */

const file = loadEpochInventoryVectors();
const ERRORS = '../../../packages/receipt/src/errors.ts';

/**
 * How many units of a quoted detail the reader publishes, read out of the file that cuts it. Stating the
 * number here would let the pin drift behind the bound: the width the rows are measured at has to be the
 * width the reader applies.
 */
function detailBound(): number {
  const stated = /const MAX_DETAIL = (\d+);/u.exec(readSourceFile(ERRORS));
  if (stated === null) throw new Error('the registry no longer states a bound on a quoted detail');
  return Number(stated[1]);
}

const BOUND = detailBound();

/** The fixed sentence the registry publishes beside one code, as written there and not as copied here. */
const FIXED_SENTENCES = new Map(
  literalEntries('ERROR_MESSAGE', ERRORS).map((one) => [one.key, one.value.replace(/^'(.*)'$/su, '$1')]),
);

/**
 * What an operator can read of one published refusal: the part of its detail the bound lets through. The
 * published message already carries the cut, so this takes the fixed sentence off the front and keeps the
 * units behind it that the reader was willing to print, whole where the detail was short enough to publish
 * entire.
 */
function survivesTheBound(one: EpochInventoryVector): string {
  const sentence = FIXED_SENTENCES.get(one.verdict);
  if (sentence === undefined) {
    throw new Error(`${one.name} answers ${one.verdict}, whose fixed sentence the registry does not publish`);
  }
  const head = `${sentence}: `;
  if (one.message === undefined || !one.message.startsWith(head)) {
    throw new Error(`${one.name} publishes no sentence beginning with the fixed words of ${one.verdict}`);
  }
  return one.message.slice(head.length, head.length + BOUND);
}

/**
 * The pairs of rows in a group that read as one another inside the bound, each named by both of its row
 * names. A refusal that says which two collided is the difference between this file telling an operator which
 * row to look at and telling them that something is wrong somewhere among the suite's refusals.
 */
function collidingPairs(rows: readonly EpochInventoryVector[]): string[] {
  const first = new Map<string, string>();
  const collisions: string[] = [];
  for (const one of rows) {
    const readable = survivesTheBound(one);
    const seen = first.get(readable);
    if (seen === undefined) first.set(readable, one.name);
    else collisions.push(`${seen} and ${one.name}`);
  }
  return collisions;
}

/**
 * The first unit of two details at which they differ. Where that falls decides whether the words or a
 * digest carries the difference: the two paths of a contiguity detail are 83 units each and the bound cuts
 * inside the second of them, so a difference that only shows up past the first path could be nothing but
 * the pair the row happens to name.
 */
function firstDifference(left: string, right: string): number {
  let at = 0;
  while (at < left.length && at < right.length && left[at] === right[at]) at += 1;
  return at;
}

const bytes = (base64url: string): Uint8Array => new Uint8Array(Buffer.from(base64url, 'base64url'));

/** The options a row's designation builds, which are the reader's two shapes and no third. */
function optionsFor(one: EpochInventoryVector): EpochInventoryVerifyOptions {
  const presence = one.read.presence?.map((one) => bytes(one));
  const key: EpochInventoryVerifyOptions = (() => {
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
  })();
  return presence === undefined ? key : { ...key, presence };
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

  it('declares every column its published rows carry', () => {
    // The equality itself is written once, in `assertRowRoster`, because four sibling suites hold their rows to
    // the same published roster and a rule kept per file is a rule one file can quietly stop following. What is
    // specific to this one is where the naming columns come from: this file publishes them as
    // `layout.rowNamingFields`, so the generator's list is what is compared rather than a copy of it written
    // here.
    //
    // The list this file publishes is also the list those four siblings are handed: one list written in two
    // places, and a test that reads only one of them proves that one. Each test takes one or the other, so a
    // generator-side rename of a naming column would leave the shared list standing beside a file that does not
    // name it while every roster equality stays true. Compared as sets, because the order is what the rows' own
    // bytes state and no reader depends on where a list of naming columns puts a name.
    expect(
      [...file.layout.rowNamingFields].sort(),
      'the naming list this file publishes and the list the sibling suites are handed are not the same names',
    ).toEqual([...ROW_NAMING_FIELDS].sort());
    assertRowRoster(file, file.layout.rowNamingFields);
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

  it('tells the three contiguity findings apart inside the bound', () => {
    // One code, three findings, and two different remedies among them: a gap is a period the epoch states it
    // attests and does not, an overlap is the same receipts under two signatures, and an entry whose own window
    // does not run forwards is neither. A contiguity detail carries pack paths of 83 units, and two of them
    // where a pair of neighbours is the finding, which is more than the bound lets through. So the words
    // naming the finding have to sit ahead of the paths rather than after them, or an operator reads one
    // sentence for three faults.
    const rows = file.vectors.filter((one) => one.verdict === 'EPOCH_INVENTORY_RUN_NOT_CONTIGUOUS');
    expect(rows.map((one) => one.name).sort()).toEqual([
      'a-window-left-out-of-the-run',
      'a-window-sealed-twice',
      'an-entry-whose-own-window-does-not-run-forwards',
    ]);
    expect(collidingPairs(rows), 'two of the three contiguity refusals read as the same words').toEqual([]);
    // And the difference is carried by the finding and not by a digest: every pair parts company before the
    // first pack path of either detail begins, which is the half an operator can act on whatever the run holds.
    for (const [index, one] of rows.entries()) {
      for (const other of rows.slice(index + 1)) {
        const mine = survivesTheBound(one);
        const theirs = survivesTheBound(other);
        const pathAt = Math.min(mine.indexOf('packs/'), theirs.indexOf('packs/'));
        expect(pathAt, `${one.name} and ${other.name} carry no pack path to measure against`).toBeGreaterThan(-1);
        expect(
          firstDifference(mine, theirs),
          `${one.name} and ${other.name} differ only where a digest would have differed, not in the words`,
        ).toBeLessThan(pathAt);
      }
    }
  });

  it('tells every multi-finding refusal of this family apart inside the bound', () => {
    // The same promise one class wider. The error-code document states of several of these codes that the detail
    // says which finding it was, and the published rows are the only place that claim is checkable. The class is
    // read off the registry rather than named here: every code this package declares for the container, grouped
    // by the refusing rows that answer with it, which is seven codes carrying more than one row over 46 refusing
    // rows. Three rows of the suite answer with codes shared with another container, `NOT_COSE_SIGN1`,
    // `UNSUPPORTED_ALG` and `INVALID_SIGNATURE`, and are outside this class because their sentences belong to
    // that container's reader. Before the contiguity wording moved, one of the seven published two rows as one
    // identical string and the other six already read apart; the measurement is the point, so a code that
    // collapses back is named by its own rows.
    const family = unionMembers('ReceiptErrorCode', ERRORS).filter((code) => code.startsWith('EPOCH_INVENTORY_'));
    const refused = file.vectors.filter((one) => typeof one.message === 'string' && one.message !== '');
    const groups = family
      .map((code) => ({ code, rows: refused.filter((one) => one.verdict === code) }))
      .filter((group) => group.rows.length > 1);
    // A guard over nothing is no guard at all, so the bound below is a floor on how many codes the
    // family answers more than one row with: a reading that found fewer would be a suite that lost
    // rows, not a family that grew out of needing this.
    expect(groups.length).toBeGreaterThanOrEqual(5);
    for (const group of groups) {
      expect(collidingPairs(group.rows), `${group.code} is answered by rows that read as one another`).toEqual([]);
    }
  });
});
