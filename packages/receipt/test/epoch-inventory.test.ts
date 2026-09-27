import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha2.js';
import { Ajv2020 } from 'ajv/dist/2020.js';
import {
  EPOCH_INVENTORY_CONTENT_TYPE,
  EPOCH_INVENTORY_LABEL_MAX_BYTES,
  EPOCH_INVENTORY_PACK_FILE,
  EPOCH_INVENTORY_PACKS_DIRECTORY,
  EPOCH_INVENTORY_RETENTION_FILE,
  ReceiptError,
  decodeCanonical,
  decodeEpochInventory,
  decodePack,
  encodeCanonical,
  encodeEpochInventoryManifest,
  encodeEpochInventoryProtectedHeader,
  encodePackManifest,
  epochInventorySigStructure,
  sealEpochInventory,
  signEpochInventory,
  signingKeyFromSeed,
  toHex,
  verifyEpochInventory,
  type EpochInventoryBreak,
  type EpochInventoryManifest,
  type EpochInventoryPack,
  type EpochInventoryShort,
  type EpochInventoryVerifyOptions,
  type PackManifest,
  type SigningKey,
} from '../src/index.js';
import {
  DECLARED_EPOCH_INVENTORY_PROTECTED_LABELS,
  EPOCH_INVENTORY_BREAK_MEMBERS,
  EPOCH_INVENTORY_CHAIN_MEMBERS,
  EPOCH_INVENTORY_DEPLOYMENT_MEMBERS,
  EPOCH_INVENTORY_DUTY_MEMBERS,
  EPOCH_INVENTORY_MANIFEST_MEMBERS,
  EPOCH_INVENTORY_PACK_CHAIN_MEMBERS,
  EPOCH_INVENTORY_PACK_DUTY_MEMBERS,
  EPOCH_INVENTORY_PACK_MEMBERS,
  EPOCH_INVENTORY_SHORT_MEMBERS,
  EPOCH_INVENTORY_SPAN_MEMBERS,
} from '../src/epoch-inventory.js';
import { cddlRule } from './cddl.js';

/**
 * The epoch inventory: a deployment's statement about a closed run of packs, and the arithmetic a reader owes
 * itself over that statement.
 *
 * An inventory lists the packs of a run and folds three summaries from them, a window, a chain claim and a duty
 * claim, inside its own signature. The cases below are grouped around the properties a reviewer holding only
 * this document is owed: that it is an inventory, that a key signed it, that its entries name one pack each and
 * are filed where they say they are, and that its summaries are the arithmetic of the entries rather than the
 * writer's recollection of them. Each is asked in the way that would fail if the property were dropped.
 *
 * Two sources of bytes, and the split is the one `redaction.test.ts` makes. Honest documents come from
 * `signEpochInventory`, so the writer is witnessed producing what the reader accepts, and every document meant
 * to be refused is assembled from the published pieces and re-sealed under the key its own header names, because
 * a writer that runs its own parse and its own fold before signing cannot be asked to make a fault it refuses to
 * sign. The summaries of a mutated case are computed by `foldOf` below, which is this file's own second reading
 * of the writer's arithmetic rather than a call into the shipped module, so a fold that drifted there shows up
 * here as a disagreement instead of agreeing with itself.
 *
 * The packs themselves are none of this file's business. An inventory describes files a reader is not handed,
 * and no case below pretends that a reader of this document can check a digest against a pack.
 */

const KEY: SigningKey = signingKeyFromSeed(new Uint8Array(32).fill(51));
const SECOND: SigningKey = signingKeyFromSeed(new Uint8Array(32).fill(52));

const RUN_START = 1_700_000_000;
const WINDOW = 1_000;
const DAY = 86_400;
/** The assembly stamp of the first pack, which is where the JSON text below is edited by a case. */
const FIRST_AT = RUN_START + WINDOW + 10;

const cddlPath = fileURLToPath(new URL('../epoch-inventory.cddl', import.meta.url));
const schemaPath = fileURLToPath(new URL('../schemas/epoch-inventory-v1.schema.json', import.meta.url));
const errorsPath = fileURLToPath(new URL('../src/errors.ts', import.meta.url));

function thrownCode(run: () => unknown): string {
  try {
    run();
    return 'accepted';
  } catch (err) {
    return err instanceof ReceiptError ? err.code : `UNCODED:${String(err)}`;
  }
}

/** A digest of a label, so every case states figures of the right width without inventing hex by hand. */
function digest(label: string): string {
  return toHex(sha256(new TextEncoder().encode(label)));
}

/** One pack of a run, as an inventory states it. */
function packEntry(one: {
  readonly index: number;
  readonly from: number;
  readonly to: number;
  readonly anchor: string;
  readonly required?: number;
  readonly held?: number;
  readonly art?: string;
}): EpochInventoryPack {
  const sha = digest(`pack/${String(one.index)}`);
  const home = `${EPOCH_INVENTORY_PACKS_DIRECTORY}/${sha}`;
  return {
    file: `${home}/${EPOCH_INVENTORY_PACK_FILE}`,
    retention: `${home}/${EPOCH_INVENTORY_RETENTION_FILE}`,
    sha256: sha,
    retentionSha256: digest(`retention/${String(one.index)}`),
    at: one.to + 10,
    span: { from: one.from, to: one.to },
    items: 3,
    chain: { anchor: one.anchor, head: digest(`head/${String(one.index)}`) },
    kid: digest(`kid/${String(one.index)}`),
    duty: {
      art: one.art ?? '19(1)',
      rev: one.from - DAY,
      required: one.required ?? 100,
      held: one.held ?? 200,
    },
  };
}

/**
 * The three summaries, folded by this file over the entries in the order their figures put them: the outer edges
 * of the windows, each pair whose digests do not meet, and each pack whose own two integers disagree.
 */
function summariesOf(packs: readonly EpochInventoryPack[]): Pick<EpochInventoryManifest, 'window' | 'chain' | 'duty'> {
  const run = [...packs].sort(
    (a, b) => a.span.from - b.span.from || a.at - b.at || (a.sha256 < b.sha256 ? -1 : a.sha256 > b.sha256 ? 1 : 0),
  );
  const breaks: EpochInventoryBreak[] = [];
  const short: EpochInventoryShort[] = [];
  let previous: EpochInventoryPack | undefined;
  for (const one of run) {
    if (previous !== undefined && one.chain.anchor !== previous.chain.head) {
      breaks.push({ file: one.file, afterHead: previous.chain.head, anchor: one.chain.anchor });
    }
    if (one.duty.held < one.duty.required) {
      short.push({
        file: one.file,
        art: one.duty.art,
        required: one.duty.required,
        held: one.duty.held,
        shortBy: one.duty.required - one.duty.held,
      });
    }
    previous = one;
  }
  const first = run[0];
  const last = run[run.length - 1];
  if (first === undefined || last === undefined) throw new Error('a run of no packs states no window to fold');
  return {
    window: { from: first.span.from, to: last.span.to },
    chain: { anchor: first.chain.anchor, head: last.chain.head, continuous: breaks.length === 0, breaks },
    duty: { carried: short.length === 0, short },
  };
}

/** A whole document over one run: the entries, and the summaries this file folds from them. */
function inventory(packs: readonly EpochInventoryPack[]): EpochInventoryManifest {
  return {
    v: 1,
    epoch: 'quarter-one',
    manifest: { iss: 'dpl-inventory-test', ins: 'cvm-inventory-test', epk: 3 },
    packs,
    ...summariesOf(packs),
  };
}

/** A run of three windows that continues itself, the middle one short of its own required period. */
function runOf(count: number, over: (index: number, pack: EpochInventoryPack) => EpochInventoryPack = (_, one) => one): EpochInventoryManifest {
  const packs: EpochInventoryPack[] = [];
  let anchor = digest('the seam a retirement left');
  for (let index = 0; index < count; index += 1) {
    const pack = packEntry({ index, from: RUN_START + index * WINDOW, to: RUN_START + (index + 1) * WINDOW, anchor });
    packs.push(over(index, pack));
    anchor = pack.chain.head;
  }
  return inventory(packs);
}

const HONEST: EpochInventoryManifest = runOf(3, (index, one) =>
  index === 1 ? { ...one, duty: { ...one.duty, required: 500, held: 100 } } : one,
);

/** The honest run with its second pack anchored somewhere other than the first pack's head. */
const BROKEN: EpochInventoryManifest = (() => {
  const packs = HONEST.packs.map((one, index) =>
    index === 1 ? { ...one, chain: { ...one.chain, anchor: digest('a chain this run never held') } } : one,
  );
  return inventory(packs);
})();

/** A document sealed through the four published pieces rather than `signEpochInventory`, which would refuse it. */
function sealDocument(manifest: EpochInventoryManifest, signer: SigningKey = KEY): Uint8Array {
  return sealPayload(encodeEpochInventoryManifest(manifest), signer);
}

/** Arbitrary payload bytes under an inventory header, signed by whoever the case names. */
function sealPayload(payloadBytes: Uint8Array, signer: SigningKey = KEY, contentType = EPOCH_INVENTORY_CONTENT_TYPE): Uint8Array {
  const header = encodeEpochInventoryProtectedHeader(signer.kid, contentType);
  return sealEpochInventory(header, payloadBytes, ed25519.sign(epochInventorySigStructure(header, payloadBytes), signer.privateKey));
}

function honestText(): string {
  return new TextDecoder().decode(encodeEpochInventoryManifest(HONEST));
}

/** The honest document's payload text with one span replaced, which is how the JSON refusals are built. */
function textWith(from: string, to: string): Uint8Array {
  const text = honestText();
  const at = text.indexOf(from);
  if (at < 0) throw new Error(`the honest document carries no ${JSON.stringify(from)} for a case to replace`);
  return new TextEncoder().encode(`${text.slice(0, at)}${to}${text.slice(at + from.length)}`);
}

function asMap(bytes: Uint8Array): Map<unknown, unknown> {
  const decoded = decodeCanonical(bytes);
  if (!(decoded instanceof Map)) throw new Error('a payload this file sealed is not a map');
  return decoded;
}

function elementsOf(bytes: Uint8Array): unknown[] {
  const contents = (decodeCanonical(bytes) as { contents?: unknown }).contents;
  if (!Array.isArray(contents)) throw new Error('a document this file sealed is not a four-element envelope');
  return contents;
}

function payloadOf(bytes: Uint8Array): Uint8Array {
  return elementsOf(bytes)[2] as Uint8Array;
}

function headerWith(alter: (map: Map<unknown, unknown>) => void): Uint8Array {
  const header = asMap(encodeEpochInventoryProtectedHeader(KEY.kid));
  alter(header);
  return encodeCanonical(header);
}

/** The honest entries with one of them replaced, and the summaries folded from the result. */
function withPacks(packs: readonly EpochInventoryPack[]): EpochInventoryManifest {
  return inventory(packs);
}

/** The honest entries with the second one's file moved under another entry's digest. */
function swapFile(packs: readonly EpochInventoryPack[]): EpochInventoryPack[] {
  const first = packs[0];
  const second = packs[1];
  if (first === undefined || second === undefined) throw new Error('this case needs a run of two packs');
  return packs.map((one, index) => (index === 0 ? { ...one, file: second.file } : one));
}

const readWith = (key: SigningKey = KEY): EpochInventoryVerifyOptions => ({ publicKey: key.publicKey });

const honest = sealDocument(HONEST);
const honestRead = () => verifyEpochInventory(honest, readWith());
const FOREIGN = `${EPOCH_INVENTORY_PACKS_DIRECTORY}/${digest('a pack of another epoch')}/${EPOCH_INVENTORY_PACK_FILE}`;

describe('the inventory writer and its own reader', () => {
  it('assembles a document through the published pieces exactly as it signs one', () => {
    const payloadBytes = encodeEpochInventoryManifest(HONEST);
    const protectedBytes = encodeEpochInventoryProtectedHeader(KEY.kid);
    const piecewise = sealEpochInventory(
      protectedBytes,
      payloadBytes,
      ed25519.sign(epochInventorySigStructure(protectedBytes, payloadBytes), KEY.privateKey),
    );
    expect(toHex(piecewise)).toBe(toHex(signEpochInventory(HONEST, KEY)));
    expect(verifyEpochInventory(piecewise, readWith()).manifest).toEqual(HONEST);
  });

  it('signs the document as written, so the bytes are the file and not a canonical rendering of it', () => {
    // A reviewer is handed a file. The signature covers its bytes, which is what makes the verdict about the
    // thing read rather than about a reconstruction of it, and the same document re-indented is therefore a
    // different document to this reader.
    const payloadBytes = payloadOf(honest);
    const [header, , , signature] = elementsOf(honest);
    expect(new TextDecoder().decode(payloadBytes)).toBe(honestText());
    expect(payloadBytes[0]).toBe(0x7b);
    expect(payloadBytes[payloadBytes.length - 1]).toBe(0x0a);
    const reformatted = new TextEncoder().encode(`${JSON.stringify(HONEST)}\n`);
    expect(
      thrownCode(() => verifyEpochInventory(sealEpochInventory(header as Uint8Array, reformatted, signature as Uint8Array), readWith())),
    ).toBe('INVALID_SIGNATURE');
    expect(verifyEpochInventory(sealPayload(reformatted), readWith()).manifest).toEqual(HONEST);
  });

  it('refuses to sign a document its own reader would reject', () => {
    const faults: Array<[string, EpochInventoryManifest, string]> = [
      ['a run of no packs', { ...HONEST, packs: [] }, 'EPOCH_INVENTORY_BAD_DOCUMENT'],
      ['a label with nothing in it', { ...HONEST, epoch: '' }, 'EPOCH_INVENTORY_BAD_DOCUMENT'],
      ['a padded label', { ...HONEST, epoch: '  quarter-one  ' }, 'EPOCH_INVENTORY_BAD_DOCUMENT'],
      ['a label past the printed width', { ...HONEST, epoch: 'x'.repeat(EPOCH_INVENTORY_LABEL_MAX_BYTES + 1) }, 'EPOCH_INVENTORY_BAD_DOCUMENT'],
      ['a figure below zero', { ...HONEST, packs: HONEST.packs.map((one) => ({ ...one, at: -1 })) }, 'EPOCH_INVENTORY_BAD_DOCUMENT'],
      ['a digest of another width', { ...HONEST, chain: { ...HONEST.chain, anchor: 'deadbeef' } }, 'EPOCH_INVENTORY_BAD_DOCUMENT'],
      ['an entry filed under another pack', inventory(swapFile(HONEST.packs)), 'EPOCH_INVENTORY_PACK_MISNAMED'],
      ['a pack named twice', { ...HONEST, packs: [...HONEST.packs, HONEST.packs[0] ?? HONEST.packs[1]!] }, 'EPOCH_INVENTORY_DUPLICATE_PACK'],
      ['a window wider than the run', { ...HONEST, window: { from: HONEST.window.from - 1, to: HONEST.window.to } }, 'EPOCH_INVENTORY_SUMMARY_DISAGREES'],
      ['a break smoothed over', { ...BROKEN, chain: { ...BROKEN.chain, continuous: true } }, 'EPOCH_INVENTORY_SUMMARY_DISAGREES'],
      ['a duty stated as carried when it is not', { ...HONEST, duty: { carried: true, short: [] } }, 'EPOCH_INVENTORY_SUMMARY_DISAGREES'],
      ['a version no format has used', { ...HONEST, v: 2 as unknown as 1 }, 'EPOCH_INVENTORY_UNSUPPORTED_VERSION'],
    ];
    for (const [name, edited, code] of faults) {
      expect(thrownCode(() => signEpochInventory(edited, KEY)), `${name} was signed`).toBe(code);
    }
  });

  it('refuses a signing key whose kid is not sha256 of its public half', () => {
    // An inventory whose key no reader can resolve is bytes with a signature on them, so this is refused where
    // the document is made rather than where somebody finds out.
    expect(thrownCode(() => signEpochInventory(HONEST, { ...KEY, kid: new Uint8Array(32) }))).toBe('BAD_SIGNING_KEY');
    expect(thrownCode(() => signEpochInventory(HONEST, { ...KEY, publicKey: SECOND.publicKey }))).toBe('BAD_SIGNING_KEY');
  });
});

describe('an accepted inventory, read the way a reviewer reads it', () => {
  it('hands back every figure the document states, and the run in the order its own figures put it', () => {
    const read = honestRead();
    expect(read.manifest).toEqual(HONEST);
    expect(read.outcome.packs).toEqual(HONEST.packs);
    expect(read.header.contentType).toBe(EPOCH_INVENTORY_CONTENT_TYPE);
    expect(read.header.alg).toBe(-8);
    expect(toHex(read.header.kid)).toBe(toHex(KEY.kid));
    expect(read.manifest.packs[1]?.duty).toEqual({ art: '19(1)', rev: RUN_START + WINDOW - DAY, required: 500, held: 100 });
    expect(read.manifest.chain.continuous).toBe(true);
    expect(read.manifest.chain.breaks).toEqual([]);
    expect(read.manifest.duty.short).toHaveLength(1);
    expect(read.manifest.window).toEqual({ from: RUN_START, to: RUN_START + 3 * WINDOW });
  });

  it('states each entry where the layout files it, and refuses one that is filed elsewhere', () => {
    const [entry] = HONEST.packs;
    expect(entry?.file).toBe(`${EPOCH_INVENTORY_PACKS_DIRECTORY}/${entry?.sha256}/${EPOCH_INVENTORY_PACK_FILE}`);
    expect(entry?.retention).toBe(`${EPOCH_INVENTORY_PACKS_DIRECTORY}/${entry?.sha256}/${EPOCH_INVENTORY_RETENTION_FILE}`);
    const misnamed = sealDocument(inventory(swapFile(HONEST.packs)));
    expect(thrownCode(() => decodeEpochInventory(misnamed))).toBe('EPOCH_INVENTORY_PACK_MISNAMED');
    expect(thrownCode(() => verifyEpochInventory(misnamed, readWith()))).toBe('EPOCH_INVENTORY_PACK_MISNAMED');
    // The same position of another shape is a malformed document and not a misnaming, and the distinction is one
    // a reviewer acts on differently: a misnaming is a path to go and look at, a shape fault is a writer that
    // did not write this layout.
    for (const [name, file] of [
      ['another shape', 'somewhere/else.cbor'],
      ['a directory of another width', `${EPOCH_INVENTORY_PACKS_DIRECTORY}/deadbeef/${EPOCH_INVENTORY_PACK_FILE}`],
      ['the retention name where the pack belongs', entry?.retention ?? ''],
    ] as const) {
      const packs = HONEST.packs.map((one, index) => (index === 0 ? { ...one, file } : one));
      expect(thrownCode(() => decodeEpochInventory(sealPayload(encodeEpochInventoryManifest({ ...HONEST, packs })))), name).toBe(
        'EPOCH_INVENTORY_BAD_DOCUMENT',
      );
    }
  });

  it('places the entries by their windows and not by the order the array arrived', () => {
    // Position in `packs` bears nothing, so a run listed backwards is the same run: same window, same chain
    // claim, same duty list. A reader that took the array as an order would state a different epoch from the
    // same bytes depending on how the file came.
    const backwards = sealDocument({ ...HONEST, packs: [...HONEST.packs].reverse() });
    const read = verifyEpochInventory(backwards, readWith());
    expect(read.outcome.packs.map((one) => one.file)).toEqual(HONEST.packs.map((one) => one.file));
    expect(read.outcome.packs.map((one) => one.file)).not.toEqual([...HONEST.packs].reverse().map((one) => one.file));
  });

  it('reports a run that does not chain itself with the two digests of the pair, and nothing else about it', () => {
    expect(BROKEN.chain.continuous).toBe(false);
    expect(BROKEN.chain.breaks).toHaveLength(1);
    expect(BROKEN.chain.breaks[0]?.file).toBe(BROKEN.packs[1]?.file);
    expect(BROKEN.chain.breaks[0]?.afterHead).toBe(BROKEN.packs[0]?.chain.head);
    expect(BROKEN.chain.breaks[0]?.anchor).toBe(BROKEN.packs[1]?.chain.anchor);
    const read = verifyEpochInventory(sealDocument(BROKEN), readWith());
    expect(read.manifest.chain.breaks).toEqual(BROKEN.chain.breaks);
    expect(read.outcome.packs.map((one) => one.file)).toEqual(HONEST.packs.map((one) => one.file));
  });

  it('carries the copied text positions at the lengths their own formats state', () => {
    // The two ids and a duty label are copied out of a deployment manifest and a pack, and both of those
    // sources declare text with a floor and no ceiling, so a long issuer and a seventy-byte label make a
    // document today's own writer emits. A ceiling on this side would refuse the inventory for a figure its
    // writer was handed by a format that allows it, which no layout that describes artifacts already in the
    // field may claim.
    const iss = `dpl-${'x'.repeat(300)}`;
    const ins = `cvm-${'y'.repeat(300)}`;
    const art = `19(${('1'.repeat(66))})`;
    const wide = runOf(2, (index, one) => ({
      ...one,
      duty: index === 1 ? { ...one.duty, art, required: 500, held: 100 } : { ...one.duty, art },
    }));
    const document: EpochInventoryManifest = { ...wide, manifest: { iss, ins, epk: wide.manifest.epk } };
    expect(new TextEncoder().encode(art)).toHaveLength(70);
    expect(thrownCode(() => decodeEpochInventory(sealDocument(document)))).toBe('accepted');
    const read = verifyEpochInventory(sealDocument(document), readWith());
    expect(read.manifest.manifest).toEqual({ iss, ins, epk: 3 });
    expect(read.manifest.packs.map((one) => one.duty.art)).toEqual([art, art]);
    expect(read.manifest.duty.short).toHaveLength(1);
    expect(read.manifest.duty.short[0]?.art).toBe(art);
    // The floor each of the three keeps is the one those sources state: text that is not empty.
    for (const [name, edited] of [
      ['an empty issuer', { ...document, manifest: { iss: '', ins, epk: 3 } }],
      ['an empty instance', { ...document, manifest: { iss, ins: '', epk: 3 } }],
      ['an empty duty label', runOf(2, (index, one) => ({
        ...one,
        duty: index === 1 ? { ...one.duty, art: '', required: 500, held: 100 } : { ...one.duty, art: '' },
      }))],
    ] as const) {
      expect(thrownCode(() => decodeEpochInventory(sealDocument(edited))), name).toBe('EPOCH_INVENTORY_BAD_DOCUMENT');
    }
    // And the label this container writes for itself keeps the width the format states beside it.
    expect(
      thrownCode(() => decodeEpochInventory(sealDocument({ ...document, epoch: 'x'.repeat(EPOCH_INVENTORY_LABEL_MAX_BYTES + 1) }))),
      'a run label past the printed width',
    ).toBe('EPOCH_INVENTORY_BAD_DOCUMENT');
  });

  it('folds the window of a run of one pack from that pack and not from the fold\'s own seeds', () => {
    // The window is folded one entry at a time from the identities of the two operations, so a run of one pack
    // states that pack's edges and an empty run, which never reaches the fold, is refused where the entries are
    // read. A document whose single window is restated wider is refused at the same position as a long run
    // whose stated edges miss an entry, which is what makes the fold one rule at either size.
    const single = runOf(1);
    const read = verifyEpochInventory(sealDocument(single), readWith());
    expect(read.outcome.packs).toHaveLength(1);
    expect(read.manifest.window).toEqual({ from: RUN_START, to: RUN_START + WINDOW });
    expect(read.manifest.chain.continuous).toBe(true);
    expect(read.manifest.duty.carried).toBe(true);
    expect(thrownCode(() => verifyEpochInventory(sealDocument({ ...single, window: { from: 0, to: single.window.to } }), readWith()))).toBe(
      'EPOCH_INVENTORY_SUMMARY_DISAGREES',
    );
  });

  it('decodes with no key at all, and answers the run only to a reader that has one', () => {
    const unsigned = sealEpochInventory(
      encodeEpochInventoryProtectedHeader(KEY.kid),
      encodeEpochInventoryManifest(HONEST),
      new Uint8Array(64),
    );
    expect(decodeEpochInventory(unsigned).manifest).toEqual(HONEST);
    expect(thrownCode(() => verifyEpochInventory(unsigned, readWith()))).toBe('INVALID_SIGNATURE');
    // A gap between two windows is a disagreement across the entries, so it is refused where the run is read:
    // under a key, and nowhere without one. The shape of the document is fine either way.
    const gapped = withPacks(HONEST.packs.map((one, index) => (index === 2 ? { ...one, span: { from: one.span.from + 5, to: one.span.to + 5 } } : one)));
    expect(decodeEpochInventory(sealDocument(gapped)).manifest.packs).toHaveLength(3);
    expect(thrownCode(() => verifyEpochInventory(sealDocument(gapped), readWith()))).toBe(
      'EPOCH_INVENTORY_RUN_NOT_CONTIGUOUS',
    );
  });
});

describe('the envelope and the header', () => {
  it('refuses another container at the header, before any key is consulted', () => {
    for (const contentType of ['ashaveri/receipt', 'ashaveri/pack', 'ashaveri/export', 'ashaveri/redaction', 'ashaveri/deployment-manifest']) {
      const bytes = sealPayload(encodeEpochInventoryManifest(HONEST), KEY, contentType);
      expect(thrownCode(() => decodeEpochInventory(bytes)), contentType).toBe('EPOCH_INVENTORY_BAD_HEADER');
      expect(thrownCode(() => verifyEpochInventory(bytes, { resolveKey: () => KEY.publicKey })), contentType).toBe(
        'EPOCH_INVENTORY_BAD_HEADER',
      );
    }
  });

  it('refuses the confusion a content type is the whole answer to, in both directions', () => {
    // A real pack manifest, whole and verifiable, handed to this reader, and a real inventory document handed
    // to a reader that believes the label. Both pairs of bytes pass their own checks, so only label 3 settles
    // which claim a reviewer is holding.
    const packManifest: PackManifest = {
      v: 1,
      at: RUN_START + 3 * WINDOW + 10,
      span: { from: RUN_START, to: RUN_START + 3 * WINDOW },
      chain: { anchor: new Uint8Array(32), head: new Uint8Array(32) },
      duty: { art: '19(1)', rev: RUN_START - DAY, required: 100, held: 200 },
      items: [],
    };
    expect(thrownCode(() => decodeEpochInventory(sealPayload(encodePackManifest(packManifest))))).toBe(
      'EPOCH_INVENTORY_MALFORMED_JSON',
    );
    const wearing = sealEpochInventory(
      encodeEpochInventoryProtectedHeader(KEY.kid, 'ashaveri/pack'),
      encodeEpochInventoryManifest(HONEST),
      new Uint8Array(64),
    );
    // The pack reader answers this in its own words, whichever of them the JSON payload trips: the fact the
    // direction states is that an inventory cannot be talked into passing as a pack, and which pack refusal it
    // answers depends on where a CBOR reader stops on JSON bytes rather than on anything this format claims.
    expect(thrownCode(() => decodePack(wearing))).toMatch(/^PACK_/u);
  });

  it('refuses a header that is not the header this format declares', () => {
    const payloadBytes = encodeEpochInventoryManifest(HONEST);
    expect(thrownCode(() => decodeEpochInventory(sealEpochInventory(headerWith((map) => map.set(5, 'what')), payloadBytes, new Uint8Array(64))))).toBe(
      'EPOCH_INVENTORY_BAD_HEADER',
    );
    expect(thrownCode(() => decodeEpochInventory(sealEpochInventory(headerWith((map) => map.set(4, KEY.kid.slice(0, 31))), payloadBytes, new Uint8Array(64))))).toBe(
      'EPOCH_INVENTORY_BAD_HEADER',
    );
    expect(thrownCode(() => decodeEpochInventory(sealEpochInventory(headerWith((map) => map.set(1, -7)), payloadBytes, new Uint8Array(64))))).toBe(
      'UNSUPPORTED_ALG',
    );
  });

  it('refuses an envelope that is not an envelope, including one cut short', () => {
    expect(thrownCode(() => decodeEpochInventory(encodeCanonical(elementsOf(honest))))).toBe('NOT_COSE_SIGN1');
    const [header, , payload, signature] = elementsOf(honest);
    expect(
      thrownCode(() => decodeEpochInventory(sealEpochInventory(header as Uint8Array, payload as Uint8Array, (signature as Uint8Array).slice(0, 63)))),
    ).toBe('NOT_COSE_SIGN1');
    expect(thrownCode(() => decodeEpochInventory(honest.slice(0, 20)))).toBe('EPOCH_INVENTORY_MALFORMED_CBOR');
    expect(thrownCode(() => decodeEpochInventory(encodeCanonical([])))).toBe('NOT_COSE_SIGN1');
  });
});

describe('the JSON reading, where this container differs from every other signed document', () => {
  it('refuses a member name stated twice, which is the one reading a parser settles silently', () => {
    const text = honestText();
    const duplicated = text.replace('"packs": [', '"packs": [],\n  "packs": [');
    expect(duplicated).not.toBe(text);
    expect(thrownCode(() => decodeEpochInventory(sealPayload(new TextEncoder().encode(duplicated))))).toBe(
      'EPOCH_INVENTORY_MALFORMED_JSON',
    );
    const twoLabels = text.replace('"epoch": "quarter-one",', '"epoch": "quarter-one",\n  "epoch": "quarter-two",');
    expect(twoLabels).not.toBe(text);
    expect(thrownCode(() => decodeEpochInventory(sealPayload(new TextEncoder().encode(twoLabels))))).toBe(
      'EPOCH_INVENTORY_MALFORMED_JSON',
    );
  });

  it('refuses a number written other than as an integer, at the read rather than at a field', () => {
    for (const [name, spelling] of [
      ['a float', `${String(FIRST_AT)}.0`],
      ['an exponent', `${String(FIRST_AT / 10)}e1`],
      ['negative zero', '-0'],
      ['a leading plus', `+${String(FIRST_AT)}`],
      ['a leading zero', `0${String(FIRST_AT)}`],
    ] as const) {
      const bytes = textWith(`"at": ${String(FIRST_AT)}`, `"at": ${spelling}`);
      expect(thrownCode(() => decodeEpochInventory(sealPayload(bytes))), `${name} was read as an integer`).toBe(
        'EPOCH_INVENTORY_MALFORMED_JSON',
      );
    }
    // The same figure written the way the format writes it is accepted, so the refusals above are about the
    // spelling and not about the number.
    expect(verifyEpochInventory(sealPayload(textWith(`"at": ${String(FIRST_AT)}`, `"at": ${String(FIRST_AT)}`)), readWith()).manifest).toEqual(HONEST);
  });

  it('refuses a payload that is not one JSON document, and one that nests past the layout', () => {
    expect(thrownCode(() => decodeEpochInventory(sealPayload(new Uint8Array([0xff, 0xfe, 0x00, 0x7b]))))).toBe(
      'EPOCH_INVENTORY_MALFORMED_JSON',
    );
    expect(thrownCode(() => decodeEpochInventory(sealPayload(new TextEncoder().encode('not json at all'))))).toBe(
      'EPOCH_INVENTORY_MALFORMED_JSON',
    );
    expect(thrownCode(() => decodeEpochInventory(sealPayload(new TextEncoder().encode('{}{}'))))).toBe(
      'EPOCH_INVENTORY_MALFORMED_JSON',
    );
    // A reader is handed bytes nobody believes, and a scanner that recursed without a bound would be a crash
    // standing where a refusal belongs.
    expect(thrownCode(() => decodeEpochInventory(sealPayload(new TextEncoder().encode(`[${'['.repeat(20)}${']'.repeat(20)}]`))))).toBe(
      'EPOCH_INVENTORY_MALFORMED_JSON',
    );
    // Past the reading, into the layout: a value that is not the document, and a document missing a member.
    expect(thrownCode(() => decodeEpochInventory(sealPayload(new TextEncoder().encode('[]'))))).toBe(
      'EPOCH_INVENTORY_BAD_DOCUMENT',
    );
    expect(thrownCode(() => decodeEpochInventory(sealPayload(new TextEncoder().encode('{"v": 1}'))))).toBe(
      'EPOCH_INVENTORY_BAD_DOCUMENT',
    );
    expect(thrownCode(() => decodeEpochInventory(sealPayload(new TextEncoder().encode('{"v": 2}'))))).toBe(
      'EPOCH_INVENTORY_UNSUPPORTED_VERSION',
    );
    expect(thrownCode(() => decodeEpochInventory(sealPayload(new TextEncoder().encode('{"v": "1"}'))))).toBe(
      'EPOCH_INVENTORY_BAD_DOCUMENT',
    );
  });

  it('stops the reading at the eight levels the layout states, and holds a figure inside what it can state', () => {
    // The cap is a rule of the format and not a parser detail: the payload is bytes nobody believes, and a
    // scanner that recursed without a bound answers a nested document with a crash where the contract
    // promises a code. Eight is the number the format file and the document both state, so the boundary is
    // asked at both sides of it: a document nested to eight gets past the reading and is refused for what it
    // says, and one nested past it never gets that far.
    const nested = (levels: number): string => `${'['.repeat(levels)}${']'.repeat(levels)}`;
    const read = (text: string): string =>
      thrownCode(() => decodeEpochInventory(sealPayload(new TextEncoder().encode(text))));
    expect(read(nested(8)), 'eight levels is the depth the format states and the reading refused').toBe(
      'EPOCH_INVENTORY_BAD_DOCUMENT',
    );
    expect(read(nested(9)), 'nine levels is past the depth the format states and the reading accepted').toBe(
      'EPOCH_INVENTORY_MALFORMED_JSON',
    );
    // The same reading is where a figure past what a reader holds exactly is settled: the scanner refuses the
    // token, so no field read is ever asked to notice that the number arrived rounded.
    expect(read(`{"v": 1, "epk": ${String(Number.MAX_SAFE_INTEGER + 2)}}`)).toBe('EPOCH_INVENTORY_MALFORMED_JSON');
    expect(read(`{"v": 1, "epk": ${String(Number.MAX_SAFE_INTEGER)}}`)).toBe('EPOCH_INVENTORY_BAD_DOCUMENT');
    // `v` is the one figure read before any other member, and it answers from the same place: a version no
    // reader holds exactly, and a version written as a float, are both refusals of the spelling, which is why
    // the version read asks nothing but whether the member is a number.
    expect(read('{"v": 9007199254740993}')).toBe('EPOCH_INVENTORY_MALFORMED_JSON');
    expect(read('{"v": 9007199254740992}')).toBe('EPOCH_INVENTORY_MALFORMED_JSON');
    expect(read('{"v": 1.0}')).toBe('EPOCH_INVENTORY_MALFORMED_JSON');
  });

  it('refuses a member this version does not define, at the document and inside an entry', () => {
    const cases: Array<[string, string, string]> = [
      ['a member beside the seven', '"v": 1,', '"v": 1,\n  "met": true,'],
      ['a member beside the ten of an entry', '"items": 3,', '"items": 3,\n        "met": true,'],
      ['a member inside the duty block', '"required": 100,', '"required": 100,\n          "met": true,'],
    ];
    for (const [name, from, to] of cases) {
      expect(thrownCode(() => decodeEpochInventory(replaceInPayload(from, to))), name).toBe(
        'EPOCH_INVENTORY_BAD_DOCUMENT',
      );
    }
  });
});

describe('the run, and what a reader recomputes from it', () => {
  it('refuses a window that leaves a period out of the run, and one that seals a window twice', () => {
    const gapped = withPacks(HONEST.packs.map((one, index) => (index === 2 ? { ...one, span: { from: one.span.from + 5, to: one.span.to + 5 } } : one)));
    const overlap = withPacks(HONEST.packs.map((one, index) => (index === 2 ? { ...one, span: { from: one.span.from - 5, to: one.span.to - 5 } } : one)));
    for (const [name, manifest] of [['a gap', gapped], ['an overlap', overlap]] as const) {
      expect(thrownCode(() => verifyEpochInventory(sealDocument(manifest), readWith())), name).toBe(
        'EPOCH_INVENTORY_RUN_NOT_CONTIGUOUS',
      );
    }
    const backwards = withPacks(HONEST.packs.map((one, index) => (index === 0 ? { ...one, span: { from: one.span.to, to: one.span.from } } : one)));
    expect(thrownCode(() => verifyEpochInventory(sealDocument(backwards), readWith())), 'a window that does not run forwards').toBe(
      'EPOCH_INVENTORY_RUN_NOT_CONTIGUOUS',
    );
  });

  it('refuses a pack named twice, which is one pack counted as two', () => {
    const [last] = HONEST.packs.slice(-1);
    const twice = { ...HONEST, packs: [...HONEST.packs, last ?? HONEST.packs[0]!] };
    const bytes = sealDocument(twice);
    expect(thrownCode(() => decodeEpochInventory(bytes))).toBe('EPOCH_INVENTORY_DUPLICATE_PACK');
    expect(thrownCode(() => verifyEpochInventory(bytes, readWith()))).toBe('EPOCH_INVENTORY_DUPLICATE_PACK');
  });

  it('refuses a break or a shortfall about a pack the run does not hold', () => {
    const breakNamed = { ...BROKEN, chain: { ...BROKEN.chain, breaks: [{ ...BROKEN.chain.breaks[0]!, file: FOREIGN }] } };
    expect(thrownCode(() => verifyEpochInventory(sealDocument(breakNamed), readWith()))).toBe(
      'EPOCH_INVENTORY_PACK_UNNAMED',
    );
    const shortNamed = { ...HONEST, duty: { ...HONEST.duty, short: [{ ...HONEST.duty.short[0]!, file: FOREIGN }] } };
    expect(thrownCode(() => verifyEpochInventory(sealDocument(shortNamed), readWith()))).toBe(
      'EPOCH_INVENTORY_PACK_UNNAMED',
    );
  });

  it('refuses a run whose two breaks, or two shortfalls, are stated as one pack twice', () => {
    // The masking case. A list compared by its size and then looked up by name lets two rows naming one pack
    // hold the count right while the second row is answered by the entry the first already settled, so a run
    // that breaks twice reads as one that breaks once and the other break is never examined. This is the
    // fault class the block exists to make refusable: a reviewer told "one break" about a run with two.
    const twoBreaks = runOf(3, (index, one) =>
      index === 0 ? one : { ...one, chain: { ...one.chain, anchor: digest(`a seam this run never held/${String(index)}`) } },
    );
    expect(twoBreaks.chain.breaks).toHaveLength(2);
    expect(twoBreaks.chain.continuous).toBe(false);
    expect(verifyEpochInventory(sealDocument(twoBreaks), readWith()).manifest.chain.breaks).toHaveLength(2);
    const [firstBreak] = twoBreaks.chain.breaks;
    const doubledBreak = { ...twoBreaks, chain: { ...twoBreaks.chain, breaks: [firstBreak!, firstBreak!] } };
    expect(doubledBreak.chain.breaks).toHaveLength(2);
    expect(
      thrownCode(() => verifyEpochInventory(sealDocument(doubledBreak), readWith())),
      'two rows naming one pack, and the run\'s other break stated by nobody',
    ).toBe('EPOCH_INVENTORY_SUMMARY_DISAGREES');

    const twoShorts = runOf(3, (index, one) =>
      index === 0 ? one : { ...one, duty: { ...one.duty, required: 500, held: 100 } },
    );
    expect(twoShorts.duty.short).toHaveLength(2);
    expect(twoShorts.duty.carried).toBe(false);
    expect(verifyEpochInventory(sealDocument(twoShorts), readWith()).manifest.duty.short).toHaveLength(2);
    const [firstShort] = twoShorts.duty.short;
    const doubledShort = { ...twoShorts, duty: { carried: false, short: [firstShort!, firstShort!] } };
    expect(doubledShort.duty.short).toHaveLength(2);
    expect(
      thrownCode(() => verifyEpochInventory(sealDocument(doubledShort), readWith())),
      'two rows naming one pack, and the run\'s other shortfall stated by nobody',
    ).toBe('EPOCH_INVENTORY_SUMMARY_DISAGREES');
  });

  it('refuses a break list or a shortfall list stating more rows than the run has', () => {
    // The lists are compared by the set of packs they name, so a count that disagrees is a disagreement whether
    // the document states too many rows or too few. Both cases here carry distinct names, because a repeat is
    // answered by the name rule before the count is reached: a case that could be refused either way witnesses
    // neither guard.
    const extraBreakRow = {
      ...BROKEN,
      chain: {
        ...BROKEN.chain,
        continuous: false,
        breaks: [
          ...BROKEN.chain.breaks,
          { file: BROKEN.packs[2]?.file ?? '', afterHead: BROKEN.packs[1]?.chain.head ?? '', anchor: BROKEN.packs[2]?.chain.anchor ?? '' },
        ],
      },
    };
    expect(extraBreakRow.chain.breaks).toHaveLength(2);
    expect(thrownCode(() => verifyEpochInventory(sealDocument(extraBreakRow), readWith())), 'the run breaks once and two rows are stated').toBe(
      'EPOCH_INVENTORY_SUMMARY_DISAGREES',
    );

    const extraShortRow = {
      ...HONEST,
      duty: {
        carried: false,
        short: [...HONEST.duty.short, { file: HONEST.packs[2]?.file ?? '', art: '19(1)', required: 100, held: 200, shortBy: 100 }],
      },
    };
    expect(extraShortRow.duty.short).toHaveLength(2);
    expect(thrownCode(() => verifyEpochInventory(sealDocument(extraShortRow), readWith())), 'the run falls short once and two rows are stated').toBe(
      'EPOCH_INVENTORY_SUMMARY_DISAGREES',
    );
  });

  it('refuses a break list or a shortfall list stating fewer rows than the run has', () => {
    // The same comparison from the other side, and the side a document reaches by leaving a row out: the run's
    // own figures fold two rows and the list carries one, with the one it carries correct as far as it goes.
    const brokenTwice = runOf(3, (index, one) =>
      index === 0 ? one : { ...one, chain: { ...one.chain, anchor: digest(`a seam this run never held/${String(index)}`) } },
    );
    expect(brokenTwice.chain.breaks).toHaveLength(2);
    const missingBreakRow = { ...brokenTwice, chain: { ...brokenTwice.chain, continuous: false, breaks: [brokenTwice.chain.breaks[0]!] } };
    expect(missingBreakRow.chain.breaks).toHaveLength(1);
    expect(thrownCode(() => verifyEpochInventory(sealDocument(missingBreakRow), readWith())), 'the run breaks twice and one row is stated').toBe(
      'EPOCH_INVENTORY_SUMMARY_DISAGREES',
    );

    const shortTwice = runOf(3, (index, one) =>
      index === 0 ? one : { ...one, duty: { ...one.duty, required: 500, held: 100 } },
    );
    expect(shortTwice.duty.short).toHaveLength(2);
    const missingShortRow = { ...shortTwice, duty: { carried: false, short: [shortTwice.duty.short[0]!] } };
    expect(missingShortRow.duty.short).toHaveLength(1);
    expect(thrownCode(() => verifyEpochInventory(sealDocument(missingShortRow), readWith())), 'the run falls short twice and one row is stated').toBe(
      'EPOCH_INVENTORY_SUMMARY_DISAGREES',
    );
  });

  it('refuses a row naming a pack the run holds where the run neither breaks nor falls short', () => {
    // `EPOCH_INVENTORY_PACK_UNNAMED` answers two documents: one naming a pack the list does not carry, and one
    // whose rows are as numerous as the run's but pointed at the wrong entries. The second is the one a reader
    // meets on a document shaped like an honest one, and it is reached only where the counts agree, so both rows
    // here carry a name taken from the run's own entries beside a row the run does support.
    const twoBreaks = runOf(3, (index, one) =>
      index === 0 ? one : { ...one, chain: { ...one.chain, anchor: digest(`a seam this run never held/${String(index)}`) } },
    );
    const namedHeldBreak = {
      ...twoBreaks,
      chain: {
        ...twoBreaks.chain,
        continuous: false,
        breaks: [
          twoBreaks.chain.breaks[0]!,
          { file: twoBreaks.packs[0]?.file ?? '', afterHead: twoBreaks.packs[2]?.chain.head ?? '', anchor: twoBreaks.packs[0]?.chain.anchor ?? '' },
        ],
      },
    };
    expect(thrownCode(() => verifyEpochInventory(sealDocument(namedHeldBreak), readWith())), 'the run begins at the pack a break row names').toBe(
      'EPOCH_INVENTORY_PACK_UNNAMED',
    );

    const twoShorts = runOf(3, (index, one) =>
      index === 0 ? one : { ...one, duty: { ...one.duty, required: 500, held: 100 } },
    );
    const namedHeldShort = {
      ...twoShorts,
      duty: {
        carried: false,
        short: [twoShorts.duty.short[0]!, { file: twoShorts.packs[0]?.file ?? '', art: '19(1)', required: 100, held: 200, shortBy: 100 }],
      },
    };
    expect(thrownCode(() => verifyEpochInventory(sealDocument(namedHeldShort), readWith())), 'the named pack holds more than it states it owed').toBe(
      'EPOCH_INVENTORY_PACK_UNNAMED',
    );
    // The detail is what tells the two apart for a reviewer, and it is the run's own entry rather than a lookup
    // miss: the reader says the pack is held and states nothing owed there.
    let namedHeldShortMessage = '';
    try {
      verifyEpochInventory(sealDocument(namedHeldShort), readWith());
    } catch (err) {
      namedHeldShortMessage = err instanceof Error ? err.message : String(err);
    }
    expect(namedHeldShortMessage).toContain('holds without a shortfall in it');
  });

  it('reads a break list and a shortfall list in any order, since each row is keyed by the pack it names', () => {
    // The reader matches a row to the pair or the entry its own `file` fixes, so a document that lists its rows
    // in another order states the same run and is answered with a pass. Only what the names settle is refused:
    // a row naming a pack with no break, and a pack named by two rows while another is named by none.
    const twoBreaks = runOf(3, (index, one) =>
      index === 0 ? one : { ...one, chain: { ...one.chain, anchor: digest(`a seam this run never held/${String(index)}`) } },
    );
    const backwards = { ...twoBreaks, chain: { ...twoBreaks.chain, breaks: [...twoBreaks.chain.breaks].reverse() } };
    expect(backwards.chain.breaks).toHaveLength(2);
    expect(verifyEpochInventory(sealDocument(backwards), readWith()).manifest.chain.breaks).toEqual(backwards.chain.breaks);
    const twoShorts = runOf(3, (index, one) =>
      index === 0 ? one : { ...one, duty: { ...one.duty, required: 500, held: 100 } },
    );
    const shortReversed = { ...twoShorts, duty: { carried: false, short: [...twoShorts.duty.short].reverse() } };
    expect(shortReversed.duty.short).toHaveLength(2);
    expect(verifyEpochInventory(sealDocument(shortReversed), readWith()).manifest.duty).toEqual(shortReversed.duty);
  });

  it('refuses each summary that is not the arithmetic of the entries', () => {
    const [second] = HONEST.packs;
    const claimed: EpochInventoryBreak = { file: second?.file ?? '', afterHead: HONEST.chain.anchor, anchor: digest('a digest of nothing') };
    const cases: Array<[string, EpochInventoryManifest]> = [
      ['a break smoothed into continuous', { ...BROKEN, chain: { ...BROKEN.chain, continuous: true } }],
      ['a break claimed where the run chains', { ...HONEST, chain: { ...HONEST.chain, continuous: false, breaks: [claimed] } }],
      ['a break quoted from the wrong pair', { ...BROKEN, chain: { ...BROKEN.chain, breaks: BROKEN.chain.breaks.map((one) => ({ ...one, afterHead: digest('another head') })) } }],
      ['a break row listed twice', { ...BROKEN, chain: { ...BROKEN.chain, breaks: [...BROKEN.chain.breaks, ...BROKEN.chain.breaks] } }],
      ['a stated anchor that is not the run begins with', { ...HONEST, chain: { ...HONEST.chain, anchor: digest('another anchor') } }],
      ['a stated head that is not where the run ends', { ...HONEST, chain: { ...HONEST.chain, head: digest('another head') } }],
      ['a window narrower than the run', { ...HONEST, window: { from: HONEST.window.from, to: HONEST.window.to - 1 } }],
      ['a duty stated as carried when it is not', { ...HONEST, duty: { carried: true, short: [] } }],
      ['a shortfall subtracted wrongly', { ...HONEST, duty: { carried: false, short: HONEST.duty.short.map((one) => ({ ...one, shortBy: one.shortBy + 1 })) } }],
      ['a shortfall measured against a neighbour', { ...HONEST, duty: { carried: false, short: HONEST.duty.short.map((one) => ({ ...one, required: 100 })) } }],
      ['a summary missing a shortfall the run has', { ...HONEST, duty: { carried: false, short: [] } }],
    ];
    for (const [name, edited] of cases) {
      expect(thrownCode(() => verifyEpochInventory(sealDocument(edited), readWith())), name).toBe(
        'EPOCH_INVENTORY_SUMMARY_DISAGREES',
      );
    }
    // The fold redone from the entries is accepted, which is what makes the cases above about the summaries and
    // not about the shape of a document that reports a broken run or a shortfall.
    expect(verifyEpochInventory(sealDocument(BROKEN), readWith()).manifest.chain.continuous).toBe(false);
    const met = withPacks(HONEST.packs.map((one) => ({ ...one, duty: { ...one.duty, held: 900 } })));
    expect(verifyEpochInventory(sealDocument(met), readWith()).manifest.duty).toEqual({ carried: true, short: [] });
  });

  it('carries a run across two duty labels without reading one against the other', () => {
    const mixed = runOf(2, (index, one) =>
      index === 1 ? { ...one, duty: { art: '26(6)', rev: one.duty.rev, required: 5 * DAY, held: DAY } } : one,
    );
    const read = verifyEpochInventory(sealDocument(mixed), readWith());
    expect(read.manifest.packs.map((one) => one.duty.art)).toEqual(['19(1)', '26(6)']);
    expect(read.manifest.duty.carried).toBe(false);
    expect(read.manifest.duty.short).toHaveLength(1);
    expect(read.manifest.duty.short[0]?.art).toBe('26(6)');
    expect(read.manifest.duty.short[0]?.shortBy).toBe(4 * DAY);
    // The 19(1) window is not measured against the five-year figure beside it, which would make a met window
    // unmet, and the 26(6) window is not measured against the 100 seconds its neighbour states.
    expect(read.manifest.packs[0]?.duty.required).toBe(100);
  });

  it('resolves the envelope under a key a resolver answers with, and refuses the rest', () => {
    const resolved = verifyEpochInventory(honest, {
      resolveKey: (kid: Uint8Array) => (toHex(kid) === toHex(KEY.kid) ? KEY.publicKey : undefined),
    });
    expect(toHex(resolved.header.kid)).toBe(toHex(KEY.kid));
    expect(thrownCode(() => verifyEpochInventory(honest, {}))).toBe('EPOCH_INVENTORY_UNKNOWN_KEY');
    expect(thrownCode(() => verifyEpochInventory(honest, { resolveKey: () => undefined }))).toBe('EPOCH_INVENTORY_UNKNOWN_KEY');
    expect(thrownCode(() => verifyEpochInventory(honest, readWith(SECOND)))).toBe('EPOCH_INVENTORY_KID_MISMATCH');
    expect(thrownCode(() => verifyEpochInventory(honest, { resolveKey: () => SECOND.publicKey }))).toBe(
      'EPOCH_INVENTORY_KID_MISMATCH',
    );
    const split = sealEpochInventory(
      encodeEpochInventoryProtectedHeader(KEY.kid),
      encodeEpochInventoryManifest(HONEST),
      ed25519.sign(epochInventorySigStructure(encodeEpochInventoryProtectedHeader(KEY.kid), encodeEpochInventoryManifest(HONEST)), SECOND.privateKey),
    );
    expect(thrownCode(() => verifyEpochInventory(split, readWith()))).toBe('INVALID_SIGNATURE');
  });
});

describe('the layout: this file, the CDDL and the twin', () => {
  const cddl = readFileSync(cddlPath, 'utf8');
  const blocks: Array<[string, readonly string[]]> = [
    ['Ashaveri-Epoch-Inventory-Document', EPOCH_INVENTORY_MANIFEST_MEMBERS],
    ['Ashaveri-Epoch-Inventory-Deployment', EPOCH_INVENTORY_DEPLOYMENT_MEMBERS],
    ['Ashaveri-Epoch-Inventory-Pack', EPOCH_INVENTORY_PACK_MEMBERS],
    ['Ashaveri-Epoch-Inventory-Span', EPOCH_INVENTORY_SPAN_MEMBERS],
    ['Ashaveri-Epoch-Inventory-Pack-Chain', EPOCH_INVENTORY_PACK_CHAIN_MEMBERS],
    ['Ashaveri-Epoch-Inventory-Pack-Duty', EPOCH_INVENTORY_PACK_DUTY_MEMBERS],
    ['Ashaveri-Epoch-Inventory-Run-Chain', EPOCH_INVENTORY_CHAIN_MEMBERS],
    ['Ashaveri-Epoch-Inventory-Break', EPOCH_INVENTORY_BREAK_MEMBERS],
    ['Ashaveri-Epoch-Inventory-Run-Duty', EPOCH_INVENTORY_DUTY_MEMBERS],
    ['Ashaveri-Epoch-Inventory-Shortfall', EPOCH_INVENTORY_SHORT_MEMBERS],
  ];

  it('lists each block exactly as the CDDL declares it, and in the order it declares it', () => {
    for (const [rule, members] of blocks) {
      expect(declaredMembers(cddlRule(cddl, rule)), `${rule} and the reader's list are two answers`).toEqual([...members]);
      expect(cddlRule(cddl, rule), `${rule} grew an open member`).not.toContain('...');
    }
    expect(headerLabels(cddl)).toEqual([...DECLARED_EPOCH_INVENTORY_PROTECTED_LABELS].sort((a, b) => a - b));
    expect(cddl).toContain(`"${EPOCH_INVENTORY_CONTENT_TYPE}"`);
    // The bound the scanner keeps is one the format states beside the other rules of the reading.
    expect(cddl).toContain('A document nests no deeper than eight levels');
    // Every bound a reader enforces is one the format states, because the projection carries floors only:
    // the label this container writes is bounded by a width, and the three positions it copies are bounded by
    // nothing above the floor their own formats give them.
    expect(cddl).toContain(`epoch: tstr .size (1..${String(EPOCH_INVENTORY_LABEL_MAX_BYTES)})`);
    for (const [rule, member] of [
      ['Ashaveri-Epoch-Inventory-Deployment', 'iss: tstr,'],
      ['Ashaveri-Epoch-Inventory-Deployment', 'ins: tstr,'],
      ['Ashaveri-Epoch-Inventory-Pack-Duty', 'art: tstr,'],
      ['Ashaveri-Epoch-Inventory-Shortfall', 'art: tstr,'],
    ] as const) {
      const block = cddlRule(cddl, rule);
      expect(block, `${rule} no longer states ${member} as text bounded by nothing`).toContain(member);
      expect(block.replace(member, ''), `${rule} grew a ceiling beside ${member}`).not.toContain('.size');
    }
    expect(cddl).toContain(`packs/<digest>/${EPOCH_INVENTORY_PACK_FILE}`);
    expect(cddl).toContain(`packs/<digest>/${EPOCH_INVENTORY_RETENTION_FILE}`);
  });

  it('closes the twin over exactly the members the reader closes, in the same order', () => {
    const schema = JSON.parse(readFileSync(schemaPath, 'utf8')) as {
      $id?: unknown;
      $defs?: Record<string, { properties?: Record<string, unknown>; required?: string[]; additionalProperties?: unknown }>;
    };
    const named = new Map(blocks.map(([, members], index) => [index, members]));
    const definitions = ['manifest', 'deployment', 'pack', 'span', 'packChain', 'packDuty', 'runChain', 'break', 'runDuty', 'shortfall'];
    for (const [index, name] of definitions.entries()) {
      const block = schema.$defs?.[name];
      const members = named.get(index) ?? [];
      if (block === undefined) throw new Error(`${name} is no definition of the published twin`);
      expect(Object.keys(block.properties ?? {}), `${name} is a twin the reader does not match`).toEqual([...members]);
      expect([...(block.required ?? [])].sort(), `${name} requires something its reader does not, or omits one`).toEqual([...members].sort());
      expect(block.additionalProperties, `${name} leaves a member open the format does not define`).toBe(false);
    }
    expect(schema.$id).toBe('https://ashaveri.com/schemas/epoch-inventory-v1.json');
  });

  it('compiles under strict mode and accepts a projection of the document the writer wrote', () => {
    const schema = JSON.parse(readFileSync(schemaPath, 'utf8')) as Record<string, unknown>;
    const validate = new Ajv2020({ strict: true }).compile(schema);
    const projection = {
      protectedHeader: { alg: 'EdDSA', kid: toHex(KEY.kid), typ: EPOCH_INVENTORY_CONTENT_TYPE },
      payload: JSON.parse(honestText()) as unknown,
    };
    expect(validate(projection), JSON.stringify(validate.errors)).toBe(true);
    const payload = projection.payload as Record<string, unknown>;
    const negative: Array<[string, Record<string, unknown>]> = [
      ['a member the format does not define', { ...payload, met: true }],
      ['a run of no packs', { ...payload, packs: [] }],
      ['a digest of another width', { ...payload, chain: { ...(payload.chain as object), anchor: 'deadbeef' } }],
      ['a break naming something other than a pack home', { ...payload, chain: { ...(payload.chain as object), continuous: false, breaks: [{ file: 'x', afterHead: digest('a'), anchor: digest('b') }] } }],
      ['a shortfall row with no subtraction', { ...payload, duty: { carried: false, short: [{ file: FOREIGN, art: '19(1)', required: 500, held: 100 }] } }],
      ['a version that is not this one', { ...payload, v: 2 }],
    ];
    for (const [name, edited] of negative) {
      expect(validate({ ...projection, payload: edited }), `${name} was accepted by the twin`).toBe(false);
    }
    // The folds across entries are not keywords a projection can carry, and the twin says so: a `continuous` of
    // true beside a break row is a document this projection accepts and the reader refuses. The case is asserted
    // rather than left implied, because the division of labour between the two is the thing a reimplementer is
    // most likely to read backwards.
    const smoothed = { ...(payload as Record<string, unknown>), chain: { ...(payload.chain as object), continuous: true, breaks: [{ file: FOREIGN, afterHead: digest('a'), anchor: digest('b') }] } };
    expect(validate({ ...projection, payload: smoothed }), 'the twin claims a fold rule it cannot carry').toBe(true);
    expect(thrownCode(() => verifyEpochInventory(sealPayload(new TextEncoder().encode(JSON.stringify(smoothed, null, 2))), readWith()))).toBe(
      'EPOCH_INVENTORY_SUMMARY_DISAGREES',
    );
    for (const member of EPOCH_INVENTORY_MANIFEST_MEMBERS) {
      const without: Record<string, unknown> = { ...payload };
      delete without[member];
      expect(validate({ ...projection, payload: without }), `${member} was not required by the twin`).toBe(false);
    }
  });

  it('carries floors and no ceiling, which is the sentence the projection states', () => {
    const text = readFileSync(schemaPath, 'utf8');
    for (const keyword of ['maxLength', 'maxItems', 'maximum', 'exclusiveMaximum']) {
      expect(text, `the twin grew a ${keyword}, which belongs to the CDDL`).not.toContain(keyword);
    }
    expect(text).toContain('the byte ceiling belongs to');
  });
});

describe('every refusal this container names is reached', () => {
  it('has a case in this file that answers with it', () => {
    const [last] = HONEST.packs.slice(-1);
    const runs: Array<() => string> = [
      () => thrownCode(() => decodeEpochInventory(honest.slice(0, 20))),
      () => thrownCode(() => decodeEpochInventory(encodeCanonical([]))),
      () => thrownCode(() => decodeEpochInventory(sealEpochInventory(headerWith((map) => map.set(1, -7)), encodeEpochInventoryManifest(HONEST), new Uint8Array(64)))),
      () => thrownCode(() => decodeEpochInventory(sealPayload(encodeEpochInventoryManifest(HONEST), KEY, 'ashaveri/pack'))),
      () => thrownCode(() => decodeEpochInventory(sealPayload(new TextEncoder().encode('{"v": 1, "v": 2}')))),
      () => thrownCode(() => decodeEpochInventory(sealPayload(new TextEncoder().encode('not json')))),
      () => thrownCode(() => decodeEpochInventory(sealPayload(new TextEncoder().encode('{"v": 2}')))),
      () => thrownCode(() => decodeEpochInventory(sealPayload(new TextEncoder().encode('{"v": 1}')))),
      () => thrownCode(() => decodeEpochInventory(sealDocument({ ...HONEST, packs: [] }))),
      () => thrownCode(() => decodeEpochInventory(sealDocument({ ...HONEST, packs: [...HONEST.packs, last ?? HONEST.packs[0]!] }))),
      () => thrownCode(() => decodeEpochInventory(sealDocument(inventory(swapFile(HONEST.packs))))),
      () => thrownCode(() => verifyEpochInventory(sealDocument(withPacks(HONEST.packs.map((one, index) => (index === 2 ? { ...one, span: { from: one.span.from + 5, to: one.span.to + 5 } } : one)))), readWith())),
      () => thrownCode(() => verifyEpochInventory(sealDocument({ ...BROKEN, chain: { ...BROKEN.chain, breaks: [{ ...BROKEN.chain.breaks[0]!, file: FOREIGN }] } }), readWith())),
      () => thrownCode(() => verifyEpochInventory(sealDocument({ ...BROKEN, chain: { ...BROKEN.chain, continuous: true } }), readWith())),
      () => thrownCode(() => verifyEpochInventory(honest, {})),
      () => thrownCode(() => verifyEpochInventory(honest, readWith(SECOND))),
      () => thrownCode(() => verifyEpochInventory(sealEpochInventory(encodeEpochInventoryProtectedHeader(KEY.kid), encodeEpochInventoryManifest(HONEST), new Uint8Array(64)), readWith())),
      () => thrownCode(() => signEpochInventory(HONEST, { ...KEY, kid: new Uint8Array(32) })),
    ];
    const observed = new Set(runs.map((run) => run()));
    for (const one of observed) {
      expect(one, 'a case answered with something no registry declares').not.toMatch(/^UNCODED/);
    }
    const declared = [...new Set([...readFileSync(errorsPath, 'utf8').matchAll(/'(EPOCH_INVENTORY_[A-Z0-9_]+)'/gu)].map((found) => found[1]!))];
    expect(declared.length).toBeGreaterThanOrEqual(12);
    for (const code of declared) {
      expect(observed, `${code} is declared and no case here reaches it`).toContain(code);
    }
  });
});

/** The payload of the honest document with one span of its text replaced, then re-sealed. */
function replaceInPayload(from: string, to: string): Uint8Array {
  const text = honestText();
  const at = text.indexOf(from);
  if (at < 0) throw new Error(`the honest document carries no ${JSON.stringify(from)} for a case to replace`);
  return sealPayload(new TextEncoder().encode(`${text.slice(0, at)}${to}${text.slice(at + from.length)}`));
}

/**
 * The members one block declares by text label, in the order it declares them, comments stripped. The rule
 * whose text this reads is the shared `cddlRule`, and only the member pattern is local, because the pattern
 * has to admit the capitals this layout's figures carry (`retentionSha256`, `afterHead`, `shortBy`) where
 * `receipt.cddl` spells every member of a block in lowercase.
 */
function declaredMembers(block: string): string[] {
  const members: string[] = [];
  for (const line of block.split('\n').slice(1)) {
    for (const piece of line.split(';')[0]!.split(',')) {
      const found = /^\s*([a-z][A-Za-z0-9_]*)\s*:/u.exec(piece);
      if (found) members.push(found[1]!);
    }
  }
  if (members.length === 0) throw new Error('this block declares no member, so a comparison against it proves nothing');
  return members;
}

/** The integer labels the signed header block declares, including the negative one the COSE registry uses. */
function headerLabels(source: string): number[] {
  const labels: number[] = [];
  for (const line of cddlRule(source, 'Ashaveri-Epoch-Inventory-Protected-Header').split('\n').slice(1)) {
    const declaration = line.split(';')[0]!;
    if (declaration.trim() === '') continue;
    const found = /^\s*(-?\d+)\s*:/u.exec(declaration);
    if (!found) throw new Error(`this reader takes one integer-labelled member per line and cannot read "${declaration.trim()}"`);
    labels.push(Number(found[1]));
  }
  if (labels.length === 0) throw new Error('the signed header declares no member by label');
  return labels.sort((a, b) => a - b);
}
