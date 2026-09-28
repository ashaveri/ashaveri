import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  EPOCH_INVENTORY_CONTENT_TYPE,
  EPOCH_INVENTORY_LABEL_MAX_BYTES,
  EPOCH_INVENTORY_PACK_FILE,
  EPOCH_INVENTORY_PACKS_DIRECTORY,
  EPOCH_INVENTORY_RETENTION_FILE,
  PACK_CONTENT_TYPE,
  ReceiptError,
  decodeCanonical,
  decodeEpochInventory,
  encodeCanonical,
  encodeEpochInventoryManifest,
  encodeEpochInventoryProtectedHeader,
  encodePackManifest,
  epochInventorySigStructure,
  sealEpochInventory,
  signEpochInventory,
  signingKeyFromSeed,
  toBase64Url,
  toHex,
  verifyEpochInventory,
  type EpochInventoryBreak,
  type EpochInventoryManifest,
  type EpochInventoryPack,
  type EpochInventoryShort,
  type EpochInventoryVerifyOptions,
  type SigningKey,
} from '@ashaveri/receipt';
import { labeled } from './seed.ts';

const DATA = join(dirname(fileURLToPath(import.meta.url)), '..', 'data');

/**
 * The epoch inventory vectors: sealed inventories and the verdict the shipped reader owes each one.
 *
 * An inventory is a deployment's statement about a closed run of packs. It lists the entries and folds three
 * summaries from them, a window, a chain claim and a duty claim, and it is the only artifact of an epoch a
 * reviewer can be handed on its own, so everything a reader can settle without the packs goes through these
 * bytes: the envelope, the header, the key, the reading of the JSON, the arithmetic over the run, and the names
 * each summary row points at.
 *
 * Two verdicts are published per row because the container has two entry points answering two questions, which
 * is the split `pack-v1.json` and `redaction-v1.json` make. `structural` is what `decodeEpochInventory` answers
 * with no key in hand, and `verdict` is what `verifyEpochInventory` answers under the designation the row
 * states. A run whose windows leave a gap is `verify-ok` structurally and a refusal under a key, because the gap
 * is an arithmetic over entries and not a shape fault; a document missing a member is refused by both. A port
 * that merged the two columns would report a whole document as a broken one.
 *
 * Nothing in the expectation columns was typed as a message. Each row's `verdict`, `structural` and refusal
 * `message` are what the shipped readers answered when this file was written, and the generator stops unless a
 * reader answers the direction its case states, so a fault that stopped being detected fails the build rather
 * than publishing a pass. The direction is stated because a suite that recorded only what came back could not
 * notice a guard going quiet: a row meant to be refused and answered with `verify-ok` is the defect a port most
 * needs told, and it is invisible to a generator that publishes whatever it observes.
 *
 * The documents come from two paths, and the split is the one the format's own test makes. Honest ones went
 * through `signEpochInventory`, so the shipping writer is witnessed producing what its reader accepts. Fault
 * ones were assembled from the four published pieces and re-sealed under the key their own header names,
 * because that writer parses and folds a manifest before it signs and refuses to make a fault it would refuse
 * to sign. `main` asks the piecewise path to reproduce `signEpochInventory` byte for byte on the honest
 * document, which is what makes every fault row below the one position its `edited` field names and nothing
 * else. Where a row states an `edit` block instead, it was built by replacing one span of the honest
 * document's own text, and the two label rows are the same document to within one byte at one position.
 *
 * The packs an inventory describes are none of this suite's business, and no row pretends that a reader of this
 * document can check a digest against a file: `verifyEpochInventory` states where the document's own arithmetic
 * ends, and `docs/epoch-inventory-v1.md` carries the list of what a reviewer has to go and check besides it.
 */

/** The three labels the signed header of this container declares, and no fourth. */
const LABEL_ALG = 1;
const LABEL_TYP = 3;
const LABEL_KID = 4;

const RUN_START = 1_700_000_000;
const WINDOW = 1_000;
const DAY = 86_400;
/** The assembly stamp of the first pack, which is where the text-level number cases edit. */
const FIRST_AT = RUN_START + WINDOW + 10;

/**
 * The keys this suite publishes. `CURRENT` seals every honest document here and the faults assembled beside
 * them; `ANOTHER` is a second deployment's key, for the row whose header names one kid while another hand made
 * the signature and for the row that pins a key the document is not under.
 */
const CURRENT: SigningKey = signingKeyFromSeed(labeled('ashaveri-epoch-inventory-v1/signer-a'));
const ANOTHER: SigningKey = signingKeyFromSeed(labeled('ashaveri-epoch-inventory-v1/signer-b'));

const KEY_MATERIAL: readonly { key: SigningKey; seed: string; role: string }[] = [
  {
    key: CURRENT,
    seed: "sha256 of 'ashaveri-epoch-inventory-v1/signer-a'",
    role: 'seals every inventory here whose header is honest, and the faults assembled from the published pieces beside that one',
  },
  {
    key: ANOTHER,
    seed: "sha256 of 'ashaveri-epoch-inventory-v1/signer-b'",
    role: "another deployment's key, for the document signed by a hand other than the one its header names and for the row that pins a key whose kid is not the document's",
  },
];

/** A digest of a label, so every case states figures of the right width without inventing hex by hand. */
function digest(label: string): string {
  return toHex(sha256(new TextEncoder().encode(label)));
}

/** One pack of a run, as an inventory states it. */
function packEntry(one: {
  index: number;
  from: number;
  to: number;
  anchor: string;
  required?: number;
  held?: number;
  art?: string;
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
 * of the windows, each pair whose digests do not meet, and each pack whose own two integers disagree. This is a
 * second reading of the writer's arithmetic rather than a call into the shipped module, so a fold that drifted
 * over there shows up here as a disagreement instead of agreeing with itself.
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

/** A whole document over one run: the entries, and the summaries folded from them. */
function inventory(packs: readonly EpochInventoryPack[]): EpochInventoryManifest {
  return {
    v: 1,
    epoch: 'quarter-one',
    manifest: { iss: 'dpl-inventory-vectors', ins: 'cvm-inventory-vectors', epk: 3 },
    packs,
    ...summariesOf(packs),
  };
}

/** A run of `count` windows that continues itself, each entry edited on the way in by `over`. */
function runOf(
  count: number,
  over: (index: number, pack: EpochInventoryPack) => EpochInventoryPack = (_, one) => one,
): EpochInventoryManifest {
  const packs: EpochInventoryPack[] = [];
  let anchor = digest('the seam a retirement left');
  for (let index = 0; index < count; index += 1) {
    const pack = packEntry({ index, from: RUN_START + index * WINDOW, to: RUN_START + (index + 1) * WINDOW, anchor });
    packs.push(over(index, pack));
    anchor = pack.chain.head;
  }
  return inventory(packs);
}

/** A run of three windows whose middle pack falls short of the period it states it owed. */
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

/** A run of three that breaks behind packs two and three, so its fold states two break rows. */
const BROKEN_TWICE: EpochInventoryManifest = runOf(3, (index, one) =>
  index === 0 ? one : { ...one, chain: { ...one.chain, anchor: digest(`a seam this run never held/${String(index)}`) } },
);

/** A run of three whose second and third packs each fall short of their own required period. */
const SHORT_TWICE: EpochInventoryManifest = runOf(3, (index, one) =>
  index === 0 ? one : { ...one, duty: { ...one.duty, required: 500, held: 100 } },
);

/** The honest run with its seven members written in another order than any writer of this format lists them. */
const MEMBERS_REORDERED: EpochInventoryManifest = {
  duty: HONEST.duty,
  chain: HONEST.chain,
  window: HONEST.window,
  packs: HONEST.packs,
  manifest: HONEST.manifest,
  epoch: HONEST.epoch,
  v: 1,
};

/** A pack manifest of the other container, whole by its own layout, for the cross-reading rows. */
const FOREIGN_PACK: Uint8Array = encodePackManifest({
  v: 1,
  at: RUN_START + 3 * WINDOW + 10,
  span: { from: RUN_START, to: RUN_START + 3 * WINDOW },
  chain: { anchor: new Uint8Array(32), head: new Uint8Array(32) },
  duty: { art: '19(1)', rev: RUN_START - DAY, required: 100, held: 200 },
  items: [],
});

/** A pack position of the honest run filed nowhere in it, for the rows naming a pack the run lacks. */
const FOREIGN = `${EPOCH_INVENTORY_PACKS_DIRECTORY}/${digest('a pack of another epoch')}/${EPOCH_INVENTORY_PACK_FILE}`;

const payloadOf = (manifest: EpochInventoryManifest): Uint8Array => encodeEpochInventoryManifest(manifest);

/** The honest document's payload text, which is where the text-level cases edit one span. */
function honestText(): string {
  return new TextDecoder().decode(payloadOf(HONEST));
}

/** The honest payload text with one span replaced, which has to be one span and not several. */
function textWith(from: string, to: string): Uint8Array {
  const text = honestText();
  const at = text.indexOf(from);
  if (at < 0) throw new Error(`the honest document carries no ${JSON.stringify(from)} for a case to replace`);
  if (text.indexOf(from, at + 1) >= 0) throw new Error(`${JSON.stringify(from)} is not one position of the honest document`);
  return new TextEncoder().encode(`${text.slice(0, at)}${to}${text.slice(at + from.length)}`);
}

/** Payload bytes sealed under a header the case built, signed by the key it names. */
function sealUnder(header: Uint8Array, payloadBytes: Uint8Array, signer: SigningKey): Uint8Array {
  return sealEpochInventory(header, payloadBytes, ed25519.sign(epochInventorySigStructure(header, payloadBytes), signer.privateKey));
}

/** Payload bytes under an inventory header of the caller's content type, signed by whoever the case names. */
function sealPayload(payloadBytes: Uint8Array, signer: SigningKey = CURRENT, contentType = EPOCH_INVENTORY_CONTENT_TYPE): Uint8Array {
  return sealUnder(encodeEpochInventoryProtectedHeader(signer.kid, contentType), payloadBytes, signer);
}

/** A document sealed through the four published pieces rather than through `signEpochInventory`. */
function sealDocument(manifest: EpochInventoryManifest, signer: SigningKey = CURRENT): Uint8Array {
  return sealPayload(payloadOf(manifest), signer);
}

/** The honest document as its writer writes it, which is the bytes every text case is edited from. */
const HONEST_BYTES = signEpochInventory(HONEST, CURRENT);
const HONEST_HEADER = encodeEpochInventoryProtectedHeader(CURRENT.kid);

/** The envelope's four elements, so a case can rebuild a document one of them at a time. */
function elementsOf(bytes: Uint8Array): unknown[] {
  const contents = (decodeCanonical(bytes) as { contents?: unknown }).contents;
  if (!Array.isArray(contents)) throw new Error('a document this file sealed is not a four-element envelope');
  return contents;
}

/** The honest protected header with one label moved, added or narrowed. */
function headerWith(alter: (map: Map<unknown, unknown>) => void): Uint8Array {
  const decoded = decodeCanonical(HONEST_HEADER);
  if (!(decoded instanceof Map)) throw new Error('the header this file sealed is not a map');
  alter(decoded);
  return encodeCanonical(decoded);
}

/** A document of nothing but `levels` of nesting, which is how the depth bound is asked at both sides. */
const nested = (levels: number): Uint8Array => new TextEncoder().encode(`${'['.repeat(levels)}${']'.repeat(levels)}`);

/** The designations a row hands its reader, which are the reader's two shapes and no third. */
interface Designation {
  /** The one key a caller pins, which answers whatever kid the header names. */
  pinned?: string;
  /** The set a resolver answers from, one public half per kid a header can name. */
  retained?: Record<string, string>;
}

const PINNED: Designation = { pinned: toBase64Url(CURRENT.publicKey) };
const RETAINED: Designation = { retained: { [toHex(CURRENT.kid)]: toBase64Url(CURRENT.publicKey) } };
const NONE: Designation = {};

/** What a designation builds for the reader: a pinned key, a kid-indexed resolver, or the call that named none. */
function optionsFor(read: Designation): EpochInventoryVerifyOptions {
  if (read.pinned !== undefined) return { publicKey: new Uint8Array(Buffer.from(read.pinned, 'base64url')) };
  if (read.retained !== undefined) {
    const held = read.retained;
    return {
      resolveKey: (kid: Uint8Array): Uint8Array | undefined => {
        const found = held[toHex(kid)];
        return found === undefined ? undefined : new Uint8Array(Buffer.from(found, 'base64url'));
      },
    };
  }
  return {};
}

interface Case {
  readonly name: string;
  readonly note: string;
  readonly bytes: Uint8Array;
  readonly read: Designation;
  /** The direction the case states for `verifyEpochInventory`, which `main` requires the reader to answer. */
  readonly verdict: string;
  /**
   * The direction the case states for `decodeEpochInventory`. Absent means the same answer as `verdict`, which
   * is the case for every fault the shape or the envelope carries: those bytes are refused with or without a
   * key. A row stating it is one the two entry points disagree on, which is where a refusal is about a key, a
   * signature or the arithmetic over a run rather than about the document.
   */
  readonly structural?: string;
  /** The one position a fault row moved, named in the document rather than as an offset. */
  readonly edited?: string;
  /** Which of the two folded lists a row guards, stated on every row that vectors one of the twin guards. */
  readonly site?: 'chain.breaks' | 'duty.short';
  /**
   * Which of the six guards of the named site a refusing row reaches. `main` requires the reader's own sentence
   * to be that guard's sentence, so a row whose guard has gone quiet and fallen through to the next throw dies
   * here even though both throws answer with the same code, which is what the code columns cannot see apart.
   */
  readonly guard?: 'claim' | 'count' | 'repeat' | 'unheld' | 'without-finding' | 'figures';
  /** The text edit a row was built by, beside the row whose text it edited. */
  readonly edit?: { of: string; from: string; to: string };
  /** The document taken apart into the pieces the format publishes, for a port that rebuilds the framing. */
  readonly reveal?: Record<string, unknown>;
}

/**
 * For each guard of each site, the pattern the reader's own sentence for that guard matches and no other
 * guard's sentence matches. `main` matches the captured refusal against it, so the direction a folded-list row
 * states is the exact branch of the exact twin it vectors, not merely the code two branches share.
 *
 * None of them carries a row position. The `[0]` of the reader's sentence is the place the moved row happens to
 * hold in the list, which is a fact of that document rather than of that guard, so a fragment naming one stops
 * matching the first time a case guards a later row and reports a live guard as a quiet one. Four of the six
 * guards of a site open their sentence with that site's own name, which is what lets a fragment hold its rows
 * apart from the twin guard of the other site: `figures` and `unheld` say the site's bracket with `\d+` standing
 * where the reader writes the position, and `repeat` says the bracket bare, because that sentence names the list
 * rather than a row of it. The two `unheld` patterns are the one pair here that is not one contiguous fragment:
 * the head and the tail sit either side of the pack name, so a `.*` spans it, which is also what keeps an
 * `unheld` pattern off the `without-finding` sentence that shares its head. `claim` and `count` need no site
 * name to separate them, because the word that says the site, `break(s)` or `shortfall(s)`, sits inside their
 * fragment already.
 *
 * Placement near the head is not what makes them match, though, and it is not guaranteed. The reader bounds a
 * quoted detail at two hundred characters, `MAX_DETAIL` at `packages/receipt/src/errors.ts:382`, and measured
 * against the published rows eight of the twelve site and guard pairs sit at the head of their detail and four
 * do not. At the head: `claim`, `repeat`, `unheld` and `figures`, each of the eight at offset 0. Off the head:
 * `count` at 27 at both sites, and `without-finding` at 121 at `chain.breaks` and 119 at `duty.short`, the two
 * numbers of a pair being its `chain.breaks` row and its `duty.short` row. What carries the four off the head is
 * that the detail each fragment sits in is shorter than the bound, at 51 to 173 characters, so the whole sentence
 * publishes and the fragment lies inside what survives. The two `unheld` patterns need the same of a longer span,
 * since their match runs to the end of a detail of 141 and 139 characters. The four `figures` rows are the ones
 * the bound does bite: their details publish cut at 203 characters, the bound plus the three dots the reader
 * appends, and their fragments still match because they sit at 0, ahead of where the cut falls. So a fragment
 * belongs near the head of the reader's sentence, and a case with anything variable between the head and its
 * fragment has to check the detail length rather than assume the fragment is there.
 */
const GUARD_SENTENCES: Record<'chain.breaks' | 'duty.short', Record<'claim' | 'count' | 'repeat' | 'unheld' | 'without-finding' | 'figures', RegExp>> = {
  'chain.breaks': {
    claim: /chain\.continuous says/u,
    count: /break\(s\) in it and the document states/u,
    repeat: /chain\.breaks states \d+ rows naming/u,
    unheld: /chain\.breaks\[\d+\] names .*which the run does not hold at all/u,
    'without-finding': /holds without a break/u,
    figures: /chain\.breaks\[\d+\] states/u,
  },
  'duty.short': {
    claim: /duty\.carried says/u,
    count: /shortfall\(s\) in it and the document states/u,
    repeat: /duty\.short states \d+ rows naming/u,
    unheld: /duty\.short\[\d+\] names .*which the run does not hold at all/u,
    'without-finding': /holds without a shortfall/u,
    figures: /duty\.short\[\d+\] states/u,
  },
};

const CASES: readonly Case[] = [
  {
    name: 'honest-run-of-three',
    note: 'Three closed windows that continue one another, the middle one short of the period it states it owed, and the three summaries folded from the entries rather than recollected. This is the document a deployment hands over, and it is the row every other row here is one edit away from: it went through `signEpochInventory`, and the `reveal` block beside it is that same document taken apart into the four pieces the format publishes, so a port can compare framings without this repository writer.',
    bytes: HONEST_BYTES,
    read: PINNED,
    verdict: 'verify-ok',
    reveal: {
      contextString: 'Signature1',
      externalAadBase64Url: toBase64Url(new Uint8Array(0)),
      protectedHeaderBase64Url: toBase64Url(HONEST_HEADER),
      payloadBase64Url: toBase64Url(payloadOf(HONEST)),
      payloadByteLength: payloadOf(HONEST).length,
      payloadSha256Hex: toHex(sha256(payloadOf(HONEST))),
      signatureHex: toHex(elementsOf(HONEST_BYTES)[3] as Uint8Array),
      sigStructureHex: toHex(epochInventorySigStructure(HONEST_HEADER, payloadOf(HONEST))),
      headerLabels: [
        { label: LABEL_ALG, name: 'alg', value: -8 },
        { label: LABEL_TYP, name: 'typ', value: EPOCH_INVENTORY_CONTENT_TYPE },
        { label: LABEL_KID, name: 'kid', value: toHex(CURRENT.kid) },
      ],
    },
  },
  {
    name: 'a-broken-run-folded-and-reported',
    note: 'The honest run with its second pack anchored somewhere the first pack is not, and the chain claim stating that break with the two digests of the pair. A break is a finding and not a fault: the document is accepted, and what the reader is owed is the pair it names. The same bytes with `continuous` set to true are the refusal in `a-break-smoothed-over`, so these two rows together are the whole of what this reader says about a run that does not chain itself.',
    bytes: sealDocument(BROKEN),
    read: PINNED,
    verdict: 'verify-ok',
  },
  {
    name: 'chain-breaks-listed-in-another-order',
    note: 'A run that breaks behind two of its packs, with the two break rows stated in the other order. This is an acceptance and not a fault: the reader keys each row by the pack its own `file` names, so the list states the same two pairs either way and order bears nothing. `two-rows-naming-one-pack-at-the-break-site` is that document with the second row pointed at the pack the first already names instead of added beside it, and that one is refused, which is what makes this row a reading of a live keying rule rather than the absence of a check.',
    bytes: sealDocument({ ...BROKEN_TWICE, chain: { ...BROKEN_TWICE.chain, breaks: [...BROKEN_TWICE.chain.breaks].reverse() } }),
    read: PINNED,
    verdict: 'verify-ok',
    site: 'chain.breaks',
  },
  {
    name: 'duty-short-listed-in-another-order',
    note: 'A run of which two packs fall short, with the two shortfall rows stated in the other order, which is accepted for the same reason and at the other summary site. The guards at `chain.breaks` and `duty.short` are twins rather than one routine, so this suite states both sites apart: a port that keyed only one list by name still fails the rows for the other.',
    bytes: sealDocument({ ...SHORT_TWICE, duty: { carried: false, short: [...SHORT_TWICE.duty.short].reverse() } }),
    read: PINNED,
    verdict: 'verify-ok',
    site: 'duty.short',
  },
  {
    name: 'entries-listed-backwards',
    note: 'The honest run with its entry array written last-first. Position in `packs` carries no claim, so this is the same epoch, the same window and the same two summaries as `honest-run-of-three`, and the reader is the place that says so: `readback.runFiles` is the order its own figures put the entries back into, and `readback.statedFiles` is the order the array arrived in.',
    bytes: sealDocument({ ...HONEST, packs: [...HONEST.packs].reverse() }),
    read: PINNED,
    verdict: 'verify-ok',
  },
  {
    name: 'members-listed-in-another-order',
    note: 'The honest document with its seven members written duty first and the version last, an order no writer of this format emits. Accepted, and readback identical to `honest-run-of-three`: the payload is rendered by `JSON.stringify`, so the emitted order is the order the calling object lists its members in, and the reader looks each one up by name rather than by position. `packages/receipt/epoch-inventory.cddl` states the field order as the order a writer lists them in, and this row publishes that as the rendering convention it is: an order of members is no claim a reader of this document answers against the layout.',
    bytes: sealDocument(MEMBERS_REORDERED),
    read: PINNED,
    verdict: 'verify-ok',
  },
  {
    name: 'run-of-one-pack',
    note: 'A closed window and nothing else beside it. The window is folded one entry at a time, so a run of one states that entry edges, and the two summaries come out of the fold seeds rather than from a special case: continuous, and the duty carried. An empty run never reaches the fold at all, which `a-run-of-no-entries` states.',
    bytes: sealDocument(runOf(1)),
    read: PINNED,
    verdict: 'verify-ok',
  },
  {
    name: 'copied-text-positions-wider-than-any-ceiling',
    note: 'An issuer and an instance id of three hundred and four characters each, and a duty label of seventy bytes: the three text positions copied out of a deployment manifest and a pack. This is an acceptance. Both of those sources declare text with a floor and no ceiling, so a wide figure is what today\'s writer emits, and a ceiling on this side would refuse an inventory for a value its own writer was handed by a format that allows it. What each of the three keeps is the floor those sources state, which is text that is not empty, and `issuer-id-stated-empty`, `instance-id-stated-empty` and `duty-label-stated-empty` are that floor.',
    bytes: (() => {
      const wide = runOf(2, (index, one) => ({
        ...one,
        duty: { ...one.duty, art: `19(${('1'.repeat(66))})`, required: index === 1 ? 500 : 100, held: index === 1 ? 100 : 200 },
      }));
      return sealDocument({ ...wide, manifest: { iss: `dpl-${'x'.repeat(300)}`, ins: `cvm-${'y'.repeat(300)}`, epk: wide.manifest.epk } });
    })(),
    read: PINNED,
    verdict: 'verify-ok',
  },
  {
    name: 'issuer-id-stated-empty',
    note: 'The honest run with its issuer id stated as empty text. The row above publishes that these copied positions carry no ceiling; this one and its two siblings publish the floor they do carry, which is text of at least one byte, refused where the deployment block is read rather than at the fold or the key.',
    bytes: sealDocument({ ...HONEST, manifest: { iss: '', ins: HONEST.manifest.ins, epk: HONEST.manifest.epk } }),
    read: PINNED,
    verdict: 'EPOCH_INVENTORY_BAD_DOCUMENT',
    edited: 'the manifest iss member, emptied',
  },
  {
    name: 'instance-id-stated-empty',
    note: 'The instance id of the same document emptied, the second of the three text floors. The answer is the one the reading gives for a figure of another type or width, because an empty id is a member the layout cannot hold rather than a deployment the reader does not know.',
    bytes: sealDocument({ ...HONEST, manifest: { iss: HONEST.manifest.iss, ins: '', epk: HONEST.manifest.epk } }),
    read: PINNED,
    verdict: 'EPOCH_INVENTORY_BAD_DOCUMENT',
    edited: 'the manifest ins member, emptied',
  },
  {
    name: 'duty-label-stated-empty',
    note: 'The first entry of the honest run carrying no duty label at all, the third of the three text floors and the one read inside an entry rather than beside the deployment. A label routes the figure beside it, so the emptiness is refused where the entry is read, before any summary is folded over it.',
    bytes: sealDocument({
      ...HONEST,
      packs: HONEST.packs.map((one, index) => (index === 0 ? { ...one, duty: { ...one.duty, art: '' } } : one)),
    }),
    read: PINNED,
    verdict: 'EPOCH_INVENTORY_BAD_DOCUMENT',
    edited: 'the first entry duty art member, emptied',
  },
  {
    name: 'run-label-at-the-printed-width',
    note: 'The operator label for the run at two hundred bytes, which is the ceiling the format states for that one position and nothing else moved: this row was built by replacing one span of the honest document text. It is an acceptance at the last byte the layout allows, and `run-label-one-byte-past-the-printed-width` is the same edit one character longer.',
    bytes: sealPayload(textWith('"epoch": "quarter-one"', `"epoch": "${'x'.repeat(EPOCH_INVENTORY_LABEL_MAX_BYTES)}"`)),
    read: PINNED,
    verdict: 'verify-ok',
    edited: 'the epoch member, at the width the format prints beside the run',
    edit: { of: 'honest-run-of-three', from: '"epoch": "quarter-one"', to: `"epoch": "${'x'.repeat(EPOCH_INVENTORY_LABEL_MAX_BYTES)}"` },
  },
  {
    name: 'run-label-one-byte-past-the-printed-width',
    note: 'The row above with one character added to the label, which is the only position differing between the two documents. This is the one text position in the layout carrying a ceiling, because it is printed beside the run in every report of it, and it refuses at two hundred and one bytes.',
    bytes: sealPayload(textWith('"epoch": "quarter-one"', `"epoch": "${'x'.repeat(EPOCH_INVENTORY_LABEL_MAX_BYTES + 1)}"`)),
    read: PINNED,
    verdict: 'EPOCH_INVENTORY_BAD_DOCUMENT',
    edited: 'the epoch member, one byte past the width the format prints',
    edit: { of: 'honest-run-of-three', from: '"epoch": "quarter-one"', to: `"epoch": "${'x'.repeat(EPOCH_INVENTORY_LABEL_MAX_BYTES + 1)}"` },
  },
  {
    name: 'two-duty-labels-carried-apart',
    note: 'A run whose second pack answers a different duty period from the first, a hundred seconds against one day. Accepted, and read under a resolver rather than a pinned key: a shortfall is measured only against the figure beside the same label, so the first window is not weighed against the five-day figure and the second not against the hundred seconds its neighbour states, which is why one row and not two comes back in the duty summary.',
    bytes: sealDocument(
      runOf(2, (index, one) => (index === 1 ? { ...one, duty: { art: '26(6)', rev: one.duty.rev, required: 5 * DAY, held: DAY } } : one)),
    ),
    read: RETAINED,
    verdict: 'verify-ok',
  },

  {
    name: 'document-cut-short-mid-envelope',
    note: 'The honest document with everything past its twentieth byte taken off, which is what a transfer that never finished leaves. The bytes are not a document at all, so the answer is the CBOR reading refusing rather than a field going missing.',
    bytes: HONEST_BYTES.slice(0, 20),
    read: PINNED,
    verdict: 'EPOCH_INVENTORY_MALFORMED_CBOR',
    edited: 'every byte from the twentieth on',
  },
  {
    name: 'signature-one-byte-narrow',
    note: 'The honest envelope with one byte taken off its signature, so the four elements are there and one of them is the wrong width. The envelope is answered before anything inside it is read, which is why this is not a signature failure: the bytes never reach a verification.',
    bytes: sealEpochInventory(
      elementsOf(HONEST_BYTES)[0] as Uint8Array,
      elementsOf(HONEST_BYTES)[2] as Uint8Array,
      (elementsOf(HONEST_BYTES)[3] as Uint8Array).slice(0, 63),
    ),
    read: PINNED,
    verdict: 'NOT_COSE_SIGN1',
    edited: 'the signature, at sixty-three bytes',
  },
  {
    name: 'header-carrying-a-label-this-format-does-not-define',
    note: 'The honest header with a fourth parameter of its own, beside the three the container declares. The header bytes are hashed into the signature, so a reader that skipped a label it has no rule for would verify a document whose header it had not read, and the extra label is answered before the key is consulted.',
    bytes: sealUnder(headerWith((map) => map.set(5, 'what')), payloadOf(HONEST), CURRENT),
    read: PINNED,
    verdict: 'EPOCH_INVENTORY_BAD_HEADER',
    edited: 'one added header label',
  },
  {
    name: 'header-kid-one-byte-narrow',
    note: 'The honest header with its `kid` shortened by one byte, which is a shape fault in the header and not an identity a reader lacks: nothing about a thirty-one byte id can hash out to a public key, so this is refused where the parameters are read rather than at the key set.',
    bytes: sealUnder(
      headerWith((map) => map.set(LABEL_KID, CURRENT.kid.slice(0, 31))),
      payloadOf(HONEST),
      CURRENT,
    ),
    read: PINNED,
    verdict: 'EPOCH_INVENTORY_BAD_HEADER',
    edited: 'the kid, at thirty-one bytes',
  },
  {
    name: 'header-declaring-an-algorithm-nobody-holds',
    note: 'The honest header with its `alg` moved to ES256. The label is one this format defines and the value is not one it can verify, so the answer names the suite rather than the header, which is what tells an operator to look at their key material instead of at their framing.',
    bytes: sealUnder(headerWith((map) => map.set(LABEL_ALG, -7)), payloadOf(HONEST), CURRENT),
    read: PINNED,
    verdict: 'UNSUPPORTED_ALG',
    edited: 'the alg, at -7',
  },
  {
    name: 'sealed-under-another-containers-content-type',
    note: 'The honest inventory document under a header declaring the evidence pack type. This reader is asked and refuses at the label before any key is consulted, which is the half of the answer: a document that is not an inventory must not reach a caller key set.',
    bytes: sealPayload(payloadOf(HONEST), CURRENT, PACK_CONTENT_TYPE),
    read: PINNED,
    verdict: 'EPOCH_INVENTORY_BAD_HEADER',
    edited: 'the content type',
  },
  {
    name: 'a-pack-document-wearing-the-inventory-label',
    note: 'A whole and separate pack manifest, its own bytes and none of them edited, under this container type. The header admits it and the JSON reading refuses it, which is the confusion the content type is not the whole answer to: these bytes pass the pack checks and fail the inventory ones, so only label three settles which claim a reviewer is holding.',
    bytes: sealPayload(FOREIGN_PACK),
    read: PINNED,
    verdict: 'EPOCH_INVENTORY_MALFORMED_JSON',
    edited: 'the whole payload',
  },
  {
    name: 'payload-that-is-not-a-json-document',
    note: 'Four bytes of the honest payload text replaced by the word `not`. The payload of this container is JSON rather than CBOR, and the reading is where that is settled, before any member is asked about.',
    bytes: sealPayload(new TextEncoder().encode('not json at all')),
    read: PINNED,
    verdict: 'EPOCH_INVENTORY_MALFORMED_JSON',
    edited: 'the whole payload',
  },
  {
    name: 'member-name-stated-twice',
    note: 'The honest document with the `packs` member written a second time, empty, ahead of the real one. A parser that keeps the last wins an honest document and one that keeps the first wins an empty run, and the two readings differ in nothing a reviewer can see, so this reader refuses the text instead of settling it.',
    bytes: sealPayload(textWith('"packs": [', '"packs": [],\n  "packs": [')),
    read: PINNED,
    verdict: 'EPOCH_INVENTORY_MALFORMED_JSON',
    edited: 'one duplicated member name',
  },
  {
    name: 'figure-spelled-as-a-float',
    note: 'The honest document with one assembly stamp written with a `.0` on the end. The number is the same number and the figure is refused: a CBOR reader hands an integer and its float imitation over as one value, so by the time a field could ask which one was signed the question has no answer left in the data.',
    bytes: sealPayload(textWith(`"at": ${String(FIRST_AT)}`, `"at": ${String(FIRST_AT)}.0`)),
    read: PINNED,
    verdict: 'EPOCH_INVENTORY_MALFORMED_JSON',
    edited: 'the first pack at member, spelled as a float',
  },
  {
    name: 'figure-past-exact-integer-range',
    note: 'The honest document with one assembly stamp replaced by two past the largest integer a reader holds exactly. The scanner refuses the token rather than reading it rounded, so no field check is ever asked to notice that the figure arrived changed.',
    bytes: sealPayload(textWith(`"at": ${String(FIRST_AT)}`, `"at": ${String(Number.MAX_SAFE_INTEGER + 2)}`)),
    read: PINNED,
    verdict: 'EPOCH_INVENTORY_MALFORMED_JSON',
    edited: 'the first pack at member, past exact range',
  },
  {
    name: 'nested-past-the-depth-the-layout-states',
    note: 'A payload of nine levels of brackets. A payload is bytes nobody believes, and a scanner that recursed with the file rather than with the layout would answer this with a crash standing where the container promises a code, so the reading stops at the bound the format states.',
    bytes: sealPayload(nested(9)),
    read: PINNED,
    verdict: 'EPOCH_INVENTORY_MALFORMED_JSON',
    edited: 'the whole payload',
  },
  {
    name: 'nested-to-the-depth-the-layout-states',
    note: 'The same payload at eight levels, which is the bound itself and not past it. This is the row that makes the refusal above about depth: eight levels gets through the reading and is answered by the layout, which has no document at all in front of it, so the two rows differ in one bracket and in which rule of the format answers.',
    bytes: sealPayload(nested(8)),
    read: PINNED,
    verdict: 'EPOCH_INVENTORY_BAD_DOCUMENT',
    edited: 'the whole payload',
  },
  {
    name: 'document-declaring-a-version-no-reader-holds',
    note: 'A payload stating version two, which no format here has used. The version is read before any other member and refused before the rest of the document is walked, because reading these bytes under the rules of a version nobody wrote would be inventing a layout.',
    bytes: sealPayload(new TextEncoder().encode('{"v": 2}')),
    read: PINNED,
    verdict: 'EPOCH_INVENTORY_UNSUPPORTED_VERSION',
    edited: 'the whole payload',
  },
  {
    name: 'a-member-this-version-does-not-define',
    note: 'The honest document with one member added beside the seven it declares. Every block of this layout is closed, so an undefined name is a document this version does not describe rather than one carrying a hint a reader may or may not use.',
    bytes: sealPayload(textWith('"v": 1,', '"v": 1,\n  "met": true,')),
    read: PINNED,
    verdict: 'EPOCH_INVENTORY_BAD_DOCUMENT',
    edited: 'one added member beside the document\'s own seven',
  },
  {
    name: 'a-run-of-no-entries',
    note: 'The honest document with its entry array empty, which is a document stating a window, a chain and a duty over nothing. The array is declared as at least one entry, so this is refused where the entries are read rather than at the fold the empty run never reaches.',
    bytes: sealDocument({ ...HONEST, packs: [] }),
    read: PINNED,
    verdict: 'EPOCH_INVENTORY_BAD_DOCUMENT',
    edited: 'the packs array, emptied',
  },
  {
    name: 'entry-path-of-another-shape',
    note: 'The first entry filed at a path that is not this layout filing rule at all. The same position carrying another entries digest is a misnaming, which is a path to go and look at; a path of another shape is a writer that did not write this layout, and the two answers are refused apart on purpose.',
    bytes: sealDocument({
      ...HONEST,
      packs: HONEST.packs.map((one, index) => (index === 0 ? { ...one, file: 'somewhere/else.cbor' } : one)),
    }),
    read: PINNED,
    verdict: 'EPOCH_INVENTORY_BAD_DOCUMENT',
    edited: 'the first entry file member',
  },
  {
    name: 'entry-digest-not-the-one-it-is-filed-under',
    note: 'The second entry\'s own `sha256` moved by one hex character, with its path left where it was, so the directory names a pack this document no longer states. This is a wrong digest over one epoch of the run, and it is refused by name: the layout files an entry under its own digest, and a reader pointed at a directory that does not match the pack beside it is handed a position to go and check.',
    bytes: sealDocument(
      inventory(
        HONEST.packs.map((one, index) =>
          index === 1 ? { ...one, sha256: `${one.sha256.slice(0, 30)}${one.sha256[30] === '0' ? '1' : '0'}${one.sha256.slice(31)}` } : one,
        ),
      ),
    ),
    read: PINNED,
    verdict: 'EPOCH_INVENTORY_PACK_MISNAMED',
    edited: 'the second entry sha256 member',
  },
  {
    name: 'a-pack-named-twice',
    note: 'The honest run with its first entry written again at the end of the array: one pack counted as two, and every figure the fold reaches over it doubled with it. The two entries answer to the same pack, so the refusal is about the name and not about a summary that fails to match.',
    bytes: sealDocument({ ...HONEST, packs: [...HONEST.packs, HONEST.packs[0] ?? HONEST.packs[1]!] }),
    read: PINNED,
    verdict: 'EPOCH_INVENTORY_DUPLICATE_PACK',
    edited: 'one repeated entry',
  },
  {
    name: 'a-window-left-out-of-the-run',
    note: 'The third entry moved five seconds late, so the run has a gap inside it. Whole by its own shape and refused by its arithmetic: this is the row the two columns exist for, because the structural reading is satisfied by these bytes and only a reader with the run in front of it says the period is missing.',
    bytes: sealDocument(
      withThirdSpanMoved(HONEST, 5),
    ),
    read: PINNED,
    verdict: 'EPOCH_INVENTORY_RUN_NOT_CONTIGUOUS',
    structural: 'verify-ok',
    edited: 'the third entry span, five seconds late',
  },
  {
    name: 'a-window-sealed-twice',
    note: 'The third entry moved five seconds early, so two entries seal over the same period. The other side of the same rule, and refused for the same reason: the run is a sequence of windows that meet, and neither a hole nor an overlap is that.',
    bytes: sealDocument(withThirdSpanMoved(HONEST, -5)),
    read: PINNED,
    verdict: 'EPOCH_INVENTORY_RUN_NOT_CONTIGUOUS',
    structural: 'verify-ok',
    edited: 'the third entry span, five seconds early',
  },
  {
    name: 'an-entry-whose-own-window-does-not-run-forwards',
    note: 'The honest run with its second entry stating a window that opens at the instant it closes, so the entry covers no period of its own. `a-window-left-out-of-the-run` and `a-window-sealed-twice` compare one entry with its neighbour, and this row is the third finding the reader answers with the same code, refused against a single entry rather than between two: an entry whose own window does not run forwards. The walk reads an entry\'s own two figures before it compares either neighbour, so it stops at the second entry, and nothing else of the document moved: the stated window, the two chain endpoints and both folded lists still fold out of these same entries.',
    bytes: sealDocument({
      ...HONEST,
      packs: HONEST.packs.map((one, index) =>
        index === 1 ? { ...one, span: { from: one.span.to, to: one.span.to } } : one,
      ),
    }),
    read: PINNED,
    verdict: 'EPOCH_INVENTORY_RUN_NOT_CONTIGUOUS',
    structural: 'verify-ok',
    edited: 'the second entry span start, set to its own end',
  },
  {
    name: 'a-window-wider-than-the-run',
    note: 'The honest entries with the stated window one second wider at the front than the entries add up to. A count that disagrees with the run at the window site, and the disagreement is refused rather than corrected, because a document stating edges its own packs do not reach cannot be trusted for the summaries it states beside them.',
    bytes: sealDocument({ ...HONEST, window: { from: HONEST.window.from - 1, to: HONEST.window.to } }),
    read: PINNED,
    verdict: 'EPOCH_INVENTORY_SUMMARY_DISAGREES',
    structural: 'verify-ok',
    edited: 'the stated window start',
  },
  {
    name: 'a-break-smoothed-over',
    note: 'The broken run with its chain claim stating continuity while the break row the fold reports stays in the list beside it. The entries are untouched, so the only difference between this row and the accepted one above it is a claim that has been made to agree with what the deployment would rather have reported. `a-duty-stated-as-carried-when-it-is-not` is that same fault at the duty site.',
    bytes: sealDocument({ ...BROKEN, chain: { ...BROKEN.chain, continuous: true } }),
    read: PINNED,
    verdict: 'EPOCH_INVENTORY_SUMMARY_DISAGREES',
    structural: 'verify-ok',
    edited: 'the chain claim of continuity',
    site: 'chain.breaks',
    guard: 'claim',
  },
  {
    name: 'a-stated-run-beginning-that-is-not-where-the-run-begins',
    note: 'The honest run with its claimed chain anchor moved to a digest of nothing, while the entries and the break list stay as they were. The reader compares the stated anchor with the anchor of the pack its walk begins at, and refuses where the walk starts rather than in the folded summaries beside it, so this is the beginning of the two chain endpoints the format names and `a-stated-run-end-that-is-not-where-the-run-ends` is the other end of them. A wrong digest over one end of the epoch is refused because the reader recomputes both ends instead of quoting them.',
    bytes: sealDocument({ ...HONEST, chain: { ...HONEST.chain, anchor: digest('an anchor this run never began at') } }),
    read: PINNED,
    verdict: 'EPOCH_INVENTORY_SUMMARY_DISAGREES',
    structural: 'verify-ok',
    edited: 'the stated chain anchor',
  },
  {
    name: 'a-stated-run-end-that-is-not-where-the-run-ends',
    note: 'The honest run with its claimed chain head moved to a digest of nothing, while the entries and the break list stay as they were. The reader compares the stated head with the head of the pack its walk ends at, and refuses where the walk ends rather than in the folded summaries beside it, so this row is the other end of the two chain endpoints the format names and `a-stated-run-beginning-that-is-not-where-the-run-begins` is the one it does not state. A wrong digest over one end of the epoch is refused because the reader recomputes both ends instead of quoting them.',
    bytes: sealDocument({ ...HONEST, chain: { ...HONEST.chain, head: digest('a head this run never reached') } }),
    read: PINNED,
    verdict: 'EPOCH_INVENTORY_SUMMARY_DISAGREES',
    structural: 'verify-ok',
    edited: 'the stated chain head',
  },
  {
    name: 'a-break-row-naming-a-pack-the-run-does-not-hold',
    note: 'The broken run with its one break row pointed at a pack outside the array. The list is as long as the fold needs and every figure in the row is right, and it is refused because it names a position the reader was given nothing for. This is the break site; `a-shortfall-row-naming-a-pack-the-run-does-not-hold` is the same fault at the duty site, and the two are vectored apart because the guards are twins rather than one routine.',
    bytes: sealDocument({ ...BROKEN, chain: { ...BROKEN.chain, breaks: [{ ...BROKEN.chain.breaks[0]!, file: FOREIGN }] } }),
    read: PINNED,
    verdict: 'EPOCH_INVENTORY_PACK_UNNAMED',
    structural: 'verify-ok',
    edited: 'the file member of the one break row',
    site: 'chain.breaks',
    guard: 'unheld',
  },
  {
    name: 'a-shortfall-row-naming-a-pack-the-run-does-not-hold',
    note: 'The honest run with its one shortfall row pointed at a pack outside the array, which is the duty site twin of the break row above. A reader that keyed only one of the two lists by name passes one of these two rows.',
    bytes: sealDocument({ ...HONEST, duty: { ...HONEST.duty, short: [{ ...HONEST.duty.short[0]!, file: FOREIGN }] } }),
    read: PINNED,
    verdict: 'EPOCH_INVENTORY_PACK_UNNAMED',
    structural: 'verify-ok',
    edited: 'the file member of the one shortfall row',
    site: 'duty.short',
    guard: 'unheld',
  },
  {
    name: 'two-rows-naming-one-pack-at-the-break-site',
    note: 'A run that breaks twice, with both break rows naming the first of the two packs. The count is right and one break is examined twice while the other is never examined, which is the masking this guard exists to refuse: a reviewer told one break about a run with two. The reader message says both halves, that the list names one distinct pack and that another of the run is named nowhere in it.',
    bytes: sealDocument({
      ...BROKEN_TWICE,
      chain: { ...BROKEN_TWICE.chain, continuous: false, breaks: [BROKEN_TWICE.chain.breaks[0]!, BROKEN_TWICE.chain.breaks[0]!] },
    }),
    read: PINNED,
    verdict: 'EPOCH_INVENTORY_SUMMARY_DISAGREES',
    structural: 'verify-ok',
    edited: 'the second break row, pointed at the pack the first names',
    site: 'chain.breaks',
    guard: 'repeat',
  },
  {
    name: 'two-rows-naming-one-pack-at-the-shortfall-site',
    note: 'The same masking at the duty site: a run of which two packs fall short, stated as two rows naming one of them. The shortfall count comes out right and one pack is weighed twice, and the refusal is the twin of the break row above rather than the same code reached by the same code.',
    bytes: sealDocument({
      ...SHORT_TWICE,
      duty: { carried: false, short: [SHORT_TWICE.duty.short[0]!, SHORT_TWICE.duty.short[0]!] },
    }),
    read: PINNED,
    verdict: 'EPOCH_INVENTORY_SUMMARY_DISAGREES',
    structural: 'verify-ok',
    edited: 'the second shortfall row, pointed at the pack the first names',
    site: 'duty.short',
    guard: 'repeat',
  },
  {
    name: 'a-break-row-more-than-the-run-has',
    note: 'The broken run, which breaks once, stating two break rows with two distinct names in them. The names are all of packs the run holds, so nothing here is a lookup miss: the list is longer than the arithmetic, and both sides of the count are refused because the lists are compared as sets and as sizes.',
    bytes: sealDocument({
      ...BROKEN,
      chain: {
        ...BROKEN.chain,
        continuous: false,
        breaks: [
          BROKEN.chain.breaks[0]!,
          { file: BROKEN.packs[2]?.file ?? '', afterHead: BROKEN.packs[1]?.chain.head ?? '', anchor: BROKEN.packs[2]?.chain.anchor ?? '' },
        ],
      },
    }),
    read: PINNED,
    verdict: 'EPOCH_INVENTORY_SUMMARY_DISAGREES',
    structural: 'verify-ok',
    edited: 'one added break row beside the one the run has',
    site: 'chain.breaks',
    guard: 'count',
  },
  {
    name: 'a-shortfall-row-more-than-the-run-has',
    note: 'The honest run, which falls short once, stating two shortfall rows with two distinct names in them, at the duty site.',
    bytes: sealDocument({
      ...HONEST,
      duty: {
        carried: false,
        short: [...HONEST.duty.short, { file: HONEST.packs[2]?.file ?? '', art: '19(1)', required: 100, held: 200, shortBy: 100 }],
      },
    }),
    read: PINNED,
    verdict: 'EPOCH_INVENTORY_SUMMARY_DISAGREES',
    structural: 'verify-ok',
    edited: 'one added shortfall row beside the one the run has',
    site: 'duty.short',
    guard: 'count',
  },
  {
    name: 'a-break-row-fewer-than-the-run-has',
    note: 'A run that breaks twice stating one break row, and the one it states is correct as far as it goes. The other side of the same comparison, which is the side a document reaches by leaving something out, and the side a reviewer most needs refused: a list that reads as a smaller problem than the run is.',
    bytes: sealDocument({ ...BROKEN_TWICE, chain: { ...BROKEN_TWICE.chain, continuous: false, breaks: [BROKEN_TWICE.chain.breaks[0]!] } }),
    read: PINNED,
    verdict: 'EPOCH_INVENTORY_SUMMARY_DISAGREES',
    structural: 'verify-ok',
    edited: 'the second break row, left out',
    site: 'chain.breaks',
    guard: 'count',
  },
  {
    name: 'a-shortfall-row-fewer-than-the-run-has',
    note: 'A run of which two packs fall short, stating one shortfall row, at the duty site.',
    bytes: sealDocument({ ...SHORT_TWICE, duty: { carried: false, short: [SHORT_TWICE.duty.short[0]!] } }),
    read: PINNED,
    verdict: 'EPOCH_INVENTORY_SUMMARY_DISAGREES',
    structural: 'verify-ok',
    edited: 'the second shortfall row, left out',
    site: 'duty.short',
    guard: 'count',
  },
  {
    name: 'a-break-row-naming-a-held-pack-with-no-break-in-it',
    note: 'A run that breaks twice, stating two rows of which one is the run\'s own pair and the other names the pack the run begins at, quoted with that pack\'s own anchor and the head before it. The counts agree and every name is a pack the reader holds, so this is reached only past the counting, and it is refused because the named pack begins the run and has no break in it.',
    bytes: sealDocument({
      ...BROKEN_TWICE,
      chain: {
        ...BROKEN_TWICE.chain,
        continuous: false,
        breaks: [
          BROKEN_TWICE.chain.breaks[0]!,
          { file: BROKEN_TWICE.packs[0]?.file ?? '', afterHead: BROKEN_TWICE.packs[2]?.chain.head ?? '', anchor: BROKEN_TWICE.packs[0]?.chain.anchor ?? '' },
        ],
      },
    }),
    read: PINNED,
    verdict: 'EPOCH_INVENTORY_PACK_UNNAMED',
    structural: 'verify-ok',
    edited: 'the second break row, pointed at the pack the run begins at',
    site: 'chain.breaks',
    guard: 'without-finding',
  },
  {
    name: 'a-break-row-stating-a-head-the-pair-does-not',
    note: 'The broken run with its one break row keeping the right pack and the right anchor and having `afterHead` replaced by a digest of nothing. The name is held and the counts agree, so this is the last guard of the site: each row is answered against the two digests of the pair its own `file` fixes, and a port that never compares a folded row to that pair passes every other row in this suite.',
    bytes: sealDocument({
      ...BROKEN,
      chain: { ...BROKEN.chain, continuous: false, breaks: [{ ...BROKEN.chain.breaks[0]!, afterHead: digest('a head no pack of this run left') }] },
    }),
    read: PINNED,
    verdict: 'EPOCH_INVENTORY_SUMMARY_DISAGREES',
    structural: 'verify-ok',
    edited: 'the afterHead member of the one break row',
    site: 'chain.breaks',
    guard: 'figures',
  },
  {
    name: 'a-break-row-stating-an-anchor-the-pack-does-not',
    note: 'The same break row with the other of its two digests moved instead: the anchor the pack does not carry. Comparing either position is enough to refuse this row, and the pair of rows states them apart so a port that reads one digest of the pair and skips the other fails at least one of them.',
    bytes: sealDocument({
      ...BROKEN,
      chain: { ...BROKEN.chain, continuous: false, breaks: [{ ...BROKEN.chain.breaks[0]!, anchor: digest('an anchor this pack never carried') }] },
    }),
    read: PINNED,
    verdict: 'EPOCH_INVENTORY_SUMMARY_DISAGREES',
    structural: 'verify-ok',
    edited: 'the anchor member of the one break row',
    site: 'chain.breaks',
    guard: 'figures',
  },
  {
    name: 'a-shortfall-row-naming-a-held-pack-with-no-shortfall-in-it',
    note: 'The same shape at the duty site: two rows, the run falling short twice, and the second naming a pack the run holds that holds more than it states it owed. The reader detail says so in those words rather than reporting a name it could not find, which is what tells the two halves of this code apart for an operator.',
    bytes: sealDocument({
      ...SHORT_TWICE,
      duty: {
        carried: false,
        short: [SHORT_TWICE.duty.short[0]!, { file: SHORT_TWICE.packs[0]?.file ?? '', art: '19(1)', required: 100, held: 200, shortBy: 100 }],
      },
    }),
    read: PINNED,
    verdict: 'EPOCH_INVENTORY_PACK_UNNAMED',
    structural: 'verify-ok',
    edited: 'the second shortfall row, pointed at the pack that met its own duty',
    site: 'duty.short',
    guard: 'without-finding',
  },
  {
    name: 'a-shortfall-row-stating-a-duty-label-the-pack-does-not',
    note: 'The honest run with its one shortfall row keeping the right pack and all three of its figures and having the `art` replaced by another article period. The label travels with the figures in the fold, so the row is refused for stating a duty that is not the one beside the pack its `file` names, even though every integer agrees.',
    bytes: sealDocument({
      ...HONEST,
      duty: { carried: false, short: [{ ...HONEST.duty.short[0]!, art: '26(6)' }] },
    }),
    read: PINNED,
    verdict: 'EPOCH_INVENTORY_SUMMARY_DISAGREES',
    structural: 'verify-ok',
    edited: 'the art member of the one shortfall row',
    site: 'duty.short',
    guard: 'figures',
  },
  {
    name: 'a-shortfall-row-stating-a-shortfall-that-is-not-the-subtraction',
    note: 'The honest run with its one shortfall row stating the right pack, the right label, the right two figures, and a `shortBy` one larger than required less held. The subtraction is recomputed rather than believed, which is the whole of what this position states: a row that agrees on every figure and lies about the arithmetic between two of them is refused.',
    bytes: sealDocument({
      ...HONEST,
      duty: { carried: false, short: [{ ...HONEST.duty.short[0]!, shortBy: 401 }] },
    }),
    read: PINNED,
    verdict: 'EPOCH_INVENTORY_SUMMARY_DISAGREES',
    structural: 'verify-ok',
    edited: 'the shortBy member of the one shortfall row, one off the subtraction',
    site: 'duty.short',
    guard: 'figures',
  },
  {
    name: 'a-duty-stated-as-carried-when-it-is-not',
    note: 'The honest run with its duty summary carrying the shortfall row the fold reports while the flag beside it states that the run carried what it was owed. The flag guard is what refuses here, not the counting: the list is the length the run asks for and every name in it is held, and the only fault is a claim of carrying contradicted by the row stated beside it, which is the duty site twin of `a-break-smoothed-over`.',
    bytes: sealDocument({ ...HONEST, duty: { carried: true, short: [HONEST.duty.short[0]!] } }),
    read: PINNED,
    verdict: 'EPOCH_INVENTORY_SUMMARY_DISAGREES',
    structural: 'verify-ok',
    edited: 'the duty flag, set to carried beside the one shortfall the run has',
    site: 'duty.short',
    guard: 'claim',
  },
  {
    name: 'an-identity-that-pins-nothing',
    note: 'The honest document read by a call that named no key at all. The document is whole and this is not about it, so the refusal comes before a byte is read and names the gap in the call rather than a fault in the artifact: an operator sent to their configuration by this row and to their inventory by the one above it.',
    bytes: HONEST_BYTES,
    read: NONE,
    verdict: 'EPOCH_INVENTORY_UNKNOWN_KEY',
    structural: 'verify-ok',
  },
  {
    name: 'a-resolver-holding-nothing-for-the-kid-named',
    note: 'The same document and the same call shape as the row above, reached through the resolver instead of the pinned key: a caller that handed a key set and got no answer for this kid. Refused by name, which is what keeps it apart from a caller that designated one key and named the wrong one.',
    bytes: HONEST_BYTES,
    read: { retained: {} },
    verdict: 'EPOCH_INVENTORY_UNKNOWN_KEY',
    structural: 'verify-ok',
  },
  {
    name: 'a-pinned-key-of-another-identity',
    note: 'The honest document read under a pinned key that is a whole and live key of this suite, whose kid is not the one the header names. The disagreement is answered rather than resolved by trying the other key, because a reader that fell back would attribute a document to a deployment that never signed it.',
    bytes: HONEST_BYTES,
    read: { pinned: toBase64Url(ANOTHER.publicKey) },
    verdict: 'EPOCH_INVENTORY_KID_MISMATCH',
    structural: 'verify-ok',
  },
  {
    name: 'signed-by-another-hand-than-its-header-names',
    note: 'The honest document and the honest header, with the signature made by another key private half. The kid matches the designated key, so this gets past the identity checks and is answered by the arithmetic over the bytes, which is the only order that keeps a key hash standing in for a signature.',
    bytes: sealUnder(HONEST_HEADER, payloadOf(HONEST), ANOTHER),
    read: PINNED,
    verdict: 'INVALID_SIGNATURE',
    structural: 'verify-ok',
    edited: 'the signature, and nothing of the document',
  },
];

/** The honest run with its third entry window moved by `by` seconds, which is how the two contiguity rows are made. */
function withThirdSpanMoved(manifest: EpochInventoryManifest, by: number): EpochInventoryManifest {
  return inventory(
    manifest.packs.map((one, index) =>
      index === 2 ? { ...one, span: { from: one.span.from + by, to: one.span.to + by } } : one,
    ),
  );
}

/** What the shipped readers answered for one case, taken rather than stated. */
function observed(one: Case): { verdict: string; structural: string; message: string } {
  const structure = codeOf(() => decodeEpochInventory(one.bytes));
  const verdict = codeOf(() => verifyEpochInventory(one.bytes, optionsFor(one.read)));
  return { verdict: verdict.code, structural: structure.code, message: verdict.message };
}

/** The code a reader answers with, or `verify-ok` when it answered by handing the document back. */
function codeOf(run: () => unknown): { code: string; message: string } {
  try {
    run();
    return { code: 'verify-ok', message: '' };
  } catch (err) {
    if (err instanceof ReceiptError) return { code: err.code, message: err.message };
    throw new Error(`a reader answered with something no registry declares: ${String(err)}`);
  }
}

/**
 * What the reader reported back for a row it accepted: the run in the order its own figures put it, the array as
 * the document wrote it, and the three summaries as the document states them.
 */
function readbackOf(one: Case): Record<string, unknown> {
  const read = verifyEpochInventory(one.bytes, optionsFor(one.read));
  return {
    runFiles: read.outcome.packs.map((each) => each.file),
    statedFiles: read.manifest.packs.map((each) => each.file),
    window: read.manifest.window,
    continuous: read.manifest.chain.continuous,
    breakFiles: read.manifest.chain.breaks.map((each) => each.file),
    carried: read.manifest.duty.carried,
    shortFiles: read.manifest.duty.short.map((each) => each.file),
  };
}

/**
 * The columns every row carries because they say which row and which document it is, rather than answering
 * anything about it. `published` writes them first, the published `rowNamingFields` is this list, and the suite
 * holds both lists beside it against the columns its rows actually carry, so a column added to a row without
 * being named here is refused by that test rather than read as a roster defect.
 */
const NAMING_FIELDS = ['name', 'note', 'documentBase64Url', 'documentByteLength', 'read'];

function published(one: Case, seen: { verdict: string; structural: string; message: string }): Record<string, unknown> {
  return {
    name: one.name,
    note: one.note,
    documentBase64Url: toBase64Url(one.bytes),
    documentByteLength: one.bytes.length,
    read: one.read,
    verdict: seen.verdict,
    structural: seen.structural,
    ...(seen.message === '' ? {} : { message: seen.message }),
    ...(one.edited === undefined ? {} : { edited: one.edited }),
    ...(one.site === undefined ? {} : { site: one.site }),
    ...(one.guard === undefined ? {} : { guard: one.guard }),
    ...(one.edit === undefined ? {} : { edit: one.edit }),
    ...(one.reveal === undefined ? {} : { reveal: one.reveal }),
    ...(seen.verdict === 'verify-ok' ? { readback: readbackOf(one) } : {}),
  };
}

function main(): void {
  // The piecewise path is only honest for the fault rows if it writes what the shipping writer writes: same
  // header, same manifest, same key, same bytes.
  const piecewise = sealUnder(HONEST_HEADER, payloadOf(HONEST), CURRENT);
  if (toHex(piecewise) !== toHex(HONEST_BYTES)) {
    throw new Error('the piecewise envelope is not the one signEpochInventory writes');
  }
  // And a document meant to be refused cannot come out of the writer: it parses and folds a manifest before it
  // signs, which is why every fault row below is assembled from the pieces beside that one.
  let writerRefused = false;
  try {
    signEpochInventory({ ...HONEST, packs: [] }, CURRENT);
  } catch (err) {
    writerRefused = err instanceof ReceiptError && err.code === 'EPOCH_INVENTORY_BAD_DOCUMENT';
  }
  if (!writerRefused) throw new Error('the inventory writer signed a run of no entries');

  const rows: Record<string, unknown>[] = [];
  for (const one of CASES) {
    const seen = observed(one);
    if (seen.verdict !== one.verdict) {
      throw new Error(`${one.name}: the reader answers ${seen.verdict}, not the ${one.verdict} this case states`);
    }
    const structural = one.structural ?? one.verdict;
    if (seen.structural !== structural) {
      throw new Error(`${one.name}: the keyless reader answers ${seen.structural}, not the ${structural} this case states`);
    }
    // A folded-list refusal names the guard of its site it reaches, and the reader's own sentence has to be
    // that guard's sentence. Two guards of one site answer with the same code, so the verdict check above
    // cannot see a row fall through to its neighbour: a claim guard gone quiet publishes a count refusal under
    // a note about the flag, and only the sentence tells.
    if (one.guard !== undefined && one.site === undefined) {
      throw new Error(`${one.name}: names the ${one.guard} guard at no site`);
    }
    if (one.site !== undefined && one.verdict !== 'verify-ok' && one.guard === undefined) {
      throw new Error(`${one.name}: refuses at ${one.site} and names no guard`);
    }
    if (one.site !== undefined && one.guard !== undefined) {
      const sentence = GUARD_SENTENCES[one.site][one.guard];
      if (!sentence.test(seen.message)) {
        throw new Error(
          `${one.name}: the refusal the reader gave carries no ${one.guard} guard sentence (${sentence.source}) of the ${one.site} site: ${seen.message}`,
        );
      }
    }
    rows.push(published(one, seen));
  }

  const names = rows.map((one) => String(one['name']));
  if (new Set(names).size !== names.length) throw new Error('two cases of this suite share a name');
  const accepted = rows.filter((one) => one['verdict'] === 'verify-ok');
  if (accepted.length < 8) throw new Error(`${String(accepted.length)} accepted rows, and the states a whole document arrives in are more than that`);
  if (rows.length < 20) throw new Error(`${String(rows.length)} rows, and the format names more faults than that`);
  // The two summary lists are guarded by twin routines rather than by one, so a suite carrying one site would let
  // a port that keyed only the other list pass every row here.
  const atBreaks = CASES.filter((one) => one.site === 'chain.breaks').length;
  const atShortfall = CASES.filter((one) => one.site === 'duty.short').length;
  if (atBreaks !== atShortfall) {
    throw new Error(`${String(atBreaks)} rows at the break site and ${String(atShortfall)} at the duty site, and the guards are twins`);
  }

  writeFileSync(
    join(DATA, 'epoch-inventory-v1.json'),
    `${JSON.stringify(
      {
        version: 1,
        description:
          'Sealed epoch inventories and the verdict the shipped reader owes each one: the envelope, the header, the key, the reading of the JSON, the arithmetic over a run of packs, and the names each summary row points at. Every claim the reader recomputes over a run is refused by a row when the document states it wrongly, and those claims are the windows meeting end to start, including one entry whose own two figures do not run forwards, the window, the two chain endpoints beside the run that begins and ends them, the claim each folded list states beside it, and every guard of each of those lists. Apart from those recomputed claims, the three text floors the layout states are each refused by an emptied value. And the acceptances include ones a reviewer would otherwise read as faults: a break list and a shortfall list stated in another order, which the reader keys by the pack each row names, a document listing its seven members in an order no writer emits, which the reader looks up by name, copied text positions wider than any ceiling this layout states, and a run label at the last byte of the width it does.',
        layout: {
          format: 'packages/receipt/epoch-inventory.cddl',
          twin: 'packages/receipt/schemas/epoch-inventory-v1.schema.json',
          prose: 'docs/epoch-inventory-v1.md',
          contentType: EPOCH_INVENTORY_CONTENT_TYPE,
          writer:
            'signEpochInventory in @ashaveri/receipt, which the honest seals here went through, and encodeEpochInventoryManifest, encodeEpochInventoryProtectedHeader, epochInventorySigStructure and sealEpochInventory, which assembled the rows that writer refuses to sign',
          reader:
            'verifyEpochInventory in @ashaveri/receipt, which is the verdict column, and decodeEpochInventory, which is the structural column and needs no key',
          headerLabels: { alg: LABEL_ALG, typ: LABEL_TYP, kid: LABEL_KID },
          sigStructure:
            'RFC 9052 section 4.4: the array ["Signature1", the protected bstr as written, the external AAD, the payload bstr], canonically encoded. The external AAD is empty for this container and nothing inside the envelope carries which one was used.',
          payloadIsText:
            'the payload of this container is JSON text rather than CBOR, two-space indented and newline terminated as the writer emits it, and the signature covers those bytes rather than a canonical rendering of them: the same document re-indented is a different document to this reader',
          nestingDepth: `the JSON reading goes to eight levels and no further, which is a rule of the format rather than a parser limit: the layout's own deepest position is five, and a payload is bytes nobody believes`,
          labelWidth: `the run label is the one text position carrying a ceiling, at ${String(EPOCH_INVENTORY_LABEL_MAX_BYTES)} bytes, because it is printed beside the run in every report of it; the issuer, the instance id and the duty label are copied out of formats that declare floors and no ceiling, and carry none here`,
          encodings: 'documents unpadded base64url, digests, kids, signatures and other byte strings lowercase hex, instants unix seconds',
          rowNamingFields: [...NAMING_FIELDS],
          verdictFields: ['verdict', 'structural', 'message', 'readback', 'edited', 'site', 'guard', 'edit', 'reveal'],
          verdictFieldsMeaning:
            '`verdictFields` is every column a row carries beyond the ones that name it, and `rowNamingFields` is those naming columns published as data beside it rather than repeated inside this sentence, so the two lists together are the whole set of columns a row may carry and a conforming reader expects no other. Two of them state a position rather than an answer. `site` names which of the two folded lists a row guards, and it appears on every refusal inside those lists and on the two acceptances that state one of them in another order. `guard` names which branch of that site the reader stopped on, and it appears beside every `site` refusal and nowhere else. The refusals about the window, the two chain endpoints, the key or the signature are outside those lists and carry neither column, because `site` names the folded lists and nothing else, and where such a row moved one position of its document it says which in `edited`. The suite holds both lists against the columns its published rows actually carry, so neither can drift and no column can be stated twice without a test saying so.',
          verdictMeaning:
            '`verdict` is what verifyEpochInventory answers for the bytes under the designation the row states: `verify-ok`, or the code it throws, whose message the row carries as `message`. `structural` is what decodeEpochInventory answers for the same bytes with no key. A row that is `verify-ok` there and a refusal in `verdict` is refused about a key, a signature or the arithmetic over a run rather than about a document shape, and every run and summary refusal in this suite is that shape. A conforming reader owes the same code; its sentence may differ, and the published message is what this one said.',
          readbackMeaning:
            '`readback` is published on every accepted row and is what the reader reported back: `runFiles` is the reader\'s own recomputation, the run in the order the entries\' own figures put them, which is what `verifyEpochInventory` hands over as its outcome, `statedFiles` is the array as the document wrote it, and the rest are the window, the chain claim and the duty summary as the document states them and the reader echoes them back. Where the two lists of files differ, the array order carried nothing and the reader put the run back.',
          readFields:
            '`read.pinned` is the one key a caller hands the reader, which answers whatever kid the header names. `read.retained` is the set a resolver answers from, one public half per kid, and is how a deployment holding several keys reads one document; an empty set is a resolver holding nothing for the kid named. A row with neither is the call that designated nothing, which this reader refuses before it reads a byte.',
          summarySites:
            'the two lists a run folds, `chain.breaks` and `duty.short`, are guarded apart rather than by one routine, and every fault a list can carry is stated at both sites: a claim of continuity or of carrying contradicted by the list beside it, a list longer than the arithmetic, a list shorter than it, two rows naming one pack, a row naming a pack the run does not hold, a row naming a pack the run holds whose own figures carry no such finding, and a row whose own two digests or four figures are not the pair or the pack it names. Every refusal at a folded-list site carries `site` and the `guard` of the branch it reaches beside it, and each list is keyed by the pack its `file` names, so the order the rows are stated in bears nothing, which is what makes the two accepted rows carrying reversed lists acceptances rather than oversights.',
          assembled:
            'every honest inventory is `signEpochInventory` and no hand-built bytes. Where a row needs something that writer refuses to sign, the manifest is encoded, one position of it is changed, and the result is signed over the published `Sig_structure` and sealed by `sealEpochInventory` under the key its own header names; the generator stops unless that path reproduces `signEpochInventory` byte for byte on the honest document, so each fault row is the one position its `edited` field names and nothing else. Where a row states an `edit` block it was built by replacing one span of the honest document text, which is the pair of run-label rows differing by one byte at one position.',
          codes: [...new Set(CASES.map((one) => one.verdict))].sort(),
          keyMaterial: KEY_MATERIAL.map((one) => ({
            id: toHex(one.key.kid).slice(0, 8),
            seed: one.seed,
            kidHex: toHex(one.key.kid),
            publicKeyHex: toHex(one.key.publicKey),
            publicKeyBase64Url: toBase64Url(one.key.publicKey),
            role: one.role,
          })),
          keyNote:
            'test-only, published so a port can produce these signatures itself rather than only checking them, and protecting nothing. The kid of each is sha256 of its own public half, which is what the writer demands of a key before it seals a document, and which is why this suite carries no row for a header naming an id that could never resolve.',
          notChecked:
            'an inventory describes files a reader is not handed. Nothing here checks that a digest is the digest of a pack that exists, that a pack is sealed by the key its entry gives, that `items` is the count of receipts inside one, or that the run is every window the deployment closed: those are a reviewer\'s next checks, over the pack files and against what the deployment published about its rotations.',
        },
        vectors: rows,
      },
      null,
      2,
    )}\n`,
  );

  for (const one of rows) console.log(`${String(one['name'])}: ${String(one['structural'])} -> ${String(one['verdict'])}`);
}

main();
