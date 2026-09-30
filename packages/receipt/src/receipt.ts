import { sha256 } from '@noble/hashes/sha2.js';
import { encodeCanonical, decodeClosedDocument, decodedMap } from './cbor.js';
import type {
  CoseSign1,
  ProtectedHeader,
  SigningKey,
} from './cose.js';
import {
  signCoseSign1,
  verifyCoseSign1,
  decodeCoseSign1,
  equalBytes,
} from './cose.js';
import { ReceiptError } from './errors.js';
import type {
  CollateralPresence,
  CollateralSlot,
  CollateralValidityAnchor,
  StampDisclosure,
} from './disclosure.js';
import { COLLATERAL_PRESENCES } from './disclosure.js';
import { firstForgingCodePoint } from './line-text.js';

/**
 * `software` makes no TEE claim: `m` is the deployment's own digest of what it runs.
 *
 * The composite suffix is generation-neutral on purpose. A card name in the wire format
 * is honest on the card it names, and a false claim on the next one; the device
 * certificate chain inside the evidence already names the silicon precisely, so the
 * label never had to.
 */
export type TeeKind = 'software' | 'snp' | 'snp+gpucc' | 'tdx' | 'tdx+gpucc';

/**
 * Measurement bytes each kind must carry. A TEE reports its platform-native SHA-384
 * value (SEV-SNP launch digest, TDX MRTD), a software deployment measures with SHA-256,
 * so width and kind are one fact rather than two that can disagree.
 */
export const MEASUREMENT_BYTES: Readonly<Record<TeeKind, 32 | 48>> = {
  software: 32,
  snp: 48,
  'snp+gpucc': 48,
  tdx: 48,
  'tdx+gpucc': 48,
};

/**
 * Whether this kind promises a device report beside the platform quote.
 *
 * A rule over the suffix rather than a list of literals, so a future composite cannot
 * be added to the enum while the client and the gateway quietly disagree about whether
 * it owes a second evidence leg.
 */
export function claimsConfidentialDevice(tee: TeeKind): boolean {
  return tee.endsWith('+gpucc');
}

export function isTeeKind(value: unknown): value is TeeKind {
  return typeof value === 'string' && value in MEASUREMENT_BYTES;
}

export interface Measurement {
  tee: TeeKind;
  m: Uint8Array;
}

export interface EvidenceRef {
  d: Uint8Array;
  ts: number;
  url: string;
}

export interface TokenMetering {
  p: number;
  c: number;
}

/**
 * The payload versions this package reads, the one place that set is written. It holds one version,
 * because nothing outside this repository holds bytes bearing another: `@ashaveri/receipt` is unpublished,
 * the package version is `0.1.0`, and no party outside this estate has ever been handed a receipt. A
 * version number is a demand on readers, and a number no reader outside these files was ever asked to
 * refuse earns its keep by nothing.
 *
 * So this one version carries what the retired numbers used to: `mk`, because a reader that found nothing
 * about a mark would verify a receipt over an unmarked response as readily as over a marked one, which is
 * silence read as a claim. `sd`, `cva` and `itm` for the same reason three times over: a reader that took
 * a stamp's source, an appraisal's context and a response's items and dropped them would verify a receipt
 * whose stamp names no source, whose appraisal recorded no context, and whose response holds no items. No
 * member changed name, type, order or meaning in the collapse, and no member was added: the seventeen
 * names below are the ones the newest retired version already spelled, at the same seventeen positions.
 */
const PARSED_VERSIONS = [1] as const;

export type ReceiptVersion = (typeof PARSED_VERSIONS)[number];

/**
 * Whether a number is one of the versions above, which is the question every reader and writer of this
 * format answers before it reads a member. Exported for `json.ts`, the one other place a version is
 * settled, and not named by `index.ts`: the set of what this package reads is stated once, in the list
 * above, and every refusal of a number outside it is read off that list rather than restated.
 */
export function isReceiptVersion(value: unknown): value is ReceiptVersion {
  return (PARSED_VERSIONS as readonly unknown[]).includes(value);
}

/**
 * The labels this package can interpret, which is the whole registry today. A label outside them is
 * a refusal rather than a best guess, because reading a region under another scheme's rule is the
 * scheme-confusion failure and this is the code that answers it.
 *
 * `none` declares that no region of the response is marked, and `provenance-v1` names the extractor
 * rule for the `ashaveri` member a marked response carries. Which of the two a receipt attests is a
 * value of the field either way, so unmarked and undecided are different bytes.
 *
 * Exported, and named by `index.ts`, because this is the set an operator's flag is read against: the
 * gateway takes its choice from here rather than keeping a second copy that a new label would have to
 * be remembered by. What each label extracts is `marking.ts`, and the published row for each is
 * section 3.3 of `docs/receipt-spec.md`.
 */
export const MARKING_SCHEMES = ['none', 'provenance-v1'] as const;

export type MarkingScheme = (typeof MARKING_SCHEMES)[number];

/** Whether a string is one of the labels above: how an operator's flag is read. */
export function isMarkingScheme(value: string): value is MarkingScheme {
  return (MARKING_SCHEMES as readonly string[]).includes(value);
}

export interface Marking {
  sch: MarkingScheme;
  /** sha256 of the marked region exactly as it appears in the response, not of the whole response. */
  d: Uint8Array;
}

/**
 * The twelve fields every receipt carries, named apart from the five that state what this issuance knew
 * about itself, because the two groups are read by different code: the walk over the payload's closed map
 * reaches all seventeen, and only the twelve below are checked in one order by one reader.
 */
interface ReceiptFields {
  iss: string;
  ins: string;
  iat: number;
  nce: Uint8Array;
  req: Uint8Array;
  res: Uint8Array;
  mdl: string;
  wts: Uint8Array;
  meas: Measurement;
  att: EvidenceRef;
  epk: number;
  tok: TokenMetering;
}

/**
 * One response item: the instant its bytes were stamped and their digest, and nothing else. The
 * order of the list this belongs to is the chain, which is why there is no predecessor field beside
 * `d`: an item has no identity to name one by. `d` is the same 32-byte representation
 * `ResponseItem.d`, `mk.d` and `att.d` use.
 */
export interface ItemStamp {
  /** unix seconds the source named by `sd` read when this item's bytes were framed. */
  t: number;
  /** sha256 of exactly this item's bytes, and of none of the framing around them. */
  d: Uint8Array;
}

/**
 * The receipt payload, one version, at seventeen positions. The twelve every document has always
 * carried, then `mk` so a mark is attested rather than passed over, then the three members that made
 * the newest retired number move: the disclosure of the source `iat` was read from, what became of the
 * two pieces of appraisal context, and one entry per response item. All five are required, because an
 * unstated mark, an unstated source, an unrecorded context, and an item list that might simply not be
 * there are silences, and a receipt is a document that states.
 */
export interface ReceiptPayload extends ReceiptFields {
  v: 1;
  mk: Marking;
  sd: StampDisclosure;
  cva: CollateralValidityAnchor;
  itm: readonly ItemStamp[];
}

/**
 * The members the payload declares, in the order `receipt.cddl` lists them: the twelve every document
 * shares, then the marking, the disclosure, the anchor and the item list.
 *
 * This list and the ones below are exported so a reader outside the package can hold each one
 * against the map `receipt.cddl` declares it for: they are the whole of what the closure walk
 * refuses, so once a map's members are written in two places the two can come apart, and only one
 * direction of the disagreement is loud. `index.ts` names none of them, so the package's public
 * surface is what it was.
 */
export const PAYLOAD_MEMBERS = [
  'v', 'iss', 'ins', 'iat', 'nce', 'req', 'res', 'mdl', 'wts', 'meas', 'att', 'epk', 'tok',
  'mk', 'sd', 'cva', 'itm',
] as const;

/**
 * A map the CDDL defines: which members it names, and which of them the format makes into another
 * such map. `Measurement` is one entry rather than two because its two arms differ only in the width
 * `m` carries, so which arm a document takes adds no member name the other lacks.
 */
interface DefinedMap {
  readonly members: readonly string[];
  readonly nested?: Readonly<Record<string, DefinedMap>>;
}

export const MEASUREMENT_MEMBERS = ['tee', 'm'] as const;
export const EVIDENCE_REF_MEMBERS = ['d', 'ts', 'url'] as const;
export const TOKEN_METERING_MEMBERS = ['p', 'c'] as const;
export const MARKING_MEMBERS = ['sch', 'd'] as const;
export const STAMP_DISCLOSURE_MEMBERS = ['name', 'unc'] as const;
export const COLLATERAL_ANCHOR_MEMBERS = ['col', 'val'] as const;
export const COLLATERAL_HELD_MEMBERS = ['p', 'd'] as const;
export const COLLATERAL_ABSENT_MEMBERS = ['p', 'r'] as const;
export const ITEM_STAMP_MEMBERS = ['t', 'd'] as const;

/**
 * Which members the payload defines, and the maps nested inside it. A map is closed: carrying a member
 * it does not define makes the document malformed rather than a document read with the extra member
 * dropped, and that is as true one level down as it is at the payload.
 *
 * Two maps here are deliberately not entries in any `nested`: the two arms of a collateral slot, because
 * which list stands behind `cva.col` is decided by the label in it and no one list answers for both, and
 * the element map of `itm`, because that member's value is an array and a walk over map members cannot
 * reach inside one. Both are closed by the reader that resolves the choice, at the position each one sits
 * at, which is what `receipt.cddl` says of them.
 *
 * This is the structure the walk reads, so the lists above answer for the format only if it is
 * read off them: a map whose entry is a copy of a list goes stale the day that list is edited, and a
 * `nested` that is missing a name stops refusing members there while every list still
 * matches the CDDL. Exported alongside the lists, for that reason and for no other, and named by
 * `index.ts` as little as they are, so the package's public surface is what it was.
 */
export const DEFINED_MAPS: Readonly<Record<ReceiptVersion, DefinedMap>> = {
  1: {
    members: PAYLOAD_MEMBERS,
    nested: {
      meas: { members: MEASUREMENT_MEMBERS },
      att: { members: EVIDENCE_REF_MEMBERS },
      tok: { members: TOKEN_METERING_MEMBERS },
      mk: { members: MARKING_MEMBERS },
      sd: { members: STAMP_DISCLOSURE_MEMBERS },
      cva: { members: COLLATERAL_ANCHOR_MEMBERS },
    },
  },
};

export interface VerifyOptions {
  publicKey?: Uint8Array;
  resolveKey?: (kid: Uint8Array) => Uint8Array | undefined;
  expectedNonce?: Uint8Array;
  /**
   * The instant the freshness windows are measured from, in whole seconds since the Unix epoch.
   * This is the format's own unit: `iat` and an `itm` entry's `t` are seconds, so the value is read
   * straight against them with no divide. Defaults to the host clock, in seconds.
   *
   * A reading is refused by `VERIFICATION_TIME_OUT_OF_RANGE` when it is not a whole number of Unix
   * seconds this reader could weigh a stamp against. The refusal is about the argument, not the
   * document: the same bytes under a stated second answer the same way they would have answered had
   * the caller handed seconds in the first place.
   */
  nowSeconds?: number;
  freshnessSeconds?: number;
  evidenceFreshnessSeconds?: number;
  /**
   * Which payload versions this call accepts, defaulting to every version this package parses.
   * The default is deliberately the wide one, and today that set is one version wide. An empty list is
   * how a caller says it reads no receipt at all; a document naming a number outside the set this
   * package parses is refused under either setting, and the refusal names the number it read.
   */
  acceptedVersions?: readonly ReceiptVersion[];
}

export interface VerifiedReceipt {
  payload: ReceiptPayload;
  header: ProtectedHeader;
  cose: CoseSign1;
}

function isUint8Array(v: unknown): v is Uint8Array {
  return v instanceof Uint8Array;
}

function badPayload(detail: string): ReceiptError {
  return new ReceiptError('BAD_PAYLOAD', detail);
}

/**
 * The versions a call accepts when it did not say, which is the set this package parses read off the
 * one list that holds it. Spelled a second time, the two can disagree and only one direction of the
 * disagreement is quiet: a default that forgot a version refuses real receipts no caller chose to
 * refuse, and a default that names a version nothing parses promises an acceptance the package
 * cannot deliver. What this package reads is therefore one decision, taken where the set of
 * what it reads lives.
 */
const ACCEPTED_BY_DEFAULT: readonly ReceiptVersion[] = PARSED_VERSIONS;

/**
 * Which version the bytes claim, settled before a single field is read. A member that is not an
 * integer at all is a malformed payload rather than a version; an integer this package cannot read
 * and one the caller did not accept are answered alike, because which of the two it was is not a
 * fact about the bytes, and a second code would let a caller probe where the boundary sits. Every
 * number outside the one list this package parses is refused here and named in the message, so no
 * retired version falls through to a structural error about a member its document did or did not carry.
 */
function claimedVersion(value: unknown, accepted: readonly ReceiptVersion[]): ReceiptVersion {
  if (typeof value !== 'number' || !Number.isInteger(value)) throw badPayload('v must be an integer receipt version');
  if (!isReceiptVersion(value)) {
    throw new ReceiptError('UNSUPPORTED_VERSION', `receipt payload version ${value} is not a format this package reads`);
  }
  if (!accepted.includes(value)) {
    throw new ReceiptError('UNSUPPORTED_VERSION', `receipt payload version ${value} is not in acceptedVersions`);
  }
  return value;
}

/**
 * How a document names a member the reader was not told about, in the refusal that names it back.
 * A map key is whatever the bytes carried, so a name that is not a text label is described by what
 * it is rather than rendered through an object's default `toString`.
 */
function memberName(key: unknown): string {
  if (typeof key === 'string') return `'${key}'`;
  if (key instanceof Uint8Array) return `a bstr key of length ${key.length}`;
  return `a key that is not a text label`;
}

/**
 * The closedness rule, applied once to a map and to every map the format puts inside it, each read
 * off the one member list that map declares. It runs before any field's value is checked, so an
 * unexpected member is the answer a caller hears whatever else the document is missing, and one rule
 * retires the whole class rather than the one name that happened to be noticed: a payload carrying a
 * name this format does not define, read with that name dropped, would hand a reader a verified receipt
 * that says nothing about the claim the extra member carried, which is the same silence the closed map
 * exists to refuse wherever it is found. That is why the walk does not stop at the
 * payload. A member inside `meas` is a claim about the measurement no verifier was told to look at,
 * and a reader that rebuilds the map from the names it knows drops it in the same silence one level
 * down. A value that is not a map is left for the reader's own check, which says which member it
 * found not a map rather than letting this one claim a membership failure it cannot see.
 */
function assertMembersAreDefined(raw: Map<unknown, unknown>, defined: DefinedMap, where: string, definer: string): void {
  for (const [key, value] of raw) {
    if (typeof key !== 'string' || !defined.members.includes(key)) {
      throw badPayload(`${where} carries a member ${definer} does not define: ${memberName(key)}`);
    }
    const nested = defined.nested?.[key];
    if (nested !== undefined) {
      const inner = decodedMap(value);
      if (inner !== null) {
        assertMembersAreDefined(inner, nested, key, 'the format');
      }
    }
  }
}

/** The twelve members that are not a statement about this issuance itself, checked in the order the CDDL lists them. */
function readReceiptFields(raw: Map<unknown, unknown>): ReceiptFields {
  const iss = raw.get('iss');
  if (typeof iss !== 'string') throw badPayload('iss must be a tstr');
  const ins = raw.get('ins');
  if (typeof ins !== 'string') throw badPayload('ins must be a tstr');
  const iat = raw.get('iat');
  if (typeof iat !== 'number' || !Number.isSafeInteger(iat) || iat < 0) throw badPayload('iat must be a non-negative integer');
  const nce = raw.get('nce');
  if (!isUint8Array(nce) || nce.length !== 16) throw badPayload('nce must be a 16-byte bstr');
  const req = raw.get('req');
  if (!isUint8Array(req) || req.length !== 32) throw badPayload('req must be a 32-byte bstr');
  const res = raw.get('res');
  if (!isUint8Array(res) || res.length !== 32) throw badPayload('res must be a 32-byte bstr');
  const mdl = raw.get('mdl');
  if (typeof mdl !== 'string') throw badPayload('mdl must be a tstr');
  const wts = raw.get('wts');
  if (!isUint8Array(wts) || wts.length !== 32) throw badPayload('wts must be a 32-byte bstr');
  const meas = decodedMap(raw.get('meas'));
  if (meas === null) throw badPayload('meas must be a map');
  const tee = meas.get('tee');
  if (!isTeeKind(tee)) throw badPayload('meas.tee is not a known environment kind');
  const m = meas.get('m');
  const width = MEASUREMENT_BYTES[tee];
  if (!isUint8Array(m) || m.length !== width) {
    throw badPayload(`meas.m must be a ${width}-byte bstr for tee '${tee}'`);
  }
  const att = decodedMap(raw.get('att'));
  if (att === null) throw badPayload('att must be a map');
  const d = att.get('d');
  if (!isUint8Array(d) || d.length !== 32) throw badPayload('att.d must be a 32-byte bstr');
  const ts = att.get('ts');
  if (typeof ts !== 'number' || !Number.isSafeInteger(ts) || ts < 0) throw badPayload('att.ts must be a non-negative integer');
  const url = att.get('url');
  if (typeof url !== 'string') throw badPayload('att.url must be a tstr');
  const epk = raw.get('epk');
  if (typeof epk !== 'number' || !Number.isSafeInteger(epk) || epk < 0) throw badPayload('epk must be a non-negative integer');
  const tok = decodedMap(raw.get('tok'));
  if (tok === null) throw badPayload('tok must be a map');
  const p = tok.get('p');
  if (typeof p !== 'number' || !Number.isSafeInteger(p) || p < 0) throw badPayload('tok.p must be a non-negative integer');
  const c = tok.get('c');
  if (typeof c !== 'number' || !Number.isSafeInteger(c) || c < 0) throw badPayload('tok.c must be a non-negative integer');
  return { iss, ins, iat, nce, req, res, mdl, wts, meas: { tee, m }, att: { d, ts, url }, epk, tok: { p, c } };
}

/**
 * `mk` is required, so an absent one is a payload failure and never a reading of "unmarked": the
 * silence would be indistinguishable from "this receipt predates marking", which is exactly the
 * claim a reader must not be able to make. Unmarked is `sch: "none"`, and only the verification
 * step that holds the response bytes can say whether its digest of the empty region agrees.
 */
function readMarking(raw: Map<unknown, unknown>): Marking {
  const value = raw.get('mk');
  if (value === undefined) throw badPayload('v1 requires an mk member; absence is mk.sch "none", not a missing mk');
  const mk = decodedMap(value);
  if (mk === null) throw badPayload('mk must be a map');
  const sch = mk.get('sch');
  if (typeof sch !== 'string') throw badPayload('mk.sch must be a tstr');
  if (!isMarkingScheme(sch)) {
    throw new ReceiptError('UNSUPPORTED_SCHEME', `marking scheme '${sch}' is not one this package can interpret`);
  }
  const d = mk.get('d');
  if (!isUint8Array(d) || d.length !== 32) throw badPayload('mk.d must be a 32-byte bstr');
  return { sch, d };
}

/**
 * `sd`, the disclosure of where the issuance instant came from. Two members, both required, because
 * the whole of what this member adds is that a reader need not go outside the signed document to
 * ask the question.
 *
 * `unc` is the one position in this payload that takes `null` as a value, and it is a value rather
 * than an absent member on purpose: `null` is that source's own statement that nobody measured how
 * far it can stand from the instants it names, `0` is that source's statement that it is right, and
 * a member that could be missing has no way to tell a reader which of the two the writer meant. A
 * policy that demands a bound reads the difference, which is why nothing here flattens it.
 */
function readStampDisclosure(raw: Map<unknown, unknown>): StampDisclosure {
  const value = raw.get('sd');
  if (value === undefined) throw badPayload('v1 requires an sd member; a stamp from an unnamed source is not the same document');
  const sd = decodedMap(value);
  if (sd === null) throw badPayload('sd must be a map');
  const name = sd.get('name');
  if (typeof name !== 'string') throw badPayload('sd.name must be a tstr');
  const unc = sd.get('unc');
  if (unc !== null) {
    if (typeof unc !== 'number' || !Number.isSafeInteger(unc) || unc < 0) {
      throw badPayload('sd.unc must be a non-negative integer or null');
    }
    return { name, uncertaintySeconds: unc };
  }
  return { name, uncertaintySeconds: null };
}

/**
 * Whether a label is one of the three presence states the format declares, which is how a slot knows
 * which of its two arms it is. The set is the one `disclosure.ts` exports and the capture record
 * spells, so a fourth label here would have to be added there first.
 */
function isCollateralPresence(value: unknown): value is CollateralPresence {
  return typeof value === 'string' && (COLLATERAL_PRESENCES as readonly string[]).includes(value);
}

/**
 * One arm of the anchor, closed by this read rather than by the walk: `p` decides which member list
 * stands behind the slot, and no single list answers for both arms. A held slot carrying a reason is
 * refused as surely as an absent one carrying a digest, because each is a document holding the
 * other arm's claim and dropping its own.
 */
function readCollateralSlot(value: unknown, where: string): CollateralSlot {
  const slot = decodedMap(value);
  if (slot === null) throw badPayload(`${where} must be a map`);
  const presence = slot.get('p');
  if (!isCollateralPresence(presence)) {
    throw badPayload(`${where}.p is not one of the three presence states the format declares`);
  }
  if (presence === 'held') {
    assertMembersAreDefined(slot, { members: COLLATERAL_HELD_MEMBERS }, where, 'a held slot');
    const digest = slot.get('d');
    if (!isUint8Array(digest) || digest.length !== 32) throw badPayload(`${where}.d must be a 32-byte bstr`);
    return { presence: 'held', sha256: digest };
  }
  assertMembersAreDefined(slot, { members: COLLATERAL_ABSENT_MEMBERS }, where, 'an absent slot');
  const reason = slot.get('r');
  if (typeof reason !== 'string') throw badPayload(`${where}.r must be a tstr`);
  return { presence, reason };
}

/**
 * `cva`, the captured validity anchor. Both halves are read and neither is defaulted: a deployment
 * that held the collateral and never took in a validity window is a state this document can state,
 * and it is not the same state as holding both or neither. What the collateral proves is nobody's
 * business here, because no field of an anchor is a verdict, and a record that printed one would
 * turn custody of bytes into verification of them.
 */
function readCollateralAnchor(raw: Map<unknown, unknown>): CollateralValidityAnchor {
  const value = raw.get('cva');
  if (value === undefined) throw badPayload('v1 requires a cva member; an unrecorded context is a state, not an omission');
  const cva = decodedMap(value);
  if (cva === null) throw badPayload('cva must be a map');
  return {
    collateral: readCollateralSlot(cva.get('col'), 'cva.col'),
    validity: readCollateralSlot(cva.get('val'), 'cva.val'),
  };
}

/**
 * `itm`, the per-item list: one entry per response item, in the order the response put them in, and
 * never empty. An empty list is refused because a run of nothing states nothing and makes the walk
 * over it vacuous, which is the reason `pack.cddl` gives for its own item list; a stream that sent no
 * data frame is a refusal at issuance rather than a receipt carrying zero entries, and a buffered
 * body of no bytes is one entry holding nothing.
 *
 * Each element is closed here rather than by the walk, because the walk reads map members and this
 * member's value is an array. The position is in the refusal so a reader learns which item of a
 * response said something the format cannot hold.
 *
 * The stamps are then compared with the order the array states, which is the reader-side half of the
 * rule: chain order is the list, stamp order is `t`, and a receipt whose later item carries an
 * earlier instant is one document contradicting another one of itself. That disagreement is its own
 * code rather than `BAD_PAYLOAD`, because every member here is well-typed and in the place the version
 * puts it, and what is refused is a pair of signed statements. Two items stamped in the same second are
 * not a disagreement, because a second is the width of the stamp and two frames of one completion fall
 * inside one routinely; a reader that asked for strictly increasing instants would refuse ordinary
 * traffic, and the residual the check leaves is stated in the specification rather than widened here.
 */
function readItemStamps(raw: Map<unknown, unknown>): readonly ItemStamp[] {
  const value = raw.get('itm');
  if (value === undefined) throw badPayload('v1 requires an itm member; a response with no items is a refusal, not an omission');
  if (!Array.isArray(value)) throw badPayload('itm must be an array');
  if (value.length === 0) throw badPayload('itm declares at least one item and carries none');
  const items = value.map((one, index) => readItemStamp(one, `itm[${index}]`));
  let previous: ItemStamp | undefined;
  for (const [index, one] of items.entries()) {
    if (previous !== undefined && one.t < previous.t) {
      throw new ReceiptError(
        'ITEM_STAMP_OUT_OF_ORDER',
        `itm[${index}] is stamped ${one.t} and itm[${index - 1}] is stamped ${previous.t}, so the order the list states and the order the stamps state disagree`,
      );
    }
    previous = one;
  }
  return items;
}

function readItemStamp(raw: unknown, where: string): ItemStamp {
  const one = decodedMap(raw);
  if (one === null) throw badPayload(`${where} must be a map`);
  assertMembersAreDefined(one, { members: ITEM_STAMP_MEMBERS }, where, 'the format');
  const t = one.get('t');
  if (typeof t !== 'number' || !Number.isSafeInteger(t) || t < 0) throw badPayload(`${where}.t must be a non-negative integer`);
  const d = one.get('d');
  if (!isUint8Array(d) || d.length !== 32) throw badPayload(`${where}.d must be a 32-byte bstr`);
  return { t, d };
}

function parsePayload(bytes: Uint8Array, accepted: readonly ReceiptVersion[]): ReceiptPayload {
  // The payload is the second of the two documents the format declares in full, so it is read under
  // the same rule as the signed header: a number that arrives here as a float is a value of a major
  // type no member of this map is written as, and the decode is the last point at which the
  // difference between that and the integer it imitates is still visible.
  const raw = decodedMap(decodeClosedDocument(bytes, 'BAD_PAYLOAD'));
  if (raw === null) throw badPayload('payload is not a map');
  const version = claimedVersion(raw.get('v'), accepted);
  assertMembersAreDefined(raw, DEFINED_MAPS[version], 'payload', `version ${version}`);
  const fields = readReceiptFields(raw);
  // One reader for the one version this format declares, and no arm left behind for a number that
  // version retired. The cascade this replaced ended in a `v: 3` object with nothing in front of it, so a
  // fourth version landed there and was read under v3's rules; that shape of bug cannot come back here,
  // because `claimedVersion` refuses every number outside `PARSED_VERSIONS` before one member is read,
  // and the number it refuses is in the message. What this return states is the format's whole member
  // set: the twelve shared fields, then the marking, the disclosure, the anchor and the item list, none of
  // them defaulted and none of them optional.
  return {
    v: version,
    ...fields,
    mk: readMarking(raw),
    sd: readStampDisclosure(raw),
    cva: readCollateralAnchor(raw),
    itm: readItemStamps(raw),
  };
}

/** The `mk` map of a payload, in the order `receipt.cddl` declares its two members. */
function markingMembers(mk: Marking): Map<string, unknown> {
  return new Map<string, unknown>([['sch', mk.sch], ['d', mk.d]]);
}

/** One arm of the anchor: the presence label, and then the digest or the reason that label selects. */
function collateralSlotMembers(slot: CollateralSlot): Map<string, unknown> {
  return slot.presence === 'held'
    ? new Map<string, unknown>([['p', slot.presence], ['d', slot.sha256]])
    : new Map<string, unknown>([['p', slot.presence], ['r', slot.reason]]);
}

/**
 * Where a member's name in the interfaces this package publishes differs from its name on the wire.
 * Three positions differ, each because the type spells out what `receipt.cddl` abbreviates: the bound
 * a stamp's source states about itself, and the two legs of the anchor. Everywhere else the two names
 * are one name, so the walk below reads the same member list the reader's closedness walk reads.
 */
const WIRE_TO_INPUT_NAME: Readonly<Record<string, string>> = {
  unc: 'uncertaintySeconds',
  col: 'collateral',
  val: 'validity',
};

/**
 * The two arms of a collateral slot under the names a caller hands them under, by the presence label
 * that chooses between them. Written out rather than read off `COLLATERAL_HELD_MEMBERS` and
 * `COLLATERAL_ABSENT_MEMBERS`, because `p`, `d` and `r` name members of four other maps of this
 * payload too, where `d` is a mark's digest and `p` a token count, so no global renaming reaches a
 * slot. Each list is one name per name of the arm's wire list, and `receipt.test.ts` holds that
 * against the two lists, which is where a fourth member added to one arm would otherwise be missed.
 */
const SLOT_INPUT_MEMBERS: Readonly<Record<CollateralPresence, readonly string[]>> = {
  held: ['presence', 'sha256'],
  'absent-at-source': ['presence', 'reason'],
  'not-taken-in': ['presence', 'reason'],
};

/** A nested map's wire members, as the interfaces name them. */
function inputMembersOf(wireMembers: readonly string[]): readonly string[] {
  return wireMembers.map((name) => WIRE_TO_INPUT_NAME[name] ?? name);
}

/**
 * The members of a map the writer was handed, once it has proved that what it was handed is a map.
 * A `null`, a primitive and an array are refused as the map the format writes rather than reaching a
 * property read that would answer `undefined` for every member and then die in one, which is the
 * uncoded `TypeError` this walk replaces. Two-step on purpose: the version and a slot's presence
 * label decide which member list applies, and nothing else about the map is asked until after they
 * have, so the position that chooses is never checked against a list it has not settled yet.
 */
function encodableMapOf(value: unknown, where: string): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw badPayload(`${where} is not a map the format writes`);
  }
  return value as Record<string, unknown>;
}

/**
 * One map the writer was handed, against the members that map defines: nothing it carries is a name
 * the definition lacks, and nothing the definition requires is a name it does not hold a value under.
 * A key whose value is `undefined` is the absence of a member and not a member carrying nothing,
 * which is what makes `sd` with `uncertaintySeconds: null` a statement and `itm: undefined` a hole.
 */
function assertEncodableMap(
  value: unknown,
  members: readonly string[],
  where: string,
  definer: string,
): Record<string, unknown> {
  const given = encodableMapOf(value, where);
  for (const name of Object.keys(given)) {
    if (!members.includes(name)) {
      throw badPayload(`${where} carries a member ${definer} does not define: ${memberName(name)}`);
    }
  }
  for (const name of members) {
    if (given[name] === undefined) {
      throw badPayload(`${where} is missing '${name}', which ${definer} requires`);
    }
  }
  return given;
}

/**
 * One arm of the anchor, closed at the position it sits on, as the reader closes it at the same one.
 * A slot carrying both arms' claims is reached by the arm its own label selects and refused there for
 * the member that arm does not define, which is the state `readCollateralSlot` answers by closing each
 * arm at its own site rather than one list for both.
 */
function assertEncodableSlot(value: unknown, where: string): void {
  const given = encodableMapOf(value, where);
  const presence = given['presence'];
  if (typeof presence !== 'string' || !isCollateralPresence(presence)) {
    throw badPayload(`${where}.p is not one of the three presence states the format declares`);
  }
  assertEncodableMap(given, SLOT_INPUT_MEMBERS[presence], where, presence === 'held' ? 'a held slot' : 'an absent slot');
}

/**
 * The attested text class: every position of a payload whose type `receipt.cddl` leaves open to a
 * `tstr`, in the order the format lists them, each with the name a caller hands its value under.
 *
 * Exported for one reason, the same reason `DEFINED_MAPS` is: `receipt.test.ts` holds this list against
 * the CDDL text beside it, so a text member that arrives in the format and not here fails a test rather
 * than encoding unrefused. Every entry of a row is one position of one document, and the two rows of
 * the anchor carry the same wire name at the two positions that name is reached through.
 */
export interface AttestedTextRow {
  /** The payload member whose map holds these positions, and `undefined` for the payload's own members. */
  readonly owner: string | undefined;
  /** The path the owning map is read at, from the object the writer was handed. */
  readonly path: readonly string[];
  /** How the refusal names the map these positions sit in: `cva.col` for the path `cva.collateral`. */
  readonly position: string;
  /** The positions this row scans, each stated as the format states it and as a caller hands it. */
  readonly positions: ReadonlyArray<{ readonly wire: string; readonly input: string }>;
}

export const ATTESTED_TEXT_ROWS: readonly AttestedTextRow[] = [
  { owner: undefined, path: [], position: '', positions: [{ wire: 'iss', input: 'iss' }, { wire: 'ins', input: 'ins' }, { wire: 'mdl', input: 'mdl' }] },
  { owner: 'att', path: ['att'], position: 'att', positions: [{ wire: 'url', input: 'url' }] },
  { owner: 'mk', path: ['mk'], position: 'mk', positions: [{ wire: 'sch', input: 'sch' }] },
  { owner: 'sd', path: ['sd'], position: 'sd', positions: [{ wire: 'name', input: 'name' }] },
  { owner: 'cva', path: ['cva', 'collateral'], position: 'cva.col', positions: [{ wire: 'r', input: 'reason' }] },
  { owner: 'cva', path: ['cva', 'validity'], position: 'cva.val', positions: [{ wire: 'r', input: 'reason' }] },
];

/**
 * One attested text member, refused before a byte of it is signed if its text could forge a line.
 *
 * Each member this reaches is bounded in byte length and in nothing else, and each is printed somewhere:
 * `iss`, `ins` and `mdl` beside the labels that name them, `mk.sch` in a marking row, `att.url` as the
 * address a verifier fetches, `sd.name` as the source a stamp is claimed from, and `cva.col.r` and
 * `cva.val.r` as the collector's own words for an absence it did not take in. A member carrying a line
 * break signs a payload whose report is two lines, and the second one is whoever set the value's to
 * write; a member carrying a directional isolate or a tag character prints a row whose visible text is
 * not its byte order. Nothing about the CBOR is wrong in either case, which is why no reader caught it:
 * a `tstr` encodes any code point. So this is the writer's question rather than the format's, and it is
 * asked in `assertEncodable`, which is the one step every path to a signature goes through.
 *
 * The class this refuses on has one owner, `src/line-text.ts`, and the epoch inventory's reader refuses on that
 * same class, at the run label it writes for itself and at the four text positions it copies out of a deployment
 * manifest and a pack (`requireText` and `requireLabel`, `src/epoch-inventory.ts`). What stays apart is everything
 * else about the two refusals: this one reaches the eight attested text positions of a payload this package signs,
 * names each the way the format spells it, and answers under `BAD_PAYLOAD` with no byte ceiling of its own,
 * while that one reaches five positions of a document this package reads, bounds only the label by a width
 * because the four it copies travel at whatever length the documents holding them state, and answers under
 * `EPOCH_INVENTORY_BAD_DOCUMENT`. One class and the site's own three facts, because which characters a printed
 * row is made of is one answer wherever the row comes from, and which positions carry a printed row, how wide
 * they may be, and what a caller is told to do about them are not.
 *
 * Leading and trailing space is refused with the class for the inventory's stated reason, which is also
 * this rule's own: these members are printed beside their labels by nothing that quotes them, and a value
 * whose extent a reader cannot state is a value it cannot cite. Anything else about the value is not this
 * refusal. A space in the middle of one, a length no ceiling here bounds, and text outside ASCII are all
 * text a line is made of, and a document carrying them is signed exactly as it was handed over. A value
 * that is not text at all is the membership walk's, not this one's, which is why this scan runs after it.
 */
function assertLineSafeText(value: unknown, position: string): void {
  if (typeof value !== 'string') return;
  const code = firstForgingCodePoint(value);
  if (code !== undefined) {
    throw badPayload(`${position} carries the code point ${code.toString(16)}, which would forge a line this document never wrote`);
  }
  if (value !== value.trim()) {
    throw badPayload(`${position} carries leading or trailing space, and it is printed beside its label unpadded`);
  }
}

/** Every attested text member the version defines, in the order the format lists the class. */
function assertAttestedText(members: Record<string, unknown>, defined: DefinedMap): void {
  for (const row of ATTESTED_TEXT_ROWS) {
    // A member this version does not define has no value to read, and the walk above already refused a
    // document that carried one anyway, so reaching past a version's own member set is not on offer here.
    if (row.owner !== undefined && !defined.members.includes(row.owner)) continue;
    if (row.owner === undefined) {
      for (const one of row.positions) {
        if (defined.members.includes(one.wire)) assertLineSafeText(members[one.input], one.wire);
      }
      continue;
    }
    let holder: Record<string, unknown> = members;
    for (const step of row.path) {
      // Every map on this path was settled by the walk above: `att`, `mk` and `sd` by the nested member
      // lists, and both legs of the anchor by `assertEncodableSlot`, which answers a non-map first.
      holder = holder[step] as Record<string, unknown>;
    }
    for (const one of row.positions) assertLineSafeText(holder[one.input], `${row.position}.${one.wire}`);
  }
}

/**
 * Whether the payload the writer was handed is one this format can state, in full, in these bytes.
 *
 * The projection below reads the members the format names, and a projection cannot notice a name it
 * was not told to look for: a member outside the seventeen was dropped without a word, and the
 * signature landed on a document that states nothing about the claim the caller handed over, while a
 * payload with no `itm` died inside a property read, which is not one of the refusals this
 * package publishes. So the writer answers the two questions the reader answers, with the reader's own
 * sentences and the reader's own code, one step before either could be noticed downstream: a member the
 * format does not define is `BAD_PAYLOAD` there and here, and a required member that is absent is
 * `BAD_PAYLOAD` there and here. `docs/error-codes.md` holds `BAD_PAYLOAD` to both readings for that
 * reason, and holds it to a third: a document this walk lets through is still not necessarily a
 * document the format admits, because what is checked here is what the writer was handed and what it
 * can write down, not whether the result is legal. An empty `itm` is that case, and the writer writes
 * it, because it was handed a list and a faithful writer states the length it was given. The reader is
 * the one that says a run of nothing is not a document, and it does. That division is not a leftover:
 * the published vector `receipt-empty-items-v1` is made by this function over an empty list, and a
 * refusal here would delete a byte that is already signed and already published.
 *
 * The version is settled first and the members then walked in the order the CDDL lists them, which is
 * the order `parsePayload` reaches them in, so the two directions of one format answer the same
 * question and answer it in the same order. The lists are read off `DEFINED_MAPS`, the structure the
 * reader's closedness walk reads, so the rule the member set is written down in one place and
 * a version that joins `PARSED_VERSIONS` fails to compile in the map that has to describe it
 * rather than agreeing to be encoded short. The two positions the reader closes at their own sites
 * rather than in a `nested` entry, the arms of the anchor and the element of the item list, are closed
 * here at the matching sites too, gated on the member being defined rather than on the payload's
 * number, which is what carries them into any later version that names them.
 *
 * A third question is answered here, and it is the writer's rather than the format's: an attested text
 * member whose content would forge the line it is printed on is refused before one byte of the payload is
 * signed, under this same code, because the encoder is the one step every path to a signature goes
 * through and no reader can refuse what it only ever sees as a well-typed `tstr`. `assertLineSafeText`
 * states which positions that reaches and what it refuses them on, and `src/line-text.ts` owns the class.
 */
function assertEncodable(payload: ReceiptPayload): void {
  const given = encodableMapOf(payload, 'payload');
  // The version, settled before a member list is read, and answered in the two shapes the reader
  // answers it in: a `v` that is no integer at all is a payload that does not match its schema, and a
  // number this package has no members for is not one it can read as another version's. Absence is the
  // first of those and not the second, because nothing about a payload that names no version says
  // which version it meant.
  const claimed = given['v'];
  if (typeof claimed !== 'number' || !Number.isInteger(claimed)) {
    throw badPayload('v must be an integer receipt version');
  }
  if (!isReceiptVersion(claimed)) {
    throw new ReceiptError(
      'UNSUPPORTED_VERSION',
      'a payload naming a version this encoder has no members for is not encoded as another version',
    );
  }
  const defined = DEFINED_MAPS[claimed];
  const members = assertEncodableMap(given, defined.members, 'payload', `version ${claimed}`);
  for (const [name, nested] of Object.entries(defined.nested ?? {})) {
    assertEncodableMap(members[name], inputMembersOf(nested.members), name, 'the format');
  }
  if (defined.members.includes('cva')) {
    const anchor = members['cva'] as Record<string, unknown>;
    assertEncodableSlot(anchor['collateral'], 'cva.col');
    assertEncodableSlot(anchor['validity'], 'cva.val');
  }
  if (defined.members.includes('itm')) {
    const items = members['itm'];
    if (!Array.isArray(items)) throw badPayload('itm must be an array');
    for (const [index, one] of items.entries()) {
      assertEncodableMap(one, ITEM_STAMP_MEMBERS, `itm[${index}]`, 'the format');
    }
  }
  // The members are settled before their characters are asked about, so a document that is short a
  // member is refused for that and not for text this walk never reached. What the class is, and why it is
  // refused here rather than read back, is `assertLineSafeText`'s own statement.
  assertAttestedText(members, defined);
}

/**
 * The payload, as the CBOR maps `receipt.cddl` declares them: one `Map` per map, so key order is
 * bytewise under Core Deterministic Encoding and no field order in this file or in a caller's object
 * can move a byte of what gets signed.
 */
export function encodePayload(payload: ReceiptPayload): Uint8Array {
  // What the writer was handed is settled before a single member is read, because every read below is
  // a projection and a projection that reaches for a name the object does not carry is the defect this
  // refuses, not a step of the layout.
  assertEncodable(payload);
  // Maps (not plain objects) so key ordering is bytewise per RFC 8949 CDE,
  // independent of any TS field ordering.
  const fields: Array<readonly [string, unknown]> = [
    ['v', payload.v],
    ['iss', payload.iss],
    ['ins', payload.ins],
    ['iat', payload.iat],
    ['nce', payload.nce],
    ['req', payload.req],
    ['res', payload.res],
    ['mdl', payload.mdl],
    ['wts', payload.wts],
    ['meas', new Map<string, unknown>([['tee', payload.meas.tee], ['m', payload.meas.m]])],
    ['att', new Map<string, unknown>([['d', payload.att.d], ['ts', payload.att.ts], ['url', payload.att.url]])],
    ['epk', payload.epk],
    ['tok', new Map<string, unknown>([['p', payload.tok.p], ['c', payload.tok.c]])],
  ];
  // The one version this format declares writes all seventeen members, in the order `receipt.cddl` lists
  // them, and nothing is trimmed for being new: `unc` is written whether or not anything was measured,
  // because `null` is the sentence the source says about itself and an omitted member is not that
  // sentence. What a writer that filtered would have hidden is the case `assertEncodable` answers: a
  // caller that handed over a member the format does not define, or held one back that it requires, gets a
  // refusal at the walk above rather than a signature over a document that states something other than
  // what it was given.
  //
  // Ask what fails if `PARSED_VERSIONS` gains a second number and nothing else is edited: `DEFINED_MAPS`,
  // keyed by `ReceiptVersion`, has to describe it, and `assertEncodable` reads the member set off that map
  // rather than restating it. What does not exist any more is an arm per number: the retired versions are
  // gone from this file rather than left unreachable in it, which is what `test/receipt.test.ts` holds.
  fields.push(
    ['mk', markingMembers(payload.mk)],
    [
      'sd',
      new Map<string, unknown>([['name', payload.sd.name], ['unc', payload.sd.uncertaintySeconds]]),
    ],
    [
      'cva',
      new Map<string, unknown>([
        ['col', collateralSlotMembers(payload.cva.collateral)],
        ['val', collateralSlotMembers(payload.cva.validity)],
      ]),
    ],
    ['itm', payload.itm.map((one) => new Map<string, unknown>([['t', one.t], ['d', one.d]]))],
  );
  return encodeCanonical(new Map(fields));
}

export function issueReceipt(payload: ReceiptPayload, key: SigningKey): Uint8Array {
  // The projection is settled first, because it is the step that proves `meas` is a map carrying both
  // of its members: the width rule below reads the kind out of it, and a payload with no `meas` at all
  // would answer `undefined` for the kind and die inside that read rather than with a named refusal.
  const payloadBytes = encodePayload(payload);
  // Catch it here rather than after signing: a receipt whose measurement does not
  // match its kind is one no verifier can accept. The two halves of that are one question the reader
  // already answers with one sentence, and `isUint8Array` is the reader's own test for a bstr: a
  // measurement that is not bytes at all has no width to compare, and reaching past it for one is the
  // uncoded `TypeError` this call exists to keep off the honest path. A `Buffer` is a `Uint8Array`, so
  // a gateway that read its deployment's measurement out of a file is not refused here for the shape of
  // what it holds.
  const width = MEASUREMENT_BYTES[payload.meas.tee];
  if (!isUint8Array(payload.meas.m) || payload.meas.m.length !== width) {
    throw new ReceiptError('BAD_PAYLOAD', `meas.m must be a ${width}-byte bstr for tee '${payload.meas.tee}'`);
  }
  return signCoseSign1(payloadBytes, key);
}

/**
 * Reads a receipt's payload without checking its signature: this is how a document is inspected
 * before anyone has decided to trust it. It takes the same version narrowing as verification, so a
 * caller that has decided not to read a version hears that refusal whichever way it opens bytes.
 */
export function decodeReceipt(bytes: Uint8Array, options?: VerifyOptions): VerifiedReceipt {
  const cose = decodeCoseSign1(bytes);
  const payload = parsePayload(cose.payloadBytes, options?.acceptedVersions ?? ACCEPTED_BY_DEFAULT);
  return { payload, header: cose.header, cose };
}

/**
 * The two ends of the span a handed clock reading is weighed in, in whole Unix seconds.
 *
 * The lower end is the first ten-digit Unix second, and the upper is the last a four-byte Unix counter
 * states before it rolls over. Between them lies every instant this format can be asked to stamp, on
 * either side of any window it is asked to run, and the same instant spelled in milliseconds lies outside
 * them by a factor of a thousand: `1772000000` read as seconds is a receipt of this estate and read as
 * milliseconds is a day in 1970, while `1772000000000` read as milliseconds is that same receipt's own
 * instant and read as seconds is a date past the counter these stamps are counted on.
 *
 * A band rather than a comparison, because the mistake this refuses has already been made in this
 * estate: a reader that fell back to a seconds figure while its parameter was named for milliseconds
 * answered with a verdict about the receipt when the only thing wrong was the unit of the argument.
 * Refusing the reading is what makes that visible at the entry rather than downstream, and it is why
 * the ends are stated in the message rather than left for the caller to guess.
 */
const EARLIEST_VERIFICATION_SECONDS = 1_000_000_000;
const LATEST_VERIFICATION_SECONDS = 4_294_967_295;

/**
 * The one question asked of a handed `nowSeconds`, answered before either window runs.
 *
 * Nothing here decides which unit the number came from; the band does that by excluding the other
 * unit's magnitude, which is why a caller handing a plausible reading is never met by a second guess
 * about what they meant to write.
 */
function assertVerificationSeconds(handed: number): void {
  if (
    !Number.isSafeInteger(handed) ||
    handed < EARLIEST_VERIFICATION_SECONDS ||
    handed > LATEST_VERIFICATION_SECONDS
  ) {
    throw new ReceiptError(
      'VERIFICATION_TIME_OUT_OF_RANGE',
      `a verification time of ${String(handed)} is not a whole number of Unix seconds between ${String(
        EARLIEST_VERIFICATION_SECONDS,
      )} and ${String(LATEST_VERIFICATION_SECONDS)}: hand the instant in whole seconds, or hand nothing and the host clock is read`,
    );
  }
}

export function verifyReceipt(bytes: Uint8Array, options: VerifyOptions): VerifiedReceipt {
  let cose: CoseSign1 & { header: ProtectedHeader };
  if (options.publicKey) {
    cose = verifyCoseSign1(bytes, options.publicKey);
  } else if (options.resolveKey) {
    cose = decodeCoseSign1(bytes);
    const key = options.resolveKey(cose.header.kid);
    if (!key) throw new ReceiptError('UNKNOWN_KEY');
    cose = verifyCoseSign1(bytes, key);
  } else {
    throw new ReceiptError('UNKNOWN_KEY', 'no publicKey or resolveKey provided');
  }
  // After the signature check, so a document nobody has signed cannot get a version answer out of
  // this package at all.
  const payload = parsePayload(cose.payloadBytes, options.acceptedVersions ?? ACCEPTED_BY_DEFAULT);

  if (options.expectedNonce && !equalBytes(payload.nce, options.expectedNonce)) {
    throw new ReceiptError('NONCE_MISMATCH');
  }
  // The reading is asked its question where it is taken up: after the checks the document itself owes,
  // and before either window weighs it. A caller who handed a number that is not a reading of a
  // seconds counter hears that, rather than hearing `STALE_RECEIPT` from a subtraction between two
  // scales, which is the wrong verdict this refusal exists to keep off the honest path.
  const handed = options.nowSeconds;
  if (handed !== undefined) assertVerificationSeconds(handed);
  const nowSeconds = handed ?? Math.floor(Date.now() / 1000);
  if (options.freshnessSeconds !== undefined && Math.abs(nowSeconds - payload.iat) > options.freshnessSeconds) {
    throw new ReceiptError('STALE_RECEIPT');
  }
  if (
    options.evidenceFreshnessSeconds !== undefined &&
    Math.abs(nowSeconds - payload.att.ts) > options.evidenceFreshnessSeconds
  ) {
    throw new ReceiptError('STALE_EVIDENCE');
  }
  return { payload, header: cose.header, cose };
}

export function hashRequest(canonicalRequest: Uint8Array): Uint8Array {
  return sha256(canonicalRequest);
}

export function randomNonce(): Uint8Array {
  const c = (globalThis as { crypto?: { getRandomValues(a: Uint8Array): Uint8Array } }).crypto;
  if (!c) throw new Error('crypto.getRandomValues is unavailable in this environment');
  const nonce = new Uint8Array(16);
  c.getRandomValues(nonce);
  return nonce;
}
