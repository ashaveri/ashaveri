import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha2.js';
import { Tag } from 'cbor2';
import { decodeCanonical, decodeClosedDocument, decodedMap, encodeCanonical } from './cbor.js';
import {
  ALG_EDDSA,
  COSE_HEADER_ALG,
  COSE_HEADER_CONTENT_TYPE,
  COSE_HEADER_KID,
  COSE_SIGN1_TAG,
  buildProtectedHeader,
  equalBytes,
  keyId,
  sealCoseSign1,
  type CoseSign1,
  type ProtectedHeader,
  type SigningKey,
} from './cose.js';
import { ReceiptError } from './errors.js';
import { readJsonBytes, type JsonObject } from './json-text.js';
import type { PackSpan } from './pack.js';
import { parseRetentionDocument, RETENTION_FILE_NAME_SET, type RetentionManifest } from './retention.js';

/**
 * The epoch inventory, read and written: what `packages/receipt/epoch-inventory.cddl` states, run.
 *
 * A deployment retires receipts out of its live store on a bound it configures, and an evidence epoch is what
 * survives that: a directory holding one sealed pack and one retention artifact per closed window, and one
 * document at its root stating what the run covers, what each pack in it says, and what the run adds up to.
 * That document is this container. It is the only artifact of a closed epoch a reviewer can be handed alone,
 * so everything in it is a figure the reviewer can re-derive from the packs beside it, and everything this
 * reader refuses is a place where the document's own statements do not agree with each other.
 *
 * It is a checker and not a verdict engine, in three specific ways. It answers nothing about a legal duty:
 * `duty.short` lists the packs whose own two integers fall short and `duty.carried` is the arithmetic of that
 * list, and whether either figure was owed turns on the mapping a revision names and on the law behind it,
 * which this package does not interpret. It establishes nothing about the packs it describes, because it is
 * not handed them: the two digests of each entry, the item count and the chain endpoints a pack signs are
 * restated here, and a reader that wanted them proven reads the pack files with `verifyPack` and compares.
 * And it decides nothing about freshness: `at` per pack is that pack's own assembly stamp, restated.
 *
 * It resolves nothing either. Every key arrives as an argument and no code path here reaches a filesystem, a
 * network or a key directory, so a reviewer holding one file and one key can run this. That is the point of
 * publishing the layout at all: an inventory a stranger cannot check without a service in the loop is a
 * receipt of the deployment's own word, and a document whose reader is named `verify` while checking only
 * structure would be the false statement this estate refuses to publish.
 *
 * The two entry points split where the run's arithmetic sits. `decodeEpochInventory` answers shape with no
 * key at all: the envelope, the content type, the JSON reading of the payload, every member's type and width,
 * the label's bound, and the contradictions inside a single entry. `verifyEpochInventory` answers the
 * envelope, the key, the signature and the run, and the run is in that order on purpose. The figures a
 * document folds across its entries are the substance of what it attests about a deployment's store, and a
 * reader that reported them before deciding whether anybody signed them would be handing out a verdict about
 * unauthenticated bytes. The same ordering rule is why the content type is answered before any resolver is
 * consulted: an inventory's payload and a pack's manifest are two documents that both pass their own checks,
 * and the confusion is not recoverable afterwards.
 *
 * A fourth statement is folded when a caller hands the run's retention artifacts beside the document, under
 * `presence`: the interval across which the store reported holding the appraisal context. It is folded rather
 * than stored, and the inventory gains no member for it, because the interval is the arithmetic of documents
 * the signature does not carry and a figure restated from evidence that is not in the document would be a
 * second owner of one fact. The split between the two artifacts is what each can attest alone: the retention
 * manifest states which collateral and validity digests one store held at one instant and carries no copy of
 * any of those bytes, and this document states which manifests the run seals and what its packs add up to, and
 * says nothing about what any store held. Neither is read as the other, and the fold is where a reader that
 * holds both finds out whether the period the inventory attests is a period the material was there: a gap
 * inside it, an observation arriving under a digest no entry of the run seals, and a stated window wider than
 * the observations support are each refused by name. Where the fold would need the material itself to say more
 * than that it was once held, it refuses on the digest and stops, because whether those bytes are replicated
 * per pack, held once and named, or shipped in a bundle is a decision this format does not make.
 *
 * The writer is `encodeEpochInventoryManifest`, `encodeEpochInventoryProtectedHeader`,
 * `sealEpochInventory` and `signEpochInventory`, the four pieces the other containers publish. The payload is
 * JSON, and unlike a pack's manifest it is signed as the bytes the writer chose rather than as a canonical
 * re-rendering: a document that is handed over as a file is verified against the bytes of that file, so the
 * serializer below is a convenience to a writer and not a rule a reader can insist on. `signEpochInventory`
 * parses and runs its own checks before it signs, so a writer cannot seal an inventory whose run does not
 * add up, and a document meant to be refused, which is what a conformance vector is, is assembled from the
 * four pieces rather than through it.
 */

/** The content type that keeps an inventory from being read as a pack, at label 3. */
export const EPOCH_INVENTORY_CONTENT_TYPE = 'ashaveri/epoch-inventory';

/**
 * The three labels `epoch-inventory.cddl` declares for a signed inventory header, exported for the same
 * reason `cose.ts` exports its own list: which labels exist is the format's answer, and only a reader of both
 * the file and this list can see that the two are one answer.
 */
export const DECLARED_EPOCH_INVENTORY_PROTECTED_LABELS: readonly number[] = [
  COSE_HEADER_ALG,
  COSE_HEADER_CONTENT_TYPE,
  COSE_HEADER_KID,
];

/**
 * The member lists of every map this format closes, in the order the CDDL declares them. Exported for a test
 * to hold against the blocks rather than against this file's reading of them, and exported from this module
 * alone: the package's public surface gains the reader and the writer, not a roster.
 */
export const EPOCH_INVENTORY_MANIFEST_MEMBERS = ['v', 'epoch', 'manifest', 'packs', 'window', 'chain', 'duty'] as const;
export const EPOCH_INVENTORY_DEPLOYMENT_MEMBERS = ['iss', 'ins', 'epk'] as const;
export const EPOCH_INVENTORY_PACK_MEMBERS = ['file', 'retention', 'sha256', 'retentionSha256', 'at', 'span', 'items', 'chain', 'kid', 'duty'] as const;
export const EPOCH_INVENTORY_SPAN_MEMBERS = ['from', 'to'] as const;
export const EPOCH_INVENTORY_PACK_CHAIN_MEMBERS = ['anchor', 'head'] as const;
export const EPOCH_INVENTORY_PACK_DUTY_MEMBERS = ['art', 'rev', 'required', 'held'] as const;
export const EPOCH_INVENTORY_CHAIN_MEMBERS = ['anchor', 'head', 'continuous', 'breaks'] as const;
export const EPOCH_INVENTORY_BREAK_MEMBERS = ['file', 'afterHead', 'anchor'] as const;
export const EPOCH_INVENTORY_DUTY_MEMBERS = ['carried', 'short'] as const;
export const EPOCH_INVENTORY_SHORT_MEMBERS = ['file', 'art', 'required', 'held', 'shortBy'] as const;

/**
 * Where the packs of a run live inside an epoch directory, and what the two files of one pack home are
 * called. The inventory states each entry's location in its directory, so these names are part of the layout a
 * reader checks a path against rather than a convention a writer picked: an entry whose `file` is not
 * `packs/<its own digest>/pack-v1.cbor` names a place that does not hold the pack it describes.
 *
 * The retention name is a set rather than a string, and the set is the retention layouts this package reads.
 * A single spelling here is the version-set defect in its quietest form: the reader would refuse a run whose
 * manifests moved to the newer layout as a malformed path, every published vector of the older spelling would
 * stay green because none of them reads a manifest, and the fold would report nothing about a store that had
 * said plenty. The name carries the version of the layout filed under it, which is what a writer states about the
 * file rather than the gate a reader answers at: the path is checked against this set, and the document inside it
 * is read through `parseRetentionDocument`, which answers for its own `v` and not for the name it arrived under.
 * An entry filed under the newer name and holding the older document is read as the older document, which states
 * no observation, rather than as a directory this layout does not describe.
 */
export const EPOCH_INVENTORY_PACKS_DIRECTORY = 'packs';
export const EPOCH_INVENTORY_PACK_FILE = 'pack-v1.cbor';
export const EPOCH_INVENTORY_RETENTION_FILES = RETENTION_FILE_NAME_SET;

/** The bound the run's label carries, which is the width it is printed at beside the run in every report. */
export const EPOCH_INVENTORY_LABEL_MAX_BYTES = 200;

/** The deployment manifest whose `keys` list named the keys this run was resolved against. */
export interface EpochInventoryDeployment {
  readonly iss: string;
  readonly ins: string;
  readonly epk: number;
}

/** One pack of the run, as the inventory states it. Every field is read from that pack or hashed from its file. */
export interface EpochInventoryPack {
  /** Relative to the epoch directory, with forward slashes: `packs/<digest>/pack-v1.cbor`. */
  readonly file: string;
  readonly retention: string;
  /** sha256 over the whole sealed pack document, the designation a redaction of that pack names it by. */
  readonly sha256: string;
  /** sha256 over the retention artifact's bytes as they sit on the volume. */
  readonly retentionSha256: string;
  readonly at: number;
  readonly span: PackSpan;
  readonly items: number;
  readonly chain: { readonly anchor: string; readonly head: string };
  /** The key this pack was sealed with, as its own protected header names it, hex. */
  readonly kid: string;
  /** The four integers the pack signs. A conclusion is not one of them and is not added here. */
  readonly duty: { readonly art: string; readonly rev: number; readonly required: number; readonly held: number };
}

/** One place where a pack's anchor is not the head before it, stated as the two digests that disagree. */
export interface EpochInventoryBreak {
  readonly file: string;
  readonly afterHead: string;
  readonly anchor: string;
}

/** One pack whose held period falls short of the period that same pack states as required. */
export interface EpochInventoryShort {
  readonly file: string;
  readonly art: string;
  readonly required: number;
  readonly held: number;
  readonly shortBy: number;
}

export interface EpochInventoryManifest {
  readonly v: 1;
  /** The operator's label for the run. It identifies the artifact and decides nothing in it. */
  readonly epoch: string;
  readonly manifest: EpochInventoryDeployment;
  readonly packs: readonly EpochInventoryPack[];
  /** The period the sealed run covers, folded from the windows the packs themselves state. */
  readonly window: PackSpan;
  readonly chain: {
    readonly anchor: string;
    readonly head: string;
    /** Whether each pack's anchor is the head before it, which is what lets a reader chain the run itself. */
    readonly continuous: boolean;
    /**
     * Where it is not, one row per such pair and each row keyed by the pack that failed to continue, with the
     * head it should have continued and the anchor it carries. The order the rows are written in bears nothing,
     * as it bears nothing in `packs`, because a reader matches every row to the pair its own `file` fixes. A
     * break is reported and not explained away: the two digests are the evidence, and what happened between
     * them is a fact about a deployment's store rather than about this document.
     */
    readonly breaks: readonly EpochInventoryBreak[];
  };
  readonly duty: {
    readonly carried: boolean;
    readonly short: readonly EpochInventoryShort[];
  };
}

/**
 * How a caller hands this reader the key an inventory's seal is checked against. The two fields are the two
 * shapes a caller's key material arrives in, as `PackVerifyOptions` states them: a `publicKey` is the one key
 * the caller means, and a `resolveKey` is asked for the kid the header carries, which is how a caller holding
 * the epochs a deployment retained reads an inventory whose run was sealed across a rotation. Which key an
 * inventory was sealed with, and where the caller got it, are the caller's facts; nothing here authenticates
 * a key.
 */
export interface EpochInventoryVerifyOptions {
  readonly publicKey?: Uint8Array;
  readonly resolveKey?: (kid: Uint8Array) => Uint8Array | undefined;
  /**
   * The retention artifacts of the run, each as the bytes that sit on the volume, for the fold of section
   * "The presence fold" below. The list is what a caller hands and this reader resolves nothing, so it is the
   * caller's job to hand every artifact the entries name: an entry whose manifest was not handed leaves its
   * window uncovered, and uncovered inside the period the document states is a refusal rather than a shorter
   * answer. Nothing in a manifest is believed because a caller produced it: each artifact is hashed and the
   * digest has to be one of the `retentionSha256` figures this very document carries inside its signature, so
   * a manifest handed on its own, or handed twice, or sealed by two entries at once, is refused before a
   * member of it is read.
   */
  readonly presence?: readonly Uint8Array[];
}

export interface DecodedEpochInventory {
  readonly manifest: EpochInventoryManifest;
  readonly header: ProtectedHeader;
  readonly envelope: CoseSign1;
}

/**
 * What the run is, as the reader put it together rather than as the document listed it. `packs` is the whole
 * inventory array ordered by the run's own rule, which is the only order the document's figures support:
 * position in `packs` carries no claim, exactly as it carries none in a pack's items. A caller that prints
 * this prints what the reader chained, and a caller that prints `manifest.packs` prints what arrived, and the
 * two are the same entries either way.
 */
export interface EpochInventoryRun {
  readonly packs: readonly EpochInventoryPack[];
  /**
   * The interval the presence observations support, when the caller handed artifacts to fold. Absent is not a
   * finding of nothing: it is the call that handed none, which is a reader of this document alone and answers
   * no question about held material. Where it is present, the interval is the arithmetic of the observations,
   * it is no wider than the document's own `window`, and the two digests of every named document are listed
   * with it so that a caller prints which material the period is a period for.
   */
  readonly presence?: EpochInventoryPresence;
}

/**
 * The period across which the run's own observations attest that named material was present, and the digests
 * they named. `from` and `to` are the outer edges of the *observations*, which is where the fold differs from
 * `window`: the window is the period the packs sealed, and this is the period the store said it held the
 * appraisal context across. The two agree or the document is refused, because a run that states one and attests
 * the other is claiming a reach it cannot show.
 *
 * The two lists are every digest whose own stretch covers the interval, sorted, so a caller reading this gets
 * the roster the interval is about rather than a count of it. A digest that names nothing here was never named
 * by a sealed observation of this run, which is what makes the interval a statement about this run and not
 * about a deployment's volume.
 */
export interface EpochInventoryPresence {
  readonly from: number;
  readonly to: number;
  /** How many of the run's entries contributed an observation, which is never more than it has. */
  readonly observations: number;
  readonly collateral: readonly string[];
  readonly validity: readonly string[];
}

export interface VerifiedEpochInventory extends DecodedEpochInventory {
  readonly outcome: EpochInventoryRun;
}

const text = new TextEncoder();

/** The widths the format writes beside each position, named once rather than per check site. */
const SIGNATURE_BYTES = 64;

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (one) => one.toString(16).padStart(2, '0')).join('');
}

function malformedCbor(detail: string): ReceiptError {
  return new ReceiptError('EPOCH_INVENTORY_MALFORMED_CBOR', detail);
}

function badHeader(detail: string): ReceiptError {
  return new ReceiptError('EPOCH_INVENTORY_BAD_HEADER', detail);
}

function malformedJson(detail: string): ReceiptError {
  return new ReceiptError('EPOCH_INVENTORY_MALFORMED_JSON', detail);
}

function badDocument(detail: string): ReceiptError {
  return new ReceiptError('EPOCH_INVENTORY_BAD_DOCUMENT', detail);
}

function summaryDisagrees(detail: string): ReceiptError {
  return new ReceiptError('EPOCH_INVENTORY_SUMMARY_DISAGREES', detail);
}

// ---------------------------------------------------------------------------
// The payload's JSON reading.
//
// The envelope is CBOR and the document inside it is JSON, which is the deployment manifest's arrangement and
// for the manifest's reason: the file a reviewer is handed is a JSON file, and the only way a verdict means
// something about the bytes read is for the signature to cover those bytes rather than a rendering of them.
//
// That reading is a format rule rather than a detail of one parser, and it is stated once, in `json-text.ts`,
// where the retention manifest's copy of the same document shape is read under it too: `JSON.parse` throws away
// the two facts this format states, a member named twice and a float wearing an integer, and both are settled
// while the characters are still distinguishable, exactly as `decodeClosedDocument` settles them for a CBOR
// document.
// ---------------------------------------------------------------------------

function decodePayload(bytes: Uint8Array): unknown {
  return readJsonBytes(bytes, (detail) => {
    throw malformedJson(detail);
  });
}

// ---------------------------------------------------------------------------
// The member reads. Each answers one position, and the refusal names the position as a reader of the
// document would write it: `packs[1].duty.required`. Nothing here decides which of the two readings a value
// takes, and nothing here reaches past the document to a pack, a store or a clock.
// ---------------------------------------------------------------------------

function readMap(value: unknown, position: string): JsonObject {
  const map = decodedMap(value);
  if (map === null) throw badDocument(`${position} is not an object`);
  return map;
}

/**
 * The closure rule, over one map and then the maps it opens, as `pack.cddl` and `redaction.cddl` state it: a
 * member this version does not define makes the document malformed rather than a member a reader agreed to
 * forget. A value the format makes an array of maps is closed at its elements by the reader of that array,
 * because the member list behind `packs` is an entry's and not the array's.
 *
 * The name is quoted through `JSON.stringify` because it lands inside a refusal and a member name is text
 * somebody else chose: `ReceiptError` bounds the detail, and this keeps an odd name to one line and visible
 * exactly as the document wrote it.
 */
interface DefinedMap {
  readonly members: readonly string[];
  readonly nested?: Readonly<Record<string, DefinedMap>>;
}

function assertDefined(raw: JsonObject, members: readonly string[], where: string, nested: Readonly<Record<string, DefinedMap>> = {}): void {
  for (const [key, value] of raw) {
    if (typeof key !== 'string' || !members.includes(key)) {
      throw badDocument(`${where} carries a member this version does not define: ${JSON.stringify(String(key))}`);
    }
    const arm = nested[key];
    if (arm === undefined) continue;
    const inner = decodedMap(value);
    // A value the format makes an object and is not one is the member read's answer, not this walk's:
    // refusing it here would report a membership problem at a position whose type has not been read.
    if (inner !== null) assertDefined(inner, arm.members, `${where}.${key}`, arm.nested);
  }
}

/**
 * Text this container copies rather than writes: a string, and not an empty one, and bounded no further. The
 * three positions read here, `manifest.iss`, `manifest.ins` and a `duty.art`, come out of documents this
 * format describes and does not author, and each of those declares its own floor with no ceiling beside it:
 * the deployment manifest states a minimum length for its two ids and no maximum, and `pack.cddl` types a
 * duty label as a bare `tstr` that its own reader asks nothing about but being text. A ceiling stated on this
 * side would refuse an inventory over a manifest the deployment published and a pack that pack format seals,
 * which is the one thing a layout written to describe artifacts already in the field may not do.
 */
function requireText(value: unknown, position: string): string {
  if (typeof value !== 'string') throw badDocument(`${position} must be a string`);
  if (text.encode(value).length < 1) throw badDocument(`${position} must be a string of at least one byte`);
  return value;
}

/**
 * The run's label, bounded the way the format states it: printable text that a report can print beside the
 * run it names. Control characters, the two line separators and a byte order mark are refused because they
 * would end the printed row rather than because they are rare, and leading or trailing space because the
 * label is quoted by nothing around it.
 *
 * This scan is the read side's, and it is not the writer's. `assertLineSafeText` in `src/receipt.ts`
 * refuses the attested text members of a payload at the step that signs them, and it refuses a wider set:
 * every Unicode format character and the tag block beside the ranges named above, which are the characters
 * that hide a line or reorder it rather than end one. The two stay apart because what each is asked about
 * is not one question: this one bounds a label a caller reads out of somebody else's document, with a byte
 * ceiling beside it, and that ceiling and that code are not the writer's to take, while widening this scan
 * to the writer's set would change which inventories this package accepts. Neither is a general text rule
 * and neither is merged into the other; a later edit that reaches for one of the two should read the other
 * before choosing.
 */
function requireLabel(value: unknown, position: string): string {
  const label = requireText(value, position);
  const bytes = text.encode(label).length;
  if (bytes > EPOCH_INVENTORY_LABEL_MAX_BYTES) {
    throw badDocument(`${position} must be at most ${String(EPOCH_INVENTORY_LABEL_MAX_BYTES)} bytes, got ${bytes}`);
  }
  if (label !== label.trim()) {
    throw badDocument(`${position} carries leading or trailing space, and it is printed beside the run unpadded`);
  }
  for (const character of label) {
    const code = character.codePointAt(0) ?? 0;
    if (code < 0x20 || (code >= 0x7f && code <= 0x9f) || code === 0x2028 || code === 0x2029 || code === 0xfeff) {
      throw badDocument(`${position} carries the code point ${code.toString(16)}, which is not printable text`);
    }
  }
  return label;
}

/**
 * A unix second, a count or an epoch number: a whole number no smaller than zero, and nothing else. The two
 * questions left to a figure by the time it reaches here are its type and its sign. Whether the token was an
 * integer spelling at all, and whether a reader holds the value exactly, were both answered where the
 * characters were still distinguishable, and `scanNumber` refuses them under `EPOCH_INVENTORY_MALFORMED_JSON`:
 * nothing that passes the reading can fail them again here.
 */
function requireFigure(value: unknown, position: string): number {
  if (typeof value !== 'number' || value < 0) {
    throw badDocument(`${position} must be a whole number no smaller than zero`);
  }
  return value;
}

/** A digest, stated the way the document states every one of them: sixty-four lowercase hex characters. */
function requireDigest(value: unknown, position: string): string {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/u.test(value)) {
    throw badDocument(`${position} must be sixty-four lowercase hex characters`);
  }
  return value;
}

function requireFlag(value: unknown, position: string): boolean {
  if (typeof value !== 'boolean') throw badDocument(`${position} must be true or false`);
  return value;
}

/**
 * A pack's location inside the epoch directory: `packs/<digest>/<file>`, with forward slashes wherever the
 * run is read. The pattern is the layout and the digest inside it is a designation, so the two reads answer
 * different questions and are refused apart. A path of another shape is a malformed document, because no
 * position of this layout holds a free string. A path of the right shape is a claim about where the bytes are
 * filed, and an entry that files one pack under another pack's digest points a reader at bytes that are not
 * the ones it describes, which is the fault a reviewer has to be told by name rather than in a sentence about
 * shape. The same pattern bounds a `breaks` or `short` row's `file`, because those name an entry of the run
 * and an entry is filed exactly once.
 *
 * `fileNames` is the set a position may be filed under, and it is one per position rather than one for the
 * document: a pack is one layout and its retention companion is whichever of the two retention layouts the run
 * was written with. A caller that passed the pair for the pack's own name would accept an entry filed under a
 * pack format this document does not describe.
 */
interface PackHome {
  readonly path: string;
  readonly digest: string;
}

function readPackHome(value: unknown, position: string, fileNames: readonly string[]): PackHome {
  if (typeof value !== 'string') throw badDocument(`${position} must be a string`);
  const directory = `${EPOCH_INVENTORY_PACKS_DIRECTORY}/`;
  const matched = fileNames.map((one) => ({ name: one, tail: `/${one}` })).find((one) => value.endsWith(one.tail));
  if (!value.startsWith(directory) || matched === undefined) {
    throw badDocument(`${position} must be ${directory}<digest>/${fileNames.join(' or ')}`);
  }
  const digest = value.slice(directory.length, value.length - matched.tail.length);
  if (!/^[0-9a-f]{64}$/u.test(digest)) {
    throw badDocument(`${position} names a directory that is not sixty-four lowercase hex characters`);
  }
  return { path: value, digest };
}

/** One entry's own location, checked against the digest the same entry states. */
function readPackPath(
  value: unknown,
  position: string,
  fileNames: readonly string[],
  sha256: string,
  where: string,
): string {
  const home = readPackHome(value, position, fileNames);
  if (home.digest !== sha256) {
    throw new ReceiptError('EPOCH_INVENTORY_PACK_MISNAMED', `${where} states the pack ${sha256} and is filed as ${home.path}`);
  }
  return home.path;
}

function readSpan(value: unknown, position: string): PackSpan {
  const span = readMap(value, position);
  assertDefined(span, EPOCH_INVENTORY_SPAN_MEMBERS, position);
  return { from: requireFigure(span.get('from'), `${position}.from`), to: requireFigure(span.get('to'), `${position}.to`) };
}

function readPack(value: unknown, position: string): EpochInventoryPack {
  const entry = readMap(value, position);
  assertDefined(entry, EPOCH_INVENTORY_PACK_MEMBERS, position, {
    span: { members: EPOCH_INVENTORY_SPAN_MEMBERS },
    chain: { members: EPOCH_INVENTORY_PACK_CHAIN_MEMBERS },
    duty: { members: EPOCH_INVENTORY_PACK_DUTY_MEMBERS },
  });
  const sha256 = requireDigest(entry.get('sha256'), `${position}.sha256`);
  const chain = readMap(entry.get('chain'), `${position}.chain`);
  const duty = readMap(entry.get('duty'), `${position}.duty`);
  return {
    file: readPackPath(entry.get('file'), `${position}.file`, [EPOCH_INVENTORY_PACK_FILE], sha256, position),
    retention: readPackPath(
      entry.get('retention'),
      `${position}.retention`,
      EPOCH_INVENTORY_RETENTION_FILES,
      sha256,
      position,
    ),
    sha256,
    retentionSha256: requireDigest(entry.get('retentionSha256'), `${position}.retentionSha256`),
    at: requireFigure(entry.get('at'), `${position}.at`),
    span: readSpan(entry.get('span'), `${position}.span`),
    items: requireFigure(entry.get('items'), `${position}.items`),
    chain: {
      anchor: requireDigest(chain.get('anchor'), `${position}.chain.anchor`),
      head: requireDigest(chain.get('head'), `${position}.chain.head`),
    },
    kid: requireDigest(entry.get('kid'), `${position}.kid`),
    duty: {
      art: requireText(duty.get('art'), `${position}.duty.art`),
      rev: requireFigure(duty.get('rev'), `${position}.duty.rev`),
      required: requireFigure(duty.get('required'), `${position}.duty.required`),
      held: requireFigure(duty.get('held'), `${position}.duty.held`),
    },
  };
}

/**
 * The entries, and the two name rules that hold across them.
 *
 * `[+]` requires at least one pack, and the reason is not tidiness: an inventory of no packs states a window
 * no pack covers, names two chain endpoints no pack chained, and carries a `duty` block that reports having
 * carried nothing. A document whose own figures are vacuous reads as evidence while attesting no receipt,
 * which is the same refusal `pack.cddl` arrives at for an empty items array.
 *
 * Two entries answering to one digest are the same pack counted twice, and every fold below is computed over
 * the list: a run that names one pack twice states a longer epoch than the directory holds and reports one
 * window from the same window twice. A digest is also an entry's location, since the path is built from it, so
 * one name is enough to refuse by, and a duplicate is refused here rather than reported by whichever of the
 * two a reader happened to meet first.
 */
function readPacks(value: unknown): readonly EpochInventoryPack[] {
  if (!Array.isArray(value)) throw badDocument('packs must be an array');
  if (value.length === 0) {
    throw badDocument('an inventory of no packs states no window, names no chain and carries no duty');
  }
  const packs = value.map((one, index) => readPack(one, `packs[${String(index)}]`));
  const filed = new Map<string, string>();
  for (const one of packs) {
    if (filed.has(one.sha256)) {
      throw new ReceiptError('EPOCH_INVENTORY_DUPLICATE_PACK', `${one.sha256} is held twice, at ${one.file} and at ${filed.get(one.sha256)}`);
    }
    filed.set(one.sha256, one.file);
  }
  return packs;
}

function readBreaks(value: unknown): readonly EpochInventoryBreak[] {
  if (!Array.isArray(value)) throw badDocument('chain.breaks must be an array');
  return value.map((one, index) => {
    const position = `chain.breaks[${String(index)}]`;
    const raw = readMap(one, position);
    assertDefined(raw, EPOCH_INVENTORY_BREAK_MEMBERS, position);
    return {
      file: readPackHome(raw.get('file'), `${position}.file`, [EPOCH_INVENTORY_PACK_FILE]).path,
      afterHead: requireDigest(raw.get('afterHead'), `${position}.afterHead`),
      anchor: requireDigest(raw.get('anchor'), `${position}.anchor`),
    };
  });
}

function readShort(value: unknown): readonly EpochInventoryShort[] {
  if (!Array.isArray(value)) throw badDocument('duty.short must be an array');
  return value.map((one, index) => {
    const position = `duty.short[${String(index)}]`;
    const raw = readMap(one, position);
    assertDefined(raw, EPOCH_INVENTORY_SHORT_MEMBERS, position);
    return {
      file: readPackHome(raw.get('file'), `${position}.file`, [EPOCH_INVENTORY_PACK_FILE]).path,
      art: requireText(raw.get('art'), `${position}.art`),
      required: requireFigure(raw.get('required'), `${position}.required`),
      held: requireFigure(raw.get('held'), `${position}.held`),
      shortBy: requireFigure(raw.get('shortBy'), `${position}.shortBy`),
    };
  });
}

function parseManifest(payload: Uint8Array): EpochInventoryManifest {
  const raw = readMap(decodePayload(payload), 'manifest');
  // The reading has already refused a `v` written as anything but an integer a reader holds exactly, so the one
  // question left to this position is whether the member is a number at all rather than a name or a flag.
  const version = raw.get('v');
  if (typeof version !== 'number') {
    throw badDocument('v must be an integer inventory version');
  }
  if (version !== 1) {
    throw new ReceiptError('EPOCH_INVENTORY_UNSUPPORTED_VERSION', `epoch inventory version ${version} is not a format this package reads`);
  }
  assertDefined(raw, EPOCH_INVENTORY_MANIFEST_MEMBERS, 'manifest', {
    manifest: { members: EPOCH_INVENTORY_DEPLOYMENT_MEMBERS },
    window: { members: EPOCH_INVENTORY_SPAN_MEMBERS },
    chain: { members: EPOCH_INVENTORY_CHAIN_MEMBERS },
    duty: { members: EPOCH_INVENTORY_DUTY_MEMBERS },
  });
  const deployment = readMap(raw.get('manifest'), 'manifest');
  const chain = readMap(raw.get('chain'), 'chain');
  const duty = readMap(raw.get('duty'), 'duty');
  return {
    v: 1,
    epoch: requireLabel(raw.get('epoch'), 'epoch'),
    manifest: {
      iss: requireText(deployment.get('iss'), 'manifest.iss'),
      ins: requireText(deployment.get('ins'), 'manifest.ins'),
      epk: requireFigure(deployment.get('epk'), 'manifest.epk'),
    },
    packs: readPacks(raw.get('packs')),
    window: readSpan(raw.get('window'), 'window'),
    chain: {
      anchor: requireDigest(chain.get('anchor'), 'chain.anchor'),
      head: requireDigest(chain.get('head'), 'chain.head'),
      continuous: requireFlag(chain.get('continuous'), 'chain.continuous'),
      breaks: readBreaks(chain.get('breaks')),
    },
    duty: {
      carried: requireFlag(duty.get('carried'), 'duty.carried'),
      short: readShort(duty.get('short')),
    },
  };
}

// ---------------------------------------------------------------------------
// The run, and the arithmetic a reader does over it.
//
// Three statements are folded from the packs and then restated inside the signature: the window the run
// covers, whether the packs chain into each other, and whether each pack's held period reaches the period
// that same pack states as required. Restating them is what makes the artifact readable at a glance, and it
// is also what makes it refusable: a document whose fold does not match its own entries is contradicting
// itself, and a reviewer who had to do the arithmetic to find out would have had to trust the arithmetic to
// notice. So the reader does it and refuses the disagreement by name.
//
// The order of the run is the first of those statements, and it is derived rather than believed. The entries
// are placed by the start of their window, then by the instant their pack was assembled, then by their own
// digest, which is a total order over a document whose digests are unique. Position in the array bears
// nothing, exactly as position bears nothing in a pack's items, so a run listed in another order is the same
// run and a reader that read the list as an order would be reporting on whichever way the file happened to
// come.
// ---------------------------------------------------------------------------

/** The run's own order, computed rather than taken from the array. */
function runOrder(packs: readonly EpochInventoryPack[]): EpochInventoryPack[] {
  return [...packs].sort(
    (a, b) =>
      a.span.from - b.span.from ||
      a.at - b.at ||
      (a.sha256 < b.sha256 ? -1 : a.sha256 > b.sha256 ? 1 : 0),
  );
}

/** The two digests that disagree about where a pack should have continued the run. */
function breakOf(one: EpochInventoryPack, previous: EpochInventoryPack): EpochInventoryBreak {
  return { file: one.file, afterHead: previous.chain.head, anchor: one.chain.anchor };
}

/** One pack's own two integers, and the subtraction that says they do not meet. */
function shortfallOf(one: EpochInventoryPack): EpochInventoryShort {
  return {
    file: one.file,
    art: one.duty.art,
    required: one.duty.required,
    held: one.duty.held,
    shortBy: one.duty.required - one.duty.held,
  };
}

function byFile(run: readonly EpochInventoryPack[]): Map<string, EpochInventoryPack> {
  return new Map(run.map((one) => [one.file, one]));
}

/**
 * The chain claim, in both directions, against the breaks the run itself has in it.
 *
 * Each pair of neighbours either continues the run or is listed with the two digests that disagree, and the
 * listing has to be the one the pair supports: a break smoothed into `continuous` is the false statement this
 * block exists to catch, and one named where the two digests meet is the same lie the other way round. A
 * stated break is matched by the pack it names rather than by its position, because a document that listed its
 * breaks in another order states the same run.
 *
 * So the stated rows have to name exactly the packs the run breaks at, and that is three questions answered
 * together below: no name stated by two rows, the count of rows against the count of breaks, and each row
 * about the pair its own `file` fixes. The count alone is not the set: two rows naming one pack keep it right
 * while the second row is answered by the entry the first already settled, so a run that breaks twice can be
 * stated as breaking once and the break nobody named is never looked at. Refusing a repeated name is what
 * makes a repeat and an omission one fault rather than one fault and one pass.
 */
function assertBreakClaim(
  manifest: EpochInventoryManifest,
  run: readonly EpochInventoryPack[],
  expected: Map<string, EpochInventoryBreak>,
): void {
  const stated = manifest.chain.breaks;
  if (manifest.chain.continuous !== (stated.length === 0)) {
    throw summaryDisagrees(`chain.continuous says ${String(manifest.chain.continuous)} beside ${String(stated.length)} stated break(s)`);
  }
  if (stated.length !== expected.size) {
    throw summaryDisagrees(
      `the run of ${String(run.length)} pack(s) has ${String(expected.size)} break(s) in it and the document states ${String(stated.length)}`,
    );
  }
  // Reached only where the counts already agree, which is what makes the next sentence a finding rather
  // than a guess: rows naming fewer packs than there are rows, in a list as long as the fold, leave some
  // pack of the run unnamed somewhere else in it.
  const named = new Set(stated.map((one) => one.file));
  if (named.size !== stated.length) {
    throw summaryDisagrees(
      `chain.breaks states ${String(stated.length)} rows naming ${String(named.size)} distinct packs, so one break is stated twice and the pack it left out is named nowhere in the list`,
    );
  }
  const held = byFile(run);
  for (const [index, one] of stated.entries()) {
    const wanted = expected.get(one.file);
    if (wanted === undefined) {
      throw new ReceiptError(
        'EPOCH_INVENTORY_PACK_UNNAMED',
        `chain.breaks[${String(index)}] names ${one.file}, which the run ${held.has(one.file) ? 'holds without a break between it and its predecessor' : 'does not hold at all'}`,
      );
    }
    if (one.afterHead !== wanted.afterHead || one.anchor !== wanted.anchor) {
      throw summaryDisagrees(
        `chain.breaks[${String(index)}] states ${one.afterHead} to ${one.anchor} beside ${one.file} and the two packs of the run state ${wanted.afterHead} to ${wanted.anchor}`,
      );
    }
  }
}

/**
 * The duty claim, pack by pack and in both directions. Each entry's two integers are compared with each other
 * and never with a neighbour's, so a routed article's period is not read against another article's figure and
 * a run whose declarations differ reports each on its own terms. `shortBy` is the subtraction, `carried` is
 * the emptiness of the list, and a shortfall named against a pack the run does not hold is refused by name.
 * The rows are matched by the pack they name and not by their position, so, as with the breaks, the stated
 * names have to be exactly the folded ones: two rows naming one pack hold the count right and answer the
 * second row out of the entry the first already settled, which is a shortfall of this run the document never
 * states. What is not here is a judgement: `held` short of `required` is lawful output, and whether it was owed
 * at all turns on the mapping the revision names and on the law behind it.
 */
function assertShortClaim(
  manifest: EpochInventoryManifest,
  run: readonly EpochInventoryPack[],
  expected: Map<string, EpochInventoryShort>,
): void {
  const stated = manifest.duty.short;
  if (manifest.duty.carried !== (stated.length === 0)) {
    throw summaryDisagrees(`duty.carried says ${String(manifest.duty.carried)} beside ${String(stated.length)} stated shortfall(s)`);
  }
  if (stated.length !== expected.size) {
    throw summaryDisagrees(
      `the run of ${String(run.length)} pack(s) has ${String(expected.size)} shortfall(s) in it and the document states ${String(stated.length)}`,
    );
  }
  // As above: the counts agree by the time this reads, so a collapsed name set is an omission as well as a
  // repetition, and the sentence says both because the guard can now prove both.
  const named = new Set(stated.map((one) => one.file));
  if (named.size !== stated.length) {
    throw summaryDisagrees(
      `duty.short states ${String(stated.length)} rows naming ${String(named.size)} distinct packs, so one shortfall is stated twice and the pack it left out is named nowhere in the list`,
    );
  }
  const held = byFile(run);
  for (const [index, one] of stated.entries()) {
    const wanted = expected.get(one.file);
    if (wanted === undefined) {
      throw new ReceiptError(
        'EPOCH_INVENTORY_PACK_UNNAMED',
        `duty.short[${String(index)}] names ${one.file}, which the run ${held.has(one.file) ? 'holds without a shortfall in it' : 'does not hold at all'}`,
      );
    }
    if (one.art !== wanted.art || one.required !== wanted.required || one.held !== wanted.held || one.shortBy !== wanted.shortBy) {
      throw summaryDisagrees(
        `duty.short[${String(index)}] states ${one.art} requiring ${String(one.required)} and holding ${String(one.held)}, short by ${String(one.shortBy)}, and ${one.file} states ${wanted.art} requiring ${String(wanted.required)} and holding ${String(wanted.held)}`,
      );
    }
  }
}

/**
 * The period the run covers: the outer edges of the windows the packs themselves state, which with the
 * windows meeting where the run is walked are the start of the first and the end of the last. Folded across
 * the entries and not over a position, so the answer cannot depend on how the array arrived, and folded one
 * entry at a time rather than by handing both edges to a spread call: `packs` is bounded by a floor and
 * nothing else, so a run long enough to overflow an argument list would otherwise answer a reader's question
 * with a `RangeError` standing where this comparison promises a code. The two seeds are the identities of the
 * two folds, and a run with nothing in it was refused where the entries were read.
 */
function assertWindow(manifest: EpochInventoryManifest, run: readonly EpochInventoryPack[]): void {
  const from = run.reduce((lowest, one) => Math.min(lowest, one.span.from), Number.POSITIVE_INFINITY);
  const to = run.reduce((latest, one) => Math.max(latest, one.span.to), Number.NEGATIVE_INFINITY);
  if (manifest.window.from !== from || manifest.window.to !== to) {
    throw summaryDisagrees(`window is ${manifest.window.from} to ${manifest.window.to} and the run reaches ${from} to ${to}`);
  }
}

/**
 * The run as a whole, in one ordered walk: the windows, then the two folds the document restates about them.
 *
 * A gap is a period this epoch states it attests and does not, and an overlap seals the same receipts twice
 * under two signatures, so both are refused rather than smoothed into a window that hides which of the two
 * the reader met. A pack whose own window does not run forwards is refused by the same check and named as
 * itself: it can meet neither a predecessor nor a successor.
 *
 * The three findings share one code, and an operator reading the line has to be told which one it is, because
 * the remedies differ: a gap is missing evidence and an overlap is the same receipts under two signatures. So
 * each of the three details opens with the words naming its finding, ahead of the two pack paths that say
 * which pair it is about. A detail is quoted to the reader up to a bound, and these three carry two full paths,
 * which is more than the bound lets through: a finding named at the end of such a sentence is a finding nobody
 * reads. The paths stay, because which pair is the other half of what a reader is owed, and what is cut is the
 * rest of the sentence rather than the part that says what was found.
 *
 * The two endpoints of the run are the anchor the walk begins from and the head of the pack that ends it, so
 * they are compared where the walk reaches each of them, and the window is compared afterwards because it is
 * the statement the contiguity of the windows makes decidable.
 */
function assertRun(manifest: EpochInventoryManifest): readonly EpochInventoryPack[] {
  const run = runOrder(manifest.packs);
  const breaks = new Map<string, EpochInventoryBreak>();
  const short = new Map<string, EpochInventoryShort>();
  let previous: EpochInventoryPack | undefined;
  for (const [index, one] of run.entries()) {
    if (one.span.to <= one.span.from) {
      throw new ReceiptError(
        'EPOCH_INVENTORY_RUN_NOT_CONTIGUOUS',
        `an entry whose own window does not run forwards: ${one.file} states the window ${one.span.from} to ${one.span.to}, so it can meet no neighbour`,
      );
    }
    if (previous === undefined) {
      if (manifest.chain.anchor !== one.chain.anchor) {
        throw summaryDisagrees(`chain.anchor is ${manifest.chain.anchor} and the run begins at ${one.file}, chained from ${one.chain.anchor}`);
      }
    } else {
      if (one.span.from !== previous.span.to) {
        const overlapped = one.span.from < previous.span.to;
        throw new ReceiptError(
          'EPOCH_INVENTORY_RUN_NOT_CONTIGUOUS',
          `${overlapped ? 'a window sealed twice' : 'a window left out of the run'}: ` +
            `${previous.file} closes at ${previous.span.to} and ${one.file} begins at ${one.span.from}, so the run ` +
            (overlapped ? 'seals the receipts between them twice' : 'attests a period it does not seal'),
        );
      }
      if (one.chain.anchor !== previous.chain.head) breaks.set(one.file, breakOf(one, previous));
    }
    if (index === run.length - 1 && manifest.chain.head !== one.chain.head) {
      throw summaryDisagrees(`chain.head is ${manifest.chain.head} and the run ends at ${one.file}, whose chain leaves ${one.chain.head}`);
    }
    if (one.duty.held < one.duty.required) short.set(one.file, shortfallOf(one));
    previous = one;
  }
  assertWindow(manifest, run);
  assertBreakClaim(manifest, run, breaks);
  assertShortClaim(manifest, run, short);
  return run;
}

// ---------------------------------------------------------------------------
// The presence fold.
//
// A retention manifest states, for the instant it stamped, which collateral and validity documents the store
// held. Those are statements about single instants, and a reviewer's question is about a period: was the
// material an anchor names there the whole way across the run this inventory attests? The fold answers it the
// way the three summaries above answer theirs, in the shape `duty.short` already uses: the entries state, the
// reader recomputes, a restatement that is not the arithmetic of the entries is refused, and the guard's own
// sentence is what tells two faults sharing one code apart.
//
// Two rules make it evidence rather than a transcript. First, an artifact is admitted only under a digest this
// document's own signature seals: the manifest is unsigned by design and the pack carries no digest of it, so
// `packs[].retentionSha256`, inside the inventory's COSE_Sign1, is the only thing here that tells a fold which
// files belong to the run. A manifest handed over on its own is refused by name, and this is the constraint the
// layout's own header states: an inventory is a checker, not a verifier of the bytes beside it. Second, nothing
// here reads the material the observations name. Whether a collateral digest resolves to bytes a reader can
// fetch is the volume question of a different task, and where this fold needed bytes it is not given, it refuses
// on the digest rather than assuming they are somewhere.
//
// The arithmetic then runs digest by digest. A digest's stretch is the run's entries naming it, and because the
// windows of a run meet end to start, a stretch that skips an entry is a period the document states it attests
// and no observation covers: the material left and came back, or the store stopped reporting it, or the caller
// handed one manifest too few. Each of those is missing evidence and is refused as one. A digest's attested
// interval is the outer edges of its stretch, and the run's interval is the intersection over the digests named,
// because the claim being folded is about the appraisal context as a whole rather than about whichever document
// happened to be held longest. That interval is then compared with the period the document states: a run whose
// first or last window carries no observation is stating a period wider than its observations support, which is
// the third refusal, and a fold with nothing to intersect states no period at all and is refused the same way.
// ---------------------------------------------------------------------------

/** The two families the fold reads, in the order the layout declares them. */
const PRESENCE_FAMILIES = ['collateral', 'validity'] as const;

function presenceDigest(digest: string, family: (typeof PRESENCE_FAMILIES)[number]): string {
  return `${family}:${digest}`;
}

/**
 * One digest's stretch: the run-order positions of the entries that name it, and the first and last of those
 * entries themselves. The two entries travel with the positions because the guard's sentence names the packs it
 * is about, and a reader that had to look an entry up by position to say which ones it meant would be making a
 * claim about the run's order rather than about the two places it actually read. `to` and `toIndex` move as the
 * walk goes forwards, which is the only difference between them and the two fields beside them.
 */
interface Stretch {
  readonly named: Set<number>;
  readonly from: EpochInventoryPack;
  readonly fromIndex: number;
  to: EpochInventoryPack;
  toIndex: number;
}

/**
 * The run's presence interval, out of the manifests a caller handed beside the document.
 *
 * The three refusals this reaches are named in the fixed sentence and opened in the detail, in the words that
 * say which finding it is, because a detail is quoted to a reader up to a bound and a finding named past the cut
 * is a finding nobody can act on. The bound runs over two pack paths and one digest easily, so each detail below
 * begins with the words that separate it from its siblings rather than with a digest or a path.
 */
function foldPresence(
  manifest: EpochInventoryManifest,
  run: readonly EpochInventoryPack[],
  artifacts: readonly Uint8Array[],
): EpochInventoryPresence {
  // The digests this document seals, each against the entries that state it. Two entries stating one digest is
  // one store state claimed for two windows, and an observation arriving under it belongs to neither.
  const sealed = new Map<string, EpochInventoryPack[]>();
  for (const one of run) {
    sealed.set(one.retentionSha256, [...(sealed.get(one.retentionSha256) ?? []), one]);
  }
  const observed = new Map<string, RetentionManifest>();
  const handed = new Set<string>();
  for (const bytes of artifacts) {
    const digest = toHex(sha256(bytes));
    const holders = sealed.get(digest) ?? [];
    const [holder] = holders;
    if (holder === undefined) {
      throw new ReceiptError(
        'EPOCH_INVENTORY_PRESENCE_UNSEALED',
        `no entry of the run seals ${digest}, so this manifest is the deployment's own report and folds as nothing`,
      );
    }
    if (holders.length > 1) {
      const [first, second] = holders as [EpochInventoryPack, EpochInventoryPack];
      throw new ReceiptError(
        'EPOCH_INVENTORY_PRESENCE_UNSEALED',
        `sealed twice: ${digest} is stated by ${first.file} and by ${second.file}, so the observation names no pack it belongs to`,
      );
    }
    if (handed.has(digest)) {
      throw new ReceiptError(
        'EPOCH_INVENTORY_PRESENCE_UNSEALED',
        `handed twice: ${digest} is the manifest the run seals once, and folding it twice counts one pack's observation as two`,
      );
    }
    handed.add(digest);
    observed.set(holder.file, parseRetentionDocument(bytes));
  }

  // Which entries name which digest, in the run's own order. A version one manifest contributes nothing, which is
  // the honest reading: it states no observation, so no period of its window is attested by it.
  const stretches = new Map<string, Stretch>();
  let observations = 0;
  for (const [index, one] of run.entries()) {
    const document = observed.get(one.file);
    if (document === undefined || document.v !== 2) continue;
    observations += 1;
    for (const family of PRESENCE_FAMILIES) {
      for (const held of document.presence[family].held) {
        const key = presenceDigest(held.sha256, family);
        const seen = stretches.get(key);
        if (seen === undefined) {
          stretches.set(key, { named: new Set([index]), from: one, to: one, fromIndex: index, toIndex: index });
        } else {
          seen.named.add(index);
          seen.to = one;
          seen.toIndex = index;
        }
      }
    }
  }
  if (stretches.size === 0) {
    throw new ReceiptError(
      'EPOCH_INVENTORY_PRESENCE_WINDOW_TOO_WIDE',
      `the run states the window ${String(manifest.window.from)} to ${String(manifest.window.to)} and its observations name no digest at all, so nothing is attested across any of it`,
    );
  }

  let from = Number.NEGATIVE_INFINITY;
  let to = Number.POSITIVE_INFINITY;
  for (const [key, stretch] of stretches) {
    // A digest named at two places of the run and absent from a place between them. The windows meet end to
    // start, so that place is inside the period the document states it attests, and the interval the fold owes
    // cannot be drawn across a stretch of it no sealed observation speaks for.
    for (const [index, entry] of run.entries()) {
      if (index <= stretch.fromIndex || index >= stretch.toIndex) continue;
      if (stretch.named.has(index)) continue;
      const family = key.slice(0, key.indexOf(':'));
      throw new ReceiptError(
        'EPOCH_INVENTORY_PRESENCE_GAP',
        `${family} digest ${key.slice(family.length + 1)} is missing from ${entry.file} between the two places that name it, ${stretch.from.file} and ${stretch.to.file}, so the run states a period it does not attest`,
      );
    }
    from = Math.max(from, stretch.from.span.from);
    to = Math.min(to, stretch.to.span.to);
  }
  if (manifest.window.from !== from || manifest.window.to !== to) {
    throw new ReceiptError(
      'EPOCH_INVENTORY_PRESENCE_WINDOW_TOO_WIDE',
      `the run states the window ${String(manifest.window.from)} to ${String(manifest.window.to)} and its observations attest ${String(from)} to ${String(to)}, so the stated period is wider than the evidence for it`,
    );
  }
  const roster = (family: (typeof PRESENCE_FAMILIES)[number]): string[] =>
    [...stretches.keys()]
      .filter((key) => key.startsWith(`${family}:`))
      .map((key) => key.slice(family.length + 1))
      .sort();
  return { from, to, observations, collateral: roster('collateral'), validity: roster('validity') };
}

// ---------------------------------------------------------------------------
// The envelope. Every signed document in this estate is framed the same way and differs in label 3 alone, so
// the framing below is the shared one and only the content type is this container's own.
// ---------------------------------------------------------------------------

/**
 * The whole `Sig_structure` of this container, exactly as RFC 9052 section 4.4 frames it and as the pack and
 * the export frame theirs: the context string, the protected bstr, the external AAD and the payload bstr,
 * canonically encoded. It is published because the bytes a signature covers are the whole contract of a COSE
 * document, and a reimplementer who cannot see them cannot compare two implementations' refusals. The payload
 * goes in as the bytes the writer chose, which for a JSON document is the whole of the point.
 */
export function epochInventorySigStructure(
  protectedBytes: Uint8Array,
  payloadBytes: Uint8Array,
  externalAad: Uint8Array = new Uint8Array(0),
): Uint8Array {
  return encodeCanonical(['Signature1', protectedBytes, externalAad, payloadBytes]);
}

/**
 * The signed header, carrying the content type the caller means it to carry. Which three labels exist and how
 * they encode is the receipt's answer; this format's own contribution is the name in label 3, so the builder
 * is shared and only that name is passed. The argument exists for the one caller who needs a header naming
 * something else, which is a document assembled to be refused: no honest inventory writes another type, and
 * the reader answers this position before it consults a key.
 */
export function encodeEpochInventoryProtectedHeader(
  kid: Uint8Array,
  contentType: string = EPOCH_INVENTORY_CONTENT_TYPE,
): Uint8Array {
  return buildProtectedHeader(kid, contentType);
}

/**
 * The four elements of a `COSE_Sign1-Epoch-Inventory-COSE`, tagged, as the format writes them. The
 * `unprotected` map is the one a signer fills at will and this reader reads nothing out of, so it is an
 * argument rather than a fixed empty map.
 */
export function sealEpochInventory(
  protectedBytes: Uint8Array,
  payloadBytes: Uint8Array,
  signature: Uint8Array,
  unprotected: Map<unknown, unknown> = new Map(),
): Uint8Array {
  return sealCoseSign1(protectedBytes, payloadBytes, signature, unprotected);
}

/**
 * The document as a file: two-space indented, newline terminated, in the field order the type declares. This
 * is a rendering and not a rule. The signature covers the bytes handed to `sealEpochInventory`, so a writer
 * that chose another indentation signed a different inventory, and a reader that compared two documents'
 * figures rather than their bytes cannot tell the two apart.
 */
export function encodeEpochInventoryManifest(manifest: EpochInventoryManifest): Uint8Array {
  return text.encode(`${JSON.stringify(manifest, null, 2)}\n`);
}

/**
 * Sign an inventory.
 *
 * The document is encoded, run back through this module's own parser and its own arithmetic, and only then
 * sealed, because a writer that produced bytes its own reader refuses has made a document that cannot be
 * handed over: a run whose windows leave a gap, a chain claim that smooths a break over and a duty list that
 * disagrees with the packs beside it are each refused where the bytes are made, under the code the reader
 * would have answered with, before a signature fixes them. A caller who wants to hand a reader a document
 * that is *meant* to be refused, which is what a conformance vector is, assembles it from the four pieces
 * above rather than through this function.
 *
 * The retention artifacts are the optional third argument, and where they are handed the fold runs here too: a
 * writer that states a window its own sealed observations do not attest would be sealing a claim about reach
 * that its reader refuses, and the place to catch that is before the signature rather than after it. Where they
 * are not handed, nothing about reach is claimed and the seal is the document's own arithmetic.
 *
 * The key is checked as the pack's seal checks its own: `kid` has to be sha256 of the public half travelling
 * beside it, because an inventory whose key no reader can resolve is bytes with a signature on them.
 */
export function signEpochInventory(
  manifest: EpochInventoryManifest,
  key: SigningKey,
  presence?: readonly Uint8Array[],
): Uint8Array {
  if (key.kid.length !== 32 || key.privateKey.length !== 32 || key.publicKey.length !== 32) {
    throw new ReceiptError('BAD_SIGNING_KEY', 'an inventory signing key is a 32-byte Ed25519 key and a 32-byte kid');
  }
  if (!equalBytes(keyId(key.publicKey), key.kid)) {
    throw new ReceiptError('BAD_SIGNING_KEY', 'the kid of an inventory signing key is sha256 of its public key');
  }
  const payloadBytes = encodeEpochInventoryManifest(manifest);
  const parsed = parseManifest(payloadBytes);
  const run = assertRun(parsed);
  if (presence !== undefined) foldPresence(parsed, run, presence);
  const protectedBytes = encodeEpochInventoryProtectedHeader(key.kid);
  const signature = ed25519.sign(epochInventorySigStructure(protectedBytes, payloadBytes), key.privateKey);
  return sealEpochInventory(protectedBytes, payloadBytes, signature);
}

function readHeader(bytes: Uint8Array): ProtectedHeader {
  // Decoded under the rule the format sets for this map, which closes its labels as well as its values: a
  // label written as the float `1.0` takes the same map slot as the integer `1`, so the two spellings are
  // indistinguishable by the time anything could ask which one the issuer signed.
  const raw = decodedMap(decodeClosedDocument(bytes, 'EPOCH_INVENTORY_BAD_HEADER'));
  if (raw === null) throw badHeader('not a map');
  for (const label of raw.keys()) {
    if (!(DECLARED_EPOCH_INVENTORY_PROTECTED_LABELS as readonly unknown[]).includes(label)) {
      throw badHeader(`it carries a label the format does not define: ${String(label)}`);
    }
  }
  // Before the key parameters and before anything of the payload, refused whatever else the document holds:
  // the payload of an inventory and the payload of a pack are two documents that both pass their own checks,
  // and the one mistake a content type exists to prevent is reading the second as the first.
  const contentType = raw.get(COSE_HEADER_CONTENT_TYPE);
  if (typeof contentType !== 'string') throw badHeader(`typ must be a tstr, got ${typeof contentType}`);
  if (contentType !== EPOCH_INVENTORY_CONTENT_TYPE) throw badHeader(`typ=${contentType}`);
  const alg = raw.get(COSE_HEADER_ALG);
  if (typeof alg !== 'number') throw new ReceiptError('UNSUPPORTED_ALG', `alg must be an integer label, got ${typeof alg}`);
  if (alg !== ALG_EDDSA) throw new ReceiptError('UNSUPPORTED_ALG', `alg=${alg}`);
  const kid = raw.get(COSE_HEADER_KID);
  if (!(kid instanceof Uint8Array) || kid.length !== 32) throw badHeader('kid must be a 32-byte bstr');
  return { alg: ALG_EDDSA, kid, contentType };
}

function readEnvelope(bytes: Uint8Array): CoseSign1 & { header: ProtectedHeader } {
  let top: unknown;
  try {
    top = decodeCanonical(bytes);
  } catch (reason) {
    throw malformedCbor(reason instanceof Error ? reason.message : String(reason));
  }
  if (!(top instanceof Tag) || top.tag !== COSE_SIGN1_TAG) {
    throw new ReceiptError('NOT_COSE_SIGN1', 'missing CBOR tag 18');
  }
  const elements = top.contents;
  if (!Array.isArray(elements) || elements.length !== 4) throw new ReceiptError('NOT_COSE_SIGN1', 'not a 4-element array');
  const [protectedBytes, unprotectedMap, payloadBytes, signature] = elements as unknown[];
  if (!(protectedBytes instanceof Uint8Array)) throw new ReceiptError('NOT_COSE_SIGN1', 'protected is not a bstr');
  const unprotected = decodedMap(unprotectedMap);
  if (unprotected === null) throw new ReceiptError('NOT_COSE_SIGN1', 'unprotected is not a map');
  if (!(payloadBytes instanceof Uint8Array)) throw new ReceiptError('NOT_COSE_SIGN1', 'payload is not a bstr');
  if (!(signature instanceof Uint8Array) || signature.length !== SIGNATURE_BYTES) {
    throw new ReceiptError('NOT_COSE_SIGN1', `signature is not a ${SIGNATURE_BYTES}-byte bstr`);
  }
  return { protectedBytes, unprotected, payloadBytes, signature, header: readHeader(protectedBytes) };
}

/**
 * A document read and a signature not yet checked: the envelope, the content type, the JSON reading of the
 * payload, and every member's shape, width and bound, including the two name rules that hold across the
 * entries. None of it needs a key to be true, so a document that contradicts itself is refused whoever signed
 * it, and a caller that only wants to know which of the files in a bundle are inventories can ask that here.
 * The arithmetic across the run is not answered in this function, which is the split `verifyEpochInventory`
 * documents.
 */
export function decodeEpochInventory(bytes: Uint8Array): DecodedEpochInventory {
  const envelope = readEnvelope(bytes);
  return { manifest: parseManifest(envelope.payloadBytes), header: envelope.header, envelope };
}

/**
 * The key an inventory verifies under, from whichever of the two designations the caller used, on the rule
 * `pack.ts` states: a `publicKey` that names another kid is the disagreement rather than a second choice, a
 * resolver that answers nothing is refused by name rather than guessed at with some other key the caller
 * owns, and a key a resolver hands back that hashes to another kid is the same disagreement reached through
 * the other door.
 */
function inventoryKey(kid: Uint8Array, options: EpochInventoryVerifyOptions): Uint8Array {
  const designated = options.publicKey !== undefined ? options.publicKey : options.resolveKey?.(kid);
  if (designated === undefined) {
    throw new ReceiptError('EPOCH_INVENTORY_UNKNOWN_KEY', `header kid=${toHex(kid)}`);
  }
  const expected = keyId(designated);
  if (!equalBytes(kid, expected)) {
    throw new ReceiptError('EPOCH_INVENTORY_KID_MISMATCH', `header kid=${toHex(kid)} key kid=${toHex(expected)}`);
  }
  return designated;
}

/**
 * Verify an inventory: the envelope, the key, the signature and the run.
 *
 * The order is what keeps a report honest. A call naming no key is refused before a byte is read, because
 * that fault is in the call and not in the document, and answering a document question about bytes nobody
 * has been given the key to check would send an operator to the inventory rather than to their own
 * configuration. The content type is answered before any resolver is consulted: a document that is not an
 * inventory must not reach a caller's key set. The signature comes before the payload's shape, and the shape
 * before the run's arithmetic, because a manifest under an unchecked signature is the writer's say-so and the
 * arithmetic is the part of it that makes claims about a deployment's store.
 *
 * What this answers and what it does not are two different things, and `outcome` says so. The run the reader
 * returns is the document's own entries in the order its figures put them, and nothing here shows that the
 * digests in it are digests of files that exist, that the packs they name are sealed by the keys their
 * entries give, that `items` is the count of receipts inside any of them, or that the run is all the epochs
 * the deployment closed. Those are a reader's next checks, made with `verifyPack` over the pack files and
 * with whatever the deployment published about its rotations, and `docs/epoch-inventory-v1.md` states the
 * list so that a reviewer reading a passing verdict knows what it leaves open.
 */
export function verifyEpochInventory(
  bytes: Uint8Array,
  options: EpochInventoryVerifyOptions,
): VerifiedEpochInventory {
  if (options.publicKey === undefined && options.resolveKey === undefined) {
    throw new ReceiptError('EPOCH_INVENTORY_UNKNOWN_KEY', 'no publicKey or resolveKey provided');
  }
  const envelope = readEnvelope(bytes);
  const publicKey = inventoryKey(envelope.header.kid, options);
  if (
    !ed25519.verify(
      envelope.signature,
      epochInventorySigStructure(envelope.protectedBytes, envelope.payloadBytes),
      publicKey,
      { zip215: false },
    )
  ) {
    throw new ReceiptError('INVALID_SIGNATURE');
  }
  const manifest = parseManifest(envelope.payloadBytes);
  const packs = assertRun(manifest);
  const presence = options.presence === undefined ? undefined : foldPresence(manifest, packs, options.presence);
  return { manifest, header: envelope.header, envelope, outcome: { packs, ...(presence === undefined ? {} : { presence }) } };
}
