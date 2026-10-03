import { sha256 } from '@noble/hashes/sha2.js';
import {
  decodeCanonical,
  decodeReceipt,
  emptyRegion,
  encodeCanonical,
  encodePayload,
  frameResponse,
  issueReceipt,
  receiptToJson,
  signCoseSign1,
  toBase64Url,
  type CollateralSlot,
  type CollateralValidityAnchor,
  type ItemStamp,
  type MarkingScheme,
  type ReceiptPayload,
  type StampDisclosure,
} from '@ashaveri/receipt';
import { writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { labeled } from './seed.ts';
import {
  markedBuffered,
  markedSentinelOnly,
  markedStreamed,
  sentinelOnlyStream,
  unmarkedResponse,
  unmarkedStream,
} from './marking-shapes.ts';
import { FIXED_IAT, FIXTURE_RESPONSE, fixtureKey, fixturePayload } from './receipt-envelope.ts';

const DATA = join(dirname(fileURLToPath(import.meta.url)), '..', 'data');

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

const text = (value: string): Uint8Array => new TextEncoder().encode(value);

/**
 * One response a published receipt attests, beside the piece of this package's own output those bytes
 * already appear in.
 *
 * Nothing here invents a body. Every byte string below is published by another suite of this package, and
 * `test/fixtures.test.ts` reads each row's bytes back out of the suite its `response` column names and
 * refuses the row if the two disagree, so the response a receipt speaks of and the response a port is
 * handed are one file's fact and not two. The assembled row is the one a reader rebuilds instead: it
 * states the published pieces it joined, in the order they were written.
 */
interface ResponseShape {
  readonly name: string;
  /** Where these bytes are published already, as `<file>#<vector>`, or `assembled#` for a joined pair. */
  readonly response: string;
  /** The published pieces an assembled row is joined from, in the order they were written. */
  readonly assembledFrom?: readonly string[];
  readonly contentType: string;
  /** Which marking setting these bytes came off, which is what decides how many items they frame. */
  readonly marking: MarkingScheme;
  readonly bytes: Uint8Array;
  /** The span `mk.d` digests: the marked region, or the empty region a `none` document names. */
  readonly region: Uint8Array;
}

const MARKED_STREAM = markedStreamed();
const MARKED_BODY = markedBuffered();
const SENTINEL_MARK = markedSentinelOnly();

const SHAPES: Record<string, ResponseShape> = {
  'stream-unmarked': {
    name: 'stream-unmarked',
    response: 'marking-v1.json#streamed-region-stripped',
    contentType: 'text/event-stream',
    marking: 'none',
    bytes: text(unmarkedStream()),
    region: emptyRegion(),
  },
  'stream-marked': {
    name: 'stream-marked',
    response: 'marking-v1.json#streamed-frame',
    contentType: 'text/event-stream',
    marking: 'provenance-v1',
    bytes: text(MARKED_STREAM.response),
    region: text(MARKED_STREAM.region),
  },
  'body-unmarked': {
    name: 'body-unmarked',
    response: 'marking-v1.json#absence-declared',
    contentType: 'application/json',
    marking: 'none',
    bytes: text(unmarkedResponse()),
    region: emptyRegion(),
  },
  'body-marked': {
    name: 'body-marked',
    response: 'marking-v1.json#buffered-member',
    contentType: 'application/json',
    marking: 'provenance-v1',
    bytes: text(MARKED_BODY.response),
    region: text(MARKED_BODY.region),
  },
  'sentinel-unmarked': {
    name: 'sentinel-unmarked',
    response: 'res-v1.json#framing.terminator',
    contentType: 'text/event-stream',
    marking: 'none',
    bytes: text(sentinelOnlyStream()),
    region: emptyRegion(),
  },
  'sentinel-marked': {
    name: 'sentinel-marked',
    response: 'assembled#marking-frame-then-terminator',
    assembledFrom: [
      'marking-v1.json#streamed-frame.region',
      'res-v1.json#framing.frameSeparator',
      'res-v1.json#framing.terminator',
    ],
    contentType: 'text/event-stream',
    marking: 'provenance-v1',
    bytes: text(SENTINEL_MARK.response),
    region: text(SENTINEL_MARK.region),
  },
};

/**
 * The disclosure of a source that admits how far its readings can stand from the instants they name.
 *
 * `host clock` at `uncertaintySeconds: null` is the shipped answer for a deployment that wired no source,
 * so the measured one below is the other half of the pair: the same two fields, one of which a process
 * can only fill by wiring something that knows its own error. Which of the two a row carries is that
 * row's `sd` column, on the bytes, and not a sentence beside them.
 */
const MEASURED_SOURCE: StampDisclosure = { name: 'ptp-disciplined host clock', uncertaintySeconds: 1 };
const UNMEASURED_SOURCE: StampDisclosure = { name: 'host clock', uncertaintySeconds: null };

const HELD_COLLATERAL: CollateralSlot = { presence: 'held', sha256: labeled('ashaveri-fixtures/collateral/v1') };
const HELD_VALIDITY: CollateralSlot = {
  presence: 'held',
  sha256: labeled('ashaveri-fixtures/validity-context/v1'),
};
const COLLATERAL_NOT_ISSUED: CollateralSlot = {
  presence: 'absent-at-source',
  reason:
    'the appraisal this receipt was issued from ran on collateral its source reports as never having been ' +
    'issued, and no byte of it reached this record',
};
const COLLATERAL_NOT_TAKEN_IN: CollateralSlot = {
  presence: 'not-taken-in',
  reason:
    'this issuer takes no collateral into the record it signs with: it is handed an evidence document, its ' +
    'stamp and a url, and nothing chained to that document, and no collector beside it holds the vendor ' +
    'chain an appraisal of those bytes would run on',
};
const VALIDITY_NOT_TAKEN_IN: CollateralSlot = {
  presence: 'not-taken-in',
  reason:
    'this issuer records no validity context at issuance: nothing in it appraises the evidence whose digest ' +
    'it signs, so no window was put into this record, and whether one stood open at the instant this receipt ' +
    'was stamped is a fact this process never looked at; the appraisal that needs one belongs to a verifier, ' +
    'run afterwards against bytes this document only digests',
};
/** The other arm's absence at its source: the window this appraisal would have run under, never issued. */
const VALIDITY_NOT_ISSUED: CollateralSlot = {
  presence: 'absent-at-source',
  reason:
    'the appraisal this receipt was issued from ran under no validity context its source reports as issued: ' +
    'the window it would have been appraised inside was never published, and no byte of one reached this record',
};

const ANCHOR_HELD_BOTH: CollateralValidityAnchor = { collateral: HELD_COLLATERAL, validity: HELD_VALIDITY };
const ANCHOR_HELD_AND_ABSENT: CollateralValidityAnchor = {
  collateral: HELD_COLLATERAL,
  validity: COLLATERAL_NOT_ISSUED,
};
const ANCHOR_NOT_TAKEN_IN: CollateralValidityAnchor = {
  collateral: COLLATERAL_NOT_TAKEN_IN,
  validity: VALIDITY_NOT_TAKEN_IN,
};
/** The anchor the refusal rows are built out of: one slot of each arm, so both closures are reachable. */
const ANCHOR_ONE_OF_EACH: CollateralValidityAnchor = {
  collateral: HELD_COLLATERAL,
  validity: COLLATERAL_NOT_TAKEN_IN,
};
/** The mirror position of the pair above, so the demand is seen to read both slots and not one name. */
const ANCHOR_COLLATERAL_ABSENT: CollateralValidityAnchor = {
  collateral: COLLATERAL_NOT_ISSUED,
  validity: HELD_VALIDITY,
};
/** Both slots stating the world's absence, the third shape a demand of one refuses for its own reason. */
const ANCHOR_BOTH_ABSENT_AT_SOURCE: CollateralValidityAnchor = {
  collateral: COLLATERAL_NOT_ISSUED,
  validity: VALIDITY_NOT_ISSUED,
};

/**
 * One row's anchor postures, spelled as a port reads them.
 *
 * A reading is the policy field's own name beside the number an operator would write, and the verdict the
 * client path gives the document under it. `null` is the policy that names no demand, which is the posture
 * every row in this suite has always been read in, so a row states it beside the two that ask: a column
 * that carried only the refusing postures would hide the one that must not move.
 *
 * The verdicts are written at each call site by whoever states the row, and are not computed here from the
 * anchor's slots. A generator that derived the answer from the same arithmetic the shipped check uses could
 * disagree with it in nothing, and the published column would record this file rather than the code.
 */
function handover(
  readings: readonly (readonly [demand: number | null, verdict: string])[],
): Array<{ minAnchorSlotsHeld: number | null; verdict: string }> {
  return readings.map(([demand, verdict]) => ({ minAnchorSlotsHeld: demand, verdict }));
}

/** The three postures `minAnchorSlotsHeld` can be in, stated in this order by every row that states any. */
const POSTURES = [null, 1, 2] as const;

/** The readings for an anchor's two slots, one verdict per posture, in the order every row states them. */
function handoverFor(verdicts: readonly [none: string, one: string, two: string]): ReturnType<typeof handover> {
  const [none, one, two] = verdicts;
  // The postures come off `POSTURES`, which is the order every row states them in, and the verdicts off
  // the tuple beside them, which is what makes three readings and not two a condition of writing this
  // row at all. An index into either would be a number this file would have to keep true by itself.
  return handover([
    [POSTURES[0], none] as const,
    [POSTURES[1], one] as const,
    [POSTURES[2], two] as const,
  ]);
}

/**
 * The item stamps of one response, taken the way the format says they are taken.
 *
 * Every `d` comes off `frameResponse`, the shipped reader of a response body and the same code a verifier
 * runs over the bytes it holds, so an item list published here is the list that reader gives those bytes
 * rather than a description of one. Every `t` comes off the source the row names in `sd`, read once per
 * item in the order the items were framed: `FIXED_IAT` less the item count, then one second per item, so
 * the last reading is the second before the receipt's own instant and no reading is that instant. The
 * sequence is a property of the item count and of the stated source alone, so these bytes cannot freeze a
 * transport accident.
 */
function itemStamps(shape: ResponseShape): ItemStamp[] {
  const framing = frameResponse(shape.contentType, shape.bytes);
  if (!framing.framed) {
    throw new Error(`${shape.name}: the shipped reader frames no item out of these bytes`);
  }
  const first = FIXED_IAT - framing.items.length;
  return framing.items.map((one, index) => ({ t: first + index, d: one.d }));
}

/**
 * The document a published row is made of: the one version this format declares, its twelve shared fields
 * over these bytes, and the four members a receipt states about itself. `mk` is read off the response
 * shape, because which marking these bytes came off is a fact of the bytes; the disclosure, the anchor and
 * the item list are what the row names, because a document that left one of them out is one the writer
 * refuses to make and the reader refuses to open.
 */
function payloadFor(
  shape: ResponseShape,
  over: { sd: StampDisclosure; cva: CollateralValidityAnchor; itm: readonly ItemStamp[] },
): ReceiptPayload {
  return {
    ...fixturePayload({ res: sha256(shape.bytes) }),
    v: 1,
    mk: { sch: shape.marking, d: sha256(shape.region) },
    sd: over.sd,
    cva: over.cva,
    itm: over.itm,
  };
}

/** The columns a row states about the document it publishes. */
interface RowColumns {
  [key: string]: unknown;
  readonly keyless: string;
  readonly v: 1;
  readonly marking: MarkingScheme;
  readonly contentType: string;
  readonly response: string;
  readonly assembledFrom?: readonly string[];
  readonly responseBase64Url: string;
  readonly responseByteLength: number;
  readonly items?: Array<{ t: number; d: string; bytesBase64Url: string; byteLength: number }>;
  readonly sd?: { name: string; unc?: number | null };
  readonly cva?: { col: { p: string; d?: string; r?: string }; val: { p: string; d?: string; r?: string } };
  readonly handover?: Array<{ minAnchorSlotsHeld: number | null; verdict: string }>;
  readonly fault?: { at: string; member?: string; states: string };
}

/** The item list as a row states it: each instant, each digest, and the bytes that digest is of. */
function itemColumns(shape: ResponseShape, stamps: readonly ItemStamp[]): RowColumns['items'] {
  const framing = frameResponse(shape.contentType, shape.bytes);
  if (!framing.framed) throw new Error(`${shape.name}: these bytes frame no item to publish beside them`);
  if (framing.items.length !== stamps.length) {
    throw new Error(`${shape.name}: the row states ${String(stamps.length)} items and these bytes frame ${String(framing.items.length)}`);
  }
  return stamps.map((one, index) => ({
    t: one.t,
    d: toHex(one.d),
    bytesBase64Url: toBase64Url(framing.items[index]!.bytes),
    byteLength: framing.items[index]!.bytes.length,
  }));
}

function slotColumn(slot: CollateralSlot): { p: string; d?: string; r?: string } {
  return slot.presence === 'held' ? { p: slot.presence, d: toHex(slot.sha256) } : { p: slot.presence, r: slot.reason };
}

/**
 * The columns one row publishes about its own bytes.
 *
 * A column is stated exactly where the document carries the member it describes, which is what makes a
 * row naming no `items` the statement that its payload names no item list rather than an omission of this
 * file's. A refusal row overrides the columns its fault reaches with what the bytes actually hold, so the
 * withheld member is absent from the column as it is absent from the document.
 */
function columnsOf(
  shape: ResponseShape,
  over: {
    v: 1;
    sd?: StampDisclosure;
    cva?: CollateralValidityAnchor;
    stamps?: readonly ItemStamp[];
    keyless?: string;
    fault?: RowColumns['fault'];
  },
): RowColumns {
  return {
    keyless: over.keyless ?? 'verify-ok',
    v: over.v,
    marking: shape.marking,
    contentType: shape.contentType,
    response: shape.response,
    ...(shape.assembledFrom === undefined ? {} : { assembledFrom: shape.assembledFrom }),
    responseBase64Url: toBase64Url(shape.bytes),
    responseByteLength: shape.bytes.length,
    ...(over.stamps === undefined ? {} : { items: itemColumns(shape, over.stamps) }),
    ...(over.sd === undefined ? {} : { sd: { name: over.sd.name, unc: over.sd.uncertaintySeconds } }),
    ...(over.cva === undefined ? {} : { cva: { col: slotColumn(over.cva.collateral), val: slotColumn(over.cva.validity) } }),
    ...(over.fault === undefined ? {} : { fault: over.fault }),
  };
}

/**
 * A document the shipped writer refuses to make, signed anyway.
 *
 * `encodePayload` writes the members its version names and nothing else, and its argument is typed, so a
 * payload carrying a name its version does not define, or leaving out one it requires, cannot reach it as
 * an object. Those are the rows the closed map exists for, so the clean bytes are made by the shipped
 * encoder, read back by the shipped decoder, and moved at the one position the row states: one edit, and
 * every other byte of the document is what the writer wrote. The signature is the published fixture key's,
 * so the refusal a row states cannot be about authenticity.
 */
function signedEditedDocument(clean: Uint8Array, edit: (payload: Map<unknown, unknown>) => void): Uint8Array {
  const decoded = decodeCanonical(clean, 'BAD_PAYLOAD');
  if (!(decoded instanceof Map)) throw new Error('the payload the writer just made is not a map');
  edit(decoded);
  return signCoseSign1(encodeCanonical(decoded), fixtureKey());
}

function asMapOf(payload: Map<unknown, unknown>, member: string): Map<unknown, unknown> {
  const value = payload.get(member);
  if (!(value instanceof Map)) throw new Error(`${member} is not a map in the document the writer just made`);
  return value;
}

/** The map a named position of a receipt payload holds, read off the document the writer just made. */
function mapAt(payload: Map<unknown, unknown>, at: string): Map<unknown, unknown> {
  if (at === 'payload') return payload;
  if (at === 'itm[0]') {
    const items = payload.get('itm');
    if (!Array.isArray(items) || items.length === 0) throw new Error('itm holds no element to reach');
    const first = items[0];
    if (!(first instanceof Map)) throw new Error('the item the writer just made is not a map');
    return first;
  }
  const [outer, inner] = at.split('.');
  const holder = asMapOf(payload, outer!);
  return inner === undefined ? holder : asMapOf(holder, inner);
}

/** Every closed map a receipt puts a member inside, by the position its reader names. */
const CLOSED_MAPS = ['payload', 'meas', 'att', 'tok', 'mk', 'sd', 'cva', 'cva.col', 'cva.val', 'itm[0]'] as const;

/** The name every unknown-member row carries, which is the name the refusal quotes back. */
const UNKNOWN_MEMBER = 'not_a_member';

const slug = (value: string): string =>
  value
    .replace(/[^a-z0-9]+/giu, '-')
    .replace(/^-|-$/gu, '');

interface PublishedRow {
  readonly name: string;
  readonly bytes: Uint8Array;
  readonly expected: string;
  readonly twin: boolean;
  readonly note?: string;
  /**
   * The columns a row states beside its verdict. `columnsOf` fills every one of them for a row built over a
   * response shape; the four fixtures this suite began with state only the response bytes, which is what the
   * shipped verifier now cannot do without, and no more of the column set than they need.
   */
  readonly columns?: Partial<RowColumns>;
}

function main(): void {
  const key = fixtureKey();

  const validBytes = issueReceipt(fixturePayload(), key);
  const softwareBytes = issueReceipt(
    fixturePayload({ meas: { tee: 'software', m: labeled('ashaveri-fixtures/software-measurement/v1') } }),
    key,
  );
  // Signed by hand on purpose: issueReceipt refuses to produce a payload whose measurement
  // contradicts its kind, and an independent implementation still has to catch that itself.
  const mismatchBytes = signCoseSign1(
    encodePayload(fixturePayload({ meas: { tee: 'snp', m: labeled('ashaveri-fixtures/mismatched-measurement/v1') } })),
    key,
  );
  const tampered = new Uint8Array(validBytes);
  tampered[tampered.length - 1]! ^= 0x01;

  /**
   * A marked receipt over the same bytes `marking-v1.json` publishes for the buffered shape, so the two
   * suites check each other: `res` is sha256 of the whole response and `mk.d` is sha256 of the one member
   * inside it, and a port that gets either span wrong disagrees with one file or the other. Nothing here
   * invents a third spelling of the mark: the response and its region come from the same builder the
   * vector generator uses, and the disclosure, the anchor and the item list come from the same envelope
   * the marking suite signs its rows under, so the two documents are one document.
   */
  const markedResponse = markedBuffered();
  const markedBytes = issueReceipt(
    fixturePayload({
      res: sha256(new TextEncoder().encode(markedResponse.response)),
      mk: { sch: 'provenance-v1', d: sha256(new TextEncoder().encode(markedResponse.region)) },
    }),
    key,
  );

  // The verifier reads a receipt's marked region out of the response, so a row a reader is asked to verify
  // owes that reader the bytes. The five fixtures this suite began with carried `res` alone, which was
  // enough while a payload naming no marking could skip the region check; every payload names one now.
  const fixtureResponseB64 = toBase64Url(FIXTURE_RESPONSE);
  const rows: PublishedRow[] = [
    {
      name: 'receipt-valid-v1',
      bytes: validBytes,
      expected: 'verify-ok',
      twin: true,
      columns: { responseBase64Url: fixtureResponseB64 },
    },
    {
      name: 'receipt-software-v1',
      bytes: softwareBytes,
      expected: 'verify-ok',
      twin: true,
      columns: { responseBase64Url: fixtureResponseB64 },
    },
    {
      name: 'receipt-marked-v1',
      bytes: markedBytes,
      expected: 'verify-ok',
      twin: true,
      columns: { responseBase64Url: toBase64Url(new TextEncoder().encode(markedResponse.response)) },
      note: 'A receipt carrying a `provenance-v1` mark: its `res` is sha256 of the marked buffered response and its `mk.d` is sha256 of the one marking member inside those same bytes, both the bytes marking-v1.json publishes for the buffered shape. The disclosure, the anchor and the item list state what this issuance says about itself beside that mark: a source nobody measured, an appraisal context never taken in, and the one buffered item, which is the whole of the body `res` digests.',
    },
    {
      name: 'receipt-meas-mismatch-v1',
      bytes: mismatchBytes,
      expected: 'BAD_PAYLOAD',
      twin: false,
      columns: { responseBase64Url: fixtureResponseB64 },
      note: 'Signature is valid; the payload claims tee "snp" but carries a 32-byte measurement, which is the software width.',
    },
    {
      name: 'receipt-tampered-v1',
      bytes: tampered,
      expected: 'INVALID_SIGNATURE',
      twin: false,
      columns: { responseBase64Url: fixtureResponseB64 },
    },
  ];

  const stream = SHAPES['stream-unmarked']!;
  const markedStream = SHAPES['stream-marked']!;
  const body = SHAPES['body-unmarked']!;
  const markedBody = SHAPES['body-marked']!;
  const sentinel = SHAPES['sentinel-unmarked']!;
  const markedSentinel = SHAPES['sentinel-marked']!;

  const streamStamps = itemStamps(stream);
  const markedStreamStamps = itemStamps(markedStream);
  const bodyStamps = itemStamps(body);
  const markedBodyStamps = itemStamps(markedBody);
  const markedSentinelStamps = itemStamps(markedSentinel);

  /** The acceptances, each over a response this package already publishes. */
  const accepted: Array<{ row: Omit<PublishedRow, 'bytes' | 'twin'>; payload: ReceiptPayload }> = [
    {
      row: {
        name: 'receipt-stream-v1',
        expected: 'verify-ok',
        note: 'A receipt over the four items a streamed completion frames, issued by a deployment whose time source declares a bound: one reading per item in the order the items were framed, the last a second before `iat`, and both anchor slots holding the digest of bytes that were taken in. Its `res` is sha256 of the whole stream with its framing and its sentinel, the bytes marking-v1.json publishes as `streamed-region-stripped`, and its `itm` digests are the four `data:` payloads inside those bytes. This is the anchor a demand of two answers: both slots state they were taken in, so every posture a policy can take about an anchor accepts it, and the column states all three beside that fact.',
        columns: {
          ...columnsOf(stream, { v: 1, sd: MEASURED_SOURCE, cva: ANCHOR_HELD_BOTH, stamps: streamStamps }),
          handover: handoverFor(['verify-ok', 'verify-ok', 'verify-ok']),
        },
      },
      payload: payloadFor(stream, { sd: MEASURED_SOURCE, cva: ANCHOR_HELD_BOTH, itm: streamStamps }),
    },
    {
      row: {
        name: 'receipt-buffered-v1',
        expected: 'verify-ok',
        note: 'A receipt over a buffered body, whose item list is the one item holding the whole of it: `itm[0].d` and `res` are two statements about one byte string, and a port that walks a buffered body for frames reads no item out of it and disagrees with both. Its anchor holds the collateral and names the validity context as a document its source reports as never issued, which is the pair of states a slot carries a label for rather than a flag. The postures say what that pair is worth: a demand of one slot is met by the half that was taken in, and a demand of both is refused by the half that was not.',
        columns: {
          ...columnsOf(body, { v: 1, sd: MEASURED_SOURCE, cva: ANCHOR_HELD_AND_ABSENT, stamps: bodyStamps }),
          handover: handoverFor(['verify-ok', 'verify-ok', 'ANCHOR_SLOT_NOT_HELD']),
        },
      },
      payload: payloadFor(body, { sd: MEASURED_SOURCE, cva: ANCHOR_HELD_AND_ABSENT, itm: bodyStamps }),
    },
    {
      row: {
        name: 'receipt-unmeasured-v1',
        expected: 'verify-ok',
        note: 'A receipt whose source declares that nobody measured it: `sd.unc` is `null`, which is that source saying nothing here knows how far its readings stand from the instants they name, and neither a bound of zero nor a member left out. The name is the shipped one for a deployment that wired no source. The response is the marked buffered completion, so this row and `receipt-marked-v1` attest one response, one disclosure apart. Its anchor holds both halves, so the two windows a policy runs and the demand a policy states are two separate questions here: this row is accepted whatever posture the anchor demand takes.',
        columns: {
          ...columnsOf(markedBody, { v: 1, sd: UNMEASURED_SOURCE, cva: ANCHOR_HELD_BOTH, stamps: markedBodyStamps }),
          handover: handoverFor(['verify-ok', 'verify-ok', 'verify-ok']),
        },
      },
      payload: payloadFor(markedBody, { sd: UNMEASURED_SOURCE, cva: ANCHOR_HELD_BOTH, itm: markedBodyStamps }),
    },
    {
      row: {
        name: 'receipt-not-taken-in-v1',
        expected: 'verify-ok',
        note: 'A receipt with both anchor slots saying `not-taken-in` beside their reasons: an issuer that takes no collateral in and appraises nothing states both absences in the words that name the collector rather than the world, and a verifier weighing the anchor refuses a declared gap instead of an undeclared one. The response is the marked stream, so the list is the four upstream chunks and the marking frame, five items in the order the bytes put them in. The postures are the whole of what a demand reaches here: naming nothing leaves this document where it was, and asking for one slot or for both refuses it, because there is no held slot to count.',
        columns: {
          ...columnsOf(markedStream, { v: 1, sd: MEASURED_SOURCE, cva: ANCHOR_NOT_TAKEN_IN, stamps: markedStreamStamps }),
          handover: handoverFor(['verify-ok', 'ANCHOR_SLOT_NOT_HELD', 'ANCHOR_SLOT_NOT_HELD']),
        },
      },
      payload: payloadFor(markedStream, { sd: MEASURED_SOURCE, cva: ANCHOR_NOT_TAKEN_IN, itm: markedStreamStamps }),
    },
    {
      row: {
        name: 'receipt-collateral-absent-v1',
        expected: 'verify-ok',
        note: 'A receipt over a buffered body whose anchor is the mirror of `receipt-buffered-v1`: the collateral its evidence was appraised against is the half its source reports as never issued, and the validity context is the half held. Written by `issueReceipt` over these bytes like every accepted row here, since a slot naming an absence and its reason is a shape the shipped writer makes. The postures read both halves: a demand of one slot is met by the half that was taken in and a demand of both is refused by the half that was not, and a row whose one held slot is the other one answers alike, which is the only way the column is seen to count slots rather than to look for one name.',
        columns: {
          ...columnsOf(body, { v: 1, sd: MEASURED_SOURCE, cva: ANCHOR_COLLATERAL_ABSENT, stamps: bodyStamps }),
          handover: handoverFor(['verify-ok', 'verify-ok', 'ANCHOR_SLOT_NOT_HELD']),
        },
      },
      payload: payloadFor(body, { sd: MEASURED_SOURCE, cva: ANCHOR_COLLATERAL_ABSENT, itm: bodyStamps }),
    },
    {
      row: {
        name: 'receipt-both-absent-at-source-v1',
        expected: 'verify-ok',
        note: 'A receipt over the marked buffered body whose anchor states both halves as material its source never had: the collateral as never issued and the validity context as never issued, each beside its own reason. This is the absence the world is account for, in contrast to `receipt-not-taken-in-v1`, whose two absences are this deployment\'s own account of looking away, and the two shapes answer a demand alike because neither gives a verifier bytes to weigh. Written by `issueReceipt` over these bytes. Naming no demand leaves it where it was, and a demand of one slot refuses it for the same count a demand of two does: there is no held slot to reach either.',
        columns: {
          ...columnsOf(markedBody, {
            v: 1,
            sd: MEASURED_SOURCE,
            cva: ANCHOR_BOTH_ABSENT_AT_SOURCE,
            stamps: markedBodyStamps,
          }),
          handover: handoverFor(['verify-ok', 'ANCHOR_SLOT_NOT_HELD', 'ANCHOR_SLOT_NOT_HELD']),
        },
      },
      payload: payloadFor(markedBody, { sd: MEASURED_SOURCE, cva: ANCHOR_BOTH_ABSENT_AT_SOURCE, itm: markedBodyStamps }),
    },
    {
      row: {
        name: 'receipt-marked-sentinel-v1',
        expected: 'verify-ok',
        note: 'A receipt over a stream that framed no item until the mark was written to it: the response is one marking frame, the blank line that closes it, and the closing sentinel, joined from the pieces the marking and response suites publish, and it frames exactly one item, the mark. The same upstream body with the marking off frames nothing at all, and no document this format declares can be signed over those bytes: `itm` is required and never empty, which is what `receipt-empty-items-v1` states as a refusal. Its anchor holds both halves, so all three postures a policy can take about an anchor accept it, which is the row that states its demand and the rows that state none agreeing.',
        columns: {
          ...columnsOf(markedSentinel, { v: 1, sd: MEASURED_SOURCE, cva: ANCHOR_HELD_BOTH, stamps: markedSentinelStamps }),
          handover: handoverFor(['verify-ok', 'verify-ok', 'verify-ok']),
        },
      },
      payload: payloadFor(markedSentinel, { sd: MEASURED_SOURCE, cva: ANCHOR_HELD_BOTH, itm: markedSentinelStamps }),
    },
  ];

  for (const one of accepted) {
    rows.push({ ...one.row, bytes: issueReceipt(one.payload, key), twin: true });
  }

  // The refusals, each assembled out of the documents above rather than out of junk: a row that refuses
  // because its bytes are nonsense tests nothing, and a row that refuses for the one member its columns
  // name tests the rule its `fault` states. Every one of these is signed under the published key, so none
  // of them refuses for authenticity, and every one is answered the same with a key in hand and without.

  const refusalBase = payloadFor(markedStream, {
    sd: MEASURED_SOURCE,
    cva: ANCHOR_ONE_OF_EACH,
    itm: markedStreamStamps,
  });

  /** The item list above with two of its instants exchanged, and every digest still beside its own item. */
  const descendingStamps: ItemStamp[] = streamStamps.map((one, index) => ({
    t: index === 1 ? streamStamps[2]!.t : index === 2 ? streamStamps[1]!.t : one.t,
    d: one.d,
  }));

  const nearMisses: PublishedRow[] = [
    {
      name: 'receipt-stamps-descending-v1',
      expected: 'ITEM_STAMP_OUT_OF_ORDER',
      twin: false,
      note: 'The four items of `receipt-stream-v1`, in their order, over the same bytes, with the instants of the middle two exchanged so that the list states one order and the stamps state another. Chain order is the array and stamp order is `t`, and a reader that let these through would be holding a signed account of when a completion\'s items were framed that contradicts itself. Every item digest still belongs to its own item, the signature is the published key\'s, and no member is out of place: this is the one state `ITEM_STAMP_OUT_OF_ORDER` exists for, and a gateway that reads one instant per item in framing order cannot produce it, so these bytes are assembled from the published list.',
      columns: columnsOf(stream, {
        v: 1,
        sd: MEASURED_SOURCE,
        cva: ANCHOR_HELD_BOTH,
        stamps: descendingStamps,
        keyless: 'ITEM_STAMP_OUT_OF_ORDER',
        fault: { at: 'itm[2]', states: 'a stamp earlier than the item before it' },
      }),
      bytes: issueReceipt(
        payloadFor(stream, { sd: MEASURED_SOURCE, cva: ANCHOR_HELD_BOTH, itm: descendingStamps }),
        key,
      ),
    },
    {
      name: 'receipt-empty-items-v1',
      expected: 'BAD_PAYLOAD',
      twin: false,
      note: 'The stream that frames no item, attested as a document whose `itm` is the empty list: a run of nothing states nothing and zero digests give a reader nothing to hold the response against. The writer writes the list it was handed, because a faithful writer states the length it was given; the reader is the one that says a run of nothing is not a document, and this row is that answer over the very bytes a gateway that marks cannot state.',
      // An empty list is a value the writer makes and the reader refuses: `itm` is required, so this
      // document carries the member and holds nothing in it, which is a state and not an omission. The
      // column states it as an empty list, because the row is about the list and not about its absence.
      columns: {
        ...columnsOf(sentinel, {
          v: 1,
          sd: MEASURED_SOURCE,
          cva: ANCHOR_HELD_BOTH,
          keyless: 'BAD_PAYLOAD',
          fault: { at: 'itm', states: 'the list the format requires and these bytes leave empty' },
        }),
        items: [],
      },
      bytes: issueReceipt(payloadFor(sentinel, { sd: MEASURED_SOURCE, cva: ANCHOR_HELD_BOTH, itm: [] }), key),
    },
    {
      name: 'receipt-held-without-a-digest-v1',
      expected: 'BAD_PAYLOAD',
      twin: false,
      note: 'An anchor slot that claims its bytes were taken in and carries no digest beside the claim: the member says `held` and the reader weighs that at the width of the digest a held arm asks for, so these bytes are refused. That the refusal is about the claim\'s own shape and not about whether the material exists is the residual section 3 states about a held digest, which a document cannot see past and a verifier holding pins can.',
      columns: {
        ...columnsOf(markedStream, {
          v: 1,
          sd: MEASURED_SOURCE,
          stamps: markedStreamStamps,
          keyless: 'BAD_PAYLOAD',
          fault: { at: 'cva.col.d', states: 'a held slot carrying no digest' },
        }),
        // The column states the anchor as these bytes hold it: a slot saying its material was taken in,
        // and a digest of no bytes beside the claim.
        cva: { col: { p: 'held', d: '' }, val: slotColumn(COLLATERAL_NOT_TAKEN_IN) },
      },
      bytes: signedEditedDocument(encodePayload(refusalBase), (payload) => {
        asMapOf(payload, 'cva').set(
          'col',
          new Map<unknown, unknown>([
            ['p', 'held'],
            ['d', new Uint8Array(0)],
          ]),
        );
      }),
    },
    {
      name: 'receipt-bound-withheld-v1',
      expected: 'BAD_PAYLOAD',
      twin: false,
      note: 'A disclosure that names its source and withholds the bound, where the shape takes two members and `null` is the answer for a source nobody measured. `receipt-unmeasured-v1` states the same source with the member present and its value `null`, and is accepted: this row is the difference between a source saying it was never measured and a writer leaving the question unasked, which is the silence the member exists to refuse.',
      columns: {
        ...columnsOf(markedStream, {
          v: 1,
          cva: ANCHOR_ONE_OF_EACH,
          stamps: markedStreamStamps,
          keyless: 'BAD_PAYLOAD',
          fault: { at: 'sd.unc', member: 'unc', states: 'the bound the shape requires and this document withholds' },
        }),
        // The column states what the bytes hold: the name, and no bound at all.
        sd: { name: MEASURED_SOURCE.name },
      },
      bytes: signedEditedDocument(encodePayload(refusalBase), (payload) => {
        asMapOf(payload, 'sd').delete('unc');
      }),
    },
    {
      name: 'receipt-retired-shape-v1',
      expected: 'BAD_PAYLOAD',
      twin: false,
      note: 'A document wearing `v: 1` with its twelve shared members present, well-typed and in place, and the four a receipt states about itself not there at all. One version requires all seventeen, so the check holds one document\'s member set against the format rather than a document\'s number against a table of member sets, and the row states which member the reader names first, because which member a document left out is not something a reader can guess from what it finds.',
      columns: columnsOf(markedStream, {
        v: 1,
        keyless: 'BAD_PAYLOAD',
        fault: { at: 'mk', states: 'the member the format requires and these bytes never wrote' },
      }),
      bytes: signedEditedDocument(encodePayload(refusalBase), (payload) => {
        for (const member of ['mk', 'sd', 'cva', 'itm']) payload.delete(member);
      }),
    },
  ];

  for (const level of CLOSED_MAPS) {
    nearMisses.push({
      name: `receipt-unknown-member-${slug(level)}-v1`,
      expected: 'BAD_PAYLOAD',
      twin: false,
      note: `A clean v1 document carrying \`${UNKNOWN_MEMBER}\` in the closed map at \`${level}\`, which is a name the format does not define anywhere. The walk over a payload reaches every map the format nests, and the two arms of the anchor and the element of the item list are closed by the reader that resolves each at its own position, so the refusal names the level the name sits on rather than dropping a claim a reader was never told about.`,
      columns: columnsOf(markedStream, {
        v: 1,
        sd: MEASURED_SOURCE,
        cva: ANCHOR_ONE_OF_EACH,
        stamps: markedStreamStamps,
        keyless: 'BAD_PAYLOAD',
        fault: { at: level, member: UNKNOWN_MEMBER, states: `a member ${level} does not define` },
      }),
      bytes: signedEditedDocument(encodePayload(refusalBase), (payload) => {
        mapAt(payload, level).set(UNKNOWN_MEMBER, 1);
      }),
    });
  }

  rows.push(...nearMisses);

  mkdirSync(join(DATA, 'keys'), { recursive: true });
  mkdirSync(join(DATA, 'receipts'), { recursive: true });

  writeFileSync(
    join(DATA, 'keys', 'receipt-key-v1.json'),
    JSON.stringify(
      {
        description: 'Deterministic Ed25519 signing key for receipt fixtures. TEST ONLY, never use in production.',
        privateKey: toHex(key.privateKey),
        publicKey: toHex(key.publicKey),
        kid: toHex(key.kid),
      },
      null,
      2,
    ) + '\n',
  );

  const manifestFixtures: Array<Record<string, unknown>> = [];
  for (const vector of rows) {
    const path = `receipts/${vector.name}.cbor`;
    writeFileSync(join(DATA, path), vector.bytes);
    const digestSha256 = toHex(sha256(vector.bytes));
    if (vector.twin) {
      const decoded = decodeReceipt(vector.bytes);
      const json = receiptToJson(decoded.payload, decoded.cose.signature, decoded.header.kid);
      writeFileSync(
        join(DATA, `receipts/${vector.name}.json`),
        JSON.stringify({ ...json, digestSha256 }, null, 2) + '\n',
      );
    }
    manifestFixtures.push({
      name: vector.name,
      path,
      digestSha256,
      expected: vector.expected,
      ...(vector.columns ?? {}),
      ...(vector.note ? { note: vector.note } : {}),
    });
  }

  writeFileSync(
    join(DATA, 'manifest.json'),
    JSON.stringify(
      {
        version: 1,
        generatedBy: 'ashaveri-fixtures generate',
        cddl: 'receipt.cddl @ashaveri/receipt v0.1.0',
        fixtures: manifestFixtures,
        layout: {
          verdictFields: ['expected', 'keyless', 'handover'],
          readers: {
            keyless:
              'decodeReceipt reads the payload a document claims with no key in hand, so a row\'s `keyless` column is the answer these bytes owe a reader that has not authenticated them',
            keyBearing:
              'verifyReceipt checks the signature under the published key first and reads the payload after it, so `expected` is the answer the same bytes owe a reader holding the key the published key file names',
          },
          columns: {
            v: 'The payload version the document names in its own `v` member. The format declares one, so every row that states this column states `1`, and the entries that state no `v` are the fixtures this suite began with.',
            marking:
              'Which marking setting the response bytes came off, `none` or `provenance-v1`. This is a fact about the bytes and not about the document: one upstream body frames no item with the marking off and one item with it on, so whether a document can be signed over a response at all depends on this column, and `receipt-marked-sentinel-v1` and `receipt-empty-items-v1` are those two answers over one completion, the second a refusal because the format requires a non-empty item list. The payload states the setting again as `mk.sch`.',
            contentType:
              'The content type the response was served with, which is what decides whether its items are `data:` frames or one whole body.',
            response:
              'Where these bytes are published already, as `<file>#<vector>`: `res` is sha256 over that file\'s bytes and every item digest is of a slice of them, so one response is read out of two files and a generator that drifted on either side disagrees here.',
            assembledFrom:
              'On a row whose response is joined rather than quoted, the published pieces it was joined from in the order they were written, each as `<file>#<path>` a reader can look up.',
            responseBase64Url:
              'The response exactly as transmitted, framing and sentinel included, unpadded base64url. These are the bytes the row\'s `res` is the digest of.',
            items:
              'One entry per item the shipped reader gives those bytes, in the order it gives them: the instant the source named by `sd` read for it, the digest of that item\'s bytes, and the bytes themselves so the digest is checkable rather than asserted. A row states `items` exactly where its document carries the list. Where a refusal is about the list, the row states the list as the bytes hold it, which is the whole of what the reader compares.',
            sd: 'The disclosure the payload carries: the source `iat` was read from, and the bound that source declares, where `null` is that source\'s statement that nobody measured it. A row stating no `unc` is a document that withheld the member, which is a refusal and not the same sentence.',
            cva: 'The anchor the payload carries, each slot one of the three presence labels with the digest or the reason that label selects. A slot stating `held` with an empty `d` is a claim with no material behind it, which is a refusal.',
            handover:
              'What the shipped client path answers for this document under each posture `minAnchorSlotsHeld` can take, three entries in the order `null`, `1`, `2`: the policy that names no demand, a demand of one held slot, a demand of both. Each entry is that policy field\'s own name beside the number an operator would write and the verdict the client gives the bytes under it, read off `verifyCompletionReceipt` with the fixture\'s issuer pinned, the clock at the instant the document names, and nothing else named, so the only thing the three readings differ in is the demand. The `null` entry repeats the row\'s `expected` rather than claiming a second answer, because what the field promises is that a demand nobody stated moves no verdict. A row states this column where this file publishes the row\'s own per-member columns: a refusal row states none because the format reader answers it before a policy is weighed at all, and the entries this suite began with state none because they carry no per-member column at all. Every document a reader accepts states an anchor with both of its halves, because the format declares one payload version and it requires the anchor, so the client reaches two slots on every accepted row. Whether a slot stating `held` still resolves is not this column and not this suite: it is answered outside the document.',
            fault:
              'On a refusal row, the position the shipped reader names in the answer these bytes get, and what the row states about it. Where the reader quotes a member back, the row states the name as `member`. The position is what makes the row about one member rather than about the document as a whole.',
          },
          encodings: 'byte strings unpadded base64url, digests lowercase hex, instants whole Unix seconds',
        },
      },
      null,
      2,
    ) + '\n',
  );

  for (const entry of manifestFixtures) console.log(`${String(entry['name'])}: ${String(entry['digestSha256'])}`);
}

main();
