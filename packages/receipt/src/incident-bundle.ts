import { sha256 } from '@noble/hashes/sha2.js';
import { ReceiptError } from './errors.js';
import { parseHoldRecord, type HoldRecord } from './hold.js';
import { readJsonBytes, type JsonObject } from './json-text.js';
import { firstForgingCodePoint } from './line-text.js';
import { PROVENANCES, isProvenance, type Provenance } from './provenance.js';

/**
 * The incident preservation bundle: a deployment's statement of one incident and the hold that
 * preserves the material around it, beside the receipts that attest the material and the hold record
 * it designates.
 *
 * A hold record states an instruction to preserve, and the receipts attest the responses the hold
 * covers. Neither says which incident prompted the hold, how long the deployment undertakes to keep
 * the material past the incident, or which provision that undertaking is weighed against. This record
 * states those things together and keeps the two kinds of statement apart, the same split the model
 * inventory draws: a field copied from the hold record is bound and checked against that record's
 * bytes, and a field the deployment asserts is the deployment's own word, which nothing in this record
 * proves. The hold's issue stamp and author and the window of record stamps are bound; the incident's
 * identity, stamp and narrative, and the number of days the deployment states as its preservation
 * floor, are asserted.
 *
 * It carries no signature, as the hold record and the model inventory carry none: its trust arrives
 * from whoever hands it over beside the receipts and the hold it speaks of. The export container is
 * what carries it as evidence, the record's bytes riding an item's inline original under the export's
 * own signature, and no member of the export contract moves for it. So the reader has two doors.
 * `parseIncidentBundle` answers the layout with no hold in hand, and a reviewer holding only the
 * bundle sees which fields are claims about a hold this record designates by digest and which are the
 * deployment's own. `verifyIncidentBundle` is handed that hold's bytes, hashes them against the
 * designation, reads the hold through `parseHoldRecord`, and refuses any copied field that disagrees
 * by name. A bound field that fails the comparison is the bundle contradicting the hold it designates;
 * an asserted field has no comparison to fail, and a mutation of one is refused while a mutation of
 * the other is read.
 *
 * The preservation floor is a pointer for counsel, not a compliance claim. The number of days is the
 * deployment's own statement, and the reader checks only that it is a positive whole number and that
 * the `preserveUntil` stamp beside it is the arithmetic of the incident stamp plus those days; it
 * judges the number against no provision's period, ninety days or any other. The one provision the
 * layout enumerates is cited as a pointer for counsel to weigh, and the limits sentence every record
 * carries says the floor is not a conclusion that a duty applies or was met.
 *
 * The seventy-two-hour notification is a process obligation of the deployment, not a product claim.
 * Nothing in this layout states it, proves it, or carries a member for it: the closed member list is
 * the witness, and the limits sentence says in the format's own words that the notification remains
 * the deployment's own process obligation, which nothing in this record states or proves. A reader
 * that looked for a notification deadline here would find no position to read one from.
 */

/** The versions this module reads, and the only place an incident bundle version is asked. */
export const INCIDENT_BUNDLE_VERSIONS: readonly number[] = [1];

/** The members of the one layout, in the order the writer emits them and the spec publishes them. */
export const INCIDENT_BUNDLE_V1_MEMBERS = ['v', 'prov', 'at', 'incident', 'hold', 'window', 'floor', 'pointers', 'limits'] as const;
export const INCIDENT_BUNDLE_INCIDENT_MEMBERS = ['id', 'at', 'states'] as const;
export const INCIDENT_BUNDLE_HOLD_MEMBERS = ['sha256', 'at', 'by'] as const;
export const INCIDENT_BUNDLE_WINDOW_MEMBERS = ['from', 'to'] as const;
export const INCIDENT_BUNDLE_FLOOR_MEMBERS = ['days', 'preserveUntil', 'pointer'] as const;

/**
 * The pointers the layout enumerates, each naming one provision a preservation floor may be weighed
 * against. The citation beside it is the instrument as the estate's own sources name it; it is a
 * pointer for counsel to weigh, not a conclusion about applicability, and the record's limits sentence
 * says so. The registry is closed at this one provision. The floor number is the deployment's own
 * statement and the pointer is counsel's to weigh; no corpus cut of this instrument exists in the
 * estate, so the citation is prose only and carries no digest and no corpus path.
 */
export const INCIDENT_BUNDLE_POINTERS = ['gsa-552-239-7001-f-5'] as const;

export type IncidentBundlePointer = (typeof INCIDENT_BUNDLE_POINTERS)[number];

/** The citation each pointer names, in the order the registry declares them. */
export const INCIDENT_BUNDLE_POINTER_CITATIONS: Readonly<Record<IncidentBundlePointer, string>> = {
  'gsa-552-239-7001-f-5': 'GSA 552.239-7001 (f)(5) (Federal Acquisition Regulation; incident preservation, ninety days)',
};

/**
 * The limits every record states, verbatim. The format owns this sentence rather than the writer: a
 * record whose limits member says anything else is refused, because the one thing a reader of a bundle
 * must not have to weigh is whether the record's own account of its limits is true. The sentence states
 * the three things a reader must not mistake the record for: the floor is a pointer for counsel and not
 * a compliance claim, the seventy-two-hour notification is a process obligation of the deployment which
 * nothing in this record states or proves, and the asserted fields are the deployment's own.
 */
export const INCIDENT_BUNDLE_LIMITS =
  'The preservation floor is a pointer for counsel, not a compliance claim. The seventy-two-hour ' +
  'notification is a process obligation of the deployment, which nothing in this record states or ' +
  'proves. The asserted fields are the deployment\'s own.';

/**
 * The width one authored text member of this layout may hold, in UTF-16 units of the text as this
 * package holds it. The incident's identity and narrative are the things a deployment authors here;
 * the copied hold author carries no ceiling, for the reason the model inventory gives beside its own
 * copied positions: a ceiling on this side would refuse a bundle over a hold the deployment issued.
 */
export const INCIDENT_BUNDLE_TEXT_MAX_UNITS = 400;

/** A incident preservation bundle at version 1: the whole layout, every member required. */
export interface IncidentBundleRecord {
  readonly v: 1;
  readonly prov: Provenance;
  /** The assembly stamp: the bundle's date, in unix seconds. */
  readonly at: number;
  /** The incident the deployment states: its identity, its stamp no later than `at`, and its narrative. Asserted. */
  readonly incident: { readonly id: string; readonly at: number; readonly states: string };
  /** The hold the record designates, by the digest of its exact bytes, beside the issue stamp and author copied from it. Bound. */
  readonly hold: { readonly sha256: string; readonly at: number; readonly by: string };
  /** The window of record stamps the hold covers, copied from the hold record's window. Bound. */
  readonly window: { readonly from: number; readonly to: number | null };
  /** The preservation floor: the days the deployment states, the stamp recomputed from them, and the pointer counsel weighs. */
  readonly floor: { readonly days: number; readonly preserveUntil: number; readonly pointer: IncidentBundlePointer };
  readonly pointers: readonly IncidentBundlePointer[];
  /** The format's limits sentence, verbatim; the reader refuses any other text at this position. */
  readonly limits: string;
}

/**
 * What a caller hands the verifying door beside the record: the exact hold record bytes the record
 * designates. The reader resolves nothing: the bytes arrive as an argument, and a caller holding only
 * the bundle reads it through `parseIncidentBundle` instead.
 */
export interface IncidentBundleVerifyOptions {
  readonly holdBytes: Uint8Array;
}

const text = new TextEncoder();

function bad(detail: string): ReceiptError {
  return new ReceiptError('INCIDENT_BUNDLE_BAD_DOCUMENT', detail);
}

function readMap(value: unknown, position: string): JsonObject {
  if (!(value instanceof Map)) throw bad(`${position} is not an object`);
  return value;
}

/**
 * Text this record copies out of the hold: a string, not an empty one, and carrying no character of the
 * printed-line class. No ceiling and no padding rule, for the model inventory's reason: the hold record
 * states its author under its own rule, and a narrowing on this side would refuse a bundle over a hold
 * the deployment issued. The class is asked because the value is printed beside the hold it names, and
 * a character that ends, hides or reorders a row makes the line a reader sees stop being the bytes the
 * hold record carries.
 */
function requireCopiedText(value: unknown, position: string): string {
  if (typeof value !== 'string' || text.encode(value).length < 1) {
    throw bad(`${position} must be a non-empty text`);
  }
  const forging = firstForgingCodePoint(value);
  if (forging !== undefined) {
    throw bad(`${position} carries the character U+${forging.toString(16).toUpperCase().padStart(4, '0')}, which forges the line it is printed on`);
  }
  return value;
}

/**
 * Text the deployment authors: the same class, beside the width this layout states and the padding rule
 * a printed row keeps. The incident's identity and narrative are prose the deployment writes, and both
 * are printed beside the incident, so one rule reads them.
 */
function requireAuthoredText(value: unknown, position: string): string {
  const label = requireCopiedText(value, position);
  if (label.length > INCIDENT_BUNDLE_TEXT_MAX_UNITS) {
    throw bad(`${position} is wider than the ${String(INCIDENT_BUNDLE_TEXT_MAX_UNITS)} units this layout holds`);
  }
  if (label.trim() !== label) {
    throw bad(`${position} carries leading or trailing space, which a printed row does not carry`);
  }
  return label;
}

/** A digest, stated the way this estate states every one of them: sixty-four lowercase hex characters. */
function requireDigest(value: unknown, position: string): string {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/u.test(value)) {
    throw bad(`${position} must be sixty-four lowercase hex characters`);
  }
  return value;
}

/** A unix second: a whole number no smaller than zero, the integer spelling already settled by the reading. */
function requireStamp(value: unknown, position: string): number {
  if (typeof value !== 'number' || value < 0) {
    throw bad(`${position} must be a whole number of unix seconds no smaller than zero`);
  }
  return value;
}

/**
 * The preservation floor's days: a positive whole number, the integer spelling already settled by the
 * reading. The reader checks the shape and nothing else: the number is the deployment's own statement,
 * and judging it against a provision's period would turn a pointer for counsel into a compliance claim
 * the limits sentence expressly disclaims.
 */
function requireDays(value: unknown, position: string): number {
  if (typeof value !== 'number' || value < 1) {
    throw bad(`${position} must be a positive whole number of days`);
  }
  return value;
}

/** The closure rule: a member the layout does not define makes the document malformed, not read around. */
function assertDefined(raw: JsonObject, members: readonly string[], where: string): void {
  for (const key of raw.keys()) {
    if (typeof key !== 'string' || !members.includes(key)) {
      throw bad(`${where} carries a member this version does not define: ${JSON.stringify(String(key))}`);
    }
  }
}

/** One pointer label, weighed against the closed registry rather than read as a citation nobody checked. */
function requirePointer(value: unknown, position: string): IncidentBundlePointer {
  if (typeof value !== 'string') throw bad(`${position} must be a text pointer label`);
  if (!(INCIDENT_BUNDLE_POINTERS as readonly string[]).includes(value)) {
    throw new ReceiptError(
      'INCIDENT_BUNDLE_UNKNOWN_POINTER',
      `${position} names ${JSON.stringify(value)}, outside the pointers the layout enumerates`,
    );
  }
  return value as IncidentBundlePointer;
}

function readPointers(value: unknown): readonly IncidentBundlePointer[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw bad('pointers must be a non-empty array: a bundle states which provisions its floor is weighed against');
  }
  const named = new Set<string>();
  return value.map((one, index): IncidentBundlePointer => {
    const site = `pointers[${String(index)}]`;
    const pointer = requirePointer(one, site);
    if (named.has(pointer)) {
      throw bad(`pointers names ${JSON.stringify(pointer)} twice`);
    }
    named.add(pointer);
    return pointer;
  });
}

/**
 * An incident preservation bundle, out of the bytes of the file as it sits on the volume.
 *
 * The reading is the strict one the hold record and the model inventory use, through the same JSON
 * scanner and for the same two reasons: a member named twice would be settled by `JSON.parse` into
 * whichever value the parser reached last while the bytes carry both, and a float wearing an integer
 * arrives at a check as the very number it imitates. The version is asked before any member is read,
 * because which member list applies is the one question a wrong version cannot be talked out of.
 *
 * This door answers the layout alone. The copied hold fields are read as text and stamps and a digest,
 * and the floor's `preserveUntil` is read as a stamp; whether the copied fields agree with the hold the
 * record designates, and whether `preserveUntil` is the arithmetic of the incident stamp and the stated
 * days, are the verifying door's questions, asked when a caller hands over the hold's bytes.
 */
export function parseIncidentBundle(bytes: Uint8Array): IncidentBundleRecord {
  const raw = readJsonBytes(bytes, (detail) => {
    throw bad(detail);
  });
  const document = readMap(raw, 'record');
  const version = document.get('v');
  if (typeof version !== 'number') {
    throw bad('v must be an integer incident bundle version');
  }
  if (!INCIDENT_BUNDLE_VERSIONS.includes(version)) {
    throw new ReceiptError(
      'INCIDENT_BUNDLE_UNSUPPORTED_VERSION',
      `incident bundle version ${String(version)} is not a layout this package reads`,
    );
  }
  assertDefined(document, INCIDENT_BUNDLE_V1_MEMBERS, 'record');
  const prov = document.get('prov');
  if (!isProvenance(prov)) {
    throw bad(`prov must be one of ${PROVENANCES.map((one) => `'${one}'`).join(', ')}, got ${typeof prov === 'string' ? `'${prov}'` : String(prov)}`);
  }
  const at = requireStamp(document.get('at'), 'at');
  const incident = readMap(document.get('incident'), 'incident');
  assertDefined(incident, INCIDENT_BUNDLE_INCIDENT_MEMBERS, 'incident');
  const incidentAt = requireStamp(incident.get('at'), 'incident.at');
  // An incident stamped after the bundle that carries it is another document's incident, the same rule
  // the model inventory states beside a review: both instants are inside one record, so a disagreement
  // is the record contradicting itself rather than a finding about the matter.
  if (incidentAt > at) {
    throw bad(`incident.at=${String(incidentAt)} postdates the bundle's assembly stamp at=${String(at)}`);
  }
  const hold = readMap(document.get('hold'), 'hold');
  assertDefined(hold, INCIDENT_BUNDLE_HOLD_MEMBERS, 'hold');
  const window = readMap(document.get('window'), 'window');
  assertDefined(window, INCIDENT_BUNDLE_WINDOW_MEMBERS, 'window');
  const from = requireStamp(window.get('from'), 'window.from');
  const toRaw = window.get('to');
  const to = toRaw === null ? null : requireStamp(toRaw, 'window.to');
  // A window closing before it opens is the hold record's own self-contradiction copied here: both ends
  // are inside one document, so a disagreement is a fault of the layout rather than a finding about the
  // matter.
  if (to !== null && to < from) {
    throw bad(`window.to=${String(to)} precedes window.from=${String(from)}, so the window closes before it opens`);
  }
  const floor = readMap(document.get('floor'), 'floor');
  assertDefined(floor, INCIDENT_BUNDLE_FLOOR_MEMBERS, 'floor');
  const limits = document.get('limits');
  if (limits !== INCIDENT_BUNDLE_LIMITS) {
    throw bad('limits must state the limits sentence this format owns, verbatim; a record does not word its own limits');
  }
  return {
    v: 1,
    prov,
    at,
    incident: {
      id: requireAuthoredText(incident.get('id'), 'incident.id'),
      at: incidentAt,
      states: requireAuthoredText(incident.get('states'), 'incident.states'),
    },
    hold: {
      sha256: requireDigest(hold.get('sha256'), 'hold.sha256'),
      at: requireStamp(hold.get('at'), 'hold.at'),
      by: requireCopiedText(hold.get('by'), 'hold.by'),
    },
    window: { from, to },
    floor: {
      days: requireDays(floor.get('days'), 'floor.days'),
      preserveUntil: requireStamp(floor.get('preserveUntil'), 'floor.preserveUntil'),
      pointer: requirePointer(floor.get('pointer'), 'floor.pointer'),
    },
    pointers: readPointers(document.get('pointers')),
    limits,
  };
}

/**
 * The record as a file: two-space indented, newline terminated, in the member order the layout declares.
 * The bytes are what an export item digests and a reviewer hashes, so one record state has to produce one
 * byte string, and a writer that emitted the caller's key order would give two writers of one state two
 * digests.
 */
export function encodeIncidentBundle(record: IncidentBundleRecord): Uint8Array {
  const document: Record<string, unknown> = {
    v: record.v,
    prov: record.prov,
    at: record.at,
    incident: { id: record.incident.id, at: record.incident.at, states: record.incident.states },
    hold: { sha256: record.hold.sha256, at: record.hold.at, by: record.hold.by },
    window: { from: record.window.from, to: record.window.to },
    floor: { days: record.floor.days, preserveUntil: record.floor.preserveUntil, pointer: record.floor.pointer },
    pointers: [...record.pointers],
    limits: record.limits,
  };
  return text.encode(`${JSON.stringify(document, null, 2)}\n`);
}

/**
 * The bytes this writer would produce for a record, run back through this module's own reader before a
 * caller files them beside the receipts and the hold they speak of. A deployment cannot hand over a
 * record its own reader refuses, which is the same promise `holdRecordBytes` and `modelInventoryBytes`
 * make: the refusal arrives where the bytes are made rather than at a reviewer holding them later.
 */
export function incidentBundleBytes(record: IncidentBundleRecord): Uint8Array {
  const bytes = encodeIncidentBundle(record);
  parseIncidentBundle(bytes);
  return bytes;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (one) => one.toString(16).padStart(2, '0')).join('');
}

/**
 * Verify a record against the hold it designates: the layout, the designation's digest, every copied
 * field against the hold's own statement, and the floor's arithmetic.
 *
 * The order is what keeps the report honest. The record is parsed first, because a document that
 * contradicts its own layout does so whoever handed it over. The digest comes next: bytes that are not
 * the ones the record designates are another hold, and reading copied fields out of them would be
 * comparing the record against a document it never named. The hold is then read through `parseHoldRecord`,
 * the hold's own whole-layout reader, and a hold those bytes cannot be read out of is refused as
 * unreadable rather than guessed at: the bundle may be whole and the hold simply not state what the
 * copied fields claim. The comparison itself is per field and names both values, because a copied field
 * that disagrees is the record contradicting the hold, and which of the two an operator has to look at
 * is the finding.
 *
 * The floor's `preserveUntil` is recomputed from the incident stamp and the stated days, because it is
 * the record's own arithmetic rather than a field copied from the hold: a stamp that is not the incident
 * stamp plus those days is the document contradicting its own figures, which is a fault of the layout.
 * The days themselves are never judged against a provision's period, and an asserted field (the
 * incident's identity, stamp and narrative, and the days as a number) is never compared, because there
 * is nothing in the hold to compare it to: that is the split the layout exists to keep.
 */
export function verifyIncidentBundle(bytes: Uint8Array, options: IncidentBundleVerifyOptions): { record: IncidentBundleRecord } {
  const record = parseIncidentBundle(bytes);
  const designated = toHex(sha256(options.holdBytes));
  if (designated !== record.hold.sha256) {
    throw new ReceiptError(
      'INCIDENT_BUNDLE_HOLD_MISMATCH',
      `the record designates ${record.hold.sha256} and the hold handed over hashes to ${designated}`,
    );
  }
  let hold: HoldRecord;
  try {
    hold = parseHoldRecord(options.holdBytes);
  } catch (reason) {
    const detail = reason instanceof Error ? reason.message : String(reason);
    throw new ReceiptError('INCIDENT_BUNDLE_HOLD_UNREADABLE', detail);
  }
  const disagrees = (position: string, stated: string | number | null, bound: string | number | null): ReceiptError =>
    new ReceiptError(
      'INCIDENT_BUNDLE_BOUND_DISAGREES',
      `${position} states ${JSON.stringify(stated)} and the designated hold binds ${JSON.stringify(bound)}`,
    );
  if (record.hold.at !== hold.at) throw disagrees('hold.at', record.hold.at, hold.at);
  if (record.hold.by !== hold.by) throw disagrees('hold.by', record.hold.by, hold.by);
  if (record.window.from !== hold.window.from) throw disagrees('window.from', record.window.from, hold.window.from);
  if (record.window.to !== hold.window.to) throw disagrees('window.to', record.window.to, hold.window.to);
  // The floor's stamp is the record's own arithmetic over its own asserted fields, recomputed here so a
  // moved floor is refused. Without this recomputation a bundle could state a preserveUntil the incident
  // stamp and the stated days do not reach, and a reader would report a preservation period the record's
  // own figures do not support.
  const preserveUntil = record.incident.at + record.floor.days * 86_400;
  if (record.floor.preserveUntil !== preserveUntil) {
    throw bad(`floor.preserveUntil states ${String(record.floor.preserveUntil)} and the incident stamp plus the stated days recomputes to ${String(preserveUntil)}`);
  }
  return { record };
}
