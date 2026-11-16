import { ReceiptError } from './errors.js';
import { readJsonBytes, type JsonObject } from './json-text.js';
import { firstForgingCodePoint } from './line-text.js';
import { PROVENANCES, isProvenance, type Provenance } from './provenance.js';

/**
 * The hold record: a deployment's own instruction to preserve material an incident or a legal matter
 * puts under hold, beside the receipts that attest it.
 *
 * A receipt attests one response, and the retention machinery retires and erases material on the
 * periods the deployment stated. Neither knows that a matter now asks for the material to stay. This
 * record states that instruction: who issued it and when, which window of record stamps it covers,
 * which credentials it names, why it was issued, and when it was released. It carries no signature,
 * as the disclosure record and the model inventory carry none: its trust arrives from whoever hands
 * it over beside the receipts it speaks of, and the export container is what carries it as evidence,
 * the record's bytes riding an item's inline original under the export's own signature.
 *
 * What the record does is suspend, never extend. The readers that consult it keep material past the
 * configured window while the hold is active, and the periods the deployment stated stay exactly as
 * stated: no member of this layout edits a retention policy, a configured window or an instruction
 * record, and the suspension is reported beside them rather than folded into them. A reader that
 * consults no hold behaves exactly as it did before, which is the limits sentence's own statement
 * that the suspension reaches only readers that consult it.
 *
 * The consultation rules are pure functions over a parsed record, so every reader that suspends
 * answers one rule rather than its own reading of the prose. `holdActiveAt` asks whether the hold is
 * in force at an instant: from the issue stamp inclusive, until the release stamp exclusive, and a
 * null release is a hold still in force. `holdCoversStamp` asks whether a record stamped at `iat` is
 * under the hold at `now`: the hold is active, and the stamp falls in the window, from inclusive and
 * to exclusive, with a null `to` an open end. `refuseErasureUnderHold` is the erasure arm: an active
 * hold that names the credential, or names none and so covers every credential, refuses the erasure
 * by name before any byte moves. The window is not consulted there, because an erasure takes all of
 * a credential's material at once and a hold naming that credential suspends the whole of it.
 */

/** The versions this module reads, and the only place a hold record version is asked. */
export const HOLD_RECORD_VERSIONS: readonly number[] = [1];

/** The members of the one layout, in the order the writer emits them and the spec publishes them. */
export const HOLD_RECORD_V1_MEMBERS = ['v', 'prov', 'at', 'by', 'window', 'credentials', 'reason', 'released', 'limits'] as const;
export const HOLD_RECORD_WINDOW_MEMBERS = ['from', 'to'] as const;

/**
 * The limits every record states, verbatim. The format owns this sentence rather than the writer: a
 * record whose limits member says anything else is refused, because the one thing a reader of a hold
 * must not have to weigh is whether the record's own account of its limits is true. The sentence
 * states what a hold is and is not: the deployment's own instruction, a suspension only in readers
 * that consult it, no change to any period the deployment stated, no legal determination, and
 * notification deadlines that remain the deployment's process obligations rather than anything this
 * record promises.
 */
export const HOLD_RECORD_LIMITS =
  'This record is the deployment\'s own instruction to preserve, not a legal determination. It ' +
  'suspends erasure and expiry only in readers that consult it, and changes no period the deployment ' +
  'stated. Notification deadlines remain the deployment\'s own process obligations.';

/**
 * The width one authored text member of this layout may hold, in UTF-16 units of the text as this
 * package holds it. The reason is the longest thing a record states; the author and the credential
 * names are labels the deployment chooses, and all of them are printed beside the hold, so one rule
 * reads them all.
 */
export const HOLD_RECORD_TEXT_MAX_UNITS = 400;

/** A hold record at version 1: the whole layout, `credentials` the one member a record may leave off. */
export interface HoldRecord {
  readonly v: 1;
  readonly prov: Provenance;
  /** The issue stamp: when the hold was issued, in unix seconds. */
  readonly at: number;
  /** Who issued the hold, in the deployment's own words. */
  readonly by: string;
  /** The window of record stamps the hold covers: `from` inclusive, `to` exclusive, a null `to` open. */
  readonly window: { readonly from: number; readonly to: number | null };
  /** The credentials the hold names; absent, the hold covers every credential. Non-empty and unique when present. */
  readonly credentials?: readonly string[];
  /** Why the hold was issued, in the deployment's own words. */
  readonly reason: string;
  /** When the hold was released, in unix seconds; null while it is in force. Never before `at`. */
  readonly released: number | null;
  /** The format's limits sentence, verbatim; the reader refuses any other text at this position. */
  readonly limits: string;
}

const text = new TextEncoder();

function bad(detail: string): ReceiptError {
  return new ReceiptError('HOLD_RECORD_BAD_DOCUMENT', detail);
}

function readMap(value: unknown, position: string): JsonObject {
  if (!(value instanceof Map)) throw bad(`${position} is not an object`);
  return value;
}

/**
 * Text the deployment authors: a string, not an empty one, carrying no character of the printed-line
 * class, under the width this layout states and with no pad on either side. The reason is prose; the
 * author and the credential names are labels the deployment chooses, and all of them are printed
 * beside the hold, so one rule reads them all. The class is asked because a character that ends,
 * hides or reorders a row makes the line a reader sees stop being the bytes the record carries.
 */
function requireAuthoredText(value: unknown, position: string): string {
  if (typeof value !== 'string' || text.encode(value).length < 1) {
    throw bad(`${position} must be a non-empty text`);
  }
  const forging = firstForgingCodePoint(value);
  if (forging !== undefined) {
    throw bad(`${position} carries the character U+${forging.toString(16).toUpperCase().padStart(4, '0')}, which forges the line it is printed on`);
  }
  if (value.length > HOLD_RECORD_TEXT_MAX_UNITS) {
    throw bad(`${position} is wider than the ${String(HOLD_RECORD_TEXT_MAX_UNITS)} units this layout holds`);
  }
  if (value.trim() !== value) {
    throw bad(`${position} carries leading or trailing space, which a printed row does not carry`);
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

/** The closure rule: a member the layout does not define makes the document malformed, not read around. */
function assertDefined(raw: JsonObject, members: readonly string[], where: string): void {
  for (const key of raw.keys()) {
    if (typeof key !== 'string' || !members.includes(key)) {
      throw bad(`${where} carries a member this version does not define: ${JSON.stringify(String(key))}`);
    }
  }
}

/**
 * A hold record, out of the bytes of the file as it sits on the volume.
 *
 * The reading is the strict one the retention manifest and the model inventory use, through the same
 * JSON scanner and for the same two reasons: a member named twice would be settled by `JSON.parse`
 * into whichever value the parser reached last while the bytes carry both, and a float wearing an
 * integer arrives at a check as the very number it imitates. The version is asked before any member
 * is read, because which member list applies is the one question a wrong version cannot be talked
 * out of.
 */
export function parseHoldRecord(bytes: Uint8Array): HoldRecord {
  const raw = readJsonBytes(bytes, (detail) => {
    throw bad(detail);
  });
  const document = readMap(raw, 'record');
  const version = document.get('v');
  if (typeof version !== 'number') {
    throw bad('v must be an integer hold record version');
  }
  if (!HOLD_RECORD_VERSIONS.includes(version)) {
    throw new ReceiptError(
      'HOLD_RECORD_UNSUPPORTED_VERSION',
      `hold record version ${String(version)} is not a layout this package reads`,
    );
  }
  assertDefined(document, HOLD_RECORD_V1_MEMBERS, 'record');
  const prov = document.get('prov');
  if (!isProvenance(prov)) {
    throw bad(`prov must be one of ${PROVENANCES.map((one) => `'${one}'`).join(', ')}, got ${typeof prov === 'string' ? `'${prov}'` : String(prov)}`);
  }
  const at = requireStamp(document.get('at'), 'at');
  const by = requireAuthoredText(document.get('by'), 'by');
  const window = readMap(document.get('window'), 'window');
  assertDefined(window, HOLD_RECORD_WINDOW_MEMBERS, 'window');
  const from = requireStamp(window.get('from'), 'window.from');
  const toRaw = window.get('to');
  const to = toRaw === null ? null : requireStamp(toRaw, 'window.to');
  // A window closing before it opens is the record contradicting itself: both ends are inside one
  // document, so a disagreement is a fault of the layout rather than a finding about the matter.
  if (to !== null && to < from) {
    throw bad(`window.to=${String(to)} precedes window.from=${String(from)}, so the window closes before it opens`);
  }
  const credentialsRaw = document.get('credentials');
  let credentials: readonly string[] | undefined;
  if (credentialsRaw !== undefined) {
    if (!Array.isArray(credentialsRaw) || credentialsRaw.length === 0) {
      throw bad('credentials must be a non-empty array when present: a hold naming no credentials leaves the member off, and an empty list would name none while stating it names some');
    }
    const named = new Set<string>();
    credentials = credentialsRaw.map((one, index): string => {
      const site = `credentials[${String(index)}]`;
      const credential = requireAuthoredText(one, site);
      if (named.has(credential)) {
        throw bad(`credentials names ${JSON.stringify(credential)} twice, so one credential is stated twice and its two entries cannot both be read`);
      }
      named.add(credential);
      return credential;
    });
  }
  const reason = requireAuthoredText(document.get('reason'), 'reason');
  const releasedRaw = document.get('released');
  const released = releasedRaw === null ? null : requireStamp(releasedRaw, 'released');
  // A release before the issue is the same self-contradiction the window's ends state: the hold
  // cannot have been released before it existed, and both stamps are inside one record.
  if (released !== null && released < at) {
    throw bad(`released=${String(released)} precedes the hold's issue stamp at=${String(at)}`);
  }
  const limits = document.get('limits');
  if (limits !== HOLD_RECORD_LIMITS) {
    throw bad('limits must state the limits sentence this format owns, verbatim; a record does not word its own limits');
  }
  const record: HoldRecord = { v: 1, prov, at, by, window: { from, to }, reason, released, limits };
  return credentials === undefined ? record : { ...record, credentials };
}

/**
 * The record as a file: two-space indented, newline terminated, in the member order the layout
 * declares. The bytes are what an export item digests and a reviewer hashes, so one record state has
 * to produce one byte string, and a writer that emitted the caller's key order would give two writers
 * of one state two digests. A record that names no credentials leaves the member off the wire rather
 * than writing an empty list, which the reader refuses: absence is the statement that the hold covers
 * every credential, and an empty list would be a hold naming none.
 */
export function encodeHoldRecord(record: HoldRecord): Uint8Array {
  const document: Record<string, unknown> = {
    v: record.v,
    prov: record.prov,
    at: record.at,
    by: record.by,
    window: { from: record.window.from, to: record.window.to },
  };
  if (record.credentials !== undefined) {
    document['credentials'] = [...record.credentials];
  }
  document['reason'] = record.reason;
  document['released'] = record.released;
  document['limits'] = record.limits;
  return text.encode(`${JSON.stringify(document, null, 2)}\n`);
}

/**
 * The bytes this writer would produce for a record, run back through this module's own reader before
 * a caller files them beside the receipts they speak of. A deployment cannot hand over a record its
 * own reader refuses, which is the same promise `modelInventoryBytes` makes: the refusal arrives
 * where the bytes are made rather than at a reviewer holding them later.
 */
export function holdRecordBytes(record: HoldRecord): Uint8Array {
  const bytes = encodeHoldRecord(record);
  parseHoldRecord(bytes);
  return bytes;
}

/**
 * Whether the hold is in force at an instant: from the issue stamp inclusive, until the release stamp
 * exclusive. A null release is a hold still in force. The release comparison is load-bearing: without
 * it a released hold would suspend forever, which is the opposite of what a release states.
 */
export function holdActiveAt(record: HoldRecord, at: number): boolean {
  return record.at <= at && (record.released === null || at < record.released);
}

/**
 * Whether a record stamped at `iat` is under the hold at `now`: the hold is active at `now`, and the
 * stamp falls in the window the hold states, `from` inclusive and `to` exclusive, a null `to` an open
 * end. The two instants are separate questions: `now` asks whether the instruction is in force, and
 * `iat` asks which records it covers, so a hold issued today can cover last month's receipts and a
 * released hold covers nothing however wide its window.
 */
export function holdCoversStamp(record: HoldRecord, iat: number, now: number): boolean {
  return holdActiveAt(record, now) && record.window.from <= iat && (record.window.to === null || iat < record.window.to);
}

/**
 * The erasure arm: refuse, by name, an erasure an active hold suspends. A hold that names the
 * credential suspends it; a hold that names no credentials covers every credential, because absence
 * is the deployment's statement that the whole of its material is under the instruction. The window
 * is not consulted here: an erasure takes all of a credential's material at once, so a hold naming
 * that credential suspends the whole of it rather than a slice. The refusal names the credential and
 * the hold's issue stamp and author, so an operator can see which instruction suspends the call, and
 * it arrives before the caller moves a byte.
 */
export function refuseErasureUnderHold(holds: readonly HoldRecord[], credential: string, at: number): void {
  for (const hold of holds) {
    if (!holdActiveAt(hold, at)) continue;
    if (hold.credentials !== undefined && !hold.credentials.includes(credential)) continue;
    throw new ReceiptError(
      'HOLD_ERASURE_REFUSED',
      `credential ${JSON.stringify(credential)} is under the hold issued at ${String(hold.at)} by ${JSON.stringify(hold.by)}`,
    );
  }
}