import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  INCIDENT_BUNDLE_FLOOR_MEMBERS,
  INCIDENT_BUNDLE_HOLD_MEMBERS,
  INCIDENT_BUNDLE_INCIDENT_MEMBERS,
  INCIDENT_BUNDLE_LIMITS,
  INCIDENT_BUNDLE_POINTERS,
  INCIDENT_BUNDLE_POINTER_CITATIONS,
  INCIDENT_BUNDLE_TEXT_MAX_UNITS,
  INCIDENT_BUNDLE_V1_MEMBERS,
  INCIDENT_BUNDLE_VERSIONS,
  INCIDENT_BUNDLE_WINDOW_MEMBERS,
  ReceiptError,
  decodeExport,
  equalBytes,
  encodeIncidentBundle,
  exportRecordDigest,
  fromBase64Url,
  incidentBundleBytes,
  parseHoldRecord,
  parseIncidentBundle,
  reduceProvenance,
  signExport,
  toBase64Url,
  toHex,
  verifyExport,
  verifyIncidentBundle,
  type ExportAnchoredCollection,
  type ExportChainedItem,
  type ExportManifest,
  type HoldRecord,
  type IncidentBundleRecord,
} from '@ashaveri/receipt';
import { loadExportVectors, loadHoldVectors } from '@ashaveri/fixtures';
import { FIXED_IAT, fixtureKey } from './receipt-envelope.ts';

const DATA = join(dirname(fileURLToPath(import.meta.url)), '..', 'data');

const encoded = (text: string): Uint8Array => new TextEncoder().encode(text);
const decoded = (bytes: Uint8Array): string => new TextDecoder().decode(bytes);

/**
 * The hold this family is built on: the honest record the hold family publishes, read out of that file
 * rather than typed beside it, so the digest the bundle designates, the issue stamp and author it copies
 * and the window it states are one document's facts, and a port handed this family's bytes and the hold
 * family's bytes finds them in agreement.
 */
const HOLD_FAMILY = loadHoldVectors();

function holdRow(name: string): Uint8Array {
  const found = HOLD_FAMILY.vectors.find((one) => one.name === name);
  if (found === undefined) throw new Error(`hold-v1.json publishes no ${name} row to designate`);
  return fromBase64Url(found.recordBase64Url);
}

const HOLD_BYTES = holdRow('hold-fixture-v1');
const HOLD_RECORD: HoldRecord = parseHoldRecord(HOLD_BYTES);

/**
 * The floor's day ceiling, restated here so a refusal row can be built one day past it. This is the
 * reader's own bound and not a second rule: the run at the bottom asks the shipped reader about every row
 * it publishes, so a module that moved its ceiling would make the row beside it answer something other
 * than what it states, and the generation stops rather than publishing a wrong verdict.
 */
const FLOOR_DAYS_MAX = Math.floor(Number.MAX_SAFE_INTEGER / 86_400);

const INCIDENT_AT = FIXED_IAT - 3_600;
const INCIDENT_ID = 'inc-fixture-001';
const INCIDENT_STATES =
  'Fixture statement of the incident the published hold record was issued over: one completion window whose material is under that instruction, stated by the fixture deployer for counsel to weigh.';
const POINTER = INCIDENT_BUNDLE_POINTERS[0]!;

function floorOf(incidentAt: number, days: number): number {
  return incidentAt + days * 86_400;
}

/** The record every refusal row below edits one position of. */
const BASE: IncidentBundleRecord = {
  v: 1,
  prov: 'fixture',
  at: FIXED_IAT,
  incident: { id: INCIDENT_ID, at: INCIDENT_AT, states: INCIDENT_STATES },
  hold: { sha256: toHex(sha256(HOLD_BYTES)), at: HOLD_RECORD.at, by: HOLD_RECORD.by },
  window: { from: HOLD_RECORD.window.from, to: HOLD_RECORD.window.to },
  floor: { days: 30, preserveUntil: floorOf(INCIDENT_AT, 30), pointer: POINTER },
  pointers: [...INCIDENT_BUNDLE_POINTERS],
  limits: INCIDENT_BUNDLE_LIMITS,
};

const RECORD_BYTES = incidentBundleBytes(BASE);

/** The same record stating ninety days, the number the pointer's instrument names, and read anyway. */
const NINETY_DAY_RECORD: IncidentBundleRecord = {
  ...BASE,
  floor: { days: 90, preserveUntil: floorOf(INCIDENT_AT, 90), pointer: POINTER },
};

/**
 * The authored narrative at exactly the width this layout holds. The bound is a number a port can get
 * wrong in either direction, so the family measures it the way the hold family measures its own: one
 * accepted record at the ceiling and one refused record one unit past it, built from one sentence.
 */
const STATES_LEAD = 'A fixture narrative padded to the widest authored text this layout reads: ';
const statesOfUnits = (units: number): string => STATES_LEAD + 'p'.repeat(units - STATES_LEAD.length);
const AT_WIDTH_RECORD: IncidentBundleRecord = {
  ...BASE,
  incident: { ...BASE.incident, states: statesOfUnits(INCIDENT_BUNDLE_TEXT_MAX_UNITS) },
};

/** The floor stated at the widest day count this layout can state as a stamp, its incident at the epoch. */
const AT_CEILING_RECORD: IncidentBundleRecord = {
  ...BASE,
  at: 0,
  incident: { ...BASE.incident, at: 0 },
  floor: { days: FLOOR_DAYS_MAX, preserveUntil: floorOf(0, FLOOR_DAYS_MAX), pointer: POINTER },
};

/** An incident stamp high enough that adding any statable floor to it leaves the range a stamp holds. */
const NEAR_RANGE_INCIDENT_AT = 8_000_000_000_000_000;
const NEAR_RANGE_RECORD: IncidentBundleRecord = {
  ...BASE,
  at: NEAR_RANGE_INCIDENT_AT,
  incident: { ...BASE.incident, at: NEAR_RANGE_INCIDENT_AT },
  floor: {
    days: FLOOR_DAYS_MAX,
    preserveUntil: NEAR_RANGE_INCIDENT_AT + 86_400,
    pointer: POINTER,
  },
};

/**
 * One edit to the writer's own bytes, every other byte left as the writer wrote it, which is how the
 * refusal rows are made: the writer refuses a malformed record, so a refusal row cannot come from it
 * directly, and a row assembled out of junk would test nothing. The writer's format is `JSON.stringify`
 * at two spaces with a trailing newline, so parsing that text, moving one position and writing it back
 * in the same format reproduces the writer's bytes everywhere except the edit.
 */
function editedRecord(base: IncidentBundleRecord, mutate: (document: Record<string, unknown>) => void): Uint8Array {
  const document = JSON.parse(decoded(encodeIncidentBundle(base))) as Record<string, unknown>;
  mutate(document);
  return encoded(`${JSON.stringify(document, null, 2)}\n`);
}

/** The writer's bytes, text-edited at one position, for the two faults a parse cannot survive. */
function editText(base: IncidentBundleRecord, find: string, replace: string): Uint8Array {
  return encoded(decoded(incidentBundleBytes(base)).replace(find, replace));
}

interface Row {
  readonly name: string;
  readonly note: string;
  readonly expected: string;
  readonly bytes: Uint8Array;
  readonly fault?: { readonly at: string; readonly states: string };
}

const ROWS: readonly Row[] = [
  {
    name: 'bundle-fixture-v1',
    note: 'A whole bundle beside the hold record the hold family publishes: the incident the deployment states, the designated hold\'s own digest with its issue stamp and author copied from it, the window copied from it, a floor of thirty days whose stamp recomputes from the incident stamp, the one pointer the registry enumerates, and the format\'s limits sentence verbatim. The provenance is fixture, so the record labels itself as describing fixture material. These are the bytes every refusal row below edits one position of.',
    expected: 'verify-ok',
    bytes: RECORD_BYTES,
  },
  {
    name: 'bundle-floor-days-not-weighed-v1',
    note: 'The same record stating ninety days, the period the cited instrument names, and read exactly as the thirty-day record above is: the days are the deployment\'s own statement, and the reader judges that number against no provision\'s period. The pair is the witness that a floor is a pointer for counsel rather than a compliance claim, because a reader that weighed it would accept one of these two and refuse the other.',
    expected: 'verify-ok',
    bytes: incidentBundleBytes(NINETY_DAY_RECORD),
  },
  {
    name: 'bundle-narrative-at-width-v1',
    note: `A record whose incident narrative is exactly ${String(INCIDENT_BUNDLE_TEXT_MAX_UNITS)} units wide, the ceiling this layout states for every authored text member. The row is the measured half of the bound: the width is the number the rule block publishes, and these accepted bytes beside the refusal one unit wider are what say so.`,
    expected: 'verify-ok',
    bytes: incidentBundleBytes(AT_WIDTH_RECORD),
  },
  {
    name: 'bundle-floor-days-at-ceiling-v1',
    note: `A record stating the widest floor this layout can state, ${String(FLOOR_DAYS_MAX)} days from an incident stamped at the epoch, whose preserveUntil is that product and is still a whole number of unix seconds a reader can hold exactly. The bound on a day count is a bound on what a stamp can say, not on how long a period may be, and this row beside the refusal one day past it is what measures it.`,
    expected: 'verify-ok',
    bytes: incidentBundleBytes(AT_CEILING_RECORD),
  },
  {
    name: 'bundle-floor-preserve-until-moved-v1',
    note: 'The honest record with its floor\'s stamp moved one second, the days and the incident stamp left where they were. Both figures are inside this one record, so a preserveUntil that is not the incident stamp plus the stated days is the document contradicting itself, and the layout door answers it before any hold is handed over: a floor a reviewer reads off the page would otherwise point at an instant no arithmetic in the record states.',
    expected: 'INCIDENT_BUNDLE_BAD_DOCUMENT',
    bytes: editedRecord(BASE, (document) => {
      const floor = document['floor'] as Record<string, unknown>;
      floor['preserveUntil'] = (floor['preserveUntil'] as number) + 1;
    }),
    fault: { at: 'floor.preserveUntil', states: 'a floor stamp that is not the incident stamp plus the stated days' },
  },
  {
    name: 'bundle-floor-days-zero-v1',
    note: 'A record stating a floor of no days. The days are the deployment\'s own undertaking to keep material past the incident, and zero of them is the record stating no undertaking while carrying the member that states it; an open-ended floor is already what the window\'s null end says about reach, and this position says how long, which has to be a number of days.',
    expected: 'INCIDENT_BUNDLE_BAD_DOCUMENT',
    bytes: editedRecord(BASE, (document) => {
      const floor = document['floor'] as Record<string, unknown>;
      floor['days'] = 0;
    }),
    fault: { at: 'floor.days', states: 'a day count that is not a positive whole number' },
  },
  {
    name: 'bundle-floor-days-past-a-statable-floor-v1',
    note: `The widest statable floor with one day added to it, ${String(FLOOR_DAYS_MAX + 1)} days and nothing else moved. Past that count the product of the days and the seconds in a day is no longer a whole number any reader carries exactly, so the floor would be an equality this layout cannot state rather than a disagreement it can refuse; the refusal names the count it met, which is what keeps its own detail statable.`,
    expected: 'INCIDENT_BUNDLE_BAD_DOCUMENT',
    bytes: editedRecord(AT_CEILING_RECORD, (document) => {
      const floor = document['floor'] as Record<string, unknown>;
      floor['days'] = FLOOR_DAYS_MAX + 1;
    }),
    fault: { at: 'floor.days', states: 'a day count whose floor no stamp can state exactly' },
  },
  {
    name: 'bundle-floor-sum-past-a-statable-stamp-v1',
    note: `An incident stamped near the top of the range a stamp holds, with the widest statable floor added to it. The day count is inside the ceiling above and the sum is not, so this is the other half of the same rule: what the layout bounds is the arithmetic a reader has to state, and the refusal names the two terms that do not land inside it rather than printing a recomputed floor that could not be printed.`,
    expected: 'INCIDENT_BUNDLE_BAD_DOCUMENT',
    bytes: editedRecord(NEAR_RANGE_RECORD, (document) => {
      const floor = document['floor'] as Record<string, unknown>;
      floor['preserveUntil'] = NEAR_RANGE_INCIDENT_AT + 86_400;
    }),
    fault: { at: 'floor', states: 'an incident stamp and a floor whose sum leaves the range a unix second holds' },
  },
  {
    name: 'bundle-unknown-member-v1',
    note: 'A well-formed record carrying one member the top level does not define. The layout closes every map it declares, so an unknown member is a malformed document rather than a member a reader agreed to forget, and a bundle that silently carried a notification member would be read as a record that states one.',
    expected: 'INCIDENT_BUNDLE_BAD_DOCUMENT',
    bytes: editedRecord(BASE, (document) => {
      document['future'] = 'a member no version names';
    }),
    fault: { at: 'record', states: 'a top-level member the layout does not define' },
  },
  {
    name: 'bundle-unknown-incident-member-v1',
    note: 'A record whose incident block carries a member the incident does not define, beside the three it does. The closure rule reaches the maps inside the record and not only the record itself: the incident is what this record asserts, and an unlisted position there is a second answer to a question the layout never asks.',
    expected: 'INCIDENT_BUNDLE_BAD_DOCUMENT',
    bytes: editedRecord(BASE, (document) => {
      const incident = document['incident'] as Record<string, unknown>;
      incident['severity'] = 'a claim no member of this layout holds';
    }),
    fault: { at: 'incident', states: 'an incident member the layout does not define' },
  },
  {
    name: 'bundle-unknown-floor-member-v1',
    note: 'A record whose floor block carries a member the floor does not define. The floor is the one figure a reviewer of a bundle reads as an undertaking, so an extension stated beside the days and their recomputed stamp is exactly the position a reader must not have to weigh: either it is in the layout and checked, or the document is malformed.',
    expected: 'INCIDENT_BUNDLE_BAD_DOCUMENT',
    bytes: editedRecord(BASE, (document) => {
      const floor = document['floor'] as Record<string, unknown>;
      floor['extendedBy'] = 'a period no member of this layout holds';
    }),
    fault: { at: 'floor', states: 'a floor member the layout does not define' },
  },
  {
    name: 'bundle-limits-reworded-v1',
    note: 'A record wording its own limits. The limits are the format\'s sentence, verbatim, and a record widening or narrowing them is a document of a shape the layout does not define: the one thing a reader of a bundle must not have to weigh is whether the record\'s own account of its limits is true.',
    expected: 'INCIDENT_BUNDLE_BAD_DOCUMENT',
    bytes: editedRecord(BASE, (document) => {
      document['limits'] = 'This bundle has no limits.';
    }),
    fault: { at: 'limits', states: 'a limits sentence the format does not own' },
  },
  {
    name: 'bundle-version-two-v1',
    note: 'A record declaring a version nothing has published. The version is asked before any member is read, because which member list applies is the one question a wrong version cannot be talked out of.',
    expected: 'INCIDENT_BUNDLE_UNSUPPORTED_VERSION',
    bytes: editedRecord(BASE, (document) => {
      document['v'] = 2;
    }),
    fault: { at: 'v', states: 'a version no layout this package reads defines' },
  },
  {
    name: 'bundle-version-not-an-integer-v1',
    note: 'A record spelling its version as text. The number is asked of a closed list, and a string that looks like one of its members is not that member: the answer is the malformed-document code rather than the unsupported-version one, because the reader never reaches the question of which layout applies.',
    expected: 'INCIDENT_BUNDLE_BAD_DOCUMENT',
    bytes: editedRecord(BASE, (document) => {
      document['v'] = '1';
    }),
    fault: { at: 'v', states: 'a version spelled as text where the layout holds an integer' },
  },
  {
    name: 'bundle-member-named-twice-v1',
    note: 'The writer\'s bytes with the version member written a second time, the two spellings identical. A JSON parse would keep the last and say nothing while the bytes carry both, so the strict reading refuses the document while the characters are still distinguishable.',
    expected: 'INCIDENT_BUNDLE_BAD_DOCUMENT',
    bytes: editText(BASE, '"v": 1,', '"v": 1,\n  "v": 1,'),
    fault: { at: 'record', states: 'the member name v, stated twice in the file\'s own text' },
  },
  {
    name: 'bundle-float-stamp-v1',
    note: 'The assembly stamp written as a fraction that equals the integer it imitates. By the time a field check could ask which spelling the writer chose the two are one JavaScript number, so the reading refuses the spelling rather than the value, and a stamp two documents disagree about in text alone stays a disagreement a reader sees.',
    expected: 'INCIDENT_BUNDLE_BAD_DOCUMENT',
    bytes: editText(BASE, `"at": ${String(FIXED_IAT)}`, `"at": ${String(FIXED_IAT)}.0`),
    fault: { at: 'at', states: 'a number written as a fraction where the layout holds an integer' },
  },
  {
    name: 'bundle-incident-after-assembly-v1',
    note: 'A record whose incident is stamped one second after the bundle that carries it. Both instants are inside one record, so an incident postdating its own statement is another document\'s incident, the same rule the export states beside a claim that outlives the assembly it is made in.',
    expected: 'INCIDENT_BUNDLE_BAD_DOCUMENT',
    bytes: editedRecord(BASE, (document) => {
      const incident = document['incident'] as Record<string, unknown>;
      incident['at'] = FIXED_IAT + 1;
    }),
    fault: { at: 'incident.at', states: 'an incident stamp after the bundle that carries it' },
  },
  {
    name: 'bundle-window-closes-before-opens-v1',
    note: 'The honest record with its copied window end moved before its own start. The hold this record designates states both ends in order, so this is the bundle contradicting itself before it ever contradicts the hold, and the layout door answers it: which of the two the reader was handed stops being a question.',
    expected: 'INCIDENT_BUNDLE_BAD_DOCUMENT',
    bytes: editedRecord(BASE, (document) => {
      const window = document['window'] as Record<string, unknown>;
      window['to'] = (window['from'] as number) - 1;
    }),
    fault: { at: 'window.to', states: 'a window end before the window start beside it' },
  },
  {
    name: 'bundle-negative-stamp-v1',
    note: 'A record opening its window at one second before the unix epoch. Every stamp is a whole number of unix seconds no smaller than zero, and a negative reach is refused rather than read as an open start, because the layout already states an open start as a null at the other end.',
    expected: 'INCIDENT_BUNDLE_BAD_DOCUMENT',
    bytes: editedRecord(BASE, (document) => {
      const window = document['window'] as Record<string, unknown>;
      window['from'] = -1;
    }),
    fault: { at: 'window.from', states: 'a stamp below zero where the layout holds unix seconds' },
  },
  {
    name: 'bundle-narrative-one-unit-wide-v1',
    note: `The record at the width ceiling with one character added to its narrative, ${String(INCIDENT_BUNDLE_TEXT_MAX_UNITS + 1)} units at one position and nothing else moved. A text bound is worth nothing unless it refuses at the step past it, and a reader that truncated rather than refused would report a narrative the record never stated.`,
    expected: 'INCIDENT_BUNDLE_BAD_DOCUMENT',
    bytes: editedRecord(AT_WIDTH_RECORD, (document) => {
      const incident = document['incident'] as Record<string, unknown>;
      incident['states'] = statesOfUnits(INCIDENT_BUNDLE_TEXT_MAX_UNITS + 1);
    }),
    fault: { at: 'incident.states', states: `authored text ${String(INCIDENT_BUNDLE_TEXT_MAX_UNITS + 1)} units wide against the ${String(INCIDENT_BUNDLE_TEXT_MAX_UNITS)} this layout holds` },
  },
  {
    name: 'bundle-padded-narrative-v1',
    note: 'A record whose narrative carries a space at either end. A printed row does not pad itself, and the text that survives a trim is not the text the deployment wrote: the rule is one check on the authored values rather than a repair, because a reader that trimmed would answer for a narrative the record never stated.',
    expected: 'INCIDENT_BUNDLE_BAD_DOCUMENT',
    bytes: editedRecord(BASE, (document) => {
      const incident = document['incident'] as Record<string, unknown>;
      incident['states'] = ` ${INCIDENT_STATES} `;
    }),
    fault: { at: 'incident.states', states: 'authored text padded on either side' },
  },
  {
    name: 'bundle-forging-character-in-incident-id-v1',
    note: 'A record whose incident identity carries one character of the printed-line class, the code point that reverses the order the rest of the row renders in. Every authored text is asked of that class because a bundle is printed beside the hold and the receipts it names: an identity that reorders a row makes the line a reviewer reads a different document than the bytes.',
    expected: 'INCIDENT_BUNDLE_BAD_DOCUMENT',
    bytes: editedRecord(BASE, (document) => {
      const incident = document['incident'] as Record<string, unknown>;
      incident['id'] = 'inc\u202Eident';
    }),
    fault: { at: 'incident.id', states: 'a character that forges the printed line it is printed on' },
  },
  {
    name: 'bundle-unknown-pointer-v1',
    note: 'A well-formed record whose pointer list names a label one paragraph short of the registry entry: a near miss of the provision the registry holds rather than a label no instrument resembles. The document is whole and it is the provision it names that this reader has no pointer for, which is the refusal INCIDENT_BUNDLE_UNKNOWN_POINTER exists for, apart from a malformed document.',
    expected: 'INCIDENT_BUNDLE_UNKNOWN_POINTER',
    bytes: editedRecord(BASE, (document) => {
      document['pointers'] = ['gsa-552-239-7001-f-6'];
    }),
    fault: { at: 'pointers[0]', states: 'a label the pointer registry does not hold' },
  },
  {
    name: 'bundle-floor-pointer-unknown-v1',
    note: 'The same label moved at the position the floor itself names, where the array of counsel pointers agrees with the registry. Which position a pointer is refused at is a fact about the record: the floor\'s pointer is the provision its own stamp is weighed against, and a registry answer to a list cannot settle it.',
    expected: 'INCIDENT_BUNDLE_UNKNOWN_POINTER',
    bytes: editedRecord(BASE, (document) => {
      const floor = document['floor'] as Record<string, unknown>;
      floor['pointer'] = 'gsa-552-239-7001-f-6';
    }),
    fault: { at: 'floor.pointer', states: 'a label the pointer registry does not hold' },
  },
  {
    name: 'bundle-pointer-not-text-v1',
    note: 'A record whose pointers list carries a number where a label sits. A pointer is a citation counsel reads off the page, and a value that is not text names no instrument at all, so the answer is the malformed-document code rather than the unknown-pointer one: the reader never reaches the question of which provision is named.',
    expected: 'INCIDENT_BUNDLE_BAD_DOCUMENT',
    bytes: editedRecord(BASE, (document) => {
      document['pointers'] = [7001];
    }),
    fault: { at: 'pointers[0]', states: 'a pointer that is not a text label' },
  },
  {
    name: 'bundle-empty-pointers-v1',
    note: 'A record whose pointer list is empty while its floor states a provision it is weighed against. An empty list would leave the floor\'s own pointer the only citation in the document, which is the same vacuity the pack and the model inventory refuse beside an empty list of their own: a record whose figures are vacuous reads as evidence while attesting nothing.',
    expected: 'INCIDENT_BUNDLE_BAD_DOCUMENT',
    bytes: editedRecord(BASE, (document) => {
      document['pointers'] = [];
    }),
    fault: { at: 'pointers', states: 'the non-empty list the layout requires, emptied' },
  },
  {
    name: 'bundle-duplicate-pointer-v1',
    note: 'A record naming the one registered label twice. The list is a set of provisions a floor is weighed against, so a duplicate says nothing new while making a refusal ambiguous about which entry it answers, and the unique rule is what keeps the list a statement rather than a transcript.',
    expected: 'INCIDENT_BUNDLE_BAD_DOCUMENT',
    bytes: editedRecord(BASE, (document) => {
      document['pointers'] = [POINTER, POINTER];
    }),
    fault: { at: 'pointers[1]', states: 'the pointer pointers[0] already names' },
  },
];

/** What the shipped layout door answers for each row, so the file cannot lie about itself. */
function verdictOf(bytes: Uint8Array): string {
  try {
    parseIncidentBundle(bytes);
    return 'verify-ok';
  } catch (err) {
    if (err instanceof ReceiptError) return err.code;
    throw err;
  }
}

interface VerifyCase {
  readonly name: string;
  readonly note: string;
  readonly expected: string;
  readonly recordBytes: Uint8Array;
  /** The hold-family row whose published bytes the call is handed. */
  readonly holdRow: string;
  readonly holdBytes: Uint8Array;
  /** Where the record and the designated hold disagree, on the cases that say so. */
  readonly disagree?: { readonly at: string; readonly states: string; readonly binds: string };
}

/** The hold the honest bundle does not designate: a whole record of its own, released since. */
const OTHER_HOLD_BYTES = holdRow('hold-released-v1');

/** A document the hold reader refuses: whole JSON, and a member the hold layout does not define. */
const UNREADABLE_HOLD_BYTES = holdRow('hold-unknown-member-v1');

/** The hold that states no window end and names no credential, the other bound shape worth reading. */
const OPEN_HOLD_BYTES = holdRow('hold-covers-every-credential-v1');
const OPEN_HOLD_RECORD = parseHoldRecord(OPEN_HOLD_BYTES);
const RECORD_DESIGNATING_OPEN: IncidentBundleRecord = {
  ...BASE,
  hold: { sha256: toHex(sha256(OPEN_HOLD_BYTES)), at: OPEN_HOLD_RECORD.at, by: OPEN_HOLD_RECORD.by },
  window: { from: OPEN_HOLD_RECORD.window.from, to: OPEN_HOLD_RECORD.window.to },
};

/**
 * A bundle whose designation is exactly the unreadable document's digest, with the copied fields left
 * agreeing with the hold this family is built on. Designating the refused bytes is what reaches the
 * unreadable refusal at all: the digest is weighed before the hold is read, so a record naming other bytes
 * is refused for the wrong reason and never reaches the question of whether these can be read.
 */
const RECORD_DESIGNATING_UNREADABLE: IncidentBundleRecord = {
  ...BASE,
  hold: { ...BASE.hold, sha256: toHex(sha256(UNREADABLE_HOLD_BYTES)) },
};

const VERIFY_CASES: readonly VerifyCase[] = [
  {
    name: 'verified-honest-hold',
    note: 'The honest bundle beside the exact bytes of the hold it designates, the record the hold family publishes. The digest matches, the hold reads, and every copied field agrees, which is the pair this family is built on and the row every case below moves one side of.',
    expected: 'verify-ok',
    recordBytes: RECORD_BYTES,
    holdRow: 'hold-fixture-v1',
    holdBytes: HOLD_BYTES,
  },
  {
    name: 'verified-open-window-hold',
    note: 'A bundle designating the hold family\'s open record: the one that leaves the credentials member off and states no window end. A null end is a bound field like any other, copied and compared, and this row is what says the verifying door reads that null rather than replacing it with a number or refusing it as missing.',
    expected: 'verify-ok',
    recordBytes: incidentBundleBytes(RECORD_DESIGNATING_OPEN),
    holdRow: 'hold-covers-every-credential-v1',
    holdBytes: OPEN_HOLD_BYTES,
  },
  {
    name: 'bound-mutated-hold-at-refused',
    note: 'The honest bundle with its copied hold issue stamp moved one second, beside the untouched hold bytes. The stamp is copied from that record and checked against it, so a bundle stating another instant is contradicting the hold it designates, and the refusal names both values and the position they disagree at.',
    expected: 'INCIDENT_BUNDLE_BOUND_DISAGREES',
    recordBytes: editedRecord(BASE, (document) => {
      const hold = document['hold'] as Record<string, unknown>;
      hold['at'] = HOLD_RECORD.at + 1;
    }),
    holdRow: 'hold-fixture-v1',
    holdBytes: HOLD_BYTES,
    disagree: { at: 'hold.at', states: String(HOLD_RECORD.at + 1), binds: String(HOLD_RECORD.at) },
  },
  {
    name: 'bound-mutated-window-to-refused',
    note: 'The honest bundle with its copied window end moved one second past the hold\'s own, the start left agreeing. One of four bound fields disagreeing is enough to refuse the pair: the window this record states is a claim about which records the designated hold covers, and a reader that weighed only the first field would accept a bundle whose reach claim is false.',
    expected: 'INCIDENT_BUNDLE_BOUND_DISAGREES',
    recordBytes: editedRecord(BASE, (document) => {
      const window = document['window'] as Record<string, unknown>;
      window['to'] = (window['to'] as number) + 1;
    }),
    holdRow: 'hold-fixture-v1',
    holdBytes: HOLD_BYTES,
    disagree: {
      at: 'window.to',
      states: String((HOLD_RECORD.window.to ?? 0) + 1),
      binds: String(HOLD_RECORD.window.to ?? 0),
    },
  },
  {
    name: 'asserted-mutation-read',
    note: 'The honest bundle with one asserted field moved: the narrative is another statement the deployment could make about the same incident. Nothing in the designated hold compares against it, so the verifying door reads it and reports the record whole, while the bound fields still agree. This row and the two above are the split\'s witness: a bound mutation is refused and an asserted mutation is read.',
    expected: 'verify-ok',
    recordBytes: editedRecord(BASE, (document) => {
      const incident = document['incident'] as Record<string, unknown>;
      incident['states'] = 'A narrative the fixture deployer stated after assembly.';
    }),
    holdRow: 'hold-fixture-v1',
    holdBytes: HOLD_BYTES,
  },
  {
    name: 'hold-mismatch-refused',
    note: 'The honest bundle beside the bytes of a different hold, the released record the hold family publishes: whole, readable, and not the document this record designates. The digest refuses before a copied field is read, because comparing against bytes the record never named would be comparing it against a document it never named.',
    expected: 'INCIDENT_BUNDLE_HOLD_MISMATCH',
    recordBytes: RECORD_BYTES,
    holdRow: 'hold-released-v1',
    holdBytes: OTHER_HOLD_BYTES,
  },
  {
    name: 'hold-unreadable-refused',
    note: 'A bundle designating the hold family\'s own refused bytes and handed exactly those: the designation is right, the hold cannot be read, and the answer is neither a malformed bundle nor a disagreement about a field. There is nothing on the other side to compare the copied claims to, so the hold\'s own refusal rides in the detail and an operator sees which position the hold failed at. A record designating the honest hold beside these bytes would be refused for the designation first, which is the row above.',
    expected: 'INCIDENT_BUNDLE_HOLD_UNREADABLE',
    recordBytes: incidentBundleBytes(RECORD_DESIGNATING_UNREADABLE),
    holdRow: 'hold-unknown-member-v1',
    holdBytes: UNREADABLE_HOLD_BYTES,
  },
];

/** The hold-family row this bundle designates, spelled as the hold family publishes it. */
const DESIGNATED_HOLD_ROW = 'hold-fixture-v1';

/** Counts stated as words, because published prose spells its numbers rather than showing digits. */
const COUNT_WORDS = ['zero', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'ten'] as const;

/**
 * The hold-family rows the verification cases hand over besides the one this bundle designates. The
 * published note counts these rather than repeating a numeral of its own, because a note written by hand
 * can say one count while the cases carry another, and the count is a claim about this list.
 */
const OTHER_HOLD_ROWS: readonly string[] = [
  ...new Set(VERIFY_CASES.map((one) => one.holdRow)),
].filter((name) => name !== DESIGNATED_HOLD_ROW);

/** The count of `OTHER_HOLD_ROWS` as the published prose states it. */
const OTHER_HOLD_ROW_COUNT = COUNT_WORDS[OTHER_HOLD_ROWS.length] ?? String(OTHER_HOLD_ROWS.length);

function verifyVerdictOf(one: VerifyCase): string {
  try {
    verifyIncidentBundle(one.recordBytes, { holdBytes: one.holdBytes });
    return 'verify-ok';
  } catch (err) {
    if (err instanceof ReceiptError) return err.code;
    throw err;
  }
}

/**
 * The export ride, which is this family\'s acceptance clause. The document is the technical export the
 * export family publishes as its honest anchored run, extended by two inline items: the hold record whose
 * bytes the bundle designates, and the bundle itself. The three receipt records are reused as that run
 * chained them, from the anchor and head the export family\'s own document states, so the ride is the
 * published contract carrying published material and two more originals rather than a container assembled
 * for the purpose. It is signed by the fixture receipt key, the same key the model inventory ride is signed
 * by, and no member of the export contract moves for either record.
 */
const EXPORT_KEY = fixtureKey();
const HOLD_ITEM_ID = 'hold-fixture-v1';
const BUNDLE_ITEM_ID = 'incident-bundle-fixture-v1';

const EXPORT_FAMILY = loadExportVectors();
const ANCHORED_ROW = EXPORT_FAMILY.vectors.find((one) => one.name === 'well-formed-anchored');
if (ANCHORED_ROW === undefined) throw new Error('export-v1.json publishes no well-formed-anchored document to extend');
const PUBLISHED_DECODED = decodeExport(fromBase64Url(ANCHORED_ROW.documentBase64Url));
if (PUBLISHED_DECODED.manifest.collection.k !== 'anchored') {
  throw new Error('the export family\'s honest document is not the anchored arm this ride extends');
}
const PUBLISHED_COLLECTION = PUBLISHED_DECODED.manifest.collection as ExportAnchoredCollection;
const RECEIPT_ITEMS: readonly ExportChainedItem[] = PUBLISHED_COLLECTION.items;

function chainedItem(one: { id: string; iat: number; bytes: Uint8Array }, prev: Uint8Array): ExportChainedItem {
  return { id: one.id, iat: one.iat, prov: 'fixture', d: sha256(one.bytes), p: prev, orig: { k: 'inline', bytes: one.bytes } };
}

/** The published run, then the hold it speaks of, then the bundle that designates that hold's exact bytes. */
const RIDE_ITEMS: readonly ExportChainedItem[] = [
  ...RECEIPT_ITEMS,
  chainedItem({ id: HOLD_ITEM_ID, iat: FIXED_IAT, bytes: HOLD_BYTES }, PUBLISHED_COLLECTION.head),
  chainedItem(
    { id: BUNDLE_ITEM_ID, iat: FIXED_IAT, bytes: RECORD_BYTES },
    exportRecordDigest({ id: HOLD_ITEM_ID, iat: FIXED_IAT, p: PUBLISHED_COLLECTION.head, bytes: HOLD_BYTES }),
  ),
];
const RIDE_HEAD = exportRecordDigest({
  id: BUNDLE_ITEM_ID,
  iat: FIXED_IAT,
  p: exportRecordDigest({ id: HOLD_ITEM_ID, iat: FIXED_IAT, p: PUBLISHED_COLLECTION.head, bytes: HOLD_BYTES }),
  bytes: RECORD_BYTES,
});

const RIDE_COLLECTION: ExportAnchoredCollection = {
  k: 'anchored',
  prov: reduceProvenance(RIDE_ITEMS.map((one) => one.prov)),
  anchor: PUBLISHED_COLLECTION.anchor,
  head: RIDE_HEAD,
  items: RIDE_ITEMS,
};

const RIDE_MANIFEST: ExportManifest = {
  v: 1,
  at: FIXED_IAT,
  assessment: { k: 'none', states: 'No assessment is stated by this fixture export.' },
  collection: RIDE_COLLECTION,
  claim: {
    made: FIXED_IAT,
    by: 'the fixture deployer',
    kind: 'provenance',
    states: 'Fixture hold record and incident preservation bundle riding the published export contract beside the fixture receipts.',
  },
};
const RIDE_BYTES = signExport(RIDE_MANIFEST, EXPORT_KEY);
const RIDE_WALKED = RIDE_ITEMS.map((one) => one.id);

/**
 * What the published doors answer for the ride, in the order the acceptance clause states it: the export
 * closes its own walk, each item's original bytes are the record bytes the families publish read back
 * through that record's own door, and the bundle verifies against the hold bytes taken out of the export
 * rather than out of this file. The floor is then recomputed from the record the ride carries, because the
 * claim a bundle makes about a period is only worth publishing if the stamp beside it still follows.
 */
function witnessTheRide(): void {
  const verified = verifyExport(RIDE_BYTES, EXPORT_KEY.publicKey);
  const outcome = verified.outcome;
  if (outcome.kind !== 'anchored') throw new Error('the ride is not the anchored arm it was assembled as');
  const walked = outcome.walked.map((one) => one.id);
  if (walked.join(',') !== RIDE_WALKED.join(',')) {
    throw new Error(`the ride walks ${walked.join(', ')}, not ${RIDE_WALKED.join(', ')}`);
  }
  /** One item's inline original, named by id, or the run stops: the ride states nothing it does not carry. */
  const items = outcome.items;
  const inlineBytesOf = (id: string): Uint8Array => {
    const found = items.find((one) => one.id === id);
    if (found === undefined) throw new Error(`the ride carries no item named ${id}`);
    if (found.orig.k !== 'inline') throw new Error(`the ride's ${id} item is not an inline original`);
    return found.orig.bytes;
  };
  const holdBytesFromRide = inlineBytesOf(HOLD_ITEM_ID);
  const bundleBytesFromRide = inlineBytesOf(BUNDLE_ITEM_ID);
  if (!equalBytes(holdBytesFromRide, HOLD_BYTES)) throw new Error('the ride\'s hold item is not the hold family\'s published bytes');
  if (!equalBytes(bundleBytesFromRide, RECORD_BYTES)) throw new Error('the ride\'s bundle item is not the record bytes this family publishes');
  const holdFromRide = parseHoldRecord(holdBytesFromRide);
  if (JSON.stringify(holdFromRide) !== JSON.stringify(HOLD_RECORD)) {
    throw new Error('the hold read out of the ride is not the record the hold family publishes');
  }
  const verifiedRecord = verifyIncidentBundle(bundleBytesFromRide, { holdBytes: holdBytesFromRide }).record;
  if (verifiedRecord.floor.preserveUntil !== verifiedRecord.incident.at + verifiedRecord.floor.days * 86_400) {
    throw new Error('the floor the ride carries does not recompute from the incident stamp and the stated days');
  }
  if (verifiedRecord.hold.sha256 !== toHex(sha256(holdBytesFromRide))) {
    throw new Error('the ride\'s bundle does not designate the hold bytes it rides beside');
  }
}

function main(): void {
  const layoutAnswers = ROWS.map((one) => {
    const observed = verdictOf(one.bytes);
    if (observed !== one.expected) {
      throw new Error(`${one.name}: the reader answers ${observed}, not the ${one.expected} this row states`);
    }
    return observed;
  });
  const verifyAnswers = VERIFY_CASES.map((one) => {
    const observed = verifyVerdictOf(one);
    if (observed !== one.expected) {
      throw new Error(`${one.name}: the verifying door answers ${observed}, not the ${one.expected} this case states`);
    }
    return observed;
  });
  witnessTheRide();

  const vectors = ROWS.map((one, index) => ({
    name: one.name,
    note: one.note,
    expected: layoutAnswers[index]!,
    recordBase64Url: toBase64Url(one.bytes),
    recordByteLength: one.bytes.length,
    ...(one.fault === undefined ? {} : { fault: one.fault }),
  }));

  const verifyCases = VERIFY_CASES.map((one, index) => ({
    name: one.name,
    note: one.note,
    expected: verifyAnswers[index]!,
    recordBase64Url: toBase64Url(one.recordBytes),
    holdRow: one.holdRow,
    holdBase64Url: toBase64Url(one.holdBytes),
    ...(one.disagree === undefined ? {} : { disagree: one.disagree }),
  }));

  writeFileSync(
    join(DATA, 'incident-bundle-v1.json'),
    JSON.stringify(
      {
        version: 1,
        description:
          'The incident preservation bundle beside the hold record it designates and the receipts that attest the material: the layout its strict reader reads, the bound and asserted fields the layout keeps apart, the pointer registry it enumerates, the limits sentence every record states verbatim, and the floor arithmetic the layout door recomputes rather than believes. The designated hold is the record the hold family publishes, byte for byte out of that file, so the digest, the copied issue stamp and author and the copied window are one document\'s facts and a port handed both families finds them in agreement. Every row is labeled fixture and speaks of fixture material, and the preservation floor is a pointer for counsel rather than a conclusion about a provision: the accepted records state thirty days and ninety days and the reader answers the same way for both, because the days are the deployment\'s own statement and no period here weighs them. The layout rows carry the bytes the shipped writer made, or one edit of them at the position the fault names, and the verdict `parseIncidentBundle` answers for them. The verification cases carry the record beside the hold bytes it designates and the answer `verifyIncidentBundle` owes the pair, including the mutation pair that witnesses the split: a bound mutation refused and an asserted mutation read, and the two refusals that name which document the reader was handed rather than which field moved. The export ride publishes the hold and the bundle as two more inline items of the technical export the export family publishes for its honest anchored run, signed by the fixture receipt key, which the shipped reader closes over and reads back through both records\' own doors; no member of the export contract moves for either record.',
        rule: {
          registry: 'docs/receipt-spec.md section 4.11',
          reader: 'parseIncidentBundle in @ashaveri/receipt',
          verifier: 'verifyIncidentBundle in @ashaveri/receipt',
          writer: 'incidentBundleBytes in @ashaveri/receipt',
          doors: 'The layout door answers the record\'s own shape and arithmetic, and the floor is part of that: preserveUntil is recomputed from the incident stamp and the stated days, both inside this one document, and no byte outside it is read. The verifying door is handed the designated hold\'s bytes and compares the copied fields against them, field by field, naming both values. What neither door asks is whether the days are the right number: they are the deployment\'s own statement, weighed against no provision\'s period.',
          versions: [...INCIDENT_BUNDLE_VERSIONS],
          members: [...INCIDENT_BUNDLE_V1_MEMBERS],
          incidentMembers: [...INCIDENT_BUNDLE_INCIDENT_MEMBERS],
          holdMembers: [...INCIDENT_BUNDLE_HOLD_MEMBERS],
          windowMembers: [...INCIDENT_BUNDLE_WINDOW_MEMBERS],
          floorMembers: [...INCIDENT_BUNDLE_FLOOR_MEMBERS],
          pointers: [...INCIDENT_BUNDLE_POINTERS],
          pointerCitations: { ...INCIDENT_BUNDLE_POINTER_CITATIONS },
          limits: INCIDENT_BUNDLE_LIMITS,
          textMaxUnits: INCIDENT_BUNDLE_TEXT_MAX_UNITS,
          boundFields: ['hold.at', 'hold.by', 'window.from', 'window.to'],
          assertedFields: ['incident.id', 'incident.at', 'incident.states', 'floor.days'],
          floor: {
            incidentAt: INCIDENT_AT,
            days: BASE.floor.days,
            preserveUntil: BASE.floor.preserveUntil,
            daysMax: FLOOR_DAYS_MAX,
            note: 'Unix seconds and whole days. The floor is the incident stamp plus the stated days in seconds, recomputed by the reader; daysMax is the widest count whose product with 86400 is still a whole number a reader carries exactly. Nothing here weighs a period: the rows state thirty, ninety and the ceiling itself, and the reader answers for each on the arithmetic alone.',
          },
          instants: {
            assembly: FIXED_IAT,
            incidentAt: INCIDENT_AT,
            holdIssue: HOLD_RECORD.at,
            windowFrom: HOLD_RECORD.window.from,
            windowTo: HOLD_RECORD.window.to,
            receiptFixtureStamp: FIXED_IAT,
            note: 'Unix seconds. The assembly stamp is the instant every published receipt fixture is issued at, the incident is stamped one hour before it, and the window and hold issue stamp are read out of the designated hold rather than typed beside it. Nothing here is a deployment\'s date: these are fixture instants, stated so a port can hand its own reader the same numbers.',
          },
          hold: {
            row: 'hold-v1.json#hold-fixture-v1',
            recordBase64Url: toBase64Url(HOLD_BYTES),
            note: `The hold this record designates, byte for byte the row the hold family publishes, together with the ${OTHER_HOLD_ROW_COUNT} other published hold rows the verification cases hand over: the open record whose null window end is a bound field like any other, the released record that is whole but not this record's hold, and the refused document that makes the unreadable refusal a finding about the hold rather than about the bundle. Each case carries its own hold bytes, so a port replays a pair without reaching into another family.`,
          },
          unsigned: 'An incident preservation bundle carries no signature, as the hold record and the model inventory carry none. No row of this family is sealed by a key of its own, and no digest of a record is claimed by anything here: what a reader weighs is the layout, the designated hold\'s bytes and the arithmetic of the floor. The export container is what carries these bytes as evidence under its own signature, and the ride below is that statement measured rather than asserted.',
          exportRide: {
            exportBase64Url: toBase64Url(RIDE_BYTES),
            publicKeyBase64Url: toBase64Url(EXPORT_KEY.publicKey),
            receiptItemIds: RECEIPT_ITEMS.map((one) => one.id),
            holdItemId: HOLD_ITEM_ID,
            bundleItemId: BUNDLE_ITEM_ID,
            walkedItemIds: RIDE_WALKED,
            floor: BASE.floor.preserveUntil,
            note: 'The hold record and the bundle as two inline items of the anchored export the export family publishes for its honest run, signed by the fixture receipt key. verifyExport closes the walk over all five records; each item\'s original bytes are read back through the shipped door of the record it carries, and the bundle is verified against the hold bytes taken out of the export itself, so the pair the ride attests is the pair this family publishes. The floor stated beside it is the preserveUntil of the record the ride carries, recomputed from the incident stamp and the days the same bytes state. No member of the export contract moved for either record.',
          },
          encodings: 'byte strings unpadded base64url, digests lowercase hex, instants whole numbers of unix seconds',
        },
        vectors,
        verifyCases,
      },
      null,
      2,
    ) + '\n',
  );

  for (const one of vectors) console.log(`${one.name}: ${one.expected}`);
  for (const one of verifyCases) console.log(`${one.name}: ${one.expected}`);
}

main();
