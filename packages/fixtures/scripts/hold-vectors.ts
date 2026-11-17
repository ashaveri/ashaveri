import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  HOLD_RECORD_LIMITS,
  HOLD_RECORD_TEXT_MAX_UNITS,
  HOLD_RECORD_V1_MEMBERS,
  HOLD_RECORD_VERSIONS,
  HOLD_RECORD_WINDOW_MEMBERS,
  ReceiptError,
  holdActiveAt,
  holdCoversStamp,
  holdRecordBytes,
  parseHoldRecord,
  refuseErasureUnderHold,
  toBase64Url,
  type HoldRecord,
} from '@ashaveri/receipt';
import { FIXED_IAT } from './receipt-envelope.ts';

const DATA = join(dirname(fileURLToPath(import.meta.url)), '..', 'data');

const encoded = (text: string): Uint8Array => new TextEncoder().encode(text);
const decoded = (bytes: Uint8Array): string => new TextDecoder().decode(bytes);

/**
 * The fixture instants, stated once.
 *
 * The issue stamp is the instant every published receipt fixture is issued at, and the window reaches a
 * day either side of it, so a coverage row can be read against a stamp this repository already publishes
 * rather than against a number only this file knows. The release stamp is one hundred seconds after the
 * issue, which is wide enough to keep the three calls around it (one second before, exactly at, one
 * second after) distinguishable in a row's note and narrow enough to read as one working session.
 */
const ISSUE = FIXED_IAT;
const WINDOW_FROM = FIXED_IAT - 86_400;
const WINDOW_TO = FIXED_IAT + 86_400;
const RELEASED = FIXED_IAT + 100;
const BY = 'the fixture deployer';
const HELD = 'cred-fixture-held';
const ELSEWHERE = 'cred-fixture-elsewhere';
const REASON =
  'Fixture hold over the material the published receipts attest, issued so that this suite reads its own bytes against a rule it ships.';

/**
 * The record the family is built on: credentials named, a window with both ends stated, no release.
 * Every refusal row is one edit of the bytes this record's writer produces, so each row tests the rule
 * it names and not the accident of a document assembled out of junk.
 */
const BASE: HoldRecord = {
  v: 1,
  prov: 'fixture',
  at: ISSUE,
  by: BY,
  window: { from: WINDOW_FROM, to: WINDOW_TO },
  credentials: [HELD, ELSEWHERE],
  reason: REASON,
  released: null,
  limits: HOLD_RECORD_LIMITS,
};

/** The one member a record may leave off, left off: absence is the statement that every credential is under the hold. */
const { credentials: _credentials, ...BASE_WITHOUT_CREDENTIALS } = BASE;
const OPEN_HOLD: HoldRecord = { ...BASE_WITHOUT_CREDENTIALS, window: { from: WINDOW_FROM, to: null } };

/** The same hold after its own release, the only shape at which the suspension lifts without a byte moving. */
const RELEASED_HOLD: HoldRecord = { ...BASE, released: RELEASED };

/**
 * A hold whose window lies wholly before its own issue stamp, which the layout allows on purpose: the
 * window says which record stamps are under the instruction and the issue stamp says when the
 * instruction was given, and the two are separate questions. This is the record the erasure arm and the
 * coverage arm disagree about, which is the pair that proves the window is weighed at one door only.
 */
const PAST_WINDOW_HOLD: HoldRecord = { ...BASE, window: { from: ISSUE - 200, to: ISSUE - 100 } };

/** A hold naming the other credential, for the row where the list a caller is handed holds two instructions. */
const ELSEWHERE_HOLD: HoldRecord = { ...BASE, credentials: [ELSEWHERE] };

/**
 * A reason carrying exactly the units this layout holds, and one more than that.
 *
 * The width is a bound a port can get wrong in either direction, so the family measures it rather than
 * quoting it: one accepted record at the ceiling and one refused record one unit past it, both built from
 * the same sentence, which is the pair that says the ceiling is the number the published rule block
 * states and not a word in a document.
 */
const REASON_LEAD = 'A fixture reason padded to the widest authored text this layout reads: ';
const reasonOfUnits = (units: number): string => REASON_LEAD + 'p'.repeat(units - REASON_LEAD.length);
const AT_WIDTH_HOLD: HoldRecord = { ...BASE, reason: reasonOfUnits(HOLD_RECORD_TEXT_MAX_UNITS) };

/**
 * One edit to the writer's own bytes, every other byte left as the writer wrote it, which is how the
 * refusal rows are made: the writer refuses a malformed record, so a refusal row cannot come from it
 * directly, and a row assembled out of junk would test nothing. The writer's format is `JSON.stringify`
 * at two spaces with a trailing newline, so parsing that text, moving one position and writing it back
 * in the same format reproduces the writer's bytes everywhere except the edit.
 */
function editedRecord(base: HoldRecord, mutate: (document: Record<string, unknown>) => void): Uint8Array {
  const document = JSON.parse(decoded(holdRecordBytes(base))) as Record<string, unknown>;
  mutate(document);
  return encoded(`${JSON.stringify(document, null, 2)}\n`);
}

interface Row {
  readonly name: string;
  readonly note: string;
  readonly expected: string;
  readonly bytes: Uint8Array;
  readonly fault?: { readonly at: string; readonly states: string };
}

/** The writer's bytes, text-edited at one position, for the two faults a parse cannot survive: a name stated twice and a number spelled as a fraction. */
function editText(base: HoldRecord, find: string, replace: string): Uint8Array {
  return encoded(decoded(holdRecordBytes(base)).replace(find, replace));
}

const ROWS: readonly Row[] = [
  {
    name: 'hold-fixture-v1',
    note: 'A whole record: issued at the instant the published receipt fixtures are issued at, covering the window a day either side of it, naming two credentials, stating a reason in the deployer\'s own words, released at nothing, and closing with the format\'s limits sentence verbatim. These are the bytes every refusal row below edits one position of.',
    expected: 'verify-ok',
    bytes: holdRecordBytes(BASE),
  },
  {
    name: 'hold-covers-every-credential-v1',
    note: 'A record leaving the credentials member off and opening its window with no end: `to` is null and `credentials` is absent, which are the layout\'s two statements of an open reach. The member is the one a record may omit, and an omission is read here rather than defaulted, so the writer emits no empty list for it and the reader below refuses one.',
    expected: 'verify-ok',
    bytes: holdRecordBytes(OPEN_HOLD),
  },
  {
    name: 'hold-released-v1',
    note: 'A record that released itself one hundred seconds after it was issued. A release is a value the same member carries as an open hold\'s null, so the accepted shape of a closed hold is published beside the open one rather than left for a port to infer from a refusal row.',
    expected: 'verify-ok',
    bytes: holdRecordBytes(RELEASED_HOLD),
  },
  {
    name: 'hold-reason-at-width-limit-v1',
    note: `A record whose reason is exactly ${String(HOLD_RECORD_TEXT_MAX_UNITS)} units wide, the ceiling this layout states for every authored text member. The row is the measured half of the bound: the width is the number the rule block publishes, and the accepted bytes beside the refusal one unit wider are what say so.`,
    expected: 'verify-ok',
    bytes: holdRecordBytes(AT_WIDTH_HOLD),
  },
  {
    name: 'hold-reason-one-unit-wide-v1',
    note: `The row above with one character added to its reason, ${String(HOLD_RECORD_TEXT_MAX_UNITS + 1)} units at one position and nothing else moved. A text bound is worth nothing unless it refuses at the step past it, and a reader that truncates rather than refuses would accept a record whose printed row it had already shortened.`,
    expected: 'HOLD_RECORD_BAD_DOCUMENT',
    bytes: editedRecord(AT_WIDTH_HOLD, (document) => {
      document['reason'] = reasonOfUnits(HOLD_RECORD_TEXT_MAX_UNITS + 1);
    }),
    fault: { at: 'reason', states: `authored text ${String(HOLD_RECORD_TEXT_MAX_UNITS + 1)} units wide against the ${String(HOLD_RECORD_TEXT_MAX_UNITS)} this layout holds` },
  },
  {
    name: 'hold-version-two-v1',
    note: 'A record declaring a version nothing has published. The version is asked before any member is read, because which member list applies is the one question a wrong version cannot be talked out of, and this is the only refusal this layout answers with a code of its own.',
    expected: 'HOLD_RECORD_UNSUPPORTED_VERSION',
    bytes: editedRecord(BASE, (document) => {
      document['v'] = 2;
    }),
    fault: { at: 'v', states: 'a version no layout this package reads defines' },
  },
  {
    name: 'hold-version-not-an-integer-v1',
    note: 'A record spelling its version as text. The number is asked of a closed list, and a string that looks like one of its members is not that member: the answer is the malformed-document code rather than the unsupported-version one, because the reader never reaches the question of which layout applies.',
    expected: 'HOLD_RECORD_BAD_DOCUMENT',
    bytes: editedRecord(BASE, (document) => {
      document['v'] = '1';
    }),
    fault: { at: 'v', states: 'a version spelled as text where the layout holds an integer' },
  },
  {
    name: 'hold-member-named-twice-v1',
    note: 'The writer\'s bytes with the version member written a second time, the two spellings identical. A JSON parse would keep the last and say nothing while the bytes carry both, so the strict reading refuses the document while the characters are still distinguishable, and which spelling a caller meant stops being a question a reader answers by accident.',
    expected: 'HOLD_RECORD_BAD_DOCUMENT',
    bytes: editText(BASE, '"v": 1,', '"v": 1,\n  "v": 1,'),
    fault: { at: 'record', states: 'the member name v, stated twice in the file\'s own text' },
  },
  {
    name: 'hold-float-stamp-v1',
    note: 'The issue stamp written as a fraction that equals the integer it imitates. By the time a field check could ask which spelling the writer chose the two are one JavaScript number, so the reading refuses the spelling rather than the value, and a stamp two documents disagree about in text alone stays a disagreement a reader sees.',
    expected: 'HOLD_RECORD_BAD_DOCUMENT',
    bytes: editText(BASE, `"at": ${String(ISSUE)}`, `"at": ${String(ISSUE)}.0`),
    fault: { at: 'at', states: 'a number written as a fraction where the layout holds an integer' },
  },
  {
    name: 'hold-unknown-member-v1',
    note: 'A well-formed record carrying one member the top level does not define. The layout closes every map it declares, so an unknown member is a malformed document rather than a member a reader agreed to forget, and a hold that silently carried a fifth instruction would be read as the three doors this package ships.',
    expected: 'HOLD_RECORD_BAD_DOCUMENT',
    bytes: editedRecord(BASE, (document) => {
      document['future'] = 'a member no version names';
    }),
    fault: { at: 'record', states: 'a top-level member the layout does not define' },
  },
  {
    name: 'hold-unknown-window-member-v1',
    note: 'A record whose window block carries a member the window does not define, beside the two it does. The closure rule reaches the map inside the record and not only the record itself: a time zone stated beside a pair of unix seconds is a second answer to a question the layout already answered, and a reader cannot tell which end moved.',
    expected: 'HOLD_RECORD_BAD_DOCUMENT',
    bytes: editedRecord(BASE, (document) => {
      const window = document['window'] as Record<string, unknown>;
      window['tz'] = 'a zone no member of this layout holds';
    }),
    fault: { at: 'window', states: 'a window member the layout does not define' },
  },
  {
    name: 'hold-reason-withheld-v1',
    note: 'A record with its reason member left out. Every member but credentials is required, and the reason is the one a reviewer of a suspension reads first: a hold that states nothing about why it exists is a document a reader would have to supply a purpose to.',
    expected: 'HOLD_RECORD_BAD_DOCUMENT',
    bytes: editedRecord(BASE, (document) => {
      delete document['reason'];
    }),
    fault: { at: 'reason', states: 'the member the layout requires and these bytes leave out' },
  },
  {
    name: 'hold-window-closes-before-opens-v1',
    note: 'A record whose window ends before it starts. Both ends are inside one document, so the disagreement is a fault of the layout rather than a finding about the matter, and a window nothing can fall inside would read as a hold covering no records while stating it covers some.',
    expected: 'HOLD_RECORD_BAD_DOCUMENT',
    bytes: editedRecord(BASE, (document) => {
      const window = document['window'] as Record<string, unknown>;
      window['to'] = WINDOW_FROM - 1;
    }),
    fault: { at: 'window.to', states: 'a window end before the window start beside it' },
  },
  {
    name: 'hold-negative-stamp-v1',
    note: 'A record opening its window at one second before the unix epoch. Every stamp is a whole number of unix seconds no smaller than zero, and a negative reach is refused rather than read as an open start, because the layout already states an open start as a null at the other end.',
    expected: 'HOLD_RECORD_BAD_DOCUMENT',
    bytes: editedRecord(BASE, (document) => {
      const window = document['window'] as Record<string, unknown>;
      window['from'] = -1;
    }),
    fault: { at: 'window.from', states: 'a stamp below zero where the layout holds unix seconds' },
  },
  {
    name: 'hold-released-before-issue-v1',
    note: 'A record released one second before it was issued. The same self-contradiction the window states at its own two ends, and the same reason: a release that precedes the instruction is a document that cannot say whether anything is suspended, and a reader weighing `at <= now && now < released` would answer false everywhere without ever reporting the fault.',
    expected: 'HOLD_RECORD_BAD_DOCUMENT',
    bytes: editedRecord(BASE, (document) => {
      document['released'] = ISSUE - 1;
    }),
    fault: { at: 'released', states: 'a release stamp before the issue stamp in the same record' },
  },
  {
    name: 'hold-empty-credentials-v1',
    note: 'A record stating its credentials list as empty. Absence is the statement that the hold covers every credential and an empty list is the statement that it covers none while looking like it names some, which are two instructions and only one of them is what the layout carries.',
    expected: 'HOLD_RECORD_BAD_DOCUMENT',
    bytes: editedRecord(BASE, (document) => {
      document['credentials'] = [];
    }),
    fault: { at: 'credentials', states: 'the list this member requires to be non-empty, emptied' },
  },
  {
    name: 'hold-credential-named-twice-v1',
    note: 'A record naming one credential twice and another once. The list is a set of names the erasure arm tests membership of, so a duplicate says nothing new while making a refusal ambiguous about which entry it answers, and the unique rule is what keeps the list a statement rather than a transcript.',
    expected: 'HOLD_RECORD_BAD_DOCUMENT',
    bytes: editedRecord(BASE, (document) => {
      const credentials = document['credentials'] as string[];
      credentials.push(credentials[0]!);
    }),
    fault: { at: 'credentials[2]', states: 'the credential credentials[0] already names' },
  },
  {
    name: 'hold-unknown-provenance-v1',
    note: 'A record naming a provenance outside the three the vocabulary holds. The label is what tells a reader whether these bytes speak of fixture material, and a fourth word is refused rather than read as the nearest one, because a hold claiming live material it cannot show is the exact misreading this member exists to prevent.',
    expected: 'HOLD_RECORD_BAD_DOCUMENT',
    bytes: editedRecord(BASE, (document) => {
      document['prov'] = 'synthetic';
    }),
    fault: { at: 'prov', states: 'a provenance outside the three the vocabulary holds' },
  },
  {
    name: 'hold-limits-reworded-v1',
    note: 'A record wording its own limits. The limits are the format\'s sentence, verbatim, and a record widening or narrowing them is a document of a shape the layout does not define: the one thing a reader of a suspension must not have to weigh is whether the record\'s own account of its limits is true.',
    expected: 'HOLD_RECORD_BAD_DOCUMENT',
    bytes: editedRecord(BASE, (document) => {
      document['limits'] = 'This hold has no limits.';
    }),
    fault: { at: 'limits', states: 'a limits sentence the format does not own' },
  },
  {
    name: 'hold-forging-character-in-author-v1',
    note: 'A record whose author carries one character of the printed-line class, the code point that reverses the order the rest of the row renders in. Every authored text is asked of that class because a hold is printed beside the receipts it suspends: a name that reorders a row makes the line a reviewer reads a different document than the bytes.',
    expected: 'HOLD_RECORD_BAD_DOCUMENT',
    bytes: editedRecord(BASE, (document) => {
      document['by'] = 'the\u202Edeployer';
    }),
    fault: { at: 'by', states: 'a character that forges the printed line it is printed on' },
  },
  {
    name: 'hold-padded-reason-v1',
    note: 'A record whose reason carries a space at either end. A printed row does not pad itself, and the text that survives a trim is not the text that was signed over by nothing: the rule is one check on the authored values rather than a repair, because a reader that trimmed would answer for a reason the record never stated.',
    expected: 'HOLD_RECORD_BAD_DOCUMENT',
    bytes: editedRecord(BASE, (document) => {
      document['reason'] = ` ${REASON} `;
    }),
    fault: { at: 'reason', states: 'authored text padded on either side' },
  },
];

/** What the shipped reader answers for each layout row, so the file cannot lie about itself. */
function verdictOf(bytes: Uint8Array): string {
  try {
    parseHoldRecord(bytes);
    return 'verify-ok';
  } catch (err) {
    if (err instanceof ReceiptError) return err.code;
    throw err;
  }
}

type Door = 'erasure' | 'active' | 'coverage';

interface ConsultationRow {
  readonly name: string;
  readonly note: string;
  /** Which of the three shipped doors answers this row. */
  readonly door: Door;
  /** The holds the door is handed, as records, and read back through the shipped reader before the call. */
  readonly holds: readonly HoldRecord[];
  /** The instant the call is weighed at: the erasure or reading instant for every door. */
  readonly at: number;
  /** The credential an erasure call names. */
  readonly credential?: string;
  /** The record stamp a coverage call asks about. */
  readonly iat?: number;
  /** The answer this row claims, checked against the door's before a byte is written. */
  readonly states: string;
}

const CONSULTATIONS: readonly ConsultationRow[] = [
  {
    name: 'erasure-named-credential-mid-hold-refused',
    note: 'An erasure of a credential the hold names, weighed at an instant well inside the hold\'s reach. The refusal is the whole point of the record: the call stops by name before any byte moves, and the detail carries the credential and the hold\'s own issue stamp and author so an operator can see which instruction suspended it.',
    door: 'erasure',
    holds: [BASE],
    at: ISSUE + 1_000,
    credential: HELD,
    states: 'HOLD_ERASURE_REFUSED',
  },
  {
    name: 'erasure-at-issue-instant-refused',
    note: 'The same call at the issue stamp exactly. The hold is in force from that instant inclusive, so a record written at the second it was issued already suspends an erasure handed the same second, and a port that opened the reach one step late would let the first second of a hold pass.',
    door: 'erasure',
    holds: [BASE],
    at: ISSUE,
    credential: HELD,
    states: 'HOLD_ERASURE_REFUSED',
  },
  {
    name: 'erasure-one-second-before-issue-allowed',
    note: 'The same call one second before the issue stamp. Nothing is suspended, because the instruction did not exist yet, and the row beside this one is what says the difference is the bound and not an accident of the number: one second moves the answer.',
    door: 'erasure',
    holds: [BASE],
    at: ISSUE - 1,
    credential: HELD,
    states: 'verify-ok',
  },
  {
    name: 'erasure-unheld-credential-allowed',
    note: 'An erasure of a credential the hold does not name, weighed while the hold is in force. A hold suspends the material it speaks of and nothing else, which is the difference between an instruction and a freeze on the whole deployment.',
    door: 'erasure',
    holds: [BASE],
    at: ISSUE + 1_000,
    credential: 'cred-nobody-holds',
    states: 'verify-ok',
  },
  {
    name: 'erasure-open-hold-covers-every-credential-refused',
    note: 'An erasure of a credential no record names, under the hold that leaves the credentials member off entirely. Absence is the deployment\'s statement that the whole of its material is under the instruction, so the one hold shape that names nothing suspends everything, and a reader that read the omission as an empty list would erase the material the record was written to protect.',
    door: 'erasure',
    holds: [OPEN_HOLD],
    at: ISSUE + 1_000,
    credential: 'cred-never-named-by-anyone',
    states: 'HOLD_ERASURE_REFUSED',
  },
  {
    name: 'erasure-one-second-before-release-refused',
    note: 'An erasure of the held credential one second before the release stamp. The hold is still in force, and the row is the pair that makes the release boundary a fact about the instant rather than about the record being closed: the bytes are identical here and at the two rows beside this one.',
    door: 'erasure',
    holds: [RELEASED_HOLD],
    at: RELEASED - 1,
    credential: HELD,
    states: 'HOLD_ERASURE_REFUSED',
  },
  {
    name: 'erasure-at-release-instant-allowed',
    note: 'The same call at the release stamp exactly. The reach runs until the release exclusive, so the instant a hold names as its release is the first instant the erasure proceeds, and a port that closed the reach inclusively would suspend one second more than the record asked for while claiming to obey it.',
    door: 'erasure',
    holds: [RELEASED_HOLD],
    at: RELEASED,
    credential: HELD,
    states: 'verify-ok',
  },
  {
    name: 'erasure-long-after-release-allowed',
    note: 'The same call one second past the release. A released hold suspends nothing at any later instant, which is the comparison a reader is most likely to leave out: without it a hold that released itself would suspend forever, the opposite of what a release states.',
    door: 'erasure',
    holds: [RELEASED_HOLD],
    at: RELEASED + 1,
    credential: HELD,
    states: 'verify-ok',
  },
  {
    name: 'erasure-open-hold-long-after-issue-refused',
    note: 'An erasure a long way past the issue stamp, under a hold stating no release. A null release is a hold still in force however far the clock runs, so the row is the other half of the rule above: the absence of a release is a statement, and it suspends indefinitely until the record is replaced.',
    door: 'erasure',
    holds: [BASE],
    at: ISSUE + 10_000_000,
    credential: HELD,
    states: 'HOLD_ERASURE_REFUSED',
  },
  {
    name: 'erasure-with-no-holds-handed-allowed',
    note: 'An erasure handed no holds at all. A reader that consults nothing behaves exactly as it did before the record existed, which is the limits sentence\'s own statement that the suspension reaches only readers that consult it, and the empty list is the shape of that caller.',
    door: 'erasure',
    holds: [],
    at: ISSUE,
    credential: HELD,
    states: 'verify-ok',
  },
  {
    name: 'erasure-second-hold-of-the-list-names-it-refused',
    note: 'An erasure under a list of two holds, the first naming another credential and the second naming this one. The scan answers for every instruction a deployment is under rather than only the first it meets, so a caller holding two live matters is not free to erase what the second of them protects.',
    door: 'erasure',
    holds: [ELSEWHERE_HOLD, BASE],
    at: ISSUE + 1_000,
    credential: HELD,
    states: 'HOLD_ERASURE_REFUSED',
  },
  {
    name: 'erasure-window-not-weighed-refused',
    note: 'An erasure under a hold whose window lies wholly before the instant the call is weighed at. The erasure arm does not read the window: an erasure takes all of a credential\'s material at once, so a hold naming that credential suspends the whole of it rather than the slice its window happens to cover. The coverage row beside this one reads the same bytes and answers the other way, which is the pair that keeps the two arms apart.',
    door: 'erasure',
    holds: [PAST_WINDOW_HOLD],
    at: ISSUE + 1_000,
    credential: HELD,
    states: 'HOLD_ERASURE_REFUSED',
  },
  {
    name: 'active-before-issue-inactive',
    note: 'The reach asked of one instant, one second before the issue stamp: not in force. This is the door the erasure arm and the coverage arm both stand on, published apart so a port that gets the reach right at one of them can be shown to get it wrong at the other.',
    door: 'active',
    holds: [BASE],
    at: ISSUE - 1,
    states: 'inactive',
  },
  {
    name: 'active-at-issue-instant-active',
    note: 'The same question at the issue stamp: in force, inclusive. The two rows beside this one fix both ends of the reach, and nothing in the published bytes tells a reader which way round they run.',
    door: 'active',
    holds: [BASE],
    at: ISSUE,
    states: 'active',
  },
  {
    name: 'active-one-second-before-release-active',
    note: 'The question one second before a stated release: still in force. The release lifts the reach at the instant it names and not before it, which is the comparison the layout\'s whole point turns on.',
    door: 'active',
    holds: [RELEASED_HOLD],
    at: RELEASED - 1,
    states: 'active',
  },
  {
    name: 'active-at-release-instant-inactive',
    note: 'The question at the release stamp exactly: not in force. The reach is exclusive of its end, and the row beside this one is the same record one second earlier, so the boundary is measured rather than asserted.',
    door: 'active',
    holds: [RELEASED_HOLD],
    at: RELEASED,
    states: 'inactive',
  },
  {
    name: 'active-open-hold-long-after-active',
    note: 'The question a long way past the issue stamp of a hold stating no release: in force. A null release is an open end, not a missing value, and a reader that treated it as zero would report every open hold as expired.',
    door: 'active',
    holds: [BASE],
    at: ISSUE + 10_000_000,
    states: 'active',
  },
  {
    name: 'coverage-window-start-inclusive-covers',
    note: 'A record stamped at the window\'s own start, weighed while the hold is in force: covered. `from` is inclusive, which is the difference between a hold that begins with a record and one that quietly drops it, and the row beside this one is the same call one second earlier.',
    door: 'coverage',
    holds: [BASE],
    iat: WINDOW_FROM,
    at: ISSUE,
    states: 'covers',
  },
  {
    name: 'coverage-one-second-before-window-does-not-cover',
    note: 'The same call at one second before the window opens: not covered. The hold is active and the stamp is the only thing that moved, so the answer is about the window and not about the reach.',
    door: 'coverage',
    holds: [BASE],
    iat: WINDOW_FROM - 1,
    at: ISSUE,
    states: 'does-not-cover',
  },
  {
    name: 'coverage-last-instant-inside-window-covers',
    note: 'A record stamped one second before the window closes: covered. The published receipt fixtures carry an item stamp one second before their own issue stamp, which sits inside this window, so the row is the ordinary case rather than a boundary drawn for its own sake.',
    door: 'coverage',
    holds: [BASE],
    iat: WINDOW_TO - 1,
    at: ISSUE,
    states: 'covers',
  },
  {
    name: 'coverage-window-end-exclusive-does-not-cover',
    note: 'A record stamped at the window\'s end exactly: not covered. `to` is exclusive, which is what makes two holds whose windows meet at one instant state two disjoint sets of records rather than one record under two instructions.',
    door: 'coverage',
    holds: [BASE],
    iat: WINDOW_TO,
    at: ISSUE,
    states: 'does-not-cover',
  },
  {
    name: 'coverage-open-window-end-covers',
    note: 'A record stamped long after the window of the hold that states no end: covered. A null `to` is an open end at the same door where a null `released` is an open reach, and a reader that read either as zero answers the other way on both.',
    door: 'coverage',
    holds: [OPEN_HOLD],
    iat: ISSUE + 10_000_000,
    at: ISSUE,
    states: 'covers',
  },
  {
    name: 'coverage-released-hold-covers-nothing',
    note: 'A record stamped squarely inside the window of a hold that has since released, weighed at the release instant: not covered. The window is wide and the instruction is spent, which is the pair of questions this door keeps apart: a released hold covers nothing however wide its window, and no removal is suspended by an instruction that was withdrawn.',
    door: 'coverage',
    holds: [RELEASED_HOLD],
    iat: WINDOW_FROM + 10,
    at: RELEASED,
    states: 'does-not-cover',
  },
  {
    name: 'coverage-receipt-fixture-stamp-covers',
    note: 'A record stamped at the instant the published receipt fixtures are issued at, weighed at that same instant under the hold issued then: covered. The row is the family\'s join to the bytes beside it, and it is the reason the window reaches a day either side of the issue rather than forward from it: the receipts a hold speaks of were written before the instruction that suspends their retirement.',
    door: 'coverage',
    holds: [BASE],
    iat: ISSUE,
    at: ISSUE,
    states: 'covers',
  },
  {
    name: 'coverage-stamp-older-than-the-hold-covers',
    note: 'A record stamped an hour before the hold was issued, weighed at the issue instant: covered. The issue stamp says when the instruction was given and the window says which records it reaches, so a hold issued today covers yesterday\'s receipts, and a reader that compared a stamp against `at` instead of against the window would let the oldest material the instruction names be retired first.',
    door: 'coverage',
    holds: [BASE],
    iat: ISSUE - 3_600,
    at: ISSUE,
    states: 'covers',
  },
  {
    name: 'coverage-past-window-does-not-cover',
    note: 'The same record stamped and weighed at an instant the window of the hold beside it does not reach, the mirror of the erasure row that reads these very bytes and refuses anyway. Two doors, one record, two answers, and the difference is the window: which is exactly what the erasure arm declines to weigh.',
    door: 'coverage',
    holds: [PAST_WINDOW_HOLD],
    iat: ISSUE + 1_000,
    at: ISSUE + 1_000,
    states: 'does-not-cover',
  },
];

/**
 * What the shipped door answers, read back through the shipped reader first.
 *
 * The holds reach the call as records the published bytes parse to, not as the objects this file built,
 * so a row whose record the reader would refuse fails the run here rather than becoming a published
 * answer no document supports. An erasure answers `verify-ok` where nothing suspends the call and the
 * code where something does; the two reach doors answer in words, because a reach is neither accepted
 * nor refused and a word invented for it would read as an error code.
 */
function answerOf(one: ConsultationRow): string {
  const holds = one.holds.map((hold) => parseHoldRecord(holdRecordBytes(hold)));
  if (one.door === 'erasure') {
    if (one.credential === undefined) throw new Error(`${one.name}: an erasure row states no credential`);
    try {
      refuseErasureUnderHold(holds, one.credential, one.at);
      return 'verify-ok';
    } catch (err) {
      if (err instanceof ReceiptError && err.code === 'HOLD_ERASURE_REFUSED') return err.code;
      throw err;
    }
  }
  const [only] = holds;
  if (holds.length !== 1 || only === undefined) {
    throw new Error(`${one.name}: a ${one.door} row is answered by one hold, and this states ${String(holds.length)}`);
  }
  if (one.door === 'active') return holdActiveAt(only, one.at) ? 'active' : 'inactive';
  if (one.iat === undefined) throw new Error(`${one.name}: a coverage row states no record stamp`);
  return holdCoversStamp(only, one.iat, one.at) ? 'covers' : 'does-not-cover';
}

function main(): void {
  const layoutAnswers = ROWS.map((one) => {
    const observed = verdictOf(one.bytes);
    if (observed !== one.expected) {
      throw new Error(`${one.name}: the reader answers ${observed}, not the ${one.expected} this row states`);
    }
    return observed;
  });
  const consultationAnswers = CONSULTATIONS.map((one) => {
    const observed = answerOf(one);
    if (observed !== one.states) {
      throw new Error(`${one.name}: the ${one.door} door answers ${observed}, not the ${one.states} this row states`);
    }
    return observed;
  });

  const vectors = ROWS.map((one, index) => ({
    name: one.name,
    note: one.note,
    expected: layoutAnswers[index]!,
    recordBase64Url: toBase64Url(one.bytes),
    recordByteLength: one.bytes.length,
    ...(one.fault === undefined ? {} : { fault: one.fault }),
  }));

  const consultations = CONSULTATIONS.map((one, index) => ({
    name: one.name,
    note: one.note,
    door: one.door,
    expected: consultationAnswers[index]!,
    holdsBase64Url: one.holds.map((hold) => toBase64Url(holdRecordBytes(hold))),
    call: {
      at: one.at,
      ...(one.credential === undefined ? {} : { credential: one.credential }),
      ...(one.iat === undefined ? {} : { iat: one.iat }),
    },
  }));

  writeFileSync(
    join(DATA, 'hold-v1.json'),
    JSON.stringify(
      {
        version: 1,
        description:
          'The hold record beside the receipts it asks to be kept: the layout its strict reader reads, one edit of the writer\'s own bytes per refusal, and the answers the three shipped consultation doors give the calls these rows state. The record is unsigned, so this family needs no key material and publishes none: a hold\'s bytes are the whole of what a reader is handed, and its trust arrives from whoever hands them over beside the receipts it speaks of. Every row is labeled fixture and speaks of fixture material, and the window the records carry covers the instant the published receipt fixtures are issued at, so a coverage row can be read against a stamp this repository already publishes. The layout rows state the verdict `parseHoldRecord` answers for the bytes beside them, and because this layout names no pointer registry those are the only two codes a document is refused with: `HOLD_RECORD_UNSUPPORTED_VERSION` for a version no layout reads and `HOLD_RECORD_BAD_DOCUMENT` for every structural fault. The consultation rows state which door answered, the holds it was handed as the bytes it is given, the call, and the answer the shipped door gave: erasure states `verify-ok` where no instruction suspends the call and `HOLD_ERASURE_REFUSED` where one does, active states `active` or `inactive`, coverage states `covers` or `does-not-cover`. Two pairs are published as pairs because each half is unreadable without the other: the reach measured at one second either side of a bound that a reader can leave out, and the one hold whose window the erasure arm declines to weigh while the coverage arm reads it and answers the other way.',
        rule: {
          registry: 'docs/receipt-spec.md section 4.10',
          reader: 'parseHoldRecord in @ashaveri/receipt',
          writer: 'holdRecordBytes in @ashaveri/receipt',
          consultations: {
            active: 'holdActiveAt in @ashaveri/receipt',
            coverage: 'holdCoversStamp in @ashaveri/receipt',
            erasure: 'refuseErasureUnderHold in @ashaveri/receipt',
          },
          doors: 'The door column names which of the three answered a row. Erasure takes the list of holds, a credential and an instant, and states verify-ok or HOLD_ERASURE_REFUSED. Active takes one record and an instant, and states active or inactive. Coverage takes one record, the stamp of a record and the instant it is weighed at, and states covers or does-not-cover. A non-refusal answer is a word rather than a code because a reach is neither accepted nor refused.',
          versions: [...HOLD_RECORD_VERSIONS],
          members: [...HOLD_RECORD_V1_MEMBERS],
          windowMembers: [...HOLD_RECORD_WINDOW_MEMBERS],
          limits: HOLD_RECORD_LIMITS,
          textMaxUnits: HOLD_RECORD_TEXT_MAX_UNITS,
          instants: {
            issue: ISSUE,
            windowFrom: WINDOW_FROM,
            windowTo: WINDOW_TO,
            released: RELEASED,
            receiptFixtureStamp: FIXED_IAT,
            note: 'Unix seconds. The issue stamp is the instant every published receipt fixture is issued at, the window reaches one day either side of it, and the release is one hundred seconds after the issue, which is the span the three rows around a boundary are measured across. Nothing here is a deployment\'s date: these are fixture instants, stated so a port can hand its own reader the same numbers.',
          },
          unsigned: 'A hold record carries no signature, as the disclosure record and the model inventory carry none. No row of this family is sealed, no key is published beside one, and no digest of a record is claimed by anything here: what a reader weighs is the layout and the consultation, and the export container is what carries these bytes as evidence under its own signature.',
          encodings: 'byte strings unpadded base64url, instants whole numbers of unix seconds',
        },
        vectors,
        consultations,
      },
      null,
      2,
    ) + '\n',
  );

  for (const one of vectors) console.log(`${one.name}: ${one.expected}`);
  for (const one of consultations) console.log(`${one.name}: ${one.expected}`);
}

main();
