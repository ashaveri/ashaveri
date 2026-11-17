import { describe, expect, it } from 'vitest';
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
  encodeIncidentBundle,
  equalBytes,
  fromBase64Url,
  incidentBundleBytes,
  parseHoldRecord,
  parseIncidentBundle,
  toBase64Url,
  verifyExport,
  verifyIncidentBundle,
  type IncidentBundleRecord,
  type VerifiedExport,
} from '@ashaveri/receipt';
import { loadExportVectors, loadHoldVectors, loadIncidentBundleVectors, type IncidentBundleVerifyCase } from '../src/index.js';

/**
 * The published incident bundle vectors, replayed the way a port replays them: decode the record bytes, hand
 * them to the shipped layout door, and answer the verdict the row promises. The accepted rows are written
 * back through the shipped writer too, so the bytes a port holds are the bytes this repository's own writer
 * produces for the record they parse to. The verification cases are replayed at the verifying door over the
 * hold bytes their row publishes, and the ride is replayed at the export door, which is what the acceptance
 * clause of this family is stated at.
 *
 * Nothing here restates a rule. Every answer is what `parseIncidentBundle`, `verifyIncidentBundle` or
 * `verifyExport` gave when the run reached it, which is what makes a hand-edited verdict fail: the published
 * word is the only claim, and the shipped door is the only witness.
 */

const file = loadIncidentBundleVectors();

const decoded = (bytes: Uint8Array): string => new TextDecoder().decode(bytes);

function verdictOf(bytes: Uint8Array): string {
  try {
    parseIncidentBundle(bytes);
    return 'verify-ok';
  } catch (err) {
    if (err instanceof ReceiptError) return err.code;
    throw err;
  }
}

function verifyVerdictOf(recordBytes: Uint8Array, holdBytes: Uint8Array): string {
  try {
    verifyIncidentBundle(recordBytes, { holdBytes });
    return 'verify-ok';
  } catch (err) {
    if (err instanceof ReceiptError) return err.code;
    throw err;
  }
}

const HONEST = file.vectors.find((one) => one.name === 'bundle-fixture-v1');
if (HONEST === undefined) throw new Error('the family publishes no bundle-fixture-v1 row to replay the others against');
const HONEST_BYTES = fromBase64Url(HONEST.recordBase64Url);
const HONEST_RECORD = parseIncidentBundle(HONEST_BYTES);

/** The hold bytes the published hold family carries for the row one case names, read from that file. */
function holdRowBytes(name: string): Uint8Array {
  const found = loadHoldVectors().vectors.find((one) => one.name === name);
  if (found === undefined) throw new Error(`hold-v1.json publishes no ${name} row`);
  return fromBase64Url(found.recordBase64Url);
}

function caseNamed(name: string): IncidentBundleVerifyCase {
  const found = file.verifyCases.find((one) => one.name === name);
  if (found === undefined) throw new Error(`the family publishes no verification case named ${name}`);
  return found;
}

/** One layout row by name, and the record it publishes read back through the shipped reader. */
function layoutNamed(name: string): IncidentBundleRecord {
  const found = file.vectors.find((one) => one.name === name);
  if (found === undefined) throw new Error(`the family publishes no layout row named ${name}`);
  return parseIncidentBundle(fromBase64Url(found.recordBase64Url));
}

/** Every member name the published file carries, at every depth, for the closed-list checks. */
function memberNames(value: unknown, into: Set<string>): Set<string> {
  if (Array.isArray(value)) {
    for (const item of value) memberNames(item, into);
    return into;
  }
  if (value !== null && typeof value === 'object') {
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      into.add(key);
      memberNames(item, into);
    }
  }
  return into;
}

describe('the incident bundle family states the shipped rule', () => {
  it('publishes the versions, members, registry, limits and text bound the package declares', () => {
    expect(file.rule.versions).toEqual([...INCIDENT_BUNDLE_VERSIONS]);
    expect(file.rule.members).toEqual([...INCIDENT_BUNDLE_V1_MEMBERS]);
    expect(file.rule.incidentMembers).toEqual([...INCIDENT_BUNDLE_INCIDENT_MEMBERS]);
    expect(file.rule.holdMembers).toEqual([...INCIDENT_BUNDLE_HOLD_MEMBERS]);
    expect(file.rule.windowMembers).toEqual([...INCIDENT_BUNDLE_WINDOW_MEMBERS]);
    expect(file.rule.floorMembers).toEqual([...INCIDENT_BUNDLE_FLOOR_MEMBERS]);
    expect(file.rule.pointers).toEqual([...INCIDENT_BUNDLE_POINTERS]);
    expect(file.rule.pointerCitations).toEqual({ ...INCIDENT_BUNDLE_POINTER_CITATIONS });
    expect(file.rule.limits).toBe(INCIDENT_BUNDLE_LIMITS);
    expect(file.rule.textMaxUnits).toBe(INCIDENT_BUNDLE_TEXT_MAX_UNITS);
    expect(file.rule.reader).toBe('parseIncidentBundle in @ashaveri/receipt');
    expect(file.rule.verifier).toBe('verifyIncidentBundle in @ashaveri/receipt');
    expect(file.rule.writer).toBe('incidentBundleBytes in @ashaveri/receipt');
  });

  it('keeps the bound fields and the asserted fields apart, and names each one', () => {
    // The split is the layout's whole point, so the file states it as positions rather than as prose a port
    // has to infer: which members are copied from the designated hold and checked, and which are the
    // deployment's own word and never compared against anything.
    expect([...file.rule.boundFields].sort()).toEqual(['hold.at', 'hold.by', 'window.from', 'window.to']);
    expect([...file.rule.assertedFields].sort()).toEqual(['floor.days', 'incident.at', 'incident.id', 'incident.states']);
    const overlap = file.rule.boundFields.filter((one) => file.rule.assertedFields.includes(one));
    expect(overlap, `${overlap.join(', ')} is stated as both bound and asserted`).toEqual([]);
  });

  it('carries no notification member anywhere, because the closed list is the witness', () => {
    // The layout defines every member it has, so the absence of a position stating a notification deadline is
    // a fact of the published lists rather than of a sentence beside them. Both sides are read here: the
    // member names this file carries at every depth, and the member set of every record the writer accepts.
    const names = memberNames(file, new Set<string>());
    for (const name of names) {
      expect(name.toLowerCase(), `the family publishes a member named ${name}`).not.toMatch(/notif|deadline|hours/u);
    }
    for (const one of file.vectors) {
      if (one.expected !== 'verify-ok') continue;
      const document = JSON.parse(decoded(fromBase64Url(one.recordBase64Url))) as Record<string, unknown>;
      expect(Object.keys(document), `${one.name} is accepted with a member the layout does not define`).toEqual([
        ...INCIDENT_BUNDLE_V1_MEMBERS,
      ]);
    }
  });

  it('designates the hold the hold family publishes, byte for byte', () => {
    expect(file.rule.hold.recordBase64Url).toBe(toBase64Url(holdRowBytes('hold-fixture-v1')));
    const designated = parseHoldRecord(fromBase64Url(file.rule.hold.recordBase64Url));
    expect(HONEST_RECORD.hold.at).toBe(designated.at);
    expect(HONEST_RECORD.hold.by).toBe(designated.by);
    expect(HONEST_RECORD.window.from).toBe(designated.window.from);
    expect(HONEST_RECORD.window.to).toBe(designated.window.to);
    expect(file.rule.instants.holdIssue).toBe(designated.at);
    expect(file.rule.instants.windowFrom).toBe(designated.window.from);
    expect(file.rule.instants.windowTo).toBe(designated.window.to);
  });

  it('publishes the floor it recomputes rather than a floor it asserts', () => {
    expect(file.rule.floor.preserveUntil).toBe(file.rule.floor.incidentAt + file.rule.floor.days * 86_400);
    expect(file.rule.floor.daysMax).toBe(Math.floor(Number.MAX_SAFE_INTEGER / 86_400));
    for (const one of file.vectors) {
      if (one.expected !== 'verify-ok') continue;
      const record = parseIncidentBundle(fromBase64Url(one.recordBase64Url));
      expect(
        record.floor.preserveUntil,
        `${one.name} states a floor that is not the incident stamp plus its days`,
      ).toBe(record.incident.at + record.floor.days * 86_400);
    }
  });
});

describe('the incident bundle layout rows replay', () => {
  for (const one of file.vectors) {
    it(`${one.name} answers ${one.expected}`, () => {
      const bytes = fromBase64Url(one.recordBase64Url);
      expect(bytes.length).toBe(one.recordByteLength);
      expect(verdictOf(bytes)).toBe(one.expected);
      if (one.expected !== 'verify-ok') return;
      const parsed = parseIncidentBundle(bytes);
      expect(encodeIncidentBundle(parsed)).toEqual(bytes);
      expect(incidentBundleBytes(parsed)).toEqual(bytes);
      expect(parsed.prov).toBe('fixture');
      expect(parsed.limits).toBe(INCIDENT_BUNDLE_LIMITS);
      for (const pointer of parsed.pointers) {
        expect(INCIDENT_BUNDLE_POINTERS as readonly string[]).toContain(pointer);
      }
      expect(INCIDENT_BUNDLE_POINTERS as readonly string[]).toContain(parsed.floor.pointer);
    });
  }

  it('writes the accepted record in the member order the layout declares', () => {
    const document = JSON.parse(decoded(HONEST_BYTES)) as Record<string, unknown>;
    expect(Object.keys(document)).toEqual([...INCIDENT_BUNDLE_V1_MEMBERS]);
    expect(Object.keys(document['incident'] as object)).toEqual([...INCIDENT_BUNDLE_INCIDENT_MEMBERS]);
    expect(Object.keys(document['hold'] as object)).toEqual([...INCIDENT_BUNDLE_HOLD_MEMBERS]);
    expect(Object.keys(document['window'] as object)).toEqual([...INCIDENT_BUNDLE_WINDOW_MEMBERS]);
    expect(Object.keys(document['floor'] as object)).toEqual([...INCIDENT_BUNDLE_FLOOR_MEMBERS]);
  });

  it('refuses with one of the three codes this layout can answer, and names where', () => {
    const refusals = file.vectors.filter((one) => one.expected !== 'verify-ok');
    expect(refusals.length).toBeGreaterThan(0);
    for (const one of refusals) {
      expect(
        ['INCIDENT_BUNDLE_UNSUPPORTED_VERSION', 'INCIDENT_BUNDLE_BAD_DOCUMENT', 'INCIDENT_BUNDLE_UNKNOWN_POINTER'],
        `${one.name} names ${one.expected}`,
      ).toContain(one.expected);
      expect(one.fault, `${one.name} states no fault block`).toBeDefined();
      expect(fromBase64Url(one.recordBase64Url)).not.toEqual(HONEST_BYTES);
    }
    const stated = new Set(refusals.map((one) => one.expected));
    expect(stated.has('INCIDENT_BUNDLE_UNSUPPORTED_VERSION'), 'no row tests the version list').toBe(true);
    expect(stated.has('INCIDENT_BUNDLE_UNKNOWN_POINTER'), 'no row tests the pointer registry').toBe(true);
  });

  it('measures the authored-text bound at the unit either side of the ceiling', () => {
    const at = layoutNamed('bundle-narrative-at-width-v1');
    const wide = file.vectors.find((one) => one.name === 'bundle-narrative-one-unit-wide-v1');
    expect(wide, 'the family publishes no row one unit past the ceiling').toBeDefined();
    expect(at.incident.states.length).toBe(INCIDENT_BUNDLE_TEXT_MAX_UNITS);
    const wideDocument = JSON.parse(decoded(fromBase64Url(wide!.recordBase64Url))) as {
      incident: { states: string };
    };
    expect(wideDocument.incident.states.length).toBe(INCIDENT_BUNDLE_TEXT_MAX_UNITS + 1);
    expect(verdictOf(fromBase64Url(wide!.recordBase64Url))).toBe('INCIDENT_BUNDLE_BAD_DOCUMENT');
  });

  it('measures the floor at the day either side of what a stamp can state', () => {
    // Two bounds on one number, and each needs both sides published: the day count whose product with a day's
    // seconds is still exact, and the sum of that product with an incident stamp. A port that rounded rather
    // than refused, or that compared a stated floor it could not state exactly, answers these differently.
    const at = layoutNamed('bundle-floor-days-at-ceiling-v1');
    expect(at.floor.days).toBe(file.rule.floor.daysMax);
    expect(at.floor.preserveUntil).toBe(at.incident.at + at.floor.days * 86_400);
    const past = refusedNamed('bundle-floor-days-past-a-statable-floor-v1');
    expect(past.document.floor.days).toBe(file.rule.floor.daysMax + 1);
    expect(past.verdict).toBe('INCIDENT_BUNDLE_BAD_DOCUMENT');
    const moved = refusedNamed('bundle-floor-preserve-until-moved-v1');
    expect(moved.document.floor.preserveUntil).not.toBe(moved.document.incident.at + moved.document.floor.days * 86_400);
    const sum = refusedNamed('bundle-floor-sum-past-a-statable-stamp-v1');
    expect(sum.verdict).toBe('INCIDENT_BUNDLE_BAD_DOCUMENT');
    expect(sum.document.floor.days).toBe(file.rule.floor.daysMax);
  });

  it('reads the same floor stated as thirty days and as ninety, because it weighs neither', () => {
    const thirty = layoutNamed('bundle-fixture-v1');
    const ninety = layoutNamed('bundle-floor-days-not-weighed-v1');
    expect(thirty.floor.days).toBe(30);
    expect(ninety.floor.days).toBe(90);
    expect(ninety.floor.pointer).toBe(thirty.floor.pointer);
    expect(ninety.hold).toEqual(thirty.hold);
    expect(ninety.window).toEqual(thirty.window);
    expect(ninety.pointers).toEqual(thirty.pointers);
    expect(verdictOf(incidentBundleBytes(ninety))).toBe('verify-ok');
  });

  it('refuses a pointer outside the registry and a pointer that names nothing at all', () => {
    const unknown = file.vectors.find((one) => one.name === 'bundle-unknown-pointer-v1');
    expect(unknown, 'the family publishes no row named bundle-unknown-pointer-v1').toBeDefined();
    const notText = file.vectors.find((one) => one.name === 'bundle-pointer-not-text-v1');
    expect(notText, 'the family publishes no non-text pointer row').toBeDefined();
    expect(verdictOf(fromBase64Url(notText!.recordBase64Url))).toBe('INCIDENT_BUNDLE_BAD_DOCUMENT');
    expect(unknown!.expected).toBe('INCIDENT_BUNDLE_UNKNOWN_POINTER');
    for (const one of file.vectors) {
      if (one.expected !== 'INCIDENT_BUNDLE_UNKNOWN_POINTER') continue;
      expect(one.fault?.at, `${one.name} states no pointer position`).toBeDefined();
    }
  });
});

/** The two positions the refused floor rows state figures at, read out of a document a reader will not parse. */
interface RefusedDocument {
  incident: { at: number };
  floor: { days: number; preserveUntil: number };
}

/**
 * One refused row read as a document rather than as a record: a refusal cannot be parsed, and the figures a
 * refusal is about have to be seen in the bytes the row publishes for the pair either side of a bound to be
 * a measurement rather than a sentence.
 */
function refusedNamed(name: string): { bytes: Uint8Array; verdict: string; document: RefusedDocument } {
  const found = file.vectors.find((one) => one.name === name);
  if (found === undefined) throw new Error(`the family publishes no row named ${name}`);
  const bytes = fromBase64Url(found.recordBase64Url);
  return {
    bytes,
    verdict: verdictOf(bytes),
    document: JSON.parse(decoded(bytes)) as RefusedDocument,
  };
}

describe('the incident bundle verification cases replay', () => {
  for (const one of file.verifyCases) {
    it(`${one.name} answers ${one.expected} beside the hold it is handed`, () => {
      const recordBytes = fromBase64Url(one.recordBase64Url);
      const holdBytes = fromBase64Url(one.holdBase64Url);
      // Every case is answered by a bundle the layout door itself takes: a pair refused for its own shape
      // would otherwise report a code about the hold that has nothing to do with it.
      expect(verdictOf(recordBytes), `${one.name} hands a bundle the layout door refuses`).toBe('verify-ok');
      expect(holdRowBytes(one.holdRow)).toEqual(holdBytes);
      expect(verifyVerdictOf(recordBytes, holdBytes)).toBe(one.expected);
    });
  }

  it('agrees field by field when the record and the designated hold are one pair', () => {
    for (const name of ['verified-honest-hold', 'verified-open-window-hold']) {
      const one = caseNamed(name);
      const recordBytes = fromBase64Url(one.recordBase64Url);
      const holdBytes = fromBase64Url(one.holdBase64Url);
      const { record } = verifyIncidentBundle(recordBytes, { holdBytes });
      const hold = parseHoldRecord(holdBytes);
      expect(record.hold.at).toBe(hold.at);
      expect(record.hold.by).toBe(hold.by);
      expect(record.window.from).toBe(hold.window.from);
      expect(record.window.to).toBe(hold.window.to);
    }
    const open = caseNamed('verified-open-window-hold');
    expect(parseHoldRecord(fromBase64Url(open.holdBase64Url)).window.to).toBeNull();
    expect(parseIncidentBundle(fromBase64Url(open.recordBase64Url)).window.to).toBeNull();
  });

  it('refuses a bound mutation by naming the position and both values', () => {
    for (const name of ['bound-mutated-hold-at-refused', 'bound-mutated-window-to-refused']) {
      const one = caseNamed(name);
      let caught: unknown;
      try {
        verifyIncidentBundle(fromBase64Url(one.recordBase64Url), { holdBytes: fromBase64Url(one.holdBase64Url) });
      } catch (err) {
        caught = err;
      }
      expect(caught).toBeInstanceOf(ReceiptError);
      const message = (caught as ReceiptError).message;
      expect(one.disagree, `${one.name} states no disagreement block`).toBeDefined();
      expect(message).toContain(one.disagree!.at);
      expect(message).toContain(one.disagree!.states);
      expect(message).toContain(one.disagree!.binds);
    }
  });

  it('reads an asserted mutation that changes no claim about the hold', () => {
    const read = caseNamed('asserted-mutation-read');
    const record = verifyIncidentBundle(fromBase64Url(read.recordBase64Url), {
      holdBytes: fromBase64Url(read.holdBase64Url),
    }).record;
    const honest = parseIncidentBundle(HONEST_BYTES);
    expect(record.incident.states).not.toBe(honest.incident.states);
    expect(record.hold).toEqual(honest.hold);
    expect(record.window).toEqual(honest.window);
  });

  it('separates the wrong hold from an unreadable one, and both from a disagreement', () => {
    const mismatch = caseNamed('hold-mismatch-refused');
    const unreadable = caseNamed('hold-unreadable-refused');
    expect(mismatch.holdBase64Url).toBe(toBase64Url(holdRowBytes('hold-released-v1')));
    expect(unreadable.holdBase64Url).toBe(toBase64Url(holdRowBytes('hold-unknown-member-v1')));
    // The mismatched bytes are a whole hold the reader could read if it were the one designated, and the
    // unreadable ones are not a hold at all: the two refusals answer different questions, and a port that
    // merged them would report a document problem as a pair problem.
    expect(() => parseHoldRecord(fromBase64Url(mismatch.holdBase64Url))).not.toThrow();
    expect(() => parseHoldRecord(fromBase64Url(unreadable.holdBase64Url))).toThrow(
      expect.objectContaining({ code: 'HOLD_RECORD_BAD_DOCUMENT' }),
    );
    // The unreadable row designates exactly the bytes it is handed, so the digest agrees and the refusal
    // arrives one step later: these are the record's hold, and they are not a readable one.
    expect(parseIncidentBundle(fromBase64Url(unreadable.recordBase64Url)).hold.sha256).not.toBe(
      HONEST_RECORD.hold.sha256,
    );
  });
});

describe('the export ride carries both records', () => {
  const ride = file.rule.exportRide;
  let opened: VerifiedExport | undefined;
  // The ride is opened at the export door from inside a test, never beside one: a ride that no longer
  // verifies then fails under the name of the claim it breaks, rather than as a suite that never ran.
  function openRide(): VerifiedExport {
    opened ??= verifyExport(fromBase64Url(ride.exportBase64Url), fromBase64Url(ride.publicKeyBase64Url));
    return opened;
  }

  it('closes the walk the signed document claims', () => {
    const verified = openRide();
    expect(verified.outcome.kind).toBe('anchored');
    if (verified.outcome.kind !== 'anchored') return;
    expect(verified.outcome.walked.map((one) => one.id)).toEqual(ride.walkedItemIds);
    expect(ride.walkedItemIds).toEqual([...ride.receiptItemIds, ride.holdItemId, ride.bundleItemId]);
    // The three receipts are the published run, not a stand-in assembled beside it.
    const published = decodeExport(
      fromBase64Url(loadExportVectors().vectors.find((one) => one.name === 'well-formed-anchored')!.documentBase64Url),
    );
    expect(published.manifest.collection.k).toBe('anchored');
    if (published.manifest.collection.k !== 'anchored') return;
    const rideIds = verified.outcome.items.map((one) => one.id);
    for (const item of published.manifest.collection.items) {
      expect(rideIds, `the ride does not carry the published export item ${item.id}`).toContain(item.id);
      const ridden = verified.outcome.items.find((one) => one.id === item.id);
      // An arm that moved is a failure here rather than a comparison skipped: the published run carries every
      // item inline, so a ride handing one back on another arm has changed the contract, not narrowed the check.
      expect(ridden?.orig.k, `the ride carries ${item.id} on an arm the published export does not state`).toBe(
        item.orig.k,
      );
      expect(item.orig.k, `the published export carries ${item.id} on a non-inline arm`).toBe('inline');
      if (ridden === undefined || ridden.orig.k !== 'inline' || item.orig.k !== 'inline') continue;
      expect(equalBytes(ridden.orig.bytes, item.orig.bytes)).toBe(true);
    }
  });

  it('reads each item back through the door of the record it carries', () => {
    const verified = openRide();
    if (verified.outcome.kind !== 'anchored') throw new Error('the ride is not the anchored arm it states');
    const items = verified.outcome.items;
    const holdItem = items.find((one) => one.id === ride.holdItemId);
    const bundleItem = items.find((one) => one.id === ride.bundleItemId);
    expect(holdItem?.orig.k).toBe('inline');
    expect(bundleItem?.orig.k).toBe('inline');
    if (holdItem?.orig.k !== 'inline' || bundleItem?.orig.k !== 'inline') return;
    expect(toBase64Url(holdItem.orig.bytes)).toBe(toBase64Url(holdRowBytes('hold-fixture-v1')));
    expect(toBase64Url(bundleItem.orig.bytes)).toBe(HONEST.recordBase64Url);
    const hold = parseHoldRecord(holdItem.orig.bytes);
    const { record } = verifyIncidentBundle(bundleItem.orig.bytes, { holdBytes: holdItem.orig.bytes });
    expect(record.hold.at).toBe(hold.at);
    expect(record.window.to).toBe(hold.window.to);
    expect(holdRowBytes('hold-fixture-v1')).toEqual(fromBase64Url(file.rule.hold.recordBase64Url));
  });

  it('recomputes the floor the ridden record states', () => {
    const verified = openRide();
    if (verified.outcome.kind !== 'anchored') throw new Error('the ride is not the anchored arm it states');
    const bundleItem = verified.outcome.items.find((one) => one.id === ride.bundleItemId);
    if (bundleItem?.orig.k !== 'inline') throw new Error('the ride carries no inline bundle item');
    const record = parseIncidentBundle(bundleItem.orig.bytes);
    expect(record.floor.preserveUntil).toBe(ride.floor);
    expect(record.floor.preserveUntil).toBe(record.incident.at + record.floor.days * 86_400);
  });
});
