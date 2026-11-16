import { describe, expect, it } from 'vitest';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  HOLD_RECORD_LIMITS,
  INCIDENT_BUNDLE_FLOOR_MEMBERS,
  INCIDENT_BUNDLE_HOLD_MEMBERS,
  INCIDENT_BUNDLE_INCIDENT_MEMBERS,
  INCIDENT_BUNDLE_LIMITS,
  INCIDENT_BUNDLE_POINTERS,
  INCIDENT_BUNDLE_POINTER_CITATIONS,
  INCIDENT_BUNDLE_V1_MEMBERS,
  INCIDENT_BUNDLE_WINDOW_MEMBERS,
  ReceiptError,
  encodeIncidentBundle,
  holdRecordBytes,
  incidentBundleBytes,
  parseHoldRecord,
  parseIncidentBundle,
  toHex,
  verifyIncidentBundle,
  type HoldRecord,
  type IncidentBundleRecord,
} from '../src/index.js';

/**
 * The incident bundle's strict reader, driven over the bytes of a file rather than over objects, and
 * the bound/asserted split driven over a hold record the reader is handed beside the bundle. The
 * refusal cases are one edit of the writer's own bytes at the position each fault names, so a row tests
 * the rule it states rather than a document assembled out of junk.
 */

const encoded = (text: string): Uint8Array => new TextEncoder().encode(text);
const decoded = (bytes: Uint8Array): string => new TextDecoder().decode(bytes);

const AT = 1_772_000_000;
const INCIDENT_AT = AT - 3_600;
const HOLD_AT = AT - 7_200;
const FROM = AT - 86_400;
const TO = AT + 86_400;
const BY = 'the fixture deployer';
const DAYS = 90;
const PRESERVE_UNTIL = INCIDENT_AT + DAYS * 86_400;
const POINTER = 'gsa-552-239-7001-f-5';

function hold(): HoldRecord {
  return {
    v: 1,
    prov: 'fixture',
    at: HOLD_AT,
    by: BY,
    window: { from: FROM, to: TO },
    credentials: ['cred-one'],
    reason: 'Fixture hold over the test deployment this suite reads its own bytes for.',
    released: null,
    limits: HOLD_RECORD_LIMITS,
  };
}

const HOLD_BYTES = holdRecordBytes(hold());
const HOLD_SHA256 = toHex(sha256(HOLD_BYTES));
const HOLD = parseHoldRecord(HOLD_BYTES);

function record(): IncidentBundleRecord {
  return {
    v: 1,
    prov: 'fixture',
    at: AT,
    incident: {
      id: 'incident/one',
      at: INCIDENT_AT,
      states: 'Fixture incident over the test deployment this suite reads its own bytes for.',
    },
    hold: { sha256: HOLD_SHA256, at: HOLD.at, by: HOLD.by },
    window: { from: HOLD.window.from, to: HOLD.window.to },
    floor: { days: DAYS, preserveUntil: PRESERVE_UNTIL, pointer: POINTER },
    pointers: [...INCIDENT_BUNDLE_POINTERS],
    limits: INCIDENT_BUNDLE_LIMITS,
  };
}

/** One edit of the writer's bytes, every other byte left as the writer wrote it. */
function edited(base: IncidentBundleRecord, mutate: (document: Record<string, unknown>) => void): Uint8Array {
  const document = JSON.parse(decoded(encodeIncidentBundle(base))) as Record<string, unknown>;
  mutate(document);
  return encoded(`${JSON.stringify(document, null, 2)}\n`);
}

/** The refusal a run raises, so a row can name the figures a detail has to carry as well as the code. */
function refusalOf(run: () => unknown): ReceiptError {
  try {
    run();
  } catch (err) {
    if (err instanceof ReceiptError) return err;
    throw err;
  }
  throw new Error('the reader accepted a document this case states it refuses');
}

function codeOf(run: () => unknown): string {
  return refusalOf(run).code;
}

describe('the incident bundle layout', () => {
  it('round-trips a record through the writer and the reader', () => {
    const base = record();
    const bytes = incidentBundleBytes(base);
    expect(parseIncidentBundle(bytes)).toEqual(base);
    expect(encoded(`${JSON.stringify(JSON.parse(decoded(bytes)), null, 2)}\n`)).toEqual(bytes);
  });

  it('round-trips a record over a hold with an open-ended window', () => {
    const openHold = holdRecordBytes({ ...hold(), window: { from: FROM, to: null } });
    const parsed = parseHoldRecord(openHold);
    const base: IncidentBundleRecord = {
      ...record(),
      hold: { sha256: toHex(sha256(openHold)), at: parsed.at, by: parsed.by },
      window: { from: FROM, to: null },
    };
    expect(parseIncidentBundle(incidentBundleBytes(base))).toEqual(base);
    expect(verifyIncidentBundle(incidentBundleBytes(base), { holdBytes: openHold }).record).toEqual(base);
  });

  it('reads an incident stamped at the very instant of the bundle that carries it', () => {
    // `incident.at` may equal the assembly stamp and is refused only past it, so the boundary reads.
    const base: IncidentBundleRecord = {
      ...record(),
      incident: { ...record().incident, at: AT },
      floor: { days: DAYS, preserveUntil: AT + DAYS * 86_400, pointer: POINTER },
    };
    expect(parseIncidentBundle(incidentBundleBytes(base))).toEqual(base);
    expect(verifyIncidentBundle(incidentBundleBytes(base), { holdBytes: HOLD_BYTES }).record).toEqual(base);
  });

  it('declares the member lists the wire closes over', () => {
    const document = JSON.parse(decoded(encodeIncidentBundle(record()))) as Record<string, unknown>;
    expect(Object.keys(document)).toEqual([...INCIDENT_BUNDLE_V1_MEMBERS]);
    expect(Object.keys(document['incident'] as object)).toEqual([...INCIDENT_BUNDLE_INCIDENT_MEMBERS]);
    expect(Object.keys(document['hold'] as object)).toEqual([...INCIDENT_BUNDLE_HOLD_MEMBERS]);
    expect(Object.keys(document['window'] as object)).toEqual([...INCIDENT_BUNDLE_WINDOW_MEMBERS]);
    expect(Object.keys(document['floor'] as object)).toEqual([...INCIDENT_BUNDLE_FLOOR_MEMBERS]);
  });

  it('carries no notification member, the closed layout being the witness', () => {
    expect([...INCIDENT_BUNDLE_V1_MEMBERS]).toEqual(['v', 'prov', 'at', 'incident', 'hold', 'window', 'floor', 'pointers', 'limits']);
    expect(INCIDENT_BUNDLE_V1_MEMBERS.some((member) => member.toLowerCase().includes('notif'))).toBe(false);
    const document = JSON.parse(decoded(encodeIncidentBundle(record()))) as Record<string, unknown>;
    expect(Object.keys(document).some((member) => member.toLowerCase().includes('notif'))).toBe(false);
  });

  it('gives every pointer a citation', () => {
    for (const pointer of INCIDENT_BUNDLE_POINTERS) {
      expect(INCIDENT_BUNDLE_POINTER_CITATIONS[pointer].length).toBeGreaterThan(0);
    }
  });

  it('states the limits the format owns, verbatim', () => {
    expect(INCIDENT_BUNDLE_LIMITS).toContain('pointer for counsel, not a compliance claim');
    expect(INCIDENT_BUNDLE_LIMITS).toContain('seventy-two-hour');
    expect(INCIDENT_BUNDLE_LIMITS).toContain('process obligation of the deployment');
    expect(INCIDENT_BUNDLE_LIMITS).toContain('nothing in this record states or proves');
    expect(INCIDENT_BUNDLE_LIMITS).toContain("asserted fields are the deployment's own");
  });
});

describe('the incident bundle reader refuses', () => {
  it('a document that is not one JSON object', () => {
    expect(codeOf(() => parseIncidentBundle(encoded('not json')))).toBe('INCIDENT_BUNDLE_BAD_DOCUMENT');
    expect(codeOf(() => parseIncidentBundle(encoded('[]')))).toBe('INCIDENT_BUNDLE_BAD_DOCUMENT');
  });

  it('a member named twice, while the bytes carry both', () => {
    const bytes = encoded(decoded(encodeIncidentBundle(record())).replace('"v": 1,', '"v": 1,\n  "v": 1,'));
    expect(codeOf(() => parseIncidentBundle(bytes))).toBe('INCIDENT_BUNDLE_BAD_DOCUMENT');
  });

  it('a float wearing an integer', () => {
    const bytes = encodeIncidentBundle(record());
    const spelled = encoded(decoded(bytes).replace(`"at": ${AT}`, `"at": ${AT}.0`));
    expect(codeOf(() => parseIncidentBundle(spelled))).toBe('INCIDENT_BUNDLE_BAD_DOCUMENT');
  });

  it('a version no layout reads', () => {
    const bytes = edited(record(), (document) => {
      document['v'] = 2;
    });
    expect(codeOf(() => parseIncidentBundle(bytes))).toBe('INCIDENT_BUNDLE_UNSUPPORTED_VERSION');
  });

  it('a version that is not an integer at all', () => {
    const bytes = edited(record(), (document) => {
      document['v'] = '1';
    });
    expect(codeOf(() => parseIncidentBundle(bytes))).toBe('INCIDENT_BUNDLE_BAD_DOCUMENT');
  });

  it('a member the top level does not define', () => {
    const bytes = edited(record(), (document) => {
      document['future'] = 'a member no version names';
    });
    expect(codeOf(() => parseIncidentBundle(bytes))).toBe('INCIDENT_BUNDLE_BAD_DOCUMENT');
  });

  it('a member of the incident block the layout does not define', () => {
    const bytes = edited(record(), (document) => {
      const incident = document['incident'] as Record<string, unknown>;
      incident['severity'] = 'a grade no member of this layout holds';
    });
    expect(codeOf(() => parseIncidentBundle(bytes))).toBe('INCIDENT_BUNDLE_BAD_DOCUMENT');
  });

  it('a member of the hold block the layout does not define', () => {
    const bytes = edited(record(), (document) => {
      const holdBlock = document['hold'] as Record<string, unknown>;
      holdBlock['released'] = null;
    });
    expect(codeOf(() => parseIncidentBundle(bytes))).toBe('INCIDENT_BUNDLE_BAD_DOCUMENT');
  });

  it('a member of the floor block the layout does not define', () => {
    const bytes = edited(record(), (document) => {
      const floor = document['floor'] as Record<string, unknown>;
      floor['notification'] = 'a deadline no member of this layout holds';
    });
    expect(codeOf(() => parseIncidentBundle(bytes))).toBe('INCIDENT_BUNDLE_BAD_DOCUMENT');
  });

  it('a member of the window block the layout does not define', () => {
    const bytes = edited(record(), (document) => {
      const window = document['window'] as Record<string, unknown>;
      window['tz'] = 'a zone no member of this layout holds';
    });
    expect(codeOf(() => parseIncidentBundle(bytes))).toBe('INCIDENT_BUNDLE_BAD_DOCUMENT');
  });

  it('an absent member', () => {
    const bytes = edited(record(), (document) => {
      delete document['floor'];
    });
    expect(codeOf(() => parseIncidentBundle(bytes))).toBe('INCIDENT_BUNDLE_BAD_DOCUMENT');
  });

  it('a limits member wording its own limits', () => {
    const bytes = edited(record(), (document) => {
      document['limits'] = 'This bundle has no limits.';
    });
    expect(codeOf(() => parseIncidentBundle(bytes))).toBe('INCIDENT_BUNDLE_BAD_DOCUMENT');
  });

  it('a pointers entry outside the registry', () => {
    const bytes = edited(record(), (document) => {
      document['pointers'] = ['some-other-provision'];
    });
    expect(codeOf(() => parseIncidentBundle(bytes))).toBe('INCIDENT_BUNDLE_UNKNOWN_POINTER');
  });

  it('a floor pointer outside the registry', () => {
    const bytes = edited(record(), (document) => {
      const floor = document['floor'] as Record<string, unknown>;
      floor['pointer'] = 'some-other-provision';
    });
    expect(codeOf(() => parseIncidentBundle(bytes))).toBe('INCIDENT_BUNDLE_UNKNOWN_POINTER');
  });

  it('a pointers entry that is not a text at all', () => {
    const bytes = edited(record(), (document) => {
      document['pointers'] = [1];
    });
    expect(codeOf(() => parseIncidentBundle(bytes))).toBe('INCIDENT_BUNDLE_BAD_DOCUMENT');
  });

  it('a floor pointer that is not a text at all', () => {
    const bytes = edited(record(), (document) => {
      const floor = document['floor'] as Record<string, unknown>;
      floor['pointer'] = 1;
    });
    expect(codeOf(() => parseIncidentBundle(bytes))).toBe('INCIDENT_BUNDLE_BAD_DOCUMENT');
  });

  it('an empty pointers list and one pointer named twice', () => {
    expect(
      codeOf(() =>
        parseIncidentBundle(
          edited(record(), (document) => {
            document['pointers'] = [];
          }),
        ),
      ),
    ).toBe('INCIDENT_BUNDLE_BAD_DOCUMENT');
    expect(
      codeOf(() =>
        parseIncidentBundle(
          edited(record(), (document) => {
            const pointers = document['pointers'] as string[];
            pointers.push(pointers[0]!);
          }),
        ),
      ),
    ).toBe('INCIDENT_BUNDLE_BAD_DOCUMENT');
  });

  it('an incident stamped after the bundle that carries it', () => {
    const bytes = edited(record(), (document) => {
      const incident = document['incident'] as Record<string, unknown>;
      incident['at'] = AT + 1;
    });
    expect(codeOf(() => parseIncidentBundle(bytes))).toBe('INCIDENT_BUNDLE_BAD_DOCUMENT');
  });

  it('a window closing before it opens', () => {
    const bytes = edited(record(), (document) => {
      const window = document['window'] as Record<string, unknown>;
      window['to'] = FROM - 1;
    });
    expect(codeOf(() => parseIncidentBundle(bytes))).toBe('INCIDENT_BUNDLE_BAD_DOCUMENT');
  });

  it('a floor days that is not a positive whole number', () => {
    expect(
      codeOf(() =>
        parseIncidentBundle(
          edited(record(), (document) => {
            const floor = document['floor'] as Record<string, unknown>;
            floor['days'] = 0;
          }),
        ),
      ),
    ).toBe('INCIDENT_BUNDLE_BAD_DOCUMENT');
    expect(
      codeOf(() =>
        parseIncidentBundle(
          edited(record(), (document) => {
            const floor = document['floor'] as Record<string, unknown>;
            floor['days'] = -1;
          }),
        ),
      ),
    ).toBe('INCIDENT_BUNDLE_BAD_DOCUMENT');
  });

  it('a floor whose preserveUntil is not the incident stamp plus the stated days', () => {
    const bytes = edited(record(), (document) => {
      const floor = document['floor'] as Record<string, unknown>;
      floor['preserveUntil'] = PRESERVE_UNTIL + 1;
    });
    // Both figures the floor relates are inside this one record and no external byte is read to compare
    // them, so the layout door answers the arithmetic rather than the door handed the hold: a caller
    // holding only the bundle is refused too.
    const fault = refusalOf(() => parseIncidentBundle(bytes));
    expect(fault.code).toBe('INCIDENT_BUNDLE_BAD_DOCUMENT');
    expect(fault.message).toContain(String(PRESERVE_UNTIL + 1));
    expect(fault.message).toContain(String(PRESERVE_UNTIL));
  });

  it('a floor whose days cannot be stated as a stamp', () => {
    const bytes = edited(record(), (document) => {
      const floor = document['floor'] as Record<string, unknown>;
      floor['days'] = Number.MAX_SAFE_INTEGER;
    });
    // Past the largest integer a JavaScript number carries exactly, `days * 86400` is a rounded float a
    // stated value could match by luck, so the days are refused before any floor is compared to them.
    const fault = refusalOf(() => parseIncidentBundle(bytes));
    expect(fault.code).toBe('INCIDENT_BUNDLE_BAD_DOCUMENT');
    expect(fault.message).toContain('floor.days');
  });

  it('a preserveUntil stated before the incident it preserves', () => {
    const bytes = edited(record(), (document) => {
      const floor = document['floor'] as Record<string, unknown>;
      floor['preserveUntil'] = INCIDENT_AT - 1;
    });
    const fault = refusalOf(() => parseIncidentBundle(bytes));
    expect(fault.code).toBe('INCIDENT_BUNDLE_BAD_DOCUMENT');
    expect(fault.message).toContain('floor.preserveUntil');
  });

  it('a hold digest in uppercase hex', () => {
    const bytes = edited(record(), (document) => {
      const holdBlock = document['hold'] as Record<string, unknown>;
      holdBlock['sha256'] = HOLD_SHA256.toUpperCase();
    });
    expect(codeOf(() => parseIncidentBundle(bytes))).toBe('INCIDENT_BUNDLE_BAD_DOCUMENT');
  });

  it('a provenance outside the vocabulary', () => {
    const bytes = edited(record(), (document) => {
      document['prov'] = 'synthetic';
    });
    expect(codeOf(() => parseIncidentBundle(bytes))).toBe('INCIDENT_BUNDLE_BAD_DOCUMENT');
  });

  it('an incident identity carrying a character that forges the printed line', () => {
    const bytes = edited(record(), (document) => {
      const incident = document['incident'] as Record<string, unknown>;
      incident['id'] = 'incident\u202E/one';
    });
    expect(codeOf(() => parseIncidentBundle(bytes))).toBe('INCIDENT_BUNDLE_BAD_DOCUMENT');
  });

  it('a copied hold author carrying a character that forges the printed line', () => {
    const bytes = edited(record(), (document) => {
      const holdBlock = document['hold'] as Record<string, unknown>;
      holdBlock['by'] = 'the\u202E fixture deployer';
    });
    expect(codeOf(() => parseIncidentBundle(bytes))).toBe('INCIDENT_BUNDLE_BAD_DOCUMENT');
  });

  it('an incident narrative padded on either side', () => {
    const bytes = edited(record(), (document) => {
      const incident = document['incident'] as Record<string, unknown>;
      incident['states'] = ' a narrative a printed row does not pad ';
    });
    expect(codeOf(() => parseIncidentBundle(bytes))).toBe('INCIDENT_BUNDLE_BAD_DOCUMENT');
  });

  it('a record whose writer state the reader would refuse', () => {
    const base = record();
    const broken: IncidentBundleRecord = { ...base, limits: 'worded by the writer' };
    expect(codeOf(() => incidentBundleBytes(broken))).toBe('INCIDENT_BUNDLE_BAD_DOCUMENT');
  });
});

describe('the bound and asserted split, over the hold the record designates', () => {
  it('verifies an honest record against its hold bytes', () => {
    const verified = verifyIncidentBundle(incidentBundleBytes(record()), { holdBytes: HOLD_BYTES });
    expect(verified.record).toEqual(record());
  });

  it('refuses hold bytes that are not the ones the record designates', () => {
    const other = holdRecordBytes({ ...hold(), by: 'someone else' });
    expect(
      codeOf(() => verifyIncidentBundle(incidentBundleBytes(record()), { holdBytes: other })),
    ).toBe('INCIDENT_BUNDLE_HOLD_MISMATCH');
  });

  it('refuses designated hold bytes that do not parse as a hold record', () => {
    const notJson = encoded('not json');
    const designating: IncidentBundleRecord = {
      ...record(),
      hold: { ...record().hold, sha256: toHex(sha256(notJson)) },
    };
    expect(
      codeOf(() => verifyIncidentBundle(incidentBundleBytes(designating), { holdBytes: notJson })),
    ).toBe('INCIDENT_BUNDLE_HOLD_UNREADABLE');
  });

  it('refuses a designated hold whose positions are ill-shaped', () => {
    const illShaped = encoded(decoded(HOLD_BYTES).replace('"released": null', `"released": ${String(HOLD_AT - 1)}`));
    const designating: IncidentBundleRecord = {
      ...record(),
      hold: { ...record().hold, sha256: toHex(sha256(illShaped)) },
    };
    expect(
      codeOf(() => verifyIncidentBundle(incidentBundleBytes(designating), { holdBytes: illShaped })),
    ).toBe('INCIDENT_BUNDLE_HOLD_UNREADABLE');
  });

  it('accepts a mutation of an asserted incident narrative, which stays asserted', () => {
    const bytes = edited(record(), (document) => {
      const incident = document['incident'] as Record<string, unknown>;
      incident['states'] = 'A narrative the deployment stated after assembly.';
    });
    const verified = verifyIncidentBundle(bytes, { holdBytes: HOLD_BYTES });
    expect(verified.record.incident.states).toBe('A narrative the deployment stated after assembly.');
    expect(verified.record.hold).toEqual(record().hold);
  });

  it('accepts a stated floor of any positive whole days, recomputing preserveUntil', () => {
    const days = 120;
    const base: IncidentBundleRecord = {
      ...record(),
      floor: { days, preserveUntil: INCIDENT_AT + days * 86_400, pointer: POINTER },
    };
    const verified = verifyIncidentBundle(incidentBundleBytes(base), { holdBytes: HOLD_BYTES });
    expect(verified.record.floor.days).toBe(days);
    expect(verified.record.floor.preserveUntil).toBe(INCIDENT_AT + days * 86_400);
  });

  it('refuses a mutation of the bound hold issue stamp, with the two values named', () => {
    const bytes = edited(record(), (document) => {
      const holdBlock = document['hold'] as Record<string, unknown>;
      holdBlock['at'] = HOLD_AT + 1;
    });
    let caught: unknown;
    try {
      verifyIncidentBundle(bytes, { holdBytes: HOLD_BYTES });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(ReceiptError);
    expect((caught as ReceiptError).code).toBe('INCIDENT_BUNDLE_BOUND_DISAGREES');
    expect((caught as ReceiptError).message).toContain('hold.at');
    expect((caught as ReceiptError).message).toContain(String(HOLD_AT + 1));
    expect((caught as ReceiptError).message).toContain(String(HOLD_AT));
  });

  it('refuses a mutation of the bound hold author', () => {
    const bytes = edited(record(), (document) => {
      const holdBlock = document['hold'] as Record<string, unknown>;
      holdBlock['by'] = 'someone else';
    });
    expect(
      codeOf(() => verifyIncidentBundle(bytes, { holdBytes: HOLD_BYTES })),
    ).toBe('INCIDENT_BUNDLE_BOUND_DISAGREES');
  });

  it('refuses a mutation of the bound window from', () => {
    const bytes = edited(record(), (document) => {
      const window = document['window'] as Record<string, unknown>;
      window['from'] = FROM + 1;
    });
    expect(
      codeOf(() => verifyIncidentBundle(bytes, { holdBytes: HOLD_BYTES })),
    ).toBe('INCIDENT_BUNDLE_BOUND_DISAGREES');
  });

  it('refuses a mutation of the bound window to', () => {
    const bytes = edited(record(), (document) => {
      const window = document['window'] as Record<string, unknown>;
      window['to'] = TO + 1;
    });
    expect(
      codeOf(() => verifyIncidentBundle(bytes, { holdBytes: HOLD_BYTES })),
    ).toBe('INCIDENT_BUNDLE_BOUND_DISAGREES');
  });

  it('refuses a designated hold that is whole bytes of a version this package does not read', () => {
    const laterVersion = encoded(decoded(HOLD_BYTES).replace('"v": 1,', '"v": 2,'));
    const designating: IncidentBundleRecord = {
      ...record(),
      hold: { ...record().hold, sha256: toHex(sha256(laterVersion)) },
    };
    // The hold is read through its own whole-layout reader, and whatever that reader refuses is what an
    // operator has to see: the bundle's code closes the family, the hold's own message carries the reason.
    const holdFault = refusalOf(() => parseHoldRecord(laterVersion));
    const fault = refusalOf(() => verifyIncidentBundle(incidentBundleBytes(designating), { holdBytes: laterVersion }));
    expect(holdFault.code).toBe('HOLD_RECORD_UNSUPPORTED_VERSION');
    expect(fault.code).toBe('INCIDENT_BUNDLE_HOLD_UNREADABLE');
    expect(fault.message).toContain(holdFault.message);
  });
});
