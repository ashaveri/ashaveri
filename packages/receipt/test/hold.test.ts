import { describe, expect, it } from 'vitest';
import {
  HOLD_RECORD_LIMITS,
  HOLD_RECORD_V1_MEMBERS,
  HOLD_RECORD_WINDOW_MEMBERS,
  ReceiptError,
  encodeHoldRecord,
  holdActiveAt,
  holdCoversStamp,
  holdRecordBytes,
  parseHoldRecord,
  refuseErasureUnderHold,
  type HoldRecord,
} from '../src/index.js';

/**
 * The hold record's strict reader, driven over the bytes of a file rather than over objects, and the
 * consultation rules driven over parsed records. The refusal cases are one edit of the writer's own
 * bytes at the position each fault names, so a row tests the rule it states rather than a document
 * assembled out of junk.
 */

const encoded = (text: string): Uint8Array => new TextEncoder().encode(text);
const decoded = (bytes: Uint8Array): string => new TextDecoder().decode(bytes);

const AT = 1_772_000_000;
const FROM = AT - 86_400;
const TO = AT + 86_400;
const BY = 'the fixture deployer';
const CREDENTIAL = 'cred-one';

function record(): HoldRecord {
  return {
    v: 1,
    prov: 'fixture',
    at: AT,
    by: BY,
    window: { from: FROM, to: TO },
    credentials: [CREDENTIAL, 'cred-two'],
    reason: 'Fixture hold over the test deployment this suite reads its own bytes for.',
    released: null,
    limits: HOLD_RECORD_LIMITS,
  };
}

/** One edit of the writer's bytes, every other byte left as the writer wrote it. */
function edited(base: HoldRecord, mutate: (document: Record<string, unknown>) => void): Uint8Array {
  const document = JSON.parse(decoded(encodeHoldRecord(base))) as Record<string, unknown>;
  mutate(document);
  return encoded(`${JSON.stringify(document, null, 2)}\n`);
}

function codeOf(run: () => unknown): string {
  try {
    run();
  } catch (err) {
    if (err instanceof ReceiptError) return err.code;
    throw err;
  }
  throw new Error('the reader accepted a document this case states it refuses');
}

describe('the hold record layout', () => {
  it('round-trips a record through the writer and the reader', () => {
    const base = record();
    const bytes = holdRecordBytes(base);
    expect(parseHoldRecord(bytes)).toEqual(base);
    expect(encoded(`${JSON.stringify(JSON.parse(decoded(bytes)), null, 2)}\n`)).toEqual(bytes);
  });

  it('round-trips a record that names no credentials, leaving the member off the wire', () => {
    const { credentials: _credentials, ...open } = record();
    const bytes = holdRecordBytes(open);
    expect(parseHoldRecord(bytes)).toEqual(open);
    expect(JSON.parse(decoded(bytes))).not.toHaveProperty('credentials');
  });

  it('round-trips a released record with an open-ended window', () => {
    const base: HoldRecord = { ...record(), released: AT + 500, window: { from: FROM, to: null } };
    expect(parseHoldRecord(holdRecordBytes(base))).toEqual(base);
  });

  it('declares the member lists the wire closes over', () => {
    const document = JSON.parse(decoded(encodeHoldRecord(record()))) as Record<string, unknown>;
    expect(Object.keys(document)).toEqual([...HOLD_RECORD_V1_MEMBERS]);
    expect(Object.keys(document['window'] as object)).toEqual([...HOLD_RECORD_WINDOW_MEMBERS]);
  });
});

describe('the hold record reader refuses', () => {
  it('a document that is not one JSON object', () => {
    expect(codeOf(() => parseHoldRecord(encoded('not json')))).toBe('HOLD_RECORD_BAD_DOCUMENT');
    expect(codeOf(() => parseHoldRecord(encoded('[]')))).toBe('HOLD_RECORD_BAD_DOCUMENT');
  });

  it('a member named twice, while the bytes carry both', () => {
    const bytes = encoded(decoded(encodeHoldRecord(record())).replace('"v": 1,', '"v": 1,\n  "v": 1,'));
    expect(codeOf(() => parseHoldRecord(bytes))).toBe('HOLD_RECORD_BAD_DOCUMENT');
  });

  it('a float wearing an integer', () => {
    const bytes = encodeHoldRecord(record());
    const spelled = encoded(decoded(bytes).replace(`"at": ${AT}`, `"at": ${AT}.0`));
    expect(codeOf(() => parseHoldRecord(spelled))).toBe('HOLD_RECORD_BAD_DOCUMENT');
  });

  it('a version no layout reads', () => {
    const bytes = edited(record(), (document) => {
      document['v'] = 2;
    });
    expect(codeOf(() => parseHoldRecord(bytes))).toBe('HOLD_RECORD_UNSUPPORTED_VERSION');
  });

  it('a version that is not an integer at all', () => {
    const bytes = edited(record(), (document) => {
      document['v'] = '1';
    });
    expect(codeOf(() => parseHoldRecord(bytes))).toBe('HOLD_RECORD_BAD_DOCUMENT');
  });

  it('a member the top level does not define', () => {
    const bytes = edited(record(), (document) => {
      document['future'] = 'a member no version names';
    });
    expect(codeOf(() => parseHoldRecord(bytes))).toBe('HOLD_RECORD_BAD_DOCUMENT');
  });

  it('a member of the window block the layout does not define', () => {
    const bytes = edited(record(), (document) => {
      const window = document['window'] as Record<string, unknown>;
      window['tz'] = 'a zone no member of this layout holds';
    });
    expect(codeOf(() => parseHoldRecord(bytes))).toBe('HOLD_RECORD_BAD_DOCUMENT');
  });

  it('an absent member', () => {
    const bytes = edited(record(), (document) => {
      delete document['reason'];
    });
    expect(codeOf(() => parseHoldRecord(bytes))).toBe('HOLD_RECORD_BAD_DOCUMENT');
  });

  it('a limits member wording its own limits', () => {
    const bytes = edited(record(), (document) => {
      document['limits'] = 'This hold has no limits.';
    });
    expect(codeOf(() => parseHoldRecord(bytes))).toBe('HOLD_RECORD_BAD_DOCUMENT');
  });

  it('a release stamped before the hold was issued', () => {
    const bytes = edited(record(), (document) => {
      document['released'] = AT - 1;
    });
    expect(codeOf(() => parseHoldRecord(bytes))).toBe('HOLD_RECORD_BAD_DOCUMENT');
  });

  it('a window closing before it opens', () => {
    const bytes = edited(record(), (document) => {
      const window = document['window'] as Record<string, unknown>;
      window['to'] = FROM - 1;
    });
    expect(codeOf(() => parseHoldRecord(bytes))).toBe('HOLD_RECORD_BAD_DOCUMENT');
  });

  it('an empty credentials list', () => {
    const bytes = edited(record(), (document) => {
      document['credentials'] = [];
    });
    expect(codeOf(() => parseHoldRecord(bytes))).toBe('HOLD_RECORD_BAD_DOCUMENT');
  });

  it('one credential named twice', () => {
    const bytes = edited(record(), (document) => {
      const credentials = document['credentials'] as string[];
      credentials.push(credentials[0]!);
    });
    expect(codeOf(() => parseHoldRecord(bytes))).toBe('HOLD_RECORD_BAD_DOCUMENT');
  });

  it('a provenance outside the vocabulary', () => {
    const bytes = edited(record(), (document) => {
      document['prov'] = 'synthetic';
    });
    expect(codeOf(() => parseHoldRecord(bytes))).toBe('HOLD_RECORD_BAD_DOCUMENT');
  });

  it('an author carrying a character that forges the printed line', () => {
    const bytes = edited(record(), (document) => {
      document['by'] = 'the\u202Edeployer';
    });
    expect(codeOf(() => parseHoldRecord(bytes))).toBe('HOLD_RECORD_BAD_DOCUMENT');
  });

  it('a reason padded on either side', () => {
    const bytes = edited(record(), (document) => {
      document['reason'] = ' a reason a printed row does not pad ';
    });
    expect(codeOf(() => parseHoldRecord(bytes))).toBe('HOLD_RECORD_BAD_DOCUMENT');
  });

  it('a record whose writer state the reader would refuse', () => {
    const base = record();
    const broken: HoldRecord = { ...base, limits: 'worded by the writer' };
    expect(codeOf(() => holdRecordBytes(broken))).toBe('HOLD_RECORD_BAD_DOCUMENT');
  });
});

describe('holdActiveAt', () => {
  it('is active from the issue stamp inclusive, while no release is stated', () => {
    const base = record();
    expect(holdActiveAt(base, AT - 1)).toBe(false);
    expect(holdActiveAt(base, AT)).toBe(true);
    expect(holdActiveAt(base, AT + 10_000_000)).toBe(true);
  });

  it('stops at the release stamp exclusive', () => {
    const base: HoldRecord = { ...record(), released: AT + 100 };
    expect(holdActiveAt(base, AT + 99)).toBe(true);
    expect(holdActiveAt(base, AT + 100)).toBe(false);
    expect(holdActiveAt(base, AT + 101)).toBe(false);
  });
});

describe('holdCoversStamp', () => {
  it('covers the window from inclusive to exclusive', () => {
    const base = record();
    expect(holdCoversStamp(base, FROM - 1, AT)).toBe(false);
    expect(holdCoversStamp(base, FROM, AT)).toBe(true);
    expect(holdCoversStamp(base, TO - 1, AT)).toBe(true);
    expect(holdCoversStamp(base, TO, AT)).toBe(false);
  });

  it('covers any stamp at or after an open-ended window opens', () => {
    const base: HoldRecord = { ...record(), window: { from: FROM, to: null } };
    expect(holdCoversStamp(base, FROM - 1, AT)).toBe(false);
    expect(holdCoversStamp(base, FROM, AT)).toBe(true);
    expect(holdCoversStamp(base, AT + 10_000_000, AT)).toBe(true);
  });

  it('covers nothing once the hold is released, and nothing before it is issued', () => {
    const released: HoldRecord = { ...record(), released: AT + 100 };
    expect(holdCoversStamp(released, FROM, AT + 100)).toBe(false);
    expect(holdCoversStamp(released, FROM, AT)).toBe(true);
    expect(holdCoversStamp(record(), FROM, AT - 1)).toBe(false);
  });
});

describe('refuseErasureUnderHold', () => {
  it('refuses erasure of a credential an active hold names, naming the credential and the hold', () => {
    let caught: unknown;
    try {
      refuseErasureUnderHold([record()], CREDENTIAL, AT);
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(ReceiptError);
    expect((caught as ReceiptError).code).toBe('HOLD_ERASURE_REFUSED');
    expect((caught as ReceiptError).message).toContain(CREDENTIAL);
    expect((caught as ReceiptError).message).toContain(String(AT));
    expect((caught as ReceiptError).message).toContain(BY);
  });

  it('refuses erasure under an active hold that names no credentials, which covers every credential', () => {
    const { credentials: _credentials, ...open } = record();
    expect(codeOf(() => refuseErasureUnderHold([open], 'any-credential', AT))).toBe('HOLD_ERASURE_REFUSED');
  });

  it('does not refuse for a credential the hold does not name', () => {
    expect(() => refuseErasureUnderHold([record()], 'cred-elsewhere', AT)).not.toThrow();
  });

  it('does not refuse under a released hold', () => {
    const released: HoldRecord = { ...record(), released: AT };
    expect(() => refuseErasureUnderHold([released], CREDENTIAL, AT)).not.toThrow();
    expect(() => refuseErasureUnderHold([released], CREDENTIAL, AT + 1)).not.toThrow();
  });

  it('does not refuse before the hold is issued, or with no holds at all', () => {
    expect(() => refuseErasureUnderHold([record()], CREDENTIAL, AT - 1)).not.toThrow();
    expect(() => refuseErasureUnderHold([], CREDENTIAL, AT)).not.toThrow();
  });

  it('refuses when any hold of the list names the credential while active', () => {
    const other: HoldRecord = { ...record(), credentials: ['cred-elsewhere'] };
    expect(codeOf(() => refuseErasureUnderHold([other, record()], CREDENTIAL, AT))).toBe('HOLD_ERASURE_REFUSED');
  });
});
