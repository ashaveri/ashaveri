import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import {
  canonicalEventJsonV2,
  equalBytes,
  fromHex,
  replayRtmr3,
  runtimeEventDigest,
  runtimeEventPreimage,
  validateEventLog,
} from '../src/index.js';
import type { RuntimeEvent, TdxEvent } from '../src/index.js';
import { expectErrorCode, tdxEventsFor } from './helpers.js';

function sha384(...parts: Uint8Array[]): Uint8Array {
  const hash = createHash('sha384');
  for (const part of parts) {
    hash.update(part);
  }
  return new Uint8Array(hash.digest());
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

describe('V2 runtime event canonical JSON', () => {
  it('is byte-exact JCS', () => {
    expect(canonicalEventJsonV2('app-id', fromHex('86e59625be93207bc2351c4d1bba20037cec8e16'))).toBe(
      '{"name":"app-id","payload":"86e59625be93207bc2351c4d1bba20037cec8e16","type":134217729}',
    );
  });

  it('escapes JSON-special characters', () => {
    expect(canonicalEventJsonV2('a"b\\c\nd', new Uint8Array([0x00]))).toBe(
      '{"name":"a\\"b\\\\c\\nd","payload":"00","type":134217729}',
    );
  });

  it('digests the canonical representation', () => {
    const event: RuntimeEvent = {
      event: 'app-id',
      payload: fromHex('86e59625be93207bc2351c4d1bba20037cec8e16'),
      version: 2,
    };
    const canonical = new TextEncoder().encode(
      '{"name":"app-id","payload":"86e59625be93207bc2351c4d1bba20037cec8e16","type":134217729}',
    );
    expect(equalBytes(runtimeEventDigest(event), sha384(canonical))).toBe(true);
  });
});

describe('V1 runtime event preimage', () => {
  it('is type-prefixed name and payload', () => {
    const payload = fromHex('deadbeef');
    const event: RuntimeEvent = { event: 'boot-mr-done', payload, version: 1 };
    const name = new TextEncoder().encode('boot-mr-done');
    const expected = new Uint8Array(4 + 1 + name.length + 1 + payload.length);
    new DataView(expected.buffer).setUint32(0, 0x08000001, true);
    expected[4] = 0x3a;
    expected.set(name, 5);
    expected[5 + name.length] = 0x3a;
    expected.set(payload, 5 + name.length + 1);
    expect(equalBytes(runtimeEventPreimage(event), expected)).toBe(true);
    expect(equalBytes(runtimeEventDigest(event), sha384(expected))).toBe(true);
  });
});

describe('RTMR-3 replay', () => {
  it('chains sha384 from the zero measurement', () => {
    expect(equalBytes(replayRtmr3([]), new Uint8Array(48))).toBe(true);
    const event: RuntimeEvent = { event: 'e', payload: fromHex('01'), version: 1 };
    expect(equalBytes(replayRtmr3([event]), sha384(new Uint8Array(48), runtimeEventDigest(event)))).toBe(true);
    const other: RuntimeEvent = { event: 'f', payload: fromHex('02'), version: 1 };
    expect(equalBytes(replayRtmr3([event, other]), replayRtmr3([other, event]))).toBe(false);
  });
});

describe('event log validation', () => {
  const events: RuntimeEvent[] = [
    { event: 'one', payload: fromHex('aa'), version: 1 },
    { event: 'two', payload: fromHex('bb'), version: 1 },
  ];

  it('accepts a consistent log', () => {
    expect(() => validateEventLog(tdxEventsFor(events), events)).not.toThrow();
  });

  it('rejects a payload that does not match its stored digest', () => {
    const log = tdxEventsFor(events);
    (log[1] as { eventPayload: Uint8Array }).eventPayload = fromHex('cc');
    expectErrorCode(() => validateEventLog(log, events), 'BAD_EVENT_DIGEST');
  });

  it('rejects entries targeting IMR above 3', () => {
    const log = tdxEventsFor(events);
    (log[0] as { imr: number }).imr = 4;
    expectErrorCode(() => validateEventLog(log, events), 'BAD_EVENT_DIGEST');
  });

  it('rejects count mismatches between log and stack', () => {
    expectErrorCode(() => validateEventLog(tdxEventsFor(events), events.slice(1)), 'EVENT_LOG_MISMATCH');
  });

  it('rejects reordered runtime events', () => {
    expectErrorCode(() => validateEventLog(tdxEventsFor(events), [events[1]!, events[0]!]), 'EVENT_LOG_MISMATCH');
  });

  it('rejects version disagreement', () => {
    expectErrorCode(
      () => validateEventLog(tdxEventsFor(events), [events[0]!, { ...events[1]!, version: 2 }]),
      'EVENT_LOG_MISMATCH',
    );
  });

  it('validates V2 preimages against the canonical representation', () => {
    const event: RuntimeEvent = {
      event: 'app-id',
      payload: fromHex('86e59625be93207bc2351c4d1bba20037cec8e16'),
      version: 2,
    };
    const canonical = runtimeEventPreimage(event);
    const log: TdxEvent[] = [
      {
        imr: 3,
        eventType: 0x08000001,
        digest: runtimeEventDigest(event),
        event: event.event,
        eventPayload: event.payload,
        version: 2,
        preimage: toHex(canonical),
      },
    ];
    expect(() => validateEventLog(log, [event])).not.toThrow();

    const tampered = new Uint8Array(canonical);
    tampered[tampered.length - 1]! ^= 0x01;
    expectErrorCode(() => validateEventLog([{ ...log[0]!, preimage: toHex(tampered) }], [event]), 'BAD_EVENT_PREIMAGE');

    expectErrorCode(() => validateEventLog([{ ...log[0]!, preimage: null }], [event]), 'BAD_EVENT_PREIMAGE');
  });
});
