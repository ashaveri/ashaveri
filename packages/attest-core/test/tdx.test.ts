import { describe, it, expect } from 'vitest';
import { decodeAttestation, fromHex, replayRtmr3, verifyAttestation } from '../src/index.js';
import type { RuntimeEvent, TdxEvent } from '../src/index.js';
import { encodeV0Tdx, expectErrorCode, tdxEventsFor } from './helpers.js';

const reportData = new Uint8Array(64).fill(0xcd);
const runtimeEvents: RuntimeEvent[] = [
  { event: 'system-preparing', payload: new Uint8Array(0), version: 1 },
  { event: 'app-id', payload: fromHex('86e59625be93207bc2351c4d1bba20037cec8e16'), version: 1 },
];

// A synthetic TDX quote: only RTMR-3 and REPORT_DATA matter for the replay
// checks; the Intel DCAP signature itself is out of scope for attest-core.
function buildQuote(): Uint8Array {
  const quote = new Uint8Array(0x278);
  quote.set(replayRtmr3(runtimeEvents), 0x208);
  quote.set(reportData, 0x238);
  return quote;
}

function tdxAttestation(
  quote: Uint8Array = buildQuote(),
  eventLog: readonly TdxEvent[] = tdxEventsFor(runtimeEvents),
  events: readonly RuntimeEvent[] = runtimeEvents,
  data: Uint8Array = reportData,
): Uint8Array {
  return encodeV0Tdx({ quote, eventLog, runtimeEvents: events, reportData: data, config: 'tdx-test' });
}

describe('dStack TDX attestation verification', () => {
  it('verifies a synthetic quote whose RTMR-3 replays from runtime events', () => {
    const result = verifyAttestation(tdxAttestation());
    expect(result.platformKind).toBe('tdx');
    expect(result.version).toBe(0);
    expect(result.quoteSignatureVerified).toBe(false);
    expect(result.reportData).toEqual(reportData);
    expect(result.runtimeEvents.map((e) => e.event)).toEqual(['system-preparing', 'app-id']);
    expect(result.config).toBe('tdx-test');
    expect(result.tdx?.quote.mrTd.length).toBe(48);
    expect(result.tdx?.quote.rtmr[3]?.length).toBe(48);
  });

  it('decodes the TDX platform evidence', () => {
    const attestation = decodeAttestation(tdxAttestation());
    expect(attestation.platform.kind).toBe('tdx');
    if (attestation.platform.kind !== 'tdx') {
      throw new Error('expected tdx platform');
    }
    expect(attestation.platform.quote.length).toBe(0x278);
    expect(attestation.platform.eventLog.length).toBe(2);
  });

  it('rejects an RTMR-3 that does not match the replay', () => {
    const quote = buildQuote();
    quote[0x208]! ^= 0x01;
    expectErrorCode(() => verifyAttestation(tdxAttestation(quote)), 'RTMR_MISMATCH');
  });

  it('rejects a tampered event payload', () => {
    const log = tdxEventsFor(runtimeEvents).map((entry) => ({ ...entry }));
    (log[1] as { eventPayload: Uint8Array }).eventPayload = fromHex('ff');
    expectErrorCode(() => verifyAttestation(tdxAttestation(buildQuote(), log)), 'BAD_EVENT_DIGEST');
  });

  it('rejects a stack report_data that differs from the quote', () => {
    expectErrorCode(
      () => verifyAttestation(tdxAttestation(buildQuote(), tdxEventsFor(runtimeEvents), runtimeEvents, new Uint8Array(64).fill(0xff))),
      'REPORT_DATA_MISMATCH',
    );
  });

  it('rejects a truncated quote', () => {
    expectErrorCode(() => verifyAttestation(tdxAttestation(new Uint8Array(0x200))), 'MALFORMED_QUOTE');
  });
});
