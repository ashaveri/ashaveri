import { describe, it, expect } from 'vitest';
import { decodeAttestation, fromHex, mrConfigDocumentDigest, parseTdxQuote, pinnedComposeHash, platformMeasurement, replayRtmr3, verifyAttestation } from '../src/index.js';
import type { RuntimeEvent, TdxEvent } from '../src/index.js';
import { encodeV0Tdx, expectErrorCode, fixture, tdxEventsFor } from './helpers.js';

const reportData = new Uint8Array(64).fill(0xcd);
const runtimeEvents: RuntimeEvent[] = [
  { event: 'system-preparing', payload: new Uint8Array(0), version: 1 },
  { event: 'app-id', payload: fromHex('86e59625be93207bc2351c4d1bba20037cec8e16'), version: 1 },
];

// A synthetic TDX quote carrying only what the replay checks need: RTMR-3 and
// REPORT_DATA, with no signature block. Real Intel-signed quotes are in tdx-dcap.
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

// MR_CONFIG_ID occupies quote bytes 0xe8 through 0x118 and is 48 bytes wide.
const MR_CONFIG_ID_OFFSET = 0xe8;

function quoteWithMrConfigId(binding: Uint8Array): Uint8Array {
  const quote = buildQuote();
  quote.set(binding, MR_CONFIG_ID_OFFSET);
  return quote;
}

function tag3Binding(digest: Uint8Array): Uint8Array {
  const binding = new Uint8Array(48);
  binding[0] = 3;
  binding.set(digest, 1);
  return binding;
}

describe('TDX MR_CONFIG_ID binding', () => {
  it('reports no pinned configuration when the field is empty', () => {
    const result = verifyAttestation(tdxAttestation(quoteWithMrConfigId(new Uint8Array(48))));
    expect(result.tdx?.mrConfig).toBeNull();
  });

  it('reads a tag 3 binding as the pinned document digest', () => {
    const digest = new Uint8Array(32).fill(0x5a);
    const result = verifyAttestation(tdxAttestation(quoteWithMrConfigId(tag3Binding(digest))));
    expect(result.tdx?.mrConfig).toEqual({ tag: 3, digest });
  });

  it('pins the digest a mr_config document hashes to', () => {
    const document = `{"version":3,"compose_hash":"${'ab'.repeat(32)}","key_provider":"kms"}`;
    const digest = mrConfigDocumentDigest(document);
    const result = verifyAttestation(tdxAttestation(quoteWithMrConfigId(tag3Binding(digest))));
    expect(result.tdx?.mrConfig?.digest).toEqual(digest);
  });

  it('rejects a binding with an unsupported tag', () => {
    const binding = tag3Binding(new Uint8Array(32).fill(1));
    binding[0] = 1;
    expectErrorCode(() => verifyAttestation(tdxAttestation(quoteWithMrConfigId(binding))), 'BAD_MR_CONFIG_ID');
  });

  it('rejects non-zero padding after the digest', () => {
    const binding = tag3Binding(new Uint8Array(32).fill(1));
    binding[33] = 1;
    expectErrorCode(() => verifyAttestation(tdxAttestation(quoteWithMrConfigId(binding))), 'BAD_MR_CONFIG_ID');
  });
});

// MR_TD occupies quote bytes 0xb8 through 0xe8.
const MR_TD_OFFSET = 0xb8;

function quoteWithMrTd(mrTd: Uint8Array): Uint8Array {
  const quote = buildQuote();
  quote.set(mrTd, MR_TD_OFFSET);
  return quote;
}

function quoteFor(events: readonly RuntimeEvent[]): Uint8Array {
  const quote = quoteWithMrTd(new Uint8Array(48).fill(0x7a));
  quote.set(replayRtmr3(events), 0x208);
  return quote;
}

describe('TDX pinning extraction', () => {
  it('returns the MR_TD the quote attests to', () => {
    const result = verifyAttestation(tdxAttestation(quoteWithMrTd(new Uint8Array(48).fill(0x7a))));
    expect(platformMeasurement(result)).toEqual(new Uint8Array(48).fill(0x7a));
  });

  it('reports no compose hash when the deployment recorded none', () => {
    expect(pinnedComposeHash(verifyAttestation(tdxAttestation()))).toBeNull();
  });

  it('reads the compose hash from the events replayed into RTMR-3', () => {
    const composeHash = new Uint8Array(32).fill(0x3c);
    const events = [...runtimeEvents, { event: 'compose-hash', payload: composeHash, version: 1 }] as RuntimeEvent[];
    const quote = quoteFor(events);
    const result = verifyAttestation(tdxAttestation(quote, tdxEventsFor(events), events));
    expect(pinnedComposeHash(result)).toEqual(composeHash);
  });
});

// Pinning Intel roots turns "we did not look" into "this quote must verify", so
// a deployment that has the collateral cannot silently fall back to replay-only.
describe('TDX DCAP wiring', () => {
  const trustedIntelRoots = [fixture('intel-sgx-root-ca.pem')];

  it('rejects a quote that does not verify once Intel roots are pinned', () => {
    expectErrorCode(
      () => verifyAttestation(tdxAttestation(), { trustedIntelRoots }),
      'MALFORMED_QUOTE',
    );
  });

  it('keeps the replay-only path when no Intel roots are pinned', () => {
    expect(verifyAttestation(tdxAttestation(), { trustedIntelRoots: [] }).quoteSignatureVerified).toBe(false);
  });
});

describe('TDX quote header', () => {
  // The header packs three separate numbers in its first eight bytes; a verifier
  // needs each one on its own to reject the wrong quote kind.
  function quoteWithHeader(version: number, attestationKeyType: number, teeType: number): Uint8Array {
    const quote = buildQuote();
    const view = new DataView(quote.buffer, quote.byteOffset, quote.byteLength);
    view.setUint16(0x00, version, true);
    view.setUint16(0x02, attestationKeyType, true);
    view.setUint32(0x04, teeType, true);
    return quote;
  }

  it('reads version, attestation key type and TEE type as separate fields', () => {
    const parsed = parseTdxQuote(quoteWithHeader(4, 2, 0x81));
    expect(parsed.version).toBe(4);
    expect(parsed.attestationKeyType).toBe(2);
    expect(parsed.teeType).toBe(0x81);
  });
});
