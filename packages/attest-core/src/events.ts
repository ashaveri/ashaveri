import { sha384 } from '@noble/hashes/sha2.js';
import { fail } from './errors.js';
import { DSTACK_RUNTIME_EVENT_TYPE } from './types.js';
import type { RuntimeEvent, TdxEvent } from './types.js';

const RUNTIME_EVENT_TYPE_DECIMAL = 134217729;

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const part of parts) total += part.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function toHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) {
    out += b.toString(16).padStart(2, '0');
  }
  return out;
}

function isHex(value: string): boolean {
  return value.length % 2 === 0 && /^[0-9a-fA-F]*$/.test(value);
}

export function fromHex(value: string): Uint8Array {
  if (!isHex(value)) {
    throw new Error('invalid hex string');
  }
  const out = new Uint8Array(value.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function jcsEscape(value: string): string {
  let out = '"';
  for (let i = 0; i < value.length; i++) {
    const code = value.codePointAt(i) as number;
    if (code >= 0x10000) {
      out += String.fromCodePoint(code);
      i += String.fromCodePoint(code).length - 1;
      continue;
    }
    out += jcsEscapeChar(code);
  }
  return out + '"';
}

function jcsEscapeChar(code: number): string {
  switch (code) {
    case 0x08:
      return '\\b';
    case 0x09:
      return '\\t';
    case 0x0a:
      return '\\n';
    case 0x0c:
      return '\\f';
    case 0x0d:
      return '\\r';
    case 0x22:
      return '\\"';
    case 0x5c:
      return '\\\\';
  }
  if (code < 0x20 || (code >= 0xd800 && code <= 0xdfff)) {
    return '\\u' + code.toString(16).padStart(4, '0');
  }
  return String.fromCharCode(code);
}

// JCS (RFC 8785) canonical JSON for a dstack V2 runtime event.
// Keys are emitted in UTF-16 code unit order (name < payload < type) and the
// payload is lowercase hex, matching dstack's serde_jcs output byte for byte.
export function canonicalEventJsonV2(event: string, payload: Uint8Array): string {
  return `{${jcsEscape('name')}:${jcsEscape(event)},${jcsEscape('payload')}:"${toHex(payload)}",${jcsEscape('type')}:${RUNTIME_EVENT_TYPE_DECIMAL}}`;
}

export function runtimeEventPreimage(event: RuntimeEvent): Uint8Array {
  if (event.version === 1) {
    const prefix = new Uint8Array(5);
    new DataView(prefix.buffer).setUint32(0, DSTACK_RUNTIME_EVENT_TYPE, true);
    prefix[4] = 0x3a;
    return concatBytes(prefix, new TextEncoder().encode(event.event), new Uint8Array([0x3a]), event.payload);
  }
  return new TextEncoder().encode(canonicalEventJsonV2(event.event, event.payload));
}

export function runtimeEventDigest(event: RuntimeEvent): Uint8Array {
  return sha384(runtimeEventPreimage(event));
}

export function isRuntimeEvent(event: TdxEvent): boolean {
  return event.eventType === DSTACK_RUNTIME_EVENT_TYPE;
}

export function tdxEventDigest(event: TdxEvent): Uint8Array {
  if (isRuntimeEvent(event)) {
    const runtimeEvent: RuntimeEvent = {
      event: event.event,
      payload: event.eventPayload,
      version: event.version,
    };
    return runtimeEventDigest(runtimeEvent);
  }
  return event.digest;
}

export function replayRtmr3(runtimeEvents: readonly RuntimeEvent[]): Uint8Array {
  let mr = new Uint8Array(48);
  for (const event of runtimeEvents) {
    mr = sha384(concatBytes(mr, runtimeEventDigest(event)));
  }
  return mr;
}

// Validate that every runtime event's stored digest matches the recomputed
// digest, that V2 events carry a canonical preimage hashing to that digest,
// and that RTMR-3 events in the platform event log agree with the stack
// runtime events.
export function validateEventLog(eventLog: readonly TdxEvent[], runtimeEvents: readonly RuntimeEvent[]): void {
  const imr3Events: TdxEvent[] = [];
  for (let i = 0; i < eventLog.length; i++) {
    const event = eventLog[i] as TdxEvent;
    if (event.imr > 3) {
      fail('BAD_EVENT_DIGEST', `event ${i} targets IMR ${event.imr}`);
    }
    if (isRuntimeEvent(event)) {
      const computed = tdxEventDigest(event);
      if (!equalBytes(computed, event.digest)) {
        fail('BAD_EVENT_DIGEST', `event ${i} (${event.event}) digest does not match its content`);
      }
      if (event.version === 2) {
        validateV2Preimage(event, i);
      }
    }
    if (event.imr === 3) {
      imr3Events.push(event);
    }
  }
  if (imr3Events.length !== runtimeEvents.length) {
    fail('EVENT_LOG_MISMATCH', `event log carries ${imr3Events.length} IMR-3 events, stack carries ${runtimeEvents.length} runtime events`);
  }
  for (let i = 0; i < imr3Events.length; i++) {
    const tdx = imr3Events[i] as TdxEvent;
    const runtime = runtimeEvents[i] as RuntimeEvent;
    if (tdx.event !== runtime.event || tdx.eventType !== DSTACK_RUNTIME_EVENT_TYPE || !equalBytes(tdx.eventPayload, runtime.payload)) {
      fail('EVENT_LOG_MISMATCH', `IMR-3 event ${i} (${tdx.event}) disagrees with stack runtime event ${i} (${runtime.event})`);
    }
    if (tdx.version !== runtime.version) {
      fail('EVENT_LOG_MISMATCH', `IMR-3 event ${i} (${tdx.event}) version ${tdx.version} disagrees with stack version ${runtime.version}`);
    }
  }
}

function validateV2Preimage(event: TdxEvent, index: number): void {
  if (event.preimage === null) {
    fail('BAD_EVENT_PREIMAGE', `V2 runtime event ${index} (${event.event}) is missing its digest preimage`);
  }
  if (!isHex(event.preimage)) {
    fail('BAD_EVENT_PREIMAGE', `V2 runtime event ${index} (${event.event}) has a malformed digest preimage`);
  }
  const supplied = fromHex(event.preimage);
  const hashed = sha384(supplied);
  if (!equalBytes(hashed, event.digest)) {
    fail('BAD_EVENT_PREIMAGE', `V2 runtime event ${index} (${event.event}) digest does not match its preimage`);
  }
  const runtimeEvent: RuntimeEvent = {
    event: event.event,
    payload: event.eventPayload,
    version: 2,
  };
  const canonical = runtimeEventPreimage(runtimeEvent);
  if (!equalBytes(supplied, canonical)) {
    fail('BAD_EVENT_PREIMAGE', `V2 runtime event ${index} (${event.event}) preimage is not the canonical event representation`);
  }
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}
