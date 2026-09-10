import { readFileSync } from 'node:fs';
import { expect } from 'vitest';
import { sha384 } from '@noble/hashes/sha2.js';
import { AttestationError, runtimeEventPreimage } from '../src/index.js';
import { decodeBase64 } from '../src/der.js';
import type { EventLogVersion, RuntimeEvent, TdxEvent } from '../src/index.js';

export function fixture(name: string): Uint8Array {
  return new Uint8Array(readFileSync(new URL(`./fixtures/${name}`, import.meta.url)));
}

export function expectErrorCode(fn: () => unknown, code: string): void {
  try {
    fn();
  } catch (e) {
    expect((e as AttestationError).code).toBe(code);
    return;
  }
  throw new Error(`expected AttestationError with code ${code}, but no error was thrown`);
}

// Extracts the DER bytes from a single-certificate PEM blob.
export function pemToDer(pem: Uint8Array): Uint8Array {
  const text = new TextDecoder('latin1').decode(pem);
  const match = /-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]+?)-----END CERTIFICATE-----/.exec(text);
  if (match === null) {
    throw new Error('fixture is not a PEM certificate');
  }
  return decodeBase64((match[1] as string).replace(/\s/g, ''));
}

// A test-side SCALE (Parity codec) writer, written independently of the
// ScaleReader so round-trip tests exercise both sides.
export class ScaleWriter {
  private readonly bytes: number[] = [];

  finish(): Uint8Array {
    return new Uint8Array(this.bytes);
  }

  byte(value: number): this {
    this.bytes.push(value);
    return this;
  }

  u32le(value: number): this {
    this.bytes.push(value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff);
    return this;
  }

  compact(value: number): this {
    if (value < 0x40) {
      this.bytes.push((value << 2) | 0x00);
    } else if (value < 0x4000) {
      const v = ((value << 2) | 0x01) & 0xffff;
      this.bytes.push(v & 0xff, (v >>> 8) & 0xff);
    } else {
      const v = ((value << 2) | 0x02) >>> 0;
      this.bytes.push(v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff);
    }
    return this;
  }

  fixed(value: Uint8Array): this {
    for (const b of value) {
      this.bytes.push(b);
    }
    return this;
  }

  vec(value: Uint8Array): this {
    return this.compact(value.length).fixed(value);
  }

  string(value: string): this {
    return this.vec(new TextEncoder().encode(value));
  }
}

export interface SnpV0Fields {
  report: Uint8Array;
  certChain: readonly Uint8Array[];
  mrConfig: string;
  runtimeEvents: readonly RuntimeEvent[];
  reportData: Uint8Array;
  config: string;
}

export function encodeV0Snp(fields: SnpV0Fields): Uint8Array {
  const w = new ScaleWriter();
  w.byte(0x00).byte(3);
  w.vec(fields.report);
  w.compact(fields.certChain.length);
  for (const cert of fields.certChain) {
    w.vec(cert);
  }
  w.string(fields.mrConfig);
  w.compact(fields.runtimeEvents.length);
  for (const event of fields.runtimeEvents) {
    w.string(event.event).vec(event.payload);
  }
  w.fixed(fields.reportData);
  w.string(fields.config);
  return w.finish();
}

export interface TdxV0Fields {
  quote: Uint8Array;
  eventLog: readonly TdxEvent[];
  runtimeEvents: readonly RuntimeEvent[];
  reportData: Uint8Array;
  config: string;
}

export function encodeV0Tdx(fields: TdxV0Fields): Uint8Array {
  const w = new ScaleWriter();
  w.byte(0x00).byte(0);
  w.vec(fields.quote);
  w.compact(fields.eventLog.length);
  for (const event of fields.eventLog) {
    w.u32le(event.imr)
      .u32le(event.eventType)
      .vec(event.digest)
      .string(event.event)
      .vec(event.eventPayload);
  }
  w.compact(fields.runtimeEvents.length);
  for (const event of fields.runtimeEvents) {
    w.string(event.event).vec(event.payload);
  }
  w.fixed(fields.reportData);
  w.string(fields.config);
  return w.finish();
}

// A test-side msgpack writer for V1 envelopes, again independent of the reader.
export class MsgpackWriter {
  private readonly bytes: number[] = [];

  finish(): Uint8Array {
    return new Uint8Array(this.bytes);
  }

  private push(value: Uint8Array): void {
    for (const b of value) {
      this.bytes.push(b);
    }
  }

  map(size: number): this {
    if (size <= 15) {
      this.bytes.push(0x80 | size);
    } else {
      this.bytes.push(0xde, (size >> 8) & 0xff, size & 0xff);
    }
    return this;
  }

  array(size: number): this {
    if (size <= 15) {
      this.bytes.push(0x90 | size);
    } else {
      this.bytes.push(0xdc, (size >> 8) & 0xff, size & 0xff);
    }
    return this;
  }

  uint(value: number): this {
    if (value <= 0x7f) {
      this.bytes.push(value);
    } else if (value <= 0xff) {
      this.bytes.push(0xcc, value);
    } else {
      this.bytes.push(0xcd, (value >> 8) & 0xff, value & 0xff);
    }
    return this;
  }

  str(value: string): this {
    const bytes = new TextEncoder().encode(value);
    if (bytes.length <= 31) {
      this.bytes.push(0xa0 | bytes.length);
    } else if (bytes.length <= 0xff) {
      this.bytes.push(0xd9, bytes.length);
    } else {
      this.bytes.push(0xda, (bytes.length >> 8) & 0xff, bytes.length & 0xff);
    }
    this.push(bytes);
    return this;
  }

  bin(value: Uint8Array): this {
    if (value.length <= 0xff) {
      this.bytes.push(0xc4, value.length);
    } else {
      this.bytes.push(0xc5, (value.length >> 8) & 0xff, value.length & 0xff);
    }
    return this.push(value), this;
  }
}

export function encodeV1Snp(fields: SnpV0Fields): Uint8Array {
  const w = new MsgpackWriter();
  w.map(3);
  w.str('version').uint(1);
  w.str('platform');
  w.map(2);
  w.str('kind').str('sev-snp');
  w.str('data');
  w.map(3);
  w.str('report').bin(fields.report);
  w.str('cert_chain').array(fields.certChain.length);
  for (const cert of fields.certChain) {
    w.bin(cert);
  }
  w.str('mr_config').str(fields.mrConfig);
  w.str('stack');
  w.map(2);
  w.str('kind').str('dstack');
  w.str('data');
  w.map(3);
  w.str('report_data').bin(fields.reportData);
  w.str('runtime_events').array(fields.runtimeEvents.length);
  for (const event of fields.runtimeEvents) {
    w.map(3);
    w.str('event').str(event.event);
    w.str('payload').bin(event.payload);
    w.str('version').uint(event.version);
  }
  w.str('config').str(fields.config);
  return w.finish();
}

// Builds the TDX event-log entries that mirror a list of stack runtime events
// (imr 3, dstack runtime-event type, digest of the event).
export function tdxEventsFor(events: readonly RuntimeEvent[], version: EventLogVersion = 1): TdxEvent[] {
  return events.map((event) => ({
    imr: 3,
    eventType: 0x08000001,
    digest: sha384(runtimeEventPreimage(event)),
    event: event.event,
    eventPayload: event.payload,
    version,
    preimage: null,
  }));
}
