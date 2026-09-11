import { describe, expect, it } from 'vitest';
import { reportDataBinds } from '../src/index.js';

const DIGEST = new Uint8Array(32).fill(0xab);

function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function padded(value: Uint8Array, total: number, atEnd: boolean): Uint8Array {
  const out = new Uint8Array(total);
  out.set(value, atEnd ? total - value.length : 0);
  return out;
}

// The platform field is 64 bytes and the guest agent's padding convention is not part of the
// documented interface, so both placements are accepted and anything else is not. The rule lives
// here because the gateway that asks for evidence and the client that checks it must agree, and
// a client that disagrees fails every real deployment while agreeing with every test.
describe('report data binding', () => {
  it('accepts a shorter request digest right-padded with zeros', () => {
    expect(reportDataBinds(padded(DIGEST, 64, false), DIGEST)).toBe(true);
  });

  it('accepts a shorter request digest left-padded with zeros', () => {
    expect(reportDataBinds(padded(DIGEST, 64, true), DIGEST)).toBe(true);
  });

  it('accepts a full-width value that needs no padding', () => {
    const full = padded(DIGEST, 64, false);
    expect(reportDataBinds(full, full)).toBe(true);
    expect(reportDataBinds(utf8('attest-test-fixture-2026'), utf8('attest-test-fixture-2026'))).toBe(true);
  });

  it('rejects padding that is not zeros', () => {
    const field = padded(DIGEST, 64, false);
    field[40] = 0x01;
    expect(reportDataBinds(field, DIGEST)).toBe(false);
  });

  it('rejects a digest that is not at either end of the field', () => {
    const shifted = new Uint8Array([0x00, ...DIGEST, ...new Uint8Array(31)]);
    expect(shifted.length).toBe(64);
    expect(reportDataBinds(shifted, DIGEST)).toBe(false);
  });

  it('rejects a request longer than the quoted field', () => {
    expect(reportDataBinds(DIGEST.subarray(0, 16), DIGEST)).toBe(false);
  });

  it('rejects an empty request rather than binding it to any field', () => {
    // A zero-length value is a prefix of everything, which would turn a missing
    // expectation into a pass.
    expect(reportDataBinds(padded(DIGEST, 64, false), new Uint8Array(0))).toBe(false);
  });
});
