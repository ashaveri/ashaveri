import { describe, expect, it } from 'vitest';
import { fromBase64, fromBase64Url } from '../src/bytes.js';

/**
 * Both decoders are handed strings out of a fetched document, so the shape of a rejected tail is
 * attacker-chosen and the cost of rejecting it is not. The first case is the one a regex would lose.
 */
describe('a decoder reading an untrusted tail', () => {
  it('refuses a long run of padding that ends unmatched', () => {
    const tail = `AAAA${'='.repeat(40_000)}X`;
    expect(fromBase64Url(tail)).toBeNull();
    expect(fromBase64(tail)).toBeNull();
  });

  it('reads what it declares, padding and all', () => {
    expect(Array.from(fromBase64Url('YWJjZA==') as Uint8Array)).toEqual([97, 98, 99, 100]);
    expect(Array.from(fromBase64('YWJjZA==') as Uint8Array)).toEqual([97, 98, 99, 100]);
  });

  it('refuses a length no base64 encoding can have', () => {
    expect(fromBase64Url('A')).toBeNull();
    expect(fromBase64('A')).toBeNull();
  });
});
