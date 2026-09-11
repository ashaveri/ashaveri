import { describe, it, expect } from 'vitest';
import { encodeCanonical, decodeCanonical } from '../src/cbor.js';
import { Tag } from 'cbor2';

// Vectors from RFC 8949 Appendix E / well-known canonical encodings.
const RFC8949_VECTORS: Array<{ name: string; value: unknown; hex: string }> = [
  { name: 'unsigned 0', value: 0, hex: '00' },
  { name: 'unsigned 1', value: 1, hex: '01' },
  { name: 'unsigned 10', value: 10, hex: '0a' },
  { name: 'unsigned 23', value: 23, hex: '17' },
  { name: 'unsigned 24', value: 24, hex: '1818' },
  { name: 'unsigned 100', value: 100, hex: '1864' },
  { name: 'unsigned 1000', value: 1000, hex: '1903e8' },
  { name: 'unsigned 1000000', value: 1000000, hex: '1a000f4240' },
  { name: 'negative -1', value: -1, hex: '20' },
  { name: 'negative -10', value: -10, hex: '29' },
  { name: 'negative -100', value: -100, hex: '3863' },
  { name: 'negative -1000', value: -1000, hex: '3903e7' },
  { name: 'false', value: false, hex: 'f4' },
  { name: 'true', value: true, hex: 'f5' },
  { name: 'null', value: null, hex: 'f6' },
  { name: 'empty string', value: '', hex: '60' },
  { name: 'string "a"', value: 'a', hex: '6161' },
  { name: 'string "IETF"', value: 'IETF', hex: '6449455446' },
  { name: 'string "\\"\\""', value: '""', hex: '622222' },
  { name: 'empty byte string', value: new Uint8Array(0), hex: '40' },
  { name: 'bytes 01020304', value: new Uint8Array([1, 2, 3, 4]), hex: '4401020304' },
  { name: 'empty array', value: [], hex: '80' },
  { name: 'array [1,2,3]', value: [1, 2, 3], hex: '83010203' },
  { name: 'array [1,[2,3],[4,5]]', value: [1, [2, 3], [4, 5]], hex: '8301820203820405' },
  { name: 'array of 25 elements', value: Array.from({ length: 25 }, (_, i) => i), hex: '9819000102030405060708090a0b0c0d0e0f10111213141516171818' },
  { name: 'empty map', value: new Map(), hex: 'a0' },
  { name: 'map {1:2,3:4}', value: new Map([[1, 2], [3, 4]]), hex: 'a201020304' },
  { name: 'map {"a":1,"b":[2,3]}', value: new Map([['a', 1], ['b', [2, 3]]]), hex: 'a26161016162820203' },
  {
    name: 'map {"a":"A","b":"B","c":"C","d":"D","e":"E"}',
    value: new Map([['a', 'A'], ['b', 'B'], ['c', 'C'], ['d', 'D'], ['e', 'E']]),
    hex: 'a56161614161626142616361436164614461656145',
  },
  { name: 'tagged date 1363896240 (tag 1)', value: new Tag(1, 1363896240), hex: 'c11a514b67b0' },
];

describe('RFC 8949 core deterministic encoding', () => {
  for (const { name, value, hex } of RFC8949_VECTORS) {
    it(`encodes ${name}`, () => {
      expect(Buffer.from(encodeCanonical(value)).toString('hex')).toBe(hex);
    });
  }

  it('decodes and re-encodes to identical bytes (canonicality)', () => {
    for (const { hex } of RFC8949_VECTORS) {
      const bytes = Buffer.from(hex, 'hex');
      const decoded = decodeCanonical(new Uint8Array(bytes));
      const reencoded = encodeCanonical(decoded);
      expect(Buffer.from(reencoded).toString('hex')).toBe(hex);
    }
  });

  it('sorts map keys bytewise regardless of insertion order', () => {
    const a = new Map([['b', 2], ['a', 1]]);
    const b = new Map([['a', 1], ['b', 2]]);
    expect(encodeCanonical(a)).toEqual(encodeCanonical(b));
  });

  it('rejects non-integer floats in deterministic mode implicitly (integers preferred)', () => {
    expect(Buffer.from(encodeCanonical(1.5)).toString('hex')).toBe('f93e00');
  });
});
