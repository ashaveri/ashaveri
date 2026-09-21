import { describe, it, expect } from 'vitest';
import { encodeCanonical, decodeCanonical, decodeClosedDocument } from '../src/cbor.js';
import { ReceiptError } from '../src/errors.js';
import { Tag, encode, defaultEncodeOptions, encodedNumber } from 'cbor2';
import { sortCoreDeterministic } from 'cbor2/sorts';

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
  { name: 'map {"a":1,"b":[2,3]}', value: new Map<string, number | number[]>([['a', 1], ['b', [2, 3]]]), hex: 'a26161016162820203' },
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

/**
 * Bytes with every number written as the major type it was given: the codec's own canonical writer
 * cannot produce these, because it turns any whole number into an integer, which is what the format
 * requires of it. A float reaching a reader at all is therefore something another implementation
 * wrote, and these are the bytes it would write.
 */
function encodeKeepingTypes(value: unknown): Uint8Array {
  return new Uint8Array(encode(value, { ...defaultEncodeOptions, sortKeys: sortCoreDeterministic }));
}

function codeOf(read: () => unknown): string {
  try {
    read();
  } catch (err) {
    return err instanceof ReceiptError ? err.code : `foreign:${String(err)}`;
  }
  return 'accepted';
}

describe('the two documents the format declares member by member', () => {
  // One rule, three shapes: a float as a value, a float nested one map down, and a float as a key.
  // The third is the one no later check could reach, because a `Map` compares keys by identity and
  // the float 1.0 is the same key as the integer 1 by the time anything looks.
  const floats: Array<[string, unknown]> = [
    ['half-precision', encodedNumber(2, 'f16')],
    ['single-precision', encodedNumber(2, 'f32')],
    ['double-precision', encodedNumber(2, 'f64')],
    ['negative zero', encodedNumber(-0, 'f16')],
  ];

  for (const [name, floated] of floats) {
    it(`refuses a ${name} number in a declared document, wherever it sits`, () => {
      const atValue = new Map([['iat', floated]]);
      const nested = new Map([['tok', new Map([['p', floated]])]]);
      const asKey = new Map<unknown, unknown>([[1, -8], [floated, 'x']]);
      for (const [shape, bytes] of [
        ['a value', atValue],
        ['one map down', nested],
        ['a key beside the integer it imitates', asKey],
      ] as const) {
        expect(codeOf(() => decodeClosedDocument(encodeKeepingTypes(bytes), 'BAD_PAYLOAD')), `${name} as ${shape}`).toBe('BAD_PAYLOAD');
      }
    });
  }

  it('reads an integer, a text string and a byte string in the same positions', () => {
    // The other half of every case above: a guard that also refused this document would be a
    // regression dressed as a rule, and these are the kinds the CDDL actually writes.
    const counts = new Map([['p', 128], ['c', 64]]);
    const document = new Map<unknown, unknown>([
      ['iat', 1_772_000_000],
      ['mdl', 'mock-model-1'],
      ['nce', new Uint8Array(16).fill(7)],
      ['tok', counts],
    ]);
    const read = decodeClosedDocument(encodeKeepingTypes(document), 'BAD_PAYLOAD');
    expect(read).toBeInstanceOf(Map);
    const map = read as Map<string, unknown>;
    expect(map.get('iat')).toBe(1_772_000_000);
    expect(map.get('mdl')).toBe('mock-model-1');
    expect((map.get('nce') as Uint8Array).length).toBe(16);
    expect((map.get('tok') as Map<string, number>).get('p')).toBe(128);
    // Encoded by the package's own writer as well, which is the path a real receipt takes.
    expect(codeOf(() => decodeClosedDocument(encodeCanonical(document), 'BAD_PAYLOAD'))).toBe('accepted');
  });

  it('leaves the envelope it does not close free to carry one', () => {
    // `{ * any => any }` in the CDDL is the map the format declines to describe, and it sits outside
    // the signature. Refusing a float there would be a rule this format does not state, so the
    // envelope reader takes the same bytes the declared-document reader refuses.
    const open = new Map<unknown, unknown>([[encodedNumber(1, 'f16'), encodedNumber(2.5, 'f64')]]);
    const bytes = encodeKeepingTypes(open);
    expect(codeOf(() => decodeClosedDocument(bytes, 'BAD_PAYLOAD'))).toBe('BAD_PAYLOAD');
    const read = decodeCanonical(bytes) as Map<unknown, unknown>;
    expect(read.get(1)).toBe(2.5);
  });
});
