import { describe, it, expect } from 'vitest';
import { encodeCanonical, decodeCanonical, decodeClosedDocument } from '../src/cbor.js';
import { ReceiptError } from '../src/errors.js';
import { Tag, encode, defaultEncodeOptions, encodedNumber } from 'cbor2';
import { generateSigningKey } from '../src/cose.js';
import { isSealedDeploymentManifest, sealDeploymentManifest, decodeSealedDeploymentManifest, verifySealedDeploymentManifest } from '../src/manifest-seal.js';
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

/** What the package's writer makes of a whole number that JavaScript holds as negative zero. */
function canonicalHex(value: unknown): string {
  return Buffer.from(encodeCanonical(value)).toString('hex');
}

describe('the canonical writer spells negative zero as the integer zero', () => {
  // The describe block below refuses every floating-point number inside the two documents the format
  // declares member by member, so while the writer emitted a float for this one value the package was
  // signing documents it would not read back. `Object.is(value, -0)` is the only test that tells that
  // value apart from the zero it prints as: `Number.isSafeInteger(-0)` holds and `-0 < 0` does not, so
  // no integrality or range check downstream could ever have caught it. The bytes are chosen in one
  // place, for every value at every depth, which is where the rule sits: see `encodeCanonical`.
  it('at every depth it reaches, in a value and in a key alike', () => {
    expect(canonicalHex(-0)).toBe('00');
    expect(canonicalHex(new Map([['iat', -0]]))).toBe('a16369617400');
    expect(canonicalHex(new Map([['tok', new Map([['p', -0]])]]))).toBe('a163746f6ba1617000');
    expect(canonicalHex([-0, 0])).toBe('820000');
    // The key position needs the key to be a composite: a `Map` takes a `-0` key and stores it as the
    // same key `0` would be, so a primitive negative zero never reaches the writer's key branch at all
    // and an assertion written that way would stand even with the rule removed. An array key does
    // reach it, and the map encodes keys through that same writer.
    expect(canonicalHex(new Map([[[-0, 1], 'v']]))).toBe('a18200016176');
    // And the rule is only about a value that has an integer spelling. A number that does not still
    // goes out as the float it is, because coercing it here would be the writer deciding a fact the
    // format never gave it: `1.5` above and `0.5` here both keep their major type.
    expect(canonicalHex(new Map([['iat', 0.5]]))).toBe('a163696174f93800');
  });

  it('writes the same bytes the same document writes with a plain zero', () => {
    // The pairing stated as one fact: negative zero has one canonical integer spelling and it is the
    // one `0` gets, so the two documents cannot be told apart by anything that reads them.
    expect(canonicalHex(new Map([['iat', -0]]))).toBe(canonicalHex(new Map([['iat', 0]])));
    expect(canonicalHex(new Map([[[-0, 1], 'v']]))).toBe(canonicalHex(new Map([[[0, 1], 'v']])));
    expect(canonicalHex(new Map([['tok', new Map([['p', -0]])]]))).toBe(canonicalHex(new Map([['tok', new Map([['p', 0]])]])));
  });

  it('leaves the reader of a declared document something it can read', () => {
    // The half that the writer alone does not prove: these bytes go through the same option the two
    // declared documents are read under, and come back as the integer zero rather than as a refusal.
    // The value is `0` and not `-0`, which is what a client comparing an `iat` against a window sees.
    const read = decodeClosedDocument(encodeCanonical(-0), 'BAD_PAYLOAD');
    expect(read).toBe(0);
    expect(Object.is(read, -0)).toBe(false);
    // And a document that carries the float anyway — because a stranger wrote it — is still refused.
    // The writer's rule is not the reader's rule loosened: these are the bytes `f9 80 00`, and the
    // reader of a declared document takes none of them.
    expect(codeOf(() => decodeClosedDocument(encodeKeepingTypes(encodedNumber(-0, 'f16')), 'BAD_PAYLOAD'))).toBe('BAD_PAYLOAD');
  });
});

/**
 * Bytes with every number written as the major type it was given: the codec's own canonical writer
 * cannot produce these, because it writes every whole number as an integer, negative zero included,
 * which is what the format requires of it. A float reaching a reader at all is therefore something
 * another implementation wrote, and these are the bytes it would write.
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

describe('encodeCanonical, on the byte strings a caller can actually hand it', () => {
  const hexOf = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
  const PLAIN = new Uint8Array([1, 2, 3]);
  const PLAIN_HEX = hexOf(encodeCanonical(PLAIN));

  it('writes a Buffer as the byte string it holds, wherever it sits', () => {
    // `Buffer` passes for `Uint8Array` to the type checker and to every `readFile` in the estate, and
    // the writer used to take its generic object path on it: a two-entry map holding `type` and a
    // `data` array of numbers. Same signature, different document, and the reader of the document the
    // signature covers is the thing that would refuse it.
    const cases: Array<[string, unknown, unknown]> = [
      ['on its own', PLAIN, Buffer.from(PLAIN)],
      ['inside an array', [PLAIN], [Buffer.from(PLAIN)]],
      ['inside a map value', new Map([['k', PLAIN]]), new Map([['k', Buffer.from(PLAIN)]])],
      ['inside a map key', new Map([[PLAIN, 1]]), new Map([[Buffer.from(PLAIN), 1]])],
      ['inside an object', { d: PLAIN }, { d: Buffer.from(PLAIN) }],
      ['inside a tagged envelope', new Tag(18, [PLAIN]), new Tag(18, [Buffer.from(PLAIN)])],
      ['nested two levels down', new Map([['t', [PLAIN]]]), new Map([['t', [Buffer.from(PLAIN)]]])],
    ];
    for (const [where, plain, buffered] of cases) {
      expect(hexOf(encodeCanonical(buffered)), `a Buffer ${where} went out as something else`).toBe(
        hexOf(encodeCanonical(plain)),
      );
    }
    expect(PLAIN_HEX).toBe('43010203');
  });

  it('shows a Buffer a view of, and not the pool behind it', () => {
    const pool = Buffer.from([9, 9, 1, 2, 3, 9]);
    const view = pool.subarray(2, 5);
    expect(view.constructor.name, 'the case is only real if a view is still a Buffer').toBe('Buffer');
    expect(hexOf(encodeCanonical(view))).toBe('43010203');
  });

  it('leaves a structure that already holds plain bytes exactly as it was written', () => {
    // The writer is on the path of every signature made, so the fix may cost a copy of anything that
    // needs none. A deep clone of one document must encode to the same bytes as the original.
    const document = new Map<unknown, unknown>([
      ['iat', 1_772_000_000],
      ['nce', new Uint8Array(16).fill(7)],
      ['tok', new Map([['p', 128], ['c', 64]])],
      ['items', [new Uint8Array([0]), new Uint8Array([254])]],
    ]);
    const clone: Map<unknown, unknown> = new Map(
      Array.from(document, ([key, value]) => [
        key,
        Array.isArray(value) ? value.map((element) => element) : value instanceof Map ? new Map(value) : value,
      ]),
    );
    expect(hexOf(encodeCanonical(clone))).toBe(hexOf(encodeCanonical(document)));
    expect(hexOf(encodeCanonical(PLAIN))).toBe(PLAIN_HEX);
  });

  it('seals a manifest read off a disk and lets its own reader verify it', () => {
    // The reported failure was this path exactly: bytes from a file, sealed, and the envelope refused
    // as not a COSE_Sign1 because the payload inside it had become an array of numbers.
    const key = generateSigningKey();
    const text = JSON.stringify({ v: 1, iss: 'dpl-9f2a41c3' });
    const sealed = sealDeploymentManifest(Buffer.from(text, 'utf8'), key);
    expect(isSealedDeploymentManifest(sealed)).toBe(true);
    const read = decodeSealedDeploymentManifest(sealed);
    expect(new TextDecoder().decode(read.payloadBytes)).toBe(text);
    expect(() => verifySealedDeploymentManifest(sealed, key.publicKey)).not.toThrow();
  });
});
