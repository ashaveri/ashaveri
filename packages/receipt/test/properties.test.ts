import { afterAll, describe, expect, it } from 'vitest';
import fc from 'fast-check';
import {
  decodeReceipt,
  encodePayload,
  equalBytes,
  issueReceipt,
  MEASUREMENT_BYTES,
  parsePopAuthorization,
  POP_NONCE_BYTES,
  ReceiptError,
  sha256Hex,
  signPopAuthorization,
  signingKeyFromSeed,
  verifyPopSignature,
  type PopFields,
  type ReceiptPayload,
  type TeeKind,
} from '../src/index.js';
import { check, fingerprint, hostile, hostileText, outcome, RUNS, SEED, type Outcome } from './generators.js';

const isOwnError = (err: unknown): boolean => err instanceof ReceiptError;

// A fixed seed rather than a fresh key, so the corpus these properties mutate is the same bytes on
// every run and one command line replays a red one.
const key = signingKeyFromSeed(new Uint8Array(32).fill(0x11));

const payload: ReceiptPayload = {
  v: 1,
  iss: 'dpl-property-test',
  ins: 'cvm-property-test',
  iat: 1_772_000_000,
  nce: new Uint8Array(16).fill(0xab),
  req: new Uint8Array(32).fill(1),
  res: new Uint8Array(32).fill(2),
  mdl: 'meta-llama/Llama-3.1-8B-Instruct',
  wts: new Uint8Array(32).fill(3),
  meas: { tee: 'software', m: new Uint8Array(32).fill(4) },
  att: { d: new Uint8Array(32).fill(5), ts: 1_772_000_000 - 60, url: 'https://inference.ashaveri.test/v1/attestation' },
  epk: 3,
  tok: { p: 128, c: 64 },
};

const signed = issueReceipt(payload, key);

const fields: PopFields = {
  ts: 1_772_000_000,
  nonce: new Uint8Array(POP_NONCE_BYTES).fill(0xcd),
  method: 'post',
  target: '/v1/chat/completions?user=42',
  bodyDigestHex: sha256Hex(new TextEncoder().encode('{"model":"m"}')),
};
const header = signPopAuthorization(fields, 'cred-property-test', key.privateKey);

/** The longest byte string anywhere inside a decoded value, which is what a parser can invent. */
function longestByteField(value: unknown): number {
  if (value instanceof Uint8Array) {
    return value.length;
  }
  if (Array.isArray(value)) {
    return value.reduce((max, item) => Math.max(max, longestByteField(item)), 0);
  }
  if (value !== null && typeof value === 'object') {
    return Object.values(value).reduce((max, item) => Math.max(max, longestByteField(item)), 0);
  }
  return 0;
}

/**
 * The shortest prefix the parser accepts, found by asking it rather than by restating a length from
 * the format. The check below compares it against the whole document, so a corpus that changed shape
 * cannot quietly make the truncation rule mean nothing.
 */
function acceptanceBoundary<T extends Uint8Array | string>(
  parse: (input: T) => unknown,
  source: T,
  prefix: (source: T, length: number) => T,
): number {
  for (let length = 0; length <= source.length; length += 1) {
    try {
      parse(prefix(source, length));
      return length;
    } catch (err) {
      if (!isOwnError(err)) {
        throw err;
      }
    }
  }
  return source.length + 1;
}

function sameOutcome(a: Outcome, b: Outcome): boolean {
  if (a.kind === 'value' && b.kind === 'value') {
    return a.shape === b.shape;
  }
  if (a.kind === 'error' && b.kind === 'error') {
    return a.code === b.code;
  }
  return a.kind === 'foreign' && b.kind === 'foreign' && a.name === b.name;
}

const receiptBoundary = acceptanceBoundary(decodeReceipt, signed, (source, length) => source.slice(0, length));
const headerBoundary = acceptanceBoundary(parsePopAuthorization, header, (source, length) => source.slice(0, length));

const TEE_KINDS = Object.keys(MEASUREMENT_BYTES) as TeeKind[];

const payloadArbitrary: fc.Arbitrary<ReceiptPayload> = fc
  .record({
    iss: fc.string({ minLength: 1, maxLength: 24 }),
    ins: fc.string({ minLength: 1, maxLength: 24 }),
    iat: fc.integer({ min: 0, max: 2_000_000_000 }),
    nce: fc.uint8Array({ minLength: 16, maxLength: 16 }),
    req: fc.uint8Array({ minLength: 32, maxLength: 32 }),
    res: fc.uint8Array({ minLength: 32, maxLength: 32 }),
    mdl: fc.string({ minLength: 1, maxLength: 40 }),
    wts: fc.uint8Array({ minLength: 32, maxLength: 32 }),
    meas: fc
      .constantFrom(...TEE_KINDS)
      .chain((tee) =>
        fc
          .uint8Array({ minLength: MEASUREMENT_BYTES[tee], maxLength: MEASUREMENT_BYTES[tee] })
          .map((m) => ({ tee, m })),
      ),
    att: fc.record({
      d: fc.uint8Array({ minLength: 32, maxLength: 32 }),
      ts: fc.integer({ min: 0, max: 2_000_000_000 }),
      url: fc.string({ minLength: 1, maxLength: 60 }),
    }),
    epk: fc.integer({ min: 0, max: 1_000_000 }),
    tok: fc.record({ p: fc.integer({ min: 0, max: 1_000_000 }), c: fc.integer({ min: 0, max: 1_000_000 }) }),
  })
  .map((each) => ({ v: 1 as const, ...each }));

const popFieldsArbitrary: fc.Arbitrary<PopFields> = fc.record({
  ts: fc.integer({ min: 0, max: 2_000_000_000 }),
  nonce: fc.uint8Array({ minLength: POP_NONCE_BYTES, maxLength: POP_NONCE_BYTES }),
  method: fc.string({ minLength: 1, maxLength: 8 }),
  target: fc.string({ minLength: 1, maxLength: 80 }),
  bodyDigestHex: fc
    .uint8Array({ minLength: 32, maxLength: 32 })
    .map((bytes) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')),
});

describe('receipt and PoP parsers, by property', () => {
  afterAll(() => {
    if (process.env['FC_SEED'] === undefined) {
      process.stdout.write(`property seeds for this run: ${String(SEED)} (runs per property: ${String(RUNS)})\n`);
    }
  });

  it('states each truncation rule against a boundary that is the whole document', () => {
    // Neither format has an optional tail, so a prefix is not a document. If a measured boundary
    // ever came in below the corpus length, the property that truncations are refused would be
    // asserting something other than what it says.
    expect(receiptBoundary).toBe(signed.length);
    expect(headerBoundary).toBe(header.length);
  });

  it('decodeReceipt: every input either returns a value or throws its own error', () => {
    check(hostile(signed), [signed, new Uint8Array(0)], (input) => {
      const result = outcome(decodeReceipt, input, isOwnError);
      return result.kind === 'error' || (result.kind === 'value' && result.shape !== 'undefined:undefined');
    });
  });

  it('decodeReceipt: the same bytes decide the same way twice, and are left alone', () => {
    // No twin of this case over the header parser, on purpose: a string cannot be written through,
    // so the same assertion there would agree with itself whatever the input was.
    check(hostile(signed), [signed], (input) => {
      const before = input.slice();
      const first = outcome(decodeReceipt, input, isOwnError);
      const second = outcome(decodeReceipt, before.slice(), isOwnError);
      const untouched = before.length === input.length && before.every((byte, index) => input[index] === byte);
      return untouched && sameOutcome(first, second);
    });
  });

  it('decodeReceipt: no prefix of a signed receipt decodes, and nothing is invented', () => {
    // Every length below the boundary, walked rather than sampled: a sample can miss the one prefix
    // that parses, and this is the claim a length field read from the input and believed fails.
    for (let length = 0; length < receiptBoundary; length += 1) {
      const result = outcome(decodeReceipt, signed.slice(0, length), isOwnError);
      expect(result.kind, `decodeReceipt accepted a ${String(length)}-byte prefix`).toBe('error');
    }
    check(hostile(signed), [signed], (input) => {
      const result = outcome(decodeReceipt, input, isOwnError);
      return result.kind !== 'value' || longestByteField(decodeReceipt(input)) <= input.length;
    });
  });

  it('parsePopAuthorization: every header either returns a value or throws its own error', () => {
    check(hostileText(header), [header, ''], (input) => {
      const result = outcome(parsePopAuthorization, input, isOwnError);
      return result.kind === 'error' || (result.kind === 'value' && result.shape !== 'undefined:undefined');
    });
  });

  it('parsePopAuthorization: no prefix of a signed header parses, and a value carries only given text', () => {
    // Walked rather than sampled, for the same reason as the receipt case above.
    for (let length = 0; length < headerBoundary; length += 1) {
      const result = outcome(parsePopAuthorization, header.slice(0, length), isOwnError);
      expect(result.kind, `parsePopAuthorization accepted a ${String(length)}-character prefix`).toBe('error');
    }
    check(hostileText(header), [header], (input) => {
      const result = outcome(parsePopAuthorization, input, isOwnError);
      if (result.kind !== 'value') {
        return true;
      }
      const parsed = parsePopAuthorization(input);
      // A signature is base64url text in the header, so a decoded one cannot be wider than 64 bytes,
      // and a credential cannot hold more characters than the header it was read out of.
      return parsed.signature.length === 64 && parsed.credential.length <= input.length;
    });
  });

  it('a decoded receipt re-encodes to the bytes that were signed', () => {
    check(payloadArbitrary, [payload], (generated) => {
      const issued = issueReceipt(generated, key);
      const decoded = decodeReceipt(issued);
      return (
        equalBytes(encodePayload(decoded.payload), encodePayload(generated)) &&
        fingerprint(decoded.payload) === fingerprint(generated)
      );
    });
    // The same claim for the corpus, spelled out: the bytes a signature covers are the bytes a
    // client gets back, so re-encoding a decoded payload reproduces what was checked.
    expect(equalBytes(encodePayload(decodeReceipt(signed).payload), encodePayload(payload))).toBe(true);
  });

  it('a PoP header verifies under the key that signed it, and not under a moved request', () => {
    check(popFieldsArbitrary, [fields], (generated) => {
      const signedHeader = signPopAuthorization(generated, 'cred-property-test', key.privateKey);
      const parsed = parsePopAuthorization(signedHeader);
      if (!verifyPopSignature(generated, parsed.signature, key.publicKey)) {
        return false;
      }
      // The same signature has to be refused once the request moves, or the header is a bearer
      // token rather than a proof of possession of one.
      const other: PopFields = { ...generated, target: `${generated.target}/moved` };
      // And refused when only the nonce changes: the nonce says which request this signature was
      // made for, and flipping one byte keeps the width legal while naming another request.
      const otherNonce: PopFields = {
        ...generated,
        nonce: Uint8Array.from(generated.nonce, (byte) => byte ^ 0x01),
      };
      return (
        !verifyPopSignature(other, parsed.signature, key.publicKey) &&
        !verifyPopSignature(otherNonce, parsed.signature, key.publicKey)
      );
    });
    // A signature that exists but was not made, so the refusal above is not a verifier that simply
    // answers false, and the header above is not a parser that never returns.
    expect(verifyPopSignature(fields, new Uint8Array(64), key.publicKey)).toBe(false);
    expect(() => parsePopAuthorization(header)).not.toThrow();
  });
});

/**
 * The characters `errors.ts` promises never to leave raw, restated here so a test can disagree
 * with the producer rather than borrow its pattern.
 */
const INVISIBLE = /[\p{Cc}\p{Cf}\u{2028}\u{2029}\u{e0000}-\u{e007f}]/u;

/** A header carrying `name` as a parameter this parser does not know. */
function popQuoting(name: string): string {
  return `Ashaveri-PoP credential=x, ts=1, sig=AA, ${name}=1`;
}

/** The same name with no `=` after it, which the parser quotes in a different sentence. */
function popUnnamed(name: string): string {
  return `Ashaveri-PoP credential=x, ts=1, sig=AA, ${name}`;
}

/** Accepted, or refused with a message that is one line of visible text. */
function staysOnOneLine(header: string): boolean {
  try {
    parsePopAuthorization(header);
    return true;
  } catch (err) {
    return err instanceof ReceiptError && !INVISIBLE.test(err.message);
  }
}

describe('a refusal that quotes a parameter name out of the header', () => {
  // A name is whatever precedes an `=`, trimmed at the ends only, and the two sentences that
  // refuse one quote it. Everything below is legal header text: a break a line-splitting log reader
  // honours, and the invisible formatting a terminal or an editor honours.
  const hostileName = fc.string({
    unit: fc.constantFrom(...['c', 'r', 'e', 'd', '=', ' ', '\n', '\r', '\v', '\u001c', '\u0085', '\u2028', '\u2029', '\u202e', '\0']),
    maxLength: 14,
  });

  it('leaves a name built from anything that can break a line inside one line', () => {
    const headers = fc.tuple(hostileName, fc.boolean()).map(([name, tailless]) => (tailless ? popUnnamed(name) : popQuoting(name)));
    check(headers, [popQuoting('a\nb'), popUnnamed('a\u2028b'), popQuoting('plain'), ''], staysOnOneLine);
  });

  it('holds once the rest of the header is hostile too', () => {
    const corpus = popQuoting('a\u2029b');
    check(hostileText(corpus), [corpus, ''], staysOnOneLine);
  });

  it('escapes the name it quoted, in both sentences that quote one', () => {
    for (const [header, quoted] of [
      [popQuoting('a\nb'), "unknown parameter 'a\\u000ab'"],
      [popUnnamed('a\rb'), "parameter 'a\\u000db' is not name=value"],
    ] as const) {
      try {
        parsePopAuthorization(header);
        throw new Error('expected a refusal');
      } catch (err) {
        expect(err).toBeInstanceOf(ReceiptError);
        const failure = err as ReceiptError;
        expect(failure.code).toBe('BAD_POP_HEADER');
        // Without these the properties above could pass on a parser that refuses a header before it
        // reads a name, since a sentence that never carried one has nothing to escape.
        expect(failure.message).toContain(quoted);
        expect(failure.message.split('\n')).toHaveLength(1);
      }
    }
  });
});
