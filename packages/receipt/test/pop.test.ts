import { describe, expect, it } from 'vitest';
import { ed25519, ED25519_TORSION_SUBGROUP } from '@noble/curves/ed25519';
import { fromBase64Url, toBase64Url } from '../src/b64.js';
import {
  EMPTY_BODY_SHA256_HEX,
  POP_AUTH_PREFIX,
  POP_NONCE_BYTES,
  POP_SCHEME,
  POP_TIMESTAMP_TOLERANCE_SECONDS,
  encodePopAuthorization,
  parsePopAuthorization,
  popSigningString,
  sha256Hex,
  signPopAuthorization,
  verifyPopSignature,
  type PopFields,
} from '../src/pop.js';
import { ReceiptError } from '../src/errors.js';

describe('base64url without browser globals', () => {
  const cases: ReadonlyArray<readonly [number[], string]> = [
    [[], ''],
    [[0x66], 'Zg'],
    [[0x66, 0x6f], 'Zm8'],
    [[0x66, 0x6f, 0x6f], 'Zm9v'],
    [[0x66, 0x6f, 0x6f, 0x00], 'Zm9vAA'],
    // `_` is an ordinary alphabet character, not padding: this is a legal encoding of three bytes.
    [[0x66, 0x6f, 0x7f], 'Zm9_'],
    [[0xfb, 0xff, 0xbf], '-_-_'],
  ];

  it.each(cases)('encodes %j as a stable alphabet string', (bytes, expected) => {
    const encoded = toBase64Url(Uint8Array.from(bytes));
    expect(encoded).toBe(expected);
    expect(encoded).not.toMatch(/[+/=]/u);
    expect(Array.from(fromBase64Url(encoded))).toEqual(bytes);
  });

  it('rejects padding, the other alphabet and anything longer than a whole byte permits', () => {
    for (const bad of ['Zm9v=', 'Zm9+', 'Zm9vA', 'Zm 9', 'a']) {
      expect(() => fromBase64Url(bad), bad).toThrow(ReceiptError);
    }
  });

  it('reports a malformed value under the code the caller asked for', () => {
    try {
      fromBase64Url('!!!!', 'BAD_POP_NONCE');
      throw new Error('expected a ReceiptError');
    } catch (err) {
      expect(err).toBeInstanceOf(ReceiptError);
      expect((err as ReceiptError).code).toBe('BAD_POP_NONCE');
    }
  });
});

function errorCodeOf(fn: () => unknown): string {
  try {
    fn();
    return 'no-error';
  } catch (err) {
    return err instanceof ReceiptError ? err.code : `non-ReceiptError: ${String(err)}`;
  }
}

const KEY_SEED = new Uint8Array(32).fill(7);
const PUBLIC_KEY = ed25519.getPublicKey(KEY_SEED);
const NONCE = new Uint8Array(POP_NONCE_BYTES).fill(0xab);
const BODY = '{"model":"m","messages":[]}';

function fields(overrides: Partial<PopFields> = {}): PopFields {
  return {
    ts: 1_772_000_000,
    nonce: NONCE,
    method: 'POST',
    target: '/v1/chat/completions',
    bodyDigestHex: sha256Hex(new TextEncoder().encode(BODY)),
    ...overrides,
  };
}

describe('PoP signing string', () => {
  it('joins the six components with one newline and an upper-cased method', () => {
    const string = popSigningString(fields());
    expect(string.split('\n')).toHaveLength(6);
    expect(string.startsWith(`${POP_SCHEME}\n1772000000\n`)).toBe(true);
    expect(string).toContain(`\n${toBase64Url(NONCE)}\nPOST\n`);
    expect(popSigningString(fields({ method: 'post' }))).toBe(string);
  });

  it('hashes the empty body to the published constant', () => {
    expect(EMPTY_BODY_SHA256_HEX).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    expect(sha256Hex(new Uint8Array(0))).toBe(EMPTY_BODY_SHA256_HEX);
  });

  it('covers the request target whole, so a query string cannot be swapped', () => {
    const base = fields();
    const withQuery = popSigningString({ ...base, target: '/v1/attestation?report_data=aa' });
    const otherQuery = popSigningString({ ...base, target: '/v1/attestation?report_data=bb' });
    expect(withQuery).not.toBe(otherQuery);
  });
});

describe('PoP Authorization header', () => {
  it('round-trips a signed header back to its fields', () => {
    const header = signPopAuthorization(fields(), 'cred-1', KEY_SEED);
    expect(header.startsWith(`${POP_AUTH_PREFIX} credential=cred-1,`)).toBe(true);
    const parsed = parsePopAuthorization(header);
    expect(parsed.credential).toBe('cred-1');
    expect(parsed.ts).toBe(1_772_000_000);
    expect(parsed.signature).toHaveLength(64);
    expect(verifyPopSignature(fields(), parsed.signature, PUBLIC_KEY)).toBe(true);
  });

  it('accepts the three parameters in any order and tolerates whitespace after commas', () => {
    const signature = ed25519.sign(new TextEncoder().encode(popSigningString(fields())), KEY_SEED);
    const header = encodePopAuthorization({ credential: 'cred-1', ts: 1_772_000_000, signature });
    const params = header.slice(POP_AUTH_PREFIX.length).trim().split(',');
    const reordered = `${POP_AUTH_PREFIX} ${params.reverse().join(', ')}`;
    expect(verifyPopSignature(fields(), parsePopAuthorization(reordered).signature, PUBLIC_KEY)).toBe(true);
  });

  const malformed: ReadonlyArray<readonly [string, string]> = [
    ['missing credential', 'Ashaveri-PoP ts=1, sig=aa'],
    ['missing ts', 'Ashaveri-PoP credential=c, sig=aa'],
    ['missing sig', 'Ashaveri-PoP credential=c, ts=1'],
    ['unknown parameter', 'Ashaveri-PoP credential=c, ts=1, sig=aa, extra=1'],
    ['non-numeric ts', 'Ashaveri-PoP credential=c, ts=soon, sig=aa'],
    ['negative ts', 'Ashaveri-PoP credential=c, ts=-1, sig=aa'],
    ['empty credential id', 'Ashaveri-PoP credential=, ts=1, sig=aa'],
    ['credential id with a comma', 'Ashaveri-PoP credential=a%2Cb, ts=1, sig=aa'],
    ['signature too short', 'Ashaveri-PoP credential=c, ts=1, sig=aa'],
    ['duplicated credential', 'Ashaveri-PoP credential=c, credential=d, ts=1, sig=aa'],
  ];

  it.each(malformed)('refuses %s with BAD_POP_HEADER', (_name, header) => {
    expect(errorCodeOf(() => parsePopAuthorization(header))).toBe('BAD_POP_HEADER');
  });

  it('names a header that is not PoP at all as a scheme mismatch', () => {
    for (const header of ['Bearer abc', '', 'ashaveri-pop credential=c, ts=1, sig=aa']) {
      expect(errorCodeOf(() => parsePopAuthorization(header)), header).toBe('AUTH_SCHEME_MISMATCH');
    }
  });

  // `Ashaveri-PoPv2` is somebody else's scheme: no credential was ever named, so the refusal is a
  // scheme disagreement. A tab between the scheme and the parameters is still this scheme, because
  // `encodePopAuthorization` writes the parameters after whitespace and the parser trims each part.
  it('requires the scheme to be the whole first token, not a prefix of it', () => {
    for (const header of [
      'Ashaveri-PoPv2 credential=c, ts=1, sig=aa',
      'Ashaveri-PoPv10 credential=c, ts=1, sig=aa',
      'Ashaveri-PoP-2 credential=c, ts=1, sig=aa',
      'Ashaveri-PoPXYZ credential=c, ts=1, sig=aa',
    ]) {
      expect(errorCodeOf(() => parsePopAuthorization(header)), header).toBe('AUTH_SCHEME_MISMATCH');
    }
    expect(errorCodeOf(() => parsePopAuthorization('Ashaveri-PoP\tcredential=c, ts=1, sig=aa'))).toBe('BAD_POP_HEADER');
  });

  // A `ts` outside the safe integer range cannot be read back by this same file's parser, so an
  // encoder that emitted one would be publishing a header no verifier can use.
  it('refuses to encode a timestamp its own parser would refuse', () => {
    const signature = new Uint8Array(64);
    for (const ts of [2 ** 53, 2 ** 53 + 2, 2 ** 60, Number.MAX_SAFE_INTEGER + 2]) {
      expect(errorCodeOf(() => encodePopAuthorization({ credential: 'cred-1', ts, signature })), String(ts)).toBe(
        'BAD_POP_HEADER',
      );
    }
    const widest = encodePopAuthorization({ credential: 'cred-1', ts: Number.MAX_SAFE_INTEGER, signature });
    expect(parsePopAuthorization(widest).ts).toBe(Number.MAX_SAFE_INTEGER);
  });

  it('refuses a credential id longer than the file format can store', () => {
    const long = 'x'.repeat(65);
    expect(() => parsePopAuthorization(`Ashaveri-PoP credential=${long}, ts=1, sig=aa`)).toThrow(ReceiptError);
  });

  it('refuses to sign with a nonce of the wrong width, before signing anything', () => {
    expect(errorCodeOf(() => signPopAuthorization({ ...fields(), nonce: new Uint8Array(8) }, 'cred-1', KEY_SEED))).toBe(
      'BAD_POP_NONCE',
    );
    expect(errorCodeOf(() => signPopAuthorization({ ...fields(), nonce: new Uint8Array(32) }, 'cred-1', KEY_SEED))).toBe(
      'BAD_POP_NONCE',
    );
  });

  it('quotes only the head of a hostile parameter, so a refusal stays a sentence', () => {
    const hostile = `Ashaveri-PoP ${'z'.repeat(5_000)}, ts=1, sig=aa`;
    let message = 'nothing was refused';
    try {
      parsePopAuthorization(hostile);
    } catch (err) {
      message = err instanceof ReceiptError ? err.message : `not a ReceiptError: ${String(err)}`;
    }
    expect(message).toContain('the PoP Authorization header is not parseable');
    // The measured ceiling, not a round number: 45 characters of canned sentence, ': ', and a
    // detail cut to MAX_DETAIL 200 plus '...'. The old 300 left 50 characters of slack.
    expect(message.length).toBeLessThanOrEqual(250);

    // That 250 is not slack: a header one character over it exists, and this is how. A control
    // character is quoted into the detail as a six-character `\uXXXX` escape by `asOneLine`, which
    // runs after the bound, so 29 of them give 45 + 2 + 11 + 29 * 6 + 19 = 251 characters. A
    // bound this side of that is a bound on the quoted text, not on the escaped one.
    const oneOver = `Ashaveri-PoP ${'\u0001'.repeat(29)}, ts=1, sig=aa`;
    let overMessage = 'nothing was refused';
    try {
      parsePopAuthorization(oneOver);
    } catch (err) {
      overMessage = err instanceof ReceiptError ? err.message : 'not a ReceiptError';
    }
    expect(overMessage.length).toBeGreaterThan(250);
  });
});

describe('PoP signature', () => {
  it('rejects a signature made over another body', () => {
    const signature = ed25519.sign(new TextEncoder().encode(popSigningString(fields())), KEY_SEED);
    const tamperedBody = { ...fields(), bodyDigestHex: sha256Hex(new TextEncoder().encode('{"a":1}')) };
    expect(verifyPopSignature(tamperedBody, signature, PUBLIC_KEY)).toBe(false);
  });

  it('rejects a signature checked against another key', () => {
    const signature = ed25519.sign(new TextEncoder().encode(popSigningString(fields())), KEY_SEED);
    expect(verifyPopSignature(fields(), signature, ed25519.getPublicKey(new Uint8Array(32).fill(8)))).toBe(false);
  });

  it('exports the tolerance a caller reads to decide staleness', () => {
    expect(POP_TIMESTAMP_TOLERANCE_SECONDS).toBe(120);
  });
});

describe('proof of possession against small-order public keys', () => {
  const FIELD_PRIME = 2n ** 255n - 19n;
  const HONEST_SEED = new Uint8Array(32).fill(11);
  const HONEST_PUBLIC_KEY = ed25519.getPublicKey(HONEST_SEED);

  function fromHexString(digits: string): Uint8Array {
    const bytes = new Uint8Array(digits.length / 2);
    for (let i = 0; i < bytes.length; i += 1) {
      bytes[i] = Number.parseInt(digits.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }

  function toHexString(bytes: Uint8Array): string {
    let out = '';
    for (const byte of bytes) out += byte.toString(16).padStart(2, '0');
    return out;
  }

  /**
   * The `y + p` spelling of the same point. A decoder that reduces the field element modulo `p`
   * reads it back as the same key, so a verifier that accepts it accepts a second encoding of every
   * small-order point. Only a point whose `y` is below 19 has one, and this subgroup list holds
   * three of them.
   */
  function plusPEncoding(bytes: Uint8Array): Uint8Array | undefined {
    let y = 0n;
    for (let i = 31; i >= 0; i -= 1) y = (y << 8n) | BigInt((bytes[i] ?? 0) & 0x7f);
    const signBit = ((bytes[31] ?? 0) & 0x80) === 0 ? 0n : 2n ** 255n;
    const shifted = y + FIELD_PRIME;
    if (shifted >= 2n ** 255n) return undefined;
    const encoded = new Uint8Array(32);
    let value = shifted | signBit;
    for (let i = 0; i < 32; i += 1) {
      encoded[i] = Number(value & 0xffn);
      value >>= 8n;
    }
    return encoded;
  }

  const canonicalKeys = [...new Set(ED25519_TORSION_SUBGROUP)].map(fromHexString);
  const nonCanonicalKeys = canonicalKeys.flatMap((encoded) => {
    const alternative = plusPEncoding(encoded);
    return alternative === undefined ? [] : [alternative];
  });

  it('refuses a signature nobody made, for every encoding of every small-order key', () => {
    // The counts name the shape of the attack surface: eight distinct subgroup points, three of
    // them reachable by a second encoding, so eleven keys that would each accept any request.
    expect(canonicalKeys).toHaveLength(8);
    expect(nonCanonicalKeys).toHaveLength(3);
    const zeroSignature = new Uint8Array(64);
    for (const smallOrderKey of [...canonicalKeys, ...nonCanonicalKeys]) {
      expect(verifyPopSignature(fields(), zeroSignature, smallOrderKey), toHexString(smallOrderKey)).toBe(false);
    }
  });

  it('accepts a real signature under an honest key, so the refusals above are not an always-false verifier', () => {
    const signature = ed25519.sign(new TextEncoder().encode(popSigningString(fields())), HONEST_SEED);
    expect(verifyPopSignature(fields(), signature, HONEST_PUBLIC_KEY)).toBe(true);
    expect(verifyPopSignature({ ...fields(), target: '/v1/other' }, signature, HONEST_PUBLIC_KEY)).toBe(false);
  });
});
