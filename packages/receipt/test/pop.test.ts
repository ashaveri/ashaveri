import { describe, expect, it } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519';
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
    expect(message.length).toBeLessThanOrEqual(300);
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
