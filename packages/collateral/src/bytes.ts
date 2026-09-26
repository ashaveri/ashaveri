import { sha256 } from '@noble/hashes/sha2.js';

/** Lowercase hex, spelled without a Buffer so a digest a verdict prints reads the same anywhere. */
export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

export function sha256Hex(bytes: Uint8Array): string {
  return toHex(sha256(bytes));
}

export function utf8(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

const BASE64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const BASE64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

function decode(text: string, alphabet: string): Uint8Array | null {
  // Padding is trimmed by index, not by /"+$/: a quantifier anchored at the end of an
  // untrusted string backtracks once per character the tail does not match.
  let end = text.length;
  while (end > 0 && text[end - 1] === '=') {
    end -= 1;
  }
  const body = text.slice(0, end);
  if (body.length % 4 === 1) {
    return null;
  }
  const bytes: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const char of body) {
    const value = alphabet.indexOf(char);
    if (value < 0) {
      return null;
    }
    buffer = (buffer << 6) | value;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >> bits) & 0xff);
    }
  }
  return Uint8Array.from(bytes);
}

/**
 * Base64url text decoded strictly, or null.
 *
 * A padded length of one mod four is not a thing base64 can encode, and a character outside the
 * alphabet is refused rather than skipped: this is the door the signed envelope comes through, and a
 * decoder that ignored what it could not read would turn a corrupted certificate into a shorter one.
 */
export function fromBase64Url(text: string): Uint8Array | null {
  return decode(text, BASE64URL);
}

/**
 * Standard base64, which is the spelling RFC 7515 gives the `x5c` entries of a JWS header, as against
 * the base64url spelling the envelope's own three parts use. The two alphabets are kept apart
 * because `+` and `-` name different six-bit values, and reading one as the other yields a
 * certificate that parses as nothing.
 */
export function fromBase64(text: string): Uint8Array | null {
  return decode(text, BASE64);
}
