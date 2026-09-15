import { ReceiptError, type ReceiptErrorCode } from './errors.js';

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const NOT_BASE64URL = /[^A-Za-z0-9_-]/u;

function sextet(char: string, code: ReceiptErrorCode): number {
  const index = ALPHABET.indexOf(char);
  if (index < 0) {
    throw new ReceiptError(code, `not a base64url character: ${char}`);
  }
  return index;
}

/**
 * Node has base64url through Buffer and the web has it through btoa, and a client
 * compiled for a browser or an edge runtime has only one of the two. This table is
 * the third option, so a receipt-side helper stays portable to both.
 */
export function toBase64Url(bytes: Uint8Array): string {
  const chars: number[] = [];
  for (let i = 0; i < bytes.length; i += 3) {
    const first = bytes[i] ?? 0;
    const second = bytes[i + 1];
    const third = bytes[i + 2];
    chars.push(ALPHABET.charCodeAt(first >> 2));
    chars.push(ALPHABET.charCodeAt(((first & 0b11) << 4) | ((second ?? 0) >> 4)));
    if (second === undefined) break;
    chars.push(ALPHABET.charCodeAt(((second & 0b1111) << 2) | ((third ?? 0) >> 6)));
    if (third === undefined) break;
    chars.push(ALPHABET.charCodeAt(third & 0b111111));
  }
  return String.fromCharCode(...chars);
}

/**
 * Unpadded and alphabet-strict, because a PoP header is signed material: `=` is not part of
 * the form, and `+` or `/` mean the value came from the other base64. The length rule is the
 * one a decoder cannot skip: a chunk of one character stands for no byte at all, since the
 * first character contributes only six bits.
 */
export function fromBase64Url(value: string, code: ReceiptErrorCode = 'BAD_POP_HEADER'): Uint8Array {
  if (NOT_BASE64URL.test(value) || value.length % 4 === 1) {
    throw new ReceiptError(code, `not unpadded base64url: ${value}`);
  }
  const bytes: number[] = [];
  for (let i = 0; i < value.length; i += 4) {
    const a = value[i];
    const b = value[i + 1];
    if (a === undefined || b === undefined) break;
    const bBits = sextet(b, code);
    bytes.push((sextet(a, code) << 2) | (bBits >> 4));
    const c = value[i + 2];
    if (c === undefined) break;
    const cBits = sextet(c, code);
    bytes.push(((bBits & 0b1111) << 4) | (cBits >> 2));
    const d = value[i + 3];
    if (d === undefined) break;
    bytes.push(((cBits & 0b11) << 6) | sextet(d, code));
  }
  return Uint8Array.from(bytes);
}
