import { encode, decode, cdeEncodeOptions, cdeDecodeOptions } from 'cbor2';
import { ReceiptError, type ReceiptErrorCode } from './errors.js';

export function encodeCanonical(value: unknown): Uint8Array {
  return new Uint8Array(encode(value, cdeEncodeOptions));
}

// A read failure names the part being read, because the caller knows whether the
// document, its protected header or its payload was unparseable, and a reader
// exception is not a code a client can branch on.
// preferMap: cbor2 maps string-keyed CBOR maps to plain objects by default;
// uniform Map output keeps downstream type checks single-shaped.
export function decodeCanonical(bytes: Uint8Array, malformed: ReceiptErrorCode = 'MALFORMED_CBOR'): unknown {
  try {
    return decode(bytes, { ...cdeDecodeOptions, preferMap: true });
  } catch (err) {
    throw new ReceiptError(malformed, err instanceof Error ? err.message : String(err));
  }
}
