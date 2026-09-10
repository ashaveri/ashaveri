import { encode, decode, cdeEncodeOptions, cdeDecodeOptions } from 'cbor2';

export function encodeCanonical(value: unknown): Uint8Array {
  return new Uint8Array(encode(value, cdeEncodeOptions));
}

// preferMap: cbor2 maps string-keyed CBOR maps to plain objects by default;
// uniform Map output keeps downstream type checks single-shaped.
export function decodeCanonical(bytes: Uint8Array): unknown {
  return decode(bytes, { ...cdeDecodeOptions, preferMap: true });
}
