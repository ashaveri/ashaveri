import { encode, decode, cdeEncodeOptions, cdeDecodeOptions, type DecodeOptions } from 'cbor2';
import { ReceiptError, type ReceiptErrorCode } from './errors.js';

export function encodeCanonical(value: unknown): Uint8Array {
  return new Uint8Array(encode(value, cdeEncodeOptions));
}

// A read failure names the part being read, because the caller knows whether the document, its
// protected header or its payload was unparseable, and a reader exception is not a code a client can
// branch on.
// preferMap: cbor2 maps string-keyed CBOR maps to plain objects by default; uniform Map output keeps
// downstream type checks single-shaped.
function decodeWith(bytes: Uint8Array, options: DecodeOptions, malformed: ReceiptErrorCode): unknown {
  try {
    return decode(bytes, options);
  } catch (err) {
    throw new ReceiptError(malformed, err instanceof Error ? err.message : String(err));
  }
}

export function decodeCanonical(bytes: Uint8Array, malformed: ReceiptErrorCode = 'MALFORMED_CBOR'): unknown {
  return decodeWith(bytes, { ...cdeDecodeOptions, preferMap: true }, malformed);
}

/**
 * The two documents `receipt.cddl` declares member by member — the protected header and the payload
 * — read under one rule the rest of the envelope is not: no floating-point number may appear in
 * either, at any depth, as a value or as a key.
 *
 * The rule has to be part of the decode, because nothing placed after one can be enforced. A CBOR
 * float holding a whole number decodes to the very JavaScript `number` the integer it imitates
 * decodes to, and `Map` compares keys by identity rather than by the bytes that wrote them, so the two
 * are not merely similar by the time a reader looks: an `iat` of the half-float `2.0` reads as the
 * integer `2`, and a header label written as the float `1.0` lands in the same `Map` slot as the
 * integer label `1` and overwrites whatever was there, in whichever order the document lists them,
 * because core deterministic ordering puts the one-byte integer first and the three-byte float last.
 * A `typeof` check, a closed set of labels and a closure walk all see one merged map and cannot
 * recover which bytes built it.
 *
 * Refusing floats is as wide as these two documents and no wider. Both close: every label the
 * protected header carries is one of three integers, and every member of the payload and of the maps
 * nested inside it is named in the CDDL, where the number positions are written `int`. Nothing any of
 * them declares can be a float, so a document containing one is malformed rather than one a reader
 * should coerce. The map the format does leave free, the unprotected one, is read through
 * `decodeCanonical` above and keeps admitting anything: it sits outside the signature and carries no
 * claim, so a float inside it is nobody's integer wearing a different coat.
 */
export function decodeClosedDocument(bytes: Uint8Array, malformed: ReceiptErrorCode): unknown {
  return decodeWith(bytes, { ...cdeDecodeOptions, preferMap: true, rejectFloats: true }, malformed);
}

/**
 * A decoded CBOR map arrives as `Map<any, any>`, which makes every value read look like
 * `any` and stops the `typeof` and `instanceof` checks in the parsers from counting as
 * narrowing. This performs the map check once and gives back unknown-valued reads, so a
 * check decides the type instead of asserting it.
 */
export function decodedMap(value: unknown): Map<unknown, unknown> | null {
  return value instanceof Map ? (value as Map<unknown, unknown>) : null;
}
