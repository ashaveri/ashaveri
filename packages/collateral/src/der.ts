/**
 * The DER element reader this package's binary answers share.
 *
 * Two origins answer in DER (the Intel PCK CRL as a `CertificateList`, the OCSP responder as an
 * `OCSPResponse`), and both are weighed by the same rules: definite lengths only, no multi-byte tags, no
 * trailing data inside a sequence the reader walked to its end, and every value kept as the bytes that
 * arrived rather than as a re-encoding of it. One reader of these elements is where a rule of that kind
 * belongs, because a second copy is a second answer to what a malformed answer is, and the two would drift.
 */

/** One DER element, with the offsets needed to keep its bytes exactly as they arrived. */
export interface Tlv {
  readonly tag: number;
  readonly start: number;
  readonly contentStart: number;
  readonly end: number;
}

/** One DER element read with a definite length, a bounded length field and no trailing bytes implied. */
export function readTlv(body: Uint8Array, offset: number, limit: number, context: string): Tlv {
  if (offset >= limit) {
    fail(`${context} is truncated at its tag`);
  }
  const tag = body[offset] as number;
  if ((tag & 0x1f) === 0x1f) {
    fail(`${context} uses a multi-byte tag`);
  }
  let at = offset + 1;
  if (at >= limit) {
    fail(`${context} is truncated at its length`);
  }
  const first = body[at] as number;
  let length: number;
  if (first < 0x80) {
    length = first;
    at += 1;
  } else {
    const count = first & 0x7f;
    if (count === 0) {
      fail(`${context} uses an indefinite length`);
    }
    if (count > 4) {
      fail(`${context} states a length wider than four bytes`);
    }
    if (at + count >= limit) {
      fail(`${context} is truncated inside its length`);
    }
    if ((body[at + 1] as number) === 0) {
      fail(`${context} states a length with a leading zero`);
    }
    length = 0;
    for (let index = 1; index <= count; index += 1) {
      length = length * 0x100 + (body[at + index] as number);
    }
    if (length < 0x80) {
      fail(`${context} states a long-form length for a value that fits the short form`);
    }
    at += 1 + count;
  }
  if (length > limit - at) {
    fail(`${context} overruns the bytes that carry it`);
  }
  return { tag, start: offset, contentStart: at, end: at + length };
}

export function expectTag(tlv: Tlv, tag: number, context: string): void {
  if (tlv.tag !== tag) {
    fail(`${context} is tag 0x${tlv.tag.toString(16)}, not 0x${tag.toString(16)}`);
  }
}

/** The content of one element, as the bytes that carry it and nothing wider. */
export function contentOf(body: Uint8Array, tlv: Tlv): Uint8Array {
  return body.slice(tlv.contentStart, tlv.end);
}

/**
 * An OID as its own dotted text.
 *
 * The first sub-identifier packs the first two arcs, as X.690 states it, and a value whose last byte still
 * has the continuation bit set is truncated rather than a very large arc.
 */
export function decodeOid(body: Uint8Array, tlv: Tlv): string {
  if (tlv.end === tlv.contentStart) {
    fail('an OID states no arc');
  }
  const arcs: number[] = [];
  let value = 0;
  for (let at = tlv.contentStart; at < tlv.end; at += 1) {
    const byte = body[at] as number;
    if (value > Number.MAX_SAFE_INTEGER / 128) {
      fail('an OID arc is larger than this reader can state');
    }
    value = value * 128 + (byte & 0x7f);
    if ((byte & 0x80) === 0) {
      arcs.push(value);
      value = 0;
    }
  }
  if ((body[tlv.end - 1] as number) & 0x80) {
    fail('an OID ends in the middle of an arc');
  }
  const first = arcs[0] as number;
  const firstArc = first < 40 ? 0 : first < 80 ? 1 : 2;
  const secondArc = first < 40 ? first : first < 80 ? first - 40 : first - 80;
  return [firstArc, secondArc, ...arcs.slice(1)].join('.');
}

/** One Time value as Unix seconds, with the calendar checked rather than normalized. */
export function parseTime(body: Uint8Array, tlv: Tlv, context: string): number {
  if (tlv.tag !== 0x17 && tlv.tag !== 0x18) {
    fail(`${context} is neither UTCTime nor GeneralizedTime`);
  }
  const text = new TextDecoder('latin1').decode(body.subarray(tlv.contentStart, tlv.end));
  const match = tlv.tag === 0x17
    ? /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/u.exec(text)
    : /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/u.exec(text);
  if (match === null) {
    fail(`${context} is not a DER time`);
  }
  let year = Number(match[1]);
  if (tlv.tag === 0x17) {
    year += year >= 50 ? 1900 : 2000;
  }
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const millis = Date.UTC(year, month - 1, day, hour, minute, second);
  const date = new Date(millis);
  if (
    date.getUTCFullYear() !== year
    || date.getUTCMonth() !== month - 1
    || date.getUTCDate() !== day
    || date.getUTCHours() !== hour
    || date.getUTCMinutes() !== minute
    || date.getUTCSeconds() !== second
  ) {
    fail(`${context} names a calendar instant that does not exist`);
  }
  return Math.floor(millis / 1000);
}

/** A DER INTEGER's canonical unsigned value, refused where its bytes would read as negative or redundant. */
export function positiveInteger(body: Uint8Array, tlv: Tlv, context: string): bigint {
  const length = tlv.end - tlv.contentStart;
  if (length === 0) {
    fail(`${context} is an empty INTEGER`);
  }
  const first = body[tlv.contentStart] as number;
  if ((first & 0x80) !== 0) {
    fail(`${context} is negative`);
  }
  if (length > 1 && first === 0 && ((body[tlv.contentStart + 1] as number) & 0x80) === 0) {
    fail(`${context} has a redundant leading zero`);
  }
  let value = 0n;
  for (let at = tlv.contentStart; at < tlv.end; at += 1) {
    value = (value << 8n) | BigInt(body[at] as number);
  }
  return value;
}

/** A BIT STRING's contents, less the unused-bits byte, which must state no unused bits here. */
export function bitStringContent(body: Uint8Array, tlv: Tlv, context: string): Uint8Array {
  const length = tlv.end - tlv.contentStart;
  if (length < 2) {
    fail(`${context} is too short to hold a value`);
  }
  if ((body[tlv.contentStart] as number) !== 0) {
    fail(`${context} states unused bits`);
  }
  return body.slice(tlv.contentStart + 1, tlv.end);
}

export function fail(why: string): never {
  throw new Error(why);
}
