import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha2.js';
// The signing string is UTF-8 bytes, and this package has no DOM or Node global types, so the
// encoder comes from the hash library already at the bottom of the signature path instead.
import { utf8ToBytes } from '@noble/hashes/utils.js';
import { ReceiptError } from './errors.js';
import { fromBase64Url, toBase64Url } from './b64.js';

export const POP_SCHEME = 'ashaveri-pop-v1';
export const POP_AUTH_PREFIX = 'Ashaveri-PoP';
export const POP_NONCE_BYTES = 16;
export const POP_TIMESTAMP_TOLERANCE_SECONDS = 120;

/** sha256 of the empty byte string, which is what a bodyless request signs. */
export const EMPTY_BODY_SHA256_HEX = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

const CREDENTIAL_ID = /^[A-Za-z0-9_-]{1,64}$/u;
const TIMESTAMP = /^[0-9]{1,20}$/u;

export interface PopFields {
  readonly ts: number;
  readonly nonce: Uint8Array;
  readonly method: string;
  readonly target: string;
  readonly bodyDigestHex: string;
}

export interface PopAuthorization {
  readonly credential: string;
  readonly ts: number;
  readonly signature: Uint8Array;
}

// Local rather than the codec's `toHex`: importing that one would drag the CBOR and COSE
// modules into every client that only needs to sign a request.
function hex(bytes: Uint8Array): string {
  let out = '';
  for (const byte of bytes) out += byte.toString(16).padStart(2, '0');
  return out;
}

export function sha256Hex(bytes: Uint8Array): string {
  return hex(sha256(bytes));
}

/**
 * A newline joins the components because a pipe would not survive a query string:
 * `|` is legal in a URL, and a separator that can appear inside a field cannot be
 * split unambiguously by a verifier written in another language. The method is
 * upper-cased on the way in so a client and a gateway that disagree only on case
 * still agree on the bytes.
 */
export function popSigningString(fields: PopFields): string {
  return [
    POP_SCHEME,
    String(fields.ts),
    toBase64Url(fields.nonce),
    fields.method.toUpperCase(),
    fields.target,
    fields.bodyDigestHex,
  ].join('\n');
}

export function encodePopAuthorization(input: {
  credential: string;
  ts: number;
  signature: Uint8Array;
}): string {
  if (!CREDENTIAL_ID.test(input.credential)) {
    throw new ReceiptError('BAD_POP_HEADER', `credential id ${input.credential} is not 1-64 of [A-Za-z0-9_-]`);
  }
  if (!Number.isInteger(input.ts) || input.ts < 0) {
    throw new ReceiptError('BAD_POP_HEADER', `ts must be a non-negative integer, got ${input.ts}`);
  }
  if (input.signature.length !== 64) {
    throw new ReceiptError('BAD_POP_HEADER', `signature must be 64 bytes, got ${input.signature.length}`);
  }
  return `${POP_AUTH_PREFIX} credential=${input.credential}, ts=${input.ts}, sig=${toBase64Url(input.signature)}`;
}

/**
 * The nonce width is refused before anything is signed: `ed25519.sign` would happily sign a
 * string built from an eight-byte nonce, so a client that got the width wrong would pay for a
 * signature and then be refused at the gateway with a code that names the signature rather
 * than the mistake.
 */
export function signPopAuthorization(
  fields: PopFields,
  credential: string,
  privateKey: Uint8Array,
): string {
  if (fields.nonce.length !== POP_NONCE_BYTES) {
    throw new ReceiptError('BAD_POP_NONCE', `nonce must be ${POP_NONCE_BYTES} bytes, got ${fields.nonce.length}`);
  }
  const toSign = utf8ToBytes(popSigningString(fields));
  const signature = ed25519.sign(toSign, privateKey);
  return encodePopAuthorization({ credential, ts: fields.ts, signature });
}

/**
 * Parameters are comma-separated and order-free, which is how an `Authorization` header is
 * usually written and what lets a proxy re-emit it without breaking the signature: only the
 * three names are read, never their positions. The signature itself is signed material, so a
 * header that parses but carries a wrong-width signature is a client bug and not a scheme
 * disagreement, which is why the two refusals are two codes.
 */
export function parsePopAuthorization(header: string): PopAuthorization {
  const trimmed = header.trim();
  if (!trimmed.startsWith(POP_AUTH_PREFIX)) {
    throw new ReceiptError('AUTH_SCHEME_MISMATCH', 'the Authorization header is not an Ashaveri-PoP header');
  }
  const seen = new Map<string, string>();
  for (const part of trimmed.slice(POP_AUTH_PREFIX.length).split(',')) {
    const pair = part.trim();
    if (pair.length === 0) continue;
    const equals = pair.indexOf('=');
    if (equals < 1) {
      throw new ReceiptError('BAD_POP_HEADER', `parameter '${pair}' is not name=value`);
    }
    const name = pair.slice(0, equals);
    if (seen.has(name)) {
      throw new ReceiptError('BAD_POP_HEADER', `parameter '${name}' appears twice`);
    }
    seen.set(name, pair.slice(equals + 1).trim());
  }
  const credential = required(seen, 'credential');
  const ts = required(seen, 'ts');
  const signature = required(seen, 'sig');
  for (const name of seen.keys()) {
    if (name !== 'credential' && name !== 'ts' && name !== 'sig') {
      throw new ReceiptError('BAD_POP_HEADER', `unknown parameter '${name}'`);
    }
  }
  if (!CREDENTIAL_ID.test(credential)) {
    throw new ReceiptError('BAD_POP_HEADER', 'credential id is outside the allowed character set or length');
  }
  if (!TIMESTAMP.test(ts)) {
    throw new ReceiptError('BAD_POP_HEADER', 'ts is not a plain non-negative integer');
  }
  const asNumber = Number(ts);
  if (!Number.isSafeInteger(asNumber)) {
    throw new ReceiptError('BAD_POP_HEADER', `ts ${ts} is beyond the safe integer range`);
  }
  const bytes = fromBase64Url(signature);
  if (bytes.length !== 64) {
    throw new ReceiptError('BAD_POP_HEADER', `signature decodes to ${bytes.length} bytes, not 64`);
  }
  return { credential, ts: asNumber, signature: bytes };
}

/**
 * Strict (RFC 8032) verification rather than the subgroup-tolerant default the library picks,
 * because the option is the difference between a key that can absorb a signature nobody made and
 * a key that cannot. A public key of small order is a universal acceptor under the relaxed rule,
 * where one all-zero signature verifies for every message, and this option is what refuses it.
 * What it costs is a signature whose encoding is not canonical, which is nothing here: every
 * signature on this wire format is produced by `signPopAuthorization` in this file or by the SDK
 * that calls it, and both emit canonical encodings.
 */
export function verifyPopSignature(
  fields: PopFields,
  signature: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  if (signature.length !== 64 || publicKey.length !== 32) return false;
  return ed25519.verify(signature, utf8ToBytes(popSigningString(fields)), publicKey, { zip215: false });
}

function required(seen: Map<string, string>, name: 'credential' | 'ts' | 'sig'): string {
  const value = seen.get(name);
  if (value === undefined || value.length === 0) {
    throw new ReceiptError('BAD_POP_HEADER', `missing required parameter '${name}'`);
  }
  return value;
}
