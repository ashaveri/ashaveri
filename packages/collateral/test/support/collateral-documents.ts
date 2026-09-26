import { p256 } from '@noble/curves/nist.js';
import { sha256 } from '@noble/hashes/sha2.js';

/**
 * Certificates and signed documents for these tests, written here rather than captured.
 *
 * No answer of the vendor's is stored in this repository, so every document a test hands to the reader is
 * built to the shape `intel-origin.ts` declares and signed by a key generated in the test. That keeps the
 * assertions about *this* path honest: they show the reader honours its own declaration, and they show
 * nothing about whether the declaration matches what the vendor publishes, which is the limitation the
 * lane records.
 */

const OID_ECDSA_SHA256 = '1.2.840.10045.4.3.2';
const OID_ECDSA_SHA384 = '1.2.840.10045.4.3.3';
const OID_EC_PUBLIC_KEY = '1.2.840.10045.2.1';
const OID_P256 = '1.2.840.10045.3.1.7';
const OID_COMMON_NAME = '2.5.4.3';
const OID_BASIC_CONSTRAINTS = '2.5.29.19';
const BASE64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const BASE64_URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/** A stand-in vendor: the self-signed root a caller can pin and the CA beneath it that signs documents. */
export interface TestVendor {
  readonly rootDer: Uint8Array;
  readonly issuerDer: Uint8Array;
  readonly signingKey: Uint8Array;
  /** sha256 of `rootDer` as lowercase hex, computed here so a test can name the anchor it pinned. */
  readonly rootDigest: string;
}

/** A vendor whose signing certificate names a suite its key does not carry, which is a substitution. */
export function mismatchedVendor(): TestVendor {
  const rootKey = p256.utils.randomPrivateKey();
  const signingKey = p256.utils.randomPrivateKey();
  const notBefore = secondsOf('2026-01-01T00:00:00.000Z');
  const notAfter = secondsOf('2036-01-01T00:00:00.000Z');
  const rootDer = certificate({
    commonName: 'Test Vendor Root CA',
    issuerCommonName: 'Test Vendor Root CA',
    serial: 1,
    notBefore,
    notAfter,
    key: rootKey,
    issuerKey: rootKey,
    isCa: true,
  });
  const issuerDer = certificate({
    commonName: 'Test Vendor Platform CA',
    issuerCommonName: 'Test Vendor Root CA',
    serial: 2,
    notBefore,
    notAfter,
    key: signingKey,
    issuerKey: rootKey,
    isCa: true,
    signatureOid: OID_ECDSA_SHA384,
  });
  return { rootDer, issuerDer, signingKey, rootDigest: toHex(sha256(rootDer)) };
}

interface CertificateSpec {
  readonly commonName: string;
  readonly issuerCommonName: string;
  readonly serial: number;
  readonly notBefore: number;
  readonly notAfter: number;
  readonly key: Uint8Array;
  readonly issuerKey: Uint8Array;
  readonly isCa: boolean;
  /** A certificate can be handed an algorithm identifier its own key does not carry. */
  readonly signatureOid?: string;
}

export function secondsOf(text: string): number {
  return Math.floor(Date.parse(text) / 1000);
}

/**
 * A root and an issuing CA, both P-256 and both CA certificates, because this path reads the vendor's
 * statement as signed by an authority rather than by a leaf. Two calls with the same names hand back the
 * same distinguished names over different keys, which is what a chain borrowing a trusted name looks like.
 */
export function testVendor(input: {
  readonly rootName?: string;
  readonly issuerName?: string;
  readonly notBefore?: number;
  readonly notAfter?: number;
} = {}): TestVendor {
  const notBefore = input.notBefore ?? secondsOf('2026-01-01T00:00:00.000Z');
  const notAfter = input.notAfter ?? secondsOf('2036-01-01T00:00:00.000Z');
  const rootName = input.rootName ?? 'Test Vendor Root CA';
  const issuerName = input.issuerName ?? 'Test Vendor Platform CA';
  const rootKey = p256.utils.randomPrivateKey();
  const issuerKey = p256.utils.randomPrivateKey();
  const rootDer = certificate({
    commonName: rootName,
    issuerCommonName: rootName,
    serial: 1,
    notBefore,
    notAfter,
    key: rootKey,
    issuerKey: rootKey,
    isCa: true,
  });
  const issuerDer = certificate({
    commonName: issuerName,
    issuerCommonName: rootName,
    serial: 2,
    notBefore,
    notAfter,
    key: issuerKey,
    issuerKey: rootKey,
    isCa: true,
  });
  return { rootDer, issuerDer, signingKey: issuerKey, rootDigest: toHex(sha256(rootDer)) };
}

/** The certificates a header would present for this vendor, leaf first, as the answer spells them. */
export function x5cOf(vendor: TestVendor): readonly string[] {
  return [toBase64(vendor.issuerDer), toBase64(vendor.rootDer)];
}

/** A key the vendor never issued a certificate for, so a document signed with it is not the vendor's. */
export function foreignKey(): Uint8Array {
  return p256.utils.randomPrivateKey();
}

/** The document as the origin serves it: three dot-separated base64url parts, certificates in the header. */
export function signedDocument(
  payload: Record<string, unknown>,
  vendor: TestVendor,
  header: Record<string, unknown> = { alg: 'ES256', x5c: x5cOf(vendor) },
): Uint8Array {
  const first = toBase64Url(utf8(JSON.stringify(header)));
  const second = toBase64Url(utf8(JSON.stringify(payload)));
  const signature = p256.sign(sha256(utf8(`${first}.${second}`)), vendor.signingKey).toCompactRawBytes();
  return utf8(`${first}.${second}.${toBase64Url(signature)}`);
}

export function tcbInfo(input: {
  readonly fmspc: string;
  readonly issueDate: string;
  readonly nextUpdate: string;
  readonly levels: readonly { readonly tcbDate: string; readonly tcbStatus: string }[];
}): Record<string, unknown> {
  return {
    tcbInfo: {
      fmspcid: input.fmspc,
      issueDate: input.issueDate,
      nextUpdate: input.nextUpdate,
      tcb: input.levels.map((level) => ({ tcbDate: level.tcbDate, tcbStatus: level.tcbStatus })),
    },
  };
}

export function qeIdentity(input: {
  readonly issueDate: string;
  readonly nextUpdate: string;
  readonly tcbStatus: string;
}): Record<string, unknown> {
  return { issueDate: input.issueDate, nextUpdate: input.nextUpdate, tcbStatus: input.tcbStatus };
}

function certificate(spec: CertificateSpec): Uint8Array {
  const algorithm = sequence(oidNode(spec.signatureOid ?? OID_ECDSA_SHA256));
  const body = sequence(
    tlv(0xa0, integerNode(2)),
    integerNode(spec.serial),
    algorithm,
    nameNode(spec.issuerCommonName),
    sequence(utcTimeNode(spec.notBefore), utcTimeNode(spec.notAfter)),
    nameNode(spec.commonName),
    sequence(
      sequence(oidNode(OID_EC_PUBLIC_KEY), oidNode(OID_P256)),
      bitStringNode(p256.getPublicKey(spec.key, false)),
    ),
    tlv(0xa3, sequence(sequence(oidNode(OID_BASIC_CONSTRAINTS), booleanNode(true), octetNode(sequence(booleanNode(spec.isCa)))))),
  );
  const signature = p256.sign(sha256(body), spec.issuerKey).toDERRawBytes();
  return sequence(body, algorithm, bitStringNode(signature));
}

function nameNode(commonName: string): Uint8Array {
  return sequence(setNode(sequence(oidNode(OID_COMMON_NAME), printableNode(commonName))));
}

function utf8(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function toBase64(bytes: Uint8Array, alphabet: string = BASE64): string {
  const padded = alphabet === BASE64;
  const text: string[] = [];
  for (let offset = 0; offset < bytes.length; offset += 3) {
    const chunk = bytes.subarray(offset, Math.min(offset + 3, bytes.length));
    const value = (chunk[0] ?? 0) << 16 | (chunk[1] ?? 0) << 8 | (chunk[2] ?? 0);
    const chars = [
      alphabet[(value >> 18) & 0x3f] as string,
      alphabet[(value >> 12) & 0x3f] as string,
      chunk.length > 1 ? alphabet[(value >> 6) & 0x3f] as string : padded ? '=' : '',
      chunk.length > 2 ? alphabet[value & 0x3f] as string : padded ? '=' : '',
    ];
    text.push(...chars);
  }
  return text.join('');
}

function toBase64Url(bytes: Uint8Array): string {
  return toBase64(bytes, BASE64_URL);
}

function concat(parts: readonly Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((total, part) => total + part.byteLength, 0));
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.byteLength;
  }
  return out;
}

function tlv(tag: number, content: Uint8Array): Uint8Array {
  const length = content.byteLength;
  if (length < 0x80) {
    return concat([Uint8Array.from([tag, length]), content]);
  }
  const encoded: number[] = [];
  let rest = length;
  while (rest > 0) {
    encoded.unshift(rest & 0xff);
    rest = Math.floor(rest / 256);
  }
  return concat([Uint8Array.from([tag, 0x80 | encoded.length, ...encoded]), content]);
}

function sequence(...parts: readonly Uint8Array[]): Uint8Array {
  return tlv(0x30, concat(parts));
}

function setNode(...parts: readonly Uint8Array[]): Uint8Array {
  return tlv(0x31, concat(parts));
}

function octetNode(content: Uint8Array): Uint8Array {
  return tlv(0x04, content);
}

function bitStringNode(bits: Uint8Array): Uint8Array {
  return tlv(0x03, concat([Uint8Array.from([0]), bits]));
}

function integerNode(value: number): Uint8Array {
  const bytes: number[] = [];
  let rest = value;
  do {
    bytes.unshift(rest & 0xff);
    rest = Math.floor(rest / 256);
  } while (rest > 0);
  if ((bytes[0] ?? 0) >= 0x80) {
    bytes.unshift(0);
  }
  return tlv(0x02, Uint8Array.from(bytes));
}

function booleanNode(value: boolean): Uint8Array {
  return tlv(0x01, Uint8Array.from([value ? 0xff : 0x00]));
}

function printableNode(text: string): Uint8Array {
  return tlv(0x13, utf8(text));
}

function oidNode(dotted: string): Uint8Array {
  const arcs = dotted.split('.').map((arc) => Number(arc));
  const first = arcs[0] ?? 0;
  const second = arcs[1] ?? 0;
  const bytes: number[] = [first * 40 + second];
  for (const arc of arcs.slice(2)) {
    const encoded: number[] = [];
    let rest = arc;
    do {
      encoded.unshift(rest & 0x7f);
      rest = Math.floor(rest / 128);
    } while (rest > 0);
    for (let index = 0; index < encoded.length; index += 1) {
      bytes.push(index === encoded.length - 1 ? (encoded[index] as number) : (encoded[index] as number) | 0x80);
    }
  }
  return tlv(0x06, Uint8Array.from(bytes));
}

function utcTimeNode(seconds: number): Uint8Array {
  const at = new Date(seconds * 1000);
  const part = (value: number) => String(value).padStart(2, '0');
  const text = `${part(at.getUTCFullYear() % 100)}${part(at.getUTCMonth() + 1)}${part(at.getUTCDate())}${part(at.getUTCHours())}${part(at.getUTCMinutes())}${part(at.getUTCSeconds())}Z`;
  return tlv(0x17, utf8(text));
}
