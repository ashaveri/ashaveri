import { p256 } from '@noble/curves/nist.js';
import { sha1 } from '@noble/hashes/legacy.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { parseCertificateChain } from '@ashaveri/attest-core';
import type { TestVendor } from '@ashaveri/fixtures';

/**
 * A writer for the OCSP request and answer shapes, so the cases in `ocsp.test.ts` hand the reader real
 * signed answers without storing anybody's responder bytes.
 *
 * Every answer here is signed by a key generated in the run that asks for it, over the issuer certificate
 * `@ashaveri/fixtures` made for the same run. Nothing vendor-authored is stored: the members the writer emits
 * are the members RFC 6960 names, spelled as that specification states them, and the shape a responder answers
 * in is cited at the declaration in `src/intel-origin.ts`.
 *
 * The module RFC 6960 defines is read as `EXPLICIT TAGS`, and the one place it says otherwise is `CertStatus`,
 * whose three choices are `IMPLICIT`: `good` and `unknown` are therefore written as the empty primitive tags
 * `[0]` and `[2]`, and a revoked standing as the constructed `[1]` holding `RevokedInfo`'s own members. The two
 * hashes a `CertID` carries are taken over what RFC 6960 names them on (the whole DER `Name` for the issuer,
 * and the subject public key value with tag, length and unused-bit count left out), because a writer that
 * hashed anything else would test a reader rather than an answer.
 */

const OID_ECDSA_SHA256 = '1.2.840.10045.4.3.2';
const OID_SHA1 = '1.3.14.3.2.26';
const OID_OCSP_BASIC = '1.3.6.1.5.5.7.48.1.1';
const OID_COMMON_NAME = '2.5.4.3';
const OID_UNKNOWN = '1.2.3.4.5';

/** What a case can vary about the one answer it writes. */
export interface OcspInput {
  /** The vendor whose CA certificate signs the answer and whose key the reader weighs it under. */
  readonly responder: TestVendor;
  /** The certificate the question is about, as the DER a caller hands in `ocspCertificate`. */
  readonly certificate: Uint8Array;
  /** The issuer of that certificate, as the DER a caller hands in `ocspIssuer`. */
  readonly issuer: Uint8Array;
  readonly producedAt: number;
  readonly thisUpdate: number;
  /** The instant at or before which newer information is available, or null where a case states none. */
  readonly nextUpdate: number | null;
  readonly status?: 'good' | 'revoked' | 'unknown';
  /** The instant a `revoked` standing states, which is required for that standing and read by nothing else. */
  readonly revokedAt?: number;
  /** Which of the two responder identities to write, as the answer spells the signer. */
  readonly responderBy?: 'name' | 'key';
  /** A key other than the responder's, which makes a well-formed answer that its chain did not sign. */
  readonly signingKey?: Uint8Array;
  /** The certificates an answer presents in its optional `certs` slot, in the order a case names them. */
  readonly presentCerts?: readonly Uint8Array[];
  /** The response status figure, which is `successful` unless a case asks what another one answers with. */
  readonly responseStatus?: number;
  /** Leave the signed bytes out entirely, which is what a non-successful status is stated to do. */
  readonly omitResponseBytes?: boolean;
  /** The OID an answer names its response type with, which is the BasicOCSPResponse one unless a case asks. */
  readonly respTypeOid?: string;
  /** The OID an answer names its signature algorithm with. */
  readonly suiteOid?: string;
  /** The OID an answer names its `CertID` hash with. */
  readonly hashOid?: string;
  /** A name hash other than the issuer's, for a case that asks what a `CertID` about another issuer gets. */
  readonly nameHash?: Uint8Array;
  /** A key hash other than the issuer's. */
  readonly keyHash?: Uint8Array;
  /** A responder name other than the issuer's, for a case that asks what an answer from another signer gets. */
  readonly responderName?: Uint8Array;
  /** A responder key hash other than the issuer's, in the same slot. */
  readonly responderHash?: Uint8Array;
  /** A serial other than the certificate's, spelled as hex. */
  readonly serialHex?: string;
  /** How many `SingleResponse` entries to write, which is one unless a case asks what two answer with. */
  readonly entries?: number;
  /** The `ResponseData` version to state, which is absent unless a case writes one. */
  readonly version?: number;
  /** A critical extension the reader has no rule for, beside the standing of the first entry. */
  readonly unknownCriticalExtension?: boolean;
  /** Bytes after the outer sequence, which a strict reader refuses. */
  readonly trailing?: Uint8Array;
}

/** A device certificate the writer can be asked about: the DER, and the serial it states. */
export interface OcspDevice {
  readonly der: Uint8Array;
  readonly serialHex: string;
}

/**
 * One certificate under a named CA, for the pair a question is built from.
 *
 * The issuer field is copied from the CA's own parsed subject rather than re-spelled from a string, because a
 * name hash taken over a name that merely looks the same is a fixture that fails for the wrong reason.
 */
export function ocspDevice(
  issuerDer: Uint8Array,
  issuerKey: Uint8Array,
  serial: number,
  commonName = 'Ashaveri Test OCSP Device',
): OcspDevice {
  const issuer = parseCertificateChain(issuerDer)[0];
  if (issuer === undefined) {
    throw new Error('the OCSP fixture was handed an issuer that does not parse');
  }
  const key = p256.utils.randomSecretKey();
  const algorithm = sequence(oidNode(OID_ECDSA_SHA256));
  const tbs = sequence(
    tlv(0xa0, integerNode(2)),
    integerNode(serial),
    algorithm,
    wrap(0x30, issuer.subject),
    sequence(generalTime(1767225600), generalTime(2209000000)),
    nameNode(commonName),
    sequence(
      sequence(oidNode('1.2.840.10045.2.1'), oidNode('1.2.840.10045.3.1.7')),
      bitStringNode(p256.getPublicKey(key, false)),
    ),
  );
  const signature = p256.sign(sha256(tbs), issuerKey).toBytes('der');
  return { der: sequence(tbs, algorithm, bitStringNode(signature)), serialHex: BigInt(serial).toString(16) };
}

/** The DER `Name` a certificate states, wrapper and all, which is what an identity is spelled with. */
export function derNameOf(certDer: Uint8Array): Uint8Array {
  const cert = parseCertificateChain(certDer)[0];
  if (cert === undefined) {
    throw new Error('the OCSP fixture was handed a certificate that does not parse');
  }
  return wrap(0x30, cert.subject);
}

/** The DER `Name` a certificate states, wrapper and all, which is what RFC 6960 hashes a name over. */
export function issuerNameHashOf(issuerDer: Uint8Array): Uint8Array {
  const cert = parseCertificateChain(issuerDer)[0];
  if (cert === undefined) {
    throw new Error('the OCSP fixture was handed an issuer that does not parse');
  }
  return Uint8Array.from(sha1(wrap(0x30, cert.subject)));
}

/** The hash of an issuer's public key, over the value alone, as RFC 6960 states it. */
export function issuerKeyHashOf(issuerDer: Uint8Array): Uint8Array {
  const cert = parseCertificateChain(issuerDer)[0];
  if (cert === undefined) {
    throw new Error('the OCSP fixture was handed an issuer that does not parse');
  }
  return Uint8Array.from(sha1(subjectPublicKeyValue(cert.subjectPublicKeyInfo)));
}

/** The one certificate the responder answers with, signed over its own `tbsResponseData`. */
export function writeOcspResponse(input: OcspInput): Uint8Array {
  const status = input.status ?? 'good';
  const responder = parseCertificateChain(input.issuer)[0];
  if (responder === undefined) {
    throw new Error('the OCSP fixture was handed an issuer that does not parse');
  }
  const asked = parseCertificateChain(input.certificate)[0];
  if (asked === undefined) {
    throw new Error('the OCSP fixture was handed a certificate that does not parse');
  }
  const certId = sequence(
    sequence(oidNode(input.hashOid ?? OID_SHA1)),
    octetNode(input.nameHash ?? issuerNameHashOf(input.issuer)),
    octetNode(input.keyHash ?? issuerKeyHashOf(input.issuer)),
    tlv(0x02, input.serialHex === undefined ? asked.serial : serialBytes(input.serialHex)),
  );
  const entries: Uint8Array[] = [];
  for (let index = 0; index < (input.entries ?? 1); index += 1) {
    entries.push(singleResponse(certId, input, status));
  }
  const identity = (input.responderBy ?? 'name') === 'name'
    ? tlv(0xa1, input.responderName ?? wrap(0x30, responder.subject))
    : tlv(0xa2, octetNode(input.responderHash ?? issuerKeyHashOf(input.issuer)));
  const responseData = sequence(
    ...(input.version === undefined ? [] : [tlv(0xa0, integerNode(input.version))]),
    identity,
    generalTime(input.producedAt),
    sequence(...entries),
    ...(input.unknownCriticalExtension === true
      ? [tlv(0xa1, sequence(extension(OID_UNKNOWN, true, tlv(0x04, Uint8Array.of(1)))))]
      : []),
  );
  const signingKey = input.signingKey ?? input.responder.signingKey;
  const suite = sequence(oidNode(input.suiteOid ?? OID_ECDSA_SHA256));
  const signature = p256.sign(sha256(responseData), signingKey).toBytes('der');
  const basic = sequence(
    responseData,
    suite,
    bitStringNode(signature),
    ...(input.presentCerts === undefined ? [] : [tlv(0xa0, sequence(...input.presentCerts))]),
  );
  const responseBytes = sequence(oidNode(input.respTypeOid ?? OID_OCSP_BASIC), octetNode(basic));
  const statusFigure = input.responseStatus ?? 0;
  return concat([
    sequence(
      tlv(0x0a, Uint8Array.of(statusFigure)),
      ...(statusFigure === 0 && input.omitResponseBytes !== true ? [tlv(0xa0, responseBytes)] : []),
    ),
    input.trailing ?? new Uint8Array(0),
  ]);
}

/** One `SingleResponse`: the identity it answers about, the standing, and the window it states. */
function singleResponse(certId: Uint8Array, input: OcspInput, status: 'good' | 'revoked' | 'unknown'): Uint8Array {
  const standing = status === 'good'
    ? tlv(0x80, new Uint8Array(0))
    : status === 'unknown'
      ? tlv(0x82, new Uint8Array(0))
      : tlv(0xa1, concat([generalTime(input.revokedAt ?? input.thisUpdate)]));
  return sequence(
    certId,
    standing,
    generalTime(input.thisUpdate),
    ...(input.nextUpdate === null ? [] : [tlv(0xa0, generalTime(input.nextUpdate as number))]),
  );
}

/** The value of a `SubjectPublicKeyInfo`'s public-key BIT STRING, which is what a key hash is taken over. */
function subjectPublicKeyValue(spki: Uint8Array): Uint8Array {
  const outer = lengthOf(spki, 0);
  const algorithm = lengthOf(spki, outer.contentStart);
  const bits = lengthOf(spki, algorithm.end);
  return spki.slice(bits.contentStart + 1, bits.end);
}

interface Element {
  readonly contentStart: number;
  readonly end: number;
}

/** One DER element's boundaries, read only far enough to walk a `SubjectPublicKeyInfo`. */
function lengthOf(body: Uint8Array, offset: number): Element {
  let at = offset + 1;
  const first = body[at] as number;
  if (first < 0x80) {
    return { contentStart: at + 1, end: at + 1 + first };
  }
  const count = first & 0x7f;
  let length = 0;
  for (let index = 1; index <= count; index += 1) {
    length = length * 0x256 + (body[at + index] as number);
  }
  at += 1 + count;
  return { contentStart: at, end: at + length };
}

function serialBytes(hex: string): Uint8Array {
  const padded = hex.length % 2 === 0 ? hex : `0${hex}`;
  let bytes: number[] = [];
  for (let at = 0; at < padded.length; at += 2) {
    bytes.push(Number.parseInt(padded.slice(at, at + 2), 16));
  }
  while (bytes.length > 1 && bytes[0] === 0) {
    bytes = bytes.slice(1);
  }
  if (((bytes[0] as number) & 0x80) !== 0) {
    bytes.unshift(0);
  }
  return Uint8Array.from(bytes);
}

function extension(oid: string, critical: boolean, value: Uint8Array): Uint8Array {
  return sequence(oidNode(oid), ...(critical ? [tlv(0x01, Uint8Array.of(0xff))] : []), value);
}

function nameNode(commonName: string): Uint8Array {
  return sequence(tlv(0x31, sequence(oidNode(OID_COMMON_NAME), tlv(0x13, new TextEncoder().encode(commonName)))));
}

function integerNode(value: number): Uint8Array {
  const bytes: number[] = [];
  let rest = value;
  do {
    bytes.unshift(rest & 0xff);
    rest = Math.floor(rest / 256);
  } while (rest > 0);
  if ((bytes[0] as number) >= 0x80) {
    bytes.unshift(0);
  }
  return tlv(0x02, Uint8Array.from(bytes));
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

/** A `GeneralizedTime`, which is the one spelling RFC 6960 states for the three instants an answer carries. */
function generalTime(seconds: number): Uint8Array {
  const at = new Date(seconds * 1000);
  const part = (value: number) => String(value).padStart(2, '0');
  const text = `${String(at.getUTCFullYear())}${part(at.getUTCMonth() + 1)}${part(at.getUTCDate())}`
    + `${part(at.getUTCHours())}${part(at.getUTCMinutes())}${part(at.getUTCSeconds())}Z`;
  return tlv(0x18, new TextEncoder().encode(text));
}

function octetNode(content: Uint8Array): Uint8Array {
  return tlv(0x04, content);
}

function bitStringNode(bits: Uint8Array): Uint8Array {
  return tlv(0x03, concat([Uint8Array.of(0), bits]));
}

function sequence(...parts: readonly Uint8Array[]): Uint8Array {
  return tlv(0x30, concat(parts));
}

function wrap(tag: number, content: Uint8Array): Uint8Array {
  return tlv(tag, content);
}

function tlv(tag: number, content: Uint8Array): Uint8Array {
  const length = content.byteLength;
  if (length < 0x80) {
    return concat([Uint8Array.of(tag, length), content]);
  }
  const encoded: number[] = [];
  let rest = length;
  while (rest > 0) {
    encoded.unshift(rest & 0xff);
    rest = Math.floor(rest / 256);
  }
  return concat([Uint8Array.of(tag, 0x80 | encoded.length, ...encoded), content]);
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
