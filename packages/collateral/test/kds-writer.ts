import { constants, generateKeyPairSync, sign as nodeSign, type KeyObject } from 'node:crypto';
import { p384 } from '@noble/curves/nist.js';
import { sha384, sha512 } from '@noble/hashes/sha2.js';

/**
 * A writer for the AMD KDS certificate shapes, so the cases in `kds.test.ts` hand the reader real
 * certificates without storing anybody's served bytes.
 *
 * Every certificate here is signed by a key generated in the run that asks for it. The members the writer
 * emits are the ones X.509 names, and the AMD members are the two extensions the reader binds a chip with:
 * the product name as an IA5String and the hardware id as 64 bytes. The shape those members describe is
 * cited at the declaration in `src/intel-origin.ts`, which is where the suites below are stated as measured
 * facts rather than as guesses: the root and the intermediate carry rsa keys and sign with rsa-pss over
 * SHA-384, MGF1-SHA384 and a 48-byte salt, and the per-chip certificate carries a P-384 key beneath that same
 * suite and no `BasicConstraints` extension.
 *
 * Nothing here stores a byte a vendor wrote. An issuer name is a string a case names, a serial is a number a
 * case names, and a key is drawn fresh, which is what lets one case hand another's key under the same name and
 * ask what the reader makes of a chain that did not sign what it claims to have signed.
 */

const OID_ECDSA_SHA384 = '1.2.840.10045.4.3.3';
const OID_RSASSA_PSS = '1.2.840.113549.1.1.10';
const OID_SHA384 = '2.16.840.1.101.3.4.2.2';
const OID_MGF1 = '1.2.840.113549.1.1.8';
const OID_COMMON_NAME = '2.5.4.3';
const OID_BASIC_CONSTRAINTS = '2.5.29.19';
const OID_PRODUCT_NAME = '1.3.6.1.4.1.3704.1.2';
const OID_HWID = '1.3.6.1.4.1.3704.1.4';

/** The salt length the AMD certificates state and the verifier insists on. */
const SALT_LENGTH = 48;

/** One certificate's key, with the public part spelled as the `SubjectPublicKeyInfo` a certificate carries. */
export interface AmdKeyPair {
  readonly spki: Uint8Array;
  /** Signs with this key, in the form a certificate's own `signatureValue` carries. */
  readonly sign: (message: Uint8Array) => Uint8Array;
  /** The suite `sign` writes, which is what a certificate's algorithm identifier has to name. */
  readonly suite: 'rsa-pss' | 'ecdsa-sha384';
}

/** An authority: the root or the intermediate, with the certificate that states it. */
export interface AmdAuthority {
  readonly name: string;
  readonly key: AmdKeyPair;
  readonly der: Uint8Array;
}

/** A per-chip certificate, with the identity its own extensions state, or null where it states neither. */
export interface AmdChipCertificate {
  readonly der: Uint8Array;
  readonly productName: string | null;
  readonly hwid: Uint8Array | null;
  readonly hwidHex: string | null;
}

/** An RSA key of the size the published roots are bounded by, able to sign the PSS form AMD states. */
export function rsaKeyPair(): AmdKeyPair {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  return {
    spki: der(publicKey),
    suite: 'rsa-pss',
    sign: (message) => Uint8Array.from(nodeSign('sha384', message, {
      key: privateKey,
      padding: constants.RSA_PKCS1_PSS_PADDING,
      saltLength: SALT_LENGTH,
    })),
  };
}

/** A P-384 key for a per-chip certificate, signed by the issuer rather than carrying its own suite. */
export function chipKeyPair(): AmdKeyPair {
  const secret = p384.utils.randomSecretKey();
  return {
    spki: sequence(
      sequence(oidNode('1.2.840.10045.2.1'), oidNode('1.3.132.0.34')),
      bitStringNode(p384.getPublicKey(secret, false)),
    ),
    suite: 'ecdsa-sha384',
    sign: (message) => p384.sign(sha384(message), secret).toBytes('der'),
  };
}

/** The 64 bytes a chip id is, drawn from a label so a case can name the hex it expects back. */
export function hwidOf(label: string): Uint8Array {
  return Uint8Array.from(sha512(new TextEncoder().encode(label)));
}

/** The hardware id as the route spells it and as the reader reports it: 128 lowercase hex characters. */
export function hwidHex(hwid: Uint8Array): string {
  return Array.from(hwid, (one) => one.toString(16).padStart(2, '0')).join('');
}

/**
 * The Milan root: self-signed, an authority, and the name a caller pins.
 *
 * The names here are the writer's own and say what they are, because a chain that borrows a published name is
 * one of the cases the suite runs, and it has to be tellable from the real thing.
 */
export function amdRoot(name = 'Ashaveri Test AMD ARK Milan', key = rsaKeyPair()): AmdAuthority {
  return {
    name,
    key,
    der: certificate({
      subject: name,
      issuer: name,
      serial: 1,
      notBefore: secondsOf('2020-01-01T00:00:00Z'),
      notAfter: secondsOf('2040-01-01T00:00:00Z'),
      subjectKey: key,
      issuerKey: key,
      isCa: true,
    }),
  };
}

/** The intermediate beneath a root, naming that root as its issuer. */
export function amdAsk(root: AmdAuthority, name = 'Ashaveri Test AMD ASK Milan'): AmdAuthority {
  const key = rsaKeyPair();
  return {
    name,
    key,
    der: certificate({
      subject: name,
      issuer: root.name,
      serial: 2,
      notBefore: secondsOf('2020-01-01T00:00:00Z'),
      notAfter: secondsOf('2040-01-01T00:00:00Z'),
      subjectKey: key,
      issuerKey: root.key,
      isCa: true,
    }),
  };
}

/**
 * The per-chip certificate.
 *
 * Both identity extensions are optional here, because a case that asks what the reader makes of a certificate
 * stating none is a case this suite runs: the route publishes the extensions, and an answer without them is a
 * different shape rather than the same shape with a gap in it.
 */
export function amdVcek(
  ask: AmdAuthority,
  input: {
    readonly productName?: string;
    readonly hwid?: Uint8Array;
    readonly notBefore: number;
    readonly notAfter: number;
    readonly serial?: number;
    readonly key?: AmdKeyPair;
  },
): AmdChipCertificate {
  const key = input.key ?? chipKeyPair();
  const bytes = certificate({
    subject: 'Ashaveri Test AMD VCEK',
    issuer: ask.name,
    serial: input.serial ?? 3,
    notBefore: input.notBefore,
    notAfter: input.notAfter,
    subjectKey: key,
    issuerKey: ask.key,
    isCa: null,
    productName: input.productName,
    hwid: input.hwid,
  });
  return {
    der: bytes,
    productName: input.productName ?? null,
    hwid: input.hwid ?? null,
    hwidHex: input.hwid === undefined ? null : hwidHex(input.hwid),
  };
}

/**
 * The two authorities as the chain route sends them: PEM blocks, intermediate first and root second.
 *
 * That is the order the measured answer presents, and the reader is tested against the reverse as well, so
 * nothing in this file or in the reader treats an order as a rule.
 */
export function amdChain(...certificates: readonly Uint8Array[]): Uint8Array {
  return new TextEncoder().encode(certificates.map((one) => pemBlock(one)).join(''));
}

export function secondsOf(text: string): number {
  return Math.floor(Date.parse(text) / 1000);
}

interface CertificateInput {
  readonly subject: string;
  readonly issuer: string;
  readonly serial: number;
  readonly notBefore: number;
  readonly notAfter: number;
  readonly subjectKey: AmdKeyPair;
  readonly issuerKey: AmdKeyPair;
  /** True for an authority, null for a certificate that states no `BasicConstraints` at all. */
  readonly isCa: boolean | null;
  readonly productName?: string;
  readonly hwid?: Uint8Array;
}

/** One `Certificate`, signed by the issuer key over the `TBSCertificate` as it was written. */
function certificate(input: CertificateInput): Uint8Array {
  const algorithm = algorithmNode(input.issuerKey.suite);
  const extensions = [...authorityExtensions(input.isCa), ...chipExtensions(input.productName, input.hwid)];
  const tbs = sequence(
    tlv(0xa0, integerNode(2)),
    integerNode(input.serial),
    algorithm,
    nameNode(input.issuer),
    sequence(timeNode(input.notBefore), timeNode(input.notAfter)),
    nameNode(input.subject),
    input.subjectKey.spki,
    ...(extensions.length === 0 ? [] : [tlv(0xa3, sequence(...extensions))]),
  );
  return sequence(tbs, algorithm, bitStringNode(input.issuerKey.sign(tbs)));
}

function authorityExtensions(isCa: boolean | null): Uint8Array[] {
  if (isCa === null) {
    return [];
  }
  return [extension(OID_BASIC_CONSTRAINTS, true, sequence(booleanNode(isCa)))];
}

function chipExtensions(productName: string | undefined, hwid: Uint8Array | undefined): Uint8Array[] {
  const found: Uint8Array[] = [];
  if (productName !== undefined) {
    found.push(extension(OID_PRODUCT_NAME, false, tlv(0x16, new TextEncoder().encode(productName))));
  }
  if (hwid !== undefined) {
    found.push(extension(OID_HWID, false, hwid));
  }
  return found;
}

function extension(oid: string, critical: boolean, value: Uint8Array): Uint8Array {
  return sequence(oidNode(oid), ...(critical ? [booleanNode(true)] : []), octetNode(value));
}

/**
 * The algorithm identifier, with the rsa-pss parameters spelled the RFC 4055 way.
 *
 * The digest, the mask and the salt are the three the published certificates state, and the verifier this
 * estate uses refuses the suite without them, so a writer that left one out would be testing a refusal rather
 * than a chain.
 */
function algorithmNode(suite: AmdKeyPair['suite']): Uint8Array {
  if (suite === 'ecdsa-sha384') {
    return sequence(oidNode(OID_ECDSA_SHA384));
  }
  return sequence(
    oidNode(OID_RSASSA_PSS),
    sequence(
      tlv(0xa0, sequence(oidNode(OID_SHA384))),
      tlv(0xa1, sequence(oidNode(OID_MGF1), sequence(oidNode(OID_SHA384)))),
      tlv(0xa2, integerNode(SALT_LENGTH)),
    ),
  );
}

function nameNode(commonName: string): Uint8Array {
  return sequence(tlv(0x31, sequence(oidNode(OID_COMMON_NAME), tlv(0x13, new TextEncoder().encode(commonName)))));
}

function der(key: KeyObject): Uint8Array {
  return new Uint8Array(key.export({ type: 'spki', format: 'der' }));
}

function pemBlock(der: Uint8Array): string {
  const body = toBase64(der);
  const lines: string[] = [];
  for (let offset = 0; offset < body.length; offset += 64) {
    lines.push(body.slice(offset, offset + 64));
  }
  return `-----BEGIN CERTIFICATE-----\n${lines.join('\n')}\n-----END CERTIFICATE-----\n`;
}

function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64');
}

function timeNode(seconds: number): Uint8Array {
  const at = new Date(seconds * 1000);
  const part = (value: number) => String(value).padStart(2, '0');
  const year = at.getUTCFullYear();
  const body = `${part(at.getUTCMonth() + 1)}${part(at.getUTCDate())}${part(at.getUTCHours())}${part(at.getUTCMinutes())}${part(at.getUTCSeconds())}Z`;
  return year >= 1950 && year <= 2049
    ? tlv(0x17, new TextEncoder().encode(`${part(year % 100)}${body}`))
    : tlv(0x18, new TextEncoder().encode(`${String(year).padStart(4, '0')}${body}`));
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

function booleanNode(value: boolean): Uint8Array {
  return tlv(0x01, Uint8Array.of(value ? 0xff : 0x00));
}

function octetNode(content: Uint8Array): Uint8Array {
  return tlv(0x04, content);
}

function bitStringNode(bits: Uint8Array): Uint8Array {
  return tlv(0x03, concat([Uint8Array.of(0), bits]));
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

function sequence(...parts: readonly Uint8Array[]): Uint8Array {
  return tlv(0x30, concat(parts));
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
