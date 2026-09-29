import { p256 } from '@noble/curves/nist.js';
import { sha256 } from '@noble/hashes/sha2.js';

/**
 * Certificates and signed documents for these tests, written here rather than captured.
 *
 * No answer of the vendor's is stored in this repository, so every document a test hands to the reader is
 * built here and signed by a key generated in the test. What it is built to is the layout the vendor
 * publishes, member for member and word for word, as cited at each declaration in `intel-origin.ts`: the
 * levels under `tcbLevels`, each entry stating its composition as the component numbers of an object under
 * `tcb`, the status in `tcbStatus` with the vendor's own words, the window in `issueDate` and `nextUpdate`
 * inside `tcbInfo`, and the QE Identity's members inside `enclaveIdentity`. The member naming the CPU type
 * is the vendor's `fmspc`, so a test cannot make the identity guard fire by writing a name here that the
 * reader looks for there.
 *
 * One shape is deliberately not the vendor's: the envelope. `signedDocument` writes three base64url parts
 * with the certificates in the header, because that is the envelope `read.ts` decodes, while Intel answers
 * a JSON body with a hex `signature` member and its issuer chain in a response header. Material that
 * arrives inside a pack arrives alone, with no response header beside it, so the two cannot be reconciled
 * from this file, and `servedJsonBody` below hands a test the vendor's own shape precisely so a case can
 * pin the refusal it earns rather than pretend the gap away.
 *
 * Builders here state only the members this path reads, spelled as the vendor spells them. The members a
 * served body states and nothing here reads (`id`, `version`, `pceId`, `tcbType`,
 * `tcbEvaluationDataNumber`, `tdxModule`, `tdxModuleIdentities`) are left out rather than guessed at, and
 * a case that needs one of them is a case about a member this path does not read.
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

/** The number of components a served TCB Info level lists. */
const COMPONENT_COUNT = 16;

/**
 * One level as the vendor's body spells it: `tcb` stating its composition as component numbers, then
 * `tcbDate`, then the word in `tcbStatus`, then `advisoryIDs` where the vendor has one to name.
 */
export interface ServedLevel {
  readonly tcbDate: string;
  readonly tcbStatus: string;
  /** The `svn` of each component, in the order the vendor lists them. Sixteen zeros where a case omits them. */
  readonly svns?: readonly number[];
  /** The `svn` of each TDX component, which a TDX document lists beside the SGX ones. */
  readonly tdxSvns?: readonly number[];
  /** The vendor's PCE SVN, stated beside the component numbers. */
  readonly pceSvn?: number;
  /** The one number a QE Identity level's composition is, spelled `isvsvn`. */
  readonly isvSvn?: number;
  readonly advisoryIDs?: readonly string[];
}

/** Whose component arrays a level states: the SGX document lists one, the TDX document lists two. */
export type ServedComposition = 'sgx' | 'tdx' | 'isvsvn';

function componentNodes(svns: readonly number[]): readonly Record<string, unknown>[] {
  return svns.map((svn) => ({ svn }));
}

function zeros(): number[] {
  return new Array<number>(COMPONENT_COUNT).fill(0);
}

/** The composition member of one level entry, spelled the way the served body spells it. */
export function servedTcb(level: ServedLevel, composition: ServedComposition): Record<string, unknown> {
  if (composition === 'isvsvn') {
    return { isvsvn: level.isvSvn ?? 0 };
  }
  const stated: Record<string, unknown> = {
    sgxtcbcomponents: componentNodes(level.svns ?? zeros()),
    pcesvn: level.pceSvn ?? 0,
  };
  if (composition === 'tdx') {
    stated['tdxtcbcomponents'] = componentNodes(level.tdxSvns ?? zeros());
  }
  return stated;
}

/** One entry of `tcbLevels`, in the member order the vendor's bodies write. */
export function servedLevel(level: ServedLevel, composition: ServedComposition): Record<string, unknown> {
  return {
    tcb: servedTcb(level, composition),
    tcbDate: level.tcbDate,
    tcbStatus: level.tcbStatus,
    ...(level.advisoryIDs === undefined ? {} : { advisoryIDs: [...level.advisoryIDs] }),
  };
}

/** What the vendor writes inside the member its declaration names for the document. */
export function tcbInfoBody(input: {
  readonly fmspc: string;
  readonly issueDate: string;
  readonly nextUpdate: string;
  readonly composition?: ServedComposition;
  readonly levels: readonly ServedLevel[];
}): Record<string, unknown> {
  return {
    issueDate: input.issueDate,
    nextUpdate: input.nextUpdate,
    fmspc: input.fmspc,
    tcbLevels: input.levels.map((level) => servedLevel(level, input.composition ?? 'sgx')),
  };
}

export function tcbInfo(input: {
  readonly fmspc: string;
  readonly issueDate: string;
  readonly nextUpdate: string;
  readonly composition?: ServedComposition;
  readonly levels: readonly ServedLevel[];
}): Record<string, unknown> {
  return { tcbInfo: tcbInfoBody(input) };
}

/** The QE Identity document, whose every named member sits inside `enclaveIdentity`. */
export function qeIdentity(input: {
  readonly issueDate: string;
  readonly nextUpdate: string;
  readonly levels: readonly ServedLevel[];
}): Record<string, unknown> {
  return {
    enclaveIdentity: {
      issueDate: input.issueDate,
      nextUpdate: input.nextUpdate,
      tcbLevels: input.levels.map((level) => servedLevel(level, 'isvsvn')),
    },
  };
}

/**
 * The answer that address actually returns: the document object and a hex `signature` member, as UTF-8.
 *
 * This is the shape a real Intel document arrives in, and this path refuses it, because the certificates a
 * chain walk needs are not inside it. A case in `test/read.test.ts` hands the reader these bytes and reads
 * the refusal, so the gap stays measured rather than remembered.
 */
export function servedJsonBody(document: Record<string, unknown>): Uint8Array {
  return utf8(JSON.stringify({ ...document, signature: 'ab'.repeat(64) }));
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
