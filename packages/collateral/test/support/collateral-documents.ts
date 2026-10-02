import { p256 } from '@noble/curves/nist.js';
import { sha256 } from '@noble/hashes/sha2.js';

/**
 * Certificates and signed documents for these tests, written here rather than captured.
 *
 * No answer of the vendor's is stored in this repository, so every document a test hands to the reader is
 * built here and signed by a key generated in the test, from a label in the one case whose bytes are published
 * and so has to come out the same every time its generator runs. What it is built to is the layout the vendor
 * publishes, member for member and word for word, as cited at each declaration in `intel-origin.ts`: the
 * levels under `tcbLevels`, each entry stating its composition as the component numbers of an object under
 * `tcb`, the status in `tcbStatus` with the vendor's own words, the window in `issueDate` and `nextUpdate`
 * inside `tcbInfo`, and the QE Identity's members inside `enclaveIdentity`. The member naming the CPU type
 * is the vendor's `fmspc`, so a test cannot make the identity guard fire by writing a name here that the
 * reader looks for there.
 *
 * Two envelopes are written here, because this package reads two. `signedDocument` writes three base64url
 * parts with the certificates in the header, which is the envelope `readSignedCollateral` decodes and the
 * shape Intel does not answer in. `servedAnswer` writes the answer that address returns, the document member
 * and a hex `signature` member, beside the issuer chain a response header carries, which is what
 * `readServedCollateral` weighs. Material that arrived inside a pack arrives alone, with no response header
 * beside it, so the two are kept apart rather than reconciled from here, and `servedJsonBody` hands a test
 * the vendor's own body with no chain anywhere, precisely so a case can pin the refusal the JWS arm owes it
 * rather than pretend the gap away.
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
 * A root and an issuing CA over two keys the caller names, both P-256 and both CA certificates.
 *
 * The two vendors below are this and nothing else: one hands its keys to the random source, one names them.
 */
function vendorWithKeys(input: {
  readonly rootKey: Uint8Array;
  readonly issuerKey: Uint8Array;
  readonly rootName: string;
  readonly issuerName: string;
  readonly notBefore: number;
  readonly notAfter: number;
}): TestVendor {
  const rootDer = certificate({
    commonName: input.rootName,
    issuerCommonName: input.rootName,
    serial: 1,
    notBefore: input.notBefore,
    notAfter: input.notAfter,
    key: input.rootKey,
    issuerKey: input.rootKey,
    isCa: true,
  });
  const issuerDer = certificate({
    commonName: input.issuerName,
    issuerCommonName: input.rootName,
    serial: 2,
    notBefore: input.notBefore,
    notAfter: input.notAfter,
    key: input.issuerKey,
    issuerKey: input.rootKey,
    isCa: true,
  });
  return { rootDer, issuerDer, signingKey: input.issuerKey, rootDigest: toHex(sha256(rootDer)) };
}

/**
 * A vendor drawn fresh from the random source, for a case that signs and reads inside one run.
 *
 * Two calls with the same names hand back the same distinguished names over different keys, which is what a
 * chain borrowing a trusted name looks like, and that is the point of drawing again: nothing a case trusts may
 * be inferred from the issuer the last case happened to make.
 */
export function testVendor(input: {
  readonly rootName?: string;
  readonly issuerName?: string;
  readonly notBefore?: number;
  readonly notAfter?: number;
} = {}): TestVendor {
  return vendorWithKeys({
    rootKey: p256.utils.randomPrivateKey(),
    issuerKey: p256.utils.randomPrivateKey(),
    rootName: input.rootName ?? 'Test Vendor Root CA',
    issuerName: input.issuerName ?? 'Test Vendor Platform CA',
    notBefore: input.notBefore ?? secondsOf('2026-01-01T00:00:00.000Z'),
    notAfter: input.notAfter ?? secondsOf('2036-01-01T00:00:00.000Z'),
  });
}

/** A P-256 private key read off a label, which is the same key every run that label is written again. */
function keyOfLabel(label: string): Uint8Array {
  return sha256(new TextEncoder().encode(label));
}

/**
 * The vendor a published document is issued by: the same two certificates as `testVendor`, over two keys read
 * off labels rather than off the random source.
 *
 * A document that leaves this repository as data has to come out byte for byte again every time its generator
 * runs, and a random issuer hands every run a different signature to publish. These keys are fixed, so the
 * served answer they sign is the same bytes in the committed vectors and in a reader's hands, and a port that
 * writes `rootDer` to a file can pin it and weigh those bytes for itself. Nothing published by a real vendor is
 * anywhere in them, and nothing here reaches an endpoint to make them.
 */
export function fixtureVendor(): TestVendor {
  return vendorWithKeys({
    rootKey: keyOfLabel('ashaveri-fixture-vendor/root'),
    issuerKey: keyOfLabel('ashaveri-fixture-vendor/issuer'),
    rootName: 'Ashaveri Fixture Vendor Root CA',
    issuerName: 'Ashaveri Fixture Vendor Platform CA',
    notBefore: secondsOf('2020-01-01T00:00:00.000Z'),
    notAfter: secondsOf('2040-01-01T00:00:00.000Z'),
  });
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
 * The answer that address actually returns: the document object and a hex `signature` member, as UTF-8, with
 * no chain anywhere beside it.
 *
 * This is the body shape a real Intel document arrives in, and the JWS arm refuses it, because the certificates
 * a chain walk needs are not inside it. A case in `test/read.test.ts` hands that reader these bytes and reads
 * the refusal, so the gap stays measured rather than remembered. `servedAnswer` below is the same body with the
 * chain the answer actually carries.
 */
export function servedJsonBody(document: Record<string, unknown>): Uint8Array {
  return utf8(JSON.stringify({ ...document, signature: 'ab'.repeat(64) }));
}

/**
 * One served answer, in the two halves it arrives in: the body the origin sent, and the chain that arrived
 * beside it in the response header the document's declaration names.
 */
export interface ServedAnswer {
  readonly body: Uint8Array;
  readonly chain: Uint8Array;
}

/**
 * The text a served body holds for one wrapper member, compact and in the key order the builders above write.
 *
 * These are the bytes a served signature covers, and they are written from the object rather than re-made at
 * the reader's end, because the measured rule is that the signature holds over the span the vendor wrote and
 * not over a sorted one. A writer that reordered these keys would then be signing something other than the
 * text it put in the body, which is the mistake the sorted-key case in `test/served-envelope.test.ts` keeps.
 */
export function servedMemberText(document: Record<string, unknown>, member: string): string {
  const value = document[member];
  if (value === undefined) {
    throw new Error(`the wrapper holds no ${member} member to serve`);
  }
  return JSON.stringify(value);
}

/**
 * The `signature` member of a served answer: the raw `r` and `s` of a P-256 signature over exactly these bytes,
 * as the 128 lowercase hex characters the vendor sends them in. This is the member named by
 * `declaration.signature.served.signatureMember`, which the first case in that test reads against it.
 */
export function servedSignatureMember(text: string, vendor: TestVendor): string {
  return toHex(p256.sign(sha256(utf8(text)), vendor.signingKey).toCompactRawBytes());
}

/** The wrapper the origin answers: the document member's own text, and a hex signature member beside it. */
export function servedWrapperBody(member: string, memberText: string, signature: string): Uint8Array {
  return utf8(`{"${member}":${memberText},"signature":"${signature}"}`);
}

/**
 * The chain header's value, built the way the vendor builds one: two PEM blocks, leaf first and then the root,
 * joined with newlines and URL-encoded so the value holds no literal newline.
 */
export function servedChain(vendor: TestVendor): Uint8Array {
  return servedChainOf([vendor.issuerDer, vendor.rootDer]);
}

/**
 * The same header spelling over blocks a case names itself, in the order it names them: a chain built from one
 * vendor's leaf and another's certificate of the same name is what a walk meets on the way to a borrowed root.
 */
export function servedChainOf(blocks: readonly Uint8Array[]): Uint8Array {
  return utf8(encodeURIComponent(blocks.map((one) => pemBlock(one)).join('')));
}

/**
 * A whole served answer, built from the two pieces above: the wrapper over the document member's own text,
 * signed over exactly that text, and the chain that arrives in the header beside it.
 */
export function servedAnswer(document: Record<string, unknown>, member: string, vendor: TestVendor): ServedAnswer {
  const text = servedMemberText(document, member);
  return {
    body: servedWrapperBody(member, text, servedSignatureMember(text, vendor)),
    chain: servedChain(vendor),
  };
}

function pemBlock(der: Uint8Array): string {
  const body = toBase64(der);
  const lines: string[] = [];
  for (let offset = 0; offset < body.length; offset += 64) {
    lines.push(body.slice(offset, offset + 64));
  }
  return `-----BEGIN CERTIFICATE-----\n${lines.join('\n')}\n-----END CERTIFICATE-----\n`;
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
