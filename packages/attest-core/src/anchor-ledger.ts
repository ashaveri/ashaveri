import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { AMD_ARK_MILAN_PEM, INTEL_SGX_ROOT_CA_PEM, NVIDIA_DEVICE_IDENTITY_CA_PEM } from './trust-anchors.js';
import { parseCertificateChain, type ParsedCertificate } from './der.js';
import { fail } from './errors.js';

/**
 * The anchor provenance ledger: one signed statement of where every trust anchor this package embeds and
 * every certificate it tracks came from, when its bytes were taken from that source, and under which
 * licence class the source stated them.
 *
 * A row is half computation and half claim. The computation is everything a reader holding the file can redo
 * for itself: the digest of the bytes as shipped, and the digest of the SubjectPublicKeyInfo of the one
 * certificate those bytes hold. The claim is the part no computation produces, which is why the document is
 * signed: the source that published the bytes, the instant they were taken, and the licence that source
 * named. `anchor-provenance.cddl` is the normative statement of the layout and
 * `schemas/anchor-provenance-v1.schema.json` its machine-readable twin.
 *
 * The key that verifies a ledger belongs to the reader's caller and to nobody else. This document ships
 * beside the bytes it describes, so a reader that took its verifying key from wherever it liked would be
 * checking a claim about this repository under this repository's own authority, which proves nothing about
 * anything. The pin is the caller's decision, named in the same place every other anchor decision is named
 * (a client of `@ashaveri/sdk` names it in `policy.trustAnchors`), and a call that hands over no pin is
 * refused by name rather than passed. The `keys` list inside the ledger is the issuer's own statement about
 * which keys may stand behind these rows: it is weighed against the sealed header after the signature that
 * covers it, and it never replaces the caller's pin.
 *
 * The body is CBOR and the envelope is `COSE_Sign1`, the same framing the receipt family seals its five
 * documents with, and the ledger's content type is declared in `packages/receipt/src/cose.ts` beside theirs.
 * The two packages share no module, so the framing rules are restated here against that declaration rather
 * than imported: the kid is `sha256` of the public key as `keyId` computes it, the protected header carries
 * the COSE registry's three labels and no other, the `Sig_structure` is RFC 9052 section 4.4 in that order,
 * and numbers go out in the shortest spelling with map keys in Core Deterministic Encoding order, which is
 * what lets a reader rebuild the signed bytes instead of guessing which of several equivalent spellings
 * produced them. `test/anchor-ledger.test.ts` holds each of those against the declaration the receipt
 * package makes, so a restatement that drifts fails rather than diverges.
 */

/** The protected content type that names this document, the sixth in the family `ashaveri/receipt` starts. */
export const ANCHOR_LEDGER_CONTENT_TYPE = 'ashaveri/anchor-provenance';

/** The one version of this layout this package reads. */
export const ANCHOR_LEDGER_FORMAT_VERSION = 1;

/**
 * The band an instant of this document is held to, which is the receipt format's own: a whole number of
 * seconds since the Unix epoch, no smaller than the first and no larger than the last a reader of that
 * format can weigh a stamp against, `EARLIEST_VERIFICATION_SECONDS` and `LATEST_VERIFICATION_SECONDS` in
 * `packages/receipt/src/receipt.ts`. The two ends exclude a reading counted in milliseconds or in
 * microseconds by their magnitude, so a reader never has to guess which unit arrived, and a caller handing a
 * plausible number is met by the band rather than by a second guess about what they meant.
 */
export const ANCHOR_LEDGER_EARLIEST_SECONDS = 1_000_000_000;
export const ANCHOR_LEDGER_LATEST_SECONDS = 4_294_967_295;

/** The three COSE header labels this document's protected header closes against, as the registry fixes them. */
export const ANCHOR_LEDGER_DECLARED_PROTECTED_LABELS: readonly number[] = [1, 3, 4];

/** The members the document map names, in the order the layout declares them. */
export const ANCHOR_LEDGER_DOCUMENT_MEMBERS = ['v', 'generatedAt', 'keys', 'rows'] as const;

/** The members a row names, in the order the layout declares them. */
export const ANCHOR_LEDGER_ROW_MEMBERS = [
  'family',
  'file',
  'digest',
  'subject',
  'serial',
  'spki',
  'validity',
  'origin',
  'takenAt',
  'licence',
  'licenceNote',
] as const;

/**
 * The four members a certificate answers for. They arrive together or not at all, because a row that names
 * one of them is speaking about a certificate, and a row that names two of them about two different
 * certificates is not a row about anything.
 */
export const ANCHOR_LEDGER_CERTIFICATE_MEMBERS = ['subject', 'serial', 'spki', 'validity'] as const;

/** The members of a row's validity window. */
export const ANCHOR_LEDGER_VALIDITY_MEMBERS = ['from', 'to'] as const;

/** Which vendor class a row's bytes belong to: three platforms, because this package verifies three. */
export const ANCHOR_FAMILIES = ['amd', 'intel', 'nvidia'] as const;
export type AnchorFamily = (typeof ANCHOR_FAMILIES)[number];

/**
 * The licence classes the sources of these bytes stated, closed to the four this repository's documents
 * record. `none-stated` is a finding rather than a grant: it says the source published the bytes without
 * naming a code licence behind them, which is the case for Intel's published SGX provisioning root, and it
 * is not a named licence wearing another name.
 */
export const ANCHOR_LICENCE_CLASSES = ['apache-2.0', 'bsd-3-clause', 'agpl-3.0', 'none-stated'] as const;
export type AnchorLicenceClass = (typeof ANCHOR_LICENCE_CLASSES)[number];

/** The three anchors this package embeds, named the way a row names them. */
const EMBEDDED_ANCHOR_FILES = [
  'src/trust-anchors.ts#INTEL_SGX_ROOT_CA_PEM',
  'src/trust-anchors.ts#AMD_ARK_MILAN_PEM',
  'src/trust-anchors.ts#NVIDIA_DEVICE_IDENTITY_CA_PEM',
] as const;

/** The bytes of each embedded anchor as they ship: the PEM text the constant holds, as UTF-8. */
const EMBEDDED_ANCHOR_BYTES: ReadonlyMap<string, Uint8Array> = new Map<string, Uint8Array>([
  [EMBEDDED_ANCHOR_FILES[0], asShippedBytes(INTEL_SGX_ROOT_CA_PEM)],
  [EMBEDDED_ANCHOR_FILES[1], asShippedBytes(AMD_ARK_MILAN_PEM)],
  [EMBEDDED_ANCHOR_FILES[2], asShippedBytes(NVIDIA_DEVICE_IDENTITY_CA_PEM)],
]);

/** Every tracked fixture under `test/fixtures/`, named the way a row names it. */
const TRACKED_FIXTURE_FILES = [
  'test/fixtures/sev-snp-attestation.bin',
  'test/fixtures/sev-snp-ask.pem',
  'test/fixtures/sev-snp-vcek.pem',
  'test/fixtures/amd-ark-milan.pem',
  'test/fixtures/tdx-quote-v4.bin',
  'test/fixtures/intel-sgx-root-ca.pem',
  'test/fixtures/nvidia-hopper-report.bin',
  'test/fixtures/nvidia-hopper-report-bad-signature.bin',
  'test/fixtures/nvidia-hopper-cert-chain.pem',
  'test/fixtures/nvidia-device-identity-ca.pem',
] as const;

/**
 * The whole roster: the thirteen shipped files a row may name. Exported because it is this package's own
 * statement of what ships, and a row naming anything else is the drift this document exists to catch rather
 * than a member no reader has seen.
 */
export const ANCHOR_LEDGER_FILES: readonly string[] = [...EMBEDDED_ANCHOR_FILES, ...TRACKED_FIXTURE_FILES];

/** One row: a claim about one shipped file. */
export interface AnchorLedgerRow {
  readonly family: AnchorFamily;
  readonly file: string;
  /** `sha256` of the named bytes exactly as they ship. */
  readonly digest: Uint8Array;
  /** The certificate's subject as the DER holds it, the RDN sequence content. Present with all four. */
  readonly subject?: Uint8Array;
  /** The TBSCertificate serialNumber as its DER INTEGER content bytes, sign byte included. */
  readonly serial?: Uint8Array;
  /** `sha256` of the whole SubjectPublicKeyInfo element, tag and length included. */
  readonly spki?: Uint8Array;
  /** The window the certificate states for itself, in the same seconds as every other instant here. */
  readonly validity?: { readonly from: number; readonly to: number };
  /** The source that published the bytes, as a URL. */
  readonly origin: string;
  /** The instant the bytes were taken from that source. */
  readonly takenAt: number;
  readonly licence: AnchorLicenceClass;
  readonly licenceNote?: string;
}

/** The signed body: the version, the instant the rows were assembled, the keys the issuer names, the rows. */
export interface AnchorLedgerDocument {
  readonly v: 1;
  readonly generatedAt: number;
  readonly keys: readonly Uint8Array[];
  readonly rows: readonly AnchorLedgerRow[];
}

/** What a reader is handed beside the bytes. */
export interface AnchorLedgerReadOptions {
  /**
   * The caller's pin: the Ed25519 public keys this ledger is verified against, each named by the kid it
   * hashes to. This is where the decision about the provenance key lives, and it is not read out of the
   * document. Empty or absent is a refusal, never a pass.
   */
  readonly trustedKeys?: readonly Uint8Array[];
  /**
   * The tracked fixtures, by the name a row gives them. The three embedded anchors resolve from source and
   * need no help; the bytes under `test/fixtures/` belong to whoever holds the repository, and a row naming
   * one whose bytes were not handed over is refused rather than believed.
   */
  readonly shipped?: ReadonlyMap<string, Uint8Array>;
}

/** A ledger that verified: the body, the key that sealed it, and the bytes the signature covered. */
export interface VerifiedAnchorLedger {
  readonly document: AnchorLedgerDocument;
  readonly kid: Uint8Array;
  readonly protectedBytes: Uint8Array;
  readonly payloadBytes: Uint8Array;
  readonly signature: Uint8Array;
}

function asShippedBytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

/**
 * The printed-line class, restated here for this boundary the way `errors.ts` restates it for a message: the
 * control and format characters, the two line separators and the tag block. A value that ends, hides or
 * reorders the row it is printed on cannot be quoted into a review of a ledger, which is the only thing a
 * provenance document is for, so every text member is walked code point by code point before it is kept.
 */
const FORGES_A_LINE = /[\p{Cc}\p{Cf}\u{2028}\u{2029}\u{e0000}-\u{e007f}]/u;

/** Whether `value` is one of the three platform classes a row may name. */
function isAnchorFamily(value: string): value is AnchorFamily {
  return (ANCHOR_FAMILIES as readonly string[]).includes(value);
}

/** Whether `value` is one of the four licence classes the format declares. */
function isAnchorLicenceClass(value: string): value is AnchorLicenceClass {
  return (ANCHOR_LICENCE_CLASSES as readonly string[]).includes(value);
}

// ---------------------------------------------------------------------------
// The CBOR writer, for the layouts this file names and nothing else.
//
// Values are written in the shortest spelling that holds them and map keys are ordered by the bytes of the
// encoded key, which together are Core Deterministic Encoding as RFC 8949 states it and as the receipt
// family writes its five documents. The two rules matter only together: a signature covers bytes, so the
// writer that produces them has to produce the same ones every time, and a reader that rebuilds the signed
// structure to check it has to rebuild the same bytes the issuer signed.
// ---------------------------------------------------------------------------

/** One CBOR head: a major type and an argument, in the shortest of the spellings that holds it. */
function head(majorType: number, argument: number): number[] {
  const shifted = majorType << 5;
  if (argument < 24) return [shifted | argument];
  if (argument <= 0xff) return [shifted | 24, argument];
  if (argument <= 0xffff) return [shifted | 25, (argument >> 8) & 0xff, argument & 0xff];
  if (argument <= 0xffffffff) {
    return [shifted | 26, (argument >> 24) & 0xff, (argument >> 16) & 0xff, (argument >> 8) & 0xff, argument & 0xff];
  }
  const wide = BigInt(argument);
  return [shifted | 27, ...[7, 6, 5, 4, 3, 2, 1, 0].map((shift) => Number((wide >> BigInt(shift * 8)) & 0xffn))];
}

function writeInteger(value: number): number[] {
  if (!Number.isSafeInteger(value)) throw new Error(`a ledger number past what a reader holds exact cannot be written: ${String(value)}`);
  return value >= 0 ? head(0, value) : head(1, -value - 1);
}

function writeBytes(bytes: Uint8Array): number[] {
  return [...head(2, bytes.length), ...bytes];
}

function writeText(value: string): number[] {
  const encoded = asShippedBytes(value);
  return [...head(3, encoded.length), ...encoded];
}

function writeArray(items: readonly (readonly number[])[]): number[] {
  return [...head(4, items.length), ...items.flat()];
}

function writeMap(entries: readonly (readonly [readonly number[], readonly number[]])[]): number[] {
  const ordered = [...entries].sort((a, b) => compareEncodedKeys(a[0], b[0]));
  return [...head(5, ordered.length), ...ordered.flatMap(([key, value]) => [...key, ...value])];
}

/** Bytewise lexicographic order, a shorter prefix first, which is the ordering Core Deterministic Encoding names. */
function compareEncodedKeys(a: readonly number[], b: readonly number[]): number {
  const shared = Math.min(a.length, b.length);
  for (let index = 0; index < shared; index += 1) {
    const difference = (a[index] ?? 0) - (b[index] ?? 0);
    if (difference !== 0) return difference;
  }
  return a.length - b.length;
}

function toBytes(parts: readonly number[]): Uint8Array {
  return Uint8Array.from(parts);
}

/** The body map: the members a row names, in the order the layout declares them, and only those present. */
function encodeRow(row: AnchorLedgerRow): number[] {
  const entries: (readonly [readonly number[], readonly number[]])[] = [
    [writeText('family'), writeText(row.family)],
    [writeText('file'), writeText(row.file)],
    [writeText('digest'), writeBytes(row.digest)],
  ];
  if (row.subject !== undefined) entries.push([writeText('subject'), writeBytes(row.subject)]);
  if (row.serial !== undefined) entries.push([writeText('serial'), writeBytes(row.serial)]);
  if (row.spki !== undefined) entries.push([writeText('spki'), writeBytes(row.spki)]);
  if (row.validity !== undefined) {
    entries.push([
      writeText('validity'),
      writeMap([
        [writeText('from'), writeInteger(row.validity.from)],
        [writeText('to'), writeInteger(row.validity.to)],
      ]),
    ]);
  }
  entries.push(
    [writeText('origin'), writeText(row.origin)],
    [writeText('takenAt'), writeInteger(row.takenAt)],
    [writeText('licence'), writeText(row.licence)],
  );
  if (row.licenceNote !== undefined) entries.push([writeText('licenceNote'), writeText(row.licenceNote)]);
  return writeMap(entries);
}

/** The CBOR body of a ledger, canonical and deterministic: the same document always writes the same bytes. */
export function encodeAnchorLedger(document: AnchorLedgerDocument): Uint8Array {
  return toBytes(
    writeMap([
      [writeText('v'), writeInteger(document.v)],
      [writeText('generatedAt'), writeInteger(document.generatedAt)],
      [writeText('keys'), writeArray(document.keys.map((kid) => writeBytes(kid)))],
      [writeText('rows'), writeArray(document.rows.map((row) => encodeRow(row)))],
    ]),
  );
}

// ---------------------------------------------------------------------------
// The CBOR reader.
//
// One walker, two readings of it. The strict one is what a signed document is read under: definite lengths
// only, integers only in their shortest spelling, no tag, no floating-point number and no simple value, no
// key written twice, nothing past the value it was handed, and a depth bound at four levels, which is slack
// above the deepest position this layout writes. Each of those is refused where it is still distinguishable,
// because a float wearing an integer and a member written twice are both invisible to anything placed after
// the decode: the two arrive as one map entry, and which of them the bytes carried stops having an answer.
//
// The permissive reading has exactly one customer, the `unprotected` map of the envelope, which the format
// declares a writer may fill and which sits outside the signature. Nothing read under it is a claim about an
// anchor, so a reader that refused a document for what somebody put there would be refusing bytes no
// signature covers.
// ---------------------------------------------------------------------------

const MAX_DEPTH = 4;
const MAJOR_TAG = 6;
const MAJOR_SIMPLE = 7;
const CBOR_BREAK = 0xff;
const COSE_SIGN1_TAG = 18;

/** One decoded CBOR value, named by what it is, so nothing downstream reads a value as `any`. */
type CborValue =
  | { readonly kind: 'integer'; readonly value: number }
  | { readonly kind: 'bytes'; readonly value: Uint8Array }
  | { readonly kind: 'text'; readonly value: string }
  | { readonly kind: 'array'; readonly value: readonly CborValue[] }
  | { readonly kind: 'map'; readonly value: ReadonlyMap<string | number, CborValue> }
  | { readonly kind: 'other'; readonly value: null };

type Refuse = (detail: string) => never;

interface CborItem {
  readonly node: CborValue;
  readonly offset: number;
}

function readArgument(
  bytes: Uint8Array,
  offset: number,
  info: number,
  strict: boolean,
  refuse: Refuse,
): { readonly argument: number; readonly offset: number } {
  if (info < 24) return { argument: info, offset };
  if (info === 31) {
    if (strict) refuse('an indefinite-length item, which a canonical writer never produces');
    return { argument: -1, offset };
  }
  if (info > 27) refuse(`the reserved additional information value ${info}`);
  const width = info === 24 ? 1 : info === 25 ? 2 : info === 26 ? 4 : 8;
  const end = offset + width;
  if (end > bytes.length) refuse('the item ends inside its own length');
  let argument = 0;
  for (let index = offset; index < end; index += 1) argument = argument * 256 + (bytes[index] ?? 0);
  if (strict) {
    const smallest = info === 24 ? 24 : info === 25 ? 0x100 : info === 26 ? 0x10000 : 0x100000000;
    if (argument < smallest) refuse(`a length of ${String(argument)} written in ${String(width)} bytes, which is not its shortest spelling`);
    if (width === 8 && argument > Number.MAX_SAFE_INTEGER) refuse('a number past what a reader holds exactly');
  }
  return { argument, offset: end };
}

function readValue(bytes: Uint8Array, start: number, depth: number, strict: boolean, refuse: Refuse): CborItem {
  const first = bytes[start];
  if (first === undefined) refuse('the value ends before its head');
  const major = first >> 5;
  const info = first & 0x1f;
  const argument = readArgument(bytes, start + 1, info, strict, refuse);
  let offset = argument.offset;

  if (major === MAJOR_SIMPLE) {
    if (strict) refuse('a floating-point number or a simple value, and no position of this layout may be written as one');
    // The permissive reading keeps the shape of the free map without pretending to name its values: which
    // simple value sat here is nobody's claim, and nothing downstream reads it as one.
    return { node: { kind: 'other', value: null }, offset };
  }
  if (major === MAJOR_TAG) {
    if (strict) refuse('a CBOR tag inside a document whose layout names none');
    return readValue(bytes, offset, depth, strict, refuse);
  }

  switch (major) {
    case 0:
      if (!Number.isSafeInteger(argument.argument)) refuse('an unsigned integer past what a reader holds exactly');
      return { node: { kind: 'integer', value: argument.argument }, offset };
    case 1: {
      const negative = -argument.argument - 1;
      if (!Number.isSafeInteger(negative)) refuse('a negative integer past what a reader holds exactly');
      return { node: { kind: 'integer', value: negative }, offset };
    }
    case 2:
    case 3: {
      const end = stringEnd(bytes, offset, argument.argument, refuse);
      const slice = bytes.slice(offset, end);
      if (major === 2) return { node: { kind: 'bytes', value: slice }, offset: end };
      let text: string;
      try {
        text = new TextDecoder('utf-8', { fatal: true }).decode(slice);
      } catch {
        return refuse(`a text string that is not valid UTF-8 at offset ${String(start)}`);
      }
      return { node: { kind: 'text', value: text }, offset: end };
    }
    case 4: {
      if (depth >= MAX_DEPTH) refuse(`a document nested past ${String(MAX_DEPTH)} levels, which is deeper than this layout writes`);
      const items: CborValue[] = [];
      if (argument.argument === -1) {
        for (;;) {
          if (bytes[offset] === CBOR_BREAK) return { node: { kind: 'array', value: items }, offset: offset + 1 };
          const item = readValue(bytes, offset, depth + 1, strict, refuse);
          items.push(item.node);
          offset = item.offset;
        }
      }
      for (let index = 0; index < argument.argument; index += 1) {
        const item = readValue(bytes, offset, depth + 1, strict, refuse);
        items.push(item.node);
        offset = item.offset;
      }
      return { node: { kind: 'array', value: items }, offset };
    }
    default: {
      if (depth >= MAX_DEPTH) refuse(`a document nested past ${String(MAX_DEPTH)} levels, which is deeper than this layout writes`);
      if (major !== 5) refuse(`the CBOR major type ${String(major)}, which this layout never writes`);
      const entries = new Map<string | number, CborValue>();
      const count = argument.argument === -1 ? Number.MAX_SAFE_INTEGER : argument.argument;
      for (let index = 0; index < count; index += 1) {
        if (argument.argument === -1 && bytes[offset] === CBOR_BREAK) return { node: { kind: 'map', value: entries }, offset: offset + 1 };
        const key = readValue(bytes, offset, depth + 1, strict, refuse);
        if (key.node.kind !== 'text' && key.node.kind !== 'integer') {
          refuse(`a map key that is neither text nor an integer at offset ${String(key.offset)}`);
        }
        if (strict && entries.has(key.node.value)) refuse(`a map that writes the key ${String(key.node.value)} twice`);
        const value = readValue(bytes, key.offset, depth + 1, strict, refuse);
        entries.set(key.node.value, value.node);
        offset = value.offset;
      }
      return { node: { kind: 'map', value: entries }, offset };
    }
  }
}

/** The end of a byte string or text string. An indefinite length only reaches here from the free map. */
function stringEnd(bytes: Uint8Array, offset: number, argument: number, refuse: Refuse): number {
  if (argument === -1) {
    let scan = offset;
    while (scan < bytes.length && bytes[scan] !== CBOR_BREAK) scan += 1;
    if (scan >= bytes.length) refuse('an indefinite-length string that never breaks');
    return scan;
  }
  const end = offset + argument;
  if (end > bytes.length) refuse(`a length of ${String(argument)} bytes past the end of the document`);
  return end;
}

// ---------------------------------------------------------------------------
// The layout, read member by member.
// ---------------------------------------------------------------------------

function memberAt(map: ReadonlyMap<string | number, CborValue>, member: string, position: string, refuse: Refuse): CborValue {
  const value = map.get(member);
  if (value === undefined) refuse(`${position}.${member} is absent`);
  return value;
}

function bytesAt(map: ReadonlyMap<string | number, CborValue>, member: string, position: string, refuse: Refuse): Uint8Array {
  const node = memberAt(map, member, position, refuse);
  if (node.kind !== 'bytes') refuse(`${position}.${member} is not a byte string`);
  return node.value;
}

function textAt(map: ReadonlyMap<string | number, CborValue>, member: string, position: string, refuse: Refuse): string {
  const node = memberAt(map, member, position, refuse);
  if (node.kind !== 'text') refuse(`${position}.${member} is not a text string`);
  return node.value;
}

function integerAt(map: ReadonlyMap<string | number, CborValue>, member: string, position: string, refuse: Refuse): number {
  const node = memberAt(map, member, position, refuse);
  if (node.kind !== 'integer') refuse(`${position}.${member} is not an integer`);
  return node.value;
}

function mapAt(node: CborValue, position: string, refuse: Refuse): ReadonlyMap<string | number, CborValue> {
  if (node.kind !== 'map') refuse(`${position} is not a map`);
  return node.value;
}

function arrayAt(node: CborValue, position: string, refuse: Refuse): readonly CborValue[] {
  if (node.kind !== 'array') refuse(`${position} is not an array`);
  return node.value;
}

/** Every member of a closed map is one the layout names, and not one of the members it requires is absent. */
function assertClosedMembers(
  map: ReadonlyMap<string | number, CborValue>,
  declared: readonly string[],
  required: readonly string[],
  position: string,
  refuse: Refuse,
): void {
  for (const key of map.keys()) {
    if (typeof key !== 'string' || !declared.includes(key)) {
      refuse(`${position} carries the member ${String(key)}, which this version does not define`);
    }
  }
  for (const member of required) {
    if (!map.has(member)) refuse(`${position} names no ${member}`);
  }
}

function assertPrintsClean(text: string, position: string, refuse: Refuse): void {
  for (const character of text) {
    if (FORGES_A_LINE.test(character)) {
      const codePoint = character.codePointAt(0);
      refuse(`${position} carries U+${codePoint === undefined ? '?' : codePoint.toString(16).toUpperCase()}, which ends, hides or reorders the row it prints on`);
    }
  }
}

function readInstant(map: ReadonlyMap<string | number, CborValue>, member: string, position: string, refuse: Refuse): number {
  const value = integerAt(map, member, position, refuse);
  if (value < ANCHOR_LEDGER_EARLIEST_SECONDS || value > ANCHOR_LEDGER_LATEST_SECONDS) {
    fail(
      'ANCHOR_LEDGER_INSTANT_OUT_OF_RANGE',
      `${position}.${member} of ${String(value)} is not a whole number of Unix seconds between ${String(
        ANCHOR_LEDGER_EARLIEST_SECONDS,
      )} and ${String(ANCHOR_LEDGER_LATEST_SECONDS)}`,
    );
  }
  return value;
}

function readRow(
  map: ReadonlyMap<string | number, CborValue>,
  index: number,
  shipped: ReadonlyMap<string, Uint8Array>,
  refuse: Refuse,
): AnchorLedgerRow {
  const position = `rows[${String(index)}]`;
  assertClosedMembers(
    map,
    ANCHOR_LEDGER_ROW_MEMBERS,
    ['family', 'file', 'digest', 'origin', 'takenAt', 'licence'],
    position,
    refuse,
  );

  const family = textAt(map, 'family', position, refuse);
  assertPrintsClean(family, `${position}.family`, refuse);
  if (!isAnchorFamily(family)) {
    refuse(`${position}.family is ${family}, and three platforms are the whole of what this package weighs`);
  }

  const file = textAt(map, 'file', position, refuse);
  if (file.length === 0) refuse(`${position}.file names nothing`);
  assertPrintsClean(file, `${position}.file`, refuse);

  const digest = bytesAt(map, 'digest', position, refuse);
  if (digest.length !== 32) refuse(`${position}.digest is ${String(digest.length)} bytes, and a sha256 is thirty-two`);

  const origin = textAt(map, 'origin', position, refuse);
  if (origin.length === 0) refuse(`${position}.origin names no source`);
  assertPrintsClean(origin, `${position}.origin`, refuse);

  const takenAt = readInstant(map, 'takenAt', position, refuse);

  const licence = textAt(map, 'licence', position, refuse);
  assertPrintsClean(licence, `${position}.licence`, refuse);
  if (!isAnchorLicenceClass(licence)) {
    fail(
      'ANCHOR_LEDGER_LICENCE_UNKNOWN',
      `${position}.licence is ${licence}, outside the four classes the format declares: ${ANCHOR_LICENCE_CLASSES.join(', ')}`,
    );
  }

  let licenceNote: string | undefined;
  if (map.has('licenceNote')) {
    const note = textAt(map, 'licenceNote', position, refuse);
    if (note.length === 0) {
      refuse(`${position}.licenceNote holds nothing; say nothing by leaving the member out, and say something by writing it`);
    }
    assertPrintsClean(note, `${position}.licenceNote`, refuse);
    licenceNote = note;
  }

  const carried = ANCHOR_LEDGER_CERTIFICATE_MEMBERS.filter((member) => map.has(member));
  if (carried.length > 0 && carried.length < ANCHOR_LEDGER_CERTIFICATE_MEMBERS.length) {
    refuse(
      `${position} carries ${carried.join(', ')} of the four members a certificate answers for, and they arrive together or not at all`,
    );
  }

  const bytes = resolveShippedBytes(file, shipped, position);
  const recomputed = sha256(bytes);
  if (!sameBytes(recomputed, digest)) {
    fail('ANCHOR_LEDGER_DIGEST_MISMATCH', `${position}: the named bytes hash to ${hex(recomputed)} and the row states ${hex(digest)}`);
  }

  if (carried.length === 0) {
    return { family, file, digest, origin, takenAt, licence, licenceNote };
  }

  const subject = bytesAt(map, 'subject', position, refuse);
  const serial = bytesAt(map, 'serial', position, refuse);
  const spki = bytesAt(map, 'spki', position, refuse);
  if (spki.length !== 32) refuse(`${position}.spki is ${String(spki.length)} bytes, and a sha256 is thirty-two`);
  if (subject.length === 0) refuse(`${position}.subject holds nothing`);
  if (serial.length === 0) refuse(`${position}.serial holds nothing`);

  const validity = mapAt(memberAt(map, 'validity', position, refuse), `${position}.validity`, refuse);
  assertClosedMembers(validity, ANCHOR_LEDGER_VALIDITY_MEMBERS, ['from', 'to'], `${position}.validity`, refuse);
  const from = integerAt(validity, 'from', `${position}.validity`, refuse);
  const to = integerAt(validity, 'to', `${position}.validity`, refuse);
  if (from < 0 || to < 0) refuse(`${position}.validity names an instant before the epoch`);
  if (to <= from) refuse(`${position}.validity closes at ${String(to)}, which is not later than the ${String(from)} it opens at`);

  const certificate = singleCertificate(bytes, position);
  const derived = sha256(certificate.subjectPublicKeyInfo);
  if (!sameBytes(derived, spki)) {
    fail(
      'ANCHOR_LEDGER_SPKI_MISMATCH',
      `${position}: the named bytes carry the SubjectPublicKeyInfo digest ${hex(derived)} and the row states ${hex(spki)}`,
    );
  }

  return {
    family,
    file,
    digest,
    subject,
    serial,
    spki,
    validity: { from, to },
    origin,
    takenAt,
    licence,
    licenceNote,
  };
}

/**
 * The bytes a row names, resolved from source where this package ships them itself and from the caller where
 * it does not. A name outside the roster is the ledger disagreeing with the repository; a name inside it
 * whose bytes were not handed over is a reader that has not been given enough to check.
 */
function resolveShippedBytes(file: string, shipped: ReadonlyMap<string, Uint8Array>, position: string): Uint8Array {
  const embedded = EMBEDDED_ANCHOR_BYTES.get(file);
  if (embedded !== undefined) return embedded;
  if (!ANCHOR_LEDGER_FILES.includes(file)) {
    fail(
      'ANCHOR_LEDGER_FILE_UNNAMED',
      `${position} names ${file}, which is not one of the ${String(ANCHOR_LEDGER_FILES.length)} files this package ships`,
    );
  }
  const handed = shipped.get(file);
  if (handed === undefined) {
    fail('ANCHOR_LEDGER_BYTES_UNAVAILABLE', `${position} names ${file}; open it, hand its bytes over, and read again`);
  }
  return handed;
}

/**
 * The one certificate a row's bytes hold. A row carries the four certificate members only when the named
 * bytes are one certificate, so bytes that hold none or hold several cannot answer for the one key digest the
 * row states, which is the same finding as a key digest copied from another certificate and is refused by the
 * same code with a detail that tells them apart.
 */
function singleCertificate(bytes: Uint8Array, position: string): ParsedCertificate {
  let parsed: ParsedCertificate[];
  try {
    parsed = parseCertificateChain(bytes);
  } catch {
    return fail('ANCHOR_LEDGER_SPKI_MISMATCH', `${position} states certificate members for bytes that hold no parseable certificate`);
  }
  const only = parsed[0];
  if (parsed.length !== 1 || only === undefined) {
    fail(
      'ANCHOR_LEDGER_SPKI_MISMATCH',
      `${position} states one SubjectPublicKeyInfo for bytes that hold ${String(parsed.length)} certificates`,
    );
  }
  return only;
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (const [index, byte] of a.entries()) difference |= byte ^ (b[index] ?? 0);
  return difference === 0;
}

function hex(bytes: Uint8Array): string {
  let out = '';
  for (const byte of bytes) out += byte.toString(16).padStart(2, '0');
  return out;
}

/**
 * Read the CBOR body of a ledger and refuse every row this package cannot stand behind.
 *
 * The body is checked against the bytes it names, which is the whole of what makes it evidence: a row whose
 * digest is not the digest of the file it points at, whose key digest is not the key inside that file, or
 * whose file is not in this package at all, is a claim the repository contradicts. A caller that hands no
 * fixture bytes gets `ANCHOR_LEDGER_BYTES_UNAVAILABLE` for the rows that need them, and never a pass.
 */
export function parseAnchorLedger(
  body: Uint8Array,
  options: { readonly shipped?: ReadonlyMap<string, Uint8Array> } = {},
): AnchorLedgerDocument {
  const refuse: Refuse = (detail) => fail('ANCHOR_LEDGER_BAD_DOCUMENT', detail);
  const item = readValue(body, 0, 0, true, refuse);
  if (item.offset !== body.length) refuse('bytes past the encoded document');
  const document = mapAt(item.node, 'the ledger', refuse);
  assertClosedMembers(document, ANCHOR_LEDGER_DOCUMENT_MEMBERS, ['v', 'generatedAt', 'keys', 'rows'], 'the ledger', refuse);

  const version = integerAt(document, 'v', 'the ledger', refuse);
  if (version !== ANCHOR_LEDGER_FORMAT_VERSION) {
    fail(
      'ANCHOR_LEDGER_UNSUPPORTED_VERSION',
      `the ledger declares version ${String(version)} and this package reads ${String(ANCHOR_LEDGER_FORMAT_VERSION)}`,
    );
  }
  const generatedAt = readInstant(document, 'generatedAt', 'the ledger', refuse);

  const declaredKeys = arrayAt(memberAt(document, 'keys', 'the ledger', refuse), 'the ledger.keys', refuse);
  if (declaredKeys.length === 0) {
    refuse('the ledger names no verifying key, and a ledger nobody can pin is nothing to verify');
  }
  const keys = declaredKeys.map((entry, index) => {
    if (entry.kind !== 'bytes' || entry.value.length !== 32) refuse(`keys[${String(index)}] is not a thirty-two byte key id`);
    return entry.value;
  });

  const listedRows = arrayAt(memberAt(document, 'rows', 'the ledger', refuse), 'the ledger.rows', refuse);
  if (listedRows.length === 0) refuse('the ledger holds no rows, and the package beside it ships thirteen files');
  const shipped = options.shipped ?? new Map<string, Uint8Array>();
  const rows = listedRows.map((entry, index) => readRow(mapAt(entry, `rows[${String(index)}]`, refuse), index, shipped, refuse));

  return { v: ANCHOR_LEDGER_FORMAT_VERSION, generatedAt, keys, rows };
}

// ---------------------------------------------------------------------------
// The envelope.
// ---------------------------------------------------------------------------

const ALG_EDDSA = -8;
const HEADER_ALG = 1;
const HEADER_CONTENT_TYPE = 3;
const HEADER_KID = 4;

/** The `Sig_structure` of RFC 9052 section 4.4, in the order the receipt family builds it. */
function sigStructure(protectedBytes: Uint8Array, externalAad: Uint8Array, payloadBytes: Uint8Array): Uint8Array {
  return toBytes(
    writeArray([writeText('Signature1'), writeBytes(protectedBytes), writeBytes(externalAad), writeBytes(payloadBytes)]),
  );
}

function protectedHeaderFor(kid: Uint8Array): Uint8Array {
  return toBytes(
    writeMap([
      [writeInteger(HEADER_ALG), writeInteger(ALG_EDDSA)],
      [writeInteger(HEADER_CONTENT_TYPE), writeText(ANCHOR_LEDGER_CONTENT_TYPE)],
      [writeInteger(HEADER_KID), writeBytes(kid)],
    ]),
  );
}

/**
 * The CBOR body and a 32-byte Ed25519 seed in, a sealed ledger and its kid out.
 *
 * The seed is a parameter and never a default, and the kid written into the protected header is `sha256` of
 * the public key the seed derives, which is the lookup rule every signed document of this estate follows
 * rather than one this format restates. A ledger that found its own signing key would be a document that
 * signed itself, and the signature would say no more than the file already did.
 */
export function sealAnchorLedger(
  body: Uint8Array,
  seed: Uint8Array,
  externalAad: Uint8Array = new Uint8Array(0),
): { readonly bytes: Uint8Array; readonly kid: Uint8Array } {
  if (seed.length !== 32) throw new Error('an anchor provenance ledger is sealed with a 32-byte Ed25519 seed');
  const kid = sha256(ed25519.getPublicKey(seed));
  const protectedBytes = protectedHeaderFor(kid);
  const signature = ed25519.sign(sigStructure(protectedBytes, externalAad, body), seed);
  const fourElements = writeArray([
    writeBytes(protectedBytes),
    writeMap([]),
    writeBytes(body),
    writeBytes(signature),
  ]);
  return { bytes: toBytes([...head(MAJOR_TAG, COSE_SIGN1_TAG), ...fourElements]), kid };
}

/**
 * The four elements of a `COSE_Sign1`, with nothing inside them decided.
 *
 * The shell is walked permissively and its parts are then read on their own terms: the protected header and
 * the payload go back through the strict rule, because each is a document this layout declares member by
 * member, while the `unprotected` element is only checked to be a map, because the format says a writer may
 * fill it and no signature covers what it holds. A reader that refused a ledger over a value sitting in that
 * map would be refusing bytes that carry no claim about any anchor.
 */
function decodeCoseSign1(bytes: Uint8Array): {
  readonly protectedBytes: Uint8Array;
  readonly payloadBytes: Uint8Array;
  readonly signature: Uint8Array;
  readonly kid: Uint8Array;
} {
  const notSealed: Refuse = (detail) => fail('ANCHOR_LEDGER_NOT_SEALED', detail);
  if (bytes.length === 0) notSealed('the document holds nothing');
  if (bytes[0] !== ((MAJOR_TAG << 5) | COSE_SIGN1_TAG)) {
    notSealed('it does not begin with CBOR tag 18, which is what makes a COSE_Sign1 one');
  }
  const item = readValue(bytes, 1, 1, false, notSealed);
  if (item.offset !== bytes.length) notSealed('bytes past the COSE_Sign1');
  const elements = arrayAt(item.node, 'the COSE_Sign1', notSealed);
  if (elements.length !== 4) notSealed(`it is an array of ${String(elements.length)} elements, not the four a COSE_Sign1 writes`);
  const protectedBytes = elementBytes(elements[0], 'the protected header is not a byte string', notSealed);
  const unprotected = elements[1];
  if (unprotected === undefined || unprotected.kind !== 'map') notSealed('the unprotected map is not a map');
  const payloadBytes = elementBytes(elements[2], 'the payload is not a byte string', notSealed);
  const signature = elementBytes(elements[3], 'the signature is not a byte string', notSealed);
  if (signature.length !== 64) notSealed(`the signature is ${String(signature.length)} bytes, and an Ed25519 one is sixty-four`);
  return { protectedBytes, payloadBytes, signature, kid: parseProtectedHeader(protectedBytes) };
}

function elementBytes(node: CborValue | undefined, detail: string, refuse: Refuse): Uint8Array {
  if (node === undefined || node.kind !== 'bytes') refuse(detail);
  return node.value;
}

/** The `kind` a header refusal names, for a label that may hold nothing at all. */
function kindOf(node: CborValue | undefined): string {
  return node === undefined ? 'nothing' : node.kind;
}

/**
 * The signed header, which closes against the three labels the COSE registry fixes.
 *
 * Closed before any declared label is read, because these bytes are inside the signature: the `Sig_structure`
 * hashes the protected string itself, so a label the layout does not declare is an authenticated parameter,
 * and a reader that walked past one would be holding a different document from the one the issuer signed.
 * An algorithm other than EdDSA is answered by this code too, where the receipt family keeps a separate one
 * for it: a header that carries another suite is not holding what this layout declares, and this union has no
 * algorithm code to say it with.
 */
function parseProtectedHeader(bytes: Uint8Array): Uint8Array {
  const refuse: Refuse = (detail) => fail('ANCHOR_LEDGER_BAD_HEADER', detail);
  const item = readValue(bytes, 0, 0, true, refuse);
  if (item.offset !== bytes.length) refuse('bytes past the encoded header');
  const header = mapAt(item.node, 'the protected header', refuse);
  for (const label of header.keys()) {
    if (typeof label !== 'number' || !ANCHOR_LEDGER_DECLARED_PROTECTED_LABELS.includes(label)) {
      refuse(`it carries a label the format does not define: ${String(label)}`);
    }
  }
  const alg = header.get(HEADER_ALG);
  if (alg === undefined || alg.kind !== 'integer') refuse(`alg must be an integer, got ${kindOf(alg)}`);
  // An algorithm this format does not sign with is answered by the header's own code rather than by a second
  // one: the receipt family keeps `UNSUPPORTED_ALG` apart from its header refusal because that package names
  // both, and this union has no counterpart to keep apart. A reader that added one would be giving two
  // voices to the same finding, which is a header that does not hold what the layout declares.
  if (alg.value !== ALG_EDDSA) refuse(`alg=${String(alg.value)}, and this layout signs with EdDSA only`);
  const kid = header.get(HEADER_KID);
  if (kid === undefined || kid.kind !== 'bytes' || kid.value.length !== 32) refuse('kid must be a 32-byte bstr');
  const contentType = header.get(HEADER_CONTENT_TYPE);
  if (contentType === undefined || contentType.kind !== 'text') refuse(`typ must be a tstr, got ${kindOf(contentType)}`);
  if (contentType.value !== ANCHOR_LEDGER_CONTENT_TYPE) refuse(`typ=${contentType.value}`);
  return kid.value;
}

/**
 * Decode, verify against the caller's pin, and read the rows.
 *
 * The order is the answer to "what does this reader trust". The pin is asked first and refused by name when
 * it is absent, because a reader that verified under a key it chose itself would be reporting this
 * repository's bytes as self-attesting. The envelope comes next, then the kid against the pin, then the
 * signature, and only then the body: a document nobody signed gets no answer about its rows at all, so nobody
 * can learn what an unverified ledger claims by watching it be parsed. The ledger's own `keys` list is weighed
 * last, after the signature that covers it, because before that it is text somebody could have written.
 */
export function verifyAnchorLedger(bytes: Uint8Array, options: AnchorLedgerReadOptions): VerifiedAnchorLedger {
  const pins = options.trustedKeys ?? [];
  if (pins.length === 0) {
    fail(
      'ANCHOR_LEDGER_PIN_MISSING',
      'a ledger is verified against a key its caller names, and none was handed: pin the provenance key where the anchors are pinned, in policy.trustAnchors or an equivalent the caller owns',
    );
  }
  const cose = decodeCoseSign1(bytes);
  const pinned = pins.find((candidate) => candidate.length === 32 && sameBytes(sha256(candidate), cose.kid));
  if (pinned === undefined) {
    fail(
      'ANCHOR_LEDGER_PIN_MISMATCH',
      `the document names the kid ${hex(cose.kid)} and the caller pinned ${pins.map((candidate) => hex(sha256(candidate))).join(', ')}`,
    );
  }
  if (!ed25519.verify(cose.signature, sigStructure(cose.protectedBytes, new Uint8Array(0), cose.payloadBytes), pinned, { zip215: false })) {
    fail('BAD_SIGNATURE', 'the anchor provenance ledger signature does not verify under the key pinned for it');
  }
  const document = parseAnchorLedger(cose.payloadBytes, { shipped: options.shipped });
  if (!document.keys.some((declared) => sameBytes(declared, cose.kid))) {
    fail(
      'ANCHOR_LEDGER_KEY_UNDECLARED',
      `the kid that sealed this ledger, ${hex(cose.kid)}, is not one of the ids the ledger names: ${document.keys.map((declared) => hex(declared)).join(', ')}`,
    );
  }
  return {
    document,
    kid: cose.kid,
    protectedBytes: cose.protectedBytes,
    payloadBytes: cose.payloadBytes,
    signature: cose.signature,
  };
}
