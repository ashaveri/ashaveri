import { sha256 } from '@noble/hashes/sha2.js';
import {
  ANCHOR_PROVENANCE_CONTENT_TYPE,
  DECLARED_PROTECTED_LABELS,
  FORGES_A_LINE_RANGES,
  ReceiptError,
  decodeClosedDocument,
  decodeCoseSign1,
  decodedMap,
  encodeCanonical,
  equalBytes,
  keyId,
  signCoseSign1,
  signingKeyFromSeed,
  verifyCoseSign1,
  type CoseSign1,
  type ProtectedHeader,
} from '@ashaveri/receipt';
import { AMD_ARK_MILAN_PEM, INTEL_SGX_ROOT_CA_PEM, NVIDIA_DEVICE_IDENTITY_CA_PEM } from './trust-anchors.js';
import { parseCertificateChain, type ParsedCertificate } from './der.js';
import { fail, type AttestationErrorCode } from './errors.js';

/**
 * The anchor provenance ledger: one signed statement of where every trust anchor this package embeds and
 * every certificate it tracks came from, when its bytes were taken from that source, and under which
 * licence class the source stated them.
 *
 * A row is half computation and half claim. The computation is everything a reader holding the file can redo
 * for itself: the digest of the bytes as shipped, and the digest of the SubjectPublicKeyInfo of the one
 * certificate those bytes hold. The claim is the part no computation produces, which is why the document is
 * signed: the source that published the bytes, the instant they were taken, and the licence that source
 * named. `packages/receipt/anchor-provenance.cddl` is the normative statement of the layout and
 * `packages/receipt/schemas/anchor-provenance-v1.schema.json` its machine-readable twin.
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
 * The body is CBOR and the envelope is `COSE_Sign1`, and both are written and read by the module that owns
 * them. `@ashaveri/receipt` supplies the canonical encoder this body is written with, the seal and reader
 * that make and open this envelope, the kid rule that names a key by the digest of its public key, and the
 * printed-line class every text member is walked with before it is kept. What this file holds is the layout
 * the members name below, the roster the rows are checked against, and the code each finding arrives under:
 * the framing rules are stated once, in the package that owns them, and imported here rather than restated
 * beside them. `test/anchor-ledger.test.ts` holds this file's member lists and content type against the
 * declarations `packages/receipt` makes, so a layout that drifts from the format fails rather than diverges.
 */

/** The protected content type that names this document, taken from the family that declares it. */
export const ANCHOR_LEDGER_CONTENT_TYPE = ANCHOR_PROVENANCE_CONTENT_TYPE;

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

/** The COSE header labels this document's protected header closes against, as the framing owner fixes them. */
export const ANCHOR_LEDGER_DECLARED_PROTECTED_LABELS: readonly number[] = DECLARED_PROTECTED_LABELS;

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
 * The printed-line class, built from the ranges `packages/receipt/src/line-text.ts` owns: the control and
 * format characters, the two line separators and the tag block. A value that ends, hides or reorders the row
 * it is printed on cannot be quoted into a review of a ledger, which is the only thing a provenance document
 * is for, so every text member is walked code point by code point before it is kept. Which positions are
 * walked and what the refusal says about the character it stopped on are this file's; the class itself has
 * one owner, and this is a consumer of it rather than a second statement of it.
 */
const FORGES_A_LINE = new RegExp(`[${FORGES_A_LINE_RANGES}]`, 'u');

/** Whether `value` is one of the three platform classes a row may name. */
function isAnchorFamily(value: string): value is AnchorFamily {
  return (ANCHOR_FAMILIES as readonly string[]).includes(value);
}

/** Whether `value` is one of the four licence classes the format declares. */
function isAnchorLicenceClass(value: string): value is AnchorLicenceClass {
  return (ANCHOR_LICENCE_CLASSES as readonly string[]).includes(value);
}

// ---------------------------------------------------------------------------
// The body, written.
//
// The bytes come from `@ashaveri/receipt`'s canonical encoder, the one place this estate decides how a number
// and a map key are spelled: every value in the shortest spelling that holds it, every map key ordered by the
// bytes of the encoded key. Those two rules are Core Deterministic Encoding as RFC 8949 states it, and they
// matter only together: a signature covers bytes, so the writer that produces them has to produce the same
// ones every time, and a reader that rebuilds the signed structure to check it has to rebuild the same bytes
// the issuer signed. Which members a document and a row name, and which of them are absent rather than empty,
// is the layout below, and that part stays this file's.
// ---------------------------------------------------------------------------

/** The body map of one row: the members the layout declares, and only those this row carries. */
function rowToCbor(row: AnchorLedgerRow): Map<string, unknown> {
  const entries: (readonly [string, unknown])[] = [
    ['family', row.family],
    ['file', row.file],
    ['digest', row.digest],
  ];
  if (row.subject !== undefined) entries.push(['subject', row.subject]);
  if (row.serial !== undefined) entries.push(['serial', row.serial]);
  if (row.spki !== undefined) entries.push(['spki', row.spki]);
  if (row.validity !== undefined) {
    entries.push(['validity', new Map<string, unknown>([
      ['from', row.validity.from],
      ['to', row.validity.to],
    ])]);
  }
  entries.push(['origin', row.origin], ['takenAt', row.takenAt], ['licence', row.licence]);
  if (row.licenceNote !== undefined) entries.push(['licenceNote', row.licenceNote]);
  return new Map(entries);
}

/** The CBOR body of a ledger, canonical and deterministic: the same document always writes the same bytes. */
export function encodeAnchorLedger(document: AnchorLedgerDocument): Uint8Array {
  return encodeCanonical(
    new Map<string, unknown>([
      ['v', document.v],
      ['generatedAt', document.generatedAt],
      ['keys', document.keys],
      ['rows', document.rows.map((row) => rowToCbor(row))],
    ]),
  );
}

// ---------------------------------------------------------------------------
// The body, read.
//
// The decode is the receipt package's closed-document rule, the one it reads a signed payload and a protected
// header under: definite lengths only, integers only in their shortest spelling, no floating-point number and
// no simple value at any depth and in a key as much as in a value, no key written twice or out of the
// deterministic order, and nothing past the value it was handed. Each of those is refused where it is still
// distinguishable, because a float wearing an integer and a member written twice are both invisible to
// anything placed after the decode: the two arrive as one map entry, and which of them the bytes carried
// stops having an answer.
//
// What no decoder can answer is which members a layout names, and that stays this file's question. Every
// position below is read, weighed and refused here, under the sentence this layout writes for it; a value the
// family's decoder hands back as something other than what a position declares is refused as that position.
// ---------------------------------------------------------------------------

type Refuse = (detail: string) => never;

/** The body under the closed-document rule, refused as this format's own finding when it is not CBOR at all. */
function decodeBody(bytes: Uint8Array): unknown {
  try {
    return decodeClosedDocument(bytes, 'MALFORMED_CBOR');
  } catch (err) {
    return fail('ANCHOR_LEDGER_BAD_DOCUMENT', framingDetail(err, 'the body is not canonical CBOR as this format writes it'));
  }
}

function memberAt(map: Map<unknown, unknown>, member: string, position: string, refuse: Refuse): unknown {
  const value = map.get(member);
  if (value === undefined) refuse(`${position}.${member} is absent`);
  return value;
}

function bytesAt(map: Map<unknown, unknown>, member: string, position: string, refuse: Refuse): Uint8Array {
  const node = memberAt(map, member, position, refuse);
  if (!(node instanceof Uint8Array)) refuse(`${position}.${member} is not a byte string`);
  return node;
}

function textAt(map: Map<unknown, unknown>, member: string, position: string, refuse: Refuse): string {
  const node = memberAt(map, member, position, refuse);
  if (typeof node !== 'string') refuse(`${position}.${member} is not a text string`);
  return node;
}

function integerAt(map: Map<unknown, unknown>, member: string, position: string, refuse: Refuse): number {
  const node = memberAt(map, member, position, refuse);
  // An integer the decoder cannot hold as a `number` is one outside the range this layout writes, and it
  // arrives as a `bigint`: refused by the same sentence as a text string or a byte string standing in its
  // place, which is what a closed layout owes a position whose type the bytes did not state.
  if (typeof node !== 'number') refuse(`${position}.${member} is not an integer`);
  return node;
}

function mapAt(node: unknown, position: string, refuse: Refuse): Map<unknown, unknown> {
  const map = decodedMap(node);
  if (map === null) refuse(`${position} is not a map`);
  return map;
}

function arrayAt(node: unknown, position: string, refuse: Refuse): readonly unknown[] {
  if (!Array.isArray(node)) refuse(`${position} is not an array`);
  return node as unknown[];
}

/** Every member of a closed map is one the layout names, and not one of the members it requires is absent. */
function assertClosedMembers(
  map: Map<unknown, unknown>,
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

function readInstant(map: Map<unknown, unknown>, member: string, position: string, refuse: Refuse): number {
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
  map: Map<unknown, unknown>,
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
  if (!equalBytes(recomputed, digest)) {
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
  if (!equalBytes(derived, spki)) {
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
  const document = mapAt(decodeBody(body), 'the ledger', refuse);
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
    if (!(entry instanceof Uint8Array) || entry.length !== 32) refuse(`keys[${String(index)}] is not a thirty-two byte key id`);
    return entry;
  });

  const listedRows = arrayAt(memberAt(document, 'rows', 'the ledger', refuse), 'the ledger.rows', refuse);
  if (listedRows.length === 0) refuse('the ledger holds no rows, and the package beside it ships thirteen files');
  const shipped = options.shipped ?? new Map<string, Uint8Array>();
  const rows = listedRows.map((entry, index) => readRow(mapAt(entry, `rows[${String(index)}]`, refuse), index, shipped, refuse));

  return { v: ANCHOR_LEDGER_FORMAT_VERSION, generatedAt, keys, rows };
}

// ---------------------------------------------------------------------------
// The envelope.
//
// The tag, the four elements, the header's three labels, the kid rule, the `Sig_structure` of RFC 9052
// section 4.4 and the strict RFC 8032 check are `packages/receipt/src/cose.ts`, which writes and reads them
// for the whole family and is the one place they are stated. What this file keeps is the answer a reader of a
// ledger is owed: which refusal of the framing arrives under which code of this union, and the pin sentence
// that names every key the caller handed rather than the one the codec was asked about.
// ---------------------------------------------------------------------------

/**
 * Which refusal of the framing owner arrives under which code of this union.
 *
 * A document that is not a `COSE_Sign1` at all, and one whose structure stops short of or runs past the four
 * elements the format writes, are the same finding to whoever holds the bytes: nothing here was sealed. An
 * algorithm other than EdDSA is answered by the header's code rather than by a second one: the receipt family
 * keeps `UNSUPPORTED_ALG` apart from its header refusal because that package names both, and this union has no
 * counterpart to keep apart, so a reader that added one would be giving two voices to the same finding, which
 * is a header that does not hold what the layout declares. A signature that does not verify is `BAD_SIGNATURE`
 * whichever document carried it, exactly as the receipt family shares that one sentence.
 */
const LEDGER_CODE_FOR_FRAMING_REFUSAL: ReadonlyMap<string, AttestationErrorCode> = new Map<string, AttestationErrorCode>([
  ['MALFORMED_CBOR', 'ANCHOR_LEDGER_NOT_SEALED'],
  ['NOT_COSE_SIGN1', 'ANCHOR_LEDGER_NOT_SEALED'],
  ['BAD_PROTECTED_HEADER', 'ANCHOR_LEDGER_BAD_HEADER'],
  ['UNSUPPORTED_ALG', 'ANCHOR_LEDGER_BAD_HEADER'],
  ['KID_MISMATCH', 'ANCHOR_LEDGER_PIN_MISMATCH'],
  ['INVALID_SIGNATURE', 'BAD_SIGNATURE'],
]);

/** The one line the framing owner's refusal carries, or the sentence this file names for a failure of its own. */
function framingDetail(err: unknown, fallback: string): string {
  return err instanceof ReceiptError ? err.message : fallback;
}

/** The framing owner's refusal, answered under this union's code, and anything else rethrown as it arrived. */
function framingRefusal(err: unknown): never {
  if (err instanceof ReceiptError) {
    const code = LEDGER_CODE_FOR_FRAMING_REFUSAL.get(err.code);
    if (code !== undefined) fail(code, err.message);
  }
  throw err;
}

/**
 * The CBOR body and a 32-byte Ed25519 seed in, a sealed ledger and its kid out.
 *
 * The seed is a parameter and never a default, and the kid written into the protected header is `sha256` of
 * the public key the seed derives, which is the lookup rule every signed document of this estate follows and
 * which `keyId` decides rather than this format stating it again. A ledger that found its own signing key
 * would be a document that signed itself, and the signature would say no more than the file already did. A
 * seed of another width is refused by the framing owner's own key rule, `BAD_SIGNING_KEY`, before any byte is
 * signed.
 */
export function sealAnchorLedger(
  body: Uint8Array,
  seed: Uint8Array,
  externalAad: Uint8Array = new Uint8Array(0),
): { readonly bytes: Uint8Array; readonly kid: Uint8Array } {
  const key = signingKeyFromSeed(seed);
  return { bytes: signCoseSign1(body, key, externalAad, ANCHOR_LEDGER_CONTENT_TYPE), kid: key.kid };
}

/**
 * The sealed envelope, opened by the framing owner's reader and answered under this document's codes.
 *
 * The protected header is read under the closed rule inside that reader, because these bytes are inside the
 * signature and a label the layout does not declare is an authenticated parameter. The payload travels as
 * bytes to `parseAnchorLedger`, which reads it under the same closed rule and then answers for every member.
 * The `unprotected` element is only checked to be a map, because the format says a writer may fill it and no
 * signature covers what it holds. An empty document is refused here, by this file's sentence, because there
 * is no structure for a reader to name otherwise.
 */
function readSealed(bytes: Uint8Array): CoseSign1 & { header: ProtectedHeader } {
  if (bytes.length === 0) fail('ANCHOR_LEDGER_NOT_SEALED', 'the document holds nothing');
  try {
    return decodeCoseSign1(bytes, ANCHOR_LEDGER_CONTENT_TYPE);
  } catch (err) {
    return framingRefusal(err);
  }
}

/** The signature, checked by the reader that owns the framing, under the key the caller pinned. */
function verifySealed(bytes: Uint8Array, publicKey: Uint8Array): CoseSign1 & { header: ProtectedHeader } {
  try {
    return verifyCoseSign1(bytes, publicKey, new Uint8Array(0), ANCHOR_LEDGER_CONTENT_TYPE);
  } catch (err) {
    return framingRefusal(err);
  }
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
 *
 * The kid is weighed against the pin before the signature is, by this file and not by the framing's reader,
 * because the refusal a caller of a ledger has to read names every key it pinned beside the kid the document
 * carries, which is the sentence that tells an operator a rotation happened, and the framing's own answer is
 * about the one key it was handed.
 */
export function verifyAnchorLedger(bytes: Uint8Array, options: AnchorLedgerReadOptions): VerifiedAnchorLedger {
  const pins = options.trustedKeys ?? [];
  if (pins.length === 0) {
    fail(
      'ANCHOR_LEDGER_PIN_MISSING',
      'a ledger is verified against a key its caller names, and none was handed: pin the provenance key where the anchors are pinned, in policy.trustAnchors or an equivalent the caller owns',
    );
  }
  const sealed = readSealed(bytes);
  const pinned = pins.find((candidate) => candidate.length === 32 && equalBytes(keyId(candidate), sealed.header.kid));
  if (pinned === undefined) {
    fail(
      'ANCHOR_LEDGER_PIN_MISMATCH',
      `the document names the kid ${hex(sealed.header.kid)} and the caller pinned ${pins.map((candidate) => hex(keyId(candidate))).join(', ')}`,
    );
  }
  const verified = verifySealed(bytes, pinned);
  const document = parseAnchorLedger(verified.payloadBytes, { shipped: options.shipped });
  if (!document.keys.some((declared) => equalBytes(declared, verified.header.kid))) {
    fail(
      'ANCHOR_LEDGER_KEY_UNDECLARED',
      `the kid that sealed this ledger, ${hex(verified.header.kid)}, is not one of the ids the ledger names: ${document.keys.map((declared) => hex(declared)).join(', ')}`,
    );
  }
  return {
    document,
    kid: verified.header.kid,
    protectedBytes: verified.protectedBytes,
    payloadBytes: verified.payloadBytes,
    signature: verified.signature,
  };
}
