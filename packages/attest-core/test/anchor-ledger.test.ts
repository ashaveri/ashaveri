import { describe, expect, it } from 'vitest';
import { readdirSync, readFileSync } from 'node:fs';
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  ANCHOR_FAMILIES,
  ANCHOR_LEDGER_CERTIFICATE_MEMBERS,
  ANCHOR_LEDGER_CONTENT_TYPE,
  ANCHOR_LEDGER_DECLARED_PROTECTED_LABELS,
  ANCHOR_LEDGER_DOCUMENT_MEMBERS,
  ANCHOR_LEDGER_EARLIEST_SECONDS,
  ANCHOR_LEDGER_FILES,
  ANCHOR_LEDGER_LATEST_SECONDS,
  ANCHOR_LEDGER_ROW_MEMBERS,
  ANCHOR_LEDGER_VALIDITY_MEMBERS,
  ANCHOR_LICENCE_CLASSES,
  encodeAnchorLedger,
  parseAnchorLedger,
  sealAnchorLedger,
  verifyAnchorLedger,
  type AnchorFamily,
  type AnchorLedgerDocument,
  type AnchorLedgerRow,
  type AnchorLicenceClass,
} from '../src/anchor-ledger.js';
import { parseCertificate, parseCertificateChain, type ParsedCertificate } from '../src/der.js';
import { AMD_ARK_MILAN_PEM, INTEL_SGX_ROOT_CA_PEM, NVIDIA_DEVICE_IDENTITY_CA_PEM } from '../src/index.js';
import { expectErrorCode, fixture, pemToDer } from './helpers.js';

/**
 * The ledger is read here the way a stranger reads it: this package's own seal path produces a real
 * `COSE_Sign1` over a real body of rows about the bytes this repository ships, and every refusal below is
 * that document broken in exactly one way. A case that failed for two reasons would name a code and prove
 * nothing about it, so each one moves one member, or one byte, or one decision of the caller's, and nothing
 * else changes.
 *
 * The key that seals these documents is a test seed. No ledger in this repository carries the estate's own
 * signature, and that is not caution about a secret: the provenance key may never sit beside the document it
 * signs, in a tree or in a build secret, because the value of a ledger is that the authority shipping these
 * anchors says where they came from, and a signing key inside the checkout would let anybody who can edit the
 * checkout say anything. The published artifact arrives by a ceremony outside this repository, and the tests
 * here exercise the reader against a kid this file pins, which is the same question a caller answers when it
 * names one in `policy.trustAnchors`.
 *
 * The provenance statements these rows carry are this file's own data. The sources, instants and licence
 * classes a shipped ledger states come from the documents that record them, and copying those statements
 * beside digests of real bytes would let a reader of this file mistake a test value for a claim about the
 * estate. What is real here is the bytes, the digests over them, the framing, and the refusals.
 */

const SEED = Uint8Array.from(new Array(32).fill(7));
const PROVENANCE_PUBLIC_KEY = ed25519.getPublicKey(SEED);
const PROVENANCE_KID = sha256(PROVENANCE_PUBLIC_KEY);

/** A second synthetic key, for the cases where the caller pins something other than the one that sealed. */
const OTHER_PUBLIC_KEY = ed25519.getPublicKey(Uint8Array.from(new Array(32).fill(11)));

const TAKEN_AT = 1_772_000_000;
const GENERATED_AT = 1_772_000_001;

const EMBEDDED_INTEL = 'src/trust-anchors.ts#INTEL_SGX_ROOT_CA_PEM';
const EMBEDDED_AMD = 'src/trust-anchors.ts#AMD_ARK_MILAN_PEM';
const EMBEDDED_NVIDIA = 'src/trust-anchors.ts#NVIDIA_DEVICE_IDENTITY_CA_PEM';

const INTEL_BYTES = new TextEncoder().encode(INTEL_SGX_ROOT_CA_PEM);
const AMD_BYTES = new TextEncoder().encode(AMD_ARK_MILAN_PEM);
const NVIDIA_BYTES = new TextEncoder().encode(NVIDIA_DEVICE_IDENTITY_CA_PEM);

const EMBEDDED: ReadonlyMap<string, Uint8Array> = new Map<string, Uint8Array>([
  [EMBEDDED_INTEL, INTEL_BYTES],
  [EMBEDDED_AMD, AMD_BYTES],
  [EMBEDDED_NVIDIA, NVIDIA_BYTES],
]);

/** What this file states beside each row, in the four members no computation can produce. */
interface StatedProvenance {
  readonly family: AnchorFamily;
  readonly origin: string;
  readonly licence: AnchorLicenceClass;
  readonly licenceNote?: string;
}

const STATED: ReadonlyMap<string, StatedProvenance> = new Map<string, StatedProvenance>([
  [EMBEDDED_INTEL, { family: 'intel', origin: 'https://certificates.example/RootCA.pem', licence: 'none-stated' }],
  [EMBEDDED_AMD, { family: 'amd', origin: 'https://source.example/snp-milan.cer', licence: 'apache-2.0' }],
  [EMBEDDED_NVIDIA, { family: 'nvidia', origin: 'https://source.example/verifier_device_root.pem', licence: 'bsd-3-clause' }],
  ['test/fixtures/amd-ark-milan.pem', { family: 'amd', origin: 'https://source.example/snp-milan.cer', licence: 'apache-2.0' }],
  ['test/fixtures/tdx-quote-v4.bin', { family: 'intel', origin: 'https://source.example/blobs.go', licence: 'agpl-3.0', licenceNote: 'quote bytes only, and no code from the repository that published them' }],
  ['test/fixtures/nvidia-hopper-cert-chain.pem', { family: 'nvidia', origin: 'https://source.example/hopperCertChain.txt', licence: 'apache-2.0' }],
]);

const FILES = [...STATED.keys()];

/** The shipped bytes behind a row's name, read from this repository the way the reader reads them. */
function shippedBytesFor(file: string): Uint8Array {
  const embedded = EMBEDDED.get(file);
  if (embedded !== undefined) return embedded;
  return fixture(file.replace('test/fixtures/', ''));
}

/**
 * The half of a row a reader can redo, taken from the bytes it names: the digest of the file as it ships, and
 * the four members a single certificate answers for. A file that does not hold exactly one certificate gets
 * none of them, which is the other arm the layout declares, and the one the captured reports and a
 * five-certificate chain belong to.
 */
function derivedMembers(bytes: Uint8Array): Pick<AnchorLedgerRow, 'digest' | 'subject' | 'serial' | 'spki' | 'validity'> {
  const digest = sha256(bytes);
  let certificates: ParsedCertificate[] = [];
  try {
    certificates = parseCertificateChain(bytes);
  } catch {
    certificates = [];
  }
  const only = certificates.length === 1 ? certificates[0] : undefined;
  if (only === undefined) return { digest };
  return {
    digest,
    subject: only.subject,
    serial: only.serial,
    spki: sha256(only.subjectPublicKeyInfo),
    validity: { from: Math.trunc(only.notBefore / 1000), to: Math.trunc(only.notAfter / 1000) },
  };
}

function rowFor(file: string): AnchorLedgerRow {
  const stated = STATED.get(file);
  if (stated === undefined) throw new Error(`this file states no provenance for ${file}`);
  return {
    family: stated.family,
    file,
    ...derivedMembers(shippedBytesFor(file)),
    origin: stated.origin,
    takenAt: TAKEN_AT,
    licence: stated.licence,
    licenceNote: stated.licenceNote,
  };
}

/** The fixture bytes the reader must be handed, since only the embedded three resolve from source. */
const SHIPPED: ReadonlyMap<string, Uint8Array> = new Map<string, Uint8Array>(
  FILES.filter((file) => file.startsWith('test/fixtures/')).map((file) => [file, shippedBytesFor(file)]),
);

function ledgerOf(rows: readonly AnchorLedgerRow[]): AnchorLedgerDocument {
  return { v: 1, generatedAt: GENERATED_AT, keys: [PROVENANCE_KID], rows };
}

/** The honest document: every row derived from the bytes it names, sealed by this file's synthetic key. */
function honestRows(): AnchorLedgerRow[] {
  return FILES.map((file) => rowFor(file));
}

function sealBody(body: Uint8Array): Uint8Array {
  return sealAnchorLedger(body, SEED).bytes;
}

function sealRows(rows: readonly AnchorLedgerRow[]): Uint8Array {
  return sealBody(encodeAnchorLedger(ledgerOf(rows)));
}

/** The honest ledger, with one row replaced by what the case is about. */
function brokenRow(index: number, changed: Partial<AnchorLedgerRow>): Uint8Array {
  const rows = honestRows();
  const original = rows[index];
  if (original === undefined) throw new Error(`this ledger has no row ${String(index)}`);
  return sealRows(rows.map((row, position) => (position === index ? { ...row, ...changed } : row)));
}

function read(bytes: Uint8Array, trustedKeys: readonly Uint8Array[] = [PROVENANCE_PUBLIC_KEY]) {
  return verifyAnchorLedger(bytes, { trustedKeys, shipped: SHIPPED });
}

/**
 * One byte sequence of a body rewritten in place, where the replacement is exactly as long as what it
 * replaces, so the only thing that changed is the value under test and every length in the document still
 * stands. This is how a case reaches a value no honest writer can produce, a licence outside the declared
 * classes or an integer spelled as a floating-point number: the types of this package will not write them,
 * and a reader has to refuse them anyway. A pattern found twice would mean the case moved two positions and
 * proved neither, so the count is asserted rather than assumed.
 */
function rewrite(body: Uint8Array, pattern: readonly number[], replacement: readonly number[]): Uint8Array {
  const hits: number[] = [];
  for (let index = 0; index + pattern.length <= body.length; index += 1) {
    if (pattern.every((byte, offset) => body[index + offset] === byte)) hits.push(index);
  }
  if (hits.length !== 1) throw new Error(`expected the pattern once in the body and found it ${String(hits.length)} times`);
  if (pattern.length !== replacement.length) throw new Error('a rewrite that changes length is a different document, not a broken one');
  const at = hits[0] as number;
  return Uint8Array.from([...body.slice(0, at), ...replacement, ...body.slice(at + pattern.length)]);
}

/** The head byte of a CBOR text string beside its characters, so a key rewrite hits the key and not a value. */
function textBytes(value: string): number[] {
  return [0x60 | value.length, ...ascii(value)];
}

/** The UTF-8 bytes of a value, for a rewrite that reaches inside one text string rather than at its head. */
function ascii(value: string): number[] {
  return [...new TextEncoder().encode(value)];
}

function bigEndian(value: number): number[] {
  return [(value >> 24) & 0xff, (value >> 16) & 0xff, (value >> 8) & 0xff, value & 0xff];
}

/**
 * The `rows` member cut out of a body, entry and count and all, so the document is whole and names nothing
 * where the layout requires a list. A member cannot be dropped by a rewrite of equal length, because the map
 * header counts its entries, and a renamed member is refused as undefined long before anything misses it.
 */
function dropRowsMember(body: Uint8Array): Uint8Array {
  const rowsKey = textBytes('rows');
  const generatedKey = textBytes('generatedAt');
  const start = singleHit(body, rowsKey);
  const after = singleHit(body, generatedKey);
  if (after <= start) throw new Error('the member cut would run backwards through the document');
  const cut = Uint8Array.from([...body.slice(0, start), ...body.slice(after)]);
  const header = cut[0] as number;
  cut[0] = header - 1;
  return cut;
}

function singleHit(body: Uint8Array, pattern: readonly number[]): number {
  const hits: number[] = [];
  for (let index = 0; index + pattern.length <= body.length; index += 1) {
    if (pattern.every((byte, offset) => body[index + offset] === byte)) hits.push(index);
  }
  if (hits.length !== 1) throw new Error(`expected the pattern once in the body and found it ${String(hits.length)} times`);
  return hits[0] as number;
}

/** A one-row body, for the cases whose byte pattern must be unique. */
function singleRowBody(file: string = EMBEDDED_INTEL): Uint8Array {
  return encodeAnchorLedger(ledgerOf([rowFor(file)]));
}

describe('the anchor provenance ledger', () => {
  it('reads a sealed document and hands back the rows it names', () => {
    const verified = read(sealRows(honestRows()));
    expect(verified.kid).toEqual(PROVENANCE_KID);
    expect(verified.document.rows).toHaveLength(FILES.length);
    expect(verified.document.generatedAt).toBe(GENERATED_AT);
    expect(verified.document.keys).toEqual([PROVENANCE_KID]);
    expect(verified.payloadBytes).toEqual(encodeAnchorLedger(ledgerOf(honestRows())));
    // The reader hands back the bytes the signature covered, so a reviewer can keep them beside the file it
    // was given and say which bytes a verdict was reached over.
    expect(verified.signature).toHaveLength(64);
  });

  it('derives a certificate row from the bytes it names, and a report row carries none of the four', () => {
    const document = read(sealRows(honestRows())).document;
    const intel = document.rows.find((row) => row.file === EMBEDDED_INTEL);
    const quote = document.rows.find((row) => row.file === 'test/fixtures/tdx-quote-v4.bin');
    const chain = document.rows.find((row) => row.file === 'test/fixtures/nvidia-hopper-cert-chain.pem');
    // The Intel root as it ships in the constant, re-read the way anybody with the published file would read
    // it, so a row is held against the certificate rather than against this file's own arithmetic.
    const parsed = parseCertificate(pemToDer(INTEL_BYTES));
    expect(intel?.digest).toEqual(sha256(INTEL_BYTES));
    expect(intel?.spki).toEqual(sha256(parsed.subjectPublicKeyInfo));
    expect(intel?.subject).toEqual(parsed.subject);
    expect(intel?.serial).toEqual(parsed.serial);
    expect(intel?.validity).toEqual({ from: Math.trunc(parsed.notBefore / 1000), to: Math.trunc(parsed.notAfter / 1000) });
    // A captured quote and a five-certificate chain hold no single certificate, so their rows state no
    // subject, no serial, no key digest and no window.
    expect(quote?.spki).toBeUndefined();
    expect(quote?.validity).toBeUndefined();
    expect(quote?.licenceNote).toBe('quote bytes only, and no code from the repository that published them');
    expect(chain?.subject).toBeUndefined();
    expect(chain?.digest).toEqual(sha256(fixture('nvidia-hopper-cert-chain.pem')));
  });

  it('writes the same bytes from the same document every time it is asked', () => {
    const document = ledgerOf(honestRows());
    expect(encodeAnchorLedger(document)).toEqual(encodeAnchorLedger(document));
    expect(sealRows(document.rows)).toEqual(sealRows(document.rows));
  });

  it('reads the body it hands back through the same layout rules the envelope passes', () => {
    const verified = read(sealRows(honestRows()));
    expect(parseAnchorLedger(verified.payloadBytes, { shipped: SHIPPED })).toEqual(verified.document);
  });

  it('refuses the ledger body handed over unsealed', () => {
    // The artifact this package commits beside the bytes it describes is the unsigned body, and a reader of it
    // is being shown a statement nobody signed. Refused by name, so nobody reads a draft as evidence.
    expectErrorCode(() => read(encodeAnchorLedger(ledgerOf(honestRows()))), 'ANCHOR_LEDGER_NOT_SEALED');
  });
});

describe('a sealed ledger broken in exactly one way', () => {
  it('refuses a row whose digest is not thirty-two bytes', () => {
    expectErrorCode(() => read(brokenRow(0, { digest: new Uint8Array(31).fill(2) })), 'ANCHOR_LEDGER_BAD_DOCUMENT');
  });

  it('refuses a row whose digest is not the bytes it names', () => {
    expectErrorCode(() => read(brokenRow(0, { digest: sha256(AMD_BYTES) })), 'ANCHOR_LEDGER_DIGEST_MISMATCH');
  });

  it('refuses a row naming a file this package does not ship', () => {
    // The drift this document exists to catch, spelled from the ledger's side: a row about bytes nobody added.
    expectErrorCode(
      () => read(brokenRow(0, { file: 'test/fixtures/added-beside-the-ledger.pem' })),
      'ANCHOR_LEDGER_FILE_UNNAMED',
    );
  });

  it('refuses a row naming a shipped file whose bytes were not handed over', () => {
    expectErrorCode(
      () => verifyAnchorLedger(sealRows(honestRows()), { trustedKeys: [PROVENANCE_PUBLIC_KEY] }),
      'ANCHOR_LEDGER_BYTES_UNAVAILABLE',
    );
  });

  it('refuses a row whose spki was not derived from the bytes it names', () => {
    const borrowed = sha256(parseCertificate(pemToDer(AMD_BYTES)).subjectPublicKeyInfo);
    expectErrorCode(() => read(brokenRow(0, { spki: borrowed })), 'ANCHOR_LEDGER_SPKI_MISMATCH');
  });

  it('refuses a row that states one certificate member without the other three', () => {
    expectErrorCode(() => read(brokenRow(0, { serial: undefined })), 'ANCHOR_LEDGER_BAD_DOCUMENT');
  });

  it('refuses a row that states certificate members for bytes holding several certificates', () => {
    const chainBytes = fixture('nvidia-hopper-cert-chain.pem');
    const leaf = parseCertificateChain(chainBytes)[0];
    if (leaf === undefined) throw new Error('the tracked chain holds no leaf to copy');
    const stated = STATED.get('test/fixtures/nvidia-hopper-cert-chain.pem');
    if (stated === undefined) throw new Error('this file states no provenance for the tracked chain');
    expectErrorCode(
      () =>
        read(
          sealRows([
            {
              family: stated.family,
              file: 'test/fixtures/nvidia-hopper-cert-chain.pem',
              digest: sha256(chainBytes),
              subject: leaf.subject,
              serial: leaf.serial,
              spki: sha256(leaf.subjectPublicKeyInfo),
              validity: { from: Math.trunc(leaf.notBefore / 1000), to: Math.trunc(leaf.notAfter / 1000) },
              origin: stated.origin,
              takenAt: TAKEN_AT,
              licence: stated.licence,
            },
          ]),
        ),
      'ANCHOR_LEDGER_SPKI_MISMATCH',
    );
  });

  it('refuses a row that states certificate members for bytes that hold no certificate', () => {
    const quote = honestRows().find((row) => row.file === 'test/fixtures/tdx-quote-v4.bin');
    if (quote === undefined) throw new Error('this ledger holds no quote row');
    expectErrorCode(
      () =>
        read(
          sealRows([
            {
              ...quote,
              subject: new Uint8Array([0x30, 0x00]),
              serial: new Uint8Array([0x02, 0x01, 0x01]),
              spki: new Uint8Array(32).fill(3),
              validity: { from: 1_600_000_000, to: 1_700_000_000 },
            },
          ]),
        ),
      'ANCHOR_LEDGER_SPKI_MISMATCH',
    );
  });

  it('refuses a row stating a licence class outside the four the format declares', () => {
    const body = rewrite(singleRowBody(), textBytes('none-stated'), textBytes('cc0-license'));
    expectErrorCode(() => read(sealBody(body)), 'ANCHOR_LEDGER_LICENCE_UNKNOWN');
  });

  it('refuses an instant that is not a whole number of seconds inside the band', () => {
    // The two shapes of one mistake a caller can hand: an instant counted in milliseconds, which is this
    // document's own row moved to a unit no reader weighs, and one before the band opens.
    expectErrorCode(() => read(brokenRow(0, { takenAt: TAKEN_AT * 1000 })), 'ANCHOR_LEDGER_INSTANT_OUT_OF_RANGE');
    expectErrorCode(
      () => read(brokenRow(0, { takenAt: ANCHOR_LEDGER_EARLIEST_SECONDS - 1 })),
      'ANCHOR_LEDGER_INSTANT_OUT_OF_RANGE',
    );
    expectErrorCode(
      () => read(sealRowsWithInstant(ANCHOR_LEDGER_LATEST_SECONDS + 1)),
      'ANCHOR_LEDGER_INSTANT_OUT_OF_RANGE',
    );
  });

  it('refuses an instant written as a floating-point number rather than as an integer', () => {
    // No honest writer produces this document, so the break is at the byte level: an integer's five-byte head
    // changed to a float32's, same length and same value, and a reader that could not tell them apart after
    // the decode would be holding one map entry where the signed bytes carried two spellings.
    const body = rewrite(singleRowBody(), [0x1a, ...bigEndian(TAKEN_AT)], [0xfa, ...bigEndian(TAKEN_AT)]);
    expectErrorCode(() => read(sealBody(body)), 'ANCHOR_LEDGER_BAD_DOCUMENT');
  });

  it('refuses a row carrying a member this version does not define', () => {
    const body = rewrite(singleRowBody(), textBytes('origin'), textBytes('output'));
    expectErrorCode(() => read(sealBody(body)), 'ANCHOR_LEDGER_BAD_DOCUMENT');
  });

  it('refuses a document that names no rows at all', () => {
    expectErrorCode(() => read(sealBody(dropRowsMember(singleRowBody()))), 'ANCHOR_LEDGER_BAD_DOCUMENT');
  });

  it('refuses a ledger declaring a version this package does not read', () => {
    expectErrorCode(
      () => read(sealBody(encodeAnchorLedger({ ...ledgerOf(honestRows()), v: 2 as 1 }))),
      'ANCHOR_LEDGER_UNSUPPORTED_VERSION',
    );
  });

  it('refuses a text member carrying a character that ends the row it prints on', () => {
    // One byte of an origin moved to a line feed, which is the character a log reader would meet as the end
    // of a row and this reader refuses before it keeps the value.
    const body = rewrite(singleRowBody(), ascii('certificates.example'), ascii('certificates.exa\nple'));
    expectErrorCode(() => read(sealBody(body)), 'ANCHOR_LEDGER_BAD_DOCUMENT');
  });

  it('refuses a licence note that states nothing', () => {
    const quote = honestRows().find((row) => row.file === 'test/fixtures/tdx-quote-v4.bin');
    if (quote === undefined) throw new Error('this ledger holds no quote row');
    expectErrorCode(() => read(sealRows([{ ...quote, licenceNote: '' }])), 'ANCHOR_LEDGER_BAD_DOCUMENT');
  });

  it('refuses a key id that is not thirty-two bytes', () => {
    expectErrorCode(
      () => read(sealBody(encodeAnchorLedger({ ...ledgerOf(honestRows()), keys: [new Uint8Array(31).fill(4)] }))),
      'ANCHOR_LEDGER_BAD_DOCUMENT',
    );
  });
});

describe('what a reader will trust', () => {
  it('refuses a call that names no pin, and never passes for one', () => {
    const sealed = sealRows(honestRows());
    expectErrorCode(() => verifyAnchorLedger(sealed, { shipped: SHIPPED }), 'ANCHOR_LEDGER_PIN_MISSING');
    expectErrorCode(
      () => verifyAnchorLedger(sealed, { trustedKeys: [], shipped: SHIPPED }),
      'ANCHOR_LEDGER_PIN_MISSING',
    );
    // The same absence beside a body nobody sealed: the call is refused before a byte of the document is read,
    // so nobody learns what an unverified ledger claims by watching it be parsed.
    expectErrorCode(
      () => verifyAnchorLedger(encodeAnchorLedger(ledgerOf(honestRows())), { shipped: SHIPPED }),
      'ANCHOR_LEDGER_PIN_MISSING',
    );
  });

  it('refuses a ledger sealed by another key than the one the caller pinned', () => {
    expectErrorCode(() => read(sealRows(honestRows()), [OTHER_PUBLIC_KEY]), 'ANCHOR_LEDGER_PIN_MISMATCH');
  });

  it('refuses a sealed ledger whose signature was moved by one byte', () => {
    const bytes = Uint8Array.from(sealRows(honestRows()));
    const last = bytes.length - 1;
    bytes[last] = ((bytes[last] ?? 0) ^ 0x01) & 0xff;
    expectErrorCode(() => read(bytes), 'BAD_SIGNATURE');
  });

  it('refuses a ledger that does not name the kid that sealed it among its own keys', () => {
    // The signature is good and the caller's pin is satisfied; what disagrees is the document with itself,
    // which is the finding a reader owes whoever is deciding whether this row set was rotated.
    const forged = { ...ledgerOf(honestRows()), keys: [sha256(OTHER_PUBLIC_KEY)] };
    expectErrorCode(() => read(sealBody(encodeAnchorLedger(forged))), 'ANCHOR_LEDGER_KEY_UNDECLARED');
  });

  it('refuses a document whose protected header names another container', () => {
    // One content type tells the family's six documents apart. The bytes below are a valid `COSE_Sign1` over
    // four elements whose header names a document that is not a ledger, and the refusal arrives before any row
    // is read, so a pack is never reported as provenance about an anchor.
    const bytes = rewrite(
      sealRows([rowFor(EMBEDDED_INTEL)]),
      [...new TextEncoder().encode(ANCHOR_LEDGER_CONTENT_TYPE)],
      [...new TextEncoder().encode('ashaveri/anchor-provenancx')],
    );
    expectErrorCode(() => read(bytes), 'ANCHOR_LEDGER_BAD_HEADER');
  });

  it('refuses an envelope that is not the four elements a COSE_Sign1 writes', () => {
    const sealed = sealRows([rowFor(EMBEDDED_INTEL)]);
    expectErrorCode(() => read(sealed.slice(0, sealed.length - 1)), 'ANCHOR_LEDGER_NOT_SEALED');
  });

  it('verifies under a pin that names one key among several', () => {
    expect(() => read(sealRows(honestRows()), [OTHER_PUBLIC_KEY, PROVENANCE_PUBLIC_KEY])).not.toThrow();
  });
});

describe('the layout stated three times', () => {
  const coseSource = readFileSync(new URL('../../receipt/src/cose.ts', import.meta.url), 'utf8');

  it('names the same members in the reader, the CDDL and the twin', () => {
    // The row block reaches the four certificate members through a group, so the format's side of the pairing
    // is the block plus the arm that names them, read out of the file rather than written down again here.
    const declared = [...cddlMembers('Ashaveri-Anchor-Row'), ...cddlMembers('Certificate-Facts')].sort();
    expect(declared).toEqual([...ANCHOR_LEDGER_ROW_MEMBERS].sort());
    expect(Object.keys(twin.$defs.row.properties).sort()).toEqual([...ANCHOR_LEDGER_ROW_MEMBERS].sort());
    expect(twin.$defs.row.required).toEqual(['family', 'file', 'digest', 'origin', 'takenAt', 'licence']);
    expect(twin.$defs.row.oneOf?.[0]?.required).toEqual([...ANCHOR_LEDGER_CERTIFICATE_MEMBERS]);

    expect([...cddlMembers('Ashaveri-Anchor-Provenance-Document')].sort()).toEqual(
      [...ANCHOR_LEDGER_DOCUMENT_MEMBERS].sort(),
    );
    expect(Object.keys(twin.$defs.document.properties).sort()).toEqual([...ANCHOR_LEDGER_DOCUMENT_MEMBERS].sort());
    expect(twin.$defs.document.required).toEqual(['v', 'generatedAt', 'keys', 'rows']);

    expect([...cddlMembers('Ashaveri-Anchor-Validity')].sort()).toEqual([...ANCHOR_LEDGER_VALIDITY_MEMBERS].sort());
    expect(Object.keys(twin.$defs.validity.properties).sort()).toEqual([...ANCHOR_LEDGER_VALIDITY_MEMBERS].sort());

    // Nothing in the format leaves a map open, and nothing in the projection pretends otherwise.
    for (const rule of ['Ashaveri-Anchor-Provenance-Document', 'Ashaveri-Anchor-Row', 'Ashaveri-Anchor-Validity', 'Ashaveri-Anchor-Provenance-Protected-Header']) {
      expect(cddlRule(rule).includes('...'), `${rule} closes`).toBe(false);
    }
    expect(twin.$defs.document.additionalProperties, 'the document closes in the twin').toBe(false);
    expect(twin.$defs.row.additionalProperties, 'the row closes in the twin').toBe(false);
    expect(twin.$defs.validity.additionalProperties, 'the window closes in the twin').toBe(false);
  });

  it('declares one set of classes and one band in every voice that states them', () => {
    expect(cddlValues('Ashaveri-Anchor-Family')).toEqual([...ANCHOR_FAMILIES]);
    expect(twin.$defs.anchorFamily.enum).toEqual([...ANCHOR_FAMILIES]);
    expect(cddlValues('Ashaveri-Licence-Class')).toEqual([...ANCHOR_LICENCE_CLASSES]);
    expect(twin.$defs.licenceClass.enum).toEqual([...ANCHOR_LICENCE_CLASSES]);
    const band = /Ashaveri-Unix-Seconds = uint \.ge (\d+) \.le (\d+)/u.exec(cddl);
    expect([Number(band?.[1]), Number(band?.[2])], 'the band the CDDL states').toEqual([
      ANCHOR_LEDGER_EARLIEST_SECONDS,
      ANCHOR_LEDGER_LATEST_SECONDS,
    ]);
    expect([twin.$defs.unixSeconds.minimum, twin.$defs.unixSeconds.maximum], 'the band the twin states').toEqual([
      ANCHOR_LEDGER_EARLIEST_SECONDS,
      ANCHOR_LEDGER_LATEST_SECONDS,
    ]);
    expect(twin.$defs.row.properties.takenAt?.$ref).toBe('#/$defs/unixSeconds');
    expect(twin.$defs.document.properties.generatedAt?.$ref).toBe('#/$defs/unixSeconds');
  });

  it('names the content type once in the family, once in the format and once in the reader', () => {
    // Three statements of one string, because the ledger's reader lives in the package that ships the anchors
    // and shares no module with the package that declares the family's content types. Tied here rather than
    // trusted: a fourth spelling, or one of these three moved, is a document no reader opens.
    const declared = /export const ANCHOR_PROVENANCE_CONTENT_TYPE = '([^']+)';/u.exec(coseSource);
    expect(declared?.[1], 'what packages/receipt/src/cose.ts declares').toBe(ANCHOR_LEDGER_CONTENT_TYPE);
    const header = cddlRule('Ashaveri-Anchor-Provenance-Protected-Header');
    const typ = /3:\s*"([^"]+)"/u.exec(header);
    expect(typ?.[1], 'what anchor-provenance.cddl declares at label 3').toBe(ANCHOR_LEDGER_CONTENT_TYPE);
    expect(twin.properties.protectedHeader.properties.typ.const).toBe(ANCHOR_LEDGER_CONTENT_TYPE);
  });

  it('closes against the same three header labels the family signs with', () => {
    const labels = cddlRule('Ashaveri-Anchor-Provenance-Protected-Header')
      .split('\n')
      .slice(1)
      .map((line) => /^\s*(-?\d+):/u.exec((line.split(';')[0] ?? '').trim())?.[1])
      .filter((label): label is string => typeof label === 'string')
      .map((label) => Number(label));
    expect(labels.sort((a, b) => a - b)).toEqual([...ANCHOR_LEDGER_DECLARED_PROTECTED_LABELS].sort());
    expect(labels, 'the header names three labels and the block declares no other').toHaveLength(3);
  });

  it('holds the roster of shipped files against the directory that holds them', () => {
    // The reader's roster and the repository's own fixture directory are one list or a row naming a file that
    // exists answers `ANCHOR_LEDGER_FILE_UNNAMED`, which sends a reviewer to a file that is standing right
    // there. The embedded three are named from the source that holds them, and a constant moved there arrives
    // as this case going red.
    const onDisk = fixtureNames();
    expect([...ANCHOR_LEDGER_FILES].sort()).toEqual([EMBEDDED_INTEL, EMBEDDED_AMD, EMBEDDED_NVIDIA, ...onDisk].sort());
    expect(onDisk).toHaveLength(10);
    expect(ANCHOR_LEDGER_FILES.filter((file) => file.startsWith('test/fixtures/')).sort()).toEqual(onDisk);
    expect(embeddedConstantNames()).toEqual([EMBEDDED_INTEL, EMBEDDED_AMD, EMBEDDED_NVIDIA]);
  });
});

/** The fixture directory as it is on disk, the README excluded, since a row claims bytes, not prose. */
function fixtureNames(): string[] {
  return readdirSync(new URL('./fixtures/', import.meta.url))
    .filter((name) => name !== 'README.md')
    .map((name) => `test/fixtures/${name}`);
}

/** The anchor constants this package embeds, read out of the source that ships them. */
function embeddedConstantNames(): string[] {
  const source = readFileSync(new URL('../src/trust-anchors.ts', import.meta.url), 'utf8');
  return [...source.matchAll(/^export const ([A-Z0-9_]+_PEM) = `-----BEGIN/gmu)]
    .map((found) => `src/trust-anchors.ts#${found[1] as string}`);
}

const cddl = readFileSync(new URL('../../receipt/anchor-provenance.cddl', import.meta.url), 'utf8');

interface TwinMember {
  $ref?: string;
  const?: string;
  enum?: string[];
  minimum?: number;
  maximum?: number;
  properties?: Record<string, TwinMember>;
  required?: string[];
}

interface TwinDefinition {
  properties: Record<string, TwinMember>;
  required?: string[];
  oneOf?: { required?: string[] }[];
  additionalProperties?: boolean;
  enum?: string[];
  minimum?: number;
  maximum?: number;
}

const twin = JSON.parse(readFileSync(new URL('../../receipt/schemas/anchor-provenance-v1.schema.json', import.meta.url), 'utf8')) as {
  $defs: {
    document: TwinDefinition;
    row: TwinDefinition;
    validity: TwinDefinition;
    unixSeconds: TwinDefinition;
    anchorFamily: TwinDefinition;
    licenceClass: TwinDefinition;
  };
  properties: { protectedHeader: { properties: { typ: { const?: string } } } };
};

/**
 * The text of one CDDL block, from the line that opens it to the line that closes it. A map opens at a brace
 * and a group of members, which is how the four certificate facts are declared, opens at a parenthesis, and
 * both are the same question to a reader that wants the names inside.
 */
function cddlRule(rule: string): string {
  const opening = new RegExp(`^${rule} = [({]`, 'mu').exec(cddl);
  if (opening === null) throw new Error(`${rule} is not declared in anchor-provenance.cddl`);
  const ends = [cddl.indexOf('\n}', opening.index), cddl.indexOf('\n)', opening.index)].filter((end) => end >= 0);
  if (ends.length === 0) throw new Error(`${rule} never closes in anchor-provenance.cddl`);
  return cddl.slice(opening.index, Math.min(...ends));
}

/**
 * The members one CDDL block names, comments stripped, sorted so the pairing is about names and not order.
 * A member this reader takes is a text label in either of the two spellings the estate's formats use, the
 * receipt family's all-lowercase names and the camelCase ones an epoch inventory writes, because which
 * positions a layout names is the format's answer and a reader that silently dropped a name would tie two
 * lists that both lost it.
 */
function cddlMembers(rule: string): string[] {
  const members: string[] = [];
  for (const line of cddlRule(rule).split('\n').slice(1)) {
    for (const piece of (line.split(';')[0] ?? '').split(',')) {
      const found = /^\s*\??\s*([a-z][a-zA-Z0-9_]*)\s*:/u.exec(piece);
      if (found) members.push(found[1] as string);
    }
  }
  if (members.length === 0) throw new Error(`${rule} declares no member this reader can name`);
  return members;
}

/** The literal values one closed CDDL set declares, in the order the file writes them. */
function cddlValues(rule: string): string[] {
  const line = new RegExp(`^${rule} = (.+)$`, 'mu').exec(cddl)?.[1];
  if (line === undefined) throw new Error(`${rule} is not declared in anchor-provenance.cddl`);
  return [...line.matchAll(/"([^"]+)"/gu)].map((found) => found[1] as string);
}

/** A ledger whose own assembled instant is the number under test, with every row left honest. */
function sealRowsWithInstant(generatedAt: number): Uint8Array {
  return sealBody(encodeAnchorLedger({ ...ledgerOf(honestRows()), generatedAt }));
}
