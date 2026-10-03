import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha256 } from '@noble/hashes/sha2.js';
// The reader, the writer and the parser this file runs are the built ones, reached the way a client of this
// package reaches them. The source modules name their siblings with `.js` specifiers, which `node
// --experimental-strip-types` resolves as written and so cannot follow from `src/`, and every generator in this
// workspace runs against a build for the same reason: `pnpm build` precedes every generate step.
import {
  ANCHOR_LEDGER_FILES,
  ANCHOR_LEDGER_FORMAT_VERSION,
  encodeAnchorLedger,
  parseAnchorLedger,
  type AnchorFamily,
  type AnchorLedgerDocument,
  type AnchorLedgerRow,
  type AnchorLicenceClass,
} from '../dist/anchor-ledger.js';
import { parseCertificate, parseCertificateChain, type ParsedCertificate } from '../dist/der.js';
import { equalBytes, toHex } from '../dist/events.js';
import { AMD_ARK_MILAN_PEM, INTEL_SGX_ROOT_CA_PEM, NVIDIA_DEVICE_IDENTITY_CA_PEM } from '../dist/trust-anchors.js';

/**
 * The ledger of where this package's trust anchors came from, written from the bytes it ships.
 *
 * A row has two halves and this file keeps them visibly apart. The technical half is computed here and nowhere
 * else: the digest of the bytes as they ship, and, where those bytes hold exactly one certificate, the subject,
 * the serial, the digest of the SubjectPublicKeyInfo and the validity window, all read out of the certificate by
 * this package's own `parseCertificateChain` and then read again through `parseCertificate` over the DER it
 * returned, so a row written from a parser that disagreed with itself is refused rather than published. Nothing
 * in that half is copied from a document, a comment or an earlier run.
 *
 * The provenance half is the part no computation reaches, and it sits in one table below, one entry per shipped
 * file, each naming the file inside this package that records the statement and saying what that record does and
 * does not give. A reviewer who wants to know which fields of a row are arithmetic and which are assertions reads
 * the table; a reader of the emitted document gets the assertions signed. Where a record names a source but no
 * route, the row's `origin` goes no further than the record does, and where a record pins a revision but names no
 * date, the row's instant is the day the bytes entered this repository.
 *
 * The instants in the emitted body are stated, not sampled: a row's instant is the first second of the UTC day
 * its record names, and the document's `generatedAt` is the day this row set was assembled rather than the minute
 * some process ran, because a document that changes on every run cannot be pinned by a digest, checked against a
 * pin, or quoted in a review of the bytes it describes. Two runs of this file write the same bytes, and the
 * drift cases in `test/anchor-ledger.test.ts` are what keep the rows equal to the certificate file they name.
 *
 * The artifact is the body and not a seal. The key that will sign these rows is held outside this repository, so
 * the committed bytes name no verifying key yet, and the ceremony that seals them is what fills `keys`; a reader
 * that reaches `ANCHOR_LEDGER_KEY_UNDECLARED` over the committed file is meeting the absence of that ceremony and
 * not a fault in a row.
 */

const PACKAGE_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const LEDGER_RELATIVE_PATH = 'data/anchor-provenance-v1.cbor';
const LEDGER_PATH = join(PACKAGE_ROOT, LEDGER_RELATIVE_PATH);

/** The instant a row or a document states is the start of a UTC day, so none of them claims an hour nobody named. */
function utcDayStart(year: number, month: number, day: number): number {
  return Math.trunc(Date.UTC(year, month - 1, day) / 1000);
}

/**
 * The day this row set was assembled. It is a statement about the row set, and a row whose source statement
 * arrives later than this date has to be brought here with it, which the check in `main` refuses otherwise.
 */
const ASSEMBLED_AT = utcDayStart(2026, 10, 3);

/**
 * The one id the emitted body names in `keys`: thirty-two zero bytes, which is the layout saying that no key has
 * sealed these rows. The estate's provenance key sits outside this repository, so a committed body naming its id
 * would claim a signature nothing here carries, and a body naming no id at all is refused by the reader.
 */
const UNSEALED_KEY_ID = new Uint8Array(32);

/** One file's provenance, as this repository records it. */
interface ProvenanceStatement {
  readonly file: string;
  readonly family: AnchorFamily;
  readonly origin: string;
  readonly takenAt: number;
  readonly licence: AnchorLicenceClass;
  readonly licenceNote?: string;
  /** A path inside this package that holds the statement above. Checked to exist before a row is written. */
  readonly recordedIn: string;
  /**
   * What that record gives, and which of these fields it does not give. The layout has no member for it, so it
   * is read in review rather than by a reader: it is the reason each entry above is trusted rather than copied.
   */
  readonly asRecorded: string;
}

const INTEL_ROOT_URL = 'https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.pem';
const GO_SEV_GUEST_URL = 'https://github.com/google/go-sev-guest';
const GO_TDX_QPL_URL = 'https://github.com/edgelesssys/go-tdx-qpl';
const AMD_KDS_MILAN_URL = 'https://kdsintf.amd.com/vcek/v1/Milan';
const NVTRUST_ROOT_URL =
  'https://github.com/NVIDIA/nvtrust/blob/858ada9a17f58c482f578414ea2455498fa51e17/guest_tools/gpu_verifiers/local_gpu_verifier/src/verifier/certs/verifier_device_root.pem';
const SDK_SAMPLE_DIRECTORY =
  'https://github.com/NVIDIA/attestation-sdk/blob/73efa3ac1bec28ed7d7f0c0811a6c993e722dbd4/nv-attestation-sdk-cpp/unit-tests/testdata/sample_attestation_data/gpu';
/** The published account of our own capture, which is the source these bytes have. */
const OWN_CAPTURE_RECORD = 'https://github.com/ashaveri/ashaveri/blob/main/packages/attest-core/test/fixtures/README.md';

const PROVENANCE: readonly ProvenanceStatement[] = [
  {
    file: 'src/trust-anchors.ts#INTEL_SGX_ROOT_CA_PEM',
    family: 'intel',
    origin: INTEL_ROOT_URL,
    takenAt: utcDayStart(2026, 9, 11),
    licence: 'none-stated',
    recordedIn: 'src/trust-anchors.ts',
    asRecorded:
      'the comment beside the constant names the route it was downloaded from, the serial and the SHA-256 fingerprint, and the tracked fixture repeats them and names no code licence behind the published anchor, which is the class `none-stated`. The bytes of this row are the bytes of `test/fixtures/intel-sgx-root-ca.pem`.',
  },
  {
    file: 'src/trust-anchors.ts#AMD_ARK_MILAN_PEM',
    family: 'amd',
    origin: GO_SEV_GUEST_URL,
    takenAt: utcDayStart(2026, 9, 10),
    licence: 'apache-2.0',
    recordedIn: 'test/fixtures/README.md',
    asRecorded:
      'the fixtures note names go-sev-guest, Copyright Google LLC, Apache-2.0, and the test certificate `snp-milan.cer` inside it, and pins no revision, so `origin` names the repository. `test/trust-anchors.test.ts` holds the constant and the tracked file to one certificate, so both rows state the same take.',
  },
  {
    file: 'src/trust-anchors.ts#NVIDIA_DEVICE_IDENTITY_CA_PEM',
    family: 'nvidia',
    origin: NVTRUST_ROOT_URL,
    takenAt: utcDayStart(2026, 9, 11),
    licence: 'bsd-3-clause',
    recordedIn: 'test/fixtures/README.md',
    asRecorded:
      'the fixtures note names `certs/verifier_device_root.pem` under the local GPU verifier directory of NVIDIA/nvtrust at commit 858ada9a17f58c482f578414ea2455498fa51e17, and records that the repository carries an Apache-2.0 licence while the verifier package marks its files BSD-3-Clause. The class here is the marking on the file the bytes were read from.',
  },
  {
    file: 'test/fixtures/sev-snp-attestation.bin',
    family: 'amd',
    origin: OWN_CAPTURE_RECORD,
    takenAt: utcDayStart(2026, 6, 17),
    licence: 'apache-2.0',
    recordedIn: 'test/fixtures/README.md',
    asRecorded:
      'a capture of our own: the note names the day, the dstack SEV-SNP confidential VM, the image tag and the command that asked for the report, and attributes the envelope to the dstack project, Copyright 2025 Phala Network, Apache-2.0. It names no upstream route, so `origin` reaches the published account of the capture.',
  },
  {
    file: 'test/fixtures/sev-snp-ask.pem',
    family: 'amd',
    origin: AMD_KDS_MILAN_URL,
    takenAt: utcDayStart(2026, 6, 17),
    licence: 'none-stated',
    recordedIn: 'test/fixtures/README.md',
    asRecorded:
      'the note says the ASK was fetched from AMD KDS for the report chip id and TCB and truncates its own route after the product line, so `origin` goes no further. The same note groups this file with the dstack capture under Apache-2.0 while naming AMD as the publisher of these bytes, and AMD states no code licence at that route: the row carries the class the publisher states and the grouping stays a finding against the note.',
  },
  {
    file: 'test/fixtures/sev-snp-vcek.pem',
    family: 'amd',
    origin: AMD_KDS_MILAN_URL,
    takenAt: utcDayStart(2026, 6, 17),
    licence: 'none-stated',
    recordedIn: 'test/fixtures/README.md',
    asRecorded:
      'the same fetch as the ASK, from AMD KDS for the report chip id and TCB, with the route truncated after the product line in the note itself. The note attributes the file to the dstack capture under Apache-2.0 and names AMD as the publisher; the row carries the class the publisher states.',
  },
  {
    file: 'test/fixtures/amd-ark-milan.pem',
    family: 'amd',
    origin: GO_SEV_GUEST_URL,
    takenAt: utcDayStart(2026, 9, 10),
    licence: 'apache-2.0',
    recordedIn: 'test/fixtures/README.md',
    asRecorded:
      'the note names the go-sev-guest test certificate `snp-milan.cer`, Copyright Google LLC, Apache-2.0, and states that its DER bytes are the production AMD Milan ARK. No revision is pinned, so `origin` names the repository and the instant is the day the file arrived here.',
  },
  {
    file: 'test/fixtures/tdx-quote-v4.bin',
    family: 'intel',
    origin: GO_TDX_QPL_URL,
    takenAt: utcDayStart(2026, 9, 11),
    licence: 'agpl-3.0',
    licenceNote: 'quote bytes only, and no code from the repository that published them',
    recordedIn: 'test/fixtures/README.md',
    asRecorded:
      'the note names the `rawQuoteBlob` member of `blobs/blobs.go` in edgelesssys/go-tdx-qpl, Copyright 2023 Edgeless Systems GmbH, describes it there as an example quote generated on an Intel TDX development platform, and records that only the quote bytes were taken. No revision is pinned, so `origin` names the repository and the instant is the day the file arrived here.',
  },
  {
    file: 'test/fixtures/intel-sgx-root-ca.pem',
    family: 'intel',
    origin: INTEL_ROOT_URL,
    takenAt: utcDayStart(2026, 9, 11),
    licence: 'none-stated',
    recordedIn: 'test/fixtures/README.md',
    asRecorded:
      'the note names Intel as the publisher of this anchor, quotes the route it was downloaded from, and gives the serial, the SHA-256 fingerprint and the window the certificate states. It names no code licence, and Intel DCAP ships no SGX root CA at all, so the class is `none-stated`.',
  },
  {
    file: 'test/fixtures/nvidia-hopper-report.bin',
    family: 'nvidia',
    origin: `${SDK_SAMPLE_DIRECTORY}/hopperAttestationReport.txt`,
    takenAt: utcDayStart(2026, 9, 11),
    licence: 'apache-2.0',
    recordedIn: 'test/fixtures/README.md',
    asRecorded:
      'the note names NVIDIA/attestation-sdk, Copyright 2025 NVIDIA Corporation, Apache-2.0, at commit 73efa3ac1bec28ed7d7f0c0811a6c993e722dbd4, the directory, the file `hopperAttestationReport.txt` and its blob id, and records that the shipped bytes are a byte-for-byte decode of that hex text.',
  },
  {
    file: 'test/fixtures/nvidia-hopper-report-bad-signature.bin',
    family: 'nvidia',
    origin: `${SDK_SAMPLE_DIRECTORY}/hopperAttestationReportInvalidSignature.txt`,
    takenAt: utcDayStart(2026, 9, 11),
    licence: 'apache-2.0',
    recordedIn: 'test/fixtures/README.md',
    asRecorded:
      'the same directory and commit as the report above, the file `hopperAttestationReportInvalidSignature.txt` and its blob id, and the same decode of the hex text upstream keeps. This is the case NVIDIA marks as carrying an invalid signature, so the expected verdict travels with the vendor that published it.',
  },
  {
    file: 'test/fixtures/nvidia-hopper-cert-chain.pem',
    family: 'nvidia',
    origin: `${SDK_SAMPLE_DIRECTORY}/hopperCertChain.txt`,
    takenAt: utcDayStart(2026, 9, 11),
    licence: 'apache-2.0',
    recordedIn: 'test/fixtures/README.md',
    asRecorded:
      'the same directory and commit, the file `hopperCertChain.txt` and its blob id, copied verbatim rather than decoded. The bytes hold five certificates, so the row states no subject, serial, key digest or window: those four are a row about one certificate.',
  },
  {
    file: 'test/fixtures/nvidia-device-identity-ca.pem',
    family: 'nvidia',
    origin: NVTRUST_ROOT_URL,
    takenAt: utcDayStart(2026, 9, 11),
    licence: 'bsd-3-clause',
    recordedIn: 'test/fixtures/README.md',
    asRecorded:
      'the note names `certs/verifier_device_root.pem` from NVIDIA/nvtrust at commit 858ada9a17f58c482f578414ea2455498fa51e17 with its blob id, and records both notices: the repository is Apache-2.0 and the verifier package marks its files BSD-3-Clause. The same bytes are bundled in `src/trust-anchors.ts`.',
  },
];

const STATEMENTS_BY_FILE: ReadonlyMap<string, ProvenanceStatement> = new Map(
  PROVENANCE.map((one) => [one.file, one] as const),
);

/** The bytes of the three embedded anchors, exactly as they ship: the PEM text of each constant, as UTF-8. */
const EMBEDDED_BYTES: ReadonlyMap<string, Uint8Array> = new Map<string, Uint8Array>([
  ['src/trust-anchors.ts#INTEL_SGX_ROOT_CA_PEM', new TextEncoder().encode(INTEL_SGX_ROOT_CA_PEM)],
  ['src/trust-anchors.ts#AMD_ARK_MILAN_PEM', new TextEncoder().encode(AMD_ARK_MILAN_PEM)],
  ['src/trust-anchors.ts#NVIDIA_DEVICE_IDENTITY_CA_PEM', new TextEncoder().encode(NVIDIA_DEVICE_IDENTITY_CA_PEM)],
]);

function statementFor(file: string): ProvenanceStatement {
  const found = STATEMENTS_BY_FILE.get(file);
  if (found === undefined) throw new Error(`the provenance table states nothing about ${file}`);
  return found;
}

/** The shipped bytes behind a row's name: a constant's text where this package holds it in source, a file otherwise. */
function shippedBytesFor(file: string): Uint8Array {
  const embedded = EMBEDDED_BYTES.get(file);
  if (embedded !== undefined) return embedded;
  return new Uint8Array(readFileSync(join(PACKAGE_ROOT, file)));
}

/**
 * The computed half of a row. Bytes holding no certificate, and bytes holding anything other than exactly one,
 * answer with a digest alone: a captured report has no subject and no window of its own, and a chain has several
 * keys, so a row that stated one of the four for those bytes would be a row that invented one.
 */
function derivedFacts(
  bytes: Uint8Array,
  file: string,
): Pick<AnchorLedgerRow, 'digest' | 'subject' | 'serial' | 'spki' | 'validity'> {
  const digest = sha256(bytes);
  let certificates: ParsedCertificate[];
  try {
    certificates = parseCertificateChain(bytes);
  } catch {
    return { digest };
  }
  const only = certificates.length === 1 ? certificates[0] : undefined;
  if (only === undefined) return { digest };

  // The same bytes read a second way: the DER element the chain walk returned, handed back to the single
  // certificate reader. Two readings of one certificate that disagree about a field a row states would put a
  // row over a key the file does not carry, so the walk stops here rather than writing what it cannot stand behind.
  const again = parseCertificate(only.raw);
  const readings: readonly (readonly [string, boolean])[] = [
    ['subject', equalBytes(again.subject, only.subject)],
    ['serial', equalBytes(again.serial, only.serial)],
    ['subjectPublicKeyInfo', equalBytes(again.subjectPublicKeyInfo, only.subjectPublicKeyInfo)],
    ['notBefore', again.notBefore === only.notBefore],
    ['notAfter', again.notAfter === only.notAfter],
  ];
  const disagreed = readings.filter(([, agreed]) => !agreed).map(([name]) => name);
  if (disagreed.length > 0) {
    throw new Error(`${file}: the two readings of this certificate disagree about ${disagreed.join(', ')}`);
  }

  return {
    digest,
    subject: only.subject,
    serial: only.serial,
    spki: sha256(only.subjectPublicKeyInfo),
    // A certificate's window is read in milliseconds by the parser and stated in seconds by this layout, and
    // `Math.trunc` is the whole of the conversion: a published window never carries a fraction of a second.
    validity: { from: Math.trunc(only.notBefore / 1000), to: Math.trunc(only.notAfter / 1000) },
  };
}

function rowFor(file: string): AnchorLedgerRow {
  const stated = statementFor(file);
  return {
    family: stated.family,
    file,
    ...derivedFacts(shippedBytesFor(file), file),
    origin: stated.origin,
    takenAt: stated.takenAt,
    licence: stated.licence,
    licenceNote: stated.licenceNote,
  };
}

/** Every member of a row, spelled so two rows that state the same claim have the same string. */
function rowFingerprint(row: AnchorLedgerRow): string {
  const bytes = (value: Uint8Array | undefined): string => (value === undefined ? '-' : toHex(value));
  return [
    row.family,
    row.file,
    bytes(row.digest),
    bytes(row.subject),
    bytes(row.serial),
    bytes(row.spki),
    row.validity === undefined ? '-' : `${String(row.validity.from)}..${String(row.validity.to)}`,
    row.origin,
    String(row.takenAt),
    row.licence,
    row.licenceNote ?? '-',
  ].join('|');
}

function main(): void {
  if (STATEMENTS_BY_FILE.size !== PROVENANCE.length) throw new Error('two provenance entries name the same file');
  const missing = ANCHOR_LEDGER_FILES.filter((file) => !STATEMENTS_BY_FILE.has(file));
  if (missing.length > 0) throw new Error(`the table states no provenance for ${missing.join(', ')}`);
  const stale = PROVENANCE.map((one) => one.file).filter((file) => !ANCHOR_LEDGER_FILES.includes(file));
  if (stale.length > 0) {
    throw new Error(`the table states provenance for ${stale.join(', ')}, which this package ships no row for`);
  }
  for (const one of PROVENANCE) {
    if (!existsSync(join(PACKAGE_ROOT, one.recordedIn))) {
      throw new Error(`${one.file}: the table cites ${one.recordedIn}, which is not in this package`);
    }
  }

  // An assembly instant that predates the newest statement in the row set would be a document claiming to have
  // assembled a row it had not read yet, so the stated day has to move with the statements rather than drift.
  const newest = Math.max(...PROVENANCE.map((one) => one.takenAt));
  if (ASSEMBLED_AT < newest) {
    throw new Error(`the row set states it was assembled at ${String(ASSEMBLED_AT)}, before the ${String(newest)} one of its rows claims`);
  }

  const rows = ANCHOR_LEDGER_FILES.map((file) => rowFor(file));
  const document: AnchorLedgerDocument = {
    v: ANCHOR_LEDGER_FORMAT_VERSION,
    generatedAt: ASSEMBLED_AT,
    keys: [UNSEALED_KEY_ID],
    rows,
  };
  const body = encodeAnchorLedger(document);

  // The emitted bytes are read back through this package's own reader over the bytes they name, and every row
  // is held to what this file derived. A body its own reader refuses, or one whose row a second reading moves,
  // is not published as an artifact: a stale ledger is the failure this document exists to make loud, and the
  // generator is the one place it could arrive quietly.
  const fixtures = new Map<string, Uint8Array>(
    ANCHOR_LEDGER_FILES.filter((file) => file.startsWith('test/fixtures/')).map((file) => [file, shippedBytesFor(file)]),
  );
  const readBack = parseAnchorLedger(body, { shipped: fixtures });
  if (readBack.rows.length !== rows.length) {
    throw new Error(`the written body holds ${String(readBack.rows.length)} rows and ${String(rows.length)} were derived`);
  }
  rows.forEach((row, index) => {
    const read = readBack.rows[index];
    if (read === undefined || rowFingerprint(row) !== rowFingerprint(read)) {
      throw new Error(`rows[${String(index)}] does not survive the write and the read: ${row.file}`);
    }
  });

  mkdirSync(dirname(LEDGER_PATH), { recursive: true });
  writeFileSync(LEDGER_PATH, body);

  for (const row of rows) console.log(`${row.file} ${toHex(row.digest).slice(0, 16)} ${row.licence}`);
  console.log(
    `wrote ${String(rows.length)} rows, assembled at ${String(document.generatedAt)}, to ${LEDGER_RELATIVE_PATH}: ${toHex(sha256(body))}`,
  );
}

main();
