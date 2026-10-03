# Trust anchors and where they came from

`@ashaveri/attest-core` verifies platform evidence with no network, so the three vendor roots a
certificate chain has to reach ship inside the package, and the reports and certificates its tests
read ship beside them. Every one of those files is a row of the anchor provenance ledger,
[`packages/attest-core/data/anchor-provenance-v1.cbor`](../packages/attest-core/data/anchor-provenance-v1.cbor),
which states where the bytes came from, the day they were taken from there, and the licence class
that source stated. The layout is
[`packages/receipt/anchor-provenance.cddl`](../packages/receipt/anchor-provenance.cddl) and its JSON
twin is
[`packages/receipt/schemas/anchor-provenance-v1.schema.json`](../packages/receipt/schemas/anchor-provenance-v1.schema.json).
The refusals a reader of that document answers with are the `ANCHOR_LEDGER_` rows of
[error-codes.md](error-codes.md).

This document is the ledger's provenance half as prose. There are 13 rows, in the ledger's own
order: 3 embedded anchors and then 10 tracked files.
`packages/attest-core/test/trust-anchors-doc.test.ts` reads this file and holds it to the committed
artifact in both directions, so a row the ledger gains, loses or rewords without this table, and a
table reworded without the ledger, both fail the suite. The other half of a row is arithmetic and
is not copied here, for the reason given below.

## What a row states

A row is half computation and half claim. The computation is what a reader holding the file redoes
for itself. The claim is the part no computation produces, which is why the document is signed and
why the five members below are the ones this table repeats.

| Column | Member | What it states |
|---|---|---|
| **Family** | `family` | Which of the three platforms these bytes belong to: `amd`, `intel` or `nvidia`. |
| **File** | `file` | The bytes the row is about, named the way this repository ships them. An embedded anchor is named `src/trust-anchors.ts#<constant>`, because the bytes are the PEM text that constant holds; a tracked file is named from the package root. |
| **Taken** | `takenAt` | The first second of the UTC day the bytes were taken from their source, in Unix seconds in the ledger and as that day here. A row states a day and never an hour, so nothing in this table claims a precision the record behind it does not carry. |
| **Licence** | `licence` | The class the source stated these bytes under, one of the four below. |
| **Source** | `origin` | Where the bytes were read from, as an https URL. A record that pins a revision pins it in the URL; one that names a repository and no revision goes no further than the repository, and the row does not invent the precision the record lacks. |

The remaining members stay in the artifact. `digest` is sha256 of the bytes as they ship, and
`subject`, `serial`, `spki` and `validity` are the four facts exactly one certificate answers for,
which arrive together or not at all. Both are arithmetic over the file the row names, and
`parseAnchorLedger` recomputes them rather than trusting them: a root swapped under a row is
`ANCHOR_LEDGER_DIGEST_MISMATCH` and a key digest copied from another certificate is
`ANCHOR_LEDGER_SPKI_MISMATCH`, and the whole document is refused rather than read around either. A
digest copied into a document would be a second place for it to go stale and no place for it to be
checked, which is why this table states no digest. Bytes holding no single certificate carry none
of the four: the two captured reports are evidence rather than certificates, and the tracked Hopper
chain holds five.

The rows are written by `packages/attest-core/scripts/anchor-ledger.ts`, run as
`pnpm --dir packages/attest-core run generate:anchor-ledger`. It derives the arithmetic half from
the bytes and takes the provenance half from a table beside it holding one entry per shipped file,
each entry naming the record inside this package that states it: the fixtures note for the tracked
files and the comment beside the constant for the embedded Intel root. A file no entry names is
refused rather than written with an empty claim, and an entry naming a file this package ships no
row for is refused the same way, so the roster and the records cannot drift apart silently.

## The rows

| Family | File | Taken | Licence | Source |
|---|---|---|---|---|
| `intel` | `src/trust-anchors.ts#INTEL_SGX_ROOT_CA_PEM` | 2026-09-11 | `none-stated` | https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.pem |
| `amd` | `src/trust-anchors.ts#AMD_ARK_MILAN_PEM` | 2026-09-10 | `apache-2.0` | https://github.com/google/go-sev-guest |
| `nvidia` | `src/trust-anchors.ts#NVIDIA_DEVICE_IDENTITY_CA_PEM` | 2026-09-11 | `bsd-3-clause` | https://github.com/NVIDIA/nvtrust/blob/858ada9a17f58c482f578414ea2455498fa51e17/guest_tools/gpu_verifiers/local_gpu_verifier/src/verifier/certs/verifier_device_root.pem |
| `amd` | `test/fixtures/sev-snp-attestation.bin` | 2026-06-17 | `apache-2.0` | https://github.com/ashaveri/ashaveri/blob/main/packages/attest-core/test/fixtures/README.md |
| `amd` | `test/fixtures/sev-snp-ask.pem` | 2026-06-17 | `none-stated` | https://kdsintf.amd.com/vcek/v1/Milan |
| `amd` | `test/fixtures/sev-snp-vcek.pem` | 2026-06-17 | `none-stated` | https://kdsintf.amd.com/vcek/v1/Milan |
| `amd` | `test/fixtures/amd-ark-milan.pem` | 2026-09-10 | `apache-2.0` | https://github.com/google/go-sev-guest |
| `intel` | `test/fixtures/tdx-quote-v4.bin` | 2026-09-11 | `agpl-3.0` | https://github.com/edgelesssys/go-tdx-qpl |
| `intel` | `test/fixtures/intel-sgx-root-ca.pem` | 2026-09-11 | `none-stated` | https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.pem |
| `nvidia` | `test/fixtures/nvidia-hopper-report.bin` | 2026-09-11 | `apache-2.0` | https://github.com/NVIDIA/attestation-sdk/blob/73efa3ac1bec28ed7d7f0c0811a6c993e722dbd4/nv-attestation-sdk-cpp/unit-tests/testdata/sample_attestation_data/gpu/hopperAttestationReport.txt |
| `nvidia` | `test/fixtures/nvidia-hopper-report-bad-signature.bin` | 2026-09-11 | `apache-2.0` | https://github.com/NVIDIA/attestation-sdk/blob/73efa3ac1bec28ed7d7f0c0811a6c993e722dbd4/nv-attestation-sdk-cpp/unit-tests/testdata/sample_attestation_data/gpu/hopperAttestationReportInvalidSignature.txt |
| `nvidia` | `test/fixtures/nvidia-hopper-cert-chain.pem` | 2026-09-11 | `apache-2.0` | https://github.com/NVIDIA/attestation-sdk/blob/73efa3ac1bec28ed7d7f0c0811a6c993e722dbd4/nv-attestation-sdk-cpp/unit-tests/testdata/sample_attestation_data/gpu/hopperCertChain.txt |
| `nvidia` | `test/fixtures/nvidia-device-identity-ca.pem` | 2026-09-11 | `bsd-3-clause` | https://github.com/NVIDIA/nvtrust/blob/858ada9a17f58c482f578414ea2455498fa51e17/guest_tools/gpu_verifiers/local_gpu_verifier/src/verifier/certs/verifier_device_root.pem |

Three pairs of rows name the same bytes and are not duplicates. The embedded Intel root and the
tracked `intel-sgx-root-ca.pem` are the same certificate, one shipped as the text of a constant and
one as a file a test reads, and `packages/attest-core/test/trust-anchors.test.ts` holds the two to
one certificate; the AMD Milan ARK and the tracked `amd-ark-milan.pem` are the same pair on that
platform, as is the NVIDIA device root and `nvidia-device-identity-ca.pem`. A row is a claim about
bytes, so bytes shipped in two places are stated twice, and the two rows agree.

What each file is, field by field where the bytes carry fields a test asserts on, is
[`packages/attest-core/test/fixtures/README.md`](../packages/attest-core/test/fixtures/README.md).
That note is the record behind the provenance half of every tracked row, and this table is the
projection of the ledger it produced.

## The four licence classes

The classes are closed, and a row stating one outside them is `ANCHOR_LEDGER_LICENCE_UNKNOWN`:

| Class | Rows | What it means here |
|---|---|---|
| `apache-2.0` | 6 | The source stated Apache-2.0 over the bytes: the AMD Milan ARK from go-sev-guest, stated twice because its bytes ship in two places, the captured SEV-SNP attestation whose envelope format is dstack's, and the NVIDIA golden samples. |
| `bsd-3-clause` | 2 | The source stated BSD-3-Clause over the file the bytes were read from. The NVIDIA device identity root, which the nvtrust repository carries under an Apache-2.0 `LICENSE` while the verifier package marks its own files BSD-3-Clause; the class states the marking on the file, and the fixtures note reproduces both notices. |
| `agpl-3.0` | 1 | The tracked TDX quote, and the reason is below. |
| `none-stated` | 4 | The source published the bytes and named no code licence behind them. A finding and not a grant. |

`none-stated` is the class a reader is most likely to misread, so it is worth stating what it does
and does not say. It says that the route which published these bytes named no code licence at the
point it published them: Intel's provisioning root, shipped in two places, and the ASK and VCEK
that AMD's key distribution service answers for one chip and one TCB. It does not say the bytes are
unlicensed, freely redistributable, or forbidden; every one of those is a conclusion a caller draws
with its own counsel and not a shape a row has. What the row gives a caller is the fact the
conclusion needs: which route published these bytes, and that the route stated nothing.

### The one copyleft row

`test/fixtures/tdx-quote-v4.bin` is the row whose source states a copyleft licence, and this is the
only passage in this repository that discusses it. The bytes are the `rawQuoteBlob` member of
`blobs/blobs.go` in edgelesssys/go-tdx-qpl, described there as an example quote generated on an
Intel TDX development platform, and the row's own `licenceNote` carries the whole of the position:
quote bytes only, and no code from the repository that published them. go-tdx-qpl is AGPL-3.0, so
this repository does not claim that its own Apache-2.0 grant reaches those bytes. It carries them as
vendor-signed evidence and names where they came from, which is exactly what the row does, and a
reader that wants to weigh the class has the class and the source beside it.

The alternative to a vendor's own signed quote is a capture of our own, and that capture is gated on
live TDX hardware: a quote no vendor signed cannot exercise the DCAP path end to end, so a synthetic
vector would replace real evidence with a shape this suite invented. The row therefore stands as it
is, with its source named and its class stated, and the bytes are carried as evidence rather than as
a grant this repository can make on somebody else's behalf.

## What the ledger does not say

- **No verdict.** A row states where bytes came from and under which class. It says nothing about
  whether a chain verifies, whether a certificate is revoked, or whether a platform is current, and
  no verdict in this repository reads a row as one.
- **No freshness and no revocation.** Nothing here fetches a CRL, an OCSP responder, a TCB Info
  document, a QE Identity or a golden measurement. The tracked certificates do carry those pointers
  inside their own bytes, and
  [threat-model.md](threat-model.md) section 6 lists which certificate carries which and states what
  leaving them unfollowed costs a verdict.
- **No claim about a deployment's own anchors.** A deployment that keeps its own roots passes them
  through the verification options or through `policy.trustAnchors`, and the three embedded
  constants play no part in its verdicts. The ledger is a statement about the bytes this repository
  ships, not a list of the bytes a caller must pin.
- **No measurement values.** The NVIDIA golden measurements live at the vendor's RIM service behind
  an account, and a report verifying under the pinned device root proves that a genuine device
  signed it, not that its measured software is a known-good release.

## Reading a sealed ledger

The verifying key is the caller's decision and nobody else's. The ledger ships beside the bytes it
describes, so a reader that took its key from the same tree would be checking this repository's
claim under this repository's own authority, which proves nothing about where an anchor came from.
`verifyAnchorLedger` therefore refuses a call that names no pin at all
(`ANCHOR_LEDGER_PIN_MISSING`, before a byte of the document is read) and a pin the sealed header
does not answer (`ANCHOR_LEDGER_PIN_MISMATCH`). A client of `@ashaveri/sdk` names that pin in
`policy.trustAnchors`, beside every other anchor decision it makes, and the reader also requires the
bytes of every tracked file a row names, since only the three embedded anchors resolve from source.

The artifact committed here is the unsigned body the generator writes, and its `keys` list names one
id of thirty-two zero bytes, which is the layout saying that no key has sealed these rows. A reader
handed that file meets `ANCHOR_LEDGER_NOT_SEALED`, and that refusal is the point of the code: a
draft of the ledger is not evidence about an anchor. The sealed document arrives by a ceremony that
keeps the signing key outside every tree and every build secret this repository controls, because a
key sitting beside the document it signs lets anybody who can edit the checkout say anything about
where an anchor came from. The `keys` list inside a sealed ledger is the issuer's own statement
about which keys may stand behind its rows; it is weighed after the signature that covers it, and it
never replaces the caller's pin.

The instants in the body are stated rather than sampled, so two runs of the generator write the same
bytes and the artifact can be pinned by a digest: a row's instant is the first second of the day its
record names, and `generatedAt` is the day the row set was assembled. A row whose source statement
is newer than that assembly day is refused by the generator rather than written into a document
claiming to have assembled a row it had not read.
`packages/attest-core/test/anchor-ledger.test.ts` holds every committed row to the bytes it names,
one case per shipped file, and holds the layout this document describes against the CDDL and the
twin.
