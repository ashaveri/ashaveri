<!--
SPDX-FileCopyrightText: © 2026 ashaveri
SPDX-License-Identifier: Apache-2.0
-->

# Platform attestation test fixtures

Real platform attestation captured from confidential VMs, used for offline
end-to-end verification tests (nothing is fetched from AMD KDS or Intel PCS).

## Files

| File | Description |
| --- | --- |
| `sev-snp-attestation.bin` | dstack `VersionedAttestation` (SCALE V0): 1184-byte SNP report, empty `cert_chain`, `mr_config` document, runtime events, `report_data`, `config`. |
| `sev-snp-ask.pem` | AMD intermediate certificate (ASK, `CN=ASK-Milan`). |
| `sev-snp-vcek.pem` | Per-chip VCEK (`CN=SEV-VCEK`) for the report's `chip_id` and reported TCB. |
| `amd-ark-milan.pem` | AMD root key (ARK, `CN=ARK-Milan`), extracted from the go-sev-guest `snp-milan.cer` test certificate bundle. |
| `tdx-quote-v4.bin` | 4936-byte Intel TD quote (version 4, TDX) carrying the ECDSA P-256 attestation key and signature, a 384-byte QE report with its signature, 32 bytes of QE auth data, and the 3-certificate PCK chain. |
| `intel-sgx-root-ca.pem` | Pinned Intel SGX Root CA (`CN=Intel SGX Root CA`), the anchor the PCK chain must reach. |

## Provenance and attribution

- `sev-snp-attestation.bin`, `sev-snp-ask.pem`, `sev-snp-vcek.pem` are from the
  dstack project, Copyright © 2025 Phala Network, Apache-2.0. Captured
  2026-06-17 from a dstack SEV-SNP CVM (app `attest-test`,
  `dstack-nvidia-0.6.0.a2` image, AMD EPYC Milan host) via
  `dstack-util quote-report --report-data 6174746573742d746573742d666978747572652d32303236`
  (ASCII `attest-test-fixture-2026`). ASK/VCEK were fetched from AMD KDS
  (`https://kdsintf.amd.com/vcek/v1/Milan/...`) for the report's `chip_id` and
  TCB and pinned here so the tests stay offline and deterministic.
- `amd-ark-milan.pem` is from go-sev-guest, Copyright Google LLC, Apache-2.0
  (test certificate `snp-milan.cer`). Its DER bytes are the production AMD
  Milan ARK that signs the ASK above.
- `tdx-quote-v4.bin` is the `rawQuoteBlob` from edgelesssys/go-tdx-qpl
  (`blobs/blobs.go`), Copyright © 2023 Edgeless Systems GmbH, described there as
  "an example quote generated on an Intel TDX development platform". It is
  therefore genuine Intel-signed evidence rather than a synthetic vector: its
  PCK chain reaches Intel's root CA and both ECDSA P-256 signatures verify. Only
  the quote bytes were taken, no Go code, but go-tdx-qpl is **AGPL-3.0**, so this
  one data file is not covered by the repository's Apache-2.0 grant. Replace it
  with a quote captured from our own CVM if that becomes a problem. Edgeless's
  matching TCB Info collateral expired in 2023, which is one reason this package
  does not check TCB freshness.
- `intel-sgx-root-ca.pem` is Intel's published SGX provisioning trust anchor,
  downloaded from
  `https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.pem`
  (serial `22650cd65a9d3489f383b49552bf501b392706ac`, SHA-256 fingerprint
  `44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3`,
  valid 2018-05-21 to 2049-12-31). It is the third certificate of the quote's
  PCK chain, so pinning it is what makes the chain trustworthy rather than
  merely well-formed.

## Quote fields (informational)

```
version 4, attestation key type 2 (ECDSA P-256), TEE type 0x81 (TDX)
mr_td:       b65ea009e424e6f761fdd3d7c8962439453b37ecdf62da04f7bc5d327686bb8b...
report_data: 48656c6c6f2066726f6d20456467656c6573732053797374656d7321... (ASCII
             "Hello from Edgeless Systems!" zero-padded to 64 bytes)
rtmr[0..3]:  rtmr0, rtmr1 and rtmr2 are non-zero; rtmr3 is all zeros
pck chain:   leaf 2023-01-26..2030-01-26, PCK Platform CA 2018-05-21..2033-05-21,
             Intel SGX Root CA 2018-05-21..2049-12-31
```

Because `rtmr3` is all zeros, the only event list that replays against it is an empty one. That is
enough to run `verifyAttestation` end to end with `quoteSignatureVerified` true on real Intel
bytes, which the end-to-end block in `test/tdx-dcap.test.ts` does; what this fixture cannot show
is a non-trivial replay, and that stays covered by the synthetic quotes in `test/tdx.test.ts` and
by the live CVM. Verification time for the DCAP tests is pinned inside the PCK leaf window for the
same reason the SNP tests pin one.

## Verified values (informational)

```
chip_id:    38d174589d2dff97a6d40cb9f9d90b9507c027491219083cef3ce73e
            d18f7289142d941ad61eabecd27d25f268c1095d665f6001358e98a4769c82734a6bb877
measurement: 7f51e17f72a04d5422cb2c00998166536019a217376f3aa45a630e59c805a599...
host_data:  783f0057820acb99249af56cc3b07b4e8d80f65183167cba9cf437bb680f742f
```

VCEK/ASK are immutable for a given chip + TCB, so these files need no rotation. They do
carry a validity window (this VCEK is valid 2026-06-17 to 2033-06-17), which is why the
tests pin a verification time. If the report itself is regenerated (different host or
firmware), re-capture all files together. The VCEK must match the new report's
`chip_id`/TCB.
