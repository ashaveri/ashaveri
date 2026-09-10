<!--
SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
SPDX-License-Identifier: Apache-2.0
-->

# AMD SEV-SNP attestation test fixtures

Real AMD SEV-SNP attestation captured from a live dstack CVM, used for
offline end-to-end verification tests (nothing is fetched from AMD KDS).

## Files

| File | Description |
| --- | --- |
| `sev-snp-attestation.bin` | dstack `VersionedAttestation` (SCALE V0): 1184-byte SNP report, empty `cert_chain`, `mr_config` document, runtime events, `report_data`, `config`. |
| `sev-snp-ask.pem` | AMD intermediate certificate (ASK, `CN=ASK-Milan`). |
| `sev-snp-vcek.pem` | Per-chip VCEK (`CN=SEV-VCEK`) for the report's `chip_id` and reported TCB. |
| `amd-ark-milan.pem` | AMD root key (ARK, `CN=ARK-Milan`), extracted from the go-sev-guest `snp-milan.cer` test certificate bundle. |

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
