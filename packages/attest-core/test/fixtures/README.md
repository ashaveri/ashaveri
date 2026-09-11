<!--
SPDX-FileCopyrightText: © 2026 ashaveri
SPDX-License-Identifier: Apache-2.0
-->

# Platform attestation test fixtures

Real platform attestation, used for offline end-to-end verification tests. The SNP and TDX
documents were captured from confidential VMs; the GPU report is NVIDIA's own published sample.
Nothing is fetched from AMD KDS, Intel PCS or NVIDIA while the tests run.

## Files

| File | Description |
| --- | --- |
| `sev-snp-attestation.bin` | dstack `VersionedAttestation` (SCALE V0): 1184-byte SNP report, empty `cert_chain`, `mr_config` document, runtime events, `report_data`, `config`. |
| `sev-snp-ask.pem` | AMD intermediate certificate (ASK, `CN=ASK-Milan`). |
| `sev-snp-vcek.pem` | Per-chip VCEK (`CN=SEV-VCEK`) for the report's `chip_id` and reported TCB. |
| `amd-ark-milan.pem` | AMD root key (ARK, `CN=ARK-Milan`), extracted from the go-sev-guest `snp-milan.cer` test certificate bundle. |
| `tdx-quote-v4.bin` | 4936-byte Intel TD quote (version 4, TDX) carrying the ECDSA P-256 attestation key and signature, a 384-byte QE report with its signature, 32 bytes of QE auth data, and the 3-certificate PCK chain. |
| `intel-sgx-root-ca.pem` | Pinned Intel SGX Root CA (`CN=Intel SGX Root CA`), the anchor the PCK chain must reach. |
| `nvidia-hopper-report.bin` | 4052-byte NVIDIA GPU report: 37-byte SPDM `GET_MEASUREMENTS` request followed by a signed 4015-byte response ending in a raw P-384 signature. |
| `nvidia-hopper-report-bad-signature.bin` | Second Hopper report, well-formed but carrying a signature NVIDIA marks as invalid. |
| `nvidia-hopper-cert-chain.pem` | Five-certificate device chain, leaf first (`CN=GH100 A01 GSP FMC LF`) down to the device identity root. |
| `nvidia-device-identity-ca.pem` | Pinned NVIDIA device identity root (`CN=NVIDIA Device Identity CA`), the anchor that chain must reach. |

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
- `nvidia-hopper-report.bin`, `nvidia-hopper-report-bad-signature.bin` and
  `nvidia-hopper-cert-chain.pem` are NVIDIA's own golden samples, taken from
  `nv-attestation-sdk-cpp/unit-tests/testdata/sample_attestation_data/gpu/` in
  NVIDIA/attestation-sdk (Copyright 2025 NVIDIA Corporation, Apache-2.0) at commit
  `73efa3ac1bec28ed7d7f0c0811a6c993e722dbd4`. Upstream stores the two reports as hex
  text, so the `.bin` files are a byte-for-byte decode of `hopperAttestationReport.txt`
  (blob `0fe5474d0c3dacf6990d18b8c7cff630c743d0e8`) and
  `hopperAttestationReportInvalidSignature.txt` (blob
  `ddf8f050f69b5a330fcb31ab0a953bcd30c164c3`); `hopperCertChain.txt` (blob
  `ad1b89df4c26880b8877d549d3560947fdbe477f`) is copied verbatim. These are the vectors
  NVIDIA's verifier is tested against, and the second one is NVIDIA's own named
  bad-signature case, so the expected verdicts come from the vendor rather than from us.
- `nvidia-device-identity-ca.pem` is `certs/verifier_device_root.pem` from
  NVIDIA/nvtrust (`guest_tools/gpu_verifiers/local_gpu_verifier/src/verifier/`),
  blob `00db2d93992ce2654b242ff140ca48997f9f674b`, taken at commit
  `858ada9a17f58c482f578414ea2455498fa51e17`. The nvtrust repository carries an
  Apache-2.0 `LICENSE` while the verifier package marks its files
  `SPDX-License-Identifier: BSD-3-Clause`, so both notices are reproduced here.
  `src/trust-anchors.ts` bundles these same bytes as `NVIDIA_DEVICE_IDENTITY_CA_PEM`,
  and `test/trust-anchors.test.ts` asserts the two stay identical.

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

## GPU report fields (informational)

```
request  37 bytes: SPDM 1.1 (0x11), GET_MEASUREMENTS (0xe0), attributes 0x01, blocks 0xff,
         32 random bytes 27a328247bf7935c993341cf587be6f05986ccce4fe7ba2c54100bd616a58f66, slot 0
response 4015 bytes: SPDM 1.1, MEASUREMENTS_RESPONSE (0x60), 64 blocks, 3520-byte measurement
         record (= 64 × 55), nonce 08f2fd1f8bb769d087f6b0de1b389594e6cd2415c2f92cf4894fd617d8ddd7e6,
         opaque data 357 bytes, raw P-384 r||s signature (96 bytes) at offset 3956, no trailing bytes
chain    GH100 A01 GSP FMC LF (valid from 2020-10-17) → GH100 A01 GSP BROM →
         NVIDIA GH100 Provisioner ICA 1 → NVIDIA GH100 Identity → NVIDIA Device Identity CA
         (self-signed, serial 2d3670b1ca100411c1fec0e82a065b54, P-384, from 2021-11-05)
```

`test/nvidia.test.ts` pins 2024-01-15 as the evaluation time because the leaf only becomes valid
in October 2020, and reaches `CERT_EXPIRED` from the same fixture by asking about 2019 instead. The
bad-signature fixture has the same shape with 567 bytes of opaque data (nonce
`60f0a94bf956f53b4509bb2eb4cfc6720f87a5471d9bb7f65eb73b51a6a9365d`, signature at offset 4166), which
keeps the parser honest on a second real length. Upstream keeps `hopperAttestationReportExpired.txt`
and `hopperCertChainExpired.txt` next to these files if expiry needs its own vector later.

The nonce the verifier returns is the 32 bytes the GPU wrote into its response, and the tamper test
flips one of them to show the field sits inside the signed span. Note that in this vendor sample
that value differs from the request's own 32 random bytes, so the fixture proves the response nonce
is covered by the signature; that a client can make a GPU sign a challenge it chose stays a
property of the live device, and the live CVM is where it gets exercised.

What is deliberately not checked: the measurement blocks are read only for their length, so no
driver or VBIOS version is asserted; revocation status at `ocsp.ndis.nvidia.com` and the golden
measurement values at `rim.attestation.nvidia.com` are not consulted. A successful verification
therefore means the report is genuine NVIDIA-signed evidence from a device holding a chain to the
pinned root, not that its measured software is a known-good release.

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
