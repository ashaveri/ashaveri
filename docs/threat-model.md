# Ashaveri Threat Model

Status: Draft. This is the working threat model for the receipt protocol specified in
[receipt-spec.md](receipt-spec.md). It describes the threats the current implementation
addresses, and, just as importantly, the ones it does not.

## 1. Scope

What receipts protect: the integrity and provenance of inference responses. A client can
prove, offline, that the exact bytes it received were vouched for by a specific gateway
deployment, under a specific key, with a specific claim about model, weights, measurement,
and token metering.

What receipts do not protect: confidentiality of prompts or responses, availability, or the
truthfulness of a gateway's claims about hardware it does not actually run on. Section 6 is
explicit about the current gaps.

## 2. Assets

- **A1 Response integrity.** The completion the user saw is the completion the gateway signed.
- **A2 Request-response binding.** The receipt is about this request, not another one.
- **A3 Gateway identity.** Which deployment, under which signing key, produced the response.
- **A4 Deployment claims.** Model id, weights digest, TEE measurement, attestation evidence reference.
- **A5 Token metering.** The counts a receipt signs cannot be revised afterwards, so whichever
  gateway claimed them owns that claim. Where the counts came from is T9's problem, not A5's.
- **A6 Client policy.** The client's pinned keys, issuers, instances, and measurements.

## 3. Actors and trust boundaries

- **Client** holds the policy (A6) and generates nonces. Trusted by itself.
- **signerd gateway** signs receipts. Trusted only as far as its signature and the client's pins go.
- **Inference backend** computes completions behind the gateway. Untrusted from the client's
  perspective; the gateway vouches for what it forwarded.
- **Network** between client and gateway. Fully untrusted (TLS is assumed for confidentiality
  and authentication of the transport, but receipts are designed to not depend on it).
- **Manifest channel**. The deployment manifest is fetched from the gateway. In `strict`
  mode its contents must match the client's pins to matter.

## 4. Assumptions

- Ed25519 is unforgeable and sha256 is collision and preimage resistant for the horizon that
  matters. Both are generously conservative assumptions today.
- The client's policy is obtained and stored through a trusted path. A corrupted policy
  corrupts every guarantee in this document.
- Nonces come from a cryptographic RNG. A predictable nonce weakens replay protection.
- The client completes reading the response body before trusting it. In the SDKs, streaming
  responses surface verification failures as stream errors precisely so partial consumption
  cannot silently proceed past a failed check.

## 5. Threats and mitigations

| # | Threat | Mitigation | Residual risk |
|---|---|---|---|
| T1 | Network attacker modifies the response body in transit | `res` binds the exact response bytes; hash mismatch fails verification | None within the crypto assumptions |
| T2 | Attacker substitutes a different valid response (cross-request) | `req` binds the exact request bytes, `nce` the per-request nonce | None; a receipt for another request cannot verify against this one |
| T3 | Replay of an old but valid receipt for a fresh request | Client-generated nonce must be echoed; optional freshness windows on `iat` and `att.ts` | None if freshness is configured |
| T4 | Gateway signs a receipt, then serves different bytes | Same as T1: the served bytes fail the `res` check | None |
| T5 | A different key signs receipts (gateway compromise or impersonation) | `kid` must resolve to a manifest-declared key; in strict mode, to a policy-pinned key that also matches the manifest | In `receipt` mode a gateway that controls its own manifest can introduce a new key; strict mode closes this |
| T6 | Gateway omits receipts selectively | Strict mode rejects unreceipted responses | `receipt` mode returns a null receipt by design; callers must check for it |
| T7 | Gateway lies about model, weights, measurement, or tokens | These fields are signed, so lying is attributable to the signing gateway and detectable against a pinned policy | The gateway can still lie consistently. See section 6 |
| T8 | Manifest tampering | Strict mode requires the manifest key to equal the pinned key (`MANIFEST_KEY_NOT_PINNED`), and pins issuer, instance, measurements | None in strict mode |
| T9 | Token metering inflation | `tok` is signed and attributable | The SDK does not recount tokens from the response text; it verifies who claimed the counts |
| T10 | DoS: gateway refuses to serve receipts | Receipt and evidence fetches retry with a short window, then fail closed as `RECEIPT_NOT_FOUND` or `EVIDENCE_NOT_FOUND` rather than falling back to unverified acceptance | Availability is out of scope |
| T11 | Side channels on prompt content via receipts | Receipts contain hashes and counts only, never content | Hashes reveal content length implicitly (already visible in the response) |
| T12 | Strict mode: gateway serves evidence from other work, another instance, or one not matching the receipt | The client recomputes the expected report data from its own nonce and request bytes, requires `sha256(document) == att.d`, requires the quote's platform to agree with the receipt's `tee` (a `software` receipt is refused before the fetch), and requires the measured launch digest to equal `meas.m` | Collateral freshness. The signature chain is checked against a pinned vendor root, but TCB Info, the QE identity and the CRL are not consulted, so a since-revoked platform still verifies |
| T13 | Strict mode: a receipt bearing a composite `tee` claims a confidential GPU the deployment does not have, or quotes a device report captured for someone else | The label is only ever an operator's request, and the gateway will not start under it unless one of its accelerators signs that deployment's standing challenge. Strict mode then fetches the device document for the client's own challenge and requires a report whose signature chains to a pinned NVIDIA device root and whose signed challenge matches | Residual trust in one label choice: the operator picks the composite and the gateway confirms only that its platform quote and a device report answer the same challenge. See section 6 |

## 6. Current limitations, stated plainly

The gateway has two modes, and the difference between them is the substance of this section.

`signerd --live` closes the "nothing binds the claims to hardware" gap on the
serving side:

- The signing key is derived by the guest agent inside the CVM from `--key-path`, not a key
  file, an environment variable, or process memory that survives a restart. The application
  never writes it anywhere, so nothing outside the confidential VM extracts it through this
  code. Which agent is asked remains an operator setting: `--guest-socket` and
  `DSTACK_SIMULATOR_ENDPOINT` point signerd at any socket or URL they name, so a key is only as
  local as the peer that supplied it.
- `meas`, the issuer and the instance are read out of the guest's own evidence at startup.
  A hand-entered value is only possible through the explicit `--issuer` / `--instance`
  overrides, and `--tee` refuses to start if the evidence contradicts the configured platform.
- Every receipt points at evidence bound to that request's nonce: the gateway checks that the
  quote's report data equals `sha256(nonce, hashRequest(request))` before it publishes the
  document, so a quote captured for another request is rejected.
- The entrypoint verifies the mounted model files against a manifest before `signerd` starts when
  the container sets both `ASHAVERI_WEIGHTS_DIR` and `ASHAVERI_WEIGHTS_MANIFEST`, which the
  bundled compose does (see [enclave/README.md](../enclave/README.md)), so a swapped model file
  stops the process at startup instead of quietly signing the wrong weights. It is an opt-in
  check reading environment variables while `wts` comes from the separate `--weights-manifest`
  flag, so a deployment that sets one without the other signs a digest nothing checked at boot.

What is still true, in both modes:

- **Intel and AMD collateral is never fetched.** With a pinned Intel root,
  `@ashaveri/attest-core` verifies a TDX quote through Intel DCAP: the quote under its
  attestation key, that key inside the QE report, and the report under a PCK chain reaching the
  pinned root. Intel's SGX root CA and the AMD Milan ARK are bundled with the package, so SDK
  `strict` mode verifies against them unless `policy.trustAnchors` says otherwise. Without a root
  for the platform the receipt claims, the leg is replay-only, so `quoteSignatureVerified` is
  `false` and the client is checking self-consistency plus its own pins, not an Intel signature.
  In neither mode does the verifier consult Intel TCB Info, the QE Identity or the PCK CRL, and on
  AMD it uses the ASK and VCEK files you supply rather than querying KDS. A platform that is
  genuinely signed but since deprecated or revoked by the vendor therefore still verifies. Checking
  freshness needs network access and is deliberately outside the offline verification path.
- **The gateway does not deep-verify its own evidence.** It reads the measurement and the
  report-data binding; the certificate chain, TCB and event-log replay are the client's job,
  through `@ashaveri/sdk` in strict mode or `@ashaveri/cli`. That is deliberate, but it means a
  gateway that lied about its platform could still serve receipts: the detection lives on the
  verifying side.
- **A composite claim has no proof of attachment.** Neither `"snp+h100cc"` nor `"tdx+h100cc"` is
  ever read off hardware. An operator asks for it, and the gateway refuses to start under that
  label unless one of its accelerators signs the deployment's standing challenge; a client then
  requires a device report signing its own challenge under a pinned NVIDIA root. That establishes
  a genuine confidential-computing GPU attesting to this request and a genuine SNP or TDX VM
  serving it. It does not establish that the GPU is the card plugged into that VM, because the
  vendor's report carries no host binding, so an operator with a CC GPU anywhere it can reach
  could pair the two documents. TDISP/TEE-IO is the mechanism that would close this, and no
  deployment here has it. Device collection costs a real device seconds, so the gateway asks once
  per challenge and caches the answer, and a plain `"snp"` or `"tdx"` deployment is never upgraded
  into the claim or charged for it.
- **The producing path has not been answered by a real image.** The gateway calls dstack's v1
  device attestation route and serves the vendor's `nvattest` bundle unchanged; both are
  implemented from published shapes and tested against a fake guest. The guest agent's wire
  contract and the per-device field names stay assumptions until a real dstack image replies to
  the call. Nothing degrades silently in the meantime: an image that offers no device route stops
  a deployment configured to claim one.
- **The mock gateway is not a TEE deployment.** It signs with an ephemeral development key,
  its `meas` and `att` fields are digests of fixed strings, and its evidence URL uses the
  `mock://` scheme. It reports `tee: "software"`, the member of the enum that claims no
  hardware protection, so no field of a mock receipt reads as a TEE assertion.
- **Receipts live in process memory.** An issued receipt stays fetchable until the process
  restarts or until 10,000 later completions push it out of the store, whichever comes first,
  the same shape as the evidence caches beside it that keep 256 documents each. A read does not
  move a receipt, so a client that delays its fetch past that many completions loses the
  document. There is no runtime key rotation either: `--epk` publishes the epoch of the key a
  process started with, so rotating means a new deployment with a new `--key-path` and a higher
  epoch. A real deployment needs a retention window it can state in time rather than count, and
  storage that survives a restart.
- **The manifest is unsigned.** Strict-mode pinning is what gives it weight today; the
  intended end state is a manifest signed by a long-term deployment identity.
- **The weights digest chain has one open link.** The receipt binds `sha256(manifest)` and the
  manifest binds each model file, but the manifest itself is not carried in the receipt and is
  not in the compose measurement unless the operator mounts the weights as a dm-verity volume.
  A client that has not been given the manifest out of band sees an opaque `wts` value.
- **On the managed dStack platform, TLS terminates outside the TEE.** The measured container
  serves plain HTTP behind the platform gateway, so transport confidentiality depends on the
  platform edge, not on a channel the workload terminates inside the enclave.
- **Nothing here measures model behaviour.** A receipt proves who served which bytes; it says
  nothing about quality, alignment, or the prompt template behind the completion.

The SDK's `strict` mode verifies receipts and the manifest against pins and then fetches and
deep-verifies the evidence each receipt commits to. What remains unproven is the end-to-end run:
strict mode has accepted captured vendor-signed evidence replayed into a locally issued receipt,
but no client has yet completed one against a live CVM. The composite case has not even been
replayed: the published NVIDIA fixture signs the challenge named in its own provenance, not one
this suite controls, so no report a vendor signed can answer a challenge the tests invent, and
both legs together are covered only by live hardware. Until that has happened, the honest
summary is: receipts deliver byte-level integrity and provenance, the hardware gate is implemented
and tested against captured evidence rather than demonstrated live.

## 7. Relationship to attest-core

`@ashaveri/attest-core` verifies attestation evidence: certificate chains against a pinned
AMD ARK, report signatures, TCB, runtime event logs, measurement values, and the NVIDIA SPDM
device reports behind a composite claim. The receipt's `att` field is the designed rendezvous
point: once the gateway must present evidence whose digest matches `att.d`, freshness within
`att.ts`, and a measurement consistent with `meas`, the T7 "consistent lying" residual shrinks
from "trust the gateway's self-description" to "trust the hardware's measurement." The
integration sequencing is deliberately staged: the
receipt format and client verification shipped first, so the hardware gate changes the
gateway, not the clients. Strict mode is where that rendezvous is consumed, and consuming it
added one step inside an existing mode rather than a new client API.
