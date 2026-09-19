# Ashaveri Threat Model

Status: Draft. This is the working threat model for the receipt protocol specified in
[receipt-spec.md](receipt-spec.md) and for the gateway access floor specified in
[access-control.md](access-control.md). It describes the threats the current implementation
addresses, and, just as importantly, the ones it does not.

## 1. Scope

What receipts protect: the integrity and provenance of inference responses. A client can
prove, offline, that the exact bytes it received were vouched for by a specific gateway
deployment, under a specific key, with a specific claim about model, weights, measurement,
and token metering.

What receipts do not protect: confidentiality of prompts or responses, availability, or the
truthfulness of a gateway's claims about hardware it does not actually run on. Nor do they decide
who may ask: every route this gateway serves sits behind the admission pipeline in
[access-control.md](access-control.md), which holds no prompt and no response bytes, and every
request that reaches it, admitted or refused, writes one line to an access log the deployer holds on
a retention window of its own. Section 6 is explicit about the current gaps on both sides.

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
| T13 | Strict mode: a receipt bearing a composite `tee` claims a confidential GPU the deployment does not have, or quotes a device report captured for someone else | The label is only ever an operator's request, and the gateway will not start under it unless one of its accelerators signs that deployment's standing challenge. The platform's agent collects that report today; the settled direction is for the vendor's own tool to run inside the deployment's container instead, which emits the same bundle format, so the client's checks stay checks on the bytes rather than on who collected them. Strict mode then fetches the device document for the client's own challenge and requires a report whose signature chains to a pinned NVIDIA device root and whose signed challenge matches | Residual trust in one label choice: the operator picks the composite and the gateway confirms only that its platform quote and a device report answer the same challenge. See section 6 |
| T14 | A bearer credential is stolen, and someone else presents it | `--allow-bearer` is off by default, and it is deployment-wide rather than per credential, so a process is bearer-capable or it is not and one convenience fallback cannot be introduced for a single record. A bearer secret is held only as its SHA-256 and every stored digest is compared in a loop that does not exit early on the first differing byte, so a wrong secret reveals nothing about which one was close. Each record a bearer secret admitted writes `auth=bearer` on its own line, so the log says which posture produced it rather than the widest thing the process tolerates | The start-up banner states this and this document does not soften it: a stolen bearer credential is undetectable, and a log record cannot tell its holder from a thief. The secret is the whole credential, it does not expire on its own, and it authorizes any request its scopes allow from any address. A bearer path also has no replay step at all, because it has no signed nonce to check |
| T15 | Refusals used as an oracle to enumerate which credential ids a deployment has issued, or which paths it has scoped | On both paths the answers are collapsed. Bearer: a secret matching no stored digest and a revoked record both end as `AUTH_UNKNOWN`, because the digest scan passes over a revoked record as though it had never existed, and a distinct answer would tell a prober which ids the file holds and which were once live. Proof of possession, since 19 September 2026: a `credential` this file does not carry, and a name whose record is a bearer one with no key to verify against, are refused through the same code path as a failed signature and with the same code, `AUTH_SIGNATURE`, after one Ed25519 verification against a key that is in no credential file and whose result is discarded rather than read. The timestamp window and the presented nonce are checked before the file is consulted, so they answer alike whoever the header names, and what the file says about a record it holds is told only to a request whose signature verified. An unlisted target is read off the route table first but answered only at the scope check, so a caller who presented nothing usable is refused for that (`AUTH_MALFORMED`, `AUTH_SCHEME`) and learns nothing about the path, whether or not the server registered it. Rate limiting cannot be turned into an oracle either: the bucket is taken at the last check, after scope, so an id the file does not hold is refused before any budget is consulted | What an unauthenticated guesser learns is closed; what a stopwatch and a key holder learn is not. A lookup that hits and a lookup that misses do not take the same time, and an unknown name now costs one verification rather than a map read, which makes the two paths do the same work rather than the same number of nanoseconds: nothing here measures or bounds that difference, and no constant-time claim belongs in this row. Behind a valid signature the answers are specific by design, revoked, replayed, out of scope, over limit, because that caller is the one who can act on them. A `SCOPE_DENIED` refusal still says in its message whether the table has no row for the target or the credential lacks the row's scope, so paths remain enumerable from inside, by a credential this deployment issued. None of this makes the credential file invisible to the people who hold it: an operator, a reader of that volume, or anything that can write it knows every id in it, and the access log names the id a refused request presented even where the response never acknowledged it. The bearer digest scan's cost also grows with the size of the credential file rather than with how close a guess was |
| T16 | A receipt id reaches someone it was not issued to, in a log line, a proxy access record, or a pasted URL, and that holder reads whose credential minted it, or walks the deployment's other receipts | This gateway mints every id itself: sixteen hex tag characters then thirty-two hex characters from a fresh draw, replacing the upstream-chosen id a counter or a timestamp could have made walkable. The tag is `HMAC-SHA256(namespaceKey, credentialId)` truncated to eight bytes, and the namespace key is an HKDF over the deployment's own Ed25519 signing seed, so a holder of an id cannot reverse the tag into a credential id and cannot compute the tag for one: neither is possible without the seed. The fetch route then asks whether the presenting credential's own tag heads the id and serves nothing when it does not, which is why no ownership state is kept that could drift out of step with the receipts it governs | Linkability, not identification, plus the operator's own reach, which is the reading [access-control.md](access-control.md) section 8.3 gives. Two ids carrying one tag came from one credential, so anyone who sees both knows they belong together; and the deployment holding the seed can compute each credential's tag and so name the credential behind any id shown to it. An erasure does not close either: the tag is not a log field, it is a prefix of the id, and the receipt chain is append-only, so scrubbing a credential's lines leaves every id it ever read in place. See section 6 |

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
- **A composite claim has no proof of attachment.** Neither `"snp+gpucc"` nor `"tdx+gpucc"` is
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
- **The producing path has not been answered by a real image.** Today the gateway asks dstack's v1
  device attestation route and serves the vendor's `nvattest` bundle unchanged; both are
  implemented from published shapes and tested against a fake guest. The guest agent's wire
  contract and the per-device field names stay assumptions until a real dstack image replies to
  the call. The settled direction, recorded 12 September 2026, is to collect device evidence
  inside our own container with the vendor's own tool instead of depending on a guest-agent
  release: that tool is what the platform's agent itself shells out to, other vendors document
  their customers running it, and one producing path then serves every rail this stack can run on
  rather than only the one rented first. That collection code is not in this repository yet. The
  route already written stays and is used when an image offers it, since it is written and tested
  and deleting it buys nothing. Both producers emit the vendor tool's own bundle format, so the
  verifier cannot tell them apart and does not need to, and what the bundle proves is unchanged by
  who collected it: a genuine confidential-computing GPU answered this challenge. Acceptance is
  therefore the bundle verifying under a pinned device root against the challenge the platform
  quote committed to, not the tool having run. Nothing degrades silently in the meantime: an image
  that offers no device route stops a deployment configured to claim one.
- **The mock gateway is not a TEE deployment.** It signs with an ephemeral development key,
  its `meas` and `att` fields are digests of fixed strings, and its evidence URL uses the
  `mock://` scheme. It reports `tee: "software"`, the member of the enum that claims no
  hardware protection, so no field of a mock receipt reads as a TEE assertion.
- **The access floor attributes requests, it does not conceal them.** Admission runs before any
  route answers, including a target the server never registered, so an unmatched path is refused for
  the credential its caller omitted rather than as a 404 ([access-control.md](access-control.md)
  section 2). What that decision costs is one line of twelve allowlisted fields per request, admitted
  or refused, and the field list is the whole record: no body, header, secret, key, query string,
  source address or user agent has anywhere to be written. The line is the deployer's artifact, kept
  for `--access-log-days` (184 by default, and a shorter value starts with a note rather than a
  refusal), and `ashaveri accesslog scrub --credential <id>` empties one credential's lines and
  files a marker saying it ran. Two things sit outside that erasure, and they are the residuals of
  T15 and T16: a receipt id's tag is legible to whoever holds the signing seed, log or no log, and a
  credential this deployment issued can still ask a route whether the table has a row for its target
  and read the answer in the refusal's message. What is not there is the older T15 residual, closed
  on 19 September 2026: an invented `pop` credential id is refused exactly as a failed signature is,
  so no refusal distinguishes a real id from an invented one for a caller that has proved nothing. The
  access log does keep the true reason for such a refusal, and the log is the deployer's artifact,
  erased with the credential it names.
- **Receipt retention is a deployment choice, not a protocol guarantee.** A signerd started with
  `--receipts-dir` appends each receipt to a hash-chained file on that volume and keeps it for 184
  days, or until 10,000 later receipts push it out as a bound on the volume, whichever comes
  first, and the store then reports the window it actually kept rather than the one it was asked
  for. Without the flag, receipts stay in this process's memory and are gone at restart, which is
  the default the mock gateway and the test suite run on. Chaining buys one thing and not the
  other: removing a record from the middle breaks every digest after it and the gateway refuses to
  open the file, while retiring an aged prefix is written down as a record saying how many it
  dropped. What it cannot do is resist an operator who holds every record and rebuilds the file
  from scratch. Catching that needs the chain head kept somewhere the operator does not control
  and compared for continuity across windows, and no client does that yet. There is no runtime key
  rotation either: `--epk` publishes the epoch of the key a process started with, so rotating
  means a new deployment with a new `--key-path` and a higher epoch.
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
