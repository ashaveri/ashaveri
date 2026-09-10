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
truthfulness of a gateway's claims about hardware it does not actually run on. Section 5 is
explicit about the current gaps.

## 2. Assets

- **A1 Response integrity.** The completion the user saw is the completion the gateway signed.
- **A2 Request-response binding.** The receipt is about this request, not another one.
- **A3 Gateway identity.** Which deployment, under which signing key, produced the response.
- **A4 Deployment claims.** Model id, weights digest, TEE measurement, attestation evidence reference.
- **A5 Token metering.** The billed token counts are the ones signed.
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
| T10 | DoS: gateway refuses to serve receipts | Receipt fetch retries with a short window, then fails closed in verification | Availability is out of scope |
| T11 | Side channels on prompt content via receipts | Receipts contain hashes and counts only, never content | Hashes reveal content length implicitly (already visible in the response) |

## 6. Current limitations, stated plainly

The MVP gateway, `signerd --mock`, is a development tool. Concretely, today:

- **Receipt issuance is not TEE-backed.** The signing key is a development Ed25519 key held
  in process memory. The `meas` and `att` fields are digests of fixed mock strings, and the
  evidence URL is a mock scheme. A mock receipt proves the mock gateway signed the bytes; it
  makes no statement about confidential hardware.
- **No attestation verification is wired into the serving path.** `@ashaveri/attest-core`
  can independently verify dStack SEV-SNP and TDX attestations offline, but nothing yet
  forces signerd to hold fresh attestation evidence before it is allowed to sign. Closing
  this, binding the signing key to a measured boot, is the explicitly planned hardware gate
  in the roadmap.
- **Receipts live in process memory** on the mock gateway, with no persistence or rotation
  (`epk` is always 0). A real deployment needs key management with epoch rotation and a
  retention store for receipts.
- **The manifest is unsigned.** In strict mode this is mitigated by policy pinning, but the
  intended end state is a manifest signed by a long-term deployment identity.

Until the hardware gate lands, the honest summary is: receipts deliver byte-level integrity
and provenance today, and TEE-backed measurement claims are protocol-ready but not yet
enforced. The SDK's strict mode is built so that the enforcement step can be added without
changing the client contract.

## 7. Relationship to attest-core

`@ashaveri/attest-core` verifies attestation evidence: certificate chains against a pinned
AMD ARK, report signatures, TCB, runtime event logs, and measurement values. The receipt's
`att` field is the designed rendezvous point: once the gateway must present evidence whose
digest matches `att.d`, freshness within `att.ts`, and a measurement consistent with `meas`,
the T7 "consistent lying" residual shrinks from "trust the gateway's self-description" to
"trust the hardware's measurement." The integration sequencing is deliberately staged: the
receipt format and client verification shipped first, so the hardware gate changes the
gateway, not the clients.
