# Ashaveri Receipt Specification

Status: Draft, format version 1. The binary format is normatively defined by
[`packages/receipt/receipt.cddl`](../packages/receipt/receipt.cddl) and the golden conformance
vectors in `@ashaveri/fixtures`. This document specifies the format together with the HTTP
protocol used to deliver receipts, and the algorithm clients follow to verify them.

## 1. Overview

An Ashaveri receipt is a detached, signed statement from a gateway about one inference
response. It binds, under a single Ed25519 signature:

- the exact request bytes the client sent,
- the exact response bytes the client received,
- the model id and a weights digest,
- the TEE measurement the deployment claims,
- the token metering for the call,
- a client-supplied nonce and an issuance time.

A client that holds the gateway's public key can verify, offline, that the bytes it saw are
the bytes the gateway vouches for, and can pin which keys, deployments, and measurements it
is willing to accept.

## 2. Envelope

A receipt is a COSE_Sign1 object (RFC 9052 section 4.2) encoded with deterministic CBOR
(RFC 8949 Core Deterministic Encoding, section 4.2.1) and tagged with CBOR tag 18:

```text
COSE_Sign1([
    protected:   bstr  ; CBOR-encoded Ashaveri-Protected-Header
    unprotected: {}
    payload:     bstr  ; CBOR-encoded Ashaveri-Receipt-Payload
    signature:   bstr  ; 64 bytes, Ed25519 over the Sig_structure
])
```

The protected header contains exactly three parameters:

| Label | Name | Value |
|---|---|---|
| 1 | alg | -8 (EdDSA, Ed25519 per RFC 8032) |
| 3 | typ | "ashaveri/receipt" |
| 4 | kid | 32-byte key id, sha256 of the Ed25519 public key |

The signature is computed over the RFC 9052 Sig_structure
`["Signature1", protected, external_aad, payload]` with an empty external AAD.

The unprotected header is empty. Receipts are always exactly one signature; multiparty or
counter-signature variants, if ever needed, would be a new format version.

## 3. Payload

| Field | Type | Meaning |
|---|---|---|
| `v` | int | Format version. Always 1 in this version. |
| `iss` | tstr | Issuing deployment identity. |
| `ins` | tstr | Issuing instance identity. |
| `iat` | int | Issuance time, Unix seconds. |
| `nce` | bstr (16) | The client nonce echoed back. See section 4. |
| `req` | bstr (32) | sha256 of the exact raw request body bytes. |
| `res` | bstr (32) | sha256 of the exact raw response body bytes, including SSE framing. |
| `mdl` | tstr | Model id, e.g. "mock-model-1". |
| `wts` | bstr (32) | sha256 digest of the deployment's weights manifest. |
| `meas` | map | `{ tee, m }`: the environment kind, one of `"software"`, `"snp"`, `"snp+gpucc"`, `"tdx"`, `"tdx+gpucc"`, plus the measurement for that kind. A TEE reports its platform-native 48-byte SHA-384 value (SEV-SNP launch digest or TDX MRTD); `"software"` makes no hardware claim and carries a 32-byte SHA-256 digest of what the deployment runs. The width is fixed by the kind, so a digest that does not match its own kind is malformed. |
| `att` | map | `{ d, ts, url }`: digest of the attestation evidence document, its timestamp (Unix seconds), and a URL where the evidence can be fetched and re-verified. |
| `epk` | int | Signing-key epoch, for key rotation. A gateway publishes the value it was started with (`--epk` on signerd) and never changes it, so rotating a key means a new process with a higher epoch. |
| `tok` | map | `{ p, c }`: prompt and completion token counts for the call, as the serving stack reported them. A receipt proves who claimed a count, not that the count is right. |

All integers are non-negative. Maps use bytewise canonical key ordering per RFC 8949 CDE.

### 3.1 Hash definitions

Both hashes are computed over raw bytes on the wire, before any decoding:

- `req` = sha256 of the request body exactly as transmitted. Two JSON bodies that parse to
  the same object but differ by a byte produce different `req` values.
- `res` = sha256 of the response body exactly as transmitted. For streaming responses this
  includes every SSE frame, separator, and terminator, not only the concatenated `data:`
  payloads.

This is why the gateway signs the bytes it forwarded, and the client hashes the bytes it
received: any difference, including a transport-level re-encoding, breaks verification.

### 3.2 Environment kinds

`meas.tee` names what is vouching for the measurement, and `meas.m` is that thing's native
output. Kind and width are therefore one decision, not two that can drift apart:

| `tee` | `m` | Meaning |
|---|---|---|
| `"software"` | 32 bytes | No TEE. SHA-256 digest of what the deployment runs. |
| `"snp"` | 48 bytes | AMD SEV-SNP SHA-384 launch digest. |
| `"snp+gpucc"` | 48 bytes | SNP launch digest, where the accelerator half of the label is proven by the device report in section 4.6, not by this digest. |
| `"tdx"` | 48 bytes | Intel TDX SHA-384 measurement (MRTD). |
| `"tdx+gpucc"` | 48 bytes | TDX MRTD, where the accelerator half of the label is proven by the device report in section 4.6, not by this digest. |

`+gpucc` says the deployment also runs a GPU in confidential-computing mode, proven by a device
report that answers the same challenge as the platform quote. It names no card generation on
purpose: the device certificate chain inside that report already names the silicon precisely, and
a label that named a generation would be a false claim on the next one.

A decoder rejects a pair that disagrees, in both directions, even when the signature over it
is valid: a 48-byte digest claiming `"software"` and a 32-byte digest claiming a TEE are both
malformed. Enforcing the width per kind is what keeps a deployment from making a hardware claim
it cannot produce hardware evidence for. `"software"` exists so a deployment with no TEE can say
so in the same field without borrowing a value it does not own.

## 4. HTTP protocol

Receipts ride alongside an OpenAI-compatible chat completions API. The paths in this section are
relative to the deployment's base URL, the value a client configures as `baseUrl`, and a signerd
deployment mounts each one under `/v1`: on such a gateway the receipt route is
`GET /v1/receipts/<receipt-id>`.

### 4.1 Request

The client POSTs to `/chat/completions` with header:

```text
x-ashaveri-nonce: <base64url, 16 random bytes>
```

The nonce must be fresh per request and generated with a cryptographic RNG. A gateway that
does not receive the header MAY generate its own nonce, in which case the receipt carries no
anti-replay value for the client.

### 4.2 Response

Responses carry one additional header:

```text
x-ashaveri-receipt-id: <opaque id>
```

The id is meaningful only to the gateway that issued it.

### 4.3 Fetching a receipt

```text
GET /receipts/<receipt-id>    -> 200 application/cbor, receipt bytes
                              -> 404 if unknown
```

Gateways may register a receipt shortly after the response body completes; clients should
retry briefly on 404. How long a receipt stays fetchable is the gateway's choice and the
protocol does not carry that answer, so treat an id as a handle rather than a proof: signerd
serves the 10,000 receipts it issued most recently, drops the oldest to make room for the next,
and loses all of them on restart. Fetch the bytes and keep them if the proof has to outlive the
deployment.

### 4.4 Deployment manifest

```text
GET /deployment-manifest
```

```json
{
  "v": 1,
  "iss": "ashaveri-mock",
  "ins": "mock-instance-1",
  "epk": 0,
  "keys": [
    { "kid": "<64 hex chars>", "alg": "Ed25519", "publicKey": "<base64url, 32 bytes>" }
  ],
  "models": [
    { "id": "mock-model-1", "wts": "<64 hex chars>" }
  ],
  "meas": { "tee": "software", "m": "<64 hex chars>" }
}
```

`keys` lists the Ed25519 public keys the deployment currently signs with, keyed by the same
kid the receipts carry. `models` lists model ids with the weights digest each receipt for
that model must carry. `meas` is the launch measurement the deployment claims, and its width
follows from its kind: 96 hex characters for an SEV-SNP launch digest or a TDX MRTD, 64 for a
`"software"` deployment that has no hardware measurement to report. The example above is a
mock deployment, so it reports `"software"`.

The manifest carries no signature. It is a claim about the deployment, delivered over
whatever transport the endpoint happens to use, so it cannot vouch for itself. A client
gives it weight by treating its values as pins to be met rather than facts to be believed:
fetch the evidence the receipts point at, verify it offline, and require the measurement and
keys to match what was expected. A policy that pins issuers, keys, instances and
measurements turns an unverified manifest into at most a failed check, which is the only
reading of it that is safe.

### 4.5 Attestation evidence

```text
GET /attestation                      -> 200 application/octet-stream, evidence document
GET /attestation?report_data=<64 hex> -> 200, document bound to that report data
                                      -> 400 if report_data is not 64 hex characters
```

The body is the platform's native evidence envelope, not JSON: on dStack deployments it is
the V1 msgpack structure carrying the hardware quote, the runtime event log and the app
configuration. `sha256` of the served bytes must equal the `att.d` of any receipt naming this
URL, so a client can confirm the document it verifies is the one that was signed. Evidence is
re-fetchable only while the gateway retains it, and the protocol carries no announcement of
that window; a signerd process keeps the most recent 256 documents on each evidence route and
drops the oldest first. A receipt whose evidence can no longer be fetched still verifies
cryptographically, but the client can no longer re-check the hardware claims and should treat
it as an archived proof.

### 4.6 Device evidence

A deployment whose receipts say `"snp+gpucc"` or `"tdx+gpucc"` serves the accelerator half
beside the platform document:

```text
GET /attestation/gpu?report_data=<64 hex> -> 200 application/octet-stream, device evidence
                                          -> 404 if the deployment makes no device claim
                                          -> 400 if report_data is missing or not 64 hex characters
```

A deployment answers the capability question first: one that makes no device claim returns 404
without reading the query, because no parameter could make the answer yes.

`report_data` is required here, where the platform route can serve a standing document without
it: an accelerator report is only worth fetching if it names the challenge of the receipt being
checked, and there is no general-purpose answer to fall back on. The body is the JSON array
`nvattest --collect` wrote, byte for byte, each element carrying one device's base64 `evidence`
(the SPDM request followed by its signed response) and `certificate` chain, so the same bytes
still work in NVIDIA's own tool. Serving them unaltered is also why a deployment answers with a
single device's array rather than merging several into a shape neither the vendor nor the
verification library recognizes.

The path is a convention rather than a published value: `att.url` names the platform document
and `att.d` commits to it alone. A client reaches the device route by joining this path to the
receipt's own challenge, which it recomputes, so the gateway never gets to point the client at
evidence for other work.

What the two documents jointly support is narrow, and worth stating exactly. A verified device
report proves a genuine confidential-computing GPU signed `sha256(nce, req)`; the platform quote
proves a genuine attesting VM served that same value. Neither signature covers the other's
bytes, and the NVIDIA report binds the device and its challenge but not the host it sits in, so
nothing here proves the two are the same machine. Only TDISP/TEE-IO device binding closes that
gap. Until a deployment can show it, a composite label means "a real CC GPU attested to this
request" and no more.

One stronger statement is available on TDX and structurally unavailable on SEV-SNP. A TDX
deployment can measure a boot-time GPU appraisal into its runtime event register, which the
platform quote then covers, so the quote itself says this VM booted with this appraised device.
SEV-SNP has no runtime event register, so on that platform the statement is not merely unserved,
it cannot be made. The ceiling on it is as important as the statement: a boot appraisal says the
device was present and appraised at boot, not that it served this request and not that it is still
attached. It is stronger than a device report answered beside the quote and weaker than TDISP/TEE-IO.

That difference is a property of the evidence a client received and the roots it pinned, not a
property of the deployment, so it belongs to a verification result rather than to `meas.tee`. A
kind per tier would describe the serving platform twice, cross the enum with every tier a verifier
might reach, cost a payload version for a judgement made on the far side of the wire, and make the
receipt assert something its signer cannot know, which is whether the client holds the anchors the
tier needs. No verifier in this repository reports a tier yet, so read every composite kind at the
weaker of the two strengths: this challenge was answered by a genuine confidential-computing GPU
and by a genuine VM, and the pairing of the two is the operator's claim.

## 5. Verification algorithm

A verifying client proceeds as follows:

1. **Decode.** Parse the COSE_Sign1 tag, the 4-element array, and both protected header and
   payload. Reject anything malformed.
2. **Resolve the key.** Take `kid` from the protected header. With a policy, the key must be
   pinned in the policy AND declared by the deployment manifest. Without a policy, the key
   must be declared by the manifest. Otherwise reject (unknown or swapped key).
3. **Verify the signature.** Ed25519 over the Sig_structure. Reject on failure.
4. **Check the nonce.** The payload `nce` must equal the nonce the client sent for this
   request. Reject otherwise (replay or cross-request substitution).
5. **Check freshness.** If the client sets a freshness window, `iat` must be within it; the
   evidence timestamp `att.ts` may have its own window. Reject stale receipts.
6. **Check the request hash.** `req` must equal sha256 of the exact bytes the client sent.
7. **Check the response hash.** `res` must equal sha256 of the exact bytes the client
   received.
8. **Check policy pins.** Issuer, instance, and measurement must each be pinned by the
   policy when the client pins that dimension.
9. **Verify the evidence the receipt commits to.** Strict mode only. The client asks the
   gateway for the attestation document whose report data equals
   `sha256(nce, req)`, a value it recomputes rather than reads off the wire, then requires
   that `sha256(document)` equals `att.d`, that the platform signature chains to a pinned
   vendor root, that the document's platform agrees with `meas.tee`, and that the launch
   digest the hardware reports equals `meas.m`. A `tee` of `"software"` claims no hardware,
   so strict mode refuses it before the fetch. This is the receipt's only cross-protocol
   link: the receipt format specifies a digest commitment and nothing else, and the checks
   above belong to the evidence format that `@ashaveri/attest-core` parses. For a composite
   `"snp+gpucc"` or `"tdx+gpucc"` the client additionally fetches the device document from
   the route in section 4.6, using the same challenge it just recomputed, and requires at
   least one NVIDIA SPDM measurement report whose signature verifies under a chain anchored at
   a pinned NVIDIA device root and whose signed challenge equals that same
   `sha256(nce, req)`. The shared challenge is the only link between the two documents:
   neither vendor's signature covers the other's bytes, so a client holding no device
   report has not verified the accelerator half of the label and must reject it.

Steps 6 and 7 are what make the receipt a statement about *this* exchange rather than a
generic artifact: a receipt whose hashes do not match the observed bytes is rejected even
when its signature is perfectly valid.

### 5.1 Verification modes

The SDK exposes three levels:

| Mode | Behavior |
|---|---|
| `off` | No nonce header, no verification, receipts never fetched. |
| `receipt` | Nonce injected, receipt fetched and verified (steps 1 through 7). Key resolution uses the deployment manifest. An unreceipted response returns a `null` receipt instead of failing. |
| `strict` | As `receipt`, plus a required policy (step 2 and 8 with pins, optional freshness), an unreceipted response is an error, and the evidence behind step 9 is fetched and verified. |

`receipt` mode proves the response came from the deployment that controls the manifest's
keys. `strict` mode additionally freezes the deployment's identity: keys, issuer, instance,
and measurements cannot change without the client updating its policy.

## 6. Versioning

The payload `v` field and the manifest `v` field are both 1. A verifier rejects values it
does not know, which is the compatibility contract: a future format version must change `v`,
and existing verifiers will refuse it rather than misinterpret it.

The `"software"` kind and the rule that ties `m` to its kind were added without a version bump,
because the contract above covers the direction that matters: a verifier from before the change
refuses an unknown kind instead of reading it as a TEE it does not know, so it rejects a software
receipt rather than misgrading it as a hardware claim. The other direction is a tightening rather
than a break. An older verifier accepted either width for any kind, so it still waves through the
mismatched pair that `receipt-meas-mismatch-v1` exists to catch.

## 7. References

- RFC 8949, Concise Binary Object Representation (CBOR); section 4.2.1 Core Deterministic Encoding
- RFC 9052, CBOR Object Signing and Encryption (COSE): Structures and Process
- RFC 8032, Edwards-Curve Digital Signature Algorithm (EdDSA)
- [Ashaveri threat model](threat-model.md)
