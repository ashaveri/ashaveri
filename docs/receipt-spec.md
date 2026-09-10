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
| `meas` | map | `{ tee, m }`: TEE kind ("snp", "snp+h100cc", or "tdx") and the platform's native measurement digest, 48 bytes on live hardware (SHA-384 SNP launch digest or TDX MRTD) and 32 bytes for a software deployment. |
| `att` | map | `{ d, ts, url }`: digest of the attestation evidence document, its timestamp (Unix seconds), and a URL where the evidence can be fetched and re-verified. |
| `epk` | int | Signing-key epoch, for key rotation. The gateway increments it when it replaces its signing key. |
| `tok` | map | `{ p, c }`: prompt and completion token counts for the call. |

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

## 4. HTTP protocol

Receipts ride alongside an OpenAI-compatible chat completions API.

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
retry briefly on 404. Receipts remain fetchable for a retention window the gateway chooses
and advertises out of band.

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
  "meas": { "tee": "snp", "m": "<96 hex chars on hardware>" }
}
```

`keys` lists the Ed25519 public keys the deployment currently signs with, keyed by the same
kid the receipts carry. `models` lists model ids with the weights digest each receipt for
that model must carry. `meas.m` is the launch measurement the deployment claims, at the
platform's native width: 96 hex characters for the SEV-SNP launch digest or the TDX MRTD,
and 64 for a software build that has no hardware measurement to report.

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
re-fetchable only while the gateway retains it, for a window it chooses and advertises out of
band; a receipt whose evidence can no longer be fetched still verifies cryptographically, but
the client can no longer re-check the hardware claims and should treat it as an archived proof.

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

Steps 6 and 7 are what make the receipt a statement about *this* exchange rather than a
generic artifact: a receipt whose hashes do not match the observed bytes is rejected even
when its signature is perfectly valid.

### 5.1 Verification modes

The SDK exposes three levels:

| Mode | Behavior |
|---|---|
| `off` | No nonce header, no verification, receipts never fetched. |
| `receipt` | Nonce injected, receipt fetched and verified (steps 1 through 7). Key resolution uses the deployment manifest. An unreceipted response returns a `null` receipt instead of failing. |
| `strict` | As `receipt`, plus a required policy (step 2 and 8 with pins, optional freshness), and an unreceipted response is an error. |

`receipt` mode proves the response came from the deployment that controls the manifest's
keys. `strict` mode additionally freezes the deployment's identity: keys, issuer, instance,
and measurements cannot change without the client updating its policy.

## 6. Versioning

The payload `v` field and the manifest `v` field are both 1. A verifier rejects values it
does not know, which is the compatibility contract: a future format version must change `v`,
and existing verifiers will refuse it rather than misinterpret it.

## 7. References

- RFC 8949, Concise Binary Object Representation (CBOR); section 4.2.1 Core Deterministic Encoding
- RFC 9052, CBOR Object Signing and Encryption (COSE): Structures and Process
- RFC 8032, Edwards-Curve Digital Signature Algorithm (EdDSA)
- [Ashaveri threat model](threat-model.md)
