# Ashaveri Receipt Specification

Status: Draft, payload versions 1 and 2. The binary format is normatively defined by
[`packages/receipt/receipt.cddl`](../packages/receipt/receipt.cddl) and the golden conformance
vectors in `@ashaveri/fixtures`. Which suites and fixtures are published, and which payload version
each of the receipt fixtures carries, is stated once in the inventory in
[vectors.md](vectors.md) rather than restated file by file here. This document specifies the format
together with the HTTP protocol used to deliver receipts, and the algorithm clients follow to
verify them. Section 6 says which payload versions a verifier reads.

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
    unprotected: { * any => any }
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

The list is exhaustive, not illustrative. Those bytes are hashed into the `Sig_structure`, so a label
the table does not name is a parameter the issuer authenticated, and a verifier that read the three
it knows and returned those would hand its caller a document other than the one that was signed. A
receipt whose protected header carries any other label is refused, and the refusal names the label. The
rule closes by number rather than by names this document recognises, so it reaches the parameters RFC
9052 registers as well: `crit`, label 2, a sender's way of asking that a recipient understand something
about the message, is refused in the signed header like any label the table does not name. Nothing here
answers such an ask, and not because the number is unknown to it: a sender may still write a label 2
into the unprotected map, which the format leaves open on purpose, and that map carries no claim about
the response, as the paragraph below says of it.

The list is exhaustive about names, and it is exhaustive about types. The three labels are integers and
the value at each is the kind the table gives it, so the header is decoded where no floating-point
number may appear, in a key as much as in a value. A label written as the half-float `1.0` arrives in
the same slot of the map a reader is handed as the integer `1`, and the value it carries is the one
that stands for both, because core deterministic ordering writes the one-byte integer first and the
three-byte float last and the later key is the one a reader of the finished map sees. Refusing that
document is the header's closure rule applied where it still means something rather than a type check
run late: once the bytes have become a map there is nothing left to distinguish, and two verifiers can
read one signed header and name different parameters in it. The same reaches `alg`, whose value is the
integer `-8`; a `-8` written as a float is refused with the header, while an `alg` holding a suite this
format does not sign with keeps its own answer. The map outside the signature is not read this way: the
format writes `{ * any => any }` for it, and a number in a place the format declines to describe is
not an integer wearing another coat.

The signature is computed over the RFC 9052 Sig_structure (section 4.4)
`["Signature1", protected, external_aad, payload]` with an empty external AAD.

The unprotected header is not part of the signature, and the format therefore declares nothing about
its contents: it is the map that carries no claim, and a verifier reads no verdict out of what it
holds. Its emptiness is not enforced, because enforcing it would add a refusal with nothing behind it.
Receipts are always exactly one signature; multiparty or
countersignature variants (RFC 9338), if ever needed, would be a new format version.

## 3. Payload

| Field | Type | Meaning |
|---|---|---|
| `v` | int | Payload version, and the member that says which shape the rest of the map is: `1` is the thirteen fields of this table, `2` is those same thirteen plus a required `mk`, the marking attestation [`receipt.cddl`](../packages/receipt/receipt.cddl) defines. Which of the two a verifier reads is section 6's rule, and the map is closed, so a member a document carries that its own version does not define is a malformed payload rather than one the reader leaves out. |
| `iss` | tstr | Issuing deployment identity. |
| `ins` | tstr | Issuing instance identity. |
| `iat` | int | Issuance time, Unix seconds: the moment the gateway signed this receipt, and the instant a verifier's receipt window is measured from. |
| `nce` | bstr (16) | The client nonce echoed back. See section 4. |
| `req` | bstr (32) | sha256 of the exact raw request body bytes. |
| `res` | bstr (32) | sha256 of the exact raw response body bytes, including SSE framing. |
| `mdl` | tstr | Model id, e.g. "mock-model-1". |
| `wts` | bstr (32) | sha256 digest of the deployment's weights manifest. |
| `meas` | map | `{ tee, m }`: the environment kind, one of `"software"`, `"snp"`, `"snp+gpucc"`, `"tdx"`, `"tdx+gpucc"`, plus the measurement for that kind. A TEE reports its platform-native 48-byte SHA-384 value (SEV-SNP launch digest or TDX MRTD); `"software"` makes no hardware claim and carries a 32-byte SHA-256 digest of what the deployment runs. The width is fixed by the kind, so a digest that does not match its own kind is malformed. |
| `att` | map | `{ d, ts, url }`: digest of the attestation evidence document, its timestamp (Unix seconds) — the moment the evidence was collected, which is the instant a verifier's evidence window is measured from, and is earlier than `iat` on a deployment that quotes per request — and a URL where the evidence can be fetched and re-verified. |
| `epk` | int | Signing-key epoch, for key rotation. A gateway publishes the value it was started with (`--epk` on signerd) and never changes it, so rotating a key means a new process with a higher epoch. |
| `tok` | map | `{ p, c }`: prompt and completion token counts for the call, as the serving stack reported them. A receipt proves who claimed a count, not that the count is right. |
| `mk` | map | `{ sch, d }`: the marking attestation, and the only member `v: 2` adds to the thirteen above, where `v: 1` carries no `mk` at all because the closed map named in the row above refuses a v1 document that does. It is required in v2, so an absent `mk` is a malformed payload (`BAD_PAYLOAD`) rather than a reading of "unmarked": unmarked is a declared value of `sch`, never an omitted member. `d` is sha256 of the marked region exactly as the response bytes carry it, not of the whole response. The shape is `Marking` in [`receipt.cddl`](../packages/receipt/receipt.cddl), and which labels `sch` draws on, with the bytes each one marks, is section 3.3. |

All integers are non-negative. Every one of them is a CBOR integer as well: the payload is decoded
where no floating-point number may appear, at any depth, so a `tok.p` written as the float `128.0` and
an `iat` written as the half-precision negative zero `f9 80 00` are malformed payloads (`BAD_PAYLOAD`)
rather than 128 and 0 read loosely. The positions are `v`, `iat`, `att.ts`, `epk`, `tok.p` and `tok.c`:
five the normative CDDL writes `int`, and the version it writes as the integer literals `1` and `2`,
which a `1.0` does not become. The writer that issues a receipt keeps the same rule from its own side,
and `encodeCanonical` in this repository is where it does so: negative zero has one canonical integer
spelling, the one `0` gets, so a float standing at one of these positions is a document another
implementation wrote and never one this package signed and could not read back. The width of the rule
is the table above and no more: it names every member of the payload and of the maps inside it, and
none of those positions is written as a float. A bignum is refused too, and twice over: the canonical
encoding this format requires rejects the bignum spelling of any value a plain integer can hold, and
one it cannot is outside the range the six positions above are read in, so it arrives as a value no
position here takes. Maps use bytewise canonical key ordering per RFC 8949 CDE.

### 3.1 Hash definitions

Both hashes are computed over raw bytes on the wire, before any decoding:

- `req` = sha256 of the request body exactly as transmitted. Two JSON bodies that parse to
  the same object but differ by a byte produce different `req` values.
- `res` = sha256 of the response body exactly as transmitted. For streaming responses this
  includes every SSE frame, separator, and terminator, not only the concatenated `data:`
  payloads.

This is why the gateway signs the bytes it forwarded, and the client hashes the bytes it
received: any difference, including a transport-level re-encoding, breaks verification.

Both rules are published as vectors a reimplementation can check itself against:
`packages/fixtures/data/req-v1.json` for `req`, and `packages/fixtures/data/res-v1.json` for
`res`, including a streamed response whose framing is inside the hash. How to read those
files, and what they do not settle, is in [vectors.md](vectors.md).

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

### 3.3 Marking schemes

`mk.sch` is a label from this table and from nothing else. What a label marks is settled here, in a
document a stranger may read, rather than inside the software that writes a mark: a detector
belonging to a customer, an auditor or a competitor has to arrive at the same span of bytes that the
receipt digested, and a writer that hashes one span while a reader hashes another agree with
themselves and disagree with each other, with nothing to show for it but a digest that does not match
over bytes nobody edited. `extractMarkedRegion` in `@ashaveri/receipt` is the executable form of these
two rows, and it is the module the gateway writes from and the live client checks with, so the
published rule and the running one are one rule.

| `mk.sch` | What it declares | What a verifier looks for, and what `d` is the digest of |
|---|---|---|
| `"none"` | No region of this response carries a marking, which is a claim about the bytes rather than an absence of a field | No `provenance-v1` region in the response at all. The marked region is the empty input, and `d` is sha256 of zero bytes. A response that does carry a marked region is refused over a `"none"` receipt, so a backend that marks its own output bites a deployment that marks nothing. |
| `"provenance-v1"` | The response carries one machine-readable marking, and that marking says the content it accompanies was generated | Exactly one region, and `d` is sha256 of exactly its bytes and of nothing beside them. In a buffered completion the region is one top-level member: its name, its colon and its value, spelled as the body carries them. In a stream the region is one `data:` field line, its terminator excluded, whose payload is a completion chunk carrying an empty `choices` beside that same member. |

The marked region of a `provenance-v1` response is this member:

```json
"ashaveri": { "marking": { "sch": "ashaveri/provenance-v1", "gen": "ai", "at": 1772000000 } }
```

`gen` says the accompanying content was generated, `at` is the marking time in whole Unix seconds,
and the whole number is load-bearing because the member's own text is what `d` hashes: a fraction, or
the negative zero a floating-point spelling keeps, would be baked into the digest as a document no
reader can reproduce from a timestamp.

Four things follow from the table, and a detector needs them all:

- **The frame is a chunk, not a bare frame.** The `choices` array has to be present and empty, which is
  what makes the marking one more chunk to anything accumulating a completion off a stream. Measured,
  not assumed: a frame that is neither a chunk nor the sentinel is delivered whole by that accumulator's
  iterator and then breaks it, after content has already reached the caller
  (`packages/sdk/test/unknown-response-members.test.ts`). A mark that costs the customer their
  completion is not a mark.
- **Exactly one region, so two is a refusal.** A response carrying the shape twice — which is what an
  upstream that marks its own output writes — has no marked region, because a verifier would have to
  choose which one the receipt meant. Zero and two are both answered `MARK_MISMATCH`, the code the
  field exists to have, and neither is ever `INVALID_SIGNATURE`.
- **A label is bound to one byte shape for as long as it exists.** A shape change takes a new label
  rather than re-pointing an old one, because a detector that read the first spelling would read the
  second one's bytes and find them satisfactory. An unknown label is `UNSUPPORTED_SCHEME`, raised by the
  parser before a payload is read, which is the refusal that stops a verifier guessing at a rule it has
  never been given. Adding a scheme is one row above and one entry in `MARKING_SCHEMES`
  (`packages/receipt/src/receipt.ts`); it is not a payload version, and `v` does not move for it.
- **Two spellings, one scheme.** The registry label is `provenance-v1`; the member carries
  `ashaveri/provenance-v1`. They are one scheme written for two readers: the member is bytes of a
  transcript that anyone may republish, where a name worth looking up needs an owner beside it, and
  `mk.sch` is a field of a document that already names its issuer in `iss`. Locating a region is
  structural and never reads that text; the text is what tells this marking apart from an unrelated
  extension of somebody else's that happens to share the member name.

What the registry does not do is certify a mark. A region bearing a known label is not thereby
genuine: anyone can type the member, and a mark standing alone in a transcript is a string with no
verifier. What makes one this deployment's is `d` inside a signed payload whose `res` covers the bytes
around it, which is why the pair is checked together and why neither half is the evidence on its own.
And what a verifier needs is the bytes: a reader holding the words alone, pasted out of a chat window
or retyped, has no region to look for, which section 6 of [threat-model.md](threat-model.md) states as
a limit rather than as a gap on a roadmap.

## 4. HTTP protocol

Receipts ride alongside an OpenAI-compatible chat completions API. The paths in this section are
relative to the deployment's base URL, the value a client configures as `baseUrl`, and a signerd
deployment mounts each one under `/v1`: on such a gateway the receipt route is
`GET /v1/receipts/<receipt-id>`.

### 4.1 Request

The client POSTs to `/chat/completions`. A deployment that requires a proof of possession refuses
the request before any inference runs unless it carries an `Authorization` header that names a
credential and signs the request:

```text
Authorization: Ashaveri-PoP credential=<id>, ts=<seconds>, sig=<base64url>
x-ashaveri-nonce: <base64url, 16 random bytes>
```

The header carries the credential id, the request timestamp, and the signature, and nothing else
about the credential: the id is looked up in the deployment's own credential set, and the signature
proves the caller holds the key that id names. `sig` is the Ed25519 signature over a signing string
of six components joined by `\n`, in this order:

1. the scheme string `ashaveri-pop-v1`,
2. `ts`, the same Unix-seconds value the header carries, written in decimal,
3. the nonce as unpadded base64url, exactly the sixteen bytes in `x-ashaveri-nonce`,
4. the HTTP method, upper-cased,
5. the request target the client actually sent, the path and query including the deployment's mount
   prefix, so `/v1/chat/completions` on a signerd gateway,
6. the lowercase hex SHA-256 of the request body, or of the empty byte string when the request has
   none.

The gateway checks that signature against the key the named credential holds. It also requires the
request to be fresh: a `ts` further from the gateway's own clock than the deployment's tolerance, in
either direction, is refused, and 120 seconds is what a deployment that sets nothing runs with. On
this deployment the nonce is not something the gateway invents. A proof-of-possession request whose
`x-ashaveri-nonce` header is absent, or is not unpadded base64url for sixteen bytes, is refused with
`AUTH_NONCE_MISSING`, and the bytes in that header must be the same sixteen that went into
component 3, because the signature covers them. The published proof-of-possession vectors in
`packages/fixtures/data/pop-v1.json` all carry one fixed `ts` chosen for reproducibility rather than
plausibility, which sits outside the 120-second window above, so a verifier that applies the
freshness rule refuses those authorizations on the timestamp alone even though each signature
verifies over the published signing string.

A deployment that runs in bearer mode admits the same completion without a signed header. There the
client MAY omit `x-ashaveri-nonce`, and a gateway that does not receive it generates its own nonce;
a receipt made over a generated nonce carries no anti-replay value for the client, because the
client never chose it. A header that is present and unreadable is not replaced: the completion
handler answers 400 for it, so a bearer client that sends a nonce had better send sixteen bytes of
it.

### 4.2 Response

Responses carry one additional header:

```text
x-ashaveri-receipt-id: <id>
```

The id is a handle to bytes only this gateway holds, not a proof: only the issuing deployment
resolves it to a receipt, its second half is fresh randomness nobody can guess, and it is the key
the store is looked up by. It is not, however, opaque about where it came from. The id is 48
lowercase hex characters: the first 16 are an eight-byte tag the gateway derives from the minting
credential's id, and the remaining 32 are the random bytes. Anyone holding the id can read that
tag off its front, so two ids that share the prefix were minted by the same credential: the id
links receipts to each other even to a reader with no secret. Recovering which credential a tag
stands for takes the key the gateway derives tags under, which the deployment keeps, so an id on
its own does not hand a stranger a name. Fetching the bytes the id points at needs the `read`
scope and the tag check described in section 4.7.

### 4.3 Fetching a receipt

```text
GET /receipts/<receipt-id>    -> 200 application/cbor, receipt bytes
                              -> 404 if unknown
```

Gateways may register a receipt shortly after the response body completes; clients should
retry briefly on 404. How long a receipt stays fetchable is the gateway's choice and the
protocol does not carry that answer, so treat an id as a handle rather than a proof. A signerd
started with `--receipts-dir` appends each receipt to a hash-chained file on that volume and
keeps it for 184 days, or until 10,000 later receipts push it out as a bound on the volume,
whichever comes first; one started without it keeps receipts in process memory and serves none
of them after a restart. Fetch the bytes and keep them if the proof has to outlive the
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
kid the receipts carry. A verifier reads such a key as untrusted input and checks signatures
against it under the strict (RFC 8032) rule, so a key of small order and a signature whose
encoding is not canonical are refused instead of accepting every message. `models` lists model
ids with the weights digest each receipt for that model must carry. `meas` is the launch
measurement the deployment claims, and its width follows from its kind: 96 hex characters for
an SEV-SNP launch digest or a TDX MRTD, 64 for a `"software"` deployment that has no hardware
measurement to report. The example above is a mock deployment, so it reports `"software"`.

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

### 4.7 Receipt authorization

The fetch in section 4.3 is not a public read. On a gateway that keeps a credential set the route
`GET /receipts/<id>` is granted to the `read` scope, so a request for it is admitted on the same
proof-of-possession or bearer terms as any other route, and one that names no usable credential is
turned away before the gateway looks at the id. The scope table and the fuller account of what each
route demands are in `docs/access-control.md`; this section records only what the fetch route itself
does with the id.

A credential with `read` still cannot read another credential's receipt. The gateway derives the
caller's own tag from the credential it just admitted and checks that tag against the first sixteen
characters of the id before it asks the store for anything. An id carrying a different tag, or one
too short to carry a tag at all, is refused at that check and the store is never read.

A refusal at the tag check is answered exactly as a request for an id this gateway never minted:
status 404 with the message `no receipt for id <id>`, the caller's id quoted back unchanged. The
compare does not fail early on the first differing character, and the two refusals share one text,
so the route discloses nothing about whether bytes exist for someone else. It answers whether this
caller's credential could have minted the id, not whether the id exists. What the tag prefix reveals
to a holder of the id, and what erasing the access log can and cannot undo around it, is treated in
`docs/access-control.md`.

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
5. **Check freshness.** `iat` must be within the verifier's receipt window of the checking moment,
   and `att.ts` within its evidence window; both are compared as magnitudes, so a stamp hours in
   the future is refused exactly as one hours in the past is. The two windows measure different
   things: the receipt window bounds how long after issuance a receipt may be presented, and the
   evidence window bounds how old the attestation may be relative to when it was read, which on a
   per-request deployment is the whole duration of the request plus the presentation delay. That is
   why a client that pins a policy and sets neither number still checks a clock, and why the two
   defaults it gets are not equal: 300 seconds on `iat`, 900 on `att.ts`
   (`DEFAULT_MAX_RECEIPT_AGE_SECONDS` and `DEFAULT_MAX_EVIDENCE_AGE_SECONDS` in
   `packages/sdk/src/policy.ts`). A policy that names its own number replaces the default, and a
   policy that names `Number.POSITIVE_INFINITY` switches that one window off, which is the way to
   say so out loud when verifying an archived receipt. A verifier handed no policy at all, which is
   what `@ashaveri/receipt` gives an offline auditor working on last year's receipt, checks no
   clock: the format never assumes one.
6. **Check the request hash.** `req` must equal sha256 of the exact bytes the client sent.
7. **Check the response hash.** `res` must equal sha256 of the exact bytes the client
   received.
8. **Check the marked region.** A `v: 2` payload names one marking scheme and one digest of a region
   inside the response, so a reader holding those bytes extracts the region by the rule the label
   names — section 3.3, whose rows are executable in `extractMarkedRegion` in `@ashaveri/receipt` —
   and requires `sha256(region)` to equal `mk.d`. A region that fails to be exactly one answers
   `MARK_MISMATCH` either way: a `provenance-v1` response carrying the shape twice has no marked
   region, because a reader would have to choose which one the receipt meant, and so has one carrying
   it not at all. Under `sch: none` the region is the empty input, whose digest `mk.d` carries, and a
   response that does carry a marked region is refused over that receipt too. The other two failures
   keep their own codes: a mark deleted from bytes a reader stored moves `res` and stops at step 7,
   and `INVALID_SIGNATURE` stays the answer about a receipt that is not authentic. A reader handed no
   response bytes performs no marking check, and a `v: 1` payload makes no marking claim to check.
9. **Check policy pins.** Issuer, instance, and measurement must each be pinned by the
   policy when the client pins that dimension.
10. **Verify the evidence the receipt commits to.** Strict mode only. The client asks the
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
| `off` | No nonce of the client's own, no verification, receipts never fetched. It is not a claim about the wire: a proof-of-possession client still sends `x-ashaveri-nonce`, because the signing wrapper has to put a nonce under the signature and the gateway refuses a PoP request that carries none. |
| `receipt` | Nonce injected, receipt fetched and verified (steps 1 through 8, step 5 only for a caller that hands the verifier a window). Key resolution uses the deployment manifest. An unreceipted response returns a `null` receipt instead of failing. |
| `strict` | As `receipt`, plus a required policy (step 2 and 9 with pins, and step 5's two freshness windows, which run at the SDK's shipped defaults unless the policy names its own numbers), an unreceipted response is an error, and the evidence behind step 10 is fetched and verified. |

`receipt` mode proves the response came from the deployment that controls the manifest's
keys. `strict` mode additionally freezes the deployment's identity: keys, issuer, instance,
and measurements cannot change without the client updating its policy.

Which payload versions a call reads is none of these three choices to make. Section 6's
`acceptedVersions` is an option on `@ashaveri/receipt`'s own `verifyReceipt` and `decodeReceipt`, and
no mode above passes it, so an integrator verifying through the SDK gets the default set, which
today admits both versions, and has no flag to refuse a `v: 2` receipt with.

### 5.2 Record framing and chain recomputation

Everything above verifies one receipt at a time. A reader holding a pack — many receipts gathered
from one deployment over a span of time — has a second job: recompute, with no network and none of
our code, the digest chain that binds those receipts to each other. This section states the byte
framing that recomputation rests on. The bytes are published as file images in
`packages/fixtures/data/chain-v1.json`, and `gateway/src/store.ts` writes them; where a sentence here
and those two disagree, the vector file and the store are the authority, not this prose.

**The frame.** The store appends one record per receipt to a single file it names `receipts.log`
(`RECEIPT_STORE_FILE` in `gateway/src/store.ts`), concatenating the frames with nothing between them.
A frame reads, field by field:

```text
len:u32 || kind:u8 || prev:32 || iat:u64 || idLen:u16 || id || payload || digest:32
```

`id` and `payload` have no fixed width, so the byte ranges below are those of one concrete record — the
first record of the `first-record` scenario, whose `id` is 48 bytes and whose `payload` is 64 — counting
from the frame's own first byte. A reader who changes the id or the payload length moves only the last
three ranges, and moves them by the amount stated under the table:

| Field | Byte offset in one frame | Width |
|---|---|---|
| `len` | 0-3 | 4 |
| `kind` | 4-4 | 1 |
| `prev` | 5-36 | 32 |
| `iat` | 37-44 | 8 |
| `idLen` | 45-46 | 2 |
| `id` | 47-94 | 48 |
| `payload` | 95-158 | 64 |
| `digest` | 159-190 | 32 |

The offsets of the fixed fields are not free to move: each is the running sum of the widths of every
field ahead of it, so `kind` sits at byte 4, `prev` at 5, `iat` at 37 and `idLen` at 45 the moment the
widths are what they are. `id` starts at byte 47, one past `idLen`, and runs for `idLen` bytes;
`idLen` holds the byte length of `id`, not a character count. `payload` starts where `id` ends and runs
to the byte before the digest, and `digest` is always the frame's final 32 bytes. `len` counts from
`kind` through `digest` inclusive, which is the whole frame minus the 4 bytes of `len` itself, so a
reader locates the end of a record by adding `len` to the offset `len` starts at rather than by reading
the payload. Every integer in a frame — `len`, `kind`, `iat`, `idLen`, and the trim counters below — is
unsigned and stored big-endian.

**Why the digest covers less than the frame.** `digest` is `sha256` over every byte between the length
prefix and the digest: `kind` through `payload`, bytes 4 through 158 of the record above, 155 bytes, or
`len` minus its own 32. It cannot cover the digest that is its own output, and it does not cover the
`len` prefix, because that prefix is a count of the bytes that follow it and would have to change
whenever they did. `len` and the digest input are therefore deliberately different spans: `len` runs
from `kind` to the last byte of `digest`, the digest is taken over `kind` to the last byte of `payload`,
and the 36-byte gap between the frame and the hashed input is the 4 length bytes plus the 32 digest
bytes. A reader who hashed the whole frame, length prefix and digest included, would recompute a value
no record carries and refuse a file the store wrote correctly.

**Kinds.** `kind` takes one of two values, and they decide how the rest of the frame reads:

| Record kind | Byte value |
|---|---|
| `receipt` | 0 |
| `trim` | 1 |

A receipt's `payload` is the signed receipt bytes, stored whole and opaque to the chain; nothing in a
record digest depends on what they hold. A trim is the record the store writes at the very front of the
file when retention reclaims a retired prefix. It carries no receipt, so its `id` is empty, and its
payload is a second fixed layout:

```text
seam:32 || byAge:u32 || byCount:u32 || maxAgeSeconds:u32 || maxCount:u32
```

within the trim payload, counting from that payload's first byte:

| Field | Byte offset in the trim payload | Width |
|---|---|---|
| `seam` | 0-31 | 32 |
| `byAge` | 32-35 | 4 |
| `byCount` | 36-39 | 4 |
| `maxAgeSeconds` | 40-43 | 4 |
| `maxCount` | 44-47 | 4 |

A bound of zero in a trim states that no such bound was configured, which a reader has to tell apart
from a bound of one. A trim is not a link in the receipt chain: it precedes every receipt in the file
and nowhere else, and a reader folding one into a recomputation as if it were a receipt has misread the
frame, not found a broken chain.

**Walking from an anchor to a head.** Recomputation runs forward, from an anchor to a head, and the
per-record digest is what makes each step checkable:

- The anchor is the digest the oldest receipt the reader was given was chained from, and that receipt
  names it in its own `prev`. In a file nothing has retired, the anchor is thirty-two zero bytes,
  because the head of an empty chain has no predecessor; after a retirement, the anchor is the `seam`
  the trim record carries (`anchor` in `gateway/src/store.ts`).
- Each later receipt names, in `prev`, the digest of the receipt before it. The reader recomputes a
  receipt's digest over the input above and checks that the next receipt's `prev` equals it.
- The walk ends at the head, the digest of the last receipt in the chain.

Both endpoints come from the deployment, not from the bytes in the reader's hands, and the reader takes
them from the signed pack manifest, which carries both the anchor and the head. That signature is what
gives the walk its meaning. A chain that recomputes cleanly from the anchor it was given to the head it
was given shows that the receipts inside the pack were not reordered, edited, or lifted from the middle —
but it says that only against a head the reader has no cause to doubt, and the reader's only cause to
doubt or to believe that head is the manifest that states it. Publishing the head is what makes deletion
detectable, in the store's own words (`head()` in `gateway/src/store.ts`); the chain on its own says
nothing about a run of receipts the reader was never handed.

A reader follows the `prev` links to order the walk, not the offsets in the file, because retention
retires prefixes and a compaction rewrites the front of the file without changing any surviving
record's digest. Which receipts a pack holds is a separate question from which the chain links: the
store serves every receipt whose `iat` is at or after a `from` stamp and strictly before a `to` stamp,
so a pack's interval is half-open and its end is excluded — a receipt issued at exactly the end stamp
belongs to the next pack, not this one (`range` and `inRange` in `gateway/src/store.ts`).

**The window's bound, and whether its end is included.** The store's default retention keeps a receipt
for at least `MINIMUM_RETENTION_SECONDS`, which is 184 days — six months rounded up to whole days so
the window is never shorter than the floor it answers to (`gateway/src/store.ts`). The store states that
floor against a legal minimum and says plainly that the code cannot itself check whether a given receipt
falls under that law, so nothing here should be read past what it says. The bound is inclusive at its
older edge: a receipt is retained while its `iat` is at or after `now - maxAgeSeconds`, so one stamped
exactly at the cutoff is still kept. A count cap and the half-open pack interval above are different
bounds answered elsewhere, and neither moves this floor.

**What a partial tail means.** A record whose bytes run past the end of the file — fewer than `len`
after the length prefix — is not a broken chain but an append that never finished: the writer was
interrupted before the record's last byte arrived, and that record can never verify because its bytes
were never all there. A reader takes it back off the file and opens the rest. Nothing can sit behind it,
because nothing was ever written there. The head the reader reports afterward is the digest of the last
complete record, and the next receipt chains onto that head as though the cut had cost only the
unfinished record (the walk's stop in `gateway/src/store.ts`, and the `partial-tail-repair` tail in
`chain-v1.json`). A short read behind a length that does not lie about its own size is the different
case: that is a refusal, not a short file.

**The refusals a reader reproduces.** A chain that cannot be read raises one code, `STORE_CHAIN_BROKEN`,
and names the byte offset it stopped at (`StoreErrorCode` in `gateway/src/store.ts`). Four images in
`chain-v1.json` show four distinct ways that happens, and a reader is expected to reproduce all four:

- `tampered-record-byte` — one bit flipped inside a receipt's payload. The frame still states its own
  length and names the right predecessor; only its digest over its own bytes stops matching, and that
  is what a reader checks.
- `deleted-first-record` — the first of two records lifted out. What remains is whole by its own digest
  and is still refused, because its predecessor slot names a record the reader was never shown.
- `trim-after-a-receipt` — a trim written behind a receipt, describing a hole in the middle of a chain as
  if it were intended, refused on that alone.
- `frame-length-too-short` — a `len` claiming fewer bytes than the header needs, so the reader stops at
  the size and never reaches the digest.

## 6. Versioning

Two payload versions are defined. `v: 1` is section 3's thirteen fields, and `v: 2` is those same
thirteen plus a required `mk`. A payload map is closed at either version, so a member the version a
document names does not define is a malformed payload (`BAD_PAYLOAD`) rather than a member the reader
agrees to leave out: that is what makes "`v: 1` carries no `mk`" a fact of the format rather than an
expectation about it. The rule is not the payload map's alone: the four maps nested inside it,
`meas`, `att`, `tok` and `mk`, carry no `...` in the normative CDDL either, and `@ashaveri/receipt`
refuses an undefined member of any of them with `BAD_PAYLOAD` rather than reading what it names there
and dropping the rest; the signed `Ashaveri-Protected-Header` closes with them, and a label its three
do not name is refused there with `BAD_PROTECTED_HEADER`, before any of the three is read. A reader
that rebuilt a nested value from only the members it knows would
leave its holder no way to tell a receipt that attested one thing from one that attested that thing
and something more, which is the same silence `mk` was given a version to refuse. The mark is why the
number moved rather than the field arriving as an optional member of v1: a reader of a v1 payload
looks at thirteen fields, finds nothing about a mark, and verifies a receipt over an unmarked response
exactly as readily as over a marked one. The deployment manifest is a different document and still has
the one version, `v: 1`.

Which versions a call reads is a setting rather than a fact about the format. `acceptedVersions`
names them on both `verifyReceipt` and `decodeReceipt`, and its default is every version the
package parses, which today is `[1, 2]`. Narrowing it to `[1]` is how a verifier refuses a marked
receipt on purpose, and it is not the setting a caller gets for free. A version outside the
accepted set and a version no format has ever used get one answer, `UNSUPPORTED_VERSION`, because
which of the two it was is a fact about the reader rather than about the bytes, and two codes would
let a caller probe where a release's knowledge ends. A `v` that is not an integer at all is a
malformed payload and gets `BAD_PAYLOAD`, the same answer as any other mis-typed member, and "not an
integer" is meant of the CBOR major type: the float `1.0` is not an integer written in a second way,
it is another type, and it reaches a reader as the number 1. That is why the refusal is made while the
payload is decoded rather than where its version is read, and why `1.0` gets `BAD_PAYLOAD` while `3`,
an integer no format has used, gets `UNSUPPORTED_VERSION`.

The compatibility contract itself is unchanged, and it is the reason a version is the right place
for an addition: software released before payload version 2 existed refuses a `v` that is not 1
with `BAD_PAYLOAD`, which is a fact about the verifiers already in customers' hands and not
something any verifier can alter. A marked receipt therefore reaches an un-updated verifier as a
refusal rather than as a misreading, and a future format version must still change `v`, which
existing verifiers will refuse rather than misinterpret.

The `"software"` kind and the rule that ties `m` to its kind were added without a version bump,
because the contract above covers the direction that matters: a verifier from before the change
refuses an unknown kind instead of reading it as a TEE it does not know, so it rejects a software
receipt rather than misgrading it as a hardware claim. The other direction is a tightening rather
than a break. An older verifier accepted either width for any kind, so it still waves through the
mismatched pair that `receipt-meas-mismatch-v1` exists to catch.

## 7. References

- RFC 8949, Concise Binary Object Representation (CBOR); section 4.2.1 Core Deterministic Encoding
- RFC 9052, CBOR Object Signing and Encryption (COSE): Structures and Process, as updated by
  RFC 9338, CBOR Object Signing and Encryption (COSE): Countersignatures. RFC 9052 removed all
  countersignature text from itself, and RFC 9338 supplies it again. Neither document changes the
  two parts this format rests on: the Sign1 structure (section 4.2) and the Sig_structure
  (section 4.4).
- RFC 8032, Edwards-Curve Digital Signature Algorithm (EdDSA)
- [Ashaveri threat model](threat-model.md)
