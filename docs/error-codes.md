# Error codes

Every error code this workspace raises, what condition raises it, and what a caller should do
about it. There are 80 declarations across six unions, resolving to 79 distinct strings;
`UNSUPPORTED_PLATFORM` is the one string two unions share, and the last section
says why that pair is deliberate while every other overlap is not.

Codes are stable identifiers. Messages are not: each is a fixed sentence plus whatever the raise
site knew, so the detail reads differently for a quote than for a certificate. Branch on `code`.

## How to read this

| | |
|---|---|
| **Union** | Which error class carries the code, and therefore which package raised it. A caught exception's class and its `code` say the same thing; a log line carries only the string, which is why every string here names its layer. |
| **Raised when** | The condition at the raise site, not a paraphrase of the message. |
| **What the caller does** | The action that can change the outcome. "Refuse" means present the failure; the receipt is not proven and must not be treated as one. |
| **Verdict** | `terminal`: the same bytes will fail the same way forever, so a retry only adds latency. `retryable`: a later attempt can differ without anything being fixed. Startup refusals are terminal for the process. |

The six unions:

| Union | Package | Owns |
|---|---|---|
| `ReceiptErrorCode` | `@ashaveri/receipt` | The COSE receipt wire format and the PoP Authorization header: decoding, signature, payload fields |
| `SdkErrorCode` | `@ashaveri/sdk` | Client behaviour: transport, policy pins, strict-mode evidence verification |
| `AttestationErrorCode` | `@ashaveri/attest-core` | Platform evidence: dStack envelopes, SNP reports, TDX quotes, device reports, X.509 |
| `GuestErrorCode` | `@ashaveri/signerd` | The guest agent socket inside the confidential VM |
| `DstackErrorCode` | `@ashaveri/signerd` | Gateway startup: the deployment's own evidence, identity and device claim |
| `StoreErrorCode` | `@ashaveri/signerd` | The receipt store file on the deployment's volume |

## `ReceiptErrorCode`

| Code | Union | Raised when | What the caller does | Verdict |
|---|---|---|---|---|
| `MALFORMED_CBOR` | `ReceiptErrorCode` | Receipt bytes do not decode as canonical CBOR | Refuse; the bytes are not a receipt | terminal |
| `NOT_COSE_SIGN1` | `ReceiptErrorCode` | Not tag 18, or not the four-element array COSE_Sign1 specifies | Refuse; check nothing re-encoded the document in transit | terminal |
| `UNSUPPORTED_ALG` | `ReceiptErrorCode` | The protected header's `alg` is not an integer label, or is not EdDSA | Refuse; the receipt claims a suite this spec does not define | terminal |
| `BAD_PROTECTED_HEADER` | `ReceiptErrorCode` | Header is not a map, `kid` is not 32 bytes, or `typ` is not the receipt content type | Refuse; this is a signed envelope for something else | terminal |
| `KID_MISMATCH` | `ReceiptErrorCode` | The header's `kid` differs from the key it was verified against | Supply the key the header names, from the deployment manifest | terminal |
| `UNKNOWN_KEY` | `ReceiptErrorCode` | No key for that `kid`, or the verifier was given neither a key nor a resolver | Fetch the manifest and pass its declared key for that `kid` | terminal |
| `INVALID_SIGNATURE` | `ReceiptErrorCode` | EdDSA verification of the payload fails | Refuse; nothing about the payload can be trusted | terminal |
| `NONCE_MISMATCH` | `ReceiptErrorCode` | `nce` differs from the client nonce the caller expected | Refuse; the receipt answers a different request than the one sent | terminal |
| `STALE_RECEIPT` | `ReceiptErrorCode` | `iat` is outside `freshnessSeconds` of the verification time | Refuse for this receipt; a new request gets a fresh `iat` | terminal |
| `STALE_EVIDENCE` | `ReceiptErrorCode` | `att.ts` is outside `evidenceFreshnessSeconds` of the verification time | Refuse; the platform evidence the receipt commits to has aged out. Re-attest | terminal |
| `BAD_PAYLOAD` | `ReceiptErrorCode` | A payload field is missing, mis-typed, or has a version other than 1; also a measurement whose width disagrees with its kind, at issue time | Refuse; a signed garbage payload is still garbage | terminal |
| `BAD_SIGNING_KEY` | `ReceiptErrorCode` | A signing seed handed to `signingKeyFromSeed` is not 32 bytes | Fix the key material; nothing was signed | terminal |
| `BAD_POP_HEADER` | `ReceiptErrorCode` | A header that does name `Ashaveri-PoP` is missing `credential`, `ts` or `sig`, repeats a parameter, carries one the format does not define, or holds a `ts` or signature outside the width the format allows | Fix the client. The request was not admitted, and the same header will fail the same way | terminal |
| `BAD_POP_NONCE` | `ReceiptErrorCode` | The nonce handed to `signPopAuthorization` is not `POP_NONCE_BYTES` long | Fix the nonce before signing. No signature was made, so nothing left the client | terminal |
| `AUTH_SCHEME_MISMATCH` | `ReceiptErrorCode` | The `Authorization` header does not name the `Ashaveri-PoP` scheme, so no credential was ever named | Send the header form the deployment speaks. Nothing about the credential is known yet | terminal |

## `SdkErrorCode`

| Code | Union | Raised when | What the caller does | Verdict |
|---|---|---|---|---|
| `NO_POLICY` | `SdkErrorCode` | `verify: 'strict'` was configured with no policy to pin keys and measurements | Supply a policy. Strict mode with nothing pinned verifies nothing | terminal |
| `BAD_MANIFEST` | `SdkErrorCode` | The deployment manifest does not parse, or does not declare the `kid` a receipt was signed with | Treat the deployment as unverifiable; the manifest and the signing key disagree | terminal |
| `MANIFEST_KEY_NOT_PINNED` | `SdkErrorCode` | A declared key is not in the policy's pinned set, or disagrees with the pinned key of the same id | Repin deliberately. A rotation is a deployment change, not a transient | terminal |
| `RECEIPT_NOT_FOUND` | `SdkErrorCode` | The receipt route still 404s after the SDK's retry window | Ask again with a new request; the gateway may not have written it, or may not receipt at all | terminal |
| `REQUEST_HASH_MISMATCH` | `SdkErrorCode` | `req` does not equal the hash of the bytes actually sent | Refuse; the receipt is not for this request | terminal |
| `RESPONSE_HASH_MISMATCH` | `SdkErrorCode` | `res` does not equal the hash of the bytes actually received | Refuse; the answer served is not the answer receipted | terminal |
| `ISSUER_NOT_ALLOWED` | `SdkErrorCode` | `iss` is not pinned by the policy | Repin, or refuse. The issuer is who vouched, so this is the decision | terminal |
| `INSTANCE_NOT_ALLOWED` | `SdkErrorCode` | `ins` is not pinned by the policy | Repin, or refuse; an instance id is not a stable pin by itself | terminal |
| `MEASUREMENT_NOT_ALLOWED` | `SdkErrorCode` | The measurement is not pinned for that `tee` | Refuse, or add the digest after re-building the image and re-measuring | terminal |
| `GATEWAY_ERROR` | `SdkErrorCode` | A request to the gateway failed, returned a non-2xx status, or returned a body that is not a chat completion | Retry at a higher level if the operation allows it; a non-JSON body can also mean an intermediary answered | retryable |
| `NOT_RECEIPTED` | `SdkErrorCode` | The gateway answered without a receipt header | Refuse; an unreceipted response is not a completion this format can prove | terminal |
| `EVIDENCE_NOT_FOUND` | `SdkErrorCode` | The evidence or device route still 404s after the retry window | Treat as a refusal for this response. A deployment that never answers the device route cannot back a composite claim | terminal |
| `EVIDENCE_NOT_HARDWARE` | `SdkErrorCode` | Strict mode was asked of a receipt declaring `tee: 'software'` | Do not retry: it claims no hardware, so no evidence endpoint could ever satisfy it | terminal |
| `EVIDENCE_NO_TRUST_ANCHORS` | `SdkErrorCode` | No pinned root is configured for that platform, or none for the device leg | Configure anchors. Without one the signature cannot be checked offline, which is the whole point of strict mode | terminal |
| `EVIDENCE_DIGEST_MISMATCH` | `SdkErrorCode` | `sha256` of the served document differs from the `att.d` the receipt signed | Refuse; the route is serving something other than what was attested | terminal |
| `EVIDENCE_VERIFICATION_FAILED` | `SdkErrorCode` | `@ashaveri/attest-core` refused the evidence; the inner code and message are carried in the message | Read the inner code for the reason. The verdict is already final | terminal |
| `EVIDENCE_NOT_VERIFIED` | `SdkErrorCode` | The quote was replayed and matched, but its own signature was never checked against a pinned root | Refuse. A replayed structure that was not verified proves nothing about who signed it | terminal |
| `EVIDENCE_REPORT_DATA_MISMATCH` | `SdkErrorCode` | The evidence is bound to report data other than what this request recomputed | Refuse; it is evidence of a different moment | terminal |
| `EVIDENCE_TEE_MISMATCH` | `SdkErrorCode` | The receipt's `tee` names a different platform family than the quote is from | Refuse; the label and the hardware disagree | terminal |
| `EVIDENCE_GPU_MISSING` | `SdkErrorCode` | The receipt claims a composite kind and no device report was verified beside it | Refuse. The accelerator half of the claim is unevidenced | terminal |
| `EVIDENCE_MEASUREMENT_MISMATCH` | `SdkErrorCode` | The platform's measured digest differs from the `meas.m` the receipt signed | Refuse; a different image served this, or the receipt is not from this deployment | terminal |

## `AttestationErrorCode`

| Code | Union | Raised when | What the caller does | Verdict |
|---|---|---|---|---|
| `MALFORMED_ATTESTATION` | `AttestationErrorCode` | The envelope does not decode: empty input, unknown first byte, a missing field, a wrong msgpack or SCALE type, or an oversize document | Refuse; nothing downstream can be reasoned about | terminal |
| `UNSUPPORTED_VERSION` | `AttestationErrorCode` | A legacy SCALE tag, a V1 envelope version field other than the one defined, or `gcp-tdx` outside the V1 envelope | Refuse, or update the verifier. The document is from a format this version does not read | terminal |
| `UNKNOWN_PLATFORM` | `AttestationErrorCode` | The platform evidence carries a kind the decoder does not know | Refuse; an unknown platform has no measurement rule to check against | terminal |
| `UNKNOWN_STACK` | `AttestationErrorCode` | The stack evidence carries a kind the decoder does not know | Refuse for the same reason | terminal |
| `UNSUPPORTED_PLATFORM` | `AttestationErrorCode` | The platform is decodable but verification is not implemented for that kind | Refuse. Also raised by `@ashaveri/signerd` for the same condition at startup | terminal |
| `TRAILING_BYTES` | `AttestationErrorCode` | Bytes remain after the encoded value, or a device report leaves bytes after its measurement fields that are not its signature | Refuse; a length disagreement is a corrupted or hand-edited document | terminal |
| `MALFORMED_QUOTE` | `AttestationErrorCode` | A TDX quote is shorter than its declared parts, or its signature data, certification data or PCK chain lengths run past the buffer | Refuse; the quote is incomplete | terminal |
| `UNSUPPORTED_QUOTE` | `AttestationErrorCode` | A quote version, TEE type, certification-data type or SPDM version this verifier does not handle | Update the verifier or refuse. Do not fall through to a weaker path | terminal |
| `MALFORMED_REPORT` | `AttestationErrorCode` | An SEV-SNP report has the wrong size or version, a reserved field is nonzero, or a device report is too short to hold request and response | Refuse | terminal |
| `MALFORMED_GPU_BUNDLE` | `AttestationErrorCode` | Device evidence is not the JSON array `nvattest` writes, or an entry lacks a base64 field it must carry | Refuse; the bundle did not come from the vendor tool | terminal |
| `UNSUPPORTED_SIGNATURE_ALGO` | `AttestationErrorCode` | A report or certificate uses a signature algorithm, curve or parameter set outside the small set these formats allow | Refuse; an unsupported algorithm is not a weaker one | terminal |
| `BAD_EVENT_DIGEST` | `AttestationErrorCode` | An event log entry's digest does not match its content, or it targets an IMR that is not in its family | Refuse; the log has been edited or truncated | terminal |
| `BAD_EVENT_PREIMAGE` | `AttestationErrorCode` | A V2 event's preimage is missing, malformed, does not hash to its digest, or is not the canonical representation | Refuse; without the preimage the replay is not this event's | terminal |
| `EVENT_LOG_MISMATCH` | `AttestationErrorCode` | The platform event log and the stack's runtime events disagree in count, in per-event identity, or in version | Refuse; two views of the same boot disagree, and only one can be true | terminal |
| `RTMR_MISMATCH` | `AttestationErrorCode` | RTMR3 replayed from runtime events differs from the value in the quote | Refuse; what ran is not what the quote attests | terminal |
| `REPORT_DATA_MISMATCH` | `AttestationErrorCode` | The stack's `report_data` differs from the field inside the platform report or quote | Refuse; the two halves were not produced for one another | terminal |
| `CHALLENGE_MISMATCH` | `AttestationErrorCode` | The challenge a device signed differs from the one the caller expected | Refuse; a genuine report of another moment is still not this one's | terminal |
| `QE_REPORT_MISMATCH` | `AttestationErrorCode` | `sha256(attestation key ‖ QE auth data)` differs from the QE report's `REPORT_DATA` | Refuse; the quote's attestation key is not bound to the quote | terminal |
| `MR_CONFIG_MISMATCH` | `AttestationErrorCode` | The `mr_config` document does not hash to `HOST_DATA`, is not a JSON object, or is missing or malformed in a field the measurement depends on | Refuse; the configuration the platform committed to cannot be reconstructed | terminal |
| `BAD_MR_CONFIG_ID` | `AttestationErrorCode` | `MR_CONFIG_ID` carries an unsupported tag, or nonzero bytes after its digest | Refuse; the binding to a configuration is not the one this format defines | terminal |
| `PIN_MISMATCH` | `AttestationErrorCode` | Declared here, raised by `@ashaveri/cli`: an `--expect-*` pin has no counterpart in the evidence, or the observed value differs from the pinned one | Compare the printed values. A mismatch is an image or compose change, or evidence from another VM | terminal |
| `MALFORMED_CERTIFICATE` | `AttestationErrorCode` | DER does not parse, a PEM block is absent, a chain input is empty, or an AMD certificate table is missing a member or its terminator | Refuse; a certificate that does not parse cannot anchor anything | terminal |
| `UNSUPPORTED_CERT_ALGORITHM` | `AttestationErrorCode` | A certificate's key, curve, hash or parameter set is not one the format allows, or a leaf key does not match the signature it carries | Refuse. These are vendor-fixed parameters, so a deviation is a different device family at best | terminal |
| `CERT_CHAIN_INVALID` | `AttestationErrorCode` | A chain does not link leaf to authority: issuer and subject disagree, a CA flag is wrong, an entry was not issued by the next, or a VCEK HWID differs from the report's chip id | Refuse; the chain asserts no path to a root | terminal |
| `CERT_EXPIRED` | `AttestationErrorCode` | A certificate is outside its validity window at the verification time | Check the clock, then the collateral. An expired CA is refreshable; an expired report is not this moment's | terminal |
| `PRODUCT_MISMATCH` | `AttestationErrorCode` | The VCEK's product name extension does not match the platform the report's CPUID identifies | Refuse; the key is for a different generation of chip | terminal |
| `MISSING_TRUST_ROOT` | `AttestationErrorCode` | No chain reaches a pinned root, or verification was asked with no roots configured at all | Configure roots. Without one, no chain reaches anything | terminal |
| `BAD_SIGNATURE` | `AttestationErrorCode` | A cryptographic signature does not verify under the key that should have made it | Refuse; nothing else in the document is corroborated | terminal |
| `DEBUG_NOT_ALLOWED` | `AttestationErrorCode` | The guest policy permits host-assisted debugging | Refuse; a debuggable guest has no confidentiality claim | terminal |
| `POLICY_NOT_ALLOWED` | `AttestationErrorCode` | The report is not at VMPL 0, a migration agent is permitted, the signing key is not the VCEK, the chip key is masked, or SMT is enabled against the policy | Refuse, or decide deliberately that a given exception is acceptable for this deployment | terminal |

## `GuestErrorCode`

Raised inside the confidential VM, by the gateway talking to the guest agent over its Unix socket.
None of them is a client-facing failure; they are what the operator sees in the gateway's log when
a deployment will not start.

| Code | Union | Raised when | What the caller does | Verdict |
|---|---|---|---|---|
| `GUEST_ENDPOINT_MISSING` | `GuestErrorCode` | No guest socket at any candidate path | Start on a confidential VM, or set `DSTACK_SIMULATOR_ENDPOINT` / `--guest-socket`. Off a CVM the gateway has no evidence to serve | terminal |
| `GUEST_REQUEST_FAILED` | `GuestErrorCode` | The socket request failed at transport level | Restart the deployment. If it repeats, the agent is not serving | retryable |
| `GUEST_RPC_ERROR` | `GuestErrorCode` | The agent answered with an error status; the remote text and status are in the message | Read the status. An agent refusing a call is an image difference, not a network one | terminal |
| `GUEST_MALFORMED_RESPONSE` | `GuestErrorCode` | The agent's reply does not match its schema. Two of its sites reject the caller's own argument, before any request is sent, so the name says more than the code's history | Fix the argument if the message names one; otherwise the agent is not the version this gateway speaks | terminal |
| `GPU_ATTESTATION_UNAVAILABLE` | `GuestErrorCode` | The device route answered 404 or 501: this image exposes no device attestation at all | Use an image whose agent offers the route, or serve a plain `snp` or `tdx` claim. The gateway re-presents this as `GPU_EVIDENCE_UNAVAILABLE` | terminal |

## `DstackErrorCode`

Each of these is a startup refusal: `dstackDeployment()` throws, the process exits, and no receipt
is ever served. That is the intended shape. A gateway that started under a claim it cannot evidence
would produce receipts whose labels are wider than their proofs.

| Code | Union | Raised when | What the caller does | Verdict |
|---|---|---|---|---|
| `EVIDENCE_UNDECODABLE` | `DstackErrorCode` | The guest's own evidence does not decode, or carries a report field that is not the width the platform uses | Fix the image or the agent version; the deployment's measurement is unknowable from these bytes | terminal |
| `UNSUPPORTED_PLATFORM` | `DstackErrorCode` | The evidence is from a platform kind this gateway has no measurement rule for | Deploy on SEV-SNP or TDX, or add the rule. The same name `@ashaveri/attest-core` uses, for the same condition | terminal |
| `TEE_MISMATCH` | `DstackErrorCode` | The `--tee` the operator configured disagrees with the platform the evidence shows | Correct `--tee`, or move to the machine claimed. The flag is a request, never an inference | terminal |
| `IDENTITY_MISSING` | `DstackErrorCode` | The event log carries no compose hash and no instance id | Pass `--issuer` and `--instance` explicitly, understanding that a hand-set identity is the operator's assertion rather than the platform's | terminal |
| `GUEST_EVIDENCE_UNBOUND` | `DstackErrorCode` | The guest returned evidence bound to a report data value other than the standing challenge this deployment chose | Restart. The agent answered a question that was not asked, so its document is not this deployment's | terminal |
| `GPU_EVIDENCE_UNSUPPORTED` | `DstackErrorCode` | Device evidence is from another vendor or format, is not the bundle the vendor tool writes, or a report inside it does not parse | Serve only the on-demand NVIDIA format this deployment claims; fix the collection path | terminal |
| `GPU_EVIDENCE_UNAVAILABLE` | `DstackErrorCode` | `--tee` claims a device and the image gave none, or no accelerator answered at all | Either drop to a plain platform claim or fix device collection. Silence is never promotion to a composite | terminal |
| `GPU_EVIDENCE_UNBOUND` | `DstackErrorCode` | A device signed a report for a challenge other than the one this deployment chose | Restart with working device collection. A cached or borrowed report is evidence of another moment | terminal |

## `StoreErrorCode`

Raised while opening a receipt store, before the gateway serves a request. The store chains every
record to the one before it, so this code is the file saying it was changed after it was written.
The byte offset in the message names which of the three disagreements it found: a record whose
digest does not match its own bytes, a record naming a predecessor other than the one before it, or
a retirement record that does not sit at the very front. A record left half-written by an
interrupted append is not one of them: that tail is repaired at open rather than reported, because
no receipt was ever handed out for bytes that never finished.

| Code | Union | Raised when | What the caller does | Verdict |
|---|---|---|---|---|
| `STORE_CHAIN_BROKEN` | `StoreErrorCode` | The store file fails to chain at open, at the byte offset the message gives | Stop, and do not serve from that file. Restore from a copy whose head a customer already holds, or investigate the offset: a deleted middle record and a hand-edited one look the same from here, and both mean retained receipts can no longer be shown to be complete | terminal |

## Why these strings do not overlap

A bare code string has to say which layer failed. Two pairs did not, and both sides were renamed
rather than one:

- `NONCE_MISMATCH` was raised by the receipt codec for a receipt echoing the wrong client nonce,
  and by the device verifier for a GPU that signed another challenge. The receipt keeps the name,
  because `nce` is the nonce. The device check is `CHALLENGE_MISMATCH`, which is what its own
  message and its test names already called the value.
- `EVIDENCE_REPORT_DATA_MISMATCH` was raised by the SDK when evidence fetched over the network is
  bound to another report data, and by the gateway when its own guest agent returns such a
  document. The SDK keeps the name; the gateway's is `GUEST_EVIDENCE_UNBOUND`, matching the
  sibling `GPU_EVIDENCE_UNBOUND` for the same shape of failure on the other leg.

`UNSUPPORTED_PLATFORM` is deliberately the same string in two unions: it is one condition, a
platform kind neither layer can handle, seen from the verifier and from the deployment. Collapsing
it onto attest-core's spelling costs a search and replace while nothing is published, and after
the first publish it would cost a deprecation cycle.

## Keeping this file true

`packages/fixtures/test/error-codes.test.ts` reads the six unions out of source and checks them
against this file: every declared code has exactly one row, every code in a row is declared, and
the counts in the opening paragraph agree. A new code with no row fails CI, which is the only
reason a reference table like this one stays correct after its first month.
