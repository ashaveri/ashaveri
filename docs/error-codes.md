# Error codes

Every error code this workspace raises, what condition raises it, and what a caller should do
about it. There are 103 declarations across seven unions, resolving to 101 distinct strings;
`UNSUPPORTED_PLATFORM` and `UNSUPPORTED_VERSION` are the two strings two unions share, and the last
section says why those pairs are deliberate while every other overlap is not.

Codes are stable identifiers. Messages are not: each is a fixed sentence plus whatever the raise
site knew, so the detail reads differently for a quote than for a certificate. Branch on `code`.

## How to read this

| | |
|---|---|
| **Union** | Which error class carries the code, and therefore which package raised it. A caught exception's class and its `code` say the same thing; a log line carries only the string, which is why every string here names its layer. |
| **Raised when** | The condition at the raise site, not a paraphrase of the message. |
| **What the caller does** | The action that can change the outcome. "Refuse" means present the failure; the receipt is not proven and must not be treated as one. |
| **Verdict** | `terminal`: the same bytes will fail the same way forever, so a retry only adds latency. `retryable`: a later attempt can differ without anything being fixed. Startup refusals are terminal for the process. |

The seven unions:

| Union | Package | Owns |
|---|---|---|
| `ReceiptErrorCode` | `@ashaveri/receipt` | The COSE receipt wire format and the PoP Authorization header: decoding, signature, payload fields |
| `SdkErrorCode` | `@ashaveri/sdk` | Client behaviour: transport, policy pins, strict-mode evidence verification, credential refusal |
| `AttestationErrorCode` | `@ashaveri/attest-core` | Platform evidence: dStack envelopes, SNP reports, TDX quotes, device reports, X.509 |
| `GuestErrorCode` | `@ashaveri/signerd` | The guest agent socket inside the confidential VM |
| `DstackErrorCode` | `@ashaveri/signerd` | Gateway startup: the deployment's own evidence, identity and device claim |
| `StoreErrorCode` | `@ashaveri/signerd` | The receipt store file on the deployment's volume |
| `AccessErrorCode` | `@ashaveri/signerd` | Admission of one request: proof of possession, replay, scope, rate limit, and the credential file those checks read, which is refused at start-up and on reload rather than by a request |

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
| `STALE_RECEIPT` | `ReceiptErrorCode` | `iat` is outside `freshnessSeconds` of the verification time, in either direction; `@ashaveri/sdk` supplies a 300-second window for that option whenever the caller verified against a policy | Refuse for this receipt; a new request gets a fresh `iat` | terminal |
| `STALE_EVIDENCE` | `ReceiptErrorCode` | `att.ts` is outside `evidenceFreshnessSeconds` of the verification time, in either direction; `@ashaveri/sdk` supplies a 900-second window for that option whenever the caller verified against a policy | Refuse; the platform evidence the receipt commits to has aged out. Re-attest, or widen the window deliberately for an archive | terminal |
| `UNSUPPORTED_VERSION` | `ReceiptErrorCode` | The payload's `v` is an integer this package cannot parse, or one the caller's `acceptedVersions` did not accept. The two are one answer, because which of them it was is not a property of the bytes and a second code would let a caller probe the boundary. A `v` that is not an integer at all is a malformed payload, so it is `BAD_PAYLOAD` | Refuse; this is not a receipt this verifier was told to read. A caller that means to take only one version narrows `acceptedVersions`; nothing re-asks with the other | terminal |
| `BAD_PAYLOAD` | `ReceiptErrorCode` | A payload field is missing or mis-typed: a `v` that is not an integer, a `v: 2` document with no `mk`, a member the format makes a map and is not one, an integer where the format promises a non-negative one. Also a measurement whose width disagrees with its kind, at issue time | Refuse; a signed garbage payload is still garbage | terminal |
| `UNSUPPORTED_SCHEME` | `ReceiptErrorCode` | `mk.sch` names a marking scheme outside the registry this package reads, which holds `none` and `provenance-v1`. A label the reader cannot interpret is refused rather than guessed at, because reading a region under another scheme's extraction rule is the confusion this code is the answer to | Refuse; the receipt attests a mark this verifier cannot look for, and nothing about the region is inferred from a label it does not know | terminal |
| `MARK_MISMATCH` | `ReceiptErrorCode` | `sha256` of the marked region, taken by the extraction rule `mk.sch` names, does not equal the `d` this receipt signed. Its raise site is a reader holding the response bytes: neither `verifyReceipt` nor `decodeReceipt` reaches it, because neither is handed the stream the region is carved out of | Refuse; the response carries a mark that is not the one the receipt attests. Deleting the mark is a different failure and announces itself as the response no longer hashing to `res` | terminal |
| `BAD_SIGNING_KEY` | `ReceiptErrorCode` | A signing seed handed to `signingKeyFromSeed` is not 32 bytes | Fix the key material; nothing was signed | terminal |
| `BAD_POP_HEADER` | `ReceiptErrorCode` | A header that does name `Ashaveri-PoP` is missing `credential`, `ts` or `sig`, repeats a parameter, carries one the format does not define, holds a piece that is not a `name=value` pair, carries a credential id outside the character set the wire allows, or holds a `ts` or signature outside the width the format allows | Fix the client. The request was not admitted, and the same header will fail the same way | terminal |
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
| `GATEWAY_ERROR` | `SdkErrorCode` | A request to the gateway failed, returned a non-2xx status, or returned a body that is not a chat completion. `wrapOpenAI` raises it one step earlier too, when the client object it was handed has no `fetch` to wrap, so no request was attempted | Retry at a higher level if the operation allows it; a non-JSON body can also mean an intermediary answered | retryable |
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
| `AUTH_CONFIG` | `SdkErrorCode` | The credential a client was handed cannot be used, or the request cannot be signed. A `pop` secret that is not 64 hex digits, or is the wrong width once decoded; a `bearer` secret that is not base64url; an `ASHAVERI_CREDENTIAL_KIND` other than `pop` or `bearer`; an `x-ashaveri-nonce` header that is not base64url, or decodes to something other than the 16 bytes the signing string commits to; a request body in a form this client cannot hash byte for byte | Fix the credential or the body form: re-read the id and the secret from wherever they are kept, and pass a body as a string or a `Uint8Array`. Nothing was sent, so no gateway refused anything | terminal |
| `POLICY_FILE_INVALID` | `SdkErrorCode` | A policy document is not one JSON object, repeats a key, carries a key this format does not define or lacks one it requires, holds a value of the wrong type, gives hex or base64url that is not what it claims to be, names an environment kind that is not defined, or gives an anchor path that is absolute or climbs out of the directory holding the document | Fix the document. Every one of these is a refusal because the loader cannot tell which of two readings it was handed, and a digest published over a misread policy is a digest of a policy nobody pinned | terminal |
| `POLICY_FILE_UNREADABLE` | `SdkErrorCode` | The policy file named on the command line or by the loader cannot be read | Check the path. Nothing was pinned yet, so nothing was verified either | terminal |
| `POLICY_NOTHING_PINNED` | `SdkErrorCode` | A policy names none of `issuers`, `instances`, `keys` or `measurements`, which is the document equivalent of strict mode with no policy | Pin at least one dimension, or do not call it a policy. A trust anchor that anchors nothing accepts every receipt | terminal |
| `POLICY_EMPTY_PIN` | `SdkErrorCode` | One of those four fields is present but empty: `[]`, `{}`, or an empty list under a named environment kind | Name a value or delete the field. An empty list reads as no check at all, so it accepts anything | terminal |
| `POLICY_ANCHOR_UNREADABLE` | `SdkErrorCode` | The file at a pinned trust anchor's path cannot be read | Put the root where the document says, or repoint the path. The path is resolved below the directory holding the policy file | terminal |
| `POLICY_ANCHOR_DIGEST_MISMATCH` | `SdkErrorCode` | The bytes at a pinned trust anchor's path do not hash to the SHA-256 the policy records | Restore the file the policy was written against, or repin deliberately. A checkout that rewrites a PEM's line endings lands here: the recorded digest is of the bytes, so the fix is to re-record it, not to accept the drift | terminal |

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

## `AccessErrorCode`

What `CredentialStore.admit` answers a request with, and what the store answers where its records
enter it. The checks run in order: the header the caller wrote, the proof of possession, then what
the file says about a credential that proved it, then the route's scope, then the rate bucket. The
order is part of the meaning, because a request that fails two checks gets the earlier code, and it
sorts by what an answer discloses rather than by what a check costs: the answers that depend on the
credential file are given after a signature verifies, so a revoked credential produces a signature
before it is told it is revoked, while a credential with no scope for the route never spends a
token. `docs/access-control.md` section 1 states the rule the ordering comes from. Codes after the
first three are 401, 403, 409 or 429 on the request that earned them; the credential-file codes are
500s no request receives, because what is broken is the file the operator installed and no header a
client sends can fix it.

| Code | Union | Raised when | What the caller does | Verdict |
|---|---|---|---|---|
| `BAD_CREDENTIAL_FILE` | `AccessErrorCode` | The file the gateway was pointed at cannot be used: unreadable, not JSON, a version other than the one this gateway writes, `credentials` not a list, more records than `MAX_CREDENTIALS`, or a store built with both a path and an in-memory file, or with neither | Operator-side. Nothing is admitted until the file is fixed; a failed reload keeps the records already read and retries on the next request | terminal |
| `BAD_CREDENTIAL_RECORD` | `AccessErrorCode` | One record is unusable: an id outside `[A-Za-z0-9_-]{1,64}`, an unknown kind, a public key or secret hash that is not base64url text or decodes to the wrong width, a `secretHash` that is not 64 hex characters, a `bearer` secret hash that is the digest of no bytes, a `scopes` list that grants `complete` without `read`, an unknown scope, a missing `createdAt`, a `rate` that is not a whole number of at least 1, or a field whose value is not of the type the record allows. The store also raises it, on the same rule, where records enter it: a `pop` record carrying no public key, or one that does not decode to the 32 bytes its kind has to be verified against, is refused there whether the records came from the file on disk or were handed over in memory. No request is answered with this code by the pipeline. As of 19 September 2026 it answers where a credential file is taken in, so a file holding such a record stops the boot, and a reload that hits one fails while the records already loaded keep answering later requests | Fix that record. A `bearer` hash comes from the generator, which writes the digest of 32 random bytes and never the digest of none. A `scopes` list that grants `complete` alone is fixed by adding `read`, or by dropping `complete` if the credential only sends. The message names the record's position in the file, and the store's own ingest adds the id, which is what an operator reads the file by | terminal |
| `DUPLICATE_CREDENTIAL_ID` | `AccessErrorCode` | Two records in one file share an id, so a header naming it could resolve to either | Delete one record or rename it. Admission refuses rather than choosing | terminal |
| `AUTH_MALFORMED` | `AccessErrorCode` | No `Authorization` header at all, or one that names `Ashaveri-PoP` and still does not parse: a parameter piece that is not a `name=value` pair, a missing parameter, a repeated one, a parameter the format does not define, a credential id outside the character set the wire allows, or a `ts` or signature outside the width it allows | Fix the client. The request was never admitted and the same header will fail the same way | terminal |
| `AUTH_SCHEME` | `AccessErrorCode` | The header is neither `Ashaveri-PoP` nor `Bearer`, or it is `Bearer` on a deployment that was not started with `--allow-bearer`. Both are statements about the request or the deployment rather than about the file, so neither depends on what the credential file holds. An `Ashaveri-PoP` header naming a record that is a bearer one is not answered with this code: it is answered as `AUTH_SIGNATURE`, the same way a name the file does not carry is | Speak the scheme the deployment requires. A client that has a key pair and gets this has found a bearer-only deployment, not a bug in its signing | terminal |
| `AUTH_UNKNOWN` | `AccessErrorCode` | No stored bearer digest matches the secret presented. That one answer covers a secret matching nothing and a secret belonging to a retired record, because the digest scan passes over a revoked record as though it had never existed, and a distinct answer for either would tell a prober which ids the file holds and which were once live. The proof-of-possession path does not raise this code to its caller: a name the file does not carry is answered as `AUTH_SIGNATURE`, because anything else is a reply to the question "is this id issued?" from a caller who has proved nothing. The access log still records `AUTH_UNKNOWN` for such a request, because the line is what this gateway decided and the response is what the caller was told, and those differ by design on a collapsed refusal | Check the secret against the credential file the operator holds. On the bearer path a 401 here says the deployment has never heard of this credential, or retired it, and the two are one answer on purpose | terminal |
| `AUTH_REVOKED` | `AccessErrorCode` | The named record carries a `revokedAt`, so the operator has withdrawn it while the holder still has the key. The request proved that key first: revocation withdraws a credential and keeps the public key in the record, so the signature is checkable, and the withdrawal is told to the party holding the key rather than to whoever typed the id. A request naming a revoked id without a valid signature gets `AUTH_SIGNATURE` | Stop presenting it and get a new credential. Waiting does not help: the file is re-read when it changes, so the revocation is already live | terminal |
| `AUTH_STALE` | `AccessErrorCode` | The request's `ts` is further from this clock than the accepted window, 120 seconds unless the deployment configures another value. Both directions, so a client running behind and one running ahead look the same from here. The tolerance is a setting of the process and never a field of a record, so this is answered before the credential file is read and reaches a caller naming a real credential and a caller inventing one alike | Fix the clock, not the request. A fresh `ts` on the same bytes is a new request that may be admitted | terminal |
| `AUTH_SIGNATURE` | `AccessErrorCode` | EdDSA over the signing string fails: the record holds another key, or the method, target, body digest or nonce the header carries is not what was signed. This is also the answer to a nonce header that disagrees with the signed nonce, because the nonce is a signing-string term. It is the answer as well to a `credential` this file does not carry, and to one that names a bearer record, both refused through the same path as a failed signature and indistinguishable from it: one verification against a key no credential file holds, then this refusal whatever that verification answered | Refuse. The key is wrong, or something changed the request after it was signed, or the id the header names is not one this deployment holds. Check the id and the key pair against the credential file; none of the three is a retry | terminal |
| `AUTH_NONCE_MISSING` | `AccessErrorCode` | The `x-ashaveri-nonce` header is absent, is not unpadded base64url, or decodes to something other than `POP_NONCE_BYTES` bytes. The nonce is a term of the signing string, so this header is where the gateway reads the bytes its replay set keys on, and it is read before the credential file, whoever the header names | Fix the client: send the header with the same nonce that went into the signing string | terminal |
| `NONCE_SEEN` | `AccessErrorCode` | The same credential presented the same nonce inside the replay window. The key is the decoded nonce bytes, so re-spelling the header in another valid base64url form is the same nonce | Send a new request with a fresh nonce. Resending these bytes is exactly what just failed | terminal |
| `SCOPE_DENIED` | `AccessErrorCode` | The route requires a scope the credential does not carry, or the target is not in the route table at all, which is a refusal rather than a route that needs nothing | Use a credential that holds the scope, or ask the operator to scope the route. This answer takes no token from the credential's own bucket, though the connection's bound was charged before it was decided | terminal |
| `RATE_LIMITED` | `AccessErrorCode` | One of two buckets is empty. The credential's own: it is over the `perMinute` it is held to, past its `burst`. Or the connection address the request arrived on has spent the request bound taken ahead of every credential check, which is refused without the header being read and so on a name the file does not hold as on one it does. The message says which of the two fired, and `retryAfterSeconds` says when the next token appears, never less than one. The access log separates them by reason, and that separation adds no row to this table: the credential's bucket writes `RATE_LIMITED` to the deployer's `deny` field and the connection's bound writes `PEER_RATE_LIMITED`, which is what this gateway decided and never what a caller is told | Wait the stated seconds, then send a new request. Splitting one workload across credentials is a deployment decision, not a client fix, and it is no fix at all for the connection's bucket: waiting refills that one, and an operator raises it with `--peer-rate` | retryable |

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

`UNSUPPORTED_VERSION` is the second pair, and it is the same shape of claim: a document whose
declared version this reader cannot interpret, once in a receipt payload and once in a platform
evidence envelope. Neither answer depends on the other layer's vocabulary, because both are a
refusal to read the document rather than a verdict on a field of it, and a caller that caught two
names for that branch would do the one thing either way: refuse, and say which reader refused. The
receipt's own message says payload and attest-core's says attestation, so a log line that carries
the message still names its layer even where the code does not.

## Keeping this file true

`packages/fixtures/test/error-codes.test.ts` reads the seven unions out of source and checks them
against this file: every declared code has exactly one row, every code in a row is declared, the
counts in the opening paragraph agree, and the only strings two unions share are the two this
section explains. A new code with no row fails CI, which is the only
reason a reference table like this one stays correct after its first month.
