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

Marking is a third thing, and the duty on it does not fall to this repository. Article 50(2) of
Regulation (EU) 2024/1689 binds the provider of the AI system that generates the synthetic content:
that provider has the output marked in a machine-readable format and made detectable as artificially
generated, and the article's next sentence asks of the technical solutions that they be effective,
interoperable, robust and reliable "as far as this is technically feasible, taking into account the
specificities and limitations of various types of content, the costs of implementation and the
generally acknowledged state of the art". What the marking work here is about is a mechanism and a
signed record that the mechanism was applied to one particular response, and A7 says how much of
either this repository contains today. Whether a given deployment is that provider, or is serving
one, is a fact about the deployment and the system it runs, and this document does not decide it.
Two dates from the consolidated text as amended by
Regulation (EU) 2026/1744 are the ones the marking work is planned against. Article 50 sits in
Chapter IV, which Article 113 does not carve out of the general date of application, so the
transparency obligations run from 2 August 2026. Article 111(4) then gives providers of AI systems
generating synthetic content that were on the market before 2 August 2026 until 2 December 2026 to
take the necessary steps for Article 50(2). Nothing here says that any system meets that article, and
the mechanism described below is a mark plus the evidence of a mark, not a certification of anything.

## 2. Assets

- **A1 Response integrity.** The completion the user saw is the completion the gateway signed.
- **A2 Request-response binding.** The receipt is about this request, not another one.
- **A3 Gateway identity.** Which deployment, under which signing key, produced the response.
- **A4 Deployment claims.** Model id, weights digest, TEE measurement, attestation evidence reference.
- **A5 Token metering.** The counts a receipt signs cannot be revised afterwards, so whichever
  gateway claimed them owns that claim. Where the counts came from is T9's problem, not A5's.
- **A6 Client policy.** The client's pinned keys, issuers, instances, and measurements, and the two
  freshness windows a strict verification measures a receipt's stamps against.
- **A7 The marked response.** A response whose own bytes carry a machine-readable marking: one extra
  top-level member on a buffered completion, or one extra server-sent-events data frame on a streamed
  one, put there through the same path every other byte of that response takes, so that `res`, the
  digest in section 3.1 of [receipt-spec.md](receipt-spec.md), covers it as part of the same job
  rather than through a second mechanism. The payload names the scheme a mark is written under and
  carries a digest of that region alone, so a detector can be told what to look for and can check it
  in isolation. The mark is not the evidence; the receipt is. A mark is bytes anyone holding the
  response can delete, and the signed statement about those bytes is the part that cannot be edited
  without the edit showing. Three pieces, and this tree holds all three. The payload:
  `@ashaveri/receipt` reads a `v: 2` document that carries `mk` and refuses a `v: 1` one that carries
  it, because a payload map is closed at either version ([receipt-spec.md](receipt-spec.md) section 6),
  so the marking attestation cannot arrive on a document that has agreed to say nothing about it. The
  rule: `extractMarkedRegion` in `packages/receipt/src/marking.ts` locates a region inside response
  bytes and answers `MARK_MISMATCH` when those bytes hold none or hold the shape twice, and the live
  client compares the digest of whatever it locates against `mk.d`, because
  `verifyCompletionReceipt` in `packages/sdk/src/verify.ts` is handed those bytes beside their digest
  (T18, T20). The bytes: `gateway/src/server.ts` signs a `v: 2` payload
  for every completion it issues, and whether any byte is added to a customer's response is the
  deployment's own setting, `--marking`, whose shipped value is `none`. Section 6 says what none of the
  three amounts to proving.
- **A8 The marking-scheme registry.** The table that binds every scheme label to exactly one byte
  shape, which is what lets a reader who was not present when a response was written decide what to
  look for. It is published, as section 3.3 of [receipt-spec.md](receipt-spec.md), where the two labels
  `"none"` and `"provenance-v1"` each carry the span they mark, and it is executable in
  `extractMarkedRegion` (`packages/receipt/src/marking.ts`), which is the module the gateway writes from
  and the live client reads with, so neither side of this repository can hold a second copy of the rule
  (T19). It is an asset because its failure mode is silent: a label standing for two shapes turns each
  detector's answer into a guess about which shape it happened to read.

## 3. Actors and trust boundaries

- **Client** holds the policy (A6) and generates nonces. Trusted by itself.
- **signerd gateway** signs receipts. Trusted only as far as its signature and the client's pins go.
- **Mark writer.** This is the gateway and nothing else: it adds its marking to the response through
  the same write path every other byte of that response takes, and digests the region from the bytes it
  just handed to the response hash, so there is no route by which a receipt is issued over bytes that
  were never marked. Both shapes are written that way: `markBufferedBody` splices the member into the
  body before that body is hashed, and `MarkedStreamTail` puts the frame through the streaming `write`
  closure ahead of the sentinel rather than after it (`gateway/src/marking.ts`). Started with the
  shipped `--marking none`, this actor adds no byte to anyone's response and signs `sch: none` over the
  empty region to say so.
- **Mark remover.** Anyone holding the response bytes, which is every party that ever receives or
  stores them: the client that kept its copy, a deployment's own archive, anyone a transcript was
  forwarded to. Removing a marking member or frame takes no key and no privilege. What is not
  available to any of them is keeping a receipt verifying afterwards (T17).
- **Inference backend** computes completions behind the gateway. Untrusted from the client's
  perspective; the gateway vouches for what it forwarded. It is also the one party positioned to put
  mark-shaped bytes into a stream from the inside, since the gateway forwards and hashes whatever the
  backend yields without reading it (T20).
- **Network** between client and gateway. Fully untrusted (TLS is assumed for confidentiality
  and authentication of the transport, but receipts are designed to not depend on it).
- **Manifest channel**. The deployment manifest is fetched from the gateway, as itself or inside a
  `COSE_Sign1` this deployment signed with a key it was handed for the purpose. A wrapper a client can
  verify under a key it designated out of band makes the document the deployment's own statement; without
  one the manifest is what it has always been, a claim from the party being verified, and in `strict`
  mode its contents must match the client's pins to matter either way.
- **Marking-scheme registry**. The boundary between whoever writes a mark and everyone who reads one,
  holding each scheme label against the one byte shape it names. A label is bound to that shape for
  as long as it exists and is never repurposed, and a label a reader does not know is a refusal
  rather than an interpretation. What this boundary does not carry is authority over genuineness: it
  cannot tell a mark a gateway wrote from a well-shaped copy of one (T19).

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
| T3 | Replay of an old but valid receipt for a fresh request | Client-generated nonce must be echoed, and strict mode measures `iat` against the client's clock by default (300 seconds) and `att.ts` against its own (900 seconds), either of which a policy can override or switch off | Below strict mode there is no policy and so no window: a replay still has to match the nonce this client chose for this request. In strict mode the clock is on unless the caller wrote infinity into one of the two fields, which is the archive case and says so |
| T4 | Gateway signs a receipt, then serves different bytes | Same as T1: the served bytes fail the `res` check | None |
| T5 | A different key signs receipts (gateway compromise or impersonation) | `kid` must resolve to a manifest-declared key; in strict mode, to a policy-pinned key that also matches the manifest. Either way the key also has to be the one the manifest declares for the epoch the receipt claims, inside the window that epoch opens, so a key the deployment retired cannot sign fresh traffic and have it read as history | In `receipt` mode a gateway that controls its own manifest can introduce a new key; strict mode closes this. A deployment that publishes no per-key windows states one epoch and every key it lists, which is the weaker reading and the honest one for a document that says nothing about the past |
| T6 | Gateway omits receipts selectively | Strict mode rejects unreceipted responses | `receipt` mode returns a null receipt by design; callers must check for it |
| T7 | Gateway lies about model, weights, measurement, or tokens | These fields are signed, so lying is attributable to the signing gateway and detectable against a pinned policy | The gateway can still lie consistently. See section 6 |
| T8 | Manifest tampering | Where an operator handed the deployment a key for the purpose, the document is served inside a COSE_Sign1 whose payload is the bytes the deployment wrote, so an edit after signing is `MANIFEST_SIGNATURE_INVALID` for every client that designated that key and the client refuses rather than downgrading to the unsigned reading. The key a wrapper is verified under is designated in `AshaveriPolicy.manifestKeys`, apart from the receipt keys the manifest itself lists, so one compromised signing key cannot forge the rotation record meant to retire it. Strict mode additionally requires the manifest key to equal the pinned key (`MANIFEST_KEY_NOT_PINNED`), and pins issuer, instance, measurements | Sealed only where an operator handed the deployment a key for the purpose and the client designated one: a deployment with no manifest signing identity serves the plain document, and a client that designated no manifest key has nothing to check a seal against and reads the document as unauthenticated from the start. Either way an unauthenticated manifest is reported as such, and is able to fail a check but never to open one. A client that predates sealed manifests refuses a sealed route as `BAD_MANIFEST` rather than misreading it, so turning sealing on is an operator's compatibility decision |
| T9 | Token metering inflation | `tok` is signed and attributable | The SDK does not recount tokens from the response text; it verifies who claimed the counts |
| T10 | DoS: gateway refuses to serve receipts | Receipt and evidence fetches retry with a short window, then fail closed as `RECEIPT_NOT_FOUND` or `EVIDENCE_NOT_FOUND` rather than falling back to unverified acceptance | Availability is out of scope |
| T11 | Side channels on prompt content via receipts | Receipts contain hashes and counts only, never content | Hashes reveal content length implicitly (already visible in the response) |
| T12 | Strict mode: gateway serves evidence from other work, another instance, or one not matching the receipt | The client recomputes the expected report data from its own nonce and request bytes, requires `sha256(document) == att.d`, requires the quote's platform to agree with the receipt's `tee` (a `software` receipt is refused before the fetch), and requires the measured launch digest to equal `meas.m` | Collateral freshness. The signature chain is checked against a pinned vendor root, but TCB Info, the QE identity and the CRL are not consulted, so a since-revoked platform still verifies |
| T13 | Strict mode: a receipt bearing a composite `tee` claims a confidential GPU the deployment does not have, or quotes a device report captured for someone else | The label is only ever an operator's request, and the gateway will not start under it unless one of its accelerators signs that deployment's standing challenge. The platform's agent collects that report today; the settled direction is for the vendor's own tool to run inside the deployment's container instead, which emits the same bundle format, so the client's checks stay checks on the bytes rather than on who collected them. Strict mode then fetches the device document for the client's own challenge and requires a report whose signature chains to a pinned NVIDIA device root and whose signed challenge matches | Residual trust in one label choice: the operator picks the composite and the gateway confirms only that its platform quote and a device report answer the same challenge. See section 6 |
| T14 | A bearer credential is stolen, and someone else presents it | `--allow-bearer` is off by default, and it is deployment-wide rather than per credential, so a process is bearer-capable or it is not and one convenience fallback cannot be introduced for a single record. A bearer secret is held only as its SHA-256 and every stored digest is compared in a loop that does not exit early on the first differing byte, so a wrong secret reveals nothing about which one was close. Each record a bearer secret admitted writes `auth=bearer` on its own line, so the log says which posture produced it rather than the widest thing the process tolerates | The start-up banner states this and this document does not soften it: a stolen bearer credential is undetectable, and a log record cannot tell its holder from a thief. The secret is the whole credential, it does not expire on its own, and it authorizes any request its scopes allow from any address. A bearer path also has no replay step at all, because it has no signed nonce to check |
| T15 | Refusals used as an oracle to enumerate which credential ids a deployment has issued, or which paths it has scoped | On both paths the answers are collapsed. Bearer: a secret matching no stored digest and a revoked record both end as `AUTH_UNKNOWN`, because the digest scan passes over a revoked record as though it had never existed, and a distinct answer would tell a prober which ids the file holds and which were once live. Proof of possession, since 19 September 2026: a `credential` this file does not carry, and a name whose record is a bearer one with no key to verify against, are refused through the same code path as a failed signature and with the same code, `AUTH_SIGNATURE`, after one Ed25519 verification against a key that is in no credential file and whose result is discarded rather than read. The timestamp window and the presented nonce are checked before the file is consulted, so they answer alike whoever the header names, and what the file says about a record it holds is told only to a request whose signature verified. An unlisted target is read off the route table first but answered only at the scope check, so a caller who presented nothing usable is refused for that (`AUTH_MALFORMED`, `AUTH_SCHEME`) and learns nothing about the path, whether or not the server registered it. Rate limiting cannot be turned into an oracle either: the credential's bucket is taken at the last check, after scope, so an id the file does not hold is refused before any credential budget is consulted, and the one budget taken ahead of that, the request bound held on the connection address, is taken from every request whoever it names and answers with the same words whether or not the file holds the id the header wrote. That answer is what the caller catches, and it is unchanged by the record's separation: a refusal of this bound writes `PEER_RATE_LIMITED` to the access log's `deny` field where a credential over its own rate writes `RATE_LIMITED`, and the line sits inside the trust boundary the response sits outside, so nothing a caller is handed distinguishes the two by a code it can branch on | What an unauthenticated guesser learns is closed; what a stopwatch and a key holder learn is not. A lookup that hits and a lookup that misses do not take the same time, and an unknown name now costs one verification rather than a map read, which makes the two paths do the same work rather than the same number of nanoseconds: nothing here measures or bounds that difference, and no constant-time claim belongs in this row. Behind a valid signature the answers are specific by design, revoked, replayed, out of scope, over limit, because that caller is the one who can act on them. A `SCOPE_DENIED` refusal still says in its message whether the table has no row for the target or the credential lacks the row's scope, so paths remain enumerable from inside, by a credential this deployment issued. None of this makes the credential file invisible to the people who hold it: an operator, a reader of that volume, or anything that can write it knows every id in it, and the access log names the id a refused request presented even where the response never acknowledged it. The bearer digest scan's cost also grows with the size of the credential file rather than with how close a guess was |
| T16 | A receipt id reaches someone it was not issued to, in a log line, a proxy access record, or a pasted URL, and that holder reads whose credential minted it, or walks the deployment's other receipts | This gateway mints every id itself: sixteen hex tag characters then thirty-two hex characters from a fresh draw, replacing the upstream-chosen id a counter or a timestamp could have made walkable. The tag is `HMAC-SHA256(namespaceKey, credentialId)` truncated to eight bytes, and the namespace key is an HKDF over the deployment's own Ed25519 signing seed, so a holder of an id cannot reverse the tag into a credential id and cannot compute the tag for one: neither is possible without the seed. The fetch route then asks whether the presenting credential's own tag heads the id and serves nothing when it does not, which is why no ownership state is kept that could drift out of step with the receipts it governs | Linkability, not identification, plus the operator's own reach, which is the reading [access-control.md](access-control.md) section 8.3 gives. Two ids carrying one tag came from one credential, so anyone who sees both knows they belong together; and the deployment holding the seed can compute each credential's tag and so name the credential behind any id shown to it. An erasure does not close either: the tag is not a log field, it is a prefix of the id, and the receipt chain is append-only, so scrubbing a credential's lines leaves every id it ever read in place. See section 6 |
| T17 | Strip the mark. A party holding the response bytes deletes the marking member from a buffered completion, or the marking frame from a stream, before storing, showing, or republishing the transcript, so the content reads as though it were never marked | The response digest is taken over exactly those bytes, so the deletion is not a clean removal: it moves the bytes away from what the receipt attests. `res` is sha256 of the buffered body the gateway is about to send, and for a stream it is the digest of every chunk as it passes through the same closure that puts it on the socket (`gateway/src/server.ts`), and a verifier hashes the bytes it is holding and compares them, so the stripped transcript fails as `RESPONSE_HASH_MISMATCH` through the SDK's comparison (`packages/sdk/src/verify.ts`) and as a plain recompute failure for an auditor holding no software of ours. Nothing new is spent to get that refusal, and that is the design's point: the mark rides inside bytes `res` already covers, so removing it costs the receipt rather than clearing the record of ever having been marked. The mark is not the evidence; the receipt is, and this row is about the artifact anybody can edit | The pairing is the residue. A party who controls both the stored bytes and how they are presented can show a clean transcript beside a valid receipt made for different bytes and say which goes with which, because the two artifacts are separate documents and nothing in either one names the other except digests. What defeats that is recomputation by a checker who holds the bytes and the receipt from channels the presenter does not control: `res` over the transcript being offered, and the marked region's digest over the region inside it, both read off the signed payload. A viewer handed both by the same party and checking neither has no cryptographic protection, and routing around the presenter does not help them either, because fetching a receipt needs the `read` scope and that caller's own tag on the id ([receipt-spec.md](receipt-spec.md) section 4.7). Two further readings stay honest: a receipt that declares its response unmarked is a valid receipt over an unmarked response, so an unmarked transcript is not by itself evidence of a stripping, and whether a deployment marks at all is its own decision, taken by starting the process with `--marking provenance-v1` or leaving it out (section 6) |
| T18 | Move or forge the mark. A plausible marking member or frame is written into a transcript that never carried one, or a genuine marking is moved onto other bytes, so that human-authored text reads as machine generated, or a deployment is quoted as having served a response it never served | A mark pasted into a transcript changes that transcript's bytes, so it no longer hashes to the `res` of the receipt that attested the original, and the pasted region does not hash to the region digest any signed payload names. Producing a receipt for the forged pair takes the deployment's signing key, which is T5 and not this row. The design separates the region check from the response check on purpose, because the case the region digest catches is the one `res` cannot see: a transcript that is whole, complete, and hashes correctly but carries a marking that was not the attested one. That separation is built: `extractMarkedRegion` in `packages/receipt/src/marking.ts` identifies the region inside the bytes it is handed, `verifyCompletionReceipt` in `packages/sdk/src/verify.ts` compares that region's digest against the signed `d`, and `MARK_MISMATCH` in `packages/receipt/src/errors.ts` is what they answer with, for a response carrying no region, one carrying the shape twice, or one carrying a region that hashes elsewhere than `mk.d` | A marking standing alone in a transcript, with no receipt beside it, is a string anyone can type and a reader cannot check, which is exactly why the mark cannot be the evidence. So a forged mark is fully effective against an audience that pattern-matches on the transcript instead of verifying it, and that is a claim about that audience's diligence rather than about anything in this format. A genuine marked response whose receipt was not kept is the mirror case and is unfalsifiable from the transcript alone, since a receipt stays fetchable only for as long as the deployment decides ([receipt-spec.md](receipt-spec.md) section 4.3) |
| T19 | Scheme confusion. A detector reads a scheme label and applies the wrong extractor, either because a label was reused after its byte shape changed or because a mark written under one scheme is judged by another scheme's rule, so its verdict about a mark being present or absent is a reading of bytes it never correctly looked at | The registry (A8) is where this is settled, and what it guarantees is narrow enough to hold: a label is bound to one byte shape for as long as it exists and is never repurposed, so a shape change takes a new label, and a new label is something an un-updated reader refuses rather than reinterprets. A label a reader does not know is a refusal and not a guess, which is the whole of what the registry can do about a reader that is behind the times. The same reasoning sits one level up in the design, where a payload version outside the set a verifier accepts and a version it has never heard of are refused with one code, because the difference between those two is a fact about a release schedule and not a secret worth a distinguishable answer. What the registry guarantees is therefore about shapes and never about truth: a label is a pointer to an extractor, and genuineness belongs to the region digest and the signature over it (T18) | This is a guarantee about a table, written by one party and read by parties outside this repository, and nothing in the design puts a signature on the table itself. A detector shipping the wrong shape rule, or reading a stale copy of the registry, is wrong in a way no cryptographic check catches, since the bytes it accepts and the bytes it rejects are each self-consistent under the rule it holds. The table is no longer the gap: section 3.3 of [receipt-spec.md](receipt-spec.md) publishes both rows, `packages/receipt/src/marking.ts` is their executable form, the gateway's writer and the live client's check call that one module rather than two rules, and `packages/fixtures/data/marking-v1.json` lets a reader outside this repository compare their own extractor's spans with what this one locates. What publishing it does not change is the residual above: no signature covers the table, so a hand-copied or stale row stays self-consistent and answers to nothing |
| T20 | Injection by the model backend. A backend emits a marking frame or member of its own, so the stream the gateway forwards and hashes carries two candidate regions and a reader cannot tell the one the gateway digested from the one the model wrote for itself | A receipt attests one region digest, so a stream carrying two candidate regions is a stream no receipt can be about, and that is why the extraction rule the design settles on is exactly one: a response with more than one region matching a label's shape is a verification failure, not a choice between candidates. The gateway's own marking is computed over the bytes it wrote through the same path as the rest of the stream, so the two candidates are distinguished by which one the signature names and not by anything observable in the bytes. That the attack is open at all is a property of this gateway's own byte handling rather than of a filter it forgot: the streaming path takes every buffer the backend yields straight into the hash and the socket without reading what is inside it, which is the contract `gateway/src/backend.ts` states for `res` and the reason the insertion point for a mark has to be that same write path ahead of the finalised digest | A verifier does hold that rule now, on the bytes: `responseBytes` is required on `VerifyCompletionParams` beside their digest, so a live verification cannot be run in a shape that reads no region (`packages/sdk/src/verify.ts`), and a response carrying two candidates is `MARK_MISMATCH` rather than a choice between them (`packages/receipt/src/marking.ts`). What an injected frame still buys is the response rather than the verdict: the streaming path is the one that reads nothing inside a backend's buffers, so its refusal lands when the customer verifies rather than when this gateway serves, and a customer that verifies nothing, in `off` mode or holding no bytes, never sees it. The buffered shape is refused here instead, with a 502 naming the reason, because a body whose member name is already taken is a body that cannot carry a mark (`markBufferedBody` in `gateway/src/marking.ts`, `gateway/src/server.ts`). A backend can also write mark-shaped text into the assistant's content, where it is model output and `res` covers it as the transcript it is, so a reader looking for the shape rather than at the region reports a marking the deployment never wrote; the exactly-one rule counts frames, and keeping a sentence inside a paragraph out of that count is a claim about one scheme's shape rule being precise, which is a registry question and not a signature one |

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

- **No vendor platform-health data is fetched by anything in this code today.** With a pinned Intel
  root, `@ashaveri/attest-core` verifies a TDX quote through Intel DCAP: the quote under its
  attestation key, that key inside the QE report, and the report under a PCK chain reaching the
  pinned root. Intel's SGX root CA and the AMD Milan ARK are bundled with the package, so SDK
  `strict` mode verifies against them unless `policy.trustAnchors` says otherwise. Without a root
  for the platform the receipt claims, the leg is replay-only, so `quoteSignatureVerified` is
  `false` and the client is checking self-consistency plus its own pins, not an Intel signature.
  In neither mode does the verifier consult Intel TCB Info, the QE Identity or the PCK CRL, and on
  AMD it uses the ASK and VCEK files you supply rather than querying KDS. A platform that is
  genuinely signed but since deprecated or revoked by the vendor therefore still verifies. Checking
  freshness needs network access and is deliberately outside the offline verification path. The
  residual risk in T12 is the whole of this limitation, and it is not scheduled away: a service
  publishing this data for deployments that want it was decided on 21 September 2026, described in the
  README's platform-health section, and nothing of it is in this code or is a precondition of any
  verdict a third party can reach. This document describes the offline path as it is built.
- **The client's clock is a stranger's, and its two windows are chosen numbers.** In strict mode the
  client refuses a receipt whose `iat` is more than 300 seconds from its own clock, and evidence
  whose `att.ts` is more than 900 seconds from it. Those bound how much skew between two
  uncoordinated machines, and how much of a request's own generation time, the SDK will absorb; they
  measure no deployment. Nothing bounds how long a completion may stream, so past roughly fifteen
  minutes of generation it is the evidence window that refuses the response, not anything about its
  content, and a client pointed at a long-streaming deployment has to widen
  `maxEvidenceAgeSeconds` or switch it off. Both numbers are the client's to set, and neither is
  read from the wire.
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
- **A sealed manifest is available to a deployment, not owed by one.** `signerd --live` wraps the
  manifest in a COSE_Sign1 only when an operator names a second guest key path with
  `--manifest-key-path`, and a mock deployment never does: nothing here generates, embeds or derives a
  signing identity, and the same key is refused for both duties. The client half is the other condition:
  `manifestKeys` is a field of a policy built in code and not of the policy file format, so a policy read
  from a file designates no manifest signer and hears its manifest reported as unauthenticated. A
  deployment that wants its manifest attributed has to hand a key to that duty and tell its clients which
  key it was. What no deployment here can do is present a long-term identity of its own: the wrapper
  names whoever holds the key an operator pointed at, and the decision about which identity that should
  be, and where its key lives, is outside this code.
- **The weights digest chain has one open link.** The receipt binds `sha256(manifest)` and the
  manifest binds each model file, but the manifest itself is not carried in the receipt and is
  not in the compose measurement unless the operator mounts the weights as a dm-verity volume.
  A client that has not been given the manifest out of band sees an opaque `wts` value.
- **On the managed dStack platform, TLS terminates outside the TEE.** The measured container
  serves plain HTTP behind the platform gateway, so transport confidentiality depends on the
  platform edge, not on a channel the workload terminates inside the enclave.
- **Nothing here measures model behaviour.** A receipt proves who served which bytes; it says
  nothing about quality, alignment, or the prompt template behind the completion.
- **Marking is issued, read and refused in this code, and none of that reaches past the bytes.** The
  gateway signs a `v: 2` payload for every completion it issues (`issue()` in `gateway/src/server.ts`),
  which is the version that has to carry `mk`, and it writes a marking into the response only under
  `--marking provenance-v1`: started with the shipped `none`, or with nothing, it adds no byte to anyone's
  response and signs `sch: none` beside the digest of an empty region to declare that (`gateway/src/cli.ts`
  and `unmarked()` in `gateway/src/marking.ts`). A verifier holding response bytes does carve the region
  out of them and compare its digest against the signed `d`, by the published rule made executable in
  `extractMarkedRegion` (`packages/receipt/src/marking.ts`) and reached from the live client
  (`verifyCompletionReceipt`, `packages/sdk/src/verify.ts`), so `MARK_MISMATCH` has its raise sites.
  `verifyReceipt` and `decodeReceipt` still never reach that code, and cannot: neither is handed a
  response, so a reader holding the receipt alone performs no marking check. What a receipt carrying `mk`
  establishes is one pairing and no more: the holder of a deployment's signing key matched one labelled
  extraction rule and one 32-byte digest with the bytes of one response. The published artifacts are no
  longer all v1 either: a marked-region suite (`packages/fixtures/data/marking-v1.json`) measures the
  extraction rule, and one of the five receipt fixtures is a `v: 2` document, which is as far as version 2
  reaches in published coverage, as [vectors.md](vectors.md) states. That a marked receipt verifies
  wherever the accepted version set is left at its default, which is every version the package parses and
  which no client in this estate narrows, is a fact about readers rather than a guard for them. Whether a
  deployment marks at all is now a start-up setting rather than an unmade decision, and T17 through T20
  are written to hold under either setting. Why a mark took a new version rather than arriving as an optional member of the old one is
  section 6 of [receipt-spec.md](receipt-spec.md), and it holds: a v1 reader checks the thirteen fields
  it knows, finds nothing about a mark, and would verify a receipt over an unmarked response exactly
  as readily as over a marked one, which is silence read as a claim. The closedness that refusal rests
  on is not the payload map's alone: `meas`, `att`, `tok` and `mk` are closed the same way, and an
  undefined member of any of them is `BAD_PAYLOAD` rather than a member a reader takes no account of,
  and the signed `Ashaveri-Protected-Header` closes against the three labels `receipt.cddl` names and
  answers any other with `BAD_PROTECTED_HEADER` before it reads one of them. Closing by number is not
  the whole of that rule, because a label is bytes before it is a map key: an entry written as the
  half-float `1.0` shares the slot of the integer `1` in the map a reader is handed, and core
  deterministic ordering always writes the one-byte integer first and the three-byte float last, so the
  float's value is the one that stands and the header's `alg` or `kid` is whatever the last entry
  carried. A verifier that read the same bytes by their integer labels can be handed a different
  parameter set, both readings are self-consistent, and no reader settles the difference by choosing
  one, so the two documents that declare every member they carry are decoded where no floating-point
  number may appear, a key included. That is the last point at which the two are still two: after the
  decode there is one map entry and nothing left to check. It reaches the payload's numbers as well,
  and the format says which ones. The positions are `v`, `iat`, `att.ts`, `epk`, `tok.p` and `tok.c`,
  each read as the integer `receipt.cddl` types it, so a `128.0` written as a float is a malformed
  payload rather than 128 taken on trust. The writer that issues a receipt holds the same line from its
  own side and spells negative zero as the integer zero, so a float standing at one of these positions
  is a document another implementation wrote, not one this package signed and could not read back. So
  no field of a
  receipt that verifies is carrying something the verifier dropped on its way to agreeing, and none is
  carrying something it merged away.
- **A mark does not prove what its own text reads as proving.** What the mechanism supports is a
  statement about bytes and about who signed them; four readings the marking member invites are outside
  it. A mark does not prove the words beside it were generated by a model. `gen: "ai"` is text inside the
  region, written by the gateway, and the signature covers those bytes rather than the authorship they
  assert: that is T7's consistent lying read onto the marking field, and the same shape as the
  specification's sentence about `tok`, that a receipt proves who claimed a count and not that the count
  is right. A mark does not prove itself genuine. A label from section 3.3 of
  [receipt-spec.md](receipt-spec.md) is a pointer to an extraction rule and nothing more, so genuineness
  belongs to the region digest and the signature over it, never to the label (T18, T19). A marked
  response does not prove that the transcript in front of a reader is the one the receipt beside it
  attests, where both were placed there by one party; only a checker who recomputes `res` and `mk.d` from
  channels that party does not control settles it, and fetching a receipt takes the `read` scope and that
  caller's own tag on the id (T17, [receipt-spec.md](receipt-spec.md) section 4.7). Nor does an unmarked
  response prove anything about intent: `sch: none` is signed alike by a deployment that never thought
  about marking and one that thought about it and left the flag alone, because the field's claim is about
  these bytes and not about a configuration. Whose output has to carry a mark, and for what, is the
  question section 1 leaves as a fact about a deployment, and no receipt holds an answer to it.
- **A mark is detectable only by someone who has the bytes, and nothing here reaches further.** The
  marking this repository now builds is a member of the response envelope or a frame of the stream, never a
  property of the words, so a consumer of the text alone, pasted out of a chat window or retyped, has
  nothing to find and no way to tell marked content from unmarked. That is stated as the limit it is,
  and it is not on a roadmap to close. A statistical watermark carried in the text itself is out of
  technical reach for text at the reliability Article 50(2) asks for on that article's own feasibility
  terms, it changes what the user reads, and claiming it is the model vendor's ground rather than
  ours. What this stack can offer such a consumer is the receipt, and the receipt needs the bytes it
  attests or a holder of them.
- **A mark survives a client in the shape a client reads, and not in the shape of a bare frame.** What
  the two clients here do with the shapes a mark could take is measured, in
  `packages/sdk/test/unknown-response-members.test.ts`: a buffered completion carrying one top-level
  member no chat completion schema declares reaches the official OpenAI client and this SDK with that
  member intact on the object each hands its caller, and it survives the test stringifying the
  official client's object, which is the only re-serialisation measured here. A streamed response
  carrying the same member on a final chunk whose `choices` is empty reaches both the raw iterator
  and the official accumulator the same way. A `data:` frame that is neither a chunk nor the
  `[DONE]` sentinel is the shape neither reader gets through unharmed: the official client hands the
  frame to an iterator that is not looking inside it, and stops the moment a consumer adds the stream
  up, with `chunk.choices is not iterable` after the content chunks have already been delivered, while
  `parseChunk` in `packages/sdk/src/client.ts` requires a string `id` and an array `choices` on every
  frame and raises `GATEWAY_ERROR` with `stream chunk is not a chat completion chunk`. Clients other
  than these two, and any intermediary between them and the gateway, are unmeasured: what a receipt
  attests is the bytes the gateway wrote, not what a reader kept of them.

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
