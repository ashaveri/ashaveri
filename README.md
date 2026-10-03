<div align="center">

<a href="https://github.com/ashaveri/ashaveri">
  <img src="assets/ashaveri-banner.png" width="1200" alt="ashaveri. Change the model. Keep the evidence." />
</a>

<a href="https://github.com/ashaveri/ashaveri/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/ashaveri/ashaveri/ci.yml?branch=main&label=CI&labelColor=0A1517&color=0FA5A0" alt="CI on main" /></a>
<a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-E8B84B?labelColor=0A1517" alt="License: Apache-2.0" /></a>
<a href="tsconfig.base.json"><img src="https://img.shields.io/badge/TypeScript-strict-3178C6?labelColor=0A1517" alt="TypeScript strict mode" /></a>
<a href="#packages"><img src="https://img.shields.io/badge/version-0.1.0--dev-0B7A77?labelColor=0A1517" alt="Version 0.1.0 in development" /></a>

<!-- Publish day: replace the static version badge with these and drop the Status note.
<a href="https://www.npmjs.com/package/@ashaveri/sdk"><img src="https://img.shields.io/npm/v/@ashaveri/sdk?label=@ashaveri/sdk&labelColor=0A1517&color=0FA5A0" alt="@ashaveri/sdk on npm" /></a>
<a href="https://www.npmjs.com/package/@ashaveri/receipt"><img src="https://img.shields.io/npm/v/@ashaveri/receipt?label=@ashaveri/receipt&labelColor=0A1517&color=0FA5A0" alt="@ashaveri/receipt on npm" /></a>
<a href="https://www.npmjs.com/package/@ashaveri/attest-core"><img src="https://img.shields.io/npm/v/@ashaveri/attest-core?label=@ashaveri/attest-core&labelColor=0A1517&color=0FA5A0" alt="@ashaveri/attest-core on npm" /></a>
<a href="https://www.npmjs.com/package/@ashaveri/cli"><img src="https://img.shields.io/npm/v/@ashaveri/cli?label=@ashaveri/cli&labelColor=0A1517&color=0FA5A0" alt="@ashaveri/cli on npm" /></a>
<a href="https://www.npmjs.com/package/@ashaveri/fixtures"><img src="https://img.shields.io/npm/v/@ashaveri/fixtures?label=@ashaveri/fixtures&labelColor=0A1517&color=0FA5A0" alt="@ashaveri/fixtures on npm" /></a>
-->

</div>

# ashaveri

ashaveri is the evidence layer under an AI workflow: OpenAI-compatible inference where every completion
comes back with a signed receipt. A receipt is a COSE_Sign1 document binding the request hash, the
response hash, the model, the weights manifest, and the measurement of the confidential hardware
that answered, and `@ashaveri/sdk` verifies it before your code sees the answer. No verification
service of ours sits in the loop, and the checks are cryptographic rather than something we answer
for you: they run in the copy of this code you build, and the hardware trust roots, AMD's, Intel's and
NVIDIA's published keys, ship inside `@ashaveri/attest-core`. The only thing this project has decided
to run a service for is vendor attestation collateral, the revocation information and TCB info a
verifier would otherwise fetch from the chip vendor itself, offered as a convenience and as a second
source rather than as a precondition; that decision, what it covers and what it leaves to you are in
[Attestation collateral](#attestation-collateral).

## Status

The six publishable packages are at `0.1.0` and none of them is on a registry, so take them
from this repository: `pnpm install && pnpm build`, then import them by path or link the workspace.
Publishing is scheduled against a result rather than a date. `@ashaveri/*` goes to npm with trusted
publishing from CI once a receipt issued by confidential hardware, not by the mock gateway, verifies
end to end through the SDK in strict mode.

## Packages

| Package | Purpose |
|---|---|
| `@ashaveri/receipt` | Deterministic CBOR + COSE_Sign1 receipt codec (RFC 8949 / RFC 9052) |
| `@ashaveri/attest-core` | Offline verification of dStack confidential-VM attestations (SEV-SNP and TDX) |
| `@ashaveri/sdk` | Client SDK: `AshaveriClient` and `wrapOpenAI` with receipt verification |
| `@ashaveri/signerd` | Receipt-signing gateway: mock mode for development, live dStack CVM mode. Every route it serves demands a credential, checks the scope that route needs and rejects a replay and a spent rate bucket before it answers, and writes one access-log line per request; a live start requires `--credentials-path` and `--access-log-path` |
| `@ashaveri/cli` | `ashaveri` binary: `verify` for offline attestation checks, plus `keygen`, `credential` and `accesslog` operator commands, with CI-friendly exit codes |
| `@ashaveri/fixtures` | Golden conformance vectors shared by every implementation |

## Development

```bash
pnpm install
pnpm build
pnpm test
pnpm typecheck
pnpm lint
```

`pnpm lint` checks types through the declarations `pnpm build` emits, so the build has to
run first; CI uses that order.

The receipt wire format is normatively defined in `packages/receipt/receipt.cddl`,
with the full protocol in [docs/receipt-spec.md](docs/receipt-spec.md) and the
threat model in [docs/threat-model.md](docs/threat-model.md). Every error code those
packages throw, with what raises it and what a caller should do, is tabulated in
[docs/error-codes.md](docs/error-codes.md). Who may call at all is
[docs/access-control.md](docs/access-control.md): the admission checks every route runs,
the scope each one needs, and what the per-request access log holds, how long it keeps it,
and how a line is erased. The published conformance vectors are in
[docs/vectors.md](docs/vectors.md). That document says what a
reimplementation in any language is measured against, and how to read each suite.
Fixtures and vectors are regenerated deterministically
with `pnpm --filter @ashaveri/fixtures generate`, and the `generate:` variants named in
that document. What the evidence behind a receipt looked like as it arrived, and the record that would
hold those original bytes beside the context that made them verifiable, is
[docs/capture-v1.md](docs/capture-v1.md): the layout member by member, what each one lets a reader
conclude, and what none of them can.

Reporting a vulnerability and submitting a change have their own pages:
[SECURITY.md](SECURITY.md) and [CONTRIBUTING.md](CONTRIBUTING.md).

## Verifying inference receipts

Start the mock gateway, then call it through the SDK:

```bash
node gateway/dist/cli.js --mock --port 7173
```

Every route a signerd gateway serves refuses a request that names no credential, so the
client signs each request with one. `--mock` prints a development credential at start-up: the id
`dev`, and a key generated when that process starts and gone when it stops. That record is a fixture
of a process that refuses nothing real. `dev` names nothing outside the run that printed it, and a
live gateway answers from the credential file its operator installed, where an id the file does not
carry is refused exactly as a bad signature is. `credentialFromEnv` reads the id and key from the
environment:

```ts
import { AshaveriClient, credentialFromEnv } from '@ashaveri/sdk';

// ASHAVERI_CREDENTIAL_ID=dev ASHAVERI_CREDENTIAL_SECRET=<the privateKeyHex the gateway printed>
const client = new AshaveriClient({ baseUrl: 'http://127.0.0.1:7173/v1', credential: credentialFromEnv(process.env) });
const { completion, receipt } = await client.chat.completions.create({
  messages: [{ role: 'user', content: 'hello' }],
});
// receipt is a verified COSE_Sign1: its hashes bind the exact request and
// response bytes, the model, the token metering, and the claimed measurement.

for await (const chunk of await client.chat.completions.stream({
  messages: [{ role: 'user', content: 'hello' }],
})) {
  process.stdout.write(String(chunk.choices[0]?.delta.content ?? ''));
}
```

For existing code built on the official `openai` client, `wrapOpenAI(client)` wraps the
client's fetch so the same verification runs transparently, with receipts available through
`client.ashaveri.getReceipt(id)`. Verification modes are `off`, `receipt` (default), and
`strict`. Strict mode requires a policy pinning keys, issuers, instances and measurements, and
adds the hardware step: it fetches the evidence whose digest the receipt signed, verifies the
platform signature offline, and refuses a document whose report data or measurement disagrees
with this request and the receipt. `@ashaveri/attest-core` bundles Intel's SGX root CA, the
AMD Milan ARK and NVIDIA's device identity root as the roots to chain to;
`policy.trustAnchors` replaces them. A receipt whose `tee` claims a confidential-computing GPU
costs a second fetch, the device bundle from the route beside the platform one, and is refused
unless a device report that signed this request's digest verifies inside it.

`--live` runs the same gateway inside a dStack confidential VM. There the signing key comes
from the guest agent and the measurement, issuer and instance come out of the hardware
evidence rather than from strings; [enclave/README.md](enclave/README.md) is the deployment
procedure.

The mock gateway signs with a development key in process memory, and its measurement, evidence
URL and weights digests are fixed development values. It reports `tee: "software"`, the one kind
in the protocol that claims no hardware protection, so read a mock receipt as proof that the mock
gateway signed those bytes and nothing more. See
[docs/threat-model.md](docs/threat-model.md) for what receipts do and do not prove in mock mode
and in live mode.

## Verifying an attestation

```bash
node packages/cli/dist/cli.js verify attestation.bin \
  --ark amd-ark.pem --ask ask.pem --vcek vcek.pem \
  --expect-measurement <96-hex> --expect-compose-hash <64-hex>
```

SEV-SNP attestations are verified offline against a pinned AMD ARK: the ARK to ASK to VCEK
certificate chain, the VCEK-to-report binding (chip id, product line, TCB), the report's
ECDSA P-384 signature, the guest policy, the runtime event log, and the mr_config to
HOST_DATA binding. Exit code 0 means verified and every `--expect-*` pin matched; 1 means
verification or a pin failed; 2 means usage or input error. Pass `--json` for
machine-readable output and `--report-data <hex>` to bind a nonce. TDX attestations always
verify the event log and RTMR3 replay. With `--intel-root <pem>` they also verify the Intel
DCAP quote signature: the quote's ECDSA P-256 signature under its attestation key, that key
bound by the QE report, and the report bound by a PCK chain that must reach the pinned Intel
root CA. Without it, `quoteSignatureVerified` is `false` on TDX and the CLI says so. Either
way the MVP does not fetch Intel collateral, so a verified TDX signature does not yet tell you
that the platform's TCB is unexpired, that its QE identity is valid, or that its PCK has not
been revoked.

A confidential-computing GPU attests on its own: the dStack envelope carries no device
report, so `--gpu-report <bin> --gpu-chain <pem>` supplies a captured NVIDIA SPDM
measurements report and the chain it was signed under, paired by position, and
`--gpu-root <pem>` names the device identity root that chain must reach. Each report's
ECDSA P-384 signature is verified offline under that root, and the challenge the device
signed is printed beside the report data above. With `--report-data` pinned, a device that
answered a different challenge fails with `CHALLENGE_MISMATCH`, because it is evidence about
some other request. What the check does not establish is that the device which signed the
report is the one attached to the attesting VM. That needs TDISP, and no route purchasable
today provides it, so a composite claim proves a genuine CPU TEE and a genuine device
signature and stops there.

Verification proves an attestation is genuine; pinning turns it into a decision about *this*
deployment. `--expect-measurement` compares the platform launch digest, the SEV-SNP launch
digest or the TDX MRTD, against the value you measured when you built the image.
`--expect-compose-hash` compares the dstack compose hash the platform committed to: on
SEV-SNP it is read from the mr_config document already hashed into HOST_DATA, and on TDX,
where the envelope carries no document, from the `compose-hash` runtime event that the RTMR3
replay ties to the quote. A mismatch exits 1 with code `PIN_MISMATCH` and names both the
observed and the pinned value, so a rebuilt image, an edited compose file, or evidence from
another VM is rejected rather than merely reported. Take pinned values from a source you
trust independently of the deployment under test: a measurement the deployment publishes
about itself is a claim to check against your pin, not a pin.

## Verifying a handover with nothing installed

`pnpm -C packages/cli bundle` writes `packages/cli/dist/ashaveri-bundle.mjs`: the CLI as one
file, with its dependencies inside it and every import resolved to the standard library. Copy that
one file to a machine that has no checkout, no `node_modules` and no network, and it runs. The
prerequisites are the file, the documents, the inputs named below, and Node.

**Node.** The artifact targets the release this repository is developed against, `24.21.0`, the
version `.nvmrc` names and `engines.node` bounds to `>=24.21.0 <25`. It is plain JavaScript with no
build step at the far end and no native module: nothing is fetched, compiled or installed while it
runs. The acceptance recorded in this repository was run on `24.7.0`, below the declared floor, and
every command below behaved as documented; treat the declared range as what is supported and a
different `24.x` as something to try before relying on.

**No network, and no route that would take one.** `verify-receipt` reads its deployment manifest from
`--manifest` and refuses every other address, so a receipt pointing its `att.url` at a host does not
make this tool reach that host; the refusal names the file the manifest came from. `verify`,
`verify-handover`, `verify-pack` and `verify-export` open only the paths you type. Certificate
revocation is not consulted, and no vendor endpoint is called: a verified platform signature says the
chain reached the root you named, not that the platform is still current.

**What each verb needs.**

| Verb | Inputs, all files or the command line |
| --- | --- |
| `verify <attestation>` | The attestation, `--ask` and `--vcek` when the document carries no chain, and a root: `--ark`, `--intel-root` or `--gpu-root`. With no policy and no root flag it trusts nothing you did not name, and says so with `MISSING_TRUST_ROOT`. |
| `verify-receipt <receipt>` | The receipt, `--policy`, `--manifest`, `--nonce`, one of `--request-body` or `--request-hash`, and one of `--response-body` or `--response-hash`. A receipt whose payload names a marking needs the response bytes, not only their digest, because its claim is a region inside them. A policy demanding weighed anchor material is answered here and nowhere else on the command line: `--anchor-file <slot>=<file>` hands the document a `held` slot digests and `--anchor-chain <slot>=<file>` the header that arrived beside it, weighed under `--intel-root` and described by the four `--collateral-*` flags, and the report prints the digest the slot states beside the digest those bytes hash to, the root the answer reached and the instant it was read at. A run naming no file keeps the answer it always gave, `ANCHOR_MATERIAL_UNREACHED`, because a slot stating held is not a claim that some reader can resolve it. |
| `verify-handover <document>` | One signed document and `--key` for a receipt, pack, redaction or export, or `--manifest-key` for a deployment manifest. A redaction is the one shape that arrives as a pair: the pack its own signature designates travels in `--companion`. It classifies the document by the content type inside its own signature and reads it with the reader for that type. |
| `verify-pack <document>` | The pack and at least one `--key`: every key whose receipts a span crosses, since a pack over a rotation carries signatures from the epochs current then. `--intel-root` beside `--collateral-origin`, `--collateral-platform`, `--collateral-cpu-type` and `--collateral-level`, each keyed `<slot>=<value>`, ask what the material this pack carries says about a platform; the rule for the roots is below. |
| `verify-export <document>` | The export, its `--key`, and one `--companion` per signed item: the original whose digest is recomputed, given by its own name or by a path to it. |

A policy document and a deployment manifest are inputs, and this repository publishes no runnable
pair of them. The committed receipt vectors carry the values a pair has to agree with:
`packages/fixtures/data/receipts/receipt-valid-v1.json` holds the issuer, instance, model, weights,
measurement, digests and issuance time, and `packages/fixtures/data/keys/receipt-key-v1.json` holds
the public half in hex, which is the base64url the pins want. `packages/cli/scripts/offline-proof.ts`
turns those two files into a `policy.json`, a `manifest.json` and the four values above, in a
directory outside the checkout, and it is the readable form of what the pair has to say. A real
handover brings its own: a deployment serves the manifest once, you keep the copy, and the policy is
yours.

**What a run refuses to assume, and prints instead.** Keys come only from the command line, and the
report says which it was handed and whether the document in front of it consulted them. An evidence key
does not authenticate a deployment manifest, so a manifest read without `--manifest-key` comes back
`authenticated: false` beside the reason, at exit 0, which is the narrower question rather than a
pass. `--manifest-key` designates a signer for one run and sits outside the policy digest the report
cites, and the report says that too. A pack's two duty figures are printed as the deployment states
them and judged by nothing here, because whether a duty was owed turns on the mapping revision the
pack names and on the law behind it. What a pack carries is weighed against the roots `--intel-root`
names and against nothing else: no root bundled with the verifier is consulted on this path, the
instant an answer is read at is the stamp the record naming the material was chained at rather than a
clock this run reads, and a run that named no origin and no platform prints every held slot as not
weighed beside the flag that would have supplied one. Whether a pack is all the deployment still holds,
and whether it agrees with the copy a reader held before, are stated as not checked. `--now` is the
clock, and it is how an archived receipt is read at all: the windows close against it, so last year's
receipt judged by
today's clock is a refusal with a code, and a verdict reached at a stated instant is a historical
appraisal of that instant rather than a current one. A date the verifier cannot weigh as a reading of
its own clock, because it is counted in the scale the stamps are not, is refused by name at that entry
before it closes a window on anything, so a caller who mixed the two is told about the clock.

**What it does not do.** It reads the one document you name, plus the files that document designates:
a directory is refused with the reason, and there is no bundle mode that decides which files stand in a
handover, which are omitted or which are extra. An export is read with the originals its items name,
and an amendment with the one pack whose whole bytes its own signature designates, and those are the
pairs the option carries rather than a pile it chooses from. The rules that come closest are per
document and were all seen to fire: an export original missing, substituted at the right name, or named
by a path that climbs out of its directory is refused as `EXPORT_ORIGINAL_UNAVAILABLE`,
`EXPORT_DIGEST_MISMATCH` and `EXPORT_BAD_MANIFEST`, a pack whose span crosses an epoch nobody retained
is refused as `PACK_UNKNOWN_KEY`, a pack whose attached material contradicts the references its sealed
receipts name is refused for the one position that contradicts them, under `PACK_ATTACHED_DIGEST_MISMATCH`,
`PACK_ATTACHED_DUPLICATE`, `PACK_ATTACHED_UNNAMED` or `PACK_ATTACHED_UNRESOLVED`, and a receipt outside
its window as `STALE_RECEIPT`. And it never reads the evidence document behind a
receipt's `att.d`: the timestamp is windowed and the document itself is fetched by a client talking to
a deployment.

```bash
node ashaveri.mjs verify-pack pack-well-formed-three-items.cbor \
  --key=E6uO0ed3_zm-Ix32lLu8j5Z9W3eet8q1WHYstU-WCwU
```

That key is the receipt signing key of the published fixtures, TEST ONLY, printed by
`packages/fixtures/data/keys/receipt-key-v1.json` in hex and given here in base64url; the document
names the kid it was sealed under, and the run reports which designation it consulted.

## Attestation collateral

**What the verifier does today.** It checks signatures and certificate chains offline, against the
roots bundled in `@ashaveri/attest-core` or the roots you pass it, and it consults no vendor endpoint
for attestation collateral, and that includes our own. The consequence is written down rather than
smoothed over: with a pinned Intel root, a TDX quote is verified under its attestation key, that key
inside the QE report, and the report under a PCK chain reaching the root, while Intel's TCB Info, the
QE Identity and the TCB CRL go unread; on AMD, the ASK and VCEK are the files you supply and KDS is not
queried; a confidential-computing GPU's chain is verified under the device root you pin, and NVIDIA's
revocation information and reference driver and VBIOS measurements go unread as well. So a platform
that its vendor has since deprecated or revoked still verifies here, which is what
[docs/threat-model.md](docs/threat-model.md) row T12 and section 6 say in the same terms. That is a
property of an offline check and it is deliberate. Which source each bundled root was read from, on
which day, and under which licence class that source published it, is one row each of the anchor
provenance ledger, and [docs/trust-anchors.md](docs/trust-anchors.md) prints those rows beside the
rows for every vendor file this repository tracks. The evidence document reaches a client from the
deployment's own evidence URL, in `strict` mode, and that fetch is to the deployment rather than to
us.

**The planned collateral service.** This project will run a service publishing exactly
the collateral named above: the TCB info, the QE identity and the revocation status, and the reference
measurements a device verdict needs, all fetched from Intel's, AMD's and NVIDIA's own endpoints and
republished, offered as a convenience and as a second source. Nothing of it exists yet: no endpoint
runs, and nothing a shipped command does asks one, because the fetching code is a call a caller makes
rather than a step any path here takes. Three things accompany it. A deployer who declines the service
gives up nothing, because a feed is a second source and not a precondition, and no verdict a third party
can reach depends on our service existing; the fetching code and the defaults it fetches under are
published here in source, because fetching collateral that can change a verdict is itself something a
verdict reads; and an unreachable or unanswered feed has to be reported as freshness unknown and refused
rather than pass a check it did not perform. That refusal, and every other answer the collateral package
gives, is tabulated under `CollateralErrorCode` in [docs/error-codes.md](docs/error-codes.md), including
the ones naming a status the vendor no longer stands behind and a window that had closed. The answers a
shipped command gives are reached by weighing material a caller hands over rather than by asking an
origin, and weighing answers only for material of the envelope the origin's declaration decodes. Intel's
documents present their certificates in a header beside the body, so a pack states a signed reference per
held slot and material handed in beside its chain digest is weighed rather than refused at the envelope;
[docs/pack-v1.md](docs/pack-v1.md) states what a reference answers for, and what a reader that reaches
nothing is told instead. None of it reaches an
attestation verdict. `ashaveri verify`
consults no vendor endpoint and no attached material, so a quote verified under a pinned root still says
nothing about whether that vendor stands behind the platform.

**What stays the deployer's if the service is declined.** The freshness judgement, entirely, exactly
as it is today. Either source the collateral directly, from Intel's provisioning certification
endpoints, AMD's KDS and NVIDIA's revocation and reference measurements, and hand it to the verifier
through its own options, or accept the documented residual risk in
[docs/threat-model.md](docs/threat-model.md) and say so plainly in your own deployment's
documentation. A pinned root answers who signed something. It answers nothing about whether the
platform behind that signature is still trusted by its vendor, and this repository's documents are
written so that a deployer finds that out by reading them rather than by being attacked.

## License

Code is licensed under [Apache-2.0](LICENSE). The golden conformance vectors in `@ashaveri/fixtures` are dedicated to the public domain under [CC0-1.0](packages/fixtures/LICENSE), so downstream reimplementations can embed them without attribution obligations.

What this repository keeps public, and the one rule that decides it, is
[CONTRIBUTING.md § What stays open, and what does not](CONTRIBUTING.md#what-stays-open-and-what-does-not).
The same page states this repository's patent and design position under the heading
[Patents and designs](CONTRIBUTING.md#patents-and-designs), and the scope it states is what this
repository publishes: over that material it claims none, and it asks nothing of anybody who builds a
verifier, a reimplementation, a marking detector or a deployment from these sources.
