# signerd on a dStack confidential VM

This is the operating procedure for a live CPU-only TEE deployment whose receipts an
outside client can verify. It is written against the documented dStack 0.6 and `phala` CLI
surface, and it has **not been executed end to end yet**. Lines marked `CONFIRM` are the
points that depend on the account, the assigned hostname, or the exact flags that tier
accepts; they get resolved the first time this runs.

## Files

| File | Role |
| --- | --- |
| `docker-compose.yaml` | The compose text the platform measures. It defines `inference` (llama.cpp, loopback only) and `gateway` (signerd, the only published port). |
| `Dockerfile` | Compiles `@ashaveri/signerd` from source in a build stage, then copies the production install into a slim `node:24-bookworm-slim` runtime stage. |
| `docker-entrypoint.sh` | Checks the mounted model files against the manifest when both weights environment variables are set, then execs `signerd`. |
| `weights.mjs` | Emits and checks the model manifest whose sha256 every receipt carries as `wts`. |

The compose text is the measurement. A rebuilt image tag, a different model file, or a changed
`--tee` value changes what the hardware attests to, which is why the image is pinned by digest
below and why `--expect-compose-hash` exists in `ashaveri verify`.

## 1. Build and publish the gateway image

```bash
git rev-parse --short HEAD                       # 1a2b3c4, used as the image tag
docker build -f enclave/Dockerfile -t ghcr.io/<account>/signerd:<tag> .
docker push ghcr.io/<account>/signerd:<tag>
docker buildx imagetools inspect ghcr.io/<account>/signerd:<tag>   # read the sha256 digest
```

Then replace the `image:` line in `docker-compose.yaml` with the digest form,
`ghcr.io/<account>/signerd@sha256:<digest>`. `:latest` is only usable for local bring-up,
because a mutable tag makes the measured compose text point at something that can change
underneath it.

The image is x86-64 only, like the llama.cpp server image: `--platform linux/amd64`.

## 2. Stage the model and its manifest

Weights are staged offline and mounted read-only. Nothing at runtime downloads a model.

```bash
mkdir -p enclave/release
curl -L -o enclave/release/<model>.gguf https://huggingface.co/<repo>/resolve/main/<file>.gguf
node enclave/weights.mjs generate enclave/release enclave/release/weights-manifest.json
```

`generate` prints the manifest digest. That digest is what `weightsOf()` puts in the manifest's
`models[].wts` and in every receipt for that model, so record it: it is the value a client
compares against after it has the manifest file itself. `verify` re-walks the directory and
lists every difference at once (content mismatch, canonical-order problem, missing or extra
file) and exits non-zero; the entrypoint runs it before the gateway starts signing.

## 3. Deploy

`enclave/.env` holds the two values the compose text interpolates:

```bash
ASHAVERI_TEE=tdx                                      # CONFIRM: what this instance type reports
ASHAVERI_PUBLIC_URL=https://<app-id>.<cluster>.phala.network
```

```bash
phala apps                                            # available instance types, current free tier
phala deploy -c enclave/docker-compose.yaml -e enclave/.env \
  --name ashaveri-signerd --instance-type <free cpu tier>   # CONFIRM: exact flags and tier name
phala cvms list
phala logs                                            # CONFIRM: whether logs are available on this tier
```

Two properties of the managed platform shape this step:

- The public hostname is assigned by the platform, so `ASHAVERI_PUBLIC_URL` cannot be known
  before the first boot. Boot once with a placeholder, read the hostname from `phala apps`,
  then deploy again with the real value. The redeploy changes the compose hash and therefore
  the measurement, which is expected: pin only after the URL is final. `--public-url` is used
  solely to build the `att.url` evidence link, so a stale value is visible to any client as a
  broken or wrong evidence URL rather than a silent inconsistency.
- TLS terminates at the platform gateway, outside the TEE, and the container listens on plain
  HTTP. Confidentiality of the request path therefore rests on the platform's edge plus the
  fact that the CVM memory is protected; it does not rest on an end-to-end TLS channel that
  the measured workload terminates itself.

`/var/run/dstack.sock` is mounted into the gateway container. That socket is the only source of
the signing key and of the evidence; there is no key file in the image, no key in an env var,
and nothing to seal after the fact.

## 4. Verify from a laptop

```bash
RD=$(printf '%064x' 0xdeadbeef)                      # any 64-hex report data
curl -s "$BASE/v1/deployment-manifest" -o manifest.json
curl -s "$BASE/v1/attestation?report_data=$RD" -o attestation.bin

node packages/cli/dist/cli.js verify attestation.bin \
  --report-data $RD \
  --intel-root intel-sgx-root-ca.pem \
  --expect-measurement <96 hex from a source you trust> \
  --expect-compose-hash <64 hex of the compose text you deployed>
```

Exit 0 means the envelope decoded, the runtime events replayed into the platform registers, the
report data matched, and both pins matched. `--expect-measurement` is the TDX MRTD on this
hardware, and the compose hash comes from the `compose-hash` runtime event that the RTMR3
replay ties to the quote.

`--intel-root` is what makes this a hardware claim. The file is Intel's published SGX root CA,
so with it the quote must carry an attestation key that the platform's PCK chain signed, and that
chain must reach Intel; drop the flag and a forged quote that is merely self-consistent would
pass. The root is also committed as a test fixture
(`packages/attest-core/test/fixtures/intel-sgx-root-ca.pem`) if you want a copy to compare
yours against.

The SDK side is `verify: 'strict'` with a policy:

```ts
const client = new AshaveriClient({
  baseUrl: `${BASE}/v1`,
  verify: 'strict',
  policy: { issuers: ['dstack-<12 hex>'], measurements: { tdx: ['<96 hex>'] } },
});
```

`policyFromManifest(manifest)` builds a policy from the served manifest. That is trust on first
use and nothing more; the pinned values above have to come from somewhere else, ideally the
operator out of band.

On every completion, strict mode repeats the laptop checks against the deployment itself: it
derives the report data from its own nonce and request bytes, fetches
`GET /v1/attestation?report_data=<hex>`, requires the served bytes to hash to the `att.d` the
gateway signed, chains the quote signature to a pinned vendor root (the Intel SGX root CA bundled
with `@ashaveri/attest-core`, or your own through `policy.trustAnchors`), and requires the MRTD
the hardware reports to equal the receipt's `meas.m`. The verified document comes back as the
`attestation` field on the result, and as a promise on a stream. Any of those checks failing
rejects the call; strict mode never degrades to a receipt-only verdict.

## A confidential GPU claim needs more than these steps

Everything above is a CPU-only deployment, and the compose text is what it measures: `llama.cpp`
on CPU and `signerd`, with no device reservation. A receipt labelled `snp+h100cc` is a different
deployment, and the gate is on the operator's side of it.

Three things have to be true before `--tee snp+h100cc` starts:

1. The instance is an AMD SEV-SNP VM with an H100 in confidential-computing mode. The `--tee`
   value is a request, never an inference: the platform half is checked against the CPU quote,
   and the label is adopted only if a device then answers the deployment's standing challenge.
2. The guest image's agent answers the device attestation call, and `nvattest` is present in it
   to produce the bundle. This repository has never had that call answered by a real image, so
   an image that offers no device route stops the deployment at startup rather than serving a
   weaker claim.
3. Collection runs once per challenge and takes seconds on real hardware, so the gateway caches
   each answer. A deployment that does not ask for the device label never triggers it.

A client in strict mode then reads two documents for one request: the platform quote at
`GET /v1/attestation?report_data=<hex>` and the device bundle at
`GET /v1/attestation/gpu?report_data=<hex>`, both keyed by the same challenge it computed itself.
The second is verified under a pinned NVIDIA device root, and a composite receipt with no
verifiable device report is refused.

What still is not proven by either document: that the attesting GPU is the card attached to the
attesting VM. The vendor's report carries no host binding, and only TDISP/TEE-IO device binding
would supply one. See section 6 of [docs/threat-model.md](../docs/threat-model.md).

## What this proves, and what it does not

Proves, once run: a receipt signed by a key the guest derived, binding the exact request and
response bytes, the model and `wts` digest, and a measurement and compose hash that a client
checked against values it did not learn from the deployment.

Does not prove:

- **Intel collateral freshness on TDX.** With a pinned Intel root (`--intel-root`),
  `attest-core` verifies the Intel DCAP quote signature: the quote under its attestation key,
  the key inside the QE report, and the report under a PCK chain reaching that root. Without a
  pinned root the TDX leg is replay-only and `quoteSignatureVerified` is `false`. Either way no
  Intel collateral is fetched, so a verified TDX signature does not show that the platform's TCB
  is still trusted by Intel, that its QE identity is valid, or that its PCK is unrevoked. Only
  version-4 TD quotes are accepted; a newer quote fails closed with `UNSUPPORTED_QUOTE`.
  SEV-SNP evidence is checked the same way offline, against a pinned ARK, with no KDS lookup.
- That the weights behind `wts` match the files in the container. The receipt binds the
  manifest digest; the manifest binds each file digest; the gap between the manifest and the
  mounted bytes is closed by the entrypoint check plus the measured compose text, not by the
  receipt chain. The manifest is also not published by the gateway, so a client needs it out
  of band to make `wts` more than an opaque hash.
- That the measured image contains the inference code you think it does, beyond what the
  compose hash pins: image contents are covered transitively through the digest in the compose
  text, which is why the digest pin matters more than the tag.
- Transport security end to end, for the TLS reason above.
- Anything about model quality, alignment, or whether the operator is honest about the
  prompt template it served.
