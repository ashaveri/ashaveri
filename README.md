# ashaveri

The Ashaveri Verifiable AI Inference SDK. OpenAI-compatible inference with cryptographic receipts: every response ships with a signed COSE_Sign1 receipt binding the request hash, response hash, model, weights manifest, and TEE measurement.

## Packages

| Package | Purpose |
|---|---|
| `@ashaveri/receipt` | Deterministic CBOR + COSE_Sign1 receipt codec (RFC 8949 / RFC 9052) |
| `@ashaveri/attest-core` | Offline verification of dStack confidential-VM attestations (SEV-SNP and TDX) |
| `@ashaveri/sdk` | Client SDK: `AshaveriClient` and `wrapOpenAI` with receipt verification |
| `@ashaveri/signerd` | Receipt-signing gateway: mock mode for development, live dStack CVM mode |
| `@ashaveri/cli` | `ashaveri verify` command with CI-friendly exit codes |
| `@ashaveri/fixtures` | Golden conformance vectors shared by every implementation |

## Development

```bash
pnpm install
pnpm build
pnpm test
```

The receipt wire format is normatively defined in `packages/receipt/receipt.cddl`,
with the full protocol in [docs/receipt-spec.md](docs/receipt-spec.md) and the
threat model in [docs/threat-model.md](docs/threat-model.md).
Fixtures are regenerated deterministically with `pnpm --filter @ashaveri/fixtures generate`.

## Verifying inference receipts

Start the mock gateway, then call it through the SDK:

```bash
node gateway/dist/cli.js --mock --port 7173
```

```ts
import { AshaveriClient } from '@ashaveri/sdk';

const client = new AshaveriClient({ baseUrl: 'http://127.0.0.1:7173/v1' });
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
`strict` (requires a policy pinning keys, issuers, instances, and measurements).

`--live` runs the same gateway inside a dStack confidential VM. There the signing key comes
from the guest agent and the measurement, issuer and instance come out of the hardware
evidence rather than from strings; [enclave/README.md](enclave/README.md) is the deployment
procedure.

The mock gateway signs with a development key in process memory, and its measurement, evidence
URL and weights digests are fixed development values. It reports `tee: "software"`, the one kind
in the protocol that claims no hardware protection, so read a mock receipt as proof that the mock
gateway signed those bytes and nothing more. See
[docs/threat-model.md](docs/threat-model.md) for what receipts do and do not prove at each
stage of the roadmap.

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
machine-readable output and `--report-data <hex>` to bind a nonce. TDX attestations verify
the event log and RTMR3 replay; Intel DCAP quote signature verification is out of scope for
the MVP.

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

## License

Code is licensed under [Apache-2.0](LICENSE). The golden conformance vectors in `@ashaveri/fixtures` are dedicated to the public domain under [CC0-1.0](packages/fixtures/LICENSE), so downstream reimplementations can embed them without attribution obligations.
