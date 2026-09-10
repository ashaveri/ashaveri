# ashaveri

The Ashaveri Verifiable AI Inference SDK. OpenAI-compatible inference with cryptographic receipts: every response ships with a signed COSE_Sign1 receipt binding the request hash, response hash, model, weights manifest, and TEE measurement.

## Packages

| Package | Purpose |
|---|---|
| `@ashaveri/receipt` | Deterministic CBOR + COSE_Sign1 receipt codec (RFC 8949 / RFC 9052) |
| `@ashaveri/attest-core` | Offline verification of dStack confidential-VM attestations (SEV-SNP and TDX) |
| `@ashaveri/cli` | `ashaveri verify` command with CI-friendly exit codes |
| `@ashaveri/fixtures` | Golden conformance vectors shared by every implementation |

## Development

```bash
pnpm install
pnpm build
pnpm test
```

The receipt wire format is normatively defined in `packages/receipt/receipt.cddl`.
Fixtures are regenerated deterministically with `pnpm --filter @ashaveri/fixtures generate`.

## Verifying an attestation

```bash
node packages/cli/dist/cli.js verify attestation.bin \
  --ark amd-ark.pem --ask ask.pem --vcek vcek.pem
```

SEV-SNP attestations are verified offline against a pinned AMD ARK: the ARK to ASK to VCEK
certificate chain, the VCEK-to-report binding (chip id, product line, TCB), the report's
ECDSA P-384 signature, the guest policy, the runtime event log, and the mr_config to
HOST_DATA binding. Exit code 0 means verified; 1 means verification failed; 2 means usage
or input error. Pass `--json` for machine-readable output and `--report-data <hex>` to
bind a nonce. TDX attestations verify the event log and RTMR3 replay; Intel DCAP quote
signature verification is out of scope for the MVP.

## License

Code is licensed under [Apache-2.0](LICENSE). The golden conformance vectors in `@ashaveri/fixtures` are dedicated to the public domain under [CC0-1.0](packages/fixtures/LICENSE), so downstream reimplementations can embed them without attribution obligations.
