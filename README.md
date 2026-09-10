# ashaveri

The Ashaveri Verifiable AI Inference SDK. OpenAI-compatible inference with cryptographic receipts: every response ships with a signed COSE_Sign1 receipt binding the request hash, response hash, model, weights manifest, and TEE measurement.

## Packages

| Package | Purpose |
|---|---|
| `@ashaveri/receipt` | Deterministic CBOR + COSE_Sign1 receipt codec (RFC 8949 / RFC 9052) |
| `@ashaveri/fixtures` | Golden conformance vectors shared by every implementation |

## Development

```bash
pnpm install
pnpm build
pnpm test
```

The receipt wire format is normatively defined in `packages/receipt/receipt.cddl`.
Fixtures are regenerated deterministically with `pnpm --filter @ashaveri/fixtures generate`.

## License

Code is licensed under [Apache-2.0](LICENSE). The golden conformance vectors in `@ashaveri/fixtures` are dedicated to the public domain under [CC0-1.0](packages/fixtures/LICENSE), so downstream reimplementations can embed them without attribution obligations.
