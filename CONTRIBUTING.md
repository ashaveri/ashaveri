# Contributing

## Setup

Node 24 and pnpm 12.3.4. Both are declared rather than assumed: `engines.node` is `>=24` and
`packageManager` is `pnpm@12.3.4` in the root `package.json`.

```bash
pnpm install
pnpm -w build
pnpm -w test
pnpm -w lint
```

Run the build before the tests. Workspace packages resolve to built output — each package's `dist`,
which is gitignored — so a test run against a stale `dist` reports on code that is not the code in
front of you. It can pass a change it never compiled and fail a change it did. `pnpm -w lint` has the
same dependency for the same reason: the type-aware rules read types through the declarations that
build emits.

`pnpm -w typecheck` is a separate pass, and it covers more than the lint rules do: it typechecks each
package's tests as well as its sources, while the type-aware lint rules read only the `src` projects.
The CI workflow runs install, build, lint, test and typecheck in that order. Two suites — the
gateway's and the CLI's — assert on file modes and rename behaviour they read back off disk, and a
mode is only observable against the process umask, so the test step sets `umask 0022` rather than
inheriting whatever the host has. Run a filesystem-touching test under that umask before you report it
as passing.

## What a change has to carry

**Tests for behaviour.** Vitest, in the package that owns the behaviour. A change to a refusal, a
verification step or a wire byte needs a case that fails without it. Property cases (`fast-check`)
cover the codec and the attestation parsers where a generator is cheaper than a table.

**One row, and the counted sentence, for a new error code.** Declare the code in the union that owns
the layer — the seven unions and which package owns what are tabulated at the top of
`docs/error-codes.md` — then add exactly one row for it to that union's table there. The opening
paragraph of that file counts the declarations, the unions and the distinct strings, and both
numbers have to still match the source: `packages/fixtures/test/error-codes.test.ts` reads every code
out of the declarations and every row out of the document, and fails the run when either direction
disagrees or a count is off. A bare code string has to name the layer that raised it, which is why
two unions sharing one string is a deliberate decision rather than a collision to fix; the section
"Why these strings do not overlap" in `docs/error-codes.md` explains that pair.

**Regenerated fixtures, never hand-edited ones.**

```bash
pnpm --filter @ashaveri/fixtures generate      # data/receipts/*.cbor, the .json twins of the vectors
                                               # that decode, data/keys/, data/manifest.json
pnpm --filter @ashaveri/fixtures generate:pop  # data/pop-v1.json
```

The generators derive their key material and most of their digests from a labelled SHA-256 seed
(`packages/fixtures/scripts/seed.ts`); the framing, the labels and the structure around those come
from the generator itself. Nothing is drawn at random, so the output is reproducible and a
hand-edited vector is visible the moment anyone re-runs a generator.
If your change was not meant to move a vector, regenerating produces an empty diff — that is the check
the vectors job runs, `git diff --exit-code packages/fixtures/data` after both generators. A non-empty
diff you did not intend means your change moved a signed byte.

**A format change carries the format's own documents.** `packages/receipt/receipt.cddl` is normative
for the wire format and `packages/receipt/schemas/receipt-v1.schema.json` describes the JSON
projection of the same payload, which `packages/receipt/test/schema.test.ts` checks against what the
codec emits. A format change is therefore one change covering the CDDL, the schema, the codec,
`docs/receipt-spec.md` and the vectors, and `docs/receipt-spec.md` section 6 is the rule for when `v`
itself has to move.

**Docs that still describe the code.** The documents in `docs/` are read as data in places:
`packages/fixtures/test/access-doc.test.ts` parses tables and section bodies out of
`docs/access-control.md` and `docs/error-codes.md`, and checks them against the source those
behaviours live in. A document that stops agreeing with the code can fail a run on its own.

## Commit messages

Conventional Commits v1.0.0: <https://www.conventionalcommits.org/en/v1.0.0/>. Most of this history
uses `type(scope): subject`, with the scope naming the package or the document the change touches —
`feat(sdk)`, `fix(gateway)`, `docs(access)`, `test(fixtures)` — and that is the form a new commit is
asked for. Keep the subject to one clause and in the imperative; put the reasoning in the body, where
it survives a collapsed diff view.

## Licensing

The code in this workspace is offered under the Apache License 2.0 (`LICENSE`). The one package-level
exception is `@ashaveri/fixtures`, whose golden conformance vectors are dedicated to the public domain
under CC0-1.0 (`packages/fixtures/LICENSE`) so a reimplementation elsewhere carries no attribution
obligation. Those two sentences speak for this workspace's own material; the pinned third-party
attestation fixtures are recorded file by file, with their provenance and their licence terms, in
`packages/attest-core/test/fixtures/README.md`. A contribution is accepted under the licence that
already covers the files you touched. Nothing is assigned to us and there is no contributor licence
agreement to sign: section 5 of Apache-2.0 is what
carries a contribution in, because anything you intentionally submit for inclusion arrives under the
terms of that licence and no additional ones unless you say otherwise, and submitting is the act that
grants the copyright licence of section 2 and the patent licence of section 3. Do not submit code you
have no right to license this way. This is a policy statement about how this repository accepts
contributions, not legal advice; if it and the licence text ever read differently, the licence text
governs.

Contributing does not create an employment, contractor or agency relationship between you and this
project.

## Vulnerabilities are not bugs

Something that is a vulnerability rather than a bug does not go in the issue tracker. `SECURITY.md`
is the intake path, and opening an issue for one discloses it.
