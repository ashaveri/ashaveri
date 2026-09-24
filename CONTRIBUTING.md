# Contributing

## Setup

Node 24.21.0 and pnpm 12.3.4. Both are declared rather than assumed: `.nvmrc` names `24.21.0` and
every CI job that installs a Node reads that file, while the root `package.json` declares
`engines.node` as `>=24.21.0 <25` and `packageManager` as `pnpm@12.3.4`.

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
package's tests as well as its sources, and the scripts folders that hold the fixture generators and
the erasure-pass measurement along with them, while the type-aware lint rules read only the `src`
projects.
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
pnpm --filter @ashaveri/fixtures generate          # data/manifest.json, data/keys/, data/receipts/
pnpm --filter @ashaveri/fixtures generate:pop      # data/pop-v1.json
pnpm --filter @ashaveri/fixtures generate:req      # data/req-v1.json
pnpm --filter @ashaveri/fixtures generate:res      # data/res-v1.json
pnpm --filter @ashaveri/fixtures generate:marking  # data/marking-v1.json
pnpm --filter @ashaveri/fixtures generate:chain    # data/chain-v1.json
pnpm --filter @ashaveri/fixtures generate:export   # data/export-v1.json
pnpm --filter @ashaveri/fixtures generate:manifest # data/manifest-v1.json
```

The generators derive their key material and most of their digests from a labelled SHA-256 seed
(`packages/fixtures/scripts/seed.ts`); the framing, the labels and the structure around those come
from the generator itself. Nothing is drawn at random, so the output is reproducible and a
hand-edited vector is visible the moment anyone re-runs a generator.
If your change was not meant to move a vector, regenerating produces an empty diff — that is the check
the vectors job runs, `git diff --exit-code packages/fixtures/data` after all six generators. A
non-empty diff you did not intend means your change moved a signed byte.

**A measured number, re-run rather than hand-written.** One command regenerates the latency figures for
an erasure pass running beside live traffic. Any such number quoted in this repository is to be read as
a copy of what this command printed, and re-run rather than edited in place:

```bash
pnpm measure:erasure-pass    # packages/cli/scripts/erasure-pass, builds first
```

It writes its parts, its scrub markers and its access log into a directory the system temporary path
gives it, and removes them at the end of the run, so it touches nothing under version control and a
vector job can never see its output. Nothing here writes into `packages/fixtures/data`. The run lasts
minutes, asks the machine what request rate it can serve with room to print a tail, and states the
sample count beside every percentile; the same bytes at the same rate over its own repeats give the
spread each number carries. Read those numbers as a statement about the host that printed them.

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

## What stays open, and what does not

This repository is the open half of the project. Where the line falls is decided by one rule rather
than by a list, and the rule is worth stating because it is the rule a contribution is measured
against. **A thing belongs outside this repository only if publishing it could not change what a third
party's verifier concludes about a receipt.** Not whether it is valuable, and not whether a rival
could copy it: the test is whether someone holding a receipt, a copy of this code and nothing else
from us would reach a different verdict if they could read the thing. If they would, it is here in
source. If they would not, it is decided on its own merits.

On the public side, and staying there:

- the receipt format, normatively in `packages/receipt/receipt.cddl` with its JSON projection in
  `packages/receipt/schemas/receipt-v1.schema.json`, because every implementation is measured against
  both;
- the verification path, which is `@ashaveri/attest-core`, `@ashaveri/sdk` and `@ashaveri/cli`;
- the gateway that signs receipts, `@ashaveri/signerd`. Anything that signs, seals or changes what a
  verdict means is open in source and in its published form permanently, and the gateway is one of
  those things, so taking its source out of public view later would be a reclassification with a date
  and a reason rather than a quiet removal. Its source is here today; a decision of 21 September 2026
  is that its published package belongs on this side too, and as of that date nothing in this project
  is on a registry at all and the workspace manifest still marks that package `private`, which is what
  `SECURITY.md` records when it says the gateway is run from source;
- the conformance vectors in `@ashaveri/fixtures`, dedicated to the public domain so that a
  reimplementation in any language carries no attribution obligation;
- the documents that say what a verdict does and does not prove, in `docs/`.

The rule keeps nothing back that a verdict reads, and it names its two survivors. A maintained
duty-mapping dataset, and the tooling that produces a pack from it, sit outside this repository: the
first is work someone has to keep correct, and its worth is the maintenance rather than the secrecy.
A decision of 21 September 2026 is that a deployment receives it as a dated snapshot carrying its own
revision date, so that a claim made in 2027 is read against the version it was made from. The layout
such a pack carries is a separate matter, because a deployment reads it and so a verdict can turn on
it: the rule puts that layout on this side, and the same date settled the order — the layout is
published here before the tooling that writes it moves on. As of 21 September 2026 no pack layout is
published in this repository, for the plain reason that nothing in this repository writes one.

What a contributor should expect to follow. A change that touches what a verdict means has to be made
here, because a closed half cannot hold it without breaking the rule above. A component no verdict
reads — routing choices, cache tuning, deployment plumbing — is classified case by case, and a
proposal to keep one back is argued on its own facts rather than on this page. And everything named
above stays where it is: this is a boundary drawn to be checkable, so a reader who finds a mechanism a
verifier depends on missing from these sources has found a defect worth reporting, in the sense that
`SECURITY.md` means it and not in the sense that a paid feature is missing.

## Licensing

The code in this workspace is offered under the Apache License 2.0 (`LICENSE`). The one package-level
exception is `@ashaveri/fixtures`, whose golden conformance vectors are dedicated to the public domain
under CC0-1.0 (`packages/fixtures/LICENSE`) so a reimplementation elsewhere carries no attribution
obligation. Those two sentences speak for this workspace's own material; the pinned third-party
attestation fixtures are recorded file by file, with their provenance and their licence terms, in
`packages/attest-core/test/fixtures/README.md`. A contribution is accepted under the licence that
already covers the files you touched. Nothing is assigned to us and there is no contributor licence
agreement to sign: section 5 of Apache-2.0 is what carries a contribution in, because anything you
intentionally submit for inclusion arrives under the terms of that licence and no additional ones
unless you say otherwise, and submitting is the act that grants the copyright licence of section 2
and the patent licence of section 3. Do not submit code you have no right to license this way. This
is a policy statement about how this repository accepts contributions, not legal advice; if it and
the licence text ever read differently, the licence text governs.

Contributing does not create an employment, contractor or agency relationship between you and this
project.

### Patents and designs

The two sections above are the whole of this project's intellectual-property position, and holding no
patent position is part of it rather than a gap in it. **No patent or design position is claimed on
what this repository publishes.** That was decided explicitly on 21 September 2026 instead of being
left to drift: this project files no patent application on the receipt format, the verification path
or the output marking, registers no design over any of them, and claims nothing by silence. Openness
is the stated position, and it is a credible one here for a reason worth naming: receipts of this
shape were published by others before this repository existed, so the field is already open and a
position taken on it would be a position over disclosure that is no longer anyone's to keep.

What follows from that is a statement about what this project asserts, not about anybody else's
rights. This project will not assert a patent or design right against anyone who implements a
verification path — a client that checks a receipt, a reimplementation of the published format, a
detector reading the published marking schemes, or a deployment serving this protocol — and that
includes a competitor. It does not license and cannot speak for a patent some third party may hold
over the same ground, and nothing in this file warrants that implementing the specification infringes
nothing. A contributor's position is untouched by this section: what a contributor grants is exactly
the grant the licence above carries, and no assignment, waiver or additional grant is asked for.

## Vulnerabilities are not bugs

Something that is a vulnerability rather than a bug does not go in the issue tracker. `SECURITY.md`
is the intake path, and opening an issue for one discloses it.
