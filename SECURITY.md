# Security

How to reach this project about a vulnerability, what to expect back, and which surfaces are ours.

## Reporting a vulnerability

Two channels reach this project. Write to `info@ashaveri.com`, or use the private vulnerability
reporting form shown on this repository's Security page. Both are private to the reporter and neither
is a public issue: what you send is seen by the one person who reads this project's intake, and stays
unseen by anyone else unless an advisory is published from it. No second address and no public
tracker is published here.

Send the smallest reproducible case. What that means here: the input, the command you ran, what
happened, and what you expected, in a form that does not depend on anything of ours running. Name
the commit you built from (`git rev-parse HEAD`), and say which mode the observation came from,
`--mock` or `--live`. The two modes claim different things, so a result from one is usually not a
result about the other: a mock gateway signs with an ephemeral in-process key and reports
`tee: "software"`, which claims no hardware protection at all.

Neither channel is encrypted end to end: we publish no key for that address, and the reporting form
is encrypted to GitHub in transit rather than to a key only we hold, so do not send a credential,
a signing key, or anybody's request data. Describe where the secret is and how to reach it instead.

There is no bug bounty here. No reward is paid for a report.

## What you get back

The published address is read every day, and a report filed through the form reaches the same reader.
That is the whole of the promise here, and it is deliberately small: there is no response-time target,
no acknowledgement window, no service level and no escalation path in this document, and nothing in it
commits anybody to a date for a reply or for a fix. One person reads this intake, so whoever reads your
report is whoever answers it, with no queue and no hand-off between people. What comes back is
whatever there is to say: a reproduction, a question about yours, or a fix.

## What not to do

- **No public issue before a fix is available.** The receipt format is shared by every deployment
  built from this repository, so a write-up in the open is a working instruction set until the fix
  is in `main`. Open the issue after that, or with our agreement by mail.
- **Do not test against a deployment you do not run.** Every gateway built from this code belongs to
  whoever started it, and we run none, so there is nothing of ours to probe. Get that operator's
  permission in writing before sending anything at their endpoint.
- **Do not run anything that disrupts a service.** No request floods, no rate-limit or availability
  testing against an endpoint that is not yours, no filling a receipt store or an access-log volume.
  Availability is explicitly outside what a receipt is for (`docs/threat-model.md` section 1), so a
  disruptive test produces no evidence about this protocol and can cost somebody their deployment.

## Surfaces we own

| Surface | Code |
|---|---|
| `@ashaveri/receipt` | `packages/receipt` — the deterministic CBOR and COSE_Sign1 receipt codec |
| `@ashaveri/attest-core` | `packages/attest-core` — offline verification of SEV-SNP, TDX and device evidence |
| `@ashaveri/sdk` | `packages/sdk` — client verification, policy pins, proof-of-possession signing |
| `@ashaveri/signerd` | `gateway` — the receipt-signing gateway |
| `@ashaveri/cli` | `packages/cli` — the `ashaveri` binary: attestation verification and the operator commands |
| the guest container | `enclave` — the image, entrypoint, compose text and weights tooling a live deployment measures |

`@ashaveri/signerd` is the workspace's private package and is not built to be installed from a
registry; it is run from source, and its `--mock` mode is a development fixture rather than a
deployment. That sentence is about where the package stands today, not about keeping its code back:
`CONTRIBUTING.md` states the rule that keeps the gateway in public view.

## What is not here

- **No published packages.** As of September 2026 none of the above is on a registry, so there is no
  published artifact to substitute, no install-time provenance question to raise about a release, and
  no package page whose text could contradict this code.
- **No hosted service.** We operate no gateway, no verification endpoint, no API and no telemetry
  intake. There is no account, tenant or console of ours to attack, no support desk, and no uptime
  figure anywhere in this project. Nothing of ours sits in a caller's verification loop either: the
  checks are local, against the vendor roots bundled in `@ashaveri/attest-core` and the pins a client
  supplies. That covers the present and the decided future alike: the platform-health feed described
  in `README.md` was decided on 21 September 2026 and nothing of it runs, so as of this writing there
  is still no endpoint of ours for a report to be about.
- **No certifications and no audits.** This repository has completed neither, so it holds no seal to
  lose and no attestation of its own processes. Where a document here names an article of the EU AI
  Act or of the GDPR, it names it as the reason a number or a field is what it is. That is a design
  input, not a compliance claim, and `docs/access-control.md` says plainly which questions it does
  not settle.

## Third parties

The inference backend a gateway proxies to (`--upstream`), and the hardware vendors' attestation
services and certificate endpoints, are parties a deployment depends on. They are not surfaces this
project owns or can fix, and a finding against them belongs to the vendor's own intake.

## Limits already written down

`docs/threat-model.md` section 6 lists what this design does not do, and it is current rather than
aspirational. A sample, so you know what you are walking into:

- Nothing in this code fetches vendor platform-health data, so a genuinely signed but since-revoked
  platform still verifies. Checking freshness needs network access and is deliberately outside the
  offline path. A convenience feed of that data was decided on 21 September 2026 and is described in
  `README.md`; nothing of it runs today, and it changes nothing about what you are reporting.
- A composite `snp+gpucc` or `tdx+gpucc` label does not prove the attesting GPU is the card attached
  to the attesting VM. That needs TDISP/TEE-IO and no deployment here has it.
- The deployment manifest is unsigned. Strict-mode pinning is what gives it weight today.
- In `receipt` mode a receipt's key resolves through the manifest the deployment itself serves; only
  `strict` mode pins keys, issuers, instances and measurements.
- The eight-byte tag at the front of a receipt id links receipts minted by one credential to each
  other, and that link survives erasing the access log.

A report that restates one of these is not wrong, it is already known, and the answer is most likely
a link to the row. Reading that section first saves us both the exchange. What is worth the mail is
something the section does not cover: a way past a check the code does make, rather than a check it
never claimed to make.
