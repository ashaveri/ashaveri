# Configured values

Every value a deployment can point this gateway at, and every value the code holds when the
deployment named nothing. Three tables sort them by class, and the counts below are the counts the
tables carry: 28 flag rows, 12 shipped defaults, and 8 environment variables, of which 7 are
settings and 1 carries credential material. 3 flags name their default in the block that declares
them. Coverage is the gateway's operator surface only: the values a client verifies against, pinned
in `packages/sdk/src/policy.ts`, and the record constants in `packages/cli/src/records.ts` are out
of scope here and belong to whichever document needs them next.
[access-control.md](access-control.md) holds the pipeline these values configure, and
[threat-model.md](threat-model.md) holds what each of them is trusted to protect.

The three classes:

- **shipped default**, public source, and the value a process runs when the operator named nothing.
- **the operator's to declare**, a value belonging to the deployment, which this repository bounds,
  reports or reads, and never chooses.
- **never in a commit or a log**, material that is a credential, named here by its shape and never
  by its value.

A default spelled in capitals inside backticks names a constant the second table carries, or an
environment variable the third does. A default spelled in backticks without capitals is a literal the
code holds in a defaulting position. A default in plain prose has no single value in source to point
at, because the code reaches it through a refusal or through another module. `gateway/test/configured-values.test.ts`
reads these tables against the source and the container files, so a row that stops being true fails a
run rather than aging quietly.

## 1. Flags this gateway accepts

Class: the operator's to declare. All 28 are declared together in `gateway/src/cli.ts`, in the block
`parseArgs` is handed, and are spelled here as an operator types them, with the leading dashes. The
Bound column is what the code refuses outside; where a period or a duty is the deployment's own, the
row says so rather than inventing a number for it.

| Flag | What it governs | Bound or shape | Default this process runs | Class | Declared in |
|---|---|---|---|---|---|
| `--mock` | Deterministic completions, an ephemeral dev signing key and no TEE | boolean, and exactly one of the two mode flags | none: a run naming neither mode is refused | the operator's to declare | `gateway/src/cli.ts` |
| `--live` | The signing key and every measurement, from the dStack guest agent in this CVM | boolean, and exactly one of the two mode flags | none: a run naming both modes is refused | the operator's to declare | `gateway/src/cli.ts` |
| `--host` | The address the process binds | an address the platform will bind | `127.0.0.1` | the operator's to declare | `gateway/src/cli.ts` |
| `--port` | The port the process binds | a whole number from 0 to 65535, where 0 leaves the choice to the operating system and the start-up report names the number it chose | `7173` | the operator's to declare | `gateway/src/cli.ts` |
| `--help` | The usage text, then nothing else | boolean | none: the usage text is printed and the process exits 0 | the operator's to declare | `gateway/src/cli.ts` |
| `--public-url` | The origin clients refetch the evidence behind each receipt from | an absolute URL | none: a live run without it is refused | the operator's to declare | `gateway/src/cli.ts` |
| `--model` | The served model ids, one per occurrence | one or more ids, each checked against what the upstream reports | none: a live run naming no model is refused | the operator's to declare | `gateway/src/cli.ts` |
| `--weights-manifest` | The file whose digest every receipt for a model carries | a readable file, hashed once at start-up | none: a live run without it is refused | the operator's to declare | `gateway/src/cli.ts` |
| `--upstream` | The OpenAI-compatible root this gateway proxies completions to | a URL this process can reach | the mock backend, so completions are answered here rather than fetched | the operator's to declare | `gateway/src/cli.ts` |
| `--guest-socket` | The guest agent socket, or an http endpoint for the dStack simulator | a path or an http URL | `DSTACK_SIMULATOR_ENDPOINT`, then the first standard guest path that exists | the operator's to declare | `gateway/src/cli.ts` |
| `--key-path` | The guest key path that signs receipts | a path the guest agent will derive a key from | `/ashaveri/receipt` | the operator's to declare | `gateway/src/cli.ts` |
| `--key-purpose` | The purpose string mixed into the derived key | a string, and this deployment's to match against what it designated | the empty purpose | the operator's to declare | `gateway/src/cli.ts` |
| `--manifest-key-path` | A second guest key path, which signs the deployment manifest | a path, and a different one from the receipt key's, because one key cannot sign both | none: the manifest is served as plain JSON, which a client can only report as unauthenticated | the operator's to declare | `gateway/src/cli.ts` |
| `--manifest-key-purpose` | The purpose string mixed into the manifest key | a string, and this deployment's to match against what it designated | the empty purpose | the operator's to declare | `gateway/src/cli.ts` |
| `--epk` | The epoch of the signing key, published in the manifest | a non-negative whole number | `0` | the operator's to declare | `gateway/src/cli.ts` |
| `--issuer` | The issuer a receipt names | a string | none: the issuer the event log derives is used | the operator's to declare | `gateway/src/cli.ts` |
| `--instance` | The instance id a receipt names | a string | none: the instance the event log derives is used | the operator's to declare | `gateway/src/cli.ts` |
| `--tee` | The environment the evidence has to agree with | one of the hardware kinds the receipt package's measurement table names, where a composite kind also asks for a device report | none: no agreement is demanded beyond what the guest reports | the operator's to declare | `gateway/src/cli.ts` |
| `--marking` | What every completion this process serves is marked with | one of the scheme registry's labels, and a response whose shape cannot carry a mark is refused rather than served unmarked | `none` | the operator's to declare | `gateway/src/cli.ts` |
| `--receipts-dir` | Where issued receipts are kept across restarts, chained so a removal shows | an existing directory, so a volume you forgot to mount is a refusal | none: receipts are kept in this process only and are gone on restart | the operator's to declare | `gateway/src/cli.ts` |
| `--receipts-keep` | The durability bound: how many receipts the volume keeps | a positive whole number, and the store compares it against the period and the traffic on its own file | `SHIPPED_RETAINED_RECEIPTS`, which is a capacity decision of this deployment and not a period anyone owes | the operator's to declare | `gateway/src/cli.ts` |
| `--receipts-per-query` | The serving bound: how many receipts one range query holds at once | a positive whole number, bounding a walk and retiring nothing | `SHIPPED_SERVED_RECEIPTS`, and a walk over a longer window is answered in batches | the operator's to declare | `gateway/src/cli.ts` |
| `--credentials-path` | The records every request has to present one from | a readable file of public keys and hashes, which is why mounting it through a platform is safe in a way a secret file never is | none: required in live mode, and a mock run makes one dev credential and prints it | the operator's to declare | `gateway/src/cli.ts` |
| `--access-log-path` | Where the per-request access log is written | an existing directory, so a volume you forgot to mount is a refusal | none: required in live mode, and a mock run keeps the log in memory | the operator's to declare | `gateway/src/cli.ts` |
| `--access-log-days` | How long access log files are kept | a positive whole number of days; shorter than the default is allowed and the start-up report says so; the period a deployment owes is its own to declare and nothing in this repository validates it | `MINIMUM_RETENTION_DAYS` | the operator's to declare | `gateway/src/cli.ts` |
| `--allow-bearer` | Whether bearer credentials are accepted beside proof of possession | boolean, and never per credential | none: off, which is the posture that keeps a stolen credential detectable | the operator's to declare | `gateway/src/cli.ts` |
| `--pop-tolerance` | The clock slack accepted for a proof-of-possession timestamp | a positive whole number of seconds | `POP_TIMESTAMP_TOLERANCE_SECONDS` | the operator's to declare | `gateway/src/cli.ts` |
| `--peer-rate` | What one connection address may ask for, ahead of every credential check | `perMinute` and `burst`, both positive whole numbers, both required, and no spelling turns the bound off | `DEFAULT_PEER_RATE` | the operator's to declare | `gateway/src/cli.ts` |

## 2. Shipped defaults named in source

Class: shipped default. Each row is a constant this repository declares and reads in a defaulting
position, which is where the fallback lives: the left of a `??`, a parameter's own default, or the
fallback slot of the CLI's whole-number reader. The Value column is the source's own spelling, so a
change to it is a change here too.

| Name | Value as source | What it governs | Class | Declared in |
|---|---|---|---|---|
| `DEFAULT_MARKING` | `'none'` | The marking a gateway build serves when the run named none | shipped default | `gateway/src/server.ts` |
| `POP_TIMESTAMP_TOLERANCE_SECONDS` | `120` | The clock slack a proof-of-possession timestamp is trusted within | shipped default | `packages/receipt/src/pop.ts` |
| `DEFAULT_PEER_RATE` | `{ perMinute: 6000, burst: 2000 }` | What one connection address is held to before its header is read | shipped default | `gateway/src/access.ts` |
| `DEFAULT_RATE` | `{ perMinute: 60, burst: 120 }` | What a credential record carrying no rate of its own is held to | shipped default | `gateway/src/access.ts` |
| `REPLAY_WINDOW_SECONDS` | `900` | How long a credential and nonce pair is remembered as spent | shipped default | `gateway/src/access.ts` |
| `REPLAY_MAX_ENTRIES` | `65_536` | How many spent pairs are remembered at once | shipped default | `gateway/src/access.ts` |
| `MINIMUM_RETENTION_DAYS` | `184` | How long access log files are kept when no flag named a number | shipped default | `gateway/src/aclog.ts` |
| `MAX_ACCESS_FILE_BYTES` | `32 * 1024 * 1024` | The size one access log file reaches before the next day's part opens | shipped default | `gateway/src/aclog.ts` |
| `DEFAULT_TIMEOUT_MS` | `30_000` | How long a guest agent call waits before the request behind it fails | shipped default | `gateway/src/guest.ts` |
| `DEFAULT_MOCK_MODEL` | `'mock-model-1'` | The model id a mock completion is answered with when none was named | shipped default | `gateway/src/mock.ts` |
| `SHIPPED_RETAINED_RECEIPTS` | `10_000` | The durability bound a receipt volume is opened with when no flag named one | shipped default | `gateway/src/cli.ts` |
| `SHIPPED_SERVED_RECEIPTS` | `10_000` | The serving bound a query is walked with when no flag named one | shipped default | `gateway/src/cli.ts` |

Bounds shipped in the same source, and holding whatever the operator named, are not fallbacks and so
are not rows above: `MAX_CREDENTIALS`, `MAX_TRACKED_PEERS`, `MAX_BUFFERED_BODY`,
`MAX_CACHED_EVIDENCE`, `MAX_REPORT_DATA_BYTES`, `FIRST_EVENT_TIMEOUT_MS` and
`MINIMUM_RETENTION_SECONDS` each bound one behaviour, no flag reaches any of them, and the receipt
store's period is the last of those rather than a duration a deployment chooses per run.

## 3. Environment settings the operator declares

Class: the operator's to declare. These are read from the process environment rather than from a
flag, and the Declared column names the file that reads or substitutes them.

| Variable | What it governs | Shape | Class | Declared in |
|---|---|---|---|---|
| `ASHAVERI_PUBLIC_URL` | The origin the container advertises, and so the one receipts point a client back to | required, and an https URL a client can reach | the operator's to declare | `enclave/docker-compose.yaml` |
| `ASHAVERI_TEE` | The environment the container starts expecting | one of the platform's TEE kinds | the operator's to declare | `enclave/docker-compose.yaml` |
| `ASHAVERI_WEIGHTS_DIR` | The directory the entrypoint verifies against the manifest before the gateway starts | a directory the manifest's files are read from | the operator's to declare | `enclave/docker-compose.yaml` |
| `ASHAVERI_WEIGHTS_MANIFEST` | The manifest those weights are checked against | a file inside that directory | the operator's to declare | `enclave/docker-compose.yaml` |
| `DSTACK_SIMULATOR_ENDPOINT` | The guest endpoint a development run talks to instead of a real guest agent | a path or an http URL, and a real CVM ignores it | the operator's to declare | `gateway/src/guest.ts` |
| `ASHAVERI_CREDENTIAL_ID` | Which credential a client signs with | a credential name, and public | the operator's to declare | `packages/sdk/src/auth.ts` |
| `ASHAVERI_CREDENTIAL_KIND` | Whether that credential is proved by possession or presented as a bearer token | `pop` or `bearer`, and `pop` when unset | the operator's to declare | `packages/sdk/src/auth.ts` |

## 4. The one value that is credential material

Class: never in a commit or a log. It is listed with the rest because the shipped code reads it, and
its value is the only thing here that a reader must never write down: it is a signing key, so a
record that names its holder proves nothing once the key is in a repository, a log line or an image.

| Variable | What it governs | Shape | Class | Declared in |
|---|---|---|---|---|
| `ASHAVERI_CREDENTIAL_SECRET` | The key a client signs each request with | 64 hex digits for a proof-of-possession credential, and never printed | never in a commit or a log | `packages/sdk/src/auth.ts` |
