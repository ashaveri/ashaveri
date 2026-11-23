# Configured values

Every value a deployment can point this gateway at, and every value the code holds when the
deployment named nothing. Three tables sort them by class, and the counts below are the counts the
tables carry: 36 flag rows, 21 shipped defaults, and 11 environment variables, of which 10 are
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

A default spelled in capitals inside backticks names a constant or an environment variable one of the
tables below carries. A default spelled in backticks without capitals is a literal the code holds in a
defaulting position. A default in plain prose has no single value in source to point at, because the
code reaches it through a refusal or through another module.
`gateway/test/configured-values.test.ts` reads these tables against the source and the container
files, so a row that stops being true fails a run rather than aging quietly.

## 1. Flags this gateway accepts

Class: the operator's to declare. All 36 are declared together in `gateway/src/cli.ts`, in the block
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
| `--model` | The served model ids, one per occurrence | one or more ids, each checked against what the upstream reports | none: a live run naming no model is refused, and a mock run naming none serves the synthetic id it ships with, while a mock run naming a model and giving no weights file is refused because its receipts would carry a digest no route answers | the operator's to declare | `gateway/src/cli.ts` |
| `--weights-manifest` | The file whose digest every receipt for a model carries | a readable file, read and hashed once per run; where the container sets both weights environment values, the same file `ASHAVERI_WEIGHTS_MANIFEST` names, so the manifest the entrypoint checks those files against is the manifest a receipt's digest covers; a mock run reads its flag and neither environment value, since it verified no boot files | none: a live run without it is refused, and an environment manifest without it is refused before the gateway starts; a mock run without it publishes no document behind its digests, so its weights route answers 404 for the synthetic ones, and a mock run given the file with no model named is refused | the operator's to declare | `gateway/src/cli.ts` |
| `--upstream` | The OpenAI-compatible root this gateway proxies completions to | a URL this process can reach | the mock backend, so completions are answered here rather than fetched | the operator's to declare | `gateway/src/cli.ts` |
| `--guest-socket` | The guest agent socket, or an http endpoint for the dStack simulator | a path or an http URL | `DSTACK_SIMULATOR_ENDPOINT`, then the first standard guest path that exists | the operator's to declare | `gateway/src/cli.ts` |
| `--key-path` | The guest key path that signs receipts | a path the guest agent will derive a key from | `/ashaveri/receipt` | the operator's to declare | `gateway/src/cli.ts` |
| `--key-purpose` | The purpose string mixed into the derived key | a string, and this deployment's to match against what it designated | the empty purpose | the operator's to declare | `gateway/src/cli.ts` |
| `--manifest-key-path` | A second guest key path, which signs the deployment manifest | a path, and a different one from the receipt key's, because one key cannot sign both; a live run that has recorded more than one signing epoch is refused at start without it, because the history its manifest would publish states which keys were retired and signs nothing | none: the manifest is served as plain JSON, which a client can only report as unauthenticated | the operator's to declare | `gateway/src/cli.ts` |
| `--manifest-key-purpose` | The purpose string mixed into the manifest key | a string, and this deployment's to match against what it designated | the empty purpose | the operator's to declare | `gateway/src/cli.ts` |
| `--epk` | The epoch of the signing key, published in the manifest and recorded in the journal as the entry this process serves under | a non-negative whole number; a new key beside a higher number here is a rotation, and the entry it writes opens at the instant that run first serves, so a number moved without a new key states a rotation that did not happen | `0` | the operator's to declare | `gateway/src/cli.ts` |
| `--issuer` | The issuer a receipt names | a string | none: a live run uses the issuer the event log derives and a mock run uses `ashaveri-mock` | the operator's to declare | `gateway/src/cli.ts` |
| `--instance` | The instance id a receipt names | a string | none: a live run uses the instance the event log derives and a mock run uses `mock-instance-1` | the operator's to declare | `gateway/src/cli.ts` |
| `--tee` | The environment the evidence has to agree with | one of the hardware kinds the receipt package's measurement table names, where a composite kind also asks for a device report | none: no agreement is demanded beyond what the guest reports | the operator's to declare | `gateway/src/cli.ts` |
| `--marking` | What every completion this process serves is marked with | one of the scheme registry's labels, and a response whose shape cannot carry a mark is refused rather than served unmarked | `none` | the operator's to declare | `gateway/src/cli.ts` |
| `--receipts-dir` | Where issued receipts are kept across restarts, chained so a removal shows, and where a live run keeps the journal of its own signing epochs beside them | an existing directory, so a volume you forgot to mount is a refusal | none: receipts are kept in this process only and are gone on restart, and with no volume to keep it on no epoch is recorded, so the manifest publishes the one key this process stands on | the operator's to declare | `gateway/src/cli.ts` |
| `--receipts-keep` | The durability bound: how many receipts the volume keeps | a positive whole number no wider than 4294967295, which is the widest a trim record files a bound in and a count above it stops the start rather than being filed as that ceiling, and the store compares it against the period and the traffic on its own file | `SHIPPED_RETAINED_RECEIPTS`, which is a capacity decision of this deployment and not a period anyone owes | the operator's to declare | `gateway/src/cli.ts` |
| `--receipts-days` | The age bound: how long the receipts store keeps a receipt before it ages out | a positive whole number of days, at most 49710 of them because the store files the resulting period in a 4 byte field; shorter than the default is allowed and the start-up report says so; where an instruction record states a longer period this run is refused at start, because the period that record states is the window this software enforces; the period a deployment owes is its own to declare and nothing in this repository validates it; what this window ages is receipts and nothing else, so the epoch journal kept in the same directory is not retired with them and outlives every record whose epoch it states | `MINIMUM_RETENTION_DAYS`, the same number the access log's window falls back on, so a deployment that names neither keeps what it kept before this flag | the operator's to declare | `gateway/src/cli.ts` |
| `--receipts-per-query` | The serving bound: how many receipts one range query holds at once | a positive whole number, bounding a walk and retiring nothing | `SHIPPED_SERVED_RECEIPTS`, and a walk over a longer window is answered in batches | the operator's to declare | `gateway/src/cli.ts` |
| `--receipts-guard-at` | When the durability guard is read while serving, rather than only when the store opens | a whole percentage from 1 to 100 of the durability bound, where a value that is not one stops the start rather than falling back; once the store holds that share of `--receipts-keep`, a completion is refused with `RECEIPT_WINDOW_UNHOLDABLE` before any inference runs if the period configured beside the bound cannot be held at the rate the store's own retained stamps measure; the share sets only the point from which the guard starts reading, and the shortfall it states is measured against `--receipts-keep` itself rather than against that point, so lowering the percentage is the way to have the guard answer before the retained set ever reaches the bound | `DEFAULT_INTAKE_GUARD_FRACTION`, which is the whole of the durability bound, so a run naming no percentage weighs the one pairing the store's own opening weighs by the same arithmetic: a file store whose retained set stands at or past that bound and spans less than the period configured beside it is refused when it opens rather than served, and a serving refusal reaches such a volume only once it grew into the pairing after an opening that held; the guard answers while serving on its own where the percentage is lowered below the bound, and where the in-process store is what stands at the pairing, since that engine opens no file and meets no opening refusal | the operator's to declare | `gateway/src/cli.ts` |
| `--receipts-grow-past-guard` | Keep issuing past the durability guard instead of refusing | boolean, it takes no argument, and it overrides `--receipts-guard-at`; with it the volume grows, the bound keeps retiring the oldest prefix, and the window served is the shorter one that bound reaches rather than the period configured beside it | none: off, which is the posture that leaves a receipt the configured period still covers in the file | the operator's to declare | `gateway/src/cli.ts` |
| `--receipts-record-kind` | Which kind of receipt record this process appends | `receipt`, or `bounded=<seconds>`, where the seconds are the retention period written at the front of every record this run appends; a spelling that names neither kind stops the start rather than falling back, and a volume whose records were written under the other kind is refused by `STORE_RECEIPT_KIND_MISMATCH` rather than converted. What the period itself may say is the store's rule and not this one: `RECORD_BOUND_OUT_OF_RANGE` for a number its 4 byte field cannot state, `RECORD_BOUND_REDUNDANT` for one its own durability window reaches first | `DEFAULT_RECEIPT_RECORD_KIND`, which is the receipt kind stating no period and the layout every store file this repository has published is made of | the operator's to declare | `gateway/src/cli.ts` |
| `--credentials-path` | The records every request that asks for a credential has to present one from | a readable file of public keys and hashes, which is why mounting it through a platform is safe in a way a secret file never is | none: required in live mode, and a mock run makes one dev credential and prints it | the operator's to declare | `gateway/src/cli.ts` |
| `--access-log-path` | Where the per-request access log is written | an existing directory, so a volume you forgot to mount is a refusal | none: required in live mode, and a mock run keeps the log in memory | the operator's to declare | `gateway/src/cli.ts` |
| `--access-log-days` | How long access log files are kept | a positive whole number of days; shorter than the default is allowed and the start-up report says so; where an instruction record states a longer period this run is refused at start, because the period that record states is the window this software enforces; the period a deployment owes is its own to declare and nothing in this repository validates it | `MINIMUM_RETENTION_DAYS` | the operator's to declare | `gateway/src/cli.ts` |
| `--instruction-record` | The file this deployment's own statement of its duty period is read from: the period it states it owes, and whether it takes the 184-day floor as a duty of its own | a readable file holding one JSON object of exactly three members, `version`, `statedRetentionDays` and `acceptsMinimumFloor`; a member beside those three, a `version` other than `INSTRUCTION_RECORD_VERSION`, a period that is not a whole number of days at least one, or a named file that is not there stops the start rather than being read past; a window shorter than the stated period stops the start naming both numbers and where each came from; a record that accepts the floor and states less than it stops the start on its own account | `DEFAULT_INSTRUCTION_RECORD_PATH`, which is one file in the directory the process starts in, and no file there is no instruction: the run then keeps the number `MINIMUM_RETENTION_DAYS` gives or the days flag names, and the start-up report says no record was read | the operator's to declare | `gateway/src/cli.ts` |
| `--hold-record` | The instruction to preserve that the receipts store and the access log are told to consult | a readable file holding one hold record of a version this package reads, repeatable, and a path named twice is read once; a named file that cannot be read, or whose bytes are not such a record, stops the start naming the path and the reason; every record read is reported at start-up with the sha256 of its bytes, the window it states and its state; the window suspends retirement for the stamps it covers and the access log days it overlaps while the hold is in force, and moves no configured window, no stated period and no refusal | none: a run naming no hold record reads none, and each reader ages exactly what it aged before this flag | the operator's to declare | `gateway/src/cli.ts` |
| `--time-source-state` | The state file every stamp this process signs is read from, which the operator's own clock synchronisation maintains, instead of this host's clock | a readable file holding one JSON object of exactly four members, `version`, `source`, `uncertaintySeconds` and `measuredAtSeconds`, read on a timer and served from memory between reads. The document states the source's name and the bound on how far its readings can stand from the instants they name, and no flag states either, because the writer is the thing that knows: the name and the bound travel into every payload's `sd` exactly as the file states them, and a number typed at a shell beside them would be a second claim about one clock. The reader re-reads on an interval derived from the bound the document states, floored at `MIN_TIME_SOURCE_STATE_REFRESH_SECONDS` and capped at `MAX_TIME_SOURCE_STATE_REFRESH_SECONDS`, and between reads advances the instant on a monotonic clock, so a host clock step moves no stamp and no stamp pays for a file read. A state whose instant sits further behind the instant this source stamps than its own bound plus twice that interval stops the run signing receipts and names the age, the bound and the file, while reads of receipts already filed go on answering. A file that is missing, unreadable, cut in the middle, stating a member this reader has no name for, stating a version this gateway does not read, or stating an instant outside `TIME_SOURCE_STATE_PLAUSIBILITY_BAND_SECONDS` of the host's own claim at the start stops the run rather than falling back | none: a run naming no state file reads `HOST_CLOCK_SOURCE`, this host's own claim at the uncertainty nobody measured | the operator's to declare | `gateway/src/cli.ts` |
| `--allow-bearer` | Whether bearer credentials are accepted beside proof of possession | boolean, and never per credential | none: off, which is the posture that keeps a stolen credential detectable | the operator's to declare | `gateway/src/cli.ts` |
| `--pop-tolerance` | The clock slack accepted for a proof-of-possession timestamp | a positive whole number of seconds | `POP_TIMESTAMP_TOLERANCE_SECONDS` | the operator's to declare | `gateway/src/cli.ts` |
| `--peer-rate` | What one connection address may ask for, ahead of every credential check | `perMinute` and `burst`, both positive whole numbers, both required, and no spelling turns the bound off | `DEFAULT_PEER_RATE` | the operator's to declare | `gateway/src/cli.ts` |
| `--completion-rate` | What one process may admit completions, ahead of any inference and behind every credential check | `perMinute` and `burst`, both positive whole numbers, both required, and no spelling turns the bound off. The same two fields as `--peer-rate`, in the same unit, so an operator reads one against the other: this is what a process can write, that is what one address can ask | `DEFAULT_COMPLETION_RATE` | the operator's to declare | `gateway/src/cli.ts` |

Where a row names a file this deployment wrote, its Bound cell states one rule, and the rule is the
named-by-operator one: the operator named that file, so a file that cannot be read, or whose bytes are not
the document the reader reads, stops the start and names which path and for what reason, and a run that names
no such flag reads no file at the path that flag would have named and keeps every behaviour it had before the
flag existed. Reading past a named file would enforce a period, a source, or a preservation instruction nobody
wrote down, which is why the refusal is the whole answer rather than a line beside a banner. That last half
speaks of the path a flag names, and one row above reads a file no operator named: `--instruction-record`
falls back to `DEFAULT_INSTRUCTION_RECORD_PATH`, and a file sitting there that cannot be read stops the start
the same way, because "there is no statement" and "the statement is unreadable" are two different answers
about one duty period. `--hold-record` names no default, so a run that types it nowhere opens no hold file at
all.

`--hold-record` is read under exactly that rule, with one difference: it is repeated, one file per distinct
path, because a deployment can have two matters under hold at once and a reader that stopped at the first
record no longer in force would retire material the second still covers. Each path is read once, whatever the
number of times that exact text was typed, at start-up, before any store or log opens, and the report prints one
line per record with the sha256 of the bytes that came back from it, the window it states and its state at that
instant; the note a window judgement prints beside those bytes carries the same digest. What a hold does with
them is suspend retirement in the readers that consult it, and nothing else: no window, stated period,
durability figure or retention-manifest
number in these tables moves, and a pairing that `--receipts-days` or `--access-log-days` refused is refused
beside an active hold with the identical sentence. The doors a hold reaches, and what each keeps, are section
8.2 of [access-control.md](access-control.md).

The two receipt bounds are counts, and each has a measured cost beside it on this store's compiled output. The
baseline is part of every number below: one Windows host, one Node 24 process, calls issued serially, nothing
else on the volume, and frames of 191 bytes carrying a 48-character minted id and a 64-byte payload, which is a
synthetic record rather than a signed receipt. With retention configured an append costs 1.326 ms against
20,000 receipts retained and 1.947 ms against 100,200, so the size of the set `--receipts-keep` bounds is not
what an append's cost is a function of. A served walk reads 5.11 us per record over 20,000 records, and
`--receipts-per-query` decides how many records one batch of that walk carries. With thirty-two callers in
flight inside that one process the store answers 18,867 appends a second at a 1.54 ms median, so at concurrency
the ceiling sits on what the volume can hold and on the walk over its bytes rather than on the write path. Each
figure is one host's measurement at one narrow frame width; [receipt-spec.md](receipt-spec.md) section 5.2
carries the whole set beside the two trees it compares.

## 2. Shipped defaults named in source

Class: shipped default. Each row is a constant this repository declares and reads in a defaulting
position, which is where the fallback lives: the right of a `??`, a parameter's own default, or the
fallback slot of the CLI's whole-number reader. The Value column is the source's own spelling, so a
change to it is a change here too.

| Name | Value as source | What it governs | Class | Declared in |
|---|---|---|---|---|
| `DEFAULT_MARKING` | `'none'` | The marking a gateway build serves when the run named none | shipped default | `gateway/src/server.ts` |
| `DEFAULT_INTAKE_GUARD_FRACTION` | `1` | The share of the durability bound a completion is refused at when the run named no percentage | shipped default | `gateway/src/server.ts` |
| `POP_TIMESTAMP_TOLERANCE_SECONDS` | `120` | The clock slack a proof-of-possession timestamp is trusted within | shipped default | `packages/receipt/src/pop.ts` |
| `DEFAULT_PEER_RATE` | `{ perMinute: 6000, burst: 2000 }` | What one connection address is held to before its header is read | shipped default | `gateway/src/access.ts` |
| `DEFAULT_COMPLETION_RATE` | `{ perMinute: 50_220, burst: 837 }` | What one process is held to on the completions it admits, taken ahead of the upstream call and behind every credential check: one throughput this build measures on its own completion path, 837 completions a second at 32 callers in flight with the other two buckets lifted, so 50,220 a minute with 837 at once, stated as a rate so it reads against `DEFAULT_PEER_RATE` above it. A bound and not a sentinel: a deployment that names nothing is refused at the ceiling rather than serving past it | shipped default | `gateway/src/server.ts` |
| `DEFAULT_RATE` | `{ perMinute: 60, burst: 120 }` | What a credential record carrying no rate of its own is held to | shipped default | `gateway/src/access.ts` |
| `REPLAY_WINDOW_SECONDS` | `900` | How long a credential and nonce pair is remembered as spent | shipped default | `gateway/src/access.ts` |
| `REPLAY_MAX_ENTRIES` | `65_536` | How many spent pairs are remembered at once | shipped default | `gateway/src/access.ts` |
| `MINIMUM_RETENTION_DAYS` | `184` | How long access log files are kept when `--access-log-days` named no number, and the same 184 days the receipts store ages by when `--receipts-days` named no number: one shipped default reaching both windows, and in each case a number a run weighs against the period a deployment states in its own instruction record rather than a minimum it enforces | shipped default | `gateway/src/aclog.ts` |
| `DEFAULT_INSTRUCTION_RECORD_PATH` | `'ashaveri-instruction-record.json'` | The file a run reads when the operator named no `--instruction-record`: one file in the directory the process starts in, reaching no other directory by itself. A deployment that keeps its statement elsewhere names it with the flag; a deployment that keeps none reads none, which is the state every deployment was already in, and the window then comes from the days flag or from `MINIMUM_RETENTION_DAYS` | shipped default | `gateway/src/instruction-record.ts` |
| `MAX_ACCESS_FILE_BYTES` | `32 * 1024 * 1024` | The size one access log file reaches before the next day's part opens | shipped default | `gateway/src/aclog.ts` |
| `DEFAULT_REQUEST_BODY_LIMIT_BYTES` | `128 * 1024 * 1024` | The largest request body this process reads, in bytes, for a run that stated no other: 128 MiB. A body past it is refused 413 `BODY_TOO_LARGE` in the shape the route gives its own refusals, ahead of the pipeline, so nothing is forwarded to the upstream and no receipt is issued for bytes this gateway would not hold. The figure was 16 MiB, and that default was the reason a customer's own payload could be refused by this gateway rather than by the inference server they chose, because a body past this bound never reaches that server: the standing condition the number is held to is that a gateway must not be the tightest constraint on a request it serves. What the raise costs in bytes held at once is a second question, and the row below it carries its answer. What the raise does not move is the bound on one answer coming back, and the last paragraph of this section states that pairing beside `MAX_BUFFERED_BODY` itself | shipped default | `gateway/src/server.ts` |
| `DEFAULT_REQUEST_BODY_BUDGET_BYTES` | `384 * 1024 * 1024` | The request-body bytes one process will hold at once, summed across the requests in flight, for a run that stated no other: 384 MiB. Where the row above bounds one body, this bounds how many of them are resident together, and it exists because a body stays held for the whole life of its completion, since the receipt signs those bytes and the upstream is forwarded them, so a deployment that raised the one without stating the other would size its memory against its busiest minute rather than against a number it chose. A caller is admitted while the bytes already resident plus its own stay within the budget; past it the request is refused 429 `RESIDENT_BODY_BUDGET_EXCEEDED` at the reader, ahead of every credential check, with a `retry-after` that is a floor rather than a refill time, and the message names the budget, what was resident at the instant the refusal was decided, what this request asked for, and which of the two arms decided it. Nothing of that request is forwarded to the upstream and no receipt is issued for it. `ASHAVERI_REQUEST_BODY_BUDGET_BYTES` or the `requestBodyBudgetBytes` option of `buildGateway` states another, and no spelling turns the budget off: a large number is how a deployment says it does not want one, because the bound is what makes the raised body limit above it safe to serve. The shipped figure is arithmetic on a measured multiple and on the memory a deployment is given, and not a measurement of the traffic a deployment will see: a process holding a budget peaks at 2.05 times the budget plus the 98 MiB the process costs before a byte arrives, both read inside `node:26-slim` at `v26.13.1` at 128 MiB bodies, so a container of `L` MiB clears its budget when `2.05 x budget + 98 <= L` and the budget an operator states is at most `(L - 98) / 2.05`, rounded down to whole bodies of the width above because a budget that could not hold one admitted body would bound nothing. At the 1 GiB this default is derived for that is 451.7 MiB and three bodies, 384 MiB; at 1.5 GiB it is 701.5 MiB and five bodies, 640 MiB; at 2 GiB it is 951.2 MiB and seven bodies, 896 MiB. Read against the worst multiple measured, 2.12 rather than 2.05, the 1 GiB division is 436.8 MiB and still three bodies, so the shipped number does not turn on which reading of the multiple is taken. What a request admitted under this budget can still be refused for on the way back is `MAX_BUFFERED_BODY`, 32 MiB, and the last paragraph of this section states that pairing | shipped default | `gateway/src/server.ts` |
| `DEFAULT_REQUEST_BODY_DRAIN_TIMEOUT_MS` | `60_000` | How long this process keeps reading the part of a request body it has already refused, in milliseconds, before it writes the refusal anyway and ends the connection. Both bounds on the caller's bytes are decided as those bytes arrive, so a refusal is usually decided while the caller is still writing, and the rest of that upload is then read and dropped rather than held: the answer a refused caller can name is owed after the body ends, and a caller that stops sending would otherwise leave it owed for ever. The shipped figure is the whole of the widest admitted body over a 20 Mbit/s uplink, which is 53.7 s of arithmetic on 128 MiB and therefore a bound a progressing upload does not trip. It sits far above what the drain itself costs: the same 128 MiB arriving over loopback on one host took 155.6 ms, 163.0 ms and 182.8 ms in three runs (`v26.13.0`, `win32 x64`, a read-and-discard socket with no gateway in the measurement). And it is a bound where there was none, read beside what the socket layer of a build of this shape answers when asked: `server.timeout` 0, `server.requestTimeout` 0, `server.headersTimeout` 60000 ms and `server.keepAliveTimeout` 72000 ms, so nothing in the platform bounded how long an arriving body might take before this row existed. What running past it costs is one file descriptor and no part of the budget, because a drained datum is never charged, which is why the figure can afford to be generous: the refusal is decided ahead of every bucket, so no rate this process holds bounds how many waiting callers are open at once, and the number it does bound is the process's own descriptors. When it expires the answer is written before the socket goes, which is the whole of the reason to write it at all. `ASHAVERI_REQUEST_BODY_DRAIN_TIMEOUT_MS` or the `requestBodyDrainTimeoutMs` option of `buildGateway` states another for a deployment whose callers arrive more slowly or whose operator wants the sockets gone sooner, and no spelling turns the bound off | shipped default | `gateway/src/server.ts` |
| `DEFAULT_TIMEOUT_MS` | `30_000` | How long a guest agent call waits before the request behind it fails | shipped default | `gateway/src/guest.ts` |
| `DEFAULT_MOCK_MODEL` | `'mock-model-1'` | The model id a mock completion is answered with when none was named | shipped default | `gateway/src/mock.ts` |
| `SHIPPED_RETAINED_RECEIPTS` | `10_000` | The durability bound a receipt volume is opened with when no flag named one | shipped default | `gateway/src/cli.ts` |
| `SHIPPED_SERVED_RECEIPTS` | `10_000` | The serving bound a query is walked with when no flag named one | shipped default | `gateway/src/cli.ts` |
| `DEFAULT_RECEIPT_RECORD_KIND` | `{ kind: 'receipt' }` | Which kind of receipt record a store appends when the deployment named none: the layout that states no period, which is what every store file this repository has published is made of. The other kind puts a per-record retention period, `boundSeconds:u32`, ahead of the receipt bytes inside the digest the chain folds, and a store's log holds records of one kind or the other: a file holding both is refused at the opening by `STORE_RECEIPT_KIND_MISMATCH`, because "what does this deployment keep" would then depend on which record a reader picked up. The period a bounded record states is a statement about that record: retirement drops a prefix at the durability bound and the retention manifest reports that bound, so nothing in this repository reads a record's own period as a bound. `--receipts-record-kind` is the flag a run states the choice with | shipped default | `gateway/src/store.ts` |
| `EPOCH_JOURNAL_FILE` | `'epoch-journal.json'` | The file a deployment that named `--receipts-dir` keeps its signing history in, beside the receipt log it explains. One entry per epoch this gateway has served under, each stating the key that signed then, the first instant that key's window opened, and which source read that instant: a boot under an epoch the file already names writes nothing at all, so the history is what the deployment lived rather than what an operator typed. No window reaches it. `--receipts-days` ages receipts and leaves this file whole, and the access log's erasure does not touch it, because it is operational state about keys and holds no personal data: a journal retired before the receipts it explains would leave those records answering to no window, which is the failure this file exists to close. A document whose stated history does not match what the entries themselves say was recorded before it is refused on read and named, and nothing is written over it | shipped default | `gateway/src/epoch-journal.ts` |
| `HOST_CLOCK_SOURCE` | `{ name: 'host clock', uncertaintySeconds: null, nowSeconds: () => Math.floor(Date.now() / 1000) }` | The source every whole-second stamp this process signs is read from when the deployment wired none, and the bound nobody measured on it. This null is what the process states about itself, on the store through `timeSource()` and beside every record a range walk hands back, and no flag here hides it or widens it. **It is the fallback of a run that named nothing, and nothing else:** `--time-source-state` is the command-line route to a different source, a state file the operator's own clock synchronisation maintains, whose document states the name and the bound that then travel into every receipt instead of these; a run that names that file and cannot read it is refused rather than handed back to this constant, because `sd` is the artifact's promise about which source read the stamp. A caller of the library still substitutes a `TimeSource` through `buildGateway` or `openFileReceiptStore`, where the name and the bound travel with it. What a client makes of that answer is a client question and not a row of this inventory: the demand a policy may state of a stamp's source under `maxTimeUncertaintySeconds`, what that demand does to this null, and where a verifier can weigh it at all, are written once in [error-codes.md](error-codes.md); the field itself is a member of the client's policy document and of nothing this gateway reads | shipped default | `gateway/src/store.ts` |

Bounds shipped in the same source, and holding whatever the operator named, are not fallbacks and so
are not rows above: `MAX_CREDENTIALS`, `MAX_TRACKED_PEERS`, `MAX_BUFFERED_BODY`,
`MAX_CACHED_EVIDENCE`, `MAX_REPORT_DATA_BYTES`, `STREAM_USAGE_INJECTION_MAX_BYTES` and
`FIRST_EVENT_TIMEOUT_MS` each bound one behaviour that no flag reaches.
`MINIMUM_RETENTION_SECONDS` is the same kind of shipped number and the store
package's own age bound, 184 days stated in seconds: it is the window a run ages by when `--receipts-days`
names nothing, because that flag's default is the same 184 days held in whole days and converted to
seconds at `gateway/src/duty-window.ts`. The receipts period is therefore a duration a deployment chooses
per run, and this constant stays here rather than becoming a row above because the shipped code reads it in
no defaulting position. `SIDECAR_BLOCK_RECORDS` is a shipped bound of the same
kind and the checkpoint cadence: the count of records a sidecar block indexes, read by the store's append
and resume paths, and reached by no flag. The period a bounded record states is chosen per run, by
`--receipts-record-kind`, and it is a statement inside the record rather than a bound this process
enforces. The same posture holds for the four values the state-file route reads without an operator naming
any of them: `TIME_SOURCE_STATE_FILE_VERSION` is the only version of a state document this gateway reads,
`MIN_TIME_SOURCE_STATE_REFRESH_SECONDS` and `MAX_TIME_SOURCE_STATE_REFRESH_SECONDS` are the two ends of the
interval it re-reads on, which the bound the document states picks between, and
`TIME_SOURCE_STATE_PLAUSIBILITY_BAND_SECONDS` is the distance a document's instant may stand from the host's
own claim at the one moment the two are weighed against each other. `--time-source-state` names a path and
nothing else, so no flag reaches these four, and none of them is a bound anybody may set on a source: the
bound belongs to the document, and these are what the reader does with it.

One of the bounds above decides what a completion states about its own cost. A streamed request past
`STREAM_USAGE_INJECTION_MAX_BYTES` of wire, one mebibyte, is forwarded to the inference server as it
arrived, and this gateway asks for no usage figures, because the ask is a parse and a re-serialisation of
the caller's body held for the life of the completion and what it buys is a count. A request under it is
asked, as it always was, and a buffered request is never copied for the ask at any size, because its
figures ride in its body. What the large arm gives up is stated and not left to be inferred: `tok` is a
required map of two figures that are each an integer or an absence, the reader refuses a negative and refuses
a pair split between one count and one absence, so a completion whose figures were never obtained states two
absences where a stack that counted none would state two zeros, and the response carries
`x-ashaveri-metering: declined` beside them. The header names what this gateway did rather than what
arrived: an inference server that reports usage without being asked is still read, and the header still
says this gateway did not ask. It cannot say more than that, because the headers are written before the
body ends, and whether a figure an upstream was asked for arrives is not known until after they have.
Which figures a deployment would rather have, the copy or the count, is the reason the bound is a number
in the source rather than a rule in the prose.

Another of the bounds above stands on the answer rather than on the ask. `MAX_BUFFERED_BODY`, 32 MiB, is what
this process will hold of one buffered completion: a buffered answer is collected whole before a byte of it
reaches the client, because the digest a receipt signs and the item it stamps are cut out of those bytes, and
past the bound the answer is refused rather than held. The refusal is `RESPONSE_TOO_LARGE`, answered 413 with
the bound printed in its sentence, and it replaced an untyped error that the generic handler reported as a 502
upstream failure: a caller reading that answer had no number to act on and an operator read a broken
installation where what is short is a number this build ships. A streamed completion never meets this bound,
because its frames are forwarded and hashed as they arrive and nothing is collected, which is why what a
caller does at the bound is ask for the completion streamed, or for less of an answer, and not send fewer
bytes.

Those two bounds are read together, and the pairing is a rule a caller has to be able to find rather than infer
from two rows: a request of 128 MiB, the whole of `DEFAULT_REQUEST_BODY_LIMIT_BYTES`, is admitted on the ask side
and still meets `MAX_BUFFERED_BODY`, 32 MiB, on the answer side. Sending that much buys a larger request, not a
larger response, and the refusal that says so is `RESPONSE_TOO_LARGE`, answered 413 with the bound it passed
printed in its sentence, for either of the two answers this route collects: the completion it was about to sign,
and the upstream's own failure, whose body is collected on either arm so that it can be handed back as it arrived.
What a caller does at that pairing is ask for the completion streamed, which a bound of this kind never reaches, or
ask for less of an answer; sending fewer request bytes changes nothing, because the number that was passed is on
the bytes coming back. A streamed completion is bounded on the ask side instead, by `DEFAULT_REQUEST_BODY_LIMIT_BYTES`
for one body and by `DEFAULT_REQUEST_BODY_BUDGET_BYTES` for how many of them are resident at once, and those two
refusals are answered 413 and 429 before a byte of an answer exists rather than 413 after one has been paid for.

What this process gives back and what the allocator gives back are two different figures, and a container limit
reads the second. The readings below were taken inside `node:26-slim`, the same family of Debian slim base the
published image is built on, from a run of sixteen callers each uploading a 128 MiB body. Such a body is made of
two allocation classes: the concatenated copy is above the C library's mmap threshold, so it is its own mapping
and `munmap` returns it the moment the request dies, while the 64 KiB datums it arrived in come from the heap,
and a freed block there moves into the allocator's bins rather than back to the kernel. A reader that decides the
budget only after a whole body has arrived was left holding 2,113.7 MiB after a forced collect against 0.3 MiB of
bytes still reachable, the kernel listing 2,024.6 MiB of that as one `[heap]` mapping. A reader that charges as
the bytes arrive, which is what this gateway does, bounds how many datums exist at once and settled at 529.2 MiB
of heap on the same load. The retained figure therefore tracks the budget rather than the traffic, which is why
the derivation above sizes a deployment from the peak and not from what one request can be shown to hold.

Three settings were tried against that retention and one moved it. `MALLOC_MMAP_THRESHOLD_=65536` puts every
64 KiB datum above the threshold at which an allocation is its own mapping, so it is returned when it dies: the
same load settled at 133.2 MiB instead of 2,113.7 MiB, with the heap at 45.7 MiB. `MALLOC_ARENA_MAX=1`, the usual
container advice, changed nothing beyond 3 MiB, because Node's JavaScript runs on one thread and every datum was
already in the main arena; `MALLOC_TRIM_THRESHOLD_=0` beside `MALLOC_TOP_PAD_=0` changed nothing beyond 10 MiB,
because the heap shrinks only from its top and the freed blocks sit in bins below it. Two things about the setting
that did move it are unmeasured and are stated rather than smoothed over. It was read against the reader that
charges after arrival, so what it adds to a gateway that already bounds arrival is not known; and it turns every
datum into an `mmap` and a `munmap`, 2,048 pairs for a 128 MiB body, which was not timed. It is a knob for the
floor a settled process sits at, and the multiple the budget is derived from is the default allocator's peak, so
setting it moves no figure in the arithmetic above.

This variable is not a row in the tables, and the reason is a rule rather than an omission: a test holds those
tables to naming exactly the settings a shipped file reads or substitutes, and no shipped file reads or
substitutes `MALLOC_MMAP_THRESHOLD_`. The allocator reads it, and an operator states it in the container's
environment beside the variables section 3 names.

## 3. Environment settings the operator declares

Class: the operator's to declare. These are read from the process environment rather than from a
flag, and the Declared column names the file that reads or substitutes them.

| Variable | What it governs | Shape | Class | Declared in |
|---|---|---|---|---|
| `ASHAVERI_PUBLIC_URL` | The origin the container advertises, and so the one receipts point a client back to | required, and an https URL a client can reach | the operator's to declare | `enclave/docker-compose.yaml` |
| `ASHAVERI_TEE` | The environment the container starts expecting | one of the platform's TEE kinds | the operator's to declare | `enclave/docker-compose.yaml` |
| `ASHAVERI_WEIGHTS_DIR` | The directory the entrypoint verifies against the manifest before the gateway starts | a directory the manifest's files are read from, set only beside `ASHAVERI_WEIGHTS_MANIFEST`, because a run that sets one without the other is refused | the operator's to declare | `enclave/docker-compose.yaml` |
| `ASHAVERI_WEIGHTS_MANIFEST` | The manifest those weights are checked against | a file inside that directory, and the same file `--weights-manifest` names, so a receipt's digest covers the manifest the entrypoint checks those files against | the operator's to declare | `enclave/docker-compose.yaml` |
| `DSTACK_SIMULATOR_ENDPOINT` | The guest endpoint a development run talks to instead of a real guest agent | a path or an http URL, and a real CVM ignores it | the operator's to declare | `gateway/src/guest.ts` |
| `ASHAVERI_REQUEST_BODY_LIMIT_BYTES` | The largest request body this gateway reads, in bytes | a positive whole number of bytes a number can count exactly, at most 9007199254740991, and a value that is not one stops the build rather than falling back to the shipped bound, because a deployment that believes it set a number and is served another is running a configuration nobody wrote, and a bound past that count reaches a caller printed as an exponent instead of as the figure it is told to stay under. The bound is read where it is applied, ahead of the pipeline: what crosses it is answered 413 `BODY_TOO_LARGE` in the shape the route gives its own refusals, with the number this process holds printed in the message, and the refusal says what to do about it rather than what the bytes were. A caller of `buildGateway` that passed `requestBodyLimitBytes` keeps that number whatever this variable states | the operator's to declare | `gateway/src/server.ts` |
| `ASHAVERI_REQUEST_BODY_BUDGET_BYTES` | The request-body bytes this gateway will hold at once, summed across the requests in flight | a positive whole number of bytes a number can count exactly, at most 9007199254740991, and a value that is not one stops the build rather than falling back to the shipped budget, for the reason the row above states: a deployment that believes it bounded what it holds and is served another bound is running a configuration nobody wrote. A budget below one body's worth is not refused, because that is a legal statement about a deployment, and the refusal it produces carries no wait, since nothing about the traffic can make room for a body past the whole budget. The bound is read where it is applied, at the reader and ahead of the pipeline: what passes it is answered 429 `RESIDENT_BODY_BUDGET_EXCEEDED` with the budget, the figure resident at that instant and this request's own byte count printed in the message. A caller of `buildGateway` that passed `requestBodyBudgetBytes` keeps that number whatever this variable states | the operator's to declare | `gateway/src/server.ts` |
| `ASHAVERI_REQUEST_BODY_DRAIN_TIMEOUT_MS` | How long this gateway keeps reading the part of a request body it has already refused, in milliseconds | a positive whole number of milliseconds, and a value that is not one stops the build rather than falling back to the shipped bound, for the reason the two rows above it state: a deployment that believes it bounded how long it waits and is served another wait is running a configuration nobody wrote. It is read where it is applied, at the reader: it bounds the drain of the datums behind a refusal, and when it expires the refusal is written anyway and the connection ends, so the number states the latest a caller can be answered and not whether it is answered. A caller of `buildGateway` that passed `requestBodyDrainTimeoutMs` keeps that number whatever this variable states | the operator's to declare | `gateway/src/server.ts` |
| `ASHAVERI_CREDENTIAL_ID` | Which credential a client signs with | a credential name, and public | the operator's to declare | `packages/sdk/src/auth.ts` |
| `ASHAVERI_CREDENTIAL_KIND` | Whether that credential is proved by possession or presented as a bearer token | `pop` or `bearer`, and `pop` when unset | the operator's to declare | `packages/sdk/src/auth.ts` |

## 4. The one value that is credential material

Class: never in a commit or a log. It is listed with the rest because the shipped code reads it, and
its value is the only thing here that a reader must never write down: it is a signing key, so a
record that names its holder proves nothing once the key is in a repository, a log line or an image.

| Variable | What it governs | Shape | Class | Read from |
|---|---|---|---|---|
| `ASHAVERI_CREDENTIAL_SECRET` | The key a client signs each request with | 64 hex digits for a proof-of-possession credential, and never printed | never in a commit or a log | `packages/sdk/src/auth.ts` |
