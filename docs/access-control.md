# Access control

Every route this gateway serves sits behind one pipeline. A client presents a credential; the
gateway decides whether that credential may reach the route named in the request target; a refusal
leaves nothing further to evaluate; and whichever way the decision goes the request is written to a
log the deployer holds. This document states how each of those steps behaves, what it records, how
long the record lives, and how it is removed. Legal grounding is named where a requirement rests on
an instrument, and a sentence says plainly where the choice is ours rather than the law's. Two
neighbours hold what this document does not: [receipt-spec.md](receipt-spec.md) specifies the receipt
format and the HTTP protocol around it, and [threat-model.md](threat-model.md) lists the threats this
design addresses and the ones it leaves open.

## 1. The pipeline

`CredentialStore.admit` runs five checks in a fixed order, and the order is the contract rather than
an optimization. Each check is listed below with what it proves and, in parentheses, the refusal it
raises when it fails.

1. **The credential resolves and is usable.** The `Authorization` header names one record in the
   credential file; that record must exist, must be of the kind the header speaks, must not be
   revoked, and must carry a key its kind can be verified against
   (`AUTH_UNKNOWN`, `AUTH_SCHEME`, `AUTH_REVOKED`, `BAD_CREDENTIAL_RECORD`).
2. **The request proves possession of that credential's key.** The `ts` parameter is within the
   deployment's tolerance; the `x-ashaveri-nonce` header carries exactly the sixteen signed bytes;
   and an Ed25519 signature over the signing string verifies under the key in the file
   (`AUTH_STALE`, `AUTH_NONCE_MISSING`, `AUTH_SIGNATURE`).
3. **The request is new.** The credential-and-nonce pair has not been presented inside the replay
   window (`NONCE_SEEN`).
4. **The route accepts the credential's scope.** The request target is in the route table, and the
   scopes the record grants include what that row requires (`SCOPE_DENIED`).
5. **The credential is within its rate.** A token is taken from its bucket (`RATE_LIMITED`).

The reason for the order: a request that fails two of them reports the earlier one, so a revoked
credential is never asked to sign anything and a credential that has no scope for the route never
spends budget it was not going to use. Two placements carry that further than they look. The route
table is read first, because it is the cheapest step, but it answers only at check four: refusing an
unlisted target before a credential is named would let anyone enumerate which paths this gateway has
scoped. And check three runs before scope, which means a replay is refused as a replay even when the
replayed request would also have been a scope violation.

The bearer path is a different shape and is documented that way rather than blurred: it is check 1
by digest scan, then check 4, then check 5, with no replay step at all, because a bearer request has
no signed nonce to check. Section 4 says what that costs.

### Refusals, and what a client does

`docs/error-codes.md` holds one row per code and is the source of truth for the wording above. The
table below is the same set restated as something a caller can act on: a retry decision, not a
definition.

| Code | HTTP | Meaning | What a client does |
|---|---|---|---|
| `AUTH_MALFORMED` | 401 | No `Authorization` header, or one that names `Ashaveri-PoP` and still does not parse | Fix the client. These bytes will fail the same way on any route |
| `AUTH_SCHEME` | 401 | The header is neither `Ashaveri-PoP` nor `Bearer`; or it is `Bearer` on a deployment started without `--allow-bearer`; or it names a bearer record while presenting a proof of possession | Speak the scheme this deployment runs. A key pair and this answer means the deployment is bearer-only |
| `AUTH_UNKNOWN` | 401 | Nothing in the file answers to the named id, or no stored digest matches the presented secret | Check the id against the credential file. The deployment has never heard of this credential |
| `AUTH_REVOKED` | 401 | The record carries a `revokedAt` | Stop presenting it and get a new credential. Waiting does not help: the file is re-read when it changes |
| `AUTH_STALE` | 401 | `ts` is further from this clock than the tolerance, either side | Fix the clock, not the request. A fresh `ts` over the same bytes is a new request that may be admitted |
| `AUTH_NONCE_MISSING` | 401 | The nonce header is absent, is not unpadded base64url, or does not decode to sixteen bytes | Send the header carrying the same nonce that went into the signing string |
| `AUTH_SIGNATURE` | 401 | EdDSA over the signing string failed | Refuse. Either the key is wrong or something changed the request after it was signed; neither is a retry |
| `NONCE_SEEN` | 409 | This credential presented this nonce inside the replay window | Build a new request with a fresh nonce. Resending these bytes is exactly what just failed |
| `SCOPE_DENIED` | 403 | The route needs a scope the credential does not hold, or the target has no row | Use a credential that holds it, or ask the operator to scope the route. Rate budget is untouched |
| `RATE_LIMITED` | 429 | The credential's bucket is empty | Wait `retryAfterSeconds`, then send a new request |
| `BAD_CREDENTIAL_FILE`, `BAD_CREDENTIAL_RECORD`, `DUPLICATE_CREDENTIAL_ID` | 500 | The operator's file is unusable | Not a client fix. Nothing is admitted until the file is repaired |

## 2. Routes and scopes

The table below is the whole of `ROUTE_SCOPES`, one row per declared route. A route is listed
once, with the least scope it accepts.

| Route | Required scope | Why |
|---|---|---|
| `GET /v1/deployment-manifest` | `any` | `any` is not anonymous: the pipeline runs first, and the SDK's manifest fetch goes out over the same credential-signed transport as its completions. What this row drops is the scope test, so a credential holding only `read` can fetch what it needs to check a receipt. Requiring `complete` here would leave a verifier holding a reader's credential unable to verify the receipt it was given |
| `GET /v1/attestation` | `read` | It hands out live evidence, so the deployment chose to attribute the fetch |
| `GET /v1/attestation/gpu` | `read` | Device evidence, fetched with a caller-named `report_data`, which makes the fetch attributable in a way a signed completion's route is not |
| `POST /v1/chat/completions` | `complete` | The route that costs money, generates content, and has a privacy surface |
| `GET /v1/receipts/:id` | `read` | Receipts are private objects, and an id is unguessable rather than public: this row is what makes a read attributable to a credential instead of to whoever holds a string |

`HEAD` is answered as `GET`: Fastify registers a `HEAD` route for every `GET` route, so an
unnormalized `HEAD` would arrive as a target the table does not contain, and an absent table row is
a refusal rather than an unclassified route.

An unknown route is a startup failure rather than a serving decision. Every route the server
registers is checked against the table when it is registered, and a route with no row raises
`UndeclaredRouteError`, which the process treats as fatal and reports as `ROUTE_UNDECLARED`. A
gateway that booted cannot be serving an unclassified path.

That sentence is about registration. A request for a target the server never registered is a
separate case, and admission runs on it too: the pipeline answers before routing does, so an
unmatched path comes back as a credential refusal rather than as a 404. Measured on a gateway
holding one credential, with no signed header on the request, `GET /v1/nope`, `GET
/v1/deployment-manifest` and `GET /` each answered 401 with `AUTH_MALFORMED`, and each wrote an
access record whose `cred`, `auth`, `scope`, `rcp` and `nce` were null and whose `deny` carried
that same code. The registered route and the unregistered one were refused identically.

Scope arithmetic is one-directional: `any` is always satisfied, `complete` needs `complete`, and
`read` is satisfied by a credential holding either. A credential file that grants `complete` without
`read` is refused at parse time, so no credential this gateway will load can generate content and be
refused the receipts for it: a completing credential is always also a reading one, which is the only
combination with a coherent use.

Scope is a product and security decision, not an Article 15 requirement. Article 15(5) of the GDPR
covers a restriction of processing in response to an erasure request, which is not a routing table.
What the Article 15(5)-adjacent obligations actually reach are the credential, possession and replay
checks: they are what makes a log record mean something about a real holder.

## 3. Proof of possession on the wire

The client signs each request with an Ed25519 key it never transmits, and the gateway verifies the
signature against the public key stored in the credential file. A captured `Authorization` header is
therefore not a usable credential: it authorizes exactly one request, for the length of the
timestamp tolerance.

The header is `Authorization: Ashaveri-PoP credential=<id>, ts=<unix-seconds>, sig=<base64url>`.
`credential` is the operator's id for the record and must match exactly one entry in the file;
`ts` is the time the client signed at, in whole seconds; `sig` is the Ed25519 signature over the
signing string.

The signing string is six components joined by `\n` (a single line feed), in this order:

1. The scheme identifier, `ashaveri-pop-v1`.
2. `ts`, the same Unix-seconds integer that appears in the header.
3. The nonce, as unpadded base64url. These are the same sixteen bytes as the `x-ashaveri-nonce`
   header, and the two must agree.
4. The HTTP method, upper-case.
5. The request target: the path and, if there is one, the query string. `/v1/attestation?report_data=…`
   is signed as a whole, because for that route the query is the request.
6. The body digest: the lower-case hex SHA-256 of the raw request bytes. A bodyless request (a
   `GET`, or a `DELETE`) signs the published constant
   `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`, which is the digest of the
   empty byte string. Stating the constant is the point: a client author does not guess it.

The separator is `\n` rather than a delimiter such as `|` because a pipe can appear inside a request
target: a path segment or a query value may legitimately contain one, and a separator that can occur
within a field lets two different requests serialize to the same signing string. A line feed cannot
appear in a method, in a path, in a hex digest, or in a base64url string, so none of the six
components can carry the separator inside themselves.

The timestamp is checked against the gateway's own clock. The default tolerance is ±120 seconds, in
both directions, so a client running behind and one running ahead look the same from here. An
operator changes it with `--pop-tolerance <seconds>`. A stale request is a refusal, not a re-dated
request: a client that re-stamps the same bytes has built a new request, which is the point.

A replayed signature is refused by the nonce. The gateway keys its replay set on the credential id
and the decoded nonce bytes, so re-spelling the header in another valid base64url form is the same
nonce. The window is 900 seconds and the set is capped, so memory is fixed whatever the traffic. The
signed nonce and the receipt's `nce` claim are the same sixteen bytes: one value proves freshness
and ties the log line to a receipt, which is why dropping the nonce header is a refusal rather than
something the gateway works around by generating one itself.

<!-- pop-signing-string:completion-post -->
```text
ashaveri-pop-v1
1772000000
UFdDxyVjlgySSGS0GFRbMg
POST
/v1/chat/completions
98e1ee609c31e633262268087e341cc85c22a10867f7f77cf1c9a1e910dc4907
```

The block above is the golden vector named `completion-post`, printed component per line and matched
byte for byte by a test. Its `ts` is a reproducibility value and sits outside the freshness window,
so this exact string is a wire-format specimen and not a request that would be admitted. The key
that signs it is published with the fixture, and it protects nothing.

## 4. Bearer mode

`--allow-bearer` makes the gateway accept `Authorization: Bearer <secret>` alongside proof of
possession. It is deployment-wide. There is no per-credential override: either the process is
bearer-capable or it is not, and one credential file can hold records of both kinds because the
`kind` field decides what the gateway looks for. A bearer credential must still appear in the
credential file. The secret is not stored; the file holds the SHA-256 of it, and admission hashes
the presented secret and compares every digest in the file with a loop that does not exit early on
the first differing byte.

The gateway prints its mode at start-up and does not soften it. In proof-of-possession mode the
banner line reads `auth: proof of possession, timestamps trusted within N seconds; bearer
credentials refused`. With the flag it reads:

> auth: bearer credentials also accepted, which is a refusal of the strongest posture here: a stolen
> bearer credential is undetectable, and a log record cannot tell its holder from a thief

In that mode a request admitted on a bearer secret carries `auth=bearer` and a request admitted on a
key still carries `auth=pop`, because the field records the kind a request was verified as and not
the widest thing the process will tolerate. That is more useful to a reader of the log than a
deployment-wide flag would be: the line says which posture produced it. A deployment-wide setting is
still the right shape, because per-credential settings encourage a single bearer fallback out of
convenience and then treat it as a detail.

This section states the limit rather than paraphrasing it. A stolen bearer credential is
undetectable, and a log record cannot tell its holder from a thief. The credential is the whole
secret, it does not expire on its own, it authorizes any request its scopes allow from any address,
and nothing about the request distinguishes the person it was issued to from the person who took it.
Proof of possession is the default because a captured signed request authorizes one request and
nothing else.

## 5. The credentials file

The gateway reads its credentials from one JSON file, and its shape is the CLI's output shape:

```json
{
  "version": 1,
  "credentials": [
    {
      "id": "svc-1",
      "kind": "pop",
      "publicKey": "broCD3p8hud4yry0KBPiTUyBVGEGu9TvXU_J4dBSvbc",
      "scopes": ["read", "complete"],
      "label": "internal testing",
      "createdAt": 1772000000
    }
  ]
}
```

`version` is the file's schema version, and the gateway refuses a file that declares any other
value: a wrong version is an accident the operator should hear about rather than records the
gateway invents a reading for.

`kind` decides which field carries the credential material. A `pop` record carries `publicKey`, the
unpadded base64url of an Ed25519 key, and no secret: the rule is about the decoded bytes, which must
be exactly 32, so two spellings of one key name one record and a 64-character hex string is a
48-byte decode the parser refuses. A `bearer` record carries `secretHash`, the lower-case hex of the
SHA-256 of the bearer secret, and no key. A record whose material does not match its `kind` is a
parse failure or is skipped during admission, so it is never silently treated as the other kind. An
id is `[A-Za-z0-9_-]{1,64}`; two records sharing one id are refused.

`scopes` is the list admission checks the route table against, and it is documented in section 2.
A list that grants `complete` without `read` is refused at parse time; the gateway has no coherent
reading of a credential that may generate content but may not read back what it generated.

`rate` is optional and per-credential: `{ "perMinute": 60, "burst": 120 }`. A record without one is
held to `{ perMinute: 60, burst: 120 }`, which is a starting point and not a safe default. The
operator sizes each bucket against the traffic the deployment actually carries.

`label` is free text, and it is the only place in the credential file a person can be named. That
makes it the only field in this file an erasure request can reach by name. The gateway does not
interpret it; a deployer who writes an email address in a label has added a second copy of personal
data to keep.

`createdAt` and `revokedAt` are whole seconds since the epoch, which is the unit the command that
writes this file uses and prints. `revokedAt` is optional, and the gateway reads it as a flag rather
than a date: any value present revokes the record, whatever it is, and nothing compares it to a
clock. A revoked `pop` record answers `AUTH_REVOKED`. A revoked `bearer` record answers
`AUTH_UNKNOWN`, because the digest scan passes over it as though it had never existed, and a
distinct answer for it would tell a prober which ids the file holds and which of them were once
live.

**The file is re-read when it changes.** The gateway checks the file's mtime on each request and
reloads in the background when it has moved, so a revoked record stops working without a restart.
One reload covers a whole edit: a request in flight is admitted against the file as it stood when
that request began. A file that will not parse leaves the records already loaded in place and the
mtime unrecorded, so the next request tries again; a half-written file in the middle of an operator's
edit is one failed reload rather than a deployment that has forgotten its credentials.

**What a revocation does not move.** A credential edit changes neither digest a receipt carries.
`wts` is the gateway's hash of a manifest that lists every file under the deployment's weights
directory, and `enclave/docker-compose.yaml` mounts the credential file outside that directory for
this reason: an operator-edited file inside it would either fail the entrypoint's check or put the
edit inside the digest every receipt carries, so a routine enrolment or revocation would move the
deployment's attested identity. `meas.m` is a platform launch value, a statement about what runs
rather than a hash of what it is pointed at. What a revocation changes is the answer and the record:
`AUTH_REVOKED` on a proof-of-possession credential, `AUTH_UNKNOWN` on a bearer one, each written to
the access log with the credential id it refused. A verifier that pins a measurement and a weights
digest pins the software a deployment runs, and not the list of who may call it; that list is the
deployer's, and the log is where its use shows.

## 6. Flags that change the access floor

| Flag | Default | Effect |
|---|---|---|
| `--credentials-path <file>` | required in a live start | The file every request must present a credential from. In `--mock` it is optional, and without it the process keeps its own in-memory records |
| `--access-log-path <dir>` | required in a live start | Where the per-request log is written. The value must name an existing directory, so a volume that was not mounted is a refusal rather than a log written onto the root filesystem |
| `--access-log-days <n>` | 184 | How long log files are kept, in days. 184 is the default and the floor the code names, and it is not enforced as a ceiling on the operator's choice: a shorter value starts, and the start-up report says out loud that the run is below the floor (section 8.2) |
| `--pop-tolerance <seconds>` | 120 | Clock slack accepted for a proof-of-possession timestamp, in both directions |
| `--allow-bearer` | off | Accepts bearer credentials deployment-wide, says so at start-up, and writes `auth=bearer` on every record a bearer secret admitted |

## 7. The access log

One JSON object per line, one line per request, written whether the request was admitted or refused.
The field names are the entire allowlist: the writer reads exactly these keys out of an object, so an
object a future hook learns to assemble cannot widen the record. There is no field for a body, a
header, a key, a secret, or an address to be written into.

The twelve fields, in the order the writer emits them:

| Field | Purpose |
|---|---|
| `t` | Epoch milliseconds at the request's arrival |
| `rid` | Server-generated request id, the join key between a line and a support ticket |
| `cred` | Which credential made the request; `null` only when the request named none, since a refusal that got as far as reading an id records the id the header carried, known to the file or not |
| `auth` | `pop`, `bearer`, or `null`. What this request was verified as, so the two postures read differently even in one bearer-capable deployment |
| `scope` | Which scope the route needed, so a reader can compare it against the credential's grant without reloading the credential file |
| `m` | The HTTP method |
| `p` | The path only, with the query string dropped: it can carry a report-data challenge and receipt ids |
| `rcp` | The receipt a read route was asked for. Only `GET /v1/receipts/:id` names one in its target, so a completion that issues a receipt records nothing here |
| `nce` | The request's nonce, so a record can be tied to a receipt |
| `st` | The HTTP status this gateway answered with |
| `dur` | Request duration in milliseconds |
| `deny` | The refusal code from section 1's table, on a request the pipeline rejected |

Deliberately not recorded: request and response bodies, so no prompt and no completion; the
`Authorization` header; bearer secrets; public keys; query strings; source IP; user agent.

Those two omissions carry weight, because a source address and a user agent are personal data, and a
record without them cannot identify a person's location or device. Their absence rests on Recital 49
of the GDPR, which is the processing ground the field allowlist has, and on that recital's own
limiter, "to the extent strictly necessary and proportionate": the allowlist is closed, and a field
that is nice to have in a debugging session is not within that phrase. Article 32(4) reaches people
acting under a controller's or processor's authority, which is the population one credential per
principal attributes; it does not reach every caller of an API, and this document does not claim that
it does.

### Rotation and retention

Files are named `access-YYYY-MM-DD-NNN.jsonl`. The date is the UTC day the writer was on when the
line was produced, and a new part begins on the day boundary and again when a file passes 32 MiB, so
a busy day's records are spread across parts and a quiet day is one file. `--access-log-days` prunes
by name read from the file name, not by inode mtime: a file system whose timestamps have been touched
does not change which day a file belongs to. 184 days is the default, and the log itself neither
clamps nor refuses what it is handed: `--access-log-days` reaches the writer as a request, and the
surface that reads the operator's configuration is where the floor is spoken to. A value below 184
therefore starts, and the start-up report says in as many words that the run is under the floor
rather than stopping it. Section 8.2 says where 184 comes from and what a longer window would rest
on.

`window()` reports what the process actually holds: the earliest and latest timestamp on the volume
and a count of the records it can read back. A line that fails to parse is skipped, so the number is
of readable records rather than of lines. It is a count of what survives, not of what was written, so
an operator who pruned early sees a shorter window rather than a number that implies the missing days
exist somewhere. `--access-log-days` is the request; the window is the result.

### Erasure

`ashaveri accesslog scrub --credential <id>` is the erasure route. It filters one credential's
records out of every part, publishes its counts and rewrites each affected part at the permission
bits read back from that part, since a publish replaces the part whole and the mode is the only
setting that carries across, and leaves a marker named `scrub-<day>-<seq>.jsonl`. The marker is the
proof that an erasure ran, which matters for Article 15(5)'s notification duty: the deployer who
erases has to be able to say the erasure happened, and the log's own lines cannot do that once they
are gone. The retention sweep collects markers on their own day's schedule, because a marker is
personal data at the level of a credential id and cannot outlive the window that erased its subject.
`--request <ref>` records the deployer's own reference for the instruction the run answers, so a later
reader can tell which request a given erasure discharged.

Erasure is not expiry. Pruning deletes a whole day's records when that day's retention has run out,
and needs no subject, no instruction and no marker. Scrubbing answers an instruction, keeps every
other line, and files a marker. The two meet at the same file name: a scrubbed part whose records are
all gone is removed rather than renamed, and pruning collects it by name alone.

## 8. Retention, erasure, and who decides

### 8.1 The record as a unit

A data subject makes a request; the credential is the subject's handle inside this system, and not
every subject holds one. The log records that handle alongside the request's shape, its outcome, and
the receipt it touched. The record cannot be separated from its context: a line that says a request
was refused is meaningless without the credential that made it. Retention and erasure therefore
apply at the line level, and the line's subject is the credential named in `cred`.

Receipts are a separate artifact. The chain is append-only and carries no `Authorization` data, no
credential id, and no field that could be made to carry one. Read attribution lives here, in the
erasable log, and that split is the reason an erasure request is answerable at all: the log is the
artifact an erasure can empty, and the chain is the artifact a verifier must be able to hold
independently. Section 8.3 states the one link that survives erasure.

### 8.2 Retention, and where the number comes from

`--access-log-days` carries these records, and the default is 184 days: six months rounded up to
whole days. The number is not invented here. Article 19(1) of the EU AI Act requires a provider of a
high-risk AI system to keep, to the extent within its control, the logs such a system generates
automatically under Article 12(1) for a period appropriate to its intended purpose and of at least
six months, and Article 26(6) states the same duty for a deployer; the gateway's usage text names
those two paragraphs as where 184 sits. Two conditions travel with that. Whether a per-request access
record is an Article 12(1) log turns on the system and on the actor, and this document cannot settle
it either; `store.ts` makes the same assumption for a receipt and says so in the same terms. And both
paragraphs yield to applicable Union or national law, "in particular in Union law on the protection
of personal data", which can cut this window as well as lengthen it. What the code does not do is
refuse to start under the floor: a shorter value is accepted, and the start-up report prints the
reason it is a floor, so overriding it stays the operator's move and not the software's.
The direction of the default is the deployer's duties being longer than the window rather than
shorter. Nothing in the writer bounds the total size of that window: the 32 MiB figure is a per-file
part size, so a busy deployment grows in parts and the volume the log sits on is the real limit.

Four duties run against that window. None of them is satisfied here, and none of them is answered by
a shorter number.

- **A subject's access request.** Article 15(3) requires a copy of "the personal data undergoing
  processing", so a deployment asked for the log lines about a credential can only produce the ones
  still on the volume. Nothing in the access log's design addresses this, and a longer window is a
  configuration decision, not a code change.
- **Notification after erasure.** Article 19 of the GDPR requires telling each recipient to whom
  personal data has been disclosed about a rectification or erasure, and Article 15(5) requires telling
  those recipients about a restriction. Both assume the deployer still knows who received what, which
  retention against a fixed window can erase, and the scrub marker is the artifact that lets an
  operator prove a removal happened.
- **Security logging.** Article 32(2) and (4) plus the NIS2 provisions on logging and access control
  (the relevant NIS2 points are its Article 21(2)(c) and (d) and Article 23(2)) point toward keeping
  security logs. The one period they do fix is a floor rather than a window: the EU AI Act's
  Article 19(1) for a provider and Article 26(6) for a deployer of a high-risk AI system both ask for
  the logs its system automatically generates to be kept for a period appropriate to the purpose and
  no shorter than six months, and 184 days sits on that floor. Anything above it is ours to set, not
  the Act's.
- **Evidence.** Article 20(3) gives the lawful basis for processing needed to establish or defend
  legal claims, and national limitation periods run to years. A window shorter than the applicable
  period erases the evidence before the claim arrives.

### 8.3 What erasure achieves, and its limit

A scrub removes a credential's lines and files a marker. Section 7 explains what a marker is for. The
limit: these records are the deployer's, and the deployer's lawful basis is the one that runs here,
whether the deployer acts as controller or as processor. This document is written so that it holds in
either case; that dual usability is a property of the text, chosen deliberately. The place a
designation is actually made is the deployer's own Article 30 record, and it is not made here.

One link does not live in the log, and saying so is part of what an erasure can be asked to do. The
first sixteen hex characters of a receipt id, eight bytes, are a tag derived from the minting
credential's id, and that id is what the `x-ashaveri-receipt-id` response header carries, what a
client fetches the receipt by, and what `rcp` copies on a read. What the link discloses is narrower
than the word "derived" suggests, and the difference matters to anyone reading an erasure's residue.
The tag is a keyed hash: its key comes from this deployment's own signing seed, so a tag is
not a name and cannot be reversed into one. A reader holding an id, the receipt behind it and every
credential file the deployment keeps still cannot say which credential minted it. Two things remain true
without that. Ids carrying the same tag came from the same credential, so anyone who sees both ids can tell they
belong together, which is linkability rather than identification. And the deployment itself, holding the seed,
can compute each credential's tag and so name the credential behind any id it is shown. The strongest reader of a
tag is the operator who already holds the log.

The signed receipt bytes carry no id, and their `nce` claim is the request nonce rather than the handle, so a
holder of receipt bytes alone is not that reader. That is not a property of the log: erasing the log does not
disturb it, because the chain is append-only. The link the log creates is a read event, and only a read event is
erasable.

That limit is the cost of unguessability: an id a stranger cannot walk is an id whose tag is still legible
to anyone who has the id. The tag is what makes the fetch route refuse one tenant's receipt to another
without storing ownership state that could drift, and the same value is what survives an erasure.

## 9. Appendix: data map

| Field | Purpose | Retention | Where it lives | How it is erased | Whose lawful basis |
|---|---|---|---|---|---|
| `t`, `rid`, `m`, `p`, `st`, `dur` | one request's shape and outcome | `--access-log-days`, default 184, and a shorter value starts with a start-up note | one JSONL file per day | deleted with its file on a name read from the file name | the deployer's |
| `cred`, `auth`, `scope` | which credential made the request, in which mode | same | same | `ashaveri accesslog scrub --credential <id>` | the deployer's |
| `nce` | the request's nonce, so a record can be tied to a receipt | same | same | scrub | the deployer's |
| `rcp` | which receipt a read route was asked for | same | same | scrub | the deployer's |
| credential `label` | operator's own name for a credential, and the one field that can identify a person | until the operator edits it out | the credentials file, rewritable in place | remove or blank the record | the deployer's |
| prompt and completion bytes | not recorded, at any retention | n/a | n/a | n/a | n/a |
| `Authorization`, bearer secrets, public keys, query strings, source IP, user agent | not recorded; the first two are credentials, the third is a key, the fourth carries a report-data challenge, and the last two are personal data the decision does not need | n/a | n/a | n/a | n/a |

`rcp` creates a link from a credential to a receipt, and that link is what makes these records
personal data rather than a count. It is here because this file is rewritable and the receipt
chain is not, so the answer to "who read this receipt" lives in the artifact an erasure request
can empty. Recital 26 is the reason the link makes the record personal; Recital 49's "to the
extent strictly necessary and proportionate" is the reason the allowlist is closed and the two
omissions in section 7 are omissions. Article 32(4) reaches people acting under a
controller's or processor's authority, which is the population one credential per principal
attributes; it does not reach every caller of an API, and this document does not claim it does.
