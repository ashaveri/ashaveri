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

`CredentialStore.admit` runs five checks in a fixed order, one bound on the connection ahead of all
five, and one guard on the deployment behind them. The order is the contract rather than an
optimization. It sorts by what an answer discloses, not by what a check costs, and it keeps the
property that makes the difference knowable: a request that fails two of them reports the earlier one.
Each check is listed below with what it proves and, in parentheses, the refusal it raises when it
fails; the bound is described with them, because it answers with one of their codes, and the guard is
described after them, because it is the one check that reads the store rather than the credential.

1. **The request says who it is, and when.** The `Authorization` header parses and speaks a scheme
   this deployment runs; the `ts` parameter is within the deployment's tolerance; the
   `x-ashaveri-nonce` header carries exactly the sixteen signed bytes
   (`AUTH_MALFORMED`, `AUTH_SCHEME`, `AUTH_STALE`, `AUTH_NONCE_MISSING`). Each of these reads only
   what the caller wrote, so each is owed to every proof-of-possession request whoever it names, and
   each answers identically to a request naming a credential this file holds and to one naming a
   credential it does not.
2. **The request proves possession of the key its header names.** The named record is looked up, and
   an Ed25519 signature over the signing string verifies against the key that record carries
   (`AUTH_SIGNATURE`). A name the file does not carry, and a name whose record is a bearer one and so
   offers no key to verify against, are refused with this same code through this same path.
3. **What the file says about a credential it holds.** The record carries no `revokedAt`
   (`AUTH_REVOKED`), and the credential-and-nonce pair has not been presented inside the replay
   window (`NONCE_SEEN`). Both are reachable only by a request whose signature verified.
4. **The route accepts the credential's scope.** The request target is in the route table, and the
   scopes the record grants include what that row requires (`SCOPE_DENIED`).
5. **The credential is within its rate.** A token is taken from its bucket (`RATE_LIMITED`).

**Ahead of all five sits one bound, and it is held on the connection rather than on a credential.** Before
the request has said anything about itself, the gateway asks how many requests the address it arrived on has
made recently, and one from an address that has spent its allowance is refused `RATE_LIMITED` without its
header being read. The bound is there because check 2 gives a guess a cost: a name this file does not carry
is answered by performing one Ed25519 verification, so a loop over names would otherwise buy computation for
the price of sending it. Check 5 cannot bound that, because a guess holds no credential to charge, so the
charge goes on the thing a guesser cannot choose - the address its connection came from. It is set generously
and it is a floor rather than an allowance: 2,000 requests in a burst and 6,000 a minute from one address,
which is a hundred requests a second sustained and no single client of this gateway's shape reaching it. The
number has to clear the traffic the shape does carry, because the bucket is shared: a deployment behind one
reverse proxy puts every request it serves through one address, and fifteen credentials running their own
default of 60 a minute are 900 requests a minute down that one pipe. An operator whose deployment is bigger
sets both halves with `--peer-rate perMinute=<n>,burst=<n>` (section 6), and there is no flag that takes the
bound off, because a large number does that and says so. A refused request costs this process a lookup and
a 429.

That placement is lawful for the same reason the freshness window's is, and it is the reason the bound has to
be uniform: every request meets it, whoever it names and whatever its header says, so the answer is a
statement about this deployment and never about the file. What a throttled caller learns is that it is
throttled. It is answered in the same words either bucket gives - `RATE_LIMITED`, status 429, and a
`retry-after` - and the sentence says which one fired, because waiting refills the connection's and the fix
for the credential's is the rate the operator set. Nothing in that answer depends on whether a name the
caller typed is in the file, and it names none. The uniformity is the answer's and not the record's: a
refusal of this bound writes `PEER_RATE_LIMITED` to the log's `deny` field where the credential's bucket
writes `RATE_LIMITED`, and a line carries no refusal message, so that field is where an operator reads the
two incidents apart instead of inferring them from whether a name was recorded.

Two consequences follow from keying a bound on a connection. Behind a reverse proxy every request arrives
from the proxy's address, so this is not a per-client limit unless the operator puts a trusted proxy in front
and has the real address passed on; and no header is consulted for an address at all, `X-Forwarded-For` and
`Forwarded` included, because a key the caller chooses is a bound the caller can move or reset. Neither
figure is a flag: the software holds the floor, and a deployment that needs per-client limits needs a proxy
that can name the client. The counter is memory only, is never written down, and does not outlive the
process, so it is not the record section 7 declines to keep an address in; how many addresses it remembers is
capped, so it cannot be grown by making the gateway meet more of them.

**Behind all five sits one guard, and it is held on the deployment rather than on a caller.** A
completion is the request that issues a receipt, and a receipt is only worth issuing while the
deployment can keep it: the durability bound retires the oldest prefix of the chain, and the period
configured beside it states how long a receipt stays fetchable. Where the two cannot both be honoured,
this gateway refuses the completion at admission, ahead of the upstream call, with
`RECEIPT_WINDOW_UNHOLDABLE`; section 6 names the two flags that set it, and
`docs/error-codes.md` gives the refusal its row. Reads, verification of a receipt already filed, and
a handover assembled from the retained set keep serving, because none of them adds a receipt to the
store, and what a walk over the retained set costs is what it cost before this check existed.

The guard reads the retained set and the two configured numbers, so it names no credential,
distinguishes no id, and varies with nothing in the file: it answers one completion as it answers the
next, whoever sent it. That is what makes a place behind the five lawful for it, on the same rule that
makes the bound ahead of them lawful. It sits behind them rather than ahead because a request that
fails one of the five is answered by the earlier check, which is the rule the ordering comes from, and
because the credential whose completion this is has to be admitted before anything is declined on its
behalf. It spends the credential's token on the way, since the bucket is the fifth check and this is
the sixth: a guard refusal is a request this deployment answered, and the line it writes names the
credential it refused.

Three states keep a quiet deployment from starting to refuse, and they are the three the store's own
opening refusal respects. A policy bounded on one side only has no pairing to contradict, so it is
never asked. A retained set below the configured point of its bound is shedding nothing, however
little it has issued. A store at its bound whose stamps already span the configured period is holding
what it asked for at the traffic it carries, and a store that has retained fewer than two receipts has
measured no rate at all, which is that condition's own precondition. The threshold is a fraction of
the bound and defaults to the bound itself: the retained set never exceeds the count that retires it,
so that default is the one state a store already refuses to open at, which is why a deployment that
configures nothing behaves here exactly as it did before this pairing was read while serving.

Growing past the guard is permitted as a named decision and not as a value of the threshold.
`--receipts-grow-past-guard` turns the refusal off, off being its default: with it the volume keeps
growing, the durability bound keeps retiring the oldest prefix, the window served is the shorter one
that bound reaches rather than the period configured beside it, and the pairing is met at the next
restart by a store refusing to open rather than by an answer a caller can read. That is the cost of
it, and it is discovered inside a write rather than at a refusal, which is why it is opt-in, why the
start-up report prints whichever posture the process is running, and why no percentage of the bound
switches this off instead.

`BAD_CREDENTIAL_RECORD` is not a refusal the pipeline answers a request with, as of 19 September
2026. A `pop` record carrying no key its kind can be verified against never reaches a request: it is
refused where records enter the store, so a credential file with such a record in it stops the boot,
and a reload that hits one keeps serving the records it already had. Section 5 says what each of
those does.

### The rule the order comes from

**Answer a request out of what the credential file holds only after that request has proved it holds
the key its own header names.** The reason is that any refusal which varies with the file's contents
is a yes-or-no question a caller can put by typing a name. Credential ids are the operator's own
words rather than random handles, so an answer that distinguishes a name this file holds from one it
does not tells whoever sent both which names this deployment issued, without their holding a single
key.

Restated as a test of where a check may sit, which is the form a port to another language has to
reproduce: a check has exactly two lawful homes. It runs before the file is consulted and applies
identically to a request that names a record and to a request that names nothing, or it runs after a
signature verifies. A check placed between those two points is an enumeration oracle whatever its
message text says.

Two placements follow from that test, and both are load-bearing rather than stylistic. The freshness
window and the presented nonce run ahead of the lookup, because a stale stamp and a malformed nonce
are properties of the bytes the caller wrote and vary with nothing in the file. An unknown name is
answered behind the lookup by performing one Ed25519 verification against a key that is in no
credential file and is made once when the process starts, and then throwing `AUTH_SIGNATURE` without
reading what that verification answered. The verification is the same function, called the same way,
that every other proof-of-possession request is checked with, and the throw is unconditional. A port
that branches on the dummy verification's result, or that reaches past `verifyPopSignature` for the
Ed25519 library directly, rebuilds the oracle: the library this gateway verifies with,
`@noble/curves`, accepts a 64-byte zero signature against a 32-byte constant key under its own
defaults, because such a key is a point of small order, and what refuses it is that function's width
checks and its strict verification options. An accepted signature for a name the file does not hold
discloses more than the refusal this path exists to make indistinguishable.

Two things this arrangement does not claim, and a port must not upgrade it into either. It does not
make the two paths equal in time: a name the file holds and a name it does not each perform one
verification, which is the point of the arrangement, but a lookup that hits and a lookup that misses
are not the same duration on any machine, and nothing here bounds or observes the difference. It does
not withhold anything from a caller who verified. Once a signature checks out, the answers this
gateway gives are specific: revoked, already presented, out of scope, over rate. That caller is the
only party who can do anything about any of the four. What is closed is what an
unauthenticated guesser learns; the residue is threat row T15 of
[threat-model.md](threat-model.md).

Two placements carry the order further than they look. The route table is read first, because it is
the cheapest step, but it answers only at check 4: refusing an unlisted target before a credential
is named would let anyone enumerate which paths this gateway has scoped. And the replay test runs
before scope, which means a replay is refused as a replay even when the replayed request would also
have been a scope violation. The ordering gives something up. A revoked credential is asked to sign
before it is told it is revoked: the withdrawal reaches the party holding the key, and a caller that
typed the id without the key gets the answer any failed signature gets.

The bearer path is a different shape and is documented that way rather than blurred: the header
checks of check 1, then a digest scan of the whole file, then check 4, then check 5, with no replay
step at all, because a bearer request has no signed nonce to check. Nothing on that path names an id,
so nothing about an id can be disclosed by it, and the check-2 collapse does not reach it:
`AUTH_UNKNOWN` is what a bearer request gets, as described below. Section 4 says what that costs.

### Refusals, and what a client does

`docs/error-codes.md` holds one row per code and is the source of truth for the wording above. The
table below is the same set restated as something a caller can act on: a retry decision, not a
definition.

| Code | HTTP | Meaning | What a client does |
|---|---|---|---|
| `AUTH_MALFORMED` | 401 | No `Authorization` header, or one that names `Ashaveri-PoP` and still does not parse | Fix the client. These bytes will fail the same way on any route |
| `AUTH_SCHEME` | 401 | The header is neither `Ashaveri-PoP` nor `Bearer`, or it is `Bearer` on a deployment started without `--allow-bearer`. An `Ashaveri-PoP` header naming a record that is a bearer one is refused as `AUTH_SIGNATURE` rather than as this | Speak the scheme this deployment runs. A key pair and this answer means the deployment is bearer-only |
| `AUTH_UNKNOWN` | 401 | No stored digest matches the bearer secret presented. That one answer covers a secret belonging to a retired record as well as one this file never held. A proof-of-possession request is never answered with this code | Check the secret against the credential file. The deployment has never heard of this credential, or retired it, and the two are deliberately the same answer |
| `AUTH_REVOKED` | 401 | The named record carries a `revokedAt`, and the request's signature verified against the key that record still holds | Stop presenting it and get a new credential. Waiting does not help: the file is re-read when it changes |
| `AUTH_STALE` | 401 | `ts` is further from this clock than the tolerance, either side. Answered before the file is read, whoever the header names | Fix the clock, not the request. A fresh `ts` over the same bytes is a new request that may be admitted |
| `AUTH_NONCE_MISSING` | 401 | The nonce header is absent, is not unpadded base64url, or does not decode to sixteen bytes. Answered before the file is read, so it reaches a caller naming a real credential and a caller inventing one alike | Send the header carrying the same nonce that went into the signing string |
| `AUTH_SIGNATURE` | 401 | EdDSA over the signing string failed, or the name the header carries is not one the file holds, or the record it names is a bearer one with no key to verify against | Refuse. The key is wrong, or something changed the request after it was signed, or the credential id is not one this deployment holds. Check the id and the key; none of the three is a retry |
| `NONCE_SEEN` | 409 | This credential presented this nonce inside the replay window | Build a new request with a fresh nonce. Resending these bytes is exactly what just failed |
| `SCOPE_DENIED` | 403 | The route needs a scope the credential does not hold, or the target has no row | Use a credential that holds it, or ask the operator to scope the route. This answer takes no token from the credential's own bucket, though the connection's bound was charged before it was decided |
| `RATE_LIMITED` | 429 | Either the credential's bucket is empty or the connection has spent the request bound held ahead of the five checks. The refusal's own sentence says which, and it names no credential on the connection's answer. The two are separated in the access log and nowhere a caller looks: the connection's bound writes `PEER_RATE_LIMITED` to `deny` and the credential's bucket writes `RATE_LIMITED`, so the volume tells the incidents apart while this answer stays the one answer | Wait `retryAfterSeconds`, then send a new request. One answer is fixed by the rate the operator set for the credential; the other by how much this one address is asking at once |
| `RECEIPT_WINDOW_UNHOLDABLE` | 429 | This deployment cannot issue a receipt it can keep for the period it configured: the store's retained set has reached the configured point of its durability bound, and the rate that set's own stamps measure says the period takes more receipts than the bound holds. Refused ahead of the upstream call and behind the five checks, on the one route that issues a receipt, and it carries no `retry-after` because no refill is known | Wait, and expect a deployment at its bound to still be at it: this is not a bucket refilling, and nothing a caller holds changes it. The condition clears when this deployment's issuance falls below the rate its bound cannot hold, or when its operator raises the bound to the count the message states or shortens the period beside it. A caller that needs the receipt takes it from a deployment able to keep it, and a caller that needs an answer can take this one, which says plainly that no receipt is coming |
| `BAD_CREDENTIAL_FILE`, `BAD_CREDENTIAL_RECORD`, `DUPLICATE_CREDENTIAL_ID` | 500 | The operator's file is unusable. None of the three is a refusal the pipeline gives a request: they answer where records enter the store, at start-up and on reload | Not a client fix. A file that will not parse, or that holds a record with no key its kind can be verified against, stops the boot; a reload that fails keeps the records already loaded answering later requests while the file is repaired |

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
separate case, and admission runs on it too: the unmatched lookup falls to Fastify's not-found
route, and the pre-handler hook that admits requests runs on that route as it runs on a declared
one, so an unmatched path comes back as a credential refusal rather than as a 404. Measured on a gateway
holding one credential, with no signed header on the request, `GET /v1/nope`, `GET
/v1/deployment-manifest` and `GET /` each answered 401 with `AUTH_MALFORMED`, and each wrote an
access record whose `cred`, `auth`, `scope`, `rcp` and `nce` were null and whose `deny` carried
that same code. The registered route and the unregistered one were refused identically.

Scope arithmetic is one-directional: `any` is always satisfied, `complete` needs `complete`, and
`read` is satisfied by a credential holding either. A credential file that grants `complete` without
`read` is refused at parse time, so no credential this gateway will load can generate content and be
refused the receipts for it: a completing credential is always also a reading one, which is the only
combination with a coherent use.

Scope is a product and security decision, not an Article 15 requirement of the GDPR. Article 18 of
the GDPR gives a data subject the right to obtain a restriction of processing, one of its cases being
a subject who opposes an erasure and asks that the use of their data be restricted instead, which is
not a routing table. What the GDPR's Article 5(1)(f) and Article 32(1) obligations actually reach are
the credential, possession and replay checks: they are what makes a log record mean something about a
real holder.

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
SHA-256 of the bearer secret, and no key. Material that does not match its `kind` never becomes a
record that speaks the other kind. Read from a file, a `pop` record with no public key of the width
its kind needs is a parse failure, and a `secretHash` beside a `pop` kind or a `publicKey` beside a
`bearer` one is a field the parser never reads, so the record it returns carries one kind's material
and nothing else. Records handed to a store in memory go through that store's own ingest, which
refuses a `pop` record with no key of the width its kind needs, on the rule the parser already
applies to a file, and clears a stray `secretHash` beside a `pop` kind so the record is the one the
disk route would have returned. Two shapes the in-memory route can still hold are passed over rather
than refused: a `bearer` record whose digest is not 32 bytes, which no presented secret can match,
and a `bearer` record that also carries a public key, which takes no part in the digest scan. An id
is `[A-Za-z0-9_-]{1,64}`; two records sharing one id are refused.

**Records are checked where they enter the store, not where a request reads them.** Every route into
a `CredentialStore` ends at the same ingest, so a file read from disk and a set of records handed
over in memory are held to one rule rather than two. A record the ingest refuses is never served, and
it is never a request's answer either: the refusal lands at start-up, where the process stops rather
than booting over a file it cannot use, or on a reload, where the records already loaded keep
serving, as described below. That placement is what keeps a wrong file visible to the operator who
can fix it while a caller who can fix nothing learns nothing about which names the file holds.

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
clock. A revoked `pop` record answers `AUTH_REVOKED`, and only to a request whose signature verifies
against the key that record still carries: revocation withdraws the credential, it does not delete
the key, and the party who can act on a withdrawal is the party holding it. A caller that names a
revoked id without proving the key is refused as `AUTH_SIGNATURE`, the answer every other failed
signature gets. A revoked `bearer` record answers `AUTH_UNKNOWN`, because the digest scan passes over
it as though it had never existed, and a distinct answer for it would tell a prober which ids the
file holds and which of them were once live.

**The file is re-read when it changes.** The gateway checks the file's mtime on each request and
reloads in the background when it has moved, so a revoked record stops working without a restart.
One reload covers a whole edit: a request in flight is admitted against the file as it stood when
that request began. A file that will not parse, or that parses into a record the ingest refuses,
leaves the records already loaded in place and the mtime unrecorded, so the next request tries again;
a half-written file in the middle of an operator's edit is one failed reload rather than a deployment
that has forgotten its credentials. A reload that fails on one unusable record is reported with that
record and the file it came from named, and admission keeps answering from the records that had
already loaded: dropping to none would turn one typo in a large file into an outage that reads as the
gateway misbehaving. A request that triggered a failed read is not admitted against the file that
failed it, and the read is tried again on the next one.

**What a revocation does not move.** A credential edit changes neither digest a receipt carries.
`wts` is the gateway's hash of a manifest that lists every file under the deployment's weights
directory, and `enclave/docker-compose.yaml` mounts the credential file outside that directory for
this reason: an operator-edited file inside it would either fail the entrypoint's check or put the
edit inside the digest every receipt carries, so a routine enrolment or revocation would move the
deployment's attested identity. `meas.m` is a platform launch value, a statement about what runs
rather than a hash of what it is pointed at. What a revocation changes is the answer and the record:
`AUTH_REVOKED` on a proof-of-possession credential whose signature verified, written to the access
log with the credential id it refused, and `AUTH_UNKNOWN` on a bearer one, written with `cred` null
because a bearer request names no id and the refusal invents none. A proof-of-possession request that
names a revoked id without a valid signature is refused as `AUTH_SIGNATURE`, and its line still names
the id it was asked about. A verifier that pins a measurement and a weights
digest pins the software a deployment runs, and not the list of who may call it; that list is the
deployer's, and the log is where its use shows.

## 6. Flags that change the access floor

| Flag | Default | Effect |
|---|---|---|
| `--credentials-path <file>` | required in a live start | The file every request must present a credential from. In `--mock` it is optional, and without it the process holds one credential in memory under the id `dev` and prints its key at start-up. That record is a fixture of a process that refuses nothing real: it exists so a quick start has something to sign with, the key is generated when the process starts and dies with it, and `dev` names nothing outside that run. A live gateway answers from whatever its operator's file holds, and its refusals are built so that a name alone earns no answer about that file |
| `--access-log-path <dir>` | required in a live start | Where the per-request log is written. The value must name an existing directory, so a volume that was not mounted is a refusal rather than a log written onto the root filesystem |
| `--access-log-days <n>` | 184 | How long log files are kept, in days. 184 is the default and the floor the code names, and it is not enforced as a ceiling on the operator's choice: a shorter value starts, and the start-up report says out loud that the run is below the floor (section 8.2) |
| `--pop-tolerance <seconds>` | 120 | Clock slack accepted for a proof-of-possession timestamp, in both directions |
| `--peer-rate perMinute=<n>,burst=<n>` | `perMinute=6000,burst=2000` | The request bound one connection address is held to ahead of every credential check, which section 1 explains: behind one proxy this is the whole deployment sharing one bucket. Both fields are required, each is a whole number of at least 1, and a value that is not stops the start rather than falling back to the default. No value removes the bound, and a large number is the way to stop being shed; the start-up report prints the number the process is holding and says whether it came from this flag. How often this bound refuses is legible on the access log as lines whose `deny` reads `PEER_RATE_LIMITED`, and the count is the whole of what the volume says about it: a line records no address, and the bucket itself is never written down |
| `--receipts-guard-at <percent>` | 100 | The point of the durability bound from which the guard described in section 1 is read while serving rather than only at an opening. Once the store holds this percentage of `--receipts-keep` receipts, a completion is refused `RECEIPT_WINDOW_UNHOLDABLE` ahead of the upstream call if the period configured beside the bound cannot be held at the rate the store's own retained stamps measure. A whole percentage from 1 to 100, and a value that is not one stops the start rather than falling back. 100 is the bound itself, which is the state a store already refuses to open at, so the default changes nothing for a deployment that sets neither flag; a lower number refuses while there is still room, and no number switches the guard off, because nothing sits above the bound for a threshold to reach. The start-up report prints the percentage this process is holding |
| `--receipts-grow-past-guard` | off | The named decision to keep issuing past the guard instead of refusing, and the only spelling that turns the check off. With it the volume grows and the durability bound keeps retiring the oldest prefix, so the window served is the shorter one that bound reaches rather than the period configured beside it, and the shortfall is met at the next restart by the store refusing to open rather than by an answer a caller reads. It overrides `--receipts-guard-at`, and the start-up report says which of the two this process is running |
| `--allow-bearer` | off | Accepts bearer credentials deployment-wide, says so at start-up, and writes `auth=bearer` on every record a bearer secret admitted |

## 7. The access log

One JSON object per line, one line per request this process routes, written whether the request was
admitted or refused; a request the HTTP parser refuses before a route is looked up leaves no line.
The field names are the entire allowlist: the writer reads exactly these keys out of an object, so an
object a future hook learns to assemble cannot widen the record. There is no field for a body, a
header, a key, a secret, or an address to be written into.

The twelve fields, in the order the writer emits them:

| Field | Purpose |
|---|---|
| `t` | Epoch milliseconds at the request's arrival |
| `rid` | Server-generated request id, the join key between a line and a support ticket |
| `cred` | Which credential made the request. A refusal that got as far as reading an id records the id the header carried, known to the file or not, including a name the file does not carry whose response said only that the signature failed; `null` covers the rest, which is a request that named none, a refusal raised before the header's id could be read, and the bearer scan's `AUTH_UNKNOWN` |
| `auth` | `pop`, `bearer`, or `null`. What this request was verified as, so the two postures read differently even in one bearer-capable deployment; `null` on a refusal, since what was verified is the thing the refusal says did not happen |
| `scope` | Which scope the route needed, on a request the pipeline admitted. A refusal records `null`, and the row it was refused against is named in that refusal's own message |
| `m` | The HTTP method |
| `p` | The path only, with the query string dropped: it can carry a report-data challenge and receipt ids |
| `rcp` | The receipt a read route was asked for. Only `GET /v1/receipts/:id` names one in its target, so a completion that issues a receipt records nothing here |
| `nce` | The request's nonce, so a record can be tied to a receipt; `null` on a bearer request, which presents no nonce to record |
| `st` | The HTTP status this gateway answered with |
| `dur` | Request duration in milliseconds |
| `deny` | What this gateway decided the refusal was, on a request the pipeline rejected. This is not always the code the caller was told, and the difference is deliberate: the two part where a refusal is collapsed and where one answer stands for two decisions. An id this file does not carry is answered to its caller as `AUTH_SIGNATURE` and written here as `AUTH_UNKNOWN`, because the line sits inside the trust boundary and the response outside it, and an operator reading a spike needs the reason rather than the cover. The sibling case is a name this file carries as a bearer record, answered to its caller as `AUTH_SIGNATURE` and written here as `AUTH_SCHEME`. The third separation is between two limits rather than two names: a connection that has spent the request bound is answered `RATE_LIMITED`, the very code the credential's own bucket answers with, and written here as `PEER_RATE_LIMITED`. What differs between those two refusals is the operator's fix and not the client's, which is to wait `retry-after` either way, so the reason is recorded where a deployer reads and left out of an answer nobody can act on. It is in no status and no message, and it has no row of its own in `docs/error-codes.md`, whose `RATE_LIMITED` row names it as the deployer's reason and not as something a caller catches, which is what it being a reason rather than an answer means. Nothing the caller can observe changes: the status and the body both carry the collapsed answer. The fourth case on this line is the opposite shape, and it is here because the field is where the two are told apart: a completion refused on the durability guard is answered `RECEIPT_WINDOW_UNHOLDABLE` and written here as that same word, because that refusal is a fact about this deployment which no caller can act on and no wait answers, so it joined the codes a caller branches on rather than staying a reason only a deployer reads. A line whose `deny` names a credential the response never acknowledged is still that credential's record, so the scrub described below erases it on the same instruction |

Deliberately not recorded: request and response bodies, so no prompt and no completion; the
`Authorization` header; bearer secrets; public keys; query strings; source IP; user agent.

Those two omissions carry weight, because a source address and a user agent are personal data, and a
record without them cannot identify a person's location or device. Their absence rests on Recital 49
of the GDPR, which is the processing ground the field allowlist has, and on that recital's own
limiter, "to the extent strictly necessary and proportionate": the allowlist is closed, and a field
that is nice to have in a debugging session is not within that phrase. Article 32(4) reaches people
acting under a controller's or processor's authority, which is the population one credential per
principal attributes; it does not reach every caller of an API, and this document does not claim that
it does. The connection bound in section 1 does not reopen this. It counts requests per address in
memory to decide what this process will spend on one, is never written to a log line, and dies with the
process; the counter is not a record of who connected, and there is no field for it to be recorded into.

### Rotation and retention

Files are named `access-YYYY-MM-DD-NNN.jsonl`. The date is the UTC day of the line's own `t`, the
stamp taken when the request arrived and not when the append runs, so a request that straddles
midnight is filed under the day it began, and a new part begins on that day's boundary and again
when a file passes 32 MiB, so
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
setting that carries across, and leaves a marker named `scrub-<day>-<seq>.jsonl`. The filter is the
`cred` field, so a line this gateway refused without ever acknowledging the name it was given is
erased with the rest: a collapsed refusal still records which credential the request named, and that
record is about the subject even when the response said nothing about it. The marker is the proof
that an erasure ran, which matters for the notification duty in Article 19(1) of the GDPR: the
deployer who erases has to be able to say the erasure happened, and the log's own lines cannot do
that once they are gone. The retention sweep collects markers on their own day's schedule, because a
marker is personal data at the level of a credential id and cannot outlive the window that erased
its subject.
`--request <ref>` records the deployer's own reference for the instruction the run answers, so a later
reader can tell which request a given erasure discharged.

The scrub is a separate program from the gateway that owns the directory, and it is a separate program
in a way that matters to what its output means: it takes no lock, it asks the running gateway for
nothing, and it does not stop that gateway appending while it runs. Section 8.3 states what that costs
and what an erasure does not reach.

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

- **A subject's access request.** Article 15(3) of the GDPR requires a copy of "the personal data
  undergoing processing", so a deployment asked for the log lines about a credential can only produce
  the ones still on the volume. Nothing in the access log's design addresses this, and a longer window
  is a configuration decision, not a code change.
- **Notification after erasure.** Article 19(1) of the GDPR requires the controller to communicate a
  rectification or an erasure to each recipient the personal data has been disclosed to, and the same
  paragraph names a restriction of processing carried out under Article 18 beside them. That duty
  assumes the deployer still knows who received what, which retention against a fixed window can
  erase, and the scrub marker is the artifact that lets an operator prove a removal happened.
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

Two further limits belong to the tool rather than to the log's shape, and they are stated here because a
marker is easy to read as a stronger document than it is.

The first is concurrency. `ashaveri accesslog scrub` is a separate program from the gateway, it holds no
lock, and it does not pause or coordinate with the process appending to the directory. What it does
instead is read a part, compare that part with the bytes at the name in the last instant before it
publishes its rewritten copy over them, and retry a part that moved up to three times. The window that
survives that is the one between the last comparison and the publish, which nothing in the platform's
file interface can be made conditional: an append that lands in it is removed by the publish, is in no
count and under no digest, and is disclosed by no marker. That is why the tool's own guidance is to run
it against a deployment that is not serving, and why a scrub of a live log is a statement about the
records this run saw rather than about every record that existed while it ran.

The second is depth. A scrub removes names, not bytes. A rewritten part is published by renaming a copy
over the original and a part emptied of the subject's records is deleted outright, which drops the
directory entry and frees the space; nothing in this command overwrites the freed blocks or touches the
volume underneath the file system. An image taken before the run still holds the lines, and recovery of
freed blocks on an unencrypted volume can hold them too. Nothing in this document claims otherwise, and
no marker digest is evidence of byte destruction: the digests a marker carries are an account of what
this run read and what it published, which is a claim about a file and not about a volume. Where a
deployer needs the bytes to be unreachable rather than merely unreferenced, that is arranged below this
software, at the volume, by encrypting what the log sits on or sanitising the media when it leaves. The
erasure duty itself belongs to whoever holds it: under Article 17(1) of the GDPR it is the controller's,
and a deployer acting as processor discharges it on the controller's documented instruction. This tool is
what a deployer has for the log, and it is not offered as settling that duty for anyone.

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
