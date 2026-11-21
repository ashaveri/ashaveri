# The file anchor (file-anchor-v1)

A file anchor is one member of a request body. It states that the client that wrote the request
digested a file before it sent anything, and it states what that digest was.

It is an evidence field and nothing more: it is not a verdict about anything outside the request, and it
proves no fact about the file itself. What it does is reach an offline verifier: a request the receipt
digests carries the claim, so a stranger holding the receipt and the file can check the two against each
other for a file whose bytes never passed through anybody's gateway.

## The member

One top-level member, namespaced so that no provider's grammar owns it:

```json
{
  "ashaveri": {
    "file": { "sha256": "<64 lowercase hex>", "bytes": 1382400, "media_type": "audio/wav" }
  }
}
```

| Field | Statement |
| --- | --- |
| `sha256` | sha256 of the file's bytes, written as sixty-four lowercase hex characters. |
| `bytes` | The decoded length of those bytes, as a whole number a JSON reader reproduces exactly. |
| `media_type` | What the client says the bytes are. Declared, never weighed: nothing in this estate opens a media type. |
| `name` | Absent unless the client chooses to disclose a filename. A name is personal data about whoever saved the file, so the field is written only by a caller that decided to write it. |

The shape is stated by this page, by the writer that produces it and by the reader that weighs it. There
is no CDDL for it and no JSON schema for it, and that is deliberate: the member is not a document
anybody signs, it is a claim inside a document that is. A layout change takes a new spelling of the
member rather than a quiet widening of this one, because the digest a receipt already carries covers the
old bytes exactly as written.

## What it proves, and the two things it does not

The anchor proves one thing: **this request carried this claimed digest.**

It does not prove that the digest is the digest of the file a person held. It does not prove that the
provider read that file. Both readings are open to anybody who reads the field, and the second one is
the tempting one, so they are stated here in the order that cannot be misread:

- A verifier holding the file recomputes and compares. Agreement says the claim and the bytes in hand
  go together. It still does not say the bytes came from anywhere in particular, and nothing in the
  receipt says they did.
- A verifier holding only the receipt, or only the claim, can say the claim was made inside a signed
  request. That is a fact about the request. It is not a fact about the file, and it is not a
  refutation of a claim that the file was something else.

A claim can be made about a file that does not exist, and it will anchor just as well. The value of the
field is that the claim cannot afterwards be quietly changed, not that a claim was ever true.

## The three answers a verifier gets

`verifyFileAnchor` in `@ashaveri/receipt` takes the request body and the bytes a verifier was handed,
and answers one of three named results. It throws for none of them.

| Result | When it is the answer | What it is not |
| --- | --- | --- |
| `match` | The body states a claim in this shape, and the digest and the byte count both equal what these bytes are. | Not a statement that the file is genuine, nor that anybody read it. |
| `mismatch` | The body states a claim and these bytes are not it. Also the answer when the claim is stated in a shape no reader can weigh: a digest that is not sixty-four lowercase hex, a length that is a fraction or past what a JSON reader holds exactly, a length of nothing, a media type that is not text or declares nothing. | Not an absence. The claim was made. |
| `absent` | There was no claim to weigh: no member under this namespace, a member holding no `file`, or a body that is not one JSON object. The reason names which. | Not a refutation. A receipt whose request stated nothing is not a receipt that contradicts a file. |

The reader refuses the two claims the writer refuses, a length of nothing and a media type of
nothing, rather than weighing them. A verifier that reached `match` over a member no client can
state would be reporting an agreement about a document that cannot exist, so the answer is the
named disagreement above. `packages/sdk/test/file-anchor.test.ts` holds the case that fails if the
two lists ever drift apart.

`absent` is refused as a spelling of `mismatch` on purpose. Reporting the two as one answer would let a
request that never mentioned a file read as a request that misdescribed one, which is the difference
between silence and a contradiction, and the only difference an offline reader is asked to care about.

The digest and the length are both weighed. A claim naming the right sixty-four characters and the
wrong byte count is about two different files, and a reader that matched on the digest alone would be
reporting exactly the reading this field must not support.

## Where the claim is written, and where it stops

The client's helper is `fileAnchor` in `@ashaveri/sdk`. It takes the bytes and a declared media type,
computes the digest with the same sha256 the verifier will recompute with, refuses an input of no bytes
and a length no JSON reader reproduces exactly, and returns the member. It sends nothing, so the same
claim covers a file that travels inside the request and a file that travelled out of band to a
provider's upload endpoint and came back as an identifier.

The gateway reads none of it. A chat completion request is parsed for `model`, `messages` and `stream`,
and the digest a receipt signs is taken over the whole bytes the deployment read, which are the bytes the
client wrote. That is why a claim in the body is inside the signed evidence without any gateway change,
and why there is none here.

What the deployment then hands its upstream is one of two things, and they differ, so both are stated.
A buffered request goes on as the bytes that arrived, member and all. A streamed request goes through a
metering rewrite first: `gateway/src/upstream.ts` parses the body, adds a `stream_options` member asking
for a usage frame, and re-serializes, unless the request already asked for that frame. The claim
survives that rewrite, because the rewrite carries every member it did not read, but the text the
provider parses is no longer the text `req` digests, which is a fact about the whole streamed body and
not about this field. The same sentence the stripping case earns is the one that covers it: where a
deployment hands an upstream bytes other than the ones it digested, the request digest binds a body the
provider did not receive.

The two paths a client can take are different code and are measured separately, in
`packages/sdk/test/file-anchor-transport.test.ts`: the wrapper of an official client hands on the body
text it was given and changes only headers, and this repository's own client builds its body by
serializing the caller's params. Both reach the wire carrying the member. The wrapper is measured with a
body written by hand rather than by a serializer, so a transport that re-serialized on the way through
would arrive as different text and move the digest rather than as the same text written a different way.

The top-level name is the one a marked response also writes into. The two are not the same member and
neither reader borrows the other: the marking rule reads a `marking` object of a scheme it names and
refuses to see anything else under the name, and this reader does the mirror of that.

## Whether an upstream tolerates the member is not measured here

Every provider a deployment talks to is somebody else's grammar, and whether each of them accepts an
unknown top-level member of a chat completion request is unmeasured by this repository. Nothing here
promises that none will refuse it. The risk in one line: the claim is a member of a body a provider
parses, and a provider that refuses what it cannot parse refuses the request.

What a refusal looks like, and what to do about it. It surfaces as an upstream error on the completion,
which the client reports as a failed request: the request either goes through carrying the claim or it
does not go through, and the field is never quietly dropped on the way out by anything shipped here. So
the deployment has a choice to make per route, and the three that exist do not all keep the same
evidence:

- Keep sending it, and treat the refusal as the route being unusable for anchored traffic.
- Stop sending it on that route. Receipts for that traffic then carry no claim to weigh, which is the
  honest answer an offline verifier gets.
- Send the file's own bytes in the body instead of a digest of bytes the provider resolves later. Then
  the digest covers content the provider parses, and the question of tolerance goes away at the cost of
  moving the file's bytes through a gateway, which is the thing this field exists to avoid.

A deployment that strips the member on its way to an upstream is the case a reader has to be warned
about, and the warning is one sentence: if a deployment strips the member to keep an upstream happy, the
request digest then binds a body the provider did not receive. The two variants fail differently, which
is why both are named. Stripping after the digest is taken is invisible to a client and defeats the
field's purpose, since the signed evidence now covers bytes nobody upstream was handed. Stripping before
the digest is taken breaks the client's own check instead: the SDK compares the request it sent against
the digest the receipt carries, and a body whose claim has been removed is a different body, so such a
deployment fails its verifications loudly rather than quietly.

## Where the code lives

| Part | File | Names |
| --- | --- | --- |
| The client's claim | `packages/sdk/src/file-anchor.ts` | `fileAnchor`, re-exported from the package entry with `FILE_ANCHOR_MEMBER_NAME` and `FILE_ANCHOR_CLAIM_MEMBER_NAME`. |
| The verifier's weighing | `packages/receipt/src/file-anchor.ts` | `verifyFileAnchor`, the three result shapes and the two member names. |
| The transport measurements | `packages/sdk/test/file-anchor-transport.test.ts` | What a body carries to the wire, on both client paths, and what it does to the request digest. |
| The reader's answers | `packages/receipt/test/file-anchor.test.ts` | Match, mismatch, absence, and the shapes that cannot be weighed. |

A caller that wants the claim in its own body writes it there; a verifier that wants to weigh it needs
the request body and the file, and needs to know that the body it holds is the one whose digest the
receipt carries. That last check belongs to whoever runs the verification, and it is the one check this
field cannot do for anybody: an anchor read out of a body nobody bound is a sentence somebody typed.
