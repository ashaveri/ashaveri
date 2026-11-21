# Multimodal content admission

A chat completion request states what each of its messages carries either as text or as a list of
content parts, and this gateway answers both shapes. The parts a client sends are admitted before the
provider is asked, they are forwarded as the caller wrote them, and the digest a receipt carries is taken
over the bytes that arrived rather than over a reading of them, so an image, an audio clip or a document
inline in a request is inside the evidence the moment the completion is receipted. This document states
which shapes are admitted, which are refused and by what sentence, what the parsed request holds, and
what the mock backend's token figures count. The protocol around a completion, the headers that authorize
it and the payload a receipt signs are specified in [receipt-spec.md](receipt-spec.md), section 4.

## 1. The two shapes a content may take

`gateway/src/mock.ts` parses the body a route received. It reads three things out of that body: whether
`messages` is a list this gateway can answer at all, `model`, and `stream`. A message is an object with a
non-empty string `role` and a `content`, and `content` is one of two shapes:

- a string, which is the text a message states;
- a non-empty array of parts, where a part is a JSON object that states its `type` as a string.

Admission reads nothing of a part besides its `type`, and every other member travels through unchanged.
That is a rule about who owns a grammar: the member names inside an `image_url`, an `input_audio` or a
`file` object belong to the vendor that published them, and a gateway that checked them would be answering
a well-formed request with its own opinion of a grammar it does not hold. The question this gateway asks is
the narrower one of whether the content is text or a list of parts, and section 4 states the one figure a
deployment later takes from a text part.

The part types a client meets in the published shapes are below, with what each of them carries. The
table is a description of what callers send and not a list the admission rule reads: no part type is
named in the code that decides whether a request is served.

| Part type | What the client sends beside it | What this gateway does |
| --- | --- | --- |
| `text` | `text`, a string | Admits the part and keeps its member |
| `image_url` | `image_url`, an object whose `url` is a string, either an address or a `data:` URL carrying base64 bytes | Admits the part and keeps its member |
| `input_audio` | `input_audio`, an object whose `data` and `format` are strings | Admits the part and keeps its member |
| `file` | `file`, an object carrying `file_data` or `file_url`, either of them a string | Admits the part and keeps its member |
| a type not listed above | whatever the caller's vendor defines | Admits the part and keeps every member it arrived with |

A part whose `type` is the empty string is a part with a string type, so it is admitted too. A `role` is
held to a non-empty string because the mock backend writes one into the answer it gives. Admission asks
nothing further of a `type` than that it be a string, and the only code that reads it afterwards is the
metering in section 4, which asks which parts name text: a `type` nobody uses, and an empty one, are a
part that states no text and so adds nothing to a count, while still reaching the deployment whole. A
refusal over such a name would answer a well-formed request with this code's opinion of another vendor's
field names.

## 2. What is still refused, and in what words

Each refusal below is a `RequestError` from the parse, and the completion route turns one into a 400 whose
body is the OpenAI-shaped error object: `error.message` carries the sentence written here, and
`error.type` is `invalid_request_error`. Named codes for the failures of this protocol are tabulated in
[error-codes.md](error-codes.md); a request-shape refusal carries a sentence and no code, because it is
the caller's own body that is wrong and there is nothing for a caller to look up.

| The request | The sentence the 400 carries |
| --- | --- |
| the body parses to something other than an object | `request body must be a JSON object` |
| `messages` is absent, is not an array, or is an empty array | `messages must be a non-empty array` |
| a message is not an object | `each message must be an object` |
| a message's `role` is absent, is not a string, or is empty | `each message must have a non-empty string role` |
| a message's content is neither a string nor an array | `each message must have a string content or an array of content parts` |
| a content array holds no parts | `a content array must hold at least one content part` |
| a part is not an object, including a part written as a string or as null | `each content part must be an object` |
| a part states no `type`, or states one that is not a string | `each content part must have a string type` |
| `model` is present and is not a non-empty string | `model must be a non-empty string` |
| `stream` is present and is not a boolean | `stream must be a boolean` |

Nothing else about a body's shape is refused here. A part with no media member, an `image_url` whose `url`
is a number, and a `file` object that names neither `file_data` nor `file_url` are all served: an upstream
deployment passes such a request to the provider it is pointed at and answers with whatever that provider
returns, and the mock backend meters only the text it can read and states nothing about the rest.

## 3. What the parsed request holds

`ChatMessage.content` is `string | readonly ContentPart[]`, and `ContentPart` states `type` as a string
beside an index signature that carries every other member the caller sent. One field names both shapes
rather than a second field standing beside the first, because two fields would let a message state both
of them or neither, and neither of those is a request anyone sends.

A part is kept as the object that came out of the body, member for member, so no byte a client sent is
read into the parsed value and then left out of it. The parse is no part of a body's serialization: the
digest a receipt carries over the request is taken from the buffer the request arrived in, whatever a
backend does with the bytes afterwards, and the parsed messages are read by the mock backend that meters
an answer. Admission is the whole of what the parse decides about a content, beside the `model` and
`stream` a route also reads out of the body.

## 4. What the mock backend counts

The mock answers a completion it generates itself, and it meters the request it is answering out of the
parsed messages. `promptTokens` is the total character count below divided by four, rounded up, and the
count is of text and nothing else:

- a string content counts its whole length;
- a parts content counts the `text` member of every part whose `type` is `text`, and counts nothing for a
  part that names anything else;
- a `text` part whose `text` member is absent or is not a string contributes no characters.

So a request carrying a PDF inline meters at the number of characters its text parts state, and at
nothing that is a measurement of that file. The mock never opens the media bytes and states no figure
about them, which is the honest position: any number it produced from a base64 string's length would read
as a token count of the document and would be a token count of its encoding at best. A request whose parts
name no text at all meters at zero, and the receipt format carries a zero.

The completion sentence names both figures rather than one, so the number's scope travels with it: a
parts message is answered as `with N characters in X text part(s) beside Y part(s) naming something
else`, where N is the count above. A string content is answered as `with N characters`. The figure
a receipt carries in `tok.p` is the same `promptTokens` the completion's `usage` states.

## 5. What a receipt binds

`req` is SHA-256 over the request bytes exactly as they arrived, so the whole body is inside the claim a
receipt makes, including any media inlined in it. A file a client sent is therefore in the evidence, and
it is there as the bytes that were sent.

One byte changed inside an inline data URL moves `req`. A reader holding the document issued for the
untouched request and the bytes of the changed one finds the two digests disagree, which is the request
binding a client checks after it has verified the signature: the document is authentic and it is about
those other bytes. Two requests differing only inside their media are therefore receipted as two
different claims, and neither receipt can be passed off as the other's.

`gateway/test/multimodal-admission.test.ts` witnesses all of the above: the admitted shapes and the
refusal list read as the code writes them, the mock's figure over a parts request beside the length of
the media it did not count, and a parts request carrying inline base64 receipted over the bytes the test
itself digested.
