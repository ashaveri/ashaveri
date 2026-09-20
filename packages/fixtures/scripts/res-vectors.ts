import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { hashRequest, toBase64Url, toHex } from '@ashaveri/receipt';

const DATA = join(dirname(fileURLToPath(import.meta.url)), '..', 'data');

/** The request `data/req-v1.json` publishes, named so the two files can be checked against each other. */
const REQUEST_BODY = '{"model":"mock-model-1","messages":[{"role":"user","content":"hello"}]}';
const REQUEST_VECTOR = 'gateway-completion-request';

const CONTENT = 'Mock reply: café ☕ served.';
const ID = 'chatcmpl-vector-1';
const CREATED = 1_772_000_000;
const MODEL = 'mock-model-1';
const PREFIX = 'data: ';
const SEPARATOR = '\n\n';
const TERMINATOR = 'data: [DONE]\n\n';

const encoded = (text: string): Uint8Array => new TextEncoder().encode(text);

function chunk(delta: Record<string, unknown>, finishReason: string | null): string {
  return `${PREFIX}${JSON.stringify({
    id: ID,
    object: 'chat.completion.chunk',
    created: CREATED,
    model: MODEL,
    choices: [{ index: 0, delta, finish_reason: finishReason }],
  })}${SEPARATOR}`;
}

function bufferedBody(): string {
  return JSON.stringify({
    id: ID,
    object: 'chat.completion',
    created: CREATED,
    model: MODEL,
    choices: [{ index: 0, message: { role: 'assistant', content: CONTENT }, finish_reason: 'stop' }],
    usage: { prompt_tokens: 9, completion_tokens: 6, total_tokens: 15 },
  });
}

/** A streamed completion as it goes down the wire: content frames, a finish frame, and the terminator. */
function streamedBody(): string {
  return (
    chunk({ role: 'assistant', content: CONTENT.slice(0, 11) }, null) +
    chunk({ content: CONTENT.slice(11, 18) }, null) +
    chunk({ content: CONTENT.slice(18) }, null) +
    chunk({}, 'stop') +
    TERMINATOR
  );
}

/** The frames of the stream above, each written to the socket as one piece. */
function wholeFrames(): readonly Uint8Array[] {
  return streamedBody()
    .split(/(?<=\n\n)/u)
    .filter((frame) => frame.length > 0)
    .map(encoded);
}

/** The same bytes broken at a write boundary that falls inside a multi-byte character. */
function brokenMidCharacter(): readonly Uint8Array[] {
  const bytes = encoded(streamedBody());
  // The first byte of the symbol character, so the first write ends with half of it and the next
  // begins with the rest. No character boundary falls here, which is the whole point.
  const at = bytes.indexOf(0xe2) + 1;
  return [bytes.slice(0, at), bytes.slice(at)];
}

/** The payload texts of the stream above, with every piece of framing stripped off. */
function payloadsOnly(): readonly Uint8Array[] {
  const frames = streamedBody()
    .split(SEPARATOR)
    .filter((frame) => frame.length > 0)
    .map((frame) => frame.slice(PREFIX.length));
  return [encoded(frames.join(''))];
}

interface Case {
  readonly name: string;
  readonly note: string;
  readonly contentType: string;
  /** The body as it is written: one piece, or the several pieces a stream is written in. */
  readonly chunks: () => readonly Uint8Array[];
}

const CASES: readonly Case[] = [
  {
    name: 'buffered-completion',
    note: 'One JSON body, written as one piece. `res` is sha256 over exactly these bytes: no framing a buffered response never had, and no whitespace a prettifier would add.',
    contentType: 'application/json',
    chunks: () => [encoded(bufferedBody())],
  },
  {
    name: 'buffered-completion-trailing-newline',
    note: 'The body above with a single newline appended at its tail. Two responses that differ by one byte at the end have two `res` values, and no JSON equivalence closes that gap.',
    contentType: 'application/json',
    chunks: () => [encoded(`${bufferedBody()}\n`)],
  },
  {
    name: 'streamed-frames',
    note: 'A streamed completion as the client receives it: every `data:` prefix, every blank-line separator and the terminating `data: [DONE]` line are inside the hashed bytes. Hashing the payloads instead gives the value published under streamed-payloads-without-framing, which is a different digest of different bytes.',
    contentType: 'text/event-stream',
    chunks: wholeFrames,
  },
  {
    name: 'streamed-frames-split-mid-character',
    note: 'Byte for byte the response above, written in two pieces that break inside the three bytes of a symbol character. The digest is of the stream and not of the writes, so this vector and streamed-frames carry the same `res`; a port that hashes each write on its own, or decodes before hashing, disagrees.',
    contentType: 'text/event-stream',
    chunks: brokenMidCharacter,
  },
  {
    name: 'streamed-payloads-without-framing',
    note: 'The same payload texts stripped of their framing, published so the difference is checkable rather than asserted: one text, two byte strings, two digests, and only the framed one is what a receipt claims.',
    contentType: 'text/event-stream',
    chunks: payloadsOnly,
  },
];

function concat(parts: readonly Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

const vectors = CASES.map((each) => {
  const chunks = each.chunks();
  const bytes = concat(chunks);
  return {
    name: each.name,
    note: each.note,
    contentType: each.contentType,
    request: REQUEST_VECTOR,
    requestBase64Url: toBase64Url(encoded(REQUEST_BODY)),
    // The bytes as written, piece by piece, so a port can reproduce a completion that arrives in
    // arbitrary pieces rather than only one that arrives whole.
    chunksBase64Url: chunks.map((part) => toBase64Url(part)),
    responseBase64Url: toBase64Url(bytes),
    responseByteLength: bytes.length,
    resHex: toHex(hashRequest(bytes)),
  };
});

writeFileSync(
  join(DATA, 'res-v1.json'),
  `${JSON.stringify(
    {
      version: 1,
      description:
        'The response digest a receipt carries in `res`, published as (exact response bytes, expected digest) pairs for both shapes of a completion. `res` is sha256 over the response body exactly as transmitted. For a streamed completion that includes the framing itself: every `data:` prefix, every blank-line frame separator, and the terminating `data: [DONE]` line are hashed as the bytes the client received. Concatenating the payloads and hashing the result is wrong, and hashing each write on its own is wrong in a different way.',
      rule: {
        receiptField: 'res',
        algorithm: 'sha256',
        input: 'the response body bytes exactly as transmitted, framing included',
        encoding: 'lowercase hex, 64 characters',
        computedBefore: 'event parsing',
      },
      framing: {
        contentType: 'text/event-stream',
        fieldPrefix: PREFIX,
        frameSeparator: SEPARATOR,
        terminator: TERMINATOR,
        note: 'How a completion is framed on its way to a client. A receipt is not bound to this spelling: `res` commits to whatever bytes were transmitted, and these vectors were transmitted this way.',
      },
      vectors,
    },
    null,
    2,
  )}\n`,
);

console.log(`${join(DATA, 'res-v1.json')}: ${String(vectors.length)} vectors`);
