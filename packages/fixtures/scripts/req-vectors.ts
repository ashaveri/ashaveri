import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { hashRequest, toBase64Url, toHex } from '@ashaveri/receipt';

const DATA = join(dirname(fileURLToPath(import.meta.url)), '..', 'data');

/**
 * The completion body `pop-vectors.ts` signs, restated here as bytes rather than as a signature.
 * Both files then name one set of request bytes: `pop-v1.json` proves what digest of them goes into
 * a proof-of-possession signing string, and this file proves what digest of them a receipt carries
 * in `req`. Neither claim is checkable against the other until a reader holds both, which is the
 * point of publishing them as two files instead of one.
 */
const POP_COMPLETION_BODY =
  '{"model":"meta-llama/Llama-3.1-8B-Instruct","messages":[{"role":"user","content":"hello"}]}';
const POP_STREAM_BODY =
  '{"model":"meta-llama/Llama-3.1-8B-Instruct","messages":[{"role":"user","content":"hello"}],"stream":true}';
/** The body a gateway in this repository actually serves, so a response vector can be asked with it. */
const GATEWAY_REQUEST_BODY = '{"model":"mock-model-1","messages":[{"role":"user","content":"hello"}]}';
const NON_ASCII_BODY =
  '{"model":"meta-llama/Llama-3.1-8B-Instruct","messages":[{"role":"user","content":"héllo 你好 ☕"}]}';
/** The completion body with spaces added around its punctuation: one object, different bytes. */
const REFORMATTED_BODY =
  '{ "model" : "meta-llama/Llama-3.1-8B-Instruct", "messages" : [ { "role" : "user", "content" : "hello" } ] }';
/** A body whose only content is a newline and a tab, which a text-mode reader can lose. */
const CONTROL_BODY = '{"model":"mock-model-1","messages":[{"role":"user","content":"a\\nb\\tc"}]}';

interface Case {
  readonly name: string;
  readonly note: string;
  readonly body: string;
}

const CASES: readonly Case[] = [
  {
    name: 'buffered-completion',
    note: 'The exact bytes data/pop-v1.json signs for its completion-post vector. The two files state the same digest of the same bytes, so each one checks the other.',
    body: POP_COMPLETION_BODY,
  },
  {
    name: 'streaming-request',
    note: 'A stream request is a body like any other: `stream` is a member of it, and the digest covers it as written.',
    body: POP_STREAM_BODY,
  },
  {
    name: 'empty-body',
    note: 'sha256 of nothing. A bodyless route signs this value, and a receipt over a request with no body claims it, so a port that never hashes an empty input gets both wrong at once.',
    body: '',
  },
  {
    name: 'non-ascii-content',
    note: 'Accented, CJK and symbol characters in one content string. The digest is of the UTF-8 bytes, so a port that hashes the character count, the code points, or a locale-encoded copy of this text will not agree with the published value.',
    body: NON_ASCII_BODY,
  },
  {
    name: 'control-characters',
    note: 'A newline and a tab written as JSON escapes, which are two ASCII backslash sequences on the wire and not the characters they stand for.',
    body: CONTROL_BODY,
  },
  {
    name: 'same-object-reformatted',
    note: 'Parses to the same object as buffered-completion and differs from it by bytes alone. Two bodies that a JSON reader cannot tell apart still produce two different req values.',
    body: REFORMATTED_BODY,
  },
  {
    name: 'gateway-completion-request',
    note: 'The request every data/res-v1.json vector is served to. It appears here so the response suite can be read without a request digest copied from somewhere else.',
    body: GATEWAY_REQUEST_BODY,
  },
];

const vectors = CASES.map((each) => {
  const bytes = new TextEncoder().encode(each.body);
  return {
    name: each.name,
    note: each.note,
    bodyBase64Url: toBase64Url(bytes),
    bodyByteLength: bytes.length,
    reqHex: toHex(hashRequest(bytes)),
  };
});

writeFileSync(
  join(DATA, 'req-v1.json'),
  `${JSON.stringify(
    {
      version: 1,
      description:
        'The request digest a receipt carries in `req`, published as (exact request bytes, expected digest) pairs. Every byte of `req` is sha256 over the request body as transmitted, before any parsing and independent of it: a body that decodes to the same object but differs by one byte has a different `req`. The input is the whole body, the empty body included, and it is hashed as octets, never as text in whatever encoding the reader happens to hold.',
      rule: {
        receiptField: 'req',
        algorithm: 'sha256',
        input: 'the request body bytes exactly as transmitted',
        encoding: 'lowercase hex, 64 characters',
        computedBefore: 'json-parse',
      },
      vectors,
    },
    null,
    2,
  )}\n`,
);

console.log(`${join(DATA, 'req-v1.json')}: ${String(vectors.length)} vectors`);
