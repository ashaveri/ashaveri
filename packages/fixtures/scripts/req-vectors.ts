import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  decodeReceipt,
  hashRequest,
  issueReceipt,
  toBase64Url,
  toHex,
  type ReceiptPayloadV1,
} from '@ashaveri/receipt';
import { fixtureKey, fixturePayload } from './receipt-envelope.ts';

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

/**
 * One body a client holds beside the `req` a receipt attests for it, the two apart by exactly the
 * mistake the row names.
 *
 * The accepted vectors above state what a digest is; these state what a reader owes a digest that is
 * nearly right, which is the half a second implementation is actually measured on. Each row names the
 * vector whose bytes are handed to the client and the vector whose digest is signed into the receipt
 * beside it, so the disagreement is one of the two published byte strings against the other's value
 * rather than a random hex that nothing produces. The refusal is `REQUEST_HASH_MISMATCH`, the answer a
 * client gives when the body it sent is not the body its receipt attests.
 */
interface RefusalCase {
  readonly name: string;
  readonly note: string;
  /** The published vector whose bytes the client holds. */
  readonly held: string;
  /** The published vector whose digest the receipt attests instead. */
  readonly claimed: string;
  readonly code: 'REQUEST_HASH_MISMATCH';
}

const REFUSALS: readonly RefusalCase[] = [
  {
    name: 'req-of-the-reformatted-bytes',
    note: 'The body a client sent is the reformatted one, and the receipt attests the digest of the compact spelling. The two parse to the same object, which is exactly why the pair is refused: a port that hashed the body after parsing it and writing it out again produced a `req` for bytes no one transmitted.',
    held: 'same-object-reformatted',
    claimed: 'buffered-completion',
    code: 'REQUEST_HASH_MISMATCH',
  },
  {
    name: 'req-of-the-buffered-spelling',
    note: 'A streamed request presented against a receipt digesting the same body without its `stream` member. The bodies differ by one JSON member and nothing else, so this is the near miss a client that normalised its own request before hashing would ship itself into.',
    held: 'streaming-request',
    claimed: 'buffered-completion',
    code: 'REQUEST_HASH_MISMATCH',
  },
];

/**
 * The signed document one refusal is stated in: a v1 receipt over the bytes the client does not hold,
 * issued under the key `data/keys/receipt-key-v1.json` publishes.
 *
 * The `res` of these documents is the envelope's own value rather than a digest of any response, which
 * is what keeps this suite about one input: the harness hands the client the response digest the receipt
 * states and the bytes it does hold on the request side, so the only rule that can refuse is the one
 * over `req`.
 */
function refusalReceipt(claimed: string): { receiptBase64Url: string; receiptSha256Hex: string } {
  const source = vectors.find((each) => each.name === claimed);
  if (source === undefined) throw new Error(`req-v1.json states no vector named ${claimed}`);
  const payload: ReceiptPayloadV1 = {
    ...fixturePayload({ req: new Uint8Array(Buffer.from(source.reqHex, 'hex')) }),
    v: 1,
  };
  const bytes = issueReceipt(payload, fixtureKey());
  const decoded = decodeReceipt(bytes);
  if (toHex(decoded.payload.req) !== source.reqHex) {
    throw new Error(`the receipt issued for ${claimed} does not carry the digest this row attests`);
  }
  return { receiptBase64Url: toBase64Url(bytes), receiptSha256Hex: toHex(sha256(bytes)) };
}

const refusals = REFUSALS.map((each) => {
  const held = vectors.find((vector) => vector.name === each.held);
  const claimed = vectors.find((vector) => vector.name === each.claimed);
  if (held === undefined || claimed === undefined) {
    throw new Error(`${each.name} names a vector this file does not publish`);
  }
  // The row is only a near miss if these two bodies are distinct bytes with distinct digests: a pair
  // that happened to agree would state a refusal nothing can reach.
  if (held.bodyBase64Url === claimed.bodyBase64Url || held.reqHex === claimed.reqHex) {
    throw new Error(`${each.name}: ${each.held} and ${each.claimed} are not the near miss this row claims`);
  }
  return {
    name: each.name,
    note: each.note,
    heldVector: each.held,
    claimedVector: each.claimed,
    bodyBase64Url: held.bodyBase64Url,
    bodyByteLength: held.bodyByteLength,
    claimedReqHex: claimed.reqHex,
    code: each.code,
    ...refusalReceipt(each.claimed),
  };
});

writeFileSync(
  join(DATA, 'req-v1.json'),
  `${JSON.stringify(
    {
      version: 1,
      description:
        'The request digest a receipt carries in `req`, published as (exact request bytes, expected digest) pairs. Every byte of `req` is sha256 over the request body as transmitted, before any parsing and independent of it: a body that decodes to the same object but differs by one byte has a different `req`. The input is the whole body, the empty body included, and it is hashed as octets, never as text in whatever encoding the reader happens to hold. `refusals` are the near misses: a body a client holds beside a signed receipt attesting the digest of another vector of this file, with the code the client owes for that pair.',
      rule: {
        receiptField: 'req',
        algorithm: 'sha256',
        input: 'the request body bytes exactly as transmitted',
        encoding: 'lowercase hex, 64 characters',
        computedBefore: 'json-parse',
      },
      vectors,
      refusals,
    },
    null,
    2,
  )}\n`,
);

console.log(
  `${join(DATA, 'req-v1.json')}: ${String(vectors.length)} vectors, ${String(refusals.length)} refusals`,
);
