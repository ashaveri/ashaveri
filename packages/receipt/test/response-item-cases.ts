/**
 * The material the response-item framing is checked against, in one place because two suites read it.
 *
 * `response-items.test.ts` asks what these bodies frame to, and `response-items-split.test.ts` asks
 * whether the answer depends on how the bytes were delivered. The second question is only worth asking
 * if the first has an answer written down somewhere else, so the expected payloads and their digests
 * live here and neither suite derives them from the code under test.
 *
 * Every digest below is a literal. Each one was produced over the bytes the case names by `node:crypto`,
 * which is a second SHA-256 implementation next to the `@noble/hashes` one the framing uses, and none
 * of them was produced by running this repository's code. A match is therefore agreement between two
 * implementations over fixed bytes, which is what a claim about a digest has to rest on: a test that
 * hashed the same bytes with the same library would only have measured one code twice.
 */

import { toHex, type ResponseItemFraming } from '../src/index.js';

/** One response, as its bytes were transmitted, and the items the rule says are in it. */
export interface FrameCase {
  readonly name: string;
  /** The declared content type, which is the only thing that decides framing. */
  readonly contentType: string;
  /** The whole response body, written out as the text it decodes to; the bytes are UTF-8. */
  readonly body: string;
  /**
   * The payload of every item, in order, as the text each one decodes to. Empty when the case is a
   * refusal, which is a stream that sent no frame at all.
   */
  readonly items: readonly string[];
}

export const STREAMED = 'text/event-stream';
export const BUFFERED = 'application/json';

/**
 * What the framing says about a stream that sent no frame, which two suites have to answer the same way:
 * `response-items.test.ts` reads it out of the refusal, and the split suite compares a piecewise run
 * against it, because a rule that refused at one split and answered an empty list at another would be
 * the very dependence on transport this framing exists to remove.
 */
export const NO_FRAME_REASON = 'the response sent no data frame, so it states nothing for an item to attest';

export const FRAME_CASES: readonly FrameCase[] = [
  {
    name: 'three frames, the last of them the sentinel',
    contentType: STREAMED,
    body: 'data: {"a":1}\n\ndata: {"b":2}\n\ndata: [DONE]\n\n',
    items: ['{"a":1}', '{"b":2}'],
  },
  {
    name: 'a final frame whose terminator never arrived',
    contentType: STREAMED,
    body: 'data: {"a":1}\n\ndata: {"b":2}',
    items: ['{"a":1}', '{"b":2}'],
  },
  {
    name: 'one frame and nothing else',
    contentType: STREAMED,
    body: 'data: {"a":1}',
    items: ['{"a":1}'],
  },
  {
    name: 'CRLF terminators, sentinel without its trailing blank line',
    contentType: STREAMED,
    body: 'data: {"a":1}\r\n\r\ndata: [DONE]',
    items: ['{"a":1}'],
  },
  {
    name: 'CRLF terminators throughout',
    contentType: STREAMED,
    body: 'data: {"a":1}\r\n\r\ndata: {"b":2}\r\n\r\ndata: [DONE]\r\n\r\n',
    items: ['{"a":1}', '{"b":2}'],
  },
  {
    name: 'a bare carriage return ends a frame, including the last one of the response',
    contentType: STREAMED,
    body: 'data: {"a":1}\rdata: {"b":2}\r',
    items: ['{"a":1}', '{"b":2}'],
  },
  {
    name: 'a carriage return after a terminated frame ends a line of no bytes',
    contentType: STREAMED,
    body: 'data: {"a":1}\n\rdata: {"b":2}\n\n',
    items: ['{"a":1}', '{"b":2}'],
  },
  {
    name: 'the sentinel ended by a bare carriage return',
    contentType: STREAMED,
    body: 'data: [DONE]\r',
    items: [],
  },
  {
    name: 'an empty data payload, with and without the space',
    contentType: STREAMED,
    body: 'data:\n\ndata: \n\ndata: {"b":2}\n\n',
    items: ['', '', '{"b":2}'],
  },
  {
    name: 'the sentinel mid-stream, with frames after it',
    contentType: STREAMED,
    body: 'data: {"a":1}\n\ndata: [DONE]\n\ndata: {"b":2}\n\n',
    items: ['{"a":1}', '{"b":2}'],
  },
  {
    name: 'a sentinel near miss is content',
    contentType: STREAMED,
    body: 'data: [DONE]\n\ndata: [DONE ]\n\ndata: [DONE\n\n',
    items: ['[DONE ]', '[DONE'],
  },
  {
    name: 'a stream that ends inside a payload',
    contentType: STREAMED,
    body: 'data: {"a":1}\n\ndata: {"b"',
    items: ['{"a":1}', '{"b"'],
  },
  {
    name: 'fields that are not data, and a comment',
    contentType: STREAMED,
    body: 'event: ping\nid: 7\ndata: {"a":1}\n\n: keep-alive\ndata: {"b":2}\n\n',
    items: ['{"a":1}', '{"b":2}'],
  },
  {
    name: 'two data lines in one block are two frames',
    contentType: STREAMED,
    body: 'data: {"a":1}\ndata: {"b":2}\n\n',
    items: ['{"a":1}', '{"b":2}'],
  },
  {
    name: 'the field name with no space, then with two',
    contentType: STREAMED,
    body: 'data:{"a":1}\n\ndata:  {"b":2}\n\n',
    items: ['{"a":1}', ' {"b":2}'],
  },
  {
    name: 'a stream that sent only the sentinel',
    contentType: STREAMED,
    body: 'data: [DONE]\n\n',
    items: [],
  },
  {
    name: 'a stream that sent nothing',
    contentType: STREAMED,
    body: '',
    items: [],
  },
  {
    name: 'a stream of framing and no data frame',
    contentType: STREAMED,
    body: '\n\nid: 7\nevent: ping\n\n',
    items: [],
  },
  {
    name: 'a buffered completion',
    contentType: BUFFERED,
    body: '{"id":"x","choices":[]}',
    items: ['{"id":"x","choices":[]}'],
  },
  {
    name: 'a buffered body that happens to look like frames',
    contentType: BUFFERED,
    body: 'data: {"a":1}\n\ndata: [DONE]\n\n',
    items: ['data: {"a":1}\n\ndata: [DONE]\n\n'],
  },
  {
    name: 'a buffered body of no bytes at all',
    contentType: BUFFERED,
    body: '',
    items: [''],
  },
];

/**
 * sha256 of each payload text above, lowercase hex, over the UTF-8 bytes of the text.
 *
 * `''` is the empty input, whose digest this repository already publishes for another purpose in
 * `EMPTY_BODY_SHA256_HEX`; it is written here as a literal too, so that an item of no bytes is checked
 * against the same value the rest of the estate holds rather than against a recomputation.
 */
export const ITEM_SHA256_HEX: Readonly<Record<string, string>> = {
  '{"a":1}': '015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862',
  '{"b":2}': '0ab1a6d394cd30195f0642b67ae1180c375ffadf5dd7f39c390668b5fdb6da93',
  '': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  ' {"b":2}': 'd550137e6165098ab6487a8a13d1233ef0eb1b16d0f79f81f9fcb139fc78b277',
  '[DONE ]': '8554fa50b104c84fefc2aa7c809ff3a7ddb50bbdbdfd7c5030e24de8fffa3ebf',
  '[DONE': 'f33737cc8a7f3c3d80aff8c9d43f7bc1a8d904c5514e40782056098884f4251a',
  '{"b"': '5f30d1ec207d5e5c998ce2b6fbe0b9581b442e20a5684cbef591c2b25821c32d',
  '{"id":"x","choices":[]}': 'e019ccc7bdbdf9599ee13e21fa6f490a185a01a977a14ffb08076399ce75e2c6',
  'data: {"a":1}\n\ndata: [DONE]\n\n': '9aeb47f386d7cbcec405aaf0909a98141fce39237a411a656ad8695ff028fd46',
};

/**
 * The body of a frame whose whole framing is inside the digest, and the digest of one line with its
 * prefix still on it. Both are witnesses for what an item's `d` does not cover, which is the half of the
 * rule a reader is most likely to get backwards.
 */
export const WHOLE_BODY_SHA256_HEX = 'f6e9d5b89016aba3e6c5cddd69e6fbb649365401a337580b329efcbcddfe71fd';
export const FRAMED_LINE_SHA256_HEX = '47f89d91b5a851f874c3be00995558358078cd2ee81437bb17e96b678081c977';

/** The four chunks of `streamed-frames`, each payload's digest, and the whole body's published `res`. */
export const PUBLISHED_ITEM_SHA256_HEX = [
  '0a016ea80b566b6b007de75041f085677238bc7d85f48debed01fdbc69558e6c',
  'f25f456f8a2adeb8ed6699b4a1d1d13870e9670bb404de909ba2c38ec67d6d2f',
  '1e41fc01008b97e29b17de581478cfd16b1dcd19545460cd89cb0542ea27af47',
  '933953117e02a387095f83ea7096779a0fc33dbac9d4127cf368f22bc5c2ac9d',
] as const;

/** The byte count of the framing the published stream carries outside its four payloads. */
export const PUBLISHED_FRAMING_BYTES = 46;

/**
 * A payload text's digest, from the table above rather than from a hash call.
 *
 * The run stops on a case whose payload was never given a literal, because a comparison against
 * `undefined` would pass for the wrong bytes and fail for the right ones.
 */
export function itemDigestHex(payload: string): string {
  const hex = ITEM_SHA256_HEX[payload];
  if (hex === undefined) throw new Error(`no digest is written down for the payload ${JSON.stringify(payload)}`);
  return hex;
}

/**
 * The whole answer of the framing, as one comparable string: each item's digest and its bytes, or the
 * refusal. Both suites reduce a run to this, so the two questions they ask, what the items are and
 * whether the delivery of the bytes changes them, are answered about the same visible thing.
 */
export function framingText(outcome: ResponseItemFraming): string {
  if (!outcome.framed) return `refused: ${outcome.why}`;
  const decoder = new TextDecoder();
  return outcome.items.map((item) => `${toHex(item.d)}<${decoder.decode(item.bytes)}>`).join('|');
}

/** What the case table publishes for one body, in the same shape, built without touching the framing. */
export function expectedFramingText(caseItem: FrameCase): string {
  if (caseItem.items.length === 0) return `refused: ${NO_FRAME_REASON}`;
  return caseItem.items.map((payload) => `${itemDigestHex(payload)}<${payload}>`).join('|');
}
