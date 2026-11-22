import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import type { HTTPMethods } from 'fastify';
import { decodeReceipt, hashRequest, toHex, type ReceiptPayload } from '@ashaveri/receipt';
import { mockDeployment } from '../src/deployment.js';
import { parseChatCompletionRequest, readChatCompletionHead, RequestError } from '../src/mock.js';
import { generated, harness, type Harness } from './helpers.js';

/**
 * The scan that reads a route's two fields off a request's bytes and the parse that builds the message
 * graph behind them answer one grammar, so this file puts the same body to both and refuses the two
 * answers disagreeing.
 *
 * What a route reads decides an arm and a model, and what it does not read still has to be refused when it
 * is malformed, because a body this gateway forwards is a body it told the caller nothing about. A scan
 * that let a shape the parse refuses reach an inference server would widen what this deployment admits
 * without saying so, and one that refused a shape the parse admits would narrow it. Either way the
 * disagreement is the finding, so it is settled by comparison rather than by examples that could stop
 * being the grammar the parse holds.
 */

/** What the scan makes of a body: the two fields, or the sentence it answers with. */
function scanAnswer(text: string): string {
  try {
    const head = readChatCompletionHead(Buffer.from(text, 'utf8'));
    return `ok:${JSON.stringify({ model: head.model, stream: head.stream })}`;
  } catch (err) {
    return err instanceof RequestError ? `refuse:${err.message}` : 'invalid-json';
  }
}

/** What the parse makes of the same body, reached the way the route reached it before the scan existed. */
function parseAnswer(text: string): string {
  let written: unknown;
  try {
    written = JSON.parse(text);
  } catch {
    return 'invalid-json';
  }
  try {
    const parsed = parseChatCompletionRequest(written);
    return `ok:${JSON.stringify({ model: parsed.model, stream: parsed.stream })}`;
  } catch (err) {
    return err instanceof RequestError ? `refuse:${err.message}` : 'invalid-json';
  }
}

/** One body, both readers, and a failure naming the body rather than echoing a grammar back. */
function agree(text: string, why: string): void {
  expect(scanAnswer(text), `${why}: ${JSON.stringify(text.slice(0, 200))}`).toBe(parseAnswer(text));
}

const M = 'mock-model-1';
const OK = `{"model":"${M}","messages":[{"role":"user","content":"hello"}]}`;

/**
 * A body that names the route's fields twice over: once as text a caller wrote, and once as real JSON
 * members at a depth the route reads nothing of, and writes the answer behind both.
 *
 * The order and the two forms are the point. Inside a message's text the quotes arrive escaped, so a
 * search for the bare characters misses them; inside a nested member they arrive as JSON, and a search
 * that walked the bytes instead of the grammar would settle on `other-model` and on the arm this caller
 * did not ask for. The members that decide are written last.
 */
function trapBody(stream: boolean): string {
  return JSON.stringify({
    messages: [
      {
        role: 'user',
        content:
          'read this text and weigh it not: "model":"not-served", "stream":' +
          String(!stream) +
          ', "messages":[7], and "model": ""',
      },
      {
        role: 'assistant',
        content: [
          { type: 'text', text: '{"model":"other","stream":false}' },
          { type: 'image_url', image_url: { url: `data:image/png;base64,${'A'.repeat(4096)}` } },
        ],
        model: 'not-served',
        stream: !stream,
        metadata: { model: 'other-model', stream: !stream, messages: [7], model2: '' },
      },
    ],
    model: M,
    stream,
  });
}

/** The bodies every sentence on this grammar belongs to, and the shapes that carry no sentence. */
const CORPUS: readonly (readonly [string, string])[] = [
  ['the shipped mock body', OK],
  ['the same body asking for a stream', `{"model":"${M}","messages":[{"role":"user","content":"hello"}],"stream":true}`],
  ['a body naming no model', '{"messages":[{"role":"user","content":"hi"}]}'],
  ['a body naming no stream', `{"messages":[{"role":"a","content":"b"}],"stream":false}`],
  ['an empty object', '{}'],
  ['a body that is a list', '[]'],
  ['a body that is a list of messages', '[{"role":"user","content":"hi"}]'],
  ['a body that is a number', '7'],
  ['a body that is text', '"hello"'],
  ['a body that is null', 'null'],
  ['a body that is a bare word', 'true'],
  ['a body that is nothing at all', ''],
  ['a body that is not JSON', '{not json'],
  ['bytes after the object', `${OK} x`],
  ['a comma after the last member', '{"messages":[{"role":"a","content":"b"}],}'],
  ['a body with no messages', `{"model":"${M}"}`],
  ['messages that is text', `{"model":"${M}","messages":"hello"}`],
  ['messages that is empty', `{"model":"${M}","messages":[]}`],
  ['messages that is an object', `{"model":"${M}","messages":{}}`],
  ['a message that is text', `{"model":"${M}","messages":["a string"]}`],
  ['a message that is null', `{"model":"${M}","messages":[null]}`],
  ['a message that is a number', `{"model":"${M}","messages":[7]}`],
  ['a message that is a list', `{"model":"${M}","messages":[["role","user"]]}`],
  ['a message with no role', `{"model":"${M}","messages":[{}]}`],
  ['a message with an empty role', `{"model":"${M}","messages":[{"role":"","content":"hi"}]}`],
  ['a message whose role is a number', `{"model":"${M}","messages":[{"role":7,"content":"hi"}]}`],
  ['a message whose role is null', `{"model":"${M}","messages":[{"role":null,"content":"hi"}]}`],
  ['a role written out of escapes', `{"model":"${M}","messages":[{"role":"\\u0075ser","content":"hi"}]}`],
  ['a role that escapes decode to one character', `{"model":"${M}","messages":[{"role":"\\u0000","content":"hi"}]}`],
  ['a message with no content', `{"model":"${M}","messages":[{"role":"user"}]}`],
  ['a message whose content is a number', `{"model":"${M}","messages":[{"role":"user","content":7}]}`],
  ['a message whose content is an object', `{"model":"${M}","messages":[{"role":"user","content":{}}]}`],
  ['a message whose content is null', `{"model":"${M}","messages":[{"role":"user","content":null}]}`],
  ['an empty part list', `{"model":"${M}","messages":[{"role":"user","content":[]}]}`],
  ['a part that is text', `{"model":"${M}","messages":[{"role":"user","content":["hello"]}]}`],
  ['a part that is null', `{"model":"${M}","messages":[{"role":"user","content":[null]}]}`],
  ['a part that is a list', `{"model":"${M}","messages":[{"role":"user","content":[["type","text"]]}]}`],
  ['a part naming no type', `{"model":"${M}","messages":[{"role":"user","content":[{"text":"hi"}]}]}`],
  ['a part whose type is a number', `{"model":"${M}","messages":[{"role":"user","content":[{"type":7}]}]}`],
  ['a part whose type is empty', `{"model":"${M}","messages":[{"role":"user","content":[{"type":""}]}]}`],
  ['a part whose type is null', `{"model":"${M}","messages":[{"role":"user","content":[{"type":null}]}]}`],
  ['a model that is a number', `{"messages":[{"role":"a","content":"b"}],"model":7}`],
  ['a model that is empty', `{"messages":[{"role":"a","content":"b"}],"model":""}`],
  ['a model that is null', `{"messages":[{"role":"a","content":"b"}],"model":null}`],
  ['a model that is an object', `{"messages":[{"role":"a","content":"b"}],"model":{}}`],
  ['a stream that is text', `{"messages":[{"role":"a","content":"b"}],"stream":"yes"}`],
  ['a stream that is null', `{"messages":[{"role":"a","content":"b"}],"stream":null}`],
  ['a stream that is a number', `{"messages":[{"role":"a","content":"b"}],"stream":1}`],
  ['a stream spelled with spaces', '{"messages":[{"role":"a","content":"b"}] , "stream" : true}'],
  ['members in the other order', `{"stream":true,"messages":[{"content":"hi","role":"user"}],"model":"${M}"}`],
  ['the model named twice, read as its last value', `{"model":"first","model":"${M}","messages":[{"role":"a","content":"b"}]}`],
  ['the last model malformed', `{"model":"${M}","model":7,"messages":[{"role":"a","content":"b"}]}`],
  ['the stream named twice', '{"messages":[{"role":"a","content":"b"}],"stream":true,"stream":false}'],
  ['the messages named twice and the last one malformed', '{"messages":[{"role":"a","content":"b"}],"messages":[]}'],
  [
    'a part carrying an inline file and a nested object',
    `{"model":"${M}","messages":[{"role":"user","content":[{"type":"image_url",` +
      `"image_url":{"url":"data:image/png;base64,${'A'.repeat(2048)}"},"extra":{"a":[1,2,{"b":null}]}}]}]}`,
  ],
  [
    'a member this gateway reads nothing of',
    `{"model":"${M}","messages":[{"role":"user","content":"hi"}],` +
      `"ashaveri":{"file":{"sha256":"${'ab'.repeat(32)}","bytes":3,"media_type":"audio/wav"}}}`,
  ],
  [
    'whitespace wherever the grammar allows it',
    ` {\n"model"\t: "${M}" ,\r\n"messages" : [ {\n"role" : "user" , "content" : [ ] } ] } `,
  ],
  ['a brace inside text', `{"model":"${M}","messages":[{"role":"user","content":"a brace: {"}]}`],
  ['a quote and a backslash inside text', `{"model":"${M}","messages":[{"role":"user","content":"say \\"hi\\" \\\\ now"}]}`],
  ['a model name written out of escapes', `{"model":"mock\\u002dmodel\\u002d1","messages":[{"role":"a","content":"b"}]}`],
  ['a model name outside ASCII', `{"model":"mødel-ünïcode-✓","messages":[{"role":"a","content":"b"}]}`],
  [
    'numbers in members nothing reads',
    `{"model":"${M}","messages":[{"role":"a","content":"b"}],"n":[0,-0,1e3,-1.5e-7,12345678901234567890,0.1]}`,
  ],
  ['a number that is not one', `{"model":"${M}","messages":[{"role":"a","content":"b"}],"n":01}`],
  ['a nested message list inside a part', `{"model":"${M}","messages":[{"role":"a","content":[{"type":"t","x":[[{"y":1}]]}]}]}`],
  ['an unterminated token', `{"model":"${M},"messages":[]}`],
  ['an unterminated body', `{"model":"${M}"`],
  ['a bare colon where a value belongs', '{"model":,"messages":[]}'],
  ['a bare comma where a value belongs', '{"model":,"messages"}'],
  ['the trap, asking for none of it', trapBody(false)],
  ['the trap, asking for a stream', trapBody(true)],
  [
    'the trap written as a member name rather than as a value',
    JSON.stringify({ '{"model":"other","stream":true}': 1, messages: [{ role: 'a', content: 'b' }], model: M }),
  ],
  [
    'the answer spelled before the text that contradicts it',
    JSON.stringify({ model: M, messages: [{ role: 'user', content: '"model":"not-served" "stream":true' }], stream: true }),
  ],
];

/**
 * One body whose message content holds exactly the token bytes given. The body is written rather than
 * serialised, so a cell can put a backslash anywhere inside a token and know what bytes the reader is handed.
 */
function contentBody(token: string): string {
  return `{"model":"${M}","messages":[{"role":"user","content":"${token}"}],"stream":true}`;
}

/** The same, with the bytes in a message's role rather than in its content. */
function roleBody(token: string): string {
  return `{"model":"${M}","messages":[{"role":"${token}","content":"hi"}],"stream":true}`;
}

/**
 * The escape sequences a JSON document is allowed to hold inside a string token, one per spelling, as the
 * bytes of a token carrying each. Every one of these decodes to text rather than to a refusal, and a scan
 * that bounded a token without reading its escapes would take the closing quote of a text saying `a"b`.
 */
const VALID_ESCAPES: readonly (readonly [string, string])[] = [
  ['an escaped quotation mark', 'a\\"b'],
  ['an escaped reverse solidus', 'a\\\\b'],
  ['an escaped solidus', 'a\\/b'],
  ['an escaped backspace', 'a\\bb'],
  ['an escaped form feed', 'a\\fb'],
  ['an escaped newline', 'a\\nb'],
  ['an escaped carriage return', 'a\\rb'],
  ['an escaped tab', 'a\\tb'],
  ['a \\u naming a character of the basic plane', 'a\\u00e9b'],
  ['a \\u naming the nul character', 'a\\u0000b'],
  ['a \\u naming a quotation mark', 'a\\u0022b'],
  ['a \\u naming an astral character as a surrogate pair', '\\ud83d\\ude00'],
];

/**
 * The escapes a caller can write inside a string token, and the shapes that show whether the scan read them.
 *
 * `JSON.stringify` never writes an escape its own reader refuses, so a body built by serialising a graph
 * carries only the escapes the grammar allows, and no corpus of such bodies reaches this defect class. The
 * rows below are bytes. The invalid ones sit in the spans a scan weighs by length and never decodes (a
 * content token, a role, a member this route reads nothing of), which is where the scan has to state the
 * refusal itself rather than leave it to the parse that runs behind it, and in the spans it does decode,
 * where the two readers are asked to agree either way. The valid ones are here so that a scanner refusing
 * too much fails in this same file rather than in a deployment that refused a well-formed caller.
 */
const ESCAPE_BODIES: readonly (readonly [string, string])[] = [
  ['a content holding an invalid escape letter', contentBody('a\\zb')],
  ['a content holding an invalid escape letter beside a digit', contentBody('a\\1b')],
  ['a content holding an invalid escape letter that is a brace', contentBody('a\\{b')],
  ['a content holding an escape letter outside ASCII', contentBody('a\\ég')],
  ['a content holding a backslash before a raw tab', contentBody('a\\\tb')],
  ['a content holding a backslash before a raw line feed', contentBody('a\\\nb')],
  ['a content holding a backslash before a raw nul', contentBody('a\\' + String.fromCharCode(0) + 'b')],
  ['a role holding an invalid escape letter', roleBody('u\\xser')],
  ['a role whose bytes are one backslash and nothing else', roleBody('\\')],
  ['a member this route reads nothing of', `{"model":"${M}","messages":[{"role":"a","content":"b"}],` +
    `"ashaveri":{"file":{"sha256":"ab\\zcd"}}}`],
  ['a part member this route reads nothing of', `{"model":"${M}","messages":[{"role":"user",` +
    `"content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,Q\\I=="}}]}]}`],
  ['a member name holding an invalid escape letter', `{"mo\\odel":"${M}","messages":[{"role":"a","content":"b"}]}`],
  ['a backslash before the closing quote', contentBody('ab\\')],
  ['a backslash before the closing quote, with a member behind it', `{"model":"${M}","messages":` +
    `[{"role":"user","content":"a\\"}],"stream":true}`],
  ['a backslash closing the document', `{"model":"${M}","messages":[{"role":"a","content":"b"}],"x":"c\\`],
  ['a \\u with no digits after it', contentBody('a\\u')],
  ['a \\u with two hexadecimal digits', contentBody('a\\u12')],
  ['a \\u with three hexadecimal digits', contentBody('a\\u12b')],
  ['a \\u with a non-hexadecimal digit first', contentBody('a\\u0g12')],
  ['a \\u whose fourth digit is the closing quote', contentBody('a\\u123')],
  ['a \\u naming an unpaired surrogate', contentBody('\\ud83d')],
  ...VALID_ESCAPES.map(([name, token]) => [`${name}, inside a content token`, contentBody(token)] as const),
];

describe('the escape grammar of one string token', () => {
  for (const [name, body] of ESCAPE_BODIES) {
    it(`answers the body holding ${name} the same way twice`, () => agree(body, name));
  }

  for (const [name, token] of VALID_ESCAPES) {
    it(`admits a content holding ${name}`, () => {
      const written = contentBody(token);
      const served = `ok:${JSON.stringify({ model: M, stream: true })}`;
      expect(scanAnswer(written), 'the scan reads the whole body').toBe(served);
      expect(parseAnswer(written), 'and the parse reads it too').toBe(served);
    });
  }

  it('bounds a token whose own closing quote a backslash has taken', () => {
    // The disagreement this file exists for, spelled out on one body rather than left to the comparison:
    // an escape is two bytes the token keeps, so `\"` is a character of the text and not the end of it, and
    // a backslash before the last quote leaves the token open past the end of the document. Both readers
    // answer that body as not-JSON; a scan that stopped at the escaped quote would read a message list the
    // bytes never held.
    expect(scanAnswer(contentBody('a\\"b')), 'a quote the caller escaped is text').toBe(
      `ok:${JSON.stringify({ model: M, stream: true })}`,
    );
    expect(scanAnswer(contentBody('ab\\')), 'a backslash before the closing quote leaves the token open').toBe(
      'invalid-json',
    );
    expect(parseAnswer(contentBody('ab\\')), 'and the parse says the same of those bytes').toBe('invalid-json');
  });
});

describe('the request scan against the request parse', () => {
  it('answers every body the grammar has a sentence for the same way twice', () => {
    for (const [name, body] of CORPUS) agree(body, name);
  });

  it('reads the members and not the sentences, whichever came first', () => {
    // A route field spelled inside message text is characters inside a token. Both readers are asked the
    // same question here, and the answer is the member: the model the deployment serves, and the arm the
    // caller wrote beside the text that names the other one.
    expect(scanAnswer(trapBody(false)), 'the trap, buffered').toBe(`ok:${JSON.stringify({ model: M, stream: false })}`);
    expect(scanAnswer(trapBody(true)), 'the trap, streamed').toBe(`ok:${JSON.stringify({ model: M, stream: true })}`);
    const asKey = JSON.stringify({
      '{"model":"other","stream":true}': 1,
      messages: [{ role: 'a', content: 'b' }],
      model: M,
    });
    expect(scanAnswer(asKey), 'a key that is a whole route field, spelled as text').toBe(
      `ok:${JSON.stringify({ model: M, stream: false })}`,
    );
  });

  it('agrees with the parse over bodies no example above thought of', () => {
    // The corpus is written by the same hand as the scan, so it proves the cases that were thought of and
    // nothing else. Generated documents are what asks whether the two readers part on a shape neither of
    // them was written for.
    fc.assert(fc.property(requestBodies(), (text) => scanAnswer(text) === parseAnswer(text)), { numRuns: 5_000 });
  });
});

/**
 * The request bodies this grammar reaches, as text.
 *
 * Grapheme clusters rather than the 16-bit units, because a lone surrogate is replaced on the way into a
 * buffer and the two readers would then be handed two documents rather than one document twice, which is a
 * difference in the fixture and not in the grammar. Every member is optional and every member can hold
 * anything, because the scan is asked to settle a refusal for a body a caller wrote, not for one this file
 * chose.
 *
 * Half of the return is then handed through an injection that writes an escape sequence into one of the
 * document's string tokens, because the bytes a serialiser emits are only ever the escapes it chose to
 * write, and a corpus confined to them cannot reach the grammar's answer to an escape it refuses.
 */
function requestBodies(): fc.Arbitrary<string> {
  const names = fc.constantFrom('model', 'messages', 'role', 'content', 'type', 'stream', 'x');
  const text = fc.string({ unit: 'grapheme' });
  const key = fc.oneof(text, names);
  const scalar = fc.oneof(
    fc.constant(null),
    fc.boolean(),
    fc.integer({ min: -9, max: 9 }),
    fc.double({ noNaN: true, noDefaultInfinity: true }),
    text,
  );
  const part = fc.oneof(
    scalar,
    fc.record({ type: key, text }),
    fc.record({ type: text, image_url: fc.record({ url: text }) }),
    fc.array(scalar, { maxLength: 2 }),
  );
  const message = fc.oneof(
    scalar,
    fc.record({ role: text, content: fc.oneof(text, fc.array(part, { maxLength: 3 })) }),
    fc.record({ content: fc.oneof(text, fc.array(part, { maxLength: 2 })) }),
    fc.array(part, { maxLength: 2 }),
    // A message that carries members of its own spelling the route's two fields: the grammar reaches them
    // as characters inside a nested object and reads nothing of them, which is where a byte search and a
    // walk over the members give different answers.
    fc.record({
      role: text,
      content: text,
      model: text,
      stream: fc.boolean(),
      metadata: fc.record({ model: text, stream: fc.boolean(), messages: fc.array(scalar, { maxLength: 2 }) }),
    }),
  );
  const body = fc.record({
    // The message list first and the answer behind it, because the order is what a byte search would be
    // reading rather than the grammar.
    messages: fc.option(fc.array(message, { maxLength: 3 }), { nil: undefined }),
    model: fc.option(text, { nil: undefined }),
    stream: fc.option(fc.oneof(fc.boolean(), scalar), { nil: undefined }),
    ashaveri: fc.option(fc.record({ file: fc.record({ sha256: text, bytes: fc.nat(1_000_000) }) }), { nil: undefined }),
  });
  const serialised = body.map((document) => JSON.stringify(document));
  return fc.oneof(
    serialised,
    fc.tuple(serialised, fc.nat(), fc.nat(), escapeSequences()).map(
      ([document, tokenPick, offset, escape]) => injectedEscape(document, tokenPick, offset, escape),
    ),
  );
}

/**
 * The escape sequences a caller can write inside a string token, as the bytes they put in the body.
 *
 * The valid ones travel with the invalid ones because an escape is read for its length as much as for its
 * meaning: `\"` is two bytes of text and takes no quote off the token, so it moves the end of that token,
 * and every member written behind it, to somewhere else in the document.
 */
function escapeSequences(): fc.Arbitrary<string> {
  return fc.constantFrom(
    '\\"',
    '\\\\',
    '\\/',
    '\\b',
    '\\f',
    '\\n',
    '\\r',
    '\\t',
    '\\u0075',
    '\\u00e9',
    '\\u0000',
    '\\ud83d\\ude00',
    '\\z',
    '\\x',
    '\\e',
    '\\1',
    '\\ ',
    '\\u',
    '\\u12',
    '\\u12g4',
  );
}

/** The half-open ranges of the string tokens in text that `JSON.stringify` wrote, quotes included. */
function stringTokens(text: string): readonly { readonly start: number; readonly end: number }[] {
  const found: { start: number; end: number }[] = [];
  let i = 0;
  while (i < text.length) {
    if (text[i] !== '"') {
      i += 1;
      continue;
    }
    let j = i + 1;
    while (j < text.length) {
      if (text[j] === '\\') j += 2;
      else if (text[j] === '"') break;
      else j += 1;
    }
    found.push({ start: i, end: j + 1 });
    i = j + 1;
  }
  return found;
}

/**
 * The document with one escape sequence written inside one of its string tokens, which is what takes these
 * bytes past anything a serialiser emits.
 *
 * A token of no payload is included, because an escape written into one is the case of a backslash standing
 * where the closing quote was: the token stops being one, and what the readers then make of the rest of the
 * document is the question. The cut never falls between the two halves of an astral character, for the same
 * reason the strings above are grapheme clusters: a lone half encodes to a replacement character, and the
 * two readers would be handed two documents instead of one document twice.
 */
function injectedEscape(document: string, tokenPick: number, offset: number, escape: string): string {
  const tokens = stringTokens(document);
  const token = tokens[tokenPick % Math.max(1, tokens.length)];
  if (token === undefined) return document;
  const room = token.end - token.start - 1;
  let cut = token.start + 1 + (room <= 0 ? 0 : offset % room);
  const lead = document.charCodeAt(cut - 1);
  const trail = document.charCodeAt(cut);
  if (lead >= 0xd800 && lead <= 0xdbff && trail >= 0xdc00 && trail <= 0xdfff) cut += 1;
  return document.slice(0, cut) + escape + document.slice(cut);
}

/**
 * The same trap through the route, which is where the two fields decide something: which model served the
 * request, which arm answered it, and that the evidence is still the digest of the bytes as they arrived.
 */
describe('the route over a body whose text names another route', () => {
  const CREDENTIAL = 'scanner';
  const NONCE = Uint8Array.from({ length: 16 }, (_, i) => i + 1);

  async function session(): Promise<Harness> {
    return await harness({
      credentials: [generated(CREDENTIAL, ['complete', 'read'])],
      gateway: { deployment: mockDeployment({ model: M }) },
    });
  }

  interface Answer {
    readonly statusCode: number;
    readonly headers: Record<string, string | string[] | number | undefined>;
    readonly body: string;
    readonly raw: Buffer;
  }

  /**
   * One request as the route answers it.
   *
   * A literal method pins inject's awaitable Response overload; the union form leaves the awaited value
   * without a status or a body to read, which is why the method is typed as the union and then read as one
   * member of it.
   */
  async function complete(h: Harness, body: string, nonce?: Uint8Array): Promise<Answer> {
    const target = '/v1/chat/completions';
    const method: HTTPMethods = 'POST';
    const answer = await h.app.inject({
      method: method as 'POST',
      url: target,
      headers: {
        'content-type': 'application/json',
        ...h.signFor(CREDENTIAL, 'POST', target, body, nonce === undefined ? undefined : { nonce }),
      },
      payload: body,
    });
    return {
      statusCode: answer.statusCode,
      headers: answer.headers,
      body: answer.payload,
      raw: answer.rawPayload,
    };
  }

  async function receiptOf(h: Harness, id: string): Promise<ReceiptPayload> {
    const target = `/v1/receipts/${id}`;
    const method: HTTPMethods = 'GET';
    const answer = await h.app.inject({
      method: method as 'GET',
      url: target,
      headers: h.signFor(CREDENTIAL, 'GET', target, null),
    });
    expect(answer.statusCode).toBe(200);
    return decodeReceipt(new Uint8Array(answer.rawPayload)).payload;
  }

  it('serves the model the member names and the buffered arm the member asks for', async () => {
    const h = await session();
    try {
      const sent = trapBody(false);
      const answer = await complete(h, sent, NONCE);
      expect(answer.statusCode, 'a text naming another model is not a request for it').toBe(200);
      expect(String(answer.headers['content-type']), 'and a text naming a stream is not one').toContain(
        'application/json',
      );
      expect(JSON.parse(answer.body).model, 'the mock answers with the model the member named').toBe(M);
      const payload = await receiptOf(h, String(answer.headers['x-ashaveri-receipt-id']));
      expect(payload.mdl).toBe(M);
      expect(toHex(payload.req), 'the evidence digests the bytes as they arrived').toBe(
        toHex(hashRequest(new TextEncoder().encode(sent))),
      );
    } finally {
      await h.app.close();
    }
  });

  it('serves the streamed arm when the member asks for it, whatever the text says', async () => {
    const h = await session();
    try {
      const sent = trapBody(true);
      const answer = await complete(h, sent, NONCE);
      expect(answer.statusCode).toBe(200);
      expect(String(answer.headers['content-type'])).toContain('text/event-stream');
      expect(answer.raw.toString('utf8')).toContain('data: [DONE]');
      const payload = await receiptOf(h, String(answer.headers['x-ashaveri-receipt-id']));
      expect(payload.mdl).toBe(M);
      expect(toHex(payload.req)).toBe(toHex(hashRequest(new TextEncoder().encode(sent))));
    } finally {
      await h.app.close();
    }
  });

  it('refuses a model the deployment does not serve before an inference is asked for', async () => {
    const h = await session();
    try {
      const sent = JSON.stringify({
        messages: [{ role: 'user', content: '"model":"' + M + '"' }],
        model: 'not-served',
      });
      const answer = await complete(h, sent);
      expect(answer.statusCode).toBe(400);
      expect(JSON.parse(answer.body)).toMatchObject({
        error: { message: "model 'not-served' is not served by this deployment", type: 'invalid_request_error' },
      });
    } finally {
      await h.app.close();
    }
  });

  it('refuses a malformed message list before the upstream is reached', async () => {
    const h = await session();
    try {
      // The scan settles the whole grammar, not only the two members it keeps, so a shape this gateway has
      // always refused is still refused ahead of any inference, whichever backend the deployment runs.
      const sent = JSON.stringify({
        messages: [{ type: 'text', text: 'a part where a message was meant' }],
        model: M,
      });
      const answer = await complete(h, sent);
      expect(answer.statusCode).toBe(400);
      expect(JSON.parse(answer.body)).toMatchObject({
        error: { message: 'each message must have a non-empty string role', type: 'invalid_request_error' },
      });
    } finally {
      await h.app.close();
    }
  });

  it('refuses a body whose message text holds an invalid escape, before the graph is asked for it', async () => {
    // The scan bounds a content token and never decodes it, so the parse that builds the message graph is
    // the only reader of the escapes inside one. When the scan admits an escape the grammar refuses, that
    // parse throws while the backend reads `request.messages`, and the route answers with what it says
    // about a failed upstream: a refusal of another kind, at another status, and in a deployment running a
    // real inference server only after the body had been forwarded and the completion paid for.
    const h = await session();
    try {
      const answer = await complete(h, contentBody('a\\zb'));
      expect(answer.statusCode, 'an escape no reader can decode is not a completion').toBe(400);
      expect(JSON.parse(answer.body)).toMatchObject({
        error: { message: 'request body is not valid JSON', type: 'invalid_request_error' },
      });
    } finally {
      await h.app.close();
    }
  });

  it('serves a body whose message text holds the escapes the grammar writes', async () => {
    const h = await session();
    try {
      for (const [name, token] of VALID_ESCAPES) {
        const answer = await complete(h, contentBody(token));
        expect(answer.statusCode, `a completion whose text holds ${name} is served`).toBe(200);
      }
    } finally {
      await h.app.close();
    }
  });
});
