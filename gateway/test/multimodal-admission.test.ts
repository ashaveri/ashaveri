import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { decodeReceipt, fromBase64Url, toHex, verifyReceipt } from '@ashaveri/receipt';
import { RECEIPT_ID } from '../src/access.js';
import { mockCompletion, parseChatCompletionRequest, RequestError } from '../src/mock.js';
// The member type is named through the entry point, the only place a consumer of the package can reach it.
import type { ContentPart } from '../src/index.js';
import { generated, harness, nonceAt, type Harness } from './helpers.js';

/**
 * What a message is when the client sends something other than text. Three readers are watched here:
 * the parse that decides whether the request is answered at all, the mock that meters it, and the
 * receipt that binds the bytes it was sent in. A part that reaches only the first two is a part the
 * evidence never saw.
 */

const MODEL = 'mock-model-1';
const CREDENTIAL = 'multimodal';

/** The byte a marker nonce carries, so a failure here names a nonce this file built. */
const MARKER = 0x4d;

/**
 * Stand-in media bytes, assembled from an index rather than written out, so no tracked file carries a
 * long base64 run. The value is that the gateway never opens these bytes: the shapes below are admitted
 * whatever this string holds.
 */
const INLINE_DATA = Buffer.from(
  Uint8Array.from({ length: 512 }, (_byte, at) => (at * 37) % 256),
).toString('base64');
const IMAGE_DATA_URL = `data:image/png;base64,${INLINE_DATA}`;

/** One user message carrying these parts, as a client would send it. */
function bodyWithParts(content: readonly unknown[]): string {
  return JSON.stringify({ model: MODEL, messages: [{ role: 'user', content }] });
}

/** A message list spelled as a caller sent it, for a case whose point is the message and not its content. */
function bodyWithMessages(messages: readonly unknown[]): string {
  return JSON.stringify({ model: MODEL, messages });
}

/** One message that parses, so a refusal below is about the member its row names and not about this. */
const ONE_MESSAGE = { role: 'user', content: 'hello' };

/** The text part of the request every case here shares, and one media part beside it. */
function mixedContent(text: string, dataUrl: string): unknown[] {
  return [
    { type: 'text', text },
    { type: 'image_url', image_url: { url: dataUrl } },
  ];
}

/**
 * sha256 taken here, over the bytes this file is about to hand the route. The gateway digests what it
 * read and never what it parsed, so a witness written in the test is the only place the two spellings
 * of "the request" get compared.
 */
function digestOf(text: string): string {
  return createHash('sha256').update(Buffer.from(text, 'utf8')).digest('hex');
}

/**
 * One character inside the inline data moved to a different base64 character, at an index the caller
 * chooses. The length is unchanged, which is the point: the two requests differ by one byte of the file
 * and by nothing a client could see in the framing.
 */
function flipOneCharacter(text: string, at: number): string {
  const replacement = text.charAt(at) === 'A' ? 'B' : 'A';
  return `${text.slice(0, at)}${replacement}${text.slice(at + 1)}`;
}

/** Where the inline data begins, so a byte inside it can be named without counting by hand. */
function inlineDataStart(text: string): number {
  return text.indexOf('base64,') + 'base64,'.length;
}

/** What a parse answered: the sentence it refused with, or `admitted` where it took the body. */
function refusalOf(raw: unknown): string {
  try {
    parseChatCompletionRequest(raw);
    return 'admitted';
  } catch (err) {
    return err instanceof RequestError ? err.message : `non-RequestError: ${String(err)}`;
  }
}

async function session(): Promise<Harness> {
  return harness({ credentials: [generated(CREDENTIAL, ['complete', 'read'])] });
}

async function send(h: Harness, method: 'GET' | 'POST', target: string, body: string | null, nonce?: Uint8Array) {
  return await h.app.inject({
    // inject resolves its overload from a literal method; the union selects the chainable form, whose
    // awaited value has no statusCode.
    method: method as 'GET',
    url: target,
    headers: {
      ...(body === null ? {} : { 'content-type': 'application/json' }),
      ...h.signFor(CREDENTIAL, method, target, body, nonce === undefined ? undefined : { nonce }),
    },
    ...(body === null ? {} : { payload: body }),
  });
}

/** The key this deployment publishes for its receipts, read from the manifest it serves. */
async function publishedKey(h: Harness): Promise<Uint8Array> {
  const manifest = await send(h, 'GET', '/v1/deployment-manifest', null);
  const document = manifest.json() as { keys: { kid: string; alg: string; publicKey: string }[] };
  return fromBase64Url(document.keys[0]!.publicKey);
}

/** The signed document one completion's id addresses. */
async function receiptBytesOf(h: Harness, completionId: string): Promise<Uint8Array> {
  const receipt = await send(h, 'GET', `/v1/receipts/${completionId}`, null);
  expect(receipt.statusCode).toBe(200);
  return new Uint8Array(receipt.rawPayload);
}

const PART_SHAPES: readonly (readonly [string, Record<string, unknown>])[] = [
  ['a text part', { type: 'text', text: 'describe this image' }],
  ['an image part naming a url', { type: 'image_url', image_url: { url: 'https://example.test/a.png' } }],
  ['an image part carrying inline data', { type: 'image_url', image_url: { url: IMAGE_DATA_URL, detail: 'high' } }],
  ['an audio part', { type: 'input_audio', input_audio: { data: INLINE_DATA, format: 'wav' } }],
  ['a file part carrying its bytes', { type: 'file', file: { file_data: INLINE_DATA, filename: 'contract.pdf' } }],
  ['a file part naming a url', { type: 'file', file: { file_url: 'https://example.test/contract.pdf' } }],
  ['a file part naming neither its bytes nor a url', { type: 'file' }],
  ['an image part whose url is not a string', { type: 'image_url', image_url: { url: 7 } }],
  ['a part type this code does not know', { type: 'video_url', video_url: { url: 'https://example.test/a.mp4' } }],
  ['a part with members this code has never read', { type: 'tool_result', ok: true, nested: { depth: 3 } }],
];

describe('parseChatCompletionRequest, the two shapes a content may take', () => {
  it('admits each published part shape and keeps every part exactly as it arrived', () => {
    for (const [name, part] of PART_SHAPES) {
      const parsed = parseChatCompletionRequest(JSON.parse(bodyWithParts([part])));
      expect(parsed.messages, `${name} reaches the parsed message`).toHaveLength(1);
      // The part is the object that came out of the body, member for member: nothing a caller sent is
      // read into the parsed value and then left out of it.
      expect(parsed.messages[0]!.content, `${name} keeps the whole part`).toEqual([part]);
    }
  });

  it('admits a string content and a mixed part array on one message list', () => {
    const parsed = parseChatCompletionRequest(
      JSON.parse(
        bodyWithMessages([
          { role: 'user', content: 'hello' },
          { role: 'user', content: PART_SHAPES.map(([, part]) => part) },
        ]),
      ),
    );
    expect(parsed.messages[0]!.content).toBe('hello');
    expect(parsed.messages[1]!.content).toHaveLength(PART_SHAPES.length);
  });

  it('asks only that a part type be a string, so a name no provider uses is still a part', () => {
    // A role is written into the answer the mock gives, so an empty one is refused. A part's type decides
    // only how that part is metered, so an empty one is a string this parse asks nothing further about.
    expect(refusalOf(JSON.parse(bodyWithParts([{ type: '' }])))).toBe('admitted');
    expect(refusalOf(JSON.parse(bodyWithParts([{ type: 'text' }])))).toBe('admitted');
  });

  const REFUSALS: readonly (readonly [string, readonly unknown[], string])[] = [
    ['a message that is not an object', ['a string'], 'each message must be an object'],
    ['a message with no role', [{ content: 'hello' }], 'each message must have a non-empty string role'],
    [
      'a message with an empty role',
      [{ role: '', content: 'hello' }],
      'each message must have a non-empty string role',
    ],
    [
      'a message whose role is not a string',
      [{ role: 7, content: 'hello' }],
      'each message must have a non-empty string role',
    ],
    [
      'a content that is neither text nor parts',
      [{ role: 'user', content: 7 }],
      'each message must have a string content or an array of content parts',
    ],
    [
      'a content that is an object',
      [{ role: 'user', content: { type: 'text' } }],
      'each message must have a string content or an array of content parts',
    ],
    [
      'an empty part array',
      [{ role: 'user', content: [] }],
      'a content array must hold at least one content part',
    ],
    ['a part that is a string', [{ role: 'user', content: ['hello'] }], 'each content part must be an object'],
    ['a part that is null', [{ role: 'user', content: [null] }], 'each content part must be an object'],
    [
      'a part naming no type',
      [{ role: 'user', content: [{ text: 'hello' }] }],
      'each content part must have a string type',
    ],
    [
      'a part whose type is a number',
      [{ role: 'user', content: [{ type: 7 }] }],
      'each content part must have a string type',
    ],
  ];

  it('refuses the shapes that still mean something, each by name', () => {
    for (const [name, messages, message] of REFUSALS) {
      expect(refusalOf(JSON.parse(bodyWithMessages(messages))), name).toBe(message);
    }
  });
});

describe('parseChatCompletionRequest, the body a content arrives in', () => {
  /**
   * The refusals that come from the members read beside a message list. Each row hands the parse a value as
   * it would parse to, because what a row is about is the member and not how a caller spelled the JSON.
   */
  const BODY_REFUSALS: readonly (readonly [string, unknown, string])[] = [
    ['a body that is a number', 7, 'request body must be a JSON object'],
    ['a body that is null', null, 'request body must be a JSON object'],
    ['a body with no messages', { model: MODEL }, 'messages must be a non-empty array'],
    ['messages that is a string', { model: MODEL, messages: 'hello' }, 'messages must be a non-empty array'],
    ['messages that is empty', { model: MODEL, messages: [] }, 'messages must be a non-empty array'],
    ['a model that is a number', { messages: [ONE_MESSAGE], model: 7 }, 'model must be a non-empty string'],
    ['a model that is empty', { messages: [ONE_MESSAGE], model: '' }, 'model must be a non-empty string'],
    ['a stream that is a string', { messages: [ONE_MESSAGE], stream: 'yes' }, 'stream must be a boolean'],
  ];

  it('refuses the body itself and the members read beside its messages, each by name', () => {
    for (const [name, body, message] of BODY_REFUSALS) {
      expect(refusalOf(body), name).toBe(message);
    }
  });
});

describe('the numbers the mock backend states about what a message carries', () => {
  const TEXT = 'what is in this image?';

  it('counts the characters of the text parts and none of the inline data', () => {
    const request = parseChatCompletionRequest(JSON.parse(bodyWithParts(mixedContent(TEXT, IMAGE_DATA_URL))));
    const completion = mockCompletion(request);
    // The figure is this file's own arithmetic over the text, so it is the mock's meter and not a
    // reading of the media: the same completion over a one-byte file and a one-gigabyte file is one number.
    expect(completion.promptTokens).toBe(Math.ceil(TEXT.length / 4));
    expect(completion.promptTokens).toBeLessThan(Math.ceil(IMAGE_DATA_URL.length / 4));
    expect(completion.content).toContain(
      `${TEXT.length} characters in 1 text part(s) beside 1 part(s) naming something else`,
    );
  });

  it('counts nothing at all when no part states text', () => {
    const completion = mockCompletion(
      parseChatCompletionRequest(JSON.parse(bodyWithParts([{ type: 'file', file: { file_data: INLINE_DATA } }]))),
    );
    // The honest answer about a file this code cannot open is zero, and the sentence beside it says which
    // parts were counted, rather than guessing a length from the bytes a caller happened to inline.
    expect(completion.promptTokens).toBe(0);
    expect(completion.content).toContain('0 characters in 0 text part(s) beside 1 part(s) naming something else');
    expect(completion.completionTokens).toBeGreaterThan(0);
  });

  it('counts a string content whole, and answers it with the one figure it has', () => {
    // The other branch of both readers: a message stating text as a string has no parts to count, so the
    // sentence beside its figure names no part of either kind.
    const spoken = 'a message that is text on its own';
    const completion = mockCompletion(
      parseChatCompletionRequest(JSON.parse(bodyWithMessages([{ role: 'user', content: spoken }]))),
    );
    expect(completion.promptTokens).toBe(Math.ceil(spoken.length / 4));
    expect(completion.content).toContain(`with ${spoken.length} characters`);
    expect(completion.content).not.toContain('text part(s)');
  });

  it('counts no characters for a text part whose text member is absent or is not a string', () => {
    // Admission asks only that a part's type be a string, so a part naming text can arrive holding no such
    // member. The sound part beside each defective one keeps the figure off zero, so a metering of the
    // defective member would show as a larger number rather than as a zero that went missing.
    const DEFECTIVE_TEXT_PARTS: readonly (readonly [string, unknown])[] = [
      ['no text member at all', { type: 'text' }],
      ['a text member that is a number', { type: 'text', text: 7 }],
    ];
    for (const [name, part] of DEFECTIVE_TEXT_PARTS) {
      const completion = mockCompletion(
        parseChatCompletionRequest(JSON.parse(bodyWithParts([{ type: 'text', text: TEXT }, part]))),
      );
      expect(completion.promptTokens, `a text part with ${name}`).toBe(Math.ceil(TEXT.length / 4));
      expect(completion.content, `a text part with ${name}`).toContain(
        `${TEXT.length} characters in 2 text part(s) beside 0 part(s) naming something else`,
      );
    }
  });

  it('reads no text out of a part whose type names something else, text member and all', () => {
    // The type decides which reader a part answers to, so a media part that also spells `text` states no
    // characters here. This is the case that tells the type check inside the reader from its own absence:
    // drop that check and both parts below are metered as the text they do not name.
    const spelled = 'characters no media part has any business stating';
    const parts: readonly ContentPart[] = [
      { type: 'image_url', image_url: { url: IMAGE_DATA_URL }, text: spelled },
      { type: 'file', file: { file_data: INLINE_DATA }, text: spelled },
    ];
    const completion = mockCompletion(parseChatCompletionRequest(JSON.parse(bodyWithParts(parts))));
    expect(completion.promptTokens).toBe(0);
    const sentence = '0 characters in 0 text part(s) beside 2 part(s) naming something else';
    expect(completion.content).toContain(sentence);
    expect(completion.content).not.toContain(spelled);
  });

  it('sums the text of every message and not only the last one', () => {
    const first = 'alpha beta gamma';
    const second = 'delta';
    const completion = mockCompletion(
      parseChatCompletionRequest(
        JSON.parse(
          bodyWithMessages([
            { role: 'user', content: mixedContent(first, IMAGE_DATA_URL) },
            { role: 'assistant', content: second },
          ]),
        ),
      ),
    );
    expect(completion.promptTokens).toBe(Math.ceil((first.length + second.length) / 4));
  });
});

describe('a multimodal request through the completion route', () => {
  const TEXT = 'what is in this image?';
  const body = () => bodyWithParts(mixedContent(TEXT, IMAGE_DATA_URL));

  it('admits a parts request carrying inline base64 media, and receipts it', async () => {
    const h = await session();
    try {
      const completion = await send(h, 'POST', '/v1/chat/completions', body(), nonceAt(1, MARKER));
      expect(completion.statusCode).toBe(200);
      const completionId = completion.headers['x-ashaveri-receipt-id'] as string;
      expect(RECEIPT_ID.test(completionId), completionId).toBe(true);
      const receipt = await receiptBytesOf(h, completionId);
      const payload = decodeReceipt(receipt).payload;
      expect(payload.mdl).toBe(MODEL);
      expect(payload.tok.p).toBe(Math.ceil(TEXT.length / 4));
      expect(completion.json().choices).toHaveLength(1);
    } finally {
      await h.app.close();
    }
  });

  it('receipts a parts request that names no text at all, and carries its zero', async () => {
    const h = await session();
    try {
      const noText = bodyWithParts([{ type: 'file', file: { file_data: INLINE_DATA } }]);
      const completion = await send(h, 'POST', '/v1/chat/completions', noText, nonceAt(5, MARKER));
      expect(completion.statusCode).toBe(200);
      const completionId = completion.headers['x-ashaveri-receipt-id'] as string;
      const payload = decodeReceipt(await receiptBytesOf(h, completionId)).payload;
      // A request with nothing to count is served rather than refused, and the figure it answers with is
      // the one the signed document carries: zero, stated, rather than a number drawn from the file.
      expect(payload.tok.p).toBe(0);
      expect(completion.json().usage.prompt_tokens).toBe(0);
    } finally {
      await h.app.close();
    }
  });

  it('answers a part refusal with the 400 whose shape the protocol states', async () => {
    const h = await session();
    try {
      const refused = bodyWithParts([{ image_url: { url: IMAGE_DATA_URL } }]);
      const res = await send(h, 'POST', '/v1/chat/completions', refused);
      // The sentence above the route is the parse's own, and the type beside it is what a caller with no
      // code of its own to look up reads, so both travel through this one request.
      expect(res.statusCode).toBe(400);
      expect(res.json()).toMatchObject({
        error: { message: 'each content part must have a string type', type: 'invalid_request_error' },
      });
    } finally {
      await h.app.close();
    }
  });

  it('binds the receipt to the exact bytes sent, digest computed in this file', async () => {
    const h = await session();
    try {
      const sent = body();
      const completion = await send(h, 'POST', '/v1/chat/completions', sent, nonceAt(2, MARKER));
      const completionId = completion.headers['x-ashaveri-receipt-id'] as string;
      const verified = verifyReceipt(await receiptBytesOf(h, completionId), {
        publicKey: await publishedKey(h),
        expectedNonce: nonceAt(2, MARKER),
      });
      // The document is authentic before its digest means anything, and the digest it carries is the one
      // this file took over the bytes it wrote into the request: the media inside the JSON is inside the
      // evidence, because the whole body is.
      expect(toHex(verified.payload.req)).toBe(digestOf(sent));
    } finally {
      await h.app.close();
    }
  });

  it('breaks the original claim when one byte inside the inline data changes', async () => {
    const h = await session();
    try {
      const original = body();
      const changed = flipOneCharacter(original, inlineDataStart(original) + 40);

      const firstNonce = nonceAt(3, MARKER);
      const secondNonce = nonceAt(4, MARKER);
      const first = await send(h, 'POST', '/v1/chat/completions', original, firstNonce);
      const second = await send(h, 'POST', '/v1/chat/completions', changed, secondNonce);
      expect(first.statusCode).toBe(200);
      expect(second.statusCode).toBe(200);
      const key = await publishedKey(h);
      const firstReceipt = await receiptBytesOf(h, first.headers['x-ashaveri-receipt-id'] as string);

      // The claim a client carries beside a receipt is that these are the bytes that produced it. Both
      // documents verify as documents, and the first one answers that claim for the bytes it was issued
      // over and refuses it for the twin that differs by one byte of the media.
      const verifiedFirst = verifyReceipt(firstReceipt, { publicKey: key, expectedNonce: firstNonce });
      const verifiedSecond = verifyReceipt(
        await receiptBytesOf(h, second.headers['x-ashaveri-receipt-id'] as string),
        { publicKey: key, expectedNonce: secondNonce },
      );
      expect(toHex(verifiedFirst.payload.req)).toBe(digestOf(original));
      expect(toHex(verifiedFirst.payload.req)).not.toBe(digestOf(changed));
      expect(toHex(verifiedSecond.payload.req)).toBe(digestOf(changed));
      expect(verifiedFirst.payload.nce).not.toEqual(verifiedSecond.payload.nce);
    } finally {
      await h.app.close();
    }
  });
});
