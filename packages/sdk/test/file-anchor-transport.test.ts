import { describe, expect, it } from 'vitest';
import OpenAI from 'openai';
import { hashRequest, sha256Hex, toHex, type VerifiedReceipt } from '@ashaveri/receipt';
import { AshaveriClient, wrapOpenAI } from '../src/index.js';
import { createFakeGateway, FAKE_BASE_URL, FAKE_RECEIPT_ID, type FakeGateway } from './mock-gateway.js';

/**
 * What a request body carries on its way to the receipt, measured rather than assumed.
 *
 * The digest a receipt signs is taken over the bytes this side wrote, so a claim inside the body is
 * inside `req` for free only if nothing between the caller and the wire rewrites or drops it. Two
 * paths write that body and they are not the same code: the wrapper of an official client hands on
 * the text it was handed and changes only headers (`src/wrap.ts`), and this package's own client
 * builds its text from the params object (`src/client.ts`). Both are run here against the deployment
 * double this suite already ships, whose `requests` list holds what a downstream would forward.
 */

const CHAT_URL = `${FAKE_BASE_URL}/chat/completions`;

/** The namespaced top-level body member a file claim travels in. */
const ANCHOR_MEMBER = 'ashaveri';

/** The bytes a client digests before handing a file to a provider's upload endpoint. */
const FILE_BYTES = new TextEncoder().encode('a recording of the conversation, in full');

const CLAIM = {
  file: { sha256: sha256Hex(FILE_BYTES), bytes: FILE_BYTES.byteLength, media_type: 'audio/wav' },
};

const MESSAGES = [{ role: 'user' as const, content: 'what is in this file?' }];

function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

/** A chat completion body carrying the member, written the way a caller writes it: one more key. */
function bodyCarrying(anchor: unknown): string {
  return JSON.stringify({ model: 'fake-model', messages: MESSAGES, [ANCHOR_MEMBER]: anchor });
}

/**
 * The bodies this completion was handed to the double, oldest first, with the receipt fetches the
 * same client made between them left out. The receipt of a verification is fetched after the
 * completion it addresses, so a fixed index into `requests` would read a GET as a body.
 */
function completionBodies(gateway: FakeGateway): string[] {
  return gateway.requests
    .filter((one) => one.method === 'POST' && one.url === CHAT_URL && typeof one.body === 'string')
    .map((one) => one.body as string);
}

/** The bytes the double was handed, which are the bytes a deployment forwards to its upstream. */
function forwarded(gateway: FakeGateway, index = 0): string {
  const body = completionBodies(gateway)[index];
  if (body === undefined) {
    throw new Error(`the deployment double recorded no completion body at position ${index}`);
  }
  return body;
}

function memberOf(body: string): unknown {
  return (JSON.parse(body) as Record<string, unknown>)[ANCHOR_MEMBER];
}

/** Reads the request digest a receipt signed, refusing a completion that came back unreceipted. */
function reqDigestOf(receipt: VerifiedReceipt | null): string {
  if (receipt === null) {
    throw new Error('a completion against a receipting gateway came back with no receipt');
  }
  return toHex(receipt.payload.req);
}

/**
 * A completion body written by hand rather than by a serializer: the spacing below is what no
 * `JSON.stringify` of this claim emits, so a transport that re-serialized on the way through would
 * arrive as different text rather than as the same text written a different way.
 */
function handWrittenBody(): string {
  const file =
    `{ "sha256" : "${sha256Hex(FILE_BYTES)}", "bytes" : ${String(FILE_BYTES.byteLength)}, ` +
    '"media_type" : "audio/wav" }';
  return (
    '{ "model" : "fake-model", "messages" : [ { "role" : "user", "content" : "what is in this file?" } ],' +
    ` "ashaveri" : { "file" : ${file} } }`
  );
}

describe('an unknown top-level member of the request body', () => {
  it('reaches the wire unchanged through the wrapper, which rewrites only headers', async () => {
    const sent = handWrittenBody();
    const gateway = createFakeGateway();
    const wrapped = wrapOpenAI({ apiKey: 'test-key', fetch: gateway.fetch });
    const response = await wrapped.fetch(CHAT_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: sent,
    });
    await response.text();
    const receipt = await wrapped.ashaveri.getReceipt(FAKE_RECEIPT_ID);
    const arrived = forwarded(gateway);
    // Identity of the whole text, not of a parse of it: a re-serialization that happened to keep the
    // member would still have moved the whitespace above, and `req` commits to every one of those
    // bytes, so a rewrite is a different digest rather than a silent rescue of the claim.
    expect(arrived).toBe(sent);
    expect(memberOf(arrived)).toEqual(CLAIM);
    expect(toHex(receipt.payload.req)).toBe(toHex(hashRequest(utf8(arrived))));
  });

  it('survives the serializer of the official client on its way into that wrapper', async () => {
    const gateway = createFakeGateway();
    const openai = new OpenAI({ apiKey: 'test-key', baseURL: FAKE_BASE_URL, fetch: gateway.fetch, maxRetries: 0 });
    const wrapped = wrapOpenAI(openai);
    const params: Record<string, unknown> = { model: 'fake-model', messages: MESSAGES, [ANCHOR_MEMBER]: CLAIM };
    await wrapped.chat.completions.create(params as unknown as Parameters<typeof openai.chat.completions.create>[0]);
    const arrived = forwarded(gateway);
    expect(memberOf(arrived)).toEqual(CLAIM);
    const receipt = await wrapped.ashaveri.getReceipt(FAKE_RECEIPT_ID);
    expect(toHex(receipt.payload.req)).toBe(toHex(hashRequest(utf8(arrived))));
  });

  it('is written into the body this package builds, and the deployment reads past it', async () => {
    const gateway = createFakeGateway();
    const client = new AshaveriClient({ baseUrl: FAKE_BASE_URL, fetch: gateway.fetch });
    const result = await client.chat.completions.create({
      model: 'fake-model',
      messages: MESSAGES,
      [ANCHOR_MEMBER]: CLAIM,
    });
    const arrived = forwarded(gateway);
    expect(memberOf(arrived)).toEqual(CLAIM);
    // The double takes `model`, `messages` and `stream` out of the body and says nothing about the
    // rest, which is the same refusal to interpret the deployment makes: the member is still on the
    // bytes here, and the model the receipt names still came from the key beside it.
    expect(result.completion.model).toBe('fake-model');
    expect(reqDigestOf(result.receipt)).toBe(toHex(hashRequest(utf8(arrived))));
  });

  it('moves the request digest on its own, every other member of the body untouched', async () => {
    const gateway = createFakeGateway();
    const anchored = new AshaveriClient({ baseUrl: FAKE_BASE_URL, fetch: gateway.fetch });
    const withAnchor = await anchored.chat.completions.create({
      model: 'fake-model',
      messages: MESSAGES,
      [ANCHOR_MEMBER]: CLAIM,
    });
    const bodyWithAnchor = forwarded(gateway, 0);
    const withoutAnchor = await anchored.chat.completions.create({ model: 'fake-model', messages: MESSAGES });
    const bodyWithout = forwarded(gateway, 1);
    // One member is the only difference between the two texts, so the two digests differ by the claim
    // and by nothing else. A deployment that stripped the member before hashing it would have signed
    // one digest for two bodies, and the assertions below refuse that in both directions.
    expect(bodyWithAnchor).toBe(bodyCarrying(CLAIM));
    expect(bodyWithout).toBe(JSON.stringify({ model: 'fake-model', messages: MESSAGES }));
    expect(reqDigestOf(withAnchor.receipt)).not.toBe(reqDigestOf(withoutAnchor.receipt));
    expect(reqDigestOf(withAnchor.receipt)).toBe(toHex(hashRequest(utf8(bodyWithAnchor))));
  });
});
