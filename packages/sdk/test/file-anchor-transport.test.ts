import { describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import OpenAI from 'openai';
import { toHex, type VerifiedReceipt } from '@ashaveri/receipt';
import { AshaveriClient, wrapOpenAI, type ChatCompletionParams } from '../src/index.js';
import { createFakeGateway, FAKE_BASE_URL, FAKE_RECEIPT_ID, type FakeGateway } from './mock-gateway.js';

/**
 * What a request body carries on its way to the receipt, measured rather than assumed.
 *
 * The digest a receipt signs is taken over the bytes the transport handed on, so a claim inside the
 * body is inside `req` for free only if nothing between the caller and the wire rewrites or drops it.
 * Two paths write that body and they are not the same code: the wrapper of an official client hands on
 * the text it was handed and changes only headers (`src/wrap.ts`), and this package's own client builds
 * its text from the params object (`src/client.ts`). Both are run here against the deployment double
 * this suite already ships, whose `requests` list records the body each call arrived with.
 *
 * Nothing on the expected side of an assertion here is read back from that recording, and nothing on it
 * is this estate's own hashing: the double digests the very string it records, so a `req` compared
 * against `hashRequest` over the recorded text is one computation checked against itself and reddens
 * for no transport at all. The expected sides below are texts written out in this file and digests
 * reached two ways over them, by `node:crypto` (which no shipped code of this estate calls for a
 * request digest) and by a literal written down away from this repository.
 */

const CHAT_URL = `${FAKE_BASE_URL}/chat/completions`;

/** The namespaced top-level body member a file claim travels in. */
const ANCHOR_MEMBER = 'ashaveri';

/** The bytes a client digests before handing a file to a provider's upload endpoint. */
const FILE_BYTES = new TextEncoder().encode('a recording of the conversation, in full');

/** sha256 from `node:crypto`, over the UTF-8 of the text handed to it. */
function otherSha256Hex(text: string): string {
  return createHash('sha256').update(new TextEncoder().encode(text)).digest('hex');
}

/**
 * The digest of the fixture above and the digests of the three body texts below were each produced
 * over those exact bytes by `node:crypto`, outside this repository's code. A helper that hashed
 * something other than the bytes it names therefore disagrees with the number pinned here rather than
 * agreeing with itself, which is the only way these cases can say anything about a digest.
 */
const FILE_DIGEST_HEX = '7d4214c1df232f32b9e6935af6a7a422de12cdfecd6ba35a9b11f43113e52e45';

const CLAIM = {
  file: { sha256: FILE_DIGEST_HEX, bytes: FILE_BYTES.byteLength, media_type: 'audio/wav' },
};

const MESSAGES = [{ role: 'user' as const, content: 'what is in this file?' }];

/** The member as a caller passes it: one more key beside `model` and `messages`. */
function anchorParam(): ChatCompletionParams {
  return { model: 'fake-model', messages: MESSAGES, [ANCHOR_MEMBER]: CLAIM };
}

/**
 * The body both transports are expected to put on the wire for the params above, written out rather
 * than serialized here: a transport that rewrote it arrives as different text, not as the same text
 * written a different way.
 */
const ANCHORED_BODY_TEXT =
  '{"model":"fake-model","messages":[{"role":"user","content":"what is in this file?"}],' +
  `"ashaveri":{"file":{"sha256":"${FILE_DIGEST_HEX}","bytes":${String(FILE_BYTES.byteLength)},"media_type":"audio/wav"}}}`;
const ANCHORED_BODY_SHA256_HEX = '6c17b450d293a604b47c14b633e2b7b19cc537416d9f12237b1ceb0d84b071cc';

/** The same body with the member left out, the other half of the pair that measures what it moves. */
const BARE_BODY_TEXT = '{"model":"fake-model","messages":[{"role":"user","content":"what is in this file?"}]}';
const BARE_BODY_SHA256_HEX = '15194b3b2ad77cec53bb7539d48e78e3b19475ae458d46a0ab3aedba52f198ff';

/**
 * The same claim again in text no `JSON.stringify` emits, spaces around the colons. It is the body the
 * wrapper is handed, and the spacing is what a transport that re-serialized on the way through would
 * lose.
 */
const SPACED_BODY_TEXT =
  '{ "model" : "fake-model", "messages" : [ { "role" : "user", "content" : "what is in this file?" } ],' +
  ` "ashaveri" : { "file" : { "sha256" : "${FILE_DIGEST_HEX}", "bytes" : ${String(FILE_BYTES.byteLength)}, ` +
  '"media_type" : "audio/wav" } } }';
const SPACED_BODY_SHA256_HEX = '212fa1da419651cf0d3e285f3df32d2d0060960daa6fc9f68e188967a4eca07f';

/**
 * The bodies this suite's completion calls arrived with, oldest first, with the receipt fetches the
 * same client made between them left out. The receipt of a verification is fetched after the
 * completion it addresses, so a fixed index into `requests` would read a GET as a body.
 */
function receivedBodies(gateway: FakeGateway): string[] {
  return gateway.requests
    .filter((one) => one.method === 'POST' && one.url === CHAT_URL && typeof one.body === 'string')
    .map((one) => one.body as string);
}

/** What the double was handed, which is what it digested. Nothing downstream is measured by this. */
function receivedBody(gateway: FakeGateway, index = 0): string {
  const body = receivedBodies(gateway)[index];
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

describe('an unknown top-level member of the request body', () => {
  it('reaches the double unchanged through the wrapper, which rewrites only headers', async () => {
    const gateway = createFakeGateway();
    const wrapped = wrapOpenAI({ apiKey: 'test-key', fetch: gateway.fetch });
    const response = await wrapped.fetch(CHAT_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: SPACED_BODY_TEXT,
    });
    await response.text();
    const receipt = await wrapped.ashaveri.getReceipt(FAKE_RECEIPT_ID);
    const arrived = receivedBody(gateway);
    expect(FILE_BYTES.byteLength).toBe(CLAIM.file.bytes);
    // Identity of the whole text, not of a parse of it: a re-serialization that happened to keep the
    // member would still have moved the spacing above, and `req` commits to every one of those bytes,
    // so a rewrite is a different digest rather than a silent rescue of the claim.
    expect(arrived).toBe(SPACED_BODY_TEXT);
    expect(memberOf(arrived)).toEqual(CLAIM);
    expect(reqDigestOf(receipt)).toBe(otherSha256Hex(SPACED_BODY_TEXT));
    expect(reqDigestOf(receipt)).toBe(SPACED_BODY_SHA256_HEX);
  });

  it('survives the serializer of the official client on its way into that wrapper', async () => {
    const gateway = createFakeGateway();
    const openai = new OpenAI({ apiKey: 'test-key', baseURL: FAKE_BASE_URL, fetch: gateway.fetch, maxRetries: 0 });
    const wrapped = wrapOpenAI(openai);
    const params = anchorParam();
    await wrapped.chat.completions.create(params as unknown as Parameters<typeof openai.chat.completions.create>[0]);
    const arrived = receivedBody(gateway);
    expect(arrived).toBe(ANCHORED_BODY_TEXT);
    expect(memberOf(arrived)).toEqual(CLAIM);
    const receipt = await wrapped.ashaveri.getReceipt(FAKE_RECEIPT_ID);
    expect(reqDigestOf(receipt)).toBe(otherSha256Hex(ANCHORED_BODY_TEXT));
    expect(reqDigestOf(receipt)).toBe(ANCHORED_BODY_SHA256_HEX);
  });

  it('is written into the body this package builds, and the deployment reads past it', async () => {
    const gateway = createFakeGateway();
    const client = new AshaveriClient({ baseUrl: FAKE_BASE_URL, fetch: gateway.fetch });
    const result = await client.chat.completions.create(anchorParam());
    const arrived = receivedBody(gateway);
    expect(arrived).toBe(ANCHORED_BODY_TEXT);
    expect(memberOf(arrived)).toEqual(CLAIM);
    // The double takes `model`, `messages` and `stream` out of the body and says nothing about the
    // rest, which is the same refusal to interpret the deployment makes: the member is still on the
    // bytes here, and the model the receipt names still came from the key beside it.
    expect(result.completion.model).toBe('fake-model');
    expect(reqDigestOf(result.receipt)).toBe(otherSha256Hex(ANCHORED_BODY_TEXT));
    expect(reqDigestOf(result.receipt)).toBe(ANCHORED_BODY_SHA256_HEX);
  });

  it('moves the request digest on its own, every other member of the body untouched', async () => {
    const gateway = createFakeGateway();
    const anchored = new AshaveriClient({ baseUrl: FAKE_BASE_URL, fetch: gateway.fetch });
    const withAnchor = await anchored.chat.completions.create(anchorParam());
    const bodyWithAnchor = receivedBody(gateway, 0);
    const withoutAnchor = await anchored.chat.completions.create({ model: 'fake-model', messages: MESSAGES });
    const bodyWithout = receivedBody(gateway, 1);
    // One member is the only difference between the two texts, so the two digests differ by the claim
    // and by nothing else. A deployment that stripped the member before hashing it would have signed
    // one digest for two bodies, and the assertions below refuse that in both directions.
    expect(bodyWithAnchor).toBe(ANCHORED_BODY_TEXT);
    expect(bodyWithout).toBe(BARE_BODY_TEXT);
    expect(reqDigestOf(withAnchor.receipt)).not.toBe(reqDigestOf(withoutAnchor.receipt));
    expect(reqDigestOf(withAnchor.receipt)).toBe(otherSha256Hex(ANCHORED_BODY_TEXT));
    expect(reqDigestOf(withAnchor.receipt)).toBe(ANCHORED_BODY_SHA256_HEX);
    expect(reqDigestOf(withoutAnchor.receipt)).toBe(otherSha256Hex(BARE_BODY_TEXT));
    expect(reqDigestOf(withoutAnchor.receipt)).toBe(BARE_BODY_SHA256_HEX);
  });
});
