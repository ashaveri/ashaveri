import { describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { FILE_ANCHOR_MEMBER_NAME, toHex, verifyFileAnchor } from '@ashaveri/receipt';
import { AshaveriClient, fileAnchor } from '../src/index.js';
import { createFakeGateway, FAKE_BASE_URL } from './mock-gateway.js';

/**
 * The claim a client writes about a file, and the body it writes it into.
 *
 * The bytes of the file are never what travels. A client digests them once, before it hands the file
 * to a provider's upload endpoint or to anybody else, and the request that goes on to reach a gateway
 * carries the digest. What a receipt then signs is the digest of that request, so the claim is inside
 * the evidence without the file ever passing through the deployment. The chain below is run against
 * the deployment double this suite ships, from the helper to the bytes the double was handed to the
 * digest the receipt carries, because each of those steps is a place a claim can be quietly lost.
 *
 * No expected value here comes out of the code under test. The digests are literals produced over the
 * fixture bytes away from this repository, and each is cross-checked against `node:crypto`, which no
 * shipped code of this estate uses for a file or request digest. A helper that hashed something other
 * than the bytes it names therefore disagrees with the number written down for it, which is the only
 * thing a witness over a digest can measure.
 */

const FILE = new TextEncoder().encode('a recording of the conversation, in full');
const OTHER_FILE = new TextEncoder().encode('a recording of the conversation, in part');

/** sha256 from `node:crypto`, a second implementation next to the one this package digests through. */
function otherSha256Hex(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

/**
 * The digest of each fixture above, written down rather than computed: each was produced over those
 * bytes by `node:crypto` outside this repository's code, and the two are checked against each other
 * in the cases below.
 */
const FILE_SHA256_HEX = '7d4214c1df232f32b9e6935af6a7a422de12cdfecd6ba35a9b11f43113e52e45';
const OTHER_FILE_SHA256_HEX = '70613f5e0981e52cba4d2a6cbba1e00534292f0fadb4ea750c8c9c37b81a7362';

/** The request below as the transport is expected to write it, and the digest of that text. */
const ANCHORED_REQUEST_TEXT =
  '{"model":"fake-model","messages":[{"role":"user","content":"what is in this file?"}],' +
  '"file":"file-9YwQhXkLmRt2VuPz","ashaveri":{"file":{"sha256":"' +
  FILE_SHA256_HEX +
  '","bytes":40,"media_type":"audio/wav"}}}';
const ANCHORED_REQUEST_SHA256_HEX = 'abbd858b52b4958be15d2eda0baef7ce6346c335904471f333141b21b99565a9';

function forwarded(gateway: ReturnType<typeof createFakeGateway>): string {
  const body = gateway.requests.find((one) => one.method === 'POST' && typeof one.body === 'string')?.body;
  if (typeof body !== 'string') {
    throw new Error('the deployment double recorded no completion body to read');
  }
  return body;
}

describe('the claim a client states', () => {
  it('names the digest, the length and the declared media type of the bytes it was handed', () => {
    const member = fileAnchor(FILE, 'audio/wav');
    // The literal and `node:crypto` are two spellings of one hash reached away from this code, and the
    // helper has to agree with both: an expected value taken from the helper itself could not disagree
    // with it whatever bytes it hashed.
    expect(otherSha256Hex(FILE)).toBe(FILE_SHA256_HEX);
    expect(member).toEqual({
      file: { sha256: FILE_SHA256_HEX, bytes: FILE.byteLength, media_type: 'audio/wav' },
    });
    expect(member.file.sha256).toMatch(/^[0-9a-f]{64}$/u);
  });

  it('states nothing about the file it cannot state, and discloses a name only when asked', () => {
    expect(Object.keys(fileAnchor(FILE, 'audio/wav').file)).toEqual(['sha256', 'bytes', 'media_type']);
    expect(fileAnchor(FILE, 'audio/wav', { name: 'session-12.wav' }).file.name).toBe('session-12.wav');
  });

  it('is data a caller puts in its own body, and not a request of its own', () => {
    const member = fileAnchor(FILE, 'audio/wav');
    // Plain JSON all the way down: the value survives a round trip through a serializer untouched,
    // which is the whole of what it owes a caller, and it carries no byte of the file with it.
    expect(JSON.parse(JSON.stringify(member))).toEqual(member);
    expect(JSON.stringify(member)).not.toContain('recording');
  });

  it('refuses the inputs that would state no claim at all', () => {
    expect(() => fileAnchor(new Uint8Array(0), 'audio/wav')).toThrow(TypeError);
    expect(() => fileAnchor(new Uint8Array(0), 'audio/wav')).toThrow(/no bytes at all/u);
    expect(() => fileAnchor(FILE, '')).toThrow(/media type/u);
    expect(() => fileAnchor(FILE, 'audio/wav', { name: '' })).toThrow(/discloses nothing/u);
  });
});

describe('a claim carried by a real request', () => {
  it('is inside the digest the receipt signs, while the file itself never reaches the wire', async () => {
    const gateway = createFakeGateway();
    const client = new AshaveriClient({ baseUrl: FAKE_BASE_URL, fetch: gateway.fetch });
    const member = fileAnchor(FILE, 'audio/wav');
    const result = await client.chat.completions.create({
      model: 'fake-model',
      messages: [{ role: 'user', content: 'what is in this file?' }],
      // The provider's own handle for the bytes, obtained out of band: in a request that digests a
      // file this is often the only place the file is mentioned at all.
      file: 'file-9YwQhXkLmRt2VuPz',
      [FILE_ANCHOR_MEMBER_NAME]: member,
    });
    if (result.receipt === null) throw new Error('a receipting gateway returned a completion with no receipt');
    const body = forwarded(gateway);
    // The text is the one this test wrote, and the digest the receipt carries is that text's own,
    // measured against the literal and against `node:crypto` rather than against a re-run of the
    // hashing this package does.
    expect(body).toBe(ANCHORED_REQUEST_TEXT);
    expect(toHex(result.receipt.payload.req)).toBe(ANCHORED_REQUEST_SHA256_HEX);
    expect(toHex(result.receipt.payload.req)).toBe(otherSha256Hex(new TextEncoder().encode(ANCHORED_REQUEST_TEXT)));
    expect(body).toContain('file-9YwQhXkLmRt2VuPz');
    expect(body).not.toContain('recording');
    // A `match` says the request stated this digest and these bytes are that digest. It says nothing
    // about who held the file and nothing about whether a provider read it.
    expect(verifyFileAnchor(body, FILE)).toEqual({ status: 'match', sha256: FILE_SHA256_HEX, bytes: FILE.byteLength });
    expect(verifyFileAnchor(body, OTHER_FILE)).toEqual({
      status: 'mismatch',
      computedSha256: OTHER_FILE_SHA256_HEX,
      computedBytes: OTHER_FILE.byteLength,
      claimedSha256: FILE_SHA256_HEX,
      claimedBytes: FILE.byteLength,
    });
  });
});
