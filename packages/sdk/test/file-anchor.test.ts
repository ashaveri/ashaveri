import { describe, expect, it } from 'vitest';
import { sha256 } from '@noble/hashes/sha2.js';
import { FILE_ANCHOR_MEMBER_NAME, hashRequest, verifyFileAnchor } from '@ashaveri/receipt';
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
 */

const FILE = new TextEncoder().encode('a recording of the conversation, in full');
const OTHER_FILE = new TextEncoder().encode('a recording of the conversation, in part');

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

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
    // The digest is reached by the hash function straight from the dependency, so the value a client
    // states is witnessed against the function the verifier will recompute with rather than against
    // a second copy of the client's own arithmetic.
    expect(member).toEqual({
      file: { sha256: hex(sha256(FILE)), bytes: FILE.byteLength, media_type: 'audio/wav' },
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
    expect(body).toContain('file-9YwQhXkLmRt2VuPz');
    expect(body).not.toContain('recording');
    expect(hashRequest(new TextEncoder().encode(body))).toEqual(result.receipt.payload.req);
    expect(verifyFileAnchor(body, FILE)).toEqual({ status: 'match', sha256: member.file.sha256, bytes: FILE.byteLength });
    expect(verifyFileAnchor(body, OTHER_FILE).status).toBe('mismatch');
  });
});
