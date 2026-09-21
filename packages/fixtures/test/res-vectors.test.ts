import { describe, expect, it } from 'vitest';
import {
  fromBase64Url,
  hashRequest,
  signingKeyFromSeed,
  toBase64Url,
  toHex,
  verifyReceipt,
  type VerifiedReceipt,
} from '@ashaveri/receipt';
import {
  buildGateway,
  CREDENTIALS_FILE_VERSION,
  CredentialStore,
  mockDeployment,
  newBearerCredential,
  openMemoryAccessLog,
  openMemoryReceiptStore,
  type CompletionBackend,
} from '@ashaveri/signerd';
import {
  loadReqVectors,
  loadResVectors,
  type RequestVector,
  type ResponseVector,
} from '../src/index.js';

const file = loadResVectors();
const requests = loadReqVectors();

const MODEL_ID = 'mock-model-1';
const CLOCK = 1_772_000_000;
/** The lead byte of the three-byte symbol character one of these responses carries. */
const MULTIBYTE_LEAD = 0xe2;

/**
 * A host key for these runs, derived from a readable phrase so nothing key-shaped is tracked.
 * TEST ONLY: it signs the receipts this suite reads back, and signs nothing anywhere else.
 */
const HOST_KEY = signingKeyFromSeed(
  hashRequest(new TextEncoder().encode('ashaveri-digest-vector-host-key')),
);

function vectorNamed(name: string): ResponseVector {
  const found = file.vectors.find((each) => each.name === name);
  if (found === undefined) throw new Error(`data/res-v1.json has no vector named ${name}`);
  return found;
}

function requestOf(vector: ResponseVector): RequestVector {
  const found = requests.vectors.find((each) => each.name === vector.request);
  if (found === undefined) throw new Error(`data/req-v1.json has no vector named ${vector.request}`);
  return found;
}

/** A nonce per vector, so no two runs of this file present the same one. */
function nonceFor(vector: ResponseVector): Uint8Array {
  return hashRequest(new TextEncoder().encode(vector.name)).slice(0, 16);
}

/** The published response, as the pieces the file says it was written in. */
function piecesOf(vector: ResponseVector): Buffer[] {
  return vector.chunksBase64Url.map((part) => Buffer.from(part, 'base64url'));
}

function whole(vector: ResponseVector): Buffer {
  return Buffer.concat(piecesOf(vector));
}

function asBytes(vector: ResponseVector): Buffer {
  return Buffer.from(fromBase64Url(vector.responseBase64Url));
}

/**
 * One completion out of a gateway that is running, with the vector's bytes as its upstream body.
 *
 * This is why the response suite is published at all: the digest in the file is the one the gateway
 * wrote into a receipt it signed, over bytes this call received on the wire, rather than a digest a
 * test worked out for itself. The upstream is fixed because the mock model stamps each completion
 * with a fresh identifier and the current time, and a vector has to be the same bytes whenever
 * anyone reads it.
 */
async function completion(vector: ResponseVector): Promise<{ receipt: VerifiedReceipt; wire: Buffer }> {
  const chunks = piecesOf(vector);
  const backend: CompletionBackend = {
    async respond() {
      return {
        status: 200,
        contentType: vector.contentType,
        chunks: (async function* (): AsyncGenerator<Buffer> {
          for (const each of chunks) {
            yield each;
          }
        })(),
        usage: Promise.resolve({ model: MODEL_ID, promptTokens: 9, completionTokens: 6 }),
      };
    },
  };
  const caller = newBearerCredential({ id: 'digest-vector-caller', scopes: ['complete', 'read'], now: CLOCK });
  const receipts = openMemoryReceiptStore();
  const deployment = mockDeployment({ key: HOST_KEY });
  const app = buildGateway({
    deployment,
    backend,
    store: receipts,
    access: new CredentialStore({
      file: { version: CREDENTIALS_FILE_VERSION, credentials: [caller.record] },
      allowBearer: true,
    }),
    accessLog: openMemoryAccessLog(),
  });
  try {
    const response = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${toBase64Url(caller.secret)}`,
        'x-ashaveri-nonce': toBase64Url(nonceFor(vector)),
      },
      payload: Buffer.from(fromBase64Url(vector.requestBase64Url)).toString('utf8'),
    });
    expect(response.statusCode, `${vector.name} was never completed`).toBe(200);
    expect(response.headers['content-type']).toContain(vector.contentType);
    const id = response.headers['x-ashaveri-receipt-id'];
    if (typeof id !== 'string') throw new Error(`${vector.name} was completed without a receipt id`);
    const stored = await receipts.get(id);
    if (stored === null) throw new Error(`no receipt was kept for ${id}`);
    return {
      receipt: verifyReceipt(stored, { publicKey: deployment.key.publicKey }),
      wire: response.rawPayload,
    };
  } finally {
    await app.close();
  }
}

describe('data/res-v1.json', () => {
  it('states which receipt field it pins and how the digest is written', () => {
    expect(file.version).toBe(1);
    expect(file.rule.receiptField).toBe('res');
    expect(file.rule.algorithm).toBe('sha256');
    expect(file.rule.encoding).toBe('lowercase hex, 64 characters');
    expect(file.vectors.length).toBeGreaterThanOrEqual(5);
    for (const vector of file.vectors) {
      expect(vector.resHex).toMatch(/^[0-9a-f]{64}$/u);
      expect(Buffer.from(vector.resHex, 'hex')).toHaveLength(32);
      expect(['application/json', file.framing.contentType]).toContain(vector.contentType);
    }
    expect(new Set(file.vectors.map((vector) => vector.name)).size).toBe(file.vectors.length);
  });

  it('publishes one byte string per response, however many writes carried it', () => {
    for (const vector of file.vectors) {
      expect(whole(vector)).toEqual(asBytes(vector));
      expect(vector.responseByteLength).toBe(asBytes(vector).length);
    }
  });

  it('names the request it answered with the bytes the request suite publishes', () => {
    for (const vector of file.vectors) {
      expect(vector.requestBase64Url).toBe(requestOf(vector).bodyBase64Url);
    }
  });

  it.each(file.vectors)('a running gateway signs $name as the file states', async (vector) => {
    const { receipt, wire } = await completion(vector);
    expect(wire).toEqual(asBytes(vector));
    expect(toHex(receipt.payload.res)).toBe(vector.resHex);
    expect(toHex(receipt.payload.req)).toBe(requestOf(vector).reqHex);
  });

  it('hashes the framing a streamed completion arrives in', async () => {
    const framed = vectorNamed('streamed-frames');
    const text = whole(framed).toString('utf8');
    // The framing this file states is the framing these bytes carry, and it is inside the hash.
    expect(text.startsWith(file.framing.fieldPrefix)).toBe(true);
    expect(text.endsWith(file.framing.terminator)).toBe(true);
    expect(text).toContain(`[DONE]${file.framing.frameSeparator}`);
    const frames = text.split(file.framing.frameSeparator).filter((each) => each.length > 0);
    expect(frames.length).toBeGreaterThanOrEqual(4);
    for (const frame of frames) {
      expect(frame.startsWith(file.framing.fieldPrefix)).toBe(true);
    }

    const { receipt, wire } = await completion(framed);
    // Byte for byte: what the client received is what the file states, and what the file states is
    // what the gateway signed.
    expect(wire).toEqual(asBytes(framed));
    expect(toHex(receipt.payload.res)).toBe(framed.resHex);
    expect(toHex(receipt.payload.nce)).toBe(toHex(nonceFor(framed)));
    expect(receipt.payload.mdl).toBe(MODEL_ID);
  });

  it('takes the digest of the stream and not of the writes', async () => {
    const framed = vectorNamed('streamed-frames');
    const broken = vectorNamed('streamed-frames-split-mid-character');
    expect(broken.chunksBase64Url.length).toBeGreaterThan(1);
    expect(whole(broken)).toEqual(whole(framed));
    expect(broken.resHex).toBe(framed.resHex);
    // The break falls inside a character rather than between two of them, which no amount of
    // text handling recovers: the hash is of the octets of the stream.
    const firstWrite = piecesOf(broken)[0] ?? Buffer.alloc(0);
    expect(firstWrite[firstWrite.length - 1]).toBe(MULTIBYTE_LEAD);
    const { receipt } = await completion(broken);
    expect(toHex(receipt.payload.res)).toBe(framed.resHex);
  });

  it('tells a framed stream from the same payloads without their framing', () => {
    const framed = vectorNamed('streamed-frames');
    const stripped = vectorNamed('streamed-payloads-without-framing');
    const framedText = whole(framed).toString('utf8');
    const strippedText = whole(stripped).toString('utf8');
    // Every payload of the framed stream is in the stripped body, which is exactly the mistake: the
    // two digests are as far apart as the bytes they were taken over.
    for (const event of framedText.split(file.framing.frameSeparator).filter((each) => each.length > 0)) {
      expect(strippedText).toContain(event.slice(file.framing.fieldPrefix.length));
    }
    expect(stripped.resHex).not.toBe(framed.resHex);
    expect(toHex(hashRequest(whole(stripped)))).toBe(stripped.resHex);
  });

  it('counts one byte at the end of a body as the difference it is', async () => {
    const plain = vectorNamed('buffered-completion');
    const extended = vectorNamed('buffered-completion-trailing-newline');
    expect(whole(extended)).toEqual(Buffer.concat([whole(plain), Buffer.from('\n')]));
    expect(extended.resHex).not.toBe(plain.resHex);
    expect((await completion(plain)).wire).toEqual(asBytes(plain));
    expect((await completion(extended)).wire).toEqual(asBytes(extended));
  });
});
