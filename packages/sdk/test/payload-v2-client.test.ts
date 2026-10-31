import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  MARKING_MEMBER_NAME,
  decodeReceipt,
  extractMarkedRegion,
  hashRequest,
  issueReceipt,
  provenanceV1Member,
  signingKeyFromSeed,
  toHex,
  type Marking,
  type ReceiptPayload,
  type ReceiptPayloadV2,
  type SigningKey,
  type VerifiedReceipt,
} from '@ashaveri/receipt';
import { GatewaySession } from '../src/gateway.js';
import { MANIFEST_BASE_URL, keyEntry, manifestTransport, plainManifest } from './manifest-documents.js';

/**
 * The receipt a customer's verifier actually runs is the one the shipped client path reads, and the
 * published vectors are the bytes that path is measured against. Nothing here widens that path: what it
 * asks is whether a document whose payload names the newer version reaches the checks every receipt owes,
 * and whether it is refused for what it states rather than for the number it wears.
 *
 * Three properties, in this order. The marking claim and the anchor demands are read off the payload
 * members that carry them and never off `v`, so a version 2 document is weighed over the bytes it was
 * handed, and a client that stepped around its mark would answer nothing wrong about it. A refusal of a
 * version 2 statement about encryption answers with the code of that rule and not with a version error,
 * which is the answer the format gives before the client's own policy stage is reached at all. And a
 * session document names a key the receipt itself cannot tie to a measurement: `att` states a digest, an
 * instant and a route, and no member states what that evidence's report data carried, so the binding
 * belongs to a second document the deployment's key route would serve and no shipped route serves today.
 * The last case is written to keep that absence from quietly becoming a claim: a client that answered
 * differently about two documents whose only difference was the key they name would be measuring
 * something no member of either document states.
 */

const DATA = fileURLToPath(new URL('../../fixtures/data/', import.meta.url));
const utf8 = (value: string): Uint8Array => new TextEncoder().encode(value);

/** One published receipt row, as far as this file reads it. */
interface PublishedRow {
  readonly name: string;
  readonly path: string;
  readonly expected: string;
  readonly responseBase64Url?: string;
  readonly enc?: { sch: string; pkBase64Url?: string };
}

const manifest = JSON.parse(readFileSync(join(DATA, 'manifest.json'), 'utf8')) as { fixtures: PublishedRow[] };
const keyFile = JSON.parse(readFileSync(join(DATA, 'keys', 'receipt-key-v1.json'), 'utf8')) as {
  publicKey: string;
  kid: string;
  privateKey: string;
};

/** The key the published family is signed under, read out of the file that publishes it. */
const PUBLISHED_KEY: SigningKey = {
  privateKey: new Uint8Array(Buffer.from(keyFile.privateKey, 'hex')),
  publicKey: new Uint8Array(Buffer.from(keyFile.publicKey, 'hex')),
  kid: new Uint8Array(Buffer.from(keyFile.kid, 'hex')),
};

/** A key of this file's own, for the documents the shipped writer is asked to make below. */
const LOCAL_KEY: SigningKey = signingKeyFromSeed(new Uint8Array(32).fill(21));
const LOCAL_IAT = 1_700_000_000;

function rowNamed(name: string): PublishedRow {
  const found = manifest.fixtures.find((each) => each.name === name);
  if (found === undefined) throw new Error(`the published manifest states no row named ${name}`);
  return found;
}

function publishedBytes(row: PublishedRow): Uint8Array {
  return new Uint8Array(readFileSync(join(DATA, row.path)));
}

function publishedResponse(row: PublishedRow): Uint8Array {
  if (row.responseBase64Url === undefined) throw new Error(`${row.name} publishes no response bytes`);
  return new Uint8Array(Buffer.from(row.responseBase64Url, 'base64url'));
}

/**
 * A session over one deployment manifest. The document declares the keys the session may resolve, in the
 * epoch the manifest itself states, and its transport serves nothing else, so a verification below cannot
 * quietly reach a host this file did not point it at.
 */
function sessionDeclaring(keys: readonly SigningKey[], epoch: number, issuer: string): GatewaySession {
  const served = plainManifest({ iss: issuer, epoch, keys: keys.map((one) => keyEntry(one)) });
  return new GatewaySession(MANIFEST_BASE_URL, { fetchImpl: manifestTransport(served) });
}

/** One handover of the client path: the document, the bytes it claims, and the instant it names. */
async function verifyThroughTheClient(
  session: GatewaySession,
  receiptBytes: Uint8Array,
  responseBytes: Uint8Array,
  over: { readonly requestHash?: Uint8Array } = {},
) {
  const claims = decodeReceipt(receiptBytes).payload;
  return session.verifyReceipted({
    receiptBytes,
    nonce: claims.nce,
    requestHash: over.requestHash ?? claims.req,
    responseHash: claims.res,
    responseBytes,
    nowMillis: claims.iat * 1000,
  });
}

/** The payload of a document this file has just read, at the version that names an encryption arm. */
function encryptionOf(receipt: VerifiedReceipt): ReceiptPayloadV2['enc'] {
  if (receipt.payload.v !== 2) throw new Error('the client read a document that names no encryption arm');
  return receipt.payload.enc;
}

/** The key a verified document names, in hex, or the plain arm's statement that it names none. */
function keyNamed(receipt: VerifiedReceipt): string {
  const enc = encryptionOf(receipt);
  return enc.sch === 'none' ? 'no key' : toHex(enc.pk);
}

/** The identity of a refusal, so no case is satisfied by just any error. */
async function failureFrom(run: () => Promise<unknown>): Promise<{ name: string; code: string; message: string }> {
  try {
    await run();
  } catch (error) {
    const given = error as { name?: string; code?: string; message?: string };
    return { name: given.name ?? 'none', code: given.code ?? 'none', message: given.message ?? '' };
  }
  throw new Error('expected a refusal and the call returned normally');
}

/** The member text a marking gateway writes into a buffered completion, at one instant. */
function memberText(at: number): string {
  return `${JSON.stringify(MARKING_MEMBER_NAME)}:${JSON.stringify(provenanceV1Member(at))}`;
}

function markedBody(at: number): string {
  return `{"id":"chatcmpl-v2proof","object":"chat.completion","choices":[]${`,\n  ${memberText(at)}`}}`;
}

/**
 * The twelve shared fields over `responseBytes`, then the five a receipt states about itself, written the
 * way an issuing gateway writes them, so the only thing a case below moves is the one member it names.
 */
function v2Over(responseBytes: Uint8Array, mk: Marking, enc: ReceiptPayloadV2['enc']): ReceiptPayloadV2 {
  const res = hashRequest(responseBytes);
  const fields: Omit<ReceiptPayload, 'v' | 'mk' | 'sd' | 'cva' | 'itm' | 'enc'> = {
    iss: 'v2proof-issuer',
    ins: 'v2proof-instance',
    iat: LOCAL_IAT,
    nce: new Uint8Array(16).fill(3),
    req: hashRequest(utf8('the request')),
    res,
    mdl: 'v2proof-model',
    wts: new Uint8Array(32).fill(8),
    meas: { tee: 'software', m: new Uint8Array(32).fill(6) },
    att: { d: new Uint8Array(32).fill(9), ts: LOCAL_IAT, url: `${MANIFEST_BASE_URL}/attestation` },
    epk: 0,
    tok: { p: 1, c: 1 },
  };
  return {
    ...fields,
    v: 2,
    mk,
    sd: { name: 'host clock', uncertaintySeconds: null },
    cva: {
      collateral: { presence: 'held', sha256: hashRequest(utf8('the collateral this issuance took in')) },
      validity: { presence: 'not-taken-in', reason: 'no window was put into this record' },
    },
    itm: [{ t: LOCAL_IAT - 1, d: res }],
    enc,
  };
}

describe('the shipped client path reading a version 2 receipt', () => {
  it('verifies each published version 2 acceptance over the bytes its own row publishes', async () => {
    const published = decodeReceipt(publishedBytes(rowNamed('receipt-enc-plain-v2'))).payload;
    const session = sessionDeclaring([PUBLISHED_KEY], published.epk, published.iss);
    for (const name of ['receipt-enc-plain-v2', 'receipt-enc-session-v2']) {
      const row = rowNamed(name);
      const responseBytes = publishedResponse(row);
      const verified = await verifyThroughTheClient(session, publishedBytes(row), responseBytes);
      expect(verified.payload.v, `${name} version the client read`).toBe(2);
      // The digest the client weighed is the digest of the bytes it was handed, which is all a receipt
      // attests: the session row states that those bytes were sealed, and nothing here asks what they were
      // before the sealing, because the document says nothing about that either.
      expect(toHex(verified.payload.res), `${name} res over the handed bytes`).toBe(toHex(hashRequest(responseBytes)));
      expect(encryptionOf(verified).sch, `${name} arm the client read`).toBe(row.enc?.sch);
    }
  });

  it('weighs the mark the published document claims against the region in those same bytes', async () => {
    const row = rowNamed('receipt-enc-plain-v2');
    const responseBytes = publishedResponse(row);
    const payload = decodeReceipt(publishedBytes(row)).payload;
    // The claim is checkable over the published bytes before any client reads it: the region the shipped
    // rule locates in them is the region whose digest the signed document carries, so the step the client
    // takes below has an answer to compare rather than a value to trust.
    expect(payload.mk.sch).toBe('provenance-v1');
    expect(toHex(hashRequest(extractMarkedRegion(payload.mk.sch, responseBytes)))).toBe(toHex(payload.mk.d));
    const verified = await verifyThroughTheClient(
      sessionDeclaring([PUBLISHED_KEY], payload.epk, payload.iss),
      publishedBytes(row),
      responseBytes,
    );
    expect(toHex(verified.payload.mk.d)).toBe(toHex(payload.mk.d));
  });

  it('refuses a version 2 document handed the bytes another row publishes, by the digest and not the version', async () => {
    const plain = rowNamed('receipt-enc-plain-v2');
    const other = rowNamed('receipt-enc-session-v2');
    const claims = decodeReceipt(publishedBytes(plain)).payload;
    const session = sessionDeclaring([PUBLISHED_KEY], claims.epk, claims.iss);
    const failure = await failureFrom(async () =>
      verifyThroughTheClient(session, publishedBytes(plain), publishedResponse(other)),
    );
    expect(failure.name).toBe('SdkError');
    expect(failure.code).toBe('RESPONSE_HASH_MISMATCH');
    expect(failure.message).not.toContain('version');
  });

  it('answers the published encryption refusals with their own codes, not with a version error', async () => {
    for (const name of ['receipt-enc-missing-v2', 'receipt-enc-unknown-v2', 'receipt-enc-plaintext-key-v2']) {
      const row = rowNamed(name);
      const session = sessionDeclaring([PUBLISHED_KEY], 1, 'dpl-9f2a41c3');
      const failure = await failureFrom(async () =>
        verifyThroughTheClient(session, publishedBytes(row), publishedResponse(row)),
      );
      expect(failure.name, name).toBe('ReceiptError');
      expect(`${name}: ${failure.code}`, 'the code the published row promises').toBe(`${name}: ${row.expected}`);
      expect(failure.code, name).not.toBe('UNSUPPORTED_VERSION');
    }
  });
  it('refuses a version 2 document whose attested mark is not the one in the bytes', async () => {
    const requestHash = hashRequest(utf8('the request'));
    const body = utf8(markedBody(LOCAL_IAT));
    const attested: Marking = { sch: 'provenance-v1', d: hashRequest(utf8(memberText(LOCAL_IAT))) };
    const misplaced: Marking = { sch: 'provenance-v1', d: hashRequest(utf8(memberText(LOCAL_IAT + 60))) };
    const session = sessionDeclaring([LOCAL_KEY], 0, 'v2proof-issuer');
    const signedWith = (mk: Marking): Uint8Array => issueReceipt(v2Over(body, mk, { sch: 'none' }), LOCAL_KEY);

    const failure = await failureFrom(async () =>
      verifyThroughTheClient(session, signedWith(misplaced), body, { requestHash }),
    );
    expect(failure.name).toBe('ReceiptError');
    expect(failure.code).toBe('MARK_MISMATCH');
    expect(failure.message).toContain('mk.d');
    // The same document at the same version, with the region it does attest, passes on the same call: the
    // refusal above is the mark, and not a client that answers every version 2 document with a marking
    // code because it never learned to read the newer number.
    const verified = await verifyThroughTheClient(session, signedWith(attested), body, { requestHash });
    expect(verified.payload.v).toBe(2);
    expect(encryptionOf(verified).sch).toBe('none');
  });

  it('says nothing about the key a session names: two documents apart only in `pk` answer alike', async () => {
    const body = utf8(markedBody(LOCAL_IAT));
    const mark: Marking = { sch: 'provenance-v1', d: hashRequest(utf8(memberText(LOCAL_IAT))) };
    const first = issueReceipt(v2Over(body, mark, { sch: 'x25519-aes-256-gcm-v1', pk: new Uint8Array(32).fill(4) }), LOCAL_KEY);
    const second = issueReceipt(v2Over(body, mark, { sch: 'x25519-aes-256-gcm-v1', pk: new Uint8Array(32).fill(5) }), LOCAL_KEY);
    const session = sessionDeclaring([LOCAL_KEY], 0, 'v2proof-issuer');
    const handed = { requestHash: hashRequest(utf8('the request')) };
    const one = await verifyThroughTheClient(session, first, body, handed);
    const two = await verifyThroughTheClient(session, second, body, handed);
    // Two documents naming different keys, and the client answers both alike, because what it weighs is
    // bytes and digests. A verdict that moved here would be a claim about a measurement that no member of
    // either document makes: the receipt states a key and stays silent on its binding, and the second
    // document that could answer for it is one no shipped route serves.
    expect(keyNamed(one)).not.toBe(keyNamed(two));
    expect(toHex(one.payload.res)).toBe(toHex(two.payload.res));
    expect(encryptionOf(one).sch).toBe('x25519-aes-256-gcm-v1');
  });
});
