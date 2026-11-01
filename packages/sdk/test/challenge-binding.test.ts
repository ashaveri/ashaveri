import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  decodeReceipt,
  emptyRegion,
  hashRequest,
  issueReceipt,
  signingKeyFromSeed,
  toHex,
  type Encryption,
  type ReceiptPayload,
  type ReceiptPayloadV2,
} from '@ashaveri/receipt';
import { encodeV0Tdx } from '../../attest-core/test/helpers.js';
import { GatewaySession, SdkError, evidenceReportData, verifyCompletionEvidence } from '../src/index.js';

/**
 * The challenge a receipt states, and the two ways a reader can get it wrong.
 *
 * The rule is one line and no signature test catches it: a session receipt binds the quote to
 * `sha256(nce || pk || keyId(pk) || req)`, a plain one to `sha256(nce || req)`, and every part is read out
 * of the signed payload rather than handed in beside it. What is held here is therefore what a stranger's
 * implementation can disagree about and still produce a document that parses: which arm decides, where the
 * key comes from, and in which order the parts are concatenated.
 *
 * The refusals are run through the shipped verifier rather than asserted from prose. A document minted for
 * the *other* rule's value is answered `EVIDENCE_DIGEST_MISMATCH` on the receipt-linked path, because the
 * evidence route mints for any caller-named value instead of looking one up, so the skew surfaces at the
 * receipt's own digest commitment and never as `EVIDENCE_NOT_FOUND`; a document the receipt genuinely
 * commits to, whose quoted field is not this rule's value, is answered `EVIDENCE_REPORT_DATA_MISMATCH`.
 * No quote under `attest-core/test/fixtures/` carries a composite, because a captured report data is fixed
 * by its own signature: the arithmetic is pinned here and published as a vector, and the platform seal over
 * a composite is owed to a capture.
 */

const utf8 = (value: string): Uint8Array => new TextEncoder().encode(value);

function concat(...parts: readonly Uint8Array[]): Uint8Array {
  const all = new Uint8Array(parts.reduce((total, one) => total + one.length, 0));
  let at = 0;
  for (const part of parts) {
    all.set(part, at);
    at += part.length;
  }
  return all;
}

function fromHex(value: string): Uint8Array {
  return new Uint8Array(value.match(/../g)!.map((pair) => Number.parseInt(pair, 16)));
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const one of bytes) binary += String.fromCharCode(one);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

const KEY = signingKeyFromSeed(hashRequest(utf8('ashaveri-test-challenge-binding-key')));
const BASE = 'https://challenge.test/v1';
const IAT = 1_772_000_000;
const RESPONSE_BYTES = utf8('{"id":"chatcmpl-challenge","object":"chat.completion","choices":[]}');

/** One triple, in both arms, with both digests computed here rather than by the code under test. */
const NONCE = new Uint8Array(16).fill(9);
const REQUEST_HASH = hashRequest(utf8('{"model":"m","messages":[]}'));
const SESSION_KEY = new Uint8Array(32).fill(17);
const TWO_PART = sha256(concat(NONCE, REQUEST_HASH));
// The key identifier the composite carries: `sha256(pk)`, the same 32 bytes a reader computes for a
// header `kid`, so the value inside the sealed digest is a value reachable from the receipt alone.
const KEY_ID = sha256(SESSION_KEY);
const FOUR_PART = sha256(concat(NONCE, SESSION_KEY, KEY_ID, REQUEST_HASH));
// The composite as it read before the identifier joined it. It is not a rule any arm states, so it
// belongs to the refused set: a quote sealed under the older order must not bind a current receipt.
const LEGACY_THREE_PART = sha256(concat(NONCE, SESSION_KEY, REQUEST_HASH));
const PLAIN: Encryption = { sch: 'none' };
const SESSION: Encryption = { sch: 'x25519-aes-256-gcm-v1', pk: SESSION_KEY };

// A real Intel-signed TD quote, so the binding step below runs over bytes Intel sealed rather than over a
// stand-in a parser bug could agree with. Its REPORT_DATA is the fixture host's own ASCII value: no captured
// quote can be asked to carry a digest this file chooses, which is the half owed to a capture.
const QUOTE = new Uint8Array(readFileSync(new URL('../../attest-core/test/fixtures/tdx-quote-v4.bin', import.meta.url)));
// The quote's own REPORT_DATA field: 28 ASCII bytes the fixture host wrote, zero-padded to the 64 the
// platform signs. Stated as a length and a padding rather than as a hex literal, because the width is the
// fact the binding rule is read against.
const QUOTE_REPORT_DATA = toHex(concat(utf8('Hello from Edgeless Systems!'), new Uint8Array(36)));
const MR_TD = 'b65ea009e424e6f761fdd3d7c8962439453b37ecdf62da04f7bc5d327686bb8bafc8a5d24a9c31cee60e4aba87c2f71b';
const NOW = Date.UTC(2026, 0, 15);
const INTEL_DOCUMENT = encodeV0Tdx({
  quote: QUOTE,
  eventLog: [],
  runtimeEvents: [],
  reportData: fromHex(QUOTE_REPORT_DATA),
  config: 'ashaveri-challenge-test',
});

/** A version 2 document stating the arm the case names, over the bytes this suite hands the client. */
function receiptPayload(over: {
  readonly enc: Encryption;
  readonly attested: Uint8Array;
  readonly tee?: ReceiptPayload['meas']['tee'];
}): ReceiptPayloadV2 {
  return {
    v: 2,
    iss: 'challenge-issuer',
    ins: 'cvm-i-challenge',
    iat: IAT,
    nce: NONCE,
    req: REQUEST_HASH,
    res: hashRequest(RESPONSE_BYTES),
    mdl: 'challenge-model',
    wts: hashRequest(utf8('weights:challenge-model')),
    meas: { tee: over.tee ?? 'tdx', m: fromHex(MR_TD) },
    att: { d: over.attested, ts: IAT - 30, url: `${BASE}/attestation` },
    epk: 0,
    tok: { p: 3, c: 4 },
    mk: { sch: 'none', d: sha256(emptyRegion()) },
    sd: { name: 'host clock', uncertaintySeconds: null },
    cva: {
      collateral: { presence: 'not-taken-in', reason: 'this suite takes no collateral in' },
      validity: { presence: 'not-taken-in', reason: 'this suite records no validity context' },
    },
    itm: [{ t: IAT - 1, d: hashRequest(RESPONSE_BYTES) }],
    enc: over.enc,
  };
}

function issued(payload: ReceiptPayloadV2): Uint8Array {
  return issueReceipt(payload, KEY);
}

/** The document the route mints for one named value: a stand-in, since the minting is what is at issue. */
const mint = (reportData: Uint8Array): Uint8Array => concat(utf8('evidence-minted-for-'), reportData);

/** What a receipt commits to when the deployment minted its evidence for one named value. */
const attestedFor = (reportData: Uint8Array): Uint8Array => sha256(mint(reportData));

/**
 * A deployment that signs receipts under `KEY`, declares that key in its manifest, and answers each evidence
 * route with the document it mints for the value it was named, which is what the shipped route does and is the
 * fact that decides which code a skew lands on. Every URL it was asked for is recorded, so a case below reads
 * the client's own challenge out of the request rather than out of a return value.
 */
function serving(): { session: GatewaySession; urls: string[] } {
  const urls: string[] = [];
  const fetchImpl: typeof fetch = async (input) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    urls.push(url);
    if (url === `${BASE}/deployment-manifest`) {
      return Response.json({
        v: 1,
        iss: 'challenge-issuer',
        ins: 'cvm-i-challenge',
        epk: 0,
        keys: [{ kid: toHex(KEY.kid), alg: 'Ed25519', publicKey: toBase64Url(KEY.publicKey) }],
        models: [{ id: 'challenge-model', wts: toHex(hashRequest(utf8('weights:challenge-model'))) }],
        meas: { tee: 'tdx', m: toHex(fromHex(MR_TD)) },
      });
    }
    const evidence = /\/attestation(\/gpu)?\?report_data=([0-9a-f]{64})$/u.exec(url.toLowerCase());
    if (evidence !== null) return new Response(mint(fromHex(evidence[2]!)), { status: 200 });
    return new Response('not found', { status: 404 });
  };
  return { session: new GatewaySession(BASE, { fetchImpl }), urls };
}

/** The evidence routes a run was answered by, in the order they were asked, as the challenge each carried. */
function challengesAsked(urls: readonly string[]): string[] {
  return urls
    .filter((url) => url.includes('/attestation'))
    .map((url) => new URL(url).searchParams.get('report_data') ?? '');
}

async function refusal(run: () => Promise<unknown>): Promise<string> {
  try {
    await run();
  } catch (error) {
    expect(error, 'the client path threw something that was not its own coded error').toBeInstanceOf(SdkError);
    return (error as SdkError).code;
  }
  throw new Error('expected a refusal and the call returned normally');
}

function refusalCode(run: () => unknown): string {
  try {
    run();
  } catch (error) {
    if (error instanceof SdkError) return error.code;
    throw error;
  }
  throw new Error('expected a refusal and the call returned normally');
}

describe('the challenge a receipt states', () => {

  it('asks the evidence route with the composite the session arm names', async () => {
    const receiptBytes = issued(receiptPayload({ enc: SESSION, attested: attestedFor(FOUR_PART) }));
    const served = serving();
    const code = await refusal(() =>
      served.session.verifyCompletion({
        receiptBytes,
        nonce: NONCE,
        requestHash: REQUEST_HASH,
        responseHash: hashRequest(RESPONSE_BYTES),
        responseBytes: RESPONSE_BYTES,
        verifyEvidence: true,
        nowMillis: IAT * 1000,
      }),
    );
    expect(challengesAsked(served.urls)).toEqual([toHex(FOUR_PART)]);
    // The digest check above passed, because the route minted for the very value the receipt commits to, so
    // the refusal is the next step and these bytes are no platform document. The challenge in the URL is
    // therefore the client's own and not one the deployment handed it.
    expect(code).toBe('EVIDENCE_VERIFICATION_FAILED');
  });

  it('asks with the two-part value where the receipt states the plain arm', async () => {
    const receiptBytes = issued(receiptPayload({ enc: PLAIN, attested: attestedFor(TWO_PART) }));
    const served = serving();
    await refusal(() =>
      served.session.verifyCompletion({
        receiptBytes,
        nonce: NONCE,
        requestHash: REQUEST_HASH,
        responseHash: hashRequest(RESPONSE_BYTES),
        responseBytes: RESPONSE_BYTES,
        verifyEvidence: true,
        nowMillis: IAT * 1000,
      }),
    );
    expect(challengesAsked(served.urls)).toEqual([toHex(TWO_PART)]);
  });

  it('takes the key out of the decoded receipt rather than from a caller beside it', async () => {
    // Nothing in the call names a key: `verifyCompletion` is handed a nonce, a request digest, a response and
    // bytes. The value both runs asked for is the composite over the key inside the document, so an auditor
    // holding one receipt recomputes what the client asked without holding anything the client held.
    const payload = receiptPayload({ enc: SESSION, attested: attestedFor(FOUR_PART) });
    const receiptBytes = issued(payload);
    const asked: string[][] = [];
    for (const _ of [0, 1]) {
      const served = serving();
      await refusal(() =>
        served.session.verifyCompletion({
          receiptBytes,
          nonce: NONCE,
          requestHash: REQUEST_HASH,
          responseHash: hashRequest(RESPONSE_BYTES),
          responseBytes: RESPONSE_BYTES,
          verifyEvidence: true,
          nowMillis: IAT * 1000,
        }),
      );
      asked.push(challengesAsked(served.urls));
    }
    expect(asked[1]).toEqual(asked[0]);
    const stated = decodeReceipt(receiptBytes).payload;
    if (stated.v !== 2 || stated.enc.sch === 'none') throw new Error('this case issues a session-arm document');
    expect(toHex(stated.enc.pk)).toBe(toHex(SESSION_KEY));
    expect(asked[0]).toEqual([toHex(sha256(concat(NONCE, SESSION_KEY, KEY_ID, REQUEST_HASH)))]);
  });

  it('gives the device route the same composite it gave the platform route', async () => {
    const receiptBytes = issued(receiptPayload({ enc: SESSION, attested: attestedFor(FOUR_PART), tee: 'tdx+gpucc' }));
    const served = serving();
    await refusal(() =>
      served.session.verifyCompletion({
        receiptBytes,
        nonce: NONCE,
        requestHash: REQUEST_HASH,
        responseHash: hashRequest(RESPONSE_BYTES),
        responseBytes: RESPONSE_BYTES,
        verifyEvidence: true,
        nowMillis: IAT * 1000,
      }),
    );
    const asked = challengesAsked(served.urls);
    expect(asked).toHaveLength(2);
    expect(new Set(asked).size, `the two routes were asked ${asked.join(' and ')}`).toBe(1);
    expect(asked[0]).toBe(toHex(FOUR_PART));
  });
});

describe('the two rules refuse each other', () => {
  /**
   * One skew, in each direction: the receipt commits to the document minted under its own rule and the reader
   * is handed the document the route minted for the *other* rule's value. The route answers 200, minting for
   * any named value rather than looking one up, so the refusal lands on the receipt's own digest commitment.
   * A reader that answered `EVIDENCE_NOT_FOUND` here would be reporting an aged-out artifact, and a reader that
   * answered nothing would be binding one document for two rules.
   */
  const cases = [
    {
      name: 'a session receipt handed the document minted for the two-part value',
      enc: SESSION,
      attested: FOUR_PART,
      stale: TWO_PART,
    },
    {
      name: 'a plain receipt handed the document minted for the composite',
      enc: PLAIN,
      attested: TWO_PART,
      stale: FOUR_PART,
    },
  ];

  for (const one of cases) {
    it(one.name, async () => {
      const payload = receiptPayload({ enc: one.enc, attested: attestedFor(one.attested) });
      const served = serving();
      const wrongDocument = await served.session.attestationBytes(one.stale);
      // The route answered rather than 404'd: it mints for whatever value the caller names, which is exactly
      // why a skew cannot show up as `EVIDENCE_NOT_FOUND` on this path.
      expect(served.urls.filter((url) => url.includes(`report_data=${toHex(one.stale)}`))).toHaveLength(1);
      const code = refusalCode(() =>
        verifyCompletionEvidence({
          document: wrongDocument,
          expectedReportData: one.stale,
          payload,
          nowMillis: NOW,
        }),
      );
      expect(code).toBe('EVIDENCE_DIGEST_MISMATCH');
      // The same document under the rule that minted it takes the binding step and no refusal of the digest,
      // so the code above is the skew and not a double that cannot serve bytes.
      expect(refusalCode(() =>
        verifyCompletionEvidence({
          document: mint(one.attested),
          expectedReportData: one.attested,
          payload,
          nowMillis: NOW,
        }),
      )).toBe('EVIDENCE_VERIFICATION_FAILED');
    });
  }

  it('refuses a session receipt whose quoted field is not the composite, by the binding code', () => {
    // This document is the one the receipt commits to, so the digest step passes, the Intel signature passes,
    // and only the binding step can answer: the field Intel sealed carries the fixture host's value, which is
    // neither rule's digest of this triple, so both readings are refused by name and neither passes. The
    // accepted call at the end is the pairing that says the refusal was the binding step and nothing else.
    const attested = sha256(INTEL_DOCUMENT);
    const payload = decodeReceipt(issued(receiptPayload({ enc: SESSION, attested }))).payload;
    const ask = (expected: Uint8Array): string =>
      refusalCode(() => verifyCompletionEvidence({ document: INTEL_DOCUMENT, expectedReportData: expected, payload, nowMillis: NOW }));
    expect(ask(FOUR_PART)).toBe('EVIDENCE_REPORT_DATA_MISMATCH');
    expect(ask(TWO_PART)).toBe('EVIDENCE_REPORT_DATA_MISMATCH');
    expect(ask(LEGACY_THREE_PART)).toBe('EVIDENCE_REPORT_DATA_MISMATCH');
    expect(ask(sha256(concat(NONCE, REQUEST_HASH, SESSION_KEY)))).toBe('EVIDENCE_REPORT_DATA_MISMATCH');
    // The pairing: this document, this receipt, and the value the field actually carries. The three refusals
    // above are the binding step and nothing else, because the same call with that value returns evidence.
    const accepted = verifyCompletionEvidence({
      document: INTEL_DOCUMENT,
      expectedReportData: utf8('Hello from Edgeless Systems!'),
      payload,
      nowMillis: NOW,
    });
    expect(toHex(accepted.reportData)).toBe(QUOTE_REPORT_DATA);
  });

  it('keeps the rules apart on one triple, so no document can answer both', () => {
    expect(toHex(TWO_PART)).not.toBe(toHex(FOUR_PART));
    expect(toHex(evidenceReportData(NONCE, REQUEST_HASH, SESSION))).toBe(toHex(FOUR_PART));
    expect(toHex(evidenceReportData(NONCE, REQUEST_HASH, PLAIN))).toBe(toHex(TWO_PART));
    expect(toHex(evidenceReportData(NONCE, REQUEST_HASH))).toBe(toHex(TWO_PART));
    // The order is the wire fact the published vector pins: the same four members in another order, the
    // identifier omitted, or the identifier first are values neither arm states, and a vector each.
    expect(toHex(sha256(concat(NONCE, REQUEST_HASH, SESSION_KEY, KEY_ID)))).not.toBe(toHex(FOUR_PART));
    expect(toHex(LEGACY_THREE_PART)).not.toBe(toHex(FOUR_PART));
    expect(toHex(sha256(concat(NONCE, KEY_ID, REQUEST_HASH)))).not.toBe(toHex(FOUR_PART));
  });
});
