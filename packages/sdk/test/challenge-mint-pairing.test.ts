import { describe, expect, it } from 'vitest';
import { reportDataBinds } from '@ashaveri/attest-core';
import { decodeReceipt, hashRequest, sha256Hex, toHex, type ReceiptPayload } from '@ashaveri/receipt';
import {
  buildGateway,
  CredentialStore,
  mockDeployment,
  newPopCredential,
  openMemoryAccessLog,
  type AttestationBundle,
  type Deployment,
  type GatewayInstance,
} from '@ashaveri/signerd';
import { sha256 } from '@noble/hashes/sha2.js';
import { authorizedFetch, GatewaySession, SdkError, type AshaveriCredential } from '../src/index.js';

/**
 * The two readings of one challenge, measured against each other at the two ends of one run.
 *
 * A platform quote is asked to seal a value, and a reader that has never seen that request has to reach the
 * same value out of the signed document alone: `@ashaveri/sdk` reads `nce`, `req` and the arm's `enc.pk` off
 * the payload it has already verified, and `gateway/src/server.ts` hands a value to `deployment.attestation`
 * before a single response byte has arrived. Nothing in either reading is checkable from inside its own file.
 * A gateway that folds the two parts while the document it signs names a session key serves a quote no client
 * will ever ask for, and every receipt of that run is strict-unverifiable in a way no unit test in either
 * package can see, because each package's own arithmetic agrees with itself.
 *
 * So this file states the pairing and not the arithmetic: one issuance through the real routes, the value
 * the mint handed the platform captured at the deployment seam, the value the shipped client recomputed
 * captured off the URL it asked the evidence route with, and the requirement that they are the same bytes.
 * The client is imported rather than paraphrased, so the arm extraction this holds is the one a customer runs.
 *
 * What a mock deployment cannot reach is stated rather than skipped. Its evidence is bytes this repository
 * invents for whichever value it was named, so the reader's fetch succeeds at the receipt's own digest
 * commitment and then stops at the vendor root: `EVIDENCE_NO_TRUST_ANCHORS` on a matching pair, and
 * `EVIDENCE_DIGEST_MISMATCH` the moment the two readings come apart. That difference is the assertion, and a
 * quote signed by real hardware over a value this file chooses is owed to a capture, as
 * `packages/sdk/test/challenge-binding.test.ts` and `docs/vectors.md` both already record.
 */

const BASE = 'http://mint-pairing.invalid/v1';
const MODEL = 'mock-model-1';
const CREDENTIAL_ID = 'mint-pairing-credential';

/** Fixed bytes, so the value under test is this request's challenge and not one a run chose for itself. */
const NONCE = new Uint8Array(16).fill(11);

const utf8 = (value: string): Uint8Array => new TextEncoder().encode(value);

const BUFFERED_BODY = utf8(`{"model":"${MODEL}","messages":[{"role":"user","content":"pair the mint"}]}`);
const STREAM_BODY = utf8(
  `{"model":"${MODEL}","messages":[{"role":"user","content":"pair the mint"}],"stream":true}`,
);

/** The width a sha256 is, and the width the platform's `report_data` field is padded to. */
const DIGEST_BYTES = 32;
const QUOTE_REPORT_DATA_BYTES = 64;

/**
 * Evidence for one named value and no other, which is the fact the pairing is read out of. A document keyed
 * by the value it was minted for makes the receipt's own `att.d` a statement about that value: the reader
 * whose challenge matches reaches the vendor root, and the reader whose challenge does not is refused at the
 * digest before it ever gets there.
 */
const mintFor = (reportData: Uint8Array): Uint8Array => utf8(`evidence-minted-for-${toHex(reportData)}`);

/**
 * A deployment that claims a hardware tee, because a reader asked to fetch evidence refuses a receipt
 * declaring `software` before it looks at any route, and records every value it was asked to bind. The claim
 * is about the fixture and not about a quote: the bytes served for it are the stand-in above, and the launch
 * digest is the width the format grants the platform that claims it.
 *
 * One run of the pairing below asks this seam twice, in a fixed order: first the completion route, before a
 * response byte has arrived, whose value is the gateway's own challenge, then the evidence route, whose value
 * is whatever the reader named in its query. Both are recorded so the two are told apart by position rather
 * than by a flag this file invented.
 */
function recordingDeployment(asked: Uint8Array[]): Deployment {
  const base = mockDeployment({ model: MODEL });
  return {
    ...base,
    tee: 'tdx',
    measurement: new Uint8Array(48).fill(3),
    async attestation(reportData: Uint8Array | null): Promise<AttestationBundle> {
      if (reportData !== null) asked.push(reportData);
      const bundle = await base.attestation(reportData);
      return reportData === null ? bundle : { ...bundle, document: mintFor(reportData) };
    },
  };
}

/**
 * One request path with no socket in it: the SDK's own fetch, carried to the in-process gateway. The PoP
 * signature covers the origin-form target and the body bytes, both of which this passes on untouched, so the
 * route sees what the client signed and the admission layer admits it. The evidence route is the one URL
 * whose query is this file's subject, and it is read off the request rather than off a return value.
 */
function bridgedFetch(app: GatewayInstance, clientAsked: string[]): typeof fetch {
  return async (input, init) => {
    const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url);
    if (url.pathname === '/v1/attestation') {
      const named = url.searchParams.get('report_data');
      if (named !== null) clientAsked.push(named);
    }
    const served = await app.inject({
      method: (init?.method ?? 'GET') as 'GET' | 'POST',
      url: `${url.pathname}${url.search}`,
      headers: Object.fromEntries(new Headers(init?.headers).entries()),
      payload:
        init?.body === undefined || init.body === null
          ? undefined
          : typeof init.body === 'string'
            ? init.body
            : Buffer.from(init.body as Uint8Array),
    });
    return new Response(new Uint8Array(served.rawPayload), {
      status: served.statusCode,
      headers: new Headers(served.headers as Record<string, string>),
    });
  };
}

/**
 * One nonce per request, because the gateway replay-checks a proof-of-possession nonce and the receipt's `nce`
 * is that same header: the completion is the first request this file makes, so it carries `NONCE`, and the
 * manifest, receipt and evidence reads behind it are admitted on the ones after rather than refused `409`.
 */
function nonceSequence(): () => Uint8Array {
  let issued = 0;
  return () => {
    issued += 1;
    return issued === 1 ? NONCE : Uint8Array.from({ length: 16 }, (_, at) => at + issued);
  };
}

interface Pairing {
  /** The request bytes this run sent, whose digest is one of the two parts every reading folds. */
  readonly requestBody: Uint8Array;
  /** What the mint handed `deployment.attestation` for this run's completion. */
  readonly minted: Uint8Array;
  /** The hex value the shipped client asked the evidence route for, computed from the receipt it verified. */
  readonly requested: string;
  /** The served document, decoded by the shipped reader, so the arm in force is named rather than assumed. */
  readonly payload: ReceiptPayload;
  /** The code the strict reader reached with, which says whether the two readings agreed. */
  readonly outcome: string;
}

/**
 * One issuance, one strict verification of its receipt, and the two challenge readings taken off it. Each
 * arm of the completion route gets its own run: the buffered one signs before a byte is sent and the streamed
 * one signs after the last frame, and both take their challenge from the same line above the branch.
 */
async function pair(arm: 'buffered' | 'streamed'): Promise<Pairing> {
  const requestBody = arm === 'buffered' ? BUFFERED_BODY : STREAM_BODY;
  const askedAtTheSeam: Uint8Array[] = [];
  const clientAsked: string[] = [];

  const issued = newPopCredential({ id: CREDENTIAL_ID, scopes: ['read', 'complete'] });
  const app = buildGateway({
    access: new CredentialStore({ file: { version: 1, credentials: [issued.record] } }),
    accessLog: openMemoryAccessLog(),
    deployment: recordingDeployment(askedAtTheSeam),
  });
  const credential: AshaveriCredential = { kind: 'pop', id: CREDENTIAL_ID, privateKey: issued.privateKey };
  const fetchImpl = authorizedFetch(credential, bridgedFetch(app, clientAsked), { nonce: nonceSequence() });

  const served = await fetchImpl(`${BASE}/chat/completions`, {
    method: 'POST',
    body: requestBody,
    headers: { 'content-type': 'application/json' },
  });
  expect(served.status).toBe(200);
  const receiptId = served.headers.get('x-ashaveri-receipt-id');
  expect(typeof receiptId, 'the completion carried no receipt id').toBe('string');
  const responseBytes = new Uint8Array(await served.arrayBuffer());

  const session = new GatewaySession(BASE, { fetchImpl });
  const receiptBytes = await session.receiptBytes(receiptId as string);
  const outcome = await session
    .verifyCompletion({
      receiptBytes,
      nonce: NONCE,
      requestHash: hashRequest(requestBody),
      responseHash: sha256(responseBytes),
      responseBytes,
      verifyEvidence: true,
      // No root is pinned for any family, so a run whose two readings agree stops at the anchor and a run
      // whose two readings differ stops one step earlier, at the digest the receipt signed.
      anchors: { amdArks: [], intelSgxRoots: [], nvidiaRoots: [] },
    })
    .then(() => 'verified')
    .catch((err: unknown) => (err instanceof SdkError ? err.code : `thrown: ${String(err)}`));

  await app.close();

  expect(askedAtTheSeam, 'the completion route and the evidence route did not each ask the seam once').toHaveLength(2);
  expect(clientAsked, 'the reader never asked the evidence route for a value').toHaveLength(1);
  // The seam's second ask is the evidence route passing the reader's own query down to the platform, which is
  // why the digest step below is the reader's guard rather than a lookup the gateway could fake.
  expect(toHex(askedAtTheSeam[1]!)).toBe(clientAsked[0]);
  return {
    requestBody,
    minted: askedAtTheSeam[0]!,
    requested: clientAsked[0]!,
    payload: decodeReceipt(receiptBytes).payload,
    outcome,
  };
}

function checkPairing(run: Pairing): void {
  // The pairing itself, as bytes: what the gateway asked the platform to seal is what the reader computes
  // from the document the same run signed. This is the line the two sites fail on if they ever disagree.
  expect(toHex(run.minted)).toBe(run.requested);

  // The same fact one layer down, where a reader reaches it without this file's help: the served document is
  // the one the receipt's `att.d` committed to, so the digest check passed and the refusal is the anchor.
  expect(run.outcome).toBe('EVIDENCE_NO_TRUST_ANCHORS');

  // Which rule was in force, stated by the document rather than by this file: no arm, so no key folded.
  expect(run.payload.v).toBe(1);
  expect(run.payload.nce).toEqual(NONCE);
  expect(toHex(run.payload.req)).toBe(sha256Hex(run.requestBody));

  // The value is a digest, and the platform's field is the width the shipped reader tolerates a pad to: the
  // zero run beside it is accepted at either end by `reportDataBinds`, which is what both the gateway's own
  // live measurement path and the client call on the quoted bytes.
  const padded = new Uint8Array(QUOTE_REPORT_DATA_BYTES);
  padded.set(run.minted);
  expect(run.minted.byteLength).toBe(DIGEST_BYTES);
  expect(padded.byteLength).toBe(QUOTE_REPORT_DATA_BYTES);
  expect(reportDataBinds(padded, run.minted)).toBe(true);
}

describe('the value a quote is sealed for, at both ends of one run', () => {
  it('pairs the buffered mint with what the client computes from its receipt', async () => {
    checkPairing(await pair('buffered'));
  });

  it('pairs the streamed mint with what the client computes from its receipt', async () => {
    checkPairing(await pair('streamed'));
  });
});
