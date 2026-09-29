import { describe, expect, it } from 'vitest';
import { hashRequest, randomNonce, type ReceiptPayload } from '@ashaveri/receipt';
import {
  GatewaySession,
  parseManifest,
  policyFromManifest,
  toBase64Url,
  verifyCompletionReceipt,
  type AshaveriPolicy,
} from '../src/index.js';
import { createFakeGateway, FAKE_BASE_URL, FAKE_RECEIPT_ID, type FakeGateway } from './mock-gateway.js';

/**
 * The clock a caller hands the client verifier, and the two answers its two spellings get.
 *
 * `nowMillis` is the one client parameter that reads the caller's wall clock in milliseconds while every
 * instant it is weighed against, `iat` and a `v: 3` item's `t`, is counted in seconds. That is the whole
 * distance a wrong reading has to travel to become a wrong verdict: hand the seconds figure, the entry
 * divides it, and an honest receipt comes back refused for an age of fifty-seven years. The pair of cases
 * below is arranged so the refusal cannot be a blanket. One instant, the same bytes under the same policy,
 * is weighed and passes when it is spelled in milliseconds and is refused by name when it is spelled in
 * seconds, which is what shows the guard answering the scale rather than answering the call.
 *
 * The first two verdicts are reached through the shipped client path rather than through the function
 * beside it, which is how `anchor-slot-demand.test.ts` reads the same entry: a caller can call anything
 * wrongly, and only the route a deployment's artifact is handed to proves what a client is told.
 */
const MESSAGES = [{ role: 'user', content: 'hi' }];

/** The instant every case here claims, and the same instant counted in each of the two scales. */
const AT_SECONDS = 1_800_000_000;
const AT_MILLIS = AT_SECONDS * 1_000;

/** A deployment stamping this one instant on both halves of the document the client weighs. */
function gatewayStampingTheClaimedInstant(): FakeGateway {
  return createFakeGateway({
    mutatePayload: (payload: ReceiptPayload): ReceiptPayload => ({
      ...payload,
      iat: AT_SECONDS,
      att: { ...payload.att, ts: AT_SECONDS },
    }),
  });
}

/**
 * One receipted completion, verified under the clock the case names, answered with the code it failed
 * with or `verified`. The receipt is stamped at `AT_SECONDS` and the policy is the deployment's own, so
 * the two windows are running at their shipped numbers over a document that is whole.
 */
async function verdictUnderClock(nowMillis: number): Promise<string> {
  const gateway = gatewayStampingTheClaimedInstant();
  const policy: AshaveriPolicy = policyFromManifest(parseManifest(gateway.manifestJson));
  const nonce = randomNonce();
  const body = JSON.stringify({ messages: MESSAGES });
  const response = await gateway.fetch(`${FAKE_BASE_URL}/chat/completions`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-ashaveri-nonce': toBase64Url(nonce) },
    body,
  });
  if (!response.ok) {
    throw new Error(`the fake gateway refused its own completion with ${String(response.status)}`);
  }
  const session = new GatewaySession(FAKE_BASE_URL, { fetchImpl: gateway.fetch, policy });
  const responseBytes = new Uint8Array(await response.arrayBuffer());
  try {
    await session.verifyReceipted({
      receiptBytes: await session.receiptBytes(FAKE_RECEIPT_ID),
      nonce,
      requestHash: hashRequest(new TextEncoder().encode(body)),
      responseHash: hashRequest(responseBytes),
      responseBytes,
      nowMillis,
    });
    return 'verified';
  } catch (err) {
    const code = (err as { code?: string })?.code;
    return typeof code === 'string' ? code : `unexpected:${String(err)}`;
  }
}

describe('the clock a caller hands the client verifier', () => {
  it('refuses a reading spelled in the seconds the format counts in as a clock that is not milliseconds', async () => {
    // Without the guard this case answers `STALE_RECEIPT`, which is the wrong verdict and the reason the
    // reading is asked its question at the entry: the receipt is a moment old and nothing about it aged.
    expect(await verdictUnderClock(AT_SECONDS)).toBe('CLIENT_CLOCK_OUT_OF_RANGE');
  });

  it('weighs the same instant spelled in milliseconds and lets both windows pass it', async () => {
    expect(await verdictUnderClock(AT_MILLIS)).toBe('verified');
  });

  it('refuses the reading before a byte of a document is read, and states both ends of the band', () => {
    // The empty bytes are the point rather than an oversight: a reader that reached the receipt would
    // have answered about the receipt, and the refusal here is about the argument. The message is read
    // as well as the code, because the code says the clock was impossible and the sentence is what tells
    // whoever handed it what to hand back.
    let code = 'nothing thrown';
    let message = '';
    try {
      verifyCompletionReceipt({
        receiptBytes: new Uint8Array(0),
        nonce: randomNonce(),
        requestHash: new Uint8Array(32),
        responseHash: new Uint8Array(32),
        responseBytes: new Uint8Array(0),
        verifyKey: new Uint8Array(32),
        nowMillis: AT_SECONDS,
      });
    } catch (err) {
      code = (err as { code?: string })?.code ?? 'no code';
      message = err instanceof Error ? err.message : String(err);
    }
    expect(code).toBe('CLIENT_CLOCK_OUT_OF_RANGE');
    expect(message).toContain('1000000000000');
    expect(message).toContain('4294967295000');
    expect(message).toContain(String(AT_SECONDS));
  });
});
