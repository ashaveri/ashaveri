import { describe, expect, it } from 'vitest';
import { hashRequest, randomNonce, ReceiptError, type ReceiptPayload, type VerifiedReceipt } from '@ashaveri/receipt';
import {
  AshaveriClient,
  DEFAULT_MAX_EVIDENCE_AGE_SECONDS,
  DEFAULT_MAX_RECEIPT_AGE_SECONDS,
  GatewaySession,
  parseManifest,
  policyFromManifest,
  toBase64Url,
  type AshaveriPolicy,
} from '../src/index.js';
import { createFakeGateway, FAKE_BASE_URL, FAKE_RECEIPT_ID, type FakeGateway } from './mock-gateway.js';

const MESSAGES = [{ role: 'user', content: 'hi' }];

/**
 * The wall clock every case here claims, so that no test depends on the minute it ran in.
 * The receipt it checks is stamped against the same number.
 */
const NOW_SECONDS = 1_800_000_000;
const NOW_MS = NOW_SECONDS * 1_000;

/** How far behind `now` a stamped value sits. A negative age is a stamp ahead of it. */
interface Ages {
  readonly receipt: number;
  readonly evidence: number;
}

/** Comfortably inside both shipped windows: what a client checking its own completion sees. */
const RECENT = 60;
/** Six minutes old: past a 300-second receipt window, inside a 900-second evidence one. */
const PAST_RECEIPT_WINDOW = 360;
/** Sixteen minutes old: past either window the SDK could plausibly ship. */
const PAST_EVIDENCE_WINDOW = 960;
/** A completion that took ten minutes to stream: its quote predates the stamp by that much. */
const LONG_GENERATION = 600;
/** A year, which is what an archivist presents. */
const ARCHIVE = 31_536_000;

/** A gateway that stamps `iat` and `att.ts` the stated number of seconds before the client's clock. */
function gatewayStamping(ages: Ages): FakeGateway {
  return createFakeGateway({
    mutatePayload: (payload: ReceiptPayload): ReceiptPayload => ({
      ...payload,
      iat: NOW_SECONDS - ages.receipt,
      att: { ...payload.att, ts: NOW_SECONDS - ages.evidence },
    }),
  });
}

/** The pins a strict client reads off the deployment's own manifest, with nothing about clocks added. */
function manifestPolicy(gateway: FakeGateway): AshaveriPolicy {
  return policyFromManifest(parseManifest(gateway.manifestJson));
}

/**
 * One completion over the fake transport, then the receipt half of strict mode run against it:
 * the same `GatewaySession.verifyReceipted` call that `verify: 'strict'` makes, with the same
 * policy and the same clock. This level is the one that can answer both ways, because a strict
 * completion against this software deployment always ends at the hardware refusal afterwards.
 */
async function checkedReceiptStep(
  gateway: FakeGateway,
  policy: AshaveriPolicy | undefined,
): Promise<VerifiedReceipt> {
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
  return session.verifyReceipted({
    receiptBytes: await session.receiptBytes(FAKE_RECEIPT_ID),
    nonce,
    requestHash: hashRequest(new TextEncoder().encode(body)),
    responseHash: hashRequest(responseBytes),
    responseBytes,
    now: NOW_MS,
  });
}

/** The code a receipt step refused with, or the string `verified` when it refused nothing. */
async function receiptStepCode(ages: Ages, override?: Partial<AshaveriPolicy>): Promise<string> {
  const gateway = gatewayStamping(ages);
  const policy: AshaveriPolicy = { ...manifestPolicy(gateway), ...override };
  try {
    await checkedReceiptStep(gateway, policy);
    return 'verified';
  } catch (err) {
    expect(err, 'a refused receipt step throws an error').toBeInstanceOf(Error);
    return (err as { code?: string }).code ?? 'no code';
  }
}

/** One whole strict completion, reported as the code it failed with or `verified`. */
async function strictCompletionCode(ages: Ages, override?: Partial<AshaveriPolicy>): Promise<string> {
  const gateway = gatewayStamping(ages);
  const client = new AshaveriClient({
    baseUrl: FAKE_BASE_URL,
    fetch: gateway.fetch,
    verify: 'strict',
    policy: { ...manifestPolicy(gateway), ...override },
    now: () => NOW_MS,
  });
  try {
    await client.chat.completions.create({ messages: MESSAGES });
    return 'verified';
  } catch (err) {
    return (err as { code?: string }).code ?? 'no code';
  }
}

describe('the freshness defaults a strict policy carries', () => {
  it('ships two different windows, the evidence one the looser of them', () => {
    expect(DEFAULT_MAX_RECEIPT_AGE_SECONDS).toBe(300);
    expect(DEFAULT_MAX_EVIDENCE_AGE_SECONDS).toBe(900);
    expect(DEFAULT_MAX_EVIDENCE_AGE_SECONDS).toBeGreaterThan(DEFAULT_MAX_RECEIPT_AGE_SECONDS);
  });

  it('sets neither window from the manifest it is handed', () => {
    const policy = manifestPolicy(gatewayStamping({ receipt: RECENT, evidence: RECENT }));
    // The manifest is unsigned and served by the party being checked, so it cannot be where a
    // window is loosened: both numbers below this line come from the code, not from the wire.
    expect(policy.maxReceiptAgeSeconds).toBeUndefined();
    expect(policy.maxEvidenceAgeSeconds).toBeUndefined();
  });
});

describe('a strict receipt step with no age fields configured', () => {
  it('refuses a receipt stamped before the default window', async () => {
    const gateway = gatewayStamping({ receipt: PAST_RECEIPT_WINDOW, evidence: RECENT });
    await expect(checkedReceiptStep(gateway, manifestPolicy(gateway))).rejects.toBeInstanceOf(ReceiptError);
    expect(await receiptStepCode({ receipt: PAST_RECEIPT_WINDOW, evidence: RECENT })).toBe('STALE_RECEIPT');
  });

  it('refuses evidence older than its own window while the receipt itself is in time', async () => {
    expect(await receiptStepCode({ receipt: RECENT, evidence: PAST_EVIDENCE_WINDOW })).toBe('STALE_EVIDENCE');
  });

  it('refuses a receipt stamped ahead of the client clock by more than the window', async () => {
    expect(await receiptStepCode({ receipt: -PAST_RECEIPT_WINDOW, evidence: RECENT })).toBe('STALE_RECEIPT');
  });

  it('refuses evidence dated ahead of the client clock the same way', async () => {
    expect(await receiptStepCode({ receipt: RECENT, evidence: -PAST_EVIDENCE_WINDOW })).toBe('STALE_EVIDENCE');
  });

  it('accepts the otherwise identical receipt stamped inside both windows', async () => {
    expect(await receiptStepCode({ receipt: RECENT, evidence: RECENT })).toBe('verified');
  });

  it('judges the evidence by its own window, not by the tighter receipt one', async () => {
    // Older than the receipt window, younger than the evidence window, and the receipt itself is
    // current: exactly a long completion, where the quote was taken before the first token.
    expect(await receiptStepCode({ receipt: RECENT, evidence: LONG_GENERATION + RECENT })).toBe('verified');
  });

  it('refuses a stale receipt before it ever looks at the evidence window', async () => {
    // Both out of time. The issuance check is the one that answers, because the receipt's own age
    // is the fact a caller acts on; the evidence leg is reported only when it is the sole fault.
    expect(await receiptStepCode({ receipt: PAST_RECEIPT_WINDOW, evidence: PAST_EVIDENCE_WINDOW })).toBe('STALE_RECEIPT');
  });
});

describe('a policy that names its own number', () => {
  it('tightens the receipt window below the default', async () => {
    expect(await receiptStepCode({ receipt: PAST_RECEIPT_WINDOW, evidence: RECENT }, { maxReceiptAgeSeconds: 120 })).toBe(
      'STALE_RECEIPT',
    );
  });

  it('loosens the receipt window above the default', async () => {
    expect(await receiptStepCode({ receipt: PAST_RECEIPT_WINDOW, evidence: RECENT }, { maxReceiptAgeSeconds: 1_200 })).toBe(
      'verified',
    );
  });

  it('tightens the evidence window below the default', async () => {
    expect(
      await receiptStepCode({ receipt: RECENT, evidence: LONG_GENERATION + RECENT }, { maxEvidenceAgeSeconds: 300 }),
    ).toBe('STALE_EVIDENCE');
  });

  it('loosens the evidence window above the default', async () => {
    expect(await receiptStepCode({ receipt: RECENT, evidence: PAST_EVIDENCE_WINDOW }, { maxEvidenceAgeSeconds: 3_600 })).toBe(
      'verified',
    );
  });

  it('keeps the other window at its default while one is overridden', async () => {
    // Only the evidence window is named, so the receipt window is still the shipped 300 seconds.
    expect(await receiptStepCode({ receipt: PAST_RECEIPT_WINDOW, evidence: RECENT }, { maxEvidenceAgeSeconds: 3_600 })).toBe(
      'STALE_RECEIPT',
    );
    // And the other direction.
    expect(await receiptStepCode({ receipt: RECENT, evidence: PAST_EVIDENCE_WINDOW }, { maxReceiptAgeSeconds: 1_200 })).toBe(
      'STALE_EVIDENCE',
    );
  });
});

describe('turning a window off on purpose', () => {
  it('takes the receipt window off for an archive when the policy says infinity', async () => {
    expect(
      await receiptStepCode(
        { receipt: ARCHIVE, evidence: RECENT },
        { maxReceiptAgeSeconds: Number.POSITIVE_INFINITY },
      ),
    ).toBe('verified');
  });

  it('leaves the evidence window running when only the receipt one is off', async () => {
    expect(
      await receiptStepCode(
        { receipt: ARCHIVE, evidence: ARCHIVE },
        { maxReceiptAgeSeconds: Number.POSITIVE_INFINITY },
      ),
    ).toBe('STALE_EVIDENCE');
    expect(
      await receiptStepCode(
        { receipt: ARCHIVE, evidence: ARCHIVE },
        { maxEvidenceAgeSeconds: Number.POSITIVE_INFINITY },
      ),
    ).toBe('STALE_RECEIPT');
  });

  it('verifies a year-old receipt with both windows deliberately off', async () => {
    expect(
      await receiptStepCode(
        { receipt: ARCHIVE, evidence: ARCHIVE },
        { maxReceiptAgeSeconds: Number.POSITIVE_INFINITY, maxEvidenceAgeSeconds: Number.POSITIVE_INFINITY },
      ),
    ).toBe('verified');
  });
});

describe('where the defaults do and do not reach', () => {
  it('refuses a stale receipt through a whole strict completion', async () => {
    expect(await strictCompletionCode({ receipt: PAST_RECEIPT_WINDOW, evidence: RECENT })).toBe('STALE_RECEIPT');
  });

  it('refuses stale evidence through a whole strict completion', async () => {
    expect(await strictCompletionCode({ receipt: RECENT, evidence: PAST_EVIDENCE_WINDOW })).toBe('STALE_EVIDENCE');
  });

  it('clears the clock on a current strict completion and refuses the software deployment for its hardware', async () => {
    // The same stamped-receipt path as the two cases above, one minute old instead of stale: the
    // refusal that comes back is strict mode's next step, which is only reached once both windows
    // have passed. This fake deployment attests no hardware, so that is where it stops.
    expect(await strictCompletionCode({ receipt: RECENT, evidence: RECENT })).toBe('EVIDENCE_NOT_HARDWARE');
  });

  it('checks no clock where no policy is pinned', async () => {
    // `receipt` mode asks for no policy, so it has no window either: what holds a stale receipt
    // there is the nonce the client chose for the request it is checking.
    const gateway = gatewayStamping({ receipt: ARCHIVE, evidence: ARCHIVE });
    await expect(checkedReceiptStep(gateway, undefined)).resolves.toMatchObject({
      payload: { iat: NOW_SECONDS - ARCHIVE },
    });
  });
});
