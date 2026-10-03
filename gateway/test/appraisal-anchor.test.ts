import { readFileSync } from 'node:fs';
import { afterEach, describe, expect, it } from 'vitest';
import { decodeReceipt, sha256Hex, toHex, type CollateralHeld, type CollateralSlot, type ReceiptPayload, type StampDisclosure } from '@ashaveri/receipt';
import {
  notTakenInAnchor,
  type AppraisalReader,
  type AppraisalReading,
  type AttestationBundle,
  type BackendResponse,
  type CachedAppraisal,
  type CompletionBackend,
  type CompletionUsage,
  type TimeSource,
} from '../src/index.js';
import { sha256 } from '../src/digest.js';
import { CLOCK_SECONDS, fixedClock, generated, harness, type Generated, type Harness } from './helpers.js';

/**
 * The anchor a booted gateway signs, one case per state a read of a cached appraisal can be in.
 *
 * Nothing below converts a reading by hand. Each case builds a gateway, sends one completion through it,
 * fetches the receipt the gateway filed and decodes it with the shipped reader, so what is asserted is the
 * document a deployment's client can hold and not the output of a function a test called itself. The rule
 * that matters, that an entry whose own window has closed is never signed as a digest, is a rule about what
 * reaches a signature, and a conversion checked on its own would prove nothing about that.
 */

const MODEL = 'mock-model-1';
const CREDENTIAL_ID = 'appraisal';
const TARGET = '/v1/chat/completions';
const REQUEST_BODY = `{"model":"${MODEL}","messages":[{"role":"user","content":"hello"}]}`;

const UPSTREAM_BUFFERED = JSON.stringify({
  id: 'chatcmpl-appraisal-1',
  object: 'chat.completion',
  created: CLOCK_SECONDS,
  model: MODEL,
  choices: [{ index: 0, message: { role: 'assistant', content: 'a buffered reply' }, finish_reason: 'stop' }],
  usage: { prompt_tokens: 9, completion_tokens: 6, total_tokens: 15 },
});

/** The cache key every case names, so a reason that dropped it or quoted another one is a red case. */
const CACHE_KEY = 'snp:00906e1b0d00:tcb-info:2025-06-01';

/** The three instants of a cached answer, all of them the appraiser's and none of them the issuance clock's. */
const OBSERVED_AT = 1_700_000_010;
const JUDGED_AT = 1_700_000_060;
const OPEN_UNTIL = 1_700_086_400;
const CLOSED_UNTIL = 1_699_999_000;

/** An issuance instant far from every instant above, so a reason quoting one cannot be quoting the other. */
const ISSUANCE_SECONDS = CLOCK_SECONDS + 4_211;

const COLLATERAL_SHA256 = sha256(new TextEncoder().encode('the collateral bytes the appraiser observed'));
const VALIDITY_SHA256 = sha256(new TextEncoder().encode('the validity context the appraiser observed'));

const utf8 = (value: string): Uint8Array => new TextEncoder().encode(value);

function bufferedBackend(): CompletionBackend {
  const usage: Promise<CompletionUsage> = Promise.resolve({
    model: MODEL,
    promptTokens: 9,
    completionTokens: 6,
  });
  return {
    async respond(): Promise<BackendResponse> {
      return {
        status: 200,
        contentType: 'application/json',
        chunks: (async function* (): AsyncGenerator<Uint8Array> {
          yield utf8(UPSTREAM_BUFFERED);
        })(),
        usage,
      };
    },
  };
}

/** A reader that answers one reading whatever evidence it is handed. */
function readerOf(reading: AppraisalReading): AppraisalReader {
  return () => reading;
}

/** One cached answer, fresh unless a case says otherwise. */
function cached(overrides: Partial<CachedAppraisal> = {}): AppraisalReading {
  return {
    state: 'held',
    appraisal: {
      cacheKey: CACHE_KEY,
      collateralSha256: COLLATERAL_SHA256,
      validitySha256: VALIDITY_SHA256,
      observedAt: OBSERVED_AT,
      sourceUncertaintySeconds: null,
      until: OPEN_UNTIL,
      judgedAt: JUDGED_AT,
      ...overrides,
    },
  };
}

const credential: Generated = generated(CREDENTIAL_ID, ['complete', 'read']);

let session: Harness | undefined;
let presentations = 0;

async function close(): Promise<void> {
  if (session !== undefined) {
    const closing = session;
    session = undefined;
    await closing.app.close();
  }
}

afterEach(close);

/**
 * One issuance through a gateway built with these options, and the anchor of the receipt it filed, read
 * back out of the served bytes by the shipped reader.
 */
async function issue(options: {
  readonly appraisal?: AppraisalReader;
  readonly time?: TimeSource;
}): Promise<ReceiptPayload> {
  await close();
  session = await harness({
    credentials: [credential],
    gateway: { backend: bufferedBackend(), ...options },
  });
  // One nonce per presentation, so two issuances of one credential never land on the same replay key.
  const nonce = Uint8Array.from({ length: 16 }, (_, at) => (at + presentations) % 251);
  presentations += 1;
  const served = await session.app.inject({
    method: 'POST' as 'GET',
    url: TARGET,
    headers: {
      'content-type': 'application/json',
      ...session.signFor(CREDENTIAL_ID, 'POST', TARGET, REQUEST_BODY, { nonce }),
    },
    payload: REQUEST_BODY,
  });
  expect(served.statusCode).toBe(200);
  const id = served.headers['x-ashaveri-receipt-id'] as string;
  expect(typeof id).toBe('string');
  const fetched = await session.app.inject({
    method: 'GET',
    url: `/v1/receipts/${id}`,
    headers: session.signFor(CREDENTIAL_ID, 'GET', `/v1/receipts/${id}`, null),
  });
  expect(fetched.statusCode).toBe(200);
  return decodeReceipt(new Uint8Array(fetched.rawPayload)).payload;
}

/** The reason of a slot that states one, which is the only way a case reads an absence. */
function reasonOf(slot: CollateralSlot, which: string): string {
  if (slot.presence === 'held') throw new Error(`the ${which} slot states held and carries no reason`);
  return slot.reason;
}

/** The digest of a slot that states one, which is the only way a case reads material. */
function digestOf(slot: CollateralSlot, which: string): Uint8Array {
  if (slot.presence !== 'held') throw new Error(`the ${which} slot states ${slot.presence} and carries no digest`);
  return slot.sha256;
}

function anchorOf(payload: ReceiptPayload): ReceiptPayload['cva'] {
  if (!('cva' in payload)) throw new Error('the payload carries no validity anchor');
  return payload.cva;
}

describe('the anchor a cached appraisal answers with', () => {
  it('signs both absences of a collector that took nothing in where no reader was wired', async () => {
    // The regression case, and the one a deployment that configures nothing is owed: no reader means the
    // anchor is `notTakenInAnchor`'s, reason for reason, so wiring this seam moved nothing about an
    // unwired gateway's document.
    const payload = await issue({});
    expect(anchorOf(payload)).toEqual(notTakenInAnchor());
  });

  it('names the cache, the key and its own material where the cache holds no entry', async () => {
    const handed: AttestationBundle[] = [];
    const appraisal: AppraisalReader = (evidence) => {
      handed.push(evidence);
      return { state: 'no-entry', cacheKey: CACHE_KEY };
    };
    const payload = await issue({ appraisal });
    const anchor = anchorOf(payload);
    expect(anchor.collateral.presence).toBe('not-taken-in');
    expect(anchor.validity.presence).toBe('not-taken-in');

    const collateral = reasonOf(anchor.collateral, 'collateral');
    const validity = reasonOf(anchor.validity, 'validity');
    for (const reason of [collateral, validity]) {
      expect(reason).toContain('the appraisal cache');
      expect(reason).toContain(CACHE_KEY);
    }
    // Two absences with one cause are still two sentences, because each names the material it is about and
    // a reader weighing one slot is not weighing the other.
    expect(collateral).toContain('collateral');
    expect(validity).toContain('validity');
    expect(collateral).not.toBe(validity);

    // The reader is handed the bundle the issuance itself signs a digest of, so the key a cache is asked
    // for is a key over the evidence this document names and not over something beside it. One read per
    // issuance, and not one per slot.
    expect(handed.length).toBe(1);
    const evidence = handed[0];
    if (evidence === undefined) throw new Error('the reader was handed no evidence bundle');
    expect(sha256Hex(evidence.document)).toBe(toHex(payload.att.d));
  });

  it('names both instants where the entry it holds had closed its own window', async () => {
    const payload = await issue({
      appraisal: readerOf({ state: 'expired', cacheKey: CACHE_KEY, until: CLOSED_UNTIL, judgedAt: JUDGED_AT }),
    });
    const anchor = anchorOf(payload);
    expect(anchor.collateral.presence).toBe('not-taken-in');
    expect(anchor.validity.presence).toBe('not-taken-in');
    for (const slot of ['collateral', 'validity'] as const) {
      const reason = reasonOf(anchor[slot], slot);
      expect(reason).toContain('the appraisal cache');
      expect(reason).toContain(CACHE_KEY);
      expect(reason).toContain(String(CLOSED_UNTIL));
      expect(reason).toContain(String(JUDGED_AT));
      expect(reason).toContain('its own window had closed');
    }
  });

  it('answers a held entry that is stale on its own face as the closed window it states', async () => {
    // The case that says the gateway does not trust its wiring. A reader is a deployment's own code, and
    // one that hands over an entry the document's own next update has passed is answered out of the two
    // instants it carried rather than believed: the anchor has to be the expired arm's for the same key and
    // the same two instants, including at the boundary, where a window that ends as it is judged is not
    // open either.
    const closedAtBoundary = anchorOf(
      await issue({
        appraisal: readerOf({ state: 'expired', cacheKey: CACHE_KEY, until: JUDGED_AT, judgedAt: JUDGED_AT }),
      }),
    );
    expect(anchorOf(await issue({ appraisal: readerOf(cached({ until: JUDGED_AT })) }))).toEqual(closedAtBoundary);

    const closedPastIt = anchorOf(
      await issue({
        appraisal: readerOf({ state: 'expired', cacheKey: CACHE_KEY, until: CLOSED_UNTIL, judgedAt: JUDGED_AT }),
      }),
    );
    expect(anchorOf(await issue({ appraisal: readerOf(cached({ until: CLOSED_UNTIL })) }))).toEqual(closedPastIt);
  });

  it('signs both digests where the cache holds an entry inside its own window', async () => {
    const payload = await issue({ appraisal: readerOf(cached()) });
    const anchor = anchorOf(payload);
    expect(anchor.collateral.presence).toBe('held');
    expect(anchor.validity.presence).toBe('held');
    // The bytes, and not their length: a digest of the wrong material at the right width is the failure
    // this assertion exists to catch.
    expect(toHex(digestOf(anchor.collateral, 'collateral'))).toBe(toHex(COLLATERAL_SHA256));
    expect(toHex(digestOf(anchor.validity, 'validity'))).toBe(toHex(VALIDITY_SHA256));
    expect(Object.keys(anchor).sort()).toEqual(['collateral', 'validity']);
  });

  it('signs the collateral digest and states the missing validity material beside it', async () => {
    const payload = await issue({ appraisal: readerOf(cached({ validitySha256: null })) });
    const anchor = anchorOf(payload);
    expect(anchor.collateral.presence).toBe('held');
    expect(toHex(digestOf(anchor.collateral, 'collateral'))).toBe(toHex(COLLATERAL_SHA256));
    expect(anchor.validity.presence).toBe('not-taken-in');
    const validity = reasonOf(anchor.validity, 'validity');
    expect(validity).toContain('the appraisal cache');
    expect(validity).toContain(CACHE_KEY);
    expect(validity).toContain('no validity material');
  });

  it('serves the completion and signs the failed read where the reader throws', async () => {
    // The sentinel is the point: a reason is attested text, so a message quoted into one would put words a
    // vendor or a filesystem chose inside a document a reviewer cites, and a message carrying a line
    // separator would reach the writer's refusal and take the issuance down with it.
    const sentinel = 'SENTINEL-9c41e07a';
    const payload = await issue({
      appraisal: () => {
        throw new Error(`${sentinel}: the cache volume answered nothing`);
      },
    });
    const anchor = anchorOf(payload);
    for (const slot of ['collateral', 'validity'] as const) {
      expect(anchor[slot].presence).toBe('not-taken-in');
      const reason = reasonOf(anchor[slot], slot);
      expect(reason).toContain('the appraisal cache');
      expect(reason).toContain('the read of it failed');
      expect(reason).not.toContain(sentinel);
      expect(reason).not.toContain('the cache volume answered nothing');
      expect(reason).not.toContain('SENTINEL');
    }
  });

  it('quotes the appraiser clock in a reason and the issuance clock in the stamp beside it', async () => {
    // Two clocks meet in one document, and each member states whose it read. The issuance instant comes
    // from the source this gateway was built with and lands in `iat` and `sd`; the instants a reason quotes
    // are the appraiser's, so a case that puts them a year apart and finds neither in the other's member is
    // the assertion the clock rule is rather than a comment claiming it.
    const time = fixedClock(() => ISSUANCE_SECONDS, 2);
    const expired = await issue({
      time,
      appraisal: readerOf({ state: 'expired', cacheKey: CACHE_KEY, until: CLOSED_UNTIL, judgedAt: JUDGED_AT }),
    });
    expect(expired.iat).toBe(ISSUANCE_SECONDS);
    expect(expired.sd).toEqual({ name: 'fixture clock', uncertaintySeconds: 2 });

    const held = await issue({ time, appraisal: readerOf(cached({ validitySha256: null })) });
    expect(held.iat).toBe(ISSUANCE_SECONDS);
    expect(held.sd).toEqual({ name: 'fixture clock', uncertaintySeconds: 2 });

    const reasons = [
      reasonOf(anchorOf(expired).collateral, 'collateral'),
      reasonOf(anchorOf(expired).validity, 'validity'),
      reasonOf(anchorOf(held).validity, 'validity'),
    ];
    for (const reason of reasons) {
      // Not vacuous: the expired reasons quote two instants, and they are the appraiser's.
      expect(reason).not.toContain(String(ISSUANCE_SECONDS));
    }
    expect(reasons[0]).toContain(String(CLOSED_UNTIL));
    expect(reasons[0]).toContain(String(JUDGED_AT));
    expect(reasons[0]).toContain("the appraiser's clock");
  });
});

describe('the two spellings a cached entry restates', () => {
  /**
   * A restatement held by a compiler rather than by a sentence claiming ownership of it. The bound a
   * source declares about itself and the digest a held slot carries are `packages/receipt/src/disclosure.ts`'s
   * vocabulary, and a seam that names its own shapes can still widen or narrow either one without a word
   * changing in the file that owns it, so the two spellings are compared in both directions and an
   * assignment that stops working is the failure.
   */
  it('states its source bound and its digests as the disclosure states them', () => {
    type Identical<Left, Right> = [Left] extends [Right] ? ([Right] extends [Left] ? true : false) : false;
    const bound: Identical<CachedAppraisal['sourceUncertaintySeconds'], StampDisclosure['uncertaintySeconds']> = true;
    const collateral: Identical<CachedAppraisal['collateralSha256'], CollateralHeld['sha256']> = true;
    const validity: Identical<CachedAppraisal['validitySha256'], CollateralHeld['sha256'] | null> = true;
    expect([bound, collateral, validity]).toEqual([true, true, true]);
  });

  /**
   * Three member names of a cached answer are the capture record's vocabulary rather than this seam's:
   * `cacheKey`, `observedAt` and `sourceUncertaintySeconds`, which `packages/sdk/src/capture.ts` declares
   * for the slot a collector took in. This package ships no dependency on that one, and a reader wired
   * beside an issuance spells them anyway, so the two spellings are held together by reading the owner's
   * own file: a rename there turns this case red, which is more than a comment naming the owner would do.
   * The bound on those bytes is not among them, because the seam names the vendor document's own next
   * update rather than restating the record's window pair.
   */
  it('spells the three members the capture record owns as that record spells them', () => {
    const owner = readFileSync(new URL('../../packages/sdk/src/capture.ts', import.meta.url), 'utf8');
    const seam = readFileSync(new URL('../src/appraisal-cache.ts', import.meta.url), 'utf8');
    // The declaration line and not the member name, so a widening on either side is a red case too.
    const declarations = [
      'readonly cacheKey: string;',
      'readonly observedAt: number;',
      'readonly sourceUncertaintySeconds: number | null;',
    ];
    // And the shape itself, read by a compiler rather than by a string search, so a member the seam drops
    // fails the assignment below before either file is opened.
    const shaped: Pick<CachedAppraisal, 'cacheKey' | 'observedAt' | 'sourceUncertaintySeconds'> = {
      cacheKey: CACHE_KEY,
      observedAt: OBSERVED_AT,
      sourceUncertaintySeconds: null,
    };
    expect(Object.keys(shaped).sort()).toEqual(['cacheKey', 'observedAt', 'sourceUncertaintySeconds']);
    for (const one of declarations) {
      expect(owner, `the capture record no longer declares "${one}"`).toContain(one);
      expect(seam, `the seam no longer declares "${one}"`).toContain(one);
    }
  });
});
