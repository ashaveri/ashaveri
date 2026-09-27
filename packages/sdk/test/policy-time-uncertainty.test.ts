import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { HOST_CLOCK_SOURCE, openMemoryReceiptStore, type TimeSource } from '@ashaveri/signerd';
import {
  assertStampSourceWithinPolicy,
  loadPolicyFromText,
  policyFileFromPolicy,
  policyFileToJson,
  SdkError,
  type AshaveriPolicy,
  type StampSourceDeclaration,
} from '../src/index.js';

/**
 * The demand a reviewer makes of a deployment, stated as a number in a policy document: how far the
 * source behind a stamp may stand from real time. Everything below is that demand met, refused, and
 * absent, plus the one reading a reader gets wrong, which is that a source declaring no measurement
 * sits comfortably inside any bound.
 *
 * The sources are the real declaration a deployment makes about itself. `gateway/src/store.ts` states
 * a stamp's origin as this same pair of fields, on the store and beside every record a range walk
 * hands back, so a test handing one over is reading the two names a verifier reads rather than a
 * shape invented beside the assertion.
 */

const TEMP = mkdtempSync(join(tmpdir(), 'ashaveri-policy-time-'));
afterAll(() => {
  rmSync(TEMP, { recursive: true, force: true });
});

/** A source that was measured, at the bound its operator wrote down beside it. */
function measured(name: string, uncertaintySeconds: number): TimeSource {
  return { name, uncertaintySeconds, now: () => 1_772_000_000 };
}

/** The statement a store makes about the source it stamps with, which is what a verifier is handed. */
function declaredBy(time: TimeSource | undefined): StampSourceDeclaration {
  return openMemoryReceiptStore(time === undefined ? {} : { retention: { time } }).timeSource();
}

/** The sentence an operator reads, which is the part of a refusal that says what to change. */
function refusalMessage(policy: AshaveriPolicy | undefined, source: StampSourceDeclaration): string {
  try {
    assertStampSourceWithinPolicy(policy, source);
  } catch (err) {
    if (err instanceof SdkError) return err.message;
    throw err;
  }
  throw new Error('expected a refusal, but the stamp was accepted');
}

/** The code a refusal carries, or the string `accept` when the stamp was let through. */
function refusal(policy: AshaveriPolicy | undefined, source: StampSourceDeclaration): string {
  try {
    assertStampSourceWithinPolicy(policy, source);
    return 'accept';
  } catch (err) {
    return err instanceof SdkError ? err.code : `unexpected:${String(err)}`;
  }
}

/** Every pin the policy can hold that a stamp source is not, so the demand is the only variable. */
const PINNED: AshaveriPolicy = { issuers: ['ashaveri-prod'], instances: ['cvm-1'] };

const demanding = (seconds: number | undefined): AshaveriPolicy => ({
  ...PINNED,
  maxTimeUncertaintySeconds: seconds,
});

/** The same policy read out of a document, which is the form a reviewer hands over. */
async function throughDocument(seconds: number | null): Promise<AshaveriPolicy> {
  const file = policyFileFromPolicy({ ...PINNED, maxTimeUncertaintySeconds: seconds ?? undefined });
  const loaded = await loadPolicyFromText(policyFileToJson(file), TEMP);
  return loaded.policy;
}

describe('a policy that demands a bound on a stamp source', () => {
  it('refuses a source declaring more than it demands, naming the source and both numbers', () => {
    const wide = declaredBy(measured('gps disciplined clock', 6));
    expect(refusal(demanding(5), wide)).toBe('STAMP_SOURCE_TOO_UNCERTAIN');
    const message = refusalMessage(demanding(5), wide);
    expect(message).toContain('gps disciplined clock');
    expect(message).toContain('6 seconds');
    expect(message).toContain('5 seconds');
  });

  it('accepts a named source inside the bound, at the bound, and below it', () => {
    for (const uncertainty of [5, 4, 1, 0]) {
      expect(refusal(demanding(5), declaredBy(measured('ptp grandmaster', uncertainty))), String(uncertainty)).toBe(
        'accept',
      );
    }
  });

  it('reads a bound of zero as a demand rather than as the absence of one', () => {
    const exact = declaredBy(measured('disciplined rtc', 0));
    expect(refusal(demanding(0), exact)).toBe('accept');
    expect(refusal(demanding(0), declaredBy(measured('disciplined rtc', 1)))).toBe('STAMP_SOURCE_TOO_UNCERTAIN');
    expect(refusal(demanding(0), HOST_CLOCK_SOURCE)).toBe('STAMP_SOURCE_TOO_UNCERTAIN');
  });

  it('refuses an unmeasured source, because nobody measuring is not a bound of zero', () => {
    expect(HOST_CLOCK_SOURCE.uncertaintySeconds, 'the shipped source is the unmeasured case').toBeNull();
    for (const demanded of [0, 1, 3600]) {
      expect(refusal(demanding(demanded), HOST_CLOCK_SOURCE), String(demanded)).toBe('STAMP_SOURCE_TOO_UNCERTAIN');
    }
    // A store that was wired no source says so in the same words a verifier reads.
    expect(refusal(demanding(3600), declaredBy(undefined))).toBe('STAMP_SOURCE_TOO_UNCERTAIN');
    const message = refusalMessage(demanding(3600), HOST_CLOCK_SOURCE);
    expect(message).toContain('host clock');
    expect(message).toContain('3600');
    expect(message, 'the null case has to say nobody measured rather than that a bound was exceeded').toContain(
      'no measured uncertainty',
    );
  });

  it('refuses a declaration that is not a count of seconds, which states nothing in another way', () => {
    // A wired source is not read through the policy loader, so a nonsense bound has to meet the same
    // answer here as an absent one does rather than reading as the tightest source on the wire.
    for (const nonsense of [-1, Number.NaN, Number.NEGATIVE_INFINITY]) {
      expect(
        refusal(demanding(5), { name: 'a hand-wired source', uncertaintySeconds: nonsense }),
        String(nonsense),
      ).toBe('STAMP_SOURCE_TOO_UNCERTAIN');
    }
    const message = refusalMessage(demanding(5), { name: 'a hand-wired source', uncertaintySeconds: -1 });
    expect(message).toContain('a hand-wired source');
    expect(message).toContain('5');
    expect(message).toContain('no number of seconds');
  });

  it('refuses the same stamp through the document route as through the object route', async () => {
    const wide = declaredBy(measured('gps disciplined clock', 6));
    const fromFile = await throughDocument(5);
    expect(fromFile.maxTimeUncertaintySeconds).toBe(5);
    expect(refusal(fromFile, wide)).toBe(refusal(demanding(5), wide));
    const exact = await throughDocument(0);
    expect(refusal(exact, declaredBy(measured('disciplined rtc', 0)))).toBe('accept');
    expect(refusal(exact, HOST_CLOCK_SOURCE)).toBe('STAMP_SOURCE_TOO_UNCERTAIN');
  });
});

describe('a policy that demands nothing about a stamp source', () => {
  it('lets every source through, which is what keeps an existing verdict where it was', () => {
    const sources: StampSourceDeclaration[] = [
      HOST_CLOCK_SOURCE,
      declaredBy(undefined),
      declaredBy(measured('ptp grandmaster', 0)),
      declaredBy(measured('gps disciplined clock', 60)),
    ];
    for (const source of sources) {
      expect(refusal(PINNED, source), `no field: ${source.name}`).toBe('accept');
      expect(refusal(demanding(undefined), source), `an undefined bound: ${source.name}`).toBe('accept');
      expect(refusal(undefined, source), `no policy at all: ${source.name}`).toBe('accept');
    }
  });

  it('reads a demand that is not a number as a demand that bounds nothing', () => {
    // The document route refuses both of these spellings, which is where an operator meets the field. A
    // policy object handed straight to a verifier never reaches that refusal, so the field's own
    // document states what one decides, and this is the case that keeps that sentence true.
    for (const spelled of [Number.POSITIVE_INFINITY, Number.NaN]) {
      expect(
        refusal(demanding(spelled), declaredBy(measured('gps disciplined clock', 3600))),
        String(spelled),
      ).toBe('accept');
      // A demand that bounds nothing still refuses a source that declares no count of seconds, because
      // that refusal happens before anything is compared to the demand.
      expect(
        refusal(demanding(spelled), { name: 'a hand-wired source', uncertaintySeconds: Number.NaN }),
        String(spelled),
      ).toBe('STAMP_SOURCE_TOO_UNCERTAIN');
    }
  });

  it('is the same policy whether the document names it as null or leaves it out', async () => {
    const absent = await throughDocument(null);
    expect(absent.maxTimeUncertaintySeconds, 'a document demanding nothing loads as demanding nothing').toBeUndefined();
    expect(absent.issuers).toEqual(PINNED.issuers);
    const written = policyFileToJson(policyFileFromPolicy(PINNED));
    expect(written, 'a demand that was never made is not written out').not.toContain('maxTimeUncertaintySeconds');
    expect(written, 'the two windows are still written out as the defaults they are').toContain('maxReceiptAgeSeconds');
    expect(policyFileToJson(policyFileFromPolicy(demanding(5)))).toContain('"maxTimeUncertaintySeconds": 5');
  });
});
