import { describe, expect, it } from 'vitest';
import { toHex } from '@ashaveri/receipt';
import { assertKeyBindingFreshUnderPolicy, type KeyBindingClaim } from '../src/key-binding.js';
import { SdkError } from '../src/errors.js';
import { parseManifest } from '../src/manifest.js';
import { RECEIPT_KEY, ROTATED_KEY, keyEntry, plainManifest } from './manifest-documents.js';

/**
 * The freshness demand a reader states against the key route's boot-scoped binding document.
 *
 * The document is constant for a whole boot, so it is replayable standing evidence unless a reader
 * demands an age of it. These cases hold the three readings of that demand apart: a finite bound
 * refuses an older document, the epoch that carries the key is the ceiling the bound cannot exceed,
 * and a reader that names no bound accepts a document of any date, which is the weakness owned in the
 * open rather than a hole left unnoticed. The rotation refusal is `adjudicateReceiptEpoch`'s own, raised
 * before the age is weighed, so a binding whose epoch the manifest does not support is refused however
 * large the demand.
 */

const IAT = 1_772_000_000;
const EARLIER = IAT - 10_000;
const ROTATION_STARTS = IAT + 100;

/** Epoch 1 closes where epoch 2 opens, so epoch 1's window is [EARLIER, ROTATION_STARTS). */
const WINDOWS = [
  keyEntry(RECEIPT_KEY, { epk: 1, validFrom: EARLIER }),
  keyEntry(ROTATED_KEY, { epk: 2, validFrom: ROTATION_STARTS }),
];

function manifestWith(keys: readonly Record<string, unknown>[], epoch: number) {
  return parseManifest(JSON.parse(new TextDecoder().decode(plainManifest({ keys, epoch }))));
}

const windowsManifest = manifestWith(WINDOWS, 2);
const currentOnlyManifest = manifestWith([keyEntry(RECEIPT_KEY)], 1);

/** A binding boot-scoped under epoch 1, attested at IAT, inside that epoch's window. */
const CLAIM: KeyBindingClaim = { kid: toHex(RECEIPT_KEY.kid), epoch: 1, issuedAt: IAT };

const at = (secondsAfterIat: number): number => (IAT + secondsAfterIat) * 1000;

function refusalFrom(fn: () => void): SdkError {
  try {
    fn();
  } catch (err) {
    if (err instanceof SdkError) return err;
    throw err;
  }
  throw new Error('the check accepted a binding this case expects it to refuse');
}

describe('the age a reader demands of a key binding', () => {
  it('accepts a binding collected within the demanded bound', () => {
    expect(() =>
      assertKeyBindingFreshUnderPolicy({ maxKeyBindingAgeSeconds: 300 }, CLAIM, windowsManifest, at(50)),
    ).not.toThrow();
  });

  it('refuses a binding older than the demanded bound', () => {
    const err = refusalFrom(() =>
      assertKeyBindingFreshUnderPolicy({ maxKeyBindingAgeSeconds: 30 }, CLAIM, windowsManifest, at(50)),
    );
    expect(err.code).toBe('KEY_BINDING_TOO_OLD');
    expect(err.message).toContain('30 seconds');
  });

  it('holds the demand down to the epoch window that carries the key', () => {
    // The demand is far wider than the span left in epoch 1, which ends 100 seconds after IAT. A
    // reading 200 seconds after IAT is past that end, so the epoch ceiling refuses it even though the
    // demand alone would have admitted it.
    const err = refusalFrom(() =>
      assertKeyBindingFreshUnderPolicy({ maxKeyBindingAgeSeconds: 100_000 }, CLAIM, windowsManifest, at(200)),
    );
    expect(err.code).toBe('KEY_BINDING_TOO_OLD');
    expect(err.message).toContain('capped by the epoch 1 window');
  });

  it('accepts a document of any date when no bound is named', () => {
    // The owned weakness: a reader that names no bound demands nothing, so a reading far past the
    // epoch's end is accepted rather than refused. No verdict taken under such a policy moves.
    expect(() => assertKeyBindingFreshUnderPolicy({}, CLAIM, windowsManifest, at(10_000_000))).not.toThrow();
    expect(() => assertKeyBindingFreshUnderPolicy(undefined, CLAIM, windowsManifest, at(10_000_000))).not.toThrow();
  });

  it('treats Infinity as the deliberate off switch', () => {
    expect(() =>
      assertKeyBindingFreshUnderPolicy(
        { maxKeyBindingAgeSeconds: Number.POSITIVE_INFINITY },
        CLAIM,
        windowsManifest,
        at(10_000_000),
      ),
    ).not.toThrow();
  });

  it('lets the demand stand alone when the manifest publishes no window', () => {
    const claim: KeyBindingClaim = { kid: toHex(RECEIPT_KEY.kid), epoch: 1, issuedAt: IAT };
    expect(() =>
      assertKeyBindingFreshUnderPolicy({ maxKeyBindingAgeSeconds: 300 }, claim, currentOnlyManifest, at(50)),
    ).not.toThrow();
    const err = refusalFrom(() =>
      assertKeyBindingFreshUnderPolicy({ maxKeyBindingAgeSeconds: 30 }, claim, currentOnlyManifest, at(50)),
    );
    expect(err.code).toBe('KEY_BINDING_TOO_OLD');
    expect(err.message).not.toContain('capped');
  });
});

describe('the epoch ceiling, raised before the age is weighed', () => {
  it('refuses an epoch the manifest never declared', () => {
    const claim: KeyBindingClaim = { ...CLAIM, epoch: 99 };
    const err = refusalFrom(() =>
      assertKeyBindingFreshUnderPolicy({ maxKeyBindingAgeSeconds: 300 }, claim, windowsManifest, at(50)),
    );
    expect(err.code).toBe('MANIFEST_EPOCH_UNDECLARED');
  });

  it('refuses a binding whose key is not the one the epoch names', () => {
    const claim: KeyBindingClaim = { ...CLAIM, kid: toHex(ROTATED_KEY.kid) };
    const err = refusalFrom(() =>
      assertKeyBindingFreshUnderPolicy({ maxKeyBindingAgeSeconds: 300 }, claim, windowsManifest, at(50)),
    );
    expect(err.code).toBe('MANIFEST_EPOCH_DISAGREES');
  });

  it('refuses a binding whose instant falls outside its epoch window', () => {
    const claim: KeyBindingClaim = { ...CLAIM, issuedAt: ROTATION_STARTS + 50 };
    const err = refusalFrom(() =>
      assertKeyBindingFreshUnderPolicy({ maxKeyBindingAgeSeconds: 300 }, claim, windowsManifest, at(50)),
    );
    expect(err.code).toBe('MANIFEST_EPOCH_DISAGREES');
  });
});

describe('the clock the reader hands', () => {
  it('refuses a reading that is not a whole number of milliseconds in the span', () => {
    const err = refusalFrom(() =>
      assertKeyBindingFreshUnderPolicy({ maxKeyBindingAgeSeconds: 300 }, CLAIM, windowsManifest, 123),
    );
    expect(err.code).toBe('CLIENT_CLOCK_OUT_OF_RANGE');
  });

  it('asks the clock nothing when no bound is named', () => {
    // The absent demand returns before the clock is read, so even a misspelled reading moves no
    // verdict under a policy that demands nothing.
    expect(() => assertKeyBindingFreshUnderPolicy({}, CLAIM, windowsManifest, 123)).not.toThrow();
  });
});