import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  COLLATERAL_PRESENCES,
  type CollateralAbsent,
  type CollateralHeld,
  type CollateralValidityAnchor,
  type StampDisclosure,
} from '../src/index.js';

/**
 * The two disclosures a receipt states about itself, checked as declarations.
 *
 * Both are carried by the one payload version this format declares, as required members, and the bytes that
 * carry them are driven in
 * `receipt.test.ts`. What this file holds is the vocabulary, which has to agree with code in two other
 * packages, and the requiredness, which is the half a reader of a signed document can never recover once
 * a field has gone optional.
 *
 * The requiredness witnesses are `@ts-expect-error` lines on module-level declarations, so the gate that
 * reddens them is `pnpm typecheck`. That is the right gate for a fact a type carries: the day a field of
 * either shape turns optional or a name drifts, the expectation stops being an error and the build fails,
 * which is the same mechanism a test uses to pin a refusal and the only one that can pin a member that is
 * not there.
 */

const captureSourcePath = fileURLToPath(new URL('../../sdk/src/capture.ts', import.meta.url));
const storeSourcePath = fileURLToPath(new URL('../../../gateway/src/store.ts', import.meta.url));

/** True only when `T`'s own fields and `K` are the same set, in either direction. */
type ExactFields<T, K extends readonly string[]> = [Exclude<keyof T, K[number]>] extends [never]
  ? [Exclude<K[number], keyof T>] extends [never]
    ? true
    : false
  : false;

/**
 * Each type has exactly the fields named here and no others, so a member added to one of these shapes
 * later arrives as a change to a declaration and not as a silently carried extra claim.
 */
const _disclosureFields: ExactFields<StampDisclosure, ['name', 'uncertaintySeconds']> = true;
const _anchorFields: ExactFields<CollateralValidityAnchor, ['collateral', 'validity']> = true;
const _heldFields: ExactFields<CollateralHeld, ['presence', 'sha256']> = true;
const _absentFields: ExactFields<CollateralAbsent, ['presence', 'reason']> = true;

// @ts-expect-error: `uncertaintySeconds` is required. An omitted bound would read as whichever of the
// two readings a caller prefers, and "nobody measured" already has a value of its own.
const _noBound: StampDisclosure = { name: 'host clock' };
// @ts-expect-error: `undefined` is not that value, `null` is: a field may not be left holding nothing.
const _undefinedBound: StampDisclosure = { name: 'host clock', uncertaintySeconds: undefined };
// @ts-expect-error: an unlabelled source name is not the source's name, which is the whole claim.
const _noSource: StampDisclosure = { uncertaintySeconds: 0 };
// @ts-expect-error: both halves of the anchor are required, because a half it does not mention is a hole
// rather than a state, and an anchor that defaults a missing half to a pass is not an anchor.
const _halfAnchor: CollateralValidityAnchor = { collateral: { presence: 'not-taken-in', reason: 'no window was read' } };
// @ts-expect-error: a held slot carries a digest and an absent one carries a reason. A count of bytes the
// document does not hold is neither, and nothing off it could be checked against anything.
const _countOnHeld: CollateralHeld = { presence: 'held', sha256: new Uint8Array(32), byteCount: 32 };
// @ts-expect-error: an absence nobody explained is a hole, so the reason is not omittable.
const _reasonless: CollateralAbsent = { presence: 'absent-at-source' };
// @ts-expect-error: the three labels are the set, and a fourth spelling is not a fourth state.
const _unknownPresence: CollateralAbsent = { presence: 'lost', reason: 'the collector says so' };

describe('the stamp disclosure', () => {
  it('keeps "nobody measured" a value rather than an omission, and distinct from a bound of zero', () => {
    const unmeasured: StampDisclosure = { name: 'host clock', uncertaintySeconds: null };
    const measuredToZero: StampDisclosure = { name: 'disciplined clock', uncertaintySeconds: 0 };
    expect(unmeasured.uncertaintySeconds === null).toBe(true);
    expect(measuredToZero.uncertaintySeconds === null).toBe(false);
    expect(measuredToZero.uncertaintySeconds).toBe(0);
    // A policy that demands a bound refuses the first and can accept the second, which is the difference
    // `HOST_CLOCK_SOURCE` turns on and nothing in a reader may flatten.
  });

  it('takes its two field names from the shape the store already uses to declare a source', () => {
    // `StampDeclaration` is what a disclosure will be filled from. Its names are read out of that file so
    // that a rename there is heard here, where the format member carrying it is written.
    const declaration = readFileSync(storeSourcePath, 'utf8');
    const block = /export interface StampDeclaration \{([\s\S]*?)\n\}/u.exec(declaration)?.[1];
    if (block === undefined) throw new Error('store.ts no longer declares StampDeclaration in a readable shape');
    const fields = [...block.matchAll(/readonly (\w+):/gu)].map((found) => found[1]!);
    expect(fields).toEqual(['name', 'uncertaintySeconds']);
    expect(block).toContain('number | null');
  });
});

describe('the collateral validity anchor', () => {
  it('states the three presences the capture record spells, in its words and not in a synonym', () => {
    // The labels are spelled a second time in this package because the dependency runs the other way:
    // the SDK reads `@ashaveri/receipt`, so a type here cannot import one from there. Drift between the
    // two spellings is invisible to a type checker across that boundary, so it is read off the source.
    const source = readFileSync(captureSourcePath, 'utf8');
    const line = /export type CapturePresence = ([^;]+);/u.exec(source)?.[1];
    if (line === undefined) throw new Error('capture.ts no longer declares CapturePresence in a readable shape');
    const spelled = [...line.matchAll(/'([^']+)'/gu)].map((found) => found[1]!);
    expect(spelled).toEqual([...COLLATERAL_PRESENCES]);
    expect(COLLATERAL_PRESENCES).toEqual(['held', 'absent-at-source', 'not-taken-in']);
  });

  it('holds a digest when it holds the context, and the reason it does not when it does not', () => {
    const neverProduced: CollateralAbsent = { presence: 'absent-at-source', reason: 'the source served no chain' };
    const notTakenIn: CollateralAbsent = { presence: 'not-taken-in', reason: 'the collector timed out' };
    // The two absences are different outcomes, one about the world and one about us, and the reader that
    // weighs them has to be able to tell them apart, so they are not one label.
    expect(neverProduced.presence).not.toBe(notTakenIn.presence);
    expect(notTakenIn.presence).not.toBe('held');
    const anchor: CollateralValidityAnchor = {
      collateral: { presence: 'held', sha256: new Uint8Array(32).fill(7) },
      validity: neverProduced,
    };
    expect(anchor.collateral.presence).toBe('held');
    expect(anchor.validity.presence).toBe('absent-at-source');
  });
});
