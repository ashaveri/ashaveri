import type { CollateralValidityAnchor } from '@ashaveri/receipt';
import type { AttestationBundle } from './deployment.js';
import { notTakenInAnchor } from './issuance-disclosure.js';

/**
 * The seam an issuance reads a cached appraisal through, and the anchor it authors from what it read.
 *
 * The appraiser that fills a cache is a scheduled service of a deployment's own: it runs off the request
 * path, it is the process that reaches a vendor, and it is not part of this repository. What ships is the
 * reader an issuance holds and the conversion of one reading into the two slots of a payload's `cva`, so a
 * deployment that runs such a service signs a document stating the digests that service observed, and a
 * deployment that runs none signs the document stating both absences. No request path of either contacts a
 * vendor, because the only thing this file can do with a reading is turn it into an anchor.
 *
 * The shapes are this file's own rather than another package's, which is what keeps the dependency out: the
 * vocabulary a cache entry is made of is stated beside the reader that consumes it, and a deployment wiring
 * one names the members it fills. Three of those members are not this file's to spell, and it does not claim
 * them: `cacheKey`, `observedAt` and `sourceUncertaintySeconds` are the capture record's, declared in
 * `packages/sdk/src/capture.ts` for the slot a collector took in, and `test/appraisal-anchor.test.ts` reads
 * both declarations and fails when the two stop agreeing. What this file adds to them is one bound of its
 * own, `until`, which is the vendor document's next update rather than half of a window pair.
 */

/** The name every absence this file writes gives the store a deployment wired. */
const CACHE = 'the appraisal cache';

/**
 * One cached answer, as the appraiser that wrote it left it.
 *
 * Every number is whole unix seconds. The three instants are the appraiser's and never the issuer's: an
 * anchor that quoted the issuance clock for a fact the appraiser observed would state a measurement this
 * process did not make, which is the same confusion `sd` exists to keep out of a payload's `iat`.
 */
export interface CachedAppraisal {
  /** The key this entry was filed under, named in every absence that answers for it. */
  readonly cacheKey: string;
  /** sha256 of the collateral bytes the appraiser observed, at the width a receipt's digests carry. */
  readonly collateralSha256: Uint8Array;
  /** sha256 of the validity context it observed, or null where it observed none for this key. */
  readonly validitySha256: Uint8Array | null;
  /** The instant the cached answer landed, on the appraiser's clock. */
  readonly observedAt: number;
  /**
   * How far the source of these bytes admits its own instants can be, or null where nobody measured it,
   * in the spelling `StampDisclosure` gives that absence in `packages/receipt/src/disclosure.ts`.
   *
   * Nothing in this repository reads it: a held slot of an anchor carries a digest and no bound beside it,
   * so there is no position in a payload for this number to travel in. It stays required, because an entry
   * that cannot say how far its own source admits it can be wrong is the thing this member exists to make
   * impossible, and a reader that grows a position for it is meant to find a stated bound rather than have
   * to invent one.
   */
  readonly sourceUncertaintySeconds: number | null;
  /** The vendor document's own `nextUpdate`, copied rather than computed, and the bound on these bytes. */
  readonly until: number;
  /** The instant the appraiser decided this entry, on the appraiser's clock. */
  readonly judgedAt: number;
}

/**
 * What one read of the cache answered, in the four states a read can be in.
 *
 * The three absences are three states rather than one because they name three different gaps, and a signed
 * document that collapsed them would tell a reader less than the process that issued it knew: no cache was
 * wired, a cache was wired and holds nothing under this key, or a cache holds an entry whose own window had
 * closed. `expired` carries the two instants the decision was made from so the reason that quotes them
 * quotes the appraiser's readings and not a comparison this process performed.
 */
export type AppraisalReading =
  | { readonly state: 'held'; readonly appraisal: CachedAppraisal }
  | { readonly state: 'no-cache' }
  | { readonly state: 'no-entry'; readonly cacheKey: string }
  | {
      readonly state: 'expired';
      readonly cacheKey: string;
      readonly until: number;
      readonly judgedAt: number;
    };

/**
 * The reader a deployment wires at construction.
 *
 * It takes the bundle the issuance already holds and answers with a reading. The answer may be a promise
 * because a cache a deployment wires sits on disk, and `issue` awaits it; what it may not be is a call that
 * reaches a vendor, which is the property that keeps every request path off the network and the reason the
 * appraiser runs on a schedule of its own.
 */
export type AppraisalReader = (evidence: AttestationBundle) => AppraisalReading | Promise<AppraisalReading>;

/**
 * Both slots of an anchor for one key whose entry was left unused because its own window had closed.
 *
 * One path with one spelling, and the `expired` arm and a `held` reading that is stale on its own face both
 * go through it, so the two cannot drift into two answers for one fact. That is what a gateway's own
 * arithmetic buys against its wiring: a reader that hands over an entry the document's `nextUpdate` has
 * already passed is answered with the absence its own numbers state rather than with a digest of bytes
 * nobody can weigh, and a reader that hands over the same window as an `expired` reading signs the same
 * document either way.
 */
function closedWindowAnchor(cacheKey: string, until: number, judgedAt: number): CollateralValidityAnchor {
  return {
    collateral: closedWindowSlot(cacheKey, until, judgedAt, 'collateral digest'),
    validity: closedWindowSlot(cacheKey, until, judgedAt, 'validity context'),
  };
}

function closedWindowSlot(
  cacheKey: string,
  until: number,
  judgedAt: number,
  named: string,
): CollateralValidityAnchor['collateral'] {
  return {
    presence: 'not-taken-in',
    reason:
      `${CACHE} holds an entry under the key "${cacheKey}" that was left unused because its own window had ` +
      `closed: the document those bytes came from names ${until} as its own next update and the reader judged ` +
      `at ${judgedAt}, both instants on the appraiser's clock, so no ${named} was taken into this record and ` +
      'no copy of one that has outlived its window is presented as current',
  };
}

/** Both slots of an anchor for a cache that was wired and holds no entry under this key. */
function noEntryAnchor(cacheKey: string): CollateralValidityAnchor {
  return {
    collateral: {
      presence: 'not-taken-in',
      reason:
        `${CACHE} holds no entry under the key "${cacheKey}", so no collateral digest was taken into this ` +
        'record: the appraisal that would have observed one is a service this process does not run, and ' +
        'whether collateral for this evidence exists is a fact this issuance never looked at',
    },
    validity: {
      presence: 'not-taken-in',
      reason:
        `${CACHE} holds no entry under the key "${cacheKey}", so no validity context was taken into this ` +
        'record: the appraisal that would have read a window is a service this process does not run, and ' +
        'whether one stood open for this evidence is a fact this issuance never looked at',
    },
  };
}

/**
 * Both slots of an anchor for a read that threw, which is the answer the catch at the issuance site gives.
 *
 * The failure is named and its message is not: a reason is attested text, so a message carrying a line
 * separator would reach the writer's refusal on `cva.col.r` and take the issuance down with it, and a
 * message carrying anything else would put words a vendor or a filesystem chose into a document a reviewer
 * cites. What an operator gets instead is the log line the catch writes beside it, which is where a stack
 * belongs.
 */
export function readFailedAnchor(): CollateralValidityAnchor {
  return {
    collateral: {
      presence: 'not-taken-in',
      reason:
        `${CACHE} was wired into this gateway and the read of it failed, so no collateral digest was taken ` +
        'into this record: the failure is logged at the site it happened at and no part of its message is ' +
        'written into a signed document',
    },
    validity: {
      presence: 'not-taken-in',
      reason:
        `${CACHE} was wired into this gateway and the read of it failed, so no validity context was taken ` +
        'into this record: the failure is logged at the site it happened at and no part of its message is ' +
        'written into a signed document',
    },
  };
}

/**
 * The anchor one reading of the cache authors, with both slots filled whichever way it answers.
 *
 * A slot is never omitted and an absence is never softened into something that reads as a pass, which is
 * the discipline `packages/receipt/src/disclosure.ts` states for the shape and the one `notTakenInAnchor`
 * states for a gateway that captures nothing. What this conversion adds is the freshness rule: a `held`
 * reading is weighed against the two instants it carries, and one whose window has closed is answered as
 * the closed window it is.
 */
export function anchorFrom(reading: AppraisalReading): CollateralValidityAnchor {
  switch (reading.state) {
    case 'held': {
      const { appraisal } = reading;
      if (appraisal.until <= appraisal.judgedAt) {
        return closedWindowAnchor(appraisal.cacheKey, appraisal.until, appraisal.judgedAt);
      }
      return {
        collateral: { presence: 'held', sha256: appraisal.collateralSha256 },
        validity:
          appraisal.validitySha256 === null
            ? {
                presence: 'not-taken-in',
                reason:
                  `${CACHE} holds no validity material under the key "${appraisal.cacheKey}": the collateral ` +
                  'digest it holds for that key is taken into this record and the window an appraisal of it ' +
                  'ran in is not, so this slot states a gap in what the cache kept rather than a verdict ' +
                  'about the world',
              }
            : { presence: 'held', sha256: appraisal.validitySha256 },
      };
    }
    case 'no-cache':
      return notTakenInAnchor();
    case 'no-entry':
      return noEntryAnchor(reading.cacheKey);
    case 'expired':
      return closedWindowAnchor(reading.cacheKey, reading.until, reading.judgedAt);
  }
}
