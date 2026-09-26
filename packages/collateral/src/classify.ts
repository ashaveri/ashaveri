import { CollateralError, collateralRefusal, quoteOrDigest, type CollateralRefusal } from './errors.js';
import { fetchFromOrigin, wallClock } from './fetch.js';
import { collateralCacheKey, declarationFor, requestUrl, type OriginDeclaration } from './intel-origin.js';
import { readSignedCollateral, type ReadCollateral } from './read.js';
import { sha256Hex } from './bytes.js';
import type {
  CollateralAppraisalOptions,
  CollateralClaim,
  CollateralOutcome,
  CollateralQuery,
  SignedCollateral,
  StatusReading,
} from './types.js';

/**
 * What the collateral for one identity is, at one moment.
 *
 * The order is the whole design: settle that the question is answerable, then ask, then believe, then
 * classify. Nothing is fetched before the caller's roots and the appraisal instant are in hand, and
 * nothing is classified before its signature has been established under a root the caller named, so the
 * two ways a platform gets a pass it did not earn, an unanswered question and an unverified answer, are
 * closed before either is read.
 */
export async function appraiseCollateral(
  query: CollateralQuery,
  options: CollateralAppraisalOptions = {},
): Promise<CollateralOutcome> {
  const outcome = await appraise(query, options);
  if ((outcome.state === 'unavailable' || outcome.state === 'missing-context') && query.onAbsent === 'refuse') {
    throw new CollateralError(outcome.refusal);
  }
  return outcome;
}

async function appraise(
  query: CollateralQuery,
  options: CollateralAppraisalOptions,
): Promise<CollateralOutcome> {
  const declared = declarationFor(query.origin);
  if ('refusal' in declared) {
    return unavailable(declared.refusal);
  }
  const declaration = declared;
  const missing = askedButNotGiven(query, declaration);
  if (missing !== null) {
    return missingContext(missing);
  }
  const appraisalAt = query.appraisalAt as number;
  const bytes = query.retained === null ? null : query.retained.bytes;
  if (bytes !== null && bytes.byteLength > declaration.maxResponseBytes) {
    return unavailable(refused(
      declaration,
      `a retained blob of ${String(bytes.byteLength)} bytes is over the ${String(declaration.maxResponseBytes)} this path reads`,
    ));
  }
  const url = requestUrl(query, declaration);
  if (typeof url !== 'string') {
    return missingContext(url.refusal);
  }
  let observed: { readonly bytes: Uint8Array; readonly observedAt: number } | { readonly refusal: CollateralRefusal };
  if (query.retained === null) {
    const asked = await fetchFromOrigin(url, declaration, { transport: options.transport, clock: options.clock ?? wallClock });
    if ('refusal' in asked) {
      return unavailable(asked.refusal);
    }
    observed = asked.fetched;
  } else {
    if (query.retained.observedAt === null) {
      return missingContext(
        collateralRefusal('COLLATERAL_INPUT_MISSING', 'the retained bytes carry no stamp for when they were seen', ['retained.observedAt']),
      );
    }
    observed = { bytes: query.retained.bytes, observedAt: query.retained.observedAt };
  }
  const read = readSignedCollateral(observed.bytes, { query, declaration, appraisalAt });
  if ('refusal' in read) {
    return unavailable(read.refusal);
  }
  return classify(read.read, query, declaration, observed.observedAt, appraisalAt, query.retained === null);
}

/**
 * Which of the five answers this is.
 *
 * A statement that the vendor no longer stands behind outranks a closed window, because nothing
 * published later un-revokes a level, so a revoked document answers a current question even when it is
 * itself too old to be a fresh one. Everything else reaches `current` only from bytes this run watched
 * arrive and a window that covers the moment asked about; a retained blob and an out-of-window one are
 * both `stale`, and both carry the historical reading rather than a softened pass.
 */
function classify(
  read: ReadCollateral,
  query: CollateralQuery,
  declaration: OriginDeclaration,
  observedAt: number,
  appraisalAt: number,
  askedThisRun: boolean,
): CollateralOutcome {
  const covers = appraisalAt >= read.signedAt && appraisalAt < read.validUntil;
  const trusted = declaration.status.trusted.includes(read.vendorStatus);
  const revoked = declaration.status.revoked.includes(read.vendorStatus);
  if (!trusted && !revoked) {
    return unavailable(collateralRefusal(
      declaration.refusals.statusUnknown,
      `${quoteOrDigest(read.vendorStatus)} is a status this package has no rule for`,
    ));
  }
  const key = collateralCacheKey(query, declaration);
  if (typeof key !== 'string') {
    return missingContext(collateralRefusal(
      'COLLATERAL_INPUT_MISSING',
      'the record these bytes belong to cannot be named',
      key.missing,
    ));
  }
  const claim: CollateralClaim = {
    reach: askedThisRun && covers ? 'current-knowledge' : 'historical-knowledge',
    appraisalAt,
    observedAt: askedThisRun ? observedAt : null,
    retainUntil: read.validUntil,
    cacheKey: key,
  };
  const collateral = signed(read, query, revoked ? 'revoked' : 'trusted');
  if (revoked) {
    return {
      state: 'revoked',
      collateral,
      claim,
      refusal: collateralRefusal(
        'COLLATERAL_REVOKED_BY_VENDOR',
        `the signed document reads ${quoteOrDigest(read.vendorStatus)} for the level asked about, which is a statement about ${new Date(read.signedAt * 1000).toISOString()}`,
      ),
    };
  }
  if (claim.reach === 'current-knowledge') {
    return { state: 'current', collateral, claim };
  }
  return {
    state: 'stale',
    collateral,
    claim,
    refusal: askedThisRun
      ? collateralRefusal(
        declaration.refusals.window,
        `the document stands from ${new Date(read.signedAt * 1000).toISOString()} to ${new Date(read.validUntil * 1000).toISOString()} and the moment asked is ${new Date(appraisalAt * 1000).toISOString()}`,
      )
      : collateralRefusal(
        'COLLATERAL_NOT_OBSERVED',
        `the bytes were seen at ${new Date(observedAt * 1000).toISOString()} and this run asked the origin nothing`,
        ['retained'],
      ),
  };
}

function signed(read: ReadCollateral, query: CollateralQuery, readAs: StatusReading): SignedCollateral {
  return {
    origin: query.origin,
    platform: query.platform,
    blobs: read.blobs,
    digest: sha256Hex(read.blobs[0] as Uint8Array),
    anchorDigest: read.anchorDigest,
    declared: { cpuType: read.declaredCpuType, vendorStatus: read.vendorStatus },
    classification: {
      readAs,
      window: { from: read.signedAt, until: read.validUntil },
      signedAt: read.signedAt,
    },
  };
}

/** Everything a query has to state before the origin is worth asking. */
function askedButNotGiven(query: CollateralQuery, declaration: OriginDeclaration): CollateralRefusal | null {
  if (query.roots.length === 0) {
    return collateralRefusal(declaration.refusals.anchor, 'a verdict needs a root the caller holds, and none was passed', ['roots']);
  }
  if (query.appraisalAt === null) {
    return collateralRefusal('COLLATERAL_INPUT_MISSING', 'no instant was stated for the appraisal, and no verdict can be reached about a moment nobody named', ['appraisalAt']);
  }
  if (declaration.identity.levelsMember !== null && query.level === null) {
    return collateralRefusal(
      'COLLATERAL_INPUT_MISSING',
      `${declaration.name} states its status per level and the query named none`,
      ['level'],
    );
  }
  if (query.retained !== null && query.retained.bytes.byteLength === 0) {
    return collateralRefusal('COLLATERAL_INPUT_MISSING', 'the retained blob is empty', ['retained.bytes']);
  }
  return null;
}

function missingContext(refusal: CollateralRefusal): CollateralOutcome {
  return { state: 'missing-context', collateral: null, claim: null, refusal };
}

function unavailable(refusal: CollateralRefusal): CollateralOutcome {
  return { state: 'unavailable', collateral: null, claim: null, refusal };
}

function refused(declaration: OriginDeclaration, why: string): CollateralRefusal {
  return collateralRefusal(declaration.refusals.envelope, why);
}
