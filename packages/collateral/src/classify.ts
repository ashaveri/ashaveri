import { CollateralError, collateralRefusal, quoteOrDigest, type CollateralRefusal } from './errors.js';
import { fetchFromOrigin, wallClock } from './fetch.js';
import { collateralCacheKey, declarationFor, requestUrl, type OriginDeclaration } from './intel-origin.js';
import { readSignedCollateral, type ReadCollateral } from './read.js';
import { readServedCollateral } from './served.js';
import { sha256Hex, toHex } from './bytes.js';
import type {
  CarriedCollateral,
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

/**
 * Material that arrived inside a sealed container rather than from an origin, weighed by the same rules.
 *
 * This is the one honest way to appraise bytes the caller did not fetch. The retained path already reads bytes it
 * is handed, and it refuses any set it cannot stamp, because the instant an answer was observed is the only thing
 * that separates a retained answer from a fresh one. A container states no such instant: nothing inside one
 * watched an origin answer, so no observation is recorded anywhere in it. The number a caller hands here is
 * therefore the instant the record holding the material states it held it, which for a sealed receipt is its own
 * `iat`, and the receipt states beside that stamp which source it reads and how far that source admits to being
 * from the instants it names. What the stamp is worth is the receipt's disclosure rather than a claim of this
 * path, and the alternative, minting an instant nobody recorded, is what the retained path already refuses.
 *
 * What this path appraises is material of the envelope the declaration names, and Intel answers its documents in
 * another one: a JSON body whose issuer chain arrives in a response header, cited at each declaration in
 * `intel-origin.ts`. That pair is weighed, when both halves are in hand, by `readServedCollateral`, and a container
 * hands the halves through the same two members a store hands them in. What a container states is what this weighs:
 * one that holds a body and no header hands a body alone, and the arm that reads a body alone is the one whose
 * certificates sit inside it, so such bytes are refused at the envelope rather than weighed and no stamp changes
 * that. The honesty of this path is about where an instant comes from; which arm reads the bytes is the envelope's
 * question, answered by the declaration and by whether the chain arrived beside the body it signs.
 *
 * The consequence is narrow and it is the design working rather than a gap. The instant feeds one sentence, the
 * one a stale answer carries about when the bytes were seen, and it moves no comparison of its own: the window
 * the vendor signed is read against `appraisalAt`, which stays the caller's own statement of the moment being
 * asked about. So a carried answer never reaches `current-knowledge`, which is the reach that requires this run
 * to have asked the origin, and `claim.observedAt` stays `null`, because this run saw no origin. Those are one
 * fact from two ends: no document sealed in a container becomes an observation by being read. What the window
 * check settled is left where a reader can weigh it, in `collateral.classification.window` beside
 * `claim.appraisalAt`, and a reader asking whether the context stood at the record's own instant hands that
 * instant as both numbers and reads the pair back.
 */
export async function appraiseCarriedCollateral(
  query: Omit<CollateralQuery, 'retained'>,
  carried: CarriedCollateral,
  options: CollateralAppraisalOptions = {},
): Promise<CollateralOutcome> {
  // The container's material is the only material this appraises, which is why the query type omits the field and
  // why it is written here rather than merged: a caller holding both a fetch and a container has to say which one
  // this answer is about, and the answer it gets is the one it handed in the `carried` argument. The chain beside
  // that material travels with it, so a container stating a header reaches the reader that weighs a pair and a
  // container stating none reaches the reader that weighs a body alone.
  return appraiseCollateral(
    {
      ...query,
      retained: {
        bytes: carried.bytes,
        chain: carried.chain ?? null,
        chainSha256: carried.chainSha256 ?? null,
        observedAt: carried.heldAt,
      },
    },
    options,
  );
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
  let observed: { readonly bytes: Uint8Array; readonly chain: Uint8Array | null; readonly observedAt: number } | { readonly refusal: CollateralRefusal };
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
    // A caller that states a digest for the chain beside its bytes is asking what was seen, so the pair is checked
    // against that promise before anything of the body is believed: a header swapped under the question would
    // otherwise answer a different one and report the digest the caller named.
    if (query.retained.chain !== null && query.retained.chainSha256 !== null) {
      const actual = sha256Hex(query.retained.chain);
      const stated = toHex(query.retained.chainSha256);
      if (actual !== stated) {
        return unavailable(
          collateralRefusal(
            'COLLATERAL_RETAINED_CHAIN_MISMATCH',
            `the retained chain hashes to ${actual} and the caller named ${stated}`,
            ['retained.chain', 'retained.chainSha256'],
          ),
        );
      }
    }
    // A header is not a member of a body, so what arrives beside retained bytes is whatever the caller kept. A
    // chain kept with them is carried, and its absence is carried rather than invented: nothing here reads a
    // header off the wire to complete a pair that was kept as one half.
    observed = {
      bytes: query.retained.bytes,
      chain: query.retained.chain ?? null,
      observedAt: query.retained.observedAt,
    };
  }
  const reading = { query, declaration, appraisalAt };
  // Which arm weighs the answer is a fact of the declaration and of the answer, never a guess from the bytes.
  // A declaration that states a served envelope is weighed from the pair, body and chain together, whether the pair
  // arrived from the origin in this run or was handed in as bytes the caller kept; that is the shape its origin
  // answers in. A body that arrived without its header is a body alone, and the arm that reads a body alone is the
  // one whose certificates sit inside it, so a served shape handed over alone is refused at the envelope rather
  // than weighed.
  const read = declaration.signature.served !== null && observed.chain !== null
    ? readServedCollateral(observed.bytes, observed.chain, reading)
    : readSignedCollateral(observed.bytes, reading);
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
