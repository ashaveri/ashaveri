import { CollateralError, collateralRefusal, quoteOrDigest, type CollateralRefusal } from './errors.js';
import { fetchFromOrigin, wallClock } from './fetch.js';
import { collateralCacheKey, declarationFor, isCrlDeclaration, isIntelDeclaration, isVcekDeclaration, routesAnswerNow, requestUrl, AMD_KDS, INTEL_PCK_CRL, type IntelOriginDeclaration, type CrlOriginDeclaration, type OriginDeclaration, type VcekOriginDeclaration } from './intel-origin.js';
import { readVcekChain } from './amd-kds.js';
import { readPckCrl } from './crl.js';
import { readSignedCollateral, type ReadCollateral } from './read.js';
import { readServedCollateral } from './served.js';
import { sha256Hex, toHex } from './bytes.js';
import type {
  CarriedCollateral,
  CollateralAppraisalOptions,
  CollateralClaim,
  CollateralOutcome,
  CollateralQuery,
  PckCrlQuery,
  RevocationList,
  RevocationOutcome,
  SignedCollateral,
  StatusReading,
  VcekChain,
  VcekChainOutcome,
  VcekChainQuery,
} from './types.js';

/**
 * What the collateral for one identity is, at one moment.
 *
 * The order is the whole design: settle that the question is answerable, then ask, then believe, then
 * classify. Nothing is fetched before the caller's roots and the appraisal instant are in hand, and
 * nothing is classified before its signature has been established under a root the caller named, so the
 * two ways a platform gets a pass it did not earn, an unanswered question and an unverified answer, are
 * closed before either is read.
 *
 * A CRL is not a platform-level document, so this entry point names the serial appraisal instead of
 * reading one as a level list. `appraisePckCrl` is where a list is weighed.
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

/**
 * The Intel PCK CRL asked about one certificate serial.
 *
 * A list answers whether a serial was revoked as of its own `thisUpdate`, so this entry point takes a
 * `PckCrlQuery` rather than the platform-level `CollateralQuery`. It fetches and reads through the same
 * transport, declaration and chain walk the two JSON documents use, and it keeps its answers apart because
 * `not-listed` is neither `current` nor trusted. A caller holding a list from its own store or from a sealed
 * container passes it through `retained`, with the container's own instant as `observedAt`, and the claim
 * beside the answer states that reach as historical.
 */
export async function appraisePckCrl(
  query: PckCrlQuery,
  options: CollateralAppraisalOptions = {},
): Promise<RevocationOutcome> {
  const outcome = await appraiseRevocation(query, options);
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
  if (isCrlDeclaration(declared)) {
    // A CRL has a reader here, so this is not an unsupported origin. What it lacks is a platform level, which
    // this entry point asks about; the serial question belongs to `appraisePckCrl`.
    return missingContext(collateralRefusal(
      'COLLATERAL_INPUT_MISSING',
      `${declared.name} answers about a certificate serial and this appraisal asks about a platform level; appraisePckCrl weighs that list`,
      query.level === null ? ['level'] : [],
    ));
  }
  if (isVcekDeclaration(declared)) {
    // The same sentence for the other origin with a reader that is not a level reader: a VCEK chain names a
    // chip rather than a rung, and `appraiseVcekChain` is where the pair is weighed.
    return missingContext(collateralRefusal(
      'COLLATERAL_INPUT_MISSING',
      `${declared.name} answers about one chip's certificate chain and this appraisal asks about a platform level; appraiseVcekChain weighs that chain`,
      query.level === null ? ['level'] : [],
    ));
  }
  if (!isIntelDeclaration(declared)) {
    return unavailable(collateralRefusal(
      'COLLATERAL_ORIGIN_UNSUPPORTED',
      `${declared.name} has no reader on this appraisal path`,
      ['origin'],
    ));
  }
  const declaration = declared;
  const missing = askedButNotGiven(query, declaration);
  if (missing !== null) {
    return missingContext(missing);
  }
  const appraisalAt = query.appraisalAt as number;
  const observed = await observe(query, declaration, options);
  if ('refusal' in observed) {
    return observed.state === 'missing-context' ? missingContext(observed.refusal) : unavailable(observed.refusal);
  }
  const reading = { query, declaration, appraisalAt };
  // Which arm weighs the answer is a fact of the declaration and of the answer, never a guess from the bytes.
  // A declaration that states a served envelope is weighed from the pair, body and chain together, whether the pair
  // arrived from the origin in this run or was handed in as bytes the caller kept; that is the shape its origin
  // answers in. A body that arrived without its header is a body alone, and the arm that reads a body alone is the
  // one whose certificates sit inside it, so a served shape handed over alone is refused at the envelope rather
  // than weighed.
  const read = declaration.signature.served !== null && observed.observed.chain !== null
    ? readServedCollateral(observed.observed.bytes, observed.observed.chain, reading)
    : readSignedCollateral(observed.observed.bytes, reading);
  if ('refusal' in read) {
    return unavailable(read.refusal);
  }
  return classify(read.read, query, declaration, observed.observed.observedAt, appraisalAt, query.retained === null);
}

async function appraiseRevocation(
  query: PckCrlQuery,
  options: CollateralAppraisalOptions,
): Promise<RevocationOutcome> {
  const declaration = INTEL_PCK_CRL;
  const missing = askedButNotGivenCrl(query, declaration);
  if (missing !== null) {
    return missingRevocation(missing);
  }
  const appraisalAt = query.appraisalAt as number;
  const observed = await observe(query, declaration, options);
  if ('refusal' in observed) {
    return observed.state === 'missing-context' ? missingRevocation(observed.refusal) : unavailableRevocation(observed.refusal);
  }
  const read = readPckCrl(
    observed.observed.bytes,
    observed.observed.chain,
    { query, declaration, appraisalAt },
  );
  if ('refusal' in read) {
    return unavailableRevocation(read.refusal);
  }
  return classifyRevocation(
    read.read,
    query,
    declaration,
    observed.observed.observedAt,
    appraisalAt,
    query.retained === null,
  );
}

/**
 * The AMD Key Distribution Service asked about one chip.
 *
 * The question is answered by two published routes rather than one: the per-chip route answers the certificate
 * and the chain route answers the authorities above it, so this entry point asks both and weighs the pair, and
 * it keeps its answers apart from the other two outcome types because a certificate chain states no platform
 * level, no vendor status word and no revocation. The chain is believed by the same primitives a report's own
 * certificates are believed by, under a root the caller names, and the answer it reaches is what the routes
 * state: AMD signed this key for this chip, and that signing stands over the window the certificates share.
 * A caller holding a pair from its own store or from a sealed container passes it through `retained`, the
 * certificate as `bytes` and the chain as `chain`, with the container's own instant as `observedAt`.
 */
export async function appraiseVcekChain(
  query: VcekChainQuery,
  options: CollateralAppraisalOptions = {},
): Promise<VcekChainOutcome> {
  const outcome = await appraiseChain(query, options);
  if ((outcome.state === 'unavailable' || outcome.state === 'missing-context') && query.onAbsent === 'refuse') {
    throw new CollateralError(outcome.refusal);
  }
  return outcome;
}

async function appraiseChain(
  query: VcekChainQuery,
  options: CollateralAppraisalOptions,
): Promise<VcekChainOutcome> {
  const declaration = AMD_KDS;
  const missing = askedButNotGivenChain(query, declaration);
  if (missing !== null) {
    return missingChain(missing);
  }
  const appraisalAt = query.appraisalAt as number;
  // The route is named rather than left to the declaration's order, so a question answered by two routes
  // cannot have its body read from whichever one happens to be listed first.
  const observed = await observe({ ...query, route: declaration.certificateRoute }, declaration, options);
  if ('refusal' in observed) {
    return observed.state === 'missing-context' ? missingChain(observed.refusal) : unavailableChain(observed.refusal);
  }
  const chain = await chainHalf(query, declaration, observed.observed.chain, options);
  if ('refusal' in chain) {
    return unavailableChain(chain.refusal);
  }
  const read = readVcekChain(observed.observed.bytes, chain.bytes, { query, declaration, appraisalAt });
  if ('refusal' in read) {
    return unavailableChain(read.refusal);
  }
  return classifyChain(
    read.read,
    query,
    declaration,
    // The stamp the claim carries is the instant the certificate itself landed. A question asked of two routes
    // is seen twice, and the half the question is about is the one a reader of the claim means.
    observed.observed.observedAt,
    appraisalAt,
    query.retained === null,
  );
}

/**
 * The chain beside the certificate, kept or asked.
 *
 * A retained pair arrives as the two halves the caller kept, and `observe` has already carried them. A fresh
 * one arrives at the other published route, so this asks it and hands back its bytes as they landed: the
 * second answer is under the same host, wait and cap rules as the first because both are stated on the same
 * declaration, and a refusal from it is the refusal for the question rather than a half an answer.
 */
async function chainHalf(
  query: VcekChainQuery,
  declaration: VcekOriginDeclaration,
  kept: Uint8Array | null,
  options: CollateralAppraisalOptions,
): Promise<{ readonly bytes: Uint8Array | null } | { readonly refusal: CollateralRefusal }> {
  if (kept !== null || query.retained !== null) {
    return { bytes: kept };
  }
  const url = requestUrl({ ...query, route: declaration.chainRoute }, declaration);
  if (typeof url !== 'string') {
    return { refusal: url.refusal };
  }
  const asked = await fetchFromOrigin(url, declaration, { transport: options.transport, clock: options.clock ?? wallClock });
  return 'refusal' in asked ? { refusal: asked.refusal } : { bytes: asked.fetched.bytes };
}

/** Everything a chip question has to state before either route is worth asking. */
function askedButNotGivenChain(query: VcekChainQuery, declaration: VcekOriginDeclaration): CollateralRefusal | null {
  if (query.roots.length === 0) {
    return collateralRefusal(declaration.refusals.anchor, 'a verdict needs a root the caller holds, and none was passed', ['roots']);
  }
  if (query.appraisalAt === null) {
    return collateralRefusal('COLLATERAL_INPUT_MISSING', 'no instant was stated for the appraisal, and no verdict can be reached about a moment nobody named', ['appraisalAt']);
  }
  if (query.retained !== null && query.retained.bytes.byteLength === 0) {
    return collateralRefusal('COLLATERAL_INPUT_MISSING', 'the retained blob is empty', ['retained.bytes']);
  }
  return null;
}

/**
 * Which of the chip answers this is.
 *
 * `issued` is the state for a pair this run fetched and believed at the moment asked: the certificates state
 * that AMD signed this key for this chip, and nothing else. It is not a pass for the chip, not a statement
 * about revocation, and not a level, so no vendor status word is read beside it and no window refusal travels
 * with it. Bytes this run did not fetch are `stale` under the observation refusal the other two paths already
 * give, and they reach it only after `readVcekChain` has believed the chain at the moment asked: a chain nobody
 * believes states nothing, not even that it stands, so a kept pair with a member outside its own validity is
 * the unverified refusal rather than this one, and the moment that verifier weighs at is the appraisal instant
 * rather than the instant the bytes landed. Both states carry the same `historical-knowledge` reach, because
 * `routesAnswerNow` answers false for this declaration and neither route states that it speaks for the moment
 * it is asked, so a fetch buys no reach a kept pair does not already carry. What the two states differ in is
 * the claim's `observedAt`, which stays null for bytes this run did not fetch, and the refusal that travels
 * beside the answer.
 */
function classifyChain(
  read: VcekChain,
  query: VcekChainQuery,
  declaration: VcekOriginDeclaration,
  observedAt: number,
  appraisalAt: number,
  askedThisRun: boolean,
): VcekChainOutcome {
  const key = collateralCacheKey(query, declaration);
  if (typeof key !== 'string') {
    return missingChain(collateralRefusal(
      'COLLATERAL_INPUT_MISSING',
      'the record these bytes belong to cannot be named',
      key.missing,
    ));
  }
  const claim: CollateralClaim = {
    reach: askedThisRun && routesAnswerNow(declaration) ? 'current-knowledge' : 'historical-knowledge',
    appraisalAt,
    observedAt: askedThisRun ? observedAt : null,
    retainUntil: read.window.until,
    cacheKey: key,
  };
  if (askedThisRun) {
    return { state: 'issued', chain: read, claim };
  }
  return {
    state: 'stale',
    chain: read,
    claim,
    refusal: collateralRefusal(
      'COLLATERAL_NOT_OBSERVED',
      `the bytes were seen at ${new Date(observedAt * 1000).toISOString()} and this run asked the origin nothing`,
      ['retained'],
    ),
  };
}

/** The bytes one appraisal weighs, and the instant this run watched them land. */
interface Observation {
  readonly bytes: Uint8Array;
  readonly chain: Uint8Array | null;
  readonly observedAt: number;
}

/**
 * The bytes a query names, asked of the origin or taken from the caller's store.
 *
 * Both appraisal paths share this half so a retained pair is checked against its stated chain digest, an empty
 * retained blob is refused, and a fetch keeps the host, wait, cap and header rules in one place. Which state
 * an absence produces travels beside the refusal because a missing input is the caller's question and an
 * unreachable or unreadable answer is the origin's.
 */
async function observe(
  query: CollateralQuery,
  declaration: OriginDeclaration,
  options: CollateralAppraisalOptions,
): Promise<{ readonly observed: Observation } | { readonly refusal: CollateralRefusal; readonly state: 'unavailable' | 'missing-context' }> {
  const bytes = query.retained === null ? null : query.retained.bytes;
  if (bytes !== null && bytes.byteLength > declaration.maxResponseBytes) {
    return {
      refusal: collateralRefusal(
        declaration.refusals.envelope,
        `a retained blob of ${String(bytes.byteLength)} bytes is over the ${String(declaration.maxResponseBytes)} this path reads`,
      ),
      state: 'unavailable',
    };
  }
  const url = requestUrl(query, declaration);
  if (typeof url !== 'string') {
    return { refusal: url.refusal, state: 'missing-context' };
  }
  if (query.retained === null) {
    const asked = await fetchFromOrigin(url, declaration, { transport: options.transport, clock: options.clock ?? wallClock });
    return 'refusal' in asked
      ? { refusal: asked.refusal, state: 'unavailable' }
      : { observed: asked.fetched };
  }
  if (query.retained.observedAt === null) {
    return {
      refusal: collateralRefusal('COLLATERAL_INPUT_MISSING', 'the retained bytes carry no stamp for when they were seen', ['retained.observedAt']),
      state: 'missing-context',
    };
  }
  // A caller that states a digest for the chain beside its bytes is asking what was seen, so the pair is checked
  // against that promise before anything of the body is believed: a header swapped under the question would
  // otherwise answer a different one and report the digest the caller named.
  if (query.retained.chain !== null && query.retained.chainSha256 !== null) {
    const actual = sha256Hex(query.retained.chain);
    const stated = toHex(query.retained.chainSha256);
    if (actual !== stated) {
      return {
        refusal: collateralRefusal(
          'COLLATERAL_RETAINED_CHAIN_MISMATCH',
          `the retained chain hashes to ${actual} and the caller named ${stated}`,
          ['retained.chain', 'retained.chainSha256'],
        ),
        state: 'unavailable',
      };
    }
  }
  // A header is not a member of a body, so what arrives beside retained bytes is whatever the caller kept. A
  // chain kept with them is carried, and its absence is carried rather than invented: nothing here reads a
  // header off the wire to complete a pair that was kept as one half.
  return {
    observed: {
      bytes: query.retained.bytes,
      chain: query.retained.chain ?? null,
      observedAt: query.retained.observedAt,
    },
  };
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
  declaration: IntelOriginDeclaration,
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

/**
 * Which of the revocation answers this is.
 *
 * A named serial is `revoked` even when the list stands outside the moment asked about, because the bytes
 * still carry a signature over the statement that the serial was listed; the claim beside the answer states
 * how far that reach goes, and a refusal whose moment precedes the listing says so rather than leaving the
 * reader to compare two instants. One reason code is not a revocation: `removeFromCRL` removes a listing, so
 * an entry that carries it answers `COLLATERAL_STATUS_UNSUPPORTED` instead of reading as revoked. A list
 * that does not name the serial is `not-listed` only when this run watched it arrive inside its own window;
 * otherwise the honest answer is `stale`, with the window refusal for a list that stood outside the moment
 * asked about and the observation refusal for bytes this run did not fetch. `not-listed` is deliberately not
 * a passing state: the issuer's silence about one serial is narrower than a statement that the certificate is
 * trusted.
 */
function classifyRevocation(
  list: RevocationList,
  query: PckCrlQuery,
  declaration: CrlOriginDeclaration,
  observedAt: number,
  appraisalAt: number,
  askedThisRun: boolean,
): RevocationOutcome {
  const covers = appraisalAt >= list.window.from && appraisalAt < list.window.until;
  const key = collateralCacheKey(query, declaration);
  if (typeof key !== 'string') {
    return missingRevocation(collateralRefusal(
      'COLLATERAL_INPUT_MISSING',
      'the record these bytes belong to cannot be named',
      key.missing,
    ));
  }
  const claim: CollateralClaim = {
    reach: askedThisRun && covers ? 'current-knowledge' : 'historical-knowledge',
    appraisalAt,
    observedAt: askedThisRun ? observedAt : null,
    retainUntil: list.window.until,
    cacheKey: key,
  };
  const named = list.revoked.find((entry) => entry.serialHex === normalizedSerial(query.certificateSerial));
  if (named !== undefined) {
    if (named.reasonCode === REMOVE_FROM_CRL) {
      return unavailableRevocation(collateralRefusal(
        declaration.refusals.statusUnknown,
        `the list names serial ${named.serialHex} with removeFromCRL, which removes a listing rather than revoking the certificate, and no revocation is read from it`,
      ));
    }
    const reason = named.reason ?? (named.reasonCode === null ? 'no reason stated' : `reason code ${String(named.reasonCode)}`);
    const precedes = appraisalAt < list.window.from
      ? `; asked ${iso(appraisalAt)} precedes the list's thisUpdate`
      : appraisalAt < named.revokedAt
        ? `; asked ${iso(appraisalAt)} precedes its revocation date`
        : null;
    return {
      state: 'revoked',
      list,
      claim,
      refusal: collateralRefusal(
        'COLLATERAL_REVOKED_BY_VENDOR',
        precedes === null
          ? `serial ${named.serialHex} with ${reason} at ${iso(named.revokedAt)}; the list stands ${iso(list.window.from)} to ${iso(list.window.until)}`
          : `serial ${named.serialHex} with ${reason} at ${iso(named.revokedAt)}${precedes}`,
      ),
    };
  }
  if (claim.reach === 'current-knowledge') {
    return { state: 'not-listed', list, claim };
  }
  return {
    state: 'stale',
    list,
    claim,
    refusal: askedThisRun
      ? collateralRefusal(
        declaration.refusals.window,
        `the list stands from ${new Date(list.window.from * 1000).toISOString()} to ${new Date(list.window.until * 1000).toISOString()} and the moment asked is ${new Date(appraisalAt * 1000).toISOString()}`,
      )
      : collateralRefusal(
        'COLLATERAL_NOT_OBSERVED',
        `the bytes were seen at ${new Date(observedAt * 1000).toISOString()} and this run asked the origin nothing`,
        ['retained'],
      ),
  };
}

/** A serial as the number it names, with no leading zero the query's spelling or the DER's padding added. */
function normalizedSerial(value: string): string {
  return BigInt(`0x${value}`).toString(16);
}

/** A Unix instant as the text a refusal prints. */
function iso(seconds: number): string {
  return new Date(seconds * 1000).toISOString();
}

/** Everything a query has to state before the origin is worth asking. */
function askedButNotGiven(query: CollateralQuery, declaration: IntelOriginDeclaration): CollateralRefusal | null {
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

/** Every field a CRL query has to state before the list is worth asking for. */
function askedButNotGivenCrl(query: PckCrlQuery, declaration: CrlOriginDeclaration): CollateralRefusal | null {
  if (query.roots.length === 0) {
    return collateralRefusal(declaration.refusals.anchor, 'a verdict needs a root the caller holds, and none was passed', ['roots']);
  }
  if (query.appraisalAt === null) {
    return collateralRefusal('COLLATERAL_INPUT_MISSING', 'no instant was stated for the appraisal, and no verdict can be reached about a moment nobody named', ['appraisalAt']);
  }
  const serial = query.certificateSerial;
  if (typeof serial !== 'string' || serial.length === 0) {
    return collateralRefusal(
      'COLLATERAL_INPUT_MISSING',
      `${declaration.name} answers about one certificate serial and none was given`,
      ['certificateSerial'],
    );
  }
  if (!SERIAL.test(serial)) {
    return collateralRefusal(
      'COLLATERAL_INPUT_MISSING',
      `certificateSerial ${quoteOrDigest(serial)} is not one to 128 hex characters`,
      ['certificateSerial'],
    );
  }
  if (query.retained !== null && query.retained.bytes.byteLength === 0) {
    return collateralRefusal('COLLATERAL_INPUT_MISSING', 'the retained blob is empty', ['retained.bytes']);
  }
  return null;
}

/** A certificate serial as a query spells it: hex digits and nothing else. */
const SERIAL = /^[0-9a-fA-F]{1,128}$/u;

/** RFC 5280's reason that takes an entry out of a listing rather than revoking the certificate. */
const REMOVE_FROM_CRL = 8;

function missingContext(refusal: CollateralRefusal): CollateralOutcome {
  return { state: 'missing-context', collateral: null, claim: null, refusal };
}

function unavailable(refusal: CollateralRefusal): CollateralOutcome {
  return { state: 'unavailable', collateral: null, claim: null, refusal };
}

function missingRevocation(refusal: CollateralRefusal): RevocationOutcome {
  return { state: 'missing-context', list: null, claim: null, refusal };
}

function unavailableRevocation(refusal: CollateralRefusal): RevocationOutcome {
  return { state: 'unavailable', list: null, claim: null, refusal };
}

function missingChain(refusal: CollateralRefusal): VcekChainOutcome {
  return { state: 'missing-context', chain: null, claim: null, refusal };
}

function unavailableChain(refusal: CollateralRefusal): VcekChainOutcome {
  return { state: 'unavailable', chain: null, claim: null, refusal };
}
