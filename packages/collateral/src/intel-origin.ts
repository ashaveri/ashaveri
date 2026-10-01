import { collateralRefusal, quoteOrDigest, type CollateralErrorCode, type CollateralInputName, type CollateralRefusal } from './errors.js';
import type { CollateralOriginName, CollateralQuery, IntelPlatform } from './types.js';

/** The two documents this package reads. Every other name of `CollateralOriginName` is refused. */
export type ServedCollateralOrigin = 'intel-tcb-info' | 'intel-qe-identity';

/** Which field of a query the cache key is built from. */
export type CollateralCacheMember = 'origin' | 'platform' | 'cpuType' | 'level';

/**
 * Everything one retrieval path decides, written down once: where it is asked, what shape the answer
 * has to be, how long the wait is, what may be kept, and which refusal each failure answers with.
 * `test/origin-declaration.test.ts` reads this against the code that acts on it, because a
 * declaration nobody checks is a comment with a type.
 */
export interface OriginDeclaration {
  readonly name: ServedCollateralOrigin;
  /** The one host asked. An answer that redirects away from it is refused rather than followed. */
  readonly host: string;
  readonly platformPath: (platform: IntelPlatform) => string;
  readonly documentPath: string;
  /** The query member carrying the CPU type, or null when the document is not indexed by one. */
  readonly cpuTypeMember: string | null;
  /** What the signature has to look like for this path to decode it, which is not what the vendor serves.
   *
   * The served answer is a JSON body carrying a hex `signature` member, with its issuer chain in a
   * response header named after the document. This envelope is what `readSignedCollateral` walks, and the
   * gap between the two is stated at each declaration below and pinned by a case in `test/read.test.ts`.
   */
  readonly signature: {
    readonly envelope: 'jws-compact';
    readonly algorithm: 'ES256';
    readonly mediaType: string;
    readonly certificateMember: 'x5c';
  };
  /**
   * The response header that carries this document's issuer chain, or null where no served answer recorded here
   * names one. A signature is only as good as the path from it to a name a reader pinned, and that path arrives
   * beside the body rather than inside it, so the bytes are kept as the vendor sent them and nothing here
   * decodes, reorders or drops one.
   *
   * The spelling belongs to one document at one version, so it is read off that document's own cited answer,
   * quoted in the note above each declaration below: a name remembered from a neighbouring document, or from
   * the same document at another version, asks for a header no answer carries.
   */
  readonly chainHeader: string | null;
  /** Where the signed window is written, and inside which member of the payload it is written. */
  readonly window: {
    readonly documentMember: string | null;
    readonly signedMember: string;
    readonly nextUpdateMember: string;
  };
  /** How the document names the identity it covers, and where its per-level statements live. */
  readonly identity: {
    readonly cpuTypeMember: string | null;
    readonly levelsMember: string | null;
    readonly levelDateMember: string | null;
    readonly levelCompositionMember: string | null;
    /**
     * How the member named by `levelCompositionMember` states a level's composition: as hex text this
     * path could compare with a caller's, or as the component numbers the vendor lists inside an object.
     *
     * A composition stated as component numbers is read for nothing here. No served document spells a
     * composition as hex text, and which numbers a caller's hex would stand for, in what order, and
     * whether the PCE SVN is one of them, is a rule the vendor states nowhere in a body. Inventing one to
     * make an arm of a query answerable would be this package deciding what a platform reports rather
     * than reading what the vendor signed, so such a question is refused and the refusal says what the
     * document actually states.
     */
    readonly levelCompositionStatedAs: 'hex-text' | 'component-numbers';
    readonly statusMember: string;
  };
  readonly timeoutMs: number;
  readonly maxResponseBytes: number;
  readonly cache: {
    /** The fields that decide which question a kept blob is an answer to. */
    readonly keyMembers: readonly CollateralCacheMember[];
    /** A kept blob records one earlier observation, so it cannot answer what is true now. */
    readonly answersCurrentQuestions: false;
    /** How long a caller may keep the bytes: the vendor's own next update, copied and never extended. */
    readonly retainUntil: 'vendor-next-update';
  };
  /**
   * Which of the vendor's own status words this package reads as what.
   *
   * A word outside both lists is refused with the document's text quoted rather than sorted into the
   * nearer list: a status naming a mitigation is a claim about something other than "trusted" or
   * "revoked", and deciding what an appraisal should make of it is a decision, not a reading.
   */
  readonly status: {
    readonly trusted: readonly string[];
    readonly revoked: readonly string[];
  };
  readonly refusals: {
    readonly transport: CollateralErrorCode;
    readonly status: CollateralErrorCode;
    readonly oversize: CollateralErrorCode;
    readonly envelope: CollateralErrorCode;
    readonly window: CollateralErrorCode;
    readonly identity: CollateralErrorCode;
    readonly levels: CollateralErrorCode;
    readonly statusUnknown: CollateralErrorCode;
    readonly signature: CollateralErrorCode;
    readonly anchor: CollateralErrorCode;
  };
}

const REFUSALS = {
  transport: 'COLLATERAL_ORIGIN_UNREACHABLE',
  status: 'COLLATERAL_ORIGIN_REFUSED',
  oversize: 'COLLATERAL_BLOB_UNREADABLE',
  envelope: 'COLLATERAL_BLOB_UNREADABLE',
  window: 'COLLATERAL_WINDOW_CLOSED',
  identity: 'COLLATERAL_IDENTITY_MISMATCH',
  levels: 'COLLATERAL_TCB_LEVEL_UNLISTED',
  statusUnknown: 'COLLATERAL_STATUS_UNSUPPORTED',
  signature: 'COLLATERAL_SIGNATURE_UNVERIFIED',
  anchor: 'COLLATERAL_ANCHOR_NOT_PINNED',
} as const satisfies OriginDeclaration['refusals'];

/**
 * The rule a kept blob is held under, which is the same for both documents of this path.
 *
 * A level is read out of a list the document states per level, so a kept blob answers about one rung of
 * that ladder and its key has to name the rung, for both documents.
 */
const CACHE_RULE = {
  answersCurrentQuestions: false,
  retainUntil: 'vendor-next-update',
} as const;

/**
 * Intel's own words about a platform level, taken from the levels the vendor has published.
 *
 * `UpToDate` and `OutOfDate` are the only two words met on a level of any body named in the citations
 * below, on either platform, at either version, on either document: the first is the vendor standing
 * behind a level and the second is the vendor no longer standing behind it. `OK`, the word this list used
 * to hold as the only trusted one, was met nowhere, so the trusted side of this vocabulary is the one
 * word the vendor writes and nothing this repository remembered.
 *
 * The two compound spellings stay on the revoked side. They were not met in any body named below; a word
 * that says the vendor no longer stands behind a level belongs on that side on any spelling of it, while
 * dropping one would answer a revocation with the refusal for a word this package has no rule for.
 *
 * A word outside both lists is refused with the document's text quoted rather than sorted into the nearer
 * list: a status naming a mitigation is a claim about something other than "trusted" or "revoked", and
 * deciding what an appraisal should make of a word this package has not read from the vendor is a
 * decision, not a reading.
 */
const STATUS_VOCABULARY = {
  trusted: ['UpToDate'],
  revoked: ['OutOfDate', 'OutOfDateConfigurationNeeded', 'OutOfDate:ConfigurationNeeded', 'Revoked'],
} as const;

const INTEL_PATH = {
  host: 'api.trustedservices.intel.com',
  platformPath: (platform: IntelPlatform) => `/${platform}/certification/v4`,
  timeoutMs: 5000,
  maxResponseBytes: 65536,
  signature: {
    envelope: 'jws-compact',
    algorithm: 'ES256',
    mediaType: 'application/jose',
    certificateMember: 'x5c',
  },
  refusals: REFUSALS,
  status: STATUS_VOCABULARY,
} as const;

/**
 * Intel's TCB Info for one CPU type: the levels the vendor has published, each with the status it signed
 * beside it and the window the whole statement stands for.
 *
 * Every member name and status word below is settled against the vendor's own served answer. Fetched from
 * `https://api.trustedservices.intel.com/sgx/certification/v4/tcb?fmspc=00806F050000` and
 * `https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=00806F050000`, each of which
 * answered 200 with `content-type: application/json`, and from the same path at `v3`, which answered the
 * same document one version back. That FMSPC is not guessed: it is the six bytes of the SGX TCB extension
 * (OID `1.2.840.113741.1.13.1`) of the Intel-signed PCK leaf certificate in
 * `packages/attest-core/test/fixtures/tdx-quote-v4.bin`, so it is a type Intel attested for a machine this
 * repository carries evidence from.
 *
 * The route names the query member it takes. The same path with that member absent, spelled `xyz`, or
 * holding text that is not twelve hex characters answers 400 with an empty body, and one holding
 * a well-formed type the service has no document for answers 404 with an empty body, while an unknown path
 * on that host answers a JSON body naming a status code instead, so those empty answers belong to the `tcb`
 * route. `pceid` is answered 400 on this route in either case, so the one identity this document is
 * indexed by is `fmspc`, and the request member and the member naming the identity the signed body
 * declares are the one name. No member named `fmspcid` was met in any position of any body fetched for
 * these citations.
 *
 * What the served body states, member by member, against what this declaration reads:
 * - the body holds `tcbInfo` and `signature`. `tcbInfo` holds `id`, `version`, `issueDate`, `nextUpdate`,
 *   `fmspc`, `pceId`, `tcbType`, `tcbEvaluationDataNumber` and `tcbLevels`, and the TDX body holds
 *   `tdxModule` and `tdxModuleIdentities` beside them, the entries of the latter carrying their own
 *   `tcbLevels`. Of those, `id`, `version`, `pceId`, `tcbType`, `tcbEvaluationDataNumber`, `tdxModule`,
 *   `tdxModuleIdentities` and `advisoryIDs` are read by nothing here.
 * - `window` reads `tcbInfo` and, inside it, `issueDate` and `nextUpdate`. Both are spelled as UTC
 *   instants with no fraction, which is a shape `read.ts` accepts.
 * - `identity.cpuTypeMember` reads `fmspc`, the member named above.
 * - the levels list is `tcbLevels`, and its entries hold `tcb`, `tcbDate`, `tcbStatus` and, where the
 *   vendor has an advisory to name, `advisoryIDs`. That is `levelsMember`, `levelDateMember` and
 *   `statusMember`.
 * - a level's composition is `tcb`, and the vendor states it as an object of component numbers:
 *   `sgxtcbcomponents`, sixteen entries each holding `svn` and, where the component is one the vendor
 *   classifies, `category` and `type`, together with `pcesvn`, and the TDX body states
 *   `tdxtcbcomponents` beside them. The `v3` body spells the same sixteen numbers flat, as
 *   `sgxtcbcomp01svn` through `sgxtcbcomp16svn` with `pcesvn`. No hex spelling of a composition was met on
 *   any document fetched for these citations, which is what `levelCompositionStatedAs` records and what
 *   makes a `tcb-composition` question unanswerable on this path rather than unanswered.
 * - the status words met on the levels of every body fetched here are `UpToDate` and `OutOfDate`, and the
 *   vocabulary above reads exactly those.
 * - the envelope is not the one this path decodes. The served body is a JSON object carrying a `signature`
 *   member of 128 hex characters, which is 64 bytes and the raw `r` and `s` of an ECDSA P-256 signature,
 *   and the issuer chain arrives beside it in the response's `TCB-Info-Issuer-Chain` header as URL-encoded
 *   PEM. No `x5c`, no three-part envelope and no JWS was met in any body fetched here, so a document of
 *   the served shape is refused before any member of it is read, and a case in `test/read.test.ts` pins
 *   that refusal rather than smoothing it over. Reconciling the two envelopes is not a naming change: the
 *   chain a reader walks has to arrive with the bytes it signs, and material that arrives inside a pack
 *   arrives alone. That is left as an open question here because answering it reaches the container's
 *   format, which this path does not decide.
 */
export const INTEL_TCB_INFO: OriginDeclaration = {
  ...INTEL_PATH,
  name: 'intel-tcb-info',
  documentPath: 'tcb',
  cpuTypeMember: 'fmspc',
  /** The header the citation above records this document's chain arriving in, at the v4 address this path asks. */
  chainHeader: 'TCB-Info-Issuer-Chain',
  window: { documentMember: 'tcbInfo', signedMember: 'issueDate', nextUpdateMember: 'nextUpdate' },
  identity: {
    /** The vendor's own member, the same name the request is built with. See the citation above. */
    cpuTypeMember: 'fmspc',
    levelsMember: 'tcbLevels',
    levelDateMember: 'tcbDate',
    levelCompositionMember: 'tcb',
    levelCompositionStatedAs: 'component-numbers',
    statusMember: 'tcbStatus',
  },
  cache: { keyMembers: ['origin', 'platform', 'cpuType', 'level'], ...CACHE_RULE },
};

/**
 * Intel's QE Identity: the vendor's statement about the quoting enclave.
 *
 * Settled the same way, against `https://api.trustedservices.intel.com/sgx/certification/v4/qe/identity`,
 * which answers 200 with `content-type: application/json`, no query member on the request and no CPU type
 * named anywhere in the answer, which is what confirms both `cpuTypeMember` slots as null.
 *
 * The served body holds `enclaveIdentity` and a hex `signature`, and every member this document names
 * lives inside `enclaveIdentity`: `id`, `version`, `issueDate`, `nextUpdate`, `tcbEvaluationDataNumber`,
 * `miscselect`, `miscselectMask`, `attributes`, `attributesMask`, `mrsigner`, `isvprodid` and `tcbLevels`.
 * The window is therefore read inside `enclaveIdentity`, which is the wrapper `window.documentMember`
 * names, and not at the top of the payload, where the served body states nothing of the kind. The status
 * is not one statement for the whole document either: the vendor writes `tcbStatus` per entry of
 * `tcbLevels`, each entry holding `tcb`, `tcbDate` and `tcbStatus`, and `tcb` is `{isvsvn}` there, a
 * component number rather than the array of them this document's twin states. The two words met across
 * those levels are the `UpToDate` and `OutOfDate` of the vocabulary above. A kept QE Identity blob
 * answers about one rung of that ladder, so its key names the rung.
 *
 * The envelope is the same gap as the TCB Info document's, one step wider: this document's issuer chain
 * arrives in the response's `SGX-Enclave-Identity-Issuer-Chain` header, named for the enclave identity
 * rather than for the TCB Info, so no reader holding only this body walks a chain to a pinned root.
 */
export const INTEL_QE_IDENTITY: OriginDeclaration = {
  ...INTEL_PATH,
  name: 'intel-qe-identity',
  documentPath: 'qe/identity',
  cpuTypeMember: null,
  /** The header the note above records this document's chain arriving in, spelled after the enclave identity. */
  chainHeader: 'SGX-Enclave-Identity-Issuer-Chain',
  window: { documentMember: 'enclaveIdentity', signedMember: 'issueDate', nextUpdateMember: 'nextUpdate' },
  identity: {
    cpuTypeMember: null,
    levelsMember: 'tcbLevels',
    levelDateMember: 'tcbDate',
    levelCompositionMember: 'tcb',
    levelCompositionStatedAs: 'component-numbers',
    statusMember: 'tcbStatus',
  },
  cache: { keyMembers: ['origin', 'platform', 'level'], ...CACHE_RULE },
};

export const SERVED_ORIGINS: readonly ServedCollateralOrigin[] = ['intel-tcb-info', 'intel-qe-identity'];

const BY_ORIGIN: Record<ServedCollateralOrigin, OriginDeclaration> = {
  'intel-tcb-info': INTEL_TCB_INFO,
  'intel-qe-identity': INTEL_QE_IDENTITY,
};

/** The declaration for an origin, or the refusal that says this path is not read here. */
export function declarationFor(origin: CollateralOriginName): OriginDeclaration | { readonly refusal: CollateralRefusal } {
  if (origin === 'intel-tcb-info' || origin === 'intel-qe-identity') {
    return BY_ORIGIN[origin];
  }
  return {
    refusal: collateralRefusal(
      'COLLATERAL_ORIGIN_UNSUPPORTED',
      `${quoteOrDigest(origin)} is not read here, which serves ${SERVED_ORIGINS.join(' and ')}`,
      ['origin'],
    ),
  };
}

/** The CPU type this path is indexed by: Intel's FMSPC, six bytes of hex in either case. */
const CPU_TYPE = /^[0-9a-fA-F]{12}$/u;

/**
 * The address one query asks, or the refusal that stops it being asked.
 *
 * The CPU type is checked here rather than after the answer arrives because a request built from a
 * malformed identity is a round trip to a question no document can answer, and the caller learns more
 * from the refusal that names the field.
 */
export function requestUrl(query: CollateralQuery, declaration: OriginDeclaration): string | { readonly refusal: CollateralRefusal } {
  const base = `https://${declaration.host}${declaration.platformPath(query.platform)}/${declaration.documentPath}`;
  if (declaration.cpuTypeMember === null) {
    return base;
  }
  if (query.cpuType === null) {
    return { refusal: collateralRefusal('COLLATERAL_INPUT_MISSING', `${declaration.name} is indexed by CPU type and none was given`, ['cpuType']) };
  }
  if (!CPU_TYPE.test(query.cpuType)) {
    return {
      refusal: collateralRefusal('COLLATERAL_INPUT_MISSING', `cpuType ${quoteOrDigest(query.cpuType)} is not twelve hex characters`, ['cpuType']),
    };
  }
  return `${base}?${declaration.cpuTypeMember}=${query.cpuType.toLowerCase()}`;
}

/**
 * Where a kept blob belongs, spelled from the declared members in their declared order.
 *
 * The key holds what changes the answer, which the declaration states per document: a TCB Info blob
 * answers about one CPU type at one level, and a QE Identity blob about a platform and nothing
 * narrower. The appraisal instant is deliberately absent, because the same bytes are the same record
 * whichever moment they are read against, and it is the claim kept beside them that says which of
 * those questions they can answer.
 */
export function collateralCacheKey(
  query: CollateralQuery,
  declaration: OriginDeclaration,
): string | { readonly missing: readonly CollateralInputName[] } {
  const parts: string[] = [];
  const missing: CollateralInputName[] = [];
  for (const member of declaration.cache.keyMembers) {
    const spelled = spellKeyMember(query, member);
    if (spelled === null) {
      missing.push(member);
      continue;
    }
    parts.push(`${member}=${spelled}`);
  }
  return missing.length > 0 ? { missing } : parts.join('|');
}

function spellKeyMember(query: CollateralQuery, member: CollateralCacheMember): string | null {
  switch (member) {
    case 'origin':
      return query.origin;
    case 'platform':
      return query.platform;
    case 'cpuType':
      return query.cpuType?.toLowerCase() ?? null;
    case 'level':
      return query.level === null ? null : `${query.level.by}=${query.level.value}`;
  }
}
