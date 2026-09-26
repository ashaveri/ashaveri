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
  /** What the signature has to look like: three dot-separated base64url parts, ES256 over the first two. */
  readonly signature: {
    readonly envelope: 'jws-compact';
    readonly algorithm: 'ES256';
    readonly mediaType: string;
    readonly certificateMember: 'x5c';
  };
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

/** The rule a kept blob is held under, which is the same for both documents of this path. */
const CACHE_RULE = {
  answersCurrentQuestions: false,
  retainUntil: 'vendor-next-update',
} as const;

/**
 * Intel's own words about a platform level. `OK` is the only one that says nothing is owed, and the
 * out-of-date spellings are the ones that say the vendor no longer stands behind the level. The
 * `OutOfDate:ConfigurationNeeded` colon form is kept beside its underscore twin because the two
 * documents of this path have spelled the same statement both ways, and reading one as the other would
 * turn a revoked platform into an unclassified one.
 */
const STATUS_VOCABULARY = {
  trusted: ['OK'],
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
 * Intel's TCB Info for one CPU type: the levels the vendor has published, each with the status it
 * signed beside it and the window the whole statement stands for.
 */
export const INTEL_TCB_INFO: OriginDeclaration = {
  ...INTEL_PATH,
  name: 'intel-tcb-info',
  documentPath: 'tcb',
  cpuTypeMember: 'fmspc',
  window: { documentMember: 'tcbInfo', signedMember: 'issueDate', nextUpdateMember: 'nextUpdate' },
  identity: {
    cpuTypeMember: 'fmspcid',
    levelsMember: 'tcb',
    levelDateMember: 'tcbDate',
    levelCompositionMember: 'tcb',
    statusMember: 'tcbStatus',
  },
  cache: { keyMembers: ['origin', 'platform', 'cpuType', 'level'], ...CACHE_RULE },
};

/**
 * Intel's QE Identity: the vendor's statement about the quoting enclave, which carries one status for
 * the whole document rather than a ladder of levels.
 */
export const INTEL_QE_IDENTITY: OriginDeclaration = {
  ...INTEL_PATH,
  name: 'intel-qe-identity',
  documentPath: 'qe/identity',
  cpuTypeMember: null,
  window: { documentMember: null, signedMember: 'issueDate', nextUpdateMember: 'nextUpdate' },
  identity: {
    cpuTypeMember: null,
    levelsMember: null,
    levelDateMember: null,
    levelCompositionMember: null,
    statusMember: 'tcbStatus',
  },
  cache: { keyMembers: ['origin', 'platform'], ...CACHE_RULE },
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
