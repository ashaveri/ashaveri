import { sha256Hex, utf8 } from './bytes.js';

/**
 * The refusals of this package, and the layer that names them.
 *
 * `docs/error-codes.md` carries every code below as its `CollateralErrorCode` union. The rows rest on the
 * difference between this vocabulary and `AttestationErrorCode`: that answers what a document says about the
 * evidence it carries, while each refusal here answers whether the vendor's own statement about a platform can
 * be read at the moment being appraised. Prefixing the codes keeps a log line naming its layer, which is the
 * rule that document states for a bare code string.
 */
export type CollateralErrorCode =
  | 'COLLATERAL_INPUT_MISSING'
  | 'COLLATERAL_ANCHOR_NOT_PINNED'
  | 'COLLATERAL_ORIGIN_UNSUPPORTED'
  | 'COLLATERAL_ORIGIN_UNREACHABLE'
  | 'COLLATERAL_ORIGIN_REFUSED'
  | 'COLLATERAL_BLOB_UNREADABLE'
  | 'COLLATERAL_SIGNATURE_UNVERIFIED'
  | 'COLLATERAL_IDENTITY_MISMATCH'
  | 'COLLATERAL_TCB_LEVEL_UNLISTED'
  | 'COLLATERAL_STATUS_UNSUPPORTED'
  | 'COLLATERAL_WINDOW_CLOSED'
  | 'COLLATERAL_NOT_OBSERVED'
  | 'COLLATERAL_REVOKED_BY_VENDOR';

/** Whether the same inputs can ever answer differently, which is the verdict column's rule. */
export type CollateralVerdict = 'terminal' | 'retryable';

/** An input of a query, spelled the way the query spells it, so a refusal points at a field. */
export type CollateralInputName =
  | 'origin'
  | 'platform'
  | 'cpuType'
  | 'level'
  | 'appraisalAt'
  | 'roots'
  | 'retained'
  | 'retained.bytes'
  | 'retained.observedAt';

/** The refusal a caller reads, whether it arrives as a returned state or as a thrown error. */
export interface CollateralRefusal {
  readonly code: CollateralErrorCode;
  /** Which named inputs were absent; empty when nothing was absent and the answer failed on its own. */
  readonly missing: readonly CollateralInputName[];
  /** The fixed sentence for the code beside whatever the raise site was looking at, on one line. */
  readonly detail: string;
  readonly verdict: CollateralVerdict;
}

interface RefusalEntry {
  readonly message: string;
  readonly verdict: CollateralVerdict;
}

const REFUSAL: Record<CollateralErrorCode, RefusalEntry> = {
  COLLATERAL_INPUT_MISSING: {
    message: 'an input this appraisal needs was not supplied',
    verdict: 'terminal',
  },
  COLLATERAL_ANCHOR_NOT_PINNED: {
    message: 'no vendor root was pinned, so nothing signed can be read as signed',
    verdict: 'terminal',
  },
  COLLATERAL_ORIGIN_UNSUPPORTED: {
    message: 'the requested collateral origin is not one this package reads',
    verdict: 'terminal',
  },
  COLLATERAL_ORIGIN_UNREACHABLE: {
    message: 'the collateral origin was asked and did not answer',
    verdict: 'retryable',
  },
  COLLATERAL_ORIGIN_REFUSED: {
    message: 'the collateral origin answered with a refusal rather than a document',
    verdict: 'retryable',
  },
  COLLATERAL_BLOB_UNREADABLE: {
    message: 'the collateral document is not the signed shape this origin declares',
    verdict: 'terminal',
  },
  COLLATERAL_SIGNATURE_UNVERIFIED: {
    message: 'the collateral signature does not hold under any pinned root',
    verdict: 'terminal',
  },
  COLLATERAL_IDENTITY_MISMATCH: {
    message: 'the collateral document names an identity other than the one asked for',
    verdict: 'terminal',
  },
  COLLATERAL_TCB_LEVEL_UNLISTED: {
    message: 'the collateral document lists no level for the one the platform reported',
    verdict: 'terminal',
  },
  COLLATERAL_STATUS_UNSUPPORTED: {
    message: 'the collateral document states a status this package has no rule for',
    verdict: 'terminal',
  },
  COLLATERAL_WINDOW_CLOSED: {
    message: 'the collateral document speaks only for a window that has closed',
    verdict: 'terminal',
  },
  COLLATERAL_NOT_OBSERVED: {
    message: 'the collateral was retained from an earlier run and this run did not ask the origin',
    verdict: 'terminal',
  },
  COLLATERAL_REVOKED_BY_VENDOR: {
    message: 'the signed collateral states that this platform level is not trusted',
    verdict: 'terminal',
  },
};

/** Every declared code beside the sentence and the verdict that go with it. */
export function collateralRefusals(): ReadonlyArray<RefusalEntry & { readonly code: CollateralErrorCode }> {
  return (Object.keys(REFUSAL) as CollateralErrorCode[]).map((code) => ({ code, ...REFUSAL[code] }));
}

/**
 * What a refusal quotes. A token that came off the network is printed only when it is short and made
 * of characters that cannot end a log line or reorder one; anything else is printed as its digest.
 * A vendor status string and a certificate name both arrive from outside, and a refusal that copied
 * them would be two lines to anything that reads a log by lines.
 */
const QUOTABLE = /^[A-Za-z0-9:_.+-]{1,64}$/u;

export function quotable(value: string): boolean {
  return QUOTABLE.test(value);
}

/** An outside token printed as itself when it can be, and as its digest when it cannot. */
export function quoteOrDigest(value: string): string {
  return quotable(value) ? value : `${String(value.length)} characters, sha256 ${sha256Hex(utf8(value)).slice(0, 16)}`;
}

const MAX_DETAIL = 256;

function bounded(detail: string): string {
  return detail.length > MAX_DETAIL ? `${detail.slice(0, MAX_DETAIL)}...` : detail;
}

export function collateralRefusal(
  code: CollateralErrorCode,
  detail: string,
  missing: readonly CollateralInputName[] = [],
): CollateralRefusal {
  const entry = REFUSAL[code];
  return { code, missing, detail: bounded(`${entry.message}: ${detail}`), verdict: entry.verdict };
}

/**
 * Raised when the caller's policy requires the collateral and the answer is absent, which is the only
 * way a refusal here leaves the return path. A stale document and a revoked one come back as states,
 * because being unable to answer now is what those answers say rather than a reason to throw.
 */
export class CollateralError extends Error {
  readonly refusal: CollateralRefusal;

  constructor(refusal: CollateralRefusal) {
    super(refusal.detail);
    this.name = 'CollateralError';
    this.refusal = refusal;
  }

  get code(): CollateralErrorCode {
    return this.refusal.code;
  }
}
