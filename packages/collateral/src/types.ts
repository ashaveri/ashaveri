import type { CollateralRefusal } from './errors.js';

/** The two Intel platforms the served origin publishes collateral for. */
export type IntelPlatform = 'sgx' | 'tdx';

/**
 * Every path an appraisal could ask collateral of. Two are served here, and the other four are named
 * so that asking for one answers with the sentence "this origin is not read here" rather than with a
 * type error a caller could only reach by deleting the question.
 */
export type CollateralOriginName =
  | 'intel-tcb-info'
  | 'intel-qe-identity'
  | 'intel-pck-crl'
  | 'amd-kds'
  | 'nvidia-rim'
  | 'ocsp';

/**
 * Which level of the vendor's signed ladder the caller's platform sits at.
 *
 * The vendor publishes a list of levels and the platform's own evidence names which one it reports;
 * matching those is the vendor's rule and not this package's guess, so the caller names the level and
 * this package reads the status the vendor signed beside exactly that one. A query that cannot name
 * its level answers as missing context, because an unanchored level is how an archived document gets
 * read as an answer about a platform nobody checked.
 */
export type IntelTcbLevel =
  | { readonly by: 'tcb-date'; readonly value: string }
  | { readonly by: 'tcb-composition'; readonly value: string };

/** Collateral the caller kept from an earlier run, with the stamp that says when. */
export interface RetainedCollateral {
  /** The signed document exactly as it was served, which is what gets read again and not a re-encoding. */
  readonly bytes: Uint8Array;
  /**
   * Unix seconds, from the caller's own record of the run that asked the origin. It is the only thing
   * that separates a retained answer from a fresh one, so a caller that cannot state it passes `null`
   * and gets a refusal rather than a guess.
   */
  readonly observedAt: number | null;
}

/** What an appraisal asks for, and with what it was supplied. */
export interface CollateralQuery {
  readonly origin: CollateralOriginName;
  readonly platform: IntelPlatform;
  /** The CPU type the origin indexes collateral by: Intel's FMSPC id as hex text. Required for TCB Info. */
  readonly cpuType: string | null;
  readonly level: IntelTcbLevel | null;
  /**
   * The instant the answer is for, in Unix seconds. `null` is an answer rather than a default: a
   * caller that does not know what moment it is appraising cannot be handed a verdict about one.
   */
  readonly appraisalAt: number | null;
  /**
   * Roots the caller holds and will stand behind. Nothing here substitutes the roots
   * `@ashaveri/attest-core` bundles: a library default is not this caller's pin, and an appraisal that
   * quietly inherited one would report a verdict reached on a decision the caller never made.
   */
  readonly roots: readonly Uint8Array[];
  /** Collateral from the caller's own store, or `null` to ask the origin now. */
  readonly retained: RetainedCollateral | null;
  /** What an absent answer does: reported as unassessed, or refused because this appraisal requires it. */
  readonly onAbsent: 'unassessed' | 'refuse';
}

/** The identity a signed document names for itself, read off the bytes rather than assumed. */
export interface DeclaredIdentity {
  /** The CPU type the document claims to cover, verbatim, or null when it names none. */
  readonly cpuType: string | null;
  /** The level selector as the document spells it, or null when the document states no level ladder. */
  readonly level: string | null;
  /** The vendor's own status text beside what was asked, or null when the document states none. */
  readonly vendorStatus: string | null;
}

/** What this package made of the identity's own statement. */
export type StatusReading = 'trusted' | 'revoked' | 'unclassified' | 'not-stated';

/** The window the vendor signed, in Unix seconds, which is how far the answer reaches. */
export interface SignedWindow {
  readonly from: number;
  readonly until: number;
}

export interface CollateralClassification {
  readonly readAs: StatusReading;
  readonly window: SignedWindow;
  /** `issueDate` from inside the signature: the instant the vendor said these bytes stand. */
  readonly signedAt: number;
}

/** A signed blob set this package established under a root the caller named. */
export interface SignedCollateral {
  readonly origin: CollateralOriginName;
  readonly platform: IntelPlatform;
  /** The signed document first, then every certificate the answer presented with it, as served. */
  readonly blobs: readonly Uint8Array[];
  /** sha256 of `blobs[0]` as hex: what a caller retains and reads back. */
  readonly digest: string;
  /** The pinned certificate this chain reached, by sha256 of its DER, so a verdict names its anchor. */
  readonly anchorDigest: string;
  readonly declared: DeclaredIdentity;
  readonly classification: CollateralClassification;
}

/**
 * How far the answer reaches in time, which is the distinction an archive can blur.
 *
 * `current-knowledge` is only ever reported when this run asked the origin and the vendor's own window
 * covers the moment being appraised. `historical-knowledge` says the bytes were read and signed, and
 * that they stand for the instant they were signed and for no later one. Nothing here answers a
 * question about revocation today out of a document nobody asked today.
 */
export interface CollateralClaim {
  readonly reach: 'current-knowledge' | 'historical-knowledge';
  readonly appraisalAt: number;
  /** When this run saw the origin, or null when it worked only from retained bytes. */
  readonly observedAt: number | null;
  /**
   * Unix seconds until which the caller may keep these bytes as a record, which is the vendor's own
   * `nextUpdate` and nothing this package invented. Keeping them past it costs nothing and proves
   * nothing, and a reader of the retained copy sees that stated in the claim beside them.
   */
  readonly retainUntil: number;
}

/**
 * The five answers, and the one thing all of them refuse to be: a pass.
 *
 * `current` is the only state that carries no refusal, and it is reached by asking the origin in this
 * run under a root the caller pinned. `stale` and `revoked` both carry the verified bytes, because the
 * difference between them is what the vendor signed rather than whether it was readable. `unavailable`
 * and `missing-context` carry nothing, because there is nothing yet to have read.
 */
export type CollateralOutcome =
  | { readonly state: 'current'; readonly collateral: SignedCollateral; readonly claim: CollateralClaim }
  | {
      readonly state: 'stale';
      readonly collateral: SignedCollateral;
      readonly claim: CollateralClaim;
      readonly refusal: CollateralRefusal;
    }
  | {
      readonly state: 'revoked';
      readonly collateral: SignedCollateral;
      readonly claim: CollateralClaim;
      readonly refusal: CollateralRefusal;
    }
  | { readonly state: 'unavailable'; readonly collateral: null; readonly claim: null; readonly refusal: CollateralRefusal }
  | { readonly state: 'missing-context'; readonly collateral: null; readonly claim: null; readonly refusal: CollateralRefusal };

/** The transport a fetch runs on, injectable so the refusals can be tested without a network. */
export type CollateralTransport = typeof fetch;

/** Where an appraisal ran: the origin answer, or the caller's own archive. */
export interface CollateralAppraisalOptions {
  readonly transport?: CollateralTransport;
  /**
   * Wall clock in seconds since the epoch, consulted only when a query states no appraisal instant of
   * its own, which is the one place this package reads a clock and says which clock it used.
   */
  readonly now?: () => number;
}
