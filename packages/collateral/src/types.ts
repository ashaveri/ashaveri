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
 *
 * A rung named by its composition is answered only where the document states that composition as the
 * hex text the value is. Intel's bodies state a level's composition as the component numbers of an
 * object, which no hex text compares with and which this package will not fold into one by guessing
 * which numbers a caller meant; see `levelCompositionStatedAs` in `intel-origin.ts`.
 */
export type IntelTcbLevel =
  | { readonly by: 'tcb-date'; readonly value: string }
  | { readonly by: 'tcb-composition'; readonly value: string };

/** Collateral the caller kept from an earlier run, with the chain that arrived beside it and the stamp that says when. */
export interface RetainedCollateral {
  /**
   * The signed document exactly as it was taken in, which is what gets read again and not a re-encoding.
   *
   * It is read again only if it is of the envelope the origin's declaration names. Intel serves its
   * documents as a JSON body whose issuer chain arrives in a response header, cited at each declaration in
   * `intel-origin.ts`, so a body taken in as that address answers is weighed only when the header's bytes
   * were kept beside it; kept alone, it is a body alone, and the arm that reads a body alone is the one
   * whose certificates sit inside it.
   */
  readonly bytes: Uint8Array;
  /**
   * The issuer chain that arrived beside those bytes, exactly as it arrived, or null where the caller holds no
   * chain. A signature is weighed against the bytes that came beside it, so a chain this path had rewritten is
   * no longer the one the answer sent: the caller hands the header's own bytes, and this package neither decodes
   * them nor splits one certificate from the next.
   *
   * The null is a reading rather than a gap. A body kept from an earlier run without its header is a body alone,
   * and the arm that reads a body alone is the one whose certificates sit inside it.
   */
  readonly chain: Uint8Array | null;
  /**
   * sha256 of the chain the caller means, or null where the caller states none. Where it is stated, a chain that
   * hashes to something else is refused: the caller is asking what was seen, and a header swapped under the
   * question would answer a different one.
   */
  readonly chainSha256: Uint8Array | null;
  /**
   * Unix seconds, from the caller's own record of the run that asked the origin. It is the only thing
   * that separates a retained answer from a fresh one, so a caller that cannot state it passes `null`
   * and gets a refusal rather than a guess.
   */
  readonly observedAt: number | null;
}

/**
 * Material that arrived inside a sealed container rather than from an origin, with the instant the container's
 * own record states it held it.
 */
export interface CarriedCollateral {
  /** The whole of the material, byte for byte as the container carries it, which is what gets read again. */
  readonly bytes: Uint8Array;
  /**
   * The issuer chain the container holds beside those bytes, in the shape it holds it, or null where it holds none.
   *
   * Which arm weighs the material is settled by the declaration and by this member, so a container that states a
   * header gets the pair weighed exactly as a live answer's pair is weighed, and a container stating none hands a
   * body alone to the arm whose certificates sit inside it. The bytes are handed on as the container kept them:
   * this path decodes nothing and re-encodes nothing, because a header rewritten here is no longer the one the
   * answer sent.
   */
  readonly chain: Uint8Array | null;
  /**
   * sha256 of that header where the container states one, or null. Where it is stated, the header handed beside it
   * is checked against it before the pair is weighed, so a record asking what was seen gets an answer about the
   * bytes it named rather than about a header swapped under the question.
   */
  readonly chainSha256: Uint8Array | null;
  /**
   * Unix seconds. A container states no observation instant because nothing inside one watched an origin
   * answer, so the number a caller hands is the instant the record holding this material states it held it: the
   * `iat` of the sealed receipt whose anchor named these bytes. It is an instant and not the `held` figure of a
   * pack's duty block, which counts seconds and names no moment.
   *
   * It is required rather than defaulted: an appraisal that stamped carried material with the instant it was
   * asked would be reporting that an archive had just arrived, and that is the one sentence this path refuses to
   * state about bytes it never watched land.
   */
  readonly heldAt: number;
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
  /**
   * Collateral from the caller's own store, or `null` to ask the origin now. Material that arrived inside a
   * sealed container instead of a store is appraised by `appraiseCarriedCollateral`, which states where the
   * instant beside it comes from rather than leaving a caller to invent one.
   */
  readonly retained: RetainedCollateral | null;
  /** What an absent answer does: reported as unassessed, or refused because this appraisal requires it. */
  readonly onAbsent: 'unassessed' | 'refuse';
}

/** The identity a signed document names for itself, read off the bytes rather than assumed. */
export interface DeclaredIdentity {
  /** The CPU type the document claims to cover, verbatim, or null when it names none. */
  readonly cpuType: string | null;
  /** The vendor's own status text beside what was asked, copied rather than paraphrased. */
  readonly vendorStatus: string;
}

/** What this package made of the identity's own statement, which is one of two readings. */
export type StatusReading = 'trusted' | 'revoked';

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
  /** The signed document first, then every certificate the document itself presented, in the order it presented them. */
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
  /** Where these bytes belong, spelled from the declared key members, so a store cannot mix identities. */
  readonly cacheKey: string;
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

/** How an appraisal is run: what it may ask, and which clock stamps what it saw. */
export interface CollateralAppraisalOptions {
  readonly transport?: CollateralTransport;
  /**
   * Wall clock in seconds since the epoch, used only to stamp the instant an answer landed. The
   * appraisal instant is never taken from it: a query that does not say what moment it is asking
   * about is refused rather than answered about now.
   */
  readonly clock?: () => number;
}
