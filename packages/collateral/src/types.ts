import type { CollateralRefusal } from './errors.js';

/** The two Intel platforms the served origin publishes collateral for. */
export type IntelPlatform = 'sgx' | 'tdx';

/**
 * Every path an appraisal could ask collateral of. Five are read to a verdict here, and the sixth is declared
 * with the host and route its vendor publishes, read as far as its answer's own wrapper goes and refused at the
 * signature this package states no rule for weighing, so asking for an answer from it answers with a sentence
 * rather than with a type error a caller could only reach by deleting the question.
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
export interface CollateralQuery {  readonly origin: CollateralOriginName;
  readonly platform: IntelPlatform;
  /** The CPU type the origin indexes collateral by: Intel's FMSPC id as hex text. Required for TCB Info. */
  readonly cpuType: string | null;
  readonly level: IntelTcbLevel | null;
  /** Which declared route this query asks, or null for the declaration's first route. */
  readonly route?: string | null;
  /** The PCK CRL's authority scope: the processor list or the platform list. Required for that origin. */
  readonly ca?: 'processor' | 'platform' | null;
  /**
   * The certificate serial the PCK CRL is asked about, as hex text a certificate or a list states.
   *
   * A revocation list answers a question about a serial, not about a platform level, so a CRL appraisal
   * names this input rather than a level. The value is read as an unsigned number: a leading zero byte
   * and the case of the hex digits do not change which serial is meant.
   */
  readonly certificateSerial?: string | null;
  /** AMD's product line as KDS spells it, such as `Milan`. Required for a KDS address. */
  readonly product?: string | null;
  /**
   * AMD's chip id as 128 hex characters, the 64 bytes a platform's report states and the spelling the
   * per-chip route answers. Required for a VCEK address.
   *
   * The half-length spelling is refused before the origin is asked, because the route answers it with a
   * refusal of its own rather than with a certificate.
   */
  readonly hwid?: string | null;
  /** NVIDIA's RIM id, the value a GPU's attestation evidence names. Any non-empty id is percent-encoded into the path. */
  readonly rimId?: string | null;
  /**
   * The certificate an OCSP question asks about, and the issuer that signed it, both as the bytes they are.
   *
   * Both are read: the request this path writes names them, the answer's `CertID` is compared with them, and
   * the issuer is the certificate the responder's signature is weighed under. A question stating only one of
   * them states no question an address can be built for, which is the missing context the refusal reports.
   */
  readonly ocspCertificate?: Uint8Array | null;
  readonly ocspIssuer?: Uint8Array | null;
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

/**
 * A query for the Intel PCK CRL, which asks about one certificate serial rather than a platform level.
 *
 * The serial and the authority scope are required here even though the general query states them as optional,
 * because a CRL appraisal that named neither would have no question to ask and no route to ask it at. The
 * platform field stays because every query this package takes names one, and the list itself is not indexed by
 * it: the measured route returns the same list for every platform.
 */
export type PckCrlQuery = Omit<CollateralQuery, 'origin' | 'ca' | 'certificateSerial'> & {
  readonly origin: 'intel-pck-crl';
  readonly ca: 'processor' | 'platform';
  readonly certificateSerial: string;
};

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
 * One entry of a DER certificate list's revokedCertificates sequence.
 *
 * The sequence can carry an entry whose reason is `removeFromCRL`, which takes a certificate out of a
 * listing rather than revoking it. Such an entry is copied here with its own bytes, and the serial appraisal
 * refuses it under `COLLATERAL_STATUS_UNSUPPORTED` rather than reading it as a revocation.
 */
export interface RevokedCertificate {
  /** The serial exactly as the list's INTEGER content carries it, including a leading zero the DER needs. */
  readonly serial: Uint8Array;
  /** The same number as lowercase hex with no leading zeros, which is how a query names it. */
  readonly serialHex: string;
  /** The instant the list states this revocation took effect, in Unix seconds. */
  readonly revokedAt: number;
  /** RFC 5280's reason code where the entry carries a cRLReason extension, or null where it carries none. */
  readonly reasonCode: number | null;
  /** The registry name for that code where one exists, or null for a code this reader does not name. */
  readonly reason: string | null;
}

/**
 * A DER CertificateList that parsed, reached a pinned root, and verified under the issuer's own key.
 *
 * The window is the list's own `thisUpdate` and `nextUpdate`, and the revoked entries are copied with the
 * bytes that stated them. `blobs` keeps the list first and then the certificates the chain header presented,
 * in the order it presented them, so nothing here re-encodes, reorders or drops a byte.
 */
export interface RevocationList {
  /** The version the DER states: 2 where it carries the v2 marker, 1 where it carries none. */
  readonly version: 1 | 2;
  /** The one signature suite this path reads, copied from the list's own algorithm identifier. */
  readonly signatureAlgorithm: 'ecdsa-with-SHA256';
  /** The issuer Name exactly as the list carries it, without its SEQUENCE wrapper. */
  readonly issuer: Uint8Array;
  /** The window the list states for itself, in Unix seconds. */
  readonly window: SignedWindow;
  readonly revoked: readonly RevokedCertificate[];
  /** sha256 of the whole CertificateList, as the bytes arrived. */
  readonly digest: string;
  /** sha256 of the pinned certificate the issuer chain reached. */
  readonly anchorDigest: string;
  /** The list first, then every certificate the chain header presented, in the order it presented them. */
  readonly blobs: readonly Uint8Array[];
}

/**
 * A query for the AMD Key Distribution Service, which asks about one chip rather than a platform level.
 *
 * The product line and the chip id are required here even though the general query states them as optional,
 * because a KDS answer that names no chip has no question to answer: both are in the address the routes are
 * built from and both are stated again inside the certificate that comes back. The route is not a caller's
 * field on this path, because one question is answered by two published routes and the appraisal asks both.
 * The platform field stays because every query this package takes names one, and neither route is indexed by
 * it: the measured addresses are per product line and per chip alone.
 */
export type VcekChainQuery = Omit<CollateralQuery, 'origin' | 'route' | 'product' | 'hwid'> & {
  readonly origin: 'amd-kds';
  /** AMD's product line as the route spells it and as the certificate's own name begins, such as `Milan`. */
  readonly product: string;
  /** AMD's chip id as 128 hex characters, the 64 bytes a platform's report states. */
  readonly hwid: string;
};

/**
 * A VCEK that parsed, reached a root the caller pinned, and was believed under it.
 *
 * The window is the span the three believed certificates all hold themselves valid for, which is the span
 * over which the chain stands as read; it is copied from the certificates and extended by nothing here.
 * `blobs` keeps the certificate answer first and then every certificate the chain answer presented, in the
 * order it presented them, so nothing re-encodes, reorders or drops a byte. `digest` identifies one answer
 * rather than one certificate: the per-chip route re-mints its answer per request, so the digest of a kept
 * answer is not the digest of the next one, while `hwidHex` and `serialHex` are.
 */
export interface VcekChain {
  /** The product name the certificate's own AMD extension states, copied verbatim, stepping and all. */
  readonly productName: string;
  /** The chip id the certificate's own AMD extension states, as 128 lowercase hex characters. */
  readonly hwidHex: string;
  /** The VCEK's serial as its DER INTEGER content carries it, as lowercase hex. */
  readonly serialHex: string;
  /** The instants the whole believed chain holds itself valid for, in Unix seconds. */
  readonly window: SignedWindow;
  readonly digest: string;
  /** sha256 of the pinned certificate the chain was believed under. */
  readonly anchorDigest: string;
  readonly blobs: readonly Uint8Array[];
}

/**
 * The answers a KDS appraisal can give, kept apart from both other outcome types because a certificate
 * chain states no platform level and no vendor status word, and no revocation either.
 *
 * `issued` is the answer for a chain this run fetched and believed: AMD published this certificate for the
 * chip the question named, and the chain stood at the moment asked. It is not a statement that the chip is
 * trusted, not revocation knowledge and not a hardware pass, and the claim beside it says its reach is
 * historical even when this run watched both answers land. `stale` is the same believed chain from bytes this
 * run did not fetch, with the observation refusal beside it. `unavailable` and `missing-context` carry
 * nothing, because there is nothing yet to have read.
 */
export type VcekChainOutcome =
  | { readonly state: 'issued'; readonly chain: VcekChain; readonly claim: CollateralClaim }
  | {
      readonly state: 'stale';
      readonly chain: VcekChain;
      readonly claim: CollateralClaim;
      readonly refusal: CollateralRefusal;
    }
  | { readonly state: 'unavailable'; readonly chain: null; readonly claim: null; readonly refusal: CollateralRefusal }
  | { readonly state: 'missing-context'; readonly chain: null; readonly claim: null; readonly refusal: CollateralRefusal };

/**
 * The answers a CRL appraisal can give, kept apart from `CollateralOutcome` because a list states nothing
 * about a platform level.
 *
 * `not-listed` is the state a verified, current list reaches when it does not name the serial asked about.
 * It is not `current` and not a pass: the list says the issuer had not listed that certificate as of its
 * `thisUpdate`, which is a narrower statement than the certificate being trusted. A list that names the
 * serial is `revoked`, with the bytes kept beside the refusal, unless the entry states `removeFromCRL`,
 * which removes a listing rather than revoking a certificate and answers `unavailable` under
 * `COLLATERAL_STATUS_UNSUPPORTED` with no list beside it. `stale` covers a list that speaks for a window
 * outside the moment asked about, and a list this run did not observe; the claim beside it says which.
 */
export type RevocationOutcome =
  | { readonly state: 'revoked'; readonly list: RevocationList; readonly claim: CollateralClaim; readonly refusal: CollateralRefusal }
  | { readonly state: 'not-listed'; readonly list: RevocationList; readonly claim: CollateralClaim }
  | { readonly state: 'stale'; readonly list: RevocationList; readonly claim: CollateralClaim; readonly refusal: CollateralRefusal }
  | { readonly state: 'unavailable'; readonly list: null; readonly claim: null; readonly refusal: CollateralRefusal }
  | { readonly state: 'missing-context'; readonly list: null; readonly claim: null; readonly refusal: CollateralRefusal };

/**
 * The five answers, and the one thing all of them refuse to be: a pass.
 *
 * `current` is the only state that carries no refusal, and it is reached by asking the origin in this
 * run under a root the caller pinned. `stale` and `revoked` both carry the verified bytes, because the
 * difference between them is what the vendor signed rather than whether it was readable. `unavailable`
 * and `missing-context` carry nothing, because there is nothing yet to have read.
 *
 * The OCSP path answers with this union too, for the same reasons: a responder's `good` is the one word
 * beside which a current reach can be stated, a `revoked` answer carries its own bytes beside the refusal,
 * and a standing this path has no rule for is absence rather than a verdict. Where its collateral is an
 * `OcspCollateral`, which states the serial and the answer's own word beside everything a `SignedCollateral`
 * states.
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

/**
 * A query for the OCSP responder, which asks about one certificate rather than about a platform level.
 *
 * The certificate and its issuer are required here even though the general query states them as optional,
 * because a responder answer that names no certificate is not an answer to anything: the request is built from
 * them, the `CertID` of the answer is compared with them, and the issuer is the certificate the signature on
 * the answer is weighed under. The route is not a caller's field on this path, because the declaration publishes
 * one route and the question is asked at it. The platform field stays because every query this package takes
 * names one, and the responder is indexed by a certificate and not by it.
 */
export type OcspQuery = Omit<CollateralQuery, 'origin' | 'route' | 'ocspCertificate' | 'ocspIssuer'> & {
  readonly origin: 'ocsp';
  readonly ocspCertificate: Uint8Array;
  readonly ocspIssuer: Uint8Array;
};

/**
 * An `OCSPResponse` that parsed, reached a root the caller pinned, and was believed under the issuer the
 * question named.
 *
 * `window` is the single response's own `thisUpdate` and `nextUpdate`, which is the span the responder speaks
 * for and the only span a claim about this certificate may be measured against; `signedAt` is `producedAt`,
 * the instant the responder stated it signed. `certStatus` is the answer's own word, copied rather than
 * paraphrased, and `revokedAt` is the instant the `revoked` word states and `reasonCode` the reason beside it. `blobs` keeps the response first and
 * then every certificate the response itself presented, in the order it presented them, so nothing re-encodes,
 * reorders or drops a byte. A certificate the caller handed in the question is not among them: it travels
 * beside the answer rather than inside it.
 */
export interface OcspCollateral extends SignedCollateral {
  /** The serial the answer's `CertID` states, as the DER INTEGER's content spells it in lowercase hex. */
  readonly serialHex: string;
  /** The responder's own word for the certificate's standing, copied from the answer. */
  readonly certStatus: 'good' | 'revoked' | 'unknown';
  /** The instant a `revoked` answer states the revocation took effect, in Unix seconds, or null for one that states no revocation. */
  readonly revokedAt: number | null;
  /**
   * RFC 5280's `cRLReason` code the `revoked` standing carries in its `revocationReason`, or null where the
   * standing states none. An answer whose reason is `removeFromCRL` is refused under
   * `COLLATERAL_STATUS_UNSUPPORTED` rather than read as a revocation, which is the same answer a revocation
   * list's entry with that reason gets.
   */
  readonly reasonCode: number | null;
  /** The registry name for that code where one exists, or null for a code this reader does not name. */
  readonly reason: string | null;
}

/**
 * What a RIM wrapper states about the manifest it carries.
 *
 * Nothing here is a statement about the manifest's contents: `readRimManifest` weighs the wrapper's own digest
 * against the bytes the `rim` member carries and copies the identity the service states for the answer, and the
 * refusal beside it says that the manifest's own signature was weighed by nobody. `lastUpdated` is the vendor's
 * text for when the file was updated and states no window, so no reach and no expiry is derived from it.
 */
export interface RimManifest {
  /** The manifest id the wrapper states for itself, verbatim. */
  readonly id: string;
  /** Which of the three formats the service names the manifest as, copied rather than inferred. */
  readonly format: string;
  /** The wrapper's own `last_updated` text, verbatim, which states no validity window. */
  readonly lastUpdated: string;
  /** The manifest bytes exactly as the wrapper carried them, decoded from its base64 text and re-made by nobody. */
  readonly rim: Uint8Array;
  /** sha256 of `rim` as hex, which is the digest the wrapper stated and this path compared. */
  readonly digest: string;
  /** The whole answer, as it arrived, so a caller keeps the bytes rather than a re-encoding of them. */
  readonly blobs: readonly Uint8Array[];
}

/**
 * The answers one certificate's revocation question can give, kept apart from `CollateralOutcome` so a caller
 * of `appraiseOcspResponse` reads the standing, the serial, the revocation instant and the reason beside it out
 * of the answer rather than out of a cast.
 *
 * The five states and what each may say are the platform appraisal's: `current` is the one that carries no
 * refusal and is reached only when this run asked the responder and the answer's own window covers the moment
 * being appraised; `revoked` and `stale` carry the bytes the responder signed; `unavailable` and
 * `missing-context` carry nothing. `current` here is the estate's one `current-knowledge` about a revocation,
 * and it says the certificate stood good or revoked as the responder stated it, which is not a statement that
 * the platform it sits in is trusted.
 */
export type OcspOutcome =
  | { readonly state: 'current'; readonly collateral: OcspCollateral; readonly claim: CollateralClaim }
  | { readonly state: 'stale'; readonly collateral: OcspCollateral; readonly claim: CollateralClaim; readonly refusal: CollateralRefusal }
  | { readonly state: 'revoked'; readonly collateral: OcspCollateral; readonly claim: CollateralClaim; readonly refusal: CollateralRefusal }
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
