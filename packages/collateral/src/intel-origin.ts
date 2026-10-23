import type { CertificatePublicKey, SignatureAlgorithm } from '@ashaveri/attest-core';
import { sha256Hex } from './bytes.js';
import { collateralRefusal, quoteOrDigest, type CollateralErrorCode, type CollateralInputName, type CollateralRefusal } from './errors.js';
import type { CollateralOriginName, CollateralQuery, IntelPlatform } from './types.js';

/**
 * The origins this package has a reader for. A query naming an undeclared origin, or putting a question to an
 * entry point that weighs another origin's answer, is refused before any request, so a caller gets a sentence
 * rather than a type error it could only reach by deleting the question.
 *
 * Five of these read an answer to one of the five verdict states. The sixth, `nvidia-rim`, reads the wrapper its
 * route answers in and refuses the manifest inside it: a served origin here means an answer is weighed, not that
 * every answer reaches a verdict, and the refusal the wrapper reader returns beside the bytes it read says which
 * of the two a caller is holding.
 */
export type ReadCollateralOrigin =
  | 'intel-tcb-info'
  | 'intel-qe-identity'
  | 'intel-pck-crl'
  | 'amd-kds'
  | 'ocsp'
  | 'nvidia-rim';

/** The origins whose answer is the served JSON document that one reader weighs. */
export type ReadDocumentOrigin = 'intel-tcb-info' | 'intel-qe-identity';

/** Which field of a query the cache key is built from. */
export type CollateralCacheMember =
  | 'origin'
  | 'platform'
  | 'cpuType'
  | 'level'
  | 'ca'
  | 'product'
  | 'hwid'
  | 'ocspCertificate';

/**
 * The shape an origin's answer takes, which decides whether this package has an arm to weigh it.
 *
 * The shape is stated per origin rather than read off the bytes: a DER sequence, a JSON wrapper and a PEM
 * block are each a run of bytes until a reader knows what it is looking at, and the reader that exists here
 * weighs one served JSON document. The other shapes are named so a refusal can say which one arrived.
 */
export type CollateralAnswerShape =
  | 'json-signed-document'
  | 'der-crl'
  | 'pem-certificate-chain'
  | 'der-certificate'
  | 'swid-rim'
  | 'der-ocsp-response';

/**
 * A route a vendor publishes for an origin, as the vendor states it.
 *
 * The path is relative to the declaration's host and carries `{member}` placeholders that `requestUrl`
 * fills from the query. The answer shape travels beside the route because one origin can publish more
 * than one: a KDS path returns a certificate while another returns the chain beside it.
 */
export interface DeclaredRoute {
  /** The name a query selects this route by, unique within its declaration. */
  readonly name: string;
  /** The path on the declared host, with placeholders filled from the query. */
  readonly path: string;
  readonly method: 'GET' | 'POST';
  /** The media type the answer arrives in, which is what the fetch asks for. */
  readonly mediaType: string;
  readonly answer: CollateralAnswerShape;
  /**
   * How far an answer from this route reaches. A signed reference document speaks for the instant it was
   * published, which is historical knowledge; an OCSP answer speaks for the instant it was asked, which is
   * current knowledge at that instant and no later one.
   */
  readonly knowledge: 'historical' | 'current';
}

/** The refusal slots every declaration names, whether or not its origin can reach each one. */
export interface OriginRefusals {
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
}

/** How a kept blob is named, for an origin whose reader can state the identity and window it belongs to. */
export interface OriginCacheRule {
  /** The fields that decide which question a kept blob is an answer to. */
  readonly keyMembers: readonly CollateralCacheMember[];
  /** A kept blob records one earlier observation, so it cannot answer what is true now. */
  readonly answersCurrentQuestions: false;
  /**
   * How long a caller may keep the bytes: the expiry the answer itself states, copied and never extended.
   * A signed document and a revocation list write it as `nextUpdate`; a certificate writes it as its own
   * `notAfter`, which is the same kind of fact and the same kind of ban on extending it.
   */
  readonly retainUntil: 'vendor-next-update' | 'certificate-not-after';
}

/**
 * Everything one retrieval path decides, written down once: where it is asked, what shape the answer
 * has to be, how long the wait is, what may be kept, and which refusal each failure answers with.
 * `test/origin-declaration.test.ts` reads this against the code that acts on it, because a
 * declaration nobody checks is a comment with a type.
 *
 * The fields an origin does not use are absent from its arm of the union rather than left empty, so a
 * reader that needs the Intel payload members cannot be handed a declaration that states none.
 */
interface OriginDeclarationCommon {
  readonly name: CollateralOriginName;
  /** The one host asked. An answer that redirects away from it is refused rather than followed. */
  readonly host: string;
  /** The method the origin answers to. A POST declaration is asked with the body its reader builds. */
  readonly method: 'GET' | 'POST';
  /**
   * The media type a question is sent with, or null where the declaration is asked by GET and sends no body.
   *
   * `mediaType` is the type the *answer* arrives in, which is what the request's `accept` names; a POST asks
   * with a document of its own, and RFC 6960 gives the two halves different types. The pair is stated apart
   * because a request sent under the answer's type is a document the responder has no rule for reading.
   */
  readonly requestMediaType: string | null;
  /** The media type the answer arrives in. */
  readonly mediaType: string;
  /** What an answer from this origin is, where one shape describes the declaration; each route states its own. */
  readonly answer: CollateralAnswerShape;
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
  readonly timeoutMs: number;
  readonly maxResponseBytes: number;
  readonly refusals: OriginRefusals;
}

/** A declaration this package reads: the served JSON document Intel answers with. */
export interface IntelOriginDeclaration extends OriginDeclarationCommon {
  readonly reader: { readonly as: 'served-json-document' };
  readonly platformPath: (platform: IntelPlatform) => string;
  readonly documentPath: string;
  /** The query member carrying the CPU type, or null when the document is not indexed by one. */
  readonly cpuTypeMember: string | null;
  /**
   * Which envelope this path decodes, and which envelope the origin answers in.
   *
   * `envelope` is what `readSignedCollateral` walks: three dot-separated base64url parts whose certificates sit
   * inside them, which is this path's rule and not the vendor's. `served` is the envelope the answer that this
   * address returns is actually written in, or null where no served answer recorded below arrives in an
   * envelope this package can weigh: a JSON wrapper whose signature sits in a hex member and whose issuer chain
   * arrives beside the body, in the header `chainHeader` names. That is the pair `readServedCollateral` weighs.
   * The suite is the one on both sides, ES256 over P-256, spelled raw rather than as a JWS signature.
   *
   * Both are stated here rather than read off the bytes because which arm weighs an answer cannot be guessed
   * from a body: a wrapper that starts with a brace and a token that starts with base64url are the same text to
   * anything that looks, and a document is served in one envelope or the other because of who serves it.
   */
  readonly signature: {
    readonly envelope: 'jws-compact';
    readonly served: {
      readonly envelope: 'json-hex-signature';
      /** The wrapper member the hex `r` and `s` of the signature over the document member's own span arrive in. */
      readonly signatureMember: string;
    } | null;
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
  readonly cache: OriginCacheRule;
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
}

/**
 * A declaration this package names but does not read to a verdict.
 *
 * The routes are the vendor's, copied from published documentation and measured answers, and the sentence
 * states what a reader would still need. Nothing is inferred from the origin's name: an origin without a
 * reader refuses an appraisal rather than handing back bytes under a shape nobody has weighed.
 */
export interface DeclaredOriginDeclaration extends OriginDeclarationCommon {
  /**
   * What this origin's answer is weighed by, beside what it is still not weighed for.
   *
   * `lacks` names the reading that would have to exist for an appraisal of this origin to answer a verdict,
   * and `reads` names the half that a reader here does weigh, so a caller of the wrapper reader learns both
   * from one declaration rather than from the absence of a refusal.
   */
  readonly reader: { readonly as: 'declared-only'; readonly lacks: string; readonly reads?: string };
  /** The routes the vendor publishes, in the order the declaration prefers them. */
  readonly routes: readonly DeclaredRoute[];
  /**
   * No record can be named for this origin yet. A cache key names the question a kept answer answers, and
   * naming it here would require a reader that states the answer's own identity and window, which is the
   * reader this origin lacks.
   */
  readonly cache: null;
}

/**
 * A declaration this package reads as far as its answer's own wrapper, and no further.
 *
 * The wrapper is the JSON body a RIM route answers in, and `readRimManifest` weighs it: the base64 manifest
 * against the `sha256` the same body names, and the id the body carries against the id the question asked for.
 * That is a reading of an answer, so this origin is served, and it is not a verdict, because the manifest the
 * wrapper carries is signed in a form this package states no rule for canonicalizing.
 *
 * `lacks` names the reading that would have to exist for an appraisal of this origin to answer a verdict, and
 * `reads` names the half a reader here does weigh, so a caller learns both from one declaration rather than from
 * the absence of a refusal. `reads` is required here and optional on a declaration with no reader at all,
 * because this one has something to state.
 */
export interface RimOriginDeclaration extends OriginDeclarationCommon {
  readonly reader: { readonly as: 'rim-wrapper'; readonly reads: string; readonly lacks: string };
  /** The routes the vendor publishes, in the order the declaration prefers them. */
  readonly routes: readonly DeclaredRoute[];
  /**
   * No record can be named for this origin yet. A cache key names the question a kept answer answers, and a
   * wrapper whose manifest was never believed answers no question about a device, so there is no record for
   * kept bytes to belong to.
   */
  readonly cache: null;
}

/**
 * A declaration this package reads as a DER certificate list: the Intel PCK CRL.
 *
 * The list states its own window and its own issuer, so a kept blob answers about that window and about every
 * serial the list names. The query member carrying the serial is declared here rather than left to a call site,
 * because a list asked without a serial has no question to answer, and the cache key names the authority scope
 * whose list was kept rather than a serial the same list answers for every one.
 */
export interface CrlOriginDeclaration extends OriginDeclarationCommon {
  readonly reader: { readonly as: 'der-certificate-list' };
  /** The routes the vendor publishes, in the order the declaration prefers them. */
  readonly routes: readonly DeclaredRoute[];
  /** The query member that names the certificate serial this list is asked about. */
  readonly serialMember: 'certificateSerial';
  /**
   * The issuer name the list of each authority scope is expected to carry, as the common name its own Name
   * states. The scope is part of the question, so a list whose issuer is not the name of the scope asked about
   * answers `COLLATERAL_IDENTITY_MISMATCH` rather than carrying the answer over from the other authority.
   */
  readonly issuers: Readonly<Record<'processor' | 'platform', string>>;
  readonly cache: OriginCacheRule;
}

/**
 * A declaration this package reads as an AMD VCEK and the authority chain above it.
 *
 * Two published routes answer one question, so one reader weighs both: the per-chip route answers the
 * certificate the chip's own report names, and the chain route answers the authorities beneath the root the
 * caller pinned. The route names are stated here rather than read off the order, because a route that answers
 * a chain is not a route that answers a certificate and the reader has to know which half it was handed. The
 * identity members are stated for the same reason the CRL states its serial member: a VCEK is an answer about
 * one chip, and a question that names none has nothing to bind the certificate to.
 */
export interface VcekOriginDeclaration extends OriginDeclarationCommon {
  readonly reader: { readonly as: 'amd-vcek-chain' };
  /** The routes the vendor publishes, in the order the declaration prefers them. */
  readonly routes: readonly DeclaredRoute[];
  /** The route whose answer is the VCEK the question is about. */
  readonly certificateRoute: 'vcek';
  /** The route whose answer is the certificate chain beside it. */
  readonly chainRoute: 'cert-chain';
  /** The query member naming the product line, which the address carries and the certificate states. */
  readonly productMember: 'product';
  /** The query member naming the chip id, which the address carries and the certificate states. */
  readonly hwidMember: 'hwid';
  /**
   * The shape both halves of the answer have to carry to be this origin's answer at all.
   *
   * Measured on the Milan line: the root and the intermediate are rsa-pss certificates over rsa keys and the
   * per-chip certificate carries a P-384 key under that same suite. The rule inside the suite, which is the
   * hash, the mask, the salt and the curve pairing, is `@ashaveri/attest-core`'s and is stated here only as the
   * name of the suite, so a chain of another shape is refused as the wrong answer rather than believed. A line
   * that published another suite would answer this name wrongly, and no line but this one has been measured.
   */
  readonly suites: {
    readonly signature: Exclude<SignatureAlgorithm['kind'], 'unsupported'>;
    readonly authorityKey: CertificatePublicKey['kind'];
    readonly certificateKey: CertificatePublicKey['kind'];
  };
  readonly cache: OriginCacheRule;
}

export type OriginDeclaration =
  | IntelOriginDeclaration
  | DeclaredOriginDeclaration
  | RimOriginDeclaration
  | CrlOriginDeclaration
  | VcekOriginDeclaration
  | OcspOriginDeclaration;

/**
 * A declaration this package reads as a DER `OCSPResponse`: the answer one certificate's revocation status is
 * asked with.
 *
 * One route answers one certificate, and the answer is signed rather than stated: the responder signs the
 * response data and the caller's pinned root is what makes that signature an answer at all. The identity the
 * answer binds to is the certificate the question names, which is why `ocspCertificate` and `ocspIssuer` are
 * required members of the query type rather than optional ones of the general query, and why a response whose
 * `CertID` is not that certificate's answers an identity refusal rather than a verdict about this one.
 */
export interface OcspOriginDeclaration extends OriginDeclarationCommon {
  readonly reader: { readonly as: 'ocsp-response' };
  /** The routes the vendor publishes, in the order the declaration prefers them. */
  readonly routes: readonly DeclaredRoute[];
  /**
   * The suites this path weighs an answer in, stated as the shapes `@ashaveri/attest-core` parses.
   *
   * The responder's suite is not measured from an answer here: the endpoint is reached by POST and no served
   * response is committed, so these are the rules this path applies and refuses outside, the same way the
   * JWS envelope rule in `read.ts` is this package's rule and not the vendor's. A responder that signs another
   * way answers `COLLATERAL_SIGNATURE_UNVERIFIED`, which says plainly that nobody weighed that answer here.
   */
  readonly suites: {
    readonly signature: Exclude<SignatureAlgorithm['kind'], 'unsupported'>;
    readonly responderKey: CertificatePublicKey['kind'];
  };
  /**
   * Which words of the answer this path reads as which standing.
   *
   * `unknown` is deliberately in neither list: a responder that has no record of the certificate asked about
   * answers a question about its own database, not about the certificate, and a word outside both lists is
   * refused with the answer's own text rather than sorted into the nearer one.
   */
  readonly status: {
    readonly trusted: readonly string[];
    readonly revoked: readonly string[];
  };
  /**
   * The responder this path accepts a signature from: the issuer of the certificate the question names.
   *
   * RFC 6960 allows a CA to delegate OCSP signing to another certificate, and the delegation is carried in an
   * extension this package's certificate reader states no rule for reading. A response signed by anybody else
   * is refused rather than believed, so this slot is where that limit is written down rather than remembered.
   */
  readonly signer: 'issuer-named-by-the-question';
  readonly cache: OriginCacheRule;
}

/** Whether a declaration has a reader here, narrowed so a caller can reach the payload members it states. */
export function isIntelDeclaration(declaration: OriginDeclaration): declaration is IntelOriginDeclaration {
  return declaration.reader.as === 'served-json-document';
}

/** Whether a declaration names routes without a reader, narrowed so a caller can reach the routes. */
export function isDeclaredOnly(declaration: OriginDeclaration): declaration is DeclaredOriginDeclaration {
  return declaration.reader.as === 'declared-only';
}

/** Whether a declaration is read as a DER certificate list, narrowed so a caller can reach its cache rule. */
export function isCrlDeclaration(declaration: OriginDeclaration): declaration is CrlOriginDeclaration {
  return declaration.reader.as === 'der-certificate-list';
}

/** Whether a declaration is read as a VCEK beside its authority chain, narrowed for the same reason. */
export function isVcekDeclaration(declaration: OriginDeclaration): declaration is VcekOriginDeclaration {
  return declaration.reader.as === 'amd-vcek-chain';
}

/** Whether a declaration is read as a DER OCSP response, narrowed so a caller can reach its rules. */
export function isOcspDeclaration(declaration: OriginDeclaration): declaration is OcspOriginDeclaration {
  return declaration.reader.as === 'ocsp-response';
}

/**
 * Whether a declaration is read as far as its own wrapper, narrowed so a caller can reach what it lacks.
 *
 * The tag states the reach rather than the shape: a wrapper reader is a reader, and the `lacks` it carries says
 * how far short of a verdict it stops, which is the pair a caller of the appraisal path has to see together.
 */
export function isRimDeclaration(declaration: OriginDeclaration): declaration is RimOriginDeclaration {
  return declaration.reader.as === 'rim-wrapper';
}

/** Whether this declaration has a reader here at all, whatever shape that reader weighs. */
export function hasReader(declaration: OriginDeclaration): boolean {
  return declaration.reader.as !== 'declared-only';
}

/**
 * Whether the routes an answer is read from state that they speak for the moment they are asked.
 *
 * A signed document states a window and a vendor word about a level, and a reader that fetched it inside that
 * window this run reports current knowledge. A certificate chain states what its issuer signed and until when
 * its own validity runs, which is historical whatever the fetch did, so this answers from what the routes
 * state rather than from what the call site remembers. Where a declaration names the two routes one question
 * is answered with, only those two count; a question asked of a single route is answered by that route alone.
 */
export function routesAnswerNow(
  declaration: { readonly routes: readonly DeclaredRoute[] } & Partial<Pick<VcekOriginDeclaration, 'certificateRoute' | 'chainRoute'>>,
): boolean {
  const asked = declaration.certificateRoute === undefined
    ? declaration.routes
    : declaration.routes.filter((route) => route.name === declaration.certificateRoute || route.name === declaration.chainRoute);
  return asked.every((route) => route.knowledge === 'current');
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
} as const satisfies OriginRefusals;

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
 * `UpToDate` and `OutOfDate` are the only two words a published level carries, on either platform, at
 * either version, on either document: the first is the vendor standing
 * behind a level and the second is the vendor no longer standing behind it. `OK` is no word the vendor
 * publishes, so a vocabulary that trusted it would be trusting a word of ours rather than the vendor's.
 *
 * The two compound spellings stay on the revoked side. They are no words a published level carries; a word
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
  method: 'GET',
  requestMediaType: null,
  mediaType: 'application/jose',
  answer: 'json-signed-document',
  reader: { as: 'served-json-document' },
  platformPath: (platform: IntelPlatform) => `/${platform}/certification/v4`,
  timeoutMs: 5000,
  maxResponseBytes: 65536,
  signature: {
    envelope: 'jws-compact',
    /**
     * Both documents of this host are answered in the one served envelope, so it is stated once here rather than
     * per declaration: the body is `{tcbInfo, signature}` or `{enclaveIdentity, signature}`, and the signature is
     * 128 lowercase hex characters, the raw `r` and `s` of a P-256 signature over the document member's own span
     * inside that body. What differs between the two documents is where the chain arrives, which is the header
     * each declaration names for itself below.
     */
    served: { envelope: 'json-hex-signature', signatureMember: 'signature' },
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
 * declares are the one name, and no published request or answer carries a member named `fmspcid`.
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
 *   `sgxtcbcomp01svn` through `sgxtcbcomp16svn` with `pcesvn`. No published document spells a composition
 *   in hex, which is what `levelCompositionStatedAs` records and what
 *   makes a `tcb-composition` question unanswerable on this path rather than unanswered.
 * - the two status words a served level carries are `UpToDate` and `OutOfDate`, and the
 *   vocabulary above reads exactly those.
 * - the envelope is not the one `readSignedCollateral` walks. The served body is a JSON object carrying a
 *   `signature` member of 128 hex characters, which is 64 bytes and the raw `r` and `s` of an ECDSA P-256
 *   signature taken over the span of `tcbInfo` inside that body text, and the issuer chain arrives beside it in
 *   the response's `TCB-Info-Issuer-Chain` header as URL-encoded PEM. No `x5c`, no three-part envelope and no
 *   JWS is in the answer, so the JWS arm refuses a document of the served shape before any
 *   member of it is read, and a case in `test/read.test.ts` pins that refusal rather than smoothing it over.
 *   The signed-bytes rule is a fact about the shape the answer arrives in: the signature holds over the
 *   span as it arrived, and it does not hold over a sorted-key re-serialization of
 *   the parsed member, which is why `readServedCollateral` takes the span out of the text rather than re-making
 *   it. The two envelopes are weighed apart rather than reconciled into one, because the chain a reader walks
 *   has to arrive with the bytes it signs: the pair is this host's answer, and a body that arrived without its
 *   header is a body alone, which is all material that arrives inside a pack can be. What a served answer
 *   *states* is nobody's claim here: these rules are about the shape the answer arrives in.
 */
export const INTEL_TCB_INFO: IntelOriginDeclaration = {
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
 * component number rather than the array of them this document's twin states. The two words a level carries
 * are the `UpToDate` and `OutOfDate` of the vocabulary above. A kept QE Identity blob
 * answers about one rung of that ladder, so its key names the rung.
 *
 * The envelope is the same one the TCB Info document is answered in, one name wider: this document's issuer
 * chain arrives in the response's `SGX-Enclave-Identity-Issuer-Chain` header, named for the enclave identity
 * rather than for the TCB Info, so a reader holding only this body walks no chain to a pinned root and the pair
 * is what `readServedCollateral` takes. Its signature covers the span of `enclaveIdentity` inside that body
 * text, the same rule the TCB Info document is answered by, and a rule about the shape the answer arrives
 * in rather than about what any of it states.
 */
export const INTEL_QE_IDENTITY: IntelOriginDeclaration = {
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

/**
 * Intel's PCK CRL: the signed revocation list for the platform and processor PCK certificates.
 *
 * The route and the answer shape are measured: the route this declaration states answers 200 with
 * `content-type: application/pkix-crl` and a DER `CertificateList` signed with `ecdsa-with-SHA256`, and the
 * issuer chain arrives beside the body in the response's `SGX-PCK-CRL-Issuer-Chain` header as URL-encoded PEM,
 * leaf first. The same route answers for either authority scope, and each scope's list names its own
 * authority, which is why the issuer is bound to the `ca` that was asked for rather than reported beside the
 * answer. The signature is ECDSA P-256 over the DER of `tbsCertList`, including its own tag and length. No
 * bytes from either answer are kept here: a service's output travels as a reference, not as a committed blob.
 *
 * `readPckCrl` parses the list and walks the header's chain to a root the caller pinned, and `appraisePckCrl`
 * answers about one certificate serial. The list's issuer is bound to the requested `ca`: each scope's list
 * names its own authority, and the other scope's list answers `COLLATERAL_IDENTITY_MISMATCH` rather than a
 * question about this one. A list speaks for the window between its own `thisUpdate` and `nextUpdate`; an
 * instant outside that window answers `COLLATERAL_WINDOW_CLOSED` where the list does not name the serial. The
 * answer for a serial the list names is `revoked` under `COLLATERAL_REVOKED_BY_VENDOR`, wherever that moment
 * falls, and an entry whose reason is `removeFromCRL` is refused under `COLLATERAL_STATUS_UNSUPPORTED` because
 * a removal is not a revocation. A current list this run fetched that does not name the serial answers
 * `not-listed`, which is the issuer's silence about that certificate as of `thisUpdate` and not a statement
 * that the certificate is trusted. Where the moment asked precedes the listing, the revocation refusal says
 * so. Nothing here decides a hardware pass.
 */
export const INTEL_PCK_CRL: CrlOriginDeclaration = {
  name: 'intel-pck-crl',
  host: 'api.trustedservices.intel.com',
  method: 'GET',
  requestMediaType: null,
  mediaType: 'application/pkix-crl',
  answer: 'der-crl',
  /** Measured beside the answer: the header that carries this list's issuer chain. */
  chainHeader: 'SGX-PCK-CRL-Issuer-Chain',
  timeoutMs: 5000,
  maxResponseBytes: 65536,
  refusals: REFUSALS,
  reader: { as: 'der-certificate-list' },
  routes: [
    {
      name: 'pck-crl',
      path: '/sgx/certification/v4/pckcrl?ca={ca}&encoding=der',
      method: 'GET',
      mediaType: 'application/pkix-crl',
      answer: 'der-crl',
      knowledge: 'historical',
    },
  ],
  serialMember: 'certificateSerial',
  /**
   * The issuer name each authority scope's own list carries, read from that list's `issuer` field and from the
   * leaf certificate of the chain header the same answer brings. The common name is what carries the
   * authority, so it is what binds a list to the `ca` that was asked for: a processor list handed to a
   * platform question would be a true statement about another authority. A scope has a name here only where a
   * served list of that scope carried one.
   */
  issuers: {
    processor: 'Intel SGX PCK Processor CA',
    platform: 'Intel SGX PCK Platform CA',
  },
  /**
   * The list states one window for every serial it carries, so a kept copy is keyed by the authority scope
   * whose list it is. The platform is absent because the measured route is not indexed by one.
   */
  cache: { keyMembers: ['origin', 'ca'], ...CACHE_RULE },
};

/**
 * AMD's Key Distribution Service: the VCEK a chip's report names and the authority chain above it.
 *
 * Both routes are measured. Asked at `https://kdsintf.amd.com/vcek/v1/Milan/cert_chain`, the host answers 200
 * with `content-type: application/octet-stream`, `content-disposition: attachment; filename=Milan.pem` and a
 * 4602-byte body holding two PEM certificates, the attestation signing key first and the root beneath it.
 * Asked at `https://kdsintf.amd.com/vcek/v1/Milan/{hwid}` with a chip id of 64 bytes spelled as 128 hex
 * characters, the host answers 200 with `content-type: application/octet-stream`,
 * `content-disposition: attachment; filename=vcek.crt` and a 1350-byte body holding one DER certificate; the
 * same path with the id spelled at half that length answers 400, and an all-zero id of the right length answers
 * 404, so a malformed id and an unlisted one are different answers. The per-chip certificate is re-minted per
 * request: two asks inside two seconds returned different DER and different validity, with the product name,
 * chip id and serial unchanged. No bytes of either answer are kept here: a service's output travels as a
 * reference, and a certificate a customer's platform produced travels as bytes its caller supplies.
 *
 * The suites are what the vendor publishes and this path does not re-derive them. The root and the
 * intermediate are rsa-pss with SHA-384, MGF1-SHA384 and a 48-byte salt over rsa keys; the VCEK carries a P-384
 * key under that same suite and no `BasicConstraints` extension. `readVcekChain` believes the chain with
 * `verifyAmdCertificateChain` and selects the root with `findMatchingArk`, both of `@ashaveri/attest-core`, so
 * the parameter and curve rules sit where the rest of the estate's certificate rules sit and this package
 * writes none of them. Before this origin had a reader the refusal said the existing primitives could not weigh
 * the chain: they weigh it, and what they read is the walk, not the shape of a served JSON document.
 *
 * What an answer reaches is historical. A VCEK states what AMD signed about one chip and until when the
 * certificate it signed runs; it states no revocation and no vendor word about a level, so no answer from this
 * origin reports current knowledge, and none answers `COLLATERAL_WINDOW_CLOSED`, which is what a document
 * stating a vendor's own window for a level answers with. The validity the chain verifier insists on at the
 * moment asked is a different fact, and a chain that does not stand then is the unverified answer rather than a
 * closed window, so a kept pair reaches `COLLATERAL_NOT_OBSERVED` only after `readVcekChain` has believed it.
 * The chain states no TCB status either: AMD's TCB extension is read by nothing here, so the answer binds a chip
 * to a key and says nothing about which firmware that key stands for.
 */
export const AMD_KDS: VcekOriginDeclaration = {
  name: 'amd-kds',
  host: 'kdsintf.amd.com',
  method: 'GET',
  requestMediaType: null,
  mediaType: 'application/octet-stream',
  answer: 'pem-certificate-chain',
  /** Each answer carries its own bytes, so no header on either route carries a second copy to reconcile. */
  chainHeader: null,
  timeoutMs: 5000,
  maxResponseBytes: 65536,
  refusals: REFUSALS,
  reader: { as: 'amd-vcek-chain' },
  routes: [
    {
      name: 'vcek',
      path: '/vcek/v1/{product}/{hwid}',
      method: 'GET',
      mediaType: 'application/octet-stream',
      answer: 'der-certificate',
      knowledge: 'historical',
    },
    {
      name: 'cert-chain',
      path: '/vcek/v1/{product}/cert_chain',
      method: 'GET',
      mediaType: 'application/octet-stream',
      answer: 'pem-certificate-chain',
      knowledge: 'historical',
    },
  ],
  certificateRoute: 'vcek',
  chainRoute: 'cert-chain',
  productMember: 'product',
  hwidMember: 'hwid',
  suites: { signature: 'rsa-pss', authorityKey: 'rsa', certificateKey: 'ec-p384' },
  /**
   * A VCEK answers for one chip, so a kept answer is keyed by the line and the id the question named, and its
   * own validity is what bounds how long it may be kept. The platform is absent because the measured routes are
   * not indexed by one.
   */
  cache: {
    keyMembers: ['origin', 'product', 'hwid'],
    answersCurrentQuestions: false,
    retainUntil: 'certificate-not-after',
  },
};

/**
 * NVIDIA's Reference Integrity Manifest service: the signed reference document a GPU's measurements are
 * weighed against.
 *
 * The route is `https://rim.attestation.nvidia.com/v1/rim/{id}`, NVIDIA's Get RIM by ID. Asked at the bare
 * path on 17 October 2026, the host answered 403 with `content-type: application/json`; no RIM body is
 * served here without the id a GPU's evidence names. NVIDIA's API reference describes the answer as a
 * JSON wrapper carrying `$schema`, `id`, `last_updated`, `message`, `request_id`, `rim`, `rim_format` and
 * `sha256`, with `rim_format` one of `TCG`, `CORIM` or `GENERIC`, and its RIM guide describes the `TCG`
 * form as SWID XML signed with `ecdsa-sha384`, the certificates inside `ds:X509Certificate`.
 *
 * The wrapper is read, and the manifest inside it is not. `readRimManifest` weighs the wrapper's own `sha256`
 * against the bytes its `rim` member carries, reads the id and the format the service states, and answers with
 * those beside the refusal that says the bytes were signed by nobody this path weighed. What stands between
 * that and an appraisal is a canonicalization: the `TCG` form is SWID XML whose signature is taken over a
 * canonicalized element, and the package has no XML parser and no XML digital-signature canonicalization, so
 * no measurement inside a manifest is read here and no appraisal of this origin answers a verdict. Nor is the
 * variant settled from an answer: no served RIM body confirms which of the three formats a GPU RIM arrives in,
 * and a reader that assumed one would be inventing both the variant and the signature rule.
 *
 * A RIM is a signed reference document and would reach the instant it was published, not the instant it is
 * read: `last_updated` is when the vendor updated the file, not a validity window, so even a weighed manifest
 * could only ever be reported as historical knowledge. It is not revocation knowledge, which belongs to the
 * OCSP route below, and it is not a measurement match, which is what a GPU's evidence would be weighed against.
 */
export const NVIDIA_RIM: RimOriginDeclaration = {
  name: 'nvidia-rim',
  host: 'rim.attestation.nvidia.com',
  method: 'GET',
  requestMediaType: null,
  mediaType: 'application/json',
  answer: 'swid-rim',
  /**
   * The signed SWID document travels in the wrapper's `rim` member, and no response header carries the
   * certificates beside it. The wrapper's `sha256` is a digest the caller can check, not a chain.
   */
  chainHeader: null,
  timeoutMs: 5000,
  maxResponseBytes: 65536,
  refusals: REFUSALS,
  reader: {
    as: 'rim-wrapper',
    reads: 'the JSON wrapper the route answers in, which readRimManifest weighs against its own sha256',
    lacks: 'an XML digital-signature reader for the manifest the wrapper carries',
  },
  routes: [
    {
      name: 'rim',
      path: '/v1/rim/{rimId}',
      method: 'GET',
      mediaType: 'application/json',
      answer: 'swid-rim',
      knowledge: 'historical',
    },
  ],
  cache: null,
};

/**
 * NVIDIA's OCSP responder: the answer about one device identity certificate's revocation standing.
 *
 * The endpoint is `https://ocsp.ndis.nvidia.com`, an RFC 6960 responder reached by POST with a DER OCSP request
 * that names the certificate and its issuer. Asked with GET, the host answers 405 with
 * `content-type: application/json`, which states that GET is not a route there; whether an anonymous POST is
 * answered with a response or with a status asking for a credential is unmeasured, and no response of the
 * responder's is committed here. A service's output travels as a reference. What the route publishes is
 * copied from RFC 6960: a `Successful` answer carries a `BasicOCSPResponse` whose signed data states a
 * `producedAt`, one `SingleResponse` per certificate asked about, that response's `CertID`, its `certStatus`
 * of `good`, `revoked` or `unknown`, and its own `thisUpdate` beside the optional `nextUpdate`.
 *
 * `readOcspResponse` weighs that shape and `appraiseOcspResponse` answers with it. Four rules decide what the
 * answer can be relied on for, and each is stated on this declaration rather than remembered at a call site:
 * - the signer is the issuer the question names. RFC 6960 also allows a CA to delegate OCSP signing to another
 *   certificate, and the extension that carries that delegation is read by nothing in this repository's
 *   certificate parser, so a response signed by anybody else is refused rather than believed.
 * - the suite is the one this package already weighs elsewhere: ECDSA over P-256 with SHA-256, which is what
 *   `read.ts` walks chains in and what `crl.ts` reads a list's signature in. It is this path's rule, stated
 *   because no answer from this responder has been measured here; a responder signing another way meets
 *   `COLLATERAL_SIGNATURE_UNVERIFIED`, which says that nobody weighed that answer rather than that the
 *   certificate is unrevoked.
 * - the `CertID` is compared with the certificate the question states, as RFC 6960 defines it: SHA-1 over the
 *   issuer's DER `Name`, SHA-1 over the issuer's public-key BIT STRING content, and the serial. A response
 *   about another certificate is refused as the wrong answer to this question.
 * - the standing is the answer's own word. `good` and `revoked` are the two this path reads, and `unknown` is
 *   refused as a status it has no rule for, because a responder with no record of the certificate answers a
 *   question about its own database rather than one about the certificate. The reason beside a `revoked`
 *   standing is read too: RFC 6960 types it as a `cRLReason`, the code a revocation list's entry carries, and
 *   `removeFromCRL` answers with the refusal that reason already answers with on a list, so one vendor code
 *   means one thing to either reader of this package.
 *
 * What an answer reaches is the distinction `CollateralClaim` names: an answer this run asked, whose
 * `thisUpdate` covers the moment being appraised, is `current-knowledge` about that certificate's standing as
 * the responder stated it, and bytes kept from an earlier run are `historical-knowledge` beside
 * `COLLATERAL_NOT_OBSERVED`. Revocation standing is not a platform pass: nothing here reads a TCB level, a
 * measurement or a vendor status about a platform, and a certificate that is not revoked says only that.
 */
export const NVIDIA_OCSP: OcspOriginDeclaration = {
  name: 'ocsp',
  host: 'ocsp.ndis.nvidia.com',
  method: 'POST',
  /** RFC 6960 names the request and the response types apart, and the request is the one this path writes. */
  requestMediaType: 'application/ocsp-request',
  mediaType: 'application/ocsp-response',
  answer: 'der-ocsp-response',
  /** A responder certificate sits inside the signed response, and no header is declared to carry one. */
  chainHeader: null,
  timeoutMs: 5000,
  maxResponseBytes: 65536,
  refusals: REFUSALS,
  reader: { as: 'ocsp-response' },
  routes: [
    {
      name: 'ocsp',
      path: '/',
      method: 'POST',
      mediaType: 'application/ocsp-response',
      answer: 'der-ocsp-response',
      knowledge: 'current',
    },
  ],
  suites: { signature: 'ecdsa-sha256', responderKey: 'ec-p256' },
  status: { trusted: ['good'], revoked: ['revoked'] },
  signer: 'issuer-named-by-the-question',
  /**
   * One answer speaks for one certificate, so a kept answer is keyed by the certificate the question named,
   * spelled as the digest of its bytes rather than as the bytes themselves, and the window that bounds how
   * long it may be kept is the response's own `nextUpdate`. The platform is absent because the responder is
   * indexed by a certificate and not by one.
   */
  cache: {
    keyMembers: ['origin', 'ocspCertificate'],
    answersCurrentQuestions: false,
    retainUntil: 'vendor-next-update',
  },
};

/** The origins a reader here weighs an answer of. A declaration with no reader is a route, not an answer. */
export const SERVED_ORIGINS: readonly ReadCollateralOrigin[] = [
  'intel-tcb-info',
  'intel-qe-identity',
  'intel-pck-crl',
  'amd-kds',
  'ocsp',
  'nvidia-rim',
];

const BY_ORIGIN: Record<ReadDocumentOrigin, IntelOriginDeclaration> = {
  'intel-tcb-info': INTEL_TCB_INFO,
  'intel-qe-identity': INTEL_QE_IDENTITY,
};

/** Every origin this file declares, read or not, keyed by the name a query uses. */
export const ORIGIN_DECLARATIONS: Record<CollateralOriginName, OriginDeclaration> = {
  ...BY_ORIGIN,
  'intel-pck-crl': INTEL_PCK_CRL,
  'amd-kds': AMD_KDS,
  'nvidia-rim': NVIDIA_RIM,
  ocsp: NVIDIA_OCSP,
};

/** Every name this file declares, in the order the declarations were written. */
export const DECLARED_ORIGINS = Object.keys(ORIGIN_DECLARATIONS) as readonly CollateralOriginName[];

/** The origins that are read, spelled for a sentence rather than joined with a repeated conjunction. */
function readOrigins(): string {
  return `${SERVED_ORIGINS.slice(0, -1).join(', ')} and ${SERVED_ORIGINS[SERVED_ORIGINS.length - 1] as string}`;
}

/**
 * The declaration for an origin, or the refusal that says this path is not read here.
 *
 * Every name `CollateralOriginName` carries has a declaration in this file and a reader that weighs its answer,
 * so the refusal is for a name outside the union and for a declaration that states no reader at all, which a
 * caller can only hold by building one, and which is answered with the route it is declared at, what a reader
 * would still need, and the origins that are read, so a caller learns which sentence to look up rather than
 * which name to retype. A name outside the map answers with the origins that are read alone.
 */
export function declarationFor(origin: CollateralOriginName): OriginDeclaration | { readonly refusal: CollateralRefusal } {
  if (origin === 'intel-tcb-info' || origin === 'intel-qe-identity') {
    return BY_ORIGIN[origin];
  }
  if (origin === 'intel-pck-crl') {
    return INTEL_PCK_CRL;
  }
  if (origin === 'amd-kds') {
    return AMD_KDS;
  }
  if (origin === 'ocsp') {
    return NVIDIA_OCSP;
  }
  const declared: OriginDeclaration | undefined = Object.hasOwn(ORIGIN_DECLARATIONS, origin)
    ? ORIGIN_DECLARATIONS[origin]
    : undefined;
  if (declared === undefined) {
    return {
      refusal: collateralRefusal(
        'COLLATERAL_ORIGIN_UNSUPPORTED',
        `${quoteOrDigest(origin)} is not read here, which serves ${readOrigins()}`,
        ['origin'],
      ),
    };
  }
  if (isDeclaredOnly(declared)) {
    return {
      refusal: collateralRefusal(
        'COLLATERAL_ORIGIN_UNSUPPORTED',
        `${origin} is declared at ${declared.host} but unread; this reads ${readOrigins()}; missing: ${declared.reader.lacks}`,
        ['origin'],
      ),
    };
  }
  return declared;
}

/**
 * The declaration as the reader of a served JSON document needs it, or the refusal for an origin that
 * reader has no arm for. Both envelope readers call this before one byte is parsed, so a declared-only
 * origin cannot be read as if its shape were Intel's.
 */
export function servedDocumentDeclaration(
  declaration: OriginDeclaration,
): IntelOriginDeclaration | { readonly refusal: CollateralRefusal } {
  if (isIntelDeclaration(declaration)) {
    return declaration;
  }
  // An origin with a reader here is supported, so what this arm cannot weigh is the envelope, not the origin.
  const code: CollateralErrorCode = hasReader(declaration)
    ? 'COLLATERAL_BLOB_UNREADABLE'
    : 'COLLATERAL_ORIGIN_UNSUPPORTED';
  return {
    refusal: collateralRefusal(
      code,
      `${declaration.name} answers as ${declaration.answer} and this reader weighs a served JSON document alone`,
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
  if (!isIntelDeclaration(declaration)) {
    return declaredUrl(query, declaration);
  }
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
 * The address a declared origin publishes, with the members this query supplies filled in.
 *
 * A route's path is a template, and a placeholder with no value in the query stops the address rather
 * than being sent as braces: the origin would answer a request for a name it never published. A POST route
 * is addressed the same way once the certificate and issuer an OCSP question states are present, because a
 * question that names no certificate has nothing for a responder to answer about.
 */
function declaredUrl(
  query: CollateralQuery,
  declaration: DeclaredOriginDeclaration | RimOriginDeclaration | CrlOriginDeclaration | VcekOriginDeclaration | OcspOriginDeclaration,
): string | { readonly refusal: CollateralRefusal } {
  const route = query.route == null
    ? declaration.routes[0]
    : declaration.routes.find((one) => one.name === query.route);
  if (route === undefined) {
    return {
      refusal: collateralRefusal(
        'COLLATERAL_INPUT_MISSING',
        `${declaration.name} declares no route named ${quoteOrDigest(query.route ?? 'nothing')}`,
        ['route'],
      ),
    };
  }
  if (route.method === 'POST') {
    const missing: CollateralInputName[] = [];
    if (query.ocspCertificate == null) {
      missing.push('ocspCertificate');
    }
    if (query.ocspIssuer == null) {
      missing.push('ocspIssuer');
    }
    if (missing.length > 0) {
      return {
        refusal: collateralRefusal(
          'COLLATERAL_INPUT_MISSING',
          `${declaration.name} states an OCSP question with a certificate and its issuer, and one was not given`,
          missing,
        ),
      };
    }
  }
  const missing: CollateralInputName[] = [];
  const path = route.path.replace(/\{([A-Za-z]+)\}/gu, (_whole, member: string) => routeMember(query, member, missing) ?? `{${member}}`);
  if (missing.length > 0) {
    return {
      refusal: collateralRefusal(
        'COLLATERAL_INPUT_MISSING',
        `${declaration.name} is asked at ${route.name} and the address needs ${missing.join(' and ')}`,
        missing,
      ),
    };
  }
  return `https://${declaration.host}${path}`;
}

/** One placeholder of a declared route, as the query spells it, or null where the query states none. */
function routeMember(query: CollateralQuery, member: string, missing: CollateralInputName[]): string | null {
  switch (member) {
    case 'ca':
      if (query.ca == null) {
        missing.push('ca');
        return null;
      }
      return query.ca;
    case 'product':
      if (query.product == null || !/^[A-Za-z0-9._-]{1,32}$/u.test(query.product)) {
        missing.push('product');
        return null;
      }
      return query.product;
    case 'hwid':
      // The measured bound: the route answers a chip id of 64 bytes, spelled as 128 hex characters, and
      // answers 400 for the 64-character spelling and 404 for a well-formed id it has no certificate for.
      if (query.hwid == null || !/^[0-9a-fA-F]{128}$/u.test(query.hwid)) {
        missing.push('hwid');
        return null;
      }
      return query.hwid.toLowerCase();
    case 'rimId':
      // No served sample pins the id's character set, so any non-empty id is taken and
      // percent-encoded rather than refused under a class nobody measured.
      if (query.rimId == null || query.rimId.length === 0) {
        missing.push('rimId');
        return null;
      }
      return encodeURIComponent(query.rimId);
    default:
      missing.push('route');
      return null;
  }
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
): string | { readonly missing: readonly CollateralInputName[]; readonly why?: string } {
  if (declaration.cache === null) {
    return {
      missing: [],
      why: `${declaration.name} declares no cache key yet: no reader states the identity and window a kept record belongs to`,
    };
  }
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
    case 'ca':
      return query.ca ?? null;
    case 'product':
      return query.product?.toLowerCase() ?? null;
    case 'hwid':
      return query.hwid?.toLowerCase() ?? null;
    // The certificate an OCSP answer is about is a run of bytes, and a key that copied them would put a
    // certificate's bytes where a record name belongs; the digest identifies the same certificate and is
    // the spelling the rest of this package prints a blob by.
    case 'ocspCertificate':
      return query.ocspCertificate == null ? null : sha256Hex(query.ocspCertificate);
    case 'level':
      return query.level === null ? null : `${query.level.by}=${query.level.value}`;
  }
}
