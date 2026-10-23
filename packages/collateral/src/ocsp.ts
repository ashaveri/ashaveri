import { sha1 } from '@noble/hashes/legacy.js';
import { equalBytes, type ParsedCertificate } from '@ashaveri/attest-core';
import { sha256Hex } from './bytes.js';
import { collateralRefusal, quoteOrDigest, type CollateralRefusal } from './errors.js';
import { bitStringContent, contentOf, CRL_REASONS, decodeOid, expectTag, fail, parseTime, positiveInteger, readTlv, type Tlv } from './der.js';
import { hasReader, isOcspDeclaration, type OcspOriginDeclaration } from './intel-origin.js';
import { parseCertificates, parsePinned, reachAnchor, verifiesUnderLeaf, type Reading } from './read.js';
import type { CollateralQuery, SignedWindow } from './types.js';

/**
 * The DER shapes one OCSP question and its answer take, as RFC 6960 names them.
 *
 * Every member spelled here is a member that specification states, and every refusal says which of them the
 * answer did not carry: nothing here is inferred from what one responder was seen to send, because no answer of
 * the responder's is kept in this repository. The request writer exists so a question is asked under the same
 * names the answer is read by, rather than a second spelling of `CertID` maintained somewhere else. The module
 * is read as `EXPLICIT TAGS`, which is what RFC 6960 states it as, and the one place it says otherwise is
 * `CertStatus`, whose three choices are stated IMPLICIT and are read by the tags that follows from that.
 */

/** The one response type this path reads, and the one hash a `CertID` is compared under. */
const OID_OCSP_BASIC = '1.3.6.1.5.5.7.48.1.1';
const OID_SHA1 = '1.3.14.3.2.26';

/** The suites this path can weigh, keyed by the OID an answer's identifier carries. */
const SUITES: Readonly<Record<string, string>> = {
  '1.2.840.10045.4.3.2': 'ecdsa-sha256',
};

/** RFC 6960's response statuses, named so a refusal says which one answered rather than leaving a figure. */
const RESPONSE_STATUSES: Readonly<Record<number, string>> = {
  0: 'successful',
  1: 'malformedRequest',
  2: 'internalError',
  3: 'tryLater',
  5: 'sigRequired',
  6: 'unauthorized',
};

/** The three `certStatus` tags, as an IMPLICIT choice over NULL, RevokedInfo and UnknownInfo. */
const STATUS_GOOD = 0x80;
const STATUS_REVOKED = 0xa1;
const STATUS_UNKNOWN = 0x82;

/** What an OCSP read answered: the believed statement, or the refusal that says why nothing was believed. */
export type OcspReadOutcome = { readonly read: OcspReading } | { readonly refusal: CollateralRefusal };

/**
 * The statement one answer makes about the certificate asked about, once its signature has been believed.
 *
 * The standing is the answer's own word, copied rather than sorted: which of the two lists of the declaration
 * it sits in, and so whether it is a trust or a revocation, is the classification's reading rather than this
 * reader's. `revokedAt` is the instant a `revoked` word states and null for one that states no revocation, and
 * `reasonCode` is the reason beside it, read as the number the standing carries rather than sorted into a word.
 */
export interface OcspReading {
  /** The responder's own word for the certificate's standing. */
  readonly certStatus: 'good' | 'revoked' | 'unknown';
  readonly revokedAt: number | null;
  /**
   * RFC 5280's `cRLReason` code a `revoked` standing carries in its `revocationReason`, or null for one that
   * states no reason and for a standing that states no revocation. Reading it is this reader's job; which code
   * a revocation is read from is decided by the classification, the same half that decides it for a list.
   */
  readonly reasonCode: number | null;
  /** The registry name for that code where one exists, or null for a code this reader does not name. */
  readonly reason: string | null;
  /** The window the answer states for this certificate, in Unix seconds. */
  readonly window: SignedWindow;
  /** `producedAt`: the instant the responder states it signed. */
  readonly producedAt: number;
  readonly serialHex: string;
  /** sha256 of the whole answer, as the bytes arrived. */
  readonly digest: string;
  /** sha256 of the pinned certificate the issuer chain reached. */
  readonly anchorDigest: string;
  /** The answer first, then every certificate the answer itself presented, in the order it presented them. */
  readonly blobs: readonly Uint8Array[];
}

/**
 * Reads a DER `OCSPResponse` and believes it in the order the bytes require.
 *
 * The structure is parsed before anything is believed, because the response states which responder signed it
 * and that is what selects the certificate the signature is weighed under. The responder is then bound to the
 * issuer the question names, that issuer is walked to a root the caller pinned, and only then is the signature
 * checked over the DER of `tbsResponseData` as the answer arrived, tag and length included. Nothing is
 * re-encoded: `blobs` holds the response and the certificates the response itself presented, byte for byte.
 *
 * Four rules decide what the answer can be relied on for, and each is stated on the declaration this path
 * reads rather than remembered here: the signer is the issuer the question names, because the extension that
 * delegates an OCSP signing authority is read by nothing in this repository's certificate parser; the suite is
 * the one this package weighs elsewhere, and an answer wearing another is refused as unweighed rather than as
 * unrevoked; the `CertID` is compared with the certificate and issuer the question states, so an answer about
 * another certificate answers `COLLATERAL_IDENTITY_MISMATCH` rather than carrying a standing over from a
 * neighbour; and the standing is the answer's own word, which the classification reads out of the
 * declaration's two lists, so `unknown` is refused there as a word this package has no rule for. The
 * `revocationReason` beside a `revoked` instant is read as RFC 5280's code and named from the table `der.ts`
 * shares with the revocation list, so one reason code means one thing to each reader of this package; which
 * codes a revocation is read from is decided beside the list's own entries rather than here. No extension the
 * answer carries that is not marked critical is read.
 */
export function readOcspResponse(body: Uint8Array, reading: Reading): OcspReadOutcome {
  if (!isOcspDeclaration(reading.declaration)) {
    return {
      refusal: collateralRefusal(
        hasReader(reading.declaration) ? 'COLLATERAL_BLOB_UNREADABLE' : 'COLLATERAL_ORIGIN_UNSUPPORTED',
        `${reading.declaration.name} answers as ${reading.declaration.answer} and this reader weighs a DER OCSPResponse alone`,
      ),
    };
  }
  const declaration: OcspOriginDeclaration = reading.declaration;
  if (body.byteLength === 0) {
    return unreadable(declaration, 'the answer is empty');
  }
  if (body.byteLength > declaration.maxResponseBytes) {
    return unreadable(
      declaration,
      `the answer is ${String(body.byteLength)} bytes, over the ${String(declaration.maxResponseBytes)} this path reads`,
    );
  }
  let parsed: { readonly answered: AnsweredResponse } | { readonly status: number } | { readonly refusal: CollateralRefusal };
  try {
    parsed = parseResponse(body, declaration);
  } catch (err) {
    parsed = unreadable(declaration, err instanceof Error ? err.message : 'the DER answer did not parse');
  }
  if ('refusal' in parsed) {
    return parsed;
  }
  if (!('answered' in parsed)) {
    const name = RESPONSE_STATUSES[parsed.status] ?? `status ${String(parsed.status)}`;
    return {
      refusal: collateralRefusal(
        declaration.refusals.status,
        `the responder answered ${name} rather than with a signed statement about a certificate`,
      ),
    };
  }
  const answered = parsed.answered;
  const asked = askedPair(reading.query, declaration);
  if ('refusal' in asked) {
    return asked;
  }
  const delegated = delegatedResponder(declaration, answered.responder, answered.presented, asked.issuer);
  if (delegated !== null) {
    return { refusal: delegated };
  }
  const pinned = parsePinned(reading.query.roots, declaration);
  if ('refusal' in pinned) {
    return pinned;
  }
  const anchor = reachAnchor([asked.issuer, ...answered.presented], pinned, reading, declaration);
  if ('refusal' in anchor) {
    return anchor;
  }
  if (!verifiesUnderLeaf(asked.issuer, answered.signedBytes, answered.signature)) {
    return {
      refusal: collateralRefusal(
        declaration.refusals.signature,
        'the signature over the response data does not hold under the issuer the question names',
      ),
    };
  }
  const serial = bindCertId(declaration, asked, answered);
  if ('refusal' in serial) {
    return serial;
  }
  const window = windowOf(declaration, answered);
  if ('refusal' in window) {
    return window;
  }
  const standing = readStatus(declaration, answered.single);
  if ('refusal' in standing) {
    return standing;
  }
  return {
    read: {
      certStatus: standing.status,
      revokedAt: standing.revokedAt,
      reasonCode: standing.reasonCode,
      reason: standing.reasonCode === null ? null : CRL_REASONS[standing.reasonCode] ?? null,
      window,
      producedAt: answered.producedAt,
      serialHex: serial.serialHex,
      digest: sha256Hex(body),
      anchorDigest: anchor.digest,
      blobs: [body, ...answered.presented.map((one) => one.raw)],
    },
  };
}

/** The signed statement one answer carries, read out of the bytes before any of it is believed. */
interface AnsweredResponse {
  /** The `tbsResponseData` exactly as it arrived, tag and length included, which is what the signature covers. */
  readonly signedBytes: Uint8Array;
  /** The `signature` BIT STRING's contents, less the unused-bits byte. */
  readonly signature: Uint8Array;
  /** The certificates the answer presents, in the order it presents them. */
  readonly presented: readonly ParsedCertificate[];
  /** The responder identity, as one of the two spellings RFC 6960 gives it. */
  readonly responder: ResponderId;
  readonly producedAt: number;
  readonly single: SingleAnswer;
}

/** The two spellings RFC 6960 gives a responder identity: a DER `Name`, or the hash of a public key. */
type ResponderId =
  | { readonly by: 'name'; readonly name: Uint8Array }
  | { readonly by: 'key'; readonly hash: Uint8Array };

/** The one `SingleResponse` an answer holds, with the pieces the appraisal reads off it. */
interface SingleAnswer {
  readonly certId: Uint8Array;
  readonly statusTag: number;
  readonly statusContent: Uint8Array;
  readonly thisUpdate: number;
  /** The instant RFC 6960 states at or before which newer information is available, or null where none is stated. */
  readonly nextUpdate: number | null;
}

/**
 * The whole `OCSPResponse`, parsed field by field over the bytes as they arrived.
 *
 * A status that is not `successful` carries no `responseBytes` at all, which RFC 6960 states as the rule rather
 * than as an option, so this stops at the figure and the answer's words never become a verdict. The suite
 * inside `BasicOCSPResponse` is required to name one of the shapes in `SUITES`, which is read as a shape and
 * decided by the primitives in `read.ts`; a parameter rule written here would be a second answer to what a
 * signature is.
 */
function parseResponse(
  body: Uint8Array,
  declaration: OcspOriginDeclaration,
): { readonly answered: AnsweredResponse } | { readonly status: number } | { readonly refusal: CollateralRefusal } {
  const outer = readTlv(body, 0, body.byteLength, 'OCSPResponse');
  expectTag(outer, 0x30, 'OCSPResponse');
  if (outer.end !== body.byteLength) {
    fail('trailing data after the OCSPResponse');
  }
  const statusTlv = readTlv(body, outer.contentStart, outer.end, 'responseStatus');
  expectTag(statusTlv, 0x0a, 'responseStatus');
  if (statusTlv.end - statusTlv.contentStart !== 1) {
    fail('responseStatus is not one byte');
  }
  const status = body[statusTlv.contentStart] as number;
  if (status !== 0) {
    return { status };
  }
  let at = statusTlv.end;
  const wrapper = readTlv(body, at, outer.end, 'responseBytes');
  expectTag(wrapper, 0xa0, 'responseBytes');
  at = wrapper.end;
  if (at !== outer.end) {
    fail('trailing data after responseBytes');
  }
  const pair = readTlv(body, wrapper.contentStart, wrapper.end, 'ResponseBytes');
  expectTag(pair, 0x30, 'ResponseBytes');
  if (pair.end !== wrapper.end) {
    fail('trailing data inside responseBytes');
  }
  const respId = readTlv(body, pair.contentStart, pair.end, 'respId');
  expectTag(respId, 0x06, 'respId');
  const respIdOid = decodeOid(body, respId);
  if (respIdOid !== OID_OCSP_BASIC) {
    return unreadable(declaration, `the answer carries a ${respIdOid} response, and this path reads the BasicOCSPResponse alone`);
  }
  const encoded = readTlv(body, respId.end, pair.end, 'response');
  expectTag(encoded, 0x04, 'response');
  if (encoded.end !== pair.end) {
    fail('trailing data inside ResponseBytes');
  }
  const basic = body.subarray(encoded.contentStart, encoded.end);
  const answered = parseBasicResponse(basic, declaration);
  if ('refusal' in answered) {
    return answered;
  }
  return { answered: answered.answered };
}

/** The `BasicOCSPResponse` inside the answer's octet string, and the span its signature covers. */
function parseBasicResponse(
  basic: Uint8Array,
  declaration: OcspOriginDeclaration,
): { readonly answered: AnsweredResponse } | { readonly refusal: CollateralRefusal } {
  const outer = readTlv(basic, 0, basic.byteLength, 'BasicOCSPResponse');
  expectTag(outer, 0x30, 'BasicOCSPResponse');
  if (outer.end !== basic.byteLength) {
    fail('trailing data after the BasicOCSPResponse');
  }
  const tbs = readTlv(basic, outer.contentStart, outer.end, 'tbsResponseData');
  expectTag(tbs, 0x30, 'tbsResponseData');
  let at = tbs.end;
  const algorithm = readTlv(basic, at, outer.end, 'signatureAlgorithm');
  expectTag(algorithm, 0x30, 'signatureAlgorithm');
  const suite = suiteOf(basic, algorithm, declaration);
  if ('refusal' in suite) {
    return suite;
  }
  at = algorithm.end;
  const signatureTlv = readTlv(basic, at, outer.end, 'signature');
  expectTag(signatureTlv, 0x03, 'signature');
  const signature = bitStringContent(basic, signatureTlv, 'signature');
  at = signatureTlv.end;
  const presented: ParsedCertificate[] = [];
  if (at < outer.end) {
    const certs = readTlv(basic, at, outer.end, 'certs');
    expectTag(certs, 0xa0, 'certs');
    at = certs.end;
    const list = readTlv(basic, certs.contentStart, certs.end, 'certs list');
    expectTag(list, 0x30, 'certs list');
    if (list.end !== certs.end) {
      fail('trailing data inside the certificates an answer presents');
    }
    let one = list.contentStart;
    while (one < list.end) {
      const element = readTlv(basic, one, list.end, 'certificate');
      expectTag(element, 0x30, 'certificate');
      const parsed = parseCertificates(basic.subarray(element.start, element.end));
      if (parsed === null || parsed.length !== 1) {
        fail('a certificate an answer presents does not parse as one X.509 certificate');
      }
      presented.push(parsed[0] as ParsedCertificate);
      one = element.end;
    }
  }
  if (at !== outer.end) {
    fail('trailing data inside the BasicOCSPResponse');
  }
  const data = parseResponseData(basic.subarray(tbs.start, tbs.end));
  if ('refusal' in data) {
    return data;
  }
  if (suite.read !== declaration.suites.signature) {
    return {
      refusal: collateralRefusal(
        declaration.refusals.signature,
        `the answer is signed ${suite.stated} and this path weighs ${declaration.suites.signature} alone`,
      ),
    };
  }
  return { answered: { signedBytes: basic.slice(tbs.start, tbs.end), signature, presented, ...data.parsed } };
}

/** The suite an answer's algorithm identifier names, refused where it carries parameters this path reads none of. */
function suiteOf(
  body: Uint8Array,
  sequence: Tlv,
  declaration: OcspOriginDeclaration,
): { readonly stated: string; readonly read: string } | { readonly refusal: CollateralRefusal } {
  const oidTlv = readTlv(body, sequence.contentStart, sequence.end, 'signature algorithm oid');
  expectTag(oidTlv, 0x06, 'signature algorithm oid');
  if (oidTlv.end !== sequence.end) {
    return unreadable(declaration, "the answer's signature algorithm carries parameters this path reads none of");
  }
  const oid = decodeOid(body, oidTlv);
  const named = SUITES[oid];
  return named === undefined
    ? { stated: oid, read: 'unsupported' }
    : { stated: named, read: named };
}

/** The `ResponseData`: the version it states, who signed, when, and the one answer about one certificate. */
function parseResponseData(
  tbs: Uint8Array,
): { readonly parsed: Pick<AnsweredResponse, 'responder' | 'producedAt' | 'single'> } | { readonly refusal: CollateralRefusal } {
  const outer = readTlv(tbs, 0, tbs.byteLength, 'ResponseData');
  expectTag(outer, 0x30, 'ResponseData');
  if (outer.end !== tbs.byteLength) {
    fail('trailing data after the ResponseData');
  }
  let at = outer.contentStart;
  if (tbs[at] === 0xa0) {
    const version = readTlv(tbs, at, outer.end, 'version');
    const stated = positiveInteger(tbs, readTlv(tbs, version.contentStart, version.end, 'version'), 'version');
    if (stated !== 0n) {
      fail(`the answer states version ${stated.toString()}, and this path reads the version RFC 6960 defines`);
    }
    at = version.end;
  }
  const responderTlv = readTlv(tbs, at, outer.end, 'responderID');
  const responder: ResponderId = responderTlv.tag === 0xa1
    ? { by: 'name', name: responderName(tbs, responderTlv) }
    : responderTlv.tag === 0xa2
      ? { by: 'key', hash: responderKeyHash(tbs, responderTlv) }
      : fail(`responderID is tag 0x${responderTlv.tag.toString(16)}, neither byName nor byKey`);
  at = responderTlv.end;
  const producedTlv = readTlv(tbs, at, outer.end, 'producedAt');
  const producedAt = parseTime(tbs, producedTlv, 'producedAt');
  at = producedTlv.end;
  const responses = readTlv(tbs, at, outer.end, 'responses');
  expectTag(responses, 0x30, 'responses');
  at = responses.end;
  const entries: Uint8Array[] = [];
  let entry = responses.contentStart;
  while (entry < responses.end) {
    const one = readTlv(tbs, entry, responses.end, 'SingleResponse');
    expectTag(one, 0x30, 'SingleResponse');
    entries.push(tbs.slice(one.start, one.end));
    entry = one.end;
  }
  if (entries.length !== 1) {
    fail(`the answer holds ${String(entries.length)} SingleResponse entries, and this path asks about one certificate`);
  }
  if (at < outer.end) {
    const wrapper = readTlv(tbs, at, outer.end, 'responseExtensions');
    expectTag(wrapper, 0xa1, 'responseExtensions');
    skipExtensions(tbs, wrapper, 'response extension');
    at = wrapper.end;
  }
  if (at !== outer.end) {
    fail('trailing data inside the ResponseData');
  }
  const single = parseSingleResponse(entries[0] as Uint8Array);
  if ('refusal' in single) {
    return single;
  }
  return { parsed: { responder, producedAt, single: single.single } };
}

/** The one `SingleResponse` an answer holds, with its status, window and extension list located. */
function parseSingleResponse(single: Uint8Array): { readonly single: SingleAnswer } | { readonly refusal: CollateralRefusal } {
  const outer = readTlv(single, 0, single.byteLength, 'SingleResponse');
  expectTag(outer, 0x30, 'SingleResponse');
  if (outer.end !== single.byteLength) {
    fail('trailing data after the SingleResponse');
  }
  let at = outer.contentStart;
  const certId = readTlv(single, at, outer.end, 'CertID');
  expectTag(certId, 0x30, 'CertID');
  at = certId.end;
  const status = readTlv(single, at, outer.end, 'certStatus');
  at = status.end;
  const thisUpdateTlv = readTlv(single, at, outer.end, 'thisUpdate');
  const thisUpdate = parseTime(single, thisUpdateTlv, 'thisUpdate');
  at = thisUpdateTlv.end;
  let nextUpdate: number | null = null;
  if (at < outer.end && single[at] === 0xa0) {
    const wrapper = readTlv(single, at, outer.end, 'nextUpdate');
    nextUpdate = parseTime(single, readTlv(single, wrapper.contentStart, wrapper.end, 'nextUpdate'), 'nextUpdate');
    at = wrapper.end;
  }
  if (at < outer.end) {
    const wrapper = readTlv(single, at, outer.end, 'singleExtensions');
    expectTag(wrapper, 0xa1, 'singleExtensions');
    skipExtensions(single, wrapper, 'single response extension');
    at = wrapper.end;
  }
  if (at !== outer.end) {
    fail('trailing data inside the SingleResponse');
  }
  return {
    single: {
      certId: single.slice(certId.start, certId.end),
      statusTag: status.tag,
      statusContent: single.slice(status.contentStart, status.end),
      thisUpdate,
      nextUpdate,
    },
  };
}

/** The DER `Name` inside a byName responder identity, wrapper and all, which is what a name hash is taken over. */
function responderName(tbs: Uint8Array, tlv: Tlv): Uint8Array {
  const name = readTlv(tbs, tlv.contentStart, tlv.end, 'Name');
  expectTag(name, 0x30, 'Name');
  if (name.end !== tlv.end) {
    fail('trailing data inside the responder name');
  }
  return tbs.slice(name.start, name.end);
}

/** The `KeyHash` inside a byKey responder identity: the OCTET STRING RFC 6960 states it as. */
function responderKeyHash(tbs: Uint8Array, tlv: Tlv): Uint8Array {
  const hash = readTlv(tbs, tlv.contentStart, tlv.end, 'KeyHash');
  expectTag(hash, 0x04, 'KeyHash');
  if (hash.end !== tlv.end) {
    fail('trailing data inside the responder key hash');
  }
  return contentOf(tbs, hash);
}

/** One extension list an answer carries, refused where a critical one is a rule nobody here reads. */
function skipExtensions(body: Uint8Array, wrapper: Tlv, context: string): void {
  const list = readTlv(body, wrapper.contentStart, wrapper.end, `${context} list`);
  expectTag(list, 0x30, `${context} list`);
  if (list.end !== wrapper.end) {
    fail(`trailing data inside the ${context} list`);
  }
  let at = list.contentStart;
  while (at < list.end) {
    const extension = readTlv(body, at, list.end, context);
    expectTag(extension, 0x30, context);
    let inner = extension.contentStart;
    const oidTlv = readTlv(body, inner, extension.end, `${context} oid`);
    expectTag(oidTlv, 0x06, `${context} oid`);
    const oid = decodeOid(body, oidTlv);
    inner = oidTlv.end;
    let critical = false;
    if (inner < extension.end && body[inner] === 0x01) {
      const flag = readTlv(body, inner, extension.end, `${context} critical`);
      if (flag.end - flag.contentStart !== 1) {
        fail(`a ${context} critical flag is not one byte`);
      }
      critical = (body[flag.contentStart] as number) !== 0;
      inner = flag.end;
    }
    const value = readTlv(body, inner, extension.end, `${context} value`);
    expectTag(value, 0x04, `${context} value`);
    if (value.end !== extension.end) {
      fail(`trailing data inside a ${context}`);
    }
    if (critical) {
      fail(`the answer states critical extension ${oid}, which this reader does not know`);
    }
    at = extension.end;
  }
}

/**
 * The certificate and issuer the question states, each read as the one certificate a question names.
 *
 * The pair is checked against itself before anything is asked: a question whose `ocspIssuer` does not carry the
 * issuer name the certificate states has no answer any responder could give, and the request built from it
 * would be a question about a pair that does not exist.
 */
function askedPair(
  query: CollateralQuery,
  declaration: OcspOriginDeclaration,
): { readonly certificate: ParsedCertificate; readonly issuer: ParsedCertificate } | { readonly refusal: CollateralRefusal } {
  const missing: ('ocspCertificate' | 'ocspIssuer')[] = [];
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
        `${declaration.name} answers about one certificate and the issuer that signed it, and the question named neither`,
        missing,
      ),
    };
  }
  const certificate = oneCertificate(query.ocspCertificate as Uint8Array, declaration, 'certificate');
  if ('refusal' in certificate) {
    return certificate;
  }
  const issuer = oneCertificate(query.ocspIssuer as Uint8Array, declaration, 'issuer');
  if ('refusal' in issuer) {
    return issuer;
  }
  if (!equalBytes(certificate.parsed.issuer, issuer.parsed.subject)) {
    return {
      refusal: collateralRefusal(
        declaration.refusals.identity,
        'the issuer the question names does not carry the issuer name the certificate states',
        ['ocspIssuer'],
      ),
    };
  }
  return { certificate: certificate.parsed, issuer: issuer.parsed };
}

function oneCertificate(
  blob: Uint8Array,
  declaration: OcspOriginDeclaration,
  which: string,
): { readonly parsed: ParsedCertificate } | { readonly refusal: CollateralRefusal } {
  const parsed = parseCertificates(blob);
  if (parsed === null) {
    return unreadable(declaration, `the ${which} the question states does not parse as X.509`);
  }
  if (parsed.length !== 1) {
    return unreadable(declaration, `the ${which} the question states holds ${String(parsed.length)} certificates, and a question names one`);
  }
  return { parsed: parsed[0] as ParsedCertificate };
}

/**
 * The refusal for an answer whose signer is not the issuer the question names, or null where it is.
 *
 * RFC 6960 lets a CA answer for its own certificates or delegate that work to another certificate, and the
 * delegation rides in an extension this repository's certificate parser states no rule for reading. So the
 * issuer the question names is the only signer this path weighs, and a certificate the answer presents that
 * wears the responder identity but is not those bytes is refused as the answer of a responder nobody weighed
 * rather than read as a statement about this certificate.
 */
function delegatedResponder(
  declaration: OcspOriginDeclaration,
  responder: ResponderId,
  presented: readonly ParsedCertificate[],
  issuer: ParsedCertificate,
): CollateralRefusal | null {
  const claims = presented.filter((one) => identityMatches(responder, one));
  if (claims.length > 1) {
    return collateralRefusal(
      declaration.refusals.signature,
      `the answer presents ${String(claims.length)} certificates for the responder identity it states, and which one signed it is not stated`,
    );
  }
  if (claims.length === 1 && !equalBytes((claims[0] as ParsedCertificate).raw, issuer.raw)) {
    return collateralRefusal(
      declaration.refusals.signature,
      'the answer is signed by a certificate other than the issuer the question names, and an OCSP signing authority delegated by extension is not read here',
    );
  }
  if (!identityMatches(responder, issuer)) {
    return collateralRefusal(
      declaration.refusals.signature,
      'the responder identity the answer states is not the issuer the question names',
    );
  }
  return null;
}

/** Whether a certificate is the one a stated responder identity names. */
function identityMatches(responder: ResponderId, cert: ParsedCertificate): boolean {
  return responder.by === 'name'
    ? equalBytes(cert.subject, contentOf(responder.name, readTlv(responder.name, 0, responder.name.byteLength, 'Name')))
    : equalBytes(issuerKeyHash(cert), responder.hash);
}

/** The hash RFC 6960 states for an issuer identity: SHA-1 over the subject public key value, tag and length excluded. */
function issuerKeyHash(cert: ParsedCertificate): Uint8Array {
  const spki = readTlv(cert.subjectPublicKeyInfo, 0, cert.subjectPublicKeyInfo.byteLength, 'SubjectPublicKeyInfo');
  const algorithm = readTlv(cert.subjectPublicKeyInfo, spki.contentStart, spki.end, 'algorithm');
  const bits = readTlv(cert.subjectPublicKeyInfo, algorithm.end, spki.end, 'subjectPublicKey');
  expectTag(bits, 0x03, 'subjectPublicKey');
  return Uint8Array.from(sha1(bitStringContent(cert.subjectPublicKeyInfo, bits, 'subjectPublicKey')));
}

/**
 * The hash RFC 6960 states for an issuer name: SHA-1 over the DER encoding of the issuer's name field.
 *
 * The certificate parser keeps a `Name` as its content, without the SEQUENCE tag and length, and the DER
 * encoding a hash is taken over is the whole field, so the wrapper the parser left out is put back before the
 * hash is taken rather than hashing something a responder would never have written.
 */
function issuerNameHash(cert: ParsedCertificate): Uint8Array {
  return Uint8Array.from(sha1(derName(cert.subject)));
}

/** The DER `Name` a certificate states, wrapper and all, which is what a question is written with. */
function derName(name: Uint8Array): Uint8Array {
  return wrap(0x30, name);
}

/**
 * The `CertID` of the one answer, compared with the certificate and issuer the question states.
 *
 * The three members are the ones RFC 6960 defines a `CertID` by, and all three are compared: the two hashes
 * bind the issuer and the serial binds the certificate that issuer signed. The serial is read as the number it
 * names rather than as the bytes that pad it, because a query spells a serial in hex and the DER carries the
 * leading zero a high bit forces.
 */
function bindCertId(
  declaration: OcspOriginDeclaration,
  asked: { readonly certificate: ParsedCertificate; readonly issuer: ParsedCertificate },
  answered: AnsweredResponse,
): { readonly serialHex: string } | { readonly refusal: CollateralRefusal } {
  const certId = answered.single.certId;
  const outer = readTlv(certId, 0, certId.byteLength, 'CertID');
  expectTag(outer, 0x30, 'CertID');
  let at = outer.contentStart;
  const algorithm = readTlv(certId, at, outer.end, 'CertID hash algorithm');
  expectTag(algorithm, 0x30, 'CertID hash algorithm');
  const hashOid = decodeOid(certId, readTlv(certId, algorithm.contentStart, algorithm.end, 'CertID hash oid'));
  if (hashOid !== OID_SHA1) {
    return unreadable(declaration, `the answer's CertID hashes with ${hashOid}, which this path states no rule for comparing`);
  }
  at = algorithm.end;
  const nameHash = readTlv(certId, at, outer.end, 'issuerNameHash');
  expectTag(nameHash, 0x04, 'issuerNameHash');
  at = nameHash.end;
  const keyHash = readTlv(certId, at, outer.end, 'issuerKeyHash');
  expectTag(keyHash, 0x04, 'issuerKeyHash');
  at = keyHash.end;
  const serialTlv = readTlv(certId, at, outer.end, 'serialNumber');
  expectTag(serialTlv, 0x02, 'serialNumber');
  if (serialTlv.end !== outer.end) {
    fail('trailing data inside the CertID');
  }
  const serialHex = positiveInteger(certId, serialTlv, 'serialNumber').toString(16);
  if (!equalBytes(contentOf(certId, nameHash), issuerNameHash(asked.issuer))
    || !equalBytes(contentOf(certId, keyHash), issuerKeyHash(asked.issuer))) {
    return {
      refusal: collateralRefusal(
        declaration.refusals.identity,
        'the answer is about a certificate issued by somebody other than the issuer the question names',
        ['ocspCertificate', 'ocspIssuer'],
      ),
    };
  }
  if (serialHex !== serialValue(asked.certificate.serial)) {
    return {
      refusal: collateralRefusal(
        declaration.refusals.identity,
        `the answer is about serial ${quoteOrDigest(serialHex)} and the question asked about ${quoteOrDigest(serialValue(asked.certificate.serial))}`,
        ['ocspCertificate'],
      ),
    };
  }
  return { serialHex };
}

/** A serial as the number its DER INTEGER content states, which is how a query and an answer can be compared. */
function serialValue(bytes: Uint8Array): string {
  let value = 0n;
  for (const one of bytes) {
    value = (value << 8n) | BigInt(one);
  }
  return value.toString(16);
}

/**
 * The window the answer states for the certificate asked about, which is the span its word stands for.
 *
 * `thisUpdate` is the instant the responder states the standing from, and `nextUpdate` the instant at or before
 * which newer information is available; an answer that states no `nextUpdate` states no end to its own reach,
 * so nothing here can say how long it may be kept and it is refused rather than bounded by a number this path
 * invented.
 */
function windowOf(declaration: OcspOriginDeclaration, answered: AnsweredResponse): SignedWindow | { readonly refusal: CollateralRefusal } {
  const until = answered.single.nextUpdate;
  if (until === null) {
    return unreadable(
      declaration,
      'the answer states no nextUpdate, so it names no end to its own reach and no window this path can weigh',
    );
  }
  if (until <= answered.single.thisUpdate) {
    return unreadable(declaration, 'the window the answer states closes at or before the instant it opens');
  }
  return { from: answered.single.thisUpdate, until };
}

/** The standing the answer states, copied rather than inferred, and the instant and reason a `revoked` word carries. */
function readStatus(
  declaration: OcspOriginDeclaration,
  single: SingleAnswer,
): {
  readonly status: 'good' | 'revoked' | 'unknown';
  readonly revokedAt: number | null;
  readonly reasonCode: number | null;
} | { readonly refusal: CollateralRefusal } {
  if (single.statusTag === STATUS_GOOD) {
    return { status: 'good', revokedAt: null, reasonCode: null };
  }
  if (single.statusTag === STATUS_UNKNOWN) {
    return { status: 'unknown', revokedAt: null, reasonCode: null };
  }
  if (single.statusTag !== STATUS_REVOKED) {
    return unreadable(
      declaration,
      `the answer states a certStatus of tag 0x${single.statusTag.toString(16)}, which RFC 6960 states no standing for`,
    );
  }
  const body = single.statusContent;
  const time = readTlv(body, 0, body.byteLength, 'revocationTime');
  const revokedAt = parseTime(body, time, 'revocationTime');
  let reasonCode: number | null = null;
  let at = time.end;
  if (at < body.byteLength) {
    const reason = readTlv(body, at, body.byteLength, 'revocationReason');
    expectTag(reason, 0xa0, 'revocationReason');
    const code = readTlv(body, reason.contentStart, reason.end, 'revocationReason');
    expectTag(code, 0x0a, 'revocationReason');
    reasonCode = Number(positiveInteger(body, code, 'revocationReason'));
    if (code.end !== reason.end) {
      fail('trailing data inside the revocation reason');
    }
    at = reason.end;
  }
  if (at !== body.byteLength) {
    fail('trailing data inside the revoked standing');
  }
  return { status: 'revoked', revokedAt, reasonCode };
}

function unreadable(declaration: OcspOriginDeclaration, why: string): { readonly refusal: CollateralRefusal } {
  return { refusal: collateralRefusal(declaration.refusals.envelope, why) };
}

/**
 * The DER question one certificate is asked with: a `CertID` for the pair the caller names, inside the one
 * request a single answer is expected from.
 *
 * The request carries no nonce, because a nonce is an answer's binding to a moment and this package states no
 * rule for reading one back, and no signature, because RFC 6960 puts a request's signature in the hand of
 * whoever the responder would have to recognize, which is a decision about a deployment rather than a reading.
 * The `version`, the `requestorName` and both extension slots are left out rather than written as defaults, so
 * the bytes are the smallest question that asks this certificate.
 */
export function buildOcspRequest(
  certificate: Uint8Array,
  issuer: Uint8Array,
  declaration: OcspOriginDeclaration,
): Uint8Array | { readonly refusal: CollateralRefusal } {
  const asked = askedPair({ ...BLANK_QUERY, ocspCertificate: certificate, ocspIssuer: issuer }, declaration);
  if ('refusal' in asked) {
    return asked;
  }
  const certId = wrap(0x30, concat([
    wrap(0x30, oidBytes(OID_SHA1)),
    wrap(0x04, issuerNameHash(asked.issuer)),
    wrap(0x04, issuerKeyHash(asked.issuer)),
    wrap(0x02, asked.certificate.serial),
  ]));
  return wrap(0x30, wrap(0x30, wrap(0x30, wrap(0x30, certId))));
}

/** The query a request build reads no field of, so the pair is checked by the one function that checks pairs. */
const BLANK_QUERY: CollateralQuery = {
  origin: 'ocsp',
  platform: 'sgx',
  cpuType: null,
  level: null,
  appraisalAt: null,
  roots: [],
  retained: null,
  onAbsent: 'unassessed',
};

function oidBytes(dotted: string): Uint8Array {
  const arcs = dotted.split('.').map((arc) => Number(arc));
  const first = arcs[0] ?? 0;
  const second = arcs[1] ?? 0;
  const bytes: number[] = [first * 40 + second];
  for (const arc of arcs.slice(2)) {
    const encoded: number[] = [];
    let rest = arc;
    do {
      encoded.unshift(rest & 0x7f);
      rest = Math.floor(rest / 128);
    } while (rest > 0);
    for (let index = 0; index < encoded.length; index += 1) {
      bytes.push(index === encoded.length - 1 ? (encoded[index] as number) : (encoded[index] as number) | 0x80);
    }
  }
  return Uint8Array.from(bytes);
}

function wrap(tag: number, content: Uint8Array): Uint8Array {
  const length = content.byteLength;
  if (length < 0x80) {
    return concat([Uint8Array.of(tag, length), content]);
  }
  const encoded: number[] = [];
  let rest = length;
  while (rest > 0) {
    encoded.unshift(rest & 0xff);
    rest = Math.floor(rest / 256);
  }
  return concat([Uint8Array.of(tag, 0x80 | encoded.length, ...encoded), content]);
}

function concat(parts: readonly Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((total, part) => total + part.byteLength, 0));
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.byteLength;
  }
  return out;
}
