import { p256 } from '@noble/curves/nist.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { equalBytes, parseCertificateChain, type ParsedCertificate } from '@ashaveri/attest-core';
import { fromBase64, fromBase64Url, sha256Hex, utf8 } from './bytes.js';
import { collateralRefusal, quoteOrDigest, type CollateralRefusal } from './errors.js';
import type { OriginDeclaration } from './intel-origin.js';
import type { CollateralQuery, IntelTcbLevel } from './types.js';

/** What the signed document says, once its signature has been believed. */
export interface ReadCollateral {
  /** The window the vendor signed, in Unix seconds. */
  readonly signedAt: number;
  readonly validUntil: number;
  /** The identity the document names for itself, as its own text spells it. */
  readonly declaredCpuType: string | null;
  /** The vendor's status text beside the level asked about. */
  readonly vendorStatus: string;
  /** sha256 of the pinned certificate the walk ended on, so a verdict names the anchor it used. */
  readonly anchorDigest: string;
  /** The document bytes, then each certificate the answer presented, in the order it presented them. */
  readonly blobs: readonly Uint8Array[];
}

export type ReadOutcome = { readonly read: ReadCollateral } | { readonly refusal: CollateralRefusal };

interface Reading {
  readonly query: CollateralQuery;
  readonly declaration: OriginDeclaration;
  /** The instant the chain is read against, in seconds, which the caller has already settled on. */
  readonly appraisalAt: number;
}

/**
 * Reads the document and believes it, in that order.
 *
 * The signature and the chain are established before one field of the payload is looked at, because a
 * reader that parsed what it did not yet trust would be taking instructions from the answer. The
 * envelope is the vendor's own: three dot-separated base64url parts, ES256 over the first two spelled
 * as ASCII, with the certificates in the header member the declaration names.
 */
export function readSignedCollateral(bytes: Uint8Array, reading: Reading): ReadOutcome {
  const { declaration } = reading;
  const envelope = splitEnvelope(bytes, declaration);
  if ('refusal' in envelope) {
    return envelope;
  }
  const header = jsonObject(envelope.headerText);
  if (header === null) {
    return refused(declaration, 'the protected header is not a JSON object');
  }
  if (header['alg'] !== declaration.signature.algorithm) {
    return refused(declaration, `the header names ${quoteOrDigest(String(header['alg']))}, not ${declaration.signature.algorithm}`);
  }
  if (header['b64'] === false || header['crit'] !== undefined) {
    return refused(declaration, 'the header states an unencoded payload or a critical extension this path does not read');
  }
  const listed = certificateTexts(header, declaration);
  if ('refusal' in listed) {
    return listed;
  }
  const chain = parsePresented(listed.certificates, declaration);
  if ('refusal' in chain) {
    return chain;
  }
  const pinned = parsePinned(reading.query.roots, declaration);
  if ('refusal' in pinned) {
    return pinned;
  }
  const anchor = reachAnchor(chain.certificates, pinned, reading, declaration);
  if ('refusal' in anchor) {
    return anchor;
  }
  if (!verifiesEnvelope(chain.certificates[0] as ParsedCertificate, envelope)) {
    return {
      refusal: collateralRefusal(
        declaration.refusals.signature,
        'the signature over the document does not hold under the certificate at the foot of the chain',
      ),
    };
  }
  const payload = jsonObject(envelope.payloadText);
  if (payload === null) {
    return refused(declaration, 'the signed payload is not a JSON object');
  }
  const body = bodyOf(payload, bytes, reading, anchor.digest, chain.encoded);
  return 'refusal' in body ? body : { read: body };
}

function bodyOf(
  payload: Record<string, unknown>,
  bytes: Uint8Array,
  reading: Reading,
  anchorDigest: string,
  presented: readonly Uint8Array[],
): ReadCollateral | { readonly refusal: CollateralRefusal } {
  const { declaration, query } = reading;
  const document = declaration.window.documentMember === null
    ? payload
    : objectMember(payload, declaration.window.documentMember);
  if (document === null) {
    return refused(declaration, `the payload carries no ${String(declaration.window.documentMember)} object`);
  }
  const signedAt = instantMember(document, declaration.window.signedMember);
  const validUntil = instantMember(document, declaration.window.nextUpdateMember);
  if (signedAt === null || validUntil === null) {
    return refused(declaration, 'the window is not stated as two UTC instants');
  }
  if (validUntil <= signedAt) {
    return refused(declaration, 'the window it signed closes at or before the instant it opens');
  }
  const declared = readCpuType(document, query, declaration);
  if ('refusal' in declared) {
    return declared;
  }
  const status = statusOf(document, query.level, declaration);
  if ('refusal' in status) {
    return status;
  }
  return {
    signedAt,
    validUntil,
    declaredCpuType: declared.cpuType,
    vendorStatus: status.status,
    anchorDigest,
    blobs: [bytes, ...presented],
  };
}

/**
 * The identity the document claims, checked against the one asked for.
 *
 * A wrong identity is refused rather than reported: this is the one place an intermediary or a
 * misindexed answer can hand back a true statement about somebody else's hardware, and a caller told
 * about it in a field of a passing result would have to remember to look.
 */
function readCpuType(
  document: Record<string, unknown>,
  query: CollateralQuery,
  declaration: OriginDeclaration,
): { readonly cpuType: string | null } | { readonly refusal: CollateralRefusal } {
  const member = declaration.identity.cpuTypeMember;
  if (member === null) {
    return { cpuType: null };
  }
  const stated = stringMember(document, member);
  if (stated === null) {
    return refused(declaration, `the signed document carries no ${member}`);
  }
  if (query.cpuType === null || !sameHex(stated, query.cpuType)) {
    return {
      refusal: collateralRefusal(
        declaration.refusals.identity,
        `the document covers ${quoteOrDigest(stated)} and the query asked about ${quoteOrDigest(query.cpuType ?? 'nothing')}`,
        ['cpuType'],
      ),
    };
  }
  return { cpuType: stated };
}

/** The vendor's own words beside the level that was asked about, or the level list that has none. */
function statusOf(
  document: Record<string, unknown>,
  level: IntelTcbLevel | null,
  declaration: OriginDeclaration,
): { readonly status: string } | { readonly refusal: CollateralRefusal } {
  const statusMember = declaration.identity.statusMember;
  if (declaration.identity.levelsMember === null) {
    const stated = stringMember(document, statusMember);
    return stated === null
      ? refused(declaration, `the document states no ${statusMember} at its top level`)
      : { status: stated };
  }
  const levels = arrayMember(document, declaration.identity.levelsMember);
  if (levels === null) {
    return refused(declaration, `no ${declaration.identity.levelsMember} list was signed`);
  }
  if (level === null) {
    return {
      refusal: collateralRefusal(
        'COLLATERAL_INPUT_MISSING',
        `${declaration.name} states a status per level and the query named no level`,
        ['level'],
      ),
    };
  }
  for (const entry of levels) {
    const fields = typeof entry === 'object' && entry !== null && !Array.isArray(entry) ? entry as Record<string, unknown> : null;
    if (fields === null) {
      continue;
    }
    if (!levelMatches(fields, level, declaration)) {
      continue;
    }
    const stated = stringMember(fields, statusMember);
    return stated === null
      ? refused(declaration, `the matched level states no ${statusMember}`)
      : { status: stated };
  }
  return {
    refusal: collateralRefusal(
      declaration.refusals.levels,
      `the signed document lists no level spelled ${quoteOrDigest(level.value)}`,
      ['level'],
    ),
  };
}

function levelMatches(entry: Record<string, unknown>, level: IntelTcbLevel, declaration: OriginDeclaration): boolean {
  const dateMember = declaration.identity.levelDateMember;
  const compositionMember = declaration.identity.levelCompositionMember;
  if (level.by === 'tcb-date') {
    const stated = dateMember === null ? null : stringMember(entry, dateMember);
    return stated !== null && sameInstant(stated, level.value);
  }
  const stated = compositionMember === null ? null : stringMember(entry, compositionMember);
  return stated !== null && sameHex(stated, level.value);
}

function certificateTexts(
  header: Record<string, unknown>,
  declaration: OriginDeclaration,
): { readonly certificates: readonly string[] } | { readonly refusal: CollateralRefusal } {
  const listed = header[declaration.signature.certificateMember];
  if (!Array.isArray(listed) || listed.length === 0) {
    return refused(declaration, `the header names no ${declaration.signature.certificateMember} certificates`);
  }
  const certificates: string[] = [];
  for (const entry of listed) {
    if (typeof entry !== 'string') {
      return refused(declaration, 'a certificate in the header is not base64 text');
    }
    certificates.push(entry);
  }
  return { certificates };
}

interface Chain {
  readonly certificates: ParsedCertificate[];
  readonly encoded: readonly Uint8Array[];
}

function parsePresented(texts: readonly string[], declaration: OriginDeclaration): Chain | { readonly refusal: CollateralRefusal } {
  const certificates: ParsedCertificate[] = [];
  const encoded: Uint8Array[] = [];
  for (const text of texts) {
    const der = fromBase64(text);
    if (der === null) {
      return refused(declaration, 'a certificate in the header is not standard base64');
    }
    const parsed = parseCertificates(der);
    if (parsed === null) {
      return refused(declaration, 'a certificate in the header does not parse as X.509');
    }
    certificates.push(...parsed);
    encoded.push(der);
  }
  return { certificates, encoded };
}

function parsePinned(roots: readonly Uint8Array[], declaration: OriginDeclaration): readonly ParsedCertificate[] | { readonly refusal: CollateralRefusal } {
  const certificates: ParsedCertificate[] = [];
  for (const blob of roots) {
    const parsed = parseCertificates(blob);
    if (parsed === null) {
      return {
        refusal: collateralRefusal(
          declaration.refusals.anchor,
          'a certificate the caller pinned does not parse, so it pins nothing',
        ),
      };
    }
    certificates.push(...parsed);
  }
  return certificates;
}

function parseCertificates(blob: Uint8Array): ParsedCertificate[] | null {
  try {
    return parseCertificateChain(blob);
  } catch {
    return null;
  }
}

/**
 * Walks from the leaf to a certificate the caller pinned.
 *
 * Each hop is an issuer whose subject equals the child's issuer field, and the child's signature is
 * verified under that issuer's key; the walk stops at a self-signed certificate one of the pinned roots
 * matches by subject, and the *pinned* copy's key is what that certificate is checked against, so a
 * chain cannot borrow a trusted name. A chain that ends below a root is followed into the pinned set,
 * which is how these documents are published, and a chain that reaches no root is refused rather than
 * read as merely unsigned.
 */
function reachAnchor(
  presented: readonly ParsedCertificate[],
  pinned: readonly ParsedCertificate[],
  reading: Reading,
  declaration: OriginDeclaration,
): { readonly digest: string } | { readonly refusal: CollateralRefusal } {
  const pool = [...presented, ...pinned];
  const at = reading.appraisalAt * 1000;
  let index = 0;
  for (let hop = 0; hop < pool.length; hop += 1) {
    const cert = pool[index] as ParsedCertificate;
    const malformed = shapeRefusal(cert, declaration);
    if (malformed !== null) {
      return malformed;
    }
    if (cert.notBefore > at || cert.notAfter < at) {
      return {
        refusal: collateralRefusal(
          declaration.refusals.signature,
          `certificate ${String(hop)} of the chain is outside its own validity at the instant being appraised`,
        ),
      };
    }
    if (selfSigned(cert)) {
      const anchor = pinned.find((root) => equalBytes(root.subject, cert.subject));
      if (anchor === undefined) {
        return { refusal: collateralRefusal(declaration.refusals.anchor, 'the chain reaches a self-signed certificate the caller pinned nothing for') };
      }
      if (!verifiesCertificate(anchor, anchor)) {
        return {
          refusal: collateralRefusal(declaration.refusals.signature, 'the anchor does not carry its own signature under the pinned copy'),
        };
      }
      return { digest: sha256Hex(anchor.raw) };
    }
    if (cert.isCa !== true) {
      return {
        refusal: collateralRefusal(declaration.refusals.signature, `certificate ${String(hop)} of the chain is not an authority but issued the one below it`),
      };
    }
    const issuer = pool.find((other, position) => position !== index && equalBytes(other.subject, cert.issuer));
    if (issuer === undefined) {
      return { refusal: collateralRefusal(declaration.refusals.signature, 'the chain stops short of any pinned root') };
    }
    if (!verifiesCertificate(cert, issuer)) {
      return {
        refusal: collateralRefusal(declaration.refusals.signature, `certificate ${String(hop)} of the chain was not signed by the one above it`),
      };
    }
    index = pool.indexOf(issuer);
  }
  return { refusal: collateralRefusal(declaration.refusals.signature, 'the chain did not reach an anchor within the certificates presented') };
}

/** This path reads the suites its vendor publishes collateral in, and nothing weaker or other. */
function shapeRefusal(cert: ParsedCertificate, declaration: OriginDeclaration): { readonly refusal: CollateralRefusal } | null {
  if (cert.signatureAlgorithm.kind === 'ecdsa-sha256' && cert.publicKey.kind === 'ec-p256') {
    return null;
  }
  return {
    refusal: collateralRefusal(
      declaration.refusals.signature,
      `this path reads ECDSA-P256 certificates alone and met ${cert.signatureAlgorithm.kind} over ${cert.publicKey.kind}`,
    ),
  };
}

function selfSigned(cert: ParsedCertificate): boolean {
  return cert.isCa === true && equalBytes(cert.issuer, cert.subject);
}

function p256Point(cert: ParsedCertificate): Uint8Array | null {
  return cert.publicKey.kind === 'ec-p256' ? cert.publicKey.point : null;
}

/** A certificate's own DER signature, checked over its TBSCertificate under its issuer's key. */
function verifiesCertificate(cert: ParsedCertificate, issuer: ParsedCertificate): boolean {
  const point = p256Point(issuer);
  if (point === null) {
    return false;
  }
  try {
    return p256.verify(cert.signature, sha256(cert.tbs), point, { format: 'der' });
  } catch {
    return false;
  }
}

/** The envelope's signature, which a JWS writes as raw r and s and this curve verifies as compact. */
function verifiesEnvelope(
  leaf: ParsedCertificate,
  envelope: { readonly signingInput: Uint8Array; readonly signatureBytes: Uint8Array },
): boolean {
  const point = p256Point(leaf);
  if (point === null) {
    return false;
  }
  try {
    return p256.verify(envelope.signatureBytes, sha256(envelope.signingInput), point, { format: 'compact' });
  } catch {
    return false;
  }
}

interface Envelope {
  readonly headerText: string;
  readonly payloadText: string;
  readonly signingInput: Uint8Array;
  readonly signatureBytes: Uint8Array;
}

function splitEnvelope(bytes: Uint8Array, declaration: OriginDeclaration): Envelope | { readonly refusal: CollateralRefusal } {
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return refused(declaration, 'the answer is not UTF-8 text');
  }
  const parts = text.split('.');
  if (parts.length !== 3) {
    return refused(declaration, `the answer holds ${String(parts.length)} dot-separated parts, not the three a JWS has`);
  }
  const header = fromBase64Url(parts[0] as string);
  const payload = fromBase64Url(parts[1] as string);
  const signature = fromBase64Url(parts[2] as string);
  if (header === null || payload === null || signature === null) {
    return refused(declaration, 'a part of the envelope is not base64url text');
  }
  if (signature.byteLength !== 64) {
    return refused(declaration, `the signature is ${String(signature.byteLength)} bytes, and ES256 writes 64`);
  }
  return {
    headerText: new TextDecoder().decode(header),
    payloadText: new TextDecoder().decode(payload),
    signingInput: utf8(`${parts[0]}.${parts[1]}`),
    signatureBytes: signature,
  };
}

function jsonObject(text: string): Record<string, unknown> | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  return typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed) ? parsed as Record<string, unknown> : null;
}

function objectMember(owner: Record<string, unknown>, member: string): Record<string, unknown> | null {
  const value = owner[member];
  return typeof value === 'object' && value !== null && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

function arrayMember(owner: Record<string, unknown>, member: string): readonly unknown[] | null {
  const value = owner[member];
  return Array.isArray(value) ? value : null;
}

function stringMember(owner: Record<string, unknown>, member: string): string | null {
  const value = owner[member];
  return typeof value === 'string' ? value : null;
}

const INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/u;

function instantMember(owner: Record<string, unknown>, member: string): number | null {
  const text = stringMember(owner, member);
  return text === null ? null : instant(text);
}

function instant(text: string): number | null {
  if (!INSTANT.test(text)) {
    return null;
  }
  const parsed = Date.parse(text);
  return Number.isNaN(parsed) ? null : Math.floor(parsed / 1000);
}

function sameInstant(one: string, other: string): boolean {
  const first = instant(one);
  const second = instant(other);
  return first !== null && second !== null && first === second;
}

function sameHex(one: string, other: string): boolean {
  return /^[0-9a-f]+$/u.test(one.toLowerCase()) && one.toLowerCase() === other.toLowerCase();
}

function refused(declaration: OriginDeclaration, why: string): { readonly refusal: CollateralRefusal } {
  return { refusal: collateralRefusal(declaration.refusals.envelope, why) };
}
