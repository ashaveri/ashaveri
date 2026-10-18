import {
  AttestationError,
  equalBytes,
  findMatchingArk,
  verifyAmdCertificateChain,
  type AttestationErrorCode,
  type ParsedCertificate,
} from '@ashaveri/attest-core';
import { sha256Hex, toHex } from './bytes.js';
import { collateralRefusal, quoteOrDigest, type CollateralErrorCode, type CollateralRefusal } from './errors.js';
import { hasReader, isVcekDeclaration, type VcekOriginDeclaration } from './intel-origin.js';
import { parseCertificates, parsePinned, type Reading } from './read.js';
import type { SignedWindow, VcekChain } from './types.js';

/** What a KDS pair read answered: the believed chain, or the refusal that says why nothing was believed. */
export type VcekChainReadOutcome = { readonly read: VcekChain } | { readonly refusal: CollateralRefusal };

/**
 * Reads the two answers one KDS question is asked with, and believes them in the order the bytes require.
 *
 * The body is the per-chip route's answer, one certificate, and the chain is the chain route's answer, the
 * authorities beneath the root the caller pinned. The halves arrive apart because the vendor publishes them
 * apart: neither route states a header carrying the other, so a reader handed a certificate with no chain
 * beside it holds a certificate that was weighed by nobody and says so with the anchor refusal rather than
 * reading a statement out of it.
 *
 * The structure is parsed before anything is believed, because the certificate's own issuer name is what
 * selects the authority that has to have signed it. Which authority issued it is settled by matching subjects
 * rather than by the order the chain was sent in, because the measured answer puts the intermediate first and
 * the root second while nothing on either route states that it must. The chain is then believed by
 * `verifyAmdCertificateChain`, with the root taken from the caller's pinned set by `findMatchingArk`, so the
 * rsa-pss parameters, the curve pairing, the authority flags, the self-signed end and the three signatures are
 * decided where the estate already decides them for a report's own certificates. This file writes no signature
 * rule: an RSA or P-384 path written here would be a second place for those rules to drift.
 *
 * What is read after the chain is believed is the identity: the product line and the chip id the certificate
 * states for itself, compared with the ones the question named. A wrong identity is refused rather than
 * reported, because this is the one place a misindexed answer can hand back a true statement about somebody
 * else's chip. The order matters the other way round too: no member of an unbelieved certificate reaches a
 * sentence about what it names.
 */
export function readVcekChain(body: Uint8Array, chain: Uint8Array | null, reading: Reading): VcekChainReadOutcome {
  if (!isVcekDeclaration(reading.declaration)) {
    return {
      refusal: collateralRefusal(
        hasReader(reading.declaration) ? 'COLLATERAL_BLOB_UNREADABLE' : 'COLLATERAL_ORIGIN_UNSUPPORTED',
        `${reading.declaration.name} answers as ${reading.declaration.answer} and this reader weighs a VCEK and the chain above it alone`,
      ),
    };
  }
  const declaration: VcekOriginDeclaration = reading.declaration;
  if (body.byteLength === 0) {
    return unreadable(declaration, 'the certificate answer is empty');
  }
  if (body.byteLength > declaration.maxResponseBytes) {
    return oversize(declaration, body, 'certificate');
  }
  if (chain === null) {
    return {
      refusal: collateralRefusal(
        declaration.refusals.anchor,
        `no answer arrived from ${quoteOrDigest(declaration.chainRoute)}, so the certificate that arrived was weighed by nobody`,
      ),
    };
  }
  if (chain.byteLength === 0) {
    return unreadable(declaration, `the ${declaration.chainRoute} answer is empty`);
  }
  if (chain.byteLength > declaration.maxResponseBytes) {
    return oversize(declaration, chain, 'chain');
  }
  const presented = parseCertificates(body);
  if (presented === null) {
    return unreadable(declaration, 'the certificate answer does not parse as X.509');
  }
  if (presented.length !== 1) {
    return unreadable(
      declaration,
      `the ${declaration.certificateRoute} answer holds ${String(presented.length)} certificates, and that route answers one`,
    );
  }
  const vcek = presented[0] as ParsedCertificate;
  const authorities = parseCertificates(chain);
  if (authorities === null || authorities.length === 0) {
    return unreadable(declaration, `the ${declaration.chainRoute} answer holds no certificate that parses`);
  }
  const pinned = parsePinned(reading.query.roots, declaration);
  if ('refusal' in pinned) {
    return pinned;
  }
  const issuers = authorities.filter((one) => equalBytes(one.subject, vcek.issuer));
  if (issuers.length !== 1) {
    return {
      refusal: collateralRefusal(
        declaration.refusals.signature,
        issuers.length === 0
          ? `no certificate in the ${declaration.chainRoute} answer carries the issuer name the certificate states`
          : `the ${declaration.chainRoute} answer carries ${String(issuers.length)} certificates for the issuer name the certificate states, and which one signed it is not stated`,
      ),
    };
  }
  const believed = believe(declaration, pinned, issuers[0] as ParsedCertificate, vcek, reading.appraisalAt);
  if ('refusal' in believed) {
    return believed;
  }
  const stated = readIdentity(declaration, reading, vcek);
  if ('refusal' in stated) {
    return stated;
  }
  const window = sharedValidity([believed.root, believed.ask, vcek]);
  if (window.until <= window.from) {
    return unreadable(declaration, 'the certificates share no validity, so the chain states no window');
  }
  return {
    read: {
      ...stated.read,
      window,
      digest: sha256Hex(body),
      anchorDigest: sha256Hex(believed.root.raw),
      blobs: [body, ...authorities.map((one) => one.raw)],
    },
  };
}

/** The root the caller pinned that issued the intermediate, and the chain believed under it. */
interface BelievedChain {
  readonly root: ParsedCertificate;
  readonly ask: ParsedCertificate;
}

/**
 * Selects the pinned root that issued the intermediate and believes the chain under it.
 *
 * The root handed to the primitive is the caller's own copy rather than a certificate that arrived with the
 * answer, so a chain cannot borrow a trusted name: the signature above that name is checked against the key
 * the name was pinned under. Which answer the primitives refuse with is settled here and nowhere else, and an
 * answer this file has no rule for is refused as an unverifiable chain rather than passed.
 */
function believe(
  declaration: VcekOriginDeclaration,
  pinned: readonly ParsedCertificate[],
  ask: ParsedCertificate,
  vcek: ParsedCertificate,
  appraisalAt: number,
): BelievedChain | { readonly refusal: CollateralRefusal } {
  let root: ParsedCertificate;
  try {
    root = findMatchingArk(pinned, ask);
  } catch (err) {
    return { refusal: chainRefusal(declaration, err) };
  }
  for (const one of [
    { cert: root, role: 'authority' as const, name: 'the pinned root' },
    { cert: ask, role: 'authority' as const, name: 'the chain answer' },
    { cert: vcek, role: 'certificate' as const, name: 'the certificate answer' },
  ]) {
    const misshapen = suiteRefusal(declaration, one.cert, one.role, one.name);
    if (misshapen !== null) {
      return { refusal: misshapen };
    }
  }
  try {
    verifyAmdCertificateChain(root, ask, vcek, appraisalAt * 1000);
  } catch (err) {
    return { refusal: chainRefusal(declaration, err) };
  }
  return { root, ask };
}

/**
 * The refusal for a certificate wearing a suite this origin does not publish, and null where it wears one.
 *
 * This names the shape the declaration states and decides nothing about the signature: the parameter and curve
 * rules that make a suite what it is belong to `verifyCertificateSignature`, and a second copy of them here
 * would be a second answer to what a bad chain is.
 */
function suiteRefusal(
  declaration: VcekOriginDeclaration,
  cert: ParsedCertificate,
  role: 'authority' | 'certificate',
  name: string,
): CollateralRefusal | null {
  const stated = role === 'authority' ? declaration.suites.authorityKey : declaration.suites.certificateKey;
  if (cert.signatureAlgorithm.kind !== declaration.suites.signature) {
    return collateralRefusal(
      declaration.refusals.signature,
      `${name} is signed ${cert.signatureAlgorithm.kind} and ${declaration.name} publishes ${declaration.suites.signature} alone`,
    );
  }
  if (cert.publicKey.kind !== stated) {
    return collateralRefusal(
      declaration.refusals.signature,
      `${name} carries a ${cert.publicKey.kind} key where ${declaration.name} publishes a ${stated} ${role} key`,
    );
  }
  return null;
}

/** The refusal an attest-core answer about these bytes becomes for this path. */
function chainRefusal(declaration: VcekOriginDeclaration, err: unknown): CollateralRefusal {
  const code: AttestationErrorCode | null = err instanceof AttestationError ? err.code : null;
  const named = code === null ? quoteOrDigest(err instanceof Error ? err.name : 'unknown') : code;
  const message = err instanceof Error ? err.message : 'the chain verifier refused without an error object';
  return collateralRefusal(refusalSlot(declaration, code), `${named}: ${onOneLine(message)}`);
}

/** Which slot of the declaration's refusals an attest-core answer meets, with the default spelled out. */
function refusalSlot(declaration: VcekOriginDeclaration, code: AttestationErrorCode | null): CollateralErrorCode {
  if (code === 'MISSING_TRUST_ROOT') {
    return declaration.refusals.anchor;
  }
  if (code === 'MALFORMED_CERTIFICATE') {
    return declaration.refusals.envelope;
  }
  return declaration.refusals.signature;
}

/**
 * A sentence a parser built out of untrusted bytes, kept to one line.
 *
 * The code names the answer and the message names the certificate it named, which is what a caller of this
 * package has to go on, and the bytes in that message came from a certificate somebody served. Anything that
 * could end a log line or reorder one becomes a space, and a message wider than a sentence worth printing is
 * cut rather than wrapped.
 */
function onOneLine(text: string): string {
  return text.replace(/[^\x20-\x7e]/gu, ' ').slice(0, 100);
}

/** What the believed certificate states about the chip it was asked for, before any anchor or byte is attached. */
type StatedIdentity = { readonly productName: string; readonly hwidHex: string; readonly serialHex: string };

/**
 * Reads the identity the certificate states for itself and binds it to the question.
 *
 * The product line is the part of AMD's own product name before the stepping, and the chip id is the 64 bytes
 * of the certificate's HWID extension, which the question spells as 128 hex characters because that is the
 * spelling the route answers. A certificate stating neither is not this route's answer at all, which is the
 * unreadable-blob refusal rather than the identity one: nothing was compared, because nothing was stated to
 * compare against.
 */
function readIdentity(
  declaration: VcekOriginDeclaration,
  reading: Reading,
  vcek: ParsedCertificate,
): { readonly read: StatedIdentity } | { readonly refusal: CollateralRefusal } {
  const { query } = reading;
  const hwid = vcek.hwid;
  const productName = vcek.productName;
  if (hwid === null || productName === null) {
    return unreadable(
      declaration,
      `the certificate states no AMD ${hwid === null ? 'HWID' : 'product name'} extension, so it is not a ${declaration.name} answer`,
    );
  }
  const statedHwid = toHex(hwid);
  const askedHwid = query[declaration.hwidMember];
  if (askedHwid == null || askedHwid.length === 0) {
    return {
      refusal: collateralRefusal(
        'COLLATERAL_INPUT_MISSING',
        `${declaration.name} answers about one chip and the query named no ${declaration.hwidMember}`,
        [declaration.hwidMember],
      ),
    };
  }
  if (statedHwid !== askedHwid.toLowerCase()) {
    return {
      refusal: collateralRefusal(
        declaration.refusals.identity,
        `the certificate covers ${statedHwid} and the query asked about ${quoteOrDigest(askedHwid.toLowerCase())}`,
        [declaration.hwidMember],
      ),
    };
  }
  const askedProduct = query[declaration.productMember];
  if (askedProduct == null || askedProduct.length === 0) {
    return {
      refusal: collateralRefusal(
        'COLLATERAL_INPUT_MISSING',
        `${declaration.name} answers within one product line and the query named no ${declaration.productMember}`,
        [declaration.productMember],
      ),
    };
  }
  const line = productName.split('-')[0] as string;
  if (line.toLowerCase() !== askedProduct.toLowerCase()) {
    return {
      refusal: collateralRefusal(
        declaration.refusals.identity,
        `the certificate is for the ${quoteOrDigest(line)} line and the query asked within ${quoteOrDigest(askedProduct)}`,
        [declaration.productMember],
      ),
    };
  }
  return { read: { productName, hwidHex: statedHwid, serialHex: toHex(vcek.serial) } };
}

/**
 * The window the believed certificates share.
 *
 * The chain was believed at one instant inside all three validity spans, which is what
 * `verifyAmdCertificateChain` requires, so the span they all hold themselves valid for is the widest answer
 * this path can state about how far these bytes reach. Nothing is extended, rounded or remembered from another
 * origin's window, and a caller may keep the answer for no more than the end of it.
 */
function sharedValidity(certificates: readonly ParsedCertificate[]): SignedWindow {
  let from = 0;
  let until = Number.MAX_SAFE_INTEGER;
  for (const one of certificates) {
    from = Math.max(from, Math.floor(one.notBefore / 1000));
    until = Math.min(until, Math.floor(one.notAfter / 1000));
  }
  return { from, until };
}

function unreadable(declaration: VcekOriginDeclaration, why: string): { readonly refusal: CollateralRefusal } {
  return { refusal: collateralRefusal(declaration.refusals.envelope, why) };
}

function oversize(declaration: VcekOriginDeclaration, bytes: Uint8Array, which: string): { readonly refusal: CollateralRefusal } {
  return unreadable(
    declaration,
    `the ${which} answer is ${String(bytes.byteLength)} bytes, over the ${String(declaration.maxResponseBytes)} this path reads`,
  );
}
