import { p256 } from '@noble/curves/nist.js';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  checkCertificateValidity,
  derEcdsaSignature,
  parseCertificateChain,
  verifyCertificateSignature,
  type ParsedCertificate,
} from './der.js';
import { fail } from './errors.js';
import { equalBytes } from './events.js';

/**
 * Intel TD quote version 4: a 48-byte header followed by a 584-byte TD report
 * body. Those 632 bytes are what the quote signature covers; everything after
 * them is the signature data block.
 */
const SIGNED_REGION = 48 + 584;
const SIGNATURE_LENGTH_OFFSET = SIGNED_REGION;
const SIGNATURE_DATA_OFFSET = SIGNED_REGION + 4;
/** ECDSA-256 signature and P-256 attestation key, each a raw 64-byte pair. */
const ECDSA_256_BYTES = 64;
/** Certification data follows the key as a u16 type and a u32 length. */
const CERTIFICATION_DATA_HEADER = 2 * ECDSA_256_BYTES + 2 + 4;
/** Type 6 certification data: the QE report, its signature, then auth data and the PCK chain. */
const ENCLAVE_REPORT_BYTES = 384;
const ENCLAVE_REPORT_SIGNATURE_BYTES = 64;
const AUTH_DATA_LENGTH_OFFSET = ENCLAVE_REPORT_BYTES + ENCLAVE_REPORT_SIGNATURE_BYTES;
const INNER_CERTIFICATION_HEADER = 2 + 4;
/** Type 6 holds a QE report; type 5 inside it holds a PEM certificate chain. */
const CERT_DATA_TYPE_QE_REPORT = 6;
const CERT_DATA_TYPE_PEM_CHAIN = 5;
/** REPORT_DATA starts at byte 320 of the QE report; its first half is the binding digest. */
const QE_REPORT_DATA_OFFSET = 320;
const QE_REPORT_BINDING_BYTES = 32;
const QUOTE_VERSION_TD_4 = 4;
const TEE_TYPE_TDX = 0x81;

export interface TdxQuoteSignature {
  /** ECDSA signature over the quote header and TD report body, raw r||s. */
  readonly signature: Uint8Array;
  /** P-256 point (x||y) that produced it, authorized by the QE report below. */
  readonly attestationKey: Uint8Array;
  readonly certificationDataType: number;
  readonly certificationData: Uint8Array;
}

/**
 * Splits a TD quote into the bytes Intel signs and the signature data block.
 *
 * The signature layout is ECDSA-with-P-256, which the header's attestation key
 * type selects. Rather than trusting that field, the offsets are confirmed by
 * the two length prefixes: a quote in any other layout cannot declare a
 * signature data length and a certification data length that both land exactly
 * on the end of the buffer.
 */
export function parseTdxQuoteSignature(quote: Uint8Array): TdxQuoteSignature {
  if (quote.length < SIGNATURE_DATA_OFFSET) {
    fail('MALFORMED_QUOTE', `quote is ${quote.length} bytes, need at least ${SIGNATURE_DATA_OFFSET} for the signature length`);
  }
  const view = new DataView(quote.buffer, quote.byteOffset, quote.byteLength);
  const version = view.getUint16(0x00, true);
  if (version !== QUOTE_VERSION_TD_4) {
    fail('UNSUPPORTED_QUOTE', `quote version ${version} is not supported, only version ${QUOTE_VERSION_TD_4}`);
  }
  const teeType = view.getUint32(0x04, true);
  if (teeType !== TEE_TYPE_TDX) {
    fail('UNSUPPORTED_QUOTE', `TEE type 0x${teeType.toString(16)} is not TDX (0x81)`);
  }
  const signatureDataLength = view.getUint32(SIGNATURE_LENGTH_OFFSET, true);
  if (SIGNATURE_DATA_OFFSET + signatureDataLength !== quote.length) {
    fail('MALFORMED_QUOTE', `signature data is declared as ${signatureDataLength} bytes, ${quote.length - SIGNATURE_DATA_OFFSET} present`);
  }
  if (signatureDataLength < CERTIFICATION_DATA_HEADER) {
    fail('MALFORMED_QUOTE', `signature data is ${signatureDataLength} bytes, too short to hold a certification data header`);
  }
  const certificationDataType = view.getUint16(SIGNATURE_DATA_OFFSET + 2 * ECDSA_256_BYTES, true);
  const certificationDataLength = view.getUint32(SIGNATURE_DATA_OFFSET + 2 * ECDSA_256_BYTES + 2, true);
  const certificationDataOffset = SIGNATURE_DATA_OFFSET + CERTIFICATION_DATA_HEADER;
  if (certificationDataOffset + certificationDataLength !== quote.length) {
    fail('MALFORMED_QUOTE', `certification data is declared as ${certificationDataLength} bytes, ${quote.length - certificationDataOffset} present`);
  }
  return {
    signature: quote.slice(SIGNATURE_DATA_OFFSET, SIGNATURE_DATA_OFFSET + ECDSA_256_BYTES),
    attestationKey: quote.slice(SIGNATURE_DATA_OFFSET + ECDSA_256_BYTES, SIGNATURE_DATA_OFFSET + 2 * ECDSA_256_BYTES),
    certificationDataType,
    certificationData: quote.slice(certificationDataOffset),
  };
}

/**
 * The type 6 certification data a TD quote carries: a Quoting Enclave report
 * signed by the platform's PCK, the QE auth data that ties that report to the
 * quote's attestation key, and the PCK certificate chain.
 */
export interface QeReportCertificationData {
  readonly enclaveReport: Uint8Array;
  readonly enclaveReportSignature: Uint8Array;
  readonly authData: Uint8Array;
  readonly innerCertificationDataType: number;
  readonly pckCertChain: Uint8Array;
}

export function parseQeReportCertificationData(certificationData: Uint8Array): QeReportCertificationData {
  if (certificationData.length < AUTH_DATA_LENGTH_OFFSET + 2) {
    fail('MALFORMED_QUOTE', `QE report certification data is ${certificationData.length} bytes, need at least ${AUTH_DATA_LENGTH_OFFSET + 2}`);
  }
  const view = new DataView(certificationData.buffer, certificationData.byteOffset, certificationData.byteLength);
  const authDataLength = view.getUint16(AUTH_DATA_LENGTH_OFFSET, true);
  const innerOffset = AUTH_DATA_LENGTH_OFFSET + 2 + authDataLength;
  if (innerOffset + INNER_CERTIFICATION_HEADER > certificationData.length) {
    fail('MALFORMED_QUOTE', `QE auth data of ${authDataLength} bytes runs past the certification data`);
  }
  const innerCertificationDataType = view.getUint16(innerOffset, true);
  const innerCertificationDataLength = view.getUint32(innerOffset + 2, true);
  const payloadOffset = innerOffset + INNER_CERTIFICATION_HEADER;
  if (payloadOffset + innerCertificationDataLength !== certificationData.length) {
    fail('MALFORMED_QUOTE', `PCK chain is declared as ${innerCertificationDataLength} bytes, ${certificationData.length - payloadOffset} present`);
  }
  return {
    enclaveReport: certificationData.slice(0, ENCLAVE_REPORT_BYTES),
    enclaveReportSignature: certificationData.slice(ENCLAVE_REPORT_BYTES, AUTH_DATA_LENGTH_OFFSET),
    authData: certificationData.slice(AUTH_DATA_LENGTH_OFFSET + 2, innerOffset),
    innerCertificationDataType,
    pckCertChain: certificationData.slice(payloadOffset),
  };
}

export interface TdxDcapOptions {
  /** Pinned Intel SGX root CA certificates as PEM or DER blobs; each may hold several. */
  readonly trustedRoots: readonly Uint8Array[];
  /** Verification time in milliseconds since the Unix epoch, used for certificate validity. */
  readonly now: number;
}

export interface TdxQuoteVerification {
  /** The P-256 attestation key (uncompressed, without the 0x04 prefix) that signed the quote. */
  readonly attestationKey: Uint8Array;
  /** PCK leaf first, issuing CAs after it, in the order the quote presents them. */
  readonly pckChain: readonly ParsedCertificate[];
  /** The chain entry that matched a pinned root. */
  readonly trustedRoot: ParsedCertificate;
}

/**
 * Verifies a TD quote the way Intel DCAP does, offline and against pinned roots.
 *
 * Three signatures carry the trust: the PCK leaf signs the QE report, the QE
 * report's REPORT_DATA holds sha256(attestation key || QE auth data), and that
 * attestation key signs the quote itself. The attestation key and the auth data
 * sit outside every signature, so the binding digest is what stops an attacker
 * from pairing a valid quote signature with a key the platform never authorized.
 *
 * Not covered here: TCB Info freshness, QE Identity, and certificate revocation,
 * which need collateral from the Intel PCS.
 */
export function verifyTdxQuote(quote: Uint8Array, options: TdxDcapOptions): TdxQuoteVerification {
  const block = parseTdxQuoteSignature(quote);
  if (block.certificationDataType !== CERT_DATA_TYPE_QE_REPORT) {
    fail('UNSUPPORTED_QUOTE', `certification data type ${block.certificationDataType} is not the QE report shape (${CERT_DATA_TYPE_QE_REPORT})`);
  }
  const qe = parseQeReportCertificationData(block.certificationData);
  if (qe.innerCertificationDataType !== CERT_DATA_TYPE_PEM_CHAIN) {
    fail('UNSUPPORTED_QUOTE', `PCK chain is encoded as type ${qe.innerCertificationDataType}, not PEM (${CERT_DATA_TYPE_PEM_CHAIN})`);
  }
  const chain = parseCertificateChain(qe.pckCertChain);
  const roots = options.trustedRoots.flatMap((blob) => parseCertificateChain(blob));
  const trustedRoot = verifyPckChain(chain, roots, options.now);

  const leaf = chain[0] as ParsedCertificate;
  if (leaf.publicKey.kind !== 'ec-p256') {
    fail('UNSUPPORTED_CERT_ALGORITHM', `PCK leaf key is ${leaf.publicKey.kind}, a TD quote needs an EC P-256 leaf`);
  }
  verifyEcdsaP256(qe.enclaveReportSignature, qe.enclaveReport, leaf.publicKey.point, 'QE report');

  const binding = new Uint8Array(block.attestationKey.length + qe.authData.length);
  binding.set(block.attestationKey, 0);
  binding.set(qe.authData, block.attestationKey.length);
  const expected = qe.enclaveReport.subarray(QE_REPORT_DATA_OFFSET, QE_REPORT_DATA_OFFSET + QE_REPORT_BINDING_BYTES);
  if (!equalBytes(sha256(binding), expected)) {
    fail('QE_REPORT_MISMATCH', 'sha256(attestation key || QE auth data) differs from the QE report REPORT_DATA');
  }

  const attestationKey = new Uint8Array(1 + block.attestationKey.length);
  attestationKey[0] = 0x04;
  attestationKey.set(block.attestationKey, 1);
  verifyEcdsaP256(block.signature, quote.subarray(0, SIGNED_REGION), attestationKey, 'quote');

  return {
    attestationKey: block.attestationKey,
    pckChain: chain,
    trustedRoot,
  };
}

// Walks the chain from the leaf up to its self-signed anchor, which must be one
// of the pinned roots. Subject and issuer are compared as raw DER so a forged
// certificate cannot borrow a trusted name, and the anchor's self-signature is
// checked with the pinned copy's key rather than its own.
function verifyPckChain(chain: readonly ParsedCertificate[], roots: readonly ParsedCertificate[], now: number): ParsedCertificate {
  const anchor = anchorIndexOf(chain, roots);
  if (anchor < 0) {
    fail('MISSING_TRUST_ROOT', 'PCK chain does not lead to any pinned Intel SGX root certificate');
  }
  if (chain.length < 2) {
    fail('CERT_CHAIN_INVALID', 'PCK chain holds fewer than a leaf and an issuing CA');
  }
  if ((chain[0] as ParsedCertificate).isCa === true) {
    fail('CERT_CHAIN_INVALID', 'the first PCK certificate must be a leaf, not a certificate authority');
  }
  for (let i = 0; i < anchor; i++) {
    const cert = chain[i] as ParsedCertificate;
    const issuer = chain[i + 1] as ParsedCertificate;
    if (!equalBytes(cert.issuer, issuer.subject)) {
      fail('CERT_CHAIN_INVALID', `PCK chain entry ${i} was not issued by entry ${i + 1}`);
    }
    checkCertificateValidity(cert, now, certName(i, anchor));
    verifyCertificateSignature(issuer, cert, certName(i, anchor));
  }
  const anchorCert = chain[anchor] as ParsedCertificate;
  const pinned = roots.find((root) => equalBytes(root.subject, anchorCert.subject)) as ParsedCertificate;
  checkCertificateValidity(anchorCert, now, certName(anchor, anchor));
  verifyCertificateSignature(pinned, anchorCert, certName(anchor, anchor));
  return anchorCert;
}

function anchorIndexOf(chain: readonly ParsedCertificate[], roots: readonly ParsedCertificate[]): number {
  for (let i = chain.length - 1; i >= 0; i--) {
    const cert = chain[i] as ParsedCertificate;
    if (cert.isCa === true && equalBytes(cert.issuer, cert.subject)
      && roots.some((root) => equalBytes(root.subject, cert.subject))) {
      return i;
    }
  }
  return -1;
}

function certName(index: number, anchor: number): string {
  if (index === 0) {
    return 'PCK leaf';
  }
  return index === anchor ? 'Intel SGX root CA' : 'PCK CA';
}

function verifyEcdsaP256(rawSignature: Uint8Array, message: Uint8Array, point: Uint8Array, name: string): void {
  if (rawSignature.length !== ECDSA_256_BYTES) {
    fail('MALFORMED_QUOTE', `${name} signature is ${rawSignature.length} bytes, expected ${ECDSA_256_BYTES}`);
  }
  const half = rawSignature.length / 2;
  // Quotes carry ECDSA as raw r||s and noble only accepts DER; converting also
  // range-checks the pair, so a garbage signature is BAD_SIGNATURE rather than
  // an exception from inside the curve.
  const der = derEcdsaSignature(beToBigint(rawSignature.subarray(0, half)), beToBigint(rawSignature.subarray(half)), p256.Point.CURVE().n);
  if (!p256.verify(der, sha256(message), point, { format: 'der' })) {
    fail('BAD_SIGNATURE', `${name} ECDSA-P256 signature does not verify`);
  }
}

function beToBigint(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const b of bytes) {
    value = (value << 8n) | BigInt(b);
  }
  return value;
}
