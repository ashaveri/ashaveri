import { p384 } from '@noble/curves/p384';
import { sha384 } from '@noble/hashes/sha2.js';
import {
  checkCertificateValidity,
  derEcdsaSignature,
  parseCertificateChain,
  verifyCertificateSignature,
  type ParsedCertificate,
} from './der.js';
import { equalBytes, toHex } from './events.js';
import { fail } from './errors.js';

/**
 * Verification of the evidence an NVIDIA confidential-computing GPU signs about
 * itself, offline and against a pinned vendor root.
 *
 * The report is a DMTF SPDM GET_MEASUREMENTS exchange rather than a self-contained
 * signed document: the host's request is prepended to the GPU's response, and the
 * signature covers both. Nothing here reaches out to NVIDIA's attestation service,
 * the same posture the TDX and SNP legs keep, so certificate revocation and the
 * golden driver and VBIOS measurements are out of scope by design.
 */

/**
 * The request is 4 header bytes, a 32-byte nonce and one slot-id byte, and carries
 * no length field of its own, so the response boundary is fixed by that layout.
 */
const REQUEST_BYTES = 37;
/** ECDSA P-384 as the GPU writes it: raw r and s concatenated, no DER wrapper. */
const SIGNATURE_BYTES = 96;
const NONCE_BYTES = 32;
const SPDM_1_1 = 0x11;
const MEASUREMENTS_RESPONSE = 0x60;

export interface NvidiaEvidence {
  /** The captured report: SPDM request bytes followed by the signed response. */
  readonly report: Uint8Array;
  /** PEM or concatenated-DER certificates, leaf first, ending at a pinned root. */
  readonly certChain: Uint8Array;
}

export interface NvidiaVerification {
  readonly signatureVerified: true;
  /** The challenge the GPU was asked to sign, read from inside the signed region. */
  readonly nonce: Uint8Array;
}

export interface NvidiaOptions {
  readonly now?: number;
  /** DER or PEM trust anchors. Verification fails closed when none are supplied. */
  readonly trustedRoots?: readonly Uint8Array[];
  /**
   * The challenge this report had to answer. Comparing it against the nonce the
   * GPU signed is what makes the evidence fresh: a captured report answers a
   * different challenge and is refused.
   */
  readonly expectedNonce?: Uint8Array;
}

interface SpdmMeasurements {
  readonly signed: Uint8Array;
  readonly nonce: Uint8Array;
  readonly signature: Uint8Array;
}

function readUintLE(value: Uint8Array, offset: number, bytes: number): number {
  let out = 0;
  for (let i = 0; i < bytes; i++) out += (value[offset + i] ?? 0) * 2 ** (8 * i);
  return out;
}

function toBigUint(bytes: Uint8Array): bigint {
  let out = 0n;
  for (const byte of bytes) out = (out << 8n) | BigInt(byte);
  return out;
}

/** Splits a report into the signed span, the nonce and the raw signature. */
function parseSpdmMeasurements(report: Uint8Array): SpdmMeasurements {
  const response = report.subarray(REQUEST_BYTES);
  if (report.length < REQUEST_BYTES + 10 + SIGNATURE_BYTES) {
    fail('MALFORMED_REPORT', `GPU report is ${report.length} bytes, too short to hold a request and a signed response`);
  }
  if (report[0] !== SPDM_1_1) {
    fail('UNSUPPORTED_QUOTE', `GPU report request declares SPDM version 0x${(report[0] ?? 0).toString(16)}, only 1.1 (0x11)`);
  }
  if (response[0] !== SPDM_1_1) {
    fail('UNSUPPORTED_QUOTE', `GPU report response declares SPDM version 0x${(response[0] ?? 0).toString(16)}, only 1.1 (0x11)`);
  }
  if (response[1] !== MEASUREMENTS_RESPONSE) {
    fail('MALFORMED_REPORT', `GPU report holds response code 0x${(response[1] ?? 0).toString(16)}, not a measurements response (0x60)`);
  }
  const recordLength = readUintLE(response, 5, 3);
  const nonceOffset = 8 + recordLength;
  if (response.length < nonceOffset + NONCE_BYTES + 2) {
    fail('MALFORMED_REPORT', `measurement record is declared as ${recordLength} bytes, leaving no room for the nonce`);
  }
  const opaqueLength = readUintLE(response, nonceOffset + NONCE_BYTES, 2);
  const signatureOffset = nonceOffset + NONCE_BYTES + 2 + opaqueLength;
  if (response.length !== signatureOffset + SIGNATURE_BYTES) {
    fail('TRAILING_BYTES', `GPU report leaves ${response.length - signatureOffset} bytes after the measurement fields, expected a ${SIGNATURE_BYTES}-byte signature`);
  }
  return {
    signed: report.subarray(0, report.length - SIGNATURE_BYTES),
    nonce: response.slice(nonceOffset, nonceOffset + NONCE_BYTES),
    signature: response.subarray(signatureOffset),
  };
}

/** Walks from the leaf until an entry a pinned root signs, checking every link. */
function verifyDeviceChain(chain: readonly ParsedCertificate[], roots: readonly ParsedCertificate[], now: number): ParsedCertificate {
  let anchor = -1;
  for (let i = chain.length - 1; i >= 0; i--) {
    if (roots.some((root) => equalBytes(root.subject, (chain[i] as ParsedCertificate).subject))) {
      anchor = i;
      break;
    }
  }
  if (anchor < 0) {
    fail('MISSING_TRUST_ROOT', 'GPU certificate chain does not lead to any pinned NVIDIA root certificate');
  }
  if (anchor === 0) {
    fail('CERT_CHAIN_INVALID', 'GPU certificate chain begins at the trust anchor, so no device key is attested');
  }
  for (let i = 0; i < anchor; i++) {
    const cert = chain[i] as ParsedCertificate;
    const issuer = chain[i + 1] as ParsedCertificate;
    const name = `GPU chain entry ${i}`;
    if (!equalBytes(cert.issuer, issuer.subject)) {
      fail('CERT_CHAIN_INVALID', `${name} was not issued by entry ${i + 1}`);
    }
    checkCertificateValidity(cert, now, name);
    verifyCertificateSignature(issuer, cert, name);
  }
  checkCertificateValidity(chain[anchor] as ParsedCertificate, now, `GPU chain entry ${anchor}`);
  return chain[0] as ParsedCertificate;
}

/**
 * Which challenge a device report answers, read from inside the signed region.
 *
 * No signature check and no trust roots: this says nothing about whether the
 * report is genuine, only about which request it claims to reply to. A producer
 * needs exactly that much to refuse serving evidence collected for someone
 * else's challenge; the verdict stays with `verifyNvidiaRats`.
 */
export function readNvidiaChallenge(report: Uint8Array): Uint8Array {
  return parseSpdmMeasurements(report).nonce;
}

export function verifyNvidiaRats(evidence: NvidiaEvidence, options: NvidiaOptions): NvidiaVerification {
  const now = options.now ?? Date.now();
  const expectedNonce = options.expectedNonce;
  const rawRoots = options.trustedRoots ?? [];
  if (rawRoots.length === 0) {
    fail('MISSING_TRUST_ROOT', 'GPU evidence verification needs at least one pinned NVIDIA root certificate');
  }
  const { signed, nonce, signature } = parseSpdmMeasurements(evidence.report);
  if (expectedNonce !== undefined && !equalBytes(expectedNonce, nonce)) {
    fail('NONCE_MISMATCH', `the GPU signed a report for challenge ${toHex(nonce)}, this request expected ${toHex(expectedNonce)}`);
  }
  const chain = parseCertificateChain(evidence.certChain);
  if (chain.length === 0) {
    fail('MALFORMED_CERTIFICATE', 'GPU certificate chain holds no certificates');
  }
  const roots = rawRoots.flatMap((blob) => parseCertificateChain(blob));
  const leaf = verifyDeviceChain(chain, roots, now);
  if (leaf.publicKey.kind !== 'ec-p384') {
    fail('UNSUPPORTED_CERT_ALGORITHM', `GPU leaf certificate carries a ${leaf.publicKey.kind} key, not the ec-p384 key the report signature is made with`);
  }
  const der = derEcdsaSignature(
    toBigUint(signature.subarray(0, 48)),
    toBigUint(signature.subarray(48, SIGNATURE_BYTES)),
    p384.CURVE.n,
  );
  if (!p384.verify(der, sha384(signed), leaf.publicKey.point, { format: 'der' })) {
    fail('BAD_SIGNATURE', 'GPU report signature does not verify under its own leaf certificate');
  }
  return { signatureVerified: true, nonce };
}
