import { describe, it, expect } from 'vitest';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  AMD_ARK_MILAN_PEM,
  INTEL_SGX_ROOT_CA_PEM,
  NVIDIA_DEVICE_IDENTITY_CA_PEM,
  decodeAttestation,
  equalBytes,
  parseCertificate,
  parseCertificateChain,
} from '../src/index.js';
import type { ParsedCertificate } from '../src/index.js';
import { decodeBase64 } from '../src/der.js';
import { toHex } from '../src/events.js';
import { expectErrorCode, fixture, pemToDer } from './helpers.js';

const ARK = fixture('amd-ark-milan.pem');
const ASK = fixture('sev-snp-ask.pem');
const VCEK = fixture('sev-snp-vcek.pem');

// The serial and the SubjectPublicKeyInfo of each embedded root, stated here as
// literals rather than recomputed, so the reader is checked against the
// certificates themselves and not against itself. `serialHex` is the
// TBSCertificate serialNumber as the DER INTEGER content bytes, leading sign
// byte included; `spkiSha256Hex` is the digest of the whole
// SubjectPublicKeyInfo element, tag and length included, which is the form a
// third party reproduces from a published certificate.
const EMBEDDED_ROOTS = [
  {
    name: 'Intel SGX root CA',
    pem: INTEL_SGX_ROOT_CA_PEM,
    serialHex: '22650cd65a9d3489f383b49552bf501b392706ac',
    spkiSha256Hex: 'a0af031289f5d5d4132f9186068a7fc13628633ba235777472e29b6b6c67a49e',
    spkiLength: 91,
  },
  {
    name: 'AMD Milan ARK',
    pem: AMD_ARK_MILAN_PEM,
    serialHex: '010000',
    spkiSha256Hex: '9f056bee44377e29308cb5ffa895bdfb62d18881fa6bed8d6f075b0204089cb9',
    spkiLength: 550,
  },
  {
    name: 'NVIDIA device identity CA',
    pem: NVIDIA_DEVICE_IDENTITY_CA_PEM,
    serialHex: '2d3670b1ca100411c1fec0e82a065b54',
    spkiSha256Hex: 'a90c4eb5acfd3e3d03a25db6a26b84f720ad0503196c627c21ddd48dd85b06a4',
    spkiLength: 120,
  },
] as const;

// The bytes a deployment hands the reader are these constants encoded, so the
// test parses what ships rather than a copy a test invents.
function shippedRoot(pem: string): ParsedCertificate {
  return parseCertificate(pemToDer(new TextEncoder().encode(pem)));
}

function fixtureReportChipId(): Uint8Array {
  const attestation = decodeAttestation(fixture('sev-snp-attestation.bin'));
  if (attestation.platform.kind !== 'sev-snp') {
    throw new Error('expected sev-snp platform');
  }
  return attestation.platform.report.subarray(0x1a0, 0x1e0);
}

describe('AMD KDS certificate parsing', () => {
  it('parses the ARK root', () => {
    const [ark] = parseCertificateChain(ARK);
    expect(ark?.isCa).toBe(true);
    expect(equalBytes(ark!.issuer, ark!.subject)).toBe(true);
    expect(ark!.signatureAlgorithm.kind).toBe('rsa-pss');
    if (ark!.signatureAlgorithm.kind === 'rsa-pss') {
      expect(ark!.signatureAlgorithm.hashOid).toBe('2.16.840.1.101.3.4.2.2');
      expect(ark!.signatureAlgorithm.mgfOid).toBe('1.2.840.113549.1.1.8');
      expect(ark!.signatureAlgorithm.mgfHashOid).toBe('2.16.840.1.101.3.4.2.2');
      expect(ark!.signatureAlgorithm.saltLength).toBe(48);
      expect(ark!.signatureAlgorithm.trailerField).toBe(1);
    }
    expect(ark!.publicKey.kind).toBe('rsa');
    expect(ark!.notBefore).toBe(Date.UTC(2020, 9, 22, 17, 23, 5));
    expect(ark!.notAfter).toBe(Date.UTC(2045, 9, 22, 17, 23, 5));
  });

  it('parses the ASK intermediate', () => {
    const ark = parseCertificateChain(ARK)[0]!;
    const ask = parseCertificateChain(ASK)[0]!;
    expect(ask.isCa).toBe(true);
    expect(equalBytes(ask.issuer, ark.subject)).toBe(true);
    expect(ask.publicKey.kind).toBe('rsa');
  });

  it('parses the VCEK and binds it to the report chip', () => {
    const ask = parseCertificateChain(ASK)[0]!;
    const vcek = parseCertificateChain(VCEK)[0]!;
    expect(vcek.isCa).toBeNull();
    expect(vcek.productName).toBe('Milan-B0');
    expect(vcek.publicKey.kind).toBe('ec-p384');
    if (vcek.publicKey.kind === 'ec-p384') {
      expect(vcek.publicKey.point.length).toBe(97);
      expect(vcek.publicKey.point[0]).toBe(0x04);
    }
    expect(equalBytes(vcek.hwid!, fixtureReportChipId())).toBe(true);
    expect(equalBytes(vcek.issuer, ask.subject)).toBe(true);
    expect(vcek.notBefore).toBe(Date.UTC(2026, 5, 17, 1, 5, 4));
  });

  it('parses concatenated DER certificates', () => {
    const ark = pemToDer(ARK);
    const ask = pemToDer(ASK);
    const combined = new Uint8Array(ark.length + ask.length);
    combined.set(ark, 0);
    combined.set(ask, ark.length);
    const certs = parseCertificateChain(combined);
    expect(certs.length).toBe(2);
    expect(equalBytes(certs[0]!.raw, ark)).toBe(true);
    expect(equalBytes(certs[1]!.raw, ask)).toBe(true);
  });
});

describe('serial and public-key info of the embedded roots', () => {
  it('returns each serialNumber as the DER INTEGER bytes the certificate holds', () => {
    for (const root of EMBEDDED_ROOTS) {
      expect(toHex(shippedRoot(root.pem).serial), root.name).toBe(root.serialHex);
    }
  });

  it('returns each SubjectPublicKeyInfo as the DER span the walk steps over', () => {
    for (const root of EMBEDDED_ROOTS) {
      const cert = shippedRoot(root.pem);
      expect(cert.subjectPublicKeyInfo[0], root.name).toBe(0x30);
      expect(cert.subjectPublicKeyInfo.length, root.name).toBe(root.spkiLength);
      expect(toHex(sha256(cert.subjectPublicKeyInfo)), root.name).toBe(root.spkiSha256Hex);
      // A span of the input, not a re-encoding: the bytes appear verbatim in the
      // certificate that was parsed.
      expect(toHex(cert.raw), root.name).toContain(toHex(cert.subjectPublicKeyInfo));
    }
  });
});

describe('base64 decoding', () => {
  it('decodes padding cases exactly (regression: padded groups must not corrupt bytes)', () => {
    expect(decodeBase64('')).toEqual(new Uint8Array(0));
    expect(decodeBase64('QQ==')).toEqual(new Uint8Array([0x41]));
    expect(decodeBase64('QUI=')).toEqual(new Uint8Array([0x41, 0x42]));
    expect(decodeBase64('QUJD')).toEqual(new Uint8Array([0x41, 0x42, 0x43]));
    expect(decodeBase64('QUJDRA==')).toEqual(new Uint8Array([0x41, 0x42, 0x43, 0x44]));
  });

  it('matches Node decoding across the full certificate bodies', () => {
    for (const pem of [ARK, ASK, VCEK]) {
      const text = new TextDecoder('latin1').decode(pem);
      const body = text
        .replace('-----BEGIN CERTIFICATE-----', '')
        .replace('-----END CERTIFICATE-----', '')
        .replace(/\s/g, '');
      expect(decodeBase64(body)).toEqual(new Uint8Array(Buffer.from(body, 'base64')));
    }
  });

  it('rejects malformed base64', () => {
    expectErrorCode(() => decodeBase64('A'), 'MALFORMED_CERTIFICATE');
    expectErrorCode(() => decodeBase64('A==='), 'MALFORMED_CERTIFICATE');
    expectErrorCode(() => decodeBase64('AB!C'), 'MALFORMED_CERTIFICATE');
    expectErrorCode(() => decodeBase64('AB=C'), 'MALFORMED_CERTIFICATE');
  });
});
