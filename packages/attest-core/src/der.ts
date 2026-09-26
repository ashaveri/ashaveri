import { p256, p384 } from '@noble/curves/nist.js';
import { sha256, sha384 } from '@noble/hashes/sha2.js';
import { fail } from './errors.js';
import { verifyRsaPssSha384 } from './rsa-pss.js';

const OID_EC_PUBLIC_KEY = '1.2.840.10045.2.1';
const OID_P256 = '1.2.840.10045.3.1.7';
const OID_P384 = '1.3.132.0.34';
const OID_ECDSA_SHA256 = '1.2.840.10045.4.3.2';
const OID_ECDSA_SHA384 = '1.2.840.10045.4.3.3';
const OID_RSA_ENCRYPTION = '1.2.840.113549.1.1.1';
const OID_RSASSA_PSS = '1.2.840.113549.1.1.10';
const OID_SHA384 = '2.16.840.1.101.3.4.2.2';
const OID_MGF1 = '1.2.840.113549.1.1.8';
const OID_PRODUCT_NAME = '1.3.6.1.4.1.3704.1.2';
const OID_HWID = '1.3.6.1.4.1.3704.1.4';
const OID_BASIC_CONSTRAINTS = '2.5.29.19';

interface Tlv {
  readonly tag: number;
  readonly content: Uint8Array;
  readonly total: number;
}

function readTlv(data: Uint8Array, offset: number, context: string): Tlv {
  if (offset >= data.length) {
    fail('MALFORMED_CERTIFICATE', `${context}: truncated at tag`);
  }
  const tag = data[offset] as number;
  if ((tag & 0x1f) === 0x1f) {
    fail('MALFORMED_CERTIFICATE', `${context}: multi-byte tags are not supported`);
  }
  let pos = offset + 1;
  if (pos >= data.length) {
    fail('MALFORMED_CERTIFICATE', `${context}: truncated at length`);
  }
  const first = data[pos] as number;
  let length: number;
  if (first < 0x80) {
    length = first;
    pos += 1;
  } else {
    const count = first & 0x7f;
    if (count === 0 || count > 4 || pos + count > data.length) {
      fail('MALFORMED_CERTIFICATE', `${context}: unsupported length encoding`);
    }
    length = 0;
    for (let i = 0; i < count; i++) {
      length = length * 0x100 + (data[pos + 1 + i] as number);
    }
    pos += 1 + count;
  }
  if (pos + length > data.length) {
    fail('MALFORMED_CERTIFICATE', `${context}: content exceeds input`);
  }
  return { tag, content: data.slice(pos, pos + length), total: pos + length - offset };
}

function expect(context: string, tlv: Tlv, tag: number): Tlv {
  if (tlv.tag !== tag) {
    fail('MALFORMED_CERTIFICATE', `${context}: expected tag 0x${tag.toString(16)}, got 0x${tlv.tag.toString(16)}`);
  }
  return tlv;
}

function readOid(content: Uint8Array): string {
  const arcs: number[] = [];
  let value = 0;
  for (let i = 0; i < content.length; i++) {
    const b = content[i] as number;
    value = value * 128 + (b & 0x7f);
    if ((b & 0x80) === 0) {
      arcs.push(value);
      value = 0;
    }
  }
  if (arcs.length < 2) {
    return '';
  }
  // The first sub-identifier packs the first two arcs as X*40 + Y.
  const first = arcs[0] as number;
  const firstArc = first < 40 ? 0 : first < 80 ? 1 : 2;
  const secondArc = first < 40 ? first : first < 80 ? first - 40 : first - 80;
  return [firstArc, secondArc, ...arcs.slice(1)].join('.');
}

function readInteger(content: Uint8Array, context: string): bigint {
  if (content.length === 0) {
    fail('MALFORMED_CERTIFICATE', `${context}: empty INTEGER`);
  }
  let value = 0n;
  for (const b of content) {
    value = (value << 8n) | BigInt(b);
  }
  return value;
}

function readTime(tlv: Tlv, context: string): number {
  const text = new TextDecoder('latin1').decode(tlv.content);
  const match = tlv.tag === 0x17 ? /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(text) : /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(text);
  if (!match) {
    fail('MALFORMED_CERTIFICATE', `${context}: unsupported time value ${text}`);
  }
  let year = Number(match[1]);
  if (tlv.tag === 0x17) {
    year += year >= 50 ? 1900 : 2000;
  }
  return Date.UTC(year, Number(match[2]) - 1, Number(match[3]), Number(match[4]), Number(match[5]), Number(match[6]));
}

export type CertificatePublicKey =
  | { readonly kind: 'ec-p384'; readonly point: Uint8Array }
  | { readonly kind: 'ec-p256'; readonly point: Uint8Array }
  | { readonly kind: 'rsa'; readonly modulus: bigint; readonly exponent: bigint };

export type SignatureAlgorithm =
  | { readonly kind: 'rsa-pss'; readonly hashOid: string; readonly mgfOid: string; readonly mgfHashOid: string; readonly saltLength: number; readonly trailerField: number }
  | { readonly kind: 'ecdsa-sha384' }
  | { readonly kind: 'ecdsa-sha256' }
  | { readonly kind: 'unsupported'; readonly oid: string };

export interface ParsedCertificate {
  readonly raw: Uint8Array;
  readonly tbs: Uint8Array;
  readonly signatureAlgorithm: SignatureAlgorithm;
  readonly signature: Uint8Array;
  readonly issuer: Uint8Array;
  readonly subject: Uint8Array;
  readonly notBefore: number;
  readonly notAfter: number;
  readonly publicKey: CertificatePublicKey;
  readonly productName: string | null;
  readonly hwid: Uint8Array | null;
  readonly isCa: boolean | null;
}

// Parses an AlgorithmIdentifier SEQUENCE content (after the outer SEQUENCE
// wrapper) into the signature algorithms AMD KDS certificates actually use.
function parseSignatureAlgorithm(content: Uint8Array, context: string): SignatureAlgorithm {
  const oidTlv = expect(`${context} oid`, readTlv(content, 0, `${context} oid`), 0x06);
  const oid = readOid(oidTlv.content);
  const offset = oidTlv.total;
  if (oid === OID_ECDSA_SHA384) {
    if (offset !== content.length) {
      fail('UNSUPPORTED_CERT_ALGORITHM', `${context}: ECDSA-SHA384 parameters must be absent`);
    }
    return { kind: 'ecdsa-sha384' };
  }
  if (oid === OID_ECDSA_SHA256) {
    if (offset !== content.length) {
      fail('UNSUPPORTED_CERT_ALGORITHM', `${context}: ECDSA-SHA256 parameters must be absent`);
    }
    return { kind: 'ecdsa-sha256' };
  }
  if (oid === OID_RSASSA_PSS) {
    // AMD KDS wraps the PSS parameters in an extra SEQUENCE; RFC 4055 puts
    // the tagged fields directly in the AlgorithmIdentifier. Accept both.
    let fields = content;
    let fieldsOffset = oidTlv.total;
    if (fieldsOffset < content.length && (content[fieldsOffset] as number) === 0x30) {
      const wrapper = expect(`${context} pss parameters`, readTlv(content, fieldsOffset, `${context} pss parameters`), 0x30);
      if (fieldsOffset + wrapper.total !== content.length) {
        fail('MALFORMED_CERTIFICATE', `${context}: trailing data after RSA-PSS parameters`);
      }
      fields = wrapper.content;
      fieldsOffset = 0;
    }
    let hashOid = '';
    let mgfOid = '';
    let mgfHashOid = '';
    let saltLength = -1;
    let trailerField = 1;
    let offset = fieldsOffset;
    while (offset < fields.length) {
      const field = readTlv(fields, offset, `${context} pss parameter`);
      offset += field.total;
      switch (field.tag) {
        case 0xa0: {
          const hashAlg = expect(`${context} hashAlgorithm`, field, 0xa0);
          const inner = expect(`${context} hashAlgorithm inner`, readTlv(hashAlg.content, 0, `${context} hashAlgorithm`), 0x30);
          hashOid = readOid(expect(`${context} hash oid`, readTlv(inner.content, 0, `${context} hash oid`), 0x06).content);
          break;
        }
        case 0xa1: {
          const mgf = expect(`${context} maskGenAlgorithm`, field, 0xa1);
          const inner = expect(`${context} maskGenAlgorithm inner`, readTlv(mgf.content, 0, `${context} maskGenAlgorithm`), 0x30);
          const mgfOidTlv = expect(`${context} mgf oid`, readTlv(inner.content, 0, `${context} mgf oid`), 0x06);
          mgfOid = readOid(mgfOidTlv.content);
          const mgfHash = expect(`${context} mgf hash alg`, readTlv(inner.content, mgfOidTlv.total, `${context} mgf hash alg`), 0x30);
          mgfHashOid = readOid(expect(`${context} mgf hash oid`, readTlv(mgfHash.content, 0, `${context} mgf hash oid`), 0x06).content);
          break;
        }
        case 0xa2: {
          const salt = expect(`${context} saltLength`, readTlv(field.content, 0, `${context} saltLength`), 0x02);
          saltLength = Number(readInteger(salt.content, `${context} saltLength`));
          break;
        }
        case 0xa3: {
          const trailer = expect(`${context} trailerField`, readTlv(field.content, 0, `${context} trailerField`), 0x02);
          trailerField = Number(readInteger(trailer.content, `${context} trailerField`));
          break;
        }
        default:
          fail('MALFORMED_CERTIFICATE', `${context}: unexpected RSA-PSS parameter tag 0x${field.tag.toString(16)}`);
      }
    }
    if (hashOid === '' || mgfOid === '' || saltLength < 0) {
      fail('UNSUPPORTED_CERT_ALGORITHM', `${context}: RSA-PSS parameters are incomplete (AMD certificates specify hash, mask, and salt length explicitly)`);
    }
    return { kind: 'rsa-pss', hashOid, mgfOid, mgfHashOid, saltLength, trailerField };
  }
  return { kind: 'unsupported', oid };
}

function parseSubjectPublicKeyInfo(spki: Uint8Array): CertificatePublicKey {
  const alg = expect('spki algorithm', readTlv(spki, 0, 'spki algorithm'), 0x30);
  const key = expect('spki key', readTlv(spki, alg.total, 'spki key'), 0x03);
  if (key.content.length < 2 || (key.content[0] as number) !== 0) {
    fail('MALFORMED_CERTIFICATE', 'public key BIT STRING has nonzero unused bits');
  }
  const point = key.content.slice(1);
  const oidTlv = expect('spki alg oid', readTlv(alg.content, 0, 'spki alg oid'), 0x06);
  const algorithmOid = readOid(oidTlv.content);
  if (algorithmOid === OID_EC_PUBLIC_KEY) {
    if (alg.content.length <= oidTlv.total) {
      fail('MALFORMED_CERTIFICATE', 'EC public key is missing its curve parameter');
    }
    const curveOid = readOid(expect('spki curve oid', readTlv(alg.content, oidTlv.total, 'spki curve oid'), 0x06).content);
    const curve = curveOid === OID_P384 ? { kind: 'ec-p384' as const, name: 'P-384', pointLength: 97 }
      : curveOid === OID_P256 ? { kind: 'ec-p256' as const, name: 'P-256', pointLength: 65 }
      : null;
    if (curve === null) {
      fail('UNSUPPORTED_CERT_ALGORITHM', `EC certificate uses a curve other than P-256 or P-384 (${curveOid})`);
    }
    if (point.length !== curve.pointLength || (point[0] as number) !== 0x04) {
      fail('UNSUPPORTED_CERT_ALGORITHM', `public key is not an uncompressed ${curve.name} point`);
    }
    return { kind: curve.kind, point };
  }
  if (algorithmOid === OID_RSA_ENCRYPTION) {
    const rsaKey = expect('rsa public key', readTlv(point, 0, 'rsa public key'), 0x30);
    const modulusTlv = expect('rsa modulus', readTlv(rsaKey.content, 0, 'rsa modulus'), 0x02);
    const modulus = readInteger(modulusTlv.content, 'rsa modulus');
    const exponentTlv = expect('rsa exponent', readTlv(rsaKey.content, modulusTlv.total, 'rsa exponent'), 0x02);
    const exponent = readInteger(exponentTlv.content, 'rsa exponent');
    const bits = modulus.toString(2).length;
    if (bits < 2048 || bits > 8192) {
      fail('UNSUPPORTED_CERT_ALGORITHM', `RSA modulus is ${bits} bits, expected 2048 to 8192`);
    }
    if (exponent < 3n || exponent % 2n === 0n) {
      fail('UNSUPPORTED_CERT_ALGORITHM', 'RSA public exponent is not a positive odd number');
    }
    return { kind: 'rsa', modulus, exponent };
  }
  fail('UNSUPPORTED_CERT_ALGORITHM', `public key algorithm ${algorithmOid} is not RSA or EC`);
}

export function parseCertificate(der: Uint8Array): ParsedCertificate {
  const certificate = expect('certificate', readTlv(der, 0, 'certificate'), 0x30);
  const certContentOffset = der.length - certificate.content.length;
  let offset = 0;
  const tbs = expect('tbsCertificate', readTlv(certificate.content, offset, 'tbsCertificate'), 0x30);
  // X.509 signatures cover the DER encoding of the whole TBSCertificate,
  // including its SEQUENCE tag and length, not just the field list.
  const tbsDer = der.slice(certContentOffset, certContentOffset + tbs.total);
  offset += tbs.total;
  const sigAlg = expect('signatureAlgorithm', readTlv(certificate.content, offset, 'signatureAlgorithm'), 0x30);
  offset += sigAlg.total;
  const sigValue = expect('signatureValue', readTlv(certificate.content, offset, 'signatureValue'), 0x03);
  offset += sigValue.total;
  if (offset !== certificate.content.length) {
    fail('MALFORMED_CERTIFICATE', 'trailing data after certificate fields');
  }
  const signatureAlgorithm = parseSignatureAlgorithm(sigAlg.content, 'signatureAlgorithm');

  let tbsOffset = 0;
  const versionTlv = readTlv(tbs.content, tbsOffset, 'tbs field');
  if (versionTlv.tag === 0xa0) {
    tbsOffset += versionTlv.total;
  }
  tbsOffset += expect('serialNumber', readTlv(tbs.content, tbsOffset, 'serialNumber'), 0x02).total;
  const tbsSignature = expect('tbs signature', readTlv(tbs.content, tbsOffset, 'tbs signature'), 0x30);
  tbsOffset += tbsSignature.total;
  const issuer = expect('issuer', readTlv(tbs.content, tbsOffset, 'issuer'), 0x30);
  tbsOffset += issuer.total;
  const validity = expect('validity', readTlv(tbs.content, tbsOffset, 'validity'), 0x30);
  tbsOffset += validity.total;
  const subject = expect('subject', readTlv(tbs.content, tbsOffset, 'subject'), 0x30);
  tbsOffset += subject.total;
  const spki = expect('subjectPublicKeyInfo', readTlv(tbs.content, tbsOffset, 'spki'), 0x30);
  tbsOffset += spki.total;
  const publicKey = parseSubjectPublicKeyInfo(spki.content);

  // RFC 5280 requires the outer and TBS signature algorithms to match; a
  // mismatch is a classic signature-substitution vector.
  const tbsSignatureAlgorithm = parseSignatureAlgorithm(tbsSignature.content, 'tbs signature');
  if (JSON.stringify(tbsSignatureAlgorithm) !== JSON.stringify(signatureAlgorithm)) {
    fail('CERT_CHAIN_INVALID', 'signatureAlgorithm does not match the TBSCertificate signature field');
  }

  let notBefore = 0;
  let notAfter = 0;
  {
    let vOffset = 0;
    const notBeforeTlv = readTlv(validity.content, vOffset, 'notBefore');
    notBefore = readTime(notBeforeTlv, 'notBefore');
    vOffset += notBeforeTlv.total;
    const notAfterTlv = readTlv(validity.content, vOffset, 'notAfter');
    notAfter = readTime(notAfterTlv, 'notAfter');
    vOffset += notAfterTlv.total;
    if (vOffset !== validity.content.length) {
      fail('MALFORMED_CERTIFICATE', 'unexpected extra validity fields');
    }
  }

  let productName: string | null = null;
  let hwid: Uint8Array | null = null;
  let isCa: boolean | null = null;
  while (tbsOffset < tbs.content.length) {
    const field = readTlv(tbs.content, tbsOffset, 'tbs trailing field');
    tbsOffset += field.total;
    if (field.tag !== 0xa3) {
      continue;
    }
    const extensions = expect('extensions', readTlv(field.content, 0, 'extensions'), 0x30);
    let extOffset = 0;
    while (extOffset < extensions.content.length) {
      const ext = expect('extension', readTlv(extensions.content, extOffset, 'extension'), 0x30);
      extOffset += ext.total;
      let inner = 0;
      const extOid = expect('extension oid', readTlv(ext.content, inner, 'ext oid'), 0x06);
      inner += extOid.total;
      const oid = readOid(extOid.content);
      if (oid === OID_PRODUCT_NAME || oid === OID_HWID || oid === OID_BASIC_CONSTRAINTS) {
        // Extensions may carry a `critical` BOOLEAN between the OID and value.
        let afterOid = readTlv(ext.content, inner, 'ext value');
        if (afterOid.tag === 0x01) {
          inner += afterOid.total;
          afterOid = readTlv(ext.content, inner, 'ext value');
        }
        const value = expect('ext value', afterOid, 0x04);
        if (oid === OID_PRODUCT_NAME) {
          const ia5 = expect('product name', readTlv(value.content, 0, 'product name'), 0x16);
          productName = new TextDecoder('latin1').decode(ia5.content);
        } else if (oid === OID_HWID) {
          if (value.content.length !== 64) {
            fail('MALFORMED_CERTIFICATE', `hwid extension is ${value.content.length} bytes, expected 64`);
          }
          hwid = value.content;
        } else {
          const bc = expect('basic constraints', readTlv(value.content, 0, 'basic constraints'), 0x30);
          // BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER OPTIONAL }
          let bcOffset = 0;
          let ca = false;
          if (bc.content[bcOffset] === 0x01) {
            const caBool = expect('basic constraints cA', readTlv(bc.content, bcOffset, 'basic constraints cA'), 0x01);
            if (caBool.content.length !== 1) {
              fail('MALFORMED_CERTIFICATE', 'basic constraints cA BOOLEAN must be exactly one byte');
            }
            ca = (caBool.content[0] as number) !== 0;
            bcOffset += caBool.total;
          }
          if (bcOffset < bc.content.length) {
            expect('basic constraints pathLen', readTlv(bc.content, bcOffset, 'basic constraints pathLen'), 0x02);
          }
          isCa = ca;
        }
      }
    }
  }

  const signatureContent = sigValue.content;
  if (signatureContent.length < 2 || (signatureContent[0] as number) !== 0) {
    fail('MALFORMED_CERTIFICATE', 'signature BIT STRING has nonzero unused bits');
  }

  return {
    raw: der,
    tbs: tbsDer,
    signatureAlgorithm,
    signature: signatureContent.slice(1),
    issuer: issuer.content,
    subject: subject.content,
    notBefore,
    notAfter,
    publicKey,
    productName,
    hwid,
    isCa,
  };
}

export function parseCertificateChain(data: Uint8Array): ParsedCertificate[] {
  const text = new TextDecoder('latin1').decode(data);
  if (text.includes('-----BEGIN')) {
    const certs: ParsedCertificate[] = [];
    const pattern = /-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]+?)-----END CERTIFICATE-----/g;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(text)) !== null) {
      certs.push(parseCertificate(decodeBase64((match[1] as string).replace(/\s/g, ''))));
    }
    if (certs.length === 0) {
      fail('MALFORMED_CERTIFICATE', 'PEM input contains no CERTIFICATE blocks');
    }
    return certs;
  }
  const certs: ParsedCertificate[] = [];
  let offset = 0;
  while (offset < data.length) {
    if (data[offset] !== 0x30) {
      fail('MALFORMED_CERTIFICATE', `byte ${offset} is not the start of a DER certificate`);
    }
    const tlv = readTlv(data, offset, 'certificate chain entry');
    certs.push(parseCertificate(data.slice(offset, offset + tlv.total)));
    offset += tlv.total;
  }
  if (certs.length === 0) {
    fail('MALFORMED_CERTIFICATE', 'certificate chain input is empty');
  }
  return certs;
}

/** Rejects a certificate whose validity window does not contain `now`. */
export function checkCertificateValidity(cert: ParsedCertificate, now: number, name: string): void {
  if (now < cert.notBefore || now > cert.notAfter) {
    fail('CERT_EXPIRED', `${name} certificate is not valid at the verification time`);
  }
}

function derInteger(value: bigint): Uint8Array {
  const bytes: number[] = [];
  let remaining = value;
  do {
    bytes.unshift(Number(remaining & 0xffn));
    remaining >>= 8n;
  } while (remaining > 0n);
  // A leading byte of 0x80 or more would read as a negative INTEGER.
  if ((bytes[0] as number) >= 0x80) {
    bytes.unshift(0);
  }
  return Uint8Array.from([0x02, bytes.length, ...bytes]);
}

/** DER-encodes an ECDSA signature pair, the form every verify call here wants. */
export function derEcdsaSignature(r: bigint, s: bigint, curveOrder: bigint): Uint8Array {
  if (r <= 0n || r >= curveOrder || s <= 0n || s >= curveOrder) {
    fail('BAD_SIGNATURE', 'signature R or S is out of the curve order range');
  }
  const rDer = derInteger(r);
  const sDer = derInteger(s);
  const length = rDer.length + sDer.length;
  if (length < 0x80) {
    return Uint8Array.from([0x30, length, ...rDer, ...sDer]);
  }
  return Uint8Array.from([0x30, 0x81, length, ...rDer, ...sDer]);
}

/**
 * Verifies `cert`'s signature under `issuer`'s public key over the DER of its
 * TBSCertificate. RSA-PSS is accepted only with the parameters the AMD KDS
 * certificates carry (SHA-384 digest, MGF1-SHA384, 48-byte salt), so a chain
 * cannot weaken them; the ECDSA branches pair each hash with its own curve.
 */
export function verifyCertificateSignature(issuer: ParsedCertificate, cert: ParsedCertificate, name: string): void {
  const alg = cert.signatureAlgorithm;
  if (alg.kind === 'rsa-pss') {
    if (alg.hashOid !== OID_SHA384 || alg.mgfOid !== OID_MGF1 || alg.mgfHashOid !== OID_SHA384 || alg.saltLength !== 48 || alg.trailerField !== 1) {
      fail('UNSUPPORTED_CERT_ALGORITHM', `${name} RSA-PSS parameters must be SHA-384 with MGF1-SHA384 and a 48-byte salt`);
    }
    if (issuer.publicKey.kind !== 'rsa') {
      fail('UNSUPPORTED_CERT_ALGORITHM', `${name} is RSA-PSS signed but the issuer key is not RSA`);
    }
    if (!verifyRsaPssSha384(cert.tbs, cert.signature, issuer.publicKey.modulus, issuer.publicKey.exponent, alg.saltLength)) {
      fail('BAD_SIGNATURE', `${name} signature does not verify under its issuer`);
    }
    return;
  }
  if (alg.kind === 'unsupported') {
    fail('UNSUPPORTED_CERT_ALGORITHM', `${name} uses unsupported signature algorithm ${alg.oid}`);
  }
  const key = issuer.publicKey;
  if (key.kind !== 'ec-p384' && key.kind !== 'ec-p256') {
    fail('UNSUPPORTED_CERT_ALGORITHM', `${name} is ${alg.kind} signed but the issuer key is not EC`);
  }
  // Each hash must be paired with its own curve: an ECDSA-SHA256 signature
  // under a P-384 key is a substitution, not a weaker but acceptable choice.
  if ((alg.kind === 'ecdsa-sha384') !== (key.kind === 'ec-p384')) {
    fail('UNSUPPORTED_CERT_ALGORITHM', `${name} is ${alg.kind} signed but the issuer key is ${key.kind}`);
  }
  const valid = alg.kind === 'ecdsa-sha384'
    ? p384.verify(cert.signature, sha384(cert.tbs), key.point, { format: 'der' })
    : p256.verify(cert.signature, sha256(cert.tbs), key.point, { format: 'der' });
  if (!valid) {
    fail('BAD_SIGNATURE', `${name} signature does not verify under its issuer`);
  }
}

export function decodeBase64(value: string): Uint8Array {
  if (value.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) {
    fail('MALFORMED_CERTIFICATE', 'invalid base64 payload');
  }
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  // Index trimming rather than /=+$/: this string arrives from a quoted document, and an
  // anchored quantifier costs one backtrack per character of a tail that does not end matched.
  let padding = value.length;
  while (padding > 0 && value[padding - 1] === '=') {
    padding -= 1;
  }
  const body = value.slice(0, padding);
  const out = new Uint8Array(Math.floor((body.length * 6) / 8));
  let buffer = 0;
  let bits = 0;
  let pos = 0;
  for (let i = 0; i < body.length; i++) {
    buffer = (buffer << 6) | alphabet.indexOf(body[i] as string);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[pos++] = (buffer >>> bits) & 0xff;
      buffer &= (1 << bits) - 1;
    }
  }
  return out;
}
