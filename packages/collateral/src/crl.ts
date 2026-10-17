import { equalBytes } from '@ashaveri/attest-core';
import { sha256Hex } from './bytes.js';
import { collateralRefusal, quoteOrDigest, type CollateralRefusal } from './errors.js';
import { isCrlDeclaration, isDeclaredOnly, type CrlOriginDeclaration } from './intel-origin.js';
import { parsePinned, reachAnchor, verifiesUnderLeaf, type Reading } from './read.js';
import { chainCertificates } from './served.js';
import type { RevocationList, RevokedCertificate, SignedWindow } from './types.js';

const OID_ECDSA_SHA256 = '1.2.840.10045.4.3.2';
const OID_ECDSA_SHA384 = '1.2.840.10045.4.3.3';
const OID_CRL_REASON = '2.5.29.21';

/** The algorithm names a refusal can state, keyed by the OID the list carries. */
const ALGORITHM_NAMES: Readonly<Record<string, string>> = {
  [OID_ECDSA_SHA256]: 'ecdsa-with-SHA256',
  [OID_ECDSA_SHA384]: 'ecdsa-with-SHA384',
};

/** RFC 5280's reason codes, named rather than renumbered at a call site. */
const CRL_REASONS: Readonly<Record<number, string>> = {
  0: 'unspecified',
  1: 'keyCompromise',
  2: 'cACompromise',
  3: 'affiliationChanged',
  4: 'superseded',
  5: 'cessationOfOperation',
  6: 'certificateHold',
  8: 'removeFromCRL',
  9: 'privilegeWithdrawn',
  10: 'aACompromise',
};

/** One DER element, with the offsets needed to keep its bytes exactly as they arrived. */
interface Tlv {
  readonly tag: number;
  readonly start: number;
  readonly contentStart: number;
  readonly end: number;
}

/** What a CRL read answered: the list, or the refusal that says why no list was believed. */
export type RevocationReadOutcome = { readonly read: RevocationList } | { readonly refusal: CollateralRefusal };

/**
 * Reads a DER `CertificateList` and believes it in the order the bytes require.
 *
 * The structure is parsed before the chain is walked, because the list's issuer is what selects the
 * certificate that must have signed it. The chain is then walked to a root the caller pinned, and only then
 * is the signature checked over the DER of `tbsCertList`, including the tag and length the list arrived
 * with. Nothing is re-encoded: the returned `blobs` hold the body and the header's certificates as they
 * arrived, and the refusal a bad answer gets names the field that failed.
 *
 * The parser is bounded by the declaration's own byte cap and by strict DER rules: definite lengths only,
 * no multi-byte tags, no trailing data inside any sequence. A list that is not the shape this origin
 * declares answers `COLLATERAL_BLOB_UNREADABLE`, and a list whose signature does not hold answers
 * `COLLATERAL_SIGNATURE_UNVERIFIED`.
 */
export function readPckCrl(body: Uint8Array, chain: Uint8Array | null, reading: Reading): RevocationReadOutcome {
  if (!isCrlDeclaration(reading.declaration)) {
    const code = isDeclaredOnly(reading.declaration)
      ? 'COLLATERAL_ORIGIN_UNSUPPORTED'
      : 'COLLATERAL_BLOB_UNREADABLE';
    return {
      refusal: collateralRefusal(
        code,
        `${reading.declaration.name} answers as ${reading.declaration.answer} and this reader weighs a DER CertificateList alone`,
      ),
    };
  }
  const declaration: CrlOriginDeclaration = reading.declaration;
  if (body.byteLength === 0) {
    return unreadable(declaration, 'the body is empty');
  }
  if (body.byteLength > declaration.maxResponseBytes) {
    return unreadable(
      declaration,
      `the list is ${String(body.byteLength)} bytes, over the ${String(declaration.maxResponseBytes)} this path reads`,
    );
  }
  const parsed = parseCertificateList(body, declaration);
  if ('refusal' in parsed) {
    return parsed;
  }
  const list = parsed.parsed;
  if (chain === null) {
    const header = quoteOrDigest(declaration.chainHeader ?? 'a header this declaration does not name');
    return {
      refusal: collateralRefusal(
        declaration.refusals.anchor,
        `no chain arrived in ${header}, so the list that arrived was weighed by nobody`,
      ),
    };
  }
  const presented = chainCertificates(chain, declaration);
  if ('refusal' in presented) {
    return presented;
  }
  const pinned = parsePinned(reading.query.roots, declaration);
  if ('refusal' in pinned) {
    return pinned;
  }
  const signer = presented.certificates.find((cert) => equalBytes(cert.subject, list.issuer));
  if (signer === undefined) {
    return signatureRefusal(
      declaration,
      `the list names an issuer that no certificate in ${quoteOrDigest(declaration.chainHeader ?? 'the header')} carries`,
    );
  }
  const ordered = [signer, ...presented.certificates.filter((cert) => cert !== signer)];
  const anchor = reachAnchor(ordered, pinned, reading, declaration);
  if ('refusal' in anchor) {
    return anchor;
  }
  if (!verifiesUnderLeaf(signer, list.tbs, list.signature)) {
    return signatureRefusal(declaration, 'the signature over tbsCertList does not hold under the certificate that carries the list issuer name');
  }
  return {
    read: {
      version: list.version,
      signatureAlgorithm: list.signatureAlgorithm,
      issuer: list.issuer,
      window: list.window,
      revoked: list.revoked,
      digest: sha256Hex(body),
      anchorDigest: anchor.digest,
      blobs: [body, ...presented.der],
    },
  };
}

/** The fields a parsed list carries before its signature is believed. */
interface ParsedList {
  readonly version: 1 | 2;
  readonly signatureAlgorithm: 'ecdsa-with-SHA256';
  readonly issuer: Uint8Array;
  readonly window: SignedWindow;
  readonly revoked: readonly RevokedCertificate[];
  /** The DER of the whole `tbsCertList`, tag and length included, which is what the signature covers. */
  readonly tbs: Uint8Array;
  /** The signature BIT STRING's contents, less the unused-bits byte. */
  readonly signature: Uint8Array;
}

/**
 * The DER of one `CertificateList`, parsed field by field.
 *
 * The outer algorithm and the algorithm inside `tbsCertList` must name the same suite, which is the one
 * suite this path reads. The window is required: a list without `nextUpdate` states no end to its own
 * reach, so it cannot answer whether an instant falls inside it. The revoked sequence may be absent, which
 * is an empty list and not an unreadable one.
 */
function parseCertificateList(
  body: Uint8Array,
  declaration: CrlOriginDeclaration,
): { readonly parsed: ParsedList } | { readonly refusal: CollateralRefusal } {
  try {
    const outer = readTlv(body, 0, body.byteLength, 'CertificateList');
    expectTag(outer, 0x30, 'CertificateList');
    if (outer.end !== body.byteLength) {
      fail('trailing data after the CertificateList');
    }
    const tbs = readTlv(body, outer.contentStart, outer.end, 'tbsCertList');
    expectTag(tbs, 0x30, 'tbsCertList');
    const outerAlgorithm = readTlv(body, tbs.end, outer.end, 'signatureAlgorithm');
    expectTag(outerAlgorithm, 0x30, 'signatureAlgorithm');
    const signatureValue = readTlv(body, outerAlgorithm.end, outer.end, 'signatureValue');
    expectTag(signatureValue, 0x03, 'signatureValue');
    if (signatureValue.end !== outer.end) {
      fail('trailing data after signatureValue');
    }
    const signatureAlgorithm = parseAlgorithm(body, outerAlgorithm);
    if (signatureAlgorithm !== 'ecdsa-with-SHA256') {
      fail(`signatureAlgorithm is ${signatureAlgorithm}, not ecdsa-with-SHA256`);
    }
    const signature = bitStringContent(body, signatureValue);

    let at = tbs.contentStart;
    let version: 1 | 2 = 1;
    const first = readTlv(body, at, tbs.end, 'version or signature');
    if (first.tag === 0x02) {
      const stated = positiveInteger(body, first, 'version');
      if (stated === 0n) {
        version = 1;
      } else if (stated === 1n) {
        version = 2;
      } else {
        fail(`version is ${stated.toString()}, not 0 or 1`);
      }
      at = first.end;
    }
    const tbsAlgorithm = readTlv(body, at, tbs.end, 'tbs signature');
    expectTag(tbsAlgorithm, 0x30, 'tbs signature');
    const tbsAlgorithmName = parseAlgorithm(body, tbsAlgorithm);
    if (tbsAlgorithmName !== signatureAlgorithm) {
      fail(`tbsCertList names ${tbsAlgorithmName} and the list names ${signatureAlgorithm}`);
    }
    at = tbsAlgorithm.end;

    const issuerTlv = readTlv(body, at, tbs.end, 'issuer');
    expectTag(issuerTlv, 0x30, 'issuer');
    const issuer = body.slice(issuerTlv.contentStart, issuerTlv.end);
    at = issuerTlv.end;

    const thisUpdateTlv = readTlv(body, at, tbs.end, 'thisUpdate');
    const from = parseTime(body, thisUpdateTlv, 'thisUpdate');
    at = thisUpdateTlv.end;

    const nextUpdateTlv = readTlv(body, at, tbs.end, 'nextUpdate');
    if (nextUpdateTlv.tag !== 0x17 && nextUpdateTlv.tag !== 0x18) {
      fail('the list states no nextUpdate, so it names no window this path can weigh');
    }
    const until = parseTime(body, nextUpdateTlv, 'nextUpdate');
    at = nextUpdateTlv.end;
    if (until <= from) {
      fail('the window closes at or before the instant it opens');
    }

    let revoked: readonly RevokedCertificate[] = [];
    if (at < tbs.end) {
      const next = readTlv(body, at, tbs.end, 'revokedCertificates or crlExtensions');
      if (next.tag === 0x30) {
        revoked = parseRevoked(body, next);
        at = next.end;
      }
    }
    if (at < tbs.end) {
      const extensions = readTlv(body, at, tbs.end, 'crlExtensions');
      expectTag(extensions, 0xa0, 'crlExtensions');
      parseCrlExtensions(body, extensions);
      at = extensions.end;
    }
    if (at !== tbs.end) {
      fail('trailing data inside tbsCertList');
    }

    return {
      parsed: {
        version,
        signatureAlgorithm,
        issuer,
        window: { from, until },
        revoked,
        tbs: body.slice(tbs.start, tbs.end),
        signature,
      },
    };
  } catch (err) {
    return unreadable(declaration, err instanceof Error ? err.message : 'the DER list did not parse');
  }
}

/** The revokedCertificates sequence, each entry's serial, date and reason. */
function parseRevoked(body: Uint8Array, sequence: Tlv): readonly RevokedCertificate[] {
  const entries: RevokedCertificate[] = [];
  let at = sequence.contentStart;
  while (at < sequence.end) {
    const entry = readTlv(body, at, sequence.end, 'revoked entry');
    expectTag(entry, 0x30, 'revoked entry');
    let inner = entry.contentStart;
    const serialTlv = readTlv(body, inner, entry.end, 'serial');
    expectTag(serialTlv, 0x02, 'serial');
    const serial = body.slice(serialTlv.contentStart, serialTlv.end);
    const serialHex = positiveInteger(body, serialTlv, 'serial').toString(16);
    inner = serialTlv.end;
    const dateTlv = readTlv(body, inner, entry.end, 'revocationDate');
    const revokedAt = parseTime(body, dateTlv, 'revocationDate');
    inner = dateTlv.end;
    let reasonCode: number | null = null;
    if (inner < entry.end) {
      const extensions = readTlv(body, inner, entry.end, 'crlEntryExtensions');
      expectTag(extensions, 0x30, 'crlEntryExtensions');
      reasonCode = parseEntryExtensions(body, extensions);
      inner = extensions.end;
    }
    if (inner !== entry.end) {
      fail('trailing data inside a revoked entry');
    }
    entries.push({
      serial,
      serialHex,
      revokedAt,
      reasonCode,
      reason: reasonCode === null ? null : CRL_REASONS[reasonCode] ?? null,
    });
    at = entry.end;
  }
  return entries;
}

/** One entry's extensions, read for its reason and refused where an unknown critical one sits. */
function parseEntryExtensions(body: Uint8Array, sequence: Tlv): number | null {
  let reason: number | null = null;
  let at = sequence.contentStart;
  while (at < sequence.end) {
    const extension = readTlv(body, at, sequence.end, 'entry extension');
    expectTag(extension, 0x30, 'entry extension');
    let inner = extension.contentStart;
    const oidTlv = readTlv(body, inner, extension.end, 'extension oid');
    expectTag(oidTlv, 0x06, 'extension oid');
    const oid = decodeOid(body, oidTlv);
    inner = oidTlv.end;
    let critical = false;
    if (inner < extension.end && (body[inner] as number) === 0x01) {
      const criticalTlv = readTlv(body, inner, extension.end, 'extension critical');
      if (criticalTlv.end - criticalTlv.contentStart !== 1) {
        fail('an extension critical flag is not one byte');
      }
      critical = (body[criticalTlv.contentStart] as number) !== 0;
      inner = criticalTlv.end;
    }
    const valueTlv = readTlv(body, inner, extension.end, 'extension value');
    expectTag(valueTlv, 0x04, 'extension value');
    inner = valueTlv.end;
    if (inner !== extension.end) {
      fail('trailing data inside an entry extension');
    }
    if (oid === OID_CRL_REASON) {
      if (reason !== null) {
        fail('an entry states more than one cRLReason extension');
      }
      reason = parseReason(body, valueTlv);
    } else if (critical) {
      fail(`an entry states critical extension ${oid}, which this reader does not know`);
    }
    at = extension.end;
  }
  return reason;
}

/** A cRLReason extension's OCTET STRING, read as the one ENUMERATED it wraps. */
function parseReason(body: Uint8Array, valueTlv: Tlv): number {
  const inner = readTlv(body, valueTlv.contentStart, valueTlv.end, 'cRLReason');
  expectTag(inner, 0x0a, 'cRLReason');
  if (inner.end !== valueTlv.end) {
    fail('trailing data inside a cRLReason extension');
  }
  const length = inner.end - inner.contentStart;
  if (length === 0 || length > 1) {
    fail('cRLReason is not one byte');
  }
  return body[inner.contentStart] as number;
}

/** The list's CRL extensions, skipped where they are known to nobody but never where they are critical. */
function parseCrlExtensions(body: Uint8Array, wrapper: Tlv): void {
  const sequence = readTlv(body, wrapper.contentStart, wrapper.end, 'crlExtensions sequence');
  expectTag(sequence, 0x30, 'crlExtensions sequence');
  if (sequence.end !== wrapper.end) {
    fail('trailing data inside crlExtensions');
  }
  let at = sequence.contentStart;
  while (at < sequence.end) {
    const extension = readTlv(body, at, sequence.end, 'crl extension');
    expectTag(extension, 0x30, 'crl extension');
    let inner = extension.contentStart;
    const oidTlv = readTlv(body, inner, extension.end, 'extension oid');
    expectTag(oidTlv, 0x06, 'extension oid');
    const oid = decodeOid(body, oidTlv);
    inner = oidTlv.end;
    let critical = false;
    if (inner < extension.end && (body[inner] as number) === 0x01) {
      const criticalTlv = readTlv(body, inner, extension.end, 'extension critical');
      if (criticalTlv.end - criticalTlv.contentStart !== 1) {
        fail('an extension critical flag is not one byte');
      }
      critical = (body[criticalTlv.contentStart] as number) !== 0;
      inner = criticalTlv.end;
    }
    const valueTlv = readTlv(body, inner, extension.end, 'extension value');
    expectTag(valueTlv, 0x04, 'extension value');
    if (valueTlv.end !== extension.end) {
      fail('trailing data inside a crl extension');
    }
    if (critical) {
      fail(`the list states critical extension ${oid}, which this reader does not know`);
    }
    at = extension.end;
  }
}

/** The algorithm identifier as the name it carries, with the parameter field required absent. */
function parseAlgorithm(body: Uint8Array, sequence: Tlv): string {
  const oidTlv = readTlv(body, sequence.contentStart, sequence.end, 'algorithm oid');
  expectTag(oidTlv, 0x06, 'algorithm oid');
  if (oidTlv.end !== sequence.end) {
    fail(`algorithm ${decodeOid(body, oidTlv)} carries parameters this path does not read`);
  }
  const oid = decodeOid(body, oidTlv);
  return ALGORITHM_NAMES[oid] ?? oid;
}

/**
 * An OID as its own dotted text.
 *
 * The first sub-identifier packs the first two arcs, as X.690 states it, and a value whose last byte still
 * has the continuation bit set is truncated rather than a very large arc.
 */
function decodeOid(body: Uint8Array, tlv: Tlv): string {
  if (tlv.end === tlv.contentStart) {
    fail('an OID states no arc');
  }
  const arcs: number[] = [];
  let value = 0;
  for (let at = tlv.contentStart; at < tlv.end; at += 1) {
    const byte = body[at] as number;
    if (value > Number.MAX_SAFE_INTEGER / 128) {
      fail('an OID arc is larger than this reader can state');
    }
    value = value * 128 + (byte & 0x7f);
    if ((byte & 0x80) === 0) {
      arcs.push(value);
      value = 0;
    }
  }
  if ((body[tlv.end - 1] as number) & 0x80) {
    fail('an OID ends in the middle of an arc');
  }
  const first = arcs[0] as number;
  const firstArc = first < 40 ? 0 : first < 80 ? 1 : 2;
  const secondArc = first < 40 ? first : first < 80 ? first - 40 : first - 80;
  return [firstArc, secondArc, ...arcs.slice(1)].join('.');
}

/** One Time value as Unix seconds, with the calendar checked rather than normalized. */
function parseTime(body: Uint8Array, tlv: Tlv, context: string): number {
  if (tlv.tag !== 0x17 && tlv.tag !== 0x18) {
    fail(`${context} is neither UTCTime nor GeneralizedTime`);
  }
  const text = new TextDecoder('latin1').decode(body.subarray(tlv.contentStart, tlv.end));
  const match = tlv.tag === 0x17
    ? /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/u.exec(text)
    : /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/u.exec(text);
  if (match === null) {
    fail(`${context} is not a DER time`);
  }
  let year = Number(match[1]);
  if (tlv.tag === 0x17) {
    year += year >= 50 ? 1900 : 2000;
  }
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const millis = Date.UTC(year, month - 1, day, hour, minute, second);
  const date = new Date(millis);
  if (
    date.getUTCFullYear() !== year
    || date.getUTCMonth() !== month - 1
    || date.getUTCDate() !== day
    || date.getUTCHours() !== hour
    || date.getUTCMinutes() !== minute
    || date.getUTCSeconds() !== second
  ) {
    fail(`${context} names a calendar instant that does not exist`);
  }
  return Math.floor(millis / 1000);
}

/** A DER INTEGER's canonical unsigned value, refused where its bytes would read as negative or redundant. */
function positiveInteger(body: Uint8Array, tlv: Tlv, context: string): bigint {
  const length = tlv.end - tlv.contentStart;
  if (length === 0) {
    fail(`${context} is an empty INTEGER`);
  }
  const first = body[tlv.contentStart] as number;
  if ((first & 0x80) !== 0) {
    fail(`${context} is negative`);
  }
  if (length > 1 && first === 0 && ((body[tlv.contentStart + 1] as number) & 0x80) === 0) {
    fail(`${context} has a redundant leading zero`);
  }
  let value = 0n;
  for (let at = tlv.contentStart; at < tlv.end; at += 1) {
    value = (value << 8n) | BigInt(body[at] as number);
  }
  return value;
}

/** A BIT STRING's contents, less the unused-bits byte, which must state no unused bits here. */
function bitStringContent(body: Uint8Array, tlv: Tlv): Uint8Array {
  const length = tlv.end - tlv.contentStart;
  if (length < 2) {
    fail('signatureValue is too short to hold a signature');
  }
  if ((body[tlv.contentStart] as number) !== 0) {
    fail('signatureValue states unused bits');
  }
  return body.slice(tlv.contentStart + 1, tlv.end);
}

/** One DER element read with a definite length, a bounded length field and no trailing bytes implied. */
function readTlv(body: Uint8Array, offset: number, limit: number, context: string): Tlv {
  if (offset >= limit) {
    fail(`${context} is truncated at its tag`);
  }
  const tag = body[offset] as number;
  if ((tag & 0x1f) === 0x1f) {
    fail(`${context} uses a multi-byte tag`);
  }
  let at = offset + 1;
  if (at >= limit) {
    fail(`${context} is truncated at its length`);
  }
  const first = body[at] as number;
  let length: number;
  if (first < 0x80) {
    length = first;
    at += 1;
  } else {
    const count = first & 0x7f;
    if (count === 0) {
      fail(`${context} uses an indefinite length`);
    }
    if (count > 4) {
      fail(`${context} states a length wider than four bytes`);
    }
    if (at + count >= limit) {
      fail(`${context} is truncated inside its length`);
    }
    if ((body[at + 1] as number) === 0) {
      fail(`${context} states a length with a leading zero`);
    }
    length = 0;
    for (let index = 1; index <= count; index += 1) {
      length = length * 0x100 + (body[at + index] as number);
    }
    if (length < 0x80) {
      fail(`${context} states a long-form length for a value that fits the short form`);
    }
    at += 1 + count;
  }
  if (length > limit - at) {
    fail(`${context} overruns the bytes that carry it`);
  }
  return { tag, start: offset, contentStart: at, end: at + length };
}

function expectTag(tlv: Tlv, tag: number, context: string): void {
  if (tlv.tag !== tag) {
    fail(`${context} is tag 0x${tlv.tag.toString(16)}, not 0x${tag.toString(16)}`);
  }
}

function fail(why: string): never {
  throw new Error(why);
}

function unreadable(declaration: CrlOriginDeclaration, why: string): { readonly refusal: CollateralRefusal } {
  return { refusal: collateralRefusal(declaration.refusals.envelope, why) };
}

function signatureRefusal(declaration: CrlOriginDeclaration, why: string): { readonly refusal: CollateralRefusal } {
  return { refusal: collateralRefusal(declaration.refusals.signature, why) };
}
