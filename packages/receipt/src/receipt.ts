import { sha256 } from '@noble/hashes/sha2.js';
import { encodeCanonical, decodeCanonical, decodedMap } from './cbor.js';
import type {
  CoseSign1,
  ProtectedHeader,
  SigningKey,
} from './cose.js';
import {
  signCoseSign1,
  verifyCoseSign1,
  decodeCoseSign1,
  equalBytes,
} from './cose.js';
import { ReceiptError } from './errors.js';

/** `software` makes no TEE claim: `m` is the deployment's own digest of what it runs. */
export type TeeKind = 'software' | 'snp' | 'snp+h100cc' | 'tdx' | 'tdx+h100cc';

/**
 * Measurement bytes each kind must carry. A TEE reports its platform-native SHA-384
 * value (SEV-SNP launch digest, TDX MRTD), a software deployment measures with SHA-256,
 * so width and kind are one fact rather than two that can disagree.
 */
export const MEASUREMENT_BYTES: Readonly<Record<TeeKind, 32 | 48>> = {
  software: 32,
  snp: 48,
  'snp+h100cc': 48,
  tdx: 48,
  'tdx+h100cc': 48,
};

/**
 * Whether this kind promises a device report beside the platform quote.
 *
 * A rule over the suffix rather than a list of literals, so a future composite cannot
 * be added to the enum while the client and the gateway quietly disagree about whether
 * it owes a second evidence leg.
 */
export function claimsConfidentialDevice(tee: TeeKind): boolean {
  return tee.endsWith('+h100cc');
}

export function isTeeKind(value: unknown): value is TeeKind {
  return typeof value === 'string' && value in MEASUREMENT_BYTES;
}

export interface Measurement {
  tee: TeeKind;
  m: Uint8Array;
}

export interface EvidenceRef {
  d: Uint8Array;
  ts: number;
  url: string;
}

export interface TokenMetering {
  p: number;
  c: number;
}

export interface ReceiptPayload {
  v: 1;
  iss: string;
  ins: string;
  iat: number;
  nce: Uint8Array;
  req: Uint8Array;
  res: Uint8Array;
  mdl: string;
  wts: Uint8Array;
  meas: Measurement;
  att: EvidenceRef;
  epk: number;
  tok: TokenMetering;
}

export interface VerifyOptions {
  publicKey?: Uint8Array;
  resolveKey?: (kid: Uint8Array) => Uint8Array | undefined;
  expectedNonce?: Uint8Array;
  now?: number;
  freshnessSeconds?: number;
  evidenceFreshnessSeconds?: number;
}

export interface VerifiedReceipt {
  payload: ReceiptPayload;
  header: ProtectedHeader;
  cose: CoseSign1;
}

function isUint8Array(v: unknown): v is Uint8Array {
  return v instanceof Uint8Array;
}

function parsePayload(bytes: Uint8Array): ReceiptPayload {
  const bad = (detail: string): ReceiptError => new ReceiptError('BAD_PAYLOAD', detail);
  const raw = decodedMap(decodeCanonical(bytes, 'BAD_PAYLOAD'));
  if (raw === null) throw bad('payload is not a map');
  if (raw.get('v') !== 1) throw bad('v must be 1');
  const iss = raw.get('iss');
  if (typeof iss !== 'string') throw bad('iss must be a tstr');
  const ins = raw.get('ins');
  if (typeof ins !== 'string') throw bad('ins must be a tstr');
  const iat = raw.get('iat');
  if (typeof iat !== 'number' || !Number.isSafeInteger(iat) || iat < 0) throw bad('iat must be a non-negative integer');
  const nce = raw.get('nce');
  if (!isUint8Array(nce) || nce.length !== 16) throw bad('nce must be a 16-byte bstr');
  const req = raw.get('req');
  if (!isUint8Array(req) || req.length !== 32) throw bad('req must be a 32-byte bstr');
  const res = raw.get('res');
  if (!isUint8Array(res) || res.length !== 32) throw bad('res must be a 32-byte bstr');
  const mdl = raw.get('mdl');
  if (typeof mdl !== 'string') throw bad('mdl must be a tstr');
  const wts = raw.get('wts');
  if (!isUint8Array(wts) || wts.length !== 32) throw bad('wts must be a 32-byte bstr');
  const meas = decodedMap(raw.get('meas'));
  if (meas === null) throw bad('meas must be a map');
  const tee = meas.get('tee');
  if (!isTeeKind(tee)) throw bad('meas.tee is not a known environment kind');
  const m = meas.get('m');
  const width = MEASUREMENT_BYTES[tee];
  if (!isUint8Array(m) || m.length !== width) {
    throw bad(`meas.m must be a ${width}-byte bstr for tee '${tee}'`);
  }
  const att = decodedMap(raw.get('att'));
  if (att === null) throw bad('att must be a map');
  const d = att.get('d');
  if (!isUint8Array(d) || d.length !== 32) throw bad('att.d must be a 32-byte bstr');
  const ts = att.get('ts');
  if (typeof ts !== 'number' || !Number.isSafeInteger(ts) || ts < 0) throw bad('att.ts must be a non-negative integer');
  const url = att.get('url');
  if (typeof url !== 'string') throw bad('att.url must be a tstr');
  const epk = raw.get('epk');
  if (typeof epk !== 'number' || !Number.isSafeInteger(epk) || epk < 0) throw bad('epk must be a non-negative integer');
  const tok = decodedMap(raw.get('tok'));
  if (tok === null) throw bad('tok must be a map');
  const p = tok.get('p');
  if (typeof p !== 'number' || !Number.isSafeInteger(p) || p < 0) throw bad('tok.p must be a non-negative integer');
  const c = tok.get('c');
  if (typeof c !== 'number' || !Number.isSafeInteger(c) || c < 0) throw bad('tok.c must be a non-negative integer');
  return {
    v: 1,
    iss,
    ins,
    iat,
    nce,
    req,
    res,
    mdl,
    wts,
    meas: { tee, m },
    att: { d, ts, url },
    epk,
    tok: { p, c },
  };
}

export function encodePayload(payload: ReceiptPayload): Uint8Array {
  // Maps (not plain objects) so key ordering is bytewise per RFC 8949 CDE,
  // independent of any TS field ordering.
  return encodeCanonical(
    new Map<string, unknown>([
      ['v', payload.v],
      ['iss', payload.iss],
      ['ins', payload.ins],
      ['iat', payload.iat],
      ['nce', payload.nce],
      ['req', payload.req],
      ['res', payload.res],
      ['mdl', payload.mdl],
      ['wts', payload.wts],
      ['meas', new Map<string, unknown>([['tee', payload.meas.tee], ['m', payload.meas.m]])],
      ['att', new Map<string, unknown>([['d', payload.att.d], ['ts', payload.att.ts], ['url', payload.att.url]])],
      ['epk', payload.epk],
      ['tok', new Map<string, unknown>([['p', payload.tok.p], ['c', payload.tok.c]])],
    ]),
  );
}

export function issueReceipt(payload: ReceiptPayload, key: SigningKey): Uint8Array {
  // Catch it here rather than after signing: a receipt whose measurement does not
  // match its kind is one no verifier can accept.
  const width = MEASUREMENT_BYTES[payload.meas.tee];
  if (payload.meas.m.length !== width) {
    throw new ReceiptError('BAD_PAYLOAD', `meas.m must be ${width} bytes for tee '${payload.meas.tee}'`);
  }
  return signCoseSign1(encodePayload(payload), key);
}

export function decodeReceipt(bytes: Uint8Array): VerifiedReceipt {
  const cose = decodeCoseSign1(bytes);
  return { payload: parsePayload(cose.payloadBytes), header: cose.header, cose };
}

export function verifyReceipt(bytes: Uint8Array, options: VerifyOptions): VerifiedReceipt {
  let cose: CoseSign1 & { header: ProtectedHeader };
  if (options.publicKey) {
    cose = verifyCoseSign1(bytes, options.publicKey);
  } else if (options.resolveKey) {
    cose = decodeCoseSign1(bytes);
    const key = options.resolveKey(cose.header.kid);
    if (!key) throw new ReceiptError('UNKNOWN_KEY');
    cose = verifyCoseSign1(bytes, key);
  } else {
    throw new ReceiptError('UNKNOWN_KEY', 'no publicKey or resolveKey provided');
  }
  const payload = parsePayload(cose.payloadBytes);

  if (options.expectedNonce && !equalBytes(payload.nce, options.expectedNonce)) {
    throw new ReceiptError('NONCE_MISMATCH');
  }
  const now = options.now ?? Math.floor(Date.now() / 1000);
  if (options.freshnessSeconds !== undefined && Math.abs(now - payload.iat) > options.freshnessSeconds) {
    throw new ReceiptError('STALE_RECEIPT');
  }
  if (
    options.evidenceFreshnessSeconds !== undefined &&
    Math.abs(now - payload.att.ts) > options.evidenceFreshnessSeconds
  ) {
    throw new ReceiptError('STALE_EVIDENCE');
  }
  return { payload, header: cose.header, cose };
}

export function hashRequest(canonicalRequest: Uint8Array): Uint8Array {
  return sha256(canonicalRequest);
}

export function randomNonce(): Uint8Array {
  const c = (globalThis as { crypto?: { getRandomValues(a: Uint8Array): Uint8Array } }).crypto;
  if (!c) throw new Error('crypto.getRandomValues is unavailable in this environment');
  const nonce = new Uint8Array(16);
  c.getRandomValues(nonce);
  return nonce;
}
