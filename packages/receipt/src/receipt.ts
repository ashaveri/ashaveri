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

/**
 * `software` makes no TEE claim: `m` is the deployment's own digest of what it runs.
 *
 * The composite suffix is generation-neutral on purpose. A card name in the wire format
 * is honest on the card it names, and a false claim on the next one; the device
 * certificate chain inside the evidence already names the silicon precisely, so the
 * label never had to.
 */
export type TeeKind = 'software' | 'snp' | 'snp+gpucc' | 'tdx' | 'tdx+gpucc';

/**
 * Measurement bytes each kind must carry. A TEE reports its platform-native SHA-384
 * value (SEV-SNP launch digest, TDX MRTD), a software deployment measures with SHA-256,
 * so width and kind are one fact rather than two that can disagree.
 */
export const MEASUREMENT_BYTES: Readonly<Record<TeeKind, 32 | 48>> = {
  software: 32,
  snp: 48,
  'snp+gpucc': 48,
  tdx: 48,
  'tdx+gpucc': 48,
};

/**
 * Whether this kind promises a device report beside the platform quote.
 *
 * A rule over the suffix rather than a list of literals, so a future composite cannot
 * be added to the enum while the client and the gateway quietly disagree about whether
 * it owes a second evidence leg.
 */
export function claimsConfidentialDevice(tee: TeeKind): boolean {
  return tee.endsWith('+gpucc');
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

/**
 * The payload versions this package reads, the one place that set is written. `2` exists because of
 * what `mk` attests: a v1 reader checks thirteen fields, finds nothing about a mark, and would
 * verify a receipt over an unmarked response as readily as over a marked one, which is silence read
 * as a claim.
 */
const PARSED_VERSIONS = [1, 2] as const;

export type ReceiptVersion = (typeof PARSED_VERSIONS)[number];

function isReceiptVersion(value: unknown): value is ReceiptVersion {
  return (PARSED_VERSIONS as readonly unknown[]).includes(value);
}

/**
 * The labels this package can interpret, which is the whole registry today. A label outside them is
 * a refusal rather than a best guess, because reading a region under another scheme's rule is the
 * scheme-confusion failure and this is the code that answers it.
 *
 * `none` declares that no region of the response is marked, and `provenance-v1` names the extractor
 * rule for the `ashaveri` member a marked response carries. Which of the two a receipt attests is a
 * value of the field either way, so unmarked and undecided are different bytes.
 */
const MARKING_SCHEMES = ['none', 'provenance-v1'] as const;

export type MarkingScheme = (typeof MARKING_SCHEMES)[number];

function isMarkingScheme(value: string): value is MarkingScheme {
  return (MARKING_SCHEMES as readonly string[]).includes(value);
}

export interface Marking {
  sch: MarkingScheme;
  /** sha256 of the marked region exactly as it appears in the response, not of the whole response. */
  d: Uint8Array;
}

/**
 * The twelve fields every receipt carries, named once so that v2 being v1 plus one member is a
 * fact of the type rather than a second copy that can drift out of step with the first.
 */
interface ReceiptFields {
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

export interface ReceiptPayloadV1 extends ReceiptFields {
  v: 1;
}

export interface ReceiptPayloadV2 extends ReceiptFields {
  v: 2;
  mk: Marking;
}

export type ReceiptPayload = ReceiptPayloadV1 | ReceiptPayloadV2;

/**
 * The members the two payload versions have in common, in the order `receipt.cddl` lists them.
 * `mk` is absent from this list because it belongs to one version, which is the whole of what makes
 * it a v2 member rather than an optional one.
 */
const SHARED_MEMBERS = ['v', 'iss', 'ins', 'iat', 'nce', 'req', 'res', 'mdl', 'wts', 'meas', 'att', 'epk', 'tok'] as const;

/**
 * Which members a payload of each version defines. A payload map is closed: carrying a member the
 * version does not define makes the document malformed rather than a document read with the extra
 * member dropped.
 */
const DEFINED_MEMBERS: Readonly<Record<ReceiptVersion, readonly string[]>> = {
  1: SHARED_MEMBERS,
  2: [...SHARED_MEMBERS, 'mk'],
};

export interface VerifyOptions {
  publicKey?: Uint8Array;
  resolveKey?: (kid: Uint8Array) => Uint8Array | undefined;
  expectedNonce?: Uint8Array;
  now?: number;
  freshnessSeconds?: number;
  evidenceFreshnessSeconds?: number;
  /**
   * Which payload versions this call accepts, defaulting to every version this package parses.
   * The default is deliberately the wide one: narrowing to `[1]` is how a caller refuses a marked
   * receipt on purpose, and it must not be the setting a caller gets for free the day a
   * deployment starts marking.
   */
  acceptedVersions?: readonly ReceiptVersion[];
}

export interface VerifiedReceipt {
  payload: ReceiptPayload;
  header: ProtectedHeader;
  cose: CoseSign1;
}

function isUint8Array(v: unknown): v is Uint8Array {
  return v instanceof Uint8Array;
}

function badPayload(detail: string): ReceiptError {
  return new ReceiptError('BAD_PAYLOAD', detail);
}

/**
 * The versions a call accepts when it did not say, which is the set this package parses read off the
 * one list that holds it. Spelled a second time, the two can disagree and only one direction of the
 * disagreement is quiet: a default that forgot a version refuses real receipts no caller chose to
 * refuse, and a default that names a version nothing parses promises an acceptance the package
 * cannot deliver. Widening what this package reads is therefore one decision, taken where the set of
 * what it reads lives.
 */
const ACCEPTED_BY_DEFAULT: readonly ReceiptVersion[] = PARSED_VERSIONS;

/**
 * Which version the bytes claim, settled before a single field is read. A member that is not an
 * integer at all is a malformed payload rather than a version; an integer this package cannot read
 * and one the caller did not accept are answered alike, because which of the two it was is not a
 * fact about the bytes, and a second code would let a caller probe where the boundary sits.
 */
function claimedVersion(value: unknown, accepted: readonly ReceiptVersion[]): ReceiptVersion {
  if (typeof value !== 'number' || !Number.isInteger(value)) throw badPayload('v must be an integer receipt version');
  if (!isReceiptVersion(value)) {
    throw new ReceiptError('UNSUPPORTED_VERSION', `receipt payload version ${value} is not a format this package reads`);
  }
  if (!accepted.includes(value)) {
    throw new ReceiptError('UNSUPPORTED_VERSION', `receipt payload version ${value} is not in acceptedVersions`);
  }
  return value;
}

/**
 * How a document names a member the reader was not told about, in the refusal that names it back.
 * A map key is whatever the bytes carried, so a name that is not a text label is described by what
 * it is rather than rendered through an object's default `toString`.
 */
function memberName(key: unknown): string {
  if (typeof key === 'string') return `'${key}'`;
  if (key instanceof Uint8Array) return `a bstr key of ${key.length} bytes`;
  return `a key that is not a text label`;
}

/**
 * The closedness rule, applied to both arms from the one member list the version selects. It runs
 * before any field's value is checked, so an unexpected member is the answer a caller hears whatever
 * else the document is missing, and one rule retires the whole class rather than the one name that
 * happened to be noticed: a `v: 1` payload carrying `mk` read with the member dropped would hand a
 * reader a verified receipt that says nothing about a mark, which is the silence the version exists
 * to refuse, and any other unexpected name buys the same silence about whatever it stood for.
 */
function assertMembersAreDefined(raw: Map<unknown, unknown>, version: ReceiptVersion): void {
  const defined = DEFINED_MEMBERS[version];
  for (const key of raw.keys()) {
    if (typeof key !== 'string' || !defined.includes(key)) {
      throw badPayload(`payload carries a member version ${version} does not define: ${memberName(key)}`);
    }
  }
}

/** The twelve members every version carries, checked in the order the CDDL lists them. */
function readReceiptFields(raw: Map<unknown, unknown>): ReceiptFields {
  const iss = raw.get('iss');
  if (typeof iss !== 'string') throw badPayload('iss must be a tstr');
  const ins = raw.get('ins');
  if (typeof ins !== 'string') throw badPayload('ins must be a tstr');
  const iat = raw.get('iat');
  if (typeof iat !== 'number' || !Number.isSafeInteger(iat) || iat < 0) throw badPayload('iat must be a non-negative integer');
  const nce = raw.get('nce');
  if (!isUint8Array(nce) || nce.length !== 16) throw badPayload('nce must be a 16-byte bstr');
  const req = raw.get('req');
  if (!isUint8Array(req) || req.length !== 32) throw badPayload('req must be a 32-byte bstr');
  const res = raw.get('res');
  if (!isUint8Array(res) || res.length !== 32) throw badPayload('res must be a 32-byte bstr');
  const mdl = raw.get('mdl');
  if (typeof mdl !== 'string') throw badPayload('mdl must be a tstr');
  const wts = raw.get('wts');
  if (!isUint8Array(wts) || wts.length !== 32) throw badPayload('wts must be a 32-byte bstr');
  const meas = decodedMap(raw.get('meas'));
  if (meas === null) throw badPayload('meas must be a map');
  const tee = meas.get('tee');
  if (!isTeeKind(tee)) throw badPayload('meas.tee is not a known environment kind');
  const m = meas.get('m');
  const width = MEASUREMENT_BYTES[tee];
  if (!isUint8Array(m) || m.length !== width) {
    throw badPayload(`meas.m must be a ${width}-byte bstr for tee '${tee}'`);
  }
  const att = decodedMap(raw.get('att'));
  if (att === null) throw badPayload('att must be a map');
  const d = att.get('d');
  if (!isUint8Array(d) || d.length !== 32) throw badPayload('att.d must be a 32-byte bstr');
  const ts = att.get('ts');
  if (typeof ts !== 'number' || !Number.isSafeInteger(ts) || ts < 0) throw badPayload('att.ts must be a non-negative integer');
  const url = att.get('url');
  if (typeof url !== 'string') throw badPayload('att.url must be a tstr');
  const epk = raw.get('epk');
  if (typeof epk !== 'number' || !Number.isSafeInteger(epk) || epk < 0) throw badPayload('epk must be a non-negative integer');
  const tok = decodedMap(raw.get('tok'));
  if (tok === null) throw badPayload('tok must be a map');
  const p = tok.get('p');
  if (typeof p !== 'number' || !Number.isSafeInteger(p) || p < 0) throw badPayload('tok.p must be a non-negative integer');
  const c = tok.get('c');
  if (typeof c !== 'number' || !Number.isSafeInteger(c) || c < 0) throw badPayload('tok.c must be a non-negative integer');
  return { iss, ins, iat, nce, req, res, mdl, wts, meas: { tee, m }, att: { d, ts, url }, epk, tok: { p, c } };
}

/**
 * `mk` is required, so an absent one is a payload failure and never a reading of "unmarked": the
 * silence would be indistinguishable from "this receipt predates marking", which is exactly the
 * claim a reader must not be able to make. Unmarked is `sch: "none"`, and only the verification
 * step that holds the response bytes can say whether its digest of the empty region agrees.
 */
function readMarking(raw: Map<unknown, unknown>): Marking {
  const value = raw.get('mk');
  if (value === undefined) throw badPayload('v2 requires an mk member; absence is mk.sch "none", not a missing mk');
  const mk = decodedMap(value);
  if (mk === null) throw badPayload('mk must be a map');
  const sch = mk.get('sch');
  if (typeof sch !== 'string') throw badPayload('mk.sch must be a tstr');
  if (!isMarkingScheme(sch)) {
    throw new ReceiptError('UNSUPPORTED_SCHEME', `marking scheme '${sch}' is not one this package can interpret`);
  }
  const d = mk.get('d');
  if (!isUint8Array(d) || d.length !== 32) throw badPayload('mk.d must be a 32-byte bstr');
  return { sch, d };
}

function parsePayload(bytes: Uint8Array, accepted: readonly ReceiptVersion[]): ReceiptPayload {
  const raw = decodedMap(decodeCanonical(bytes, 'BAD_PAYLOAD'));
  if (raw === null) throw badPayload('payload is not a map');
  const version = claimedVersion(raw.get('v'), accepted);
  assertMembersAreDefined(raw, version);
  const fields = readReceiptFields(raw);
  if (version === 2) return { v: 2, ...fields, mk: readMarking(raw) };
  return { v: 1, ...fields };
}

export function encodePayload(payload: ReceiptPayload): Uint8Array {
  // Maps (not plain objects) so key ordering is bytewise per RFC 8949 CDE,
  // independent of any TS field ordering.
  const fields: Array<readonly [string, unknown]> = [
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
  ];
  // Only a v2 document gains the member, so the bytes a v1 payload encodes to are exactly the
  // bytes it encoded to before `mk` existed and stay signed by a verifier that never heard of it.
  if (payload.v === 2) {
    fields.push(['mk', new Map<string, unknown>([['sch', payload.mk.sch], ['d', payload.mk.d]])]);
  }
  return encodeCanonical(new Map(fields));
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

/**
 * Reads a receipt's payload without checking its signature: this is how a document is inspected
 * before anyone has decided to trust it. It takes the same version narrowing as verification, so a
 * caller that has decided not to read a version hears that refusal whichever way it opens bytes.
 */
export function decodeReceipt(bytes: Uint8Array, options?: VerifyOptions): VerifiedReceipt {
  const cose = decodeCoseSign1(bytes);
  const payload = parsePayload(cose.payloadBytes, options?.acceptedVersions ?? ACCEPTED_BY_DEFAULT);
  return { payload, header: cose.header, cose };
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
  // After the signature check, so a document nobody has signed cannot get a version answer out of
  // this package at all.
  const payload = parsePayload(cose.payloadBytes, options.acceptedVersions ?? ACCEPTED_BY_DEFAULT);

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
