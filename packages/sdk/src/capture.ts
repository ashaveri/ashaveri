import {
  decodeReceipt,
  verifyReceipt,
  ReceiptError,
  type ReceiptVersion,
} from '@ashaveri/receipt';
import { sha256 } from '@noble/hashes/sha2.js';
import { fromBase64Url, toBase64Url, toHex } from './b64.js';
import { SdkError, type SdkErrorCode } from './errors.js';
import type { EvidenceTrustAnchors } from './evidence.js';
import { ANCHOR_FAMILIES, type AnchorFamily } from './policy-file.js';
import {
  DEFAULT_MAX_EVIDENCE_AGE_SECONDS,
  DEFAULT_MAX_RECEIPT_AGE_SECONDS,
  policyKeyByKid,
  type AshaveriPolicy,
} from './policy.js';

/**
 * The capture record, and the reader that refuses the ways it can be faked.
 *
 * A receipt points at the evidence behind it with a digest, a timestamp and a URL, and a digest of a
 * document nobody retained proves a hash existed rather than that the evidence survived. This record is
 * the shape that closes the gap: one piece of evidence's exact original bytes, held as they arrived,
 * beside the context that made them verifiable at the instant they were taken in.
 *
 * Nothing here collects, fetches or stores anything, and no program in this repository writes a capture
 * record today. What is published is the layout a collector has to be written against and the reading a
 * stranger can run against whatever they are handed, which is the order `packages/receipt/pack.cddl`
 * states for a container it does not fill either. The claim about continuity is only checkable by
 * somebody who does not trust us if the shape it travels in is public and a reader for it exists.
 *
 * Two properties arrange the rest.
 *
 * An original is never re-encoded. The bytes a source produced are stored as they arrived and handed
 * back as they arrived: nothing between those two points decodes them, reformats them, or takes their
 * framing apart and writes it out again. A capture whose bytes passed through an encoder is a capture of
 * that encoder's output, and a signature checked over it was checked over the wrong document.
 *
 * Absence is stated, never invented. Every piece of context a capture may hold carries which of three
 * things happened to it: we hold it, the source never produced it, or we failed to take it in. The last
 * two are different outcomes and the reader keeps them apart, because the first is a statement about
 * the world and the second is a statement about the collector. What a reader never does is read a
 * missing input as a pass.
 */

/** The one capture format version this module reads. A record names its own, and never inherits this one. */
export const CAPTURE_FORMAT_VERSION = 1;

const IMPLEMENTED_CAPTURE_VERSIONS: readonly number[] = [CAPTURE_FORMAT_VERSION];
const IMPLEMENTED_POLICY_VERSIONS: readonly number[] = [1];

/**
 * Which receipt format versions a capture record may name, the one place that set is written for this
 * package. It is the format's own list and it carries exactly that set, which today is one version: a
 * gateway emits `v: 1` for every completion whose bytes frame into items, so a record of a check over a
 * v1 receipt is the ordinary document a collector hands over, and a reader that refused it would leave
 * every client of every emitting deployment unable to record what it verified. The list and
 * `packages/sdk/schemas/capture-v1.schema.json`'s `enum` for `check.receiptFormatVersion` are one rule
 * written twice on purpose, because the schema is what a collector outside this repository builds against
 * and the reader is what a stranger runs; `test/capture.test.ts` holds the two to each other at the
 * boundary of the list, where only a disagreement between them can be seen.
 *
 * `as const` is what makes the list and the type of the member below one fact instead of two that can
 * disagree. Widening this list is answered at the schema half of that walk, and a version the format gains
 * without a reader for it fails the same way: `receipt.cddl` and `packages/receipt/src/receipt.ts` own what
 * can be parsed, and this list only says which of those a record may claim it checked. A record naming
 * `2` or `3` is refused at that boundary, because the numbers retired with the versions they named and a
 * collector that hands one over is describing a document no reader in this estate can open.
 */
const IMPLEMENTED_RECEIPT_FORMAT_VERSIONS = [1] as const;

/** The versions above as a type, so no caller of the reader has to name them again. */
type CaptureReceiptFormatVersion = (typeof IMPLEMENTED_RECEIPT_FORMAT_VERSIONS)[number];

/**
 * What became of one piece of context. Three states because two are not enough: a record that says
 * nothing about its collateral cannot be told apart from one whose collateral never existed, and the
 * difference is between a deployment that had nothing to show and a collector that looked away.
 */
export type CapturePresence = 'held' | 'absent-at-source' | 'not-taken-in';

/** A piece of context this record holds: the bytes as they arrived, and the digest of exactly those bytes. */
export interface CaptureHeld extends Partial<CaptureCollateralObservation> {
  readonly presence: 'held';
  /** Unpadded base64url, in the one spelling that decodes back to these bytes. */
  readonly bytes: string;
  readonly sha256: string;
  readonly byteCount: number;
}

/**
 * Which reading weighed the answer a collateral slot holds.
 *
 * `served` is a signature and an issuer chain arriving apart from the body, `embedded` a signature
 * travelling inside the bytes it signs. The source's own declaration decides this and a body does not: a
 * wrapper that starts with a brace and a token that starts with base64url are the same text to anything
 * that looks, and which of the two a reader stands behind is a claim about the path, not about the bytes.
 *
 * Exported, and held to the published schema's `enum` for `weighedBy` by `test/capture.test.ts`, for the
 * one reason `SOURCE_KINDS` is exported: the schema is what a collector outside this repository builds a
 * writer against, and a third word added on one side alone is a record one authority refuses and the
 * other reads.
 */
export const COLLATERAL_WEIGHED_BY = ['served', 'embedded'] as const;

/** The two readings above as a type. */
export type CaptureCollateralWeighing = (typeof COLLATERAL_WEIGHED_BY)[number];

/** The identity a signed answer names for itself, read off the bytes the slot holds. */
export interface CaptureCollateralIdentity {
  /** The CPU type the answer claims to cover, in the answer's own words, or null where it names none. */
  readonly cpuType: string | null;
  /** The vendor's own status text beside what was asked, copied rather than paraphrased. */
  readonly vendorStatus: string;
}

/** How far an answer's own signed statement reaches: `from` included, `to` excluded, unix seconds. */
export interface CaptureSignedWindow {
  readonly from: number;
  readonly to: number;
}

/**
 * What a held collateral slot states about the answer its bytes are.
 *
 * These are the eight facts a collector watched when it took the answer in, beside the bytes themselves,
 * and they are what turns "we hold something of this length and this digest" into a statement a stranger
 * can go and re-ask: which source declaration the bytes came under, at what address, on whose clock and
 * with what bound on that clock, naming which identity, reached by which reading, standing for which
 * span, and kept under which key.
 *
 * A held slot outside `context.collateral` owes none of them, and no reader is asked to weigh a
 * manifest or a detached signature as a vendor's answer. The schema says so the way it can, which is to
 * make these members legal in any held slot and require them of a held collateral one; the reader refuses
 * a slot that states part of an observation while declaring an absence, and refuses a chain stated on one
 * side only. `docs/capture-v1.md` names which authority binds which rule, and which member of a pack's
 * custody entry each of these becomes.
 */
export interface CaptureCollateralObservation {
  /** Which source declaration this answer came under, named the way that declaration names itself. */
  readonly origin: string;
  /** The address the answer was asked at, as it was spelled on the way out, within the bytes a reference carries. */
  readonly request: string;
  /** The identity the signed answer names for itself, or null where the answer names none. */
  readonly identity: CaptureCollateralIdentity | null;
  /** Unix seconds, whole, the instant the last byte of the answer landed. */
  readonly observedAt: number;
  /** How far the clock behind `observedAt` may stand from the instant it names, or null where nobody measured. */
  readonly sourceUncertaintySeconds: number | null;
  /** The digest of the header that carried the answer's issuer chain, when a chain arrived in a header. */
  readonly chainSha256?: string;
  /** That header itself, unpadded base64url, as it arrived, beside the digest of it. */
  readonly chainBytes?: string;
  /** Which reading weighed this answer. */
  readonly weighedBy: CaptureCollateralWeighing;
  /** The span the answer's own signed statement reaches. */
  readonly window: CaptureSignedWindow;
  /** The key this answer was kept under, spelled from the members that decide which question it answers. */
  readonly cacheKey: string;
}

/** A piece of context this record does not hold, and which of the two reasons it names. */
export interface CaptureAbsent {
  readonly presence: Exclude<CapturePresence, 'held'>;
  /** One line in the collector's own words about what it saw. Required: an absence nobody explained is a hole. */
  readonly reason: string;
}

export type CaptureSlot = CaptureHeld | CaptureAbsent;

/** A held collateral slot, which owes every one of the eight facts beside its bytes. */
export type CaptureCollateralSlot = (CaptureHeld & CaptureCollateralObservation) | CaptureAbsent;

/**
 * What the stored bytes are, the whole closed set written once as a list. A new source arrives as a new
 * capture version rather than as a new string: a reader that let an unknown kind fall through to its
 * default handling would assess a document it holds no rules for, which is what the test against this
 * list below refuses.
 *
 * Exported because the list is one of two statements of this set and the other is a published document:
 * `original.sourceKind`'s `enum` in `packages/sdk/schemas/capture-v1.schema.json` is what a collector
 * outside this repository builds a writer against, and a kind added to one side alone is a document the
 * schema refuses while the type and the reader accept it. `test/capture.test.ts` reads both spellings and
 * refuses the disagreement in either direction, so the list and the enum are one set with two spellings.
 */
export const SOURCE_KINDS = ['platform-evidence', 'device-evidence', 'deployment-manifest', 'receipt'] as const;

/** The kinds above as a type, so the set is named in one place and read in two. */
export type CaptureSourceKind = (typeof SOURCE_KINDS)[number];

/** Whether a string the document named itself with is one of the kinds above. */
function isCaptureSourceKind(value: unknown): value is CaptureSourceKind {
  return typeof value === 'string' && (SOURCE_KINDS as readonly string[]).includes(value);
}

export interface CaptureRecord {
  readonly v: number;
  readonly original: {
    readonly sourceKind: CaptureSourceKind;
    /** The source's name for itself as it served it: an instance id, an endpoint. Not our label for it. */
    readonly sourceId: string;
    readonly bytes: string;
    readonly sha256: string;
    readonly byteCount: number;
    /**
     * Our assertion that the source signed these bytes. A claim, and this record carries no field that
     * could hold the other half of it: whether the signature holds is decided by a reader with the
     * caller's own pins, and a record that stated a verdict would turn custody into verification.
     */
    readonly signedBySource: boolean;
    /** True when the signature travels inside `bytes`, as a COSE_Sign1 carries its own. */
    readonly signatureEmbedded: boolean;
    /** The detached signature, and the only shape it can be in. Absent exactly when none was claimed. */
    readonly signature?: CaptureSlot;
  };
  readonly acquired: {
    /** Unix seconds on our clock at the instant the bytes were taken in. Never the source's stamp, which is beside it. */
    readonly at: number;
    /** The timestamp the source claimed for the bytes, or null when it claimed none. */
    readonly sourceStatedAt: number | null;
  };
  readonly manifests: {
    /** The deployment manifest the source served at that instant. One role, because this estate serves one manifest. */
    readonly deployment: CaptureSlot;
  };
  readonly check: {
    /** Which policy document version the check ran under, and the digest of the document it actually used. */
    readonly policyVersion: number;
    readonly policyDigest: string | null;
    /** Which receipt format version the check read, and which verifier build ran it. Versions, not a verdict. */
    readonly receiptFormatVersion: CaptureReceiptFormatVersion;
    readonly verifierVersion: string;
    /** Unix seconds on our clock when the appraisal of this context ran. */
    readonly appraisedAt: number;
  };
  readonly context: {
    /**
     * The signed collateral the bytes were appraised against: the vendor certificate chain, as served.
     * A held one states the eight facts beside its bytes, because an answer nobody can say where it came
     * from is a blob and not a reference.
     */
    readonly collateral: CaptureCollateralSlot;
    /** The validity context they were appraised in: the window and the appraisal a verifier recorded. */
    readonly validity: CaptureSlot;
  };
  readonly trust: {
    /**
     * The references the check relied on. A `digest` of null records that the collector used a root it
     * did not name, which a reader weighs as an unattributable reference rather than as a match.
     */
    readonly roots: readonly CaptureRootReference[];
    /** The binding limits the verdict was reached under, read the same two ways as the policy file's. */
    readonly limits: CaptureAppliedLimits;
  };
}

export interface CaptureRootReference {
  readonly family: AnchorFamily;
  readonly digest: string | null;
}

export interface CaptureAppliedLimits {
  readonly maxReceiptAgeSeconds: number | null;
  readonly maxEvidenceAgeSeconds: number | null;
}

/**
 * What a reader concluded, in the two halves that must never be merged.
 *
 * `stated` is the record's claim about bytes it held. `repeated` is what the reader established for
 * itself, out of those bytes and the caller's own pins. A verdict carrying only a pass or a fail would
 * let the first be read as the second, which is the mistake this record exists to make impossible.
 */
export interface CaptureVerdict {
  /**
   * `repeated`: every check the record invites ran, against this caller's own pins.
   * `qualified`: every check that could run passed, and something the record explains is missing.
   * `unassessed`: a leg this reader cannot repeat. A refusal to pass, never a soft pass.
   */
  readonly status: 'repeated' | 'qualified' | 'unassessed';
  readonly stated: {
    readonly sourceKind: CaptureSourceKind;
    readonly sourceId: string;
    readonly acquiredAt: number;
    readonly sourceStatedAt: number | null;
    readonly sha256: string;
    readonly byteCount: number;
    readonly assertsSignature: boolean;
    /**
     * What the record states its collateral slot holds, or null when that slot states an absence. The
     * collector watched these eight facts and this reader did not: a bound a source states for its own
     * clock is not a bound this reader measured, and `repeated` says nothing about any of them.
     */
    readonly collateral: CaptureCollateralObservation | null;
  };
  readonly repeated: {
    /** The stored bytes, handed back exactly as the record holds them. Never re-encoded, never re-framed. */
    readonly originalBytes: Uint8Array;
    /** The digest this reader computed over those bytes: the record's own statement, recomputed. */
    readonly sha256: string;
    /** True only when a signature leg ran to completion against a key out of the caller's own policy. */
    readonly signatureVerifiedWithOwnPins: boolean;
    readonly signingKid: string | null;
    readonly rootsMatched: readonly AnchorFamily[];
  };
  /** Context the record declared absent, with the state it declared and the reason it gave. */
  readonly absences: readonly CaptureDeclaredAbsence[];
  /** One line each, safe for a log: what this verdict had to leave out, and why. */
  readonly qualifications: readonly string[];
}

export interface CaptureDeclaredAbsence {
  readonly slot: string;
  readonly presence: Exclude<CapturePresence, 'held'>;
  readonly reason: string;
}

export interface AssessCaptureParams {
  /** The record as it was handed over. It is parsed here rather than trusted, because a reader reads. */
  readonly record: unknown;
  /** The caller's own pinning policy, which is where the signing key a signature leg needs comes from. */
  readonly policy?: AshaveriPolicy;
  /**
   * The caller's own pinned vendor roots. Nothing is substituted for them: the roots
   * `@ashaveri/attest-core` bundles are a library default, and a default is not this caller's pin.
   */
  readonly anchors?: EvidenceTrustAnchors;
  /** Wall clock in milliseconds since the epoch; defaults to Date.now. */
  readonly nowMillis?: number;
}

/** The eight facts a held collateral slot owes, in the order a reader states them. */
const OBSERVATION_MEMBERS = [
  'origin',
  'request',
  'identity',
  'observedAt',
  'sourceUncertaintySeconds',
  'weighedBy',
  'window',
  'cacheKey',
] as const;

/** Everything a held collateral slot may state beside the bytes: the eight, and the chain's two halves. */
const COLLATERAL_SLOT_MEMBERS: readonly string[] = [...OBSERVATION_MEMBERS, 'chainBytes', 'chainSha256'];

/**
 * Everything any slot may carry: the four of a held one, the two of an absent one, and the ten a held
 * collateral slot states about its answer.
 *
 * This list is `#/$defs/held`'s and `#/$defs/absent`'s member names in
 * `packages/sdk/schemas/capture-v1.schema.json` restated, which is the one reason a drift between the two
 * is a bug rather than a choice: `test/capture.test.ts` reads one document through both and refuses the
 * disagreement in either direction.
 */
const SLOT_MEMBERS: readonly string[] = ['presence', 'bytes', 'sha256', 'byteCount', 'reason', ...COLLATERAL_SLOT_MEMBERS];

/** The members only a holding slot can state, so an absence that carries one is refused rather than dropped. */
const HELD_MEMBERS: readonly string[] = ['bytes', 'sha256', 'byteCount', ...COLLATERAL_SLOT_MEMBERS];

/**
 * The longest address a slot may state its answer was asked at, counted in UTF-8 bytes.
 *
 * The address a held collateral slot states is the address the reference made from it names, and that
 * reference travels in a container which bounds the member: a stated address past the bound is a slot
 * whose bytes can be kept and never pointed at, which is the one outcome this record exists to refuse. So
 * the bound is read here, at the record's own edge, rather than left for a later step to discover. The
 * figure is the container's and not a new one, and it is a byte count rather than a character count, which
 * is why the reader holds it and the published schema names it in prose: a keyword that counts characters
 * would let a multibyte address through this edge and refuse it at none.
 */
const REQUEST_MAX_BYTES = 2_048;

const HEX64 = /^[0-9a-f]{64}$/;

function refused(code: SdkErrorCode, message: string): never {
  throw new SdkError(code, message);
}

function describe(value: unknown): string {
  if (typeof value === 'string') return `'${value}'`;
  if (value === undefined) return 'absent';
  if (value === null) return 'null';
  return `a ${Array.isArray(value) ? 'list' : typeof value}`;
}

function requireObject(value: unknown, where: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return refused('NOT_CAPTURE_RECORD', `${where} is ${describe(value)}, which is not a member block of a capture record`);
  }
  return value as Record<string, unknown>;
}

/**
 * Closure, stated the way `receipt.cddl` states it: a member the version a document names does not
 * define makes the document invalid rather than a document read with the member dropped. The reason is
 * the same here as there, and stronger for being about a record nobody signs: a collector that wrote a
 * field this reader does not know was answering a question this record cannot ask, and dropping it
 * quietly turns that answer into a silence.
 */
function requireKnownMembers(raw: Record<string, unknown>, allowed: readonly string[], where: string): void {
  for (const member of Object.keys(raw)) {
    if (!allowed.includes(member)) {
      refused(
        'NOT_CAPTURE_RECORD',
        `${where} carries '${member}', which capture version ${CAPTURE_FORMAT_VERSION} does not define`,
      );
    }
  }
}

function requireText(raw: Record<string, unknown>, key: string, where: string): string {
  const value = raw[key];
  if (typeof value !== 'string' || value.length === 0) {
    refused('NOT_CAPTURE_RECORD', `${where}.${key} is ${describe(value)}, and a record has to name it`);
  }
  return value;
}

function requireWhole(raw: Record<string, unknown>, key: string, where: string, what: string): number {
  const value = raw[key];
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    refused('NOT_CAPTURE_RECORD', `${where}.${key} is ${describe(value)}, and ${what} is a non-negative whole number`);
  }
  return value;
}

function requireOrNullWhole(raw: Record<string, unknown>, key: string, where: string, what: string): number | null {
  if (raw[key] === null) return null;
  return requireWhole(raw, key, where, what);
}

function requireBoolean(raw: Record<string, unknown>, key: string, where: string): boolean {
  const value = raw[key];
  if (typeof value !== 'boolean') {
    refused('NOT_CAPTURE_RECORD', `${where}.${key} is ${describe(value)}: this record states it either way rather than leaving it out`);
  }
  return value;
}

function requireDigest(raw: Record<string, unknown>, key: string, where: string): string {
  const value = raw[key];
  if (typeof value !== 'string' || !HEX64.test(value)) {
    refused('EVIDENCE_DIGEST_MISMATCH', `${where}.${key} is ${describe(value)}, and a digest is 64 lowercase hex characters`);
  }
  return value;
}

function requireDigestOrNull(raw: Record<string, unknown>, key: string, where: string): string | null {
  if (raw[key] === null) return null;
  return requireDigest(raw, key, where);
}

function requireImplementedVersion<T extends number>(value: unknown, what: string, implemented: readonly T[]): T {
  if (typeof value !== 'number' || !Number.isSafeInteger(value)) {
    throw new ReceiptError('UNSUPPORTED_VERSION', `${what} names ${describe(value)} where a version number belongs`);
  }
  // The element of the list, and not the number the document named: the lookup is at once the refusal
  // test and the witness that what comes back is one of the versions this reader implements, which is
  // why no caller of it has to narrow a returned number against the list a second time.
  const stated = implemented.find((each): each is T => each === value);
  if (stated === undefined) {
    throw new ReceiptError(
      'UNSUPPORTED_VERSION',
      `${what} names version ${value}, and this reader implements ${implemented.join(', ')} and does not read it as one of them`,
    );
  }
  return stated;
}

/**
 * Which receipt format version the record says the check read, against the version this package reads it
 * as. `receipt.cddl` declares one payload version and this reader names it, because a gateway emits
 * that version on the bytes of the response rather than on a capability the deployment was asked about, so
 * a record of a check is a record a collector writes. A version outside the list is still refused by
 * design and never read as one inside it: `requireImplementedVersion` answers with an `UNSUPPORTED_VERSION`
 * naming the version the record states and the versions this reader implements, which is the same rule the
 * capture and policy versions beside it run under.
 */
function requireReceiptVersion(value: unknown, where: string): CaptureReceiptFormatVersion {
  return requireImplementedVersion(value, `${where}.receiptFormatVersion`, IMPLEMENTED_RECEIPT_FORMAT_VERSIONS);
}

function readSlot(value: unknown, where: string): CaptureSlot {
  const raw = requireObject(value, where);
  for (const member of Object.keys(raw)) {
    if (!SLOT_MEMBERS.includes(member)) {
      refused('NOT_CAPTURE_RECORD', `${where} carries '${member}', which no presence state of this record defines`);
    }
  }
  const presence = raw['presence'];
  if (presence !== 'held' && presence !== 'absent-at-source' && presence !== 'not-taken-in') {
    refused('NOT_CAPTURE_RECORD', `${where} states presence ${describe(presence)}, which is none of the three states context has`);
  }
  if (presence !== 'held') {
    const reason = raw['reason'];
    if (typeof reason !== 'string' || reason.length === 0) {
      refused('NOT_CAPTURE_RECORD', `${where} is ${presence} and gives no reason, so the absence is silent`);
    }
    // The published schema closes an absent slot at `presence` and `reason`, so a reader that read the rest
    // of a holding slot's members and dropped them would be accepting documents the layout refuses, and
    // keying them as if the statement had never been made.
    for (const member of HELD_MEMBERS) {
      if (raw[member] !== undefined) {
        refused(
          'NOT_CAPTURE_RECORD',
          `${where} is ${presence} and carries '${member}', which only bytes this record holds can state`,
        );
      }
    }
    return { presence, reason };
  }
  const bytes = raw['bytes'];
  if (typeof bytes !== 'string') {
    refused('NOT_CAPTURE_RECORD', `${where} declares itself held and carries no bytes to hold`);
  }
  return {
    presence: 'held',
    bytes,
    sha256: requireDigest(raw, 'sha256', where),
    byteCount: requireWhole(raw, 'byteCount', where, 'a byte count'),
    ...readCollateralMembers(raw, where),
  };
}

/**
 * The collateral slot: a held one owes the whole observation.
 *
 * Which answer these bytes are is not a detail a collector may leave out and a reader may fill in. Bytes
 * of the right length and the right digest, with nothing naming the source they came from, are a blob:
 * a stranger cannot re-ask them, cannot say which span they stand for, and cannot tell one vendor's
 * statement about a platform from another's. So the eight are required here, one refusal each, and the
 * message names the member that is missing rather than the slot in general.
 */
function readCollateralSlot(value: unknown, where: string): CaptureCollateralSlot {
  const slot = readSlot(value, where);
  if (slot.presence !== 'held') return slot;
  for (const member of OBSERVATION_MEMBERS) {
    if (slot[member] === undefined) {
      refused(
        'NOT_CAPTURE_RECORD',
        `${where}.${member} is absent, and a slot that holds bytes without stating ${member} is a blob no reader can say anything about`,
      );
    }
  }
  // The loop above is what makes this total: it refuses every spelling in which one of the eight is
  // missing, and `readCollateralMembers` is the only other writer of these keys.
  return slot as CaptureHeld & CaptureCollateralObservation;
}

/**
 * The ten members a held slot may state about its answer, read only when the document states them.
 *
 * Each is read by the same rule its shape calls for and each refusal names the member: an absent one is
 * not this function's business, which is `readCollateralSlot`'s, and a member that arrived is either the
 * shape the layout defines or a refusal. The chain pair is the one rule here that spans two members, and
 * it is stated in `readChainPair`; the one rule here that is a count rather than a shape is stated in
 * `requireAddress`.
 */
function readCollateralMembers(raw: Record<string, unknown>, where: string): Partial<CaptureCollateralObservation> {
  return {
    ...(raw['origin'] === undefined ? {} : { origin: requireText(raw, 'origin', where) }),
    ...(raw['request'] === undefined ? {} : { request: requireAddress(raw, 'request', where) }),
    ...(raw['identity'] === undefined ? {} : { identity: readIdentity(raw['identity'], where) }),
    ...(raw['observedAt'] === undefined
      ? {}
      : { observedAt: requireWhole(raw, 'observedAt', where, 'an instant in whole unix seconds') }),
    ...(raw['sourceUncertaintySeconds'] === undefined
      ? {}
      : {
          sourceUncertaintySeconds: requireOrNullWhole(
            raw,
            'sourceUncertaintySeconds',
            where,
            'a bound in whole seconds',
          ),
        }),
    ...readChainPair(raw, where),
    ...(raw['weighedBy'] === undefined ? {} : { weighedBy: readWeighing(raw['weighedBy'], where) }),
    ...(raw['window'] === undefined ? {} : { window: readSignedWindow(raw['window'], where) }),
    ...(raw['cacheKey'] === undefined ? {} : { cacheKey: requireText(raw, 'cacheKey', where) }),
  };
}

/**
 * The address an answer was asked at, bounded by the reference this slot becomes.
 *
 * Named like every other text member first, because an address that is not there at all is the smaller
 * problem, and then counted in bytes: `REQUEST_MAX_BYTES` says why the count is this reader's to make.
 */
function requireAddress(raw: Record<string, unknown>, key: string, where: string): string {
  const value = requireText(raw, key, where);
  const stated = new TextEncoder().encode(value).length;
  if (stated > REQUEST_MAX_BYTES) {
    refused(
      'NOT_CAPTURE_RECORD',
      `${where}.${key} states an address of ${stated} bytes and a reference carries at most ${REQUEST_MAX_BYTES}, so these bytes have a record and no pointer`,
    );
  }
  return value;
}

/** The identity a signed answer names for itself, or null where the answer names none. */
function readIdentity(value: unknown, where: string): CaptureCollateralIdentity | null {
  if (value === null) return null;
  const block = requireObject(value, `${where}.identity`);
  requireKnownMembers(block, ['cpuType', 'vendorStatus'], `${where}.identity`);
  return {
    cpuType: block['cpuType'] === null ? null : requireText(block, 'cpuType', `${where}.identity`),
    vendorStatus: requireText(block, 'vendorStatus', `${where}.identity`),
  };
}

/** The span an answer's own signed statement reaches, both ends whole seconds and both ends named. */
function readSignedWindow(value: unknown, where: string): CaptureSignedWindow {
  const block = requireObject(value, `${where}.window`);
  requireKnownMembers(block, ['from', 'to'], `${where}.window`);
  return {
    from: requireWhole(block, 'from', `${where}.window`, 'the instant a statement begins to reach, in whole unix seconds'),
    to: requireWhole(block, 'to', `${where}.window`, 'the instant a statement stops reaching, in whole unix seconds'),
  };
}

/** Which reading weighed the answer, from the two this layout can state. */
function readWeighing(value: unknown, where: string): CaptureCollateralWeighing {
  if (typeof value !== 'string' || !(COLLATERAL_WEIGHED_BY as readonly string[]).includes(value)) {
    refused(
      'NOT_CAPTURE_RECORD',
      `${where}.weighedBy is ${describe(value)}, and an answer is weighed by a source served apart from its bytes or by one embedded inside them`,
    );
  }
  return value as CaptureCollateralWeighing;
}

/**
 * The issuer chain's header and its digest, which arrive together or not at all.
 *
 * One without the other is the hole this record exists to close: bytes with no digest beside them cannot
 * be named by a later reader that holds no copy, and a digest of a header nobody kept is a statement about
 * nothing but a hash. Both halves are then read by the rules any byte of this record is read by, so the
 * spelling is this reader's own and the digest is recomputed over what decoded.
 */
function readChainPair(raw: Record<string, unknown>, where: string): Partial<CaptureCollateralObservation> {
  if (raw['chainBytes'] !== undefined && raw['chainSha256'] === undefined) {
    refused(
      'NOT_CAPTURE_RECORD',
      `${where}.chainSha256 is absent beside the chainBytes the slot states, and a header nobody can name a digest of is bytes no later reader can be shown`,
    );
  }
  if (raw['chainSha256'] !== undefined && raw['chainBytes'] === undefined) {
    refused(
      'NOT_CAPTURE_RECORD',
      `${where}.chainBytes is absent beside the chainSha256 the slot states, and a digest of a header nobody kept is a statement about nothing but a hash`,
    );
  }
  if (raw['chainBytes'] === undefined) return {};
  const sha256Hex = requireDigest(raw, 'chainSha256', where);
  const statedBytes = requireText(raw, 'chainBytes', where);
  let bytes: Uint8Array;
  try {
    bytes = fromBase64Url(statedBytes);
  } catch (err) {
    return refused('NOT_CAPTURE_RECORD', `${where}.chainBytes holds ${err instanceof Error ? err.message : String(err)} where bytes belong`);
  }
  if (toBase64Url(bytes) !== statedBytes) {
    refused(
      'NOT_CAPTURE_RECORD',
      `${where}.chainBytes is spelled in a base64url form this reader does not write, so somebody wrote the header with another encoder`,
    );
  }
  const computed = toHex(sha256(bytes));
  if (computed !== sha256Hex) {
    refused('EVIDENCE_DIGEST_MISMATCH', `${where}.chainSha256 states ${sha256Hex} and the header beside it hashes to ${computed}`);
  }
  return { chainBytes: statedBytes, chainSha256: sha256Hex };
}

/** The eight facts and the chain pair, read off a slot the reader already refused for having any of them missing. */
function collateralObservationOf(slot: CaptureHeld & CaptureCollateralObservation): CaptureCollateralObservation {
  return {
    origin: slot.origin,
    request: slot.request,
    identity: slot.identity,
    observedAt: slot.observedAt,
    sourceUncertaintySeconds: slot.sourceUncertaintySeconds,
    weighedBy: slot.weighedBy,
    window: slot.window,
    cacheKey: slot.cacheKey,
    ...(slot.chainBytes === undefined || slot.chainSha256 === undefined
      ? {}
      : { chainBytes: slot.chainBytes, chainSha256: slot.chainSha256 }),
  };
}

interface StatedBytes {
  readonly bytes: string;
  readonly sha256: string;
  readonly byteCount: number;
}

/**
 * The bytes a record or one of its slots states, checked three ways before anything reads them.
 *
 * The spelling comes first, and it is the check a JSON validator cannot make. Unpadded base64url has
 * more than one spelling for the same bytes whenever the last group is short, because the bits past the
 * end of the data are free: a second encoder can hand back the bytes and not the document. Two records
 * of one capture written that way would disagree about the record while agreeing about everything in it,
 * so the spelling has to round-trip through this reader's own writer.
 *
 * The count and the digest are then computed over what decoded, which is where a re-encoded original is
 * caught. A purported equivalent, the same structure written out by a different encoder, decodes to
 * bytes that hash to something else, and nothing downstream of here can tell the two apart.
 */
function decodeStated(stated: StatedBytes, where: string): Uint8Array {
  let bytes: Uint8Array;
  try {
    bytes = fromBase64Url(stated.bytes);
  } catch (err) {
    return refused('NOT_CAPTURE_RECORD', `${where} holds ${err instanceof Error ? err.message : String(err)} where bytes belong`);
  }
  if (toBase64Url(bytes) !== stated.bytes) {
    refused('NOT_CAPTURE_RECORD', `${where} is spelled in a base64url form this reader does not write, so somebody wrote it with another encoder`);
  }
  if (bytes.length !== stated.byteCount) {
    refused('EVIDENCE_DIGEST_MISMATCH', `${where} states ${stated.byteCount} bytes and carries ${bytes.length}`);
  }
  const computed = toHex(sha256(bytes));
  if (computed !== stated.sha256) {
    refused('EVIDENCE_DIGEST_MISMATCH', `${where} states ${stated.sha256} and these bytes hash to ${computed}`);
  }
  return bytes;
}

/**
 * A capture record read out of whatever was handed over, refusing the shapes that cannot be assessed.
 *
 * The order carries the reading. The version is decided first, because nothing else can be named until
 * a reader knows which rules the bytes are read under, and a record naming a version this module does
 * not implement is refused rather than read as if it were its own: an added member a reader ignored
 * would be a claim the record never got to make, which is the reason `receipt.cddl` made marking a new
 * version rather than an optional field of an old one. Structure comes next, then the byte checks, so a
 * record whose original does not hash to what it states is caught before anything tries to interpret
 * those bytes.
 */
export function parseCaptureRecord(value: unknown): CaptureRecord {
  const root = requireObject(value, 'capture record');
  const version = requireImplementedVersion(root['v'], 'capture record', IMPLEMENTED_CAPTURE_VERSIONS);
  requireKnownMembers(root, ['v', 'original', 'acquired', 'manifests', 'check', 'context', 'trust'], 'capture record');

  const original = requireObject(root['original'], 'original');
  requireKnownMembers(
    original,
    ['sourceKind', 'sourceId', 'bytes', 'sha256', 'byteCount', 'signedBySource', 'signatureEmbedded', 'signature'],
    'original',
  );
  const sourceKind = requireText(original, 'sourceKind', 'original');
  if (!isCaptureSourceKind(sourceKind)) {
    refused('NOT_CAPTURE_RECORD', `original.sourceKind '${sourceKind}' is none of the sources this record can describe`);
  }
  const signedBySource = requireBoolean(original, 'signedBySource', 'original');
  const signatureEmbedded = requireBoolean(original, 'signatureEmbedded', 'original');
  const signature = original['signature'] === undefined ? undefined : readSlot(original['signature'], 'original.signature');
  if (signedBySource && !signatureEmbedded && signature === undefined) {
    refused(
      'NOT_CAPTURE_RECORD',
      'original claims a signature the source served apart from the bytes and carries no signature at all',
    );
  }
  if (signedBySource && !signatureEmbedded && signature !== undefined && signature.presence !== 'held') {
    refused('CAPTURE_SIGNATURE_NOT_CARRIED', `original claims a signature it does not carry: its signature slot says ${signature.presence}`);
  }
  if (!signedBySource && signature !== undefined) {
    refused(
      'NOT_CAPTURE_RECORD',
      'original carries a signature while stating the source signed nothing, so the record contradicts itself about its own contents',
    );
  }

  const acquired = requireObject(root['acquired'], 'acquired');
  requireKnownMembers(acquired, ['at', 'sourceStatedAt'], 'acquired');

  const manifests = requireObject(root['manifests'], 'manifests');
  requireKnownMembers(manifests, ['deployment'], 'manifests');
  if (manifests['deployment'] === undefined) {
    refused(
      'NOT_CAPTURE_RECORD',
      'manifests.deployment is absent, and a manifest the source never served still has to be said so rather than left out',
    );
  }

  const check = requireObject(root['check'], 'check');
  requireKnownMembers(
    check,
    ['policyVersion', 'policyDigest', 'receiptFormatVersion', 'verifierVersion', 'appraisedAt'],
    'check',
  );
  const receiptFormatVersion = requireReceiptVersion(check['receiptFormatVersion'], 'check');

  const context = requireObject(root['context'], 'context');
  requireKnownMembers(context, ['collateral', 'validity'], 'context');
  if (context['collateral'] === undefined || context['validity'] === undefined) {
    refused(
      'NOT_CAPTURE_RECORD',
      `context is missing ${context['collateral'] === undefined ? 'collateral' : 'validity'}, and a context member nobody declared is not an absent one`,
    );
  }

  const trust = requireObject(root['trust'], 'trust');
  requireKnownMembers(trust, ['roots', 'limits'], 'trust');
  const limits = requireObject(trust['limits'], 'trust.limits');
  requireKnownMembers(limits, ['maxReceiptAgeSeconds', 'maxEvidenceAgeSeconds'], 'trust.limits');

  const record: CaptureRecord = {
    v: version,
    original: {
      sourceKind,
      sourceId: requireText(original, 'sourceId', 'original'),
      bytes: requireText(original, 'bytes', 'original'),
      sha256: requireDigest(original, 'sha256', 'original'),
      byteCount: requireWhole(original, 'byteCount', 'original', 'a byte count'),
      signedBySource,
      signatureEmbedded,
      ...(signature === undefined ? {} : { signature }),
    },
    acquired: {
      at: requireWhole(acquired, 'at', 'acquired', 'a unix time'),
      sourceStatedAt: requireOrNullWhole(acquired, 'sourceStatedAt', 'acquired', 'a unix time'),
    },
    manifests: { deployment: readSlot(manifests['deployment'], 'manifests.deployment') },
    check: {
      policyVersion: requireImplementedVersion(
        check['policyVersion'],
        'check.policyVersion',
        IMPLEMENTED_POLICY_VERSIONS,
      ),
      policyDigest: requireDigestOrNull(check, 'policyDigest', 'check'),
      receiptFormatVersion,
      verifierVersion: requireText(check, 'verifierVersion', 'check'),
      appraisedAt: requireWhole(check, 'appraisedAt', 'check', 'a unix time'),
    },
    context: {
      collateral: readCollateralSlot(context['collateral'], 'context.collateral'),
      validity: readSlot(context['validity'], 'context.validity'),
    },
    trust: { roots: readRoots(trust['roots']), limits: readLimits(limits) },
  };

  decodeStated(record.original, 'original');
  return record;
}

function readRoots(value: unknown): CaptureRootReference[] {
  if (!Array.isArray(value)) {
    return refused('NOT_CAPTURE_RECORD', `trust.roots is ${describe(value)}, and the references relied on are a list`);
  }
  return value.map((entry, index) => {
    const block = requireObject(entry, `trust.roots entry ${index}`);
    requireKnownMembers(block, ['family', 'digest'], `trust.roots entry ${index}`);
    const family = requireText(block, 'family', `trust.roots entry ${index}`);
    if (!(ANCHOR_FAMILIES as readonly string[]).includes(family)) {
      refused(
        'NOT_CAPTURE_RECORD',
        `trust.roots entry ${index} names the family '${family}', which is none of ${ANCHOR_FAMILIES.join(', ')}`,
      );
    }
    return { family: family as AnchorFamily, digest: requireDigestOrNull(block, 'digest', `trust.roots entry ${index}`) };
  });
}

function readLimits(limits: Record<string, unknown>): CaptureAppliedLimits {
  return {
    maxReceiptAgeSeconds: requireOrNullWhole(limits, 'maxReceiptAgeSeconds', 'trust.limits', 'a window in seconds'),
    maxEvidenceAgeSeconds: requireOrNullWhole(limits, 'maxEvidenceAgeSeconds', 'trust.limits', 'a window in seconds'),
  };
}

/**
 * The record's identity, for whatever store a collector writes to.
 *
 * Object keys are sorted on the way in and lists keep their order, so two records of one capture agree
 * on a key while a record whose original bytes differ, by one bit or by one base64 spelling, does not.
 * The digest is over the record's canonical JSON rather than over the values of its fields because what
 * has to be unique is the document a store holds and hands back.
 */
export function captureRecordKey(record: CaptureRecord): string {
  // The prefix is a domain, not decoration: a key is a digest of a document, and one that a policy
  // digest or a receipt digest could stand in for would let a reader confuse the three.
  return toHex(sha256(new TextEncoder().encode(`${CAPTURE_KEY_DOMAIN}${canonicalJson(record)}`)));
}

const CAPTURE_KEY_DOMAIN = 'ashaveri/capture-v1 ';

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === 'string' || typeof value === 'boolean' || typeof value === 'number') {
    if (typeof value === 'number' && !Number.isFinite(value)) {
      return refused('NOT_CAPTURE_RECORD', 'a capture record holds a number no JSON document can state');
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((entry) => canonicalJson(entry)).join(',')}]`;
  }
  if (typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, entry]) => entry !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : 1));
    return `{${entries.map(([key, entry]) => `${JSON.stringify(key)}:${canonicalJson(entry)}`).join(',')}}`;
  }
  return refused('NOT_CAPTURE_RECORD', `a capture record holds a ${typeof value}, which no store can key on`);
}

/**
 * What a store decided about one write.
 *
 * `already-durable` is neither a failure nor an acknowledgement of a second copy: it is the store saying
 * it holds this record already, which is what makes a retry of one capture safe rather than additive.
 */
export type CaptureWriteOutcome = 'durable' | 'already-durable';

/**
 * Where a finished record goes to become durable, and the one promise an implementation may not break:
 * `write` resolves after the original bytes and the context they were appraised in are both durable, or
 * it rejects. Nothing resolves early.
 *
 * Both halves sit in the same sentence on purpose. A store that flushed the bytes and acknowledged
 * before the collateral reached disk would hand a collector an acknowledgement of a record no reader can
 * yet assess, and an acknowledgement of a half-written capture is worse than a failure, because the
 * collector stops retrying.
 *
 * No implementation lives here. The one that proves the promise means something is in
 * `test/capture-store.test.ts`, where it is a small in-memory thing with a failure it can be made to
 * hit: a durability claim written only in a source file is not a claim anybody can check.
 */
export interface CaptureSink {
  /** Resolves once this record can be read back after a crash, and never before. */
  write(record: CaptureRecord): Promise<CaptureWriteOutcome>;
  /** The record under its own key, or null when this store holds no such thing. */
  read(key: string): Promise<CaptureRecord | null>;
}

interface SignatureLeg {
  readonly ran: boolean;
  readonly kid: string | null;
  readonly note?: string;
}

/**
 * The signature leg, which is the half of this record a stranger can repeat alone.
 *
 * What the record states is the collector's claim: that it held these bytes from this source at this
 * instant. Nothing in the record can be believed about the signature over them, and nothing in it is.
 * What runs here is the format's own verifier, over the stored bytes, under a key resolved out of the
 * caller's pins and no other source, inside the caller's own freshness windows, and at the receipt
 * version the record names rather than the reader's default. A caller that pinned nothing reaches no
 * verdict and is told so, which is the difference between this and a log line that prints
 * `verified: true`.
 */
function repeatSignatureLeg(
  record: CaptureRecord,
  originalBytes: Uint8Array,
  policy: AshaveriPolicy | undefined,
  nowSeconds: number,
): SignatureLeg {
  const acceptedVersions: readonly ReceiptVersion[] = [record.check.receiptFormatVersion];
  if (!record.original.signedBySource) {
    return { ran: false, kid: null, note: 'the record claims no signature over these bytes, so there is nothing to repeat' };
  }
  if (record.original.sourceKind !== 'receipt') {
    return {
      ran: false,
      kid: null,
      note: `the signature over ${record.original.sourceKind} is a vendor's, and walking it needs verifyCompletionEvidence rather than this record`,
    };
  }
  let kid: Uint8Array;
  try {
    kid = decodeReceipt(originalBytes, { acceptedVersions }).header.kid;
  } catch (err) {
    if (err instanceof ReceiptError) {
      throw new ReceiptError(err.code, `these bytes carry no readable COSE_Sign1, so the signature the record claims is not in them: ${err.message}`);
    }
    throw err;
  }
  const kidHex = toHex(kid);
  const publicKey = policy === undefined ? undefined : policyKeyByKid(policy, kid);
  if (publicKey === undefined) {
    return {
      ran: false,
      kid: kidHex,
      note: `the bytes are signed under kid ${kidHex}, which this caller's own policy does not pin, so nothing was verified`,
    };
  }
  verifyReceipt(originalBytes, {
    publicKey,
    acceptedVersions,
    nowSeconds,
    freshnessSeconds: policy?.maxReceiptAgeSeconds ?? DEFAULT_MAX_RECEIPT_AGE_SECONDS,
    evidenceFreshnessSeconds: policy?.maxEvidenceAgeSeconds ?? DEFAULT_MAX_EVIDENCE_AGE_SECONDS,
  });
  return { ran: true, kid: kidHex };
}

function matchRoots(
  record: CaptureRecord,
  anchors: EvidenceTrustAnchors,
): { readonly matched: AnchorFamily[]; readonly notes: string[]; readonly unassessed: boolean } {
  const matched: AnchorFamily[] = [];
  const notes: string[] = [];
  let unassessed = false;
  for (const reference of record.trust.roots) {
    if (reference.digest === null) {
      unassessed = true;
      notes.push(`the check relied on an unnamed root in family '${reference.family}', so no reader can say which bytes it trusted`);
      continue;
    }
    const pinned = anchors[reference.family];
    if (pinned === undefined || pinned.length === 0) {
      unassessed = true;
      notes.push(`the record relies on root digest ${reference.digest} in family '${reference.family}' and this caller has pinned nothing in that family to compare it against`);
      continue;
    }
    const digests = pinned.map((root) => toHex(sha256(root)));
    if (!digests.includes(reference.digest)) {
      throw new SdkError(
        'EVIDENCE_VERIFICATION_FAILED',
        `the record relied on root digest ${reference.digest} in family '${reference.family}', which is none of this caller's pinned roots (${digests.join(', ')})`,
      );
    }
    matched.push(reference.family);
  }
  return { matched, notes, unassessed };
}

/**
 * Read a capture record, and say what can be concluded from it.
 *
 * Pure: it takes a record, the caller's own pinned roots and policy, and a clock. It writes nothing and
 * fetches nothing, and what it returns is qualified on purpose. A capture record can be whole, honest
 * and self-consistent while the collateral its bytes were appraised against is missing, and the only
 * right answer to that is a verdict that says what it could not see.
 */
export function assessCapture(params: AssessCaptureParams): CaptureVerdict {
  const record = parseCaptureRecord(params.record);
  const originalBytes = decodeStated(record.original, 'original');
  const nowSeconds = Math.floor((params.nowMillis ?? Date.now()) / 1000);
  const policy = params.policy;
  const anchors = params.anchors ?? policy?.trustAnchors ?? {};

  const qualifications: string[] = [];
  const absences: CaptureDeclaredAbsence[] = [];
  let unassessed = false;

  const slots: readonly (readonly [string, CaptureSlot])[] = [
    ['manifests.deployment', record.manifests.deployment],
    ['context.collateral', record.context.collateral],
    ['context.validity', record.context.validity],
    ...(record.original.signature === undefined
      ? []
      : ([['original.signature', record.original.signature]] as const)),
  ];
  for (const [name, slot] of slots) {
    if (slot.presence === 'held') {
      decodeStated(slot, name);
      continue;
    }
    absences.push({ slot: name, presence: slot.presence, reason: slot.reason });
    if (slot.presence === 'not-taken-in') unassessed = true;
  }

  const signature = repeatSignatureLeg(record, originalBytes, policy, nowSeconds);
  if (signature.note !== undefined) qualifications.push(signature.note);
  // A record that asserts a signature the reader could not repeat is a record whose central claim is
  // standing on nobody's checking. That is not a qualified verdict, because the qualification would be a
  // note beside a pass; it is a leg that did not run.
  if (record.original.signedBySource && !signature.ran) unassessed = true;

  const roots = matchRoots(record, anchors);
  qualifications.push(...roots.notes);
  if (roots.unassessed) unassessed = true;

  // Our clock against the record's own ordering. A record that appraised the context before it took in
  // the bytes describes an event that cannot have happened, and the honest answer is that a reader
  // cannot assess what it cannot place.
  if (record.check.appraisedAt < record.acquired.at) {
    unassessed = true;
    qualifications.push(
      `the appraisal at ${record.check.appraisedAt} precedes the acquisition at ${record.acquired.at}, so the record's own ordering is unusable`,
    );
  }
  if (record.acquired.sourceStatedAt !== null && record.acquired.sourceStatedAt > record.acquired.at) {
    qualifications.push(
      `the source dated these bytes ${record.acquired.sourceStatedAt - record.acquired.at}s after we took them in, so the two clocks disagree`,
    );
  }

  // The limits the record states sit beside the ones this reader ran. A difference is never a pass and
  // never a refusal either: the record's looser window is a somebody-else reached, and what this caller
  // has is the verdict computed under its own.
  const appliedReceipt = policy?.maxReceiptAgeSeconds ?? DEFAULT_MAX_RECEIPT_AGE_SECONDS;
  const appliedEvidence = policy?.maxEvidenceAgeSeconds ?? DEFAULT_MAX_EVIDENCE_AGE_SECONDS;
  if (record.trust.limits.maxReceiptAgeSeconds !== appliedReceipt) {
    qualifications.push(
      `the record states ${stateWindow(record.trust.limits.maxReceiptAgeSeconds)} for the receipt window while this reader applied ${stateWindow(appliedReceipt)}`,
    );
  }
  if (record.trust.limits.maxEvidenceAgeSeconds !== appliedEvidence) {
    qualifications.push(
      `the record states ${stateWindow(record.trust.limits.maxEvidenceAgeSeconds)} for the evidence window while this reader applied ${stateWindow(appliedEvidence)}`,
    );
  }

  const status: CaptureVerdict['status'] = unassessed
    ? 'unassessed'
    : absences.length > 0 || qualifications.length > 0
      ? 'qualified'
      : 'repeated';

  return {
    status,
    stated: {
      sourceKind: record.original.sourceKind,
      sourceId: record.original.sourceId,
      acquiredAt: record.acquired.at,
      sourceStatedAt: record.acquired.sourceStatedAt,
      sha256: toHex(sha256(originalBytes)),
      byteCount: originalBytes.length,
      assertsSignature: record.original.signedBySource,
      collateral:
        record.context.collateral.presence === 'held'
          ? collateralObservationOf(record.context.collateral)
          : null,
    },
    repeated: {
      originalBytes,
      sha256: toHex(sha256(originalBytes)),
      signatureVerifiedWithOwnPins: signature.ran,
      signingKid: signature.kid,
      rootsMatched: roots.matched,
    },
    absences,
    qualifications,
  };
}

/**
 * One window in the words a qualification carries. A record states a whole number of seconds or names
 * none, and a null says only the latter: it is not a window that stayed open, which this reader can meet
 * only in the policy object its own caller handed it, because `parseCaptureRecord` admits no other
 * spelling on a record's side.
 */
function stateWindow(value: number | null): string {
  if (value === null) return 'no window of its own';
  if (!Number.isFinite(value)) return 'a window that never closes';
  return `${value}s`;
}
