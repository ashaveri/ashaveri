import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha2.js';
import { ReceiptError, decodeCoseSign1, equalBytes, issueReceipt, type SigningKey } from '@ashaveri/receipt';
import {
  SdkError,
  assessCapture,
  captureRecordKey,
  fromBase64Url,
  parseCaptureRecord,
  parseManifest,
  toBase64Url,
  toHex,
  type AssessCaptureParams,
  type AshaveriPolicy,
  type CaptureVerdict,
  type EvidenceTrustAnchors,
} from '@ashaveri/sdk';
import { labeled } from './seed.ts';
import { FIXED_IAT, fixtureKey, fixturePayload } from './receipt-envelope.ts';

const DATA = join(dirname(fileURLToPath(import.meta.url)), '..', 'data');

/**
 * The capture record vectors: one evidence document's exact bytes beside the answer the published reader gives.
 *
 * Every other format whose bytes an auditor can be handed has a vector file to replay. The capture record ships a
 * schema, a reader and a document describing both, and had no file beside them, so a stranger could read the layout
 * and could run the code, but could not hand the code bytes this repository stands behind and see which answer is
 * owed. This suite is those bytes and those answers.
 *
 * What is published is bytes and verdicts. How a collector came to hold a record, and what it did to keep one,
 * reaches no row here.
 *
 * Two entry points are published and both are run, because they answer different questions and a port has to know
 * which one refused it. `parseCaptureRecord` binds the layout: closure over the members version one defines, the
 * shape of each one, the spelling a byte string has to round-trip through, and the digest each states.
 * `assessCapture` parses and then runs the reading: every held slot's digest recomputed, the signature leg over
 * the stored bytes under the caller's own pin, the stated roots against the caller's own pins, and the two clocks.
 * A document the layout refuses is refused by both calls with one code, since the second begins with the first, so
 * each refused row states which step answered it, and `reading` marks the rows whose document is whole and whose
 * answer came from something outside it.
 *
 * Nothing here states a verdict the reader did not give. Every `status`, `stated`, `repeated`, `absences`,
 * `qualifications`, `recordKey`, `code` and `message` below is what the shipped code answered when this file was
 * written, and `main` stops unless a reader answers the direction its case states. A row meant to be refused and
 * answered with a verdict is the defect a port most needs told, and it is invisible to a generator that publishes
 * whatever it observes, so the direction is written into the case and required of the run rather than inferred
 * from the outcome.
 *
 * The originals are not invented. The bytes every row states as its original, apart from the four named below, are
 * `issueReceipt` output over the fixture payload under the key `data/keys/receipt-key-v1.json` publishes, and `main`
 * requires that document to be byte for byte `data/receipts/receipt-valid-v1.cbor`, the one the receipt suite seals
 * and verifies, which is what makes every other row a capture of the file rather than of a copy of it. Those four
 * each say which bytes they name: one states the deployment manifest as its original, one states the receipt with
 * one bit changed inside it, and two state one envelope of that receipt with its four elements untouched and its
 * framing written by a second encoder. That re-framed document is assembled out of what `decodeCoseSign1` hands
 * back, which is the only way a purported equivalent can be made out of a real document rather than guessed at. The
 * manifest a held slot carries is a document `parseManifest` accepts, and `main` asks it.
 */

/** A key derived from a label rather than drawn at random, in the shape `@ashaveri/receipt`'s writer takes. */
function keyFromLabel(label: string): SigningKey {
  const privateKey = labeled(label);
  const publicKey = ed25519.getPublicKey(privateKey);
  return { privateKey, publicKey, kid: sha256(publicKey) };
}

const TEXT = (value: string): Uint8Array => new TextEncoder().encode(value);
const digestHex = (bytes: Uint8Array): string => toHex(sha256(bytes));

/** The fixture signing key, the one every other suite that seals a receipt seals it with. */
const KEY = fixtureKey();
const KID_HEX = toHex(KEY.kid);

/**
 * A second Ed25519 key, whose private half signs nothing here. It is what a caller that pinned the wrong public
 * half for this kid hands the reader, and the row stating it publishes the half so a port can replay the call.
 */
const OTHER: SigningKey = keyFromLabel('ashaveri-capture-v1/another-pinned-key');

const PAYLOAD = fixturePayload();

/** The receipt every row states as its original, unless the row names other bytes. */
const ORIGINAL = issueReceipt(PAYLOAD, KEY);

/** The detached signature that envelope carries inside it, taken out of it rather than written beside it. */
const DETACHED_SIGNATURE = decodeCoseSign1(ORIGINAL).signature;

/**
 * The instant the captured receipt is issued at, and the three instants the records are dated by.
 *
 * `FIXED_IAT` is the clock every published receipt fixture is issued under and it is not moved here, because the
 * original bytes have to stay the bytes the receipt suite publishes. The taking-in sits thirty seconds behind it
 * and the appraisal ten behind that, which keeps both inside the three-hundred-second receipt window a caller runs
 * when it named none of its own, and keeps the appraisal after the taking-in, which is the order a record has to
 * state to be placeable at all.
 */
const ACQUIRED_AT = FIXED_IAT + 30;
const APPRAISED_AT = FIXED_IAT + 40;
const SOURCE_STATED_AT = FIXED_IAT - 60;
const AT_MILLIS = (FIXED_IAT + 40) * 1_000;

/** The manifest a held `manifests.deployment` slot carries, in the shape the manifest reader reads. */
const MANIFEST_BYTES = TEXT(
  JSON.stringify({
    v: 1,
    iss: PAYLOAD.iss,
    ins: PAYLOAD.ins,
    epk: 1,
    keys: [{ kid: KID_HEX, alg: 'Ed25519', publicKey: toBase64Url(KEY.publicKey) }],
    models: [{ id: PAYLOAD.mdl, wts: toHex(PAYLOAD.wts) }],
    meas: { tee: PAYLOAD.meas.tee, m: toHex(PAYLOAD.meas.m) },
  }),
);

const COLLATERAL_BYTES = TEXT('the vendor collateral answer these vectors hold');
const CHAIN_HEADER = TEXT('TCB-Info-Issuer-Chain: -----BEGIN CERTIFICATE-----');
const VALIDITY_BYTES = TEXT('the validity context the appraisal recorded');

/** A pinned vendor root, and a second one for the row whose caller pinned other bytes under the same family. */
const ROOT = TEXT('a pinned vendor root for these vectors');
const ANOTHER_ROOT = TEXT('a different pinned vendor root');

/** The address one collateral slot states its answer was asked at, and the bound a reference carries for it. */
const REQUEST_PREFIX = 'https://api.trustedservices.intel.com/sgx/certification/v4/tcb?fmspc=';
const REQUEST_BOUND_BYTES = 2_048;

/** An address of exactly the width a reference carries, and one byte past it. */
const requestAt = (bytes: number): string => `${REQUEST_PREFIX}${'a'.repeat(bytes - new TextEncoder().encode(REQUEST_PREFIX).length)}`;

/**
 * The eight facts a held collateral slot owes, in the order the reader asks for them.
 *
 * The suite states one refusal per member. That count is this list's length rather than a figure kept beside it:
 * `main` requires one row per entry, so a ninth member added to the layout gains a row and a refusal of its own
 * instead of a sentence counting eight over a list of nine.
 */
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

/** What each of the eight states, in the sentence of the row that leaves it out. */
const MEMBER_CLAUSES: Readonly<Record<(typeof OBSERVATION_MEMBERS)[number], string>> = {
  origin: 'bytes that name no source are a blob a reader cannot go and re-ask of anybody',
  request: 'an answer with no address beside it has no route a stranger can stand at',
  identity: 'a slot stating no identity and a slot stating it as null are two statements, and a missing member is neither',
  observedAt: 'an instant nobody states leaves the last byte of the answer landing nowhere',
  sourceUncertaintySeconds: 'an instant with no bound beside it reads as an accuracy nobody established',
  weighedBy: 'which reading weighed the answer, inside the bytes or apart from them, decides what a reader holds to re-run it',
  window: 'a span a signed statement reaches, unstated, is a statement that reaches nowhere',
  cacheKey: 'the same bytes kept for another question are another answer, and this member says which question',
};

/** A piece of context this record holds: the bytes as they arrived, and the digest of exactly those bytes. */
function held(bytes: Uint8Array): Record<string, unknown> {
  return { presence: 'held', bytes: toBase64Url(bytes), sha256: digestHex(bytes), byteCount: bytes.length };
}

/**
 * A held collateral slot: the bytes, their digest, and all eight facts beside them.
 *
 * The origin name, the address and the cache key's member order are the spellings `packages/collateral` declares
 * for this source, and the window is the span a TCB statement of that date reaches. The bytes inside them are
 * fixture labels; no vendor answer and no vendor byte is in this file.
 */
function collateralSlot(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    ...held(COLLATERAL_BYTES),
    origin: 'intel-tcb-info',
    request: `${REQUEST_PREFIX}00906f000200`,
    identity: { cpuType: '00906f000200', vendorStatus: 'UpToDate' },
    observedAt: ACQUIRED_AT - 10,
    sourceUncertaintySeconds: 2,
    chainSha256: digestHex(CHAIN_HEADER),
    chainBytes: toBase64Url(CHAIN_HEADER),
    weighedBy: 'served',
    window: { from: 1_735_689_600, to: 1_798_761_600 },
    cacheKey: 'origin=intel-tcb-info|platform=sgx|cpuType=00906f000200|level=tcb-date=2024-05-15T00:00:00Z',
    ...over,
  };
}

/** The record a row is one edit of: whole, every slot held, and stating one signature over the receipt above. */
function baseRecord(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    v: 1,
    original: {
      sourceKind: 'receipt',
      sourceId: PAYLOAD.ins,
      bytes: toBase64Url(ORIGINAL),
      sha256: digestHex(ORIGINAL),
      byteCount: ORIGINAL.length,
      signedBySource: true,
      signatureEmbedded: true,
    },
    acquired: { at: ACQUIRED_AT, sourceStatedAt: SOURCE_STATED_AT },
    manifests: { deployment: held(MANIFEST_BYTES) },
    check: {
      policyVersion: 1,
      policyDigest: digestHex(TEXT('the policy document this check loaded')),
      receiptFormatVersion: 1,
      verifierVersion: '0.1.0',
      appraisedAt: APPRAISED_AT,
    },
    context: { collateral: collateralSlot(), validity: held(VALIDITY_BYTES) },
    trust: {
      roots: [{ family: 'intelSgxRoots', digest: digestHex(ROOT) }],
      limits: { maxReceiptAgeSeconds: 300, maxEvidenceAgeSeconds: 900 },
    },
    ...over,
  };
}

/** One member of one block of a record replaced. Every path this suite edits is a block and a member. */
function member(record: Record<string, unknown>, block: string, name: string, value: unknown): Record<string, unknown> {
  return { ...record, [block]: { ...(record[block] as Record<string, unknown>), [name]: value } };
}

/** The same block with one member left out, which is how the absence a record never wrote down is built. */
function without(block: Record<string, unknown>, ...names: readonly string[]): Record<string, unknown> {
  const out = { ...block };
  for (const name of names) delete out[name];
  return out;
}

/** The original bytes of a record replaced, with its stated digest and length left standing or restated. */
function withOriginalBytes(record: Record<string, unknown>, bytes: Uint8Array, restate = false): Record<string, unknown> {
  const original = record['original'] as Record<string, unknown>;
  return {
    ...record,
    original: restate
      ? { ...original, bytes: toBase64Url(bytes), sha256: digestHex(bytes), byteCount: bytes.length }
      : { ...original, bytes: toBase64Url(bytes) },
  };
}

/**
 * One COSE_Sign1 with its four elements untouched, framed by a writer that does not pick the shortest head for a
 * number. To a lenient reader the two documents are one structure; on the wire they are different bytes, which is
 * all a capture record can see and the only thing it is allowed to accept.
 */
function reserialize(bytes: Uint8Array): Uint8Array {
  const parts = decodeCoseSign1(bytes);
  const out: number[] = [0xd8, 0x12, 0x98, 0x04];
  bstrWithInflatedHead(out, parts.protectedBytes);
  out.push(0xb8, 0x00);
  bstrWithInflatedHead(out, parts.payloadBytes);
  bstrWithInflatedHead(out, parts.signature);
  return Uint8Array.from(out);
}

function bstrWithInflatedHead(out: number[], bytes: Uint8Array): void {
  const length = bytes.length;
  if (length < 0x1_0000) {
    out.push(0x59, (length >> 8) & 0xff, length & 0xff);
  } else {
    out.push(0x5a, (length >> 24) & 0xff, (length >> 16) & 0xff, (length >> 8) & 0xff, length & 0xff);
  }
  out.push(...bytes);
}

/**
 * Another base64url spelling of the same bytes, by moving a tail bit no part of the document occupies. Both
 * spellings decode to one value and only one of them re-encodes to itself, which is the rule a JSON validator
 * cannot state and this reader holds for every byte string in a record.
 */
function secondSpelling(bytes: Uint8Array): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const canonical = toBase64Url(bytes);
  const last = canonical[canonical.length - 1]!;
  const spelled = `${canonical.slice(0, -1)}${alphabet[alphabet.indexOf(last) + 1]!}`;
  if (!equalBytes(fromBase64Url(spelled), bytes) || toBase64Url(fromBase64Url(spelled)) !== canonical) {
    throw new Error(`${spelled} is not a second spelling of these ${String(bytes.length)} bytes: a short last group is where one exists`);
  }
  return spelled;
}

/** What the caller hands the reader beside the document: its own pins and its own clock, as the file states them. */
interface Read {
  /** The caller's pinning policy. `keys` maps the hex kid a header names to the public half pinned under it. */
  policy?: { keys?: Record<string, string>; maxReceiptAgeSeconds?: number; maxEvidenceAgeSeconds?: number };
  /** The caller's own pinned vendor roots, unpadded base64url, by family. */
  anchors?: Record<string, string[]>;
  /** Wall clock in milliseconds, fixed, so a row's answer does not move with the day it is read on. */
  atMillis: number;
}

const PINNED: Read = {
  policy: { keys: { [KID_HEX]: toBase64Url(KEY.publicKey) } },
  anchors: { intelSgxRoots: [toBase64Url(ROOT)] },
  atMillis: AT_MILLIS,
};

/** The reader's parameters, built out of the published row and out of nothing else. */
function paramsFor(read: Read, record: Record<string, unknown>): AssessCaptureParams {
  const policy: AshaveriPolicy | undefined =
    read.policy === undefined
      ? undefined
      : {
          keys: read.policy.keys,
          ...(read.policy.maxReceiptAgeSeconds === undefined ? {} : { maxReceiptAgeSeconds: read.policy.maxReceiptAgeSeconds }),
          ...(read.policy.maxEvidenceAgeSeconds === undefined ? {} : { maxEvidenceAgeSeconds: read.policy.maxEvidenceAgeSeconds }),
        };
  const anchors: EvidenceTrustAnchors | undefined =
    read.anchors === undefined
      ? undefined
      : (Object.fromEntries(
          Object.entries(read.anchors).map(([family, roots]) => [family, roots.map((one) => fromBase64Url(one))]),
        ) as EvidenceTrustAnchors);
  return {
    record,
    ...(policy === undefined ? {} : { policy }),
    ...(anchors === undefined ? {} : { anchors }),
    nowMillis: read.atMillis,
  };
}

interface Case {
  readonly name: string;
  readonly note: string;
  readonly record: Record<string, unknown>;
  readonly read: Read;
  /** For a document the reader takes: the status it states, which `main` requires the reader to answer. */
  readonly status?: 'repeated' | 'qualified' | 'unassessed';
  /** For a document it refuses: which of the two published steps answered, and with the code it states. */
  readonly stage?: 'layout' | 'reading';
  readonly code?: string;
}

const RESERIALIZED = reserialize(ORIGINAL);

const CASES: readonly Case[] = [
  {
    name: 'exact-original-bytes-repeated',
    note: 'The record this suite is built around: the original bytes are the receipt `data/receipts/receipt-valid-v1.cbor` publishes, held as they arrived, and every context slot states itself held. The reader hands those bytes back unchanged, recomputes the digest the record states, resolves the kid in their own header to the key the caller pinned under it, and matches the one root the record relied on against the caller\'s own. That is the whole of `repeated`, and it is reached only out of a caller\'s pins and never out of the record\'s word.',
    record: baseRecord(),
    read: PINNED,
    status: 'repeated',
  },
  {
    name: 'collateral-absent-at-source-qualified',
    note: "The same record with its collateral slot stating that this source never produced an answer, in the collector's own words. The signature leg still runs and the root still matches, and the verdict is `qualified` rather than `repeated`, because what the bytes were appraised against is missing from the reading however well the rest of it holds. The absence reaches `absences` with the slot that named it, which is what keeps a stated absence apart from a hole.",
    record: baseRecord({
      context: {
        collateral: { presence: 'absent-at-source', reason: 'the source served no collateral answer' },
        validity: held(VALIDITY_BYTES),
      },
    }),
    read: PINNED,
    status: 'qualified',
  },
  {
    name: 'collateral-not-taken-in-unassessed',
    note: 'The collateral slot stating instead that the answer may have existed and nobody put it in the record. One word of the document separates this row from the one above and two statuses separate their verdicts: the first is a statement about the source and this one is a statement about the taking-in, which no reader repairs by looking harder.',
    record: baseRecord({
      context: {
        collateral: { presence: 'not-taken-in', reason: 'the route was never asked' },
        validity: held(VALIDITY_BYTES),
      },
    }),
    read: PINNED,
    status: 'unassessed',
  },
  {
    name: 'validity-absent-at-source-qualified',
    note: 'The second context slot stating an absence, which is the one that says what window the appraisal ran in. The collateral here is whole, so the slot named in `absences` is what tells a reader which of the two it was told about, and the status is `qualified` because the signature leg ran.',
    record: baseRecord({
      context: {
        collateral: collateralSlot(),
        validity: { presence: 'absent-at-source', reason: 'no window was recorded for this appraisal' },
      },
    }),
    read: PINNED,
    status: 'qualified',
  },
  {
    name: 'deployment-manifest-not-taken-in-unassessed',
    note: 'The manifest slot stating that nobody took it in. A receipt points at its evidence with a digest, a stamp and a URL, and the document the pins are read from is the one piece of context nothing inside this record can recover: this is the shape of a capture that keeps its bytes and loses where they came from.',
    record: member(baseRecord(), 'manifests', 'deployment', {
      presence: 'not-taken-in',
      reason: 'the manifest route answered nothing',
    }),
    read: PINNED,
    status: 'unassessed',
  },
  {
    name: 'detached-signature-slot-carried',
    note: 'A record stating that its source served the signature apart from the bytes, and carrying it as its own slot: the 64 bytes taken out of the envelope above, beside their own digest. The slot is checked the way every held slot is checked and nothing verifies through it, because the signature leg reads the kid out of the stored document and checks that document\'s own bytes. Publishing the row says which of those two a reader did.',
    record: member(
      member(baseRecord(), 'original', 'signatureEmbedded', false),
      'original',
      'signature',
      held(DETACHED_SIGNATURE),
    ),
    read: PINNED,
    status: 'repeated',
  },
  {
    name: 'weighed-by-embedded-without-a-chain',
    note: 'A collateral slot whose answer carries its signature inside the bytes it is, stated as `embedded`, and which states neither half of the chain pair. Stating neither is the spelling of a chain that arrived in no header, which is a reading and not a hole; an empty string or a guess would be a claim about a header nobody held.',
    record: member(
      baseRecord(),
      'context',
      'collateral',
      { ...without(collateralSlot(), 'chainSha256', 'chainBytes'), weighedBy: 'embedded' },
    ),
    read: PINNED,
    status: 'repeated',
  },
  {
    name: 'identity-stating-none',
    note: 'A collateral slot stating its identity as null, which is the answer naming no CPU type, and a different statement from leaving the member out. The row among the eight that states it missing is where leaving it out is refused; this is where saying it is absent is taken.',
    record: member(baseRecord(), 'context', 'collateral', collateralSlot({ identity: null })),
    read: PINNED,
    status: 'repeated',
  },
  {
    name: 'address-at-the-last-byte-a-reference-carries',
    note: `A collateral slot stating the address it was asked at at exactly ${String(REQUEST_BOUND_BYTES)} bytes of UTF-8, the width a reference carries for an address and no wider. The row beside the refusals that states one byte more is what makes the ceiling a width rule rather than a number a note quotes.`,
    record: member(baseRecord(), 'context', 'collateral', collateralSlot({ request: requestAt(REQUEST_BOUND_BYTES) })),
    read: PINNED,
    status: 'repeated',
  },
  {
    name: 'two-roots-relied-on-and-both-pinned',
    note: "A record that consulted two vendor families, and a caller that pins a root under each. `rootsMatched` comes back in the order the record stated its references, which is the order the check relied on them and not an alphabetical one; a caller pinning one of the two families and not the other is the refusal beside this row.",
    record: member(baseRecord(), 'trust', 'roots', [
      { family: 'intelSgxRoots', digest: digestHex(ROOT) },
      { family: 'amdArks', digest: digestHex(ROOT) },
    ]),
    read: {
      policy: PINNED.policy,
      anchors: { intelSgxRoots: [toBase64Url(ROOT)], amdArks: [toBase64Url(ROOT)] },
      atMillis: AT_MILLIS,
    },
    status: 'repeated',
  },
  {
    name: 'source-dated-its-bytes-after-the-taking-in',
    note: "The source's own stamp sitting sixty seconds ahead of the instant this record says the bytes were taken in. Nothing refuses it: two stamps that disagree are information, and the reader says which way they disagree and hands the pair back in `stated` rather than smoothing them into one number.",
    record: member(baseRecord(), 'acquired', 'sourceStatedAt', ACQUIRED_AT + 60),
    read: PINNED,
    status: 'qualified',
  },
  {
    name: 'record-naming-windows-wider-than-this-callers',
    note: "A record that states an hour for both windows, read by a caller that named none of its own and so runs the shipped defaults. The verdict is computed under the caller's windows and the row states both numbers, because a record's looser window is somebody else's reached: a reader that inherited the window a document claims would pass a stamp this caller refuses.",
    record: member(baseRecord(), 'trust', 'limits', { maxReceiptAgeSeconds: 3_600, maxEvidenceAgeSeconds: 3_600 }),
    read: PINNED,
    status: 'qualified',
  },
  {
    name: 'record-stating-neither-window',
    note: 'The same pair of members stated as `null`, which is the record saying it named no window of its own and not that its clock stayed open. The reader runs the shipped defaults beside that and says so; the two spellings are kept apart because a null and an unbounded window are two different claims about the check.',
    record: member(baseRecord(), 'trust', 'limits', { maxReceiptAgeSeconds: null, maxEvidenceAgeSeconds: null }),
    read: PINNED,
    status: 'qualified',
  },
  {
    name: 'appraisal-dated-before-the-taking-in',
    note: 'A record whose appraisal ran an hour before the bytes it appraises were taken in. The reader cannot place it, and the honest answer to a document that cannot be placed is `unassessed` with the ordering stated as the reason: not a refusal, because the bytes are whole, and not a pass, because nothing here saw them.',
    record: member(baseRecord(), 'check', 'appraisedAt', ACQUIRED_AT - 3_600),
    read: PINNED,
    status: 'unassessed',
  },
  {
    name: 'root-the-check-relied-on-but-never-named',
    note: 'A record whose reference names a family and states no digest for it. A reader cannot say which bytes were trusted, so it says that instead of agreeing, and the unnamed root reaches `unassessed`: the shape of a capture that is honest about having used something it did not write down.',
    record: member(baseRecord(), 'trust', 'roots', [{ family: 'intelSgxRoots', digest: null }]),
    read: PINNED,
    status: 'unassessed',
  },
  {
    name: 'caller-pinned-nothing-in-that-family',
    note: "The honest record handed to a caller that pins roots in another family. The digest the record relies on has nothing beside it to be compared against, which the reader reports rather than filling from the library default bundled next to it: a default is a vendor's choice and not this caller's pin.",
    record: baseRecord(),
    read: { policy: PINNED.policy, anchors: { amdArks: [toBase64Url(ROOT)] }, atMillis: AT_MILLIS },
    status: 'unassessed',
  },
  {
    name: 'caller-holding-no-pin-at-all',
    note: 'The same document read by a caller that pinned no key and no root. Every leg that could run is stated as one that did not, and the status is `unassessed`: a record of bytes somebody held is not a verdict, and a reader with nothing to check against says so twice rather than agreeing once.',
    record: baseRecord(),
    read: { atMillis: AT_MILLIS },
    status: 'unassessed',
  },
  {
    name: 'vendor-signed-original-this-reader-does-not-walk',
    note: "A report stated under the kind that names it a device's, whose signature is a vendor's. This reader repeats the receipt leg and names the vendor leg as one it did not run, so the verdict is `unassessed` and the qualification says which walk a caller has to go and run elsewhere. The bytes are the fixture receipt, which is stated as it is: this suite publishes no vendor document and claims none.",
    record: member(baseRecord(), 'original', 'sourceKind', 'device-evidence'),
    read: PINNED,
    status: 'unassessed',
  },
  {
    name: 'manifest-original-claiming-no-signature',
    note: 'A deployment manifest stated as the original, with `signedBySource` false, which is the record denying that anything signed these bytes rather than leaving the question out. The leg has nothing to repeat and says so, the digest and the length are recomputed over the bytes, and the status is `qualified`: a whole record of an unsigned document is a reading with one arm missing and a reader that names which.',
    record: baseRecord({
      original: {
        sourceKind: 'deployment-manifest',
        sourceId: PAYLOAD.iss,
        bytes: toBase64Url(MANIFEST_BYTES),
        sha256: digestHex(MANIFEST_BYTES),
        byteCount: MANIFEST_BYTES.length,
        signedBySource: false,
        signatureEmbedded: false,
      },
    }),
    read: PINNED,
    status: 'qualified',
  },
];

/** A member's own spelling put in the kebab case every row name of this suite is written in. */
function kebab(member: string): string {
  return member.replace(/[A-Z]/gu, (letter) => `-${letter.toLowerCase()}`);
}

/**
 * The refusals, each one a small edit to the record above rather than a document no writer could produce.
 *
 * `stage` says which of the two published steps answered: `layout` where `parseCaptureRecord` refused the document
 * and `assessCapture` then refused it with the same code because it parses first, and `reading` where the layout
 * took the bytes and the answer came from what the reading runs over them, a held slot's digest and length and
 * spelling, the signature leg, the pinned roots, or the clock.
 */
const REFUSALS: readonly Case[] = [
  {
    name: 'digest-stating-another-document',
    note: 'The honest bytes, and a digest that is the digest of nothing this suite holds. Nothing downstream of the byte check can tell the two apart, which is why the check runs before a reader interprets a document at all.',
    record: member(baseRecord(), 'original', 'sha256', 'f'.repeat(64)),
    read: PINNED,
    stage: 'layout',
    code: 'EVIDENCE_DIGEST_MISMATCH',
  },
  {
    name: 'one-bit-changed-inside-the-original',
    note: 'One bit of the stored receipt flipped, at the same length and inside the same COSE_Sign1 framing, with the digest the record states still the digest of the document that went in. A reader that recomputes refuses this; a reader that reads the stated digest back accepts a different piece of evidence.',
    record: withOriginalBytes(baseRecord(), Uint8Array.from(ORIGINAL, (byte, at) => (at === 40 ? byte ^ 0x01 : byte))),
    read: PINNED,
    stage: 'layout',
    code: 'EVIDENCE_DIGEST_MISMATCH',
  },
  {
    name: 'length-one-past-the-bytes',
    note: 'The bytes and their digest both honest, and a stated length one larger. The same code answers, because the one claim a held slot makes is that what it states and what it carries are one document, and a count disagrees with that claim as a hash does.',
    record: member(baseRecord(), 'original', 'byteCount', ORIGINAL.length + 1),
    read: PINNED,
    stage: 'layout',
    code: 'EVIDENCE_DIGEST_MISMATCH',
  },
  {
    name: 'reserialized-envelope-against-the-stated-digest',
    note: "The receipt above re-framed by a writer that does not pick the shortest head for a number, its four elements untouched, carried as the bytes while the record still states the digest of the document the source produced. Parsed as a structure the two documents are one; hashed, they are two, and the equivalence a lenient reader would grant is refused here rather than accepted as near enough.",
    record: withOriginalBytes(baseRecord(), RESERIALIZED),
    read: PINNED,
    stage: 'layout',
    code: 'EVIDENCE_DIGEST_MISMATCH',
  },
  {
    name: 'reserialized-envelope-stated-as-its-own-original',
    note: "The same re-framed bytes with the digest and the length restated for them, which is a record self-consistent about a document nobody produced. The layout takes it and the reading refuses: the kid in those bytes resolves to the key the caller pinned, and the format's own verifier will not take a non-preferred framing, so the answer comes from the leg rather than from the shape. The two records key apart, which is what `captureRecordKey` states of them: one document is one key and a re-encoding is another.",
    record: withOriginalBytes(baseRecord(), RESERIALIZED, true),
    read: PINNED,
    stage: 'reading',
    code: 'MALFORMED_CBOR',
  },
  {
    name: 'second-spelling-of-the-detached-signature',
    note: 'The signature a source served apart from the bytes, written in the other base64url spelling of the same 64 bytes, with the digest and the length recomputed over what decodes. Every member of the record is then true of the bytes and the row is still refused for the one thing a JSON document cannot state: that a byte string has one spelling a reader reproduces. The layout closes the slot\'s members and hands its bytes to the reading, which is where each held slot\'s digest, length and spelling are recomputed, so this is the byte rule stated at the one site furthest from the original.',
    record: member(
      member(baseRecord(), 'original', 'signatureEmbedded', false),
      'original',
      'signature',
      {
        presence: 'held',
        bytes: secondSpelling(DETACHED_SIGNATURE),
        sha256: digestHex(DETACHED_SIGNATURE),
        byteCount: DETACHED_SIGNATURE.length,
      },
    ),
    read: PINNED,
    stage: 'reading',
    code: 'NOT_CAPTURE_RECORD',
  },
  {
    name: 'collateral-slot-left-out-of-the-context',
    note: 'A record whose `context` block carries a validity slot and says nothing at all about collateral. The member is simply not there, which this format refuses rather than reads as an absence, because a record that never said what became of the answer its bytes were appraised against cannot be told apart from one whose answer never existed.',
    record: { ...baseRecord(), context: without(baseRecord().context as Record<string, unknown>, 'collateral') },
    read: PINNED,
    stage: 'layout',
    code: 'NOT_CAPTURE_RECORD',
  },
  {
    name: 'validity-slot-left-out-of-the-context',
    note: 'The same hole on the other side of the block. Both members of `context` are required and each refusal names which of the two was absent, since which of them a collector forgot is the first thing a reader of the refusal needs.',
    record: { ...baseRecord(), context: without(baseRecord().context as Record<string, unknown>, 'validity') },
    read: PINNED,
    stage: 'layout',
    code: 'NOT_CAPTURE_RECORD',
  },
  {
    name: 'deployment-manifest-left-out-altogether',
    note: 'A record whose `manifests` block is empty. A manifest the source never served is a slot stating `absent-at-source` with a reason beside it, and a block with nothing in it is a silence about the document the pins are read out of.',
    record: baseRecord({ manifests: {} }),
    read: PINNED,
    stage: 'layout',
    code: 'NOT_CAPTURE_RECORD',
  },
  {
    name: 'absence-with-no-reason-beside-it',
    note: 'A slot stating that the source never produced it, and no line about what the collector saw. An absence is a statement, and a statement with nothing in it is the hole this format exists to keep apart from a held slot.',
    record: member(baseRecord(), 'context', 'collateral', { presence: 'absent-at-source' }),
    read: PINNED,
    stage: 'layout',
    code: 'NOT_CAPTURE_RECORD',
  },
  {
    name: 'absence-carrying-the-bytes-of-a-held-slot',
    note: 'A slot declaring itself not taken in while carrying `bytes`, a digest and a length. The published schema closes an absent slot at two members, so a reader that read the rest of a holding slot and dropped these would accept this document and key it as though the statement about bytes had never been made.',
    record: member(baseRecord(), 'context', 'collateral', {
      presence: 'not-taken-in',
      reason: 'the route was never asked',
      bytes: toBase64Url(COLLATERAL_BYTES),
    }),
    read: PINNED,
    stage: 'layout',
    code: 'NOT_CAPTURE_RECORD',
  },
  ...OBSERVATION_MEMBERS.map((name): Case => ({
    name: `held-collateral-stating-no-${kebab(name)}`,
    note: `A collateral slot holding the answer and stating seven of the eight facts about it, with \`${name}\` left out: ${MEMBER_CLAUSES[name]}. The refusal names the member rather than the slot, and one row per member is what says the loop that asks for them is live rather than a single check a first omission satisfies.`,
    record: member(baseRecord(), 'context', 'collateral', without(collateralSlot(), name)),
    read: PINNED,
    stage: 'layout',
    code: 'NOT_CAPTURE_RECORD',
  })),
  {
    name: 'chain-header-with-no-digest-beside-it',
    note: 'A collateral slot stating the header its issuer chain arrived in and no digest of it. Bytes nobody can name a digest of are bytes no later reader can be shown, which is the half of the pair this row states alone.',
    record: member(baseRecord(), 'context', 'collateral', without(collateralSlot(), 'chainSha256')),
    read: PINNED,
    stage: 'layout',
    code: 'NOT_CAPTURE_RECORD',
  },
  {
    name: 'chain-digest-with-no-header-beside-it',
    note: 'The other half stated alone: a digest of a header nobody kept, which is a statement about nothing but a hash. The two refusals are one rule about a pair, and each names the member that was missing from it.',
    record: member(baseRecord(), 'context', 'collateral', without(collateralSlot(), 'chainBytes')),
    read: PINNED,
    stage: 'layout',
    code: 'NOT_CAPTURE_RECORD',
  },
  {
    name: 'chain-digest-of-another-header',
    note: "Both halves of the chain present, and the digest stating a header other than the one beside it. This is the record's own byte rule read at a second site rather than a new one, and the published row is what shows it holds there too: a validator that checks neither half against the other cannot refuse it.",
    record: member(baseRecord(), 'context', 'collateral', collateralSlot({ chainSha256: digestHex(ANOTHER_ROOT) })),
    read: PINNED,
    stage: 'layout',
    code: 'EVIDENCE_DIGEST_MISMATCH',
  },
  {
    name: 'chain-header-in-a-second-spelling',
    note: 'The header itself, written in the other base64url spelling of the same bytes, with its digest recomputed over what decodes. The rule the original bytes are read by is the rule a chain is read by, and this is the row that states it at the second site.',
    record: member(
      baseRecord(),
      'context',
      'collateral',
      collateralSlot({ chainBytes: secondSpelling(CHAIN_HEADER), chainSha256: digestHex(CHAIN_HEADER) }),
    ),
    read: PINNED,
    stage: 'layout',
    code: 'NOT_CAPTURE_RECORD',
  },
  {
    name: `address-one-byte-past-what-a-reference-carries`,
    note: `A collateral slot stating the address it was asked at at ${String(REQUEST_BOUND_BYTES + 1)} bytes of UTF-8, one past the bound the reference layout carries for an address. The count is in bytes and no keyword of the published schema counts bytes, so this row is the reader's rule rather than the document's, and a slot past it is a record whose bytes can be kept and never pointed at.`,
    record: member(baseRecord(), 'context', 'collateral', collateralSlot({ request: requestAt(REQUEST_BOUND_BYTES + 1) })),
    read: PINNED,
    stage: 'layout',
    code: 'NOT_CAPTURE_RECORD',
  },
  {
    name: 'instant-below-the-epoch',
    note: 'A collateral slot stating the instant its last byte landed as negative seconds. An instant, a bound on an instant and either end of a span are refused at the same edge, because an instant below the epoch is a reading no window can be weighed against.',
    record: member(baseRecord(), 'context', 'collateral', collateralSlot({ observedAt: -1 })),
    read: PINNED,
    stage: 'layout',
    code: 'NOT_CAPTURE_RECORD',
  },
  {
    name: 'weighing-naming-a-third-reading',
    note: "A collateral slot stating `weighedBy` as a word the two readings are not. Which path a signature took decides what a reader has to hold to re-run the weighing, so a third word is not a narrower reading of either one and is refused rather than defaulted to the nearer.",
    record: member(baseRecord(), 'context', 'collateral', collateralSlot({ weighedBy: 'assumed' })),
    read: PINNED,
    stage: 'layout',
    code: 'NOT_CAPTURE_RECORD',
  },
  {
    name: 'member-capture-version-one-does-not-define',
    note: 'An `original` block carrying `retainedAt`, a member no version of this record defines. Closure is the rule `receipt.cddl` states for its own container and this one keeps: a collector that wrote a field no reader knows was answering a question this record cannot ask, and dropping it quietly turns that answer into a silence.',
    record: member(baseRecord(), 'original', 'retainedAt', ACQUIRED_AT),
    read: PINNED,
    stage: 'layout',
    code: 'NOT_CAPTURE_RECORD',
  },
  {
    name: 'slot-member-no-presence-state-defines',
    note: 'A held manifest slot carrying `fetchedFrom`. A slot may state its bytes, their digest and length, one of the three presence states, the reason beside an absence, and the ten a collateral slot owes its answer; a member outside that set is a claim about where bytes came from that no presence state carries.',
    record: member(baseRecord(), 'manifests', 'deployment', {
      ...held(MANIFEST_BYTES),
      fetchedFrom: 'https://gateway.test/deployment-manifest',
    }),
    read: PINNED,
    stage: 'layout',
    code: 'NOT_CAPTURE_RECORD',
  },
  {
    name: 'source-kind-this-record-has-no-reading-for',
    note: 'An `original.sourceKind` naming a source the closed set does not carry. A new source arrives as a new capture version rather than as a new string, because a reader that fell through an unknown kind to its default handling would assess a document it holds no rules for.',
    record: member(baseRecord(), 'original', 'sourceKind', 'model-weights'),
    read: PINNED,
    stage: 'layout',
    code: 'NOT_CAPTURE_RECORD',
  },
  {
    name: 'anchor-family-no-policy-names',
    note: "A trust reference naming a vendor family no pinning policy of this estate names. The families are the closed set a policy document spells, and a reference outside it can be matched against a caller's pins nor reported as unmatched, so it is refused where it is read rather than carried to the verdict.",
    record: member(baseRecord(), 'trust', 'roots', [{ family: 'armCCA', digest: digestHex(ROOT) }]),
    read: PINNED,
    stage: 'layout',
    code: 'NOT_CAPTURE_RECORD',
  },
  {
    name: 'capture-version-two',
    note: 'A record naming capture format version 2. The version decides which members exist, so a reader with no rules for it refuses rather than reading it under the rules it does have, and the answer names the version the record stated beside the versions this build implements.',
    record: baseRecord({ v: 2 }),
    read: PINNED,
    stage: 'layout',
    code: 'UNSUPPORTED_VERSION',
  },
  {
    name: 'policy-version-two',
    note: 'The honest record with its `check.policyVersion` stating 2. A record of a check run under rules this reader does not implement names a set of pins it cannot resolve, and the refusal is the same one the record\'s own version draws.',
    record: member(baseRecord(), 'check', 'policyVersion', 2),
    read: PINNED,
    stage: 'layout',
    code: 'UNSUPPORTED_VERSION',
  },
  {
    name: 'receipt-version-two',
    note: 'A record stating that the check read a receipt at version 2, which is a payload number the format retired. The bytes beside it frame a version 1 document, and the reader answers the version the record named rather than re-reading those bytes at a version no reader of this build opens.',
    record: member(baseRecord(), 'check', 'receiptFormatVersion', 2),
    read: PINNED,
    stage: 'layout',
    code: 'UNSUPPORTED_VERSION',
  },
  {
    name: 'claiming-a-served-signature-and-carrying-none',
    note: 'A record stating that its source signed the bytes and that the signature arrived apart from them, and carrying no signature member at all. Two of the three statements a signature claim is made of, with the third left as a silence.',
    record: member(baseRecord(), 'original', 'signatureEmbedded', false),
    read: PINNED,
    stage: 'layout',
    code: 'NOT_CAPTURE_RECORD',
  },
  {
    name: 'signature-slot-stating-an-absence',
    note: "The same claim, with the slot present and stating that the signature was not taken in. This is the one refusal of this family with a code of its own rather than the layout's: the record does not contradict itself about what it holds, it says it carried a signature and did not carry one, which is a claim about the bytes a reader is owed.",
    record: member(
      member(baseRecord(), 'original', 'signatureEmbedded', false),
      'original',
      'signature',
      { presence: 'not-taken-in', reason: 'the signature was served and not put in the record' },
    ),
    read: PINNED,
    stage: 'layout',
    code: 'CAPTURE_SIGNATURE_NOT_CARRIED',
  },
  {
    name: 'signature-carried-while-denying-one',
    note: "A record stating that the source signed nothing while carrying a signature slot with bytes in it. The two members contradict each other about the document's own contents, and a reader cannot weigh a claim about a signature made by a record that denies there is one.",
    record: member(
      member(baseRecord(), 'original', 'signedBySource', false),
      'original',
      'signature',
      held(DETACHED_SIGNATURE),
    ),
    read: PINNED,
    stage: 'layout',
    code: 'NOT_CAPTURE_RECORD',
  },
  {
    name: 'callers-pin-for-this-kid-is-another-key',
    note: "The honest record, read by a caller that pins a whole live key of this suite under the kid the header names. The kid resolves and the signature does not hold under what it resolves to, and the refusal comes from the format's verifier rather than from this reader: a pin that disagrees is a deployment that rotated and a caller that did not notice.",
    record: baseRecord(),
    read: { policy: { keys: { [KID_HEX]: toBase64Url(OTHER.publicKey) } }, anchors: PINNED.anchors, atMillis: AT_MILLIS },
    stage: 'reading',
    code: 'KID_MISMATCH',
  },
  {
    name: 'receipt-outside-the-callers-window',
    note: "The honest record read four thousand seconds later than the document it appraises, by a caller that named no window and so runs the shipped three hundred seconds. The bytes are the same bytes and their digest still holds: what refused is the caller's clock against the record's, which is the half of a verdict a port cannot borrow from the document.",
    record: baseRecord(),
    read: { policy: PINNED.policy, anchors: PINNED.anchors, atMillis: (FIXED_IAT + 4_000) * 1_000 },
    stage: 'reading',
    code: 'STALE_RECEIPT',
  },
  {
    name: 'root-that-is-none-of-the-callers',
    note: "A record relying on a root while the caller has pinned different bytes under the same family. The reader compares the stated digest against the caller's own pinned roots and against nothing else, so a root out of a library default or out of another deployment is refused here, and the refusal says which digests it was handed.",
    record: baseRecord(),
    read: { policy: PINNED.policy, anchors: { intelSgxRoots: [toBase64Url(ANOTHER_ROOT)] }, atMillis: AT_MILLIS },
    stage: 'reading',
    code: 'EVIDENCE_VERIFICATION_FAILED',
  },
];

interface Observed {
  readonly outcome: string;
  readonly message: string;
}

/** The code a step answered with, or `ok` where it answered by handing something back. */
function answeredBy(run: () => unknown): Observed {
  try {
    run();
    return { outcome: 'ok', message: '' };
  } catch (err) {
    if (err instanceof SdkError || err instanceof ReceiptError) return { outcome: err.code, message: err.message };
    throw new Error(`the shipped reader answered with something no registry declares: ${String(err)}`);
  }
}

/**
 * What the two published steps answered for one case, and the verdict when both took it.
 *
 * `assessCapture` parses, so a document the layout refuses never reaches a reading at all and its assess answer is
 * the parse answer. `layoutRefused` says which of the two the row\'s code and sentence come out of, so a refusal
 * published as a layout refusal carries the parse\'s own sentence rather than a code read off a step that ran none.
 */
function outcomeOf(one: Case): {
  readonly parse: Observed;
  readonly assess: Observed;
  readonly verdict: CaptureVerdict | null;
  readonly layoutRefused: boolean;
} {
  const parse = answeredBy(() => parseCaptureRecord(one.record));
  if (parse.outcome !== 'ok') {
    return { parse, assess: parse, verdict: null, layoutRefused: true };
  }
  const assess = answeredBy(() => assessCapture(paramsFor(one.read, one.record)));
  return {
    parse,
    assess,
    verdict: assess.outcome === 'ok' ? assessCapture(paramsFor(one.read, one.record)) : null,
    layoutRefused: false,
  };
}

/** The published row: the record, the call it was read with, and what the reader answered with. */
function published(one: Case, verdict: CaptureVerdict): Record<string, unknown> {
  return {
    name: one.name,
    note: one.note,
    record: one.record,
    read: one.read,
    status: verdict.status,
    stated: verdict.stated,
    repeated: {
      sha256: verdict.repeated.sha256,
      signatureVerifiedWithOwnPins: verdict.repeated.signatureVerifiedWithOwnPins,
      signingKid: verdict.repeated.signingKid,
      rootsMatched: verdict.repeated.rootsMatched,
    },
    absences: verdict.absences,
    qualifications: verdict.qualifications,
    recordKey: captureRecordKey(parseCaptureRecord(one.record)),
  };
}

function publishedRefusal(one: Case, seen: ReturnType<typeof outcomeOf>): Record<string, unknown> {
  const answered = seen.layoutRefused ? seen.parse : seen.assess;
  return {
    name: one.name,
    note: one.note,
    record: one.record,
    read: one.read,
    stage: seen.layoutRefused ? 'layout' : 'reading',
    code: answered.outcome,
    message: answered.message,
  };
}

function main(): void {
  // The bytes this suite states as its original are the document the receipt suite seals and verifies, and a
  // capture of anything else would be a capture of a stand-in this repository does not stand behind.
  const committed = new Uint8Array(readFileSync(join(DATA, 'receipts', 'receipt-valid-v1.cbor')));
  if (!equalBytes(committed, ORIGINAL)) {
    throw new Error('the receipt this suite captures is not the byte-for-byte document data/receipts publishes');
  }
  // The published prose names the rows that state bytes other than that document's, so the set is measured here
  // rather than remembered: a row that began to state other bytes without saying which would publish a file
  // describing an original this suite does not hold and a sentence about one it does.
  const otherBytes = [...CASES, ...REFUSALS]
    .filter((one) => (one.record['original'] as Record<string, unknown>)['bytes'] !== toBase64Url(committed))
    .map((one) => one.name)
    .sort();
  const namedApart = [
    'manifest-original-claiming-no-signature',
    'one-bit-changed-inside-the-original',
    'reserialized-envelope-against-the-stated-digest',
    'reserialized-envelope-stated-as-its-own-original',
  ].sort();
  if (otherBytes.join(', ') !== namedApart.join(', ')) {
    throw new Error(
      `${otherBytes.join(', ')} state an original that is not the committed receipt, and the prose names ${namedApart.join(', ')}`,
    );
  }
  // The key is the one `data/keys/receipt-key-v1.json` publishes, so the pin a row states is a pin a port can
  // build out of a file this package already ships rather than a second identity invented for these vectors.
  const publishedKey = JSON.parse(readFileSync(join(DATA, 'keys', 'receipt-key-v1.json'), 'utf8')) as {
    publicKey: string;
    kid: string;
  };
  if (publishedKey.kid !== KID_HEX || publishedKey.publicKey !== toHex(KEY.publicKey)) {
    throw new Error("the capture suite's key is not the receipt fixture key it states it is");
  }
  // The manifest a held slot carries is a deployment manifest, not a blob with a digest beside it.
  if (parseManifest(JSON.parse(new TextDecoder().decode(MANIFEST_BYTES)) as unknown).keys[0]?.kid !== KID_HEX) {
    throw new Error('the manifest a held slot states is not read as a manifest by the reader that reads them');
  }
  // A re-framed document has to stay one structure and become different bytes, or the pair of rows built on it
  // states a fault no reader can reach.
  if (equalBytes(RESERIALIZED, ORIGINAL)) {
    throw new Error('the re-framed envelope is the bytes it was made from, so it states no purported equivalent');
  }
  const honestKey = captureRecordKey(parseCaptureRecord(baseRecord()));
  const reframedKey = captureRecordKey(parseCaptureRecord(withOriginalBytes(baseRecord(), RESERIALIZED, true)));
  if (honestKey === reframedKey) {
    throw new Error('a record of the re-framed bytes keys as the record of the original ones');
  }
  // The address bound is the figure the rows straddle, so both sides of it are measured here rather than quoted.
  for (const bytes of [REQUEST_BOUND_BYTES, REQUEST_BOUND_BYTES + 1]) {
    if (new TextEncoder().encode(requestAt(bytes)).length !== bytes) {
      throw new Error(`the address built to be ${String(bytes)} bytes is not ${String(bytes)} bytes`);
    }
  }

  const rows: Record<string, unknown>[] = [];
  const refusals: Record<string, unknown>[] = [];
  for (const one of [...CASES, ...REFUSALS]) {
    const seen = outcomeOf(one);
    if (one.status !== undefined && (one.code !== undefined || one.stage !== undefined)) {
      throw new Error(`${one.name}: states a status and a refusal, which are two answers to one question`);
    }
    if (one.status === undefined && one.code === undefined) {
      throw new Error(`${one.name}: states neither a status nor a code, so nothing is required of the reader`);
    }
    if (one.status !== undefined) {
      const verdict = seen.verdict;
      if (verdict === null) {
        throw new Error(`${one.name}: the reader refused a document this case states as taken (${seen.parse.outcome})`);
      }
      if (verdict.status !== one.status) {
        throw new Error(`${one.name}: the reader answers ${verdict.status}, not the ${one.status} this case states`);
      }
      // The stored bytes reach the caller as the record holds them, and the digest the verdict recomputes is the
      // digest the record states: the two halves of the one claim a capture is built on.
      const stated = (one.record['original'] as Record<string, unknown>)['bytes'] as string;
      if (!equalBytes(verdict.repeated.originalBytes, fromBase64Url(stated))) {
        throw new Error(`${one.name}: the reader handed back bytes other than the ones the record holds`);
      }
      if (verdict.stated.sha256 !== verdict.repeated.sha256) {
        throw new Error(`${one.name}: the two halves of the verdict disagree about one digest`);
      }
      rows.push(published(one, verdict));
      continue;
    }
    if (one.stage === undefined) throw new Error(`${one.name}: a refusal that states no step`);
    if (seen.verdict !== null) throw new Error(`${one.name}: the reader took a document this case states as refused`);
    if (one.stage === 'layout' && !seen.layoutRefused) {
      throw new Error(`${one.name}: the layout took a document this case states it refuses`);
    }
    if (one.stage === 'reading' && seen.layoutRefused) {
      throw new Error(`${one.name}: the layout refused a document this case states the reading refuses (${seen.parse.outcome})`);
    }
    const answered = seen.layoutRefused ? seen.parse : seen.assess;
    if (answered.outcome !== one.code) {
      throw new Error(`${one.name}: the reader answers ${answered.outcome}, not the ${one.code} this case states`);
    }
    refusals.push(publishedRefusal(one, seen));
  }

  const names = [...rows, ...refusals].map((one) => String(one['name']));
  if (new Set(names).size !== names.length) throw new Error('two cases of this suite share a name');
  // One refusal per fact a held collateral slot owes, which is the figure the published prose and this file quote.
  const missingMemberRows = refusals.filter((one) => String(one['name']).startsWith('held-collateral-stating-no-'));
  if (missingMemberRows.length !== OBSERVATION_MEMBERS.length) {
    throw new Error(
      `${String(missingMemberRows.length)} rows state a collateral member missing and the layout asks ${String(OBSERVATION_MEMBERS.length)}`,
    );
  }
  if (rows.length < 8) throw new Error(`${String(rows.length)} accepted rows, and the verdicts a reader returns are more than that`);
  if (refusals.length < 16) throw new Error(`${String(refusals.length)} refusals, and the layout names more faults than that`);

  writeFileSync(
    join(DATA, 'capture-v1.json'),
    `${JSON.stringify(
      {
        version: 1,
        description:
          'Capture records and the answer the published reader gives them: one evidence document\'s exact bytes as they arrived, the context stated beside them, and the refusals in between. Every row states one record, the caller\'s own pins and clock beside it, and an answer that is what `parseCaptureRecord` and `assessCapture` of `@ashaveri/sdk` returned when this file was written. The accepted rows carry the verdict the reader handed back with its two halves stated apart, what the record claims it held and what this reader established for itself. The refused rows carry the code, the sentence, and which of the two published steps gave them. The four shapes a reader is meant to be able to replay out of published bytes are a document re-framed by a second encoder, refused as bytes rather than accepted as an equivalent; a context member left unmentioned rather than declared absent; a digest that is not the digest of the bytes beside it; and an absence stated as a statement, which a row that leaves the member out shows is not the same document.',
        layout: {
          record:
            'packages/sdk/schemas/capture-v1.schema.json, published as https://ashaveri.com/schemas/capture-v1.json, which is what a collector outside this repository builds a writer against and the half of the layout that binds what a document is made of',
          prose: 'docs/capture-v1.md',
          reader:
            'parseCaptureRecord in @ashaveri/sdk, which is the layout, and assessCapture, which parses and then runs the reading: every held slot\'s digest recomputed, the signature leg over the stored bytes under the caller\'s own pin, the stated roots against the caller\'s own pins, and the two clocks',
          entryPoints:
            '`stage` on a refused row is `layout` where `parseCaptureRecord` refused the document, which `assessCapture` then refuses with the same code because it parses first, and `reading` where the layout took the bytes and the answer came from what the reading runs over them: a held slot\'s digest, length and spelling recomputed, the signature leg over the stored bytes, the pinned roots, or the clock. A conforming reader owes the same code at the same step; its sentence may differ, and the published message is what this one said.',
          verdictMeaning:
            '`status` is what `assessCapture` returned: `repeated` where every leg the record invites ran against this caller\'s own pins, `qualified` where everything that could run passed and something the record explains is missing, and `unassessed` where a leg could not run. `unassessed` is a refusal to conclude and never a soft pass. `stated` is the record\'s claim about the bytes it held, and `repeated` is what this reader established: the digest it computed over them, whether the signature leg ran to completion under a key out of the caller\'s policy, the kid it resolved, and which families\' pinned bytes matched what the record relied on. `recordKey` is what `captureRecordKey` answers for the parsed record, a digest of its canonical JSON, so two records that say the same thing are one key and a record that disagrees by one re-encoding is another. The halves are published apart because a verdict carrying one word would let the record\'s claim be read as the reader\'s finding.',
          readFields:
            '`read.policy` is the caller\'s own pinning policy: `keys` maps the hex kid a header names to the public half pinned under it, a window named there is the window this reader runs, and one named nowhere is the shipped default of 300 seconds for a receipt and 900 for evidence. `read.anchors` is the caller\'s own pinned vendor roots, unpadded base64url, by family; nothing is substituted for them, and a bundled library default is a vendor\'s choice rather than this caller\'s pin. `read.atMillis` is the clock, fixed, so a row\'s answer does not move with the day it is read on. A row stating no `policy` and no `anchors` is the call that handed nothing.',
          byteRule:
            'every byte string inside a record is unpadded base64url in the one spelling this reader\'s own writer reproduces, and its digest and length are recomputed over what decodes: an original\'s at the layout\'s own edge, and every held slot\'s where the reading runs over them. Four rows state what that buys. An issuer-chain header in the other spelling that decodes to it is refused by the layout, and a detached signature written the same way is refused by the reading. A COSE_Sign1 whose four elements are untouched and whose framing a second encoder wrote is refused where the record still states the digest of the document the source produced, and those same bytes stated as their own original are refused by the format\'s verifier: a capture whose bytes passed through an encoder is a capture of that encoder\'s output.',
          absenceRule:
            'every piece of context a record may hold states which of three things became of it: held, never produced by the source, or not taken in. The last two name a reason and carry no bytes, and both are statements; a context member that is simply not mentioned is refused, because a reader cannot tell a record that said nothing from one whose thing never existed. `absences` on an accepted row carries the slot, the state and the reason the record gave, and `not-taken-in` reaches `unassessed` where `absent-at-source` reaches `qualified`.',
          collateralRule:
            'a held collateral slot states the eight facts about the answer its bytes are, and no other slot owes them. Eight rows state one of them missing and each refusal names which; two more state the chain\'s two halves apart from each other, one states a chain digest that is not the digest of the header beside it, and one states the header in a second spelling. A row states an identity of `null` as an acceptance and a row refuses an address of one byte more than a reference carries, which is the pair the bound is measured by.',
          originals:
            'the bytes every row states as its original are `data/receipts/receipt-valid-v1.cbor`: the receipt `issueReceipt` writes for the fixture payload under the key `data/keys/receipt-key-v1.json` publishes. Four rows name other bytes and say which: one states the deployment manifest as its original, one states that receipt with one bit changed inside it, and the pair beside it states one envelope of that receipt with its four elements untouched and its framing written by a second encoder. The generator stops unless the receipt this suite captures is byte for byte the document data/receipts publishes, so this file captures evidence the repository already seals rather than a stand-in for it, and the manifest a held slot carries is read by `parseManifest`, which the generator asks.',
          keyMaterial: [
            {
              id: 'receipt-fixture-key',
              kidHex: KID_HEX,
              publicKeyHex: toHex(KEY.publicKey),
              publicKeyBase64Url: toBase64Url(KEY.publicKey),
              file: 'packages/fixtures/data/keys/receipt-key-v1.json',
              role: 'the key the captured receipt is signed by, and the pin every row that reaches `repeated` names for that kid',
            },
            {
              id: 'another-pinned-key',
              kidHex: toHex(OTHER.kid),
              publicKeyHex: toHex(OTHER.publicKey),
              publicKeyBase64Url: toBase64Url(OTHER.publicKey),
              role: 'a whole live key of this suite whose private half signs nothing here, stated by the row that refuses a caller whose pin for this kid is not the key the header names',
            },
          ],
          keyNote:
            'test-only, published so a port can produce these documents and these pins itself rather than only checking them, and protecting nothing. A capture record is signed by nobody, so a key of this suite decides what a reader hands the verifier and never what a record states.',
          clocks: `one set of instants for all of it: the captured receipt is issued at ${String(FIXED_IAT)}, the bytes are taken in ${String(ACQUIRED_AT - FIXED_IAT)} seconds later, the appraisal runs ${String(APPRAISED_AT - ACQUIRED_AT)} seconds behind that, and the clock a caller hands is ${String(AT_MILLIS)} milliseconds. The rows that move one of them say which and by how far, and the window a refusal turns on is stated as the caller's clock rather than as a byte.`,
          encodings:
            'byte strings inside a record unpadded base64url, digests and kids lowercase hex, instants unix seconds and the clock a caller hands milliseconds, and the record itself published inline as the JSON object the reader is handed rather than as its bytes, because a capture record is read as a document and its claim about bytes lives inside its members',
          codes: [...new Set(refusals.map((one) => String(one['code'])))].sort(),
          notChecked:
            'a capture record states which bytes were taken in and which context came with them. Nothing here shows that a source produced them, that a vendor chain reaches a root, that a pinned key belongs to anybody, or that the answer a collateral slot holds is still served: the vendor walk belongs to `verifyCompletionEvidence`, which takes no collateral input, and the row stating a `device-evidence` original is this reader naming the leg it did not run.',
        },
        vectors: rows,
        refusals,
      },
      null,
      2,
    )}\n`,
  );

  for (const one of rows) console.log(`${String(one['name'])}: ${String(one['status'])}`);
  for (const one of refusals) console.log(`${String(one['name'])}: ${String(one['stage'])} ${String(one['code'])}`);
}

main();
