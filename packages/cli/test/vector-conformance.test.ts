import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  POP_SCHEME,
  decodeCoseSign1,
  decodeEpochInventory,
  decodePack,
  decodeRedaction,
  decodeSealedDeploymentManifest,
  encodeCanonical,
  extractMarkedRegion,
  isSealedDeploymentManifest,
  parsePopAuthorization,
  popSigningString,
  ReceiptError,
  signPopAuthorization,
  verifyEpochInventory,
  verifyExport,
  verifyPack,
  verifyPopSignature,
  verifyRedaction,
  verifySealedDeploymentManifest,
  type EpochInventoryVerifyOptions,
  type MarkingScheme,
} from '@ashaveri/receipt';
import {
  decodeReceipt,
  hashRequest,
  readDeploymentManifest,
  adjudicateReceiptEpoch,
  SdkError,
  verifyCompletionReceipt,
  type AshaveriPolicy,
  type ReadManifestResult,
} from '@ashaveri/sdk';
import { sha256 } from '@noble/hashes/sha2.js';
import { openFileReceiptStore, RECEIPT_STORE_FILE, StoreError, type ReceiptRecordKind } from '@ashaveri/signerd';

/**
 * The published vector suites, replayed through the paths a shipped client takes.
 *
 * `data/` states a verdict for its cases, and until now the suites other than the receipt fixtures
 * were read back by tests that checked a file against its own rule. This walks every suite and asks the
 * implementation that is shipped what it answers for each row: `verifyCompletionReceipt` for anything a
 * receipt decides, the proof-of-possession signer and parser for the wire-format rows, the store reader
 * for the chain images, `readDeploymentManifest` beside its `adjudicateReceiptEpoch` for the sealed
 * deployment manifest, `verifyPack` with `decodePack` underneath it for the evidence pack,
 * `verifyEpochInventory` with `decodeEpochInventory` underneath it for the inventory of a run of packs, and
 * `verifyRedaction`, which reads the pack through `verifyPack` and answers with `decodeRedaction` alone
 * for the structural half, for a redaction manifest and the pack it names. Where a row states a refusal, the
 * code it names is the code that has to
 * come back; where a row states acceptance, the same call has to accept it. A suite that only ever
 * passed would satisfy the first half and say nothing, so the near misses published here are what make
 * the second half mean something, and each of those rows is a small edit to bytes this repository
 * already publishes rather than noise a reader could not reproduce.
 *
 * Three other files drive some of this data and are not duplicated here:
 * `packages/fixtures/test/fixtures.test.ts` gives the receipt fixtures to the format decoder with no
 * policy, `packages/cli/test/verify-receipt.test.ts` gives them to the `verify-receipt` command as a
 * child process, and `packages/fixtures/test/chain-vectors.test.ts` and
 * `packages/fixtures/test/marking-vectors.test.ts` check the store reader's messages and the marking
 * rule's located span. What is added below is the client verdict for every suite, the marking rows read
 * through the marking check rather than only through the extraction rule, and the digest and
 * proof-of-possession refusals, which no other file reaches.
 *
 * Nothing here fetches. `globalThis.fetch` is replaced for the length of the run with a recorder that
 * refuses, and the last case asserts the recorder is empty, so "the suite resolves entirely from files
 * in this repository" is measured rather than claimed.
 */

const DATA = fileURLToPath(new URL('../../fixtures/data/', import.meta.url));

/** The instant the published receipts are issued at, in whole seconds, matching their `iat`. */
const CLOCK = 1_772_000_000;
/**
 * The same instant in milliseconds. `verifyCompletionReceipt` reads its clock in milliseconds and
 * divides it to seconds before the freshness windows run, so a caller that hands it `CLOCK` would be
 * handing it a 1970 reading and every policy-governed row would answer `STALE_RECEIPT`. The client
 * verifications below take this figure, never the seconds one.
 */
const CLOCK_MILLIS = CLOCK * 1_000;

interface ManifestEntry {
  readonly name: string;
  readonly path: string;
  readonly digestSha256: string;
  readonly expected: string;
  readonly note?: string;
  /**
   * The columns a row states about its own bytes. Every document this format states names a marking, and a marking can
   * only be checked against the response it was read out of, so the client path has to be handed the
   * bytes the row itself states rather than a guess from the document's version.
   */
  readonly keyless?: string;
  readonly v?: 1 | 2 | 3;
  readonly marking?: string;
  readonly contentType?: string;
  readonly response?: string;
  readonly responseBase64Url?: string;
  readonly responseByteLength?: number;
  /** The anchor the document carries, each slot one presence label with what that label selects. */
  readonly cva?: { col: { p: string; d?: string; r?: string }; val: { p: string; d?: string; r?: string } };
  /**
   * The verdict the client path gives this document under each posture `minAnchorSlotsHeld` can take, in
   * the order the suite publishes: no demand named, a demand of one held slot, a demand of both.
   */
  readonly handover?: { minAnchorSlotsHeld: number | null; verdict: string }[];
}

interface MarkingCase {
  readonly name: string;
  readonly shape: string;
  readonly sch: string;
  readonly responseBase64Url: string;
  readonly attestedRegionBase64Url: string;
  readonly dHex: string;
  readonly expected: string;
  readonly client: { readonly receiptBase64Url: string; readonly receiptSha256Hex: string };
}

interface DigestRefusal {
  readonly name: string;
  readonly heldVector: string;
  readonly claimedVector: string;
  readonly code: string;
  readonly receiptBase64Url: string;
  readonly receiptSha256Hex: string;
}

interface RequestRefusal extends DigestRefusal {
  readonly bodyBase64Url: string;
  readonly claimedReqHex: string;
}

interface ResponseRefusal extends DigestRefusal {
  readonly responseBase64Url: string;
  readonly claimedResHex: string;
}

interface PopRefusal {
  readonly name: string;
  readonly vector: string;
  readonly stage: string;
  readonly fields: {
    readonly ts: number;
    readonly nonce: string;
    readonly method: string;
    readonly target: string;
    readonly bodyBase64Url: string;
    readonly bodyDigestHex: string;
  };
  readonly signingString: string;
  readonly authorization: string;
  readonly code: string;
}

interface ChainRefusal {
  readonly name: string;
  readonly imageBase64Url: string;
  readonly imageByteLength: number;
  /**
   * The receipt kind the opening that gives this refusal writes. Absent means the receipt kind, which is
   * the layout every other image in this file is read under. A row states it wherever the refusal it
   * publishes is a disagreement between a file and a configuration rather than a fact about bytes, and
   * this replay has to open the image under the kind the row names or it is reading a different file.
   */
  readonly openedWith?: ReceiptRecordKind;
  readonly code: string;
  readonly message: string;
}

/** The three states a client reports about the bytes it was handed, plus whether it asked for one. */
interface SealedManifestAuthentication {
  readonly sealed: boolean;
  readonly authenticated: boolean;
  readonly kid: string | null;
  readonly demanded: boolean;
  readonly advisory: boolean;
}

/** One receipt's claim about its key and moment, and the answer a document's rotation history gives. */
interface EpochClaimRow {
  readonly claim: { kid: string; epoch: number; issuedAt: number };
  readonly ok: boolean;
  readonly code?: string;
  readonly basis?: 'windows' | 'current-epoch';
  readonly superseded?: boolean;
  readonly validFrom?: number | null;
  readonly validTo?: number | null;
}

/**
 * One case of the sealed-manifest suite: the bytes handed to a reader, the manifest signing keys it
 * designates, what the client answers, and what the envelope reader answers underneath that.
 */
interface ManifestVectorCase {
  readonly name: string;
  readonly note: string;
  readonly documentBase64Url: string;
  readonly documentByteLength: number;
  readonly read: { designates: { kid: string; publicKeyBase64Url: string }[] };
  readonly verdict: string;
  readonly seal: string;
  readonly authentication?: SealedManifestAuthentication;
  readonly parsed?: Record<string, unknown>;
  readonly dropped?: string[];
  readonly edited?: string;
  readonly reveal?: {
    contextString: string;
    externalAadBase64Url: string;
    protectedHeaderBase64Url: string;
    payloadBase64Url: string;
    payloadByteLength: number;
    payloadSha256Hex: string;
    signatureHex: string;
    sigStructureHex: string;
    headerLabels: { label: number; name: string; value: string | number }[];
  };
  readonly claims?: EpochClaimRow[];
}

interface ManifestVectorFile {
  readonly version: number;
  readonly description: string;
  readonly layout: {
    readonly codes: readonly string[];
    readonly keyMaterial: { id: string; seed: string; kidHex: string; publicKeyHex: string; publicKeyBase64Url: string; role: string }[];
  };
  readonly vectors: ManifestVectorCase[];
  readonly crossReading: { readonly cases: { name: string; documentBase64Url: string; expected: string }[] };
}

/** One case of the evidence pack suite: the bytes, the designation beside them, and the two answers. */
interface PackVectorCase {
  readonly name: string;
  readonly note: string;
  readonly documentBase64Url: string;
  readonly documentByteLength: number;
  readonly read: { pinned?: string; retained?: { kid: string; publicKeyBase64Url: string }[] };
  readonly verdict: string;
  readonly structural: string;
  readonly walk?: string[];
  readonly ordering?: { kind: string; from: string; to: string; fromIat: number; toIat: number }[];
  readonly span?: { from: number; to: number };
  readonly item?: string;
  readonly edited?: string;
}

interface PackVectorFile {
  readonly version: number;
  readonly description: string;
  readonly layout: {
    readonly contentType: string;
    readonly codes: readonly string[];
    readonly keyMaterial: { kidHex: string; publicKeyHex: string; publicKeyBase64Url: string; role: string }[];
    readonly records: { position: number; id: string; iat: number; prevHex: string; digestHex: string; receiptByteLength: number }[];
  };
  readonly vectors: PackVectorCase[];
  readonly crossReading: { readonly cases: { name: string; documentBase64Url: string; expected: string }[] };
}

/**
 * One case of the redaction manifest suite: the manifest, the pack handed beside it, the designation the
 * caller makes, and what each of the reader's two entry points answers. A row with no pack is the reader
 * that was handed one document of the pair.
 */
interface RedactionVectorCase {
  readonly name: string;
  readonly note: string;
  readonly documentBase64Url: string;
  readonly documentByteLength: number;
  readonly packOf?: string;
  readonly packEdited?: string;
  readonly packBase64Url?: string;
  readonly packByteLength?: number;
  readonly read: { pinned?: string; retained?: { kid: string; publicKeyBase64Url: string }[] };
  readonly verdict: string;
  readonly structural: string;
  readonly survivors?: string[];
  readonly reducedHex?: string;
  readonly originalHeadHex?: string;
  readonly item?: string;
  readonly edited?: string;
}

interface RedactionVectorFile {
  readonly version: number;
  readonly description: string;
  readonly layout: {
    readonly contentType: string;
    readonly codes: readonly string[];
    readonly keyMaterial: { kidHex: string; publicKeyHex: string; publicKeyBase64Url: string; role: string }[];
  };
  readonly vectors: RedactionVectorCase[];
  readonly crossReading: { readonly cases: { name: string; documentBase64Url: string; expected: string }[] };
}

/**
 * One case of the epoch inventory suite: a whole sealed inventory, the designation the caller hands beside
 * it, what each of the two shipped inventory readers answers for those bytes, the refusal sentence the
 * reader gave where there is one, and what it handed back where it accepted. A row stating no designation is
 * the call that named no key.
 */
interface EpochInventoryCase {
  readonly name: string;
  readonly note: string;
  readonly documentBase64Url: string;
  readonly documentByteLength: number;
  readonly read: { pinned?: string; retained?: Record<string, string>; presence?: string[] };
  readonly verdict: string;
  readonly structural: string;
  readonly message?: string;
  readonly readback?: {
    readonly runFiles: readonly string[];
    readonly statedFiles: readonly string[];
    readonly window: { from: number; to: number };
    readonly continuous: boolean;
    readonly breakFiles: readonly string[];
    readonly carried: boolean;
    readonly shortFiles: readonly string[];
  };
  readonly site?: string;
  readonly guard?: string;
  readonly edited?: string;
}

interface EpochInventoryVectorFile {
  readonly version: number;
  readonly description: string;
  readonly layout: {
    readonly contentType: string;
    readonly codes: readonly string[];
    readonly keyMaterial: { kidHex: string; publicKeyHex: string; publicKeyBase64Url: string; role: string }[];
  };
  readonly vectors: EpochInventoryCase[];
}

function json<T>(path: string): T {
  return JSON.parse(readFileSync(join(DATA, path), 'utf8')) as T;
}
const manifest = json<{ fixtures: ManifestEntry[] }>('manifest.json');
const marking = json<{ vectors: MarkingCase[] }>('marking-v1.json');
const requests = json<{ vectors: { name: string; bodyBase64Url: string; reqHex: string }[]; refusals: RequestRefusal[] }>(
  'req-v1.json',
);
const responses = json<{
  vectors: { name: string; responseBase64Url: string; resHex: string }[];
  refusals: ResponseRefusal[];
}>('res-v1.json');
const proofOfPossession = json<{
  scheme: string;
  key: { id: string; privateKeyHex: string; publicKeyHex: string };
  vectors: {
    name: string;
    fields: { ts: number; nonce: string; method: string; target: string; bodyBase64Url: string; bodyDigestHex: string };
    signingString: string;
    authorization: string;
  }[];
  refusals: PopRefusal[];
}>('pop-v1.json');
const chain = json<{ refusals: ChainRefusal[] }>('chain-v1.json');
const sealedManifests = json<ManifestVectorFile>('manifest-v1.json');
const packVectors = json<PackVectorFile>('pack-v1.json');
const redactionVectors = json<RedactionVectorFile>('redaction-v1.json');
const epochInventories = json<EpochInventoryVectorFile>('epoch-inventory-v1.json');

/** The receipt signing key the fixtures are issued under, as the published key file states it. */
const PUBLIC_KEY = new Uint8Array(Buffer.from(json<{ publicKey: string }>('keys/receipt-key-v1.json').publicKey, 'hex'));

const bytes = (base64url: string): Uint8Array => new Uint8Array(Buffer.from(base64url, 'base64url'));
const hex = (value: Uint8Array): string => Buffer.from(value).toString('hex');

/** What a call answered: `verify-ok`, or the code the shipped implementation threw. */
function verdictOf(run: () => unknown): string {
  try {
    run();
    return 'verify-ok';
  } catch (err) {
    // The SDK re-exports the format package's error class rather than wrapping it, so one `instanceof`
    // covers both, and anything uncoded is a fault in this file rather than a verdict to report.
    if (err instanceof SdkError || err instanceof ReceiptError) {
      return err.code as string;
    }
    throw err;
  }
}

/**
 * The client's own view of a receipt: its challenge and its two digests, read out of the document with
 * the shipped parser rather than copied from a sidecar, so a row cannot be checked against a claim the
 * bytes do not make. A document whose payload will not parse at all, which is what the measurement
 * fixture is, is handed the valid fixture's claims instead: it is refused before any of them are read.
 */
function claimsOf(receiptBytes: Uint8Array): { nonce: Uint8Array; req: Uint8Array; res: Uint8Array; version: number } {
  try {
    const payload = decodeReceipt(receiptBytes).payload;
    return { nonce: payload.nce, req: payload.req, res: payload.res, version: payload.v };
  } catch {
    const fallback = decodeReceipt(readFileSync(join(DATA, 'receipts/receipt-valid-v1.cbor'))).payload;
    return { nonce: fallback.nce, req: fallback.req, res: fallback.res, version: fallback.v };
  }
}

/**
 * The response bytes one receipt row states its document attests, or `undefined` where the row names
 * none. A row naming its response is a row the client path can be run over as a client runs it, with the
 * bytes it holds in hand, and a refusal row whose bytes are not the document's subject is read as before.
 */
function responseBytesOf(entry: ManifestEntry): Uint8Array | undefined {
  return entry.responseBase64Url === undefined ? undefined : bytes(entry.responseBase64Url);
}

/**
 * One receipt handed to the shipped client path the way a client hands it: the challenge it was asked to
 * answer, the two bodies it attests, the response bytes themselves, and the policy the row names beside
 * them. With no policy the two freshness windows do not run at all, which is how every row here has always
 * been read; a policy named for the anchor postures below pins the document's own issuer and nothing else,
 * so the windows run at their shipped defaults and the only question left open is the anchor's.
 */
/**
 * The manifest row a receipt's bytes are published under, found by the digest the row states. A client
 * holds a receipt and nothing else, so this is the only way from the document back to the response it
 * names, and the row is where that response is published.
 */
function manifestEntryFor(receiptBytes: Uint8Array): ManifestEntry | undefined {
  const digest = hex(sha256(receiptBytes));
  return manifest.fixtures.find((each) => each.digestSha256 === digest);
}

/**
 * The body the fixture envelope signs by default, read off the published row rather than restated here.
 * A receipt built by overriding one member and nothing else attests this response.
 */
const FIXTURE_RESPONSE_BYTES = bytes(
  manifest.fixtures.find((each) => each.name === 'receipt-valid-v1')?.responseBase64Url ?? '',
);

function clientVerdict(
  receiptBytes: Uint8Array,
  over: {
    requestHash?: Uint8Array;
    responseHash?: Uint8Array;
    responseBytes?: Uint8Array;
    policy?: AshaveriPolicy;
    nowMillis?: number;
  } = {},
): string {
  const claims = claimsOf(receiptBytes);
  // The response bytes are the row's own, not a guess keyed to which version the document claims: every
  // payload this format reads names a marking, and the client hashes what it was handed against both
  // `res` and `mk.d`. A row publishing no response is read with none, which is the case that owes a
  // refusal rather than an acceptance.
  const entry = manifestEntryFor(receiptBytes);
  const responseBytes = over.responseBytes ?? (entry === undefined ? new Uint8Array(0) : responseBytesOf(entry) ?? new Uint8Array(0));
  return verdictOf(() =>
    verifyCompletionReceipt({
      receiptBytes,
      nonce: claims.nonce,
      requestHash: over.requestHash ?? claims.req,
      responseHash: over.responseHash ?? claims.res,
      responseBytes,
      verifyKey: PUBLIC_KEY,
      ...(over.policy === undefined ? {} : { policy: over.policy }),
      nowMillis: over.nowMillis ?? CLOCK_MILLIS,
    }),
  );
}

const tempDir = mkdtempSync(join(tmpdir(), 'ashaveri-vector-conformance-'));

afterAll(() => {
  rmSync(tempDir, { recursive: true, force: true });
});

/** Every URL this run reached for, which has to stay empty. */
const reached: string[] = [];
const realFetch = globalThis.fetch;

beforeAll(() => {
  globalThis.fetch = (async (input: Parameters<typeof fetch>[0]) => {
    reached.push(typeof input === 'string' ? input : input instanceof URL ? input.href : '<request>');
    throw new Error('the vector conformance harness resolves entirely from files in the repository');
  }) as unknown as typeof fetch;
});

afterAll(() => {
  globalThis.fetch = realFetch;
});

describe('the published receipt fixtures through the client path', () => {
  it('states a verdict for every entry and gives each entry that verdict', () => {
    expect(manifest.fixtures.length).toBeGreaterThanOrEqual(5);
    const observed = manifest.fixtures.map((entry) => {
      expect(entry.expected, `${entry.name} states no verdict`).toMatch(/^[A-Za-z0-9_-]+$/u);
      const receiptBytes = new Uint8Array(readFileSync(join(DATA, entry.path)));
      return `${entry.name}: ${clientVerdict(receiptBytes, { responseBytes: responseBytesOf(entry) })}`;
    });
    expect(observed).toEqual(manifest.fixtures.map((entry) => `${entry.name}: ${entry.expected}`));
  });

  it('reads every row that states its own answer without a key', () => {
    // The same bytes, the same shipped parser, no key in the call: a row whose refusal needs a signature
    // checked first would be a refusal about authenticity and not about the document.
    const stated = manifest.fixtures.filter((entry) => entry.keyless !== undefined);
    expect(stated.length).toBeGreaterThan(0);
    for (const entry of stated) {
      const receiptBytes = new Uint8Array(readFileSync(join(DATA, entry.path)));
      const observed = verdictOf(() => decodeReceipt(receiptBytes));
      expect(`${entry.name}: ${observed}`).toBe(`${entry.name}: ${entry.keyless}`);
    }
  });

  it('refuses the two broken documents for the two reasons their rows name', () => {
    // The near miss of each is a single field: one flipped bit in the signature bytes, and one
    // measurement of the width a different environment kind reports. Both are signed by the published
    // key, so neither refusal is about authenticity, and the codes a reader owes are different.
    const tampered = manifest.fixtures.find((entry) => entry.name === 'receipt-tampered-v1');
    const mismatched = manifest.fixtures.find((entry) => entry.name === 'receipt-meas-mismatch-v1');
    expect([tampered?.expected, mismatched?.expected]).toEqual(['INVALID_SIGNATURE', 'BAD_PAYLOAD']);
    const intact = new Uint8Array(readFileSync(join(DATA, 'receipts/receipt-valid-v1.cbor')));
    const flipped = new Uint8Array(intact);
    flipped[flipped.length - 1] = (flipped[flipped.length - 1] ?? 0) ^ 0x01;
    expect(hex(hashRequest(flipped))).not.toBe(hex(hashRequest(intact)));
    expect(clientVerdict(flipped)).toBe('INVALID_SIGNATURE');
    expect(clientVerdict(new Uint8Array(readFileSync(join(DATA, 'receipts/receipt-meas-mismatch-v1.cbor'))))).toBe(
      'BAD_PAYLOAD',
    );
  });

  it('accepts the marked fixture over the response bytes its own row states', () => {
    const marked = manifest.fixtures.find((entry) => entry.name === 'receipt-marked-v1');
    expect(marked?.expected).toBe('verify-ok');
    expect(clientVerdict(new Uint8Array(readFileSync(join(DATA, 'receipts/receipt-marked-v1.cbor'))))).toBe('verify-ok');
  });
});

/**
 * The demand a policy states about an anchor, weighed over the published receipts.
 *
 * Each row that carries an anchor the client reaches states what the shipped client answers for it under
 * each posture `minAnchorSlotsHeld` can take, and this runs those answers rather than reading them: the
 * posture is spelled as the policy field's own name beside the number an operator would write, pinned to
 * the issuer the document itself carries, and the verdict is the code the client threw or `verify-ok`.
 * Reading the column without this would leave it a claim about this repository's arithmetic, which is the
 * one thing a published column cannot be.
 *
 * The property the rows are arranged to show is the field's own: the posture naming no demand answers
 * what the row already states with no policy in the call at all. A policy that pins an issuer is not that
 * absence, and the rows say which is which beside it.
 */
describe('the anchor demand a policy states, through the client path', () => {
  /**
   * One posture, spelled as an operator spells it: the document's own issuer pinned, the demand named or
   * left out, and nothing else, so the only thing the three readings differ in is the anchor.
   */
  function policyOver(issuer: string, demand: number | null): AshaveriPolicy {
    return demand === null ? { issuers: [issuer] } : { issuers: [issuer], minAnchorSlotsHeld: demand };
  }

  // A policy runs the two freshness windows and no policy runs neither, so every reading below is
  // taken at the instant the published receipts are issued at, in milliseconds, which is the unit
  // `verifyCompletionReceipt` reads its clock in. That figure is `CLOCK_MILLIS` at module scope; the
  // seconds figure `CLOCK` is those receipts' `iat` and reaches the verifier only through it.
  const postureOrder = [null, 1, 2];

  it('gives every row that states its readings the verdict it states under each posture', () => {
    const stated = manifest.fixtures.filter((entry) => entry.handover !== undefined);
    expect(stated.length).toBeGreaterThanOrEqual(6);
    for (const entry of stated) {
      const readings = entry.handover ?? [];
      expect(readings.map((one) => one.minAnchorSlotsHeld), entry.name).toEqual(postureOrder);
      const receiptBytes = new Uint8Array(readFileSync(join(DATA, entry.path)));
      const issuer = decodeReceipt(receiptBytes).payload.iss;
      for (const reading of readings) {
        expect(
          clientVerdict(receiptBytes, {
            responseBytes: responseBytesOf(entry),
            policy: policyOver(issuer, reading.minAnchorSlotsHeld),
            nowMillis: CLOCK_MILLIS,
          }),
          `${entry.name} under demand ${String(reading.minAnchorSlotsHeld)}`,
        ).toBe(reading.verdict);
      }
      // The reading beside `null` is the row's own answer, stated twice on purpose: once with no policy in
      // the call at all, which is how this suite has always read these bytes, and once under a policy that
      // pins the issuer and names nothing about the anchor. Those two agreeing is what the field promises.
      expect(readings[0]?.verdict, entry.name).toBe(entry.expected);
    }
  });

  it('refuses with the code its row names, and weighs each presence label in each of the two slots', () => {
    const stated = manifest.fixtures.filter((entry) => entry.handover !== undefined);
    // Three published documents refuse at least one posture, so the column is not a suite of acceptances
    // with one number attached, and the refusal it states is the code the register carries a row for.
    const refusing = stated.filter((entry) => entry.handover?.some((one) => one.verdict === 'ANCHOR_SLOT_NOT_HELD'));
    expect(refusing.length).toBeGreaterThanOrEqual(3);
    for (const entry of refusing) {
      const receiptBytes = new Uint8Array(readFileSync(join(DATA, entry.path)));
      const issuer = decodeReceipt(receiptBytes).payload.iss;
      for (const reading of entry.handover ?? []) {
        if (reading.verdict !== 'ANCHOR_SLOT_NOT_HELD') continue;
        expect(
          clientVerdict(receiptBytes, {
            responseBytes: responseBytesOf(entry),
            policy: policyOver(issuer, reading.minAnchorSlotsHeld),
            nowMillis: CLOCK_MILLIS,
          }),
          `${entry.name} under demand ${String(reading.minAnchorSlotsHeld)}`,
        ).toBe('ANCHOR_SLOT_NOT_HELD');
      }
    }
    // Both absences answer a demand alike, and which of the two slots carried them answers the same: the
    // count is what decides, and the three labels each state themselves in both halves of an anchor here.
    const labels = (slot: 'col' | 'val'): string[] => [
      ...new Set(stated.map((entry) => entry.cva?.[slot]?.p).filter((one): one is string => one !== undefined)),
    ].sort();
    expect(labels('col'), 'presence labels published in the collateral slot').toEqual([
      'absent-at-source',
      'held',
      'not-taken-in',
    ]);
    expect(labels('val'), 'presence labels published in the validity slot').toEqual([
      'absent-at-source',
      'held',
      'not-taken-in',
    ]);
    // And the message a refusal carries names which label reached it, off the bytes rather than off this
    // file, since a sentence that cannot say which half of the anchor was missing says nothing an operator
    // can act on. Same call as the one above, read for its sentence instead of its code.
    const gapRow = stated.find((entry) => entry.name === 'receipt-buffered-v1');
    expect(gapRow, 'the published anchor with one slot absent at its source is not in the suite').toBeDefined();
    if (gapRow === undefined) return;
    const receiptBytes = new Uint8Array(readFileSync(join(DATA, gapRow.path)));
    const payload = decodeReceipt(receiptBytes).payload;
    let message = '';
    let code = 'verify-ok';
    try {
      verifyCompletionReceipt({
        receiptBytes,
        nonce: payload.nce,
        requestHash: payload.req,
        responseHash: payload.res,
        responseBytes: responseBytesOf(gapRow) ?? new Uint8Array(0),
        verifyKey: PUBLIC_KEY,
        policy: policyOver(payload.iss, 2),
        nowMillis: CLOCK_MILLIS,
      });
    } catch (err) {
      message = err instanceof Error ? err.message : String(err);
      code = err instanceof SdkError || err instanceof ReceiptError ? String(err.code) : 'uncoded';
    }
    expect(code, gapRow.name).toBe('ANCHOR_SLOT_NOT_HELD');
    expect(message).toContain('absent-at-source');
    expect(message).toContain('the validity slot');
    // The held half is not swept into the gap list, which is the one way this sentence could state a count
    // and a list that disagree, and the count and the demand are both in it.
    expect(message).not.toContain('the collateral slot');
    expect(message).toContain('1 of 2 slots held');
    expect(message).toContain('demands 2');
  });

  it('states its readings on every row whose anchor the client reaches', () => {
    // The roster and the rows, read off the rows: a document this suite publishes an accepted answer for
    // carries an anchor the policy stage reads, so a row added without its three readings is caught here
    // rather than published as a hole nobody noticed in the column.
    const owed = manifest.fixtures.filter((entry) => entry.cva !== undefined && entry.expected === 'verify-ok');
    expect(owed.length).toBeGreaterThanOrEqual(7);
    for (const entry of owed) {
      expect(entry.handover, `${entry.name} carries an anchor the client accepts and states no reading`).toEqual(
        expect.arrayContaining(postureOrder.map((one) => expect.objectContaining({ minAnchorSlotsHeld: one }))),
      );
    }
    // And a row stating none of the three is a row the demand cannot reach for one of two stated reasons:
    // the format reader answers it before any policy is weighed, or its document names no anchor at all and
    // so makes no presence claim to weigh. Both excuses are read off the row, not from a list kept here.
    for (const entry of manifest.fixtures.filter((each) => each.handover === undefined)) {
      const unreachable = entry.expected !== 'verify-ok' || entry.cva === undefined;
      expect(unreachable, `${entry.name} carries an anchor the client accepts and states no readings`).toBe(true);
    }
  });
});

describe('the marked-region vectors through the marking check', () => {
  it('carries a signed receipt per case, issued under the published key', () => {
    for (const one of marking.vectors) {
      const decoded = decodeReceipt(bytes(one.client.receiptBase64Url));
      expect(decoded.payload.v, `${one.name} is not a v1 document`).toBe(1);
      expect(hex(hashRequest(bytes(one.responseBase64Url))), `${one.name} response digest`).toBe(
        hex(decoded.payload.res),
      );
      expect(hex(decoded.payload.mk.d), `${one.name} attested region digest`).toBe(one.dHex);
      expect(hex(hashRequest(bytes(one.attestedRegionBase64Url))), `${one.name} attested span`).toBe(one.dHex);
      expect(Buffer.from(one.client.receiptSha256Hex, 'hex')).toHaveLength(32);
    }
  });

  it('gives the buffered case the same document the receipt fixture publishes', () => {
    // Two generators, one envelope: the marked fixture is the marked case, byte for byte. A drift
    // between the response the receipt suite signs and the response this suite publishes would make
    // the two files disagree here rather than in a port that reads both.
    const embedded = bytes(
      marking.vectors.find((each) => each.name === 'buffered-member')?.client.receiptBase64Url ?? '',
    );
    const committed = new Uint8Array(readFileSync(join(DATA, 'receipts/receipt-marked-v1.cbor')));
    expect(hex(hashRequest(embedded))).toBe(hex(hashRequest(committed)));
    expect(embedded).toEqual(committed);
  });

  it('answers each case with the verdict the row states', () => {
    expect(marking.vectors.length).toBeGreaterThanOrEqual(9);
    const observed = marking.vectors.map((one) => {
      expect(one.expected, `${one.name} states no verdict`).toMatch(/^[A-Za-z0-9_-]+$/u);
      return `${one.name}: ${clientVerdict(bytes(one.client.receiptBase64Url), {
        responseBytes: bytes(one.responseBase64Url),
      })}`;
    });
    expect(observed).toEqual(marking.vectors.map((one) => `${one.name}: ${one.expected}`));
  });

  it('reaches MARK_MISMATCH for the responses that carry the wrong mark', () => {
    // The gap this closes: `MARK_MISMATCH` needs bytes that hash to the digest the receipt attests while
    // holding a region that does not hash to the one the receipt names, because the response digest is
    // checked first. Six published rows now do that. Each one is checked at the digest first, so the
    // code below cannot be the refusal the response check raises with, which is the only way to tell a
    // marking refusal apart from a shadowed one.
    const refused = marking.vectors.filter((one) => one.expected === 'MARK_MISMATCH');
    expect(refused.length).toBeGreaterThanOrEqual(6);
    for (const one of refused) {
      const receipt = bytes(one.client.receiptBase64Url);
      const responseBytes = bytes(one.responseBase64Url);
      expect(hex(hashRequest(responseBytes)), `${one.name} response digest`).toBe(
        hex(decodeReceipt(receipt).payload.res),
      );
      expect(clientVerdict(receipt, { responseBytes }), one.name).toBe('MARK_MISMATCH');
      // The refusal is about the mark either way, and the two ways are worth telling apart: a response
      // that locates no single region, and one that locates a whole region hashing to something else.
      let located: Uint8Array | null;
      try {
        located = extractMarkedRegion(one.sch as MarkingScheme, responseBytes);
      } catch (err) {
        if (!(err instanceof ReceiptError)) throw err;
        expect(err.code, `${one.name} extraction refusal`).toBe('MARK_MISMATCH');
        located = null;
      }
      if (located !== null) {
        expect(hex(hashRequest(located)), `${one.name} located span digest`).not.toBe(one.dHex);
      }
    }
  });
});

describe('the request and response digest refusals through the client path', () => {
  const vectorsByName = new Map(requests.vectors.map((each) => [each.name, each]));

  it('states a near miss rather than a mismatch, for each request row', () => {
    for (const refusal of requests.refusals) {
      const held = vectorsByName.get(refusal.heldVector);
      const claimed = vectorsByName.get(refusal.claimedVector);
      expect(held, `${refusal.heldVector} is not a published vector`).toBeDefined();
      expect(claimed, `${refusal.claimedVector} is not a published vector`).toBeDefined();
      if (held === undefined || claimed === undefined) continue;
      expect(held.bodyBase64Url).toBe(refusal.bodyBase64Url);
      expect(claimed.reqHex).toBe(refusal.claimedReqHex);
      // The two bodies differ and so do their digests: that is the whole content of the row.
      expect(hex(hashRequest(bytes(held.bodyBase64Url)))).not.toBe(refusal.claimedReqHex);
    }
  });

  it('refuses each request row with the code it names, and accepts the body the receipt attests', () => {
    expect(requests.refusals.length).toBeGreaterThanOrEqual(2);
    for (const refusal of requests.refusals) {
      const receipt = bytes(refusal.receiptBase64Url);
      expect(hex(hashRequest(receipt))).toBe(refusal.receiptSha256Hex);
      // These receipts move `req` and nothing else, so the response they attest is the one the envelope
      // signs by default, which is published as `receipt-valid-v1`'s row. A client of a receipt has to
      // hold the body the document digests, and the marking check reads the region out of it.
      const held = vectorsByName.get(refusal.heldVector);
      expect(
        clientVerdict(receipt, { requestHash: hashRequest(bytes(held?.bodyBase64Url ?? '')), responseBytes: FIXTURE_RESPONSE_BYTES }),
      ).toBe(refusal.code);
      const claimed = vectorsByName.get(refusal.claimedVector);
      expect(
        clientVerdict(receipt, { requestHash: hashRequest(bytes(claimed?.bodyBase64Url ?? '')), responseBytes: FIXTURE_RESPONSE_BYTES }),
      ).toBe('verify-ok');
    }
  });

  it('refuses a response hashed apart from the bytes it was taken over', () => {
    expect(responses.refusals.length).toBeGreaterThanOrEqual(2);
    const responsesByName = new Map(responses.vectors.map((each) => [each.name, each]));
    for (const refusal of responses.refusals) {
      const held = responsesByName.get(refusal.heldVector);
      const claimed = responsesByName.get(refusal.claimedVector);
      expect(held, `${refusal.heldVector} is not a published vector`).toBeDefined();
      expect(claimed, `${refusal.claimedVector} is not a published vector`).toBeDefined();
      const receipt = bytes(refusal.receiptBase64Url);
      expect(hex(hashRequest(receipt))).toBe(refusal.receiptSha256Hex);
      expect(claimed?.resHex).toBe(refusal.claimedResHex);
      if (held === undefined || claimed === undefined) continue;
      expect(hex(hashRequest(bytes(held.responseBase64Url)))).not.toBe(refusal.claimedResHex);
      expect(
        clientVerdict(receipt, {
          responseHash: hashRequest(bytes(held.responseBase64Url)),
          responseBytes: bytes(held.responseBase64Url),
        }),
      ).toBe(refusal.code);
      expect(
        clientVerdict(receipt, {
          responseHash: hashRequest(bytes(claimed.responseBase64Url)),
          responseBytes: bytes(claimed.responseBase64Url),
        }),
      ).toBe('verify-ok');
    }
  });
});

describe('the proof-of-possession refusals through the shipped signer and parser', () => {
  const privateKey = new Uint8Array(Buffer.from(proofOfPossession.key.privateKeyHex, 'hex'));
  const publicKey = new Uint8Array(Buffer.from(proofOfPossession.key.publicKeyHex, 'hex'));

  const popFields = (row: {
    fields: { ts: number; nonce: string; method: string; target: string; bodyDigestHex: string };
  }) => ({
    ts: row.fields.ts,
    nonce: bytes(row.fields.nonce),
    method: row.fields.method,
    target: row.fields.target,
    bodyDigestHex: row.fields.bodyDigestHex,
  });

  it('accepts every published authorization it is checking a near miss against', () => {
    expect(proofOfPossession.scheme).toBe(POP_SCHEME);
    for (const vector of proofOfPossession.vectors) {
      const parsed = parsePopAuthorization(vector.authorization);
      expect(verifyPopSignature(popFields(vector), parsed.signature, publicKey), vector.name).toBe(true);
    }
  });

  it('refuses each near-miss row with the code the row names', () => {
    expect(proofOfPossession.refusals.length).toBeGreaterThanOrEqual(3);
    const observed = proofOfPossession.refusals.map((row) => {
      expect(row.code, `${row.name} states no code`).toMatch(/^[A-Z0-9_]+$/u);
      const base = proofOfPossession.vectors.find((each) => each.name === row.vector);
      expect(base, `${row.name} is not built from a published vector`).toBeDefined();
      if (row.stage === 'sign') {
        // The signer refuses before a header exists, so the row's own fields are the presentation and
        // the signing string beside it is the one nothing was signed over.
        expect(popSigningString(popFields(row))).toBe(row.signingString);
        return `${row.name}: ${verdictOf(() =>
          signPopAuthorization(popFields(row), proofOfPossession.key.id, privateKey),
        )}`;
      }
      expect(`${row.name}: ${verdictOf(() => parsePopAuthorization(row.authorization))}`).toBe(
        `${row.name}: ${row.code}`,
      );
      // The header parses to something or it would not be a near miss: the row has to differ from the
      // accepted header it is built from, and differ in the one place its note names.
      expect(row.authorization).not.toBe(base?.authorization);
      return `${row.name}: ${row.code}`;
    });
    expect(observed).toEqual(proofOfPossession.refusals.map((row) => `${row.name}: ${row.code}`));
  });

  it('refuses the truncated signature for its width and not for its spelling', () => {
    const row = proofOfPossession.refusals.find((each) => each.name === 'signature-two-characters-short');
    expect(row).toBeDefined();
    if (row === undefined) return;
    const signature = row.authorization.slice(row.authorization.lastIndexOf('sig=') + 4);
    // One Ed25519 signature is 64 bytes, and this row took two base64url characters off the end of it,
    // which is 63 bytes of signature in a header that is otherwise the accepted one.
    expect(bytes(signature)).toHaveLength(63);
    let code = 'no-error';
    try {
      parsePopAuthorization(row.authorization);
    } catch (err) {
      code = err instanceof ReceiptError ? err.code : 'uncoded';
    }
    expect(code).toBe('BAD_POP_HEADER');
  });
});

describe('the receipt store chain refusals through the store reader', () => {
  it('refuses every published image with the code its row states', async () => {
    expect(chain.refusals.length).toBeGreaterThanOrEqual(4);
    // A refusal between a file and a configuration is not reproducible without the configuration, and a
    // row states `openedWith` wherever its image is read under a kind other than the receipt kind. The
    // rows that state none are read under the default, which is what every published image is made of.
    expect(
      chain.refusals.filter((refusal) => refusal.openedWith !== undefined).length,
      'no published refusal is given by a store configured for the kind its image is not',
    ).toBeGreaterThanOrEqual(1);
    // And the other half, which the first half cannot say on its own: a suite that grew a configuration
    // for every row would stop reading any image as the default store reads it, and the published files
    // every one of them is made of would be replayed under a configuration none of them was written by.
    expect(
      chain.refusals.filter((refusal) => refusal.openedWith === undefined).length,
      'every published refusal now names a configuration, so no image is read the way a deployment that configured nothing reads it',
    ).toBeGreaterThanOrEqual(1);
    for (const [index, refusal] of chain.refusals.entries()) {
      const dir = mkdtempSync(join(tempDir, `chain-${String(index)}-`));
      writeFileSync(join(dir, RECEIPT_STORE_FILE), bytes(refusal.imageBase64Url));
      expect(bytes(refusal.imageBase64Url)).toHaveLength(refusal.imageByteLength);
      const opened = await openFileReceiptStore({
        dir,
        ...(refusal.openedWith === undefined ? {} : { receiptKind: refusal.openedWith }),
      }).then(
        () => null,
        (error: unknown) => error,
      );
      expect(opened, `${refusal.name} opened without refusing`).toBeInstanceOf(StoreError);
      expect((opened as StoreError).code, refusal.name).toBe(refusal.code);
    }
  });
});

/**
 * The policy a manifest row states: the keys it designates for signing manifests, by id and public half,
 * and nothing beside them. A row naming none yields an empty map, which is the state the client answers
 * with an advisory rather than a refusal.
 */
function policyDesignating(entries: readonly { kid: string; publicKeyBase64Url: string }[]): AshaveriPolicy {
  return { manifestKeys: Object.fromEntries(entries.map((one) => [one.kid, one.publicKeyBase64Url])) };
}

/** What the shipped client path answered: the verdict, and the reading whenever it returned one. */
function readAsClient(one: ManifestVectorCase): { verdict: string; read: ReadManifestResult | null } {
  try {
    return {
      verdict: 'verify-ok',
      read: readDeploymentManifest(bytes(one.documentBase64Url), policyDesignating(one.read.designates)),
    };
  } catch (err) {
    if (err instanceof SdkError || err instanceof ReceiptError) return { verdict: err.code as string, read: null };
    throw err;
  }
}

/** The public half of a key this suite publishes, by the id its own seal names. */
const PUBLISHED_KEYS = new Map(sealedManifests.layout.keyMaterial.map((one) => [one.kidHex, one.publicKeyBase64Url]));

/**
 * What the format package's envelope reader answered for the same bytes, under the key the protected
 * header names. The suite publishes this beside the client verdict because the two layers refuse for
 * different reasons, and a row whose seal holds while the client refuses is a designation problem rather
 * than a document that moved.
 */
function readAsEnvelope(one: ManifestVectorCase): string {
  const documentBytes = bytes(one.documentBase64Url);
  if (!isSealedDeploymentManifest(documentBytes)) return 'not-sealed';
  try {
    const seal = decodeSealedDeploymentManifest(documentBytes);
    const publicKey = PUBLISHED_KEYS.get(hex(seal.header.kid));
    if (publicKey === undefined) return 'kid-outside-the-material-this-suite-publishes';
    verifySealedDeploymentManifest(documentBytes, bytes(publicKey));
    return 'verify-ok';
  } catch (err) {
    if (err instanceof ReceiptError) return err.code;
    throw err;
  }
}

const manifestVectors = sealedManifests.vectors;

describe('the sealed deployment manifest vectors through the client path', () => {
  it('states a verdict for every case and gives every case that verdict', () => {
    expect(manifestVectors.length).toBeGreaterThanOrEqual(30);
    const observed = manifestVectors.map((one) => {
      expect(one.verdict, `${one.name} states no verdict`).toMatch(/^[A-Za-z0-9_-]+$/u);
      expect(bytes(one.documentBase64Url)).toHaveLength(one.documentByteLength);
      return `${one.name}: ${readAsClient(one).verdict}`;
    });
    expect(observed).toEqual(manifestVectors.map((one) => `${one.name}: ${one.verdict}`));
  });

  it('separates what the envelope refuses from what the client refuses', () => {
    // Two columns of the same file, both run: the format reader over the bytes, the client over the
    // result. A row where the seal holds and the client refuses is about who this reader designated, and
    // a port that reported those two under one code would send an operator to the wrong half of the
    // deployment. `envelope-without-its-tag` is the pair in the other direction.
    const observed = manifestVectors.map((one) => `${one.name}: ${readAsEnvelope(one)}`);
    expect(observed).toEqual(manifestVectors.map((one) => `${one.name}: ${one.seal}`));
    const sealedButRefused = manifestVectors.filter((one) => one.seal === 'verify-ok' && one.verdict !== 'verify-ok');
    expect(sealedButRefused.length).toBeGreaterThanOrEqual(2);
  });

  it('reports the three states of a whole document exactly as each row states them', () => {
    const accepted = manifestVectors.filter((one) => one.verdict === 'verify-ok');
    expect(accepted.length).toBeGreaterThanOrEqual(6);
    // The three states this container can arrive in, named rather than counted: authenticated under a
    // designated key, sealed under no designation, and served with no seal at all.
    const shapes = [...new Set(accepted.map((one) => `${String(one.authentication?.sealed)}/${String(one.authentication?.authenticated)}`))].sort();
    expect(shapes).toEqual(['false/false', 'true/false', 'true/true']);
    for (const one of accepted) {
      const read = readAsClient(one).read;
      expect(read, `${one.name} returned no reading`).not.toBeNull();
      if (read === null) continue;
      const stated = one.authentication;
      expect(stated, `${one.name} is accepted with no stated authentication`).toBeDefined();
      if (stated === undefined) continue;
      expect({
        sealed: read.authentication.sealed,
        authenticated: read.authentication.authenticated,
        kid: read.authentication.kid,
        demanded: read.authentication.demanded,
        advisory: read.authentication.advisory !== null,
      }).toEqual(stated);
      if (one.parsed !== undefined) expect(JSON.parse(JSON.stringify(read.manifest)), one.name).toEqual(one.parsed);
      // A member this version does not name is left alone, which means it is in neither the parsed
      // document nor any entry of it, whatever position in the text it arrived at.
      for (const member of one.dropped ?? []) {
        expect(JSON.stringify(read.manifest), `${one.name} kept the ${member} member`).not.toContain(`"${member}"`);
      }
      if (stated.advisory && stated.kid !== null) {
        // The reason is part of the result rather than a line the caller goes looking for, and the thing
        // it names is the id nothing vouched for.
        expect(read.authentication.advisory, one.name).toContain(stated.kid);
      }
    }
  });

  it('adjudicates every published epoch claim against the document that carries it', () => {
    const carrying = manifestVectors.filter((one) => one.claims !== undefined);
    expect(carrying.length).toBeGreaterThanOrEqual(2);
    for (const one of carrying) {
      const read = readAsClient(one).read;
      expect(read, `${one.name} states claims on a document that is not read`).not.toBeNull();
      if (read === null) continue;
      for (const row of one.claims ?? []) {
        const verdict = adjudicateReceiptEpoch(read.manifest, row.claim);
        expect(
          {
            claim: row.claim,
            ok: verdict.ok,
            code: verdict.ok ? undefined : verdict.code,
            basis: verdict.ok ? verdict.basis : undefined,
            superseded: verdict.ok ? verdict.superseded : undefined,
            validFrom: verdict.ok ? verdict.validFrom : undefined,
            validTo: verdict.ok ? verdict.validTo : undefined,
          },
          `${one.name} claim at ${String(row.claim.issuedAt)}`,
        ).toEqual(row);
      }
    }
  });

  it('publishes a Sig_structure that rebuilds from the elements it names', () => {
    const revealed = manifestVectors.filter((one) => one.reveal !== undefined);
    expect(revealed).toHaveLength(1);
    const one = revealed[0];
    const reveal = one?.reveal;
    if (one === undefined || reveal === undefined) return;
    const documentBytes = bytes(one.documentBase64Url);
    const seal = decodeSealedDeploymentManifest(documentBytes);
    const payloadBytes = bytes(reveal.payloadBase64Url);
    // The published elements are the ones inside the envelope, and the payload is the document byte for
    // byte rather than a rendering of it, which is the whole of what the signature covers.
    expect(hex(bytes(reveal.protectedHeaderBase64Url))).toBe(hex(seal.protectedBytes));
    expect(hex(payloadBytes)).toBe(hex(seal.payloadBytes));
    expect(hex(seal.signature)).toBe(reveal.signatureHex);
    expect(payloadBytes).toHaveLength(reveal.payloadByteLength);
    expect(hex(sha256(payloadBytes))).toBe(reveal.payloadSha256Hex);
    expect(encodeCanonical([reveal.contextString, bytes(reveal.protectedHeaderBase64Url), bytes(reveal.externalAadBase64Url), payloadBytes])).toEqual(
      new Uint8Array(Buffer.from(reveal.sigStructureHex, 'hex')),
    );
    expect(reveal.headerLabels.map((label) => label.label)).toEqual([1, 3, 4]);
    // And the bytes those elements describe verify, so the structure a stranger rebuilds is the one this
    // repository signed rather than a framing that happens to print the same way.
    const designated = one.read.designates[0];
    expect(designated, `${one.name} reveals nothing designated`).toBeDefined();
    expect(() => verifySealedDeploymentManifest(documentBytes, bytes(designated?.publicKeyBase64Url ?? ''))).not.toThrow();
  });

  it('refuses a sealed manifest at the receipt reader it is handed to', () => {
    // The other half of the pair that keeps the containers apart. A manifest and a receipt are one
    // envelope signed by one deployment's keys, and the reader of each answers at its header.
    expect(sealedManifests.crossReading.cases.length).toBeGreaterThanOrEqual(1);
    for (const one of sealedManifests.crossReading.cases) {
      let answer = 'verify-ok';
      try {
        decodeCoseSign1(bytes(one.documentBase64Url));
      } catch (err) {
        if (!(err instanceof ReceiptError)) throw err;
        answer = err.code;
      }
      expect(answer, one.name).toBe(one.expected);
    }
  });

  it('reaches every code the client registry declares for this document', () => {
    // A fault code with no published case is a word nothing is measured against, and this suite is where
    // the manifest half of the client registry is measured. Read off the declared union rather than from a
    // list repeated here, which is the only way an addition cannot pass unnoticed.
    const source = readFileSync(fileURLToPath(new URL('../../sdk/src/errors.ts', import.meta.url)), 'utf8');
    const declared = [...source.matchAll(/'(BAD_MANIFEST|MANIFEST_[A-Z0-9_]+)'/gu)].map((found) => found[1]!);
    expect(new Set(declared).size).toBeGreaterThanOrEqual(6);
    const reached = new Set([
      ...manifestVectors.map((one) => one.verdict),
      ...manifestVectors.flatMap((one) => (one.claims ?? []).map((row) => row.code ?? 'verify-ok')),
    ]);
    for (const code of new Set(declared)) {
      expect(reached.has(code), `${code} is declared and no published row reaches it`).toBe(true);
    }
  });
});

/**
 * The designation a pack row states, as the reader's own two shapes and no third: one key pinned, or the set
 * a resolver answers from, which is how a span crossing a key rotation is read.
 */
function packOptionsFor(read: PackVectorCase['read']): { publicKey?: Uint8Array; resolveKey?: (kid: Uint8Array) => Uint8Array | undefined } {
  if (read.pinned !== undefined) return { publicKey: bytes(read.pinned) };
  if (read.retained === undefined) return {};
  const byKid = new Map(read.retained.map((one) => [one.kid, one.publicKeyBase64Url]));
  return { resolveKey: (kid) => {
    const found = byKid.get(hex(kid));
    return found === undefined ? undefined : bytes(found);
  } };
}

const PUBLISHED_PACK_KEYS = new Map(packVectors.layout.keyMaterial.map((one) => [one.kidHex, one.publicKeyBase64Url]));

describe('the evidence pack vectors through the shipped reader', () => {
  it('states a verdict for every case and gives every case that verdict', () => {
    expect(packVectors.vectors.length).toBeGreaterThanOrEqual(20);
    const observed = packVectors.vectors.map((one) => {
      expect(one.verdict, `${one.name} states no verdict`).toMatch(/^[A-Za-z0-9_-]+$/u);
      expect(bytes(one.documentBase64Url)).toHaveLength(one.documentByteLength);
      return `${one.name}: ${verdictOf(() => verifyPack(bytes(one.documentBase64Url), packOptionsFor(one.read)))}`;
    });
    expect(observed).toEqual(packVectors.vectors.map((one) => `${one.name}: ${one.verdict}`));
  });

  it('separates what the bytes say before a key from what the signature decides after one', () => {
    // The structural column is the same file read by `decodePack`, which needs no key. A row that is `verify-ok`
    // here and a refusal in `verdict` is refusing about a designation or a signature, and a port that collapsed
    // the two would send an operator to the pack rather than to the keys it retains.
    const observed = packVectors.vectors.map((one) => `${one.name}: ${verdictOf(() => decodePack(bytes(one.documentBase64Url)))}`);
    expect(observed).toEqual(packVectors.vectors.map((one) => `${one.name}: ${one.structural}`));
    const wholeButUnattributed = packVectors.vectors.filter((one) => one.structural === 'verify-ok' && one.verdict !== 'verify-ok');
    expect(wholeButUnattributed.length).toBeGreaterThanOrEqual(4);
  });

  it('reports the run, the window and the ordering findings exactly as each row states them', () => {
    const accepted = packVectors.vectors.filter((one) => one.verdict === 'verify-ok');
    expect(accepted.length).toBeGreaterThanOrEqual(6);
    for (const one of accepted) {
      const read = verifyPack(bytes(one.documentBase64Url), packOptionsFor(one.read));
      expect(read.outcome.walked.map((each) => each.item.id), one.name).toEqual(one.walk);
      expect(read.outcome.ordering, one.name).toEqual(one.ordering ?? []);
      if (one.span !== undefined) expect(read.outcome.span, one.name).toEqual(one.span);
      expect(read.header.contentType, one.name).toBe(packVectors.layout.contentType);
      // The originals come back as the receipts the item carries, and each item's stamp is the one its own
      // receipt attests, which is the equality the walk is not.
      for (const each of read.outcome.walked) {
        expect(each.receipt.payload.iat, `${one.name} ${each.item.id}`).toBe(each.item.iat);
      }
    }
  });

  it('accepts the pack whose stamps run against its links and reports the step', () => {
    // The row exists so that a port cannot turn the finding into a refusal without this case failing: an honest
    // deployment that corrected its clock signs this document, and the format states no rule a backwards stamp
    // breaks.
    const disagreeing = packVectors.vectors.filter((one) => (one.ordering?.length ?? 0) > 0);
    expect(disagreeing.length, 'no published pack carries an ordering finding').toBeGreaterThanOrEqual(1);
    for (const one of disagreeing) {
      expect(one.verdict, `${one.name}: a disagreement was refused rather than reported`).toBe('verify-ok');
      const read = verifyPack(bytes(one.documentBase64Url), packOptionsFor(one.read));
      expect(read.outcome.ordering, one.name).toEqual(one.ordering);
      for (const finding of read.outcome.ordering) {
        expect(finding.kind, one.name).toBe('stamp-runs-backwards');
        expect(finding.toIat, one.name).toBeLessThan(finding.fromIat);
      }
    }
    // And a pack whose two orders agree states that as an empty finding rather than an absent field.
    const agreeing = packVectors.vectors.find((one) => one.name === 'well-formed-three-items');
    expect(agreeing?.ordering).toEqual([]);
  });

  it('publishes both halves of the chain rule as refusals, the walk and the count', () => {
    // `pack.cddl` says a conforming reader enforces both and that implementing one is implementing half a rule.
    // The two refusals are separate codes, so a port that only walked would accept the parked row and fail here.
    for (const code of ['PACK_CHAIN_BROKEN', 'PACK_ITEM_UNREACHED']) {
      const rows = packVectors.vectors.filter((one) => one.verdict === code);
      expect(rows.length, `${code} has no published row`).toBeGreaterThanOrEqual(1);
      for (const one of rows) {
        expect(verdictOf(() => verifyPack(bytes(one.documentBase64Url), packOptionsFor(one.read))), one.name).toBe(code);
      }
    }
  });

  it('refuses a pack document at the export reader it is handed to', () => {
    expect(packVectors.crossReading.cases.length).toBeGreaterThanOrEqual(1);
    for (const one of packVectors.crossReading.cases) {
      const documentBytes = bytes(one.documentBase64Url);
      const kidHex = hex(decodePack(documentBytes).header.kid);
      const publicKey = PUBLISHED_PACK_KEYS.get(kidHex);
      expect(publicKey, `${one.name}: the document names a kid this suite does not publish`).toBeDefined();
      if (publicKey === undefined) continue;
      expect(verdictOf(() => verifyExport(documentBytes, bytes(publicKey))), one.name).toBe(one.expected);
    }
  });

  it('reaches every code the format registry declares for this container', () => {
    // A fault code with no published row is a word nothing is measured against. Read off the declared union
    // rather than from a list repeated here, which is the only way an addition cannot pass unnoticed.
    const source = readFileSync(fileURLToPath(new URL('../../receipt/src/errors.ts', import.meta.url)), 'utf8');
    const declared = [...source.matchAll(/'(PACK_[A-Z0-9_]+)'/gu)].map((found) => found[1]!);
    expect(new Set(declared).size).toBeGreaterThanOrEqual(11);
    const reached = new Set([...packVectors.vectors.map((one) => one.verdict), ...packVectors.vectors.map((one) => one.structural)]);
    for (const code of new Set(declared)) {
      expect(reached.has(code), `${code} is declared and no published row reaches it`).toBe(true);
    }
  });
});

/**
 * What a row hands the redaction reader: the keys the caller designates, exactly as the pack rows spell
 * them, and the pack the statement is checked against. A row stating no pack hands `packBytes` as nothing,
 * which is the call a reader makes when it was handed one document of the pair.
 */
function redactionOptionsFor(one: RedactionVectorCase): {
  publicKey?: Uint8Array;
  resolveKey?: (kid: Uint8Array) => Uint8Array | undefined;
  packBytes: Uint8Array;
} {
  let keys: { publicKey?: Uint8Array; resolveKey?: (kid: Uint8Array) => Uint8Array | undefined } = {};
  if (one.read.pinned !== undefined) keys = { publicKey: bytes(one.read.pinned) };
  else if (one.read.retained !== undefined) {
    const byKid = new Map(one.read.retained.map((each) => [each.kid, each.publicKeyBase64Url]));
    keys = {
      resolveKey: (kid) => {
        const found = byKid.get(hex(kid));
        return found === undefined ? undefined : bytes(found);
      },
    };
  }
  return {
    ...keys,
    packBytes: one.packBase64Url === undefined ? (undefined as unknown as Uint8Array) : bytes(one.packBase64Url),
  };
}

describe('the redaction manifest vectors through the shipped reader', () => {
  it('states a verdict for every case and gives every case that verdict', () => {
    expect(redactionVectors.vectors.length).toBeGreaterThanOrEqual(20);
    const observed = redactionVectors.vectors.map((one) => {
      expect(one.verdict, `${one.name} states no verdict`).toMatch(/^[A-Za-z0-9_-]+$/u);
      expect(bytes(one.documentBase64Url)).toHaveLength(one.documentByteLength);
      return `${one.name}: ${verdictOf(() => verifyRedaction(bytes(one.documentBase64Url), redactionOptionsFor(one)))}`;
    });
    expect(observed).toEqual(redactionVectors.vectors.map((one) => `${one.name}: ${one.verdict}`));
  });

  it('separates what the bytes say before a key from what the pair decides after one', () => {
    // `decodeRedaction` is handed no key and no pack, so a row that is `verify-ok` there and a refusal in
    // `verdict` is refusing about a pack, a designation or the arithmetic over the survivors, and a port
    // that merged the two would send an operator to the evidence rather than to their own configuration.
    const observed = redactionVectors.vectors.map(
      (one) => `${one.name}: ${verdictOf(() => decodeRedaction(bytes(one.documentBase64Url)))}`,
    );
    expect(observed).toEqual(redactionVectors.vectors.map((one) => `${one.name}: ${one.structural}`));
    const wholeButUnpaired = redactionVectors.vectors.filter(
      (one) => one.structural === 'verify-ok' && one.verdict !== 'verify-ok',
    );
    expect(wholeButUnpaired.length).toBeGreaterThanOrEqual(8);
  });

  it('reports the survivor run and both chain heads exactly as each row states them', () => {
    const accepted = redactionVectors.vectors.filter((one) => one.verdict === 'verify-ok');
    expect(accepted.length).toBeGreaterThanOrEqual(8);
    for (const one of accepted) {
      const read = verifyRedaction(bytes(one.documentBase64Url), redactionOptionsFor(one));
      expect(read.outcome.survivors.map((each) => each.item.id), one.name).toEqual(one.survivors);
      expect(hex(read.outcome.reduced), one.name).toBe(one.reducedHex);
      expect(hex(read.outcome.originalHead), one.name).toBe(one.originalHeadHex);
      // Two findings, two fields: the pack's head holds over the pack's own run and the value above holds
      // over a shorter chain the pack does not contain. A reader that printed one where the other belongs
      // is reporting that a receipt was never removed, or that a pack lost its chain.
      expect(read.outcome.reduced, one.name).not.toEqual(read.outcome.originalHead);
      // The designation is the reader's own hash of the pack it was handed, and the originals the pack
      // carries are the records the survivor run is made of, each attesting the stamp it was hashed with.
      expect(hex(read.outcome.packSha256), one.name).toBe(hex(sha256(bytes(one.packBase64Url ?? ''))));
      expect(read.outcome.removed, one.name).toEqual(decodeRedaction(bytes(one.documentBase64Url)).manifest.removed);
      for (const each of read.outcome.survivors) {
        expect(each.receipt.payload.iat, `${one.name} ${each.item.id}`).toBe(each.item.iat);
      }
      expect(read.header.contentType, one.name).toBe(redactionVectors.layout.contentType);
    }
  });

  it('refuses a reader handed the wrong half of a pair, and one handed a chain it cannot recompute', () => {
    // The first three are answers about the pair rather than about either document, and the last is the
    // load-bearing one: it is reached only by recomputing a chain over the records the pack still carries.
    for (const code of [
      'REDACTION_PACK_UNAVAILABLE',
      'REDACTION_PACK_MISMATCH',
      'REDACTION_PACK_DISAGREES',
      'REDACTION_ITEM_ABSENT',
      'REDACTION_SURVIVORS_EMPTY',
      'REDACTION_SURVIVOR_CHAIN_MISMATCH',
    ]) {
      const rows = redactionVectors.vectors.filter((one) => one.verdict === code);
      expect(rows.length, `${code} has no published row`).toBeGreaterThanOrEqual(1);
      for (const one of rows) {
        expect(verdictOf(() => verifyRedaction(bytes(one.documentBase64Url), redactionOptionsFor(one))), one.name).toBe(code);
        expect(one.structural, `${one.name}: a pair refusal answered as a manifest fault`).toBe('verify-ok');
      }
    }
  });

  it('refuses a redaction document at the pack reader it is handed to', () => {
    // One key seals both containers and each verifies cleanly under it, so the only thing that tells a
    // reader which claim it is holding is the content type, and the refusal is the header's.
    expect(redactionVectors.crossReading.cases.length).toBeGreaterThanOrEqual(1);
    for (const one of redactionVectors.crossReading.cases) {
      const documentBytes = bytes(one.documentBase64Url);
      const publicKey = PUBLISHED_PACK_KEYS.get(hex(decodeRedaction(documentBytes).header.kid));
      expect(publicKey, `${one.name}: the document names a kid the pack suite does not publish`).toBeDefined();
      if (publicKey === undefined) continue;
      expect(verdictOf(() => verifyPack(documentBytes, { publicKey: bytes(publicKey) })), one.name).toBe(one.expected);
    }
  });

  it('reaches every code the format registry declares for this container', () => {
    // Read off the declared union rather than from a list repeated here, which is the only way an addition
    // cannot pass unnoticed.
    const source = readFileSync(fileURLToPath(new URL('../../receipt/src/errors.ts', import.meta.url)), 'utf8');
    const declared = [...source.matchAll(/'(REDACTION_[A-Z0-9_]+)'/gu)].map((found) => found[1]!);
    expect(new Set(declared).size).toBeGreaterThanOrEqual(13);
    const reached = new Set([
      ...redactionVectors.vectors.map((one) => one.verdict),
      ...redactionVectors.vectors.map((one) => one.structural),
    ]);
    for (const code of new Set(declared)) {
      expect(reached.has(code), `${code} is declared and no published row reaches it`).toBe(true);
    }
  });
});

/**
 * The public halves this suite publishes, joined both ways: by the kid a protected header names, which is how
 * a resolver answers, and by the half itself, which is how a row stating one key says which it means. A
 * designation that appears in neither column of this table is a fault this block reports rather than bytes it
 * hands a reader.
 */
const PUBLISHED_INVENTORY_KEYS = new Map(
  epochInventories.layout.keyMaterial.map((one) => [one.kidHex, one.publicKeyBase64Url]),
);

/** The published material for a designated public half, named by the kid its own seal carries. */
function publishedInventoryKey(publicKeyBase64Url: string): { kidHex: string; publicKeyBase64Url: string } {
  const found = epochInventories.layout.keyMaterial.find((one) => one.publicKeyBase64Url === publicKeyBase64Url);
  if (found === undefined) throw new Error('a published row designates a half this suite holds no key material for');
  return found;
}

/**
 * What a row hands the inventory reader: the designation it states, read out of the row and resolved through
 * the published key material rather than as a byte string written into this file. `pinned` is the one half a
 * caller means, which answers whatever kid the header names, `retained` is the set a resolver answers from,
 * one half per kid, and a row stating neither is the call that designated nothing, which this reader answers
 * before it reads a byte. `presence` is beside either of those rather than instead of them: the run's retention
 * artifacts, handed with the document, which is the fold's input, and a row stating none is the call that handed
 * nothing and owes the reading of the document alone.
 */
function inventoryOptionsFor(one: EpochInventoryCase): EpochInventoryVerifyOptions {
  const presence = one.read.presence?.map((one) => bytes(one));
  const key: EpochInventoryVerifyOptions = (() => {
    if (one.read.pinned !== undefined) {
      return { publicKey: bytes(publishedInventoryKey(one.read.pinned).publicKeyBase64Url) };
    }
    if (one.read.retained !== undefined) {
      const held = one.read.retained;
      return {
        resolveKey: (kid) => {
          const found = held[hex(kid)];
          return found === undefined ? undefined : bytes(found);
        },
      };
    }
    return {};
  })();
  return presence === undefined ? key : { ...key, presence };
}

/** What the key-bearing reader answered: the code, and the sentence it gave beside a refusal. */
function inventoryAnswer(one: EpochInventoryCase): { code: string; message: string } {
  try {
    verifyEpochInventory(bytes(one.documentBase64Url), inventoryOptionsFor(one));
    return { code: 'verify-ok', message: '' };
  } catch (err) {
    if (err instanceof ReceiptError) return { code: err.code, message: err.message };
    throw err;
  }
}

/**
 * The epoch inventory suite replayed through the two readers a consumer links against.
 *
 * This goes through `verifyEpochInventory` and `decodeEpochInventory` rather than through a command because
 * there is no command to go through. `packages/cli/src/cli.ts` states the verbs this package ships in one
 * declaration, `COMMANDS`, and dispatches on it in `run`; they are `verify`, `verify-receipt`,
 * `verify-handover`, `verify-pack`, `verify-export`, `keygen`, `credential` and `accesslog`, and no verb of
 * this package reads an epoch inventory, which the absence of the word from every source file under
 * `packages/cli/src` states outright. Writing a verb for this container would settle what an operator gets to
 * run, which is a decision about the format's surface rather than about this replay, and a file that replays
 * published rows does not settle it. What this block does prove is the claim a port has to satisfy: the
 * readers exported from `@ashaveri/receipt` answer these verdicts from bytes a consumer can hold, under the
 * key material the same file publishes and nothing else. The redaction block above is the near relation, since
 * an inventory and a redaction manifest are both summaries over a run of packs and both are read by a
 * key-bearing and a keyless reader.
 */
describe('the epoch inventory vectors through the shipped readers', () => {
  it('states a verdict for every row and gives every row that verdict', () => {
    expect(epochInventories.vectors.length).toBeGreaterThanOrEqual(20);
    const observed = epochInventories.vectors.map((one) => {
      expect(one.verdict, `${one.name} states no verdict`).toMatch(/^[A-Za-z0-9_-]+$/u);
      expect(bytes(one.documentBase64Url)).toHaveLength(one.documentByteLength);
      return `${one.name}: ${verdictOf(() => verifyEpochInventory(bytes(one.documentBase64Url), inventoryOptionsFor(one)))}`;
    });
    expect(observed).toEqual(epochInventories.vectors.map((one) => `${one.name}: ${one.verdict}`));
  });

  it('separates what the bytes say before a key from what the reader decides after one', () => {
    // `decodeEpochInventory` is handed no key and no arithmetic over a run, so a row that is `verify-ok` there
    // and a refusal in `verdict` is refused about a key, a signature or the figures the run folds, and a port
    // that answered both questions at one door would send an operator to the inventory for what is a fact about
    // their own key set. The two directions are read off the rows rather than stated as numbers here.
    const observed = epochInventories.vectors.map(
      (one) => `${one.name}: ${verdictOf(() => decodeEpochInventory(bytes(one.documentBase64Url)))}`,
    );
    expect(observed).toEqual(epochInventories.vectors.map((one) => `${one.name}: ${one.structural}`));
    const wholeButRefused = epochInventories.vectors.filter(
      (one) => one.structural === 'verify-ok' && one.verdict !== 'verify-ok',
    );
    expect(wholeButRefused.length).toBeGreaterThanOrEqual(8);
    const atTheShape = epochInventories.vectors.filter((one) => one.structural !== 'verify-ok');
    expect(atTheShape.length).toBeGreaterThanOrEqual(8);
    for (const one of atTheShape) {
      expect(one.verdict, `${one.name} is refused at the shape and answered something else at the key`).toBe(
        one.structural,
      );
    }
  });

  it('answers a refusal in the sentence the row publishes beside it and none an acceptance', () => {
    // The published sentence is this reader's own wording, and it names the guard it stopped on, so comparing
    // it is what tells a folded-list refusal reached at one branch from the same code reached at another.
    const refused = epochInventories.vectors.filter((one) => one.verdict !== 'verify-ok');
    // The sentence column exists on refusals only, so the half that carries it has to stay a real share of the
    // suite for this comparison to measure anything: a suite that lost its negatives would leave two empty
    // arrays to compare and still report green.
    expect(refused.length).toBeGreaterThanOrEqual(epochInventories.vectors.length - refused.length);
    const observed = refused.map((one) => {
      expect(one.message, `${one.name} is refused and the file publishes no sentence for it`).toBeDefined();
      const answered = inventoryAnswer(one);
      return `${one.name}: ${answered.code}: ${answered.message}`;
    });
    expect(observed).toEqual(refused.map((one) => `${one.name}: ${one.verdict}: ${one.message ?? ''}`));
    for (const one of epochInventories.vectors) {
      if (one.verdict !== 'verify-ok') continue;
      expect(one.message, `${one.name} is accepted and carries a refusal sentence`).toBeUndefined();
    }
  });

  it('hands back the run and both claims exactly as each accepted row states them', () => {
    const accepted = epochInventories.vectors.filter((one) => one.verdict === 'verify-ok');
    expect(accepted.length).toBeGreaterThanOrEqual(8);
    for (const one of accepted) {
      const stated = one.readback;
      expect(stated, `${one.name} is accepted and states no readback`).toBeDefined();
      if (stated === undefined) continue;
      const read = verifyEpochInventory(bytes(one.documentBase64Url), inventoryOptionsFor(one));
      // `runFiles` is the reader's own recomputation and `statedFiles` the array as the document wrote it, so
      // one object holds both orders and a row whose readback went missing reports which side of it was lost.
      expect(
        {
          runFiles: read.outcome.packs.map((each) => each.file),
          statedFiles: read.manifest.packs.map((each) => each.file),
          window: read.manifest.window,
          continuous: read.manifest.chain.continuous,
          breakFiles: read.manifest.chain.breaks.map((each) => each.file),
          carried: read.manifest.duty.carried,
          shortFiles: read.manifest.duty.short.map((each) => each.file),
        },
        one.name,
      ).toEqual(stated);
      // Position in the array carries no claim, so the run handed over is the listed members reordered rather
      // than a different set: the same packs, each keyed by the digest it is filed under, either way.
      expect([...read.outcome.packs.map((each) => each.sha256)].sort(), one.name).toEqual(
        [...read.manifest.packs.map((each) => each.sha256)].sort(),
      );
      expect(read.header.contentType, one.name).toBe(epochInventories.layout.contentType);
    }
  });

  it('reaches every code the published roster states, through a row it replayed', () => {
    // The roster is a column of the file and the rows answering each code are read out of the file too, both
    // ways round, so a row that left this suite is reported here as a gap rather than still being spoken of as
    // covered, and a row answering a code the file does not roster reports itself the same way.
    const roster = epochInventories.layout.codes;
    expect(roster.length, 'the published roster states one code twice').toBe(new Set(roster).size);
    expect(roster.length).toBeGreaterThanOrEqual(12);
    for (const code of roster) {
      const rows = epochInventories.vectors.filter((one) => one.verdict === code || one.structural === code);
      expect(rows.length, `${code} is on the published roster and no replayed row answers it`).toBeGreaterThanOrEqual(1);
    }
    for (const one of epochInventories.vectors) {
      expect(roster, `${one.name} answers ${one.verdict}, which the file rosters nowhere`).toContain(one.verdict);
      expect(roster, `${one.name} is ${one.structural} at the shape, which the file rosters nowhere`).toContain(
        one.structural,
      );
    }
  });

  it('designates only the key material this suite publishes, joined by the kid a header names', () => {
    // The accepted rows are read from the kid in their own protected header against the published material, so
    // a row accepted under a key its header does not name, or a retained set holding a kid this suite
    // publishes no half for, is reported rather than verified under some other key this file reached for.
    for (const one of epochInventories.vectors) {
      if (one.read.pinned !== undefined) {
        if (one.verdict !== 'verify-ok') continue;
        const headerKid = hex(decodeEpochInventory(bytes(one.documentBase64Url)).header.kid);
        expect(PUBLISHED_INVENTORY_KEYS.get(headerKid), `${one.name} is accepted under a key its own header does not name`).toBe(
          one.read.pinned,
        );
        continue;
      }
      for (const [kid, half] of Object.entries(one.read.retained ?? {})) {
        expect(PUBLISHED_INVENTORY_KEYS.get(kid), `${one.name} retains a kid this suite publishes no half for`).toBe(
          half,
        );
      }
    }
  });
});

describe('the suites resolve from files alone', () => {
  it('asked no URL during the run', () => {
    expect(reached).toEqual([]);
    expect(existsSync(join(DATA, 'manifest.json'))).toBe(true);
  });
});
