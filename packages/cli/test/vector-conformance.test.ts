import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  POP_SCHEME,
  decodeCoseSign1,
  decodeSealedDeploymentManifest,
  encodeCanonical,
  extractMarkedRegion,
  isSealedDeploymentManifest,
  parsePopAuthorization,
  popSigningString,
  ReceiptError,
  signPopAuthorization,
  verifyPopSignature,
  verifySealedDeploymentManifest,
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
import { openFileReceiptStore, RECEIPT_STORE_FILE, StoreError } from '@ashaveri/signerd';

/**
 * The published vector suites, replayed through the paths a shipped client takes.
 *
 * `data/` states a verdict for its cases, and until now the suites other than the receipt fixtures
 * were read back by tests that checked a file against its own rule. This walks every suite and asks the
 * implementation that is shipped what it answers for each row: `verifyCompletionReceipt` for anything a
 * receipt decides, the proof-of-possession signer and parser for the wire-format rows, the store reader
 * for the chain images, and `readDeploymentManifest` beside its `adjudicateReceiptEpoch` for the sealed
 * deployment manifest. Where a row states a refusal, the code it names is the code that has to
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

/** The instant the published fixtures are issued at, so no run reads a clock. */
const CLOCK = 1_772_000_000;

interface ManifestEntry {
  readonly name: string;
  readonly path: string;
  readonly digestSha256: string;
  readonly expected: string;
  readonly note?: string;
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

/** The response bytes one marked case publishes, which is what a client holding a mark has to have. */
function markingBytes(name: string): Uint8Array {
  const found = marking.vectors.find((each) => each.name === name);
  if (found === undefined) throw new Error(`marking-v1.json states no ${name} case`);
  return bytes(found.responseBase64Url);
}

/**
 * One receipt handed to the shipped client path the way a client hands it: the challenge it was asked to
 * answer, the two bodies it attests, and the response bytes themselves.
 */
function clientVerdict(
  receiptBytes: Uint8Array,
  over: { requestHash?: Uint8Array; responseHash?: Uint8Array; responseBytes?: Uint8Array } = {},
): string {
  const claims = claimsOf(receiptBytes);
  const responseBytes = over.responseBytes ?? (claims.version === 2 ? markingBytes('buffered-member') : new Uint8Array(0));
  return verdictOf(() =>
    verifyCompletionReceipt({
      receiptBytes,
      nonce: claims.nonce,
      requestHash: over.requestHash ?? claims.req,
      responseHash: over.responseHash ?? claims.res,
      responseBytes,
      verifyKey: PUBLIC_KEY,
      now: CLOCK,
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
      return `${entry.name}: ${clientVerdict(receiptBytes)}`;
    });
    expect(observed).toEqual(manifest.fixtures.map((entry) => `${entry.name}: ${entry.expected}`));
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
    const marked = manifest.fixtures.find((entry) => entry.name === 'receipt-marked-v2');
    expect(marked?.expected).toBe('verify-ok');
    expect(clientVerdict(new Uint8Array(readFileSync(join(DATA, 'receipts/receipt-marked-v2.cbor'))))).toBe('verify-ok');
  });
});

describe('the marked-region vectors through the marking check', () => {
  it('carries a signed v2 document per case, issued under the published key', () => {
    for (const one of marking.vectors) {
      const decoded = decodeReceipt(bytes(one.client.receiptBase64Url));
      expect(decoded.payload.v, `${one.name} is not a v2 document`).toBe(2);
      if (decoded.payload.v !== 2) continue;
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
    const committed = new Uint8Array(readFileSync(join(DATA, 'receipts/receipt-marked-v2.cbor')));
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
      const held = vectorsByName.get(refusal.heldVector);
      expect(clientVerdict(receipt, { requestHash: hashRequest(bytes(held?.bodyBase64Url ?? '')) })).toBe(refusal.code);
      const claimed = vectorsByName.get(refusal.claimedVector);
      expect(clientVerdict(receipt, { requestHash: hashRequest(bytes(claimed?.bodyBase64Url ?? '')) })).toBe(
        'verify-ok',
      );
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
    for (const [index, refusal] of chain.refusals.entries()) {
      const dir = mkdtempSync(join(tempDir, `chain-${String(index)}-`));
      writeFileSync(join(dir, RECEIPT_STORE_FILE), bytes(refusal.imageBase64Url));
      expect(bytes(refusal.imageBase64Url)).toHaveLength(refusal.imageByteLength);
      const opened = await openFileReceiptStore({ dir }).then(
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

describe('the suites resolve from files alone', () => {
  it('asked no URL during the run', () => {
    expect(reached).toEqual([]);
    expect(existsSync(join(DATA, 'manifest.json'))).toBe(true);
  });
});
