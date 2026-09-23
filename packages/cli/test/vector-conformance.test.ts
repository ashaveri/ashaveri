import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  POP_SCHEME,
  extractMarkedRegion,
  parsePopAuthorization,
  popSigningString,
  ReceiptError,
  signPopAuthorization,
  verifyPopSignature,
  type MarkingScheme,
} from '@ashaveri/receipt';
import {
  decodeReceipt,
  hashRequest,
  SdkError,
  verifyCompletionReceipt,
} from '@ashaveri/sdk';
import { openFileReceiptStore, RECEIPT_STORE_FILE, StoreError } from '@ashaveri/signerd';

/**
 * The published vector suites, replayed through the paths a shipped client takes.
 *
 * `data/` states a verdict for its cases, and until now the suites other than the receipt fixtures
 * were read back by tests that checked a file against its own rule. This walks every suite and asks the
 * implementation that is shipped what it answers for each row: `verifyCompletionReceipt` for anything a
 * receipt decides, the proof-of-possession signer and parser for the wire-format rows, and the store
 * reader for the chain images. Where a row states a refusal, the code it names is the code that has to
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

describe('the suites resolve from files alone', () => {
  it('asked no URL during the run', () => {
    expect(reached).toEqual([]);
    expect(existsSync(join(DATA, 'manifest.json'))).toBe(true);
  });
});
