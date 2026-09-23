import { describe, expect, it } from 'vitest';
import {
  ReceiptError,
  decodeCoseSign1,
  emptyRegion,
  equalBytes,
  generateSigningKey,
  issueReceipt,
  toBase64Url,
  toHex,
  verifyReceipt,
  type ReceiptPayload,
} from '@ashaveri/receipt';
import { sha256 } from '@noble/hashes/sha2.js';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { Ajv2020, type ValidateFunction } from 'ajv/dist/2020.js';
import { captureRecordKey, parseCaptureRecord } from '../src/capture.js';
import { fromBase64Url } from '../src/b64.js';
import { SdkError } from '../src/errors.js';
import { parseManifest } from '../src/manifest.js';

/**
 * The capture record read as a document, against bytes the estate's own encoders produced.
 *
 * Nothing here invents a signed blob: the originals are `issueReceipt` output and a manifest the
 * estate's own `parseManifest` accepts, and the re-encodings are made out of the parts the estate's own
 * decoder hands back. A test of a capture format against a fixture nobody else wrote proves only that
 * two files agree with each other.
 */

const KEY = generateSigningKey();
const KID = toHex(KEY.kid);
const NOW = 1_800_000_000;
const TEXT = (value: string): Uint8Array => new TextEncoder().encode(value);
const ROOT = TEXT('a pinned vendor root');

function receiptPayload(version: 1 | 2, at: number): ReceiptPayload {
  const shared = {
    iss: 'ashaveri-test',
    ins: 'cvm-test-1',
    iat: at,
    nce: new Uint8Array(16).fill(7),
    req: sha256(TEXT('the canonical request bytes')),
    res: sha256(TEXT('the full response bytes')),
    mdl: 'test/model-1',
    wts: sha256(TEXT('the deployment manifest digest input')),
    meas: { tee: 'snp' as const, m: new Uint8Array(48).fill(3) },
    att: {
      d: sha256(TEXT('the evidence document this receipt points at')),
      ts: at - 5,
      url: 'https://gateway.test/evidence',
    },
    epk: 1,
    tok: { p: 11, c: 22 },
  };
  return version === 2
    ? { v: 2, ...shared, mk: { sch: 'none' as const, d: sha256(emptyRegion()) } }
    : { v: 1, ...shared };
}

const receiptV1 = issueReceipt(receiptPayload(1, NOW - 20), KEY);
const receiptV2 = issueReceipt(receiptPayload(2, NOW - 20), KEY);

const manifestDocument = {
  v: 1,
  iss: 'ashaveri-test',
  ins: 'cvm-test-1',
  epk: 1,
  keys: [{ kid: KID, alg: 'Ed25519', publicKey: toBase64Url(KEY.publicKey) }],
  models: [{ id: 'test/model-1', wts: toHex(sha256(TEXT('the deployment manifest digest input')))}],
  meas: { tee: 'snp', m: '03'.repeat(48) },
};
const manifestBytes = TEXT(JSON.stringify(manifestDocument));

const held = (bytes: Uint8Array): Record<string, unknown> => ({
  presence: 'held',
  bytes: toBase64Url(bytes),
  sha256: toHex(sha256(bytes)),
  byteCount: bytes.length,
});

/** A whole record that assesses clean, with the top-level blocks a test can replace one at a time. */
function recordFor(
  original: Uint8Array,
  over: Record<string, unknown> = {},
  block: { readonly receiptFormatVersion?: 1 | 2 } = {},
): Record<string, unknown> {
  return {
    v: 1,
    original: {
      sourceKind: 'receipt',
      sourceId: 'cvm-test-1',
      bytes: toBase64Url(original),
      sha256: toHex(sha256(original)),
      byteCount: original.length,
      signedBySource: true,
      signatureEmbedded: true,
    },
    acquired: { at: NOW, sourceStatedAt: NOW - 25 },
    manifests: { deployment: held(manifestBytes) },
    check: {
      policyVersion: 1,
      policyDigest: toHex(sha256(TEXT('the policy document that was loaded'))),
      receiptFormatVersion: block.receiptFormatVersion ?? 1,
      verifierVersion: '0.1.0',
      appraisedAt: NOW,
    },
    context: { collateral: held(TEXT('the vendor certificate chain as served')), validity: held(TEXT('the appraisal record')) },
    trust: {
      roots: [{ family: 'amdArks', digest: toHex(sha256(ROOT)) }],
      limits: { maxReceiptAgeSeconds: 300, maxEvidenceAgeSeconds: 900 },
    },
    ...over,
  };
}

function codeOf(fn: () => unknown): string | undefined {
  try {
    fn();
    return undefined;
  } catch (err) {
    if (err instanceof SdkError || err instanceof ReceiptError) return err.code;
    throw err;
  }
}

describe('a capture record holds the bytes a source produced', () => {
  it('reads a record whose original came out of the receipt encoder', () => {
    const parsed = parseCaptureRecord(recordFor(receiptV1));
    expect(parsed.original.byteCount).toBe(receiptV1.length);
    expect(parsed.original.signedBySource).toBe(true);
  });

  it('hands back the stored original byte for byte, not a reconstruction of it', () => {
    const parsed = parseCaptureRecord(recordFor(receiptV1));
    const stored = fromBase64Url(parsed.original.bytes);
    expect(equalBytes(stored, receiptV1)).toBe(true);
    // The bytes a stranger gets out of the record are the bytes that were signed: the format's own
    // verifier accepts them under the key that issued them.
    expect(() => verifyReceipt(stored, { publicKey: KEY.publicKey, now: NOW })).not.toThrow();
  });

  it('refuses a record whose original does not hash to the digest it states', () => {
    // One bit, the same length, the same shape: only a digest can see it, so the record has to be
    // refused by a reader that recomputes rather than by one that reads the stated value back.
    const flipped = Uint8Array.from(receiptV1, (byte, at) => (at === 40 ? byte ^ 0x01 : byte));
    expect(flipped.length).toBe(receiptV1.length);
    expect(codeOf(() => parseCaptureRecord(swapBytes(recordFor(receiptV1), flipped)))).toBe('EVIDENCE_DIGEST_MISMATCH');
    const stated = recordFor(receiptV1).original as Record<string, unknown>;
    expect(
      codeOf(() => parseCaptureRecord({ ...recordFor(receiptV1), original: { ...stated, sha256: 'f'.repeat(64) } })),
    ).toBe('EVIDENCE_DIGEST_MISMATCH');
  });

  it('refuses a purported equivalent, the same receipt re-serialized by a different encoder', () => {
    const equivalent = reframe(receiptV1);
    expect(equalBytes(equivalent, receiptV1)).toBe(false);
    // The estate's own reader takes only preferred serializations, so an equivalence between the two can
    // never be shown to it. That is the format's rule, and it is why the byte check has to be the
    // capture's own and has to run before anything decodes.
    expect(codeOf(() => verifyReceipt(equivalent, { publicKey: KEY.publicKey, now: NOW }))).toBe('MALFORMED_CBOR');
    // A record stating the digest of what the source produced and carrying what a second encoder wrote
    // is refused rather than read as equal.
    expect(codeOf(() => parseCaptureRecord(swapBytes(recordFor(receiptV1), equivalent)))).toBe(
      'EVIDENCE_DIGEST_MISMATCH',
    );
    // A record that states the re-encoded bytes as its own original is a capture of a different
    // document, and it keys apart from the honest one, so no store can merge the two.
    const asItsOwn = parseCaptureRecord(recordFor(equivalent));
    expect(captureRecordKey(asItsOwn)).not.toBe(captureRecordKey(parseCaptureRecord(recordFor(receiptV1))));
  });

  it('refuses a second base64url spelling of the very same bytes', () => {
    const oneByte = new Uint8Array([0xff]);
    const canonical = toBase64Url(oneByte);
    const reSpelled = `${canonical.slice(0, canonical.length - 1)}x`;
    expect(canonical).not.toBe(reSpelled);
    // Both spellings decode to the same byte, so a reader that looked only at decoded bytes would see
    // one honest record of one piece of evidence written two ways, and a store would key them apart.
    expect(equalBytes(fromBase64Url(canonical), fromBase64Url(reSpelled))).toBe(true);
    const record = swapBytes(recordFor(oneByte), oneByte, reSpelled);
    expect(codeOf(() => parseCaptureRecord(record))).toBe('NOT_CAPTURE_RECORD');
  });

  it('refuses a byte count that does not match the bytes beside it', () => {
    // The same bytes, a stated length one longer: the digest agrees and the record still goes.
    const record = swapBytes(recordFor(receiptV1), receiptV1, undefined, receiptV1.length + 1);
    expect(codeOf(() => parseCaptureRecord(record))).toBe('EVIDENCE_DIGEST_MISMATCH');
  });
});

/**
 * The record's own stated digest and count, with somebody else's bytes in the `bytes` member. This is
 * the shape a capture degrades into when a store passes a document through an encoder on the way to
 * disk and keeps the digest it took on the way in.
 */
function swapBytes(
  record: Record<string, unknown>,
  bytes: Uint8Array,
  spelling?: string,
  count?: number,
): Record<string, unknown> {
  const original = record['original'] as Record<string, unknown>;
  return {
    ...record,
    original: {
      ...original,
      bytes: spelling ?? toBase64Url(bytes),
      ...(count === undefined ? {} : { byteCount: count }),
    },
  };
}

/**
 * One COSE_Sign1, its four items untouched, framed by a writer that does not pick the shortest head for
 * a number. Decoded by a lenient reader the two documents are the same structure; on the wire they are
 * different bytes, which is all a capture record can see and all it is allowed to accept.
 */
function reframe(bytes: Uint8Array): Uint8Array {
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
  if (length < 0x10000) {
    out.push(0x59, (length >> 8) & 0xff, length & 0xff);
  } else {
    out.push(0x5a, (length >> 24) & 0xff, (length >> 16) & 0xff, (length >> 8) & 0xff, length & 0xff);
  }
  out.push(...bytes);
}

describe('absence is stated, never invented', () => {
  it('reads a declared absence and keeps the two kinds apart', () => {
    const neverProduced = recordFor(receiptV1, {
      context: {
        collateral: { presence: 'absent-at-source', reason: 'the platform served no certificate chain' },
        validity: held(TEXT('the appraisal record')),
      },
    });
    expect(parseCaptureRecord(neverProduced).context.collateral).toEqual({
      presence: 'absent-at-source',
      reason: 'the platform served no certificate chain',
    });
    const notTakenIn = recordFor(receiptV1, {
      context: {
        collateral: { presence: 'not-taken-in', reason: 'the collector did not read the chain route' },
        validity: held(TEXT('the appraisal record')),
      },
    });
    expect(parseCaptureRecord(notTakenIn).context.collateral.presence).toBe('not-taken-in');
    expect(parseCaptureRecord(notTakenIn).context.collateral).not.toEqual(parseCaptureRecord(neverProduced).context.collateral);
  });

  it('refuses an absence nobody explained', () => {
    const record = recordFor(receiptV1, {
      context: {
        collateral: { presence: 'absent-at-source' },
        validity: held(TEXT('the appraisal record')),
      },
    });
    expect(codeOf(() => parseCaptureRecord(record))).toBe('NOT_CAPTURE_RECORD');
  });

  it('refuses a context member that is silently missing rather than declared absent', () => {
    const record = recordFor(receiptV1);
    const context = { ...(record['context'] as Record<string, unknown>) };
    delete context['validity'];
    expect(codeOf(() => parseCaptureRecord({ ...record, context }))).toBe('NOT_CAPTURE_RECORD');
  });

  it('refuses a held slot that carries no bytes', () => {
    const record = recordFor(receiptV1, {
      context: { collateral: { presence: 'held', sha256: '0'.repeat(64), byteCount: 0 }, validity: held(TEXT('x')) },
    });
    expect(codeOf(() => parseCaptureRecord(record))).toBe('NOT_CAPTURE_RECORD');
  });

  it('refuses a slot member no presence state defines', () => {
    const record = recordFor(receiptV1, {
      manifests: { deployment: { ...held(manifestBytes), fetchedFrom: 'https://gateway.test/manifest' } },
    });
    expect(codeOf(() => parseCaptureRecord(record))).toBe('NOT_CAPTURE_RECORD');
  });
});

describe('what a capture record never claims', () => {
  it('refuses a record that states its own verification', () => {
    const record = { ...recordFor(receiptV1), verified: true };
    expect(codeOf(() => parseCaptureRecord(record))).toBe('NOT_CAPTURE_RECORD');
    const withVerdict = { ...recordFor(receiptV1), verdict: { status: 'pass' } };
    expect(codeOf(() => parseCaptureRecord(withVerdict))).toBe('NOT_CAPTURE_RECORD');
  });

  it('refuses a record claiming a detached signature it does not carry', () => {
    const detached = (signature: Record<string, unknown>): Record<string, unknown> => ({
      ...recordFor(receiptV1),
      original: {
        sourceKind: 'device-evidence',
        sourceId: 'gpu-1',
        bytes: toBase64Url(receiptV1),
        sha256: toHex(sha256(receiptV1)),
        byteCount: receiptV1.length,
        signedBySource: true,
        signatureEmbedded: false,
        signature,
      },
    });
    expect(
      codeOf(() => parseCaptureRecord(detached({ presence: 'not-taken-in', reason: 'the device route answered nothing' }))),
    ).toBe('CAPTURE_SIGNATURE_NOT_CARRIED');
    expect(
      codeOf(() => parseCaptureRecord(detached({ presence: 'absent-at-source', reason: 'the device served no signature' }))),
    ).toBe('CAPTURE_SIGNATURE_NOT_CARRIED');
    expect(codeOf(() => parseCaptureRecord(detached(held(new Uint8Array(64).fill(9)))))).toBeUndefined();
  });

  it('refuses a record whose signature slot describes a signature it denied', () => {
    const record = recordFor(receiptV1);
    const original = record.original as Record<string, unknown>;
    expect(
      codeOf(() =>
        parseCaptureRecord({
          ...record,
          original: {
            ...original,
            signedBySource: false,
            signature: { presence: 'absent-at-source', reason: 'nothing signed these bytes' },
          },
        }),
      ),
    ).toBe('NOT_CAPTURE_RECORD');
  });
});

describe('a version the reader does not implement is refused, not read as its own', () => {
  it('refuses a capture format version it has no rules for', () => {
    expect(codeOf(() => parseCaptureRecord({ ...recordFor(receiptV1), v: 2 }))).toBe('UNSUPPORTED_VERSION');
    expect(codeOf(() => parseCaptureRecord({ ...recordFor(receiptV1), v: '1' }))).toBe('UNSUPPORTED_VERSION');
  });

  it('refuses the version before it reads anything the version would name', () => {
    // A v2 record carrying a member v1 does not define is a version question, not a closure question,
    // and the answer has to name the version: reading the rest first would let a reader that had rules
    // for the member start assessing a document whose rules it does not know.
    const record = { ...recordFor(receiptV1), v: 2, dutyPeriodDays: 3650 };
    expect(codeOf(() => parseCaptureRecord(record))).toBe('UNSUPPORTED_VERSION');
  });

  it('refuses a policy or receipt format version it does not implement', () => {
    const check = (recordFor(receiptV1).check as Record<string, unknown>);
    expect(
      codeOf(() => parseCaptureRecord({ ...recordFor(receiptV1), check: { ...check, policyVersion: 2 } })),
    ).toBe('UNSUPPORTED_VERSION');
    expect(
      codeOf(() => parseCaptureRecord({ ...recordFor(receiptV1), check: { ...check, receiptFormatVersion: 3 } })),
    ).toBe('UNSUPPORTED_VERSION');
  });

  it('reads a v2 original only for a record that says it was checked against v2', () => {
    expect(parseCaptureRecord(recordFor(receiptV2, {}, { receiptFormatVersion: 2 })).check.receiptFormatVersion).toBe(2);
    const parsed = parseCaptureRecord(recordFor(receiptV2, {}, { receiptFormatVersion: 2 }));
    expect(parsed.check.receiptFormatVersion).toBe(2);
  });

  it('refuses a member capture v1 does not define', () => {
    const record = { ...recordFor(receiptV1), retentionDuty: '19(1)' };
    expect(codeOf(() => parseCaptureRecord(record))).toBe('NOT_CAPTURE_RECORD');
    const inOriginal = { ...recordFor(receiptV1), original: { ...recordFor(receiptV1).original as object, met: true } };
    expect(codeOf(() => parseCaptureRecord(inOriginal))).toBe('NOT_CAPTURE_RECORD');
  });

  it('refuses a source kind it has no reading for', () => {
    const record = recordFor(receiptV1);
    const original = record.original as Record<string, unknown>;
    expect(
      codeOf(() => parseCaptureRecord({ ...record, original: { ...original, sourceKind: 'http-response' } })),
    ).toBe('NOT_CAPTURE_RECORD');
  });
});

describe('the published schema and the reader decide the same documents', () => {
  const schemaPath = fileURLToPath(new URL('../schemas/capture-v1.schema.json', import.meta.url));
  const ajv = new Ajv2020({ strict: true });
  const validate = ajv.compile(JSON.parse(readFileSync(schemaPath, 'utf8')) as object) as ValidateFunction<unknown>;

  const accepted: Array<[string, Record<string, unknown>]> = [
    ['a whole record', recordFor(receiptV1)],
    ['a v2 original', recordFor(receiptV2, {}, { receiptFormatVersion: 2 })],
    ['no collateral at the source', recordFor(receiptV1, { context: { collateral: { presence: 'absent-at-source', reason: 'none served' }, validity: { presence: 'not-taken-in', reason: 'not read' } } })],
    ['no policy digest', recordFor(receiptV1, { check: { ...(recordFor(receiptV1).check as object), policyDigest: null } })],
    ['an unnamed root', recordFor(receiptV1, { trust: { roots: [{ family: 'amdArks', digest: null }], limits: { maxReceiptAgeSeconds: null, maxEvidenceAgeSeconds: null } } })],
  ];

  for (const [name, record] of accepted) {
    it(`agrees that the schema and the reader both take ${name}`, () => {
      expect(validate(record)).toBe(true);
      expect(() => parseCaptureRecord(record)).not.toThrow();
    });
  }

  const refused: Array<[string, Record<string, unknown>]> = [
    ['a verdict field', { ...recordFor(receiptV1), verified: true }],
    ['an absent context member', (() => { const r = recordFor(receiptV1); delete r['context']; return r; })()],
    ['a missing reason for an absence', recordFor(receiptV1, { context: { collateral: { presence: 'absent-at-source' }, validity: held(TEXT('x')) } })],
    ['a non-hex digest', recordFor(receiptV1, { original: { ...(recordFor(receiptV1).original as object), sha256: 'zz'.repeat(32) } })],
    ['an unknown presence state', recordFor(receiptV1, { context: { collateral: { presence: 'lost', reason: 'gone' }, validity: held(TEXT('x')) } })],
    ['a second manifest role', recordFor(receiptV1, { manifests: { deployment: held(manifestBytes), models: held(manifestBytes) } })],
    ['a negative acquisition time', recordFor(receiptV1, { acquired: { at: -1, sourceStatedAt: null } })],
    ['an unimplementable version', { ...recordFor(receiptV1), v: 3 }],
  ];

  for (const [name, record] of refused) {
    it(`agrees that neither takes ${name}`, () => {
      expect(validate(record)).toBe(false);
      expect(() => parseCaptureRecord(record)).toThrow();
    });
  }

  it('keeps the manifest a manifest, so a held slot is a document and not a blob', () => {
    expect(parseManifest(JSON.parse(new TextDecoder().decode(manifestBytes)) as unknown).keys[0]?.kid).toBe(KID);
    const record = recordFor(receiptV1);
    expect(parseCaptureRecord(record).manifests.deployment.presence).toBe('held');
  });

  it('keys a record by what it holds, so a retry is one record and a re-encoding is another', () => {
    const honest = parseCaptureRecord(recordFor(receiptV1));
    // A document that says the same thing with its members written in the other order is the same
    // capture, so a collector may retry one as many times as it likes.
    expect(captureRecordKey(parseCaptureRecord(reverseKeyOrder(recordFor(receiptV1))))).toBe(captureRecordKey(honest));
    expect(captureRecordKey(parseCaptureRecord(recordFor(receiptV2, {}, { receiptFormatVersion: 2 })))).not.toBe(
      captureRecordKey(honest),
    );
    // The instant the bytes were taken in is part of the record, so a second capture of the same
    // document is a second record rather than a retry of the first.
    expect(
      captureRecordKey(parseCaptureRecord(recordFor(receiptV1, { acquired: { at: NOW + 1, sourceStatedAt: NOW - 25 } }))),
    ).not.toBe(captureRecordKey(honest));
  });
});

/** The same document with every object's members written in the opposite order. */
function reverseKeyOrder(value: unknown): unknown {
  if (Array.isArray(value)) return value.map((entry) => reverseKeyOrder(entry));
  if (value !== null && typeof value === 'object') {
    const source = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(source).reverse()) out[key] = reverseKeyOrder(source[key]);
    return out;
  }
  return value;
}
