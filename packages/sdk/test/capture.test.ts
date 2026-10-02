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
import { captureRecordKey, COLLATERAL_WEIGHED_BY, parseCaptureRecord, SOURCE_KINDS } from '../src/capture.js';
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

function receiptPayload(at: number): ReceiptPayload {
  return {
    v: 1,
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
    mk: { sch: 'none' as const, d: sha256(emptyRegion()) },
    sd: { name: 'fixture clock', uncertaintySeconds: 2 },
    cva: {
      collateral: { presence: 'not-taken-in', reason: 'the issuance took no collateral in' },
      validity: { presence: 'not-taken-in', reason: 'the issuance recorded no validity window' },
    },
    itm: [
      { t: at, d: sha256(TEXT('the first item of the response')) },
      { t: at + 1, d: sha256(TEXT('the second item of the response')) },
    ],
  };
}

const receiptV1 = issueReceipt(receiptPayload(NOW - 20), KEY);
const secondReceipt = issueReceipt(receiptPayload(NOW - 19), KEY);

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

const chainHeader = TEXT('TCB-Info-Issuer-Chain: -----BEGIN CERTIFICATE-----');

const held = (bytes: Uint8Array): Record<string, unknown> => ({
  presence: 'held',
  bytes: toBase64Url(bytes),
  sha256: toHex(sha256(bytes)),
  byteCount: bytes.length,
});

/**
 * The whole statement a held collateral slot makes about the answer it took in, beside the bytes.
 *
 * The address and the key are the spellings this estate's own declaration for that source produces, so a
 * fixture cannot state a route or a member name the repository has never named; the values inside them are
 * this test's, and no vendor byte is here.
 */
function collateralObservation(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    ...held(TEXT('the vendor certificate chain as served')),
    origin: 'intel-tcb-info',
    request: 'https://api.trustedservices.intel.com/sgx/certification/v4/tcb?fmspc=00906f000200',
    identity: { cpuType: '00906f000200', vendorStatus: 'UpToDate' },
    observedAt: NOW - 30,
    sourceUncertaintySeconds: 2,
    chainSha256: toHex(sha256(chainHeader)),
    chainBytes: toBase64Url(chainHeader),
    weighedBy: 'served',
    window: { from: 1_735_689_600, to: 1_798_761_600 },
    cacheKey: 'origin=intel-tcb-info|platform=sgx|cpuType=00906f000200|level=tcb-date=2024-05-15T00:00:00Z',
    ...over,
  };
}

/** The same record with one collateral slot in it, however shaped. */
function withCollateral(slot: Record<string, unknown>): Record<string, unknown> {
  const record = recordFor(receiptV1);
  return { ...record, context: { ...(record['context'] as Record<string, unknown>), collateral: slot } };
}

/** A whole record that assesses clean, with the top-level blocks a test can replace one at a time. */
function recordFor(
  original: Uint8Array,
  over: Record<string, unknown> = {},
  block: { readonly receiptFormatVersion?: number } = {},
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
    context: { collateral: collateralObservation(), validity: held(TEXT('the appraisal record')) },
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
    expect(() => verifyReceipt(stored, { publicKey: KEY.publicKey, nowSeconds: NOW })).not.toThrow();
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
    expect(codeOf(() => verifyReceipt(equivalent, { publicKey: KEY.publicKey, nowSeconds: NOW }))).toBe('MALFORMED_CBOR');
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

/**
 * The code and the sentence a refusal answers with, both read off the throw.
 *
 * The message is the half that carries the member's name, and a caller who is told only that a code was
 * raised cannot find out which of a slot's ten statements it left out.
 */
function refusalOf(fn: () => unknown): { readonly code: string; readonly message: string } {
  try {
    fn();
  } catch (err) {
    if (err instanceof SdkError || err instanceof ReceiptError) return { code: err.code, message: err.message };
    throw err;
  }
  throw new Error('the reader took the record, and nothing refused it');
}

/** Every member a held collateral slot owes, the eight that decide what the bytes are an answer to. */
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

describe('a held collateral slot states the answer its bytes are', () => {
  for (const member of OBSERVATION_MEMBERS) {
    it(`refuses a held collateral slot that holds bytes and states no ${member}`, () => {
      // One deletion at a time off a slot the writer accepts, so each case tests a reader's rule rather
      // than the shape of a fixture. The message names the member that is missing, not the slot.
      const slot = collateralObservation();
      delete slot[member];
      const refusal = refusalOf(() => parseCaptureRecord(withCollateral(slot)));
      expect(refusal.code, `a collateral slot with no ${member}`).toBe('NOT_CAPTURE_RECORD');
      expect(refusal.message).toContain(`context.collateral.${member}`);
    });
  }

  it('refuses chain bytes with no digest beside them, and the reverse', () => {
    for (const missing of ['chainSha256', 'chainBytes'] as const) {
      const slot = collateralObservation();
      delete slot[missing];
      const refusal = refusalOf(() => parseCaptureRecord(withCollateral(slot)));
      expect(refusal.code, `a chain stated with its ${missing} left out`).toBe('NOT_CAPTURE_RECORD');
      expect(refusal.message).toContain(`context.collateral.${missing}`);
    }
    // Neither of the two is a statement about a chain at all, and that is a reading, not a hole.
    const noChain = collateralObservation();
    delete noChain['chainSha256'];
    delete noChain['chainBytes'];
    expect(codeOf(() => parseCaptureRecord(withCollateral(noChain)))).toBeUndefined();
  });

  it('refuses an observed instant that is not a whole number of seconds', () => {
    for (const stated of [NOW - 30.5, -1, `${NOW - 30}`, null, Number.NaN]) {
      expect(
        refusalOf(() => parseCaptureRecord(withCollateral(collateralObservation({ observedAt: stated })))).code,
        `observedAt spelled ${String(stated)}`,
      ).toBe('NOT_CAPTURE_RECORD');
    }
    expect(codeOf(() => parseCaptureRecord(withCollateral(collateralObservation({ observedAt: 0 })))))
      .toBeUndefined();
  });

  it('recomputes the digest a chain states, and refuses a second spelling of one header', () => {
    expect(
      refusalOf(() =>
        parseCaptureRecord(withCollateral(collateralObservation({ chainSha256: 'f'.repeat(64) }))),
      ).code,
      'a chain digest that names no bytes beside it',
    ).toBe('EVIDENCE_DIGEST_MISMATCH');
    // One byte, two unpadded base64url spellings, both decoding to it: the reader holds the same rule for
    // a chain as for an original, because a chain written by a second encoder is a chain nobody watched.
    const oneByte = new Uint8Array([0xff]);
    const canonical = toBase64Url(oneByte);
    const reSpelled = `${canonical.slice(0, canonical.length - 1)}x`;
    expect(equalBytes(fromBase64Url(canonical), fromBase64Url(reSpelled))).toBe(true);
    const refusal = refusalOf(() =>
      parseCaptureRecord(
        withCollateral(collateralObservation({ chainBytes: reSpelled, chainSha256: toHex(sha256(oneByte)) })),
      ),
    );
    expect(refusal.code).toBe('NOT_CAPTURE_RECORD');
    expect(refusal.message).toContain('chainBytes');
  });

  it('refuses an absence that states part of an observation, or bytes at all', () => {
    // Every member only a holding slot can state: the three that describe its bytes, the eight that say
    // what answer those bytes are, and the chain's two halves. The reader's loop runs over all thirteen,
    // and an absence borrowing any of them is the same lie however it is spelled.
    for (const member of [
      ...OBSERVATION_MEMBERS,
      'chainBytes',
      'chainSha256',
      'bytes',
      'sha256',
      'byteCount',
    ] as const) {
      const stated: Record<string, unknown> = {
        presence: 'absent-at-source',
        reason: 'the source served no answer at all',
      };
      stated[member] = collateralObservation()[member];
      const refusal = refusalOf(() => parseCaptureRecord(withCollateral(stated)));
      expect(refusal.code, `an absent slot carrying '${member}'`).toBe('NOT_CAPTURE_RECORD');
      expect(refusal.message).toContain(member);
    }
  });

  it('refuses a weighing outside the two, an identity with a member it does not define, and a window with no end', () => {
    const refusals: Array<[string, Record<string, unknown>]> = [
      ['a weighing nobody uses', collateralObservation({ weighedBy: 'guessed' })],
      ['an identity stating a member no record defines', collateralObservation({ identity: { cpuType: 'a', vendorStatus: 'UpToDate', tcbDate: 'now' } })],
      ['an identity with no status in it', collateralObservation({ identity: { cpuType: 'a' } })],
      ['an identity whose cpu type is an empty name', collateralObservation({ identity: { cpuType: '', vendorStatus: 'UpToDate' } })],
      ['a window stating a member it does not define', collateralObservation({ window: { from: 1, to: 2, until: 3 } })],
      ['a window with no end', collateralObservation({ window: { from: 1 } })],
      ['a window whose half is not whole', collateralObservation({ window: { from: 1.5, to: 2 } })],
      ['a bound that is not a count of seconds', collateralObservation({ sourceUncertaintySeconds: 'wide' })],
      ['an origin named as nothing at all', collateralObservation({ origin: '' })],
      ['a cache key nobody spelled', collateralObservation({ cacheKey: null })],
    ];
    for (const [name, slot] of refusals) {
      expect(refusalOf(() => parseCaptureRecord(withCollateral(slot))).code, name).toBe('NOT_CAPTURE_RECORD');
    }
  });

  it('refuses a bound below zero in every member that carries one', () => {
    // The published document bounds all three of these at zero and the reader refuses each of them there,
    // member by member: an instant, a bound on an instant, and either end of a span.
    for (const [name, slot] of [
      ['a bound of negative seconds', collateralObservation({ sourceUncertaintySeconds: -1 })],
      ['a window beginning before the epoch', collateralObservation({ window: { from: -1, to: 2 } })],
      ['a window ending before the epoch', collateralObservation({ window: { from: 1, to: -1 } })],
    ] as Array<[string, Record<string, unknown>]>) {
      const refusal = refusalOf(() => parseCaptureRecord(withCollateral(slot)));
      expect(refusal.code, name).toBe('NOT_CAPTURE_RECORD');
      expect(refusal.message, name).toContain('non-negative');
    }
    // Zero is a number and not an absence: a bound the source states as none, and a span that begins at
    // the epoch, are both readings, and both are taken.
    expect(
      codeOf(() => parseCaptureRecord(withCollateral(collateralObservation({ sourceUncertaintySeconds: 0 })))),
    ).toBeUndefined();
    expect(codeOf(() => parseCaptureRecord(withCollateral(collateralObservation({ window: { from: 0, to: 1 } })))))
      .toBeUndefined();
  });

  it('refuses a statement block that is not a block, and a chain digest that is not a digest', () => {
    for (const [name, slot] of [
      ['an identity spelled as text', collateralObservation({ identity: 'fmspc 00906F000200' })],
      ['an identity spelled as a list', collateralObservation({ identity: ['cpuType', '00906F000200'] })],
      ['a window spelled as text', collateralObservation({ window: '1735689600' })],
      ['a window whose end is a list', collateralObservation({ window: { from: 1, to: [2] } })],
    ] as Array<[string, Record<string, unknown>]>) {
      expect(refusalOf(() => parseCaptureRecord(withCollateral(slot))).code, name).toBe('NOT_CAPTURE_RECORD');
    }
    // A digest that is not sixty-four lowercase hex characters is refused by the code the record's own
    // bytes are refused by, and named by member: the reader is telling the caller that this document does
    // not account for the material it speaks of, which is the same claim however the hash was mis-stated.
    const malformed = refusalOf(() => parseCaptureRecord(withCollateral(collateralObservation({ chainSha256: 'XYZ' }))));
    expect(malformed.code).toBe('EVIDENCE_DIGEST_MISMATCH');
    expect(malformed.message).toContain('context.collateral.chainSha256');
    // And a header of no bytes is no header, whatever digest stands beside it. The published document
    // refuses the same document for the same reason.
    const empty = refusalOf(() =>
      parseCaptureRecord(
        withCollateral(
          collateralObservation({ chainBytes: '', chainSha256: toHex(sha256(new Uint8Array(0))) }),
        ),
      ),
    );
    expect(empty.code).toBe('NOT_CAPTURE_RECORD');
    expect(empty.message).toContain('context.collateral.chainBytes');
  });

  it('bounds the address a slot states by the bytes a reference carries, not by its characters', () => {
    const base = 'https://api.trustedservices.intel.com/sgx/certification/v4/tcb?fmspc=';
    const atTheCeiling = `${base}${'0'.repeat(2_048 - base.length)}`;
    expect(new TextEncoder().encode(atTheCeiling).length, 'the ceiling is read at its own boundary').toBe(2_048);
    expect(codeOf(() => parseCaptureRecord(withCollateral(collateralObservation({ request: atTheCeiling })))))
      .toBeUndefined();
    const over = refusalOf(() =>
      parseCaptureRecord(withCollateral(collateralObservation({ request: `${atTheCeiling}0` }))),
    );
    expect(over.code).toBe('NOT_CAPTURE_RECORD');
    expect(over.message).toContain('context.collateral.request');
    // The count is of bytes, which is what the container holding an address counts, so an address of a
    // thousand and twenty-five two-byte characters is a record no reference can name even though it is
    // well inside the ceiling spelled as a count of characters. No keyword of the published document
    // counts bytes, so this is one of the rules the reader holds alone.
    const multibyte = `https://x/?a=${'é'.repeat(1_025)}`;
    expect(multibyte.length, 'the address is inside the ceiling as characters').toBeLessThanOrEqual(2_048);
    expect(refusalOf(() => parseCaptureRecord(withCollateral(collateralObservation({ request: multibyte })))).code)
      .toBe('NOT_CAPTURE_RECORD');
  });

  it('asks the eight of the collateral role alone, and binds a held slot\'s shape to every role', () => {
    // Both directions of the rule the published document states as much as it can state it. A slot in any
    // other role is complete at its four members, so the widening costs the validity slot, the signature
    // slot and the deployment manifest nothing; and the rules a held slot's shape is read by bind it
    // wherever it sits, because a chain stated on one side of itself is the same hole in a validity slot
    // that it is in a collateral one.
    const record = recordFor(receiptV1) as Record<string, unknown>;
    const context = (record['context'] as Record<string, unknown>);
    expect(Object.keys(context['validity'] as Record<string, unknown>).sort()).toEqual([
      'byteCount',
      'bytes',
      'presence',
      'sha256',
    ]);
    expect(codeOf(() => parseCaptureRecord(record))).toBeUndefined();
    const oneSided = refusalOf(() =>
      parseCaptureRecord({
        ...record,
        context: { ...context, validity: { ...(context['validity'] as Record<string, unknown>), chainBytes: toBase64Url(chainHeader) } },
      }),
    );
    expect(oneSided.code).toBe('NOT_CAPTURE_RECORD');
    expect(oneSided.message).toContain('context.validity.chainSha256');
    // A validity slot that states the whole observation is taken rather than dropped: the layout makes the
    // ten legal in any held slot and owes them of one role, and only that role's statement reaches a
    // verdict, which the reader's own test in `capture-reader.test.ts` is what pins.
    expect(
      codeOf(() => parseCaptureRecord({ ...record, context: { ...context, validity: collateralObservation() } })),
    ).toBeUndefined();
  });

  it('reads every member a slot states, and hands the eight back as the record\'s own claim', () => {
    const parsed = parseCaptureRecord(withCollateral(collateralObservation()));
    const collateral = parsed.context.collateral;
    expect(collateral.presence).toBe('held');
    if (collateral.presence !== 'held') throw new Error('the slot read as an absence');
    for (const member of OBSERVATION_MEMBERS) {
      expect(collateral[member], `the parsed slot keeps '${member}'`).toBeDefined();
    }
    expect(collateral.origin).toBe('intel-tcb-info');
    expect(collateral.window).toEqual({ from: 1_735_689_600, to: 1_798_761_600 });
    expect(collateral.identity).toEqual({ cpuType: '00906f000200', vendorStatus: 'UpToDate' });
    // The two nulls are statements, not holes: an answer that names no identity and a source nobody
    // measured are both readings a collector is entitled to write down.
    expect(parseCaptureRecord(withCollateral(collateralObservation({ identity: null, sourceUncertaintySeconds: null }))))
      .toBeTruthy();
  });

  it('keeps a record whose collateral slot is absent-at-source readable at every old member', () => {
    // The F2 witness, in code: capture-v1 widened under its own number, so a record that states an absence
    // keeps every member it ever had and gains no obligation. Nothing here reads as a v2 document.
    const absent = { presence: 'absent-at-source', reason: 'the platform served no certificate chain' };
    const parsed = parseCaptureRecord(withCollateral(absent));
    expect(parsed.context.collateral).toEqual(absent);
    expect(parsed.original.sourceKind).toBe('receipt');
    expect(parsed.original.byteCount).toBe(receiptV1.length);
    expect(parsed.acquired).toEqual({ at: NOW, sourceStatedAt: NOW - 25 });
    expect(parsed.manifests.deployment.presence).toBe('held');
    expect(parsed.check.verifierVersion).toBe('0.1.0');
    expect(parsed.trust.limits).toEqual({ maxReceiptAgeSeconds: 300, maxEvidenceAgeSeconds: 900 });
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
    // What this case holds is the boundary above the set the format defines. The payload version the
    // format declares is one, so every integer above it is a version no build of this reader names, and
    // each meets a refusal rather than a reading as the nearest version inside the set. The case below
    // that reads a v1 original is the other half: the number a record names is refused or taken, and no
    // record is ever read at a version it did not name.
    expect(
      codeOf(() => parseCaptureRecord({ ...recordFor(receiptV1), check: { ...check, receiptFormatVersion: 4 } })),
    ).toBe('UNSUPPORTED_VERSION');
  });

  it('refuses a record naming a receipt version this build has no reader for', () => {
    // The format declares one payload version, so a record naming any other number describes a document
    // no reader of these bytes can open. The refusal is the same whichever number above the one is named:
    // the reader answers the version the record claims to have checked rather than re-reading the original
    // at the nearest version it does implement.
    for (const named of [2, 3, 4] as const) {
      expect(
        codeOf(() => parseCaptureRecord(recordFor(receiptV1, {}, { receiptFormatVersion: named }))),
        `a record naming receipt version ${named}`,
      ).toBe('UNSUPPORTED_VERSION');
    }
  });

  it('reads a v1 original for the record that says it was checked against v1', () => {
    const parsed = parseCaptureRecord(recordFor(receiptV1, {}, { receiptFormatVersion: 1 }));
    expect(parsed.check.receiptFormatVersion).toBe(1);
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
  // The document read with the two members this walk compares named in its type, so a schema that loses
  // either is a compile failure in this file rather than an `undefined` sailing through an assertion.
  const schemaDocument = JSON.parse(readFileSync(schemaPath, 'utf8')) as {
    readonly properties: {
      readonly original: { readonly properties: { readonly sourceKind: { readonly enum: string[] } } };
    };
  };
  const validate = ajv.compile(schemaDocument) as ValidateFunction<unknown>;
  const declaredSourceKinds = schemaDocument.properties.original.properties.sourceKind.enum;

  const accepted: Array<[string, Record<string, unknown>]> = [
    ['a whole record', recordFor(receiptV1)],
    ['no collateral at the source', recordFor(receiptV1, { context: { collateral: { presence: 'absent-at-source', reason: 'none served' }, validity: { presence: 'not-taken-in', reason: 'not read' } } })],
    ['no policy digest', recordFor(receiptV1, { check: { ...(recordFor(receiptV1).check as object), policyDigest: null } })],
    ['an unnamed root', recordFor(receiptV1, { trust: { roots: [{ family: 'amdArks', digest: null }], limits: { maxReceiptAgeSeconds: null, maxEvidenceAgeSeconds: null } } })],
    // The two nulls the widening makes meaningful: an answer that names no identity, and a source nobody
    // ever measured. Neither is a hole a reader has to guess at, and both are states a collector writes.
    ['an answer naming no identity and a source nobody measured', withCollateral(collateralObservation({ identity: null, sourceUncertaintySeconds: null }))],
    ['a held collateral slot with no chain beside it', (() => { const slot = collateralObservation(); delete slot['chainSha256']; delete slot['chainBytes']; return withCollateral(slot); })()],
    // The role rule as the published document can state it: the eight are legal in any held slot, so a
    // validity slot stating them is a document both authorities take, and owed by one role alone, which is
    // the half only the reader can enforce.
    ['a validity slot stating the whole observation', (() => { const r = recordFor(receiptV1) as Record<string, unknown>; const c = r['context'] as Record<string, unknown>; return { ...r, context: { ...c, validity: collateralObservation() } }; })()],
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
    // The boundary of the two lists that have to stay in step: `check.receiptFormatVersion` is
    // `enum: [1]` in the published schema and `IMPLEMENTED_RECEIPT_FORMAT_VERSIONS` in the reader, and
    // every integer above that one element is a version `receipt.cddl` no longer defines. Widening one
    // side without the other fails the assertion belonging to the side that moved: a reader list that
    // gains `2` stops throwing on the case below, and a schema enum that gains it stops refusing the same
    // document.
    ['a receipt version no format defines', recordFor(receiptV1, { check: { ...(recordFor(receiptV1).check as object), receiptFormatVersion: 4 } })],
    ['the retired receipt version 2', recordFor(receiptV1, { check: { ...(recordFor(receiptV1).check as object), receiptFormatVersion: 2 } })],
    ['the retired receipt version 3', recordFor(receiptV1, { check: { ...(recordFor(receiptV1).check as object), receiptFormatVersion: 3 } })],
    // The widening, both authorities at once: the eight a held collateral slot owes, the chain that arrives
    // in pairs, and the states an absence may not borrow from a holding slot.
    ['a held collateral slot that names no origin', (() => { const slot = collateralObservation(); delete slot['origin']; return withCollateral(slot); })()],
    ['a held collateral slot that spells no address', (() => { const slot = collateralObservation(); delete slot['request']; return withCollateral(slot); })()],
    ['chain bytes with no digest beside them', (() => { const slot = collateralObservation(); delete slot['chainSha256']; return withCollateral(slot); })()],
    ['a digest with no bytes beside it', (() => { const slot = collateralObservation(); delete slot['chainBytes']; return withCollateral(slot); })()],
    ['an observed instant that is not whole', withCollateral(collateralObservation({ observedAt: NOW - 30.5 }))],
    ['an identity block with a member no record defines', withCollateral(collateralObservation({ identity: { cpuType: 'a', vendorStatus: 'UpToDate', tcbDate: 'now' } }))],
    ['a window with no end stated', withCollateral(collateralObservation({ window: { from: 1 } }))],
    ['a weighing outside the two words', withCollateral(collateralObservation({ weighedBy: 'guessed' }))],
    ['an absence that states an origin', withCollateral({ presence: 'absent-at-source', reason: 'the source served nothing', origin: 'intel-tcb-info' })],
    ['an absence that still holds bytes', withCollateral({ presence: 'not-taken-in', reason: 'the collector read no header', bytes: toBase64Url(chainHeader) })],
    // Three more the widening made documents rather than readings: a bound the published document floors at
    // zero, a header stated as no bytes at all, and the chain pair applied to a slot in another role.
    ['a bound of negative seconds', withCollateral(collateralObservation({ sourceUncertaintySeconds: -1 }))],
    ['a chain header stated as no bytes at all', withCollateral(collateralObservation({ chainBytes: '', chainSha256: toHex(sha256(new Uint8Array(0))) }))],
    ['a validity slot stating half a chain', (() => { const r = recordFor(receiptV1) as Record<string, unknown>; const c = r['context'] as Record<string, unknown>; const v = c['validity'] as Record<string, unknown>; return { ...r, context: { ...c, validity: { ...v, chainSha256: toHex(sha256(chainHeader)) } } }; })()],
  ];

  for (const [name, record] of refused) {
    it(`agrees that neither takes ${name}`, () => {
      expect(validate(record)).toBe(false);
      expect(() => parseCaptureRecord(record)).toThrow();
    });
  }

  it('says what a null window in these limits is, in the words the reader can hold to', () => {
    // A null in one of these two fields names no window; it is not a window that stayed open, which is
    // the reading `assessCapture` carries into its qualification beside its own number. The sentence is
    // part of the published contract: an auditor meets it before meeting the code.
    const schema = JSON.parse(readFileSync(schemaPath, 'utf8')) as {
      properties: { trust: { properties: { limits: { description: string } } } };
    };
    const said = schema.properties.trust.properties.limits.description;
    expect(said).toContain('or null where the check named none of its own');
    expect(said).toContain('A null is not a window that stayed open');
    expect(said, 'the reading this format no longer carries').not.toContain('the window nobody set');
  });

  it('names the same source kinds in the published document as the reader reads', () => {
    // The coupling `check.receiptFormatVersion` has had since its list was written and `sourceKind` never
    // had: the enum above is what a collector outside this repository builds a writer against, and
    // `SOURCE_KINDS` is what the reader and the type are made of. A fifth kind added to the list alone
    // agreed with the type, agreed with the reader, and disagreed with the published document in silence,
    // which is the direction this assertion closes. The order is neither set's business, so both are read
    // sorted.
    expect([...declaredSourceKinds].sort()).toEqual([...SOURCE_KINDS].sort());
    // And the document is the one that refuses, not this test's copy of it: a kind the reader's list does
    // not hold is refused by the schema too, so the two sets can only disagree by one of them moving.
    const unclaimed = recordFor(receiptV1, {
      original: { ...(recordFor(receiptV1).original as object), sourceKind: 'http-response' },
    });
    expect(validate(unclaimed)).toBe(false);
    expect(codeOf(() => parseCaptureRecord(unclaimed))).toBe('NOT_CAPTURE_RECORD');
  });

  it('names the same readings of an answer in the published document as the reader reads', () => {
    // The coupling `sourceKind` gained and nothing else in this layout had: `weighedBy` is a closed set of
    // two words in the schema a collector outside this repository writes against, and a list the reader
    // and its types are made of. A third word added on one side alone is a document one of the two refuses
    // in silence.
    const schema = JSON.parse(readFileSync(schemaPath, 'utf8')) as {
      $defs: { weighedBy: { enum: string[] }; collateralObservation: { required: string[] } };
    };
    expect([...schema.$defs.weighedBy.enum].sort()).toEqual([...COLLATERAL_WEIGHED_BY].sort());
    // The same coupling for the set of members a held collateral slot owes, so a ninth fact added to the
    // reader's list alone shows up here rather than in a deployment.
    expect([...schema.$defs.collateralObservation.required].sort()).toEqual([...OBSERVATION_MEMBERS].sort());
    const third = withCollateral(collateralObservation({ weighedBy: 'assumed' }));
    expect(validate(third)).toBe(false);
    expect(codeOf(() => parseCaptureRecord(third))).toBe('NOT_CAPTURE_RECORD');
  });

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
    expect(captureRecordKey(parseCaptureRecord(recordFor(secondReceipt)))).not.toBe(
      captureRecordKey(honest),
    );
    // The instant the bytes were taken in is part of the record, so a second capture of the same
    // document is a second record rather than a retry of the first.
    expect(
      captureRecordKey(parseCaptureRecord(recordFor(receiptV1, { acquired: { at: NOW + 1, sourceStatedAt: NOW - 25 } }))),
    ).not.toBe(captureRecordKey(honest));
    // And what a collateral slot states about the answer it holds is part of the record too: two documents
    // that agree about every byte and disagree about when the last one landed, or about which address they
    // were asked at, are two captures of two events and no store may merge them.
    const oneAnswer = captureRecordKey(parseCaptureRecord(withCollateral(collateralObservation())));
    expect(captureRecordKey(parseCaptureRecord(withCollateral(collateralObservation({ observedAt: NOW - 31 }))))).not.toBe(
      oneAnswer,
    );
    expect(
      captureRecordKey(
        parseCaptureRecord(withCollateral(collateralObservation({ request: 'https://api.trustedservices.intel.com/sgx/certification/v4/tcb' }))),
      ),
    ).not.toBe(oneAnswer);
    expect(captureRecordKey(parseCaptureRecord(withCollateral(collateralObservation())))).toBe(oneAnswer);
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
