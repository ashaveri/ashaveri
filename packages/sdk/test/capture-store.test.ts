import { describe, expect, it } from 'vitest';
import { equalBytes, generateSigningKey, issueReceipt, toBase64Url, toHex, type ReceiptPayload } from '@ashaveri/receipt';
import { sha256 } from '@noble/hashes/sha2.js';
import { captureRecordKey, parseCaptureRecord, type CaptureRecord, type CaptureSink } from '../src/capture.js';
import { fromBase64Url } from '../src/b64.js';

/**
 * Durability, acknowledged only when it has happened.
 *
 * `CaptureSink` is an interface with one promise: `write` resolves after the original bytes and the
 * context they were appraised in are both durable, or it rejects. This is the implementation that proves
 * the promise is the shape of the thing and not a sentence in a source file. It is in-memory, staged part
 * by part, and it can be made to give up at a named part, which is the only way anybody can see what the
 * acknowledgement is standing on.
 */

const KEY = generateSigningKey();
const NOW = 1_800_000_000;
const TEXT = (value: string): Uint8Array => new TextEncoder().encode(value);

const PAYLOAD: ReceiptPayload = {
  v: 1,
  iss: 'ashaveri-test',
  ins: 'cvm-test-1',
  iat: NOW - 20,
  nce: new Uint8Array(16).fill(7),
  req: sha256(TEXT('the canonical request bytes')),
  res: sha256(TEXT('the full response bytes')),
  mdl: 'test/model-1',
  wts: sha256(TEXT('the deployment manifest digest input')),
  meas: { tee: 'snp', m: new Uint8Array(48).fill(3) },
  att: { d: sha256(TEXT('the evidence document')), ts: NOW - 25, url: 'https://gateway.test/evidence' },
  epk: 1,
  tok: { p: 11, c: 22 },
};

const receipt = issueReceipt(PAYLOAD, KEY);

function held(bytes: Uint8Array): Record<string, unknown> {
  return { presence: 'held', bytes: toBase64Url(bytes), sha256: toHex(sha256(bytes)), byteCount: bytes.length };
}

function recordFor(original: Uint8Array, acquiredAt: number): Record<string, unknown> {
  return {
    v: 1,
    original: {
      sourceKind: 'receipt',
      sourceId: 'cvm-test-1',
      // The original block states its own bytes and digest: it is not a slot, and it has no presence to
      // give it, because a capture with no original is not a capture.
      bytes: toBase64Url(original),
      sha256: toHex(sha256(original)),
      byteCount: original.length,
      signedBySource: true,
      signatureEmbedded: true,
    },
    acquired: { at: acquiredAt, sourceStatedAt: acquiredAt - 5 },
    manifests: { deployment: held(TEXT('{"v":1}')) },
    check: {
      policyVersion: 1,
      policyDigest: toHex(sha256(TEXT('the policy document'))),
      receiptFormatVersion: 1,
      verifierVersion: '0.1.0',
      appraisedAt: acquiredAt,
    },
    context: { collateral: held(TEXT('the vendor chain')), validity: held(TEXT('the appraisal')) },
    trust: {
      roots: [{ family: 'amdArks', digest: toHex(sha256(TEXT('a pinned vendor root'))) }],
      limits: { maxReceiptAgeSeconds: 300, maxEvidenceAgeSeconds: 900 },
    },
  };
}

/** What one durable capture has to put on disk, in the order this implementation puts it there. */
const PARTS = ['original bytes', 'manifests', 'collateral', 'validity context', 'the record itself'] as const;
type Part = (typeof PARTS)[number];

class StagedSink implements CaptureSink {
  private readonly stored = new Map<string, CaptureRecord>();
  private readonly reached = new Map<Part, number>();
  /** What this store has acknowledged. Nothing lands here before every part is durable. */
  readonly acknowledged: string[] = [];
  private failure: Part | null = null;

  giveUpWhileWriting(part: Part | null): void {
    this.failure = part;
  }

  partsReached(part: Part): number {
    return this.reached.get(part) ?? 0;
  }

  get readableRecords(): number {
    return this.stored.size;
  }

  async write(record: CaptureRecord): Promise<'durable' | 'already-durable'> {
    const key = captureRecordKey(record);
    if (this.stored.has(key)) return 'already-durable';
    const staged: Part[] = [];
    for (const part of PARTS) {
      if (part === this.failure) {
        this.failure = null;
        // The bytes may already be on disk. What is withheld is the acknowledgement, because a capture
        // this reader could assess does not exist until the last of its parts does.
        throw new Error(`the store gave up while writing ${part}`);
      }
      staged.push(part);
      this.reached.set(part, (this.reached.get(part) ?? 0) + 1);
    }
    this.stored.set(key, record);
    this.acknowledged.push(...staged);
    return 'durable';
  }

  async read(key: string): Promise<CaptureRecord | null> {
    return this.stored.get(key) ?? null;
  }
}

describe('a capture becomes durable in one piece or not at all', () => {
  it('acknowledges only after every part reached the store', async () => {
    const sink = new StagedSink();
    const record = parseCaptureRecord(recordFor(receipt, NOW));
    await expect(sink.write(record)).resolves.toBe('durable');
    expect(sink.acknowledged).toEqual([...PARTS]);
    expect(sink.readableRecords).toBe(1);
  });

  it('hands back the stored original byte for byte after it comes out of the store', async () => {
    const sink = new StagedSink();
    const record = parseCaptureRecord(recordFor(receipt, NOW));
    const key = captureRecordKey(record);
    await sink.write(record);
    const readBack = await sink.read(key);
    if (readBack === null) throw new Error('the store acknowledged a record it does not hold');
    const stored = fromBase64Url(readBack.original.bytes);
    expect(equalBytes(stored, receipt)).toBe(true);
    expect(toHex(sha256(stored))).toBe(toHex(sha256(receipt)));
    // The key is the record's identity, and it is computed over what the store holds rather than over a
    // name somebody gave the file.
    expect(captureRecordKey(readBack)).toBe(key);
    expect(await sink.read('nothing-else-is-here')).toBeNull();
  });

  it('gives up without acknowledging when a context part never reached disk', async () => {
    const sink = new StagedSink();
    sink.giveUpWhileWriting('validity context');
    const record = parseCaptureRecord(recordFor(receipt, NOW));
    await expect(sink.write(record)).rejects.toThrow('gave up while writing validity context');
    // The original bytes went out first, and that is honest: a store may write in any order. What it may
    // not do is say the capture is durable, and nothing here does.
    expect(sink.partsReached('original bytes')).toBe(1);
    expect(sink.acknowledged).toEqual([]);
    expect(sink.readableRecords).toBe(0);
    expect(await sink.read(captureRecordKey(record))).toBeNull();
  });

  it('retries a failed capture and lands one record, not two', async () => {
    const sink = new StagedSink();
    const record = parseCaptureRecord(recordFor(receipt, NOW));
    sink.giveUpWhileWriting('collateral');
    await expect(sink.write(record)).rejects.toThrow();
    await expect(sink.write(record)).resolves.toBe('durable');
    expect(sink.readableRecords).toBe(1);
    expect(sink.partsReached('original bytes')).toBe(2);
  });

  it('treats a retry of the same capture as the record it already holds', async () => {
    const sink = new StagedSink();
    const record = parseCaptureRecord(recordFor(receipt, NOW));
    await expect(sink.write(record)).resolves.toBe('durable');
    await expect(sink.write(record)).resolves.toBe('already-durable');
    // One copy on disk: the second call never reached a part, so a collector may retry as often as it
    // likes without duplicating an evidence file.
    expect(sink.partsReached('original bytes')).toBe(1);
    expect(sink.readableRecords).toBe(1);
  });

  it('writes the same capture twice from two documents that say the same thing', async () => {
    const sink = new StagedSink();
    const first = parseCaptureRecord(recordFor(receipt, NOW));
    const second = parseCaptureRecord(JSON.parse(JSON.stringify(recordFor(receipt, NOW))) as unknown);
    await sink.write(first);
    await expect(sink.write(second)).resolves.toBe('already-durable');
    expect(sink.readableRecords).toBe(1);
  });

  it('keeps two captures of one document taken at two instants apart', async () => {
    const sink = new StagedSink();
    await sink.write(parseCaptureRecord(recordFor(receipt, NOW)));
    await expect(sink.write(parseCaptureRecord(recordFor(receipt, NOW + 1)))).resolves.toBe('durable');
    expect(sink.readableRecords).toBe(2);
  });
});
