import { toHex } from './digest.js';
import {
  DEFAULT_RECEIPT_RECORD_KIND,
  openFileReceiptStore,
  readReceiptStoreCheckpoint,
  type ReceiptRecordKind,
  type ReceiptStoreCheckpoint,
} from './store.js';

/**
 * Reading the evidence a deployment's store already holds for a retention assessment.
 *
 * `assessRetention` reads a `retention-assessment-v1` document and `produceRetentionAssessment` assembles one
 * from evidence; this module is the door between a live store and that evidence. It opens a store directory
 * through the store's own opening and reads the checkpoint through the store's own sidecar loader, then reports
 * what those two answer as the coverage a producer can write up. It re-implements no record framing and no
 * block parser: the only bytes it reads for itself are the sidecar's, and that only through
 * `readReceiptStoreCheckpoint`, which chains from the loader every normal opening already uses.
 *
 * The scope is the deployment's declaration, not this reader's arithmetic: the subject, the duty, the period,
 * the intake range, the checkpoint schedule and the expected head are handed in, because a store directory
 * holds none of them. The clock basis is the one thing this reader copies rather than accepts: it is the
 * source the store was opened with, stated by `timeSource`, so an assessment rests on the same bound the
 * receipts were stamped under. The checkpoint is the store's own statement - where it states one, that
 * checkpoint is the evidence; where it states none, the evidence says so by leaving the receipts empty and
 * offering only a span, which the reader over it reads as indeterminate rather than a pass.
 *
 * The shape returned mirrors the published assessment scope and coverage member for member, written here
 * because a gateway that imported those types from another package would be a gateway that reached outside
 * this repository's signing stack. The composition from this evidence into a document, and the reading of that
 * document, belong to a caller that holds both the store and the assessment reader; this evidence reader
 * states no verdict about the store.
 */

/** An inclusive range of intake sequences, or of unix seconds for a period and a span. */
export interface EvidenceRange {
  readonly from: number;
  readonly to: number;
}

/** One checkpoint receipt: the sequence range it covers, the instant it was taken and the head it names. */
export interface EvidenceCheckpointReceipt {
  readonly range: EvidenceRange;
  readonly at: number;
  readonly head: string;
}

/** The head the intake observed, beside the expected head the scope pins. */
export interface EvidenceObservedHead {
  readonly sequence: number;
  readonly sha256: string;
}

/** The two ends a span can state, with the head at each. */
export interface EvidenceSpan {
  readonly from: number;
  readonly to: number;
  readonly oldestHead: string;
  readonly newestHead: string;
}

/** The head the scope expects and who pinned it, spelled the way the assessment layout enumerates it. */
export interface EvidenceExpectedHead {
  readonly sha256: string | null;
  readonly pinnedBy: 'customer' | 'external-holder' | 'subject' | 'none';
  readonly reason: string | null;
}

/** The declared scope, copied from the deployment's request. */
export interface EvidenceScope {
  readonly subject: { readonly kind: 'deployment' | 'provider'; readonly id: string };
  readonly duty: { readonly article: '19(1)' | '19(2)' | '26(6)'; readonly requiredSeconds: number };
  readonly period: EvidenceRange;
  readonly intake: { readonly from: number; readonly to: number; readonly expectedHead: EvidenceExpectedHead };
  readonly checkpoint: { readonly holder: 'customer'; readonly eachCompletedBatch: true; readonly maxIntervalSeconds: number };
  readonly timeBasis: { readonly source: string; readonly uncertaintySeconds: number | null };
  readonly excludes: readonly string[];
}

/** What the store observed, in the order the coverage block writes it. */
export interface EvidenceCoverage {
  readonly runs: readonly EvidenceRange[];
  readonly acknowledged: readonly EvidenceRange[];
  readonly checkpoints: readonly EvidenceCheckpointReceipt[];
  readonly observedHead: EvidenceObservedHead | null;
  readonly span: EvidenceSpan | null;
  readonly gaps: readonly (EvidenceRange & { readonly reason: string })[];
  readonly duplicates: readonly { readonly sequence: number; readonly count: number }[];
  readonly rollbacks: readonly { readonly sequence: number; readonly observedHead: string; readonly restoredHead: string }[];
  readonly suffixLoss: (EvidenceRange & { readonly reason: string }) | null;
}

/** The evidence a producer assembles a document from: a declared scope and the store's observed coverage. */
export interface RetentionEvidence {
  readonly scope: EvidenceScope;
  readonly coverage: EvidenceCoverage;
}

/** What a caller hands this reader: the store to open and the scope the deployment declares about it. */
export interface ReadRetentionEvidenceRequest {
  readonly dir: string;
  /** The receipt record kind the store writes, so the checkpoint is read for the right log. */
  readonly receiptKind?: ReceiptRecordKind;
  /** How the store is configured: when the deployment declines its index, the evidence states no checkpoint. */
  readonly sidecarIndex?: boolean;
  readonly subject: EvidenceScope['subject'];
  readonly duty: EvidenceScope['duty'];
  readonly period: EvidenceRange;
  /** The intake range the assessment is about. Absent means the range the store's own records span. */
  readonly intake?: { readonly from: number; readonly to: number };
  readonly expectedHead: EvidenceExpectedHead;
  readonly maxIntervalSeconds: number;
  readonly excludes?: readonly string[];
}

/** The store's answers and the checkpoint it states, read once and shared by the two coverage shapes. */
interface StoreReading {
  readonly window: { readonly from: number; readonly to: number; readonly count: number };
  readonly head: Uint8Array;
  readonly anchor: Uint8Array;
  readonly source: string;
  readonly uncertaintySeconds: number | null;
  readonly checkpoint: ReceiptStoreCheckpoint;
}

/**
 * Opens the store through its own opening and reads its checkpoint through its own sidecar loader.
 *
 * The store is opened before the checkpoint is read so that a deployment which keeps an index is seen to keep
 * it: the opening leaves that index speaking for the whole file, and the loader then reports the checkpoint an
 * opening of this store would resume from. A declined index is a store with no index on the volume, and the
 * loader answers `present: false` for it without a second read.
 */
async function readOnce(
  request: ReadRetentionEvidenceRequest,
  receiptKind: ReceiptRecordKind,
): Promise<StoreReading> {
  const store = await openFileReceiptStore({
    dir: request.dir,
    receiptKind,
    ...(request.sidecarIndex === undefined ? {} : { sidecarIndex: request.sidecarIndex }),
  });
  const window = await store.window();
  const head = await store.head();
  const chain = await store.chainState();
  const time = store.timeSource();
  const checkpoint = await readReceiptStoreCheckpoint(request.dir, receiptKind);
  return {
    window,
    head,
    anchor: chain.anchor,
    source: time.name,
    uncertaintySeconds: time.uncertaintySeconds,
    checkpoint,
  };
}

/** The coverage a store whose index states a checkpoint gives: one run, acknowledged, and its one receipt. */
function coverageFromCheckpoint(reading: StoreReading): EvidenceCoverage {
  const checkpoint = reading.checkpoint;
  const range: EvidenceRange = { from: checkpoint.firstSequence, to: checkpoint.lastSequence };
  const receipt: EvidenceCheckpointReceipt = { range, at: checkpoint.at, head: checkpoint.head };
  return {
    runs: [range],
    acknowledged: [range],
    checkpoints: [receipt],
    observedHead: { sequence: checkpoint.lastSequence, sha256: checkpoint.head },
    span: null,
    gaps: [],
    duplicates: [],
    rollbacks: [],
    suffixLoss: null,
  };
}

/** The coverage a store that states no checkpoint gives: a span between its oldest and newest survivors. */
function coverageFromSpan(reading: StoreReading): EvidenceCoverage {
  if (reading.window.count === 0) {
    return { runs: [], acknowledged: [], checkpoints: [], observedHead: null, span: null, gaps: [], duplicates: [], rollbacks: [], suffixLoss: null };
  }
  const span: EvidenceSpan = {
    from: reading.window.from,
    to: reading.window.to,
    oldestHead: toHex(reading.anchor),
    newestHead: toHex(reading.head),
  };
  return { runs: [], acknowledged: [], checkpoints: [], observedHead: null, span, gaps: [], duplicates: [], rollbacks: [], suffixLoss: null };
}

/**
 * Reads a store directory as retention assessment evidence.
 *
 * The scope is the caller's declaration with the store's own clock basis beside it; the coverage is what the
 * store answers. A store whose sidecar states a checkpoint yields a sequence run the store observed, the same
 * range acknowledged, that one checkpoint, and the head it closed on; a store that states none yields a span
 * between its oldest and newest survivors and nothing else, and a store that holds nothing yields no coverage
 * at all. None of those three is a verdict: each is the evidence, which the reader over the produced document
 * weighs. A broken chain, a mixture of record kinds, or any other opening refusal comes back from the store
 * unchanged, because there is no honest assessment of a store that cannot tell what it holds.
 */
export async function readRetentionEvidence(request: ReadRetentionEvidenceRequest): Promise<RetentionEvidence> {
  const receiptKind = request.receiptKind ?? DEFAULT_RECEIPT_RECORD_KIND;
  const reading = await readOnce(request, receiptKind);
  const checkpoint = reading.checkpoint;
  const coverage = checkpoint.present ? coverageFromCheckpoint(reading) : coverageFromSpan(reading);
  const intake = request.intake ?? (checkpoint.present ? { from: checkpoint.firstSequence, to: checkpoint.lastSequence } : { from: 0, to: 0 });
  const scope: EvidenceScope = {
    subject: request.subject,
    duty: request.duty,
    period: request.period,
    intake: { from: intake.from, to: intake.to, expectedHead: request.expectedHead },
    checkpoint: { holder: 'customer', eachCompletedBatch: true, maxIntervalSeconds: request.maxIntervalSeconds },
    timeBasis: { source: reading.source, uncertaintySeconds: reading.uncertaintySeconds },
    excludes: request.excludes ?? [],
  };
  return { scope, coverage };
}
