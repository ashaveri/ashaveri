import { toHex } from './digest.js';
import {
  DEFAULT_RECEIPT_RECORD_KIND,
  openFileReceiptStore,
  readReceiptStoreCheckpoint,
  type ReceiptRecordKind,
  type ReceiptRetention,
  type ReceiptServing,
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
 *
 * Two things this reader owes the directory it opens, because opening it is a second opening of the store the
 * deployment serves from. It opens under the bounds that deployment configured, so an opening the gateway
 * would refuse at startup is refused here rather than read past, and the window the evidence reports is the
 * one the deployment retains rather than the wider span still on the volume. And it declines the sidecar index
 * unless the caller asks for it by name, because a reader of evidence has no business writing it: an ordinary
 * opening bootstraps an index beside the operator's log, and a command that came to look at a directory should
 * not have changed it.
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
  /**
   * The deployment's durability bound, forwarded into the opening. An assessment is a statement about what
   * that deployment keeps and serves, and a store opened without this bound is a store whose pruning this
   * reader did not do: it would report a wider span than the gateway holds as though the deployment held it.
   *
   * Absent is not a bound of no length. Every field of `ReceiptRetention` is optional, and each absent one
   * is documented as nothing aging out or nothing shed by count, so passing the object is not the same as
   * passing a bound and the evidence says, of itself, whether it was given one.
   */
  readonly retention?: ReceiptRetention;
  /**
   * The deployment's serving bound, forwarded with it. This one retires nothing and shortens no window - it
   * sizes how many records one walk holds - so it cannot widen what an assessment reads, and it travels here
   * because the opening is the deployment's own, and because the refusal this pairing raises names the number
   * an operator must not raise when it is configured.
   */
  readonly serving?: ReceiptServing;
  /**
   * Asks the store to keep and use its sidecar index, which an opening then writes where the volume does not
   * already hold one. Absent, or false, declines it: the door then touches only `receipts.log`, and a reader
   * of evidence leaves the directory it read as it found it.
   *
   * Declining does not hide a checkpoint the deployment keeps. The checkpoint the evidence reports is the one
   * already on the volume, read through the store's own loader, so a deployment that keeps an index is seen
   * to keep it whether or not this reader asked for one, and a deployment that declined it is seen to state
   * no temporal witness rather than a broken one.
   */
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
 * Opens the store under the deployment's own bounds and reads the checkpoint already on the volume.
 *
 * The bounds travel into the opening because this is a second opening of the same directory. DU-3.8 settled
 * the question for the serving process, where a store at its count bound derives the count its configured
 * period needs and refuses to open rather than serve a window it cannot hold; a door that opened without the
 * pairing would assess records that deployment would have pruned, and would reach past the rule for nothing
 * more than a look. Whatever the store answers to that opening - including a refusal - is what the evidence is
 * made of, because an honest assessment of a store the gateway would not start is not an assessment at all.
 *
 * The store is opened before the checkpoint is read so that a deployment which keeps an index is seen to keep
 * it: the loader reports the checkpoint an opening of this store would resume from. This opening declines the
 * index unless the caller asked for it by name, so it neither bootstraps one into the operator's directory
 * nor leaves a file there that was not there when the read began, and a deployment that runs without an index
 * is read as a store with no index on the volume, which the loader answers as no checkpoint.
 */
async function readOnce(
  request: ReadRetentionEvidenceRequest,
  receiptKind: ReceiptRecordKind,
): Promise<StoreReading> {
  const store = await openFileReceiptStore({
    dir: request.dir,
    receiptKind,
    retention: request.retention,
    serving: request.serving,
    // Declined by default, and asked for by name: the default for the store's own option is to keep the
    // index, and an opening that keeps one writes it where the volume does not hold it yet.
    sidecarIndex: request.sidecarIndex === true,
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
 * weighs. A broken chain, a mixture of record kinds, a pairing of durability bound and period that the
 * gateway would refuse to start on, or any other opening refusal comes back from the store unchanged, because
 * there is no honest assessment of a store that cannot tell what it holds.
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
