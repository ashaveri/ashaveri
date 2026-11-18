import { spawnSync } from 'node:child_process';
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createPublicKey, verify } from 'node:crypto';
import { randomNonce } from '@ashaveri/receipt';
import { fixtureCapture, fixtureIssuerPin, fixtureManifestKeys } from './checkpoint-fixture.js';
import { DEFAULT_RECEIPT_DURABILITY_COUNT } from './receipt-volume.js';
import { newPopCredential, serializeCredentialFile } from '../../src/access.js';
import {
  canonicalDigest,
  generatePinKeyPair,
  readPinEvidence,
  retainBootCapture,
  HeadPinError,
  signHeadPin,
  verifyHeadPin,
  type HeadPin,
  type PinKey,
  type PinKeyPair,
  type PinnedHead,
  type PinEvidence,
  type BootCapture,
  type BootLedger,
  type HeadPinRefusalCode,
} from './checkpoint-pin.js';
import { parseAccessLine, RETENTION_SWEEP_NAME } from '../../src/aclog.js';
import { daysToSeconds } from '../../src/duty-window.js';
import {
  readReceiptStoreCheckpoint,
  RECEIPT_SIDECAR_FILE,
  RECEIPT_STORE_FILE,
  type ReceiptRecordKind,
  type ReceiptStoreCheckpoint,
} from '../../src/store.js';
import type { RetentionEvidence } from '../../src/retention-evidence.js';
import { assertAcknowledged, bootServing, complete, sendCompletion, signedGetBytes, type ServedGateway } from './served-gateway.js';
import { buildVolume, readVolume, volumeHead, type VolumeReading } from './receipt-volume.js';

// Modeled stamps exercise retention without waiting hours; all holders remain local stand-ins.
const RECEIPTS_DAYS = 184;
/** The checkpoint schedule this deployment declares: every completed batch, and no hour without one. */
const MAX_INTERVAL_SECONDS = 3_600;
const CLOCK_SOURCE = 'drill synchronisation';
const CLOCK_UNCERTAINTY_SECONDS = 3_600;
const HOUR_SECONDS = 3_600;
const RECEIPT_KIND: ReceiptRecordKind = { kind: 'receipt' };
/** The batch shapes the run serves: four, then two that end in the kill, then three. */
const BATCH_A = 4;
const BATCH_B = 2;
const BATCH_C = 3;
/** The retried batch, and the one the kill lands inside of. */
const BATCH_D = 4;
const BATCH_E = 2;
/** One probe is a node start and a directory walk, so the patience it is given is a hang detector. */
export const PROBE_DEADLINE_MS = 20_000;

/** The batches the run serves, in the order they arrive. */
type BatchLabel = 'A' | 'B' | 'C' | 'D' | 'E';
const ORDER: readonly BatchLabel[] = ['A', 'B', 'C', 'D', 'E'];
export const DRILL_BOOT_COUNT = ORDER.length;
export const CHECKPOINT_READ_COUNT = ORDER.filter((label) => label !== 'E').length;

interface Scenario {
  readonly label: string;
  readonly group: 'assessment' | 'recovery';
  readonly pin: 'C' | 'B' | 'final' | 'none';
  readonly mutation?: 'omitted' | 'extra' | 'rollback' | 'suffix' | 'beyond' | 'restore';
  readonly whole?: boolean;
  readonly omitReplay?: boolean;
  readonly noIndex?: boolean;
}
export const DRILL_SCENARIOS: readonly Scenario[] = [
  { label: 'control: the scope as it happened, with a local stand-in pin', group: 'assessment', pin: 'C' },
  { label: 'omitted: one acknowledged receipt rebuilt out of the volume', group: 'assessment', pin: 'C', mutation: 'omitted' },
  { label: 'extra: a receipt inside the scope no client was issued', group: 'assessment', pin: 'C', mutation: 'extra' },
  { label: 'stale replay: an earlier checkpoint offered for the whole scope', group: 'assessment', pin: 'B' },
  { label: 'rollback: the same positions, different bytes at five', group: 'assessment', pin: 'C', mutation: 'rollback' },
  { label: 'suffix loss: the acknowledged tail is gone', group: 'assessment', pin: 'C', mutation: 'suffix' },
  { label: 'unpinned: the same scope without a pin', group: 'assessment', pin: 'none' },
  { label: 'no index: a volume that states no checkpoint', group: 'assessment', pin: 'C', noIndex: true },
  { label: 'beyond scope: a receipt appended past the declared end', group: 'assessment', pin: 'C', mutation: 'beyond' },
  { label: 'crash: the batch that ended in the kill has no checkpoint', group: 'recovery', pin: 'final', whole: true },
  { label: 'retry: one intent the restarted process served twice', group: 'recovery', pin: 'final', whole: true, omitReplay: true },
  { label: 'restore: an hour-one volume beside the index that is not its own', group: 'recovery', pin: 'C', mutation: 'restore' },
];

const PROBE = fileURLToPath(new URL('./evidence-probe.mjs', import.meta.url));

/** What the customer declares about one batch: the positions it holds and whether a checkpoint covers it. */
export interface DeclaredBatch {
  readonly label: string;
  readonly from: number;
  readonly to: number;
  readonly checkpointed: boolean;
  /** The instant the checkpoint was taken at, or null where none was taken. */
  readonly at: number | null;
}

/** The declared scope one assessment weighs the store's answer against. */
export interface DeclaredScope {
  readonly label: string;
  readonly subject: string;
  readonly intake: { readonly from: number; readonly to: number };
  readonly acknowledged: readonly string[];
  readonly batches: readonly DeclaredBatch[];
  readonly period: { readonly from: number; readonly to: number };
  readonly maxIntervalSeconds: number;
  /** Null preserves the no-pin outcome instead of inventing a local witness. */
  readonly expectedHead: PinnedHead | null;
  readonly pinnedBy: 'local-stand-in' | 'none';
}

export type AssessmentVerdict = 'pass' | 'gap' | 'indeterminate' | 'refused';

export type FindingKind =
  | 'omitted-record'
  | 'extra-record'
  | 'stale-replay'
  | 'pin-out-of-scope'
  | 'rollback'
  | 'suffix-loss'
  | 'unwitnessed-interval'
  | 'interval-exceeded'
  | 'no-independent-pin'
  | 'no-checkpoint-witness'
  | 'head-disagreement'
  | 'chain-disagreement'
  | 'store-refusal';

export interface Finding {
  readonly kind: FindingKind;
  readonly detail: string;
}

export interface Assessment {
  readonly label: string;
  readonly verdict: AssessmentVerdict;
  readonly findings: readonly Finding[];
  /** The head the sealed bytes state, as the reader of the volume found it. */
  readonly observed: PinnedHead | null;
  readonly expected: PinnedHead | null;
  /** Which arm the store's own evidence came back on: a stated checkpoint, a span, or nothing. */
  readonly coverageArm: 'checkpoint' | 'span' | 'empty';
  readonly detail: string;
  /** The scope this answer was reached under, so a pin can be re-derived from it. */
  readonly declared: DeclaredScope;
}

interface ProbeAnswer {
  readonly ok: boolean;
  readonly evidence: RetentionEvidence | null;
  readonly code: string | null;
  readonly message: string | null;
}

export interface PinCase {
  readonly label: string;
  readonly refused: boolean;
  readonly code: HeadPinRefusalCode | null;
  readonly head: PinnedHead | null;
  readonly pin: HeadPin;
  readonly signer: string;
  readonly issuedBy: readonly string[];
  /** Whether this case carries a signature the named key really made. */
  readonly signatureByThisKey: boolean;
}

export interface DrillResult {
  readonly served: readonly string[];
  readonly checkpoints: readonly { label: string; head: PinnedHead | null; at: number | null }[];
  readonly sealedCheckpoints: readonly { label: string; sealed: ReceiptStoreCheckpoint; volume: PinnedHead | null }[];
  readonly arms: readonly Assessment[];
  readonly legs: readonly Assessment[];
  readonly pins: readonly PinCase[];
  readonly replay: { readonly status: number; readonly code: string | undefined; readonly receiptId: string | null };
  /** This extra read preserves the served-HTTP check alongside the sealed-volume checks. */
  readonly receiptRead: { readonly status: number; readonly id: string };
  readonly clock: { readonly source: string; readonly uncertaintySeconds: number; readonly instants: readonly number[] };
  readonly access: { readonly files: readonly string[]; readonly lines: number };
  readonly holderKeyId: string;
  readonly fixtureIssuerKeyId: string;
  readonly issuanceIdentities: readonly string[];
  readonly captureLedger: readonly BootLedger[];
  readonly captures: readonly BootCapture[];
  readonly pinEvidence: PinEvidence;
  readonly wallTimeMs: number;
  readonly volumeListing: readonly string[];
  readonly table: readonly string[];
}

interface DrillPaths {
  readonly root: string;
  readonly volume: string;
  readonly access: string;
  readonly keys: string;
  readonly state: string;
  readonly credentials: string;
}

/** The scope members a pin covers: everything the customer declared except the head the pin itself names. */
export function scopeDigestOf(declared: DeclaredScope): string {
  return canonicalDigest({
    subject: declared.subject,
    intake: declared.intake,
    acknowledged: declared.acknowledged,
    batches: declared.batches,
    period: declared.period,
    maxIntervalSeconds: declared.maxIntervalSeconds,
  });
}

// Compare at the pinned position so records beyond the declared scope are not losses.
export function assessScope(args: { declared: DeclaredScope; probe: ProbeAnswer; volume: VolumeReading }): Assessment {
  const { declared, probe, volume } = args;
  const findings: Finding[] = [];
  const observed = volumeHead(volume);
  const coverageArm: Assessment['coverageArm'] =
    probe.evidence === null
      ? 'empty'
      : probe.evidence.coverage.checkpoints.length > 0
        ? 'checkpoint'
        : probe.evidence.coverage.span === null
          ? 'empty'
          : 'span';
  const answer = (verdict: AssessmentVerdict, detail: string): Assessment => ({
    label: declared.label,
    verdict,
    findings,
    observed,
    expected: declared.expectedHead,
    coverageArm,
    detail,
    declared,
  });

  if (!probe.ok) {
    findings.push({ kind: 'store-refusal', detail: `the store answered ${String(probe.code)}: ${String(probe.message)}` });
    return answer('refused', 'no evidence reading was produced');
  }
  if (volume.brokenAtSeq !== null) {
    findings.push({ kind: 'chain-disagreement', detail: `the chain stops agreeing with itself at position ${String(volume.brokenAtSeq)}` });
    return answer('refused', 'the volume does not chain');
  }
  if (declared.expectedHead === null || declared.pinnedBy !== 'local-stand-in') {
    findings.push({ kind: 'no-independent-pin', detail: 'no key outside the issuance set pinned a head, so nothing below is weighed against a witness' });
    return answer('indeterminate', 'unpinned');
  }

  const pinned = declared.expectedHead;
  if (pinned.sequence < declared.intake.to) {
    findings.push({ kind: 'stale-replay', detail: `the pin reaches position ${String(pinned.sequence)} and the scope declares ${String(declared.intake.to)}, so the tail of this scope is unwitnessed` });
  } else if (pinned.sequence > declared.intake.to) {
    findings.push({ kind: 'pin-out-of-scope', detail: `the pin is at position ${String(pinned.sequence)} and the scope stops at ${String(declared.intake.to)}` });
  }
  const atPinned = volume.records.find((each) => each.seq === pinned.sequence);
  if (atPinned === undefined) {
    const last = observed?.sequence ?? -1;
    findings.push({ kind: 'suffix-loss', detail: `the volume ends at ${String(last)} and the pinned head is at ${String(pinned.sequence)}, so everything past ${String(last)} is gone` });
  } else if (atPinned.digest !== pinned.sha256) {
    findings.push({ kind: 'head-disagreement', detail: `position ${String(pinned.sequence)} is ${atPinned.digest} on the volume and ${pinned.sha256} in the pin` });
  }

  const onVolume = new Set(volume.records.map((each) => each.id));
  const missing = declared.acknowledged.filter((id) => !onVolume.has(id));
  if (missing.length > 0) {
    findings.push({ kind: 'omitted-record', detail: `${String(missing.length)} acknowledged receipt(s) are not in the volume: ${missing.join(', ')}` });
  }
  // Surplus matters only inside the declared scope.
  const inScope = volume.records.filter((each) => each.seq <= declared.intake.to);
  const intended = new Set(declared.acknowledged);
  const surplus = inScope.filter((each) => !intended.has(each.id));
  if (surplus.length > 0) {
    findings.push({ kind: 'extra-record', detail: `${String(surplus.length)} receipt(s) in the scope belong to no acknowledgement: ${surplus.map((each) => `${String(each.seq)}=${each.id}`).join(', ')}` });
  }
  if (findings.some((each) => each.kind === 'head-disagreement') && missing.length === 0 && surplus.length === 0) {
    findings.push({ kind: 'rollback', detail: 'the same positions hold different bytes, which is a branch rather than a shorter run' });
  }
  for (const batch of declared.batches) {
    if (!batch.checkpointed) {
      findings.push({ kind: 'unwitnessed-interval', detail: `batch ${batch.label} (positions ${String(batch.from)} to ${String(batch.to)}) was acknowledged and no checkpoint covers it` });
    }
  }
  const timed = declared.batches.filter((each) => each.at !== null) as (DeclaredBatch & { at: number })[];
  for (let at = 1; at < timed.length; at += 1) {
    const apart = timed[at]!.at - timed[at - 1]!.at;
    if (apart > declared.maxIntervalSeconds) {
      findings.push({ kind: 'interval-exceeded', detail: `${String(apart)} seconds stand between the checkpoints at ${timed[at - 1]!.label} and ${timed[at]!.label}` });
    }
  }
  // Receipt stamps expose an unwitnessed tail after the last checkpoint.
  const lastAt = timed.at(-1)?.at;
  const newestInScope = inScope.at(-1)?.at;
  if (lastAt !== undefined && newestInScope !== undefined && newestInScope - lastAt > declared.maxIntervalSeconds) {
    findings.push({ kind: 'interval-exceeded', detail: `${String(newestInScope - lastAt)} seconds stand between the last checkpoint and the newest receipt in scope, past the ${String(declared.maxIntervalSeconds)} the schedule declares` });
  }
  if (probe.evidence === null || probe.evidence.coverage.checkpoints.length === 0) {
    findings.push({ kind: 'no-checkpoint-witness', detail: 'the store states no checkpoint, so the reading rests on a span between two survivors' });
  }

  const verdict: AssessmentVerdict =
    findings.length === 0
      ? 'pass'
      : findings.some((each) => each.kind === 'no-checkpoint-witness')
        ? 'indeterminate'
        : 'gap';
  return answer(verdict, findings.length === 0 ? 'the volume, the acknowledgements and the pinned head agree' : `${String(findings.length)} finding(s)`);
}

/** The state document an operator's own synchronisation writes, and `--time-source-state` reads. */
async function writeTimeSourceState(path: string, instant: number): Promise<void> {
  await writeFile(
    path,
    `${JSON.stringify({ version: 1, source: CLOCK_SOURCE, uncertaintySeconds: CLOCK_UNCERTAINTY_SECONDS, measuredAtSeconds: instant })}\n`,
    'utf8',
  );
}

/** One start of the gateway on the drill's volume, stamping from the hour it is handed. */
function startDeployment(paths: DrillPaths): Promise<ServedGateway> {
  return bootServing([
    '--receipts-dir', paths.volume,
    '--credentials-path', paths.credentials,
    '--access-log-path', paths.access,
    '--time-source-state', paths.state,
  ]);
}

async function withDeployment<T>(paths: DrillPaths, run: (served: ServedGateway) => Promise<T>): Promise<T> {
  const served = await startDeployment(paths);
  let succeeded = false;
  try {
    const result = await run(served);
    succeeded = true;
    return result;
  } finally {
    try {
      await served.kill();
    } catch (error) {
      if (succeeded) throw error;
    }
  }
}

/** The retention pairing the deployment started with, restated for whoever opens its volume. */
function deploymentRetention(instant: number): string {
  return JSON.stringify({
    maxAgeSeconds: daysToSeconds(RECEIPTS_DAYS),
    maxCount: DEFAULT_RECEIPT_DURABILITY_COUNT,
    source: { name: CLOCK_SOURCE, uncertaintySeconds: CLOCK_UNCERTAINTY_SECONDS, instant },
  });
}

function declarationOf(declared: DeclaredScope): string {
  return JSON.stringify({
    subject: { kind: 'deployment', id: declared.subject },
    duty: { article: '19(1)', requiredSeconds: daysToSeconds(RECEIPTS_DAYS) },
    period: declared.period,
    intake: declared.intake,
    expectedHead: {
      sha256: declared.expectedHead?.sha256 ?? null,
      pinnedBy: declared.pinnedBy === 'local-stand-in' ? 'customer' : 'none',
      reason: declared.pinnedBy === 'local-stand-in' ? 'synthetic local stand-in for the customer; independent custody unperformed' : 'no pin was produced for this scope',
    },
    maxIntervalSeconds: declared.maxIntervalSeconds,
  });
}

// A separate process releases store ownership when the sealed reading ends.
function probeEvidence(paths: DrillPaths, declared: DeclaredScope, instant: number, askForIndex: boolean): ProbeAnswer {
  const run = spawnSync(process.execPath, [PROBE, paths.volume, deploymentRetention(instant), declarationOf(declared), String(askForIndex)], {
    encoding: 'utf8',
    timeout: PROBE_DEADLINE_MS,
  });
  if (run.error !== undefined) {
    return { ok: false, evidence: null, code: 'PROBE_SPAWN_FAILED', message: run.error.message };
  }
  try {
    const answered = JSON.parse(run.stdout.trim()) as ProbeAnswer;
    return { ok: answered.ok, evidence: answered.evidence ?? null, code: answered.code ?? null, message: answered.message ?? null };
  } catch {
    return { ok: false, evidence: null, code: 'PROBE_UNREADABLE', message: `${run.stdout} ${run.stderr}` };
  }
}

/** The scope every arm starts from: the run's own period, positions, acknowledgements and ledger. */
function declaredScope(
  label: string,
  hourOne: number,
  hourThree: number,
  acknowledged: readonly string[],
  override: Partial<DeclaredScope>,
): DeclaredScope {
  return {
    label,
    subject: 'checkpoint-evidence-drill',
    intake: override.intake ?? { from: 0, to: acknowledged.length - 1 },
    acknowledged: override.acknowledged ?? acknowledged,
    batches: override.batches ?? [],
    period: override.period ?? { from: hourOne, to: hourThree },
    maxIntervalSeconds: MAX_INTERVAL_SECONDS,
    expectedHead: null,
    pinnedBy: 'none',
  };
}

async function restoreSidecar(paths: DrillPaths, bytes: Buffer): Promise<void> {
  if (bytes.length === 0) {
    await rm(join(paths.volume, RECEIPT_SIDECAR_FILE), { force: true });
    return;
  }
  await writeFile(join(paths.volume, RECEIPT_SIDECAR_FILE), bytes);
}

function reportLine(report: (line: string) => void, table: string[], line: string): void {
  report(line);
  table.push(line);
}

function reportAssessment(report: (line: string) => void, table: string[], answer: Assessment): void {
  const scope = `intake ${String(answer.declared.intake.from)}..${String(answer.declared.intake.to)} over ${String(answer.declared.acknowledged.length)} acknowledgements`;
  reportLine(report, table, `${answer.label.padEnd(60)} | ${answer.verdict.padEnd(13)} | ${answer.findings.map((each) => each.kind).join(',') || 'none'} | ${scope}`);
  for (const each of answer.findings) report(`      ${each.kind}: ${each.detail}`);
}

async function readAccessLog(dir: string): Promise<{ files: string[]; lines: number }> {
  const names = (await readdir(dir)).sort();
  let lines = 0;
  for (const name of names.filter((each) => RETENTION_SWEEP_NAME.test(each) && !each.startsWith('scrub-'))) {
    for (const line of (await readFile(join(dir, name), 'utf8')).split('\n')) {
      if (line.trim().length === 0) continue;
      lines += 1;
      parseAccessLine(line);
    }
  }
  return { files: names, lines };
}

// Each scenario starts from the same sealed bytes, not the previous scenario's mutation.
export async function runCheckpointDrill(report: (line: string) => void = () => undefined): Promise<DrillResult> {
  const root = await mkdtemp(join(tmpdir(), 'ashaveri-checkpoint-drill-'));
  const paths: DrillPaths = {
    root,
    volume: join(root, 'volume'),
    access: join(root, 'access'),
    keys: join(root, 'held-apart'),
    state: join(root, 'time-source.json'),
    credentials: join(root, 'credentials.json'),
  };
  try {
    return await runDrill(paths, report);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

async function runDrill(paths: DrillPaths, report: (line: string) => void): Promise<DrillResult> {
  await mkdir(paths.volume);
  await mkdir(paths.access);
  await mkdir(paths.keys);
  const pop = newPopCredential({ id: 'drill-holder', scopes: ['read', 'complete'] });
  await writeFile(paths.credentials, serializeCredentialFile({ version: 1, credentials: [pop.record] }), 'utf8');

  const wallStarted = performance.now();
  const holder = generatePinKeyPair();
  const captured: BootCapture[] = [];
  const retained: BootLedger[] = [];
  async function captureBoot(served: ServedGateway, boot: BatchLabel): Promise<void> {
    const manifest = await signedGetBytes(served, pop, '/v1/deployment-manifest');
    if (manifest.status !== 200) throw new Error(`manifest read failed for boot ${boot}: ${String(manifest.status)}`);
    const receipts: { id: string; bytes: Uint8Array }[] = [];
    for (const id of batches[boot]) {
      const response = await signedGetBytes(served, pop, `/v1/receipts/${id}`);
      if (response.status !== 200) throw new Error(`receipt read failed for ${id}: ${String(response.status)}`);
      receipts.push({ id, bytes: response.body });
    }
    const capture: BootCapture = { boot, manifest: manifest.body, receipts };
    retained.push(retainBootCapture(capture));
    captured.push(capture);
  }
  await writeFile(join(paths.keys, 'head-pin-private.pem'), holder.privateKey, { encoding: 'utf8', mode: 0o600 });

  const hourOne = Math.floor(Date.now() / 1000);
  const hourTwo = hourOne + HOUR_SECONDS;
  const hourThree = hourOne + 2 * HOUR_SECONDS;
  /** The hour the retried batch arrives in, and the one the run is killed inside of. */
  const hourFour = hourOne + 3 * HOUR_SECONDS;
  const hourCrash = hourOne + 5 * HOUR_SECONDS;
  const table: string[] = [];
  const checkpoints: { label: string; head: PinnedHead | null; at: number | null }[] = [];
  const sealedCheckpoints: { label: string; sealed: ReceiptStoreCheckpoint; volume: PinnedHead | null }[] = [];
  /** The receipts each batch holds, so the ledger is written from what was served and not from a constant. */
  const batches: Record<BatchLabel, string[]> = { A: [], B: [], C: [], D: [], E: [] };

  /** What the index beside the volume states right now, read without opening the store. */
  async function seal(label: string, bytes: Buffer): Promise<void> {
    const sealed = await readReceiptStoreCheckpoint(paths.volume, RECEIPT_KIND);
    const volume = volumeHead(readVolume(bytes));
    sealedCheckpoints.push({ label, sealed, volume });
    reportLine(
      report,
      table,
      `read without opening, ${label}: the index states ${sealed.present ? `a checkpoint to position ${String(sealed.lastSequence)} at ${sealed.head.slice(0, 16)}` : 'no checkpoint'}, the volume ends at ${volume === null ? 'nothing' : `position ${String(volume.sequence)} at ${volume.sha256.slice(0, 16)}`}`,
    );
  }

  async function serveBatch(served: ServedGateway, count: number, label: BatchLabel): Promise<string[]> {
    const ids: string[] = [];
    for (let at = 0; at < count; at += 1) {
      ids.push(assertAcknowledged(await complete(served, pop), `batch ${label} completion ${String(at)}`));
    }
    batches[label]!.push(...ids);
    return ids;
  }

  /** The positions one batch occupies, counted from the batches served before it. */
  function positionsOf(label: BatchLabel): { from: number; to: number } {
    const from = ORDER.slice(0, ORDER.indexOf(label)).reduce((total, each) => total + batches[each].length, 0);
    return { from, to: from + batches[label].length - 1 };
  }

  /** The customer's checkpoint ledger, written from the batches the run actually served. */
  function ledgerOf(checkpointed: { A: boolean; B: boolean; C: boolean; D: boolean; E: boolean }): DeclaredBatch[] {
    const hours: Record<string, number> = { A: hourOne, B: hourTwo, C: hourThree, D: hourFour, E: hourCrash };
    return ORDER.map((label) => {
      const { from, to } = positionsOf(label);
      return { label, from, to, checkpointed: checkpointed[label], at: checkpointed[label] ? hours[label]! : null };
    });
  }

  // Read the stopped volume rather than trusting a head supplied by the serving process.
  async function customerCheckpoint(label: BatchLabel, instant: number, through: string[]): Promise<PinnedHead> {
    const acknowledged = through;
    const declared = declaredScope(`checkpoint ${label}`, hourOne, instant, acknowledged, {
      intake: { from: 0, to: acknowledged.length - 1 },
      batches: ledgerOf({ A: true, B: true, C: true, D: true, E: true }).filter((each) => each.from <= each.to && each.to <= acknowledged.length - 1),
    });
    const probe = probeEvidence(paths, declared, instant, true);
    if (!probe.ok || probe.evidence === null) {
      throw new Error(`the checkpoint reading for ${label} was refused: ${String(probe.code)} ${String(probe.message)}`);
    }
    const stated = probe.evidence.coverage.checkpoints.at(-1);
    const head = stated === undefined ? null : { sequence: stated.range.to, sha256: stated.head };
    if (head === null) {
      throw new Error(`the checkpoint reading for ${label} stated no checkpoint: ${JSON.stringify(probe.evidence.coverage)}`);
    }
    checkpoints.push({ label, head, at: instant });
    await seal(`after batch ${label}`, await readFile(join(paths.volume, RECEIPT_STORE_FILE)));
    return head;
  }

  // Hour one: one batch, then the process stops so a reader can open what it wrote.
  await writeTimeSourceState(paths.state, hourOne);
  await withDeployment(paths, async (served) => {
    await serveBatch(served, BATCH_A, 'A');
    await captureBoot(served, 'A');
  });
  const afterA = await readFile(join(paths.volume, RECEIPT_STORE_FILE));
  await customerCheckpoint('A', hourOne, batches.A);

  // Hours two and three: one batch each, each closed by a checkpoint of the shape the schedule declares.
  await writeTimeSourceState(paths.state, hourTwo);
  const bNonce = await withDeployment(paths, async (served) => {
    const nonce = randomNonce();
    batches.B.push(assertAcknowledged(await sendCompletion(served, pop, nonce), 'batch B first completion'));
    await serveBatch(served, BATCH_B - 1, 'B');
    await captureBoot(served, 'B');
    return nonce;
  });
  const checkpointB = await customerCheckpoint('B', hourTwo, [...batches.A, ...batches.B]);

  await writeTimeSourceState(paths.state, hourThree);
  await withDeployment(paths, async (served) => {
    await serveBatch(served, BATCH_C, 'C');
    await captureBoot(served, 'C');
  });
  const checkpointC = await customerCheckpoint('C', hourThree, [...batches.A, ...batches.B, ...batches.C]);

  // Restart permits the repeated nonce; the retried batch then closes under a checkpoint.
  await writeTimeSourceState(paths.state, hourFour);
  const { replay, retry, receiptRead } = await withDeployment(paths, async (served) => {
    const replay = await sendCompletion(served, pop, bNonce);
    if (replay.status === 200 && replay.receiptId !== null) {
      batches.D.push(replay.receiptId);
    }
    const retry = await complete(served, pop);
    batches.D.push(assertAcknowledged(retry, 'the retry of an intent hour three already acknowledged'));
    await serveBatch(served, BATCH_D - batches.D.length, 'D');
    // Keep the served HTTP witness separate from the sealed-volume readings.
    const receiptRead = await signedGetBytes(served, pop, `/v1/receipts/${retry.receiptId}`);
    await captureBoot(served, 'D');
    return { replay, retry, receiptRead };
  });
  await customerCheckpoint('D', hourFour, [...batches.A, ...batches.B, ...batches.C, ...batches.D]);

  // Killing this batch leaves its receipts outside checkpoint coverage.
  await writeTimeSourceState(paths.state, hourCrash);
  await withDeployment(paths, async (served) => {
    await serveBatch(served, BATCH_E, 'E');
    await captureBoot(served, 'E');
  });
  const captureLedger = Object.freeze([...retained]);
  const captures = Object.freeze([...captured]);
  const pinEvidence = readPinEvidence({ ledger: captureLedger, captures, trust: { mode: 'synthetic-tofu' } });
  const issuanceIdentities = pinEvidence.issuanceIdentities;
  for (const boot of pinEvidence.boots) {
    reportLine(report, table, `boot ${boot.boot}: ${String(boot.receipts.length)} verified receipts; ${boot.authentication.advisory ?? 'authenticated manifest'}`);
  }

  const finalBytes = await readFile(join(paths.volume, RECEIPT_STORE_FILE));
  const headFinal = volumeHead(readVolume(finalBytes));
  if (headFinal === null) {
    throw new Error('the run filed no receipts, so there is nothing to assess');
  }
  checkpoints.push({ label: 'E', head: headFinal, at: null });
  await seal('after the crash', finalBytes);
  const indexAtEnd = await readFile(join(paths.volume, RECEIPT_SIDECAR_FILE)).catch(() => Buffer.alloc(0));
  const acknowledged = [...batches.A, ...batches.B, ...batches.C, ...batches.D, ...batches.E];
  const witnessed = [...batches.A, ...batches.B, ...batches.C];
  const access = await readAccessLog(paths.access);
  reportLine(
    report,
    table,
    `the run acknowledged ${String(acknowledged.length)} completions and filed ${String(readVolume(finalBytes).records.length)} receipts in five batches, and the access log holds ${String(access.lines)} line(s) in ${String(access.files.length)} part(s)`,
  );

  /** One arm: put the run's bytes back, mutate them as the arm names, and read the seal as a second process. */
  async function arm(
    label: string,
    options: {
      readonly pinTo: PinnedHead | null;
      readonly mutate?: (bytes: Buffer) => Buffer;
      readonly removeSidecar?: boolean;
      readonly declare?: Partial<DeclaredScope>;
      readonly askForIndex?: boolean;
      /** `witnessed` reaches the last checkpoint the ledger holds; `whole` reaches the crashed batch too. */
      readonly scope?: 'witnessed' | 'whole';
    },
  ): Promise<Assessment> {
    await writeFile(join(paths.volume, RECEIPT_STORE_FILE), options.mutate === undefined ? finalBytes : options.mutate(finalBytes));
    await restoreSidecar(paths, indexAtEnd);
    if (options.removeSidecar === true) {
      await rm(join(paths.volume, RECEIPT_SIDECAR_FILE), { force: true });
    }
    const whole = options.scope === 'whole';
    const acks = whole ? acknowledged : witnessed;
    const instant = whole ? hourCrash : hourFour;
    const started = declaredScope(label, hourOne, instant, acks, {
      batches: ledgerOf({ A: true, B: true, C: true, D: true, E: !whole }),
      ...options.declare,
    });
    const base: DeclaredScope = { ...started, batches: started.batches.filter((each) => each.to <= started.intake.to) };
    let declared: DeclaredScope = { ...base, expectedHead: null, pinnedBy: 'none' };
    if (options.pinTo !== null) {
      const scope = scopeDigestOf(base);
      const pin = signHeadPin({ key: holder, head: options.pinTo, scope });
      // Scope-loss scenarios must not rewrite the original capture ledger.
      declared = { ...base, expectedHead: verifyHeadPin(pin, { expectedHolder: holder, evidence: pinEvidence, scope }).head, pinnedBy: 'local-stand-in' };
    }
    const probe = probeEvidence(paths, declared, instant, options.askForIndex ?? true);
    const volume = readVolume(await readFile(join(paths.volume, RECEIPT_STORE_FILE)));
    const assessed = assessScope({ declared, probe, volume });
    reportAssessment(report, table, assessed);
    return assessed;
  }

  const rebuild = (records: readonly { at: number; id: string; payload: Buffer }[]): Buffer =>
    buildVolume(records.map((each) => ({ at: each.at, id: each.id, payload: each.payload })));
  /** Drops one receipt and re-chains the rest, which is the loss a chain check alone cannot see. */
  const dropOne = (bytes: Buffer, at: number): Buffer => rebuild(readVolume(bytes).records.filter((each) => each.seq !== at));
  /** Inserts a receipt no client was ever issued a receipt id for, inside the declared range. */
  const insertForged = (bytes: Buffer, at: number): Buffer => {
    const records = readVolume(bytes).records.map((each) => ({ at: each.at, id: each.id, payload: each.payload }));
    const copy = mutatedLastByte(records[records.length - 1]!.payload, 1);
    records.splice(at, 0, { at: hourFour, id: 'rcpt_never_acknowledged', payload: copy });
    return rebuild(records);
  };
  /** Two receipts an acknowledgement names, at the same positions, over different bytes. */
  const divergeAt = (bytes: Buffer, at: number): Buffer => {
    const records = readVolume(bytes).records.map((each) => ({ at: each.at, id: each.id, payload: each.payload }));
    const target = records[at]!;
    target.payload = mutatedLastByte(target.payload, 3);
    target.at += 7;
    return rebuild(records);
  };
  /** Keeps the volume up to one position and drops the frames behind it, leaving a chain that still holds. */
  const truncateAfter = (bytes: Buffer, at: number): Buffer => {
    const kept = readVolume(bytes).records.filter((each) => each.seq <= at);
    const last = kept.at(-1)!;
    return Buffer.from(bytes.subarray(0, last.offset + last.bytes));
  };
  const lastWitnessed = checkpointC.sequence;

  const heads = { C: checkpointC, B: checkpointB, final: headFinal, none: null };
  const mutations: Record<NonNullable<Scenario['mutation']>, (bytes: Buffer) => Buffer> = {
    omitted: (bytes) => dropOne(bytes, 2),
    extra: (bytes) => insertForged(bytes, 3),
    rollback: (bytes) => divergeAt(bytes, 5),
    suffix: (bytes) => truncateAfter(bytes, lastWitnessed - 3),
    beyond: (bytes) => rebuild([...readVolume(bytes).records, { at: hourCrash, id: 'rcpt_past_the_scope', payload: mutatedLastByte(readVolume(bytes).records.at(-1)!.payload, 5) }]),
    restore: () => afterA,
  };
  const arms: Assessment[] = [];
  const legs: Assessment[] = [];
  for (const scenario of DRILL_SCENARIOS) {
    const assessed = await arm(scenario.label, {
      pinTo: heads[scenario.pin],
      mutate: scenario.mutation === undefined ? undefined : mutations[scenario.mutation],
      removeSidecar: scenario.noIndex,
      askForIndex: !scenario.noIndex,
      scope: scenario.whole === true ? 'whole' : 'witnessed',
      declare: scenario.omitReplay === true ? { acknowledged: acknowledged.filter((id) => id !== replay.receiptId) } : {},
    });
    (scenario.group === 'assessment' ? arms : legs).push(assessed);
  }
  reportLine(report, table, `${String(arms.length)} assessment scenarios and ${String(legs.length)} recovery scenarios; ${String((hourCrash - hourOne) / HOUR_SECONDS)} modeled hours across ${String(ORDER.length)} boots; wall time ${String(Math.round(performance.now() - wallStarted))}ms`);

  const control = arms[0]!;
  const fixture = fixtureCapture();
  const fixtureEvidence = readPinEvidence({
    ledger: [retainBootCapture(fixture)], captures: [fixture],
    trust: { mode: 'designated-keys', manifestKeys: fixtureManifestKeys },
  });
  const pins: PinCase[] = [
    pinCase('refused: a valid self-pin by an authenticated fixture issuer', fixtureIssuerPin, fixtureIssuerPin, fixtureEvidence, control),
    pinCase('accepted: local stand-in, not independent operator custody', holder, holder, pinEvidence, control),
  ];
  for (const each of pins) {
    reportLine(
      report,
      table,
      `${each.label.padEnd(60)} | ${each.refused ? `refused ${String(each.code)}` : `accepted at position ${String(each.head?.sequence)}`} | signer ${each.signer.slice(0, 16)}`,
    );
  }
  const volumeListing = (await readdir(paths.volume)).sort();
  reportLine(report, table, `the volume directory the run left holds: ${volumeListing.join(', ')}`);

  return {
    served: acknowledged,
    checkpoints,
    sealedCheckpoints,
    arms,
    legs,
    pins,
    replay: { status: replay.status, code: replay.code, receiptId: replay.receiptId },
    receiptRead: { status: receiptRead.status, id: retry.receiptId as string },
    clock: { source: CLOCK_SOURCE, uncertaintySeconds: CLOCK_UNCERTAINTY_SECONDS, instants: [hourOne, hourTwo, hourThree, hourFour, hourCrash] },
    access,
    holderKeyId: holder.keyId,
    fixtureIssuerKeyId: fixtureIssuerPin.keyId,
    issuanceIdentities,
    captureLedger,
    captures,
    pinEvidence,
    wallTimeMs: performance.now() - wallStarted,
    volumeListing,
    table,
  };
}

function mutatedLastByte(bytes: Buffer, increment: number): Buffer {
  const copy = Buffer.from(bytes);
  copy[copy.length - 1] = (copy[copy.length - 1]! + increment) % 256;
  return copy;
}

function pinCase(
  label: string,
  key: PinKeyPair,
  expectedHolder: PinKey,
  evidence: PinEvidence,
  control: Assessment,
): PinCase {
  const scope = scopeDigestOf(control.declared);
  if (control.expected === null) throw new Error('the control must supply a head');
  const pin = signHeadPin({ key, head: control.expected, scope });
  // This check is independent of the guard whose refusal the case measures.
  const body = Buffer.from(`${pin.document}|${pin.scope}|${pin.signer.keyId}|${pin.signer.publicKey}|${pin.head.sequence}|${pin.head.sha256}`);
  const signatureByThisKey = verify(null, body, createPublicKey(key.publicKey), Buffer.from(pin.signature, 'hex'));
  if (!signatureByThisKey) throw new Error('the fixture pin signature must verify');
  const base = { label, pin, signer: pin.signer.keyId, issuedBy: evidence.issuanceIdentities, signatureByThisKey };
  try {
    const answered = verifyHeadPin(pin, { expectedHolder, evidence, scope });
    return { ...base, refused: false, code: null, head: answered.head };
  } catch (error) {
    if (!(error instanceof HeadPinError)) throw error;
    return { ...base, refused: true, code: error.code, head: null };
  }
}
