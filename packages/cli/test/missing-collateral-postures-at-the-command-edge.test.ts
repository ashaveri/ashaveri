import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import { noteSpawn } from './support/spawn-budget.js';
/** How long one child of the built CLI may live before this file calls it a bug rather than a slow machine. */
const SPAWN_DEADLINE_MS = 10_000;

/**
 * The two postures a run takes when collateral is missing, each with its printed answer.
 *
 * A missing appraisal context is answered one of two ways, and both are honest because both state which
 * question was asked. A reading over an archive reports the shortage: the question named no root, the
 * slot is printed as missing context with the refusal that names the field left empty, and the exit code
 * stays what the seal over the container earned, because whether material can still be reached is a
 * finding about an archive rather than a fault in a signature. A policy that demands the material
 * refuses instead: the run exits 1 with the code for the demand it could not meet, which is the same
 * shortage answered by a caller that said in advance it will not proceed without the material.
 *
 * The two answers are therefore distinguishable by exit code and by where the refusal sits: the first
 * nests a code inside the slot's own row of an accepted report, and the second is the report's own
 * top-level code. The third case below is the script that tells them apart. The weighed variant of the
 * demand, a held slot the run was handed no reading for, answers `ANCHOR_MATERIAL_UNREACHED` and is
 * proved over a receipt built in `packages/cli/test/verify-receipt.test.ts`, because no published
 * receipt states a held slot; the published absences here are what the demand refuses at this edge.
 */

const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
const DATA = fileURLToPath(new URL('../../fixtures/data/', import.meta.url));

const tempDir = mkdtempSync(join(tmpdir(), 'ashaveri-postures-'));
afterAll(() => {
  rmSync(tempDir, { recursive: true, force: true });
});

interface CliResult {
  readonly status: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

function runCli(args: readonly string[]): CliResult {
  noteSpawn(SPAWN_DEADLINE_MS);
  const result = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    timeout: SPAWN_DEADLINE_MS,
    killSignal: 'SIGKILL',
  });
  expect(result.error).toBeUndefined();
  return { status: result.status, stdout: result.stdout ?? '', stderr: result.stderr ?? '' };
}

let writtenCount = 0;
function written(name: string, data: Uint8Array | string): string {
  const path = join(tempDir, `${writtenCount++}-${name}`);
  writeFileSync(path, data);
  return path;
}

function reportOf(result: CliResult): Record<string, unknown> {
  return JSON.parse(result.stdout) as Record<string, unknown>;
}

/** The four flags that describe one slot's question, as the published pack row's own material wants them. */
const QUESTION = [
  '--collateral-origin=col=intel-tcb-info',
  '--collateral-platform=col=tdx',
  '--collateral-cpu-type=col=00906e1b0d00',
  '--collateral-level=col=tcb-date=2025-06-01T00:00:00Z',
] as const;

/** The published pack whose arm carries a served pair, which is the one row a question can be asked of. */
const SERVED = (JSON.parse(readFileSync(`${DATA}pack-v1.json`, 'utf8')) as {
  readonly vectors: readonly { readonly name: string; readonly documentBase64Url: string; readonly read: { readonly pinned?: string } }[];
}).vectors.find((one) => one.name === 'custody-served-weighed');
if (SERVED?.read.pinned === undefined) {
  throw new Error('the published served-pack row states no pinned key, so the run would designate nothing');
}
const SERVED_FILE = written('served.cbor', Buffer.from(SERVED.documentBase64Url, 'base64url'));

/**
 * The published receipt and its pins, assembled into the policy a demanding call reads.
 *
 * The receipt states both of its anchor slots as absences, which is the published shape of a corpus
 * that took no appraisal context in, so the two postures below are two policies over one document.
 */
const RECEIPT_KEY = JSON.parse(readFileSync(`${DATA}keys/receipt-key-v1.json`, 'utf8')) as {
  readonly kid: string;
  readonly publicKey: string;
};
const RECEIPT_PAYLOAD = (JSON.parse(readFileSync(`${DATA}receipts/receipt-valid-v1.json`, 'utf8')) as {
  readonly payload: {
    readonly iss: string;
    readonly ins: string;
    readonly mdl: string;
    readonly wts: string;
    readonly epk: number;
    readonly nce: string;
    readonly req: string;
    readonly iat: number;
    readonly meas: { readonly tee: string; readonly m: string };
  };
}).payload;
const RECEIPT_ROW = (JSON.parse(readFileSync(`${DATA}manifest.json`, 'utf8')) as {
  readonly fixtures: readonly { readonly name: string; readonly path: string; readonly responseBase64Url?: string }[];
}).fixtures.find((one) => one.name === 'receipt-valid-v1');
if (RECEIPT_ROW?.responseBase64Url === undefined) {
  throw new Error('the receipt index states no response bytes for the valid vector, so the marking check has nothing to read');
}
const RECEIPT_PUBLIC_B64URL = Buffer.from(RECEIPT_KEY.publicKey, 'hex').toString('base64url');
const RECEIPT_FILE = written('receipt-valid-v1.cbor', readFileSync(join(DATA, RECEIPT_ROW.path)));
const RESPONSE_FILE = written('response.bin', Buffer.from(RECEIPT_ROW.responseBase64Url, 'base64url'));
const MANIFEST_FILE = written(
  'manifest.json',
  JSON.stringify({
    v: 1,
    iss: RECEIPT_PAYLOAD.iss,
    ins: RECEIPT_PAYLOAD.ins,
    epk: RECEIPT_PAYLOAD.epk,
    keys: [{ kid: RECEIPT_KEY.kid, alg: 'Ed25519', publicKey: RECEIPT_PUBLIC_B64URL }],
    models: [{ id: RECEIPT_PAYLOAD.mdl, wts: RECEIPT_PAYLOAD.wts }],
    meas: { tee: RECEIPT_PAYLOAD.meas.tee, m: RECEIPT_PAYLOAD.meas.m },
  }),
);
const RECEIPT_INPUTS = [
  `--manifest=${MANIFEST_FILE}`,
  `--nonce=${RECEIPT_PAYLOAD.nce}`,
  `--request-hash=${RECEIPT_PAYLOAD.req}`,
  `--response-body=${RESPONSE_FILE}`,
  `--now=${new Date(RECEIPT_PAYLOAD.iat * 1000).toISOString()}`,
] as const;

/** One receipt policy over the published pins, with the anchor demand spelled by the caller. */
function receiptPolicy(name: string, demand: Record<string, number>): string {
  return written(
    name,
    JSON.stringify({
      v: 1,
      issuers: [RECEIPT_PAYLOAD.iss],
      instances: [RECEIPT_PAYLOAD.ins],
      keys: { [RECEIPT_KEY.kid]: RECEIPT_PUBLIC_B64URL },
      measurements: { [RECEIPT_PAYLOAD.meas.tee]: [RECEIPT_PAYLOAD.meas.m] },
      maxReceiptAgeSeconds: 300,
      maxEvidenceAgeSeconds: 900,
      ...demand,
    }),
  );
}

describe('the two postures for missing collateral, at the command edge', () => {
  it('reports a question asked under no root as missing context, at the exit the seal earned', () => {
    const result = runCli(['verify-pack', SERVED_FILE, `--key=${SERVED.read.pinned}`, ...QUESTION, '--json']);
    // The container is whole and the appraisal could not run: the exit code keeps saying the first,
    // and the slot row says the second, so a shortage of trust material moves no verdict.
    expect(result.stderr).toBe('');
    expect(result.status, result.stderr).toBe(0);
    const report = reportOf(result);
    expect(report.ok).toBe(true);
    const document = report.document as Record<string, unknown>;
    const roots = document.collateralRoots as { handed: number; bundledConsulted: boolean; rule: string };
    expect(roots.handed).toBe(0);
    expect(roots.bundledConsulted).toBe(false);
    expect(roots.rule).toContain('no root bundled with the verifier was consulted either');
    const slots = Object.entries(document).filter(([key]) => key.startsWith('attached-'));
    expect(slots.length).toBeGreaterThan(0);
    const asked = slots.filter(([, row]) => (row as { question: unknown }).question !== null);
    expect(asked.length).toBe(1);
    const row = asked[0]?.[1] as { state: string; refusal: { code: string; missing: readonly string[] } };
    expect(row.state).toBe('missing-context');
    expect(row.refusal.code).toBe('COLLATERAL_ANCHOR_NOT_PINNED');
    expect(row.refusal.missing).toContain('roots');
  });

  it('refuses the material under a policy that demands it, naming the absence the receipt states', () => {
    const demanding = receiptPolicy('policy-demands-held.json', { minAnchorSlotsHeld: 1 });
    const result = runCli(['verify-receipt', RECEIPT_FILE, `--policy=${demanding}`, ...RECEIPT_INPUTS, '--json']);
    // The same document that verifies under a policy asking nothing is refused here, and the sentence
    // names the slot, the state it states and the reason it gives, so the operator sees the shortage
    // rather than a generic failure.
    expect(result.status).toBe(1);
    const refusal = reportOf(result);
    expect(refusal.ok).toBe(false);
    expect(refusal.code).toBe('ANCHOR_SLOT_NOT_HELD');
    expect(String(refusal.message)).toContain('never took its material in (not-taken-in)');
    expect(String(refusal.message)).toContain('this policy demands 1');
  });

  it('gives a script the two answers apart by exit code and by where the code sits', () => {
    // The reading posture: the container is accepted and the shortage sits in the slot's own row.
    const reading = runCli(['verify-pack', SERVED_FILE, `--key=${SERVED.read.pinned}`, ...QUESTION, '--json']);
    expect(reading.status).toBe(0);
    const readingReport = reportOf(reading);
    expect(readingReport.ok).toBe(true);
    expect(readingReport.code).toBeUndefined();
    const slotRows = Object.entries(readingReport.document as Record<string, unknown>)
      .filter(([key]) => key.startsWith('attached-'))
      .map(([, row]) => row as { refusal: { code: string } | null });
    expect(slotRows.some((row) => row.refusal?.code === 'COLLATERAL_ANCHOR_NOT_PINNED')).toBe(true);

    // The refusing posture: the same kind of shortage answered by the report's own top-level code.
    const demanding = receiptPolicy('policy-demands-held-again.json', { minAnchorSlotsHeld: 1 });
    const refusing = runCli(['verify-receipt', RECEIPT_FILE, `--policy=${demanding}`, ...RECEIPT_INPUTS, '--json']);
    expect(refusing.status).toBe(1);
    const refusingReport = reportOf(refusing);
    expect(refusingReport.ok).toBe(false);
    expect(refusingReport.code).toBe('ANCHOR_SLOT_NOT_HELD');

    // A script reads the exit status first and the top-level member second, and the pair says which
    // of the two postures answered: 0 with no top-level code and the refusal nested, or 1 with the
    // code at the top. Neither answer is a pass over material that was never read.
    expect(reading.status).not.toBe(refusing.status);
    expect(readingReport.code).toBeUndefined();
    expect(refusingReport.code).toBe('ANCHOR_SLOT_NOT_HELD');
  });
});
