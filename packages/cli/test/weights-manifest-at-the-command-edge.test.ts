import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import {
  decodeReceipt,
  generateSigningKey,
  issueReceipt,
  sealDeploymentManifest,
  signingKeyFromSeed,
  toHex,
  type ReceiptPayload,
} from '@ashaveri/receipt';
import { noteSpawn } from './support/spawn-budget.js';
/** How long one child of the built CLI may live before this file calls it a bug rather than a slow machine. */
const SPAWN_DEADLINE_MS = 10_000;

/**
 * The weights manifest as a handover directory carries it, at the command edge.
 *
 * A deployment's weights manifest is the file a receipt's `wts` digests and a deployment manifest's
 * `models[].wts` digests, and the gateway serves its bytes at `GET /v1/weights/<wts>`. A handover directory
 * carries no address, so before these cases the offline verdict printed digests it could not compare with
 * anything beside them. The bytes come in through `--companion`, the option a bundle already uses for the
 * file that travels beside a document, and what is read here is what the verdict says when they meet a `wts`,
 * when they do not, when a second manifest answers nothing the document names, and when nothing arrives at all.
 *
 * Every digest asserted below is computed in this file by `node:crypto` over the bytes this file wrote, and
 * the documents are sealed to name those figures. No case asks the implementation what it would have hashed
 * to: a test that repeated the arithmetic under test could not fail, and this check is arithmetic. The receipt
 * is issued by the shipped writer under the key the published fixtures are issued under, and the deployment
 * manifest is sealed by the shipped sealer, so the only hand-built thing is the digest field a case names.
 *
 * Two claims run through the file. A mismatch is reported and never refused, because a signature over a
 * receipt says nothing about which file a caller set beside it, so the exit code a passing run had is the exit
 * code an unmet run has. And the manifest is a companion rather than an eighth signed shape, which the last
 * case proves by naming those same bytes as the document: they carry no content type and no seal, and the
 * refusal they meet is the one this command already gives any unsigned file.
 */

const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
const DATA = fileURLToPath(new URL('../../fixtures/data/', import.meta.url));

const tempDir = mkdtempSync(join(tmpdir(), 'ashaveri-weights-manifest-'));
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

/** One file kept under its own name, in a directory of its own, because a companion is keyed by its basename. */
function writtenUnderItsOwnName(name: string, data: Uint8Array): string {
  const directory = join(tempDir, `dir${writtenCount++}`);
  mkdirSync(directory, { recursive: true });
  const path = join(directory, name);
  writeFileSync(path, data);
  return path;
}

function verdictOf(result: CliResult): Record<string, unknown> {
  return JSON.parse(result.stdout) as Record<string, unknown>;
}

/** The document members of a verdict, which is where every row this file reads lives. */
function documentOf(verdict: Record<string, unknown>): Record<string, unknown> {
  return verdict.document as Record<string, unknown>;
}

/** The `weightsBytes` row of a verdict, in the shape the JSON rendering gives it. */
interface WeightsRow {
  readonly handed: readonly { readonly name: string; readonly sha256: string; readonly bytes: number }[];
  readonly stated: readonly { readonly id: string; readonly wts: string; readonly answeredBy: readonly string[] }[];
  readonly unmatched: readonly string[];
}

function weightsRow(verdict: Record<string, unknown>): WeightsRow {
  return documentOf(verdict).weightsBytes as WeightsRow;
}

/** The row this file is about, from a human rendering, or the whole report when it is not there to read. */
function weightsLine(result: CliResult): string {
  const line = result.stdout.split('\n').find((one) => one.trimStart().startsWith('weights bytes:'));
  return line ?? result.stdout;
}

const sha256Hex = (bytes: Uint8Array): string => createHash('sha256').update(bytes).digest('hex');

/**
 * A weights manifest in the canonical spelling `enclave/weights.mjs` writes.
 *
 * One of these is the reading the documents below are sealed to name. Another stands for a different
 * deployment's reading: whole in its own right, and answered for by nothing in this directory.
 */
function weightsManifest(file: string, sha256: string): Uint8Array {
  return new TextEncoder().encode(`${JSON.stringify({ files: [{ path: file, sha256 }], v: 1 }, null, 2)}\n`);
}

const WEIGHTS = weightsManifest('Meta-Llama-3.1-8B-Instruct-Q8_0.gguf', '11'.repeat(32));
const WEIGHTS_DIGEST = sha256Hex(WEIGHTS);
const FOREIGN = weightsManifest('Meta-Llama-3.1-8B-Instruct-Q8_0.gguf', '22'.repeat(32));
const FOREIGN_DIGEST = sha256Hex(FOREIGN);
const EDITED = Uint8Array.from(WEIGHTS);
EDITED[EDITED.length - 2] = (EDITED[EDITED.length - 2] as number) ^ 0x01;
const EDITED_DIGEST = sha256Hex(EDITED);

const WEIGHTS_FILE = writtenUnderItsOwnName('weights-manifest.json', WEIGHTS);
const FOREIGN_FILE = writtenUnderItsOwnName('weights-manifest-other.json', FOREIGN);
const EDITED_FILE = writtenUnderItsOwnName('weights-manifest.json', EDITED);

/** The published receipt, its key, and the model it names, read rather than restated. */
const RECEIPT_KEY = JSON.parse(readFileSync(`${DATA}keys/receipt-key-v1.json`, 'utf8')) as {
  readonly kid: string;
  readonly publicKey: string;
  readonly privateKey: string;
};
const PUBLISHED = decodeReceipt(new Uint8Array(readFileSync(`${DATA}receipts/receipt-valid-v1.cbor`))).payload;
const RECEIPT_PUBLIC_B64URL = Buffer.from(RECEIPT_KEY.publicKey, 'hex').toString('base64url');
const MODEL = PUBLISHED.mdl;

/** The fixture key, so a receipt issued here is accepted by the designation the published vectors use. */
const FIXTURE_KEY = signingKeyFromSeed(new Uint8Array(Buffer.from(RECEIPT_KEY.privateKey, 'hex')));

/** The published receipt, issued again under the same key naming one reading's digest as its `wts`. */
function receiptStating(wts: string): string {
  const payload: ReceiptPayload = { ...PUBLISHED, wts: new Uint8Array(Buffer.from(wts, 'hex')) };
  return written(`receipt-${wts.slice(0, 8)}.cbor`, issueReceipt(payload, FIXTURE_KEY));
}

const RECEIPT = receiptStating(WEIGHTS_DIGEST);
const RECEIPT_INPUTS = ['verify-handover', RECEIPT, `--key=${RECEIPT_PUBLIC_B64URL}`] as const;

/** The key that seals the deployment manifest below, and the designation a run hands it under. */
const SEALING_KEY = generateSigningKey();
const SEALING_DESIGNATION = `--manifest-key=${Buffer.from(SEALING_KEY.publicKey).toString('base64url')}`;

/** A deployment manifest naming these models, sealed by the shipped sealer over the published pins. */
function manifestStating(models: readonly { readonly id: string; readonly wts: string }[]): string {
  const document = JSON.stringify({
    v: 1,
    iss: PUBLISHED.iss,
    ins: PUBLISHED.ins,
    epk: PUBLISHED.epk,
    keys: [{ kid: RECEIPT_KEY.kid, alg: 'Ed25519', publicKey: RECEIPT_PUBLIC_B64URL }],
    models,
    meas: { tee: PUBLISHED.meas.tee, m: toHex(PUBLISHED.meas.m) },
  });
  return written(
    'deployment-manifest.cbor',
    Buffer.from(sealDeploymentManifest(new TextEncoder().encode(document), SEALING_KEY)),
  );
}

describe('the weights manifest a handover directory can carry', () => {
  it('states that nothing was handed when nothing was, and leaves the digest as the document states it', () => {
    const human = runCli(RECEIPT_INPUTS);
    expect(human.stderr).toBe('');
    expect(human.status, human.stdout).toBe(0);
    expect(weightsLine(human)).toContain(
      'nothing was handed as --companion, so the 1 served-model digest(s) this document names are met by no bytes in this run',
    );
    expect(human.stdout).toContain(
      "not checked:      whether the served-model digest this document names is the digest of any bytes this run holds: nothing was handed as --companion, so it prints as the document's own figure",
    );

    const verdict = verdictOf(runCli([...RECEIPT_INPUTS, '--json']));
    expect(verdict.ok).toBe(true);
    expect(weightsRow(verdict)).toEqual({ handed: [], stated: [{ id: MODEL, wts: WEIGHTS_DIGEST, answeredBy: [] }], unmatched: [] });
    // The signed figure prints unchanged beside the statement that nothing met it: the row compares, it does
    // not rewrite what the document says.
    expect(documentOf(verdict).weights).toBe(WEIGHTS_DIGEST);
  });

  it('meets a receipt with the bytes a handover carried and names the model they answer for', () => {
    const withBytes = [...RECEIPT_INPUTS, `--companion=${WEIGHTS_FILE}`] as const;
    const human = runCli(withBytes);
    expect(human.stderr).toBe('');
    expect(human.status, human.stdout).toBe(0);
    const line = weightsLine(human);
    expect(line).toContain('1 of 1 served-model digest(s) met by bytes this run holds');
    expect(line).toContain(
      `sha256 over the ${String(WEIGHTS.byteLength)} byte(s) handed as weights-manifest.json reaches ${WEIGHTS_DIGEST}, the wts of ${MODEL}`,
    );
    expect(human.stdout).toContain(
      'not checked:      whether the bytes handed here are the weights a model is made of, or the files a deployment mounted',
    );

    expect(weightsRow(verdictOf(runCli([...withBytes, '--json'])))).toEqual({
      handed: [{ name: 'weights-manifest.json', sha256: WEIGHTS_DIGEST, bytes: WEIGHTS.byteLength }],
      stated: [{ id: MODEL, wts: WEIGHTS_DIGEST, answeredBy: ['weights-manifest.json'] }],
      unmatched: [],
    });
  });

  it('reports one byte changed in the manifest as a wts no handed file digests to, at the same exit code', () => {
    const run = runCli([...RECEIPT_INPUTS, `--companion=${EDITED_FILE}`]);
    expect(run.stderr).toBe('');
    expect(run.status, run.stdout).toBe(0);
    const line = weightsLine(run);
    expect(line).toContain('0 of 1 served-model digest(s) met by bytes this run holds');
    expect(line).toContain(`no file handed as --companion digests to the wts of ${MODEL} (${WEIGHTS_DIGEST})`);
    // What was handed is said with the number its bytes reached, which is the whole of the disclosure: the
    // copy under the right name is another manifest, and no report has to be told that.
    expect(line).toContain(`weights-manifest.json hashes to ${EDITED_DIGEST}, which is no wts this document names`);

    const verdict = verdictOf(runCli([...RECEIPT_INPUTS, `--companion=${EDITED_FILE}`, '--json']));
    expect(weightsRow(verdict)).toEqual({
      handed: [{ name: 'weights-manifest.json', sha256: EDITED_DIGEST, bytes: EDITED.byteLength }],
      stated: [{ id: MODEL, wts: WEIGHTS_DIGEST, answeredBy: [] }],
      unmatched: ['weights-manifest.json'],
    });
    // The signature is the same statement it was: a copy beside a receipt that hashes elsewhere is a finding
    // about the room, and no reader of these bytes refuses a document for it.
    expect(documentOf(verdict).signature).toBe(true);
  });

  it('discloses a manifest for a different deployment, and answers the receipt from the copy that matches', () => {
    const foreign = runCli([...RECEIPT_INPUTS, `--companion=${FOREIGN_FILE}`]);
    expect(foreign.status, foreign.stdout).toBe(0);
    expect(weightsLine(foreign)).toContain(
      `weights-manifest-other.json hashes to ${FOREIGN_DIGEST}, which is no wts this document names`,
    );

    // Both copies handed at once, which is what a caller running one line across a bundle does: each file is
    // accounted for, one by what it answers and one by what it answers for nothing.
    const both = [...RECEIPT_INPUTS, `--companion=${FOREIGN_FILE}`, `--companion=${WEIGHTS_FILE}`] as const;
    expect(weightsRow(verdictOf(runCli([...both, '--json'])))).toEqual({
      handed: [
        { name: 'weights-manifest-other.json', sha256: FOREIGN_DIGEST, bytes: FOREIGN.byteLength },
        { name: 'weights-manifest.json', sha256: WEIGHTS_DIGEST, bytes: WEIGHTS.byteLength },
      ],
      stated: [{ id: MODEL, wts: WEIGHTS_DIGEST, answeredBy: ['weights-manifest.json'] }],
      unmatched: ['weights-manifest-other.json'],
    });

    const line = weightsLine(runCli(both));
    expect(line).toContain('1 of 1 served-model digest(s) met by bytes this run holds');
    expect(line).toContain(
      `sha256 over the ${String(WEIGHTS.byteLength)} byte(s) handed as weights-manifest.json reaches ${WEIGHTS_DIGEST}, the wts of ${MODEL}`,
    );
    expect(line).toContain(`weights-manifest-other.json hashes to ${FOREIGN_DIGEST}, which is no wts this document names`);
  });

  it('answers each model a deployment manifest names from one file, and leaves the rest stated', () => {
    // A deployment hands the reading it hashed to every model it serves, so one file in the room answers the
    // ids in bulk, and the id naming another digest is the one left unmet rather than quietly dropped.
    const document = manifestStating([
      { id: 'llama-3.1-8b', wts: WEIGHTS_DIGEST },
      { id: 'llama-3.1-70b', wts: WEIGHTS_DIGEST },
      { id: 'mistral-7b', wts: FOREIGN_DIGEST },
    ]);
    const run = runCli(['verify-handover', document, SEALING_DESIGNATION, `--companion=${WEIGHTS_FILE}`]);
    expect(run.stderr).toBe('');
    expect(run.status, run.stdout).toBe(0);
    const line = weightsLine(run);
    expect(line).toContain('2 of 3 served-model digest(s) met by bytes this run holds');
    expect(line).toContain(`reaches ${WEIGHTS_DIGEST}, the wts of llama-3.1-8b, llama-3.1-70b`);
    expect(line).toContain(`no file handed as --companion digests to the wts of mistral-7b (${FOREIGN_DIGEST})`);

    // The unmet id is met by the other copy, so both files answer and none is disclosed as idle.
    const verdict = verdictOf(runCli([
      'verify-handover', document, SEALING_DESIGNATION,
      `--companion=${WEIGHTS_FILE}`, `--companion=${FOREIGN_FILE}`, '--json',
    ]));
    expect(weightsRow(verdict)).toEqual({
      handed: [
        { name: 'weights-manifest.json', sha256: WEIGHTS_DIGEST, bytes: WEIGHTS.byteLength },
        { name: 'weights-manifest-other.json', sha256: FOREIGN_DIGEST, bytes: FOREIGN.byteLength },
      ],
      stated: [
        { id: 'llama-3.1-8b', wts: WEIGHTS_DIGEST, answeredBy: ['weights-manifest.json'] },
        { id: 'llama-3.1-70b', wts: WEIGHTS_DIGEST, answeredBy: ['weights-manifest.json'] },
        { id: 'mistral-7b', wts: FOREIGN_DIGEST, answeredBy: ['weights-manifest-other.json'] },
      ],
      unmatched: [],
    });

    // Nothing handed: the whole list prints as unanswered, because the `models[]` row states the digests and
    // this run compared them with no bytes.
    const bare = verdictOf(runCli(['verify-handover', document, SEALING_DESIGNATION, '--json']));
    expect(weightsRow(bare).stated.map((one) => one.answeredBy)).toEqual([[], [], []]);
    expect(weightsLine(runCli(['verify-handover', document, SEALING_DESIGNATION]))).toContain(
      'nothing was handed as --companion, so the 3 served-model digest(s) this document names are met by no bytes in this run',
    );
  });

  it('reads the manifest as bytes a companion carries, not as a shape the classifier holds a reader for', () => {
    // The same bytes named as the document rather than beside one: no content type sits in them and no seal
    // closes them, so the refusal is the one this command gives any unsigned file. The manifest joined the
    // companion family, and nothing about the dispatch table moved with it.
    const result = runCli(['verify-handover', WEIGHTS_FILE, `--key=${RECEIPT_PUBLIC_B64URL}`, '--json']);
    expect(result.status).toBe(1);
    const refusal = verdictOf(result);
    expect(refusal.ok).toBe(false);
    expect(refusal.code).toBe('MALFORMED_CBOR');
    expect(refusal.contentType).toBeUndefined();
    expect(String(refusal.message)).toContain('these bytes carry no COSE protected header to classify');

    // A verb pinned to one shape meets the same refusal over the same bytes, with no code of its own.
    const pinned = verdictOf(runCli(['verify-pack', WEIGHTS_FILE, `--key=${RECEIPT_PUBLIC_B64URL}`, '--json']));
    expect(pinned.code).toBe('MALFORMED_CBOR');
  });
});
