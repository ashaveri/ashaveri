import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import { generateSigningKey, sealDeploymentManifest, type SigningKey } from '@ashaveri/receipt';
import { noteSpawn } from './support/spawn-budget.js';
/** How long one child of the built CLI may live before this file calls it a bug rather than a slow machine. */
const SPAWN_DEADLINE_MS = 10_000;

/**
 * The weights digest a receipt states, weighed against the manifest that declares what is served.
 *
 * A deployment manifest's `models[]` is that deployment's own list of the readings it serves, each under
 * the id it serves it as, and a receipt's `mdl` and `wts` are its claim about which entry it was issued
 * for. Before these cases the offline verdict printed the receipt's digest and compared it with nothing,
 * so a receipt stamped for a model the manifest does not name, or for a reading the manifest does not
 * call one of its own, passed and printed its digest as though it were trusted. This file runs the built
 * CLI over each of the four states a run can be in: declared and equal, declared with another digest,
 * declared not at all, and weighed by nothing because the document carrying the declaration was not
 * authenticated.
 *
 * The two refusals and both renderings of a run that reached a verdict are asserted as printed, because
 * the sentence is part of the product here: a verdict that weighed the digest has to say it and a verdict
 * that could not has to say that, and a reader who cannot tell which of the two happened has been handed
 * the same false comfort the gap gave. The unauthenticated cases substitute a sealed document's own bytes
 * rather than its signature, so each arrives as a manifest that fails to seal and states a declaration
 * disagreeing with the receipt on purpose. Those runs keep the exit code and the verdict they had before
 * the comparison existed, which is what makes the guard a guard rather than a second way to refuse a
 * receipt: whoever can put a file at `--manifest` gets no say over which receipts pass by writing a model
 * list into it.
 *
 * Every document here is built around the published valid vector, whose receipt, key, pins and response
 * bytes are read out of `packages/fixtures/data` rather than restated, and whose `models[]` row the helper
 * declares exactly as the receipt states it. Nothing in this file moves a published byte.
 */

const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
const DATA = fileURLToPath(new URL('../../fixtures/data/', import.meta.url));

const tempDir = mkdtempSync(join(tmpdir(), 'ashaveri-weights-compared-'));
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

function verdictOf(result: CliResult): Record<string, unknown> {
  return JSON.parse(result.stdout) as Record<string, unknown>;
}

/** The `weights` row of a human rendering, or the whole report when it is not there to read. */
function weightsLine(result: CliResult): string {
  const line = result.stdout.split('\n').find((one) => one.trimStart().startsWith('weights:'));
  return line ?? result.stdout;
}

/** One `models[]` entry, spelled the way a manifest spells one. */
interface ModelRow {
  readonly id: string;
  readonly wts: string;
}

/** The published receipt's own payload, and the key its row is issued under. */
const VALID = JSON.parse(readFileSync(`${DATA}receipts/receipt-valid-v1.json`, 'utf8')) as {
  payload: {
    iss: string;
    ins: string;
    iat: number;
    nce: string;
    req: string;
    mdl: string;
    wts: string;
    meas: { tee: string; m: string };
    epk: number;
  };
};
const KEY = JSON.parse(readFileSync(`${DATA}keys/receipt-key-v1.json`, 'utf8')) as {
  kid: string;
  publicKey: string;
};
const PUBLIC_KEY = Buffer.from(KEY.publicKey, 'hex').toString('base64url');
const MODEL = VALID.payload.mdl;
const STATED = VALID.payload.wts;

/** A digest no document here states, standing for another deployment's reading of the same model. */
const FOREIGN = 'f'.repeat(64);

/** The published row's response bytes: the marking this payload names is read out of them. */
const RESPONSE_ROW = (
  JSON.parse(readFileSync(`${DATA}manifest.json`, 'utf8')) as {
    fixtures: readonly { name: string; responseBase64Url?: string }[];
  }
).fixtures.find((one) => one.name === 'receipt-valid-v1');
if (RESPONSE_ROW?.responseBase64Url === undefined) {
  throw new Error('the published receipt index states no response bytes for the valid vector, so the marking check has nothing to read');
}
const RECEIPT = `${DATA}receipts/receipt-valid-v1.cbor`;
const RESPONSE_FILE = written('response.bin', Buffer.from(RESPONSE_ROW.responseBase64Url, 'base64url'));
const NOW = new Date(VALID.payload.iat * 1000).toISOString();

/** The policy a customer of this deployment writes: every family the published pins name. */
const POLICY = written(
  'policy.json',
  JSON.stringify({
    v: 1,
    issuers: [VALID.payload.iss],
    instances: [VALID.payload.ins],
    keys: { [KEY.kid]: PUBLIC_KEY },
    measurements: { [VALID.payload.meas.tee]: [VALID.payload.meas.m] },
    maxReceiptAgeSeconds: 300,
    maxEvidenceAgeSeconds: 900,
  }),
);

/** The key every deployment manifest below is sealed under, and the designation a run hands it under. */
const SEALING_KEY = generateSigningKey();
const DESIGNATION = `--manifest-key=${Buffer.from(SEALING_KEY.publicKey).toString('base64url')}`;

/** A deployment manifest declaring these models, in the shape the SDK parses. */
function manifestText(models: readonly ModelRow[]): string {
  return JSON.stringify({
    v: 1,
    iss: VALID.payload.iss,
    ins: VALID.payload.ins,
    epk: VALID.payload.epk,
    keys: [{ kid: KEY.kid, alg: 'Ed25519', publicKey: PUBLIC_KEY }],
    models,
    meas: { tee: VALID.payload.meas.tee, m: VALID.payload.meas.m },
  });
}

/** The declaration this receipt answers: the model it names, at the digest it states. */
const DECLARED: readonly ModelRow[] = [{ id: MODEL, wts: STATED }];

function sealedManifestFile(text: string, key: SigningKey): string {
  return written('manifest.cbor', Buffer.from(sealDeploymentManifest(new TextEncoder().encode(text), key)));
}

/**
 * A sealed manifest whose document was replaced, in place, by one exactly as long.
 *
 * The payload travels as a byte string, so a same-length swap leaves an envelope that still decodes and
 * leaves the signature as the only thing that can notice the bytes are not the ones that were signed. This
 * is how a case reaches a manifest that fails to seal while still carrying a `models[]` row the comparison
 * would refuse, were the document one its reader had authenticated.
 */
function sealedAroundSwappedDocument(signed: string, swapped: string, key: SigningKey): string {
  const original = new TextEncoder().encode(signed);
  const replacement = Buffer.from(swapped, 'utf8');
  if (original.length !== replacement.length) {
    throw new Error('a swapped payload has to be exactly as long, or the envelope would not decode');
  }
  // The document goes in as a plain `Uint8Array` rather than the `Buffer` the search below needs: the
  // canonical CBOR writer in the format package takes a `Buffer` apart as the object it is instead of
  // encoding its bytes, and the envelope that comes out is nothing a reader calls a sealed manifest.
  const sealed = Buffer.from(sealDeploymentManifest(original, key));
  const at = sealed.indexOf(Buffer.from(original));
  if (at < 0) {
    throw new Error('the sealed envelope carries no copy of the document it was built from');
  }
  replacement.copy(sealed, at);
  return written('swapped.cbor', sealed);
}

/** The published model id with its last character moved, so a swapped document stays exactly as long. */
const OTHER_MODEL = `${MODEL.slice(0, -1)}${MODEL.endsWith('x') ? 'y' : 'x'}`;

/** One run of the command over a manifest this file built, in the shape the caller asked for. */
function run(manifest: string, extra: readonly string[], json: boolean): CliResult {
  return runCli([
    'verify-receipt',
    RECEIPT,
    `--policy=${POLICY}`,
    `--manifest=${manifest}`,
    `--nonce=${VALID.payload.nce}`,
    `--request-hash=${VALID.payload.req}`,
    `--response-body=${RESPONSE_FILE}`,
    `--now=${NOW}`,
    ...extra,
    ...(json ? ['--json'] : []),
  ]);
}

/** The sentence both renderings print, so a case states one string rather than two shapes of it. */
const WEIGHED = `compared with the authenticated manifest's declaration for ${MODEL}, which states ${STATED}, the same digest`;
const UNWEIGHED = `not compared: the deployment manifest declaring the reading served for ${MODEL} was not authenticated, so this run weighed no digest against it`;

describe('the weights digest compared with the manifest at the command edge', () => {
  it('weighs the receipt against the authenticated declaration and says that it did', () => {
    const manifest = sealedManifestFile(manifestText(DECLARED), SEALING_KEY);
    const human = run(manifest, [DESIGNATION], false);
    expect(human.stderr).toBe('');
    expect(human.status, human.stdout).toBe(0);
    expect(weightsLine(human)).toBe(`  weights:          ${STATED}, ${WEIGHED}`);

    const verdict = verdictOf(run(manifest, [DESIGNATION], true));
    expect(verdict.ok).toBe(true);
    expect(verdict.weights).toBe(STATED);
    expect(verdict.weightsComparedWithManifest).toEqual({
      compared: true,
      model: MODEL,
      manifestDigest: STATED,
      statement: WEIGHED,
    });
    expect(verdict.manifestSeal).toMatchObject({ sealed: true, authenticated: true });
  });

  it('refuses a model the authenticated manifest declares nothing about', () => {
    // The manifest does speak of models: one entry, for another id, which is the shape that used to print
    // this receipt's digest beside a verdict and call it done.
    const undeclared = run(sealedManifestFile(manifestText([{ id: OTHER_MODEL, wts: STATED }]), SEALING_KEY), [DESIGNATION], true);
    expect(undeclared.stderr).toBe('');
    expect(undeclared.status).toBe(1);
    const refusal = verdictOf(undeclared);
    expect(refusal.code).toBe('MODEL_UNDECLARED');
    expect(String(refusal.message)).toContain(`declares no model with id '${MODEL}'`);
    expect(String(refusal.message)).toContain('carries 1 entry and none of them names that id');
    expect(String(refusal.message)).toContain(`the weights digest this receipt states (${STATED})`);
    // The receipt's own digest is the only digest in the answer: a refusal about an absent entry has no
    // declared figure to name, and inventing one would state a declaration the manifest does not carry.
    expect(JSON.stringify(refusal)).not.toContain(FOREIGN);

    // A manifest declaring no model at all is the same fact, and the count says which of the two a reader
    // is being told about.
    const empty = run(sealedManifestFile(manifestText([]), SEALING_KEY), [DESIGNATION], true);
    expect(empty.status).toBe(1);
    expect(String(verdictOf(empty).message)).toContain('carries 0 entries');

    const human = run(sealedManifestFile(manifestText([]), SEALING_KEY), [DESIGNATION], false);
    expect(human.stdout).toBe('');
    expect(human.status).toBe(1);
    expect(human.stderr).toBe(`verification failed (MODEL_UNDECLARED): ${String(verdictOf(empty).message)}\n`);
  });

  it('refuses a reading the authenticated manifest declares otherwise, naming both digests', () => {
    const manifest = sealedManifestFile(manifestText([{ id: MODEL, wts: FOREIGN }]), SEALING_KEY);
    const refused = run(manifest, [DESIGNATION], true);
    expect(refused.stderr).toBe('');
    expect(refused.status).toBe(1);
    const refusal = verdictOf(refused);
    expect(refusal.code).toBe('WEIGHTS_DISAGREE');
    // Both figures, because what decides what a reader does next is which of the two the deployment
    // declared and which the receipt states.
    expect(String(refusal.message)).toContain(`declares model '${MODEL}' with weights ${FOREIGN}`);
    expect(String(refusal.message)).toContain(`and this receipt states ${STATED}`);
    expect(String(refusal.message)).toContain('which is a different reading of that model');

    const human = run(manifest, [DESIGNATION], false);
    expect(human.stdout).toBe('');
    expect(human.status).toBe(1);
    expect(human.stderr).toBe(`verification failed (WEIGHTS_DISAGREE): ${String(refusal.message)}\n`);
  });

  /**
   * The guard, in the shape that costs a caller the most to get wrong.
   *
   * Each manifest here fails to seal and states a declaration the receipt disagrees with, so a run that
   * trusted the text would refuse. None of them does, and none of them claims a check: each answers with
   * the verdict this command answered before the comparison existed, beside the sentence that says nothing
   * was weighed. The unauthenticated manifest's figure is asserted absent rather than merely unmentioned,
   * because a report that printed it would let a document nobody established read as a figure the verdict
   * stood on.
   */
  it('weighs nothing on a manifest it could not authenticate, and keeps the verdict the run reached', () => {
    const disagreeingDigest = sealedAroundSwappedDocument(manifestText(DECLARED), manifestText([{ id: MODEL, wts: FOREIGN }]), SEALING_KEY);
    const json = run(disagreeingDigest, [], true);
    expect(json.stderr).toBe('');
    expect(json.status, json.stdout).toBe(0);
    const verdict = verdictOf(json);
    expect(verdict.ok).toBe(true);
    expect(verdict.manifestSeal).toMatchObject({ sealed: true, authenticated: false });
    expect(verdict.weightsComparedWithManifest).toEqual({
      compared: false,
      model: MODEL,
      manifestDigest: null,
      statement: UNWEIGHED,
    });
    expect(JSON.stringify(verdict)).not.toContain(FOREIGN);

    const human = run(disagreeingDigest, [], false);
    expect(human.stderr).toBe('');
    expect(human.status, human.stdout).toBe(0);
    expect(weightsLine(human)).toBe(`  weights:          ${STATED}, ${UNWEIGHED}`);
    expect(human.stdout).not.toContain(FOREIGN);

    // The same guard over a document naming another model, and over a manifest served unsigned, which is
    // the posture of every caller that designated no signer: neither answers a new code either, and the
    // sealed and the plain document report the same absence.
    const otherModel = sealedAroundSwappedDocument(manifestText(DECLARED), manifestText([{ id: OTHER_MODEL, wts: STATED }]), SEALING_KEY);
    expect(run(otherModel, [], true).status).toBe(0);
    const unsigned = written('manifest.json', manifestText([{ id: MODEL, wts: FOREIGN }]));
    const unsignedVerdict = verdictOf(run(unsigned, [], true));
    expect(unsignedVerdict.ok).toBe(true);
    expect(unsignedVerdict.manifestSeal).toMatchObject({ sealed: false, authenticated: false });
    expect(unsignedVerdict.weightsComparedWithManifest).toMatchObject({ compared: false, manifestDigest: null });
    expect(JSON.stringify(unsignedVerdict)).not.toContain(FOREIGN);
  });
});
