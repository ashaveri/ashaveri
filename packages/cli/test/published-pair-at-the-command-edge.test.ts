import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import { MANIFEST_SIGNER_ROLE } from '@ashaveri/fixtures';
import { noteSpawn } from './support/spawn-budget.js';

/** How long one child of the built CLI may live before this file calls it a bug rather than a slow machine. */
const SPAWN_DEADLINE_MS = 10_000;

/**
 * A published receipt and the published manifest of the deployment that receipt came from, met at the
 * command line in both directions.
 *
 * The receipt vectors and the sealed-manifest vectors describe two deployments: the ten published receipts
 * all name `dpl-9f2a41c3` and one model at one weights digest, while the manifest family speaks of
 * `ashaveri-mock` at `mock-instance-1`, with a `models[]` entry naming `mock-model-1`, so a published
 * receipt brought to `ashaveri verify-receipt` beside a published manifest meets a refusal with nothing
 * committed to say whether the documents, the command or the expectation is at fault.
 * `paired-with-the-published-receipt-family` in `manifest-v1.json` is the document that closes that gap,
 * and this file is what it looks like from the outside: the same receipt bytes, the same policy, the same
 * response body, one run against each of two manifests.
 *
 * Everything here is read out of `packages/fixtures/data`: the receipt's payload, the key its protected
 * header names, the response bytes its row publishes beside it, the manifest bytes of each row and the
 * designation each row states. No value is restated from a note, because a test that retypes the digests
 * passes against whatever the vector says, and is evidence about the bytes only while it reads them.
 */

const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
const DATA = fileURLToPath(new URL('../../fixtures/data/', import.meta.url));

const tempDir = mkdtempSync(join(tmpdir(), 'ashaveri-published-pair-'));
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

/** One published row of the sealed-manifest suite, as far as this file reaches into it. */
interface ManifestRow {
  readonly name: string;
  readonly documentBase64Url: string;
  readonly read: { readonly designates: readonly { kid: string; publicKeyBase64Url: string }[] };
  readonly parsed?: {
    readonly iss: string;
    readonly ins: string;
    readonly epk: number;
    readonly keys: readonly { kid: string; publicKey: string }[];
    readonly models: readonly { id: string; wts: string }[];
    readonly meas: { tee: string; m: string };
  };
}

/** One entry of the suite's published key material: the id, the half a caller pins, and the duty it states. */
interface KeyMaterial {
  readonly kidHex: string;
  readonly publicKeyBase64Url: string;
  readonly role: string;
}

const vectors = JSON.parse(readFileSync(`${DATA}manifest-v1.json`, 'utf8')) as {
  vectors: ManifestRow[];
  layout: { keyMaterial: KeyMaterial[] };
};

/** The published material a designated id is read from, which is where a caller gets a key's duty. */
function publishedMaterial(kid: string): KeyMaterial | undefined {
  return vectors.layout.keyMaterial.find((one) => one.kidHex === kid);
}

/** The published material whose stated duty is signing the manifests a reader designates. */
function manifestSignerMaterial(): KeyMaterial {
  const material = vectors.layout.keyMaterial.find((one) => one.role === MANIFEST_SIGNER_ROLE);
  if (material === undefined) {
    throw new Error(`manifest-v1.json publishes no key material whose role is '${MANIFEST_SIGNER_ROLE}'`);
  }
  return material;
}

/** The row cut from the receipts' own deployment, and the honest row of the family this suite began with. */
const PAIRED = vectors.vectors.find((one) => one.name === 'paired-with-the-published-receipt-family');
const MOCK = vectors.vectors.find((one) => one.name === 'sealed-under-designated-key');
if (PAIRED?.parsed === undefined || PAIRED.read.designates.length !== 1) {
  throw new Error('manifest-v1.json publishes no paired row, so the published pairing this file runs is not there');
}
if (MOCK?.parsed === undefined || MOCK.read.designates.length !== 1) {
  throw new Error('manifest-v1.json publishes no honest mock row, so the refusing direction has nothing to refuse against');
}

/** The published receipt whose pairing is at issue, with the payload its own twin file states. */
const RECEIPT = `${DATA}receipts/receipt-buffered-v1.cbor`;
const receiptJson = JSON.parse(readFileSync(`${DATA}receipts/receipt-buffered-v1.json`, 'utf8')) as {
  protectedHeader: { kid: string };
  payload: {
    iss: string;
    ins: string;
    iat: number;
    nce: string;
    req: string;
    mdl: string;
    wts: string;
    epk: number;
    meas: { tee: string; m: string };
  };
};
const PAYLOAD = receiptJson.payload;

/** The signing material the published receipt was sealed under, as the committed key file states it. */
const KEY = JSON.parse(readFileSync(`${DATA}keys/receipt-key-v1.json`, 'utf8')) as {
  kid: string;
  publicKey: string;
};
const PUBLIC_KEY = Buffer.from(KEY.publicKey, 'hex').toString('base64url');

/** The response bytes the receipt index publishes beside the row, which the marking check reads. */
const RESPONSE_ROW = (
  JSON.parse(readFileSync(`${DATA}manifest.json`, 'utf8')) as {
    fixtures: readonly { name: string; responseBase64Url?: string }[];
  }
).fixtures.find((one) => one.name === 'receipt-buffered-v1');
if (RESPONSE_ROW?.responseBase64Url === undefined) {
  throw new Error('the published receipt index states no response bytes for the buffered vector');
}

const RESPONSE_FILE = written('response.bin', Buffer.from(RESPONSE_ROW.responseBase64Url, 'base64url'));
const NOW = new Date(PAYLOAD.iat * 1000).toISOString();

/** The policy a customer of the receipts' deployment writes, every family read off the published bytes. */
const POLICY = written(
  'policy.json',
  JSON.stringify({
    v: 1,
    issuers: [PAYLOAD.iss],
    instances: [PAYLOAD.ins],
    keys: { [KEY.kid]: PUBLIC_KEY },
    measurements: { [PAYLOAD.meas.tee]: [PAYLOAD.meas.m] },
    maxReceiptAgeSeconds: 300,
    maxEvidenceAgeSeconds: 900,
  }),
);

/** One published manifest row, served as the file a caller would point `--manifest` at. */
interface ServedManifest {
  readonly row: ManifestRow;
  readonly path: string;
}

function serve(row: ManifestRow): ServedManifest {
  return { row, path: written(`${row.name}.cbor`, Buffer.from(row.documentBase64Url, 'base64url')) };
}

/** The parsed document one published row states, which is where this file reads a manifest's own values. */
function parsedOf(row: ManifestRow): NonNullable<ManifestRow['parsed']> {
  if (row.parsed === undefined) throw new Error(`${row.name} states no parsed document`);
  return row.parsed;
}

/** The designation the row itself states: the id, and the public half pinned under it. */
function designated(row: ManifestRow): string {
  const pin = row.read.designates[0];
  if (pin === undefined) throw new Error(`${row.name} states no designated key`);
  return `--manifest-key=${pin.publicKeyBase64Url}`;
}

/**
 * One run of the command over one published manifest, in the rendering the caller asked for.
 *
 * The designation defaults to the one the row states, and a caller can name one read off the published
 * key material instead, which is how a run can be made to depend on a key's published duty rather than on
 * the row that carries it.
 */
function run(one: ServedManifest, json: boolean, manifestKey: string = designated(one.row)): CliResult {
  return runCli([
    'verify-receipt',
    RECEIPT,
    `--policy=${POLICY}`,
    `--manifest=${one.path}`,
    manifestKey,
    `--nonce=${PAYLOAD.nce}`,
    `--request-hash=${PAYLOAD.req}`,
    `--response-body=${RESPONSE_FILE}`,
    `--now=${NOW}`,
    ...(json ? ['--json'] : []),
  ]);
}

const PAIRED_MANIFEST = serve(PAIRED);
const MOCK_MANIFEST = serve(MOCK);

describe('a published receipt met with the published manifest of its own deployment', () => {
  /**
   * The provenance of the pairing, held before any child is started.
   *
   * Each deployment member of the paired document is the member of the published receipt it is paired
   * with, its seal is authenticated under the published material whose stated duty is signing the manifests
   * a reader designates rather than under the receipt key the document lists, and the mock document states a
   * model that receipt names nowhere, which is what the two directions below turn on. Were either of those
   * untrue, a passing run would be evidence about a pairing the published bytes never claimed. The generator
   * holds the same facts where the row is written, and this is the guard that makes a vector that drifted
   * fail in the suite consuming it rather than only in the one that produced it.
   */
  it('is built out of the receipt file rather than beside it', () => {
    const parsed = parsedOf(PAIRED);
    expect(parsed.iss).toBe(PAYLOAD.iss);
    expect(parsed.ins).toBe(PAYLOAD.ins);
    expect(parsed.epk).toBe(PAYLOAD.epk);
    expect(parsed.meas).toEqual(PAYLOAD.meas);
    expect(parsed.keys).toEqual([{ kid: receiptJson.protectedHeader.kid, alg: 'Ed25519', publicKey: PUBLIC_KEY }]);
    expect(parsed.models).toEqual([{ id: PAYLOAD.mdl, wts: PAYLOAD.wts }]);
    expect(parsedOf(MOCK).models).not.toEqual(parsed.models);
    expect(parsedOf(MOCK).iss).not.toBe(PAYLOAD.iss);
    // The seal is designated apart from the receipt key, because `--manifest-key` is what the run hands the
    // client for that duty: the id, and the public half the suite publishes beside it, have to name the key
    // whose published role is signing manifests rather than the key this row lists as signing receipts.
    const designated = PAIRED.read.designates[0];
    expect(
      designated?.kid,
      'the paired row designates the receipt key it lists as its seal signer, one key for both roles',
    ).not.toBe(receiptJson.protectedHeader.kid);
    const sealMaterial = publishedMaterial(designated?.kid ?? '');
    expect(sealMaterial?.publicKeyBase64Url, `${designated?.kid} designates a half no published material carries`).toBe(
      designated?.publicKeyBase64Url,
    );
    expect(sealMaterial?.role, `${designated?.kid} seals the paired row and publishes no manifest signing role`).toBe(
      MANIFEST_SIGNER_ROLE,
    );
  });

  it('verifies against the paired manifest and prints the weights as compared', () => {
    const human = run(PAIRED_MANIFEST, false);
    expect(human.stderr).toBe('');
    expect(human.status, human.stdout).toBe(0);
    expect(weightsLine(human)).toBe(
      `  weights:          ${PAYLOAD.wts}, compared with the authenticated manifest, which states that digest for ${PAYLOAD.mdl}`,
    );
    expect(human.stdout).toContain(`  issuer:           ${PAYLOAD.iss}`);
    const paired = parsedOf(PAIRED);
    expect(human.stdout).toContain(
      `  manifest:         ${PAIRED_MANIFEST.path} (issuer ${paired.iss}, instance ${paired.ins})`,
    );

    const verdict = verdictOf(run(PAIRED_MANIFEST, true));
    expect(verdict.ok).toBe(true);
    expect(verdict.weights).toBe(PAYLOAD.wts);
    expect(verdict.weightsComparedWithManifest).toEqual({
      compared: true,
      model: PAYLOAD.mdl,
      // The figure the manifest declares, read off the published row rather than from the receipt, so a
      // run that printed the receipt's own claim back would be caught rather than praised.
      manifestDigest: paired.models[0]?.wts,
      statement: `compared with the authenticated manifest, which states that digest for ${PAYLOAD.mdl}`,
    });
    expect(verdict.manifestSeal).toMatchObject({ sealed: true, authenticated: true });
  });

  /**
   * The other direction, over the same receipt, the same policy and the same response bytes.
   *
   * The mock manifest is whole, authenticates under its own designated key and lists the very key that
   * signed this receipt, so nothing about the seal, the pins or the epochs separates the two documents:
   * the array of what it declares it serves names another model, and the answer says exactly that.
   */
  it('refuses the same receipt against the mock manifest, naming the model it declares nothing about', () => {
    const refused = run(MOCK_MANIFEST, true);
    expect(refused.stderr).toBe('');
    expect(refused.status).toBe(1);
    const refusal = verdictOf(refused);
    expect(refusal.code).toBe('MODEL_UNDECLARED');
    const message = String(refusal.message);
    const declared = parsedOf(MOCK).models.length;
    expect(message).toContain(`declares no model with id '${PAYLOAD.mdl}'`);
    expect(message).toContain(`carries ${String(declared)} ${declared === 1 ? 'entry' : 'entries'} and none of them names that id`);
    expect(message).toContain(`the weights digest this receipt states (${PAYLOAD.wts})`);

    const human = run(MOCK_MANIFEST, false);
    expect(human.stdout).toBe('');
    expect(human.status).toBe(1);
    expect(human.stderr).toBe(`verification failed (MODEL_UNDECLARED): ${message}\n`);
  });

  /**
   * The paired bytes run with the designation named from `layout.keyMaterial` rather than from the row.
   *
   * A row that states its own designation makes this file hand the command the answer it is testing, so a
   * document sealed under the key it also lists for signing receipts would be run under that same key and
   * still exit 0. Reading the designation off the published duties instead gives the exit code something
   * to notice: the document holds under the material whose published role is signing the manifests a
   * reader designates, and designating only the receipt key this document lists leaves its seal named by no
   * one the caller accepted, which the client answers fatally rather than by reading the bytes anyway.
   * The published duty and the paired row name one key, so the flag below is the one the run in `verifies
   * against the paired manifest and prints the weights as compared` builds from that row. The first
   * assertion states the agreement, and it is what fails when the duty and the row name different keys,
   * rather than this case becoming a second child process over bytes another case already read.
   */
  it('accepts the paired bytes under the published manifest signing key', () => {
    const fromRow = PAIRED.read.designates[0];
    expect(
      manifestSignerMaterial().kidHex,
      `the published manifest signing duty names ${manifestSignerMaterial().kidHex} while the paired row designates ${fromRow?.kid}, so the designation read off the duty is no longer the one the row states`,
    ).toBe(fromRow?.kid);
    const accepted = run(PAIRED_MANIFEST, true, `--manifest-key=${manifestSignerMaterial().publicKeyBase64Url}`);
    expect(accepted.stderr).toBe('');
    expect(accepted.status, accepted.stdout).toBe(0);
    const verdict = verdictOf(accepted);
    expect(verdict.ok).toBe(true);
    expect(verdict.weights).toBe(PAYLOAD.wts);
    expect(verdict.manifestSeal).toMatchObject({ sealed: true, authenticated: true });
  });

  it('refuses the paired bytes under the published receipt key alone', () => {
    const receiptMaterial = publishedMaterial(receiptJson.protectedHeader.kid);
    if (receiptMaterial === undefined) {
      throw new Error('manifest-v1.json publishes no key material for the key the paired receipt carries');
    }
    expect(receiptMaterial.role, `${receiptMaterial.kidHex} is listed as signing receipts and also signs manifests`).not.toBe(
      MANIFEST_SIGNER_ROLE,
    );
    const refused = run(PAIRED_MANIFEST, true, `--manifest-key=${receiptMaterial.publicKeyBase64Url}`);
    expect(refused.stderr).toBe('');
    expect(refused.status).toBe(1);
    expect(verdictOf(refused).code).toBe('MANIFEST_NOT_AUTHENTICATED');
  });
});
