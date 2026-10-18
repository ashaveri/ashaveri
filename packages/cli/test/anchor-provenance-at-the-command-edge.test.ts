import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import {
  ANCHOR_LEDGER_CONTENT_TYPE,
  ANCHOR_LEDGER_FILES,
  encodeAnchorLedger,
  parseAnchorLedger,
  sealAnchorLedger,
} from '@ashaveri/attest-core';
import { signingKeyFromSeed, toHex } from '@ashaveri/receipt';
import { noteSpawn } from './support/spawn-budget.js';
/** How long one child of the built CLI may live before this file calls it a bug rather than a slow machine. */
const SPAWN_DEADLINE_MS = 10_000;

/**
 * The seventh signed content type, at the command edge.
 *
 * The document is the ledger this repository commits, its rows held against the anchors and fixtures the
 * attest package ships: the body is read once through that package's own parser with those bytes handed,
 * the declared key list is replaced with the test key's id, and the body is sealed with that key. Nothing
 * about a row is written here, so a case cannot drift from the artifact it is about.
 *
 * What each case holds is the answer the shipped reader gives through the handover dispatch: an accepted
 * ledger prints every row and the bytes each row was checked against, a ledger missing a tracked file is
 * refused by the row that names it, a pin that does not match names both keys, and a companion whose
 * bytes a row does not digest names the row and both digests. The freshness row is asserted here too,
 * because a provenance statement is historical by construction and the report must not let it read as a
 * present assurance.
 */

const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
const ATTEST = fileURLToPath(new URL('../../attest-core/', import.meta.url));
const COMMITTED_LEDGER = join(ATTEST, 'data/anchor-provenance-v1.cbor');
const FIXTURE_PREFIX = 'test/fixtures/';

const tempDir = mkdtempSync(join(tmpdir(), 'ashaveri-anchor-provenance-'));
afterAll(() => {
  rmSync(tempDir, { recursive: true, force: true });
});

interface CliResult {
  readonly status: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

function runCli(args: string[]): CliResult {
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
function written(name: string, data: Uint8Array): string {
  const path = join(tempDir, `${writtenCount++}-${name}`);
  writeFileSync(path, data);
  return path;
}

/** One file kept under its own name, because a ledger row matches a companion by the bare name it carries. */
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

/** The tracked fixture bytes the committed ledger's rows name, under the names those rows carry. */
const SHIPPED: ReadonlyMap<string, Uint8Array> = new Map<string, Uint8Array>(
  ANCHOR_LEDGER_FILES.filter((file) => file.startsWith(FIXTURE_PREFIX)).map((file) => [
    file,
    new Uint8Array(readFileSync(join(ATTEST, file))),
  ]),
);

/** The committed body, read over the bytes it names rather than over a copy of its claims. */
const COMMITTED = parseAnchorLedger(new Uint8Array(readFileSync(COMMITTED_LEDGER)), { shipped: SHIPPED });

/** A synthetic key, because the artifact's own key is held outside this repository. */
const SEED = Uint8Array.from(new Array(32).fill(7));
const KEY = signingKeyFromSeed(SEED);
const PUBLIC_KEY = Buffer.from(KEY.publicKey).toString('base64url');
const PIN = `--key=${PUBLIC_KEY}`;

const LEDGER_PATH = written(
  'committed-ledger.cbor',
  sealAnchorLedger(encodeAnchorLedger({ ...COMMITTED, keys: [KEY.kid] }), SEED).bytes,
);

/** One companion file per tracked row, each under the bare name its row states. */
const COMPANIONS: readonly string[] = [...SHIPPED.keys()].map((file) =>
  writtenUnderItsOwnName(basename(file), SHIPPED.get(file) as Uint8Array),
);
const COMPANION_ARGS = COMPANIONS.map((path) => `--companion=${path}`);

/** A fixture named by a row but carrying another file's bytes, which is the substitution a handover invites. */
const AMD_FIXTURE = `${FIXTURE_PREFIX}amd-ark-milan.pem`;
const SUBSTITUTED = writtenUnderItsOwnName(
  'amd-ark-milan.pem',
  new Uint8Array(readFileSync(join(ATTEST, `${FIXTURE_PREFIX}intel-sgx-root-ca.pem`))),
);
const SUBSTITUTED_ARGS = [
  ...COMPANIONS.filter((path) => basename(path) !== basename(AMD_FIXTURE)).map((path) => `--companion=${path}`),
  `--companion=${SUBSTITUTED}`,
];

/** The committed row's digest for one file, which is the figure the report prints. */
function committedDigest(file: string): string {
  const row = COMMITTED.rows.find((one) => one.file === file);
  if (row === undefined) throw new Error(`the committed ledger names no row for ${file}`);
  return toHex(row.digest);
}

describe('ashaveri/anchor-provenance at the command edge', () => {
  it('reads the committed ledger and prints every row with the bytes it was checked against', () => {
    const result = runCli(['verify-handover', LEDGER_PATH, PIN, ...COMPANION_ARGS, '--json']);
    expect(result.stderr).toBe('');
    expect(result.status, result.stderr).toBe(0);
    const report = verdictOf(result);
    expect(report).toMatchObject({
      ok: true,
      contentType: ANCHOR_LEDGER_CONTENT_TYPE,
      reader: 'verifyAnchorLedger',
      kid: toHex(KEY.kid),
    });
    const document = report.document as Record<string, unknown>;
    expect(document.generatedAt).toBe(COMMITTED.generatedAt);
    expect(document.declaredKeys).toEqual([toHex(KEY.kid)]);
    expect(document.shipped).toEqual({
      embedded: 3,
      fromCompanions: 10,
      companionsHanded: 10,
      unused: [],
    });
    expect(document[`row-0`]).toMatchObject({ file: 'src/trust-anchors.ts#INTEL_SGX_ROOT_CA_PEM' });
    expect((document[`row-0`] as { digest: string }).digest).toBe(committedDigest('src/trust-anchors.ts#INTEL_SGX_ROOT_CA_PEM'));
    expect(document[`row-6`]).toMatchObject({ file: AMD_FIXTURE, licence: 'apache-2.0' });
    expect((document[`row-6`] as { digest: string }).digest).toBe(committedDigest(AMD_FIXTURE));
    expect(Object.keys(document).filter((key) => key.startsWith('row-'))).toHaveLength(COMMITTED.rows.length);

    const human = runCli(['verify-handover', LEDGER_PATH, PIN, ...COMPANION_ARGS]);
    expect(human.status, human.stderr).toBe(0);
    expect(human.stdout.split('\n')[0]).toBe(`content type:     ${ANCHOR_LEDGER_CONTENT_TYPE}`);
    expect(human.stdout).toContain('generated at:');
    expect(human.stdout).toContain(committedDigest(AMD_FIXTURE));
    expect(human.stdout).toContain('licence apache-2.0');
  });

  it('refuses a ledger whose tracked bytes were not handed, naming the first row that asks for one', () => {
    const result = runCli(['verify-handover', LEDGER_PATH, PIN, '--json']);
    expect(result.status).toBe(1);
    const refusal = verdictOf(result);
    expect(refusal).toMatchObject({
      ok: false,
      contentType: ANCHOR_LEDGER_CONTENT_TYPE,
      code: 'ANCHOR_LEDGER_BYTES_UNAVAILABLE',
    });
    expect(String(refusal.message)).toContain(`rows[3] names ${FIXTURE_PREFIX}sev-snp-attestation.bin`);
  });

  it('refuses a ledger under a key this run did not pin, naming both kids', () => {
    const stranger = signingKeyFromSeed(Uint8Array.from(new Array(32).fill(11)));
    const result = runCli(['verify-handover', LEDGER_PATH, `--key=${Buffer.from(stranger.publicKey).toString('base64url')}`, ...COMPANION_ARGS, '--json']);
    expect(result.status).toBe(1);
    const refusal = verdictOf(result);
    expect(refusal).toMatchObject({
      ok: false,
      contentType: ANCHOR_LEDGER_CONTENT_TYPE,
      code: 'ANCHOR_LEDGER_PIN_MISMATCH',
    });
    expect(String(refusal.message)).toContain(toHex(KEY.kid));
    expect(String(refusal.message)).toContain(toHex(stranger.kid));
  });

  it('refuses bytes a row does not digest, naming the row and both digests', () => {
    const result = runCli(['verify-handover', LEDGER_PATH, PIN, ...SUBSTITUTED_ARGS, '--json']);
    expect(result.status).toBe(1);
    const refusal = verdictOf(result);
    expect(refusal).toMatchObject({
      ok: false,
      contentType: ANCHOR_LEDGER_CONTENT_TYPE,
      code: 'ANCHOR_LEDGER_DIGEST_MISMATCH',
    });
    const message = String(refusal.message);
    expect(message).toContain('rows[6]');
    expect(message).toContain(committedDigest(AMD_FIXTURE));
    expect(message).toContain(committedDigest(`${FIXTURE_PREFIX}intel-sgx-root-ca.pem`));
  });

  it('discloses a companion no row names, and reads the accepted ledger without it', () => {
    const uninvited = writtenUnderItsOwnName(
      'uninvited.bin',
      new TextEncoder().encode('no ledger row names these bytes'),
    );
    const result = runCli(['verify-handover', LEDGER_PATH, PIN, ...COMPANION_ARGS, `--companion=${uninvited}`, '--json']);
    expect(result.status, result.stderr).toBe(0);
    const document = verdictOf(result).document as Record<string, unknown>;
    expect(document.shipped).toMatchObject({ companionsHanded: 11, unused: ['uninvited.bin'] });
    const human = runCli(['verify-handover', LEDGER_PATH, PIN, ...COMPANION_ARGS, `--companion=${uninvited}`]);
    expect(human.stdout).toContain('1 companion file(s) no row named');
  });

  it('reports the ledger as historical and its freshness as unknown rather than present assurance', () => {
    const result = runCli(['verify-handover', LEDGER_PATH, PIN, ...COMPANION_ARGS, '--json']);
    expect(result.status, result.stderr).toBe(0);
    const document = verdictOf(result).document as Record<string, unknown>;
    expect(document.freshness).toMatchObject({
      current: null,
      freshness: 'unknown',
      clockConsulted: false,
      historical: {
        generatedAt: COMMITTED.generatedAt,
        takenAt: {
          from: Math.min(...COMMITTED.rows.map((one) => one.takenAt)),
          to: Math.max(...COMMITTED.rows.map((one) => one.takenAt)),
        },
      },
    });
    const human = runCli(['verify-handover', LEDGER_PATH, PIN, ...COMPANION_ARGS]);
    expect(human.stdout).toContain('freshness:        historical:');
    expect(human.stdout).toContain('freshness: unknown');
  });

  it('refuses the ledger handed to a verb pinned to another type, and asks for its own pin by name', () => {
    const pinned = runCli(['verify-pack', LEDGER_PATH, PIN, '--json']);
    expect(pinned.status).toBe(1);
    const refusal = verdictOf(pinned);
    expect(refusal).toMatchObject({ ok: false, code: 'BAD_PROTECTED_HEADER' });
    expect(String(refusal.message)).toContain(`typ=${ANCHOR_LEDGER_CONTENT_TYPE}`);
    expect(refusal.contentType).toBeUndefined();

    const absent = runCli(['verify-handover', LEDGER_PATH, ...COMPANION_ARGS]);
    expect(absent.status).toBe(2);
    expect(absent.stderr).toContain(`--key is required to verify ${ANCHOR_LEDGER_CONTENT_TYPE}`);
  });
});
