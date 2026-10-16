import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import { decodeEpochInventory } from '@ashaveri/receipt';
import { noteSpawn } from './support/spawn-budget.js';
/** How long one child of the built CLI may live before this file calls it a bug rather than a slow machine. */
const SPAWN_DEADLINE_MS = 10_000;

/**
 * The substitutions a handover invites, answered by the shipped verbs over published bytes.
 *
 * An evidence handover invites four substitutions, and this file runs each one through the verb a
 * reviewer holds: a trust root swapped for another (a policy pinning a different receipt key, a pack
 * whose span crosses an epoch nobody retained, an attestation chained under a root from another
 * vendor), an item name that climbs out of its own directory, a file omitted from the copy handed
 * over, and a file added beside the copy. A fifth case closes the list: a replay judged stale.
 *
 * The rules met here are the format readers' own and predate this file. What is proved here is that
 * they fire at the command edge over bytes the repository publishes rather than bytes assembled to
 * agree with the reader, and that the sentence each refusal prints names the thing it refused. Two of
 * the shapes answer with disclosure rather than with a refusal, and their cases assert the disclosure
 * as the answer it is: a file no signed item names is read by nothing, and a record parked beside the
 * run inside the signature is refused by the walk. The inventory arm hands a real directory of
 * retention artifacts, rebuilt from the published row's own column, because the fold admits an
 * artifact under the digest the entry that names it seals and never under a filename.
 *
 * Every document here is a published row's bytes and every designation is the half that row states a
 * caller holds, so nothing in this file can drift from the suite it runs.
 */

const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
const DATA = fileURLToPath(new URL('../../fixtures/data/', import.meta.url));
const ATTEST_FIXTURES = fileURLToPath(new URL('../../attest-core/test/fixtures/', import.meta.url));

const tempDir = mkdtempSync(join(tmpdir(), 'ashaveri-substitutions-'));
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

/** One file kept under its own name, because an export item matches its original by that name alone. */
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

/** One artifact's bytes written where the entry that seals them says they stand. */
function writeArtifact(root: string, relative: string, bytes: Uint8Array): void {
  const path = join(root, ...relative.split('/'));
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, bytes);
}

const sha256Hex = (bytes: Uint8Array): string => createHash('sha256').update(bytes).digest('hex');

/** A published row, refused by name rather than fallen back to a row this file picked. */
function rowOf<T extends { readonly name: string }>(file: string, rows: readonly T[], name: string): T {
  const row = rows.find((one) => one.name === name);
  if (row === undefined) {
    throw new Error(`the published ${file} has no row named '${name}', so this run would be about nothing`);
  }
  return row;
}

/** The published export and pack suites, read for the documents and the designations their rows state. */
const EXPORT_SUITE = JSON.parse(readFileSync(`${DATA}export-v1.json`, 'utf8')) as {
  readonly layout: { readonly key: { readonly publicKeyHex: string } };
  readonly vectors: readonly {
    readonly name: string;
    readonly documentBase64Url: string;
    readonly read: { readonly companions?: readonly { readonly name: string; readonly bytesBase64Url: string }[] };
  }[];
};
const PACK_SUITE = JSON.parse(readFileSync(`${DATA}pack-v1.json`, 'utf8')) as {
  readonly vectors: readonly {
    readonly name: string;
    readonly documentBase64Url: string;
    readonly read: { readonly pinned?: string; readonly retained?: readonly { readonly publicKeyBase64Url: string }[] };
  }[];
};
const EXPORT_KEY = Buffer.from(EXPORT_SUITE.layout.key.publicKeyHex, 'hex').toString('base64url');

function exportDocument(row: (typeof EXPORT_SUITE.vectors)[number]): string {
  return written(`${row.name}.cbor`, Buffer.from(row.documentBase64Url, 'base64url'));
}

function packDocument(row: (typeof PACK_SUITE.vectors)[number]): string {
  return written(`${row.name}.cbor`, Buffer.from(row.documentBase64Url, 'base64url'));
}

/**
 * The published receipt, its key material, and a policy and manifest assembled from those two files.
 *
 * The confirmation pairs this run carries are the ones the fixture's own rendering states: the policy
 * pins the issuer, the instance, the key and the measurement the receipt names, and the manifest
 * declares the same key, so the pair is the honest ceiling of what a stranger can build from this
 * repository without running a deployment.
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

/** One policy document over the published pins, with the key map spelled by the caller. */
function policyFile(name: string, keys: Record<string, string>): string {
  return written(
    name,
    JSON.stringify({
      v: 1,
      issuers: [RECEIPT_PAYLOAD.iss],
      instances: [RECEIPT_PAYLOAD.ins],
      keys,
      measurements: { [RECEIPT_PAYLOAD.meas.tee]: [RECEIPT_PAYLOAD.meas.m] },
      maxReceiptAgeSeconds: 300,
      maxEvidenceAgeSeconds: 900,
    }),
  );
}

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
const RECEIPT_FILE = written('receipt-valid-v1.cbor', readFileSync(join(DATA, RECEIPT_ROW.path)));
const RESPONSE_FILE = written('response.bin', Buffer.from(RECEIPT_ROW.responseBase64Url, 'base64url'));
const NOW_AT_ISSUANCE = new Date(RECEIPT_PAYLOAD.iat * 1000).toISOString();
/** The flags a receipt run is reached from, minus the policy and the clock its own case varies. */
const RECEIPT_INPUTS = [
  `--manifest=${MANIFEST_FILE}`,
  `--nonce=${RECEIPT_PAYLOAD.nce}`,
  `--request-hash=${RECEIPT_PAYLOAD.req}`,
  `--response-body=${RESPONSE_FILE}`,
] as const;

describe('the substitutions a handover invites, at the command edge', () => {
  it('reads the receipt under the key its policy pins, and refuses a policy that pins another', () => {
    const pinned = policyFile('policy-pinned.json', { [RECEIPT_KEY.kid]: RECEIPT_PUBLIC_B64URL });
    const accepted = runCli(['verify-receipt', RECEIPT_FILE, `--policy=${pinned}`, ...RECEIPT_INPUTS, `--now=${NOW_AT_ISSUANCE}`, '--json']);
    expect(accepted.stderr).toBe('');
    expect(accepted.status, accepted.stderr).toBe(0);
    expect(verdictOf(accepted).ok).toBe(true);

    // The same document under a policy whose key map names another identity: the substitution moves a
    // key the format carries rather than a byte anywhere, and the answer names the key it could not pin.
    const foreign = policyFile('policy-foreign.json', { ['a'.repeat(64)]: RECEIPT_PUBLIC_B64URL });
    const refused = runCli(['verify-receipt', RECEIPT_FILE, `--policy=${foreign}`, ...RECEIPT_INPUTS, `--now=${NOW_AT_ISSUANCE}`, '--json']);
    expect(refused.status).toBe(1);
    const refusal = verdictOf(refused);
    expect(refusal.ok).toBe(false);
    expect(refusal.code).toBe('MANIFEST_KEY_NOT_PINNED');
    expect(String(refusal.message)).toContain(`receipt key ${RECEIPT_KEY.kid} is not pinned by the policy`);
  });

  it('refuses a pack whose span crosses an epoch the run did not retain', () => {
    const row = rowOf('pack-v1.json', PACK_SUITE.vectors, 'rotation-read-without-the-retired-epoch');
    const retained = row.read.retained?.[0]?.publicKeyBase64Url;
    if (retained === undefined) {
      throw new Error('the published rotation row states no retained half, so the run would designate a key nothing published');
    }
    const document = packDocument(row);
    const result = runCli(['verify-pack', document, `--key=${retained}`, '--json']);
    expect(result.status).toBe(1);
    const refusal = verdictOf(result);
    expect(refusal.ok).toBe(false);
    expect(refusal.code).toBe('PACK_UNKNOWN_KEY');
    // The gap is this call's, not the document's: the pack is whole, and the key that signed the
    // earlier epoch is one this run was never handed.
    expect(String(refusal.message)).toContain('receipt-0 names a kid the reader was given no key for');
  });

  it('refuses an attestation chain under a root from another vendor', () => {
    const attestation = `${ATTEST_FIXTURES}sev-snp-attestation.bin`;
    const ask = `${ATTEST_FIXTURES}sev-snp-ask.pem`;
    const vcek = `${ATTEST_FIXTURES}sev-snp-vcek.pem`;
    const now = '2026-09-10T00:00:00Z';
    const accepted = runCli(['verify', attestation, '--ark', `${ATTEST_FIXTURES}amd-ark-milan.pem`, '--ask', ask, '--vcek', vcek, '--now', now, '--json']);
    expect(accepted.status, accepted.stderr).toBe(0);
    expect(verdictOf(accepted).ok).toBe(true);

    const substituted = runCli(['verify', attestation, '--ark', `${ATTEST_FIXTURES}intel-sgx-root-ca.pem`, '--ask', ask, '--vcek', vcek, '--now', now, '--json']);
    expect(substituted.status).toBe(1);
    const refusal = verdictOf(substituted);
    expect(refusal.ok).toBe(false);
    expect(refusal.code).toBe('MISSING_TRUST_ROOT');
    expect(String(refusal.message)).toContain('no trusted ARK certificate matches the ASK issuer');
  });

  it('refuses an item name that climbs out of its directory, and opens nothing for it', () => {
    const row = rowOf('export-v1.json', EXPORT_SUITE.vectors, 'companion-name-is-a-path');
    const document = exportDocument(row);
    // No companion is handed at all, so a reader that resolved the name against the filesystem before
    // reading it would answer about a missing file; the refusal here is about the name itself.
    const result = runCli(['verify-export', document, `--key=${EXPORT_KEY}`, '--json']);
    expect(result.status).toBe(1);
    const refusal = verdictOf(result);
    expect(refusal.ok).toBe(false);
    expect(refusal.code).toBe('EXPORT_BAD_MANIFEST');
    expect(String(refusal.message)).toContain('must be a file name and not a path or a location');
  });

  it('refuses an omitted original, and a substituted one standing at the name the item carries', () => {
    const omitted = rowOf('export-v1.json', EXPORT_SUITE.vectors, 'companion-not-handed');
    const missingRun = runCli(['verify-export', exportDocument(omitted), `--key=${EXPORT_KEY}`, '--json']);
    expect(missingRun.status).toBe(1);
    const missing = verdictOf(missingRun);
    expect(missing.code).toBe('EXPORT_ORIGINAL_UNAVAILABLE');
    expect(String(missing.message)).toContain('contract.pdf');

    // The bytes a reader would find if it matched on the name alone: the document is whole and its
    // signature holds, and only the digest recomputed over the file the item names separates the
    // copy from the claim.
    const substituted = rowOf('export-v1.json', EXPORT_SUITE.vectors, 'companion-substituted');
    const companion = substituted.read.companions?.[0];
    if (companion === undefined) {
      throw new Error('the published substituted row states no bytes, so this run would hand nothing at the name');
    }
    const substitutedBytes = Buffer.from(companion.bytesBase64Url, 'base64url');
    const path = writtenUnderItsOwnName(companion.name, substitutedBytes);
    const substitutedRun = runCli(['verify-export', exportDocument(substituted), `--key=${EXPORT_KEY}`, `--companion=${path}`, '--json']);
    expect(substitutedRun.status).toBe(1);
    const refusal = verdictOf(substitutedRun);
    expect(refusal.code).toBe('EXPORT_DIGEST_MISMATCH');
    expect(String(refusal.message)).toContain('do not hash to the digest the item carries');
    // The refusal names the item and prints the digest the handed bytes reached beside the one the
    // signature carries, so the substitution is visible as two numbers rather than as a sentence.
    expect(String(refusal.message)).toContain('contract:');
    expect(String(refusal.message)).toContain(sha256Hex(substitutedBytes));
  });

  it('reads a file no item names as unused, and refuses a record parked beside the run', () => {
    const handed = rowOf('export-v1.json', EXPORT_SUITE.vectors, 'companion-handed-and-checked');
    const companion = handed.read.companions?.[0];
    if (companion === undefined) {
      throw new Error('the published handed row states no bytes, so this run would hand nothing at the name');
    }
    const original = writtenUnderItsOwnName(companion.name, Buffer.from(companion.bytesBase64Url, 'base64url'));
    const uninvited = writtenUnderItsOwnName('uninvited.txt', new TextEncoder().encode('no signed item names these bytes'));
    const extraRun = runCli([
      'verify-export', exportDocument(handed), `--key=${EXPORT_KEY}`,
      `--companion=${original}`, `--companion=${uninvited}`,
    ]);
    // The extra file is not refused and it is not read: the report counts the companions handed over
    // beside the digests it recomputed, so a reader sees one file answered for nothing.
    expect(extraRun.status, extraRun.stderr).toBe(0);
    const valueLine = extraRun.stdout.split('\n').find((line) => line.includes('companion file(s) handed over'));
    expect(valueLine, extraRun.stdout).toContain('1 digest(s) recomputed against the bytes this run checked, 2 companion file(s) handed over');

    // The same substitution sealed inside the run is refused rather than counted: a record the walk
    // from the anchor to the head never reaches is a statement about a run this document is not.
    const parked = rowOf('export-v1.json', EXPORT_SUITE.vectors, 'item-parked-beside-the-run');
    const parkedRun = runCli(['verify-export', exportDocument(parked), `--key=${EXPORT_KEY}`, '--json']);
    expect(parkedRun.status).toBe(1);
    const refusal = verdictOf(parkedRun);
    expect(refusal.code).toBe('EXPORT_ITEM_UNREACHED');
    expect(String(refusal.message)).toContain('parked');
  });

  it('refuses a receipt replayed outside its freshness window', () => {
    const pinned = policyFile('policy-window.json', { [RECEIPT_KEY.kid]: RECEIPT_PUBLIC_B64URL });
    const later = new Date((RECEIPT_PAYLOAD.iat + 3600) * 1000).toISOString();
    const result = runCli(['verify-receipt', RECEIPT_FILE, `--policy=${pinned}`, ...RECEIPT_INPUTS, `--now=${later}`, '--json']);
    expect(result.status).toBe(1);
    const refusal = verdictOf(result);
    expect(refusal.ok).toBe(false);
    expect(refusal.code).toBe('STALE_RECEIPT');
    expect(String(refusal.message)).toContain('outside the freshness window');
  });

  it('refuses a directory whose observations name no digest at all', () => {
    // The replay this fold refuses is a directory of retention artifacts that cannot speak for the
    // period the run states: every artifact is sealable and none of them names a holding, so the
    // pair is refused rather than reported as an interval of nothing.
    const suite = JSON.parse(readFileSync(`${DATA}epoch-inventory-v1.json`, 'utf8')) as {
      readonly vectors: readonly {
        readonly name: string;
        readonly documentBase64Url: string;
        readonly verdict: string;
        readonly read: { readonly pinned?: string; readonly presence?: readonly string[] };
      }[];
    };
    const row = rowOf('epoch-inventory-v1.json', suite.vectors, 'possession-refused-when-no-artifact-states-a-holding');
    if (row.read.pinned === undefined) {
      throw new Error('the published no-holding row states no pinned half, so the run would designate no key');
    }
    const document = written(`${row.name}.cbor`, Buffer.from(row.documentBase64Url, 'base64url'));
    const entries = decodeEpochInventory(Buffer.from(row.documentBase64Url, 'base64url')).manifest.packs;
    const root = join(tempDir, 'retention-no-holding');
    mkdirSync(root, { recursive: true });
    const sealed = new Map(entries.map((one) => [one.retentionSha256, one]));
    for (const artifact of row.read.presence ?? []) {
      const bytes = Buffer.from(artifact, 'base64url');
      const holder = sealed.get(sha256Hex(bytes)) ?? entries[entries.length - 1];
      if (holder === undefined) throw new Error('the published row states no entry to file an artifact under');
      writeArtifact(root, holder.retention, bytes);
    }
    // The row's own verdict is the refusal the fold reaches with this directory handed, which is why
    // the row and this run are compared rather than an expectation written beside the code.
    expect(row.verdict).toBe('EPOCH_INVENTORY_PRESENCE_WINDOW_TOO_WIDE');
    const result = runCli(['verify-epoch-inventory', document, `--key=${row.read.pinned}`, `--retention-dir=${root}`, '--json']);
    expect(result.status).toBe(1);
    const refusal = verdictOf(result);
    expect(refusal.ok).toBe(false);
    expect(refusal.code).toBe(row.verdict);
    expect(String(refusal.message)).toContain('its observations name no digest at all');
    // The same document with nothing handed reads as its own figures, which is the reading that does
    // not refuse: the pair is what this refusal is about, never the inventory alone.
    const alone = runCli(['verify-epoch-inventory', document, `--key=${row.read.pinned}`, '--json']);
    expect(alone.status, alone.stderr).toBe(0);
    expect(verdictOf(alone).ok).toBe(true);
  });
});
