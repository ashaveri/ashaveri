import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import { EPOCH_INVENTORY_CONTENT_TYPE, RECEIPT_CONTENT_TYPE, decodeEpochInventory } from '@ashaveri/receipt';
import { printedToken } from '../src/usage.js';
import { noteSpawn, spawnCeilingForCalls } from './support/spawn-budget.js';

/**
 * `--retention-dir`, the one flag that reaches the possession fold, over a real directory.
 *
 * The fold is a reading `verifyEpochInventory` has always done and this command line has never been able to ask
 * for, because the only file-handling flag in the family matches a file by its basename and every pack's
 * retention artifact carries one of the same two names under a different directory. This file therefore asks the
 * four answers a caller can get, over a directory built from published bytes: nothing handed, everything handed
 * and matched, a digest no entry seals, and an entry whose artifact is not where the record says it is, and it
 * asks the two shapes of a directory that does not answer the record: an entry's artifact standing at another
 * entry's name, and a door the operating system will not open. Each
 * answer is read as a printed sentence and an exit code, because that is what a person at a terminal gets, and
 * the pairing itself is decided by the shipped reader rather than by anything here.
 *
 * The directories are assembled from the rows' own columns rather than from a layout this file guessed at. An
 * entry states the name its artifact lives at, and the row states the artifact's bytes, so the file a run names
 * is written where that run says it is: hashing the bytes to the digest the same entry seals is the pairing rule
 * seen from the caller's side, which is what a deployment's own directory looks like. That is also what makes the
 * replay below a check against the suite rather than against this file's memory of it: every row stating
 * `read.presence` is run with its directory handed, and the command has to answer what the published `verdict`
 * states, in the published sentence where the row gives one. The fold's refusals are the library's own, so the
 * equality that matters here is that the command path carries them out unchanged.
 *
 * What the fold answers is asserted against the document rather than recomputed. The interval a run attests is
 * the run's stated window or the reader refuses the pair, so the printed interval is compared with the published
 * `readback.window`, and the digests it prints are compared with the digests the handed artifacts name, as
 * containment rather than as a re-derived roster. A checker that folded the interval again here could agree
 * with a wrong reader, which is the failure mode the suite's own rows exist to close.
 */

const SPAWN_DEADLINE_MS = 15_000;
const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
const DATA = fileURLToPath(new URL('../../fixtures/data/', import.meta.url));

const tempDir = mkdtempSync(join(tmpdir(), 'ashaveri-possession-fold-'));
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

interface InventoryRow {
  readonly name: string;
  readonly documentBase64Url: string;
  readonly read: { readonly pinned?: string; readonly presence?: readonly string[] };
  readonly verdict: string;
  readonly message?: string;
  readonly readback?: { readonly window: { from: number; to: number } };
}

const suite = JSON.parse(readFileSync(`${DATA}epoch-inventory-v1.json`, 'utf8')) as {
  readonly vectors: readonly InventoryRow[];
};

/** A published row, refused by name rather than fallen back to a row this file picked. */
function rowNamed(name: string): InventoryRow {
  const found = suite.vectors.find((one) => one.name === name);
  if (found === undefined) throw new Error(`the published inventory suite has no vector named '${name}'`);
  return found;
}

/** Every row that hands the fold artifacts: the whole of what `--retention-dir` can be asked about. */
const foldRows = suite.vectors.filter((one) => (one.read.presence?.length ?? 0) > 0);

const sha256Hex = (bytes: Uint8Array): string => createHash('sha256').update(bytes).digest('hex');

let counter = 0;
function nextName(base: string): string {
  return `${counter++}-${base}`;
}

/** One artifact's bytes written where the entry that seals them says they are. */
function writeArtifact(root: string, relative: string, bytes: Uint8Array): void {
  const path = join(root, ...relative.split('/'));
  mkdirSync(join(path, '..'), { recursive: true });
  writeFileSync(path, bytes);
}

/**
 * The directory one published row describes: each handed artifact standing at the name the entry sealing its
 * digest states.
 *
 * An artifact no entry seals has no name in this layout, so it is parked at the name the last entry states,
 * which is how a wrong file reaches the fold from a caller's directory and is refused by its digest. Every entry
 * still names exactly one file, so the reading this builds is the reading a reviewer gets from a real epoch
 * directory rather than one assembled to make a test pass.
 */
function directoryFor(row: InventoryRow): { readonly documentPath: string; readonly root: string; readonly entries: readonly { file: string; retention: string; retentionSha256: string }[] } {
  const document = Buffer.from(row.documentBase64Url, 'base64url');
  const documentPath = join(tempDir, `${nextName(row.name)}-inventory.cbor`);
  writeFileSync(documentPath, document);
  const entries = decodeEpochInventory(document).manifest.packs;
  const root = join(tempDir, `${nextName(row.name)}-root`);
  mkdirSync(root, { recursive: true });
  const sealed = new Map(entries.map((one) => [one.retentionSha256, one]));
  const unsealed: Buffer[] = [];
  for (const one of row.read.presence ?? []) {
    const bytes = Buffer.from(one, 'base64url');
    const holder = sealed.get(sha256Hex(bytes));
    if (holder === undefined) {
      unsealed.push(bytes);
      continue;
    }
    writeArtifact(root, holder.retention, bytes);
  }
  const last = entries[entries.length - 1];
  if (last === undefined) throw new Error(`${row.name} states no entry to file an unsealed artifact under`);
  for (const one of unsealed) writeArtifact(root, last.retention, one);
  return { documentPath, root, entries };
}

function designation(row: InventoryRow): string {
  const pinned = row.read.pinned;
  if (pinned === undefined) throw new Error(`${row.name} states no pinned half to designate at the command line`);
  return `--key=${pinned}`;
}

function report(result: CliResult): Record<string, unknown> {
  return JSON.parse(result.stdout) as Record<string, unknown>;
}

/** The printed sentence a refusal carries, with the type and the code the command put in front of it. */
function refusalSentence(result: CliResult): string {
  return result.stderr.replace(/^ashaveri\/epoch-inventory: verification failed \([A-Z_]+\): /u, '').trimEnd();
}

const PROVEN = rowNamed('presence-folded-across-the-windows-the-run-seals');
const UNSEALED_ROW = rowNamed('presence-observation-no-entry-of-the-run-seals');

describe('the possession fold at the command edge', () => {
  it('answers every fold row handed its directory as the published row states it', {
    timeout: spawnCeilingForCalls(foldRows.length * 2, SPAWN_DEADLINE_MS),
  }, () => {
    expect(foldRows.length).toBeGreaterThanOrEqual(4);
    for (const row of foldRows) {
      const { documentPath, root } = directoryFor(row);
      const json = runCli(['verify-epoch-inventory', documentPath, designation(row), '--retention-dir', root, '--json']);
      expect(json.status, `${row.name}: exit code`).toBe(row.verdict === 'verify-ok' ? 0 : 1);
      const answer = report(json);
      expect(answer.ok, `${row.name}: the command answered ${row.verdict} other than its published row states`).toBe(
        row.verdict === 'verify-ok',
      );
      if (row.verdict === 'verify-ok') {
        expect(answer.document, `${row.name}: the fold printed no answer`).toHaveProperty('possession');
        continue;
      }
      // The refusal is the code the suite publishes, and the human reading of it writes no report at all.
      expect(answer).toMatchObject({ ok: false, code: row.verdict, contentType: EPOCH_INVENTORY_CONTENT_TYPE });
      const human = runCli(['verify-epoch-inventory', documentPath, designation(row), '--retention-dir', root]);
      expect(human.status, `${row.name}: exit code beside the printed sentence`).toBe(1);
      expect(human.stdout, row.name).toBe('');
      expect(refusalSentence(human), `${row.name}: the reader's sentence reached the terminal changed`).toBe(
        row.message ?? '',
      );
    }
  });

  it('prints the fold beside the figures the document states, and changes none of them', {
    timeout: spawnCeilingForCalls(3, SPAWN_DEADLINE_MS),
  }, () => {
    const { documentPath, root } = directoryFor(PROVEN);
    const folded = report(runCli(['verify-epoch-inventory', documentPath, designation(PROVEN), '--retention-dir', root, '--json']));
    const alone = report(runCli(['verify-epoch-inventory', documentPath, designation(PROVEN), '--json']));
    expect(folded.ok).toBe(true);
    const foldedDocument = folded.document as Record<string, unknown>;
    const aloneDocument = alone.document as Record<string, unknown>;
    // The flag reaches one more reading and changes no figure of the ones the document alone answers.
    const { possession, ...rest } = foldedDocument;
    expect(rest).toEqual(aloneDocument);
    expect(aloneDocument).not.toHaveProperty('possession');
    const interval = possession as { from: number; to: number; observations: number; collateral: string[]; validity: string[] };
    // The attested period is the stated one or the reader refuses the pair, so the published window is the
    // bound this file compares against, and the rosters are containment in what the handed artifacts name.
    expect([interval.from, interval.to], 'the fold attested another period than the run states').toEqual(
      PROVEN.readback === undefined ? [] : [PROVEN.readback.window.from, PROVEN.readback.window.to],
    );
    expect(interval.observations).toBeGreaterThan(0);
    const named = new Set(
      (PROVEN.read.presence ?? []).flatMap((one) => {
        const document = JSON.parse(Buffer.from(one, 'base64url').toString('utf8')) as {
          presence?: { collateral: { held: { sha256: string }[] }; validity: { held: { sha256: string }[] } };
        };
        return [...(document.presence?.collateral.held ?? []), ...(document.presence?.validity.held ?? [])].map((each) => each.sha256);
      }),
    );
    expect(interval.collateral.length + interval.validity.length).toBeGreaterThan(0);
    for (const digest of [...interval.collateral, ...interval.validity]) {
      expect(named.has(digest), `${digest} was printed without an artifact naming it`).toBe(true);
    }
    const notChecked = (folded.notChecked as string[]).join(' ');
    expect(notChecked, 'a folded reading still says the possession question was not asked').not.toContain('was not attempted');
    expect(notChecked).toContain('whether the material the two presence rosters name can still be reached');
    expect((alone.notChecked as string[]).join(' ')).toContain('this run was handed no `--retention-dir` to read them from');
    const human = runCli(['verify-epoch-inventory', documentPath, designation(PROVEN), '--retention-dir', root]);
    expect(human.status).toBe(0);
    expect(human.stdout).toContain('possession:');
    expect(human.stdout).toContain('each admitted under the digest the entry that names it seals');
  });

  it('gives the fold to whichever verb is handed the directory, in one report', {
    timeout: spawnCeilingForCalls(2, SPAWN_DEADLINE_MS),
  }, () => {
    const { documentPath, root } = directoryFor(PROVEN);
    const pinned = runCli(['verify-epoch-inventory', documentPath, designation(PROVEN), '--retention-dir', root, '--json']);
    const free = runCli(['verify-handover', documentPath, designation(PROVEN), '--retention-dir', root, '--json']);
    expect(pinned.status).toBe(0);
    expect(free.status).toBe(0);
    expect(free.stdout).toBe(pinned.stdout);
  });

  it('refuses an entry whose artifact the root does not hold, by name, and writes nothing', {
    timeout: spawnCeilingForCalls(1, SPAWN_DEADLINE_MS),
  }, () => {
    const { documentPath, root, entries } = directoryFor(PROVEN);
    const [missing] = entries;
    if (missing === undefined) throw new Error('the published row states no entry to take an artifact from');
    rmSync(join(root, ...missing.retention.split('/')));
    const result = runCli(['verify-epoch-inventory', documentPath, designation(PROVEN), '--retention-dir', root]);
    // The question an auditor asks with this flag has no partial answer, so this is a refusal about the
    // directory rather than a fold over whatever survived, and a gap in what the caller handed is exit 2.
    expect(result.status).toBe(2);
    expect(result.stdout).toBe('');
    expect(result.stderr).toContain('--retention-dir');
    expect(result.stderr).toContain(missing.file);
    expect(result.stderr).toContain(missing.retention);
    expect(result.stderr).toContain('holds no file at that name');
    expect(result.stderr).not.toContain('possession:');
  });

  it('refuses an empty --retention-dir as a gap in the call', {
    timeout: spawnCeilingForCalls(1, SPAWN_DEADLINE_MS),
  }, () => {
    const { documentPath } = directoryFor(PROVEN);
    // An empty argument is a gap in the call rather than a root that holds nothing: it would be handed, every
    // entry's path would resolve under the working directory, and a refusal about the root would print it as
    // nothing. Refused before the document is read, the way an empty --companion basename is.
    const result = runCli(['verify-epoch-inventory', documentPath, designation(PROVEN), '--retention-dir', '']);
    expect(result.status).toBe(2);
    expect(result.stdout).toBe('');
    expect(result.stderr).toContain('--retention-dir');
    expect(result.stderr).toContain("must name a directory, not ''");
    expect(result.stderr).not.toContain('holds no file at that name');
  });

  it('carries the operating system\'s reason when a door cannot be resolved at all', {
    timeout: spawnCeilingForCalls(1, SPAWN_DEADLINE_MS),
  }, () => {
    const { documentPath, root, entries } = directoryFor(PROVEN);
    const [first] = entries;
    if (first === undefined) throw new Error('the published row states no entry to knot a name with');
    // Which route is real on this host was measured, not assumed: a path through a file collapses to ENOENT on
    // Windows rather than ENOTDIR, and a directory whose ACL denies the runner still answers a stat (traverse is
    // bypassed for the owner, and the attribute query is answered where listing is refused), so neither of the
    // two shapes the review named witnesses this branch here. A knot at the artifact's own name is real on both
    // platforms, though: on Windows a directory junction that points at itself, elsewhere a symlink that does,
    // and the stat of it is the ELOOP this branch has to state rather than read as a name holding nothing.
    const knot = join(root, ...first.retention.split('/'));
    rmSync(knot);
    symlinkSync(knot, knot, 'junction');
    const result = runCli(['verify-epoch-inventory', documentPath, designation(PROVEN), '--retention-dir', root]);
    expect(result.status).toBe(2);
    expect(result.stdout).toBe('');
    expect(result.stderr).toContain('cannot read --retention-dir');
    expect(result.stderr).toContain('ELOOP');
    expect(result.stderr).not.toContain('holds no file at that name');
  });

  it('refuses a directory that holds one entry\'s artifact at another entry\'s name, by name, and writes nothing', {
    timeout: spawnCeilingForCalls(2, SPAWN_DEADLINE_MS),
  }, () => {
    const { documentPath, root, entries } = directoryFor(PROVEN);
    const [first, second] = entries;
    if (first === undefined || second === undefined) {
      throw new Error('the published row states fewer than two entries to move an artifact between');
    }
    // The two artifacts change doors. Each door still holds a manifest this run seals, so the fold's own
    // attribution by digest still finds a holder for both digests and the attested interval is unchanged; the
    // record's statement that the bytes standing at an entry's name are the artifact that entry seals is not
    // what this directory holds, and that is the statement the printed report makes.
    const firstPath = join(root, ...first.retention.split('/'));
    const secondPath = join(root, ...second.retention.split('/'));
    const a = readFileSync(firstPath);
    const b = readFileSync(secondPath);
    writeFileSync(firstPath, b);
    writeFileSync(secondPath, a);
    expect(sha256Hex(b), 'the row does not seal one artifact per entry').not.toBe(first.retentionSha256);
    const result = runCli(['verify-epoch-inventory', documentPath, designation(PROVEN), '--retention-dir', root]);
    // The route is the family's existing one for a gap in what the caller handed, and the sentence says which
    // gap: the door holds a file, and it is not the one the entry names.
    expect(result.status).toBe(2);
    expect(result.stdout).toBe('');
    expect(result.stderr).toContain('--retention-dir');
    expect(result.stderr).toContain(first.file);
    expect(result.stderr).toContain(first.retention);
    expect(result.stderr).toContain(printedToken(root));
    expect(result.stderr).toContain(sha256Hex(b));
    expect(result.stderr).toContain(first.retentionSha256);
    expect(result.stderr).toContain('holds a file at that name which is not the artifact this entry seals');
    expect(result.stderr).not.toContain('holds no file at that name');
    expect(result.stderr).not.toContain('possession:');
    // One route, whichever verb is handed the directory: the free verb prints the same refusal, byte for byte.
    const free = runCli(['verify-handover', documentPath, designation(PROVEN), '--retention-dir', root]);
    expect(free.status).toBe(2);
    expect(free.stdout).toBe('');
    expect(free.stderr).toBe(result.stderr);
  });

  it('refuses an artifact no entry seals by its digest, and reads nothing a name does not state', {
    timeout: spawnCeilingForCalls(2, SPAWN_DEADLINE_MS),
  }, () => {
    const { documentPath, root } = directoryFor(UNSEALED_ROW);
    const [foreign] = (UNSEALED_ROW.read.presence ?? [])
      .map((one) => Buffer.from(one, 'base64url'))
      .filter((one) => !decodeEpochInventory(Buffer.from(UNSEALED_ROW.documentBase64Url, 'base64url')).manifest.packs.some((each) => each.retentionSha256 === sha256Hex(one)));
    if (foreign === undefined) throw new Error('the published row hands no artifact the run leaves unsealed');
    const digest = sha256Hex(foreign);
    const result = runCli(['verify-epoch-inventory', documentPath, designation(UNSEALED_ROW), '--retention-dir', root]);
    expect(result.status).toBe(1);
    expect(result.stdout).toBe('');
    expect(result.stderr).toContain('(EPOCH_INVENTORY_PRESENCE_UNSEALED)');
    expect(result.stderr).toContain(digest);
    // The same directory with a file no entry names beside it: the run is resolved one file per entry, so a
    // stray artifact cannot reach the fold and the answer is byte for byte the one without it.
    writeArtifact(root, 'stray.json', foreign);
    const withStray = runCli(['verify-epoch-inventory', documentPath, designation(UNSEALED_ROW), '--retention-dir', root]);
    expect(withStray.stderr).toBe(result.stderr);
    expect(withStray.status).toBe(1);
  });

  it('prints the directory as not consulted beside a document that states no run of packs', {
    timeout: spawnCeilingForCalls(2, SPAWN_DEADLINE_MS),
  }, () => {
    const receiptKey = `--key=${Buffer.from(
      (JSON.parse(readFileSync(`${DATA}keys/receipt-key-v1.json`, 'utf8')) as { publicKey: string }).publicKey,
      'hex',
    ).toString('base64url')}`;
    const { root, documentPath } = directoryFor(PROVEN);
    const receipt = runCli(['verify-handover', `${DATA}receipts/receipt-valid-v1.cbor`, receiptKey, '--retention-dir', root, '--json']);
    expect(receipt.status).toBe(0);
    const rows = report(receipt).keyDesignations as Array<Record<string, unknown> | null>;
    expect(rows).toContainEqual({ consulted: false, contentType: RECEIPT_CONTENT_TYPE, root });
    // The same flag beside a verb pinned to another shape: the type is refused before a payload is opened, so
    // the unused designation is no part of that answer and the root is read by no reader but the inventory's.
    const packVerb = runCli(['verify-pack', documentPath, designation(PROVEN), '--retention-dir', root]);
    expect(packVerb.status).toBe(1);
    expect(packVerb.stdout).toBe('');
    expect(packVerb.stderr).toContain('verification failed (BAD_PROTECTED_HEADER)');
    expect(packVerb.stderr).toContain(`typ=${EPOCH_INVENTORY_CONTENT_TYPE}`);
    expect(packVerb.stderr).not.toContain('retention-dir');
  });

  it('reads a root whose name is the one the record gives and never a second document', {
    timeout: spawnCeilingForCalls(2, SPAWN_DEADLINE_MS),
  }, () => {
    const { documentPath, root } = directoryFor(PROVEN);
    // The document stays one signed file: naming a root for its artifacts does not turn the run into a bundle
    // this command walks, and the refusal a directory-as-document earns is untouched by this flag.
    const asDocument = runCli(['verify-epoch-inventory', root, designation(PROVEN), '--retention-dir', root]);
    expect(asDocument.status).toBe(2);
    expect(asDocument.stderr).toContain('is a directory');
    const nested = join(tempDir, nextName('root'));
    mkdirSync(nested, { recursive: true });
    const empty = runCli(['verify-epoch-inventory', documentPath, designation(PROVEN), '--retention-dir', nested]);
    expect(empty.status).toBe(2);
    expect(empty.stderr).toContain('holds no file at that name');
  });
});
