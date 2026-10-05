import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import {
  DEPLOYMENT_MANIFEST_CONTENT_TYPE,
  EPOCH_INVENTORY_CONTENT_TYPE,
  EXPORT_CONTENT_TYPE,
  PACK_CONTENT_TYPE,
  RECEIPT_CONTENT_TYPE,
  REDACTION_CONTENT_TYPE,
  decodeCanonical,
  generateSigningKey,
  signCoseSign1,
} from '@ashaveri/receipt';
import { noteSpawn, spawnCeilingForCalls } from './support/spawn-budget.js';
/** How long one child of the built CLI may live before this file calls it a bug rather than a slow machine. */
const SPAWN_DEADLINE_MS = 15_000;

/**
 * `ashaveri verify-handover` and `ashaveri verify-epoch-inventory` run over the published inventory suite.
 *
 * The documents are the published rows and nothing else: each run is handed the bytes the file seals and the
 * designation the file states beside them, so the answers compared here are the suite's own columns rather than
 * a framing this file assembled. `packages/cli/test/vector-conformance.test.ts` replays the same rows through
 * the two library readers; what this file adds is the command edge, which is where a person handed a pile of
 * files asks what one of them is. The redaction suite's replay in `verify-handover.test.ts` is the pattern, and
 * the same two claims are the ones worth making here: the type inside the signature reaches the inventory
 * reader, and every row answers at this edge what its published column states.
 *
 * Nine rows answer otherwise, and each of the nine says so out of a published column of its own: a row naming
 * retention artifacts to fold meets a command line with no flag carrying them, a row naming no key at all meets
 * the run that asks for one by the type it found, a row pinning a half whose own kid is not the header's meets a
 * designation matched on computed kids, two rows are refused by the classifier before any reader is reached,
 * and one row carries another shape's name in label 3 and so reaches that shape's reader. Those are listed in
 * `COMMAND_PATH_ANSWERS` beside the fact that makes them, and the replay checks both directions, so a row that
 * diverges without being listed fails and a listed row that stopped diverging fails beside it.
 *
 * The pinned verb is tested against the other five published shapes rather than only beside its own, because a
 * pin that reads whatever arrives is the defect the pin exists to remove: a step written to check the run's
 * summary, handed a pack and reporting a verdict about it, exits 0. The bytes it refuses are the same published
 * documents the free verb reads happily, which is the only reason the two answers can be set against each other.
 */

const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
const DATA = fileURLToPath(new URL('../../fixtures/data/', import.meta.url));

const tempDir = mkdtempSync(join(tmpdir(), 'ashaveri-epoch-inventory-'));
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
function written(name: string, data: Uint8Array | string): string {
  const path = join(tempDir, `${writtenCount++}-${name}`);
  writeFileSync(path, data);
  return path;
}

function verdictOf(result: CliResult): Record<string, unknown> {
  return JSON.parse(result.stdout) as Record<string, unknown>;
}

/** A published field this file cannot do without, refused by name rather than defaulted to an empty frame. */
function published(value: string | undefined, what: string): string {
  if (value === undefined) {
    throw new Error(`the published suite states no ${what}, so this file would be asserting about nothing`);
  }
  return value;
}

interface InventoryCase {
  readonly name: string;
  readonly documentBase64Url: string;
  readonly documentByteLength: number;
  readonly read: { pinned?: string; retained?: Record<string, string>; presence?: readonly string[] };
  readonly verdict: string;
  readonly structural: string;
  readonly message?: string;
  readonly readback?: {
    readonly runFiles: readonly string[];
    readonly statedFiles: readonly string[];
    readonly window: { from: number; to: number };
    readonly continuous: boolean;
    readonly breakFiles: readonly string[];
    readonly carried: boolean;
    readonly shortFiles: readonly string[];
  };
}

const inventories = JSON.parse(readFileSync(`${DATA}epoch-inventory-v1.json`, 'utf8')) as {
  readonly layout: { readonly contentType: string; readonly keyMaterial: readonly { kidHex: string; publicKeyBase64Url: string }[] };
  readonly vectors: readonly InventoryCase[];
};

/** One published row, refused by name rather than fallen back to a row this file picked. */
function inventoryRow(name: string): InventoryCase {
  const row = inventories.vectors.find((one) => one.name === name);
  if (row === undefined) {
    throw new Error(`the published inventory suite has no vector named '${name}'`);
  }
  return row;
}

/** One published row's readback, refused by name rather than skipped when the row states none. */
function readbackOf(row: InventoryCase): NonNullable<InventoryCase['readback']> {
  const stated = row.readback;
  if (stated === undefined) {
    throw new Error(`the published row '${row.name}' states no readback, so this file would be asserting about nothing`);
  }
  return stated;
}

/** A document of one of the other published shapes, for the refusals a pinned verb owes. */
function publishedDocument(file: string, name: string): Uint8Array {
  const vectorFile = JSON.parse(readFileSync(`${DATA}${file}`, 'utf8')) as { vectors: { name: string; documentBase64Url: string }[] };
  const row = vectorFile.vectors.find((one) => one.name === name);
  if (row === undefined) {
    throw new Error(`the published ${file} suite has no vector named '${name}'`);
  }
  return Buffer.from(row.documentBase64Url, 'base64url');
}

/** The published kid a designated public half computes to, which is the name a `--key` is matched on. */
function kidOfDesignatedHalf(publicKeyBase64Url: string): string {
  const found = inventories.layout.keyMaterial.find((one) => one.publicKeyBase64Url === publicKeyBase64Url);
  if (found === undefined) throw new Error('a published row designates a half the suite publishes no kid for');
  return found.kidHex;
}

/** The designation a row states, spelled as the command line takes it: one `--key` per half. */
function designationArgs(row: InventoryCase): string[] {
  const halves = row.read.pinned !== undefined ? [row.read.pinned] : Object.values(row.read.retained ?? {});
  return halves.map((half) => `--key=${half}`);
}

/** What one command run answered: the published verdict's shape, or the fact that it refused the call. */
function replayedVerdict(result: CliResult): string {
  if (result.status === 2) return 'usage';
  try {
    const report = JSON.parse(result.stdout) as { ok?: boolean; code?: string };
    return report.ok === true ? 'verify-ok' : published(report.code, 'refusal code');
  } catch {
    return 'unreadable';
  }
}

const HONEST = inventoryRow('honest-run-of-three');
const HONEST_PATH = written('honest-inventory.cbor', Buffer.from(HONEST.documentBase64Url, 'base64url'));
const HONEST_KEY = `--key=${published(HONEST.read.pinned, 'pinned key')}`;
const HONEST_KID = kidOfDesignatedHalf(published(HONEST.read.pinned, 'pinned key'));
/** A published receipt, read where it stands: the shape the dispatch reaches by its own header. */
const RECEIPT_PATH = `${DATA}receipts/receipt-valid-v1.cbor`;

/**
 * The payload of the published row, read as the bytes the signature covers.
 *
 * The suite's columns state a verdict and the run's figures, and the text a report prints beside them, the
 * run's label, the issuer and the instance, is in the document rather than in a column of its own, so this file
 * takes it out of the published bytes rather than spelling a copy of it here.
 */
const HONEST_PAYLOAD = JSON.parse(
  Buffer.from((decodeCanonical(Buffer.from(HONEST.documentBase64Url, 'base64url')) as { contents: readonly unknown[] }).contents[2] as Uint8Array).toString('utf8'),
) as { epoch: string; manifest: { iss: string; ins: string } };

/**
 * The rows this path answers otherwise than their published `verdict`, with the published fact that says why.
 *
 * Each entry is checked against the row it names inside the replay below, so a list of names cannot rest on
 * this file's memory of the suite: the replay fails a row that diverges without being listed, fails a listed
 * row that stopped diverging, and asks which member of the published row makes the command's answer a
 * different question's answer.
 */
interface CommandPathAnswer {
  readonly name: string;
  readonly answer: string;
  readonly exit: number;
  readonly because: string;
}

const COMMAND_PATH_ANSWERS: readonly CommandPathAnswer[] = [
  {
    name: 'an-identity-that-pins-nothing',
    answer: 'usage',
    exit: 2,
    because: 'the row states no designation, and this command asks for the key by the type it found before any reader is reached',
  },
  {
    name: 'a-resolver-holding-nothing-for-the-kid-named',
    answer: 'usage',
    exit: 2,
    because: 'the row states a retained set holding no half, which is the same call that named no key',
  },
  {
    name: 'a-pinned-key-of-another-identity',
    answer: 'EPOCH_INVENTORY_UNKNOWN_KEY',
    exit: 1,
    because: 'the row pins a half whose own kid is not the header\'s, and a `--key` is matched on the kid it computes to',
  },
  {
    name: 'presence-observation-no-entry-of-the-run-seals',
    answer: 'verify-ok',
    exit: 0,
    because: 'the fold is the one reading no option of this command line hands an input to',
  },
  {
    name: 'presence-gap-inside-the-period-the-run-attests',
    answer: 'verify-ok',
    exit: 0,
    because: 'the fold is the one reading no option of this command line hands an input to',
  },
  {
    name: 'presence-window-wider-than-the-observations-attest',
    answer: 'verify-ok',
    exit: 0,
    because: 'the fold is the one reading no option of this command line hands an input to',
  },
  {
    name: 'document-cut-short-mid-envelope',
    answer: 'MALFORMED_CBOR',
    exit: 1,
    because: 'the classifier reads the envelope to find a type at all, and these bytes are not a readable envelope',
  },
  {
    name: 'header-kid-one-byte-narrow',
    answer: 'BAD_PROTECTED_HEADER',
    exit: 1,
    because: 'the classifier settles which reader runs on a 32-byte kid, which is the fact the header carries wrongly',
  },
  {
    name: 'sealed-under-another-containers-content-type',
    answer: 'PACK_BAD_MANIFEST',
    exit: 1,
    because: 'the row\'s own message names the pack type its header carries, and the dispatch follows the header rather than the payload',
  },
];

/**
 * Which group a listed row belongs to. Two groups come out of the row's own `read` columns, and the four
 * whose divergence is a fact about its refusal come out of its published `name`, one of the naming columns
 * the file itself lists. The checks below then hold each of those four to a published member of the same
 * row, so a name is a pointer into the published suite rather than the reason a row diverges.
 */
function groupOf(row: InventoryCase): string {
  if (row.read.presence !== undefined) return 'presence';
  if (row.read.pinned === undefined && Object.keys(row.read.retained ?? {}).length === 0) return 'undesignated';
  if (row.name === 'a-pinned-key-of-another-identity') return 'pinned-identity';
  if (row.name === 'document-cut-short-mid-envelope') return 'envelope';
  if (row.name === 'header-kid-one-byte-narrow') return 'kid-width';
  if (row.name === 'sealed-under-another-containers-content-type') return 'relabelled';
  return 'unlisted';
}

describe('an epoch inventory at the command edge', () => {
  it('names a published inventory as an inventory, before it says anything about validity', () => {
    const human = runCli(['verify-handover', HONEST_PATH, HONEST_KEY]);
    expect(human.stderr).toBe('');
    expect(human.status).toBe(0);
    expect(human.stdout.split('\n')[0]).toBe(`content type:     ${EPOCH_INVENTORY_CONTENT_TYPE}`);
    const typeLine = human.stdout.indexOf('content type:');
    expect(typeLine).toBeGreaterThanOrEqual(0);
    expect(typeLine).toBeLessThan(human.stdout.indexOf('signature:'));
    // The run's own label and the files it lists are printed as the document spells them, because the
    // reviewer's next move is to open those names with the pack reader.
    expect(human.stdout).toContain(`run label:        ${HONEST_PAYLOAD.epoch}`);
    expect(human.stdout).toContain(`${HONEST_PAYLOAD.manifest.iss} / ${HONEST_PAYLOAD.manifest.ins}`);
    for (const file of readbackOf(HONEST).runFiles) {
      expect(human.stdout).toContain(file);
    }
    expect(human.stdout).toContain('no option of this command line hands them');

    const json = verdictOf(runCli(['verify-handover', HONEST_PATH, HONEST_KEY, '--json']));
    expect(json.ok).toBe(true);
    expect(json.contentType).toBe(EPOCH_INVENTORY_CONTENT_TYPE);
    expect(json.reader).toBe('verifyEpochInventory');
    expect(json.kid).toBe(HONEST_KID);
    expect((json.document as Record<string, unknown>).signature).toBe(true);
    expect(json.notChecked).toBeInstanceOf(Array);
  });

  it('prints the run and both folded claims exactly as each accepted row states them', {
    timeout: spawnCeilingForCalls(inventories.vectors.filter((one) => one.verdict === 'verify-ok').length, SPAWN_DEADLINE_MS),
  }, () => {
    const accepted = inventories.vectors.filter((one) => one.verdict === 'verify-ok' && one.readback !== undefined);
    expect(accepted.length).toBeGreaterThanOrEqual(8);
    for (const row of accepted) {
      const stated = row.readback;
      if (stated === undefined) continue;
      const json = verdictOf(
        runCli(['verify-handover', written(`${row.name}.cbor`, Buffer.from(row.documentBase64Url, 'base64url')), ...designationArgs(row), '--json']),
      );
      expect(json.ok, row.name).toBe(true);
      expect(json.contentType, row.name).toBe(inventories.layout.contentType);
      const document = json.document as {
        entries: { file: string; retention: string; sha256: string; retentionSha256: string; items: number }[];
        window: { from: number; to: number };
        chain: { continuous: boolean };
        breaks: { file: string }[];
        duty: { carried: boolean; short: { file: string }[] };
      };
      // The report prints the run in the order the reader's own rule puts it, which is the column the file
      // publishes for that order, and the listed set is the same entries either way.
      expect(document.entries.map((one) => one.file), row.name).toEqual(stated.runFiles);
      expect([...document.entries.map((one) => one.file)].sort(), row.name).toEqual([...stated.statedFiles].sort());
      expect(document.window, row.name).toEqual(stated.window);
      expect(document.chain.continuous, row.name).toBe(stated.continuous);
      expect(document.breaks.map((one) => one.file), row.name).toEqual(stated.breakFiles);
      expect(document.duty.carried, row.name).toBe(stated.carried);
      expect(document.duty.short.map((one) => one.file), row.name).toEqual(stated.shortFiles);
      // Every entry carries both digests, which is what an entry is a statement about.
      for (const one of document.entries) {
        expect(one.sha256, `${row.name} prints no pack digest`).toMatch(/^[0-9a-f]{64}$/u);
        expect(one.retentionSha256, `${row.name} prints no retention digest`).toMatch(/^[0-9a-f]{64}$/u);
      }
    }
  });

  it('replays every published inventory row through the command path', {
    timeout: spawnCeilingForCalls(inventories.vectors.length, SPAWN_DEADLINE_MS),
  }, () => {
    expect(inventories.vectors.length).toBeGreaterThanOrEqual(60);
    const listed = new Map(COMMAND_PATH_ANSWERS.map((one) => [one.name, one]));
    // A listed name has to name a row the suite publishes, or the table is a note about a case that left.
    for (const one of COMMAND_PATH_ANSWERS) {
      expect(inventories.vectors.some((row) => row.name === one.name), one.name).toBe(true);
    }
    const diverged: string[] = [];
    const observed: string[] = [];
    for (const row of inventories.vectors) {
      const result = runCli([
        'verify-handover',
        written(`${row.name}.cbor`, Buffer.from(row.documentBase64Url, 'base64url')),
        ...designationArgs(row),
        '--json',
      ]);
      const answer = replayedVerdict(result);
      const exception = listed.get(row.name);
      expect(answer, `${row.name}: the command path answered something other than its published row states`).toBe(
        exception === undefined ? row.verdict : exception.answer,
      );
      expect(result.status, `${row.name}: exit status beside the answer`).toBe(
        exception === undefined ? (row.verdict === 'verify-ok' ? 0 : 1) : exception.exit,
      );
      if (answer !== row.verdict) {
        diverged.push(row.name);
        // Each divergence rests on a member of the published row, not on this file's recollection of it.
        const group = groupOf(row);
        expect(group, `${row.name} is listed as diverging and no published member says why`).not.toBe('unlisted');
        if (group === 'presence') {
          expect((row.read.presence ?? []).length, `${row.name} is listed as a fold row and states no artifact`).toBeGreaterThan(0);
        }
        if (group === 'undesignated') {
          expect(result.stderr, `${row.name}: the refusal of the call names the flag it left out`).toContain(
            `--key is required to verify ${EPOCH_INVENTORY_CONTENT_TYPE}`,
          );
        }
        if (group === 'pinned-identity') {
          // The row's own sentence carries both kids, and they differ: what the command line designates is a
          // half and the kid it computes to, so a half named for another identity answers nothing here rather
          // than reaching the mismatch the library's pinned-key call states.
          const message = published(row.message, 'refusal sentence');
          const headerKid = /header kid=([0-9a-f]{64})/u.exec(message)?.[1];
          const keyKid = /key kid=([0-9a-f]{64})/u.exec(message)?.[1];
          expect(headerKid, `${row.name} states no header kid beside its refusal`).toBeDefined();
          expect(keyKid, `${row.name} states no key kid beside its refusal`).toBeDefined();
          expect(headerKid, row.name).not.toBe(keyKid);
          expect(kidOfDesignatedHalf(published(row.read.pinned, 'pinned key')), row.name).toBe(keyKid);
        }
        if (group === 'relabelled') {
          expect(published(row.message, 'refusal sentence'), row.name).toContain(PACK_CONTENT_TYPE);
        }
        if (group === 'envelope') {
          // The row's own sentence says the bytes are not a readable CBOR document, which is the fact the
          // classifier meets first, because a type is read out of an envelope before an envelope is opened.
          expect(published(row.message, 'refusal sentence'), row.name).toContain('canonical CBOR');
        }
        if (group === 'kid-width') {
          // And this one states the kid width it refuses, which is the same field the dispatch is settled on.
          expect(published(row.message, 'refusal sentence'), row.name).toContain('kid must be a 32-byte bstr');
        }
      } else if (answer !== 'verify-ok' && answer !== 'usage') {
        // A row this path answers as the library does is answered in the library's own sentence too, and the
        // type inside the signature is stated beside it: a verdict about the wrong document is not a verdict.
        const refusal = verdictOf(result);
        expect(String(refusal.message), row.name).toBe(row.message ?? '');
        expect(refusal.contentType, row.name).toBe(EPOCH_INVENTORY_CONTENT_TYPE);
      }
      observed.push(`${row.name}: ${answer}`);
    }
    // Both directions, read out of published data rather than out of a table this file keeps to itself: a row
    // that diverged without being listed failed above, and a listed row that stopped diverging fails here.
    expect(diverged.sort()).toEqual(COMMAND_PATH_ANSWERS.map((one) => one.name).sort());
    expect(observed.filter((one) => !one.endsWith('verify-ok')).length).toBeGreaterThanOrEqual(40);
  });

  it('leaves open in its own English only what the published rows leave open', () => {
    // Two registers, and the suite says which statements belong to which. A window, a chain endpoint or a duty
    // summary that disagrees with the entries is refused by published rows naming that site, so those figures are
    // judged by this reading. An item count is refused by no row at all, and a stated digest by the path the
    // entry is filed under alone, because no bytes of a pack reach this call.
    const refused = inventories.vectors.filter((one) => one.verdict !== 'verify-ok');
    for (const site of ['window', 'chain.anchor', 'chain.head', 'duty.short', 'duty.carried']) {
      expect(refused.some((one) => (one.message ?? '').includes(site)), `no published row refuses ${site}`).toBe(true);
    }
    expect(refused.every((one) => !/\bitems\b/u.test(one.message ?? '')), 'a published row refuses an item count').toBe(true);

    // What that leaves of the duty question is owed-ness, and the honest row's own columns say it is left: a pack
    // short of the period the same entry states it owed, published as `verify-ok` and named in its readback as
    // short. So a report of these bytes may list owed-ness as unchecked and may not list the comparison.
    const json = verdictOf(runCli(['verify-handover', HONEST_PATH, HONEST_KEY, '--json']));
    const duty = (json.document as { duty: { carried: boolean; short: { file: string }[] } }).duty;
    expect(duty.carried, 'the honest row states a shortfall this run carries').toBe(false);
    expect(duty.short.map((one) => one.file), 'the shortfall rows are the published ones').toEqual(readbackOf(HONEST).shortFiles);
    const notChecked = (json.notChecked as string[]).join(' ');
    expect(notChecked, 'the unchecked list calls the duty figures unjudged').not.toContain('judges neither');
    expect(notChecked, 'the unchecked list calls the duty figures unjudged').not.toContain('judged by nothing');
    expect(notChecked, 'the unchecked list names no duty question').toContain('owed');
  });

  it('answers an inventory refusal in the same breath as the type it met', () => {
    const row = inventoryRow('issuer-id-stated-empty');
    const path = written('refused-inventory.cbor', Buffer.from(row.documentBase64Url, 'base64url'));
    const human = runCli(['verify-handover', path, ...designationArgs(row)]);
    expect(human.status).toBe(1);
    expect(human.stdout).toBe('');
    expect(human.stderr.indexOf(EPOCH_INVENTORY_CONTENT_TYPE)).toBeLessThan(human.stderr.indexOf('verification failed'));
    expect(human.stderr).toContain(`(${row.verdict})`);
    expect(human.stderr).not.toMatch(/run label|entries:/);
  });

  it('refuses a content type the dispatch holds no reader for, by name rather than by guessing', () => {
    // The published inventory's own payload, sealed under a type no format publishes and signed by a key this
    // run designates, so the refusal can only be the dispatch table rather than a framing mistake or a missing
    // designation: the bytes are a document, and nothing here reads one.
    const key = generateSigningKey();
    const envelope = decodeCanonical(Buffer.from(HONEST.documentBase64Url, 'base64url')) as { contents: readonly unknown[] };
    const payload = envelope.contents[2] as Uint8Array;
    const path = written(
      'unpublished-type.cbor',
      Buffer.from(signCoseSign1(payload, key, new Uint8Array(0), 'ashaveri/telemetry')),
    );
    const designation = `--key=${Buffer.from(key.publicKey).toString('base64url')}`;
    for (const verb of ['verify-handover', 'verify-epoch-inventory']) {
      const json = runCli([verb, path, designation, '--json']);
      expect(json.status, verb).toBe(1);
      const refusal = verdictOf(json);
      expect(refusal, verb).toMatchObject({ ok: false, code: 'BAD_PROTECTED_HEADER' });
      expect(String(refusal.message), verb).toContain('typ=ashaveri/telemetry');
      expect(refusal.contentType, verb).toBeUndefined();
      const human = runCli([verb, path, designation]);
      expect(human.status, verb).toBe(1);
      expect(human.stdout, verb).toBe('');
      expect(human.stderr, verb).toContain('verification failed (BAD_PROTECTED_HEADER): ');
      expect(human.stderr, verb).toContain('typ=ashaveri/telemetry');
    }
  });

  it('refuses a directory by the rules over a bundle rather than ahead of them', () => {
    const bundle = join(tempDir, 'epoch');
    mkdirSync(bundle, { recursive: true });
    writeFileSync(join(bundle, 'inventory.cbor'), Buffer.from(HONEST.documentBase64Url, 'base64url'));
    // The name of a shape a caller is sure of is no reason to walk a root: which files stand in a substituted
    // bundle, which are omitted and which are extra answer a replay, not a content type.
    for (const verb of ['verify-handover', 'verify-epoch-inventory']) {
      const result = runCli([verb, bundle, HONEST_KEY]);
      expect(result.status, verb).toBe(2);
      expect(result.stdout, verb).toBe('');
      expect(result.stderr, verb).toContain('is a directory');
      expect(result.stderr, verb).toContain('one signed document per run');
      expect(result.stderr, verb).toContain('substituted root');
      expect(result.stderr, verb).not.toContain(EPOCH_INVENTORY_CONTENT_TYPE);
    }
    const named = runCli(['verify-epoch-inventory', join(bundle, 'inventory.cbor'), HONEST_KEY]);
    expect(named.status).toBe(0);
    expect(named.stdout.split('\n')[0]).toBe(`content type:     ${EPOCH_INVENTORY_CONTENT_TYPE}`);
  });

  it('asks for the key an inventory needs, by the type it found', () => {
    const result = runCli(['verify-handover', HONEST_PATH]);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain(`--key is required to verify ${EPOCH_INVENTORY_CONTENT_TYPE}`);
  });

  it('reads the inventory from stdin as readily as from a name', () => {
    noteSpawn(SPAWN_DEADLINE_MS);
    const pipe = spawnSync(process.execPath, [CLI, 'verify-handover', '-', HONEST_KEY, '--json'], {
      input: Buffer.from(HONEST.documentBase64Url, 'base64url'),
      encoding: 'utf8',
      timeout: SPAWN_DEADLINE_MS,
    });
    expect(pipe.status).toBe(0);
    expect(JSON.parse(pipe.stdout).contentType).toBe(EPOCH_INVENTORY_CONTENT_TYPE);
  });
});

describe('the pinned verb verify-epoch-inventory', () => {
  /** The other five published shapes, each a document the free verb reads as itself. */
  const others: readonly (readonly [string, Uint8Array, string])[] = [
    ['receipt', Buffer.from(readFileSync(`${DATA}receipts/receipt-valid-v1.cbor`)), RECEIPT_CONTENT_TYPE],
    ['pack', publishedDocument('pack-v1.json', 'well-formed-three-items'), PACK_CONTENT_TYPE],
    ['export', publishedDocument('export-v1.json', 'well-formed-plain'), EXPORT_CONTENT_TYPE],
    ['deployment manifest', publishedDocument('manifest-v1.json', 'sealed-under-designated-key'), DEPLOYMENT_MANIFEST_CONTENT_TYPE],
    ['redaction', publishedDocument('redaction-v1.json', 'removed-middle-record'), REDACTION_CONTENT_TYPE],
  ];

  it('gives an inventory the same report the free verb gives, field for field', {
    timeout: spawnCeilingForCalls(6, SPAWN_DEADLINE_MS),
  }, () => {
    for (const row of [HONEST, inventoryRow('a-broken-run-folded-and-reported')]) {
      const path = written(`pinned-${row.name}.cbor`, Buffer.from(row.documentBase64Url, 'base64url'));
      const designation = designationArgs(row);
      const pinned = runCli(['verify-epoch-inventory', path, ...designation, '--json']);
      expect(pinned.status, row.name).toBe(0);
      expect(pinned.stderr, row.name).toBe('');
      const free = runCli(['verify-handover', path, ...designation, '--json']);
      expect(free.status, row.name).toBe(0);
      // One report and not a second one shaped like the first: a pinned verb that added, dropped or reworded
      // a field would be a second reader of the same bytes here.
      expect(JSON.parse(pinned.stdout), row.name).toEqual(JSON.parse(free.stdout));
      expect(JSON.parse(pinned.stdout)).toMatchObject({ ok: true, contentType: EPOCH_INVENTORY_CONTENT_TYPE, reader: 'verifyEpochInventory' });
      const human = runCli(['verify-epoch-inventory', path, ...designation]);
      expect(human.status, row.name).toBe(0);
      expect(human.stdout, row.name).toContain(`content type:     ${EPOCH_INVENTORY_CONTENT_TYPE}`);
    }
  });

  it('refuses every document that is not an inventory, with the refusal the free verb gives', {
    timeout: spawnCeilingForCalls(others.length + 1, SPAWN_DEADLINE_MS),
  }, () => {
    for (const [what, bytes, contentType] of others) {
      const path = written(`not-an-inventory-${what}.cbor`, Buffer.from(bytes));
      const json = runCli(['verify-epoch-inventory', path, HONEST_KEY, '--json']);
      expect(json.status, what).toBe(1);
      const refusal = verdictOf(json);
      expect(refusal, what).toMatchObject({ ok: false, code: 'BAD_PROTECTED_HEADER' });
      // The refusal the free verb already gives a type it holds no reader for, wording and all: which shape
      // these bytes claim is one fact in one field, and a pinned verb states it rather than adding a code.
      expect(String(refusal.message), what).toContain(`typ=${contentType}`);
      expect(refusal.contentType, what).toBeUndefined();
      expect(refusal.document, what).toBeUndefined();
    }
    const human = runCli(['verify-epoch-inventory', HONEST_PATH, HONEST_KEY]);
    expect(human.status).toBe(0);
    expect(human.stdout.split('\n')[0]).toBe(`content type:     ${EPOCH_INVENTORY_CONTENT_TYPE}`);
  });

  it('answers the type before it asks for a key, so an undesignated run still says what the file is not', () => {
    // Two different refusals, in the order that keeps a report honest: a document of another shape is a fact
    // about the document, and a run that named no key is a fact about the call.
    const wrongType = runCli(['verify-epoch-inventory', RECEIPT_PATH, '--json']);
    expect(wrongType.status).toBe(1);
    expect(String(verdictOf(wrongType).message)).toContain(`typ=${RECEIPT_CONTENT_TYPE}`);
    const rightType = runCli(['verify-epoch-inventory', HONEST_PATH]);
    expect(rightType.status).toBe(2);
    expect(rightType.stderr).toContain(`--key is required to verify ${EPOCH_INVENTORY_CONTENT_TYPE}`);
  });

  it('names the verb it was run as when the arguments are not the ones that verb takes', () => {
    const two = runCli(['verify-epoch-inventory', 'a.cbor', 'b.cbor']);
    expect(two.status).toBe(2);
    expect(two.stderr).toContain("expected exactly one argument: 'verify-epoch-inventory <document>'");
    expect(runCli(['verify-epoch-inventory']).status).toBe(2);
  });

  it('accepts a designation it will not consult and says so, which is what a run across a bundle needs', () => {
    // A caller looping a directory hands the same flags to every file, and an unused designation is
    // disclosed rather than dropped: an inventory is authenticated by the keys that sign evidence, not by
    // the one that seals a manifest.
    const result = runCli(['verify-epoch-inventory', HONEST_PATH, HONEST_KEY, '--manifest-key=Lw8V-7JfGaLWBKP0lJG_2TwzuU18b7YKsTeaQO4XN9o', '--json']);
    expect(result.status).toBe(0);
    const rows = verdictOf(result).keyDesignations as Array<Record<string, unknown> | null>;
    const manifestRow = rows.filter((one): one is Record<string, unknown> => one !== null && one.source === '--manifest-key');
    expect(manifestRow.map((one) => one.consulted)).toEqual([false]);
    expect(manifestRow.map((one) => one.publicKey)).toEqual(['Lw8V-7JfGaLWBKP0lJG_2TwzuU18b7YKsTeaQO4XN9o']);
  });
});
