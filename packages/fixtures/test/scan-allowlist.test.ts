import { spawnSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { sha256 } from '@noble/hashes/sha2.js';
import { toHex } from '@ashaveri/sdk';
import { afterAll, describe, expect, it } from 'vitest';

/**
 * The scan config's generator, run as the vectors job runs it.
 *
 * The file it writes is the permission the history scan reads, so two properties are checked here rather than
 * assumed from a green scan: that the committed bytes are what the script produces from this tree, and that a
 * value the script cannot account for reaches no block. Both are read off the written file rather than off the
 * script's own constants, because a check that repeats the generator's data agrees with it whatever the tree
 * says.
 *
 * The roster of candidates is data at the scanned root, `scan-allowlist.json`, so the witnesses below edit a
 * copy of that file inside a temporary root rather than the committed one: a refusal witnessed against the
 * tree the estate ships would leave the shipped permission mutated for as long as the run takes, and the suite
 * would then be a hazard to itself. What each witness shows is the same in either case: the run exits 1, names
 * the file and the entry, and writes no config.
 *
 * The script runs as a child process, since writing the config is its whole job and a test that imported it
 * would rewrite the file it pins. The root passed to it carries copies of the roster and of exactly the paths
 * the committed config names, so an answer here is an answer about those bytes.
 */

const PKG = fileURLToPath(new URL('../', import.meta.url));
const ROOT = fileURLToPath(new URL('../../../', import.meta.url));
const SCRIPT = join(PKG, 'scripts', 'derive-scan-allowlist.ts');
const CONFIG_PATH = join(ROOT, '.gitleaks.toml');
const ROSTER = 'scan-allowlist.json';
const CAPTURE = 'packages/fixtures/data/capture-v1.json';
const EPOCH = 'packages/fixtures/data/epoch-inventory-v1.json';
const POP = 'packages/fixtures/data/pop-v1.json';
const SPAWN_DEADLINE_MS = 120_000;

const committed = readFileSync(CONFIG_PATH, 'utf8');
const base = mkdtempSync(join(tmpdir(), 'ashaveri-scan-allowlist-'));

afterAll(() => {
  rmSync(base, { recursive: true, force: true });
});

/** One `[[allowlists]]` block of a written file, with its arrays read out of it. */
interface WrittenBlock {
  readonly description: string;
  readonly condition: string;
  readonly regexTarget: string;
  readonly regexes: readonly string[];
  readonly paths: readonly string[];
}

/** The blocks a config states, read from its text rather than from the script that wrote it. */
function blocksOf(config: string): readonly WrittenBlock[] {
  return config.split('[[allowlists]]').slice(1).map((chunk) => {
    const array = (name: string): string[] => {
      const body = new RegExp(`^${name} = \\[([\\s\\S]*?)^\\]`, 'mu').exec(chunk)?.[1] ?? '';
      return [...body.matchAll(/'''(.*?)'''/gu)].map((found) => found[1] ?? '');
    };
    return {
      description: /^description = "(.*)"/mu.exec(chunk)?.[1] ?? '',
      condition: /^condition = "(.*)"/mu.exec(chunk)?.[1] ?? '',
      regexTarget: /^regexTarget = "(.*)"/mu.exec(chunk)?.[1] ?? '',
      regexes: array('regexes'),
      paths: array('paths'),
    };
  });
}

/** A written literal back to the value or path it anchors, escaping taken off. */
function unanchor(text: string): string {
  return text.replace(/^\^/u, '').replace(/\$$/u, '').replace(/\\([.^$+{}()|[\]])/gu, '$1');
}

/** The paths the committed config names, which are the files the script reads. */
const namedPaths = blocksOf(committed).flatMap((block) => block.paths.map(unanchor));

/** A repository root carrying one copy of the roster and of every path the committed config names. */
function treeCopy(tag: string): string {
  const dir = mkdtempSync(join(base, `${tag}-`));
  for (const relative of [ROSTER, ...namedPaths]) {
    const target = join(dir, relative);
    mkdirSync(dirname(target), { recursive: true });
    copyFileSync(join(ROOT, relative), target);
  }
  return dir;
}

/** One entry of the roster, read as the data it is so a witness can replace one field of it. */
type RosterEntry = { [key: string]: unknown };

/** The roster of a copied tree, and the same roster written back with one entry changed by the witness. */
function rosterOf(dir: string): { version: number; description: string; entries: RosterEntry[] } {
  return JSON.parse(readFileSync(join(dir, ROSTER), 'utf8')) as {
    version: number;
    description: string;
    entries: RosterEntry[];
  };
}

function writeRoster(dir: string, roster: { version: number; description: string; entries: RosterEntry[] }): void {
  writeFileSync(join(dir, ROSTER), `${JSON.stringify(roster, null, 2)}\n`, 'utf8');
}

/** The one entry of a copied roster naming this path, refusing a witness that would edit nothing. */
function entryAt(roster: { entries: RosterEntry[] }, path: string): RosterEntry {
  const entry = roster.entries.find((one) => one['path'] === path);
  if (entry === undefined) throw new Error(`${path}: the roster copy carries no entry for the witness to edit`);
  return entry;
}

/** One run of the generator over `root`, with its exit status and both streams. */
function generate(root: string): { status: number | null; stdout: string; stderr: string } {
  const result = spawnSync(process.execPath, [SCRIPT, '--root', root], {
    encoding: 'utf8',
    timeout: SPAWN_DEADLINE_MS,
    killSignal: 'SIGKILL',
  });
  expect(result.error ?? null, 'the generator did not run').toBeNull();
  return { status: result.status, stdout: result.stdout ?? '', stderr: result.stderr ?? '' };
}

/**
 * The last `recordKey` a capture file states, replaced by a value that is a well-formed digest of nothing the
 * tree carries. The line it sat on comes back so the refusal can be named rather than counted.
 */
function plantFakeCaptureKey(path: string): { readonly planted: string; readonly line: number } {
  const text = readFileSync(path, 'utf8');
  const hits = [...text.matchAll(/"recordKey": "[0-9a-f]{64}"/gu)];
  const last = hits.pop();
  if (last === undefined || last.index === undefined) {
    throw new Error(`${path} states no ${'"recordKey"'} value for the witness to replace`);
  }
  const planted = toHex(sha256(new TextEncoder().encode('ashaveri-scan-allowlist-witness/planted-fake')));
  const line = text.slice(0, last.index).split('\n').length;
  const replacement = `"recordKey": "${planted}"`;
  writeFileSync(path, text.slice(0, last.index) + replacement + text.slice(last.index + last[0].length), 'utf8');
  return { planted, line };
}

describe('the scan config as a written artifact', () => {
  it('pins the committed bytes to what the script produces from this tree', () => {
    const dir = treeCopy('pin');
    const run = generate(dir);
    expect(run.status, run.stderr).toBe(0);
    expect(readFileSync(join(dir, '.gitleaks.toml'), 'utf8')).toBe(committed);
  });

  it('refuses a stated value that digests to no bytes of the tree, and writes no config', () => {
    const dir = treeCopy('refuse');
    const path = join(dir, CAPTURE);
    const { planted, line } = plantFakeCaptureKey(path);

    const run = generate(dir);
    expect(run.status, 'a stated candidate nothing digests to must not reach a block').toBe(1);
    expect(run.stderr).toContain(CAPTURE);
    expect(run.stderr).toContain(`line ${String(line)} refused`);
    expect(run.stderr).toContain('1 unexplained candidate(s)');
    expect(`${run.stdout}${run.stderr}`).not.toContain(planted);
    expect(existsSync(join(dir, '.gitleaks.toml')), 'a refused run wrote the config anyway').toBe(false);
  });
});

describe('the roster the config is written from', () => {
  it('refuses a rule name no implementation answers, and writes no config', () => {
    const dir = treeCopy('unknown-rule');
    const roster = rosterOf(dir);
    entryAt(roster, EPOCH)['rule'] = 'sha256-of-any-string';
    writeRoster(dir, roster);

    const run = generate(dir);
    expect(run.status, 'a rule the script does not implement must not fall back to a default').toBe(1);
    expect(run.stderr).toContain(ROSTER);
    expect(run.stderr).toContain(EPOCH);
    expect(run.stderr).toContain('no implementation answers');
    expect(run.stderr).toContain('hand-written');
    expect(existsSync(join(dir, '.gitleaks.toml')), 'a refused roster wrote the config anyway').toBe(false);
  });

  it('refuses an entry whose path the root does not carry, and writes no config', () => {
    const dir = treeCopy('absent-path');
    rmSync(join(dir, EPOCH));

    const run = generate(dir);
    expect(run.status, 'an entry pointing at nothing must not write a block over it').toBe(1);
    expect(run.stderr).toContain(ROSTER);
    expect(run.stderr).toContain(EPOCH);
    expect(run.stderr).toContain('absent from this root');
    expect(existsSync(join(dir, '.gitleaks.toml')), 'a refused roster wrote the config anyway').toBe(false);
  });

  it('refuses a stated value the rule the roster names digests to nothing, and writes no config', () => {
    const dir = treeCopy('wrong-rule');
    const roster = rosterOf(dir);
    // The import rule runs over envelopes and the capture file carries records, so every record key the file
    // states is now a candidate that no recomputed address answers.
    entryAt(roster, CAPTURE)['rule'] = 'import-envelope-key';
    writeRoster(dir, roster);

    const run = generate(dir);
    expect(run.status, 'a value the bytes at its path do not digest to must not reach a block').toBe(1);
    expect(run.stderr).toContain(CAPTURE);
    expect(run.stderr).toContain('unexplained candidate(s)');
    expect(existsSync(join(dir, '.gitleaks.toml')), 'a refused roster wrote the config anyway').toBe(false);
  });

  it('refuses a hand-written value no line of its path states, and writes no config', () => {
    const dir = treeCopy('poisoned-value');
    const roster = rosterOf(dir);
    const entry = entryAt(roster, POP);
    const stated = entry['value'];
    if (typeof stated !== 'string' || stated.length === 0) {
      throw new Error(`${POP}: the roster copy states no hand-written value to poison`);
    }
    entry['value'] = `${stated.slice(0, -1)}${stated.endsWith('0') ? '1' : '0'}`;
    writeRoster(dir, roster);

    const run = generate(dir);
    expect(run.status, 'the roster is read but not believed if a poisoned value still writes a block').toBe(1);
    expect(run.stderr).toContain(ROSTER);
    expect(run.stderr).toContain(POP);
    expect(run.stderr).toContain('hand-written value, and none does');
    expect(existsSync(join(dir, '.gitleaks.toml')), 'a refused roster wrote the config anyway').toBe(false);
  });

  it('refuses an entry stating a field no rule reads, and writes no config', () => {
    const dir = treeCopy('unknown-field');
    const roster = rosterOf(dir);
    // The spelling the script's own constant used before the roster existed, which the roster does not read.
    entryAt(roster, EPOCH)['pattern'] = 'key kid=([0-9a-f]{64})';
    writeRoster(dir, roster);

    const run = generate(dir);
    expect(run.status, 'a field the script does not read must not be ignored as noise').toBe(1);
    expect(run.stderr).toContain(ROSTER);
    expect(run.stderr).toContain('pattern');
    expect(run.stderr).toContain('no rule reads');
    expect(existsSync(join(dir, '.gitleaks.toml')), 'a refused roster wrote the config anyway').toBe(false);
  });
});

describe('the pairing every written block keeps', () => {
  /** The blocks of the file the script writes for this tree, read from what it wrote rather than from its data. */
  function written(): readonly WrittenBlock[] {
    const dir = treeCopy('pairing');
    const run = generate(dir);
    expect(run.status, run.stderr).toBe(0);
    return blocksOf(readFileSync(join(dir, '.gitleaks.toml'), 'utf8'));
  }

  it('names one path per block, ANDs it to its values, and matches the secret half', () => {
    const blocks = written();
    expect(blocks.length).toBeGreaterThan(0);
    for (const block of blocks) {
      expect(block.paths, `${block.description}: a block naming more than one file`).toHaveLength(1);
      expect(block.condition, `${block.description}: the pairing is not AND`).toBe('AND');
      expect(block.regexTarget, `${block.description}: the match is not the secret half`).toBe('secret');
      expect(block.regexes.length, `${block.description}: a block naming no value`).toBeGreaterThan(0);
      for (const literal of [...block.regexes, ...block.paths]) {
        expect(literal.startsWith('^') && literal.endsWith('$'), `${block.description}: ${literal} unanchored`).toBe(
          true,
        );
      }
    }
  });

  it('exempts no value at a second path, so no block reaches a cross product', () => {
    const pathsOfValue = new Map<string, string[]>();
    for (const block of written()) {
      const paths = block.paths.map(unanchor);
      for (const value of block.regexes.map(unanchor)) {
        pathsOfValue.set(value, [...(pathsOfValue.get(value) ?? []), ...paths]);
      }
    }
    expect(pathsOfValue.size).toBeGreaterThan(0);
    for (const [value, paths] of pathsOfValue) {
      expect(new Set(paths).size, `${value.slice(0, 12)}... is exempted at ${String(paths.length)} paths`).toBe(1);
    }
  });
});
