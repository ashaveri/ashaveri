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
 * The script runs as a child process, since writing the config is its whole job and a test that imported it
 * would rewrite the file it pins. The root passed to it carries copies of exactly the paths the committed
 * config names, so an answer here is an answer about those bytes.
 */

const PKG = fileURLToPath(new URL('../', import.meta.url));
const ROOT = fileURLToPath(new URL('../../../', import.meta.url));
const SCRIPT = join(PKG, 'scripts', 'derive-scan-allowlist.ts');
const CONFIG_PATH = join(ROOT, '.gitleaks.toml');
const CAPTURE = 'packages/fixtures/data/capture-v1.json';
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

/** A repository root carrying one copy of every path the committed config names. */
function treeCopy(tag: string): string {
  const dir = mkdtempSync(join(base, `${tag}-`));
  for (const relative of namedPaths) {
    const target = join(dir, relative);
    mkdirSync(dirname(target), { recursive: true });
    copyFileSync(join(ROOT, relative), target);
  }
  return dir;
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
