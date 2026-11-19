import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import { noteSpawn, spawnCeilingForCalls } from './support/spawn-budget.js';

/**
 * The rights exercise, run the way an operator runs it.
 *
 * This suite starts the drill as a child and reads what it printed and what it filed. It imports nothing
 * from `scripts/`, because a check that reached into the drill's own functions would pass on a host where
 * the drill cannot run, and what is being proved is that one command builds a store, serves from it,
 * erases it, restores it, and reports honestly about all of that.
 *
 * The verdicts are pinned here as well as in the drill. A leg whose mechanism ships and a leg whose
 * mechanism is missing are different claims, and the day one of them changes, two files have to move:
 * a row that stopped being exercised goes red rather than disappearing from the table.
 */

const DRILL = fileURLToPath(new URL('../scripts/rights-drill/drill.ts', import.meta.url));
const SCRIPTS = fileURLToPath(new URL('../scripts/rights-drill/', import.meta.url));

/** One child that boots a gateway, runs erasures as children of its own, and opens stores to restore. */
const SPAWN_DEADLINE_MS = 60_000;
const CEILING = spawnCeilingForCalls(1, SPAWN_DEADLINE_MS);

const tempDir = mkdtempSync(join(tmpdir(), 'ashaveri-rights-drill-case-'));

afterAll(() => {
  rmSync(tempDir, { recursive: true, force: true });
});

interface Check {
  name: string;
  expect: string;
  observed: string;
  passed: boolean;
}

interface Leg {
  leg: number;
  name: string;
  summary: string;
  built: boolean;
  verdict: string;
  checks: Check[];
  commands: string[];
  notes: string[];
  missing: string[];
  readings?: {
    before: { observedFiles: string[]; syntaxInvalid: number; schemaInvalid: number; schemaInvalidMatches: number; credentialMatches: number };
    after: { observedFiles: string[]; syntaxInvalid: number; schemaInvalid: number; schemaInvalidMatches: number; credentialMatches: number };
  };
}

interface DrillRecord {
  counts: { legs: number; exercised: number; not_built: number; failed: number; checks: number; checks_failed: number };
  store: string;
  legs: Leg[];
  missing: string[];
  warnings: { code: string; message: string }[];
}

interface DrillRun {
  status: number | null;
  stdout: string;
  stderr: string;
  recordPath: string;
  record: DrillRecord;
}

function runDrill(name: string, extra: readonly string[] = []): DrillRun {
  const recordPath = join(tempDir, `${name}-record.json`);
  noteSpawn(SPAWN_DEADLINE_MS);
  const result = spawnSync(process.execPath, [DRILL, '--record', recordPath, ...extra], {
    encoding: 'utf8',
    timeout: SPAWN_DEADLINE_MS,
    killSignal: 'SIGKILL',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  expect(result.error, `the drill did not start: ${String(result.error)}`).toBeUndefined();
  expect(existsSync(recordPath), `the drill did not file the record it names: ${recordPath}`).toBe(true);
  const record = JSON.parse(readFileSync(recordPath, 'utf8')) as DrillRecord;
  const warnings = result.stderr.split('\n').filter((line) => line.length > 0 && !line.startsWith('(Use `node --trace-warnings'));
  expect(record.warnings).toHaveLength(warnings.length);
  for (const [index, line] of warnings.entries()) {
    expect(line).toMatch(/^\(node:\d+\) \[ASHAVERI_ACCESS_JOURNAL_DRAIN_STALLED\] Warning: /u);
    expect(record.warnings[index]?.code).toBe('ASHAVERI_ACCESS_JOURNAL_DRAIN_STALLED');
    expect(line).toContain(record.warnings[index]?.message);
  }
  return {
    status: result.status,
    stdout: result.stdout,
    stderr: result.stderr,
    recordPath,
    record,
  };
}

function runInjectedDrill(name: string, leg: number, source: string): DrillRun {
  const preload = join(tempDir, `${name}.mjs`);
  const recordPath = join(tempDir, `${name}-record.json`);
  writeFileSync(preload, source);
  noteSpawn(15_000);
  const result = spawnSync(process.execPath, ['--import', pathToFileURL(preload).href, DRILL, '--record', recordPath, '--only', `${String(leg)},6`], {
    encoding: 'utf8', timeout: 15_000, killSignal: 'SIGKILL', stdio: ['ignore', 'pipe', 'pipe'],
  });
  expect(result.error, `the failed drill must terminate: ${String(result.error)}\n${result.stdout}`).toBeUndefined();
  expect(existsSync(recordPath), result.stdout).toBe(true);
  return { status: result.status, stdout: result.stdout, stderr: result.stderr, recordPath, record: JSON.parse(readFileSync(recordPath, 'utf8')) as DrillRecord };
}

/** The table's rows: one per leg, each carrying a verdict and a check count. */
function tableRows(stdout: string): string[] {
  return stdout.split('\n').filter((line) => /^ {0,2}\d {2}\S/u.test(line));
}

function named(leg: Leg, name: string): Check | undefined {
  return leg.checks.find((one) => one.name === name);
}

describe('the rights exercise drill', () => {
  it('runs every leg against a temporary store and reports each one', { timeout: CEILING }, () => {
    const scripts = readdirSync(SCRIPTS).sort();
    const { status, stdout, record, recordPath } = runDrill('full');
    expect(status, `the drill exited ${String(status)}:\n${stdout}`).toBe(0);

    expect(stdout).toContain('rights exercise drill, synthetic identities only');
    expect(stdout).toContain(`record: ${recordPath}`);
    // The store the run built is the operating system's temporary directory, never this tree, and the
    // sources next to this suite are the files the drill was written from and nothing more.
    expect(record.store).toContain('ashaveri-rights-drill-');
    expect(readdirSync(SCRIPTS).sort()).toEqual(scripts);

    const rows = tableRows(stdout);
    expect(rows).toHaveLength(6);
    expect(rows.map((row) => (row.trim().split(/\s+/u))[0])).toEqual(['1', '2', '3', '4', '5', '6']);
    for (const row of rows) {
      expect(row).toMatch(/EXERCISED|NOT BUILT|NOT EXERCISED/u);
      expect(row).toMatch(/\d+\/\d+/u);
    }

    expect(record.legs).toHaveLength(6);
    expect(record.counts.failed).toBe(0);
    expect(record.counts.checks_failed).toBe(0);
    expect(record.counts.checks).toBe(record.legs.reduce((sum, leg) => sum + leg.checks.length, 0));

    expect(record.legs.map((leg) => [leg.leg, leg.name, leg.verdict])).toEqual([
      [1, 'authorized subject access', 'NOT BUILT'],
      [2, 'quiesced erasure', 'EXERCISED'],
      [3, 'coordinated erasure', 'NOT BUILT'],
      [4, 'hold conflicts', 'EXERCISED'],
      [5, 'backup restoration', 'EXERCISED'],
      [6, 'processor notification', 'NOT BUILT'],
    ]);

    for (const leg of record.legs) {
      expect(leg.checks.length, `leg ${String(leg.leg)} reported no checks to exercise`).toBeGreaterThanOrEqual(3);
      expect(leg.commands.length, `leg ${String(leg.leg)} recorded no command`).toBeGreaterThan(0);
      for (const each of leg.checks) {
        expect(each.passed, `${leg.name}: ${each.name} expected ${each.expect} and saw ${each.observed}`).toBe(true);
      }
      if (leg.verdict === 'NOT BUILT') {
        // A row claiming an absence has to have asked the shipped code about it, so the observation the
        // check rests on carries an answer rather than the expectation repeated back.
        expect(leg.missing.length, `a NOT BUILT row must name what is missing (leg ${String(leg.leg)})`).toBeGreaterThan(0);
        expect(leg.checks.every((each) => each.observed.length > 0)).toBe(true);
      } else {
        expect(leg.missing, `an exercised row must not claim past a gap it exercised (leg ${String(leg.leg)})`).toEqual([]);
      }
    }
  });

  it('reports the erasure arithmetic and the hold refusal a reviewer can check', { timeout: CEILING }, () => {
    const { record } = runDrill('arithmetic');
    const [, quiesced, coordinated, hold] = record.legs as [Leg, Leg, Leg, Leg];

    const removed = named(quiesced, 'records the run says it removed');
    expect(removed?.observed).toBe(removed?.expect);
    expect(Number(removed?.observed)).toBeGreaterThan(0);
    expect(named(quiesced, 'credential matches left in observed files')?.observed).toBe('0');
    // The count the door reports is shown against the bytes the volume holds, part by part, in both
    // directions: what it read before, and what it can be proved to have left behind.
    expect(quiesced.checks.filter((one) => one.name.endsWith('before, from the disk'))).toHaveLength(2);
    expect(quiesced.checks.filter((one) => one.name.endsWith('after, on the disk'))).toHaveLength(2);
    expect(named(quiesced, 'a second run over the same volume')?.observed).toContain('removed 0');

    expect(named(coordinated, 'the served path was live across the erasure')?.passed).toBe(true);
    expect(named(coordinated, 'credential matches left in observed files')?.observed).toBe('0');
    expect(named(coordinated, 'records the run says it removed')?.observed).toBe('16');
    const bound = named(coordinated, 'distinct peer request ids in observed files');
    expect(bound?.passed).toBe(true);
    expect(String(bound?.observed)).toMatch(/^\d+ ids for 28 answers$/u);
    expect(coordinated.notes.some((one) => one.includes('reconciliation'))).toBe(true);
    expect(named(coordinated, 'no request was shed by the erasure')?.observed).toContain('0 not 200');

    expect(named(hold, 'the refusal names the code and its sentence')?.expect).toContain('HOLD_ERASURE_REFUSED');
    expect(named(hold, 'bytes of the seeded access-log directory')?.observed).toBe('unchanged');
    expect(named(hold, 'a marker filed by the refused run')?.observed).toBe('none');
    expect(named(hold, 'the count the store reports as held')?.observed).toBe('5');
    expect(named(hold, 'records a 100s window cannot reach, kept by the hold')?.observed).toBe('6');
  });

  it('separates malformed JSON from foreign credential matches in the filed readings', { timeout: CEILING }, () => {
    const { status, stdout, record } = runDrill('classified', ['--only', '2']);
    const leg = record.legs[0];
    expect(leg?.readings?.before).toMatchObject({
      syntaxInvalid: 6, schemaInvalid: 4, schemaInvalidMatches: 3, credentialMatches: 376,
      observedFiles: [
        'access-2026-03-01-000.jsonl', 'access-2026-03-01-001.jsonl', 'access-2026-03-01-002.jsonl',
        'journal-000.jsonl', 'journal-001.jsonl', 'journal-002.jsonl',
      ],
    });
    expect(leg?.readings?.after).toMatchObject({
      syntaxInvalid: 6, schemaInvalid: 1, schemaInvalidMatches: 0, credentialMatches: 0,
      observedFiles: ['access-2026-03-01-000.jsonl', 'access-2026-03-01-001.jsonl', 'journal-000.jsonl', 'journal-002.jsonl'],
    });
    expect(leg && named(leg, 'records the run says it removed')?.observed).toBe('376');
    expect(status, stdout).toBe(0);
  });

  it('retains exact foreign bytes and receipts journal rewrites and deletions', { timeout: CEILING }, () => {
    const { status, stdout, record } = runDrill('retained', ['--only', '2', '--keep']);
    try {
      const dir = join(record.store, 'leg2');
      const markerName = readdirSync(dir).find((name) => name.startsWith('scrub-'));
      expect(markerName).toBeDefined();
      const marker = JSON.parse(readFileSync(join(dir, markerName ?? ''), 'utf8')) as {
        credential: string; removed: number; files: number;
        parts: { name: string; beforeBytes: number; beforeSha256: string; afterBytes: number; afterSha256: string }[];
      };
      expect(marker.removed).toBe(376);
      expect(marker.files).toBe(6);
      expect(marker.parts.map((part) => part.name)).toEqual([
        'access-2026-03-01-000.jsonl', 'access-2026-03-01-001.jsonl', 'access-2026-03-01-002.jsonl',
        'journal-000.jsonl', 'journal-001.jsonl', 'journal-002.jsonl',
      ]);
      const subject = marker.credential;
      const peer = '{"t":1772323200000,"rid":"drill-journal-peer","cred":"journal-peer","auth":"bearer","scope":"complete","m":"POST","p":"/v1/chat/completions","rcp":null,"nce":"journal-peer","st":200,"dur":1,"deny":null}\n';
      const foreign = '{"cred":"journal-other","note":"café"}\n';
      const malformed = `{"cred":"${subject}","note":"unfinished café\n`;
      expect(readFileSync(join(dir, 'journal-000.jsonl'))).toEqual(Buffer.from(peer + foreign + malformed));
      expect(readFileSync(join(dir, 'journal-002.jsonl'))).toEqual(Buffer.from(`{"cred":"${subject}","note":"torn café\n`));
      expect(existsSync(join(dir, 'journal-001.jsonl'))).toBe(false);
      expect(existsSync(join(dir, 'access-2026-03-01-002.jsonl'))).toBe(false);
      expect(readFileSync(join(dir, 'access-not-a-part.jsonl'), 'utf8')).toBe(`{"cred":"${subject}"}\n`);
      for (const name of ['access-2026-03-01-000.jsonl', 'access-2026-03-01-001.jsonl']) {
        const lines = readFileSync(join(dir, name), 'utf8').split('\n').filter(Boolean);
        const invalid: string[] = [];
        for (const line of lines) {
          let parsed: { cred?: unknown };
          try {
            parsed = JSON.parse(line) as { cred?: unknown };
          } catch {
            invalid.push(line);
            continue;
          }
          expect(parsed.cred).not.toBe(subject);
        }
        expect(invalid).toEqual(Array<string>(2).fill(`{"cred":"${subject}","note":"coupée en writing \u{1F600}`));
      }
      for (const part of marker.parts) {
        const path = join(dir, part.name);
        const bytes = existsSync(path) ? readFileSync(path) : Buffer.alloc(0);
        expect(part.beforeBytes).toBeGreaterThan(bytes.length);
        expect(part.beforeSha256).toMatch(/^[0-9a-f]{64}$/u);
        expect(part.afterBytes).toBe(bytes.length);
        expect(part.afterSha256).toBe(createHash('sha256').update(bytes).digest('hex'));
      }
      expect(status, stdout).toBe(0);
    } finally {
      rmSync(record.store, { recursive: true, force: true });
    }
  });

  it('never waits for a keypress when it has no terminal, even when asked to step', { timeout: CEILING }, () => {
    const { status, stdout } = runDrill('stepped', ['--step']);
    expect(status).toBe(0);
    const pauses = stdout.split('\n').filter((line) => line.includes('pause before'));
    expect(pauses).toHaveLength(5);
    for (const line of pauses) expect(line).toContain('skipped');
  });

  it.each(['empty', 'another-receipt'])('refuses restored %s bytes under the requested receipt id', { timeout: CEILING }, (body) => {
    const { status, stdout, record } = runInjectedDrill(`restore-${body}`, 5, `
      import { registerHooks } from 'node:module';
      registerHooks({ resolve(specifier, context, nextResolve) {
        const resolved = nextResolve(specifier, context);
        if (specifier !== '@ashaveri/signerd' || !context.parentURL?.endsWith('/rights-drill/legs.ts')) return resolved;
        const source = 'export * from ' + JSON.stringify(resolved.url) + ';'
          + 'import { openFileReceiptStore as open } from ' + JSON.stringify(resolved.url) + ';'
          + 'export async function openFileReceiptStore(options) {'
          + 'const store = await open(options);'
          + 'if (options.dir.endsWith("copy-whole")) store.get = async () => '
          + ${JSON.stringify(body === 'empty' ? 'new Uint8Array()' : 'new TextEncoder().encode("a synthetic receipt body 0")')}
          + '; return store; }';
        return { url: 'data:text/javascript,' + encodeURIComponent(source), shortCircuit: true };
      }});
    `);
    expect(status, stdout).toBe(1);
    const restored = record.legs[0];
    expect(restored?.verdict).toBe('NOT EXERCISED');
    expect(restored && named(restored, 'every restored receipt matches its seeded bytes')?.passed).toBe(false);
    expect(record.legs[1]?.verdict).toBe('NOT BUILT');
  });

  it.each([1, 3])('closes a failed live leg %i and files its outcome before continuing', { timeout: CEILING }, (leg) => {
    const source = leg === 1 ? `
      import http from 'node:http';
      import { syncBuiltinESMExports } from 'node:module';
      const original = http.request;
      http.request = function (...args) {
        const request = original.apply(this, args);
        process.nextTick(() => request.destroy(new Error('synthetic request failure')));
        return request;
      };
      syncBuiltinESMExports();
    ` : `
      import fs from 'node:fs/promises';
      import net from 'node:net';
      import { syncBuiltinESMExports } from 'node:module';
      let listening = false;
      const emit = net.Server.prototype.emit;
      net.Server.prototype.emit = function (event, ...args) {
        if (event === 'listening') listening = true;
        return emit.call(this, event, ...args);
      };
      const original = fs.readdir;
      fs.readdir = async function (path, ...args) {
        if (listening && String(path).replaceAll(String.fromCharCode(92), '/').endsWith('/leg3/access')) throw new Error('synthetic snapshot failure after startup');
        return original.call(this, path, ...args);
      };
      syncBuiltinESMExports();
    `;
    const { status, stdout, record } = runInjectedDrill(`failure-${String(leg)}`, leg, source);
    expect(status, stdout).toBe(1);
    expect(record.counts.failed).toBe(1);
    expect(record.legs.map((entry) => [entry.leg, entry.verdict])).toEqual([[leg, 'NOT EXERCISED'], [6, 'NOT BUILT']]);
    expect(record.legs[0]?.checks.some((entry) => !entry.passed && entry.observed.includes(leg === 1 ? 'synthetic request failure' : 'synthetic snapshot failure'))).toBe(true);
    const store = stdout.split('\n').find((line) => line.startsWith('temporary store: '))?.slice('temporary store: '.length);
    expect(store).toBeDefined();
    expect(existsSync(store ?? '')).toBe(false);
  });

  it.each(['traffic', 'scrub'])('settles both concurrent operations before closing after a %s failure', { timeout: CEILING }, (failed) => {
    const tracePath = join(tempDir, `concurrent-${failed}.json`);
    const { status, stdout, record } = runInjectedDrill(`concurrent-${failed}`, 3, `
      import http from 'node:http';
      import net from 'node:net';
      import childProcess from 'node:child_process';
      import { writeFileSync } from 'node:fs';
      import { syncBuiltinESMExports } from 'node:module';
      let activeRequests = 0;
      let requests = 0;
      let scrubStarted = false;
      let scrubSettled = false;
      const originalRequest = http.request;
      http.request = function (options, callback) {
        requests += 1;
        activeRequests += 1;
        let done = false;
        const settled = () => { if (!done) { done = true; activeRequests -= 1; } };
        const request = originalRequest.call(this, options, (response) => {
          response.once('end', settled);
          callback(response);
        });
        request.once('error', settled);
        if (${JSON.stringify(failed)} === 'traffic' && requests === 13) {
          process.nextTick(() => request.destroy(new Error(scrubStarted ? 'synthetic concurrent traffic failure' : 'traffic failed before scrub started')));
        }
        return request;
      };
      const originalSpawn = childProcess.spawn;
      childProcess.spawn = function (command, args, options) {
        const scrub = args.includes('scrub') && !scrubStarted;
        if (scrub) scrubStarted = true;
        const child = originalSpawn.call(this, scrub && ${JSON.stringify(failed)} === 'scrub' ? command + '.missing' : command, args, options);
        if (scrub) {
          child.once('error', () => { scrubSettled = true; });
          child.once('close', () => { scrubSettled = true; });
        }
        return child;
      };
      const originalClose = net.Server.prototype.close;
      net.Server.prototype.close = function (...args) {
        writeFileSync(${JSON.stringify(tracePath)}, JSON.stringify({ activeRequests, requests, scrubStarted, scrubSettled }));
        return originalClose.apply(this, args);
      };
      syncBuiltinESMExports();
    `);
    expect(status, stdout).toBe(1);
    expect(record.legs.map((leg) => [leg.leg, leg.verdict])).toEqual([[3, 'NOT EXERCISED'], [6, 'NOT BUILT']]);
    const trace = JSON.parse(readFileSync(tracePath, 'utf8')) as Record<string, unknown>;
    expect(trace).toEqual({ activeRequests: 0, requests: failed === 'traffic' ? 13 : 36, scrubStarted: true, scrubSettled: true });
    expect(record.legs[0]?.checks[0]?.observed).toContain(failed === 'traffic' ? 'synthetic concurrent traffic failure' : 'ENOENT');
  });

  it('keeps the default record after removing the temporary store', { timeout: CEILING }, () => {
    noteSpawn(SPAWN_DEADLINE_MS);
    const result = spawnSync(process.execPath, [DRILL, '--only', '6'], { encoding: 'utf8', timeout: SPAWN_DEADLINE_MS, killSignal: 'SIGKILL' });
    expect(result.error).toBeUndefined();
    expect(result.status, result.stdout).toBe(0);
    const recordPath = result.stdout.split('\n').find((line) => line.startsWith('record: '))?.slice('record: '.length);
    const store = result.stdout.split('\n').find((line) => line.startsWith('temporary store: '))?.slice('temporary store: '.length);
    expect(recordPath).toBeDefined();
    expect(store).toBeDefined();
    try {
      expect(existsSync(recordPath ?? '')).toBe(true);
      expect(existsSync(store ?? '')).toBe(false);
      const record = JSON.parse(readFileSync(recordPath ?? '', 'utf8')) as DrillRecord;
      expect(record.legs[0]?.verdict).toBe('NOT BUILT');
    } finally {
      if (recordPath !== undefined) rmSync(recordPath, { force: true });
    }
  });

  it('runs one leg at a time and reports only that leg', { timeout: CEILING }, () => {
    const { status, record, stdout } = runDrill('one-leg', ['--only', '6']);
    expect(status, stdout).toBe(0);
    expect(record.legs).toHaveLength(1);
    expect(record.legs[0]?.verdict).toBe('NOT BUILT');
    expect(record.counts.legs).toBe(1);
    expect(tableRows(stdout)).toHaveLength(1);
  });
});
