import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';

const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
const tempDir = mkdtempSync(join(tmpdir(), 'ashaveri-signerd-'));
const MANIFEST = join(tempDir, 'weights-manifest.json');
writeFileSync(MANIFEST, `{"files":[{"name":"model.safetensors","sha256":"${'ab'.repeat(32)}"}]}`);

const CREDENTIALS = join(tempDir, 'credentials.json');
const ACCESS_DIR = join(tempDir, 'access');
mkdirSync(ACCESS_DIR);
/** An empty list is a valid file: nothing is admitted, which is a starting point and not an error. */
writeFileSync(CREDENTIALS, '{"version":1,"credentials":[]}');

let written = 0;
function credentialFile(text: string): string {
  written += 1;
  const path = join(tempDir, `creds-${String(written)}.json`);
  writeFileSync(path, text);
  return path;
}

afterAll(() => {
  rmSync(tempDir, { recursive: true, force: true });
});

function run(...args: string[]) {
  const env = { ...process.env };
  delete env['DSTACK_SIMULATOR_ENDPOINT'];
  const result = spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', env });
  // Without this a process that never started leaves `status` null, which reads as the CLI
  // exiting with the wrong code rather than as the spawn itself failing.
  expect(result.error).toBeUndefined();
  return result;
}

/**
 * Start a gateway that serves, read what it printed, and stop it. Every other case in this file is an
 * exit path, so the command returns by itself; a booted gateway has no such ending, which is why the
 * spawn timeout here is the way the test finishes rather than a symptom of one failing.
 */
function runStopped(...args: string[]) {
  const env = { ...process.env };
  delete env['DSTACK_SIMULATOR_ENDPOINT'];
  const result = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    env,
    timeout: 4000,
    killSignal: 'SIGKILL',
  });
  // The only acceptable error is the stop itself: anything else means the process died on its own,
  // and its stdout would then be a refusal message rather than the banner under test. A CLI that
  // grows an exit path of its own must not pass that check by printing a line about a timeout.
  const stopped = result.error as (Error & { code?: string }) | undefined;
  expect(stopped?.code, `the spawn ended with: ${JSON.stringify(result.error)}`).toBe('ETIMEDOUT');
  return result.stdout.split('\n');
}

/**
 * Live mode asks for a credential file and an access log directory before it does anything else, so a
 * case about `--tee` or `--public-url` has to carry them too. A case that is *about* one of those two
 * flags passes its own value after these, and the later one wins.
 */
function liveArgs(...args: string[]): string[] {
  return [
    '--live',
    '--public-url',
    'https://inference.ashaveri.test',
    '--weights-manifest',
    MANIFEST,
    '--credentials-path',
    CREDENTIALS,
    '--access-log-path',
    ACCESS_DIR,
    ...args,
  ];
}

describe('signerd cli', () => {
  it('prints usage with --help', () => {
    const result = run('--help');
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('signerd');
    expect(result.stdout).toContain('--mock');
    expect(result.stdout).toContain('--public-url');
  });

  it('exits with 2 when --mock is missing', () => {
    const result = run();
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('--mock');
  });

  it('exits with 2 for an invalid port', () => {
    const result = run('--mock', '--port', 'not-a-port');
    expect(result.status).toBe(2);
    expect(result.stderr).toContain("invalid port 'not-a-port'");
  });

  it('exits with 2 for a receipts directory that is not one', () => {
    const result = run('--mock', '--receipts-dir', join(tempDir, 'not-mounted'));
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('--receipts-dir must name an existing directory');
  });

  it('refuses a receipts directory that is a file', () => {
    const result = run('--mock', '--receipts-dir', MANIFEST);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('--receipts-dir must name an existing directory');
  });

  it('exits with 2 when both modes are requested', () => {
    const result = run('--mock', '--live');
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('exactly one of --mock or --live');
  });

  it('names the live argument that is missing', () => {
    const result = run('--live', '--credentials-path', CREDENTIALS, '--access-log-path', ACCESS_DIR);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('--public-url is required in live mode');
  });

  it('rejects a public URL that is not absolute', () => {
    const result = run(
      ...liveArgs(
        '--model',
        'm',
        '--public-url',
        'inference.ashaveri.test',
      ),
    );
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('--public-url is not an absolute URL');
  });

  it('requires at least one model', () => {
    const result = run(...liveArgs('--tee', 'snp'));
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('at least one --model');
  });

  it('rejects an unknown tee kind', () => {
    const result = run(...liveArgs('--model', 'm', '--tee', 'sgx'));
    expect(result.status).toBe(2);
    expect(result.stderr).toContain("--tee must be one of snp, snp+gpucc, tdx, tdx+gpucc, got 'sgx'");
  });

  it('accepts a composite claim over TDX', () => {
    // Past validation and as far as the guest agent, which this environment has none of.
    const result = run(...liveArgs('--model', 'm', '--tee', 'tdx+gpucc'));
    expect(result.stderr).not.toContain('--tee must be');
    expect(result.stderr).toContain('GUEST_ENDPOINT_MISSING');
  });

  it('reports an unreachable guest agent without a stack trace', () => {
    const result = run(...liveArgs('--model', 'm'));
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('GUEST_ENDPOINT_MISSING');
    expect(result.stderr).not.toContain('    at ');
  });
});

describe('the banner a booted gateway prints', () => {
  // A live run cannot boot here: it stops at the guest agent, so only the mock half of the mode
  // label can be seen from a test. The two lines are still pinned to each other, because the first
  // one is what the second one claims to match. The timeout is the stop plus room to reach it,
  // since this case spends most of its life waiting to be interrupted.
  it(
    'names the mode the printed dev credential belongs to',
    () => {
      const banner = runStopped('--mock', '--port', '0');
      const printed = banner.join('\n');
      expect(banner[0], `no listening line; stdout held ${JSON.stringify(printed)}`).toMatch(
        /^signerd \(mock\) listening on http:\/\/127\.0\.0\.1:\d+$/u,
      );
      const credential = banner.find((line) => line.includes('id=dev privateKeyHex='));
      expect(credential, `no dev credential line; stdout held ${JSON.stringify(printed)}`).toMatch(
        /^ {2}dev credential for this mock run: id=dev privateKeyHex=[0-9a-f]{64}$/u,
      );
    },
    12_000,
  );
});

describe('the flags that make the access floor real', () => {
  it('names the missing credential file before it contacts the guest agent', () => {
    const result = run(
      '--live',
      '--public-url',
      'https://inference.ashaveri.test',
      '--weights-manifest',
      MANIFEST,
      '--model',
      'm',
      '--access-log-path',
      ACCESS_DIR,
    );
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('--credentials-path is required in live mode');
    expect(result.stderr).not.toContain('GUEST_ENDPOINT_MISSING');
  });

  it('names the missing access log directory', () => {
    const result = run(
      '--live',
      '--public-url',
      'https://inference.ashaveri.test',
      '--weights-manifest',
      MANIFEST,
      '--model',
      'm',
      '--credentials-path',
      CREDENTIALS,
    );
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('--access-log-path is required in live mode');
  });

  it('refuses an access log path that is not a directory', () => {
    const result = run(...liveArgs('--model', 'm', '--access-log-path', MANIFEST));
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('--access-log-path must name an existing directory');
  });

  it('refuses a credential file it cannot read', () => {
    const result = run(...liveArgs('--model', 'm', '--credentials-path', join(tempDir, 'not-mounted.json')));
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('--credentials-path');
    expect(result.stderr).toContain('could not be read');
  });

  it('refuses a credential file that is not JSON, and names the flag', () => {
    const result = run(...liveArgs('--model', 'm', '--credentials-path', credentialFile('{ not json')));
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('--credentials-path');
    expect(result.stderr).toContain('not JSON');
  });

  it('refuses a record with no public key, and says which one', () => {
    const path = credentialFile(
      '{"version":1,"credentials":[{"id":"a","kind":"pop","scopes":["complete"],"createdAt":1}]}',
    );
    const result = run(...liveArgs('--model', 'm', '--credentials-path', path));
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('--credentials-path');
    expect(result.stderr).toContain('credentials[0].publicKey');
  });

  it('refuses a bearer hash that is malformed even with bearer allowed', () => {
    const path = credentialFile(
      '{"version":1,"credentials":[{"id":"b","kind":"bearer","secretHash":"deadbeef","scopes":["complete"],"createdAt":1}]}',
    );
    const result = run(...liveArgs('--model', 'm', '--allow-bearer', '--credentials-path', path));
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('--credentials-path');
    expect(result.stderr).toContain('credentials[0].secretHash');
  });

  it('refuses a retention window that is not a whole number of days', () => {
    const result = run('--mock', '--access-log-days', '0');
    expect(result.status).toBe(2);
    expect(result.stderr).toContain("--access-log-days must be a positive whole number of days, got '0'");
  });

  it('refuses a tolerance that is not a whole number of seconds', () => {
    const result = run('--mock', '--pop-tolerance', '12.5');
    expect(result.status).toBe(2);
    expect(result.stderr).toContain("--pop-tolerance must be a positive whole number of seconds, got '12.5'");
  });

  it('reports the posture a flagless mock run boots into', () => {
    const banner = runStopped('--mock', '--port', '0');
    const printed = banner.join('\n');
    expect(banner[0], `no listening line; stdout held ${JSON.stringify(printed)}`).toMatch(
      /^signerd \(mock\) listening on http:\/\/127\.0\.0\.1:\d+$/u,
    );
    expect(banner, printed).toContain(
      '  auth: proof of possession, timestamps trusted within 120 seconds; bearer credentials refused',
    );
    expect(banner, printed).toContain(
      '  access log: this process only, kept for 184 days and gone on restart',
    );
    expect(banner, printed).not.toContain(
      '  auth: bearer credentials also accepted, which is a refusal of the strongest posture here',
    );
  });

  it('says what bearer mode costs when it is turned on', () => {
    const banner = runStopped('--mock', '--port', '0', '--allow-bearer');
    const printed = banner.join('\n');
    const line = banner.find((each) => each.includes('bearer credentials also accepted'));
    expect(line, `no bearer line; stdout held ${JSON.stringify(printed)}`).toContain(
      'a stolen bearer credential is undetectable',
    );
  });

  it('names a shortened window as the choice it is', () => {
    const banner = runStopped('--mock', '--port', '0', '--access-log-days', '30');
    const printed = banner.join('\n');
    expect(banner, printed).toContain('  access log: this process only, kept for 30 days and gone on restart');
    const note = banner.find((each) => each.startsWith('  note: '));
    expect(note, `no note line; stdout held ${JSON.stringify(printed)}`).toContain('30 days');
    expect(note, printed).toContain('184-day floor');
    expect(note, printed).toContain('Annex III point 1(a)');
  });

  it('reports the directory and what was already in it', () => {
    const dir = join(tempDir, 'already-held');
    mkdirSync(dir);
    // A name the log's own pattern produces, so the count is of files this tool recognises and not of
    // whatever a stray on the volume happens to be called.
    writeFileSync(join(dir, 'access-2026-09-16-000.jsonl'), '');
    const banner = runStopped('--mock', '--port', '0', '--access-log-path', dir);
    const printed = banner.join('\n');
    const line = banner.find((each) => each.startsWith('  access log: '));
    expect(line, `no access log line; stdout held ${JSON.stringify(printed)}`).toContain(dir);
    expect(line, printed).toContain('kept for 184 days');
    expect(line, printed).toContain('with 1 file from before this boot');
    expect(line, printed).not.toContain('this process only');
  });

  // Two boots, because the claim is about a difference between them: one run has no credential file and
  // one has. Each boot is stopped by the spawn timeout, so this case spends about twice what a
  // single-boot case does and needs the runner's allowance raised the same way.
  it(
    'keeps the dev credential to the run that has no credential file',
    () => {
      const banner = runStopped('--mock', '--port', '0');
      expect(banner.some((each) => each.includes('id=dev privateKeyHex=')), banner.join('\n')).toBe(true);
      const held = runStopped('--mock', '--port', '0', '--credentials-path', CREDENTIALS);
      expect(held.some((each) => each.includes('id=dev')), held.join('\n')).toBe(false);
    },
    12_000,
  );
});
