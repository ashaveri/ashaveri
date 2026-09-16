import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';

const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
const tempDir = mkdtempSync(join(tmpdir(), 'ashaveri-signerd-'));
const MANIFEST = join(tempDir, 'weights-manifest.json');
writeFileSync(MANIFEST, `{"files":[{"name":"model.safetensors","sha256":"${'ab'.repeat(32)}"}]}`);

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

function liveArgs(...args: string[]): string[] {
  return ['--live', '--public-url', 'https://inference.ashaveri.test', '--weights-manifest', MANIFEST, ...args];
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
    const result = run('--live');
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('--public-url is required in live mode');
  });

  it('rejects a public URL that is not absolute', () => {
    const result = run('--live', '--public-url', 'inference.ashaveri.test', '--weights-manifest', MANIFEST, '--model', 'm');
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
