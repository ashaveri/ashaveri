import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';

const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
const FIXTURES = fileURLToPath(new URL('../../attest-core/test/fixtures/', import.meta.url));
const ATTESTATION = `${FIXTURES}sev-snp-attestation.bin`;
const ARK = `${FIXTURES}amd-ark-milan.pem`;
const ASK = `${FIXTURES}sev-snp-ask.pem`;
const VCEK = `${FIXTURES}sev-snp-vcek.pem`;
const INTEL_ROOT = `${FIXTURES}intel-sgx-root-ca.pem`;
const NOW = '2026-09-10T00:00:00Z';
const FIXTURE_REPORT_DATA = '6174746573742d746573742d666978747572652d32303236';
const FIXTURE_MEASUREMENT =
  '7f51e17f72a04d5422cb2c00998166536019a217376f3aa45a630e59c805a599847ff250dbffcd07e1ba639771d6f05d';
const FIXTURE_COMPOSE_HASH = '86e59625be93207bc2351c4d1bba20037cec8e168da6b18f559af5af657b7a23';

const VERIFY_ARGS = ['verify', ATTESTATION, '--ark', ARK, '--ask', ASK, '--vcek', VCEK, '--now', NOW];

const tempDir = mkdtempSync(join(tmpdir(), 'ashaveri-cli-'));

afterAll(() => {
  rmSync(tempDir, { recursive: true, force: true });
});

interface CliResult {
  readonly status: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

function runCli(args: string[], input?: Uint8Array): CliResult {
  const result = spawnSync(process.execPath, [CLI, ...args], {
    input: input === undefined ? undefined : Buffer.from(input),
    encoding: 'utf8',
  });
  expect(result.error).toBeUndefined();
  return { status: result.status, stdout: result.stdout ?? '', stderr: result.stderr ?? '' };
}

describe('ashaveri verify', () => {
  it('verifies the SEV-SNP fixture and prints a human-readable summary', () => {
    const result = runCli(VERIFY_ARGS);
    expect(result.status).toBe(0);
    expect(result.stderr).toBe('');
    expect(result.stdout).toContain('SEV-SNP attestation verified (envelope v0)');
    expect(result.stdout).toContain('quote signature:  verified (AMD ARK -> ASK -> VCEK chain, ECDSA P-384)');
    expect(result.stdout).toContain('product:          Milan');
    expect(result.stdout).toContain(`report data:      ${FIXTURE_REPORT_DATA}`);
    expect(result.stdout).toContain('runtime events:   9 (v1)');
    expect(result.stdout).toMatch(/config: +\d+ bytes, sha256 [0-9a-f]{64}/);
  });

  it('prints machine-readable JSON with --json', () => {
    const result = runCli([...VERIFY_ARGS, '--json']);
    expect(result.status).toBe(0);
    const parsed = JSON.parse(result.stdout) as {
      ok: boolean;
      platform: string;
      envelopeVersion: number;
      quoteSignatureVerified: boolean;
      reportData: string;
      runtimeEvents: { event: string; payload: string; version: number }[];
      config: { sha256: string; bytes: number };
      snp: { product: string; mrConfig: { keyProvider: string; composeHash: string } };
    };
    expect(parsed.ok).toBe(true);
    expect(parsed.platform).toBe('sev-snp');
    expect(parsed.envelopeVersion).toBe(0);
    expect(parsed.quoteSignatureVerified).toBe(true);
    expect(parsed.reportData.startsWith(FIXTURE_REPORT_DATA)).toBe(true);
    expect(parsed.runtimeEvents).toHaveLength(9);
    expect(parsed.snp.product).toBe('Milan');
    expect(parsed.snp.mrConfig.keyProvider).toBe('kms');
    expect(parsed.snp.mrConfig.composeHash).toMatch(/^[0-9a-f]{64}$/);
    expect(parsed.config.bytes).toBeGreaterThan(0);
    expect(parsed.config.sha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it('accepts a shorter --report-data value as a prefix binding', () => {
    const result = runCli([...VERIFY_ARGS, '--report-data', FIXTURE_REPORT_DATA]);
    expect(result.status).toBe(0);
  });

  it('accepts a full 64-byte --report-data value as an exact binding', () => {
    const full = FIXTURE_REPORT_DATA + '00'.repeat(40);
    const result = runCli([...VERIFY_ARGS, '--report-data', full]);
    expect(result.status).toBe(0);
  });

  it('rejects a wrong --report-data value with exit code 1', () => {
    const result = runCli([...VERIFY_ARGS, '--report-data', 'deadbeef']);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('verification failed (REPORT_DATA_MISMATCH)');
  });

  it('reports JSON failure output with --json', () => {
    const result = runCli([...VERIFY_ARGS, '--report-data', 'deadbeef', '--json']);
    expect(result.status).toBe(1);
    const parsed = JSON.parse(result.stdout) as { ok: boolean; code: string; message: string };
    expect(parsed.ok).toBe(false);
    expect(parsed.code).toBe('REPORT_DATA_MISMATCH');
    expect(parsed.message).toContain('report data');
  });

  it('accepts a measurement pin that matches the launch digest', () => {
    const result = runCli([...VERIFY_ARGS, '--expect-measurement', FIXTURE_MEASUREMENT]);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('pinned:           measurement matches the expected value');
  });

  it('accepts measurement and compose hash pins together', () => {
    const result = runCli([
      ...VERIFY_ARGS,
      '--expect-measurement',
      FIXTURE_MEASUREMENT,
      '--expect-compose-hash',
      FIXTURE_COMPOSE_HASH,
    ]);
    expect(result.status).toBe(0);
    expect(result.stdout.match(/pinned:/g)).toHaveLength(2);
  });

  it('rejects a measurement pin from a different build', () => {
    const result = runCli([...VERIFY_ARGS, '--expect-measurement', `8${FIXTURE_MEASUREMENT.slice(1)}`]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('verification failed (PIN_MISMATCH)');
    expect(result.stderr).toContain(`measurement is ${FIXTURE_MEASUREMENT}`);
    expect(result.stderr).toContain('--expect-measurement pins 8');
  });

  it('rejects a compose hash pin that does not match the deployment', () => {
    const result = runCli([...VERIFY_ARGS, '--expect-compose-hash', 'ab'.repeat(32)]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('verification failed (PIN_MISMATCH)');
    expect(result.stderr).toContain('compose hash is');
  });

  it('reports a pin failure as JSON', () => {
    const result = runCli([...VERIFY_ARGS, '--expect-compose-hash', 'ab'.repeat(32), '--json']);
    expect(result.status).toBe(1);
    const parsed = JSON.parse(result.stdout) as { ok: boolean; code: string; message: string };
    expect(parsed.ok).toBe(false);
    expect(parsed.code).toBe('PIN_MISMATCH');
    expect(parsed.message).toContain('compose hash');
  });

  it('verifies before comparing pins, so an untrusted chain fails first', () => {
    const result = runCli([
      'verify',
      ATTESTATION,
      '--ask',
      ASK,
      '--vcek',
      VCEK,
      '--now',
      NOW,
      '--expect-measurement',
      FIXTURE_MEASUREMENT,
    ]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('MISSING_TRUST_ROOT');
  });

  it('exits 2 for a measurement pin of the wrong width', () => {
    const result = runCli([...VERIFY_ARGS, '--expect-measurement', FIXTURE_COMPOSE_HASH]);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('--expect-measurement must be 96 hex digits');
  });

  it('exits 2 for a non-hex compose hash pin', () => {
    const result = runCli([...VERIFY_ARGS, '--expect-compose-hash', 'zz'.repeat(32)]);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('--expect-compose-hash must be 64 hex digits');
  });

  it('rejects a tampered report signature with exit code 1', () => {
    const bytes = new Uint8Array(readFileSync(ATTESTATION));
    bytes[4 + 0x2a0] ^= 0x01;
    const tampered = join(tempDir, 'tampered.bin');
    writeFileSync(tampered, bytes);
    const result = runCli(['verify', tampered, '--ark', ARK, '--ask', ASK, '--vcek', VCEK, '--now', NOW]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('verification failed (BAD_SIGNATURE)');
  });

  it('reads the attestation from stdin with -', () => {
    const result = runCli(['verify', '-', '--ark', ARK, '--ask', ASK, '--vcek', VCEK, '--now', NOW], readFileSync(ATTESTATION));
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('SEV-SNP attestation verified');
  });

  it('fails verification without a trusted ARK', () => {
    const result = runCli(['verify', ATTESTATION, '--ask', ASK, '--vcek', VCEK, '--now', NOW]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('MISSING_TRUST_ROOT');
  });

  it('fails verification after certificate expiry', () => {
    const expired = VERIFY_ARGS.map((arg) => (arg === NOW ? '2035-01-01T00:00:00Z' : arg));
    const result = runCli(expired);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('CERT_EXPIRED');
  });

  it('exits 2 for a missing attestation file', () => {
    const result = runCli(['verify', join(tempDir, 'missing.bin'), '--ark', ARK, '--now', NOW]);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('cannot read attestation');
  });

  it('exits 2 for a missing certificate file', () => {
    const result = runCli(['verify', ATTESTATION, '--ark', join(tempDir, 'missing-ark.pem'), '--now', NOW]);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('--ark');
  });

  it('exits 2 for a missing Intel root certificate file', () => {
    const result = runCli(['verify', ATTESTATION, '--intel-root', join(tempDir, 'missing-intel.pem'), '--now', NOW]);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('--intel-root');
  });

  it('leaves SEV-SNP verification untouched by a pinned Intel root', () => {
    const result = runCli([...VERIFY_ARGS, '--intel-root', INTEL_ROOT]);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('SEV-SNP attestation verified');
  });

  it('exits 2 for an invalid --report-data hex string', () => {
    const result = runCli([...VERIFY_ARGS, '--report-data', 'xyz']);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('--report-data must be a hex string');
  });

  it('exits 2 for an over-long --report-data value', () => {
    const result = runCli([...VERIFY_ARGS, '--report-data', 'ab'.repeat(65)]);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('at most 64 bytes');
  });

  it('exits 2 with no arguments', () => {
    const result = runCli([]);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain("expected exactly one command: 'verify <attestation>'");
  });

  it('exits 2 for an unknown option', () => {
    const result = runCli([...VERIFY_ARGS, '--turbo']);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain("Try 'ashaveri --help'");
  });

  it('prints help with --help', () => {
    const result = runCli(['--help']);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('Usage:');
    expect(result.stdout).toContain('--report-data');
    expect(result.stdout).toContain('--expect-measurement');
    expect(result.stdout).toContain('--expect-compose-hash');
    expect(result.stdout).toContain('--intel-root');
  });

  it('prints the version with --version', () => {
    const result = runCli(['--version']);
    expect(result.status).toBe(0);
    expect(result.stdout.trim()).toMatch(/^\d+\.\d+\.\d+$/);
  });
});
