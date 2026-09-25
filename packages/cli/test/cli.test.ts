import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import { parsePolicyFile, policyFileDigest } from '@ashaveri/sdk';

const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
const FIXTURES = fileURLToPath(new URL('../../attest-core/test/fixtures/', import.meta.url));
const ATTESTATION = `${FIXTURES}sev-snp-attestation.bin`;
const ARK = `${FIXTURES}amd-ark-milan.pem`;
const ASK = `${FIXTURES}sev-snp-ask.pem`;
const VCEK = `${FIXTURES}sev-snp-vcek.pem`;
const INTEL_ROOT = `${FIXTURES}intel-sgx-root-ca.pem`;
const GPU_REPORT = `${FIXTURES}nvidia-hopper-report.bin`;
const GPU_CHAIN = `${FIXTURES}nvidia-hopper-cert-chain.pem`;
const GPU_ROOT = `${FIXTURES}nvidia-device-identity-ca.pem`;
const NOW = '2026-09-10T00:00:00Z';
const FIXTURE_REPORT_DATA = '6174746573742d746573742d666978747572652d32303236';
/** The challenge the Hopper sample signed, taken from inside its signed region. */
const FIXTURE_GPU_CHALLENGE = '08f2fd1f8bb769d087f6b0de1b389594e6cd2415c2f92cf4894fd617d8ddd7e6';
const FIXTURE_MEASUREMENT =
  '7f51e17f72a04d5422cb2c00998166536019a217376f3aa45a630e59c805a599847ff250dbffcd07e1ba639771d6f05d';
const FIXTURE_COMPOSE_HASH = '86e59625be93207bc2351c4d1bba20037cec8e168da6b18f559af5af657b7a23';

const VERIFY_ARGS = ['verify', ATTESTATION, '--ark', ARK, '--ask', ASK, '--vcek', VCEK, '--now', NOW];

/** The Hopper sample and the root its chain reaches, as the operator would pass them. */
const GPU_ARGS = ['--gpu-report', GPU_REPORT, '--gpu-chain', GPU_CHAIN, '--gpu-root', GPU_ROOT];

const tempDir = mkdtempSync(join(tmpdir(), 'ashaveri-cli-'));

afterAll(() => {
  rmSync(tempDir, { recursive: true, force: true });
});

interface CliResult {
  readonly status: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

/**
 * A V1 envelope the reader accepts as version 1 and then trips over: one unknown key whose value is
 * msgpack's unused 0xc1 marker. The reader puts the key it was skipping into the error it raises,
 * which is how the caller's own string gets into this command's sentence about it.
 */
function msgpackWithUnknownKey(key: string): Uint8Array {
  const encoded = new TextEncoder().encode(key);
  if (encoded.length > 31) {
    throw new Error('the fixture is built on msgpack fixstr headers, which cap a key at 31 bytes');
  }
  const version = new TextEncoder().encode('version');
  return new Uint8Array([0x82, 0xa0 | version.length, ...version, 0x01, 0xa0 | encoded.length, ...encoded, 0xc1]);
}

/** Lines as a reader that splits text on any terminator counts them, which is four characters, not one. */
function countLines(text: string): number {
  return text.split(/[\n\r\u2028\u2029]/u).filter((each) => each.length > 0).length;
}

function runCli(args: string[], input?: Uint8Array): CliResult {
  const result = spawnSync(process.execPath, [CLI, ...args], {
    input: input === undefined ? undefined : Buffer.from(input),
    encoding: 'utf8',
    timeout: 8000,
    killSignal: 'SIGKILL',
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

  it('accepts a shorter --report-data value the platform zero-padded', () => {
    const result = runCli([...VERIFY_ARGS, '--report-data', FIXTURE_REPORT_DATA]);
    expect(result.status).toBe(0);
  });

  it('rejects a --report-data value that is only the start of the field', () => {
    // 'attest' sits at the head of the quoted field but the bytes after it are
    // the rest of the fixture's own value, not padding, so this proves nothing
    // was bound. Any quote could be given this prefix.
    const result = runCli([...VERIFY_ARGS, '--report-data', '617474657374']);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('verification failed (REPORT_DATA_MISMATCH)');
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

  it('verifies a GPU report supplied beside the platform document', () => {
    const result = runCli([...VERIFY_ARGS, ...GPU_ARGS]);
    expect(result.status).toBe(0);
    expect(result.stderr).toBe('');
    expect(result.stdout).toContain('gpu:              1 device report verified');
    expect(result.stdout).toContain(`gpu challenge:    ${FIXTURE_GPU_CHALLENGE}`);
  });

  it('lists each verified device report in JSON output', () => {
    const result = runCli([...VERIFY_ARGS, ...GPU_ARGS, '--json']);
    expect(result.status).toBe(0);
    const parsed = JSON.parse(result.stdout) as { gpu: { signatureVerified: boolean; challenge: string }[] };
    expect(parsed.gpu).toEqual([{ signatureVerified: true, challenge: FIXTURE_GPU_CHALLENGE }]);
  });

  it('exits 2 when GPU reports and chains are given unequally many times', () => {
    const result = runCli([...VERIFY_ARGS, '--gpu-report', GPU_REPORT, '--gpu-root', GPU_ROOT]);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('--gpu-report and --gpu-chain must be given the same number of times (got 1 and 0)');
  });

  it('refuses a GPU report with no pinned root', () => {
    const result = runCli([...VERIFY_ARGS, '--gpu-report', GPU_REPORT, '--gpu-chain', GPU_CHAIN]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('at least one pinned NVIDIA root');
  });

  it('refuses a GPU chain that does not reach the pinned --gpu-root', () => {
    const result = runCli([...VERIFY_ARGS, '--gpu-report', GPU_REPORT, '--gpu-chain', GPU_CHAIN, '--gpu-root', ARK]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('does not lead to any pinned NVIDIA root');
  });

  it('refuses a GPU report that did not sign the pinned --report-data value', () => {
    // The fixture's report data is an ASCII label and the device signed a 32-byte
    // challenge, so the two halves describe different moments. A pin that only the
    // platform answers would let an unrelated GPU report ride along.
    const result = runCli([...VERIFY_ARGS, ...GPU_ARGS, '--report-data', FIXTURE_REPORT_DATA]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('verification failed (CHALLENGE_MISMATCH)');
    expect(result.stderr).toContain(`GPU signed challenge ${FIXTURE_GPU_CHALLENGE}`);
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
    bytes[4 + 0x2a0] = (bytes[4 + 0x2a0] as number) ^ 0x01;
    const tampered = join(tempDir, 'tampered.bin');
    writeFileSync(tampered, bytes);
    const result = runCli(['verify', tampered, '--ark', ARK, '--ask', ASK, '--vcek', VCEK, '--now', NOW]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('verification failed (BAD_SIGNATURE)');
  });

  it('keeps a string from the document out of the line it refuses on', () => {
    // `verify` is the one command whose input is written by a stranger, and it writes its report
    // straight to a stream instead of through the guard the other commands pass. The reader names the
    // field it was skipping inside its error, so a document can put any text it likes into the
    // sentence this program prints about it. The line separators are the case worth pinning: a
    // newline in a JSON string is escaped by the serializer, and these two are not.
    const hostile: Array<[string, string, string]> = [
      ['line separator', 'attestation\u2028FORGED key', '\\u2028FORGED'],
      ['paragraph separator', 'attestation\u2029FORGED key', '\\u2029FORGED'],
      ['reordering mark', 'attestation\u202eFORGED key', '\\u202eFORGED'],
      ['newline', 'attestation\nFORGED key', '\\u000aFORGED'],
    ];
    for (const [name, key, escape] of hostile) {
      const file = join(tempDir, `hostile-${name.replace(/ /gu, '-')}.bin`);
      writeFileSync(file, msgpackWithUnknownKey(key));

      const human = runCli(['verify', file, '--now', NOW]);
      expect(human.status, name).toBe(1);
      expect(human.stderr, name).toContain(escape);
      expect(human.stderr, name).not.toMatch(/^FORGED/mu);
      expect(countLines(human.stderr), name).toBe(1);

      const machine = runCli(['verify', file, '--now', NOW, '--json']);
      expect(machine.status, name).toBe(1);
      expect(machine.stdout, name).not.toMatch(/^FORGED/mu);
      const parsed = JSON.parse(machine.stdout) as { ok: boolean; code: string; message: string };
      expect(parsed.ok).toBe(false);
      // The refusal document is three fields and all three are read here: `ok` says the check
      // failed, `code` is the machine contract a client branches on, and `message` is the prose
      // about the document. The prose is escaped by the package that raised it, and the two
      // assertions below are what show it, one for each way that can go wrong: the escaped spelling
      // is there, and no backslash has been escaped on top of it, so nothing ran a second pass over
      // text that was already safe. The gateway quotes these messages in an error reply of its own
      // with no guard of its own, which is why the escape belongs where the message is made and not
      // only in front of this terminal.
      expect(parsed.message, name).toContain(escape);
      expect(parsed.message, name).not.toContain('\\' + escape);
      expect(parsed.code, name).toBe('MALFORMED_ATTESTATION');
      expect(countLines(machine.stdout), name).toBe(5);
    }
  });

  it('escapes an event name in a report that verified', () => {
    // The event log an envelope carries is not what the report's signature covers, and an event name
    // this program has never heard of verifies and prints, so the success report needs the guard the
    // refusal gets. The stand-in name is the same number of bytes as the one it replaces, which keeps
    // the string's length prefix true: six characters and the two separators are a twelve-byte name.
    const bytes = Buffer.from(readFileSync(ATTESTATION));
    const needle = Buffer.from('boot-mr-done', 'utf8');
    const at = bytes.indexOf(needle);
    expect(at).toBeGreaterThanOrEqual(0);
    bytes.set(Buffer.from('FORGED\u2028\u2029', 'utf8'), at);
    const file = join(tempDir, 'event-name.bin');
    writeFileSync(file, bytes);
    const args = ['verify', file, '--ark', ARK, '--ask', ASK, '--vcek', VCEK, '--now', NOW];

    const human = runCli(args);
    expect(human.status).toBe(0);
    // The printed table names the event count and the log's encoding version and never a name, so the
    // forged bytes cannot reach it. Asserting the absence rather than a line count, because a count
    // holds however a name is printed: this is the case that has to be rewritten, and the report
    // guarded, the day a human line carries an event name.
    expect(human.stdout).not.toContain('FORGED');
    expect(human.stdout).toContain('runtime events:');

    const machine = runCli([...args, '--json']);
    expect(machine.status).toBe(0);
    expect(machine.stdout).toContain('FORGED');
    expect(machine.stdout).not.toMatch(/^FORGED/mu);
    expect(countLines(machine.stdout)).toBe(machine.stdout.split('\n').filter((each) => each.length > 0).length);
    const parsed = JSON.parse(machine.stdout) as { runtimeEvents: Array<{ event: string }> };
    expect(parsed.runtimeEvents.map((each) => each.event)).toContain('FORGED\u2028\u2029');
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

  it('exits 2, naming the argument, when verify is given the wrong number of them', () => {
    const none = runCli(['verify', '--ark', ARK, '--now', NOW]);
    expect(none.status).toBe(2);
    expect(none.stderr).toContain("expected exactly one argument: 'verify <attestation>'");
    const two = runCli(['verify', ATTESTATION, ATTESTATION, '--ark', ARK, '--now', NOW]);
    expect(two.status).toBe(2);
    expect(two.stderr).toContain("expected exactly one argument: 'verify <attestation>'");
  });

  it('exits 2, naming the command list, for no command and for one that does not exist', () => {
    const none = runCli([]);
    expect(none.status).toBe(2);
    expect(none.stderr).toContain('expected a command: verify, verify-receipt, verify-handover, keygen, credential, accesslog');
    const unknown = runCli(['frobnicate', 'anything']);
    expect(unknown.status).toBe(2);
    expect(unknown.stderr).toContain(
      "unknown command 'frobnicate': expected one of verify, verify-receipt, verify-handover, keygen, credential, accesslog",
    );
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
    expect(result.stdout).toContain("--public-key=<value>");
  });

  it('prints the version with --version', () => {
    const result = runCli(['--version']);
    expect(result.status).toBe(0);
    expect(result.stdout.trim()).toMatch(/^\d+\.\d+\.\d+$/);
  });
});

/**
 * `verify --policy <file>`, the same pins the flags above take read out of a document instead.
 *
 * A policy file names its trust anchor by a path relative to itself, so every case here copies the
 * ARK fixture beside the document it writes, which is the shape a deployment publishes: a directory
 * with a policy in it and the roots it pins next to that policy.
 */

const POLICY_DIR = join(tempDir, 'policy');
mkdirSync(POLICY_DIR, { recursive: true });
mkdirSync(join(POLICY_DIR, 'roots'), { recursive: true });
copyFileSync(ARK, join(POLICY_DIR, 'ark.pem'));
copyFileSync(ARK, join(POLICY_DIR, 'roots', 'ark.pem'));
const ARK_SHA = createHash('sha256').update(readFileSync(ARK)).digest('hex');

/** Writes one policy document and answers with the path to hand to --policy. */
function policyFile(name: string, document: Record<string, unknown>): string {
  const path = join(POLICY_DIR, `${name}.json`);
  writeFileSync(path, `${JSON.stringify(document, null, 2)}\n`);
  return path;
}

function pins(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    v: 1,
    issuers: ['ashaveri-mock'],
    instances: ['mock-instance-1'],
    measurements: { snp: [FIXTURE_MEASUREMENT] },
    trustAnchors: { amdArks: [{ path: 'ark.pem', sha256: ARK_SHA }] },
    ...overrides,
  };
}

/**
 * A verification whose pins come out of a document.
 *
 * `--ask` and `--vcek` stay on the command line here because the SEV-SNP fixture carries an empty
 * `cert_chain`, and a policy document pins roots and not the intermediates below them: the ASK and
 * VCEK are the bytes a chain is built out of rather than a claim about what is acceptable, which is
 * the line `--policy` draws.
 */
const POLICY_ARGS = ['verify', ATTESTATION, '--ask', ASK, '--vcek', VCEK, '--now', NOW];
const DIGEST_LINE = /policy: +(sha256:[0-9a-f]{64})/u;

describe('ashaveri verify --policy', () => {
  it('takes the vendor root and the measurement pin from the document', () => {
    const result = runCli([...POLICY_ARGS, '--policy', policyFile('pins-everything', pins())]);
    expect(result.stderr).toBe('');
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('SEV-SNP attestation verified');
    expect(result.stdout).toContain('pinned:           measurement matches the policy file');
  });

  it('prints the digest the library publishes for the same document', () => {
    const path = policyFile('digest', pins());
    const printed = runCli([...POLICY_ARGS, '--policy', path]);
    expect(printed.status).toBe(0);
    const digest = DIGEST_LINE.exec(printed.stdout)?.[1];
    expect(digest).toBeDefined();
    expect(digest).toBe(policyFileDigest(parsePolicyFile(readFileSync(path, 'utf8'))));

    const machine = runCli([...POLICY_ARGS, '--policy', path, '--json']);
    const parsed = JSON.parse(machine.stdout) as { policy: { digest: string; file: string } };
    expect(parsed.policy.digest).toBe(digest);
    expect(parsed.policy.file).toBe(path);
  });

  it('holds the digest steady across a reformat of the same policy', () => {
    const tidy = policyFile('reformat-tidy', pins());
    const messy = join(POLICY_DIR, 'reformat-messy.json');
    const document = JSON.parse(readFileSync(tidy, 'utf8')) as Record<string, unknown>;
    const reordered = {
      trustAnchors: document['trustAnchors'],
      measurements: document['measurements'],
      instances: document['instances'],
      issuers: document['issuers'],
      v: document['v'],
    };
    writeFileSync(messy, `${JSON.stringify(reordered, null, 7).replace(/\n/gu, '\r\n')}\r\n`);
    const first = runCli([...POLICY_ARGS, '--policy', tidy]);
    const second = runCli([...POLICY_ARGS, '--policy', messy]);
    expect(first.status).toBe(0);
    expect(second.status).toBe(0);
    expect(readFileSync(messy)).not.toEqual(readFileSync(tidy));
    expect(DIGEST_LINE.exec(second.stdout)?.[1]).toBe(DIGEST_LINE.exec(first.stdout)?.[1]);
  });

  it('moves the digest when the pinned measurement moves', () => {
    const pinned = runCli([...POLICY_ARGS, '--policy', policyFile('pinned', pins())]);
    // The set this document pins moves by one value the evidence does not carry, which is a
    // different policy by digest and still a policy this attestation satisfies. A document whose
    // only measurement is another build's is a refusal and prints no report, which the case below
    // is about.
    const other = runCli([
      ...POLICY_ARGS,
      '--policy',
      policyFile('other', pins({ measurements: { snp: [FIXTURE_MEASUREMENT, `8${FIXTURE_MEASUREMENT.slice(1)}`] } })),
    ]);
    expect(DIGEST_LINE.exec(other.stdout)?.[1]).toBeDefined();
    expect(DIGEST_LINE.exec(other.stdout)?.[1]).not.toBe(DIGEST_LINE.exec(pinned.stdout)?.[1]);
  });

  it('reads a backslash in an anchor path as the separator it names', () => {
    const path = policyFile(
      'backslash',
      pins({ trustAnchors: { amdArks: [{ path: 'roots\\ark.pem', sha256: ARK_SHA }] } }),
    );
    const result = runCli([...POLICY_ARGS, '--policy', path]);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('SEV-SNP attestation verified');
  });

  it('accepts the bundled root when the document pins none, which is what leaving it out means', () => {
    const path = policyFile('no-anchors', {
      v: 1,
      issuers: ['ashaveri-mock'],
      measurements: { snp: [FIXTURE_MEASUREMENT] },
    });
    const result = runCli([...POLICY_ARGS, '--policy', path]);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('SEV-SNP attestation verified');
  });

  it('trusts nothing at all when a family is pinned to an empty list', () => {
    const result = runCli([...POLICY_ARGS, '--policy', policyFile('trust-nothing', pins({ trustAnchors: { amdArks: [] } }))]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('MISSING_TRUST_ROOT');
  });

  it('refuses a measurement pinned for a platform this attestation is not', () => {
    const result = runCli([
      ...POLICY_ARGS,
      '--policy',
      policyFile('tdx-only', pins({ measurements: { tdx: [FIXTURE_MEASUREMENT] } })),
    ]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('verification failed (PIN_MISMATCH)');
    expect(result.stderr).toContain("'tdx'");
    expect(result.stderr).toContain("'snp'");
  });

  it('refuses a pinned measurement the evidence does not carry', () => {
    const result = runCli([
      ...POLICY_ARGS,
      '--policy',
      policyFile('wrong-measurement', pins({ measurements: { snp: [`8${FIXTURE_MEASUREMENT.slice(1)}`] } })),
    ]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('verification failed (PIN_MISMATCH)');
    expect(result.stderr).toContain('measurement is');
  });

  it('refuses an anchor whose bytes are not what the document recorded, naming the path', () => {
    const path = policyFile('bad-anchor', pins({ trustAnchors: { amdArks: [{ path: 'ark.pem', sha256: 'ab'.repeat(32) }] } }));
    const result = runCli([...POLICY_ARGS, '--policy', path]);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('POLICY_ANCHOR_DIGEST_MISMATCH');
    expect(result.stderr).toContain('ark.pem');
  });

  it('refuses a document with a key the format does not define', () => {
    const result = runCli([...POLICY_ARGS, '--policy', policyFile('unknown-key', { ...pins(), issuer: 'ashaveri-mock' })]);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('POLICY_FILE_INVALID');
    expect(result.stderr).toContain("unknown key 'issuer'");
  });

  it('refuses a document that pins nothing', () => {
    const result = runCli([...POLICY_ARGS, '--policy', policyFile('empty', { v: 1 })]);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('POLICY_NOTHING_PINNED');
  });

  it('refuses a policy file that is not there', () => {
    const result = runCli([...POLICY_ARGS, '--policy', join(POLICY_DIR, 'absent.json')]);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('POLICY_FILE_UNREADABLE');
  });

  it('refuses to mix --policy with a pin flag, and names the flags involved', () => {
    const path = policyFile('mixed', pins());
    const clashes: Array<[string, string[]]> = [
      ['--ark', ['--ark', ARK]],
      ['--intel-root', ['--intel-root', INTEL_ROOT]],
      ['--gpu-root', ['--gpu-root', GPU_ROOT]],
      ['--expect-measurement', ['--expect-measurement', FIXTURE_MEASUREMENT]],
      ['--expect-compose-hash', ['--expect-compose-hash', FIXTURE_COMPOSE_HASH]],
    ];
    for (const [flag, args] of clashes) {
      const result = runCli([...POLICY_ARGS, '--policy', path, ...args]);
      expect(result.status, flag).toBe(2);
      expect(result.stderr, flag).toContain('--policy');
      expect(result.stderr, flag).toContain(flag);
    }
  });

  it('leaves the flags that carry bytes rather than pins alone', () => {
    // --ask and --vcek supply the chain under a pinned root, --gpu-report the device leg, and
    // --report-data this request's challenge. None of them is a dimension a policy could pin.
    const result = runCli([
      ...POLICY_ARGS,
      '--policy',
      policyFile('alongside', pins()),
      '--ask',
      ASK,
      '--vcek',
      VCEK,
      '--report-data',
      FIXTURE_REPORT_DATA,
    ]);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('SEV-SNP attestation verified');
  });

  it('mentions --policy in the help text', () => {
    expect(runCli(['--help']).stdout).toContain('--policy');
  });
});
