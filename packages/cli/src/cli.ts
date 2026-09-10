#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { sha256 } from '@noble/hashes/sha2.js';
import { AttestationError, equalBytes, pinnedComposeHash, platformMeasurement, verifyAttestation } from '@ashaveri/attest-core';
import type { VerificationResult } from '@ashaveri/attest-core';

const REPORT_DATA_BYTES = 64;
const PLATFORM_MEASUREMENT_BYTES = 48;
const COMPOSE_HASH_BYTES = 32;

const USAGE = `ashaveri - offline verification of dStack confidential-VM attestations

Usage:
  ashaveri verify <attestation> [options]

Arguments:
  <attestation>      Path to a dStack VersionedAttestation file, or - for stdin.

Options:
  --ark <file>       Trusted AMD root certificate (ARK), PEM or DER. Repeatable;
                     the attestation must chain to one of them.
  --ask <file>       ASK certificate, for attestations that carry no cert chain.
  --vcek <file>      VCEK certificate, for attestations that carry no cert chain.
  --report-data <hex>
                     Expected REPORT_DATA binding. A 64-byte value must match
                     exactly; a shorter value must be a prefix of the report data.
  --expect-measurement <hex>
                     Pin the 96-hex platform launch measurement: the SEV-SNP
                     launch digest or the TDX MRTD, depending on the platform.
  --expect-compose-hash <hex>
                     Pin the 64-hex dstack compose hash the deployment was
                     started with, so a rebuilt image is rejected.
  --now <iso>        Verification time (ISO 8601). Defaults to the current time.
  --allow-debug      Accept SEV-SNP guest policies that permit debugging.
  --json             Print a machine-readable JSON result.
  --version          Print the CLI version.
  --help             Print this help.

Exit codes:
  0  attestation verified, and every --expect-* pin matched
  1  verification or a pin failed
  2  usage or input error`;

class UsageError extends Error {}

function toHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) {
    out += b.toString(16).padStart(2, '0');
  }
  return out;
}

function cliVersion(): string {
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { version?: string };
  return pkg.version ?? 'unknown';
}

async function readInput(path: string): Promise<Uint8Array> {
  if (path === '-') {
    const chunks: Buffer[] = [];
    for await (const chunk of process.stdin) {
      chunks.push(chunk as Buffer);
    }
    return Buffer.concat(chunks);
  }
  try {
    return await readFile(path);
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    throw new UsageError(`cannot read attestation '${path}': ${reason}`);
  }
}

async function readCert(path: string, flag: string): Promise<Uint8Array> {
  try {
    return await readFile(path);
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    throw new UsageError(`cannot read ${flag} file '${path}': ${reason}`);
  }
}

function parseReportData(value: string): Uint8Array {
  if (!/^[0-9a-fA-F]+$/.test(value) || value.length % 2 !== 0) {
    throw new UsageError('--report-data must be a hex string of whole bytes');
  }
  if (value.length > REPORT_DATA_BYTES * 2) {
    throw new UsageError(`--report-data must be at most ${REPORT_DATA_BYTES} bytes`);
  }
  const out = new Uint8Array(value.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function checkReportDataBinding(expected: Uint8Array, actual: Uint8Array): void {
  if (expected.length > actual.length || !equalBytes(expected, actual.slice(0, expected.length))) {
    throw new AttestationError(
      'REPORT_DATA_MISMATCH',
      `report data does not match the --report-data value (${toHex(expected)})`,
    );
  }
}

function parseDigestFlag(value: string, flag: string, bytes: number): Uint8Array {
  if (!/^[0-9a-fA-F]+$/.test(value) || value.length !== bytes * 2) {
    throw new UsageError(`${flag} must be ${bytes * 2} hex digits`);
  }
  return Uint8Array.from({ length: bytes }, (_, i) => Number.parseInt(value.slice(i * 2, i * 2 + 2), 16));
}

function checkPin(label: string, flag: string, expected: Uint8Array, actual: Uint8Array | null): void {
  if (actual === null) {
    throw new AttestationError('PIN_MISMATCH', `the evidence carries no ${label} to compare with ${flag}`);
  }
  if (!equalBytes(expected, actual)) {
    throw new AttestationError('PIN_MISMATCH', `${label} is ${toHex(actual)}, ${flag} pins ${toHex(expected)}`);
  }
}

function configSummary(config: string): { sha256: string; bytes: number } {
  const encoded = new TextEncoder().encode(config);
  return { sha256: toHex(sha256(encoded)), bytes: encoded.length };
}

function describeEvents(events: readonly { version: number }[]): string {
  const versions = new Set(events.map((event) => event.version));
  const encoding = versions.size === 1 ? `v${events[0]?.version ?? 0}` : 'mixed';
  return `${events.length} (${encoding})`;
}

function humanResult(result: VerificationResult, pinned: readonly string[] = []): string {
  const lines: string[] = [];
  const platform = result.platformKind === 'sev-snp' ? 'SEV-SNP' : 'TDX';
  lines.push(`${platform} attestation verified (envelope v${result.version})`);
  if (result.snp) {
    lines.push('  quote signature:  verified (AMD ARK -> ASK -> VCEK chain, ECDSA P-384)');
    const { report, mrConfig } = result.snp;
    if (report.productLine) {
      lines.push(`  product:          ${report.productLine}`);
    }
    lines.push(
      `  tcb:              boot loader ${report.currentTcb.blSPL}, SNP firmware ${report.currentTcb.snpSPL}, microcode ${report.currentTcb.ucodeSPL}`,
    );
    lines.push(`  chip id:          ${toHex(report.chipId)}`);
    lines.push(`  measurement:      ${toHex(report.measurement)}`);
    lines.push(`  host data:        ${toHex(report.hostData)}`);
    const mrConfigParts = [
      mrConfig.appId ? `app id ${toHex(mrConfig.appId)}` : null,
      `compose hash ${toHex(mrConfig.composeHash)}`,
      mrConfig.keyProvider ? `key provider ${mrConfig.keyProvider}` : null,
    ].filter((part): part is string => part !== null);
    lines.push(`  mr config:        ${mrConfigParts.join(', ')}`);
  } else {
    lines.push('  quote signature:  not verified (Intel DCAP quote verification is out of scope)');
    if (result.tdx) {
      lines.push(`  mr td:            ${toHex(result.tdx.quote.mrTd)}`);
      lines.push(`  rtmr3:            ${toHex(result.tdx.quote.rtmr[3] ?? new Uint8Array(0))}`);
      lines.push(
        result.tdx.mrConfig
          ? `  mr config:        digest ${toHex(result.tdx.mrConfig.digest)} (tag ${result.tdx.mrConfig.tag})`
          : '  mr config:        none (MR_CONFIG_ID empty, no app configuration pinned)',
      );
    }
  }
  lines.push(`  report data:      ${toHex(result.reportData)}`);
  for (const label of pinned) {
    lines.push(`  pinned:           ${label} matches the expected value`);
  }
  lines.push(`  runtime events:   ${describeEvents(result.runtimeEvents)}`);
  const config = configSummary(result.config);
  lines.push(`  config:           ${config.bytes} bytes, sha256 ${config.sha256}`);
  return lines.join('\n');
}

function jsonResult(result: VerificationResult): string {
  const config = configSummary(result.config);
  const out: Record<string, unknown> = {
    ok: true,
    platform: result.platformKind,
    envelopeVersion: result.version,
    quoteSignatureVerified: result.quoteSignatureVerified,
    reportData: toHex(result.reportData),
    runtimeEvents: result.runtimeEvents.map((event) => ({
      event: event.event,
      payload: toHex(event.payload),
      version: event.version,
    })),
    config,
  };
  if (result.snp) {
    const { report, mrConfig } = result.snp;
    out.snp = {
      product: report.productLine,
      tcb: {
        bootLoader: report.currentTcb.blSPL,
        tee: report.currentTcb.teeSPL,
        microcode: report.currentTcb.ucodeSPL,
      },
      chipId: toHex(report.chipId),
      measurement: toHex(report.measurement),
      hostData: toHex(report.hostData),
      mrConfig: {
        version: mrConfig.version,
        appId: mrConfig.appId ? toHex(mrConfig.appId) : null,
        composeHash: toHex(mrConfig.composeHash),
        gpuPolicyHash: mrConfig.gpuPolicyHash ? toHex(mrConfig.gpuPolicyHash) : null,
        keyProvider: mrConfig.keyProvider,
        instanceId: mrConfig.instanceId ? toHex(mrConfig.instanceId) : null,
        initScriptHashes: mrConfig.initScriptHashes?.map((value) => toHex(value)) ?? null,
      },
    };
  }
  if (result.tdx) {
    out.tdx = {
      mrTd: toHex(result.tdx.quote.mrTd),
      rtmr: result.tdx.quote.rtmr.map((value) => toHex(value)),
      mrConfig: result.tdx.mrConfig
        ? { tag: result.tdx.mrConfig.tag, digest: toHex(result.tdx.mrConfig.digest) }
        : null,
    };
  }
  return JSON.stringify(out, null, 2);
}

async function main(argv: string[]): Promise<number> {
  let flags;
  try {
    flags = parseArgs({
      allowPositionals: true,
      args: argv,
      options: {
        ark: { type: 'string', multiple: true },
        ask: { type: 'string' },
        vcek: { type: 'string' },
        'report-data': { type: 'string' },
        'expect-measurement': { type: 'string' },
        'expect-compose-hash': { type: 'string' },
        now: { type: 'string' },
        'allow-debug': { type: 'boolean' },
        json: { type: 'boolean' },
        help: { type: 'boolean' },
        version: { type: 'boolean' },
      },
    });
  } catch (err) {
    throw new UsageError(err instanceof Error ? err.message : String(err));
  }
  const { values, positionals } = flags;
  if (values.help) {
    process.stdout.write(`${USAGE}\n`);
    return 0;
  }
  if (values.version) {
    process.stdout.write(`${cliVersion()}\n`);
    return 0;
  }
  if (positionals.length !== 2 || positionals[0] !== 'verify') {
    throw new UsageError("expected exactly one command: 'verify <attestation>'");
  }
  const attestation = await readInput(positionals[1] as string);
  const trustedArks: Uint8Array[] = [];
  for (const arkPath of values.ark ?? []) {
    trustedArks.push(await readCert(arkPath, '--ark'));
  }
  const askCert = values.ask !== undefined ? await readCert(values.ask, '--ask') : undefined;
  const vcekCert = values.vcek !== undefined ? await readCert(values.vcek, '--vcek') : undefined;
  let now: number | undefined;
  if (values.now !== undefined) {
    now = Date.parse(values.now);
    if (Number.isNaN(now)) {
      throw new UsageError(`--now is not a valid date: ${values.now}`);
    }
  }
  const expectedReportData = values['report-data'] !== undefined ? parseReportData(values['report-data']) : undefined;
  const expectedMeasurement =
    values['expect-measurement'] !== undefined
      ? parseDigestFlag(values['expect-measurement'], '--expect-measurement', PLATFORM_MEASUREMENT_BYTES)
      : undefined;
  const expectedComposeHash =
    values['expect-compose-hash'] !== undefined
      ? parseDigestFlag(values['expect-compose-hash'], '--expect-compose-hash', COMPOSE_HASH_BYTES)
      : undefined;
  try {
    const result = verifyAttestation(attestation, {
      now,
      trustedArks: trustedArks.length > 0 ? trustedArks : undefined,
      askCert,
      vcekCert,
      allowDebug: values['allow-debug'],
    });
    if (expectedReportData) {
      checkReportDataBinding(expectedReportData, result.reportData);
    }
    const pinned: string[] = [];
    if (expectedMeasurement) {
      checkPin('measurement', '--expect-measurement', expectedMeasurement, platformMeasurement(result));
      pinned.push('measurement');
    }
    if (expectedComposeHash) {
      checkPin('compose hash', '--expect-compose-hash', expectedComposeHash, pinnedComposeHash(result));
      pinned.push('compose hash');
    }
    process.stdout.write(`${values.json ? jsonResult(result) : humanResult(result, pinned)}\n`);
    return 0;
  } catch (err) {
    if (err instanceof AttestationError) {
      if (values.json) {
        process.stdout.write(`${JSON.stringify({ ok: false, code: err.code, message: err.message }, null, 2)}\n`);
      } else {
        process.stderr.write(`verification failed (${err.code}): ${err.message}\n`);
      }
      return 1;
    }
    const detail = err instanceof Error ? (err.stack ?? err.message) : String(err);
    process.stderr.write(`ashaveri: unexpected error: ${detail}\n`);
    return 1;
  }
}

try {
  process.exitCode = await main(process.argv.slice(2));
} catch (err) {
  if (err instanceof UsageError) {
    process.stderr.write(`ashaveri: ${err.message}\nTry 'ashaveri --help' for usage.\n`);
    process.exitCode = 2;
  } else {
    const detail = err instanceof Error ? (err.stack ?? err.message) : String(err);
    process.stderr.write(`ashaveri: unexpected error: ${detail}\n`);
    process.exitCode = 1;
  }
}
