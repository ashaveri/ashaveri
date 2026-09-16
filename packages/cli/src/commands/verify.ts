import { readFile } from 'node:fs/promises';
import { sha256 } from '@noble/hashes/sha2.js';
import { AttestationError, equalBytes, pinnedComposeHash, platformMeasurement, reportDataBinds, verifyAttestation } from '@ashaveri/attest-core';
import type { NvidiaEvidence, NvidiaVerification, VerificationResult } from '@ashaveri/attest-core';
import { toHex } from '@ashaveri/receipt';
import { escapeInvisible, escapeInvisibleJson, UsageError } from '../usage.js';

const REPORT_DATA_BYTES = 64;
const PLATFORM_MEASUREMENT_BYTES = 48;
const COMPOSE_HASH_BYTES = 32;

/** The flags `verify` reads, typed as the one parse in `cli.ts` produces them. */
export interface VerifyFlags {
  ark?: string[];
  ask?: string;
  vcek?: string;
  'intel-root'?: string[];
  'gpu-report'?: string[];
  'gpu-chain'?: string[];
  'gpu-root'?: string[];
  'report-data'?: string;
  'expect-measurement'?: string;
  'expect-compose-hash'?: string;
  now?: string;
  'allow-debug'?: boolean;
  json?: boolean;
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

async function readFlagFile(path: string, flag: string): Promise<Uint8Array> {
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
  if (!reportDataBinds(actual, expected)) {
    throw new AttestationError(
      'REPORT_DATA_MISMATCH',
      `report data does not match the --report-data value (${toHex(expected)})`,
    );
  }
}

/**
 * A pinned report data is a claim about this request, so a device leg that answers another
 * challenge is evidence about some other request. This buys freshness for the device leg.
 * It says nothing about which device, or which slot, served it.
 */
function checkGpuChallenge(expected: Uint8Array, gpus: readonly NvidiaVerification[]): void {
  for (const gpu of gpus) {
    if (!reportDataBinds(expected, gpu.nonce)) {
      throw new AttestationError(
        'CHALLENGE_MISMATCH',
        `the GPU signed challenge ${toHex(gpu.nonce)}, --report-data pins ${toHex(expected)}`,
      );
    }
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

/**
 * Verified device reports, one line each. The challenge is printed so the operator
 * can read it against the report data above; --report-data asserts the two agree.
 */
function gpuLines(gpus: readonly NvidiaVerification[]): string[] {
  if (gpus.length === 0) {
    return [];
  }
  const noun = gpus.length === 1 ? 'device report verified' : 'device reports verified';
  return [
    `  gpu:              ${gpus.length} ${noun} (ECDSA P-384, chain to a pinned NVIDIA root)`,
    ...gpus.map((gpu) => `  gpu challenge:    ${toHex(gpu.nonce)}`),
  ];
}

function humanResult(result: VerificationResult, pinned: readonly string[] = []): string {
  const lines: string[] = [];
  const platform = result.platformKind === 'sev-snp' ? 'SEV-SNP' : 'TDX';
  lines.push(`${platform} attestation verified (envelope v${result.version})`);
  if (result.snp) {
    lines.push('  quote signature:  verified (AMD ARK -> ASK -> VCEK chain, ECDSA P-384)');
    const { report, mrConfig } = result.snp;
    // Everything else in this report reaches the terminal as hex. These two are the strings: one is
    // text the guest wrote into its own document, and neither is bounded by this file, so both are
    // escaped where they are printed rather than trusted because of what they were last time.
    if (report.productLine) {
      lines.push(`  product:          ${escapeInvisible(report.productLine)}`);
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
      mrConfig.keyProvider ? `key provider ${escapeInvisible(mrConfig.keyProvider)}` : null,
    ].filter((part): part is string => part !== null);
    lines.push(`  mr config:        ${mrConfigParts.join(', ')}`);
  } else {
    lines.push(
      result.quoteSignatureVerified
        ? '  quote signature:  verified (Intel DCAP, PCK chain to a pinned Intel root)'
        : '  quote signature:  not verified (RTMR replay only; pass --intel-root to require DCAP)',
    );
    if (result.tdx) {
      lines.push(`  mr td:            ${toHex(result.tdx.quote.mrTd)}`);
      lines.push(`  rtmr3:            ${toHex(result.tdx.quote.rtmr[3])}`);
      lines.push(
        result.tdx.mrConfig
          ? `  mr config:        digest ${toHex(result.tdx.mrConfig.digest)} (tag ${result.tdx.mrConfig.tag})`
          : '  mr config:        none (MR_CONFIG_ID empty, no app configuration pinned)',
      );
    }
  }
  lines.push(`  report data:      ${toHex(result.reportData)}`);
  lines.push(...gpuLines(result.gpus));
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
    gpu: result.gpus.map((gpu) => ({ signatureVerified: gpu.signatureVerified, challenge: toHex(gpu.nonce) })),
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
  // `JSON.stringify` escapes the control characters and leaves the two line separators raw inside its
  // own quotes, so the document this command prints about someone else's attestation needs the same
  // guard the printed table gets. A `\uXXXX` escape is the other spelling of the same character to
  // anything that parses the result.
  return escapeInvisibleJson(JSON.stringify(out, null, 2));
}

/** `ashaveri verify <attestation> [options]`, the whole command including its exit codes. */
export async function runVerify(positionals: string[], values: VerifyFlags): Promise<number> {
  if (positionals.length !== 1) {
    throw new UsageError("expected exactly one argument: 'verify <attestation>'");
  }
  const attestation = await readInput(positionals[0] as string);
  const trustedArks: Uint8Array[] = [];
  for (const arkPath of values.ark ?? []) {
    trustedArks.push(await readFlagFile(arkPath, '--ark'));
  }
  const askCert = values.ask !== undefined ? await readFlagFile(values.ask, '--ask') : undefined;
  const vcekCert = values.vcek !== undefined ? await readFlagFile(values.vcek, '--vcek') : undefined;
  const trustedIntelRoots: Uint8Array[] = [];
  for (const rootPath of values['intel-root'] ?? []) {
    trustedIntelRoots.push(await readFlagFile(rootPath, '--intel-root'));
  }
  const reportPaths = values['gpu-report'] ?? [];
  const chainPaths = values['gpu-chain'] ?? [];
  if (reportPaths.length !== chainPaths.length) {
    throw new UsageError(
      `--gpu-report and --gpu-chain must be given the same number of times (got ${reportPaths.length} and ${chainPaths.length})`,
    );
  }
  const gpuEvidence: NvidiaEvidence[] = [];
  for (const [index, reportPath] of reportPaths.entries()) {
    const chainPath = chainPaths[index] as string;
    gpuEvidence.push({
      report: await readFlagFile(reportPath, '--gpu-report'),
      certChain: await readFlagFile(chainPath, '--gpu-chain'),
    });
  }
  const trustedNvidiaRoots: Uint8Array[] = [];
  for (const rootPath of values['gpu-root'] ?? []) {
    trustedNvidiaRoots.push(await readFlagFile(rootPath, '--gpu-root'));
  }
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
      trustedIntelRoots: trustedIntelRoots.length > 0 ? trustedIntelRoots : undefined,
      gpuEvidence,
      trustedNvidiaRoots: trustedNvidiaRoots.length > 0 ? trustedNvidiaRoots : undefined,
      allowDebug: values['allow-debug'],
    });
    if (expectedReportData) {
      checkReportDataBinding(expectedReportData, result.reportData);
      checkGpuChallenge(expectedReportData, result.gpus);
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
      // A parser's message can quote the bytes it choked on, and those bytes are the attester's, so
      // the two failure reports need the guard the success report gets.
      if (values.json) {
        const document = JSON.stringify({ ok: false, code: err.code, message: err.message }, null, 2);
        process.stdout.write(`${escapeInvisibleJson(document)}\n`);
      } else {
        process.stderr.write(`verification failed (${err.code}): ${escapeInvisible(err.message)}\n`);
      }
      return 1;
    }
    const detail = err instanceof Error ? (err.stack ?? err.message) : String(err);
    process.stderr.write(`ashaveri: unexpected error: ${detail}\n`);
    return 1;
  }
}
