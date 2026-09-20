import { readFile } from 'node:fs/promises';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  AttestationError,
  DEFAULT_AMD_ARKS,
  DEFAULT_INTEL_SGX_ROOTS,
  DEFAULT_NVIDIA_DEVICE_ROOTS,
  equalBytes,
  pinnedComposeHash,
  platformMeasurement,
  reportDataBinds,
  verifyAttestation,
} from '@ashaveri/attest-core';
import type { NvidiaEvidence, NvidiaVerification, VerificationResult } from '@ashaveri/attest-core';
import { toHex, type TeeKind } from '@ashaveri/receipt';
import { loadPolicyFile, SdkError, type AnchorFamily, type LoadedPolicy } from '@ashaveri/sdk';
import { escapeInvisible, UsageError, writeJson } from '../usage.js';

const REPORT_DATA_BYTES = 64;
const PLATFORM_MEASUREMENT_BYTES = 48;
const COMPOSE_HASH_BYTES = 32;

/** The environment kind a platform quote of each family is a measurement of. */
const PLATFORM_TEE_KIND: Readonly<Record<VerificationResult['platformKind'], TeeKind>> = {
  'sev-snp': 'snp',
  tdx: 'tdx',
};

/**
 * The flags `--policy` replaces, and the thing each one pins.
 *
 * Only the flags that decide what is trusted are here. `--ask`, `--vcek`, `--gpu-report` and
 * `--gpu-chain` carry bytes a verification needs rather than a claim about what is acceptable, and
 * `--report-data` is this request's challenge, which no policy could fix in advance.
 */
const POLICY_CLASHING_FLAGS: ReadonlyArray<readonly [flag: string, pinned: string, read: (values: VerifyFlags) => unknown]> = [
  ['--ark', 'the AMD roots', (values) => values.ark],
  ['--intel-root', 'the Intel roots', (values) => values['intel-root']],
  ['--gpu-root', 'the NVIDIA roots', (values) => values['gpu-root']],
  ['--expect-measurement', 'the launch measurement', (values) => values['expect-measurement']],
  ['--expect-compose-hash', 'the compose hash', (values) => values['expect-compose-hash']],
];

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
  policy?: string;
  now?: string;
  'allow-debug'?: boolean;
  json?: boolean;
}

/**
 * A policy document and the pin flags are alternatives, so a run that names both is refused.
 *
 * No precedence is defined either way: a file an operator signed and a command line that quietly
 * overrode part of it would leave the printed digest describing something other than the check that
 * ran, which is the one thing a citable policy must not do.
 */
function refuseMixingPolicyWithPins(values: VerifyFlags): void {
  if (values.policy === undefined) return;
  const given = POLICY_CLASHING_FLAGS.filter(([, , read]) => read(values) !== undefined).map(
    ([flag, pinned]) => `${flag} (${pinned})`,
  );
  if (given.length > 0) {
    throw new UsageError(
      `--policy and ${given.join(', ')} both decide the same pins, and neither one wins: pass the policy file or those flags, not both`,
    );
  }
}

/** A policy the operator named, or the refusal that says why it could not be read. */
async function readPolicyFile(path: string): Promise<LoadedPolicy> {
  try {
    return await loadPolicyFile(path);
  } catch (err) {
    if (err instanceof SdkError) {
      throw new UsageError(`policy file '${path}' refused (${err.code}): ${escapeInvisible(err.message)}`);
    }
    throw err;
  }
}

/** The measurement a policy pins for the platform this quote turned out to be, checked against it. */
function checkPolicyMeasurement(loaded: LoadedPolicy, result: VerificationResult): string | null {
  const pinned = loaded.policy.measurements;
  if (pinned === undefined) return null;
  const tee = PLATFORM_TEE_KIND[result.platformKind];
  const allowed = pinned[tee];
  if (allowed === undefined) {
    const kinds = Object.keys(pinned).map((kind) => `'${kind}'`).join(', ');
    throw new AttestationError(
      'PIN_MISMATCH',
      `the policy pins measurements for ${kinds}, and a ${result.platformKind} attestation is a '${tee}' measurement, which none of them covers`,
    );
  }
  const actual = toHex(platformMeasurement(result));
  if (!allowed.includes(actual)) {
    throw new AttestationError(
      'PIN_MISMATCH',
      `measurement is ${actual}, ${loaded.digest} pins ${allowed.join(' or ')}`,
    );
  }
  return 'measurement matches the policy file';
}

/**
 * The roots one family is trusted at.
 *
 * A document decides this in three states rather than two. A family it lists, even as an empty list,
 * is the set evidence has to chain to; a family it leaves out accepts the roots bundled with the
 * verifier, which is the default `AshaveriPolicy.trustAnchors` documents. Bundling is a property of
 * whichever `@ashaveri/attest-core` is installed rather than of the document, so the digest covers
 * the path and the bytes where the operator named them and says nothing at all where they did not.
 *
 * With no document the flags decide, and a root nobody named on the command line is not trusted: the
 * default has to stay a refusal there, or the absence of a flag becomes a statement about trust.
 */
function rootsForFamily(
  family: AnchorFamily,
  loaded: LoadedPolicy | null,
  fromFlags: readonly Uint8Array[],
  bundled: readonly Uint8Array[],
): readonly Uint8Array[] {
  if (loaded === null) return fromFlags;
  return loaded.policy.trustAnchors?.[family] ?? bundled;
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

interface Report {
  /** One line per pin this run checked and this evidence satisfied, in the order they were checked. */
  readonly pinned: readonly string[];
  /** The document the pins came from, or null when the flags decided them. */
  readonly policy: { readonly digest: string; readonly file: string } | null;
}

/**
 * What a run cites when a document decided its pins: the digest an auditor compares, and the name
 * the file was read from so the digest is never detached from the bytes it stands for.
 *
 * `file` is the path as the operator typed it rather than the resolved one, because the refusal and
 * the report should name the thing they were handed.
 */
function policyReport(loaded: LoadedPolicy | null, file: string | undefined): Report['policy'] {
  return loaded === null || file === undefined ? null : { digest: loaded.digest, file };
}

function humanResult(result: VerificationResult, outcome: Report): string {
  const lines: string[] = [];
  const platform = result.platformKind === 'sev-snp' ? 'SEV-SNP' : 'TDX';
  lines.push(`${platform} attestation verified (envelope v${result.version})`);
  if (result.snp) {
    lines.push('  quote signature:  verified (AMD ARK -> ASK -> VCEK chain, ECDSA P-384)');
    const { report, mrConfig } = result.snp;
    // The only two strings in this report; everything else is hex or a number. Neither is authored by
    // the workload: the product line is read out of CPUID family and model bits through a table of
    // three, and the key provider name comes from the application configuration document whose digest
    // the platform wrote into the report, which makes it the deployment owner's own text. The guard
    // stays because whoever runs this command is usually not whoever chose either value, and neither
    // string is bounded by this file. No input this repository can build carries a separator in
    // either field, so no test gates these two calls: the product line is inside the report the
    // platform signs, and the key provider name reaches here only through the configuration document
    // whose digest the platform wrote into that report, which a verifier only accepts with the
    // matching chain behind it.
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
  if (outcome.policy !== null) {
    lines.push(`  policy:           ${outcome.policy.digest}`);
  }
  for (const label of outcome.pinned) {
    lines.push(`  pinned:           ${label}`);
  }
  lines.push(`  runtime events:   ${describeEvents(result.runtimeEvents)}`);
  const config = configSummary(result.config);
  lines.push(`  config:           ${config.bytes} bytes, sha256 ${config.sha256}`);
  return lines.join('\n');
}

function jsonResult(result: VerificationResult, outcome: Report): Record<string, unknown> {
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
    pinned: outcome.pinned,
    policy: outcome.policy,
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
  return out;
}

/** `ashaveri verify <attestation> [options]`, the whole command including its exit codes. */
export async function runVerify(positionals: string[], values: VerifyFlags): Promise<number> {
  if (positionals.length !== 1) {
    throw new UsageError("expected exactly one argument: 'verify <attestation>'");
  }
  refuseMixingPolicyWithPins(values);
  const policyPath = values.policy;
  const loaded = policyPath === undefined ? null : await readPolicyFile(policyPath);
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
      trustedArks: rootsForFamily('amdArks', loaded, trustedArks, DEFAULT_AMD_ARKS),
      askCert,
      vcekCert,
      trustedIntelRoots: rootsForFamily('intelSgxRoots', loaded, trustedIntelRoots, DEFAULT_INTEL_SGX_ROOTS),
      gpuEvidence,
      trustedNvidiaRoots: rootsForFamily('nvidiaRoots', loaded, trustedNvidiaRoots, DEFAULT_NVIDIA_DEVICE_ROOTS),
      allowDebug: values['allow-debug'],
    });
    if (expectedReportData) {
      checkReportDataBinding(expectedReportData, result.reportData);
      checkGpuChallenge(expectedReportData, result.gpus);
    }
    const pinned: string[] = [];
    if (expectedMeasurement) {
      checkPin('measurement', '--expect-measurement', expectedMeasurement, platformMeasurement(result));
      pinned.push('measurement matches the expected value');
    }
    if (expectedComposeHash) {
      checkPin('compose hash', '--expect-compose-hash', expectedComposeHash, pinnedComposeHash(result));
      pinned.push('compose hash matches the expected value');
    }
    const policyMeasurement = loaded === null ? null : checkPolicyMeasurement(loaded, result);
    if (policyMeasurement !== null) {
      pinned.push(policyMeasurement);
    }
    const outcome: Report = {
      pinned,
      policy: policyReport(loaded, policyPath),
    };
    if (values.json) {
      writeJson(jsonResult(result, outcome));
    } else {
      process.stdout.write(`${humanResult(result, outcome)}\n`);
    }
    return 0;
  } catch (err) {
    if (err instanceof AttestationError) {
      // A parser's message can quote the bytes it choked on, and those bytes are the attester's, so
      // the two failure reports need the guard the success report gets.
      if (values.json) {
        writeJson({ ok: false, code: err.code, message: err.message });
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
