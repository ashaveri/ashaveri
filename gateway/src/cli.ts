#!/usr/bin/env node
import { readFileSync, statSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { MEASUREMENT_BYTES, POP_TIMESTAMP_TOLERANCE_SECONDS, type TeeKind } from '@ashaveri/receipt';
import { buildGateway } from './server.js';
import {
  AccessError,
  CredentialStore,
  CREDENTIALS_FILE_VERSION,
  loadCredentialFile,
  newPopCredential,
} from './access.js';
import { MINIMUM_RETENTION_DAYS, openFileAccessLog, openMemoryAccessLog, type AccessLog } from './aclog.js';
import { dstackDeployment } from './dstack.js';
import { GuestClient } from './guest.js';
import { mockBackend, type CompletionBackend } from './backend.js';
import { upstreamBackend } from './upstream.js';
import { mockDeployment, type Deployment, type HardwareTeeKind, type ModelInfo } from './deployment.js';
import { sha256, toHex } from './digest.js';
import {
  MINIMUM_RETENTION_SECONDS,
  openFileReceiptStore,
  openMemoryReceiptStore,
  type ReceiptRetention,
  type ReceiptStore,
} from './store.js';

const USAGE = `signerd - receipt-signing gateway for Ashaveri verifiable inference

Usage:
  signerd --mock [--host <host>] [--port <port>]
  signerd --live --public-url <url> --model <id> --weights-manifest <file>
          [--upstream <url>] [--guest-socket <path-or-url>] [options]

Modes:
  --mock   Deterministic completions, an ephemeral dev signing key, no TEE.
  --live   The signing key and every measurement come from the dstack guest
           agent inside this CVM. Requires --public-url, --model and
           --weights-manifest.

Options:
  --host <host>                    Bind address. Default: 127.0.0.1.
  --port <port>                    Bind port. Default: 7173.
  --public-url <url>               Public origin of this gateway, so clients can
                                   refetch the evidence each receipt points at.
  --model <id>                     Served model id; must match what the upstream
                                   reports. May be repeated.
  --weights-manifest <file>        File whose sha256 every receipt for --model
                                   carries, so the digest is pinned at build time.
  --upstream <url>                 OpenAI-compatible root to proxy. Default: the
                                   mock backend.
  --guest-socket <path-or-url>     Guest agent socket, or an http(s) endpoint for
                                   the dstack simulator. Default:
                                   $DSTACK_SIMULATOR_ENDPOINT, then the standard
                                   guest paths.
  --key-path <path>                Guest key path for the receipt key.
                                   Default: /ashaveri/receipt.
  --key-purpose <purpose>          Purpose string mixed into the derived key.
  --epk <n>                        Epoch of the signing key, published in the manifest.
  --issuer <id>                    Override the issuer derived from the event log.
  --instance <id>                  Override the instance id derived from the event log.
  --tee <environment>              Refuse to start unless the evidence agrees.
                                   One of snp, snp+gpucc, tdx, tdx+gpucc; the
                                   composite kinds also require a device report.
  --receipts-dir <path>            Keep issued receipts in this directory across
                                   restarts, hashed into a chain so a removal
                                   shows. The directory must already exist, so a
                                   volume you forgot to mount is a refusal rather
                                   than a store on the root filesystem.
                                   Default: keep receipts in this process only.
  --credentials-path <file>        The credential records every request has to present one from.
                                   Required in live mode; a mock run with no file makes one up and
                                   prints it. The file holds public keys and hashes only, never a
                                   signing key, so mounting it through a platform is safe in a way a
                                   secret file never is.
  --access-log-path <dir>          Where the per-request access log is written. Required in live
                                   mode. The directory must already exist, so a volume you forgot to
                                   mount is a refusal rather than a log on the root filesystem.
                                   Default: this process only, and gone on restart.
  --access-log-days <n>            How long to keep access log files. Default: 184, which is the
                                   six-month floor AI Act Article 19(1) and 26(6) set for a deployer
                                   whose system is in Annex III point 1(a). Shorter is allowed, and
                                   the start-up report says so.
  --allow-bearer                   Accept bearer credentials beside proof of possession. Off by
                                   default, and never per credential.
  --pop-tolerance <seconds>        Clock slack accepted for a proof-of-possession timestamp.
                                   Default: 120.
  --help                           Print this help.`;

/**
 * Read off the receipt's measurement table: a kind the wire format allows has to be
 * selectable here, and a hand-kept copy of that list is how it stops being so.
 */
const HARDWARE_TEES: readonly HardwareTeeKind[] = (Object.keys(MEASUREMENT_BYTES) as TeeKind[]).filter(
  (tee): tee is HardwareTeeKind => tee !== 'software',
);

interface CliOptions {
  readonly mock?: boolean;
  readonly live?: boolean;
  readonly host?: string;
  readonly port?: string;
  readonly help?: boolean;
  readonly 'public-url'?: string;
  readonly model?: string[];
  readonly 'weights-manifest'?: string;
  readonly upstream?: string;
  readonly 'guest-socket'?: string;
  readonly 'key-path'?: string;
  readonly 'key-purpose'?: string;
  readonly epk?: string;
  readonly issuer?: string;
  readonly instance?: string;
  readonly tee?: string;
  readonly 'receipts-dir'?: string;
  readonly 'credentials-path'?: string;
  readonly 'access-log-path'?: string;
  readonly 'access-log-days'?: string;
  readonly 'allow-bearer'?: boolean;
  readonly 'pop-tolerance'?: string;
}

function fail(message: string): never {
  process.stderr.write(`signerd: ${message}\nTry 'signerd --help' for usage.\n`);
  process.exit(2);
}

function required(values: CliOptions, name: keyof CliOptions): string {
  const value = values[name];
  if (typeof value !== 'string' || value.length === 0) {
    fail(`--${name} is required in live mode`);
  }
  return value;
}

function wholeNumber(raw: string | undefined, flag: string, unit: string, fallback: number): number {
  if (raw === undefined) return fallback;
  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed < 1) {
    fail(`--${flag} must be a positive whole number of ${unit}, got '${raw}'`);
  }
  return parsed;
}

let values: CliOptions;
try {
  values = parseArgs({
    options: {
      mock: { type: 'boolean' },
      live: { type: 'boolean' },
      host: { type: 'string', default: '127.0.0.1' },
      port: { type: 'string', default: '7173' },
      help: { type: 'boolean' },
      'public-url': { type: 'string' },
      model: { type: 'string', multiple: true },
      'weights-manifest': { type: 'string' },
      upstream: { type: 'string' },
      'guest-socket': { type: 'string' },
      'key-path': { type: 'string' },
      'key-purpose': { type: 'string' },
      epk: { type: 'string' },
      issuer: { type: 'string' },
      instance: { type: 'string' },
      tee: { type: 'string' },
      'receipts-dir': { type: 'string' },
      'credentials-path': { type: 'string' },
      'access-log-path': { type: 'string' },
      'access-log-days': { type: 'string' },
      'allow-bearer': { type: 'boolean' },
      'pop-tolerance': { type: 'string' },
    },
  }).values;
} catch (error) {
  fail(error instanceof Error ? error.message : String(error));
}

if (values.help) {
  process.stdout.write(`${USAGE}\n`);
  process.exit(0);
}
if (values.mock === values.live) {
  fail('exactly one of --mock or --live is required');
}

const port = Number(values.port);
if (!Number.isInteger(port) || port < 0 || port > 65535) {
  fail(`invalid port '${String(values.port)}'`);
}
const host = values.host as string;

function weightsOf(manifestPath: string): Uint8Array {
  let bytes: Buffer;
  try {
    bytes = readFileSync(manifestPath);
  } catch (error) {
    fail(`--weights-manifest could not be read: ${error instanceof Error ? error.message : String(error)}`);
  }
  return sha256(new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength));
}

function isDirectory(path: string): boolean {
  try {
    return statSync(path).isDirectory();
  } catch {
    return false;
  }
}

/**
 * Receipts are ~0.5 KB each, so this holds the store to a few megabytes. It is a volume bound
 * rather than a retention promise: the window is the promise, and a store that has to cut one
 * short reports the window it actually kept.
 */
const MAX_SERVED_RECEIPTS = 10_000;
const retention: ReceiptRetention = { maxAgeSeconds: MINIMUM_RETENTION_SECONDS, maxCount: MAX_SERVED_RECEIPTS };
const receiptsDir = values['receipts-dir'];
if (receiptsDir !== undefined && !isDirectory(receiptsDir)) {
  fail('--receipts-dir must name an existing directory, so a volume you forgot to mount is a refusal and not a store on the root filesystem');
}

let store: ReceiptStore;
try {
  store =
    receiptsDir === undefined
      ? openMemoryReceiptStore({ retention })
      : await openFileReceiptStore({ dir: receiptsDir, retention });
} catch (error) {
  // A store that will not open, such as one whose chain no longer closes, is a fact about the
  // volume rather than about how signerd was invoked.
  process.stderr.write(`signerd: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
}

// Live mode asks for both of these because a gateway that started without them is a gateway serving
// unauthenticated traffic and forgetting every request it served. Mock mode makes one dev credential
// and keeps its log in memory, because the point of a mock run is that nothing else has to exist yet.
const credentialsPath =
  values.mock === true ? values['credentials-path'] : required(values, 'credentials-path');
const accessLogPath = values.mock === true ? values['access-log-path'] : required(values, 'access-log-path');
if (accessLogPath !== undefined && !isDirectory(accessLogPath)) {
  fail('--access-log-path must name an existing directory, so a volume you forgot to mount is a refusal and not a log on the root filesystem');
}
const allowBearer = values['allow-bearer'] === true;
const toleranceSeconds = wholeNumber(
  values['pop-tolerance'],
  'pop-tolerance',
  'seconds',
  POP_TIMESTAMP_TOLERANCE_SECONDS,
);
const accessLogDays = wholeNumber(values['access-log-days'], 'access-log-days', 'days', MINIMUM_RETENTION_DAYS);
const devCredential =
  values.mock === true && credentialsPath === undefined
    ? newPopCredential({ id: 'dev', scopes: ['complete', 'read'] })
    : undefined;

let access: CredentialStore;
let loadedRecords: number;
try {
  if (credentialsPath === undefined) {
    const records = devCredential === undefined ? [] : [devCredential.record];
    loadedRecords = records.length;
    access = new CredentialStore({
      file: { version: CREDENTIALS_FILE_VERSION, credentials: records },
      allowBearer,
      toleranceSeconds,
    });
  } else {
    // Read once here so a broken file is a refusal at start-up, then hand the store the path: a
    // revocation that waits for a restart is not a revocation.
    const parsed = await loadCredentialFile(credentialsPath);
    loadedRecords = parsed.credentials.length;
    access = new CredentialStore({ path: credentialsPath, allowBearer, toleranceSeconds });
  }
} catch (error) {
  if (error instanceof AccessError) fail(`--credentials-path ${error.message}`);
  throw error;
}

let accessLog: AccessLog;
try {
  accessLog =
    accessLogPath === undefined
      ? openMemoryAccessLog({ days: accessLogDays })
      : await openFileAccessLog({ dir: accessLogPath, days: accessLogDays });
} catch (error) {
  // A log that will not open on a directory that exists is a fact about the volume, the same way a
  // receipt store's broken chain is, so it is reported as an exit rather than as bad usage.
  process.stderr.write(`signerd: --access-log-path ${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
}

async function liveDeployment(values: CliOptions): Promise<Deployment> {
  let publicUrl: URL;
  try {
    publicUrl = new URL(required(values, 'public-url'));
  } catch {
    fail(`--public-url is not an absolute URL: ${String(values['public-url'])}`);
  }
  const manifestPath = required(values, 'weights-manifest');
  const models: ModelInfo[] = (values.model ?? []).map((id) => ({ id, wts: weightsOf(manifestPath) }));
  if (models.length === 0) {
    fail('at least one --model is required in live mode');
  }
  const epk = values.epk === undefined ? 0 : Number(values.epk);
  if (!Number.isInteger(epk) || epk < 0) {
    fail(`--epk must be a non-negative integer, got '${String(values.epk)}'`);
  }
  if (values.tee !== undefined && !(HARDWARE_TEES as readonly string[]).includes(values.tee)) {
    fail(`--tee must be one of ${HARDWARE_TEES.join(', ')}, got '${values.tee}'`);
  }
  return dstackDeployment({
    client: new GuestClient({ endpoint: values['guest-socket'] }),
    models,
    evidenceBaseUrl: `${publicUrl.origin}${publicUrl.pathname.replace(/\/+$/, '')}/v1`,
    keyPath: values['key-path'],
    keyPurpose: values['key-purpose'],
    epk,
    issuer: values.issuer,
    instance: values.instance,
    tee: values.tee as HardwareTeeKind | undefined,
  });
}

let deployment: Deployment;
try {
  deployment = values.mock === true ? mockDeployment() : await liveDeployment(values);
} catch (error) {
  process.stderr.write(`signerd: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
}
const backend: CompletionBackend =
  values.upstream === undefined ? mockBackend() : upstreamBackend({ baseUrl: values.upstream });

const app = buildGateway({ deployment, backend, store, access, accessLog });
await app.listen({ port, host });
// One decision about the run's mode, read by both lines that describe it below, so neither can claim
// a mode the process is not in.
const mode = values.mock === true ? 'mock' : 'live';
const label =
  mode === 'mock' ? 'mock' : `live ${deployment.tee} measurement ${toHex(deployment.measurement).slice(0, 16)}...`;
const kept =
  receiptsDir === undefined
    ? 'receipts kept in this process only, and gone on restart'
    : `receipts kept in ${receiptsDir} for ${Math.round(MINIMUM_RETENTION_SECONDS / 86_400)} days, up to ${String(MAX_SERVED_RECEIPTS)} at a time`;
// `--port 0` leaves the choice to the operating system, and this report is the only place a reader
// learns where the process actually is, so the number comes off the listener rather than off the flag.
const listening = app.server.address();
const boundPort = typeof listening === 'object' && listening !== null ? listening.port : port;
const held = accessLogPath === undefined ? [] : await accessLog.files();
const recordWord = loadedRecords === 1 ? 'record' : 'records';
const credentialsLabel =
  credentialsPath === undefined
    ? `credentials: ${String(loadedRecords)} ${recordWord} held in this process only`
    : `credentials: ${String(loadedRecords)} ${recordWord} read from ${credentialsPath} at start-up${
        loadedRecords === 0 ? ', which leaves every request refused' : ''
      }`;
const logLabel =
  accessLogPath === undefined
    ? `access log: this process only, kept for ${String(accessLogDays)} days and gone on restart`
    : `access log: ${accessLogPath}, kept for ${String(accessLogDays)} days${
        held.length === 0 ? '' : `, with ${String(held.length)} file${held.length === 1 ? '' : 's'} from before this boot`
      }`;
const lines: string[] = [
  `signerd (${label}) listening on http://${host}:${boundPort}`,
  `  issuer ${deployment.issuer} instance ${deployment.instance}`,
  `  ${kept}`,
  allowBearer
    ? '  auth: bearer credentials also accepted, which is a refusal of the strongest posture here: a stolen bearer credential is undetectable, and a log record cannot tell its holder from a thief'
    : `  auth: proof of possession, timestamps trusted within ${String(toleranceSeconds)} seconds; bearer credentials refused`,
  `  ${credentialsLabel}`,
  `  ${logLabel}`,
];
if (accessLogDays < MINIMUM_RETENTION_DAYS) {
  lines.push(
    `  note: ${String(accessLogDays)} days is below the 184-day floor AI Act Article 19(1) and Article 26(6) set for a deployer whose system is in Annex III point 1(a), and this run was started with the shorter window`,
  );
}
if (devCredential !== undefined) {
  lines.push(
    `  dev credential for this ${mode} run: id=dev privateKeyHex=${toHex(devCredential.privateKey)}`,
  );
}
process.stdout.write(`${lines.join('\n')}\n`);

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => {
    // The log gets one chance to take what is already written, and a refusal to close it is not a
    // reason to hold a process the operator just asked to stop.
    void app
      .close()
      .then(() => accessLog.close().catch(() => undefined))
      .then(() => process.exit(0));
  });
}
