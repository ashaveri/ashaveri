#!/usr/bin/env node
import { readFileSync, statSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { MEASUREMENT_BYTES, type TeeKind } from '@ashaveri/receipt';
import { buildGateway } from './server.js';
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

const app = buildGateway({ deployment, backend, store });
await app.listen({ port, host });
const label =
  values.mock === true
    ? 'mock'
    : `live ${deployment.tee} measurement ${toHex(deployment.measurement).slice(0, 16)}...`;
const kept =
  receiptsDir === undefined
    ? 'receipts kept in this process only, and gone on restart'
    : `receipts kept in ${receiptsDir} for ${Math.round(MINIMUM_RETENTION_SECONDS / 86_400)} days, up to ${String(MAX_SERVED_RECEIPTS)} at a time`;
process.stdout.write(
  `signerd (${label}) listening on http://${host}:${port}\n` +
    `  issuer ${deployment.issuer} instance ${deployment.instance}\n` +
    `  ${kept}\n`,
);

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => {
    void app.close().then(() => process.exit(0));
  });
}
