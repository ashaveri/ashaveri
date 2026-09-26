#!/usr/bin/env node
import { readFileSync, statSync } from 'node:fs';
import { parseArgs } from 'node:util';
import {
  MARKING_SCHEMES,
  MEASUREMENT_BYTES,
  POP_TIMESTAMP_TOLERANCE_SECONDS,
  isMarkingScheme,
  type MarkingScheme,
  type TeeKind,
} from '@ashaveri/receipt';
import { buildGateway } from './server.js';
import {
  AccessError,
  CredentialStore,
  CREDENTIALS_FILE_VERSION,
  DEFAULT_PEER_RATE,
  DEFAULT_RATE,
  loadCredentialFile,
  newPopCredential,
  type CredentialRate,
} from './access.js';
import { MINIMUM_RETENTION_DAYS, openFileAccessLog, openMemoryAccessLog, type AccessLog } from './aclog.js';
import { dstackDeployment } from './dstack.js';
import { GuestClient } from './guest.js';
import { mockBackend, type CompletionBackend } from './backend.js';
import { upstreamBackend } from './upstream.js';
import { mockDeployment, type Deployment, type HardwareTeeKind, type ModelInfo } from './deployment.js';
import { sha256, toHex } from './digest.js';
import {
  HOST_CLOCK_SOURCE,
  MINIMUM_RETENTION_SECONDS,
  openFileReceiptStore,
  openMemoryReceiptStore,
  type ReceiptRetention,
  type ReceiptServing,
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
  --manifest-key-path <path>       Guest key path for a second key, which signs the deployment
                                   manifest. Without it the manifest is served as the plain JSON
                                   document it has always been, which a client reads and reports as
                                   unauthenticated rather than believing. With it the same document is
                                   served inside a signature, and a client that designated this key
                                   can tell the deployment's own claims about its keys from a copy
                                   made by somebody standing between it and the client. It has to be a
                                   different path from --key-path: one key cannot sign both the
                                   receipts and the manifest that lists them. A client that predates
                                   sealed manifests refuses the response instead of misreading it, so
                                   this is a compatibility event and it is yours to decide.
  --manifest-key-purpose <purpose> Purpose string mixed into the manifest key.
  --epk <n>                        Epoch of the signing key, published in the manifest.
  --issuer <id>                    Override the issuer derived from the event log.
  --instance <id>                  Override the instance id derived from the event log.
  --tee <environment>              Refuse to start unless the evidence agrees.
                                   One of snp, snp+gpucc, tdx, tdx+gpucc; the
                                   composite kinds also require a device report.
  --marking <scheme>               What every completion this process serves is
                                   marked with, from the scheme registry published
                                   in docs/receipt-spec.md. One of none (the
                                   default), provenance-v1. none adds no byte to
                                   a customer's response and signs a receipt saying
                                   so; provenance-v1 writes a machine-readable
                                   marking member into the response and signs its
                                   digest. Which of the two to run is this
                                   deployment's decision, and so is whatever duty a
                                   marking is meant to answer to: this gateway
                                   marks content and attests what it marked, and
                                   proves nothing to a reader holding only text. A
                                   response whose shape cannot carry the mark is
                                   refused rather than served unmarked.
  --receipts-dir <path>            Keep issued receipts in this directory across
                                   restarts, hashed into a chain so a removal
                                   shows. The directory must already exist, so a
                                   volume you forgot to mount is a refusal rather
                                   than a store on the root filesystem. The
                                   durability bound and the period beside it are
                                   checked against each other when a store opens:
                                   a bound that cannot hold its own period at the
                                   traffic already on that volume stops the start,
                                   naming both numbers and the count the period
                                   takes. The same pairing is read while serving,
                                   so a completion whose receipt could not be kept
                                   is refused before it is computed; see
                                   --receipts-guard-at. Default: keep receipts here
                                   in this process only.
  --receipts-keep <n>              How many receipts the volume keeps, which is
                                   the durability bound. Past it the oldest
                                   receipts leave the front of the chain, so a
                                   period is kept only as far as this count
                                   reaches, and both checks above are about
                                   this number. Receipts are ~0.5 KB each.
                                   Default: 10,000, which is a few megabytes and
                                   a deployment's capacity decision; it is a
                                   shipped default and not a period anyone owes.
  --receipts-per-query <n>         How many receipts one range query holds at
                                   once, which is the serving bound. It sizes a
                                   walk's working set and retires nothing: a walk
                                   over a window holding more receipts than this
                                   is answered in batches and returns every
                                   receipt the store kept. Raising it changes what
                                   a query costs, not what the file keeps, and it
                                   is never the number either check above is short
                                   by. Default: 10,000.
  --receipts-guard-at <percent>    When the durability guard is read while serving
                                   rather than only at an opening. Once the store
                                   holds this percentage of --receipts-keep
                                   receipts, a completion is refused with
                                   RECEIPT_WINDOW_UNHOLDABLE before any inference is
                                   run if the period configured beside the bound
                                   cannot be held at the rate that store's own
                                   retained stamps measure, because issuing it would
                                   retire a receipt the period still covers. Reads,
                                   verification and handover keep serving from the
                                   receipts already filed. Default: 100, which is the
                                   bound itself and the state a store will not open
                                   at, so a deployment that sets nothing behaves as
                                   it did before this flag. Lower it to refuse while
                                   there is still room; nothing is above 100, because
                                   no store retains more than its bound. A whole
                                   percentage from 1 to 100, and a value that is not
                                   stops the start rather than falling back.
  --receipts-grow-past-guard       Keep issuing past the guard instead of refusing.
                                   Off, and it takes no argument. With it this
                                   process never refuses on the check above: the
                                   volume grows, the durability bound keeps retiring
                                   the oldest prefix, and the window served is the
                                   shorter one that bound reaches rather than the
                                   period configured beside it. That is the
                                   behaviour the guard exists to stop, and its cost
                                   is discovered inside a write rather than in an
                                   answer: the same pairing stops this volume opening
                                   at the next restart, and the receipts retired
                                   while it kept serving are gone by then. Set it
                                   where refusing a completion costs more than a
                                   shorter window does. It overrides
                                   --receipts-guard-at, and the start-up report names
                                   whichever of the two this process is running.
  --credentials-path <file>        The credential records every request has to present one from.
                                   Required in live mode; a mock run with no file makes one up and
                                   prints it. The file holds public keys and hashes only, never a
                                   signing key, so mounting it through a platform is safe in a way a
                                   secret file never is.
  --access-log-path <dir>          Where the per-request access log is written. Required in live
                                   mode. The directory must already exist, so a volume you forgot to
                                   mount is a refusal rather than a log on the root filesystem.
                                   Default: this process only, and gone on restart.
  --access-log-days <n>            How long to keep access log files. Default: 184, six months
                                   rounded up to whole days, which is the access log retention floor
                                   Article 19(1) sets for a provider of a high-risk system and
                                   Article 26(6) states in the same terms for a deployer. Shorter is
                                   allowed, and the start-up report says so.
  --allow-bearer                   Accept bearer credentials beside proof of possession. Off by
                                   default, and never per credential.
  --pop-tolerance <seconds>        Clock slack accepted for a proof-of-possession timestamp.
                                   Default: 120.
  --peer-rate perMinute=<n>,burst=<n>
                                   How many requests a connection address may make per minute, and how
                                   many of those at once, before this gateway reads that request's header
                                   or verifies anything in it. Every request from one address spends from
                                   this bucket, so behind a reverse proxy it is the whole deployment
                                   sharing one allowance. Default:
                                   perMinute=6000,burst=2000, which is a hundred requests a second from
                                   one address, one ~183 microsecond signature check behind each of them,
                                   and under two per cent of one core spent on a guessing loop. A bound
                                   below the traffic one address legitimately carries refuses signed
                                   requests instead of guesses: fifteen credentials at their own default
                                   of 60 a minute are 900 a minute down one proxy. No flag takes the
                                   bound off, and a large number is the off switch; the start-up report
                                   prints whichever number this process is holding.
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
  readonly 'manifest-key-path'?: string;
  readonly 'manifest-key-purpose'?: string;
  readonly epk?: string;
  readonly issuer?: string;
  readonly instance?: string;
  readonly tee?: string;
  readonly marking?: string;
  readonly 'receipts-dir'?: string;
  readonly 'receipts-keep'?: string;
  readonly 'receipts-per-query'?: string;
  readonly 'receipts-guard-at'?: string;
  readonly 'receipts-grow-past-guard'?: boolean;
  readonly 'credentials-path'?: string;
  readonly 'access-log-path'?: string;
  readonly 'access-log-days'?: string;
  readonly 'allow-bearer'?: boolean;
  readonly 'pop-tolerance'?: string;
  readonly 'peer-rate'?: string;
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

/** The two halves of a rate, the same pair a credential's own `rate` field carries in the file. */
const RATE_FIELDS = ['perMinute', 'burst'] as const;
const WANTED_RATE = 'perMinute=<n>,burst=<n>';

function rateField(raw: string | undefined, flag: string, unit: string): number {
  // Digits only, then the same floor the other numeric flags hold: a positive whole number. A bound the
  // bucket cannot hold is refused here rather than arriving as `Infinity`, a hex literal or `1e30` and
  // coming back on the banner as a number nobody wrote.
  const parsed = Number(raw);
  if (raw === undefined || !/^\d+$/u.test(raw) || !Number.isInteger(parsed) || parsed < 1) {
    fail(`--${flag} must be a positive whole number of ${unit}, got '${String(raw)}'`);
  }
  return parsed;
}

/**
 * `--peer-rate perMinute=<n>,burst=<n>`: the bound one connection address is held to ahead of every
 * credential, in the two fields a credential's own rate uses and held to the same rule, a whole number of
 * at least one. Both halves are required because the pair is one decision, an unknown name is refused
 * because a flag that quietly ignored a misspelling would report a bound the process is not running, and
 * there is deliberately no spelling here that turns the bound off: the off switch is a number large
 * enough to never be reached, and it says so in the banner.
 */
function parsePeerRate(raw: string | undefined): CredentialRate {
  if (raw === undefined) return DEFAULT_PEER_RATE;
  const given = new Map<string, string>();
  for (const piece of raw.split(',')) {
    const at = piece.indexOf('=');
    const name = at === -1 ? '' : piece.slice(0, at);
    if (at === -1 || !(RATE_FIELDS as readonly string[]).includes(name)) {
      fail(`--peer-rate wants ${WANTED_RATE}, got '${raw}': '${piece}' is not one of those two fields`);
    }
    if (given.has(name)) fail(`--peer-rate wants ${WANTED_RATE}, got '${raw}': ${name} is given twice`);
    given.set(name, piece.slice(at + 1));
  }
  for (const name of RATE_FIELDS) {
    if (!given.has(name)) fail(`--peer-rate wants ${WANTED_RATE}, got '${raw}': ${name} is missing`);
  }
  return {
    perMinute: rateField(given.get('perMinute'), 'peer-rate perMinute', 'requests a minute'),
    burst: rateField(given.get('burst'), 'peer-rate burst', 'requests at once'),
  };
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
      'manifest-key-path': { type: 'string' },
      'manifest-key-purpose': { type: 'string' },
      epk: { type: 'string' },
      issuer: { type: 'string' },
      instance: { type: 'string' },
      tee: { type: 'string' },
      marking: { type: 'string', default: 'none' },
      'receipts-dir': { type: 'string' },
      'receipts-keep': { type: 'string' },
      'receipts-per-query': { type: 'string' },
      'receipts-guard-at': { type: 'string' },
      'receipts-grow-past-guard': { type: 'boolean' },
      'credentials-path': { type: 'string' },
      'access-log-path': { type: 'string' },
      'access-log-days': { type: 'string' },
      'allow-bearer': { type: 'boolean' },
      'pop-tolerance': { type: 'string' },
      'peer-rate': { type: 'string' },
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
 * The two counts a receipt store is opened with, and why they are two numbers.
 *
 * The durability bound is how many receipts the volume keeps. Receipts are ~0.5 KB each, so 10,000 of
 * them is a few megabytes, which is a statement about a volume and not about a process: a receipt past
 * it leaves as the front of the chain, and the period beside it is held only as far as this count
 * reaches. Whether it can hold that period is not asserted here: the store derives the count its own
 * period takes from the traffic already on that volume and refuses the pairing at start-up rather than
 * opening and serving a shorter window than it was asked for.
 *
 * The serving bound is how many receipts one query holds at a time. It is a separate number because it
 * bounds a walk rather than a volume, and retires nothing: a walk over a window holding more receipts
 * than this is answered in batches and returns all of them. A deployment that keeps half a year of
 * traffic and answers a question about an hour of it therefore does not have to choose between the two,
 * which is the choice one number forced.
 *
 * Both are shipped defaults and nothing more. No value of either is checked against a period anyone
 * owes, and a store that opens has said what it keeps, which is a different claim from a duty
 * discharged.
 */
const SHIPPED_RETAINED_RECEIPTS = 10_000;
const SHIPPED_SERVED_RECEIPTS = 10_000;
const retainedReceipts = wholeNumber(
  values['receipts-keep'],
  'receipts-keep',
  'receipts kept',
  SHIPPED_RETAINED_RECEIPTS,
);
const servedReceipts = wholeNumber(
  values['receipts-per-query'],
  'receipts-per-query',
  'receipts per query',
  SHIPPED_SERVED_RECEIPTS,
);
/**
 * The one source this process reads: named, and stating the bound anyone has measured on it. Nothing on
 * the command line moves it, which is the point: a deployment that can read a source other than its own
 * host's clock wires one at the seam in `buildGateway` and `openFileReceiptStore`, and the name and the
 * bound travel with it. What is left unset here is a host clock at the uncertainty nobody measured, and
 * the start-up line below says so rather than letting an unstamped process read as a measured one.
 */
const time = HOST_CLOCK_SOURCE;
const retention: ReceiptRetention = { maxAgeSeconds: MINIMUM_RETENTION_SECONDS, maxCount: retainedReceipts, time };
const serving: ReceiptServing = { maxServedReceipts: servedReceipts };
/**
 * The guard's default threshold, in per cent of the durability bound: 100, the bound itself. That is
 * not a rounded number chosen for a banner, it is the one state the store already refuses to open at,
 * because a retained set never exceeds the count that retires it. So the default shipped here leaves a
 * deployment that configures nothing behaving exactly as it behaved before this flag existed, and the
 * fraction the gateway is handed is 1.
 */
const GUARD_AT_BOUND_ITSELF_PERCENT = 100;

/**
 * `--receipts-guard-at <percent>`: the point of the durability bound from which the guard is read
 * while serving rather than only at an opening. A whole percentage of at least one, and nothing above
 * the bound itself, because no store retains more receipts than the count that retires them and a
 * threshold past it would be a guard that cannot fire. Reading that as an off switch is refused here
 * for the same reason `--peer-rate` has no value that removes its bound: turning this guard off is a
 * named decision, `--receipts-grow-past-guard`, and it prints its own line at start-up.
 */
function guardPercent(raw: string | undefined): number {
  if (raw === undefined) return GUARD_AT_BOUND_ITSELF_PERCENT;
  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > GUARD_AT_BOUND_ITSELF_PERCENT) {
    fail(`--receipts-guard-at must be a whole percentage from 1 to ${GUARD_AT_BOUND_ITSELF_PERCENT}, got '${raw}'`);
  }
  return parsed;
}
const guardAtPercent = guardPercent(values['receipts-guard-at']);
const growPastGuard = values['receipts-grow-past-guard'] === true;
const receiptsDir = values['receipts-dir'];
if (receiptsDir !== undefined && !isDirectory(receiptsDir)) {
  fail('--receipts-dir must name an existing directory, so a volume you forgot to mount is a refusal and not a store on the root filesystem');
}

let store: ReceiptStore;
try {
  store =
    receiptsDir === undefined
      ? openMemoryReceiptStore({ retention, serving })
      : await openFileReceiptStore({ dir: receiptsDir, retention, serving });
} catch (error) {
  // A store that will not open is a fact about the deployment rather than about how signerd was
  // invoked: either the file on the volume no longer chains to itself, or the period this configuration
  // asks for is wider than the durability bound it was given can hold at the traffic that file has
  // already carried. Neither is answered by the same flags on a second run, so both are reported as an
  // exit 1 with the store's own code in front of the sentence.
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
// The registry this process can mark with is the receipt package's accepted set, read off it rather
// than copied here: a label added there has to be startable without a second edit an operator could
// forget, and a flag that took any other text would name a marking no verifier can look for.
const givenMarking = values.marking as string;
if (!isMarkingScheme(givenMarking)) {
  fail(`--marking must be one of ${MARKING_SCHEMES.join(', ')}, got '${givenMarking}'`);
}
const marking: MarkingScheme = givenMarking;
const toleranceSeconds = wholeNumber(
  values['pop-tolerance'],
  'pop-tolerance',
  'seconds',
  POP_TIMESTAMP_TOLERANCE_SECONDS,
);
const peerRate = parsePeerRate(values['peer-rate']);
const peerRateGiven = values['peer-rate'] !== undefined;
const accessLogDays = wholeNumber(values['access-log-days'], 'access-log-days', 'days', MINIMUM_RETENTION_DAYS);
const devCredential =
  values.mock === true && credentialsPath === undefined
    ? newPopCredential({ id: 'dev', scopes: ['complete', 'read'] })
    : undefined;

let access: CredentialStore;
try {
  if (credentialsPath === undefined) {
    const records = devCredential === undefined ? [] : [devCredential.record];
    access = new CredentialStore({
      file: { version: CREDENTIALS_FILE_VERSION, credentials: records },
      allowBearer,
      toleranceSeconds,
      peerRate,
    });
  } else {
    // Read once here, before the store exists, so a path that is absent or a file that will not
    // parse is a refusal at start-up rather than a process serving nobody: a reload keeps the
    // records it already has, and one that has none has nothing to keep. Then hand the store the
    // path and let it read the file for itself, because a revocation that waits for a restart is
    // not a revocation.
    await loadCredentialFile(credentialsPath);
    access = new CredentialStore({ path: credentialsPath, allowBearer, toleranceSeconds, peerRate });
    await access.reloadIfNeeded();
  }
} catch (error) {
  if (error instanceof AccessError) fail(`--credentials-path ${error.message}`);
  throw error;
}
// The banner reports what this process installed, which is the store's own count and not the count
// of the read above that checked the file and handed nothing over. The two agree on every file the
// parser accepts, and the check is the point: a record the store refuses at ingest never becomes one
// it serves, so the number an operator reads is the number admission can name.
const loadedRecords = access.credentials().length;

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
    manifestKeyPath: values['manifest-key-path'],
    manifestKeyPurpose: values['manifest-key-purpose'],
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

// The guard reads the very `retention` object the store above was opened with, rather than the two
// numbers copied out of it: a refusal raised against a bound nothing retires by, or a period nothing
// ages by, would be a second configuration an operator has to keep in step with the first.
const app = buildGateway({
  deployment,
  backend,
  store,
  access,
  accessLog,
  marking,
  time,
  receiptIntakeGuard: {
    retention,
    refusesAtFraction: guardAtPercent / GUARD_AT_BOUND_ITSELF_PERCENT,
    growPastGuard,
  },
});
await app.listen({ port, host });
// One decision about the run's mode, read by both lines that describe it below, so neither can claim
// a mode the process is not in.
const mode = values.mock === true ? 'mock' : 'live';
const label =
  mode === 'mock' ? 'mock' : `live ${deployment.tee} measurement ${toHex(deployment.measurement).slice(0, 16)}...`;
/** The period this process opens its store with, in whole days, read off the seconds it is set in. */
const periodDays = Math.round(MINIMUM_RETENTION_SECONDS / 86_400);
const kept =
  receiptsDir === undefined
    ? `receipts kept in this process only, as configured: a durability bound of ${String(retainedReceipts)} receipts, one query holding ${String(servedReceipts)} of them at a time, and gone on restart`
    : `receipts kept in ${receiptsDir} as configured: a period of ${String(periodDays)} days and a durability bound of ${String(retainedReceipts)} receipts, which the store compares against the traffic on its own file and refuses to open when the bound cannot hold the period, and a serving bound of ${String(servedReceipts)} receipts to a query, which bounds what one walk holds and retires nothing`;
// The intake guard, printed as this process installed it, in both settings. A deployment that can
// refuse a completion owes its operator that sentence before the traffic arrives rather than after
// the first 429, and a deployment that took the opt-in owes the two halves of what it accepted: that
// the window in force is the one the bound reaches, and that this volume stops opening at a restart.
// Neither line claims a period was kept, which is a duty and not a configuration.
const intakeGuardLabel = growPastGuard
  ? `receipt intake guard: off, as configured with --receipts-grow-past-guard, so this process keeps issuing past the durability bound of ${String(retainedReceipts)} receipts: the window served is the shorter one that bound reaches, not the ${String(periodDays)} days configured beside it, and a store on a volume refuses to open at the next restart on that same pairing`
  : `receipt intake guard: armed at ${String(guardAtPercent)}% of the durability bound, so a completion is refused RECEIPT_WINDOW_UNHOLDABLE before any inference is run once this store holds that much of its ${String(retainedReceipts)} receipts and the ${String(periodDays)} days beside the bound cannot be held at the rate its own retained stamps measure; reads, verification and handover keep serving. --receipts-guard-at sets the point and --receipts-grow-past-guard turns this off`;
// The marking a deployment runs is reported as this process installed it, in both settings, because
// the one that changes what a customer sees is the one worth reading at a start-up log: a response
// whose shape cannot carry the mark is refused here rather than served unmarked, and that is a thing
// an operator should know before traffic arrives.
const markingLabel =
  marking === 'none'
    ? 'marking: none, so no byte of a customer response is added here and every receipt says so'
    : `marking: ${marking}, so every completion carries its marking member, a response that cannot carry one is refused, and any duty a marking answers to stays this deployment's own`;
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
// The source every stamp this process signs comes from, printed as the process reads it. A receipt's
// issuance instant is only as good as the source it was read from, and this line is where the process
// says which that was and whether anybody bounded it.
const timeLabel =
  time.uncertaintySeconds === null
    ? `time: every stamp this process signs is read from ${time.name}, on which nobody measured an uncertainty, so a receipt's issuance instant is this host's own claim`
    : `time: every stamp this process signs is read from ${time.name}, whose readings are bounded at ${String(time.uncertaintySeconds)} seconds`;
// The two rate limits a request spends, printed as this process holds them rather than as the flags
// spelled it: every request from one address, signed or not, spends from the first bucket, so behind a
// reverse proxy that number is the deployment's capacity and not a per-client one. The second is what a
// record with no `rate` of its own is held to, which is the quantity an operator multiplies by the number
// of credentials to know whether the first is big enough.
const rateLabel =
  `rate limits: ${String(peerRate.perMinute)} requests a minute and ${String(peerRate.burst)} at once per connection address, ` +
  `taken ahead of every credential check, ${peerRateGiven ? 'from --peer-rate' : 'the default'}; ` +
  `a credential with no rate in its record holds ${String(DEFAULT_RATE.perMinute)} a minute and ${String(DEFAULT_RATE.burst)} at once`;
// The manifest's posture is reported as this process actually serves it, because the two states mean
// different things to whoever is standing at the other end of the deployment: a sealed document is one
// a client can attribute to this deployment, and a plain one is a claim a client has to treat as
// unverified. Printing the kid is no disclosure, since the same value is inside the wrapper's header.
const manifestLabel =
  deployment.manifestKey === undefined
    ? 'manifest: served as plain JSON, unsigned, so a client can only report it as unauthenticated, or refuse it outright if it designated a key to sign this document'
    : `manifest: served sealed, COSE_Sign1 over the same JSON under key ${toHex(deployment.manifestKey.kid).slice(0, 16)}..., which a client authenticates only against a key it designates for the purpose`;
const lines: string[] = [
  `signerd (${label}) listening on http://${host}:${boundPort}`,
  `  issuer ${deployment.issuer} instance ${deployment.instance}`,
  `  ${manifestLabel}`,
  `  ${kept}`,
  `  ${intakeGuardLabel}`,
  `  ${markingLabel}`,
  `  ${timeLabel}`,
  allowBearer
    ? '  auth: bearer credentials also accepted, which is a refusal of the strongest posture here: a stolen bearer credential is undetectable, and a log record cannot tell its holder from a thief'
    : `  auth: proof of possession, timestamps trusted within ${String(toleranceSeconds)} seconds; bearer credentials refused`,
  `  ${rateLabel}`,
  `  ${credentialsLabel}`,
  `  ${logLabel}`,
];
if (accessLogDays < MINIMUM_RETENTION_DAYS) {
  lines.push(
    `  note: ${String(accessLogDays)} days is below the 184-day floor, six months rounded up to whole days, that Article 19(1) sets for a provider of a high-risk system and Article 26(6) states in the same terms for a deployer, and this run was started with the shorter window`,
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
