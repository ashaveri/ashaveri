import { realpathSync, statSync } from 'node:fs';
import { parseArgs } from 'node:util';
import {
  MARKING_SCHEMES,
  MEASUREMENT_BYTES,
  POP_TIMESTAMP_TOLERANCE_SECONDS,
  isMarkingScheme,
  strictVerifySource,
  type MarkingScheme,
  type TeeKind,
} from '@ashaveri/receipt';
import { buildGateway, DEFAULT_COMPLETION_RATE, type GatewayInstance } from './server.js';
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
import { mockDeployment, type Deployment, type HardwareTeeKind, type MockDeploymentOptions } from './deployment.js';
import { toHex } from './digest.js';
import { EpochJournalError, recordEpochForRun, type EpochJournal } from './epoch-journal.js';
import {
  DEFAULT_INSTRUCTION_RECORD_PATH,
  openInstructionRecord,
  type CustomerInstructionRecord,
} from './instruction-record.js';
import { openTimeSourceState, type TimeSourceStateHandle } from './time-source-state.js';
import { ACCESS_LOG_EDGE, RECEIPTS_EDGE, daysToSeconds, judgeWindow } from './duty-window.js';
import { modelsFromManifest, type ManifestModels } from './weights.js';
import {
  DEFAULT_RECEIPT_RECORD_KIND,
  HOST_CLOCK_SOURCE,
  openFileReceiptStore,
  openMemoryReceiptStore,
  retentionBoundsFault,
  type ReceiptRecordKind,
  type ReceiptRetention,
  type ReceiptServing,
  type ReceiptStore,
  type TimeSource,
} from './store.js';

const USAGE = `signerd - receipt-signing gateway for Ashaveri verifiable inference

Usage:
  signerd --mock [--host <host>] [--port <port>]
          [--model <id> --weights-manifest <file>] [--upstream <url>]
  signerd --live --public-url <url> --model <id> --weights-manifest <file>
          [--upstream <url>] [--guest-socket <path-or-url>] [options]

Modes:
  --mock   Deterministic completions, an ephemeral dev signing key, no TEE.
           Given --model together with --weights-manifest it serves the id the
           upstream answers to and every receipt carries the digest of that
           file, so the digest is one a client can fetch bytes for. One of the
           two without the other is refused.
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
                                   this number. A signed receipt runs 540 to
                                   1,532 bytes across the published vectors and
                                   the store adds 127 bytes of frame around each,
                                   so 10,000 of them is 7 to 17 megabytes on the
                                   volume. Default: 10,000, which is a
                                   deployment's capacity decision; it is a
                                   shipped default and not a period anyone owes.
  --receipts-days <n>              How long the receipts store keeps a receipt before it ages out.
                                   Default: 184, six months rounded up to whole days. A default, not a
                                   floor: a deployment whose instruction record states a longer period
                                   has to name it here as well, and the run stops when it does not.
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
  --receipts-record-kind <receipt | bounded=<seconds>>
                                   Which kind of receipt record this process writes. One store file holds
                                   receipt records of one kind, because where a record's receipt sits inside
                                   its frame depends on that byte: receipt is the layout every store file
                                   this repository has published is made of, and its records state nothing
                                   about how long they are kept. bounded=<seconds> writes the same frame
                                   with that period in front of the receipt bytes, so whoever holds one
                                   record can read the retention period this deployment stated for it
                                   without a manifest beside it. Nothing enforces the period: retirement
                                   drops a prefix at the durability bound and the age period configured
                                   beside it, and reads no period off a record. A volume whose records were
                                   written under the other kind is refused at the start and left exactly as
                                   it was found, never converted. Default: receipt.
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
                                   allowed, and the start-up report says so, unless an instruction
                                   record states a longer period: this run is then refused at start,
                                   because the period that record states is the window this software
                                   enforces.
  --instruction-record <file>      What this deployment wrote about the period it owes: that period, in
                                   statedRetentionDays, and whether it takes the floor above as its own,
                                   in acceptsMinimumFloor. Default:
                                   ashaveri-instruction-record.json in the directory the process starts
                                   in, where no such file is no instruction, so the window stays this
                                   run's own number and the report says no record was read. A record
                                   that is named and cannot be read, or that is not one version this
                                   gateway reads, or that states a member it does not define, stops the
                                   start rather than being ignored.
  --time-source-state <file>       Read every stamp this process signs from
                                   a state file this deployment's own clock
                                   synchronisation maintains, instead of from
                                   this host's clock. The file states the
                                   source's name, the bound on how far its
                                   readings can stand from the instants they
                                   name, and the instant it measured, in the
                                   same whole seconds every stamp is written
                                   in. The name and the bound travel into
                                   every payload this process issues, so the
                                   writer is the thing that states them and
                                   no flag here names a bound that could
                                   compete with the document's own number.
                                   The gateway re-reads the file on an
                                   interval derived from the bound the file
                                   states, between one and sixty seconds,
                                   and stamps from the reading it holds,
                                   moved on between reads by a monotonic
                                   clock, so a stepped host clock moves no
                                   stamp and no receipt pays for a file
                                   read. A file that is missing, unreadable,
                                   of a version this gateway does not read,
                                   carrying a member it has no name for, or
                                   stating an instant further than a day from
                                   this host's own claim at the start stops
                                   the run where it stands: this route never
                                   falls back to the host clock, because the
                                   receipt's own disclosure names whichever
                                   source read the stamp. Once serving, a
                                   file whose stated instant falls further
                                   behind this source's own than the ceiling
                                   its bound allows stops receipts being
                                   signed and prints its age, its bound and
                                   this path, while reads of receipts already
                                   filed go on answering. Default: this
                                   host's clock, at the uncertainty nobody
                                   measured.
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
                                   one address. A signature check costs 105 to 107 microseconds on this
                                   runtime's own Ed25519 primitive, whether the bytes carry a real
                                   signature or a guess built to reach the arithmetic, and 1,522 to
                                   1,549 where the JavaScript reader answers instead; a guess of random
                                   bytes is refused in 8 microseconds on either road. A guessing loop
                                   therefore spends about a hundredth of one core at that rate on the
                                   primitive and about a seventh of it on the reader. A bound
                                   below the traffic one address legitimately carries refuses signed
                                   requests instead of guesses: fifteen credentials at their own default
                                   of 60 a minute are 900 a minute down one proxy. No flag takes the
                                   bound off, and a large number is the off switch; the start-up report
                                   prints whichever number this process is holding.
  --completion-rate perMinute=<n>,burst=<n>
                                   How many completions this process admits across the whole deployment per
                                   minute, and how many of those at once, before any inference is run. Every
                                   credential and every address spends from this one bucket, so it is the
                                   deployment's own ceiling rather than a per-client one, and it is stated in
                                   the same two fields as --peer-rate so the two can be read against each
                                   other. Default: perMinute=70080,burst=1168, which is the rate this build
                                   measured on its own completion path: driven over HTTP with a file store
                                   behind it and the other two buckets lifted, one process turned over 1,168
                                   completions a second with 32 callers in flight, and past that only the
                                   wait grows. 1,168 a second is 70,080 a minute, with one second of it taken
                                   at once. Against 6,000 a minute from one address it says that 11.7 busy
                                   addresses are what one process can serve for. A declared perMinute, in a
                                   run that reads a credential file, above what every credential in that
                                   file could spend together is refused at start, because a bound that can
                                   never fire is not a bound: the fix is the roster or a second process, not
                                   this number. A completion past the bound is refused
                                   DEPLOYMENT_RATE_LIMITED with a 429 and the wait to the next token, and no
                                   receipt is issued for it. No flag takes the bound off, and a large number
                                   is the off switch; the start-up report prints whichever number this
                                   process is holding, and each process holds its own counter.
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
  readonly 'receipts-days'?: string;
  readonly 'receipts-per-query'?: string;
  readonly 'receipts-guard-at'?: string;
  readonly 'receipts-grow-past-guard'?: boolean;
  readonly 'receipts-record-kind'?: string;
  readonly 'credentials-path'?: string;
  readonly 'access-log-path'?: string;
  readonly 'access-log-days'?: string;
  readonly 'instruction-record'?: string;
  readonly 'time-source-state'?: string;
  readonly 'allow-bearer'?: boolean;
  readonly 'pop-tolerance'?: string;
  readonly 'peer-rate'?: string;
  readonly 'completion-rate'?: string;
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
 * The two fields a rate flag carries, read the one way wherever they are set: the bound one connection
 * address is held to and the bound one process is held to are the same pair of numbers in the same units,
 * so they are refused by the same rule and an operator moving between the two flags meets one spelling.
 * Both halves are required because the pair is one decision, an unknown name is refused because a flag that
 * quietly ignored a misspelling would report a bound the process is not running, and there is deliberately
 * no spelling here that turns either bound off: the off switch is a number large enough to never be
 * reached, and it says so in the banner.
 */
function parseRate(
  raw: string | undefined,
  flag: string,
  fallback: CredentialRate,
  units: { readonly perMinute: string; readonly burst: string },
): CredentialRate {
  if (raw === undefined) return fallback;
  const given = new Map<string, string>();
  for (const piece of raw.split(',')) {
    const at = piece.indexOf('=');
    const name = at === -1 ? '' : piece.slice(0, at);
    if (at === -1 || !(RATE_FIELDS as readonly string[]).includes(name)) {
      fail(`--${flag} wants ${WANTED_RATE}, got '${raw}': '${piece}' is not one of those two fields`);
    }
    if (given.has(name)) fail(`--${flag} wants ${WANTED_RATE}, got '${raw}': ${name} is given twice`);
    given.set(name, piece.slice(at + 1));
  }
  for (const name of RATE_FIELDS) {
    if (!given.has(name)) fail(`--${flag} wants ${WANTED_RATE}, got '${raw}': ${name} is missing`);
  }
  return {
    perMinute: rateField(given.get('perMinute'), `${flag} perMinute`, units.perMinute),
    burst: rateField(given.get('burst'), `${flag} burst`, units.burst),
  };
}

const PEER_RATE_UNITS = { perMinute: 'requests a minute', burst: 'requests at once' } as const;
const COMPLETION_RATE_UNITS = { perMinute: 'completions a minute', burst: 'completions at once' } as const;

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
      'receipts-days': { type: 'string' },
      'receipts-per-query': { type: 'string' },
      'receipts-guard-at': { type: 'string' },
      'receipts-grow-past-guard': { type: 'boolean' },
      'receipts-record-kind': { type: 'string' },
      'credentials-path': { type: 'string' },
      'access-log-path': { type: 'string' },
      'access-log-days': { type: 'string' },
      'instruction-record': { type: 'string' },
      'time-source-state': { type: 'string' },
      'allow-bearer': { type: 'boolean' },
      'pop-tolerance': { type: 'string' },
      'peer-rate': { type: 'string' },
      'completion-rate': { type: 'string' },
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
// Read before any store or log opens, so a weights pair that cannot name one file is refused while
// the process has touched nothing a deployment keeps.
const weightsManifest = weightsManifestPath(values);

/**
 * The instruction this deployment wrote, and the two windows it leaves this run, both read before a store
 * or a log opens, in the same breath as the weights pair, because a run that cannot state the period its
 * own deployment named has no business appending to a volume first.
 *
 * No record at the default path is the state every deployment was already in: each window stays the flag's
 * value or `MINIMUM_RETENTION_DAYS`, and nothing here argues with it, because the floor is a default and a
 * request and `MINIMUM_RETENTION_DAYS` in `aclog.ts` says that enforcing it is this surface's job rather
 * than the writer's. What a record changes is whose number a refusal answers to. The period it states is
 * the deployment's own, so a window shorter than that is refused here, and the sentence names both numbers
 * and where each came from. A record that accepts the floor while stating less than it is refused too,
 * because it says two different things about one duty and no window can be the answer to both. A record
 * that states less than the floor and declines it is obeyed, which is the whole point of reading one.
 */
const instructionRecordPath = values['instruction-record'] ?? DEFAULT_INSTRUCTION_RECORD_PATH;
let instructionRecord: CustomerInstructionRecord | null;
try {
  instructionRecord = await openInstructionRecord(
    instructionRecordPath,
    values['instruction-record'] !== undefined,
  );
} catch (error) {
  // A record this run was told to read and cannot is a file the operator named, so the flags answer it:
  // the same posture the weights manifest takes, and for the same reason that quietly running would
  // enforce a period nobody wrote down.
  fail(error instanceof Error ? error.message : String(error));
}
const accessLogDays = wholeNumber(values['access-log-days'], 'access-log-days', 'days', MINIMUM_RETENTION_DAYS);
/**
 * The receipts store's age bound, in whole days, defaulting to the same number the store was opened with
 * before this flag existed so no deployment that says nothing changes what it keeps. It is a day count
 * rather than a second count at this edge because the operator names it in days, the same unit the access
 * log's window and the instruction record are stated in; `daysToSeconds` is the one place it becomes the
 * seconds the store is configured with.
 */
const receiptsDays = wholeNumber(values['receipts-days'], 'receipts-days', 'days', MINIMUM_RETENTION_DAYS);
if (instructionRecord !== null) {
  // One record states one period, and two windows are configured against it, so both are weighed here
  // rather than one being weighed and the other assumed. The access log goes first so an operator who
  // named both short reads the same sentence first either way. The window branch is a start-up line that
  // no longer matches the paper beside it, so the flags answer it; the floor branch contradicts itself, so
  // it stops the start on the exit that says no flag answers. Neither branch refuses a period for being
  // short: the yardstick is the number this deployment wrote down, and a shorter one is obeyed.
  for (const agreement of [
    judgeWindow(ACCESS_LOG_EDGE, accessLogDays, instructionRecord, MINIMUM_RETENTION_DAYS),
    judgeWindow(RECEIPTS_EDGE, receiptsDays, instructionRecord, MINIMUM_RETENTION_DAYS),
  ]) {
    if (agreement.refused) {
      if (agreement.answeredBy === 'the record itself') refuseToStart(agreement.message);
      fail(agreement.message);
    }
  }
}

/**
 * A refusal about the files this deployment was handed rather than about how signerd was invoked.
 * The process has read the container's own values and found them inconsistent, so no command line
 * answers it. The sentence is the whole refusal, and exit 1 is the posture every other start-up
 * refusal here takes: a usage exit would send an operator to the flags when the fault is the pairing.
 */
function refuseToStart(message: string): never {
  process.stderr.write(`signerd: ${message}\n`);
  process.exit(1);
}

/**
 * The manifest a live run carries, read together with the two environment values the container sets.
 *
 * The boot check verifies a directory against a manifest, and every receipt states the digest of the
 * file this function returns. Two names for that file are two chances for the checked bytes and the
 * signed digest to part company, so a deployment that sets one weights input without the other, or
 * sets both while naming a different file with the flag, is refused before a store opens. The one
 * accepted state is one file under both names, which is one set of bytes and therefore one digest.
 *
 * A direct run outside the container names neither environment value and is not a deployment with two
 * inputs: it keeps the existing requirement for the flag and invents no pairing it never made. A mock run
 * reads its flag and nothing from the environment, because it verified no boot files and an environment
 * value left in the shell is not a manifest it checked. When that flag is present, `softwareServing`
 * reads it and a named model carries the digest of those bytes.
 */
function weightsManifestPath(values: CliOptions): string | undefined {
  const dir = process.env['ASHAVERI_WEIGHTS_DIR'];
  const manifest = process.env['ASHAVERI_WEIGHTS_MANIFEST'];
  const flag = values['weights-manifest'];
  if (values.mock === true) return flag;
  if (dir !== undefined && dir.length > 0 && (manifest === undefined || manifest.length === 0)) {
    refuseToStart(
      `ASHAVERI_WEIGHTS_DIR names ${dir} and ASHAVERI_WEIGHTS_MANIFEST is empty, so this deployment sets one weights input without the other and a receipt would carry a digest its boot check never verified`,
    );
  }
  if (manifest !== undefined && manifest.length > 0 && (dir === undefined || dir.length === 0)) {
    refuseToStart(
      `ASHAVERI_WEIGHTS_MANIFEST names ${manifest} and ASHAVERI_WEIGHTS_DIR is empty, so this deployment sets one weights input without the other and a receipt would carry a digest its boot check never verified`,
    );
  }
  if (dir === undefined || dir.length === 0 || manifest === undefined || manifest.length === 0) {
    return flag;
  }
  if (flag === undefined) {
    refuseToStart(
      `ASHAVERI_WEIGHTS_MANIFEST names ${manifest} and --weights-manifest names no file, so the manifest the boot check verified is not the manifest a receipt would carry`,
    );
  }
  let verifiedFile: string;
  let flagFile: string;
  try {
    verifiedFile = realpathSync(manifest);
    flagFile = realpathSync(flag);
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    refuseToStart(
      `--weights-manifest names ${flag} and ASHAVERI_WEIGHTS_MANIFEST names ${manifest}, and one of the two does not resolve to a file: ${reason}`,
    );
  }
  if (verifiedFile !== flagFile) {
    refuseToStart(
      `--weights-manifest names ${flag} and ASHAVERI_WEIGHTS_MANIFEST names ${manifest}, which do not resolve to the same file, so the manifest the boot check verified is not the manifest a receipt would carry`,
    );
  }
  return flag;
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
 * The durability bound is how many receipts the volume keeps. A signed receipt runs 540 to 1,532 bytes
 * across the published vectors and the store adds 127 bytes of frame around each, so 10,000 of them is 7
 * to 17 megabytes, which is a statement about a volume and not about a process: a receipt past
 * it leaves as the front of the chain, and the period beside it is held only as far as this count
 * reaches. Whether it can hold that period is not asserted here: the store derives the count its own
 * period takes from the traffic already on that volume and refuses the pairing at start-up rather than
 * opening and serving a shorter window than it was asked for.
 *
 * The serving bound is how many receipts one query holds at a time. It is a separate number because it
 * bounds a walk rather than a volume, and retires nothing: a walk over a window holding more receipts
 * than this is answered in batches and returns all of them. A deployment that keeps half a year of
 * traffic and answers a question about an hour of it therefore does not have to choose between the two,
 * which is the choice one number would force.
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
 * The one source this process reads: named, and stating the bound anyone has measured on it. Nothing else
 * on the command line moves it, which is the point: the name and the bound are the deployment's own
 * statement, either the shipped one below or the one a state file carries, and they travel with every
 * stamp into the `sd` member of each payload this process signs.
 *
 * A run that names no state file reads the source this repository ships: the host's own clock, at
 * the uncertainty nobody measured, and the start-up line below says so rather than letting an unstamped
 * process read as a measured one. A run that names one reads it here, before a receipt store or an access
 * log is opened, because a process about to append to a volume it cannot date is worse than one that
 * stopped. There is no third state: a named file that cannot be read is a refusal of the run, never a
 * return to the host clock under the name the document gave, since the promise `sd` carries is about which
 * source read the stamp and nothing this process could say afterward makes an unreadable document into one.
 */
const timeSourceStatePath = values['time-source-state'];
let time: TimeSource = HOST_CLOCK_SOURCE;
let filedTimeSource: TimeSourceStateHandle | undefined;
if (timeSourceStatePath !== undefined) {
  try {
    filedTimeSource = await openTimeSourceState({
      path: timeSourceStatePath,
      // A timer that cannot read the file says so once, here, rather than only through the refusals that
      // follow: a deployment with no traffic still learns that its synchronisation stopped writing.
      report: (line): void => {
        process.stderr.write(`signerd: ${line}\n`);
      },
    });
    time = filedTimeSource.source;
  } catch (error) {
    // The operator named a file, so the fault is the deployment's rather than the command line's, and no
    // flag spelled differently answers it: the same posture an unreadable instruction record and a store
    // that will not chain take, on the exit that says nothing about usage.
    refuseToStart(error instanceof Error ? error.message : String(error));
  }
}
/**
 * The store's age bound, in the seconds the store is configured with, from the days this run named or the
 * default beside them. This is the number `--receipts-days` moves, and the only place the day count
 * becomes seconds: a deployment that states a longer period in its own instruction record is refused above
 * rather than aged out below it, and a deployment that states less is kept to its own number.
 */
const retention: ReceiptRetention = { maxAgeSeconds: daysToSeconds(receiptsDays), maxCount: retainedReceipts, time };
const serving: ReceiptServing = { maxServedReceipts: servedReceipts };
// Both bounds are written into the store's own trim record, whose 4 byte fields saturate rather than
// fail, so a number past that width is refused here as a usage line naming the flag that typed it rather
// than filed as the ceiling and read back as a configuration nobody chose. The serving bound is not
// checked, because nothing in the layout states it and a wider walk is answered in more batches.
const boundsFault = retentionBoundsFault(retention);
if (boundsFault !== undefined) {
  fail(boundsFault);
}
/**
 * The guard's default threshold, in per cent of the durability bound: 100, the bound itself. That is
 * not a rounded number chosen for a banner, it is the one state the store already refuses to open at,
 * because a retained set never exceeds the count that retires it. So the default shipped here changes
 * nothing for a deployment that configures nothing, and the fraction the gateway is handed is 1.
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

/**
 * `--receipts-record-kind <receipt | bounded=<seconds>>`: which kind of receipt record this process
 * appends.
 *
 * One store file holds receipt records of one kind, and the kind decides where inside a record its
 * receipt sits, so this is a decision about a volume and not about a request: the number is stated here
 * once and written into every record this run appends. A spelling that names neither kind is refused
 * here, because there would be no record to write. What the period itself may say is the store's rule
 * rather than this one: a number no 4 byte field can hold, or one the durability window retires before
 * the record says it should stop being kept, is refused by the opening with the code naming which of the
 * two it is, and a volume whose records were written under the other kind is refused by
 * `STORE_RECEIPT_KIND_MISMATCH` rather than converted by this process.
 */
function receiptRecordKind(raw: string | undefined): ReceiptRecordKind {
  if (raw === undefined) {
    return DEFAULT_RECEIPT_RECORD_KIND;
  }
  if (raw === 'receipt') {
    return { kind: 'receipt' };
  }
  const seconds = /^bounded=([0-9]+)$/u.exec(raw)?.[1];
  if (seconds === undefined) {
    fail(`--receipts-record-kind must be 'receipt' or 'bounded=<seconds>', got '${raw}'`);
  }
  return { kind: 'bounded', boundSeconds: Number(seconds) };
}
const receiptKind = receiptRecordKind(values['receipts-record-kind']);

let store: ReceiptStore;
try {
  store =
    receiptsDir === undefined
      ? openMemoryReceiptStore({ retention, serving, receiptKind })
      : await openFileReceiptStore({ dir: receiptsDir, retention, serving, receiptKind });
} catch (error) {
  // A store that will not open is a fact about the deployment rather than about how signerd was
  // invoked: either the file on the volume no longer chains to itself, or it is made of receipt records
  // of the kind this run was not started to write, or the period this configuration asks for is wider
  // than the durability bound it was given can hold at the traffic that file has already carried. None of
  // them is answered by the same flags on a second run, so all are reported as an exit 1 with the store's
  // own code in front of the sentence.
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
const peerRate = parseRate(values['peer-rate'], 'peer-rate', DEFAULT_PEER_RATE, PEER_RATE_UNITS);
const peerRateGiven = values['peer-rate'] !== undefined;
// The deployment's own ceiling on the completions this process admits, read the same way and in the same
// two fields, because the two bounds are meant to be compared: what one address may ask for, and what this
// process may write. The flag names the pair, or the ceiling this build derives from its two measured
// costs decides it.
const completionRate = parseRate(
  values['completion-rate'],
  'completion-rate',
  DEFAULT_COMPLETION_RATE,
  COMPLETION_RATE_UNITS,
);
const completionRateGiven = values['completion-rate'] !== undefined;
// `accessLogDays` is read above, beside the instruction record it is weighed against, so the number the
// log opens with and the number the start-up report prints are one reading of one flag.
const devCredential =
  values.mock === true && credentialsPath === undefined
    ? newPopCredential({ id: 'dev', scopes: ['complete', 'read'], time })
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

// A bound above what every credential this process holds could spend together is a number that can never
// fire, and an operator who declared one meant a ceiling and got a decoration. So a declared pair is read
// against the roster it sits over: each record's own `rate`, or the bound a record naming none falls to,
// summed over the records that are not revoked. Three things keep to this rule's edge. It reads a file the
// operator wrote, so a mock run's made-up credential, which is a fixture rather than a roster, is not
// weighed against a flag nobody was asked to set. A revoked record is left out because admission refuses
// it, so it spends nothing and cannot lift the aggregate. And the shipped default is exempt, because it is
// a throughput this build measured on its own path rather than a declaration, and a run that names no flag
// is the run this line exists to leave alone. The sum over-states what the bucket can see, since a
// credential's rate is spent on reads as readily as on completions, and over-stating is the safe direction:
// no correctly configured start is refused here.
const rosterCompletionsPerMinute = access
  .credentials()
  .filter((record) => record.revokedAt === undefined)
  .reduce((total, record) => total + (record.rate?.perMinute ?? DEFAULT_RATE.perMinute), 0);
if (credentialsPath !== undefined && completionRateGiven && completionRate.perMinute > rosterCompletionsPerMinute) {
  fail(
    `--completion-rate perMinute=${String(completionRate.perMinute)} is above the ` +
      `${String(rosterCompletionsPerMinute)} a minute that every credential this process holds could spend together, ` +
      'so this bound could never be met and the start is refused rather than left holding a number that cannot ' +
      "fire. Raise a credential's own rate, lower this number, or run a second process and hold one counter on " +
      'each of them'
  );
}

let accessLog: AccessLog;
try {
  accessLog =
    accessLogPath === undefined
      ? openMemoryAccessLog({ days: accessLogDays, time })
      : await openFileAccessLog({ dir: accessLogPath, days: accessLogDays, time });
} catch (error) {
  // A log that will not open on a directory that exists is a fact about the volume, the same way a
  // receipt store's broken chain is, so it is reported as an exit rather than as bad usage.
  process.stderr.write(`signerd: --access-log-path ${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
}

/**
 * The models a `--mock` run serves, and the bytes behind their digests, when the operator named them.
 *
 * Naming a model is what lets a software receipt say which model answered, and the weights file is what
 * makes its `wts` fetchable: `GET /v1/weights/:digest` is the one public route a deployment has, and a
 * receipt carrying `mockWeights` names a digest that route has no bytes for. So one of the two inputs
 * without the other is refused here rather than answered with the synthetic digest, which would print a
 * field on a page no client can look up.
 *
 * Neither input is read from the environment: `weightsManifestPath` returns the flag alone in mock mode,
 * because a mock run verified no boot files and an environment value left in the shell is not a manifest
 * this process checked. Live mode keeps its own pairing rule untouched.
 *
 * An absent pair returns nothing at all, so a mock run that was told nothing stays exactly the fixture it
 * was before this function existed.
 */
function softwareServing(values: CliOptions): Pick<MockDeploymentOptions, 'models' | 'weightsManifest'> {
  const modelIds = values.model ?? [];
  if (modelIds.length === 0 && weightsManifest === undefined) return {};
  if (modelIds.length === 0) {
    refuseToStart(
      `--weights-manifest names ${String(weightsManifest)} in mock mode and no --model is given, so the bytes read behind that digest name no served model`,
    );
  }
  if (weightsManifest === undefined) {
    refuseToStart(
      `at least one --model in mock mode needs --weights-manifest, so a receipt that names a model carries a digest its own route can answer with`,
    );
  }
  try {
    const { models, manifest } = modelsFromManifest(modelIds, weightsManifest);
    return { models, weightsManifest: manifest };
  } catch (error) {
    refuseToStart(
      `--weights-manifest could not be read: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

async function liveDeployment(values: CliOptions): Promise<Deployment> {
  let publicUrl: URL;
  try {
    publicUrl = new URL(required(values, 'public-url'));
  } catch {
    fail(`--public-url is not an absolute URL: ${String(values['public-url'])}`);
  }
  const manifestPath = weightsManifest ?? required(values, 'weights-manifest');
  const modelIds = values.model ?? [];
  if (modelIds.length === 0) {
    fail('at least one --model is required in live mode');
  }
  let manifestModels: ManifestModels;
  try {
    // One reading of the manifest and one digest of those bytes, handed to every model this run
    // serves: a receipt's `wts` is the digest of the bytes this process read, not a second reading of
    // the same path that could name different bytes. The same reading travels beside the models, so
    // the route addressed by that digest serves exactly the bytes the receipts name.
    manifestModels = modelsFromManifest(modelIds, manifestPath);
  } catch (error) {
    fail(`--weights-manifest could not be read: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (values.tee !== undefined && !(HARDWARE_TEES as readonly string[]).includes(values.tee)) {
    fail(`--tee must be one of ${HARDWARE_TEES.join(', ')}, got '${values.tee}'`);
  }
  return dstackDeployment({
    client: new GuestClient({ endpoint: values['guest-socket'] }),
    models: manifestModels.models,
    weightsManifest: manifestModels.manifest,
    evidenceBaseUrl: `${publicUrl.origin}${publicUrl.pathname.replace(/\/+$/, '')}/v1`,
    keyPath: values['key-path'],
    keyPurpose: values['key-purpose'],
    manifestKeyPath: values['manifest-key-path'],
    manifestKeyPurpose: values['manifest-key-purpose'],
    epk,
    issuer: values.issuer,
    instance: values.instance,
    tee: values.tee as HardwareTeeKind | undefined,
    time,
  });
}

/**
 * The epoch this process signs under, read once for both modes because it is one fact about the run.
 *
 * A receipt states it, the manifest states it beside the keys, and the journal an epoch is recorded in states
 * it as the entry's own, so a run that read this flag in one mode and not the other would publish a document
 * about a key whose epoch it had never been told. `0` is what a first deployment starts at, and rotating means
 * a new key, a higher number here, and a restart: a gateway publishes the epoch it was started with and never
 * changes it, which is what section 3 of `docs/receipt-spec.md` states and what the journal turns into a
 * published window.
 */
const epk = values.epk === undefined ? 0 : Number(values.epk);
if (!Number.isInteger(epk) || epk < 0) {
  fail(`--epk must be a non-negative integer, got '${String(values.epk)}'`);
}

let deployment: Deployment;
try {
  deployment =
    values.mock === true
      ? mockDeployment({ time, epk, ...softwareServing(values) })
      : await liveDeployment(values);
} catch (error) {
  process.stderr.write(`signerd: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
}

/**
 * The epoch this run recorded, on the volume it keeps its receipts on, or nothing where the run records none.
 *
 * Which runs record nothing, and why the answer about sealing travels with the entry instead of beside it, is
 * `recordEpochForRun`'s own and is stated there once. What is decided here is only the ordering: this opens
 * after the store, because the store is what claims the directory and refuses a second writer on it, and after
 * the deployment, because an entry is about the key and the epoch that deployment holds. A journal that will not
 * open is a fact about the volume, the way a store that will not chain is, so it stops the run on the exit that
 * names no flag as the answer.
 */
let epochJournal: EpochJournal | undefined;
try {
  epochJournal = await recordEpochForRun({
    receiptsDir,
    mock: values.mock === true,
    deployment,
    time,
  });
} catch (error) {
  refuseToStart(error instanceof Error ? error.message : String(error));
}

const backend: CompletionBackend =
  values.upstream === undefined ? mockBackend({ time }) : upstreamBackend({ baseUrl: values.upstream });

// The guard reads the very `retention` object the store above was opened with, rather than the two
// numbers copied out of it: a refusal raised against a bound nothing retires by, or a period nothing
// ages by, would be a second configuration an operator has to keep in step with the first.
//
// Building the gateway is where a deployment finds out whether the history it holds may be published, so a
// refusal from that check is reported the way every other refusal about this deployment's own files is: the
// sentence the mechanism raised, on the exit that says no command line answers it. Anything else this build
// throws is not a refusal the operator can act on, so it is left to fail as it always did.
let app: GatewayInstance;
try {
  app = buildGateway({
    deployment,
    backend,
    store,
    access,
    accessLog,
    marking,
    time,
    epochJournal,
    receiptIntakeGuard: {
      retention,
      refusesAtFraction: guardAtPercent / GUARD_AT_BOUND_ITSELF_PERCENT,
      growPastGuard,
    },
    completionBound: { rate: completionRate },
  });
} catch (error) {
  if (error instanceof EpochJournalError) refuseToStart(error.message);
  throw error;
}
await app.listen({ port, host });
// One decision about the run's mode, read by both lines that describe it below, so neither can claim
// a mode the process is not in.
const mode = values.mock === true ? 'mock' : 'live';
const label =
  mode === 'mock' ? 'mock' : `live ${deployment.tee} measurement ${toHex(deployment.measurement).slice(0, 16)}...`;
// The period printed below is `receiptsDays`, read where it is parsed rather than derived from the seconds
// the store was handed: a line that re-derived the number could disagree with the window the run refused
// or accepted a moment earlier, and the operator would be told a figure no decision was taken against.
// Which record kind this run appends, printed as the store was handed it. A bounded record's period is
// bytes inside the file the deployment keeps, and a reader of a volume cannot tell which kind it holds
// without being told, so the line states the kind, and for a bounded record the period it states and the
// flag this run used to say so. The receipt arm describes the kind rather than the run's own provenance:
// a run that names `receipt` is told the same sentence as one that named nothing, because the two write
// the same bytes.
const recordKindLabel =
  receiptKind.kind === 'bounded'
    ? `every record stating a retention period of ${String(receiptKind.boundSeconds)} seconds ahead of its receipt bytes, from --receipts-record-kind`
    : 'every record stating no retention period of its own, the receipt kind a run without --receipts-record-kind writes';
const kept =
  receiptsDir === undefined
    ? `receipts kept in this process only, as configured: a durability bound of ${String(retainedReceipts)} receipts, one query holding ${String(servedReceipts)} of them at a time, and gone on restart; ${recordKindLabel}`
    : `receipts kept in ${receiptsDir} as configured: a period of ${String(receiptsDays)} days and a durability bound of ${String(retainedReceipts)} receipts, which the store compares against the traffic on its own file and refuses to open when the bound cannot hold the period, and a serving bound of ${String(servedReceipts)} receipts to a query, which bounds what one walk holds and retires nothing; ${recordKindLabel}`;
// The intake guard, printed as this process installed it, in both settings. A deployment that can
// refuse a completion owes its operator that sentence before the traffic arrives rather than after
// the first 429, and a deployment that took the opt-in owes the two halves of what it accepted: that
// the window in force is the one the bound reaches, and that this volume stops opening at a restart.
// Neither line claims a period was kept, which is a duty and not a configuration.
const intakeGuardLabel = growPastGuard
  ? `receipt intake guard: off, as configured with --receipts-grow-past-guard, so this process keeps issuing past the durability bound of ${String(retainedReceipts)} receipts: the window served is the shorter one that bound reaches, not the ${String(receiptsDays)} days configured beside it, and a store on a volume refuses to open at the next restart on that same pairing`
  : `receipt intake guard: armed at ${String(guardAtPercent)}% of the durability bound, so a completion is refused RECEIPT_WINDOW_UNHOLDABLE before any inference is run once this store holds that much of its ${String(retainedReceipts)} receipts and the ${String(receiptsDays)} days beside the bound cannot be held at the rate its own retained stamps measure; reads, verification and handover keep serving. --receipts-guard-at sets the point and --receipts-grow-past-guard turns this off`;
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
// What this deployment wrote about its own duty period, printed as the bytes this run read them. The
// digest is on the line because the line is the audit: a reader of a start-up log who wants to know
// which statement a run enforced has the file it came from and the bytes that were read, and a record
// edited after the boot changes the digest rather than silently agreeing with the number printed.
// With no record the line says so, because a window that came from a flag or a shipped default is a
// different answer to "what was this deployment told to keep" than a window a deployment wrote down.
const instructionLabel =
  instructionRecord === null
    ? `instruction record: none read and no file at ${instructionRecordPath}, so the ${String(
        accessLogDays,
      )} days this run keeps come from ${
        values['access-log-days'] === undefined ? 'the default this repository ships' : '--access-log-days'
      }, which is a number this deployment was offered rather than one it stated`
    : `instruction record: ${instructionRecord.path} sha256 ${instructionRecord.digestHex}, stating ${String(
        instructionRecord.statedRetentionDays,
      )} days as the period this deployment owes and ${
        instructionRecord.acceptsMinimumFloor
          ? `accepting the ${String(MINIMUM_RETENTION_DAYS)}-day floor as this deployment's own`
          : `declining the ${String(MINIMUM_RETENTION_DAYS)}-day floor as a duty of its own`
      }, so this run keeps ${String(accessLogDays)} days`;
// The source every stamp this process signs comes from, printed as the process reads it. A receipt's
// issuance instant is only as good as the source it was read from, and this line is where the process
// says which that was and whether anybody bounded it. Whose claim an unmeasured reading is comes from
// which source the process was handed: a run that named no state file rests on its own host's clock, and
// a run that read one states whose claim it is, because a file naming a source nobody bounded is a
// different document from a host that was never asked.
const unmeasuredOwner =
  filedTimeSource === undefined
    ? "this host's own claim"
    : `the claim of ${time.name}, which ${filedTimeSource.path} states and nobody has measured`;
const timeLabel =
  time.uncertaintySeconds === null
    ? `time: every stamp this process signs is read from ${time.name}, on which nobody measured an uncertainty, so a receipt's issuance instant is ${unmeasuredOwner}`
    : `time: every stamp this process signs is read from ${time.name}, whose readings are bounded at ${String(time.uncertaintySeconds)} seconds`;
// Beside a state file, the two figures a stamp's provenance now rests on, printed as this process holds
// them: how often it looks at the file, and how far behind the file's own word it will still sign. An
// operator comparing a run's receipts with a synchronisation log needs both numbers, and neither is a
// bound this repository chose for the source rather than derived from the one the document states.
const timeStateLabel =
  filedTimeSource === undefined
    ? undefined
    : `time source state: ${filedTimeSource.path}, read every ${String(filedTimeSource.policy().refreshSeconds)} seconds and stamped from the reading held between reads, so a stamp is refused once that file's instant sits more than ${String(filedTimeSource.policy().stalenessCeilingSeconds)} seconds behind the instant this source states, which stops signing and not the reads of receipts already filed`;
// The two rate limits a request spends, printed as this process holds them rather than as the flags
// spelled it: every request from one address, signed or not, spends from the first bucket, so behind a
// reverse proxy that number is the deployment's capacity and not a per-client one. The second is what a
// record with no `rate` of its own is held to, which is the quantity an operator multiplies by the number
// of credentials to know whether the first is big enough.
const rateLabel =
  `rate limits: ${String(peerRate.perMinute)} requests a minute and ${String(peerRate.burst)} at once per connection address, ` +
  `taken ahead of every credential check, ${peerRateGiven ? 'from --peer-rate' : 'the default'}; ` +
  `a credential with no rate in its record holds ${String(DEFAULT_RATE.perMinute)} a minute and ${String(DEFAULT_RATE.burst)} at once`;
// The ceiling on what this process can serve, printed beside the two bounds a request spends because it is
// the third of the three and the only one measured on this build's own path rather than against a caller. An
// operator who has to know whether the deployment is bigger than one process reads this line and the one
// above it together.
const completionBoundLabel =
  `completion bound: ${String(completionRate.perMinute)} completions a minute across this process and ` +
  `${String(completionRate.burst)} at once, refused DEPLOYMENT_RATE_LIMITED before any inference is run, ` +
  `${completionRateGiven ? 'from --completion-rate' : 'the ceiling this build measures on its own completion path'}; ` +
  `one process holds one counter, so a deployment running more than this one admits this much on each of them`;
// The manifest's posture is reported as this process actually serves it, because the two states mean
// different things to whoever is standing at the other end of the deployment: a sealed document is one
// a client can attribute to this deployment, and a plain one is a claim a client has to treat as
// unverified. Printing the kid is no disclosure, since the same value is inside the wrapper's header.
const manifestLabel =
  deployment.manifestKey === undefined
    ? 'manifest: served as plain JSON, unsigned, so a client can only report it as unauthenticated, or refuse it outright if it designated a key to sign this document'
    : `manifest: served sealed, COSE_Sign1 over the same JSON under key ${toHex(deployment.manifestKey.kid).slice(0, 16)}..., which a client authenticates only against a key it designates for the purpose`;
// Which Ed25519 implementation answers is a fact about the process rather than about a request, and the two
// paths are one rule: the refusals this build states, then the group equation. The sentence is printed because
// an operator comparing two deployments should be able to see that the arithmetic underneath a refusal differs
// even when the answer does not.
const verifierLabel =
  strictVerifySource === 'runtime'
    ? 'the runtime Ed25519 primitive, under the strict refusals this build applies ahead of it'
    : '@noble/curves in strict mode, this runtime exposing no Ed25519 primitive';
const lines: string[] = [
  `signerd (${label}) listening on http://${host}:${boundPort}`,
  `  issuer ${deployment.issuer} instance ${deployment.instance}`,
  `  ${manifestLabel}`,
  `  ${kept}`,
  `  ${intakeGuardLabel}`,
  `  ${markingLabel}`,
  `  ${timeLabel}`,
  ...(timeStateLabel === undefined ? [] : [`  ${timeStateLabel}`]),
  allowBearer
    ? `  auth: bearer credentials also accepted, which is a refusal of the strongest posture here: a stolen bearer credential is undetectable, and a log record cannot tell its holder from a thief; proof-of-possession signatures checked with ${verifierLabel}`
    : `  auth: proof of possession, timestamps trusted within ${String(toleranceSeconds)} seconds; bearer credentials refused; signatures checked with ${verifierLabel}`,
  `  ${rateLabel}`,
  `  ${completionBoundLabel}`,
  `  ${credentialsLabel}`,
  `  ${logLabel}`,
  `  ${instructionLabel}`,
];
if (accessLogDays < MINIMUM_RETENTION_DAYS) {
  // The floor keeps the meaning `aclog.ts` gives it, that it is a request rather than a clamp, so a
  // shorter window is printed as the choice it is under either hand: with no record because nobody
  // stated a period, and with one because the period that record states is shorter than the floor the
  // same record declined.
  const shorterNote =
    `note: ${String(accessLogDays)} days is below the 184-day floor, six months rounded up to whole days, that ` +
    `Article 19(1) sets for a provider of a high-risk system and Article 26(6) states in the same terms for a deployer, ` +
    `and this run was started with the shorter window`;
  lines.push(
    `  ${shorterNote}${
      instructionRecord === null
        ? ', and no instruction record was read, so no period this deployment wrote of its own duty stands behind the number'
        : `: ${instructionRecord.path} states ${String(instructionRecord.statedRetentionDays)} days and declines that floor, so the shorter window is the period this deployment wrote down`
    }`,
  );
}
if (receiptsDays < MINIMUM_RETENTION_DAYS) {
  // The receipts store's 184 days is a shipped default and this is the one moment a run says so out loud.
  // The yardstick a receipts window is weighed against is the period this deployment stated for itself, and
  // a window below the default that reaches that period is obeyed, so the line names the file the number
  // was weighed against and the flag that raises the window. It states no period anyone owes, because
  // Articles 19(1) and 26(6) both yield to applicable Union or national law, and that law moves a period in
  // either direction: a deployment keeping thirty days may be keeping exactly what it is under.
  const belowDefault =
    `note: ${String(receiptsDays)} days is below the ${String(MINIMUM_RETENTION_DAYS)}-day default this repository ships, ` +
    `and a receipt older than this window stops being served from it`;
  const weighedAgainst =
    instructionRecord === null
      ? 'no instruction record was read, so nothing states a longer period beside this number'
      : `${instructionRecord.path} states ${String(instructionRecord.statedRetentionDays)} days and this window reaches that period`;
  lines.push(
    `  ${belowDefault}; ${weighedAgainst}; the default is what a run falls back on and not a period anyone ` +
      `owes, and --receipts-days is the flag that raises it`,
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
    // The reader's timer is stopped on the way out, so a process already leaving takes no fresh reading of
    // the file it was pointed at.
    filedTimeSource?.stop();
    // The log gets one chance to take what is already written, and a refusal to close it is not a
    // reason to hold a process the operator just asked to stop.
    void app
      .close()
      .then(() => accessLog.close().catch(() => undefined))
      .then(() => process.exit(0));
  });
}
