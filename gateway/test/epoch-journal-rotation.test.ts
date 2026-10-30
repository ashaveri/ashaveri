import { spawnSync } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import {
  decodeReceipt,
  decodeSealedDeploymentManifest,
  hashRequest,
  signingKeyFromSeed,
  toBase64Url,
  toHex,
  type ReceiptPayload,
  type SigningKey,
} from '@ashaveri/receipt';
import { mockDeployment, type Deployment } from '../src/deployment.js';
import { EPOCH_JOURNAL_FILE, recordEpochForRun } from '../src/epoch-journal.js';
import { openFileReceiptStore } from '../src/store.js';
import { fixedClock, generated, harness, nonceAt, type Harness } from './helpers.js';
import { noteSpawn, spawnCeilingForCalls } from './support/spawn-budget.js';

/**
 * A rotation rehearsed against the history a running gateway wrote for itself.
 *
 * The rehearsal in `test/epoch-rotation-rehearsal.test.ts` answers the acceptance sentence about a key
 * rotation, and it has to publish the history by hand to do so: the document a gateway serves holds the one
 * key that process stands on, so the windows the verifier weighs a receipt against are built beside it. This
 * file asks the same question of a deployment that keeps an epoch journal on its own volume, where nobody
 * types a kid, a public key or a Unix second: the process records the epoch it signs under when it starts,
 * and what a verifier reads is the bytes the successor serves at `GET /v1/deployment-manifest`. Every step is
 * a shipped one. A gateway built in `gateway/src/server.ts` signs each receipt, `gateway/src/store.ts` files
 * it in a durable `receipts.log`, the successor reads it back over its own route, and `ashaveri
 * verify-receipt` adjudicates the epoch in its own process against the document the successor publishes.
 *
 * Two things separate this from a unit reading of the same rule. The history is not assembled for the case:
 * the predecessor's entry, its window and its successor's are the entries two processes wrote on the same
 * volume at the instants they first served there. And the reader is handed no second document: the bytes it
 * verifies are the ones the running deployment answers with, seal and all, so a rotation that was recorded
 * wrongly is visible here as a refusal a client would meet rather than as a fixture that disagreed.
 *
 * Like the rehearsal it replaces, this is a scripted rehearsal and not a production rotation. It runs offline,
 * in temporary directories, on keys derived from fixed seeds, with every instant read from a clock the case
 * states. No deployment was contacted, no ceremony was performed, no real key was retired.
 *
 * One limit of the shipped path is stated rather than worked around. The journal is opened only where a
 * deployment has a volume to keep it on, which is `--receipts-dir` on the command line and the directory a
 * case passes here, because a history that dies with the process that wrote it explains nothing. A receipt
 * issued before that volume existed names an epoch the journal never recorded, and the reader answers it the
 * way the last case below shows: with the refusal an undeclared epoch earns, not with a window nobody served
 * under.
 */

/** The built offline verifier, run as a child exactly as an operator runs it. */
const CLI = fileURLToPath(new URL('../../packages/cli/dist/cli.js', import.meta.url));

/** One child's patience, the figure `test/support/spawn-budget.ts` restates for the CLI. */
const SPAWN_DEADLINE_MS = 8_000;

const MODEL = 'mock-model-1';
const CREDENTIAL = 'epoch-journal-rotation';
const REQUEST_BODY = `{"model":"${MODEL}","messages":[{"role":"user","content":"hello again"}]}`;

function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

/** The instant the first process first served under its epoch, and so the opening of its window. */
const EPOCH_ONE_OPENS = 1_772_000_400;
/** The instant the successor served under its own, which closes the window above it and opens its own. */
const ROTATION_OPENS = 1_772_001_600;
/** The one instant every verifier run reads its own clock at. */
const READ_AT = ROTATION_OPENS + 3_600;
/** Wider than the rehearsal, so no run below is refused for its age rather than for its epoch. */
const POLICY_WINDOW_SECONDS = 86_400;

const EPOCH_ONE_KEY = signingKeyFromSeed(hashRequest(utf8('ashaveri-epoch-journal-rotation-first-key')));
const EPOCH_TWO_KEY = signingKeyFromSeed(hashRequest(utf8('ashaveri-epoch-journal-rotation-second-key')));
const SEAL_KEY = signingKeyFromSeed(hashRequest(utf8('ashaveri-epoch-journal-rotation-seal-key')));
const SEAL_DESIGNATION = toBase64Url(SEAL_KEY.publicKey);

/** A `keys[]` row as the running deployment publishes it, the two optional members included. */
interface ServedRow {
  readonly kid: string;
  readonly alg: 'Ed25519';
  readonly publicKey: string;
  readonly epk?: number;
  readonly validFrom?: number;
}

interface ServedDocument {
  readonly v: 1;
  readonly iss: string;
  readonly ins: string;
  readonly epk: number;
  readonly keys: readonly ServedRow[];
  readonly models: readonly { id: string; wts: string }[];
  readonly meas: { tee: string; m: string };
}

/** The parts of the reporter's JSON an epoch case reads. */
interface EpochReport {
  readonly receipt: number;
  readonly manifest: number;
  readonly accepted: boolean;
  readonly basis: string | null;
  readonly validFrom: number | null;
  readonly validTo: number | null;
  readonly superseded: boolean | null;
  readonly reason: string;
  readonly code?: string;
}

interface Report {
  readonly ok: boolean;
  readonly code?: string;
  readonly message?: string;
  readonly keyEpoch?: EpochReport;
  readonly manifestSeal?: { sealed: boolean; authenticated: boolean; kid: string | null };
}

interface Reporter {
  readonly status: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

/** One issuance, as files a verifier can be pointed at, with the challenge it answered. */
interface Issued {
  readonly receiptPath: string;
  readonly requestBodyPath: string;
  readonly responseBodyPath: string;
  readonly nonceHex: string;
  readonly payload: ReceiptPayload;
}

/** One process, its own journal entry, and the volume it shares with whoever replaces it. */
interface Booted {
  /** The document this process serves at the manifest route, sealed by the key it was handed. */
  served(): Promise<{ bytes: Uint8Array; document: ServedDocument }>;
  /** One completion served through this process at the instant named, and the receipt it filed. */
  issue(name: string, at: number): Promise<Issued>;
  /** The journal as the volume holds it: every epoch recorded there, in the order the file states. */
  filed(): Promise<{ v: number; entries: { epk: number; kid: string; validFrom: number }[] }>;
  /** Lets go of the gateway, which is the only way a case can say this process stopped serving. */
  close(): Promise<void>;
}

interface Ground {
  readonly dir: string;
  readonly booted: Booted[];
}

const tilled: Ground[] = [];

afterEach(async () => {
  for (const each of tilled.splice(0)) {
    for (const one of each.booted) await one.close();
    await rm(each.dir, { recursive: true, force: true });
  }
});

async function write(dir: string, name: string, data: string | Buffer): Promise<string> {
  const path = join(dir, name);
  await writeFile(path, data);
  return path;
}

/**
 * A rehearsal's own ground: one temporary directory, one durable volume, one journal file beside the log.
 *
 * A second boot over the same `dir` is the rotation: the successor opens the same `receipts.log`, reads the
 * same journal, and appends its own entry to it. Every case calls this and so owns every byte it publishes.
 */
async function rehearse(): Promise<Rehearsal> {
  const dir = await mkdtemp(join(tmpdir(), 'ashaveri-epoch-journal-rotation-'));
  const volume = join(dir, 'volume');
  await mkdir(volume);
  const ground: Ground = { dir, booted: [] };
  tilled.push(ground);

  async function boot(key: SigningKey, epoch: number, opened: number, record: boolean): Promise<Booted> {
    const store = await openFileReceiptStore({ dir: volume });
    const clock = { at: opened };
    const time = fixedClock(() => clock.at, 3);
    const deployment: Deployment = mockDeployment({ key, manifestKey: SEAL_KEY, epk: epoch, time });
    // Recorded through the function the binary itself calls, from the deployment this process serves and the
    // clock its stamps are read from, so what this rehearsal settles is the shipped wiring rather than a shape
    // only a rehearsal can reach. `record` false hands it no volume, which is the state a deployment that keeps
    // no receipts is in and the one shape that must publish no history at all.
    const journal = await recordEpochForRun({
      receiptsDir: record ? volume : undefined,
      mock: false,
      deployment,
      time,
    });
    const gateway: Harness = await harness({
      credentials: [generated(CREDENTIAL, ['read', 'complete'])],
      gateway: { deployment, store, epochJournal: journal, time },
    });
    let presentations = 0;
    async function call(method: string, path: string, body: string | null): Promise<Served> {
      const nonce = nonceAt(presentations, 0x6a);
      presentations += 1;
      const response = await gateway.app.inject({
        method: method as 'GET',
        url: path,
        headers: {
          ...(body === null ? {} : { 'content-type': 'application/json' }),
          ...gateway.signFor(CREDENTIAL, method, path, body, { nonce }),
        },
        ...(body === null ? {} : { payload: body }),
      });
      return {
        statusCode: response.statusCode,
        raw: new Uint8Array(response.rawPayload),
        headers: response.headers as Record<string, string>,
        nonce,
      };
    }
    const booted: Booted = {
      async served() {
        const manifest = await call('GET', '/v1/deployment-manifest', null);
        expect(manifest.statusCode).toBe(200);
        return { bytes: manifest.raw, document: servedDocument(manifest.raw) };
      },
      async issue(name, at) {
        clock.at = at;
        const completion = await call('POST', '/v1/chat/completions', REQUEST_BODY);
        expect(completion.statusCode).toBe(200);
        const id = completion.headers['x-ashaveri-receipt-id'];
        if (typeof id !== 'string') throw new Error('a served completion carried no receipt id');
        // The receipt comes back through the route a client uses, which reads the durable volume rather than
        // the bytes this call held, so the artifact a verifier is handed is the filed one.
        const fetched = await call('GET', `/v1/receipts/${id}`, null);
        expect(fetched.statusCode).toBe(200);
        return {
          receiptPath: await write(dir, `${name}-receipt.cbor`, Buffer.from(fetched.raw)),
          requestBodyPath: await write(dir, `${name}-request.json`, REQUEST_BODY),
          responseBodyPath: await write(dir, `${name}-response.bin`, Buffer.from(completion.raw)),
          nonceHex: toHex(completion.nonce),
          payload: decodeReceipt(fetched.raw).payload,
        };
      },
      async filed() {
        return JSON.parse(await readFile(join(volume, EPOCH_JOURNAL_FILE), 'utf8')) as {
          v: number;
          entries: { epk: number; kid: string; validFrom: number }[];
        };
      },
      async close() {
        await gateway.app.close();
      },
    };
    ground.booted.push(booted);
    return booted;
  }

  return {
    boot,
    async publish(bytes: Uint8Array, name: string): Promise<string> {
      return write(dir, `${name}-manifest.cbor`, Buffer.from(bytes));
    },
    async pin(served: ServedDocument): Promise<string> {
      return write(
        dir,
        'policy.json',
        JSON.stringify({
          v: 1,
          issuers: [served.iss],
          instances: [served.ins],
          keys: Object.fromEntries(served.keys.map((row) => [row.kid, row.publicKey])),
          measurements: { [served.meas.tee]: [served.meas.m] },
          maxReceiptAgeSeconds: POLICY_WINDOW_SECONDS,
          maxEvidenceAgeSeconds: POLICY_WINDOW_SECONDS,
        }),
      );
    },
    verify(issued: Issued, manifestPath: string): Reporter {
      noteSpawn(SPAWN_DEADLINE_MS);
      const result = spawnSync(
        process.execPath,
        [
          CLI,
          'verify-receipt',
          issued.receiptPath,
          `--policy=${join(dir, 'policy.json')}`,
          `--manifest=${manifestPath}`,
          `--manifest-key=${SEAL_DESIGNATION}`,
          `--nonce=${issued.nonceHex}`,
          `--request-body=${issued.requestBodyPath}`,
          `--response-body=${issued.responseBodyPath}`,
          `--now=${new Date(READ_AT * 1000).toISOString()}`,
          '--json',
        ],
        { encoding: 'utf8', timeout: SPAWN_DEADLINE_MS, killSignal: 'SIGKILL' },
      );
      expect(result.error).toBeUndefined();
      return { status: result.status, stdout: result.stdout ?? '', stderr: result.stderr ?? '' };
    },
  };
}

/** What one route answered: its status, its bytes, its headers, and the credential's challenge. */
interface Served {
  readonly statusCode: number;
  readonly raw: Uint8Array;
  readonly headers: Record<string, string>;
  readonly nonce: Uint8Array;
}

interface Rehearsal {
  /**
   * Start a process over this rehearsal's volume. `record` is whether it keeps a journal entry for the epoch
   * it runs under: false models a deployment that was serving before any volume held its history.
   */
  boot(key: SigningKey, epoch: number, opened: number, record: boolean): Promise<Booted>;
  publish(bytes: Uint8Array, name: string): Promise<string>;
  pin(served: ServedDocument): Promise<string>;
  verify(issued: Issued, manifestPath: string): Reporter;
}

/** The document inside the seal the running process serves, read as the client reads it. */
function servedDocument(bytes: Uint8Array): ServedDocument {
  return JSON.parse(new TextDecoder().decode(decodeSealedDeploymentManifest(bytes).payloadBytes)) as ServedDocument;
}

function reportOf(run: Reporter): Report {
  expect(run.stderr, `the verifier wrote to stderr and printed ${run.stdout}`).toBe('');
  return JSON.parse(run.stdout) as Report;
}

function epochOf(report: Report): EpochReport {
  if (report.keyEpoch === undefined) {
    throw new Error(`the reporter reached no epoch adjudication: ${JSON.stringify(report)}`);
  }
  return report.keyEpoch;
}

describe('a rotation a running gateway recorded for itself', () => {
  it(
    'publishes the window it opened when it started, with no history anybody typed',
    { timeout: spawnCeilingForCalls(1, SPAWN_DEADLINE_MS) },
    async () => {
      const rehearsal = await rehearse();
      const first = await rehearsal.boot(EPOCH_ONE_KEY, 1, EPOCH_ONE_OPENS, true);
      const served = await first.served();
      // The entry is the process's own statement, and both members are on it: this is the document a client
      // reads, not a history built beside it.
      expect(served.document.keys).toEqual([
        {
          kid: toHex(EPOCH_ONE_KEY.kid),
          alg: 'Ed25519',
          publicKey: expect.any(String),
          epk: 1,
          validFrom: EPOCH_ONE_OPENS,
        },
      ]);
      expect((await first.filed()).entries).toHaveLength(1);
      const issued = await first.issue('epoch-one', EPOCH_ONE_OPENS + 60);
      expect(issued.payload.epk).toBe(1);
      const published = await rehearsal.publish(served.bytes, 'served-one');
      await rehearsal.pin(served.document);
      const run = rehearsal.verify(issued, published);
      expect(run.status, run.stderr).toBe(0);
      const epoch = epochOf(reportOf(run));
      expect(epoch).toMatchObject({
        receipt: 1,
        manifest: 1,
        accepted: true,
        // The stronger reading, from a window the deployment wrote: the weaker rule a windowless document
        // falls to would state no bound at all.
        basis: 'windows',
        validFrom: EPOCH_ONE_OPENS,
        validTo: null,
        superseded: false,
      });
      expect(reportOf(run).manifestSeal).toMatchObject({ sealed: true, authenticated: true });
    },
  );

  it(
    'leaves a receipt of the superseded epoch verifying against the served history',
    { timeout: spawnCeilingForCalls(2, SPAWN_DEADLINE_MS) },
    async () => {
      const rehearsal = await rehearse();
      const first = await rehearsal.boot(EPOCH_ONE_KEY, 1, EPOCH_ONE_OPENS, true);
      const old = await first.issue('before-rotation', ROTATION_OPENS - 10);
      // The successor takes the same volume and the same journal: the record a client re-verifies below is
      // read back out of the durable file by the process that replaced the one that wrote it.
      const second = await rehearsal.boot(EPOCH_TWO_KEY, 2, ROTATION_OPENS, true);
      const fresh = await second.issue('after-rotation', ROTATION_OPENS + 30);
      const filed = await second.filed();
      expect(filed.entries.map((row) => [row.epk, row.validFrom])).toEqual([
        [1, EPOCH_ONE_OPENS],
        [2, ROTATION_OPENS],
      ]);
      const served = await second.served();
      expect(served.document.epk).toBe(2);
      expect(served.document.keys.map((row) => [row.kid, row.epk, row.validFrom])).toEqual([
        [toHex(EPOCH_ONE_KEY.kid), 1, EPOCH_ONE_OPENS],
        [toHex(EPOCH_TWO_KEY.kid), 2, ROTATION_OPENS],
      ]);
      const published = await rehearsal.publish(served.bytes, 'served-two');
      await rehearsal.pin(served.document);
      const superseded = epochOf(reportOf(rehearsal.verify(old, published)));
      expect(superseded).toMatchObject({
        receipt: 1,
        manifest: 2,
        accepted: true,
        basis: 'windows',
        validFrom: EPOCH_ONE_OPENS,
        validTo: ROTATION_OPENS,
        superseded: true,
      });
      expect(superseded.reason).toContain('was superseded by 2');
      expect(epochOf(reportOf(rehearsal.verify(fresh, published)))).toMatchObject({
        receipt: 2,
        manifest: 2,
        accepted: true,
        basis: 'windows',
        validFrom: ROTATION_OPENS,
        validTo: null,
        superseded: false,
      });
    },
  );

  it(
    'refuses a receipt the retired key stamped after its own window closed',
    { timeout: spawnCeilingForCalls(1, SPAWN_DEADLINE_MS) },
    async () => {
      const rehearsal = await rehearse();
      const first = await rehearsal.boot(EPOCH_ONE_KEY, 1, EPOCH_ONE_OPENS, true);
      // A process still holding the retired key and stamping after the successor opened: retention of a key
      // is safe only because the window beside it ends.
      const late = await first.issue('retired-key-late', ROTATION_OPENS + 10);
      const second = await rehearsal.boot(EPOCH_TWO_KEY, 2, ROTATION_OPENS, true);
      const served = await second.served();
      const published = await rehearsal.publish(served.bytes, 'closed-window');
      await rehearsal.pin(served.document);
      const run = rehearsal.verify(late, published);
      expect(run.status).toBe(1);
      const report = reportOf(run);
      expect(report.ok).toBe(false);
      expect(report.code).toBe('MANIFEST_EPOCH_DISAGREES');
      expect(report.message).toContain('outside the epoch 1 window');
    },
  );

  it(
    'reports an epoch older than the journal rather than inventing a window for it',
    { timeout: spawnCeilingForCalls(1, SPAWN_DEADLINE_MS) },
    async () => {
      const rehearsal = await rehearse();
      const journaled = await rehearsal.boot(EPOCH_ONE_KEY, 1, EPOCH_ONE_OPENS, true);
      // A deployment that was already serving under an epoch when this volume began keeping a journal: the
      // same key, an epoch the journal was never started under, and so no entry and no window for it.
      const earlier = await rehearsal.boot(EPOCH_ONE_KEY, 5, EPOCH_ONE_OPENS - 300, false);
      const issued = await earlier.issue('older-than-the-journal', EPOCH_ONE_OPENS - 200);
      expect(issued.payload.epk).toBe(5);
      const served = await journaled.served();
      expect(served.document.keys.map((row) => row.epk)).toEqual([1]);
      const published = await rehearsal.publish(served.bytes, 'journal-naming-one-epoch');
      await rehearsal.pin(served.document);
      const run = rehearsal.verify(issued, published);
      expect(run.status).toBe(1);
      const report = reportOf(run);
      expect(report.code).toBe('MANIFEST_EPOCH_UNDECLARED');
      // The key is known and pinned, so this is not a refusal of the signature: the answer is the document's
      // silence about an epoch, and it names the epochs it does hold rather than widening to reach this one.
      expect(report.message).toContain('epoch 5 is declared by no entry of this manifest');
      expect(report.message).toContain('which publishes 1');
    },
  );
});
