import { spawnSync } from 'node:child_process';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import {
  decodeReceipt,
  decodeSealedDeploymentManifest,
  hashRequest,
  sealDeploymentManifest,
  signingKeyFromSeed,
  toBase64Url,
  toHex,
  verifyReceipt,
  verifySealedDeploymentManifest,
  type ReceiptPayload,
  type SigningKey,
} from '@ashaveri/receipt';
import { mockDeployment, type Deployment } from '../src/deployment.js';
import { openFileReceiptStore } from '../src/store.js';
import { fixedClock, generated, harness, nonceAt } from './helpers.js';
import { noteSpawn, spawnCeilingForCalls } from './support/spawn-budget.js';

/**
 * What a rotation does to the receipts a deployment had already issued, asked of the shipped path.
 *
 * `packages/sdk/test/epoch.test.ts` states the adjudication rule and runs it against a manifest a test
 * built. This file asks the question a rule table cannot answer, the one an acceptance sentence about a
 * runtime key rotation asks: take a receipt a live gateway issued and filed in its durable volume,
 * publish a second epoch beside it, and ask a verifier whether that old receipt still holds and whether
 * a receipt outside its window fails. Every step is a shipped one. The receipt is signed by a gateway
 * built in `gateway/src/server.ts`, filed by `gateway/src/store.ts`, read back over
 * `GET /v1/receipts/:id`, and adjudicated by `ashaveri verify-receipt` in its own process, so what is
 * asserted is the verdict and the exit code a reader is handed rather than what a test function returned.
 *
 * This is a scripted rehearsal and not a rotation. It runs offline, in a temporary directory, on keys
 * derived from fixed seeds. No deployment was contacted, no ceremony was performed, no real key was
 * retired, and nothing here is evidence that any of that happened anywhere. What it produces is the
 * mechanically checkable form of the sentence: a superseded-epoch receipt still verifies against both
 * retained public keys, while an out-of-epoch receipt fails.
 *
 * Two limits of the running path are recorded here rather than routed around.
 *
 * - `buildGateway` publishes one `keys[]` row carrying neither optional member, so no running gateway
 *   declares a window of its own. The published history is therefore built on the bytes a process does
 *   serve, with the two members added and nothing else moved, sealed under the manifest key that process
 *   was handed. Each row a history declares is the row a running process published, kid and public key and
 *   all, so "retaining the first public key" is a check against a served document rather than a phrase.
 * - `mockDeployment` starts at epoch 0 and `--epk` is read only on the live path, so a second epoch is
 *   named on the deployment object. Section 3 of `docs/receipt-spec.md` states that act: a gateway
 *   publishes the epoch it was started with and never changes it, so rotating a key means a new process
 *   at a higher epoch. Everything else about both processes is the shipped mock deployment.
 *
 * The reader's clock is one instant for every run, an hour after the successor opened, and the policy's
 * two freshness windows are wider than the whole rehearsal. That leaves the epoch windows the only
 * instants that can refuse a receipt here, which is the thing under test: a run refused for its age
 * would be reporting a clock rather than a rotation.
 */

/** The built offline verifier, run as a child exactly as an operator runs it. */
const CLI = fileURLToPath(new URL('../../packages/cli/dist/cli.js', import.meta.url));

/** One child's patience, the figure `test/support/spawn-budget.ts` restates for the CLI. */
const SPAWN_DEADLINE_MS = 8_000;

const MODEL = 'mock-model-1';
const CREDENTIAL = 'epoch-rotation';
const REQUEST_BODY = `{"model":"${MODEL}","messages":[{"role":"user","content":"hello again"}]}`;

function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

/** The window of the first epoch, opened before any receipt below is stamped. */
const EPOCH_ONE_OPENS = 1_771_999_400;
/** The instant the successor's window opens, and so the instant the first window closes. */
const ROTATION_OPENS = 1_772_000_600;
/** The one instant every verifier run reads its own clock at. */
const READ_AT = ROTATION_OPENS + 3_600;
/** Wide enough that no run below can be refused for its age, and stated rather than left default. */
const POLICY_WINDOW_SECONDS = 86_400;

/**
 * Both signing keys, off seeds a reader can re-derive. Fixed because a rehearsal is evidence: two runs of
 * this file hold the same keys, so a receipt and the verdict beside it are the same pair every time.
 */
const EPOCH_ONE_KEY = signingKeyFromSeed(hashRequest(utf8('ashaveri-epoch-rotation-rehearsal-first-key')));
const EPOCH_TWO_KEY = signingKeyFromSeed(hashRequest(utf8('ashaveri-epoch-rotation-rehearsal-second-key')));
/** The manifest signing key both processes were handed, and the designation every run carries. */
const SEAL_KEY = signingKeyFromSeed(hashRequest(utf8('ashaveri-epoch-rotation-rehearsal-manifest-seal-key')));
const SEAL_DESIGNATION = toBase64Url(SEAL_KEY.publicKey);

/** A `keys[]` row in the only shape a running gateway publishes it. */
interface ServedRow {
  readonly kid: string;
  readonly alg: 'Ed25519';
  readonly publicKey: string;
}

/** The document inside the seal a running process serves. */
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
  readonly receiptBytes: Uint8Array;
  readonly payload: ReceiptPayload;
}

/** A published document: where it is for the child, and what it holds for an in-process check. */
interface Published {
  readonly path: string;
  readonly bytes: Uint8Array;
}

/** One signing process, over one volume. */
interface Booted {
  /** The bytes this process's manifest route answers with, seal and all, exactly as a client reads them. */
  served(): Promise<{ bytes: Uint8Array; document: ServedDocument }>;
  /** One completion served through this process at the instant named, and the receipt it filed. */
  issue(name: string, at: number): Promise<Issued>;
  /** Lets go of the gateway, which is the only way a case can say this process stopped serving. */
  close(): Promise<void>;
}

/** A case's ground: its own directory and every process it booted inside it. */
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

/**
 * A rehearsal's own ground: one temporary directory, one durable volume, and no state shared with any
 * other case. Each case calls this and so owns every byte it publishes and every file it hands a child.
 */
async function rehearse(): Promise<Rehearsal> {
  const dir = await mkdtemp(join(tmpdir(), 'ashaveri-epoch-rotation-'));
  const volume = join(dir, 'volume');
  await mkdir(volume);
  const ground: Ground = { dir, booted: [] };
  tilled.push(ground);
  const rehearsal: Rehearsal = {
    async boot(key, epoch) {
      // A second process opening the same volume is the rotation's own shape: the records a deployment
      // issued under a retired key stay fetchable by the process that replaced it. The claim a store takes
      // on its directory names this process, so a second opening inside one case is the same holder, and a
      // case writes through one process at a time so every record has one writer.
      const store = await openFileReceiptStore({ dir: volume });
      const clock = { at: EPOCH_ONE_OPENS };
      const time = fixedClock(() => clock.at);
      const deployment: Deployment = {
        ...mockDeployment({ key, manifestKey: SEAL_KEY, time }),
        epk: epoch,
      };
      const gateway = await harness({
        credentials: [generated(CREDENTIAL, ['read', 'complete'])],
        gateway: { deployment, store, time },
      });
      let presentations = 0;
      async function call(method: string, path: string, body: string | null): Promise<Served> {
        const nonce = nonceAt(presentations, 0x52);
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
          headers: response.headers as Record<string, string | string[]>,
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
          // The receipt comes back through the route a client uses, which reads the durable volume rather
          // than the bytes this call held, so the artifact a verifier is handed is the filed one.
          const fetched = await call('GET', `/v1/receipts/${id}`, null);
          expect(fetched.statusCode).toBe(200);
          return {
            receiptPath: await write(dir, `${name}-receipt.cbor`, Buffer.from(fetched.raw)),
            requestBodyPath: await write(dir, `${name}-request.json`, REQUEST_BODY),
            responseBodyPath: await write(dir, `${name}-response.bin`, Buffer.from(completion.raw)),
            nonceHex: toHex(completion.nonce),
            receiptBytes: fetched.raw,
            payload: decodeReceipt(fetched.raw).payload,
          };
        },
        async close() {
          await gateway.app.close();
        },
      };
      ground.booted.push(booted);
      return booted;
    },
    async publishServed(bytes, name) {
      return { path: await write(dir, `${name}-manifest.cbor`, Buffer.from(bytes)), bytes };
    },
    async publishHistory(base, rows, epk, name) {
      const document = JSON.stringify({ ...base, epk, keys: rows });
      const bytes = new Uint8Array(sealDeploymentManifest(utf8(document), SEAL_KEY));
      return { path: await write(dir, `${name}-manifest.cbor`, Buffer.from(bytes)), bytes };
    },
    async pin(served) {
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
    verify(issued, manifestPath) {
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
  return rehearsal;
}

/** What one route answered: its status, its bytes, the credential's challenge, and its headers. */
interface Served {
  readonly statusCode: number;
  readonly raw: Uint8Array;
  readonly headers: Record<string, string | string[]>;
  readonly nonce: Uint8Array;
}

interface Rehearsal {
  boot(key: SigningKey, epoch: number): Promise<Booted>;
  publishServed(bytes: Uint8Array, name: string): Promise<Published>;
  publishHistory(
    base: ServedDocument,
    rows: readonly Record<string, unknown>[],
    epk: number,
    name: string,
  ): Promise<Published>;
  pin(served: ServedDocument): Promise<string>;
  verify(issued: Issued, manifestPath: string): Reporter;
}

async function write(dir: string, name: string, data: string | Buffer): Promise<string> {
  const path = join(dir, name);
  await writeFile(path, data);
  return path;
}

/** The document a running process sealed around its own statement, read as the client reads it. */
function servedDocument(bytes: Uint8Array): ServedDocument {
  return JSON.parse(new TextDecoder().decode(decodeSealedDeploymentManifest(bytes).payloadBytes)) as ServedDocument;
}

/** One published row: the served row whole, beside the epoch it signed under and when that opened. */
function windowedRow(row: ServedRow, epoch: number, validFrom: number): Record<string, unknown> {
  return { kid: row.kid, alg: row.alg, publicKey: row.publicKey, epk: epoch, validFrom };
}

/**
 * The rotation published: a history naming the first epoch and its successor beside two running
 * processes, and a policy pinning both keys.
 *
 * The successor's window opens at the instant the case names, because that one figure is what the
 * boundary, the retention and the closed-window cases disagree about.
 */
async function rotate(
  rehearsal: Rehearsal,
  first: Booted,
  second: Booted,
  opened: number,
): Promise<{ one: ServedDocument; two: ServedDocument; history: Published }> {
  const servedOne = await first.served();
  const servedTwo = await second.served();
  const history = await rehearsal.publishHistory(
    servedOne.document,
    [
      windowedRow(servedOne.document.keys[0]!, 1, EPOCH_ONE_OPENS),
      windowedRow(servedTwo.document.keys[0]!, 2, opened),
    ],
    2,
    'rotated',
  );
  await rehearsal.pin({
    ...servedOne.document,
    keys: [...servedOne.document.keys, ...servedTwo.document.keys],
  });
  return { one: servedOne.document, two: servedTwo.document, history };
}

/** The verdict of one run, with the reporter's stderr held out of it: a refusal there is a fault here. */
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

describe('a rotation published beside a deployment that is serving', () => {
  it(
    'publishes the one epoch it started with and the receipt of that epoch verifies against it',
    { timeout: spawnCeilingForCalls(1, SPAWN_DEADLINE_MS) },
    async () => {
      const rehearsal = await rehearse();
      const first = await rehearsal.boot(EPOCH_ONE_KEY, 1);
      const served = await first.served();
      // The finding the publishing helper answers to: the served row carries no epoch and no start, so a
      // window reaches a reader only through the history published beside the served document.
      expect(Object.keys(served.document.keys[0]!)).toEqual(['kid', 'alg', 'publicKey']);
      const issued = await first.issue('epoch-one', ROTATION_OPENS - 10);
      expect(issued.payload.epk).toBe(1);
      const history = await rehearsal.publishHistory(
        served.document,
        [windowedRow(served.document.keys[0]!, 1, EPOCH_ONE_OPENS)],
        1,
        'epoch-one',
      );
      await rehearsal.pin(served.document);
      const run = rehearsal.verify(issued, history.path);
      expect(run.status, run.stderr).toBe(0);
      const epoch = epochOf(reportOf(run));
      expect(epoch).toMatchObject({
        receipt: 1,
        manifest: 1,
        accepted: true,
        basis: 'windows',
        validFrom: EPOCH_ONE_OPENS,
        // The highest published epoch has no end published, and the reader reports the absence rather
        // than inventing an instant that would read as a rotation nobody declared.
        validTo: null,
        superseded: false,
      });
      expect(epoch.reason).toContain("is this deployment's current epoch");
      expect(epoch.validFrom).toBeLessThanOrEqual(issued.payload.iat);
    },
  );

  it(
    'leaves a superseded-epoch receipt verifying against both retained keys once the successor is published',
    { timeout: spawnCeilingForCalls(3, SPAWN_DEADLINE_MS) },
    async () => {
      const rehearsal = await rehearse();
      const first = await rehearsal.boot(EPOCH_ONE_KEY, 1);
      const old = await first.issue('before-rotation', ROTATION_OPENS - 10);
      // New because it goes through the volume: the receipt re-verified below is read back out of the
      // durable file store by the process that replaced the one that wrote it, and no unit-level reading
      // of the rule opens a store at all.
      const second = await rehearsal.boot(EPOCH_TWO_KEY, 2);
      const fresh = await second.issue('after-rotation', ROTATION_OPENS);
      const { one, two, history } = await rotate(rehearsal, first, second, ROTATION_OPENS);

      // Retention stated as the only thing the rotation moved: both rows are the rows two running
      // processes published, kid and public key, and the first of them is still in the document.
      const published = servedDocument(history.bytes);
      expect(published.keys.map((row) => [row.kid, row.publicKey])).toEqual([
        [one.keys[0]!.kid, one.keys[0]!.publicKey],
        [two.keys[0]!.kid, two.keys[0]!.publicKey],
      ]);
      expect(published.epk).toBe(2);

      const superseded = epochOf(reportOf(rehearsal.verify(old, history.path)));
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
      expect(superseded.reason).toContain('still retains its key');

      // The successor's first receipt is stamped at exactly the instant its own window opens, which is
      // the boundary case's other half arriving as ordinary traffic rather than as a special stamp.
      expect(fresh.payload.iat).toBe(ROTATION_OPENS);
      expect(epochOf(reportOf(rehearsal.verify(fresh, history.path)))).toMatchObject({
        receipt: 2,
        manifest: 2,
        accepted: true,
        basis: 'windows',
        validFrom: ROTATION_OPENS,
        validTo: null,
        superseded: false,
      });

      // The one thing that moved between the two verdicts on the old receipt is the published document:
      // the run above read the history beside the successor, this one reads the history before it, and the
      // artifact, the policy and the reader's instant are unchanged between them.
      const single = await rehearsal.publishHistory(one, [windowedRow(one.keys[0]!, 1, EPOCH_ONE_OPENS)], 1, 'unrotated');
      const current = epochOf(reportOf(rehearsal.verify(old, single.path)));
      expect([current.superseded, current.validTo]).toEqual([false, null]);
      expect([superseded.superseded, superseded.validTo]).toEqual([true, ROTATION_OPENS]);
      expect(current.reason).not.toBe(superseded.reason);

      // Both halves of the sentence at the signature rather than at the verdict: the retained key still
      // signs its own record and the successor's key signs its own, and neither answers for the other's
      // receipt, so what passed above was the work of the retained half and not of whichever key a reader
      // happened to try first.
      const retained = Buffer.from(one.keys[0]!.publicKey, 'base64url');
      const successor = Buffer.from(two.keys[0]!.publicKey, 'base64url');
      expect(() => verifyReceipt(old.receiptBytes, { publicKey: retained })).not.toThrow();
      expect(() => verifyReceipt(fresh.receiptBytes, { publicKey: successor })).not.toThrow();
      expect(() => verifyReceipt(old.receiptBytes, { publicKey: successor })).toThrow();
      expect(() => verifyReceipt(fresh.receiptBytes, { publicKey: retained })).toThrow();
    },
  );

  it(
    'refuses a receipt the closed window of a retained key cannot carry',
    { timeout: spawnCeilingForCalls(1, SPAWN_DEADLINE_MS) },
    async () => {
      const rehearsal = await rehearse();
      const first = await rehearsal.boot(EPOCH_ONE_KEY, 1);
      // A live process still holding the retired key, stamping after the successor opened: the bound is
      // what makes retention safe, and this is the record it exists to refuse.
      const late = await first.issue('retired-key-late', ROTATION_OPENS + 10);
      const second = await rehearsal.boot(EPOCH_TWO_KEY, 2);
      const { history } = await rotate(rehearsal, first, second, ROTATION_OPENS);
      const run = rehearsal.verify(late, history.path);
      expect(run.status).toBe(1);
      const report = reportOf(run);
      expect(report.ok).toBe(false);
      expect(report.code).toBe('MANIFEST_EPOCH_DISAGREES');
      expect(report.message).toContain('outside the epoch 1 window');
      expect(report.message).toContain(`${EPOCH_ONE_OPENS} to ${ROTATION_OPENS}`);
    },
  );

  it(
    'refuses a receipt naming an epoch this deployment never declared, under its own code',
    { timeout: spawnCeilingForCalls(1, SPAWN_DEADLINE_MS) },
    async () => {
      const rehearsal = await rehearse();
      // An epoch above the published history, signed by a key the history does retain: the reader answers
      // that this deployment claims no such epoch, a different fault from a claim that disagrees, and
      // keeping the two codes apart is the point of the adjudication. The document names epochs 1 and 2;
      // this process was started at 9, which is what an undeclared epoch is on a running deployment.
      const straying = await rehearsal.boot(EPOCH_ONE_KEY, 9);
      const issued = await straying.issue('undeclared-epoch', ROTATION_OPENS - 10);
      expect(issued.payload.epk).toBe(9);
      const second = await rehearsal.boot(EPOCH_TWO_KEY, 2);
      const { history } = await rotate(rehearsal, straying, second, ROTATION_OPENS);
      const run = rehearsal.verify(issued, history.path);
      expect(run.status).toBe(1);
      const report = reportOf(run);
      expect(report.code).toBe('MANIFEST_EPOCH_UNDECLARED');
      expect(report.message).toContain('epoch 9 is declared by no entry');
      // The refusal names what the document does publish, so a reader can tell this deployment's history
      // from a receipt that wandered off it.
      expect(report.message).toContain('which publishes 1, 2');
    },
  );
});

describe('the instant a retained window closes at', () => {
  it(
    'keeps the last second of the predecessor and hands the instant a successor opens to the successor',
    { timeout: spawnCeilingForCalls(2, SPAWN_DEADLINE_MS) },
    async () => {
      const rehearsal = await rehearse();
      const retired = await rehearsal.boot(EPOCH_ONE_KEY, 1);
      const successor = await rehearsal.boot(EPOCH_TWO_KEY, 2);
      const { history } = await rotate(rehearsal, retired, successor, ROTATION_OPENS);

      const lastSecond = await retired.issue('one-second-before', ROTATION_OPENS - 1);
      const before = rehearsal.verify(lastSecond, history.path);
      expect(before.status, before.stderr).toBe(0);
      expect(epochOf(reportOf(before))).toMatchObject({
        accepted: true,
        basis: 'windows',
        superseded: true,
        validTo: ROTATION_OPENS,
      });

      const onTheInstant = await retired.issue('exactly-at-successor-start', ROTATION_OPENS);
      expect(onTheInstant.payload.iat).toBe(ROTATION_OPENS);
      expect(onTheInstant.payload.epk).toBe(1);
      const refused = rehearsal.verify(onTheInstant, history.path);
      expect(refused.status).toBe(1);
      const report = reportOf(refused);
      expect(report.ok).toBe(false);
      expect(report.code).toBe('MANIFEST_EPOCH_DISAGREES');
      // Two runs a second of stamp apart and identical otherwise: the predecessor's window holds the
      // second before the successor opens and refuses the instant the successor opens, which is the
      // half-open direction section 4.4 of `docs/receipt-spec.md` states.
      expect(report.message).toContain(`stamped ${ROTATION_OPENS}`);
    },
  );
});

describe('a manifest that declares no windows', () => {
  it(
    'keeps the weaker rule and reports which of the two strengths admitted the receipt',
    { timeout: spawnCeilingForCalls(2, SPAWN_DEADLINE_MS) },
    async () => {
      const rehearsal = await rehearse();
      const first = await rehearsal.boot(EPOCH_ONE_KEY, 1);
      const served = await first.served();
      const issued = await first.issue('windowless', ROTATION_OPENS - 10);
      // The served bytes themselves, unpublished and unedited: this is the document a running gateway
      // actually answers with, and the only epoch in it is its own `epk`.
      const asServed = await rehearsal.publishServed(served.bytes, 'served');
      expect(Object.keys(servedDocument(asServed.bytes).keys[0]!)).toEqual(['kid', 'alg', 'publicKey']);
      await rehearsal.pin(served.document);

      const run = rehearsal.verify(issued, asServed.path);
      expect(run.status, run.stderr).toBe(0);
      const epoch = epochOf(reportOf(run));
      expect(epoch).toMatchObject({
        receipt: 1,
        manifest: 1,
        accepted: true,
        basis: 'current-epoch',
        // No window is invented for a document that states none, so both bounds stay absent rather than
        // spelled as an epoch that chose its own start.
        validFrom: null,
        validTo: null,
        superseded: false,
      });
      expect(epoch.reason).toContain('the only epoch this manifest declares');
      // Read off the route, sealed by the key the operator handed over, and authenticated: the weaker
      // reading is not an unauthenticated one.
      expect(reportOf(run).manifestSeal).toMatchObject({ sealed: true, authenticated: true });

      const second = await rehearsal.boot(EPOCH_TWO_KEY, 2);
      const { history } = await rotate(rehearsal, first, second, ROTATION_OPENS);
      const declared = epochOf(reportOf(rehearsal.verify(issued, history.path)));
      expect(declared.accepted).toBe(true);
      // The two strengths are not blurred: one run reached an admission for this artifact through a
      // window and the other through the single epoch a windowless document states, and the reporter
      // carries which of the two it used beside the verdict.
      expect(declared.basis).toBe('windows');
      expect(declared.basis).not.toBe(epoch.basis);
      expect([declared.validFrom, declared.validTo]).toEqual([EPOCH_ONE_OPENS, ROTATION_OPENS]);
      expect([epoch.validFrom, epoch.validTo]).toEqual([null, null]);
      expect(declared.reason).not.toBe(epoch.reason);
    },
  );

  it(
    'refuses a past-epoch receipt against the document one deployment serves today',
    { timeout: spawnCeilingForCalls(1, SPAWN_DEADLINE_MS) },
    async () => {
      const rehearsal = await rehearse();
      const earlier = await rehearsal.boot(EPOCH_ONE_KEY, 4);
      const issued = await earlier.issue('past-epoch-windowless', ROTATION_OPENS - 10);
      expect(issued.payload.epk).toBe(4);
      // The same key at a higher epoch, which is the state a reader meets when a deployment starts a new
      // process and publishes no windows: the key is declared and pinned, and the epoch is not.
      const today = await rehearsal.boot(EPOCH_ONE_KEY, 7);
      const served = await today.served();
      const published = await rehearsal.publishServed(served.bytes, 'served-today');
      await rehearsal.pin(served.document);
      const run = rehearsal.verify(issued, published.path);
      expect(run.status).toBe(1);
      const report = reportOf(run);
      expect(report.code).toBe('MANIFEST_EPOCH_UNDECLARED');
      // The honest reading, stated as this document's silence and not as a forgery: nothing here answers
      // for an epoch it never named, and it says so by naming the one it did.
      expect(report.message).toContain('this manifest declares one epoch, 7');
    },
  );
});

describe('a published history that breaks its own shape rules', () => {
  /**
   * The three entry-shape refusals, reached through a sealed document built from a running process's
   * served bytes.
   *
   * `packages/sdk/test/epoch.test.ts` holds each of these rules against `parseManifest` on a document a
   * test wrote. What differs here is the way a rule reaches a reader: the document arrives sealed under
   * the key the deployment was handed, so the seal is checked and holds first and the history is refused
   * anyway. A signature is not a warrant for a rotation record, and the mixed-shape row is new beside the
   * unit rule for one further reason: the entry with no members is the row a running process served,
   * copied verbatim, which is how an operator publishing a first history gets a window that never ends.
   */
  interface ShapeCase {
    readonly name: string;
    readonly rows: (first: ServedRow, second: ServedRow) => Record<string, unknown>[];
    readonly rule: RegExp;
  }

  const shapeCases: readonly ShapeCase[] = [
    {
      name: 'an entry with members beside an entry copied from the served document',
      rows: (one, second) => [{ ...one }, windowedRow(second, 2, ROTATION_OPENS)],
      rule: /names an epoch while another key in the same manifest names none/u,
    },
    {
      name: 'one epoch declared with two different starts',
      rows: (one, second) => [windowedRow(one, 1, EPOCH_ONE_OPENS), windowedRow(second, 1, ROTATION_OPENS)],
      rule: /epoch 1 is declared with two validity starts/u,
    },
    {
      name: 'epochs that do not ascend in the order their starts do',
      rows: (one, second) => [windowedRow(one, 1, ROTATION_OPENS), windowedRow(second, 2, EPOCH_ONE_OPENS)],
      rule: /epoch 2 starts at/u,
    },
  ];

  for (const one of shapeCases) {
    it(
      `refuses ${one.name} after the seal held, and reports it as an exit a reader can act on`,
      { timeout: spawnCeilingForCalls(1, SPAWN_DEADLINE_MS) },
      async () => {
        const rehearsal = await rehearse();
        const first = await rehearsal.boot(EPOCH_ONE_KEY, 1);
        const served = await first.served();
        const issued = await first.issue('before-shape-refusal', ROTATION_OPENS - 10);
        const second = await rehearsal.boot(EPOCH_TWO_KEY, 2);
        const servedTwo = await second.served();
        const broken = await rehearsal.publishHistory(
          served.document,
          one.rows(served.document.keys[0]!, servedTwo.document.keys[0]!),
          2,
          'broken-history',
        );
        // The envelope first: these very bytes verify under the designated key, so what follows is a
        // refusal of the history they carry and not of the signature around it.
        expect(() => verifySealedDeploymentManifest(broken.bytes, SEAL_KEY.publicKey)).not.toThrow();
        await rehearsal.pin({
          ...served.document,
          keys: [...served.document.keys, ...servedTwo.document.keys],
        });
        const run = rehearsal.verify(issued, broken.path);
        expect(run.status).toBe(1);
        const report = reportOf(run);
        expect(report.ok).toBe(false);
        expect(report.code).toBe('BAD_MANIFEST');
        expect(report.message).toMatch(one.rule);
        // The receipt was never the fault: the document is refused before any epoch is adjudicated, so no
        // verdict about the artifact appears in the answer at all.
        expect(report.keyEpoch).toBeUndefined();
      },
    );
  }
});
