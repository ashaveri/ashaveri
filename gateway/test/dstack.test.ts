import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { FastifyInstance } from 'fastify';
import { afterAll, afterEach, describe, expect, it } from 'vitest';
import { decodeAttestation, parseSnpReport, type PlatformEvidence } from '@ashaveri/attest-core';
import { hashRequest, keyId, ReceiptError, toHex, verifyReceipt } from '@ashaveri/receipt';
import { dstackDeployment, DstackError } from '../src/dstack.js';
import { sha256 } from '../src/digest.js';
import { buildGateway } from '../src/server.js';
import { fromBase64Url, toBase64Url } from '../src/b64.js';
import type { GuestApi, GuestKey } from '../src/guest.js';

/**
 * Evidence comes from a real SEV-SNP attestation captured from a live dstack CVM
 * (the fixture @ashaveri/attest-core verifies offline against pinned AMD keys).
 * The gateway reads the measurement, the report-data binding and the runtime
 * events out of that envelope; deep signature checking is @ashaveri/cli's job.
 */
const FIXTURE = fileURLToPath(new URL('../../packages/attest-core/test/fixtures/sev-snp-attestation.bin', import.meta.url));
const captured = decodeAttestation(new Uint8Array(readFileSync(FIXTURE)));
if (captured.platform.kind !== 'sev-snp') {
  throw new Error('fixture is no longer a SEV-SNP envelope');
}
const SNP_REPORT = captured.platform.report;
const MR_CONFIG = captured.platform.mrConfig;
const MEASUREMENT = parseSnpReport(SNP_REPORT).measurement;
const COMPOSE_HASH = eventPayload(captured.stack.runtimeEvents, 'compose-hash');
const INSTANCE_ID = eventPayload(captured.stack.runtimeEvents, 'instance-id');
if (COMPOSE_HASH === null || INSTANCE_ID === null) {
  throw new Error('fixture lost its identity events');
}

function eventPayload(events: readonly { event: string; payload: Uint8Array }[], name: string): Uint8Array | null {
  return events.find((event) => event.event === name)?.payload ?? null;
}

/**
 * A minimal msgpack writer for the V1 envelope dstack 0.6 serves, so tests can
 * build evidence for any report data and any event log. Live captures use this
 * shape; the pinned fixture is the older SCALE V0 encoding.
 */
function mpBytes(values: (number | Uint8Array | number[])[]): Uint8Array {
  const out: number[] = [];
  for (const value of values) {
    if (typeof value === 'number') out.push(value);
    else if (value instanceof Uint8Array) out.push(...value);
    else out.push(...value);
  }
  return Uint8Array.from(out);
}

function mpStr(value: string): Uint8Array {
  const body = new TextEncoder().encode(value);
  if (body.length <= 31) return mpBytes([0xa0 | body.length, body]);
  if (body.length <= 0xff) return mpBytes([0xd9, body.length, body]);
  return mpBytes([0xda, (body.length >> 8) & 0xff, body.length & 0xff, body]);
}

function mpBin(value: Uint8Array): Uint8Array {
  if (value.length <= 0xff) return mpBytes([0xc4, value.length, value]);
  return mpBytes([0xc5, (value.length >> 8) & 0xff, value.length & 0xff, value]);
}

function mpMap(entries: readonly [string, Uint8Array][]): Uint8Array {
  const parts: (number | Uint8Array)[] = [0x80 | entries.length];
  for (const [key, value] of entries) {
    parts.push(mpStr(key), value);
  }
  return mpBytes(parts);
}

function mpArray(items: readonly Uint8Array[]): Uint8Array {
  return mpBytes([0x90 | items.length, ...items]);
}

/** The report-data field is 64 bytes wide and dstack zero-pads on the right. */
function padReportData(value: Uint8Array, padLeft = false): Uint8Array {
  const out = new Uint8Array(64);
  out.set(value, padLeft ? 64 - value.length : 0);
  return out;
}

interface EnvelopeArgs {
  readonly platform: PlatformEvidence;
  readonly reportData: Uint8Array;
  readonly events: readonly { event: string; payload: Uint8Array }[];
}

function platformData(platform: PlatformEvidence): Uint8Array {
  switch (platform.kind) {
    case 'sev-snp':
      return mpMap([
        ['report', mpBin(platform.report)],
        ['cert_chain', mpArray([])],
        ['mr_config', mpStr(platform.mrConfig)],
      ]);
    case 'tdx':
    case 'gcp-tdx':
      return mpMap([
        ['quote', mpBin(platform.quote)],
        ['event_log', mpArray([])],
      ]);
    case 'nitro-enclave':
      return mpMap([['nsm_quote', mpBin(platform.nsmQuote)]]);
    default:
      throw new Error(`no V1 encoder for platform kind ${platform.kind}`);
  }
}

function v1Document(args: EnvelopeArgs): Uint8Array {
  const stackData = mpMap([
    ['report_data', mpBin(args.reportData)],
    [
      'runtime_events',
      mpArray(args.events.map((event) => mpMap([['event', mpStr(event.event)], ['payload', mpBin(event.payload)], ['version', Uint8Array.from([1])]]))),
    ],
    ['config', mpStr('{}')],
  ]);
  return v1Envelope(args.platform.kind, platformData(args.platform), stackData);
}

function v1Envelope(kind: string, encodedPlatform: Uint8Array, stackData: Uint8Array): Uint8Array {
  return mpMap([
    ['version', Uint8Array.from([1])],
    ['platform', mpMap([['kind', mpStr(kind)], ['data', encodedPlatform]])],
    ['stack', mpMap([['kind', mpStr('dstack')], ['data', stackData]])],
  ]);
}

const SEED = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
const MODELS = [{ id: 'tinyllama', wts: sha256(new TextEncoder().encode('weights-manifest')) }];

class FakeGuest implements GuestApi {
  readonly attested: Uint8Array[] = [];
  readonly keyPaths: string[] = [];
  seed: Uint8Array = SEED;

  constructor(private readonly document: (reportData: Uint8Array) => Uint8Array) {}

  async getKey(path: string, purpose: string, algorithm: 'ed25519'): Promise<GuestKey> {
    this.keyPaths.push(`${path}|${purpose}|${algorithm}`);
    return { key: this.seed, signatureChain: [] };
  }

  async attest(reportData: Uint8Array): Promise<Uint8Array> {
    this.attested.push(reportData);
    return this.document(reportData);
  }
}

function snpGuest(events: readonly { event: string; payload: Uint8Array }[] = captured.stack.runtimeEvents): FakeGuest {
  return new FakeGuest((reportData) =>
    v1Document({ platform: { kind: 'sev-snp', report: SNP_REPORT, certChain: [], mrConfig: MR_CONFIG }, reportData: padReportData(reportData), events }),
  );
}

async function expectCode(fn: () => Promise<unknown>, code: DstackError['code'] | ReceiptError['code']): Promise<string> {
  try {
    await fn();
  } catch (error) {
    expect((error as { code?: string }).code).toBe(code);
    return (error as Error).message;
  }
  throw new Error(`expected ${code}, but the call succeeded`);
}

const apps: FastifyInstance[] = [];

afterEach(async () => {
  for (const app of apps.splice(0)) {
    await app.close();
  }
});

describe('dstackDeployment key material', () => {
  it('signs with the key the guest derives, under the default path', async () => {
    const guest = snpGuest();
    const deployment = await dstackDeployment({
      client: guest,
      models: MODELS,
      evidenceBaseUrl: 'https://inference.ashaveri.test/v1',
    });
    expect(guest.keyPaths).toEqual(['/ashaveri/receipt||ed25519']);
    expect(toHex(deployment.key.privateKey)).toBe(toHex(SEED));
    expect(toHex(keyId(deployment.key.publicKey))).toBe(toHex(deployment.key.kid));
  });

  it('honours an explicit key path and purpose', async () => {
    const guest = snpGuest();
    await dstackDeployment({
      client: guest,
      models: MODELS,
      evidenceBaseUrl: 'https://inference.ashaveri.test/v1',
      keyPath: '/ashaveri/receipt-2',
      keyPurpose: 'epk-1',
    });
    expect(guest.keyPaths).toEqual(['/ashaveri/receipt-2|epk-1|ed25519']);
  });

  it('refuses derived material that is not an Ed25519 seed', async () => {
    const guest = snpGuest();
    guest.seed = new Uint8Array(16);
    await expectCode(
      () =>
        dstackDeployment({
          client: guest,
          models: MODELS,
          evidenceBaseUrl: 'https://inference.ashaveri.test/v1',
        }),
      'BAD_SIGNING_KEY',
    );
  });
});

describe('dstackDeployment measurement', () => {
  it('publishes the captured SNP launch digest and derives its identity from the event log', async () => {
    const deployment = await dstackDeployment({
      client: snpGuest(),
      models: MODELS,
      evidenceBaseUrl: 'https://inference.ashaveri.test/v1',
    });
    expect(deployment.tee).toBe('snp');
    expect(deployment.measurement.length).toBe(48);
    expect(toHex(deployment.measurement)).toBe(toHex(MEASUREMENT));
    expect(deployment.issuer).toBe(`dstack-${toHex(COMPOSE_HASH).slice(0, 12)}`);
    expect(deployment.instance).toBe(toHex(INSTANCE_ID));
  });

  it('measures a TDX deployment from the quote MRTD', async () => {
    const mrTd = Uint8Array.from({ length: 48 }, (_, i) => 0xa0 + (i % 32));
    const quote = new Uint8Array(1024);
    quote.set(mrTd, 0xb8);
    const reportData = sha256(new TextEncoder().encode('ashaveri:deployment-evidence:v1'));
    const guest = new FakeGuest(() =>
      v1Document({
        platform: { kind: 'tdx', quote, eventLog: [] },
        reportData: padReportData(reportData),
        events: [],
      }),
    );
    const deployment = await dstackDeployment({
      client: guest,
      models: MODELS,
      evidenceBaseUrl: 'https://inference.ashaveri.test/v1',
      tee: 'tdx',
      issuer: 'ashaveri-test',
      instance: 'tdx-instance',
    });
    expect(deployment.tee).toBe('tdx');
    expect(toHex(deployment.measurement)).toBe(toHex(mrTd));
  });

  it('stops when the platform kind carries no defined measurement', async () => {
    const guest = new FakeGuest((reportData) =>
      v1Document({
        platform: { kind: 'nitro-enclave', nsmQuote: new Uint8Array(8) },
        reportData: padReportData(reportData),
        events: [],
      }),
    );
    await expectCode(
      () => dstackDeployment({ client: guest, models: MODELS, evidenceBaseUrl: 'https://x.test/v1' }),
      'PLATFORM_UNSUPPORTED',
    );
  });

  it('stops when the evidence contradicts the configured TEE', async () => {
    const guest = snpGuest();
    await expectCode(
      () =>
        dstackDeployment({
          client: guest,
          models: MODELS,
          evidenceBaseUrl: 'https://inference.ashaveri.test/v1',
          tee: 'tdx',
        }),
      'TEE_MISMATCH',
    );
  });

  it('stops when the event log carries no identity to publish', async () => {
    const guest = snpGuest([{ event: 'system-ready', payload: new Uint8Array(0) }]);
    const message = await expectCode(
      () => dstackDeployment({ client: guest, models: MODELS, evidenceBaseUrl: 'https://x.test/v1' }),
      'IDENTITY_MISSING',
    );
    expect(message).toContain('--issuer');
  });
});

describe('dstackDeployment evidence binding', () => {
  it('stops when the served evidence is bound to different report data', async () => {
    const guest = new FakeGuest(() =>
      v1Document({
        platform: { kind: 'sev-snp', report: SNP_REPORT, certChain: [], mrConfig: MR_CONFIG },
        reportData: new Uint8Array(64).fill(0x7e),
        events: captured.stack.runtimeEvents,
      }),
    );
    const message = await expectCode(
      () => dstackDeployment({ client: guest, models: MODELS, evidenceBaseUrl: 'https://x.test/v1' }),
      'EVIDENCE_REPORT_DATA_MISMATCH',
    );
    expect(message).toContain('not bound to report data');
  });

  it('accepts left padding as well as right padding', async () => {
    const guest = new FakeGuest((reportData) =>
      v1Document({
        platform: { kind: 'sev-snp', report: SNP_REPORT, certChain: [], mrConfig: MR_CONFIG },
        reportData: padReportData(reportData, true),
        events: captured.stack.runtimeEvents,
      }),
    );
    const deployment = await dstackDeployment({
      client: guest,
      models: MODELS,
      evidenceBaseUrl: 'https://inference.ashaveri.test/v1',
    });
    expect(deployment.issuer).toContain('dstack-');
  });

  it('stops on bytes that are not an attestation envelope', async () => {
    const guest = new FakeGuest(() => new Uint8Array([9, 9, 9, 9]));
    await expectCode(
      () => dstackDeployment({ client: guest, models: MODELS, evidenceBaseUrl: 'https://x.test/v1' }),
      'EVIDENCE_UNDECODABLE',
    );
  });

  it('serves the same bytes twice from one quote', async () => {
    const guest = snpGuest();
    const deployment = await dstackDeployment({
      client: guest,
      models: MODELS,
      evidenceBaseUrl: 'https://inference.ashaveri.test/v1',
    });
    const reportData = sha256(new TextEncoder().encode('a client nonce and request'));
    const first = await deployment.attestation(reportData);
    const second = await deployment.attestation(reportData);
    expect(second.document).toEqual(first.document);
    expect(first.url).toBe(`https://inference.ashaveri.test/v1/attestation?report_data=${toHex(reportData)}`);
    // One quote for the deployment itself at startup, one for this report data.
    expect(guest.attested.length).toBe(2);
    const standing = await deployment.attestation(null);
    expect(toHex(standing.document)).not.toBe(toHex(first.document));
    expect(standing.url).toContain(`report_data=${toHex(guest.attested[0]!)}`);
    expect(guest.attested.length).toBe(2);
  });
});

describe('gateway on a live deployment', () => {
  it('publishes the hardware measurement in the manifest', async () => {
    const app = buildGateway({
      deployment: await dstackDeployment({
        client: snpGuest(),
        models: MODELS,
        evidenceBaseUrl: 'https://inference.ashaveri.test/v1',
      }),
    });
    apps.push(app);
    const res = await app.inject({ method: 'GET', url: '/v1/deployment-manifest' });
    const manifest = res.json() as { meas: { tee: string; m: string }; models: { id: string; wts: string }[] };
    expect(manifest.meas).toEqual({ tee: 'snp', m: toHex(MEASUREMENT) });
    expect(manifest.meas.m).toMatch(/^[0-9a-f]{96}$/);
    expect(manifest.models[0]).toEqual({ id: 'tinyllama', wts: toHex(MODELS[0]!.wts) });
  });

  it('issues receipts whose evidence is fetchable and digest-matching', async () => {
    const guest = snpGuest();
    const deployment = await dstackDeployment({
      client: guest,
      models: MODELS,
      evidenceBaseUrl: 'https://inference.ashaveri.test/v1',
    });
    const app = buildGateway({ deployment });
    apps.push(app);
    const nonce = new Uint8Array(16).fill(0x42);
    const body = '{"model":"tinyllama","messages":[{"role":"user","content":"hello"}]}';
    const completion = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      headers: { 'content-type': 'application/json', 'x-ashaveri-nonce': toBase64Url(nonce) },
      payload: body,
    });
    expect(completion.statusCode).toBe(200);
    const receiptId = completion.headers['x-ashaveri-receipt-id'] as string;
    const receipt = await app.inject({ method: 'GET', url: `/v1/receipts/${receiptId}` });
    expect(receipt.statusCode).toBe(200);

    const manifest = (await app.inject({ method: 'GET', url: '/v1/deployment-manifest' })).json() as {
      keys: { publicKey: string }[];
    };
    const verified = verifyReceipt(new Uint8Array(receipt.rawPayload), {
      publicKey: fromBase64Url(manifest.keys[0]!.publicKey),
      expectedNonce: nonce,
    });
    const payload = verified.payload;
    expect(payload.mdl).toBe('tinyllama');
    expect(toHex(payload.wts)).toBe(toHex(MODELS[0]!.wts));
    expect(toHex(payload.req)).toBe(toHex(hashRequest(new TextEncoder().encode(body))));
    expect(toHex(payload.res)).toBe(toHex(sha256(new Uint8Array(completion.rawPayload))));
    expect(toHex(payload.meas.m)).toBe(toHex(MEASUREMENT));

    const served = await app.inject({ method: 'GET', url: new URL(payload.att.url).pathname + new URL(payload.att.url).search });
    expect(served.statusCode).toBe(200);
    expect(served.headers['content-type']).toContain('application/octet-stream');
    expect(toHex(sha256(new Uint8Array(served.rawPayload)))).toBe(toHex(payload.att.d));
  });
});

/**
 * What a deployment serves has to hold up away from it. This runs the bytes from
 * /v1/attestation through @ashaveri/cli against the pinned AMD keys, so the
 * measurement the gateway puts in every receipt is the measurement an offline
 * verifier accepts, and a pin that names a different build is rejected.
 */
const FIXTURE_DIR = fileURLToPath(new URL('../../packages/attest-core/test/fixtures/', import.meta.url));
const CLI = fileURLToPath(new URL('../../packages/cli/dist/cli.js', import.meta.url));
const AMD_KEYS = [
  '--ark', `${FIXTURE_DIR}amd-ark-milan.pem`,
  '--ask', `${FIXTURE_DIR}sev-snp-ask.pem`,
  '--vcek', `${FIXTURE_DIR}sev-snp-vcek.pem`,
];
const VERIFY_NOW = '2026-09-10T00:00:00Z';
const evidenceDir = mkdtempSync(join(tmpdir(), 'ashaveri-evidence-'));

afterAll(() => {
  rmSync(evidenceDir, { recursive: true, force: true });
});

async function servedEvidence(): Promise<Uint8Array> {
  const app = buildGateway({
    deployment: await dstackDeployment({
      client: snpGuest(),
      models: MODELS,
      evidenceBaseUrl: 'https://inference.ashaveri.test/v1',
    }),
  });
  apps.push(app);
  // The guest zero-pads the caller's 32-byte request on the right, so asking for the
  // first half of the fixture's own binding returns the bytes its signature covers.
  const binding = toHex(parseSnpReport(SNP_REPORT).reportData.subarray(0, 32));
  const response = await app.inject({ method: 'GET', url: `/v1/attestation?report_data=${binding}` });
  expect(response.statusCode).toBe(200);
  return new Uint8Array(response.rawPayload);
}

function verifyWithCli(document: Uint8Array, pins: readonly string[]): { status: number | null; stdout: string; stderr: string } {
  const path = join(evidenceDir, 'evidence.bin');
  writeFileSync(path, document);
  const result = spawnSync(
    process.execPath,
    [CLI, 'verify', path, ...AMD_KEYS, '--now', VERIFY_NOW, ...pins],
    { encoding: 'utf8' },
  );
  expect(result.error).toBeUndefined();
  return { status: result.status, stdout: result.stdout ?? '', stderr: result.stderr ?? '' };
}

describe('offline verification of served evidence', () => {
  it('accepts the measurement and compose hash the deployment publishes', async () => {
    const outcome = verifyWithCli(await servedEvidence(), [
      '--expect-measurement', toHex(MEASUREMENT),
      '--expect-compose-hash', toHex(COMPOSE_HASH),
    ]);
    expect(outcome.stderr).toBe('');
    expect(outcome.status).toBe(0);
    expect(outcome.stdout).toContain('SEV-SNP attestation verified (envelope v1)');
    expect(outcome.stdout).toContain('quote signature:  verified');
    expect(outcome.stdout.match(/pinned:/g)).toHaveLength(2);
  });

  it('rejects the same evidence when a pin names a different build', async () => {
    const document = await servedEvidence();
    const mispinned = `8${toHex(MEASUREMENT).slice(1)}`;
    const outcome = verifyWithCli(document, ['--expect-measurement', mispinned]);
    expect(outcome.status).toBe(1);
    expect(outcome.stderr).toContain('verification failed (PIN_MISMATCH)');
    expect(outcome.stderr).toContain(`--expect-measurement pins ${mispinned}`);
  });
});
