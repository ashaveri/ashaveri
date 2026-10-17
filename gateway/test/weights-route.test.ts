import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, afterEach, describe, expect, it } from 'vitest';
import { decodeReceipt } from '@ashaveri/receipt';
import { mockDeployment, mockWeights, type Deployment } from '../src/deployment.js';
import { fromHex, sha256, toHex } from '../src/digest.js';
import { modelsFromManifest } from '../src/weights.js';
import { DEFAULT_MOCK_MODEL } from '../src/mock.js';
import { generated, harness, type Harness } from './helpers.js';

/**
 * The manifest route, addressed by the digest a receipt already carries.
 *
 * A client holding only a receipt and network access fetches the manifest at `/v1/weights/<wts>` and
 * checks that sha256(response) is the `wts` in the document it holds. That client presents no
 * credential, and the route asks for none: the digest is the address, and the one public row in the
 * route table is this exact GET. The route therefore has to serve the bytes the gateway hashed at
 * start-up rather than a rendering or a second reading of the file, and it has to answer a digest it
 * does not hold without saying whether any other digest is held. The mock deployment has no manifest
 * file behind its digests, and that state is served as the absence it is.
 */

const tempDir = mkdtempSync(join(tmpdir(), 'ashaveri-weights-route-'));
const MANIFEST = join(tempDir, 'weights-manifest.json');
/** Spaced and ordered by hand, so a re-serialization of the parsed document cannot pass as equality. */
const MANIFEST_BYTES = new TextEncoder().encode('{\n  "files": [ ],\n  "note": "the bytes, not a rendering"\n}\n');
writeFileSync(MANIFEST, MANIFEST_BYTES);

afterAll(() => {
  rmSync(tempDir, { recursive: true, force: true });
});

const CREDENTIAL = 'weights-reader';
const open: Harness[] = [];

/** One deployment from one reading: the models that carry the digest and the bytes the route serves. */
function deploymentFromFile(modelIds: readonly string[], path: string): Deployment {
  const { models, manifest } = modelsFromManifest(modelIds, path);
  return { ...mockDeployment(), models, weightsManifest: manifest };
}

/**
 * The route as a client with only a receipt reads it: no credential of any kind. The harness holds one
 * for the cases that mint and fetch a receipt, and these reads never present it.
 */
async function serve(
  h: Harness,
  path: string,
  headers: Record<string, string> = {},
): Promise<{ statusCode: number; contentType: string; body: Buffer }> {
  const response = await h.app.inject({ method: 'GET', url: path, headers });
  return {
    statusCode: response.statusCode,
    contentType: String(response.headers['content-type'] ?? ''),
    body: Buffer.from(response.rawPayload),
  };
}

/** The refusal code a JSON error body carries, or undefined where the route answers no code. */
function errorCode(json: { error?: { code?: string } } & Record<string, unknown>): string | undefined {
  return json.error?.code;
}

async function openHarness(deployment?: Deployment): Promise<Harness> {
  const h = await harness({
    credentials: [generated(CREDENTIAL, ['read', 'complete'])],
    ...(deployment === undefined ? {} : { gateway: { deployment } }),
  });
  open.push(h);
  return h;
}

afterEach(async () => {
  for (const each of open.splice(0)) await each.app.close();
});

describe('GET /v1/weights/:digest', () => {
  it('serves the exact bytes the digest was taken over, as JSON', async () => {
    const deployment = deploymentFromFile(['model-a'], MANIFEST);
    const digest = toHex(deployment.models[0]!.wts);
    const h = await openHarness(deployment);

    const served = await serve(h, `/v1/weights/${digest}`);
    expect(served.statusCode).toBe(200);
    expect(served.contentType).toContain('application/json');
    // Byte for byte the reading, not a parse and a re-encode of it.
    expect(served.body).toEqual(Buffer.from(MANIFEST_BYTES));
    expect(served.body).not.toEqual(Buffer.from(JSON.stringify(JSON.parse(Buffer.from(MANIFEST_BYTES).toString()))));
    // The claim a client makes: the path digest, the served bytes and the receipt's wts are one value.
    expect(served.body).toEqual(Buffer.from(deployment.weightsManifest!.bytes));
    expect(toHex(sha256(served.body))).toBe(digest);
  });

  it('answers a read with no credential, and a credential changes nothing', async () => {
    const deployment = deploymentFromFile(['model-a'], MANIFEST);
    const digest = toHex(deployment.models[0]!.wts);
    const h = await openHarness(deployment);
    const anonymous = await serve(h, `/v1/weights/${digest}`);
    // The route asks for no credential, so one that is presented is not verified and not needed: a
    // client holding a receipt cannot be turned away by a header it did not have to send.
    const presented = await serve(h, `/v1/weights/${digest}`, { authorization: 'Bearer not-a-credential' });
    expect(anonymous.statusCode).toBe(200);
    expect(presented.statusCode).toBe(200);
    expect(presented.body).toEqual(anonymous.body);
  });

  it('leaves every other method and path to the credential checks', async () => {
    const deployment = deploymentFromFile(['model-a'], MANIFEST);
    const digest = toHex(deployment.models[0]!.wts);
    const h = await openHarness(deployment);
    // Same path, another method: the public row names GET and does not stand for a prefix or a verb.
    const post = await h.inject({ method: 'POST', url: `/v1/weights/${digest}` });
    expect(post.statusCode).toBe(401);
    expect(errorCode(post.json)).toBe('AUTH_MALFORMED');
    // Same method, one segment past the route: an unregistered target still meets the credential
    // checks, so the allowance cannot be walked as a prefix.
    const deeper = await h.inject({ method: 'GET', url: `/v1/weights/${digest}/past-the-end` });
    expect(deeper.statusCode).toBe(401);
    expect(errorCode(deeper.json)).toBe('AUTH_MALFORMED');
    const prefix = await h.inject({ method: 'GET', url: '/v1/weights' });
    expect(prefix.statusCode).toBe(401);
    expect(errorCode(prefix.json)).toBe('AUTH_MALFORMED');
  });


  it('serves the bytes of the one reading after the file on disk changes', async () => {
    let readings = 0;
    const { models, manifest } = modelsFromManifest(['model-a'], MANIFEST, (path) => {
      readings += 1;
      return new Uint8Array(readFileSync(path));
    });
    const digest = toHex(manifest.digest);
    const h = await openHarness({ ...mockDeployment(), models, weightsManifest: manifest });

    writeFileSync(MANIFEST, '{"files":["replaced"]}');
    try {
      const first = await serve(h, `/v1/weights/${digest}`);
      const second = await serve(h, `/v1/weights/${digest}`);
      expect(first.statusCode).toBe(200);
      expect(first.body).toEqual(Buffer.from(MANIFEST_BYTES));
      expect(second.body).toEqual(first.body);
      // No request read the path: the bytes a run serves are the ones it read once at start-up.
      expect(readings).toBe(1);
    } finally {
      writeFileSync(MANIFEST, MANIFEST_BYTES);
    }
  });

  it('names the wts a receipt of this run carries', async () => {
    const deployment = deploymentFromFile([DEFAULT_MOCK_MODEL], MANIFEST);
    const digest = toHex(deployment.weightsManifest!.digest);
    const h = await openHarness(deployment);
    const payload = '{"model":"' + DEFAULT_MOCK_MODEL + '","messages":[{"role":"user","content":"hello"}]}';
    const completion = await h.app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      headers: { 'content-type': 'application/json', ...h.signFor(CREDENTIAL, 'POST', '/v1/chat/completions', payload) },
      payload,
    });
    expect(completion.statusCode).toBe(200);
    const receiptId = String(completion.headers['x-ashaveri-receipt-id']);
    const receipt = await h.app.inject({
      method: 'GET',
      url: `/v1/receipts/${receiptId}`,
      headers: h.signFor(CREDENTIAL, 'GET', `/v1/receipts/${receiptId}`, null),
    });
    expect(receipt.statusCode).toBe(200);
    const issued = decodeReceipt(new Uint8Array(receipt.rawPayload)).payload;
    expect(toHex(issued.wts)).toBe(digest);

    const served = await serve(h, `/v1/weights/${digest}`);
    expect(served.statusCode).toBe(200);
    expect(toHex(sha256(served.body)), 'the served bytes hash to the wts the receipt names').toBe(toHex(issued.wts));
  });

  it('answers an unknown digest 404, indistinguishably from a deployment that holds none', async () => {
    const holding = await openHarness(deploymentFromFile(['model-a'], MANIFEST));
    const empty = await openHarness();
    const unknown = 'ab'.repeat(32);
    const fromHolding = await serve(holding, `/v1/weights/${unknown}`);
    const fromEmpty = await serve(empty, `/v1/weights/${unknown}`);
    expect(fromHolding.statusCode).toBe(404);
    expect(fromEmpty.statusCode).toBe(404);
    expect(fromHolding.body).toEqual(fromEmpty.body);
    const body = JSON.parse(fromHolding.body.toString()) as { error: { type: string; message: string } };
    expect(body.error.type).toBe('not_found');
    expect(body.error.message).toContain(unknown);
  });

  it('answers a malformed digest 400 under the existing error shape', async () => {
    const h = await openHarness(deploymentFromFile(['model-a'], MANIFEST));
    for (const malformed of ['A'.repeat(64), 'ab'.repeat(31), 'ab'.repeat(33), 'zz'.repeat(32), 'not-a-digest']) {
      const served = await serve(h, `/v1/weights/${malformed}`);
      expect(served.statusCode, malformed).toBe(400);
      const body = JSON.parse(served.body.toString()) as { error: { type: string; message: string; code?: string } };
      expect(body.error.type).toBe('invalid_request_error');
      expect(body.error.message).toContain('64 lowercase hex');
      // No new code and no new exit path: this is the request-validation shape the other routes use.
      expect(body.error.code).toBeUndefined();
    }
  });

  it('serves no bytes behind a mock receipt, because there is no mock manifest', async () => {
    const h = await openHarness();
    const mockDigest = toHex(mockWeights(DEFAULT_MOCK_MODEL));
    const served = await serve(h, `/v1/weights/${mockDigest}`);
    expect(served.statusCode).toBe(404);
    const body = JSON.parse(served.body.toString()) as { error: { type: string } };
    expect(body.error.type).toBe('not_found');
    // The digest is well formed and is the one the mock receipt carries: the answer is about the bytes,
    // not about the spelling.
    expect(fromHex(mockDigest)).toHaveLength(32);
  });
});
