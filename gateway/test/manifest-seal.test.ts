import { afterEach, describe, expect, it } from 'vitest';
import {
  ReceiptError,
  decodeCoseSign1,
  hashRequest,
  isSealedDeploymentManifest,
  signingKeyFromSeed,
  toHex,
  verifySealedDeploymentManifest,
} from '@ashaveri/receipt';
import { mockDeployment, type Deployment } from '../src/deployment.js';
import { generated, harness, type Harness } from './helpers.js';

/**
 * What the manifest route serves, in each of the two states a deployment can be in.
 *
 * One document sits behind both shapes, and the first pair of cases below holds that literally: the
 * bytes inside the signature are the bytes the same deployment serves when it has no seal, so a client
 * that verifies a signature is verifying the document it would otherwise have had to take on trust, and
 * a deployment that reformats its own manifest has to reseal it. Which shape a process serves is decided
 * by whether an operator handed it a key for the purpose, and the unsigned shape is a state a real
 * deployment is in rather than a failure, which is why it is served and not refused.
 *
 * The two keys are two on purpose. A wrapper that verified under the receipt signing key would let one
 * compromised signing key rewrite the rotation record meant to retire it, so the cases here check that
 * the receipt key is refused as a seal key as well as that the seal key verifies.
 */

const CREDENTIAL = 'manifest-route';
const RECEIPT_KEY = signingKeyFromSeed(hashRequest(new TextEncoder().encode('ashaveri-manifest-route-receipt-key')));
const MANIFEST_KEY = signingKeyFromSeed(hashRequest(new TextEncoder().encode('ashaveri-manifest-route-seal-key')));

const open: Harness[] = [];

/** One deployment per shape, from the same receipt key, so their documents are the same document. */
function deployment(withSeal: boolean): Deployment {
  return mockDeployment({ key: RECEIPT_KEY, ...(withSeal ? { manifestKey: MANIFEST_KEY } : {}) });
}

async function serve(withSeal: boolean): Promise<{ statusCode: number; contentType: string; bytes: Uint8Array }> {
  const h = await harness({
    credentials: [generated(CREDENTIAL, ['read', 'complete'])],
    gateway: { deployment: deployment(withSeal) },
  });
  open.push(h);
  const res = await h.app.inject({
    method: 'GET',
    url: '/v1/deployment-manifest',
    headers: h.signFor(CREDENTIAL, 'GET', '/v1/deployment-manifest', null),
  });
  return {
    statusCode: res.statusCode,
    contentType: String(res.headers['content-type'] ?? ''),
    bytes: new Uint8Array(res.rawPayload),
  };
}

/** The refusal a reader answers with, so a case can name the code and the message it owes. */
function refusal(fn: () => unknown): ReceiptError {
  try {
    fn();
  } catch (err) {
    if (err instanceof ReceiptError) return err;
    throw err;
  }
  throw new Error('the reader accepted bytes this case expects it to refuse');
}

afterEach(async () => {
  for (const each of open.splice(0)) {
    await each.app.close();
  }
});

describe('the deployment manifest route', () => {
  it('serves the plain JSON document when no manifest key was handed over', async () => {
    const served = await serve(false);
    expect(served.statusCode).toBe(200);
    expect(served.contentType).toContain('application/json');
    expect(isSealedDeploymentManifest(served.bytes)).toBe(false);
    const manifest = JSON.parse(new TextDecoder().decode(served.bytes)) as {
      v: number;
      iss: string;
      keys: { kid: string; alg: string }[];
    };
    expect(manifest.v).toBe(1);
    expect(manifest.iss).toBe('ashaveri-mock');
    expect(manifest.keys).toEqual([{ kid: toHex(RECEIPT_KEY.kid), alg: 'Ed25519', publicKey: expect.any(String) }]);
  });

  it('signs exactly the bytes the same deployment serves unsigned', async () => {
    const sealed = await serve(true);
    const plain = await serve(false);
    expect(sealed.statusCode).toBe(200);
    expect(sealed.contentType).toContain('application/cose');
    expect(isSealedDeploymentManifest(sealed.bytes)).toBe(true);
    const seal = verifySealedDeploymentManifest(sealed.bytes, MANIFEST_KEY.publicKey);
    // The whole of the claim, checked as bytes: no re-encode, no key order chosen on the way, so what a
    // client verifies is what a reader of the plain route gets.
    expect(toHex(seal.payloadBytes)).toBe(toHex(plain.bytes));
  });

  it('names a signing key that is not the one signing receipts', async () => {
    const sealed = await serve(true);
    const seal = verifySealedDeploymentManifest(sealed.bytes, MANIFEST_KEY.publicKey);
    expect(toHex(seal.header.kid)).toBe(toHex(MANIFEST_KEY.kid));
    expect(toHex(seal.header.kid)).not.toBe(toHex(RECEIPT_KEY.kid));
    expect(refusal(() => verifySealedDeploymentManifest(sealed.bytes, RECEIPT_KEY.publicKey)).code).toBe(
      'KID_MISMATCH',
    );
  });

  it('is refused by the receipt reader, which is what the content type is for', async () => {
    const sealed = await serve(true);
    // A valid `COSE_Sign1` over four elements, and both documents verify cleanly under a key the reader
    // trusted, so the field that separates an attestation about one response from a deployment's
    // statement about itself is the protected type, and it has to be read before any key is consulted.
    const confusion = refusal(() => decodeCoseSign1(sealed.bytes));
    expect(confusion.code).toBe('BAD_PROTECTED_HEADER');
    expect(confusion.message).toContain('typ=ashaveri/deployment-manifest');
  });

  it('reads as a tampered body the moment one byte of the document is moved', async () => {
    const sealed = await serve(true);
    const at = Buffer.from(sealed.bytes).indexOf(Buffer.from('ashaveri-mock'));
    expect(at).toBeGreaterThan(-1);
    const moved = sealed.bytes.slice();
    moved[at + 3] = 0x58;
    expect(refusal(() => verifySealedDeploymentManifest(moved, MANIFEST_KEY.publicKey)).code).toBe(
      'INVALID_SIGNATURE',
    );
  });

  it('answers the same admission checks whatever shape the document takes', async () => {
    const h = await harness({
      credentials: [generated(CREDENTIAL, ['read', 'complete'])],
      gateway: { deployment: deployment(true) },
    });
    open.push(h);
    const anonymous = await h.app.inject({ method: 'GET', url: '/v1/deployment-manifest' });
    expect(anonymous.statusCode).toBe(401);
    const admitted = await h.app.inject({
      method: 'GET',
      url: '/v1/deployment-manifest',
      headers: h.signFor(CREDENTIAL, 'GET', '/v1/deployment-manifest', null),
    });
    expect(admitted.statusCode).toBe(200);
    expect(isSealedDeploymentManifest(new Uint8Array(admitted.rawPayload))).toBe(true);
  });
});
