import { describe, expect, it } from 'vitest';
import { ReceiptError, decodeReceipt, toHex } from '@ashaveri/receipt';
import { SdkError } from '../src/errors.js';
import { readDeploymentManifest } from '../src/manifest-auth.js';
import { GatewaySession } from '../src/gateway.js';
import type { AshaveriPolicy } from '../src/policy.js';
import { toBase64Url } from '../src/b64.js';
import {
  MANIFEST_BASE_URL,
  MANIFEST_KEY,
  RECEIPT_KEY,
  STRANGER_KEY,
  manifestTransport,
  pinMap,
  plainManifest,
  receiptFor,
  sealedManifest,
} from './manifest-documents.js';

/**
 * What a client concludes about the document a deployment publishes about itself.
 *
 * Two facts decide it, and they are independent: what arrived, a seal or a plain document, and what this
 * client designated, a manifest signing key or none. A seal that does not hold is fatal for a client that
 * designated a key, because a body edited after it was signed is evidence about nothing, and it is exactly
 * that client's designation that makes the edit visible. A document this client cannot authenticate is
 * still read, because the pins inside it are ones a verifier checks receipts against and an unverified
 * manifest can fail a check; what it cannot do is open one.
 *
 * The refusals are separate codes because the deployments are different. One served a body its own key no
 * longer covers, which is what tampering looks like. One served a document with no signature while being
 * pointed at a signing identity, which is a misconfiguration. And one named a key this policy stores under
 * an id that key does not answer to, which is a fault in the policy.
 */

const IAT = 1_772_000_000;
const NONCE = new Uint8Array(16).fill(0x5a);
const RESPONSE_BYTES = new TextEncoder().encode('manifest-seal-response');

async function failureFrom(promise: Promise<unknown>): Promise<SdkError | ReceiptError> {
  try {
    await promise;
  } catch (err) {
    if (err instanceof SdkError || err instanceof ReceiptError) return err;
    throw err;
  }
  throw new Error('the client accepted a document this case expects it to refuse');
}

/** The same question of the reader itself, for the case that never reaches a transport. */
function failure(fn: () => unknown): SdkError | ReceiptError {
  try {
    fn();
  } catch (err) {
    if (err instanceof SdkError || err instanceof ReceiptError) return err;
    throw err;
  }
  throw new Error('the reader accepted a document this case expects it to refuse');
}

/** One session's two answers about the same bytes: the document, and what it is worth. */
async function read(manifestBytes: Uint8Array, policy?: AshaveriPolicy) {
  const session = new GatewaySession(MANIFEST_BASE_URL, { fetchImpl: manifestTransport(manifestBytes), policy });
  return {
    manifest: await session.manifest(),
    authentication: await session.manifestAuthentication(),
  };
}

/** One character of the issuer inside a finished seal, moved, with the envelope left whole. */
function tamper(bytes: Uint8Array): Uint8Array {
  const at = Buffer.from(bytes).indexOf(Buffer.from('dpl-manifestseal'));
  if (at < 0) throw new Error('the text this suite tampers with is not in the document');
  const out = bytes.slice();
  out[at + 15] = 0x78;
  return out;
}

describe('a manifest with no seal', () => {
  it('is parsed, kept, and reported as resting on nothing', async () => {
    const { manifest, authentication } = await read(plainManifest());
    expect(manifest.iss).toBe('dpl-manifestseal');
    expect(authentication).toEqual({
      sealed: false,
      authenticated: false,
      kid: null,
      demanded: false,
      advisory: expect.stringContaining('the deployment manifest is unsigned'),
    });
    expect(authentication.advisory).toContain('trust-on-first-use');
  });

  it('is refused when the policy designated somebody to sign it', async () => {
    const err = await failureFrom(read(plainManifest(), { manifestKeys: pinMap(MANIFEST_KEY) }));
    expect(err).toBeInstanceOf(SdkError);
    expect(err.code).toBe('MANIFEST_NOT_AUTHENTICATED');
    expect(err.message).toContain('designates 1 key for signing manifests');
  });

  it('is refused the same way when the key it lacks belongs to a stranger', () => {
    // Called on the reader itself rather than through a session, because this is the one refusal that
    // needs no transport: the document is unsigned and the policy asked for a signer.
    const err = failure(() => readDeploymentManifest(plainManifest(), { manifestKeys: pinMap(STRANGER_KEY) }));
    expect(err.code).toBe('MANIFEST_NOT_AUTHENTICATED');
  });
});

describe('a manifest under seal', () => {
  it('authenticates against the key the policy designates for the purpose', async () => {
    const { manifest, authentication } = await read(sealedManifest(), { manifestKeys: pinMap(MANIFEST_KEY) });
    expect(authentication).toEqual({
      sealed: true,
      authenticated: true,
      kid: toHex(MANIFEST_KEY.kid),
      demanded: true,
      advisory: null,
    });
    expect(manifest.iss).toBe('dpl-manifestseal');
    expect(manifest.keys).toHaveLength(1);
  });

  it('says the same thing the plain copy of itself says, so the wrapper adds an authentication and changes no reading', async () => {
    const document = plainManifest();
    const plain = await read(document);
    const sealed = await read(sealedManifest({}, MANIFEST_KEY), { manifestKeys: pinMap(MANIFEST_KEY) });
    expect(sealed.manifest).toEqual(plain.manifest);
  });

  it('is read but not believed when the policy designates nothing', async () => {
    const { authentication } = await read(sealedManifest());
    expect(authentication.sealed).toBe(true);
    expect(authentication.authenticated).toBe(false);
    expect(authentication.demanded).toBe(false);
    expect(authentication.kid).toBe(toHex(MANIFEST_KEY.kid));
    expect(authentication.advisory).toContain('nothing checked the seal');
  });

  it('will not be believed by a key the policy pins for receipts', async () => {
    // The seal here was made by the deployment's own receipt key, which is pinned. A manifest verified
    // under it would let one compromised signing key rewrite the rotation history meant to retire it,
    // which is why the two maps exist apart rather than as two spellings of the same set.
    const sealedByReceiptKey = sealedManifest({}, RECEIPT_KEY);
    const { authentication } = await read(sealedByReceiptKey, { keys: pinMap(RECEIPT_KEY) });
    expect(authentication.authenticated).toBe(false);
    expect(authentication.kid).toBe(toHex(RECEIPT_KEY.kid));
    expect(authentication.advisory).toContain('names no manifest signing key');

    // The same wrapper beside a manifest pin that is not for this kid is a refusal, not a quieter
    // reading of the same fact: the caller designated a signer and was shown a different one.
    const err = await failureFrom(read(sealedByReceiptKey, { manifestKeys: pinMap(STRANGER_KEY) }));
    expect(err.code).toBe('MANIFEST_NOT_AUTHENTICATED');
    expect(err.message).toContain(toHex(RECEIPT_KEY.kid));
  });

  it('is fatal when the body no longer matches the seal, and only the pin makes that visible', async () => {
    const moved = tamper(sealedManifest());
    // Unpinned, the tampered document still parses and is handed over with its status stated, because a
    // client with no signing key has no way to notice the edit at all. Pinned, the same bytes are a
    // refusal, and the refusal is about the signature rather than about the manifest's shape.
    const unpinned = await read(moved);
    expect(unpinned.manifest.iss).toBe('dpl-manifestseax');
    expect(unpinned.authentication.authenticated).toBe(false);
    const err = await failureFrom(read(moved, { manifestKeys: pinMap(MANIFEST_KEY) }));
    expect(err.code).toBe('MANIFEST_SIGNATURE_INVALID');
    expect(err.message).toContain('does not verify under the key pinned for it');
  });

  it('names a policy that stores a key under an id it does not answer to', async () => {
    const err = await failureFrom(
      read(sealedManifest(), { manifestKeys: { [toHex(MANIFEST_KEY.kid)]: toBase64Url(STRANGER_KEY.publicKey) } }),
    );
    expect(err.code).toBe('MANIFEST_KEY_NOT_PINNED');
    expect(err.message).toContain('the pin and the document disagree');
  });

  it('keeps the format refusal when the bytes are a signed receipt wearing the manifest route', async () => {
    const aReceipt = receiptFor({ key: RECEIPT_KEY, epoch: 0, issuedAt: IAT, nonce: NONCE });
    const err = await failureFrom(read(aReceipt, { manifestKeys: pinMap(MANIFEST_KEY) }));
    expect(err).toBeInstanceOf(ReceiptError);
    expect(err.code).toBe('BAD_PROTECTED_HEADER');
    expect(err.message).toContain('typ=ashaveri/receipt');
  });

  it('answers a manifest that does not parse with the parse code, sealed or not', async () => {
    const err = await failureFrom(read(sealedManifest({ iss: '' }), { manifestKeys: pinMap(MANIFEST_KEY) }));
    expect(err.code).toBe('BAD_MANIFEST');
    expect(err.message).toContain('iss must be a non-empty string');
  });
});

describe('one document behind both answers', () => {
  it('fetches the manifest once for the verdict and for the status', async () => {
    const calls: string[] = [];
    const fetchImpl: typeof fetch = async (input) => {
      calls.push(typeof input === 'string' ? input : new Request(input).url);
      return new Response(sealedManifest(), { status: 200 });
    };
    const session = new GatewaySession(MANIFEST_BASE_URL, {
      fetchImpl,
      policy: { manifestKeys: pinMap(MANIFEST_KEY) },
    });
    expect((await session.manifest()).iss).toBe('dpl-manifestseal');
    expect((await session.manifestAuthentication()).authenticated).toBe(true);
    expect(calls).toEqual([`${MANIFEST_BASE_URL}/deployment-manifest`]);
  });

  it('verifies a receipt the same way through either shape of the manifest that declares its key', async () => {
    const receipt = receiptFor({ key: RECEIPT_KEY, epoch: 0, issuedAt: IAT, nonce: NONCE });
    const payload = decodeReceipt(receipt).payload;
    for (const [shape, manifestBytes] of [
      ['plain', plainManifest()],
      ['sealed', sealedManifest()],
    ] as const) {
      const session = new GatewaySession(MANIFEST_BASE_URL, {
        fetchImpl: manifestTransport(manifestBytes),
        policy: { issuers: ['dpl-manifestseal'], keys: pinMap(RECEIPT_KEY) },
      });
      const verified = await session.verifyReceipted({
        receiptBytes: receipt,
        nonce: NONCE,
        requestHash: payload.req,
        responseHash: payload.res,
        responseBytes: RESPONSE_BYTES,
        now: IAT * 1000,
      });
      expect(toHex(verified.header.kid), shape).toBe(toHex(RECEIPT_KEY.kid));
      const authentication = await session.manifestAuthentication();
      expect(authentication.sealed, shape).toBe(shape === 'sealed');
      // Neither case designated a manifest signing key, so neither can claim one either way: what
      // differs is only whether a caller who asks could have been given an authenticated document.
      expect(authentication.authenticated, shape).toBe(false);
    }
  });

  it('answers with the pin code when a receipt key is missing rather than with the epoch code', async () => {
    const receipt = receiptFor({ key: STRANGER_KEY, epoch: 0, issuedAt: IAT, nonce: NONCE });
    const payload = decodeReceipt(receipt).payload;
    const session = new GatewaySession(MANIFEST_BASE_URL, {
      fetchImpl: manifestTransport(sealedManifest()),
      policy: { keys: pinMap(STRANGER_KEY) },
    });
    const err = await failureFrom(
      session.verifyReceipted({
        receiptBytes: receipt,
        nonce: NONCE,
        requestHash: payload.req,
        responseHash: payload.res,
        responseBytes: RESPONSE_BYTES,
        now: IAT * 1000,
      }),
    );
    expect(err.code).toBe('MANIFEST_KEY_NOT_PINNED');
    expect(err.message).toContain('does not match the pinned key');
  });
});
