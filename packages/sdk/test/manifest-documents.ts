import {
  generateSigningKey,
  hashRequest,
  issueReceipt,
  sealDeploymentManifest,
  signingKeyFromSeed,
  toHex,
  type ReceiptPayload,
  type ReceiptPayloadV1,
  type SigningKey,
} from '@ashaveri/receipt';
import { toBase64Url } from '../src/b64.js';

/**
 * The deployment manifest in each of the two shapes a client can be handed it.
 *
 * Both suites that read a manifest need the same document, sealed and unsealed, and a sealed manifest
 * is that document and nothing else: the wrapper signs the bytes it was handed, so building the
 * document twice, once for each shape, would leave the two cases comparing copies rather than the same
 * bytes. This module builds the document once and wraps it, which is also how a deployment does it.
 *
 * The signing keys are derived from readable phrases rather than written as key material, the way the
 * gateway's suites do it. They stand for deployment keys in a test and protect nothing.
 */

export const ISSUER = 'dpl-manifestseal';
export const INSTANCE = 'cvm-i-manifestseal';
export const MODEL = 'manifest-seal-model';
const MEASUREMENT = toHex(hashRequest(new TextEncoder().encode('manifest-seal-measurement')));
const WEIGHTS = toHex(hashRequest(new TextEncoder().encode(`weights:${MODEL}`)));

/** The key a deployment signs receipts with. */
export const RECEIPT_KEY: SigningKey = signingKeyFromSeed(
  hashRequest(new TextEncoder().encode('ashaveri-test-receipt-signing-key')),
);
/** The key that same deployment signs its manifest with, never the one above. */
export const MANIFEST_KEY: SigningKey = signingKeyFromSeed(
  hashRequest(new TextEncoder().encode('ashaveri-test-manifest-signing-key')),
);
/** A third key, live in a rotation: the second epoch's receipt signer. */
export const ROTATED_KEY: SigningKey = signingKeyFromSeed(
  hashRequest(new TextEncoder().encode('ashaveri-test-rotated-receipt-key')),
);
/** A stranger's key, generated rather than derived, for the cases where somebody else's seal must not pass. */
export const STRANGER_KEY: SigningKey = generateSigningKey();

/** One `keys[]` entry, with the epoch and the validity start when the caller declares a window. */
export function keyEntry(
  key: SigningKey,
  window?: { readonly epk: number; readonly validFrom: number },
): Record<string, unknown> {
  return {
    kid: toHex(key.kid),
    alg: 'Ed25519',
    publicKey: toBase64Url(key.publicKey),
    ...(window === undefined ? {} : { epk: window.epk, validFrom: window.validFrom }),
  };
}

export interface ManifestShape {
  readonly epoch?: number;
  readonly keys?: readonly Record<string, unknown>[];
  readonly iss?: string;
}

/** The document, with the members a case moves. An absent `keys` is the one key this deployment signs with. */
export function manifestDocument(shape: ManifestShape = {}): Record<string, unknown> {
  return {
    v: 1,
    iss: shape.iss ?? ISSUER,
    ins: INSTANCE,
    epk: shape.epoch ?? 0,
    keys: shape.keys ?? [keyEntry(RECEIPT_KEY)],
    models: [{ id: MODEL, wts: WEIGHTS }],
    meas: { tee: 'software', m: MEASUREMENT },
  };
}

/** The bytes of a plain manifest, as this deployment has always served them. */
export function plainManifest(shape: ManifestShape = {}): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(manifestDocument(shape)));
}

/** The same document inside a `COSE_Sign1`, sealed under the key named here. */
export function sealedManifest(
  shape: ManifestShape = {},
  key: SigningKey = MANIFEST_KEY,
  externalAad: Uint8Array = new Uint8Array(0),
): Uint8Array {
  return sealDeploymentManifest(plainManifest(shape), key, externalAad);
}

const BASE = 'https://manifest.test/v1';

/**
 * A transport that answers the manifest route with the bytes given and refuses anything else by name, so
 * a suite cannot quietly reach a host it did not point at.
 */
export function manifestTransport(manifestBytes: Uint8Array): typeof fetch {
  return async (input) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    if (url !== `${BASE}/deployment-manifest`) {
      throw new Error(`this transport serves one deployment manifest, and was asked for ${url}`);
    }
    return new Response(manifestBytes, { status: 200 });
  };
}

export const MANIFEST_BASE_URL = BASE;

/** The receipt side of a live verification: one signed statement about one exchange. */
export function receiptFor(args: {
  readonly key: SigningKey;
  readonly epoch: number;
  readonly issuedAt: number;
  readonly nonce: Uint8Array;
}): Uint8Array {
  const fields: Omit<ReceiptPayloadV1, 'v'> = {
    iss: ISSUER,
    ins: INSTANCE,
    iat: args.issuedAt,
    nce: args.nonce,
    req: hashRequest(new TextEncoder().encode('manifest-seal-request')),
    res: hashRequest(new TextEncoder().encode('manifest-seal-response')),
    mdl: MODEL,
    wts: hashRequest(new TextEncoder().encode(`weights:${MODEL}`)),
    meas: { tee: 'software', m: hashRequest(new TextEncoder().encode('manifest-seal-measurement')) },
    att: {
      d: hashRequest(new TextEncoder().encode('manifest-seal-evidence')),
      ts: args.issuedAt - 30,
      url: `${BASE}/attestation`,
    },
    epk: args.epoch,
    tok: { p: 3, c: 4 },
  };
  const payload: ReceiptPayload = { v: 1, ...fields };
  return issueReceipt(payload, args.key);
}

/**
 * A policy pin map: each key's public half by its kid, in the spelling a policy stores.
 *
 * One builder for both of the policy's two key maps, because the *entries* are the same shape and
 * which map they land in is the caller's decision, and it is the decision that matters: `keys` names
 * who may sign a receipt and `manifestKeys` names who may sign the document that lists them.
 */
export function pinMap(...keys: readonly SigningKey[]): Record<string, string> {
  return Object.fromEntries(keys.map((key) => [toHex(key.kid), toBase64Url(key.publicKey)]));
}
