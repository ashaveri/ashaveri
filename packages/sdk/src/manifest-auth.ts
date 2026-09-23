import {
  decodeSealedDeploymentManifest,
  isSealedDeploymentManifest,
  keyId,
  verifySealedDeploymentManifest,
  ReceiptError,
} from '@ashaveri/receipt';
import { fromBase64Url, toHex } from './b64.js';
import { SdkError } from './errors.js';
import { parseManifest, type DeploymentManifest } from './manifest.js';
import type { AshaveriPolicy } from './policy.js';

/**
 * Reading the bytes a deployment serves at `/deployment-manifest`, and saying afterwards what they
 * are worth.
 *
 * Three states, and a client has to be able to tell all three apart rather than collapse the last two:
 * a sealed manifest that verifies under a key this client designated for the purpose, a sealed manifest
 * that does not, and a document that carries no seal at all. The second is fatal in every posture,
 * because a body that changed after it was signed is not evidence about anything. The first three rows
 * of the table below are the whole of the policy question, and the rule they encode is the one this
 * package has always applied to a manifest: it is the party being verified talking, so it may fail a
 * check and it may not open one.
 *
 * | served | policy designates manifest keys | outcome |
 * |---|---|---|
 * | sealed, verifies | yes | authenticated, and the manifest's values are the deployment's own statement |
 * | sealed, does not verify | any | fatal: `MANIFEST_SIGNATURE_INVALID` |
 * | sealed, kid undesignated | yes | fatal: `MANIFEST_NOT_AUTHENTICATED` |
 * | sealed, kid undesignated | no | parsed, reported unauthenticated, and the advisory names the kid |
 * | plain JSON | yes | fatal: `MANIFEST_NOT_AUTHENTICATED`, since a caller who designated a signer was handed none |
 * | plain JSON | no | parsed, reported unauthenticated, and the advisory says so |
 *
 * The two refusal codes are not one code. A signature that does not hold and a document that never
 * claimed a signature are different deployments with different fixes, and the first is the one an
 * operator has to be woken up about.
 */
export interface ManifestAuthentication {
  /** Whether a COSE_Sign1 wrapper was served, whatever became of it. */
  readonly sealed: boolean;
  /** Whether this client authenticated the document it is holding. */
  readonly authenticated: boolean;
  /** The wrapper's `kid` in hex, or null when none was served. */
  readonly kid: string | null;
  /** Whether this policy designated any manifest key at all, which is what decides fatal from advisory. */
  readonly demanded: boolean;
  /**
   * The sentence to report when the document is not authenticated, and null when it is.
   *
   * It is part of the result rather than a log line the caller has to go looking for, because an
   * unauthenticated manifest is still usable, and the only thing that keeps that usable from becoming
   * believed is for whoever reads the verdict to be handed the reason it rests on nothing.
   */
  readonly advisory: string | null;
}

export interface ReadManifestResult {
  readonly manifest: DeploymentManifest;
  readonly authentication: ManifestAuthentication;
}

/** The keys a policy designates for signing manifests, or null when it designates none. */
function designated(policy: AshaveriPolicy | undefined): Readonly<Record<string, string>> | null {
  const pins = policy?.manifestKeys;
  return pins === undefined || Object.keys(pins).length === 0 ? null : pins;
}

function parseDocument(text: string): DeploymentManifest {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch (err) {
    throw new SdkError('BAD_MANIFEST', `deployment manifest is not valid JSON: ${(err as Error).message}`);
  }
  try {
    return parseManifest(value);
  } catch (err) {
    throw new SdkError('BAD_MANIFEST', (err as Error).message);
  }
}

/**
 * Read the served bytes into a manifest and a verdict on them.
 *
 * The shape of the body decides which reading it gets, off its first byte rather than off a
 * `content-type` header the sender chose: no JSON document can begin with the CBOR tag that opens a
 * `COSE_Sign1`, so the two branches cannot be crossed by a header, and the offline reporter that reads
 * these bytes out of a file has no header to consult at all.
 *
 * A body that begins with that tag and then fails to be a sealed manifest is refused by the format
 * package's own codes, which travel through here unchanged: `BAD_PROTECTED_HEADER` is what a client
 * says when somebody hands it a signed receipt or a signed pack at the manifest route, and a reader
 * that translated that into a manifest parse error would be reporting a confusion as a typo.
 */
export function readDeploymentManifest(
  bytes: Uint8Array,
  policy?: AshaveriPolicy,
): ReadManifestResult {
  const pins = designated(policy);
  if (!isSealedDeploymentManifest(bytes)) {
    const manifest = parseDocument(new TextDecoder().decode(bytes));
    if (pins !== null) {
      throw new SdkError(
        'MANIFEST_NOT_AUTHENTICATED',
        `the deployment served an unsigned manifest while this policy designates ${Object.keys(pins).length} key${Object.keys(pins).length === 1 ? '' : 's'} for signing manifests, so nothing here says this document came from ${manifest.iss}`,
      );
    }
    return {
      manifest,
      authentication: {
        sealed: false,
        authenticated: false,
        kid: null,
        demanded: false,
        advisory:
          'the deployment manifest is unsigned and no manifest signing key is pinned, so its issuers, keys, instances and measurements are trust-on-first-use values rather than an authenticated statement from the deployment',
      },
    };
  }

  const seal = decodeSealedDeploymentManifest(bytes);
  const kid = toHex(seal.header.kid);
  const pinned = pins?.[kid];
  if (pins === null || pinned === undefined) {
    const manifest = parseDocument(new TextDecoder().decode(seal.payloadBytes));
    return {
      manifest,
      authentication: {
        sealed: true,
        authenticated: false,
        kid,
        demanded: false,
        advisory:
          pins === null
            ? `the deployment manifest arrived sealed under key ${kid}, which this policy designates nothing for because it names no manifest signing key, so the seal proves the bytes are whole and nothing about who wrote them`
            : `the deployment manifest arrived sealed under key ${kid}, which this policy does not designate for signing manifests, so the seal proves the bytes are whole and nothing about who wrote them`,
      },
    };
  }

  const keyBytes = fromBase64Url(pinned);
  if (toHex(keyId(keyBytes)) !== kid) {
    throw new SdkError(
      'MANIFEST_KEY_NOT_PINNED',
      `the manifest key pinned for ${kid} is ${toHex(keyId(keyBytes))} by its own digest, so the pin and the document disagree about which key that id names`,
    );
  }
  try {
    verifySealedDeploymentManifest(bytes, keyBytes);
  } catch (err) {
    if (err instanceof ReceiptError && (err.code === 'INVALID_SIGNATURE' || err.code === 'KID_MISMATCH')) {
      throw new SdkError(
        'MANIFEST_SIGNATURE_INVALID',
        `the deployment manifest served under key ${kid} does not verify under the key pinned for it: ${err.message}`,
      );
    }
    throw err;
  }
  return {
    manifest: parseDocument(new TextDecoder().decode(seal.payloadBytes)),
    authentication: { sealed: true, authenticated: true, kid, demanded: true, advisory: null },
  };
}
