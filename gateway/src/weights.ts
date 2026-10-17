import { readFileSync } from 'node:fs';
import type { ModelInfo, WeightsManifest } from './deployment.js';
import { sha256 } from './digest.js';

/** How a manifest is read. A test names its own to count the readings rather than infer them. */
export type ManifestReader = (path: string) => Uint8Array;

function readManifest(path: string): Uint8Array {
  return new Uint8Array(readFileSync(path));
}

/** One reading of a manifest: the models that carry its digest and the bytes the route serves. */
export interface ManifestModels {
  /** Every model this run serves, each carrying the digest of the one reading as `wts`. */
  readonly models: ModelInfo[];
  /** The reading that digest was taken over, held for the route that serves those bytes. */
  readonly manifest: WeightsManifest;
}

/**
 * The models one live run serves and the manifest bytes behind them, from one reading and one digest.
 *
 * The boot check verifies the files a weights directory names against a manifest, and every receipt
 * states that manifest's digest as `wts`. A deployment that reads the file once per model can carry
 * two digests of one path and still leave the reading behind a receipt unbound to the bytes the boot
 * check verified, so the file is read once here and the one digest is handed to every model. Reusing
 * the same value is what makes every receipt in a run name the same reading of the same file.
 *
 * The bytes are returned beside the models rather than dropped after the digest is taken, because the
 * route addressed by that digest has to answer with exactly these bytes: a second read at request time
 * would serve whatever the path holds then, which is not what any receipt issued by this run states.
 *
 * The reader is a parameter because the count of readings is a property a test can observe only by
 * supplying one. Nothing in a shipped run passes it, so the default is the only reading a deployment
 * makes.
 */
export function modelsFromManifest(
  modelIds: readonly string[],
  manifestPath: string,
  read: ManifestReader = readManifest,
): ManifestModels {
  const bytes = read(manifestPath);
  const digest = sha256(bytes);
  return {
    models: modelIds.map((id) => ({ id, wts: digest })),
    manifest: { digest, bytes },
  };
}
