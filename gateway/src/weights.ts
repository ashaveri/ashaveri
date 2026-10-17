import { readFileSync } from 'node:fs';
import type { ModelInfo } from './deployment.js';
import { sha256 } from './digest.js';

/** How a manifest is read. A test names its own to count the readings rather than infer them. */
export type ManifestReader = (path: string) => Uint8Array;

function readManifest(path: string): Uint8Array {
  return new Uint8Array(readFileSync(path));
}

/**
 * The models one live run serves, from one reading of the manifest and one digest of those bytes.
 *
 * The boot check verifies the files a weights directory names against a manifest, and every receipt
 * states that manifest's digest as `wts`. A deployment that reads the file once per model can carry
 * two digests of one path and still leave the reading behind a receipt unbound to the bytes the boot
 * check verified, so the file is read once here and the one digest is handed to every model. Reusing
 * the same value is what makes every receipt in a run name the same reading of the same file.
 *
 * The reader is a parameter because the count of readings is a property a test can observe only by
 * supplying one. Nothing in a shipped run passes it, so the default is the only reading a deployment
 * makes.
 */
export function modelsFromManifest(
  modelIds: readonly string[],
  manifestPath: string,
  read: ManifestReader = readManifest,
): ModelInfo[] {
  const digest = sha256(read(manifestPath));
  return modelIds.map((id) => ({ id, wts: digest }));
}
