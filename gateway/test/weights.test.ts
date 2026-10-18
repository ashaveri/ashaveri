import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { modelsFromManifest } from '../src/weights.js';

/**
 * A live run names one manifest and one or more models. Every receipt states the manifest's digest, so
 * two readings of that path are two chances for the digest to name bytes the boot check did not
 * verify, and a digest taken per model is that chance once per model. The function under test is the
 * one seam where the reading and the digest meet, and the reader is injected here to count readings
 * rather than infer them from equal results.
 */
const tempDir = mkdtempSync(join(tmpdir(), 'ashaveri-weights-'));
const MANIFEST = join(tempDir, 'weights-manifest.json');
const FIRST_BYTES = `{"files":[{"name":"model.safetensors","sha256":"${'ab'.repeat(32)}"}]}`;
writeFileSync(MANIFEST, FIRST_BYTES);

afterAll(() => {
  rmSync(tempDir, { recursive: true, force: true });
});

function digestOf(bytes: string): Buffer {
  return createHash('sha256').update(bytes).digest();
}

describe('the models one weights manifest builds', () => {
  it('reads the manifest once and hands every model the one digest of those bytes', () => {
    let readings = 0;
    const { models, manifest } = modelsFromManifest(['first', 'second'], MANIFEST, (path) => {
      readings += 1;
      return new Uint8Array(readFileSync(path));
    });

    expect(readings, 'one run reads the manifest once, not once per model').toBe(1);
    expect(models.map((model) => model.id)).toEqual(['first', 'second']);
    for (const model of models) {
      expect(Buffer.from(model.wts), `${model.id} carries the manifest digest`).toEqual(digestOf(FIRST_BYTES));
    }
    // The same value rather than two equal copies: one reading is what the entire run states.
    expect(models[0]!.wts).toBe(models[1]!.wts);
    // The bytes the route serves are the bytes that digest was taken over, held beside it.
    expect(manifest.digest).toBe(models[0]!.wts);
    expect(Buffer.from(manifest.bytes)).toEqual(Buffer.from(FIRST_BYTES));
    expect(Buffer.from(manifest.bytes)).toEqual(Buffer.from(readFileSync(MANIFEST)));
  });

  it('digests the bytes on disk, so a rewritten manifest moves every model at once', () => {
    const before = modelsFromManifest(['m'], MANIFEST);
    writeFileSync(MANIFEST, `${FIRST_BYTES}\n`);
    const after = modelsFromManifest(['m'], MANIFEST);
    expect(Buffer.from(after.models[0]!.wts)).toEqual(digestOf(`${FIRST_BYTES}\n`));
    expect(Buffer.from(after.models[0]!.wts)).not.toEqual(Buffer.from(before.models[0]!.wts));
    // The reading a run holds is its own: a later read of the path does not move the bytes already
    // handed over, which is the property the route depends on.
    expect(Buffer.from(before.manifest.bytes)).toEqual(Buffer.from(FIRST_BYTES));
    expect(Buffer.from(after.manifest.bytes)).toEqual(Buffer.from(`${FIRST_BYTES}\n`));
  });
});
