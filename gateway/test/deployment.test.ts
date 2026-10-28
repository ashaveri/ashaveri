import { describe, expect, it } from 'vitest';
import { sha256 } from '../src/digest.js';
import { mockDeployment, mockWeights, type MockDeploymentOptions } from '../src/deployment.js';

const text = (value: string): Uint8Array => new TextEncoder().encode(value);

/** The one reading a run would carry, and the digest every model of that run names. */
const BYTES = text('{"files":[{"name":"model.safetensors","sha256":"aa"}]}');
const DIGEST = sha256(BYTES);

describe('a software deployment that names the model it served', () => {
  it('carries the digest of the bytes it was handed rather than a string derived from the id', () => {
    const options: MockDeploymentOptions = {
      models: [{ id: 'llama-3.1-8b:instruct', wts: DIGEST }],
      weightsManifest: { digest: DIGEST, bytes: BYTES },
    };
    const deployment = mockDeployment(options);
    expect(deployment.models).toEqual([{ id: 'llama-3.1-8b:instruct', wts: DIGEST }]);
    expect(deployment.weightsManifest?.digest).toEqual(DIGEST);
    expect(deployment.weightsManifest?.bytes).toEqual(BYTES);
  });

  it('keeps the synthetic model and publishes no weights document when nothing is named', () => {
    const deployment = mockDeployment();
    expect(deployment.models).toEqual([{ id: 'mock-model-1', wts: mockWeights('mock-model-1') }]);
    expect(deployment.weightsManifest).toBeUndefined();
  });

  it('honours a named model even with no document behind it, which is what a bare --model asks for', () => {
    const deployment = mockDeployment({ model: 'qwen2.5:3b' });
    expect(deployment.models).toEqual([{ id: 'qwen2.5:3b', wts: mockWeights('qwen2.5:3b') }]);
  });
});
