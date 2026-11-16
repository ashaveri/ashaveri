import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import { DISCLOSURE_RECORD_LIMITS, fromBase64Url } from '@ashaveri/receipt';
import { noteSpawn, spawnCeilingForCalls } from './support/spawn-budget.js';

/**
 * `ashaveri detect-mark`, driven by the published marking vectors.
 *
 * The three fixture classes the detection path owes an answer for are rows `marking-v1.json` already
 * publishes, each with the signed receipt attesting exactly its bytes: a marked response
 * (`buffered-member`), an unmarked response under a `none` declaration (`absence-declared`), and a
 * direct-provider bypass (`region-stripped`), where the receipt claims a mark and the response carries
 * no region because none was inserted. The verdicts asserted here are the ones that file states, so
 * this suite is not free to redefine what a fixture means.
 *
 * The limits sentence is a product requirement of the command's output, so every accepted answer is
 * held to carrying it verbatim, in both renderings, and the refusal answers are held to the codes the
 * published rule earns rather than to a detection wording.
 */

const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
const DATA = fileURLToPath(new URL('../../fixtures/data/', import.meta.url));
const SPAWN_DEADLINE_MS = 10_000;

interface MarkingVector {
  name: string;
  sch: string;
  responseBase64Url: string;
  expected: string;
  client: { receiptBase64Url: string };
}

const VECTORS = (
  JSON.parse(readFileSync(`${DATA}marking-v1.json`, 'utf8')) as { vectors: MarkingVector[] }
).vectors;

function vector(name: string): MarkingVector {
  const found = VECTORS.find((each) => each.name === name);
  if (found === undefined) throw new Error(`marking-v1.json publishes no vector named ${name}`);
  return found;
}

const KEY = JSON.parse(readFileSync(`${DATA}keys/receipt-key-v1.json`, 'utf8')) as { publicKey: string };
const PUBLIC_KEY = Buffer.from(KEY.publicKey, 'hex').toString('base64url');

const DIR = mkdtempSync(join(tmpdir(), 'ashaveri-detect-mark-'));
afterAll(() => {
  rmSync(DIR, { recursive: true, force: true });
});

let writtenCount = 0;
function written(name: string, data: Uint8Array): string {
  const path = join(DIR, `${String(writtenCount++)}-${name}`);
  writeFileSync(path, data);
  return path;
}

interface CliResult {
  status: number | null;
  stdout: string;
  stderr: string;
}

function runCli(args: string[]): CliResult {
  noteSpawn(SPAWN_DEADLINE_MS);
  const result = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    timeout: SPAWN_DEADLINE_MS,
    killSignal: 'SIGKILL',
  });
  expect(result.error).toBeUndefined();
  return { status: result.status, stdout: result.stdout ?? '', stderr: result.stderr ?? '' };
}

/** One detection run over a published vector's own receipt and response bytes. */
function detect(name: string, extra: string[] = []): CliResult {
  const one = vector(name);
  const receipt = written('receipt.cbor', fromBase64Url(one.client.receiptBase64Url));
  const response = written('response.bin', fromBase64Url(one.responseBase64Url));
  return runCli(['detect-mark', receipt, '--response-body', response, '--key', PUBLIC_KEY, ...extra]);
}

describe('detect-mark over the three fixture classes', () => {
  it('detects the marked response and states what the pair establishes', () => {
    const result = detect('buffered-member');
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('marking scheme: provenance-v1');
    expect(result.stdout).toContain('one region');
    expect(result.stdout).toContain('sha256 matches mk.d');
    expect(result.stdout).toContain('what the mark proves:');
    expect(result.stdout).toContain(`what the mark cannot prove: ${DISCLOSURE_RECORD_LIMITS}`);
  });

  it('reads the unmarked response as the absence its none receipt attests', () => {
    const result = detect('absence-declared');
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('marking scheme: none');
    expect(result.stdout).toContain('no region of this response is marked');
    expect(result.stdout).toContain(`what the mark cannot prove: ${DISCLOSURE_RECORD_LIMITS}`);
  });

  it('refuses the direct-provider bypass, where no mark was inserted, as MARK_MISMATCH', () => {
    const result = detect('region-stripped');
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('MARK_MISMATCH');
    expect(result.stderr).toContain('no region matching the shape provenance-v1 names');
    expect(result.stdout).toBe('');
  });

  it('detects the streamed shape by the same rule', () => {
    const result = detect('streamed-frame');
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('one region');
    expect(result.stdout).toContain(`what the mark cannot prove: ${DISCLOSURE_RECORD_LIMITS}`);
  });
});

describe('detect-mark under --json', () => {
  it('carries the limits sentence and the region figures in the machine answer', () => {
    const result = detect('buffered-member', ['--json']);
    expect(result.status).toBe(0);
    const answer = JSON.parse(result.stdout) as {
      ok: boolean;
      scheme: string;
      region: { count: number; byteLength: number; digestMatch: boolean };
      cannotProve: string;
    };
    expect(answer.ok).toBe(true);
    expect(answer.scheme).toBe('provenance-v1');
    expect(answer.region.count).toBe(1);
    expect(answer.region.byteLength).toBeGreaterThan(0);
    expect(answer.region.digestMatch).toBe(true);
    expect(answer.cannotProve).toBe(DISCLOSURE_RECORD_LIMITS);
  });

  it('answers the bypass with the refusal code, not a detection', () => {
    const result = detect('region-stripped', ['--json']);
    expect(result.status).toBe(1);
    const answer = JSON.parse(result.stdout) as { ok: boolean; code: string };
    expect(answer.ok).toBe(false);
    expect(answer.code).toBe('MARK_MISMATCH');
  });

  it('states the absence as zero regions under a none declaration', () => {
    const result = detect('absence-declared', ['--json']);
    expect(result.status).toBe(0);
    const answer = JSON.parse(result.stdout) as { region: { count: number; byteLength: number }; cannotProve: string };
    expect(answer.region.count).toBe(0);
    expect(answer.region.byteLength).toBe(0);
    expect(answer.cannotProve).toBe(DISCLOSURE_RECORD_LIMITS);
  });
});

describe('detect-mark refuses what it cannot check', () => {
  it('refuses a response the receipt does not attest, before any region is weighed', () => {
    const marked = vector('buffered-member');
    const clean = vector('absence-declared');
    const receipt = written('receipt.cbor', fromBase64Url(marked.client.receiptBase64Url));
    const response = written('response.bin', fromBase64Url(clean.responseBase64Url));
    const result = runCli(['detect-mark', receipt, '--response-body', response, '--key', PUBLIC_KEY]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('RESPONSE_HASH_MISMATCH');
  });

  it('refuses a key the receipt was not signed under', () => {
    const one = vector('buffered-member');
    const receipt = written('receipt.cbor', fromBase64Url(one.client.receiptBase64Url));
    const response = written('response.bin', fromBase64Url(one.responseBase64Url));
    const other = Buffer.alloc(32, 7).toString('base64url');
    const result = runCli(['detect-mark', receipt, '--response-body', response, '--key', other]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('UNKNOWN_KEY');
  });

  it('refuses a run with no response bytes, no key, or no receipt, as usage', { timeout: spawnCeilingForCalls(3, SPAWN_DEADLINE_MS) }, () => {
    const one = vector('buffered-member');
    const receipt = written('receipt.cbor', fromBase64Url(one.client.receiptBase64Url));
    const response = written('response.bin', fromBase64Url(one.responseBase64Url));
    const noResponse = runCli(['detect-mark', receipt, '--key', PUBLIC_KEY]);
    expect(noResponse.status).toBe(2);
    expect(noResponse.stderr).toContain('--response-body is required');
    const noKey = runCli(['detect-mark', receipt, '--response-body', response]);
    expect(noKey.status).toBe(2);
    expect(noKey.stderr).toContain('--key is required');
    const noReceipt = runCli(['detect-mark', '--response-body', response, '--key', PUBLIC_KEY]);
    expect(noReceipt.status).toBe(2);
  });
});