import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';

/**
 * The proof script is run as the workflow runs it, by `node` with its own type stripping, because the
 * argument shape this case is about is settled at the entry point of that file and nowhere else. The
 * artifact it goes on to run is a build of this package plus the bundle step, which `build` does not
 * produce and this suite does not exist to repeat; the case below stops before either is reached.
 */
const SCRIPT = fileURLToPath(new URL('../scripts/offline-proof.ts', import.meta.url));
const DATA = fileURLToPath(new URL('../../fixtures/data', import.meta.url));
const startDir = mkdtempSync(join(tmpdir(), 'ashaveri-offline-proof-'));

afterAll(() => {
  rmSync(startDir, { recursive: true, force: true });
});

function runProof(args: string[]) {
  // One start of a script that reads a few files and runs a built artifact: the ceiling is what turns a
  // run that hangs into a named failure rather than a job that waits, and it is far past the measured
  // cost of the refusal this case asks for.
  const result = spawnSync(process.execPath, ['--experimental-strip-types', SCRIPT, ...args], {
    cwd: startDir,
    encoding: 'utf8',
    timeout: 60_000,
    killSignal: 'SIGKILL',
  });
  expect(result.error).toBeUndefined();
  return result;
}

describe('the offline proof reads its work directory as one place', () => {
  it('refuses a relative work directory by naming the argument, before it writes anything', () => {
    // The invocation the workflow never makes, because `mktemp -d` prints an absolute path: a relative
    // work directory is used twice over, once as the front of every path this proof builds and once as
    // the working directory of every run of the artifact, so the second reading rooted it inside the
    // first and the exported original was looked for at `<work>/<work>/contract.pdf`. What that reached
    // was `ENOENT` about a file the proof had itself written one step earlier, and no word about the
    // argument it was really about.
    const result = runProof(['work', DATA]);
    expect(result.status, result.stderr).toBe(1);
    expect(result.stderr).toContain('usage: offline-proof <absolute-work-directory> <fixtures-data-directory>');
    expect(result.stderr).toContain("'work' is a relative path");
    // The refusal is at the entry point, so the run leaves nothing to be picked up afterwards: the
    // directory the argument named was never made, and none of the three inputs the proof writes appeared
    // beside it.
    expect(existsSync(join(startDir, 'work'))).toBe(false);
    expect(existsSync(join(startDir, 'manifest.json'))).toBe(false);
    expect(existsSync(join(startDir, 'policy.json'))).toBe(false);
    expect(result.stdout).toBe('');
  });

  it('refuses the two arguments it asks for by the same sentence, when one of them is missing', () => {
    // Pinned beside the case above because both are the entry point's whole job: the run that has no
    // directory to work in has to be told what it was asked to supply, in the same words.
    const result = runProof([DATA]);
    expect(result.status, result.stderr).toBe(1);
    expect(result.stderr).toContain('usage: offline-proof <work-directory> <fixtures-data-directory>');
    expect(result.stdout).toBe('');
  });
});
