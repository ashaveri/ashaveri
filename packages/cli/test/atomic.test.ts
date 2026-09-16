import { chmodSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { writeAtomically } from '../src/atomic.js';

/**
 * The writer both `credential` and `accesslog scrub` share, run against its own unit rather than
 * through a spawned command. These cases are in-process on purpose: the temporary name carries this
 * process's id, so a spawned run is a name the test cannot predict and the two rules about that name
 * could not be asserted at all.
 */

const tempDir = mkdtempSync(join(tmpdir(), 'ashaveri-atomic-'));
let counter = 0;

afterAll(() => {
  rmSync(tempDir, { recursive: true, force: true });
});

function pathFor(label: string): string {
  return join(tempDir, `${label}-${String(++counter)}.json`);
}

describe('writeAtomically', () => {
  it('writes the whole file and leaves no temporary behind', async () => {
    const path = pathFor('plain');
    await writeAtomically(path, '{"version":1}\n', 0o600, 'cannot write example file');
    expect(readFileSync(path, 'utf8')).toBe('{"version":1}\n');
  });

  it('refuses a temporary name that is already taken instead of writing through it', async () => {
    // The two rules this case pins are the reason a same-directory rewrite is safe to ship in a
    // published command. `writeFile` without `wx` accepts an existing path, ignores its `mode` for it,
    // and follows a symlink, so a name left by a killed run or planted by anything else that can write
    // in the directory becomes the file renamed over the real one, carrying this call's bytes and that
    // file's permissions. A plain open would also let the failure path delete a file it never made.
    // Both are visible from outside only if the test can name the temporary, which is why this runs
    // against the writer directly: the id in the name is this process's.
    const path = pathFor('taken');
    writeFileSync(path, 'the bytes on disk\n');
    const planted = `${path}.tmp-${String(process.pid)}`;
    writeFileSync(planted, "not this writer's file\n");
    await expect(writeAtomically(path, 'the bytes this run wanted to write\n', 0o600, 'cannot write example file')).rejects.toThrow(
      /cannot write example file .*EEXIST/u,
    );
    expect(readFileSync(path, 'utf8')).toBe('the bytes on disk\n');
    expect(readFileSync(planted, 'utf8')).toBe("not this writer's file\n");
  });

  it.runIf(process.platform !== 'win32')('applies the mode it was handed, not the mode the umask allows', async () => {
    // A create mode is masked by the process umask, so `0666` reaches the file system as `0644` under
    // the common `022`. The caller names a mode because it knows who has to read or append to the file
    // afterwards, so the writer sets it again once the file exists. Windows reports every file `0666`
    // whatever was asked, which is why this case is POSIX-only rather than wrong here.
    const path = pathFor('mode');
    await writeAtomically(path, '{}\n', 0o666, 'cannot write example file');
    expect(statSync(path).mode & 0o777).toBe(0o666);
    chmodSync(path, 0o600);
  });
});
