import { chmodSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
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
    // The second half of the title: a write that succeeded has to have taken its own temporary with
    // it, or a directory the operator lists shows a second copy of whatever was just written.
    const base = path.slice(tempDir.length + 1);
    expect(readdirSync(tempDir).filter((each) => each.startsWith(base))).toEqual([base]);
  });

  it('takes its temporary back when the rename is what fails, on either system', async () => {
    // The two permission obstacles elsewhere in this suite are refused before a temporary exists on
    // POSIX, where a rename is a directory operation, so the create-succeeded-and-the-rename-failed
    // path is reached there only by a name that cannot take a rename at all. A directory is that name
    // on both systems: the temporary is made, `rename` refuses (EPERM here, EISDIR on Linux), and the
    // writer has to remove the file it made without touching the one it found.
    const name = `a-directory-${String(++counter)}`;
    const path = join(tempDir, name);
    mkdirSync(path);
    await expect(writeAtomically(path, '{"version":1}\n', 0o600, 'cannot write example file')).rejects.toThrow(
      /cannot write example file .*(?:EPERM|EISDIR)/u,
    );
    expect(readdirSync(tempDir).filter((each) => each.startsWith(name))).toEqual([name]);
    expect(readdirSync(path)).toEqual([]);
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
    // afterwards, so the writer sets it again once the file exists. This case is POSIX-only because
    // the modes this writer is ever handed, `0600`, `0644` and `0666`, all report back as `0666` on
    // Windows, which cannot tell a landed mode from a masked create. A read-only request is observable
    // there, and the rewrite cases in both command suites use it as the obstacle.
    const path = pathFor('mode');
    await writeAtomically(path, '{}\n', 0o666, 'cannot write example file');
    expect(statSync(path).mode & 0o777).toBe(0o666);
    chmodSync(path, 0o600);
    // The ceiling is read over four digits rather than three, because what is being asserted is that
    // the fourth one never arrives: the writer takes the caller's nine permission bits and drops
    // anything above them, so a caller that handed over a set-user-id mode would get `0600` and not a
    // file the operating system treats specially.
    const above = pathFor('mode-above');
    await writeAtomically(above, '{}\n', 0o4600, 'cannot write example file');
    expect(statSync(above).mode & 0o7777).toBe(0o600);
    chmodSync(above, 0o600);
  });
});
