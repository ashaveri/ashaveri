import { chmod, rename, unlink, writeFile } from 'node:fs/promises';
import { UsageError } from './usage.js';

function codeOf(error: unknown): string | undefined {
  return error instanceof Error && 'code' in error && typeof error.code === 'string' ? error.code : undefined;
}

function reasonOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Whole-file write through a fresh name in the same directory, then a rename into place, so a reader
 * never sees half a file and a process watching the mtime reloads without a restart.
 *
 * Four rules `node:fs` makes the caller hold for itself, which is why both writers share this one:
 *
 * - The temporary is opened `wx`. A plain `writeFile` ignores its `mode` for a path that already
 *   exists and follows a symlink at it, so a stale name from a killed run, or one planted by anything
 *   that can write in the directory, would be reused as the file that gets renamed over the real one.
 *   A name that exists is therefore a refusal the operator can read, not a file this call inherits.
 * - The mode is set again with `chmod` after the create, because a create mode is masked by the
 *   process umask and the caller's value is the one that has to land.
 * - Only a temporary this call did not find in place is removed on the way out. `EEXIST` from the
 *   create is the one failure that proves the name belonged to someone else, so it is the one failure
 *   that leaves it alone; every other failure means a file this call made, including a write that
 *   filled part of the buffer and then died on a full volume, which is exactly the moment a temporary
 *   carrying personal data must not be left behind. An unlink of a name that turns out not to exist is
 *   swallowed, so this errs toward removing what may be the caller's own.
 * - The mode is read as the nine permission bits and nothing above them. Both callers pass either a
 *   literal or a masked `stat` value today, and an unmasked larger value would reach `chmod` exactly as
 *   it was handed over, so the ceiling is held here rather than repeated at every call site: a
 *   published command should not be able to put a set-user-id bit on a log part through a parameter
 *   named `mode`.
 *
 * The name carries this process's id, so two runs writing the same file do not collide, and a refusal
 * that leaves nothing behind does not hide the earlier run that left something.
 */
export async function writeAtomically(path: string, text: string, mode: number, refusal: string): Promise<void> {
  const tmp = `${path}.tmp-${String(process.pid)}`;
  const keep = mode & 0o777;
  let creating = true;
  try {
    await writeFile(tmp, text, { mode: keep, flag: 'wx' });
    creating = false;
    await chmod(tmp, keep);
    await rename(tmp, path);
  } catch (error) {
    if (!(creating && codeOf(error) === 'EEXIST')) await unlink(tmp).catch(() => undefined);
    throw new UsageError(`${refusal} '${path}': ${reasonOf(error)}`);
  }
}

/**
 * Write a file at its own name, and only when that name is free, reporting which of the two happened.
 *
 * This is the shape `rename` cannot take: `rename` replaces whatever stands at the destination, which
 * is what `writeAtomically` wants and the opposite of what a slot in a shared directory wants. The
 * caller that uses this one is asked for a name no other process has written, and the only honest
 * answer to a name that turns out to be taken is to say so and let the caller look elsewhere.
 *
 * There is no temporary here, and that is the point of it: a `.tmp-<pid>` that outlives a killed run is
 * a file the retention sweep can never match by name, so the bytes it holds stay on the volume under a
 * name nobody owns. The cost is that a reader who opens the name while this call is writing it can see
 * a short file. Nothing in the gateway reads these bytes, which keep a count for an operator, while a
 * rename would let the same run overwrite the receipt an earlier one made.
 *
 * The mode is the create's own and is not corrected afterwards, because a create mode is masked down by
 * the umask and never up: whatever lands is this call's mode or a stricter one, which is the property
 * the caller wants and the reason `writeAtomically`'s `chmod` has no counterpart here.
 */
export async function publishNew(path: string, text: string, mode: number, refusal: string): Promise<boolean> {
  try {
    await writeFile(path, text, { mode: mode & 0o777, flag: 'wx' });
    return true;
  } catch (error) {
    if (codeOf(error) === 'EEXIST') return false;
    throw new UsageError(`${refusal} '${path}': ${reasonOf(error)}`);
  }
}
