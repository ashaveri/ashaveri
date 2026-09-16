import { chmod, rename, unlink, writeFile } from 'node:fs/promises';
import { UsageError } from './usage.js';

/**
 * Whole-file write through a fresh name in the same directory, then a rename into place, so a reader
 * never sees half a file and a process watching the mtime reloads without a restart.
 *
 * Three rules `node:fs` makes the caller hold for itself, which is why both writers share this one:
 *
 * - The temporary is opened `wx`. A plain `writeFile` ignores its `mode` for a path that already
 *   exists and follows a symlink at it, so a stale name from a killed run, or one planted by anything
 *   that can write in the directory, would be reused as the file that gets renamed over the real one.
 *   A name that exists is therefore a refusal the operator can read, not a file this call inherits.
 * - The mode is set again with `chmod` after the create, because a create mode is masked by the
 *   process umask and the caller's value is the one that has to land.
 * - Only a temporary this call created is removed on the way out. One it merely found is left exactly
 *   as it was found, since it is not this call's to delete.
 *
 * The name carries this process's id, so two runs writing the same file do not collide, and a refusal
 * that leaves nothing behind does not hide the earlier run that left something.
 */
export async function writeAtomically(path: string, text: string, mode: number, refusal: string): Promise<void> {
  const tmp = `${path}.tmp-${String(process.pid)}`;
  let created = false;
  try {
    await writeFile(tmp, text, { mode, flag: 'wx' });
    created = true;
    await chmod(tmp, mode);
    await rename(tmp, path);
  } catch (error) {
    if (created) await unlink(tmp).catch(() => undefined);
    const reason = error instanceof Error ? error.message : String(error);
    throw new UsageError(`${refusal} '${path}': ${reason}`);
  }
}
