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
 *   The case of the same name in `test/atomic.test.ts` gates this on either system, at any umask.
 * - The mode is set again with `chmod` after the create, because a create mode is masked by the
 *   process umask and the caller's value is the one that has to land. What that is worth on disk
 *   depends on the platform and the process umask, so the rule itself is gated host-independently by
 *   the captured arguments in `test/fs-calls.test.ts`, and `test/atomic.test.ts` reads the landed
 *   bytes where a file system will show them.
 * - Only a temporary this call did not find in place is removed on the way out. `EEXIST` from the
 *   create is the one failure that proves the name belonged to someone else, so it is the one failure
 *   that leaves it alone; every other failure means a file this call made, including a write that
 *   filled part of the buffer and then died on a full volume, which is exactly the moment a temporary
 *   carrying personal data must not be left behind. An unlink of a name that turns out not to exist is
 *   swallowed, so this errs toward removing what may be the caller's own. The `EEXIST` half is gated by
 *   the taken-name case above; the half that asks whether the create is the call that failed is gated by
 *   the scripted rename in `test/fs-calls.test.ts`, which stands for an `EEXIST` that reached this call
 *   from somewhere other than the create, a state no host has to cooperate to produce.
 * - The mode is read as the nine permission bits and nothing above them. Both callers pass either a
 *   literal or a masked `stat` value today, and an unmasked larger value would reach `chmod` exactly as
 *   it was handed over, so the ceiling is held here rather than repeated at every call site: a
 *   published command should not be able to put a set-user-id bit on a log part through a parameter
 *   named `mode`. Nothing in the product reaches it today. The arguments a write hands to its create
 *   and to `chmod` are captured in `test/fs-calls.test.ts`, which holds on any host. The landed fourth
 *   digit is read back in `test/atomic.test.ts` only where a file system reports it, and that case is
 *   gated to a POSIX host because Windows answers `0666` for every writable mode and `0444` once a file
 *   is marked read-only, measured on this host by `chmodSync(path, 0o400)`: there the argument capture is
 *   the only witness. `publishNew`'s copy of the ceiling has no gate at all, because its one caller
 *   hands it the literal `0o600` and a masked and an unmasked `0600` cannot be told apart.
 *
 * The name carries this process's id, so two runs writing the same file do not collide, and a refusal
 * that leaves nothing behind does not hide the earlier run that left something.
 */
export async function writeAtomically(path: string, text: string, mode: number, refusal: string): Promise<void> {
  await writeGuarded(path, text, mode, refusal, holds);
}

/** A predicate for a caller with nothing to compare against: rename whatever is there. */
async function holds(): Promise<boolean> {
  return true;
}

/**
 * The same write, with one question asked of the caller in the instant before the rename: does the
 * destination still hold the bytes you read? A `false` answer takes this call's temporary back and
 * reports that nothing was published, which leaves the name exactly as the other writer left it.
 *
 * This exists because `node:fs` has no conditional rename. `rename` replaces the destination whole,
 * so a caller that read a file, worked over what it read, and then renamed cannot tell a destination it
 * left alone from one somebody appended to in the meantime, and the second case is a lost write. Asking
 * the caller at this height keeps the question as close to the rename as the language allows, which
 * narrows that window to a system call rather than a whole pass over the file; it does not close it, and
 * a caller that reports this receipt has to say so.
 *
 * A predicate that throws is a failure of the same kind as a failed rename: this call's temporary goes,
 * and the refusal names the file with the writer's own sentence about it.
 */
export async function writeGuarded(
  path: string,
  text: string,
  mode: number,
  refusal: string,
  holdsStill: () => Promise<boolean>,
): Promise<boolean> {
  const tmp = `${path}.tmp-${String(process.pid)}`;
  const keep = mode & 0o777;
  let creating = true;
  try {
    await writeFile(tmp, text, { mode: keep, flag: 'wx' });
    creating = false;
    await chmod(tmp, keep);
    if (!(await holdsStill())) {
      await unlink(tmp).catch(() => undefined);
      return false;
    }
    await rename(tmp, path);
  } catch (error) {
    if (!(creating && codeOf(error) === 'EEXIST')) await unlink(tmp).catch(() => undefined);
    throw new UsageError(`${refusal} '${path}': ${reasonOf(error)}`);
  }
  return true;
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
 * a short file, and a run killed between this create and its close leaves that short file standing at
 * the final name for the sweep to age out, because nothing comes back to finish it: the next run sees
 * the name in the listing as taken and files its own marker beside it. That is the trade, and the
 * retention sweep's own inability to match a temporary is what pays for it. Nothing in the gateway
 * reads these bytes, which keep a count for an operator, while a rename would let the same run
 * overwrite the receipt an earlier one made.
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
