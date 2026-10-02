/**
 * The patience this suite's cases owe the processes they start.
 *
 * A case here either boots a gateway that promises a banner, bounded by `BOOT_DEADLINE_MS` in
 * `gateway/test/cli.test.ts`, or runs the CLI once, bounded by that file's `SPAWN_DEADLINE_MS`. A ceiling
 * under either deadline can only expire first, and then the report says the runner gave up rather than
 * naming the process that never answered. `packages/cli` bounds its children the same way with its own
 * copy of these three functions; the two suites cannot share one owner because `@ashaveri/fixtures`,
 * which both would have to sit under, generates vectors with this package's store, so a dependency the
 * other way is the cycle pnpm refuses to build.
 */

/** A boot's deadline, restated as data because the authority for it is `gateway/test/cli.test.ts`. */
const BOOT_DEADLINE_MS = 10_000;

/** The CLI child's deadline, likewise restated. */
const SPAWN_DEADLINE_MS = 8_000;

/** The allowance for the assertions and fixture files between the processes, which are not processes. */
const CEILING_SLACK_MS = 2_000;

/** The ceiling a case is entitled to for `calls` processes, each given `deadlineMs`. */
export function spawnCeilingForCalls(calls: number, deadlineMs: number): number {
  return calls * deadlineMs + CEILING_SLACK_MS;
}

/** The default ceiling `vitest.config.ts` hands the runner: an ordinary boot plus an ordinary child. */
export const DEFAULT_SPAWN_CEILING_MS = BOOT_DEADLINE_MS + SPAWN_DEADLINE_MS + CEILING_SLACK_MS;

let calls = 0;
let spentMs = 0;

/** Called beside each deadline as a helper imposes it, so a case's cost is counted from its processes. */
export function noteSpawn(deadlineMs: number): void {
  calls += 1;
  spentMs += deadlineMs;
}

/** This case's arithmetic, and the count to write into the ceiling it needs. */
export function readAndResetSpawns(): { calls: number; deadlineMs: number; spentMs: number } {
  const seen = { calls, deadlineMs: calls === 0 ? 0 : Math.round(spentMs / calls), spentMs };
  calls = 0;
  spentMs = 0;
  return seen;
}
