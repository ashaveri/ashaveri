/**
 * The arithmetic behind every ceiling in this package's test suite.
 *
 * Each case here runs the built CLI as a real child process, and the helper that starts it gives that
 * child a deadline, on the reasoning each file writes down: a process still alive after that long is a
 * handle that never closed, and the deadline is what turns it into a named failure rather than a job that
 * waits forever. Those deadlines are 8, 10, 15 and 60 seconds, one per kind of command. The runner's
 * ceiling for a case that named none was five.
 *
 * A ceiling below the deadline the same suite hands a single child can only expire first, and what it
 * reports is `Test timed out in 5000ms`, which teaches a reader nothing about which child failed to
 * answer. That is not rare on the shared Windows runner, where one spawn costs several times what it
 * costs on a development machine: the case this started with spends five and a third seconds there
 * against a ceiling of five, and two and a third here, with nothing about the case changed between the
 * two readings.
 *
 * So a ceiling here is arithmetic over the deadlines, exactly as `gateway/test/cli.test.ts` already does
 * for the gateways it boots: the worst case is what a hang costs, and a hang is a defect worth waiting
 * for once rather than misreading. `spawn-guard.ts` refuses the suite when a case's children ask for more
 * patience than the ceiling it was given grants, which is what keeps this true after somebody adds a loop
 * rather than only today, when the sums happen to fit.
 *
 * `gateway/test/support/spawn-budget.ts` carries the same three functions for its own deadlines. They are
 * not shared in one module because `@ashaveri/fixtures`, the one package both suites could reach,
 * generates its vectors with the gateway's store, so depending on it from there is the build cycle pnpm
 * refuses. Two files that say the same thing about patience, each next to the deadlines it counts.
 */

/** The children a case may start before it has to say so, at the deadline the ordinary commands carry. */
const DEFAULT_SPAWN_CALLS = 8;

/** The default ceiling `vitest.config.ts` hands the runner: the ordinary case's arithmetic. */
export const DEFAULT_SPAWN_CEILING_MS = spawnCeilingForCalls(DEFAULT_SPAWN_CALLS, 8_000);

/**
 * The ceiling a case is entitled to for `calls` children, each given `deadlineMs`.
 *
 * The sum rather than the maximum, because a case that starts eight children can spend eight deadlines
 * in work every file here calls normal, and a ceiling that expires on the third of them reports the
 * runner's impatience instead of the child that never answered. The slack covers the assertions and the
 * fixture files between the children, which are not children of their own.
 */
export function spawnCeilingForCalls(calls: number, deadlineMs: number): number {
  return calls * deadlineMs + 2_000;
}

let calls = 0;
let spentMs = 0;

/**
 * Called by each helper beside the deadline it is about to impose, so a case's cost is counted from the
 * children it really started. A call site inside a loop is charged what the loop runs, which is the
 * reason this is a count at run time and not a number read off the source.
 */
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
