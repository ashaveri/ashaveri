import { afterEach, expect } from 'vitest';
import { readAndResetSpawns } from './spawn-budget.js';

/**
 * The witness that a case is never bounded below the patience its own children were given.
 *
 * The count comes from the helpers rather than the source, because a call site inside a loop costs what
 * the loop runs. What this refuses is the quiet form of the failure the Windows job has been showing: a
 * case starts children whose deadlines add up past the ceiling it was given, the runner gives up on it,
 * and the report says the runner timed out rather than naming the child that never answered. A red here
 * is not a problem with the case, and the sentence says so by handing over the expression whose value
 * moves with it, which is what keeps the ceiling a statement about the work instead of a number somebody
 * remembers about a machine.
 */
afterEach(({ task }) => {
  const seen = readAndResetSpawns();
  if (seen.spentMs === 0) return;
  const givenMs = task.timeout ?? 0;
  expect(
    givenMs,
    `${task.name} started ${String(seen.calls)} children carrying ${String(seen.spentMs)}ms of deadlines and was ` +
      `given ${String(givenMs)}ms. End this case with spawnCeilingForCalls(${String(seen.calls)}, SPAWN_DEADLINE_MS), ` +
      'or raise DEFAULT_SPAWN_CEILING_MS in test/support/spawn-budget.ts. A ceiling under the deadline this file hands ' +
      "one child reports the runner's impatience rather than the child that hung.",
  ).toBeGreaterThanOrEqual(seen.spentMs);
});
