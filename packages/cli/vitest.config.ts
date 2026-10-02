import { defineConfig } from 'vitest/config';
import { DEFAULT_SPAWN_CEILING_MS } from './test/support/spawn-budget.js';

/**
 * Every case here runs the built CLI as a real child process, so the runner's ceiling is a bound on
 * children, not on assertions. It is read from `test/support/spawn-budget.ts`, which holds the deadline
 * each helper gives one child and the count of children the heaviest case asks for, because a ceiling
 * below the deadline the same suite hands those children can only ever fire first: the named failure
 * the deadline exists to produce is replaced by `Test timed out`, on the heaviest case rather than on
 * the one that broke.
 *
 * The same figure bounds a hook, because a suite that writes a credential file per case and removes the
 * directory it wrote them in spends its time in the same file system the cases do.
 */
export default defineConfig({
  test: {
    setupFiles: ['./test/support/spawn-guard.ts'],
    testTimeout: DEFAULT_SPAWN_CEILING_MS,
    hookTimeout: DEFAULT_SPAWN_CEILING_MS,
  },
});
