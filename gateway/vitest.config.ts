import { defineConfig } from 'vitest/config';
import { DEFAULT_SPAWN_CEILING_MS } from './test/support/spawn-budget.js';

/**
 * Every case here either boots a gateway that promises a banner or runs the CLI as a child, so the
 * runner's ceiling bounds processes rather than assertions. It is read from
 * `test/support/spawn-budget.ts`, which carries the deadlines this suite imposes, because a ceiling under
 * a deadline can only expire first: the named failure the deadline exists to produce is replaced by
 * `Test timed out`, on whichever case happened to be running when the machine was slow.
 *
 * `spawn-guard.ts` is loaded here rather than imported by each file, so a case cannot be added without it
 * being looked at. The same figure bounds a hook, because a case that boots a gateway and then removes
 * the directory it wrote credentials into spends its time in the same file system the processes do.
 */
export default defineConfig({
  test: {
    setupFiles: ['./test/support/spawn-guard.ts'],
    testTimeout: DEFAULT_SPAWN_CEILING_MS,
    hookTimeout: DEFAULT_SPAWN_CEILING_MS,
  },
});
