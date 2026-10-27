// A second process making one store opening, and printing what it got as a single line of JSON.
//
// JavaScript rather than the suite's TypeScript because a child runs outside the runner's
// transpiler: the same reason the CLI cases start the built entry point rather than the source, and
// the reason this reads `dist/store.js`. A case that could not build would fail on the answer this
// prints rather than on a transpile the runner never does for a child.
//
// Two modes, and both end with the process exiting:
//   attempt - open the directory and report the refusal, which is the state a second writer reaches
//   claim   - open it, file one receipt, and go, leaving a claim behind that names a gone process
import { openFileReceiptStore } from '../../dist/store.js';

const [dir, mode, id] = process.argv.slice(2);
const answer = { mode, pid: process.pid, opened: false, code: null, message: null };
try {
  const store = await openFileReceiptStore({ dir });
  answer.opened = true;
  if (mode === 'claim') {
    await store.put(id, Uint8Array.from([1, 2, 3]), 1_780_000_000);
    answer.filed = id;
  }
} catch (error) {
  answer.code = typeof error.code === 'string' ? error.code : null;
  answer.message = error instanceof Error ? error.message : String(error);
}
process.stdout.write(`${JSON.stringify(answer)}\n`);
