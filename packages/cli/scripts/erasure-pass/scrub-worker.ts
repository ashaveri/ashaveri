import { parentPort } from 'node:worker_threads';
import { watchLoopGaps } from './metrics.ts';
import { wholeFilePass } from './unit-facts.ts';

/**
 * The whole-file pass, run off the loop that serves.
 *
 * This is not a reimplementation of the erasure. It calls the same function the published command calls,
 * through the same helper the in-process shape calls, so the difference between the numbers reported
 * here and the numbers reported for the same bytes inside the serving process is only which thread the
 * work stood on. A worker running something that merely resembled the shipped pass would turn the
 * comparison into a claim about the copy rather than a measurement.
 *
 * One job at a time, because that is the shape the question is asked in: an erasure holding one part is
 * the unit, and what a second one arriving mid-run costs is measured on its own terms.
 */
interface Job {
  dir: string;
  credential: string;
}

if (parentPort === null) {
  throw new Error('erasure-pass: the scrub worker is only started by a parent thread');
}
const port = parentPort;

port.on('message', (job: Job) => {
  void run(job);
});

async function run(job: Job): Promise<void> {
  // The worker's own loop stall is measured and sent, and it is not the serving loop's problem: the
  // figure is printed beside the serving process's so the two are never mistaken for one another.
  const gaps = watchLoopGaps();
  try {
    const pass = await wholeFilePass(job.dir, job.credential);
    port.postMessage({ ok: true, wallMs: pass.wallMs, ...pass.facts, gaps: gaps.stop() });
  } catch (error) {
    port.postMessage({
      ok: false,
      reason: error instanceof Error ? error.message : String(error),
      gaps: gaps.stop(),
    });
  }
}

port.postMessage({ ready: true });
