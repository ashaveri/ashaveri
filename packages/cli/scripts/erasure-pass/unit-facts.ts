import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { accesslogScrub, type ScrubMarker } from '../../dist/commands/accesslog.js';

/**
 * The whole-file pass, and the facts a pass owes whoever is checking it.
 *
 * Shared by the two shapes that run the shipped scrub — the one inside the serving process and the one
 * on a worker thread — so that the only difference between their numbers is the thread they ran on. A
 * second copy of the reading of a receipt would put that difference in doubt.
 */

export interface PassFacts {
  removed: number;
  files: number;
  beforeBytes: number;
  beforeSha256: string;
  afterBytes: number;
  afterSha256: string;
}

export interface TimedPass {
  facts: PassFacts;
  wallMs: number;
}

/** What a name that holds nothing reports, which is also what a deleted part's after-facts are. */
export const EMPTY_SHA256 = createHash('sha256').digest('hex');

export const NOTHING: PassFacts = {
  removed: 0,
  files: 0,
  beforeBytes: 0,
  beforeSha256: EMPTY_SHA256,
  afterBytes: 0,
  afterSha256: EMPTY_SHA256,
};

/**
 * One directory, holding one part, through the published command's own entry point.
 *
 * The digests come out of the marker the run filed rather than from a re-read here. That is not
 * tidiness: the marker is what a peer checks an erasure against, so a pass whose reported bytes do not
 * match its own receipt is caught by this function rather than by a comparison that would have read two
 * different things and called them equal.
 */
export async function wholeFilePass(dir: string, credential: string): Promise<TimedPass> {
  const at = performance.now();
  const result = await accesslogScrub(dir, credential, () => Date.now());
  const wallMs = performance.now() - at;
  if (result.files === 0) {
    return { facts: { ...NOTHING, removed: result.removed, files: 0 }, wallMs };
  }
  if (result.marker === null) {
    throw new Error(`erasure-pass: '${dir}' rewrote ${String(result.files)} parts and filed no marker`);
  }
  const marker = JSON.parse(await readFile(join(dir, result.marker), 'utf8')) as ScrubMarker;
  const parts = marker.parts;
  if (parts.length !== result.files) {
    throw new Error(
      `erasure-pass: the marker for '${dir}' names ${String(result.files)} files and carries ${String(parts.length)}`,
    );
  }
  const total = parts.reduce(
    (sum, each) => ({ beforeBytes: sum.beforeBytes + each.beforeBytes, afterBytes: sum.afterBytes + each.afterBytes }),
    { beforeBytes: 0, afterBytes: 0 },
  );
  if (parts.length !== 1) {
    throw new Error(`erasure-pass: '${dir}' holds ${String(parts.length)} parts and this run measures one per directory`);
  }
  const part = parts[0] as ScrubMarker['parts'][number];
  return {
    facts: {
      removed: result.removed,
      files: result.files,
      beforeBytes: total.beforeBytes,
      // One part per directory, so the marker's single pair is the run's pair; the totals above are the
      // same numbers read a second way, and a run that changed between them is a run worth stopping.
      beforeSha256: part.beforeSha256,
      afterBytes: total.afterBytes,
      afterSha256: part.afterSha256,
    },
    wallMs,
  };
}
