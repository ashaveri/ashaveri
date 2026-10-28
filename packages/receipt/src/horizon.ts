import type { PackSpan } from './pack.js';

/**
 * How far back a deployment can prove it held receipts, folded from the two places the evidence lives.
 *
 * A deployment retires receipts out of its live store on the bounds it configures, and an evidence epoch is
 * what survives that: the sealed run carries the years the file has shed, and the file carries what is still
 * live. Neither answers the question on its own, and the store alone can state very little at real traffic:
 * the shipped durability count of 10,000 receipts is seconds of traffic at the throughput one process serves
 * for, so a deployment that has been sealing for years and reads only its own live window is told about its
 * last month.
 *
 * The fold is where the two framings meet, which is the reason it exists as code rather than as a sentence an
 * operator writes. A sealed run states half-open windows, from included and to excluded, because that is what
 * lets a run's windows meet without overlapping; the store's retained set states both ends inclusive, because
 * it is reporting stamps that are on the volume. Read one as the other and every horizon is a day short or a
 * day long, so the conversion happens here, once, and each segment says which framing it came from.
 *
 * Nothing here concludes that a duty was discharged. The reach is arithmetic over evidence; which period is
 * owed, to whom, and under which article is the deployment's reading, and a fold that paired the two without
 * being asked would be this package answering a question of law. So the verdict appears exactly when a caller
 * hands in a period, and the two figures it compares stay beside it for a reader to recompute.
 */

/** One sealed run, as the epoch inventory states it. Only the run's own edges are read: the inventory's
 *  reader has already refused a document whose window is not the outer edges of the packs it lists. */
export interface HorizonSealedRun {
  readonly window: PackSpan;
}

/**
 * The live store's retained set: the oldest and newest stamps it still holds, inclusive at both ends.
 *
 * Two numbers rather than the store's three because the door a caller reads this from has already weighed the
 * count: it answers no live source at all where the store holds nothing. The pair is declared here rather than
 * imported from the gateway because the store lives there, the gateway reads this package, and a receipt type
 * that reached back up the dependency for a shape would turn a direction into a cycle.
 */
export interface HorizonLiveWindow {
  readonly from: number;
  readonly to: number;
}

/** The period the deployment takes its article to require, as the caller declares it. */
export interface HorizonDutyDeclaration {
  readonly article: string;
  readonly requiredSeconds: number;
}

/** The evidence a horizon is folded from. Both sources are optional because a deployment can legitimately hold
 *  one and not the other; what cannot be true is neither, and that is what `horizonFault` answers. */
export interface ProvableHorizonSources {
  readonly run?: HorizonSealedRun | null;
  readonly live?: HorizonLiveWindow | null;
  readonly duty?: HorizonDutyDeclaration | null;
}

export type HorizonSourceName = 'sealed-run' | 'live-window';

/** One stretch of reach, in one framing converted to the other. `toExclusive` is half-open on purpose: the
 *  store's inclusive end and a pack window's exclusive end have to be added by one rule, not by a reader. */
export interface HorizonSegment {
  readonly source: HorizonSourceName;
  readonly from: number;
  readonly toExclusive: number;
}

/** A stretch between two segments that no source states. It is unproven rather than absent: a period can have
 *  been held and sealed into a run this directory does not list. */
export interface HorizonGap {
  readonly from: number;
  readonly toExclusive: number;
}

/** The fold's answer. `from`, `toExclusive` and `seconds` describe the longest continuous reach, so a run that
 *  stops and a store that starts later are two stretches of evidence and not one horizon. */
export interface ProvableHorizon {
  readonly from: number;
  readonly toExclusive: number;
  readonly seconds: number;
  readonly continuous: boolean;
  readonly segments: readonly HorizonSegment[];
  readonly gaps: readonly HorizonGap[];
  readonly duty: (HorizonDutyDeclaration & { readonly heldSeconds: number; readonly met: boolean }) | null;
  readonly because: readonly string[];
}

/**
 * The report an empty store gives: both ends at zero, because `window()` states the zero window rather than no
 * window. Read as a stretch it would start a horizon at the epoch and state more than half a century of reach
 * for a deployment that has issued nothing, and the stamps alone cannot tell that report from a single receipt
 * stamped at zero, which is why the fold refuses it rather than measuring it. One function holds the tell
 * because both the fault and the fold answer it, and a second copy could disagree with the first about which
 * windows count as evidence.
 */
function isZeroWindow(one: HorizonLiveWindow): boolean {
  return one.from === 0 && one.to === 0;
}

/**
 * Why no horizon can be stated, or null when one can.
 *
 * Three refusals, each of them a shape a real report arrives in rather than a type the caller could not have
 * built: a window whose end precedes its start, which would be answered with a negative duration nobody could
 * disbelieve; the empty store's zero window above; and no evidence source at all, which is a question with no
 * reading rather than a reach of zero seconds.
 */
export function horizonFault(sources: ProvableHorizonSources): string | null {
  const live = sources.live ?? null;
  const run = sources.run ?? null;
  if (run !== null && run.window.to < run.window.from) {
    return `the sealed run reaches from ${String(run.window.from)} to ${String(run.window.to)} and runs backwards`;
  }
  if (live !== null && live.to < live.from) {
    return `the live window reaches from ${String(live.from)} to ${String(live.to)} and runs backwards`;
  }
  if (run !== null) return null;
  if (live === null) {
    return 'no sealed run and no live window were handed to fold, so there is no evidence to reach over';
  }
  if (isZeroWindow(live)) {
    return 'the live window is the zero window from 0 to 0, which is a store stating it holds nothing rather than a reach from the epoch';
  }
  return null;
}

/**
 * Fold the reach, or null where `horizonFault` says it cannot be stated.
 *
 * The segments are merged in the order the evidence falls, and two stretches join when one opens no later than
 * the other closes: adjacency is continuity, because a run whose exclusive end is the instant the store opens
 * at covers every stamp between its edges without a day belonging to neither. Where they do not join, the
 * stretch between them is reported as a gap and the reach is the longest continuous one, so a decade of sealed
 * evidence and a month of live evidence with a hole between them state a decade and not a decade plus a month.
 */
export function foldProvableHorizon(sources: ProvableHorizonSources): ProvableHorizon | null {
  const fault = horizonFault(sources);
  if (fault !== null) return null;

  const segments: HorizonSegment[] = [];
  const live = sources.live ?? null;
  if (sources.run !== null && sources.run !== undefined) {
    segments.push({ source: 'sealed-run', from: sources.run.window.from, toExclusive: sources.run.window.to });
  }
  if (live !== null && !isZeroWindow(live)) {
    segments.push({ source: 'live-window', from: live.from, toExclusive: live.to + 1 });
  }
  segments.sort((one, other) => one.from - other.from || one.toExclusive - other.toExclusive);

  const gaps: HorizonGap[] = [];
  // The merged stretches are the fold's working state and their ends move as neighbours join, so they are
  // built as mutable records here and reported through the read-only segment type at the return.
  const stretches: { source: HorizonSourceName; from: number; toExclusive: number }[] = [];
  for (const segment of segments) {
    const open = stretches[stretches.length - 1];
    if (open === undefined) {
      stretches.push({ ...segment });
      continue;
    }
    if (segment.from > open.toExclusive) {
      gaps.push({ from: open.toExclusive, toExclusive: segment.from });
      stretches.push({ ...segment });
    } else {
      open.toExclusive = Math.max(open.toExclusive, segment.toExclusive);
    }
  }

  // The fault answered first, so at least one source stated receipts and at least one stretch exists: the
  // fold below has no empty-array case to reach and takes its first stretch as the seed rather than casting.
  const longest = stretches.reduce((best, one) =>
    one.toExclusive - one.from > best.toExclusive - best.from ? one : best,
  );
  const seconds = longest.toExclusive - longest.from;
  const declaration = sources.duty ?? null;
  const met = declaration !== null && seconds >= declaration.requiredSeconds;
  const duty = declaration === null ? null : { ...declaration, heldSeconds: seconds, met };
  const because =
    declaration === null
      ? []
      : [
          met
            ? `the evidence reaches ${String(seconds)} seconds and the declared duty requires ${String(declaration.requiredSeconds)}, so the reach covers the period`
            : `the evidence reaches ${String(seconds)} seconds and the declared duty requires ${String(declaration.requiredSeconds)}, so the reach falls short by ${String(declaration.requiredSeconds - seconds)}`,
        ];

  return {
    from: longest.from,
    toExclusive: longest.toExclusive,
    seconds,
    continuous: gaps.length === 0,
    segments,
    gaps,
    duty,
    because,
  };
}
