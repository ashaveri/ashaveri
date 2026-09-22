/**
 * A list of durations in milliseconds reduced to the handful of numbers a comparison needs.
 *
 * Percentiles are nearest rank on the ascending sort: the value at `ceil(p/100*n)`, index 1 when the
 * list is empty. Nearest rank is chosen over interpolation because these lists are wall-clock
 * durations whose every member is a real event, and an interpolated p99 of a list that holds eight
 * members would print a number for a shape of the data that was never observed. The rule makes the
 * limit of the method visible instead of hiding it: `count` travels with every percentile, and a list
 * under `MIN_P99_SAMPLES` has a p99 that is the maximum with a new label on it.
 */
export const MIN_P99_SAMPLES = 300;

export interface Distribution {
  count: number;
  mean: number;
  p50: number;
  p90: number;
  p99: number;
  max: number;
}

export function distribution(values: readonly number[]): Distribution {
  if (values.length === 0) {
    return { count: 0, mean: 0, p50: 0, p90: 0, p99: 0, max: 0 };
  }
  const sorted = [...values].sort((left, right) => left - right);
  const total = sorted.reduce((sum, each) => sum + each, 0);
  const at = (percent: number): number => {
    const rank = Math.max(1, Math.ceil((percent / 100) * sorted.length));
    return sorted[rank - 1] as number;
  };
  return {
    count: sorted.length,
    mean: total / sorted.length,
    p50: at(50),
    p90: at(90),
    p99: at(99),
    max: sorted[sorted.length - 1] as number,
  };
}

/**
 * How long the serving loop went without running a callback.
 *
 * A one-millisecond timer is the instrument, not the loop's own statistics: `monitorEventLoopDelay`
 * answers the same question with a histogram that clamps its top bucket, and the number this
 * measurement turns on is a single stall of several hundred milliseconds, which is exactly the value
 * a clamped histogram is worst at. Each tick records how late it arrived, so a tick that fires while
 * nothing is blocking it reports about zero and a tick that fires after a whole-file parse reports
 * that parse.
 */
export interface GapWatch {
  stop(): Distribution;
}

export function watchLoopGaps(intervalMs = 1): GapWatch {
  const gaps: number[] = [];
  let last = performance.now();
  const timer = setInterval(() => {
    const now = performance.now();
    gaps.push(Math.max(0, now - last - intervalMs));
    last = now;
  }, intervalMs);
  return {
    stop(): Distribution {
      clearInterval(timer);
      return distribution(gaps);
    },
  };
}

export function sleep(ms: number): Promise<void> {
  return new Promise<void>((resolve) => {
    setTimeout(resolve, ms);
  });
}

/**
 * How long the serving process lets an acknowledgement sit before starting the work it announces.
 *
 * A write to a pipe is not the pipe's receipt of it, and the pass that follows holds that loop, so a run
 * that started immediately could leave its own acknowledgement buffered until the erasure was over and
 * have its measurement window placed around the wrong seconds. Both ends read this one constant: the
 * delay the child sleeps and the samples the parent throws away are the same number by construction.
 */
export const ACK_GRACE_MS = 60;

/** One duration, printed the way every number in this run's output is printed. */
export function ms(value: number): string {
  return `${value.toFixed(value < 10 ? 2 : 1)}ms`;
}
