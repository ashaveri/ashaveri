/**
 * The resident request-body budget: one integer of bytes, and the only two acts that move it.
 *
 * A raised per-request body bound says how large one body may be and says nothing about how many of them one
 * process holds at once, which is the question a raised bound makes expensive: a request body stays resident
 * for the whole life of its completion, because the receipt signs those exact bytes and the upstream is
 * forwarded them, so N callers in flight hold N bodies. This file bounds that sum rather than counting the
 * requests that make it up, because the cost a deployment runs out of is bytes and not requests: one 128 MiB
 * ask and one hundred 1 MiB asks are the same to a memory limit and nothing like it to a counter of requests.
 *
 * It is deliberately hand-rolled rather than a fourth bucket beside the credential, connection and completion
 * ones. Those three are rate limits, and a rate limit has a refill an arithmetic can see, which is why each
 * can state when its next token appears. This is a capacity bound, and what frees it is other requests
 * finishing: an event, on a duration nothing here observes. Turning it into a bucket would be inventing a
 * refill curve to make a number printable, and a caller that acted on the invented figure would retry on a
 * schedule that does not exist.
 *
 * One instance belongs to one process, held like the completion counter is. It is memory only, is never
 * written down, and does not outlive the process, so it is no one's record and states no obligation that
 * survives a restart.
 */

/** What one request holds, and what the answer to a refusal says about waiting. */
export interface ResidentBodyReservation {
  /** Whether the bytes are now held on this budget. True means the request is admitted on this question. */
  readonly admitted: boolean;
  /**
   * How many of the budget's bytes this refusal turned away, whether or not it was admitted. The caller owes
   * the release of exactly this number and nothing else, so the figure travels back on the answer rather than
   * being recomputed from the request, which is where a charge and a release that disagree would come from.
   */
  readonly bytes: number;
  /**
   * Seconds a caller should wait before trying again, or absent when no wait can clear the refusal.
   *
   * Absent is one state and only one: this body alone is past the whole budget, so the bytes it asks for can
   * never be held by this process as it is configured, whatever else is in flight or finished. Everything else
   * is a number, because a body that would fit if the process were emptier is refused on company and not on
   * size. The number is a floor rather than a measurement, and `resident-body-budget.test.ts` holds the two
   * arms apart; `RETRY_AFTER_FLOOR_SECONDS` above states why the number is one and not zero.
   */
  readonly retryAfterSeconds: number | undefined;
}

/**
 * The smallest wait this budget will name, and the reason it is not zero: the same one the rate buckets give
 * their own floor for in `TokenBucket.take`, that "a hint the client cannot act on invites it to retry
 * immediately, which is the traffic this is meant to hold back". A capacity refusal has no arithmetic behind
 * its wait at all, so this is the whole of what it claims to know.
 */
const RETRY_AFTER_FLOOR_SECONDS = 1;

/** The budget, as one integer of bytes held against one integer of bytes allowed. */
export class ResidentBodyBudget {
  /**
   * The whole number of request-body bytes this process may hold at once.
   *
   * A budget below one body's worth is a legal statement about a deployment ("we will not hold that much"),
   * so nothing here refuses it, and the refusal it produces is the arm that carries no wait. A budget that is
   * not a positive whole number of bytes is refused, because a bound this process cannot state is not a bound
   * it may serve on: that is the rule the request body bound already applies to its own setting, and the same
   * reasoning about what a caller would believe it had configured applies harder here, where the consequence
   * of a wrong number is an out-of-memory kill rather than a length nobody asked for.
   */
  readonly limitBytes: number;
  private held = 0;

  constructor(limitBytes: number) {
    if (!Number.isInteger(limitBytes) || limitBytes < 1) {
      throw new RangeError(
        `requestBodyBudgetBytes is ${String(limitBytes)}, and a resident request-body budget is a positive whole number of bytes`,
      );
    }
    this.limitBytes = limitBytes;
  }

  /** What this process holds now, in bytes. Read by the cells that assert a release happened. */
  get residentBytes(): number {
    return this.held;
  }

  /**
   * Take `bytes` out of the budget, or refuse and say what waiting would do.
   *
   * The sum is compared before anything is added, so a refusal changes nothing and needs no undo, which is the
   * only reason a caller can trust the figure it is told: the process either holds these bytes or it holds
   * what it held before, and never a state between the two.
   *
   * A request already past the whole budget is refused on the second arm, the one with no wait: nothing about
   * the traffic can make room for it. A request that fits is admitted even when it empties the budget, and an
   * empty budget is not an overload: it is a deployment that said how much it would hold and is holding that
   * much, which is the state the bound was chosen to reach and stop at.
   */
  reserve(bytes: number): ResidentBodyReservation {
    if (!Number.isInteger(bytes) || bytes < 0) {
      throw new RangeError(`a resident body charge of ${String(bytes)} is not a whole number of bytes taken in`);
    }
    if (bytes > this.limitBytes) {
      return { admitted: false, bytes, retryAfterSeconds: undefined };
    }
    if (this.held + bytes > this.limitBytes) {
      return { admitted: false, bytes, retryAfterSeconds: RETRY_AFTER_FLOOR_SECONDS };
    }
    this.held += bytes;
    return { admitted: true, bytes, retryAfterSeconds: undefined };
  }

  /**
   * Give `bytes` back, once.
   *
   * The clamp is not a tolerance for a double release. Exactly-once is held where the charge is held, on the
   * request's own state, because a budget that also guarded against its caller would let a caller that
   * released twice watch the resident figure fall below what is genuinely in flight and stop refusing at
   * exactly the moment it exists to refuse at. What the clamp does is refuse a worse outcome: this runs on a
   * response's `finish` and `close`, where a thrown error would reach nothing but the process, so a bookkeeping
   * fault must not become a crash, and the arithmetic has to stay in the log to be found at all.
   */
  release(bytes: number): void {
    if (bytes > this.held) {
      process.emitWarning(
        `the resident request-body budget was handed back ${String(bytes)} bytes while holding ` +
          `${String(this.held)}, so the held figure was floored at zero rather than go negative`,
        { code: 'ASHAVERI_RESIDENT_BODY_RELEASE_UNDERFLOWS' },
      );
      this.held = 0;
      return;
    }
    this.held -= bytes;
  }
}
