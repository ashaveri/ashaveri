import { readFile } from 'node:fs/promises';
import type { TimeSource } from './store.js';

/**
 * A deployment's stamps read out of a state file its own clock synchronisation maintains.
 *
 * `HOST_CLOCK_SOURCE` in `gateway/src/store.ts` is the shipped source: this host's own claim, at the
 * uncertainty nobody measured. A receipt's `sd` member names whichever of the two read the stamp, so the
 * choice of source is a statement inside the artifact and not only a setting of the process. A caller of
 * the library has always been able to substitute one at the seam in `buildGateway` and
 * `openFileReceiptStore`; a deployment running the shipped binary could not, and so stamped every receipt
 * from the clock whoever hosts it can set. This module is the route for that deployment, expressed the one
 * way that keeps the promise honest: the operator's synchronisation writes a small document saying which
 * source it read, how far that reading can be from the instant it names, and when it was taken, and the
 * gateway reads the document on a timer and stamps from what it holds in memory.
 *
 * Three decisions shape everything below, and each is a refusal of a cheaper alternative.
 *
 * **The document declares the source and the bound; the command line names only a path.** The writer is
 * the thing that knows how far it can be from the truth, so a bound typed at a shell would be a second
 * claim about one clock, free to disagree with the first. Nothing here widens, narrows or replaces a
 * number the document states.
 *
 * **The reading is cached and advanced on a monotonic base.** A synchronous read of a file of this size
 * costs hundreds of microseconds on the host this was measured on, several thousand times what `Date.now()`
 * costs, and the store's own append beside it is a millisecond and a half, so a read taken for every stamp
 * would be a tax on the signing path and would put a file system in front of every issuance. Between reads
 * the cached instant moves on `performance.now()`, which counts time since this process started and is
 * moved by nothing a host clock step does: the stamps this source yields never run backwards and never
 * inherit a step, which is the whole reason an external source is worth naming in a signed document.
 *
 * **An unreadable, unparseable or stale state stops the process rather than falling back.** A run that was
 * told where to read its time and could not, and then issued under `host clock` while its receipts named
 * the source it never read, would put a false sentence inside a signed artifact. That is not a degraded
 * mode; it is the one outcome this repository must not ship. So a state that cannot be read at the start is
 * a refusal to start, and a state that goes stale mid-run is a refusal to stamp, with the age, the bound
 * and the file named in both.
 *
 * What is left to the deployment is the writer: this module reads a document and never writes one, and the
 * writer is expected to replace the file atomically, by writing a temporary file and renaming it over this
 * path. The reader does not depend on that for its safety: a whole document is read, validated in full,
 * and adopted in one assignment, so a half-written file is refused as a whole and the reading already held
 * stays in force unchanged.
 */

/** The one version of the state document this reader reads, and the version every refusal quotes. */
export const TIME_SOURCE_STATE_FILE_VERSION = 1;

/**
 * The widest interval this route waits between two reads of a state file.
 *
 * It is a bound on the reader's own contribution to a stamp's error, because an extrapolated instant can
 * be no fresher than the last read it came from, and a deployment whose source is bounded at an hour is
 * not served by a reader that wakes every second to notice nothing changed.
 */
export const MAX_TIME_SOURCE_STATE_REFRESH_SECONDS = 60;

/**
 * The narrowest interval it reads on, whatever the document's bound allows.
 *
 * A bound of zero is a source claiming its reading is the instant, and this route cannot carry that claim
 * exactly: it can only hold the gap between two reads to one second, which is the resolution every stamp
 * in this estate is written in. A narrower interval would be a timer firing inside one stamped second,
 * which buys nothing a whole second can tell apart.
 */
export const MIN_TIME_SOURCE_STATE_REFRESH_SECONDS = 1;

/**
 * How far a state's declared instant may stand from this host's own claim at the one moment that pair is
 * weighed, in whole seconds: one day.
 *
 * The band is a statement about the document rather than about the clock. A file whose instant sits further
 * from the host's claim than a day is not a clock that drifted, it is a document that names no instant
 * anybody can reach, and no later rule can repair that: the bound it declares, the liveness rule below,
 * and every stamp taken under both are arithmetic on that instant. This is also the only moment this route
 * reads a wall clock, and the only moment it is allowed to, because the reason a deployment names an
 * external source at all is that its host claim may be away by more than a bound anybody could sign. A
 * check repeated on every read would hand a stepped host clock the power to refuse good documents, which is
 * the power this route exists to take away from it.
 */
export const TIME_SOURCE_STATE_PLAUSIBILITY_BAND_SECONDS = 86_400;

/** The members of version 1 of the document, and the only members it may carry. */
const STATE_MEMBERS: readonly string[] = [
  'version',
  'source',
  'uncertaintySeconds',
  'measuredAtSeconds',
];
const MEMBER_NAMES: ReadonlySet<string> = new Set<string>(STATE_MEMBERS);

/**
 * How many refresh intervals are added to a declared bound before the state is called stale.
 *
 * Two, and each has a reader-side reason rather than a claim about the source. One interval covers the
 * phase between the writer's own timer and this reader's: a file advanced one moment before a read is no
 * older at that read than the instant it states. One covers the fact that the check runs when a stamp is
 * taken, so an age crossing the line is noticed at the next stamp rather than at the instant it crossed.
 * Neither is a measurement of anybody's clock, which is why they are counted in intervals of this process
 * rather than in seconds borrowed from the host.
 */
const LIVENESS_ALLOWANCE_INTERVALS = 2;

/** A state document as this module reads it, after every refusal below has been passed. */
export interface TimeSourceState {
  /** The source the operator's synchronisation says it read, in its own words. */
  readonly source: string;
  /**
   * How far its readings can be from the instants they name, in whole seconds, or null for the sentence
   * that nobody measured: a different claim from zero, exactly as `TimeSource` states it.
   */
  readonly uncertaintySeconds: number | null;
  /** The instant the writer read off that source, in whole Unix seconds. */
  readonly measuredAtSeconds: number;
}

/** Why this route refuses: a fact about a file, named as one, with no code a wire format carries. */
export class TimeSourceStateError extends Error {
  constructor(detail: string) {
    super(detail);
    this.name = 'TimeSourceStateError';
  }
}

/**
 * The reading this source answers from: the file's word, the instant advanced from it, and the ceiling the
 * file's own bound sets on how far behind the word the advanced instant may fall before the pair stops
 * being one source's reading.
 *
 * It is one immutable object swapped whole, which is what makes a torn write incapable of half-updating a
 * source: no field of the reading in force is ever edited in place, so a stamp reads either the state
 * before a document was adopted or the state after it, and never a pair taken from both.
 */
interface CachedState {
  readonly source: string;
  readonly uncertaintySeconds: number | null;
  /** The instant the document last stated, which is what an age is weighed against. */
  readonly declared: number;
  /** The whole-second instant the extrapolation started from, never below one already stamped. */
  readonly base: number;
  /** The monotonic reading taken when `base` was set. */
  readonly baseMono: number;
  /** How far `declared` may sit behind a stamp before this source stops answering. */
  readonly stalenessCeilingSeconds: number;
}

/** The options this route is opened with: the path the operator named, and the seams a test reads through. */
export interface TimeSourceStateOptions {
  /** The state file to read. Required, because there is no name for it to fall back on. */
  readonly path: string;
  /**
   * The interval to read on. Absent means the interval derived from the bound the document states, which
   * is what a deployment runs; it is a seam for a caller that wants a cadence of its own and not a second
   * bound competing with the file's.
   */
  readonly refreshSeconds?: number;
  /** This process's monotonic clock, in seconds. Absent means `performance.now()` scaled to seconds. */
  readonly monotonicSeconds?: () => number;
  /** A wall clock in whole Unix seconds, read once at the start and for the plausibility band only. */
  readonly wallSeconds?: () => number;
  /** Where a mid-run read failure is reported once, so an idle operator still sees it. */
  readonly report?: (line: string) => void;
}

/** The handle a process holds: the source to wire, and the two things that keep it alive. */
export interface TimeSourceStateHandle {
  /** The state file this source reads, as this run was handed it, so a report can name it. */
  readonly path: string;
  /** The source to hand every builder that takes one, as `gateway/src/cli.ts` does. */
  readonly source: TimeSource;
  /** How many times the file has been read, start-up read included. */
  stateReads(): number;
  /**
   * One read, validation and adoption, which is exactly what the timer runs. A caller that wants to force
   * a read, or to watch one fail, asks through here rather than waiting a cadence for it.
   */
  refresh(): Promise<void>;
  /** The current cadence and ceiling, as this process holds them for the document in force. */
  policy(): { readonly refreshSeconds: number; readonly stalenessCeilingSeconds: number };
  /** Stop the timer. The source keeps answering from what it holds until the state runs past its ceiling. */
  stop(): void;
}

function reasonOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function isJsonObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** The monotonic base: seconds since this process started, moved by nothing a host clock does. */
function performanceSeconds(): number {
  return performance.now() / 1000;
}

/** The host's own claim, in the whole seconds every instant in this estate is written in. */
function hostWallSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

/**
 * The bound a document states, as the number the reader derives a cadence and a ceiling from.
 *
 * Null is kept null rather than read as zero or as some shipped figure: it says nobody measured, and every
 * sentence and every ceiling derived from it has to stay capable of saying that.
 */
function declaredBound(value: unknown, path: string): number | null {
  if (value === null) return null;
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) {
    throw new TimeSourceStateError(
      `${path} states uncertaintySeconds as ${JSON.stringify(value)}, which is neither null nor a whole number of seconds of at least zero: ` +
        'null is the sentence that nobody measured, and a number is a measurement, so no other spelling answers either',
    );
  }
  if (value > TIME_SOURCE_STATE_PLAUSIBILITY_BAND_SECONDS) {
    throw new TimeSourceStateError(
      `${path} states uncertaintySeconds as ${String(value)}, further from its own instant than the ` +
        `${String(TIME_SOURCE_STATE_PLAUSIBILITY_BAND_SECONDS)} second band this route weighs a document's instant against, ` +
        'so nothing a reader could say about this source bounds a stamp taken under it',
    );
  }
  return value;
}

/**
 * The cadence this route reads on, derived from the bound the document states.
 *
 * Half the bound, held between one second and the widest interval above. The derivation is the reason a
 * per-stamp read is unnecessary without being a licence to be slow: an extrapolated instant can be away
 * from the truth by the bound the writer declares plus at most one interval of this reader's own, so an
 * interval at or under half the bound keeps the pair inside twice the bound, which is the distance
 * `readingsApart` in `gateway/src/store.ts` already refuses to call two readings of one source different.
 * A null bound gives the reader nothing to halve, and the widest interval is what it falls to: the cadence
 * then bounds this process's curiosity and makes no claim at all about the source's accuracy, which is the
 * honest answer beside a source nobody measured.
 */
export function refreshSecondsFor(uncertaintySeconds: number | null): number {
  if (uncertaintySeconds === null) return MAX_TIME_SOURCE_STATE_REFRESH_SECONDS;
  const half = Math.floor(uncertaintySeconds / 2);
  return Math.min(MAX_TIME_SOURCE_STATE_REFRESH_SECONDS, Math.max(MIN_TIME_SOURCE_STATE_REFRESH_SECONDS, half));
}

/**
 * How far behind the document's own instant a stamp may fall before this source stops answering.
 *
 * The bound the file states, plus the intervals the reader cannot see inside, and for a bound of null the
 * intervals alone. Read the two arms as the two sentences they are. With a bound the reader is saying that a
 * measurement older than its own bound, once the writer's phase and the check's granularity are allowed for,
 * has stopped being that measurement: it is this process's arithmetic wearing its name. With no bound the
 * file states nothing an age could be weighed against, so the rule for it is liveness alone, the file having
 * to keep advancing within the reader's own intervals; the tolerance there is a fact about this reader's
 * timers and never a zero standing in for a measurement nobody took.
 *
 * With a declared bound of at least two seconds the two arms together stay inside twice that bound, which
 * is the distance `readingsApart` in `gateway/src/store.ts` already refuses to call a difference between two
 * readings of one source, so the ceiling this route enforces is the estate's own resolution and not a number
 * beside it. A bound of zero or one second is the exception the reader's own floor makes, because a timer
 * that wakes inside one stamped second sees nothing a whole second can tell apart: there the interval added
 * is the one second of that floor rather than half the bound, and it is the ceiling printed in the refusal
 * that an operator reads, never an ideal derived from a bound the timer cannot honour.
 */
export function stalenessCeilingSeconds(uncertaintySeconds: number | null, refreshSeconds: number): number {
  const allowance = LIVENESS_ALLOWANCE_INTERVALS * refreshSeconds;
  return uncertaintySeconds === null ? allowance : uncertaintySeconds + allowance;
}

/** The instant the cache answers at `mono`: the adopted whole second, moved on by elapsed monotonic time. */
function heldAt(state: CachedState, mono: number): number {
  // The floor is what keeps a stamp a whole second, and the clamp is what keeps an injected or restarted
  // monotonic base from moving an instant backwards: this source's own contract is that its stamps do not.
  const elapsed = Math.max(0, Math.floor(mono - state.baseMono));
  return state.base + elapsed;
}

/**
 * The document's bytes, read into a state or refused with the file named.
 *
 * Every member is checked before anything is returned, and nothing is returned beside the members this
 * version has, because the document is the deployment's own statement about the clock its receipts name.
 * That is why this reader is strict where `parseRecord` in `gateway/src/access.ts` is not: a credential
 * record is an input the deployment hands this process for it to use, and a member it does not know is
 * nothing to this process, while a state document *is* the statement that travels into a signed payload. A
 * member dropped here would be a claim about the source quietly left out of the artifact, and a writer that
 * began stating a tighter bound, or a second source, would find the receipts still saying the older one.
 * Refusing an unknown member makes that drift a start-up failure an operator sees instead of a disclosure
 * that stopped being true.
 */
export function parseTimeSourceState(bytes: Uint8Array, path: string): TimeSourceState {
  let value: unknown;
  try {
    value = JSON.parse(Buffer.from(bytes).toString('utf8')) as unknown;
  } catch (error) {
    throw new TimeSourceStateError(`${path} is not readable as JSON: ${reasonOf(error)}`);
  }
  if (!isJsonObject(value)) {
    throw new TimeSourceStateError(
      `${path} is not a JSON object, which is the shape one time source state takes`,
    );
  }
  for (const key of Object.keys(value)) {
    if (!MEMBER_NAMES.has(key)) {
      throw new TimeSourceStateError(
        `${path} states ${key}, which is not a member of version ${TIME_SOURCE_STATE_FILE_VERSION} of a time source state document: ` +
          `its members are ${STATE_MEMBERS.join(', ')}`,
      );
    }
  }
  for (const key of STATE_MEMBERS) {
    if (!(key in value)) {
      throw new TimeSourceStateError(
        `${path} states no ${key}, and a version ${TIME_SOURCE_STATE_FILE_VERSION} document carries all four of its members`,
      );
    }
  }
  if (value['version'] !== TIME_SOURCE_STATE_FILE_VERSION) {
    throw new TimeSourceStateError(
      `${path} states version ${JSON.stringify(value['version'])}, and this gateway reads version ` +
        `${TIME_SOURCE_STATE_FILE_VERSION} time source state documents`,
    );
  }
  const source = value['source'];
  if (typeof source !== 'string' || source.trim().length === 0) {
    throw new TimeSourceStateError(
      `${path} states source as ${JSON.stringify(source)}, which is not the text naming the clock these stamps are read from: ` +
        'that text is what the `sd` member of a signed receipt carries, so an empty one names nothing',
    );
  }
  const measuredAtSeconds = value['measuredAtSeconds'];
  if (typeof measuredAtSeconds !== 'number' || !Number.isInteger(measuredAtSeconds) || measuredAtSeconds < 0) {
    throw new TimeSourceStateError(
      `${path} states measuredAtSeconds as ${JSON.stringify(measuredAtSeconds)}, which is not a whole number of Unix seconds of at least zero: ` +
        'every comparison, retirement and stamp in this estate is taken in whole seconds, and a fractional or negative reading is neither',
    );
  }
  return { source, uncertaintySeconds: declaredBound(value['uncertaintySeconds'], path), measuredAtSeconds };
}

/** The refusal an operator reads when the state has run past what its own document can stand behind. */
function stalenessRefusal(
  path: string,
  state: CachedState,
  ageSeconds: number,
  lastFault: string | undefined,
): string {
  const bound =
    state.uncertaintySeconds === null
      ? 'on which nobody measured an uncertainty, so only the file keeping current bounds it at all'
      : `bounded at ${String(state.uncertaintySeconds)} seconds`;
  return (
    `the time source state ${path} names the source ${state.source}, ${bound}, and its stated instant is ` +
    `${String(ageSeconds)} seconds behind the instant this process is stamping with, past the ` +
    `${String(state.stalenessCeilingSeconds)} seconds this route allows, so no further receipt is signed from it` +
    (lastFault === undefined ? '' : `; the last read of it failed: ${lastFault}`)
  );
}

/** The refusal for a document whose instant no reader can place, which stops a start rather than a stamp. */
function implausibleState(path: string, state: TimeSourceState, wallSeconds: number): string {
  const apart = Math.abs(state.measuredAtSeconds - wallSeconds);
  return (
    `${path} states a measured instant of ${String(state.measuredAtSeconds)}, which is ${String(apart)} seconds from ` +
    `this host's own claim of ${String(wallSeconds)} and further than the ` +
    `${String(TIME_SOURCE_STATE_PLAUSIBILITY_BAND_SECONDS)} second band a start-up weighs a document's instant against, ` +
    'so this route refuses to sign receipts from it rather than keep a number no clock is near'
  );
}

/**
 * The source at `path`: read once and proved before anything is returned, then refreshed on a timer.
 *
 * The first read answers through here rather than through the timer, so a deployment that named a file and
 * got nothing readable is refused before a receipt store is opened, before an access log is, and before any
 * stamp is taken. Nothing in this function falls back: `HOST_CLOCK_SOURCE` is reachable only by a caller
 * that did not name a state file, and the name and bound a receipt carries are read out of the same object
 * that answered the instant, so a document that cannot be read cannot be quoted as a source.
 */
export async function openTimeSourceState(options: TimeSourceStateOptions): Promise<TimeSourceStateHandle> {
  const path = options.path;
  const monotonic = options.monotonicSeconds ?? performanceSeconds;
  const wall = options.wallSeconds ?? hostWallSeconds;
  const report = options.report;

  let reads = 0;
  let lastFault: string | undefined;
  let reported = false;

  async function readState(): Promise<TimeSourceState> {
    reads += 1;
    let bytes: Buffer;
    try {
      bytes = await readFile(path);
    } catch (error) {
      throw new TimeSourceStateError(`${path} could not be read: ${reasonOf(error)}`);
    }
    return parseTimeSourceState(bytes, path);
  }

  const first = await readState();
  const wallSeconds = wall();
  if (Math.abs(first.measuredAtSeconds - wallSeconds) > TIME_SOURCE_STATE_PLAUSIBILITY_BAND_SECONDS) {
    throw new TimeSourceStateError(implausibleState(path, first, wallSeconds));
  }
  const refreshSeconds = options.refreshSeconds ?? refreshSecondsFor(first.uncertaintySeconds);
  const startMono = monotonic();
  let state: CachedState = {
    source: first.source,
    uncertaintySeconds: first.uncertaintySeconds,
    declared: first.measuredAtSeconds,
    base: first.measuredAtSeconds,
    baseMono: startMono,
    stalenessCeilingSeconds: stalenessCeilingSeconds(first.uncertaintySeconds, refreshSeconds),
  };

  /**
   * Adopt one document, whole.
   *
   * The new reading is built in full before the reference moves, so a refusal part way through leaves the
   * reading in force exactly as it stood. The base is the greater of the document's instant and the instant
   * this source has already reached, which is what keeps a stamp from running backwards when a writer
   * reports a measurement behind the extrapolation it is being read through: the file's word still moves the
   * ceiling and the name, and an instant already signed stays signed.
   */
  async function refresh(): Promise<void> {
    const next = await readState();
    const mono = monotonic();
    state = {
      source: next.source,
      uncertaintySeconds: next.uncertaintySeconds,
      declared: next.measuredAtSeconds,
      base: Math.max(next.measuredAtSeconds, heldAt(state, mono)),
      baseMono: mono,
      stalenessCeilingSeconds: stalenessCeilingSeconds(next.uncertaintySeconds, refreshSeconds),
    };
    lastFault = undefined;
    reported = false;
  }

  const timer = setInterval(() => {
    void refresh().catch((error: unknown) => {
      lastFault = error instanceof Error ? error.message : String(error);
      // Once per fault, because a timer that prints a sentence every interval buries the one line that
      // names the file the operator has to fix, and a deployment with traffic learns about the same fault
      // from every refused stamp anyway.
      if (!reported && report !== undefined) {
        reported = true;
        report(lastFault);
      }
    });
  }, refreshSeconds * 1000);
  // The timer is not a reason for a process to stay alive: a gateway holds a listener, and a caller of the
  // library that only wanted a source should be able to finish.
  timer.unref();

  return {
    path,
    source: {
      get name(): string {
        return state.source;
      },
      get uncertaintySeconds(): number | null {
        return state.uncertaintySeconds;
      },
      nowSeconds(): number {
        const mono = monotonic();
        const held = heldAt(state, mono);
        const age = held - state.declared;
        if (age > state.stalenessCeilingSeconds) {
          throw new TimeSourceStateError(stalenessRefusal(path, state, age, lastFault));
        }
        return held;
      },
    },
    stateReads(): number {
      return reads;
    },
    refresh,
    policy(): { readonly refreshSeconds: number; readonly stalenessCeilingSeconds: number } {
      return { refreshSeconds, stalenessCeilingSeconds: state.stalenessCeilingSeconds };
    },
    stop(): void {
      clearInterval(timer);
    },
  };
}
