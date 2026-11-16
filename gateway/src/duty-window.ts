import type { CustomerInstructionRecord } from './instruction-record.js';

/**
 * The one place that answers whether a window can hold the period the same deployment states it owes.
 *
 * Three edges ask it: the receipts store's age bound, the access log's window, and a pack run's declared
 * duty against the store bounds handed to it. Each knows its own units, flags and remedy, so what is
 * shared is the comparison and the one sentence the two record-facing edges would otherwise each write
 * from scratch. Two copies of a comparison in a repository that configures windows is one renamed
 * constant away from answering the same pairing two ways, which is the defect this file exists to close.
 *
 * Two things are deliberately absent. No floor: `MINIMUM_RETENTION_SECONDS` is what a deployment gets when
 * it names nothing, and Articles 19(1) and 26(6) both yield to applicable Union or national law, which
 * moves a period in either direction, so nothing here may call a stated period malformed for being short.
 * No verdict about owed-ness: whether a period is owed at all belongs to the deployment's own record and,
 * for a pack, to the mapping revision its entry names. What this file weighs is one pairing of two
 * numbers, and it states the shortfall as a number rather than as an opinion about a duty.
 */
export const SECONDS_PER_DAY = 86_400;

/** Whole days as whole seconds, so an edge that counts in days and an edge that counts in seconds compare. */
export function daysToSeconds(days: number): number {
  return days * SECONDS_PER_DAY;
}

/** The pairing this file refuses, stated as three numbers and no opinion. */
export interface DutyWindowGap {
  readonly windowSeconds: number;
  readonly statedSeconds: number;
  readonly shortBySeconds: number;
}

/**
 * Nothing when the window reaches the stated period, and the three numbers when it does not.
 *
 * The comparison is on seconds and not on days because the two edges arrive in different units: a flag
 * names days, a pack run names seconds, and a rule that read one of them as the truth would answer a
 * pairing by which edge asked it. Equality is not a gap, because a window that reaches the period holds
 * it, and a shortfall is stated as the difference so no caller has to redo the subtraction and cannot
 * report a different one.
 */
export function decideDutyWindow(windowSeconds: number, statedSeconds: number): DutyWindowGap | null {
  if (statedSeconds <= windowSeconds) {
    return null;
  }
  return { windowSeconds, statedSeconds, shortBySeconds: statedSeconds - windowSeconds };
}

/** An edge, stated the way its operator names it. */
export interface WindowEdge {
  readonly flag: string;
  /** What the window keeps, in the words the refusal uses. */
  readonly keeps: string;
}

export const ACCESS_LOG_EDGE: WindowEdge = { flag: '--access-log-days', keeps: 'this run' };
export const RECEIPTS_EDGE: WindowEdge = { flag: '--receipts-days', keeps: 'the receipts store' };

/**
 * A window, weighed against the record this deployment handed the run, or the refusal that stops the
 * start.
 *
 * Two refusals live here, and they are answered by two different acts, which is what `answeredBy` says
 * rather than a sentence about exit codes. A window shorter than the period the record states is a
 * start-up line that no longer matches the paper beside it, so the flags answer it. A record that accepts
 * the floor while stating a period shorter than that floor contradicts itself about the duty it is
 * stating, so no flag answers it and the file has to change. Nothing here refuses a period because this
 * repository would have chosen a longer one: the record's stated period is the only yardstick a run
 * holds, and a deployment that states less and declines the floor is enforcing its own number.
 */
export type WindowAgainstRecord =
  | { readonly refused: false }
  | {
      readonly refused: true;
      readonly message: string;
      /** Which half of the deployment has to change before this run can start. */
      readonly answeredBy: 'the flags this run names' | 'the record itself';
    };

/**
 * A hold note beside one edge's judgement, or nothing.
 *
 * A hold is a deployment's instruction to keep and a window is its instruction about how long it keeps,
 * and a reader that met both needs to know which one a number answers to. The sentence is kept here
 * rather than written at each edge because two copies of it are how one pairing starts to mean two
 * things: one edge would say the records are kept, the other would say the period was extended. Nothing
 * in this function reads the window's own arithmetic: it states what a suspension does beside a figure
 * that is unchanged, which is the half of the rule that a hold never answers a shortfall and never moves
 * a stated period. `hold` arrives already narrowed to the record in force, so a deployment with none
 * hands null and reads nothing, and the digest is quoted because the note belongs in a start-up log
 * beside the bytes it was read from. The narrowing is one record deep: a deployment with two matters
 * under hold hands two records, so its caller asks twice and prints twice rather than handing this
 * function a set it would have to describe in one sentence. A note about one hold is not a note about
 * every hold, and a caller that had said both in one line would have said neither.
 */
export function holdWindowNote(
  hold: { readonly path: string; readonly digestHex: string } | null,
  windowSeconds: number,
): string | null {
  if (hold === null) {
    return null;
  }
  return (
    `records under the hold at ${hold.path} sha256 ${hold.digestHex} are kept past the ${String(windowSeconds)} ` +
    'seconds this run configures while that hold is in force, and the hold changes neither that window ' +
    'nor the period this deployment stated: it answers no shortfall'
  );
}

/**
 * The answer one record-facing edge gets, in that edge's own words.
 *
 * The floor branch is about the record alone, so it reads the same whichever edge asks it and names the
 * two members that disagree. The window branch names the edge's flag twice: once for the number this run
 * was handed and once as the thing to raise, because an operator reading a refusal at a terminal should
 * not have to look up which flag the sentence is about. Both branches quote the record's path, since the
 * number that binds comes from that file and a stale or misnamed one is the other half of the answer.
 */
export function judgeWindow(
  edge: WindowEdge,
  days: number,
  record: CustomerInstructionRecord,
  floorDays: number,
): WindowAgainstRecord {
  if (record.acceptsMinimumFloor && record.statedRetentionDays < floorDays) {
    return {
      refused: true,
      answeredBy: 'the record itself',
      message:
        `${record.path} accepts the ${floorDays}-day floor as this deployment's own and states ${record.statedRetentionDays} days, ` +
        `which is shorter than the floor it accepts, so the record contradicts itself about the period it owes and no window answers both ` +
        `halves of it; raise statedRetentionDays to at least ${floorDays}, or withdraw acceptsMinimumFloor`,
    };
  }
  const gap = decideDutyWindow(daysToSeconds(days), daysToSeconds(record.statedRetentionDays));
  if (gap === null) {
    return { refused: false };
  }
  return {
    refused: true,
    answeredBy: 'the flags this run names',
    message:
      `${edge.flag} gives ${edge.keeps} ${days} days and ${record.path} states ${record.statedRetentionDays} days as the period this ` +
      `deployment owes, so the window named at start-up is shorter than the period its own instruction record states; name ` +
      `${edge.flag} ${record.statedRetentionDays} or more, or point --instruction-record at the record this deployment wrote`,
  };
}
