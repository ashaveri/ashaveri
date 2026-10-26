import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';

/**
 * One deployment's own statement of the period it keeps its records for, read once at start-up.
 *
 * The retention floor, the scrub semantics and the identifier tag are means, and a means compiled into
 * a default is a means the software chose. This file is where a deployment says which period it states
 * it owes, so the window a run enforces is the period that deployment names rather than a number this
 * repository shipped beside it. The floor keeps the meaning `gateway/src/aclog.ts` gives it, that
 * `MINIMUM_RETENTION_DAYS` is a default and a request and binds only where a caller agrees to one: this
 * record is what such an agreement is made with, and it says so for one deployment at a time, which is
 * the only way a request can become a bound without becoming an instruction from elsewhere.
 *
 * Absent the record, nothing in here moves: the window stays the flag's value or the shipped default,
 * and the start-up report says that no instruction record was read.
 *
 * What stops at these bytes is the decision. This file reads what a deployment stated, and
 * `gateway/src/duty-window.ts` weighs a window against it, because three edges ask that question and one
 * answer written three times is how one pairing starts to mean two things.
 */
export const INSTRUCTION_RECORD_VERSION = 1;

/**
 * Where a run looks when the operator named no file: the directory the process starts in, under a name
 * that says whose it is. The default reaches nothing outside that directory, so a deployment that keeps
 * its statement elsewhere names the file with `--instruction-record`, and a deployment that keeps none
 * reads none and behaves as it did before this file existed.
 */
export const DEFAULT_INSTRUCTION_RECORD_PATH = 'ashaveri-instruction-record.json';

/** The members version 1 of this record has, and the only members it may have. */
const RECORD_MEMBERS: readonly string[] = ['version', 'statedRetentionDays', 'acceptsMinimumFloor'];
const MEMBER_NAMES: ReadonlySet<string> = new Set<string>(RECORD_MEMBERS);

/** What a read record carries, with the two facts the run reports about the bytes it was read from. */
export interface CustomerInstructionRecord {
  /** The path this record was read from, as this run was handed it. */
  readonly path: string;
  /** sha256 of the bytes, hex, so a reader can tell which statement a run enforced. */
  readonly digestHex: string;
  /** The period this deployment states it owes, in whole days. */
  readonly statedRetentionDays: number;
  /** Whether the operator accepts the floor named at start-up as this deployment's own. */
  readonly acceptsMinimumFloor: boolean;
}

/** A record that cannot be read is a fact about a file, and this is the name it arrives under. */
export class InstructionRecordError extends Error {
  constructor(detail: string) {
    super(detail);
    this.name = 'InstructionRecordError';
  }
}

/** The message a thrown error carries, for a sentence that has to name what the file system said. */
function reasonOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** A `missing` code is a file that is not there; any other failure has to reach the operator. */
function isNotFound(error: unknown): boolean {
  return error instanceof Error && 'code' in error && error.code === 'ENOENT';
}

function isJsonObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function wholeDays(value: unknown, path: string): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 1) {
    throw new InstructionRecordError(
      `${path} states statedRetentionDays as ${JSON.stringify(value)}, which is not a whole number of days of at least one`,
    );
  }
  return value;
}

function floorAcceptance(value: unknown, path: string): boolean {
  if (typeof value !== 'boolean') {
    throw new InstructionRecordError(
      `${path} states acceptsMinimumFloor as ${JSON.stringify(value)}, which is neither true nor false`,
    );
  }
  return value;
}

/**
 * The bytes of a record, read into what this run enforces.
 *
 * Every refusal here is a refusal rather than a default: a record that parses to an array, names a
 * member version 1 does not have, states a version this reader does not read, or carries a number where
 * a number of days belongs is a statement this software cannot quote back to its author, and running
 * anyway would enforce a period nobody wrote down. The digest is taken over the bytes handed in, so the
 * start-up report names the statement this run read rather than a file somebody edited afterwards.
 */
export function parseInstructionRecord(bytes: Uint8Array, path: string): CustomerInstructionRecord {
  const digestHex = createHash('sha256').update(bytes).digest('hex');
  let value: unknown;
  try {
    value = JSON.parse(Buffer.from(bytes).toString('utf8')) as unknown;
  } catch (error) {
    throw new InstructionRecordError(`${path} is not readable as JSON: ${reasonOf(error)}`);
  }
  if (!isJsonObject(value)) {
    throw new InstructionRecordError(`${path} is not a JSON object, which is the shape one instruction takes`);
  }
  for (const key of Object.keys(value)) {
    if (!MEMBER_NAMES.has(key)) {
      throw new InstructionRecordError(
        `${path} states ${key}, which is not a member of version ${INSTRUCTION_RECORD_VERSION} of an instruction record: its members are ${RECORD_MEMBERS.join(', ')}`,
      );
    }
  }
  for (const key of RECORD_MEMBERS) {
    if (!(key in value)) {
      throw new InstructionRecordError(`${path} states no ${key}, and a version ${INSTRUCTION_RECORD_VERSION} record carries all three of its members`);
    }
  }
  if (value['version'] !== INSTRUCTION_RECORD_VERSION) {
    throw new InstructionRecordError(
      `${path} states version ${JSON.stringify(value['version'])}, and this gateway reads version ${INSTRUCTION_RECORD_VERSION} instruction records`,
    );
  }
  return {
    path,
    digestHex,
    statedRetentionDays: wholeDays(value['statedRetentionDays'], path),
    acceptsMinimumFloor: floorAcceptance(value['acceptsMinimumFloor'], path),
  };
}

/**
 * The record at `path`, or nothing.
 *
 * `namedByOperator` is the whole of the difference between an absent file and an unreadable one: a run
 * that fell back to the default path and found no statement there is a deployment that gave none, which
 * is the state this software has always started in, while a run whose operator named a file has to read
 * that file or say it could not. A path that exists and cannot be read is refused under either hand,
 * because "there is no instruction" and "the instruction is unreadable" are two different answers to the
 * same question about a duty period.
 */
export async function openInstructionRecord(path: string, namedByOperator: boolean): Promise<CustomerInstructionRecord | null> {
  let bytes: Buffer;
  try {
    bytes = await readFile(path);
  } catch (error) {
    if (isNotFound(error)) {
      if (namedByOperator) {
        throw new InstructionRecordError(
          `${path} names no file, and a run whose operator named an instruction record reads it or refuses to start`,
        );
      }
      return null;
    }
    throw new InstructionRecordError(`${path} could not be read: ${reasonOf(error)}`);
  }
  return parseInstructionRecord(bytes, path);
}
