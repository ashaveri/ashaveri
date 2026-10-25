import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { MINIMUM_RETENTION_DAYS } from '../src/aclog.js';
import {
  DEFAULT_INSTRUCTION_RECORD_PATH,
  INSTRUCTION_RECORD_VERSION,
  InstructionRecordError,
  judgeAccessWindow,
  openInstructionRecord,
  parseInstructionRecord,
  type CustomerInstructionRecord,
} from '../src/instruction-record.js';

/**
 * The instruction record as a deployment writes it, and as this gateway refuses it.
 *
 * The unit is one deployment's sentence about its own duty period, so the cases below are about what
 * reaches the run and what stops the start: that the stated period and the digest of the bytes it was
 * read from both come back, that a member no version of this record defines is refused rather than
 * half-read, and that the two refusals a record can raise name the numbers they weigh and say which
 * half of the deployment has to change.
 *
 * Nothing here boots a gateway. `gateway/test/cli.test.ts` holds the start-up report lines and the
 * exits, because a claim about what a run prints, and about the exit a refusal carries, is worth
 * checking against a process that prints it.
 */
const tempDir = mkdtempSync(join(tmpdir(), 'ashaveri-instruction-'));
let made = 0;

/** One record's text written to its own file, so a case states the bytes and the path in one line. */
function recordFile(text: string): string {
  made += 1;
  const path = join(tempDir, `record-${String(made)}.json`);
  writeFileSync(path, text, 'utf8');
  return path;
}

function bytesOf(statedRetentionDays: number, acceptsMinimumFloor: boolean): Buffer {
  return Buffer.from(
    `${JSON.stringify({ version: INSTRUCTION_RECORD_VERSION, statedRetentionDays, acceptsMinimumFloor })}\n`,
    'utf8',
  );
}

function recordAt(path: string, statedRetentionDays: number, acceptsMinimumFloor: boolean): CustomerInstructionRecord {
  return parseInstructionRecord(bytesOf(statedRetentionDays, acceptsMinimumFloor), path);
}

/** The whole of a valid record with one member changed, so each case refuses one stated fact. */
function withMember(over: Record<string, unknown>): Buffer {
  return Buffer.from(
    JSON.stringify({
      version: INSTRUCTION_RECORD_VERSION,
      statedRetentionDays: 184,
      acceptsMinimumFloor: true,
      ...over,
    }),
    'utf8',
  );
}

afterAll(() => {
  rmSync(tempDir, { recursive: true, force: true });
});

describe('a record read', () => {
  it('carries the period the deployment states and whether it takes the floor', () => {
    const record = recordAt('stated-period.json', 730, false);
    expect(record.statedRetentionDays).toBe(730);
    expect(record.acceptsMinimumFloor).toBe(false);
    expect(record.path).toBe('stated-period.json');
  });

  it('carries the digest of the bytes it was read from, and no other digest', () => {
    const bytes = bytesOf(184, true);
    const path = recordFile(bytes.toString('utf8'));
    const record = parseInstructionRecord(bytes, path);
    // Weighed against a second reading of the hash over the file's own bytes, so a digest taken from
    // the parsed object, or from a re-stringified copy, is a red here rather than a tautology.
    expect(record.digestHex).toBe(createHash('sha256').update(readFileSync(path)).digest('hex'));
    expect(record.digestHex).toMatch(/^[0-9a-f]{64}$/u);
    // The same three members spelled with whitespace between them are different bytes on a volume, so a
    // digest that survived the reformatting would be a digest of the members and not of the statement.
    const reformatted = parseInstructionRecord(
      Buffer.from('{ "version" : 1, "statedRetentionDays" : 184, "acceptsMinimumFloor" : true }', 'utf8'),
      path,
    );
    expect(reformatted.digestHex).not.toBe(record.digestHex);
  });

  it('is read from the file a path names, period and digest together', async () => {
    const path = recordFile('{\n  "version": 1,\n  "statedRetentionDays": 92,\n  "acceptsMinimumFloor": false\n}\n');
    const record = await openInstructionRecord(path, true);
    expect(record?.statedRetentionDays).toBe(92);
    expect(record?.acceptsMinimumFloor).toBe(false);
    expect(record?.digestHex).toBe(createHash('sha256').update(readFileSync(path)).digest('hex'));
  });

  it('names its default as one file in the directory the run starts in', () => {
    expect(DEFAULT_INSTRUCTION_RECORD_PATH).toBe('ashaveri-instruction-record.json');
    // A default carrying a separator, a drive letter or a leading dot-dot is a default that reaches a
    // directory the deployment never pointed this run at, which is the shape this repository refuses.
    expect(DEFAULT_INSTRUCTION_RECORD_PATH).not.toMatch(/[/\\]/u);
    expect(DEFAULT_INSTRUCTION_RECORD_PATH).not.toMatch(/^[A-Za-z]:/u);
    expect(DEFAULT_INSTRUCTION_RECORD_PATH).not.toMatch(/^\.\./u);
  });
});

describe('a record this gateway cannot read', () => {
  it('refuses a member no version of this record defines, and names the member', () => {
    const path = recordFile(withMember({ signedBy: 'the customer' }).toString('utf8'));
    const bytes = readFileSync(path);
    expect(() => parseInstructionRecord(bytes, path)).toThrow(InstructionRecordError);
    expect(() => parseInstructionRecord(bytes, path)).toThrow(
      /states signedBy, which is not a member of version 1/u,
    );
  });

  it('refuses a version this reader does not have rather than guessing at it', () => {
    expect(() => parseInstructionRecord(withMember({ version: 2 }), 'future.json')).toThrow(
      /states version 2, and this gateway reads version 1 instruction records/u,
    );
  });

  it('refuses a record that is not an object at all', () => {
    for (const text of ['[184, true]', '"184"', '184', 'null']) {
      expect(() => parseInstructionRecord(Buffer.from(text, 'utf8'), 'shaped-wrong.json')).toThrow(
        /is not a JSON object, which is the shape one instruction takes/u,
      );
    }
  });

  it('refuses text that is not JSON, and names the file it could not read', () => {
    const path = recordFile('{ version: 1,');
    expect(() => parseInstructionRecord(readFileSync(path), path)).toThrow(/is not readable as JSON/u);
  });

  it('refuses a record that leaves one of its three members out', () => {
    for (const missing of ['version', 'statedRetentionDays', 'acceptsMinimumFloor']) {
      const body: Record<string, unknown> = {
        version: INSTRUCTION_RECORD_VERSION,
        statedRetentionDays: 184,
        acceptsMinimumFloor: true,
      };
      delete body[missing];
      expect(() => parseInstructionRecord(Buffer.from(JSON.stringify(body), 'utf8'), 'incomplete.json')).toThrow(
        new RegExp(`states no ${missing}, and a version ${INSTRUCTION_RECORD_VERSION} record carries all three`, 'u'),
      );
    }
  });

  it('refuses a period that is not a whole number of days', () => {
    for (const stated of [0, -1, 12.5, '184', null, true]) {
      expect(() => parseInstructionRecord(withMember({ statedRetentionDays: stated }), 'days.json')).toThrow(
        /is not a whole number of days of at least one/u,
      );
    }
  });

  it('refuses a floor answer that is neither yes nor no', () => {
    for (const accepts of ['true', 1, 0, null]) {
      expect(() => parseInstructionRecord(withMember({ acceptsMinimumFloor: accepts }), 'floor.json')).toThrow(
        /acceptsMinimumFloor as .+, which is neither true nor false/u,
      );
    }
  });

  it('refuses a file the operator named that is not there', async () => {
    await expect(openInstructionRecord(join(tempDir, 'never-written.json'), true)).rejects.toThrow(/names no file/u);
  });

  it('reads nothing where a default points and finds no file, without calling it an error', async () => {
    expect(await openInstructionRecord(join(tempDir, 'default-looked-here.json'), false)).toBeNull();
  });

  it('refuses a path that exists and cannot be read, rather than reporting no instruction', async () => {
    // A directory is the unreadable this platform hands every reader without a file-mode game to play,
    // and the distinction is the point: "no instruction" and "the instruction is unreadable" are two
    // different answers to a question about a duty period, and only the first is a deployment's own.
    await expect(openInstructionRecord(tempDir, true)).rejects.toThrow(/could not be read/u);
    await expect(openInstructionRecord(tempDir, false)).rejects.toThrow(/could not be read/u);
  });
});

describe('a window weighed against the record the deployment wrote', () => {
  const path = 'ashaveri-instruction-record.json';

  it('refuses a window shorter than the period the record states, naming both numbers and both sources', () => {
    const judge = judgeAccessWindow(30, recordAt(path, 184, false), MINIMUM_RETENTION_DAYS);
    if (!judge.refused) throw new Error('a window shorter than the stated period was not refused');
    expect(judge.message).toContain('--access-log-days gives this run 30 days');
    expect(judge.message).toContain(`${path} states 184 days as the period this deployment owes`);
    expect(judge.message).toContain('name --access-log-days 184 or more');
    expect(judge.answeredBy).toBe('the flags this run names');
  });

  it('obeys the window a record states and a longer one, and refuses one day short', () => {
    expect(judgeAccessWindow(184, recordAt(path, 184, false), MINIMUM_RETENTION_DAYS).refused).toBe(false);
    expect(judgeAccessWindow(400, recordAt(path, 184, false), MINIMUM_RETENTION_DAYS).refused).toBe(false);
    expect(judgeAccessWindow(183, recordAt(path, 184, false), MINIMUM_RETENTION_DAYS).refused).toBe(true);
  });

  it('obeys a period shorter than the floor when the record states it and declines the floor', () => {
    // The whole reason the record exists: a deployment that states its own shorter duty period is
    // enforcing what it wrote down, and nothing in here argues with the number it stated.
    expect(judgeAccessWindow(45, recordAt(path, 45, false), MINIMUM_RETENTION_DAYS)).toEqual({ refused: false });
  });

  it('refuses a record that accepts the floor while stating less than it, and names the record as what changes', () => {
    const judge = judgeAccessWindow(90, recordAt(path, 90, true), MINIMUM_RETENTION_DAYS);
    if (!judge.refused) throw new Error('a record accepting a floor it states less than was not refused');
    expect(judge.answeredBy).toBe('the record itself');
    expect(judge.message).toContain(`accepts the ${MINIMUM_RETENTION_DAYS}-day floor as this deployment's own`);
    expect(judge.message).toContain('and states 90 days');
    expect(judge.message).toContain('the record contradicts itself');
  });

  it('weighs the window against the record and not against the floor, where the record states longer than the floor', () => {
    // A record that accepts the floor and states two years leaves a window of two hundred days refused
    // on the period it states, which is the number that deployment wrote; the floor is not the yardstick
    // this check holds, and a message that named it would quote the wrong figure back.
    const judge = judgeAccessWindow(200, recordAt(path, 730, true), MINIMUM_RETENTION_DAYS);
    if (!judge.refused) throw new Error('a window shorter than a stated two years was not refused');
    expect(judge.message).toContain('states 730 days as the period this deployment owes');
    expect(judge.message).not.toContain(`${MINIMUM_RETENTION_DAYS} days as the period`);
  });
});
