import { describe, expect, it } from 'vitest';
import { mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  ACCESS_PART_NAME,
  RETENTION_SWEEP_NAME,
  openFileAccessLog,
  renderAccessLine,
  type AccessRecord,
} from '../src/aclog.js';
import { JOURNAL_PART_NAME } from '../src/journal.js';

/**
 * The instant every record below carries, shared with `aclog.test.ts`: retention is a fixed
 * distance from now, so a wall-clock read would drop these records before the run ends.
 */
const T0 = 1_772_000_000_000;

function entry(overrides: Partial<AccessRecord> = {}): AccessRecord {
  return {
    t: T0,
    rid: 'req-1',
    cred: 'svc-1',
    auth: 'pop',
    scope: 'complete',
    m: 'POST',
    p: '/v1/chat/completions',
    rcp: null,
    nce: 'AAAAAAAAAAAAAAAAAAAAAA',
    st: 200,
    dur: 12,
    deny: null,
    ...overrides,
  };
}

async function tempDir(): Promise<string> {
  return mkdtemp(join(tmpdir(), 'ashaveri-journal-'));
}

/**
 * A scheduler the test holds back: appends queue a consumer tick and nothing runs it until
 * `pump` does, so a test decides at which instant the background drain is allowed to have run.
 */
function heldScheduler() {
  const tasks: (() => void)[] = [];
  return {
    schedule(task: () => void): void {
      tasks.push(task);
    },
    pump(): void {
      const queued = tasks.splice(0);
      for (const task of queued) task();
    },
  };
}

async function accessFileNames(dir: string): Promise<string[]> {
  return (await readdir(dir)).filter((name) => name.startsWith('access-')).sort();
}

async function journalFileNames(dir: string): Promise<string[]> {
  return (await readdir(dir)).filter((name) => name.startsWith('journal-')).sort();
}

async function partLines(dir: string): Promise<string[]> {
  const lines: string[] = [];
  for (const name of await accessFileNames(dir)) {
    const text = await readFile(join(dir, name), 'utf8');
    for (const line of text.split('\n')) {
      if (line.length > 0) lines.push(`${line}\n`);
    }
  }
  return lines;
}

/**
 * Pumps the held scheduler until the pending promise settles. A tick is async, so one pump call
 * starts it rather than finishes it; the loop yields a macrotask between pumps to let the file
 * calls land, and stops once the promise itself resolves. The yield must be a live promise: a
 * pre-fulfilled constant wins the race against a settlement that needs a microtask hop, and the
 * loop would never observe the very promise it waits on.
 */
async function pumpUntilSettled(clock: ReturnType<typeof heldScheduler>, pending: Promise<unknown>): Promise<void> {
  const settled = pending.then(
    () => true as const,
    () => true as const,
  );
  for (;;) {
    clock.pump();
    const outcome = await Promise.race([
      settled,
      new Promise<'yield'>((resolve) => setImmediate(() => resolve('yield'))),
    ]);
    if (outcome === true) return;
  }
}

const DAY = new Date(T0).toISOString().slice(0, 10);

/**
 * Ages the log by the same instant the records carry. Without it the sweep reads the real clock,
 * finds every T0-day part 184 days past its window, and collects the part the test just wrote.
 */
const aged = { nowMillis: (): number => T0 };

describe('the journal write the record waits for', () => {
  it('holds the line the moment record resolves, before any drain has run', async () => {
    const dir = await tempDir();
    const clock = heldScheduler();
    const log = await openFileAccessLog({ ...aged, dir, schedule: clock.schedule });
    try {
      await log.record(entry({ rid: 'req-1' }));
      const journalNames = await journalFileNames(dir);
      expect(journalNames).toEqual(['journal-000.jsonl']);
      const journalBytes = await readFile(join(dir, 'journal-000.jsonl'), 'utf8');
      expect(journalBytes).toBe(renderAccessLine(entry({ rid: 'req-1' })));
      expect(await accessFileNames(dir)).toEqual([]);
    } finally {
      await log.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('drains the journal into the parts by pump, rotating and unlinking as it goes', async () => {
    const dir = await tempDir();
    const clock = heldScheduler();
    const log = await openFileAccessLog({ ...aged, dir, schedule: clock.schedule, maxBytesPerFile: 200 });
    try {
      const entries = [
        entry({ rid: 'req-1', nce: 'AAAAAAAAAAAAAAAAAAAAAA' }),
        entry({ rid: 'req-2', nce: 'BBBBBBBBBBBBBBBBBBBBBB' }),
        entry({ rid: 'req-3', nce: 'CCCCCCCCCCCCCCCCCCCCCC' }),
      ];
      const lines = entries.map(renderAccessLine);
      for (const one of entries) {
        await log.record(one);
      }
      expect((await journalFileNames(dir)).length).toBeGreaterThan(1);
      await pumpUntilSettled(clock, log.drain());
      expect(await journalFileNames(dir)).toEqual(['journal-002.jsonl']);
      const drained = await partLines(dir);
      expect(drained).toEqual(lines);
    } finally {
      await log.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('keeps the order the records were handed in across a burst', async () => {
    const dir = await tempDir();
    const clock = heldScheduler();
    const log = await openFileAccessLog({ ...aged, dir, schedule: clock.schedule });
    try {
      const lines: string[] = [];
      for (let index = 0; index < 50; index += 1) {
        await log.record(entry({ rid: `req-${index}` }));
        lines.push(renderAccessLine(entry({ rid: `req-${index}` })));
      }
      await pumpUntilSettled(clock, log.drain());
      expect(await partLines(dir)).toEqual(lines);
    } finally {
      await log.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('drain resolves only once every handed record sits in a part', async () => {
    const dir = await tempDir();
    const log = await openFileAccessLog({ ...aged, dir });
    try {
      for (let index = 0; index < 10; index += 1) {
        await log.record(entry({ rid: `req-${index}` }));
      }
      await log.drain();
      const drained = await partLines(dir);
      expect(drained).toHaveLength(10);
      expect(await journalFileNames(dir)).toEqual(['journal-000.jsonl']);
    } finally {
      await log.close();
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe('the replay a start runs over an undrained journal', () => {
  it('replays a journal left undrained by a dead process into the parts, exactly once', async () => {
    const dir = await tempDir();
    const deadClock = heldScheduler();
    const dead = await openFileAccessLog({ ...aged, dir, schedule: deadClock.schedule });
    await dead.record(entry({ rid: 'req-1' }));
    await dead.record(entry({ rid: 'req-2' }));
    const revived = await openFileAccessLog({ ...aged, dir, schedule: heldScheduler().schedule });
    try {
      expect(await accessFileNames(dir)).toEqual([`access-${DAY}-000.jsonl`]);
      expect(await readFile(join(dir, `access-${DAY}-000.jsonl`), 'utf8')).toBe(
        renderAccessLine(entry({ rid: 'req-1' })) + renderAccessLine(entry({ rid: 'req-2' })),
      );
      expect(await journalFileNames(dir)).toEqual([]);
      expect(await revived.window()).toEqual({ from: T0, to: T0, count: 2 });
    } finally {
      await revived.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('skips the lines a crash left in both the journal and the parts, and moves the rest', async () => {
    const dir = await tempDir();
    const first = renderAccessLine(entry({ rid: 'req-1' }));
    const second = renderAccessLine(entry({ rid: 'req-2' }));
    await writeFile(join(dir, `access-${DAY}-000.jsonl`), first, 'utf8');
    await writeFile(join(dir, 'journal-000.jsonl'), first + second, 'utf8');
    const log = await openFileAccessLog({ ...aged, dir, schedule: heldScheduler().schedule });
    try {
      expect(await readFile(join(dir, `access-${DAY}-000.jsonl`), 'utf8')).toBe(first + second);
      expect(await journalFileNames(dir)).toEqual([]);
    } finally {
      await log.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('drops a torn tail on the last part and replays the complete lines around it', async () => {
    const dir = await tempDir();
    const first = renderAccessLine(entry({ rid: 'req-1' }));
    await writeFile(join(dir, 'journal-000.jsonl'), `${first}{"t":1772`, 'utf8');
    const log = await openFileAccessLog({ ...aged, dir, schedule: heldScheduler().schedule });
    try {
      expect(await partLines(dir)).toEqual([first]);
      expect(await journalFileNames(dir)).toEqual([]);
    } finally {
      await log.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('refuses a start whose journal carries a corrupt line, naming the part', async () => {
    const dir = await tempDir();
    const first = renderAccessLine(entry({ rid: 'req-1' }));
    await writeFile(join(dir, 'journal-000.jsonl'), `${first}not an access line at all\n`, 'utf8');
    await expect(openFileAccessLog({ ...aged, dir, schedule: heldScheduler().schedule })).rejects.toThrow(
      /journal-000\.jsonl holds a line that is not an access record/,
    );
    await rm(dir, { recursive: true, force: true });
  });

  it('refuses a torn line on an earlier part, where rotation rules out a crash', async () => {
    const dir = await tempDir();
    const first = renderAccessLine(entry({ rid: 'req-1' }));
    await writeFile(join(dir, 'journal-000.jsonl'), `${first}{"t":1772`, 'utf8');
    await writeFile(join(dir, 'journal-001.jsonl'), renderAccessLine(entry({ rid: 'req-2' })), 'utf8');
    await expect(openFileAccessLog({ ...aged, dir, schedule: heldScheduler().schedule })).rejects.toThrow(
      /journal-000\.jsonl ends in a partial line/,
    );
    await rm(dir, { recursive: true, force: true });
  });
});

describe('the family the sweep and the scrub must agree on', () => {
  it('names journal parts no retention pattern collects', () => {
    expect(RETENTION_SWEEP_NAME.test('journal-000.jsonl')).toBe(false);
    expect(ACCESS_PART_NAME.test('journal-000.jsonl')).toBe(false);
    expect(JOURNAL_PART_NAME.test('journal-000.jsonl')).toBe(true);
    expect(JOURNAL_PART_NAME.exec('journal-1234.jsonl')?.[1]).toBe('1234');
    expect(JOURNAL_PART_NAME.test('access-2026-02-25-000.jsonl')).toBe(false);
    expect(JOURNAL_PART_NAME.test('scrub-2026-02-25-000.jsonl')).toBe(false);
  });

  it('leaves an empty journal after a graceful close, so a scrub that follows reads none', async () => {
    const dir = await tempDir();
    const log = await openFileAccessLog({ ...aged, dir });
    try {
      await log.record(entry({ rid: 'req-1' }));
      await log.close();
      expect(await journalFileNames(dir)).toEqual([]);
      expect(await partLines(dir)).toEqual([renderAccessLine(entry({ rid: 'req-1' }))]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('reads the window and the files only after the drain they owe the caller', async () => {
    const dir = await tempDir();
    const log = await openFileAccessLog({ ...aged, dir });
    try {
      await log.record(entry({ rid: 'req-1' }));
      expect(await log.window()).toEqual({ from: T0, to: T0, count: 1 });
      expect(await log.files()).toEqual([join(dir, `access-${DAY}-000.jsonl`)]);
    } finally {
      await log.close();
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe('the stall a rewrite from outside the process leaves behind', () => {
  it('stalls the rewritten part with a warning, keeps its records, and heals on the next start', async () => {
    const dir = await tempDir();
    const clock = heldScheduler();
    const log = await openFileAccessLog({ ...aged, dir, schedule: clock.schedule });
    const warnings: string[] = [];
    const onWarning = (warning: Error & { code?: string }): void => {
      if (warning.code === 'ASHAVERI_ACCESS_JOURNAL_DRAIN_STALLED') warnings.push(warning.message);
    };
    process.on('warning', onWarning);
    let revived: Awaited<ReturnType<typeof openFileAccessLog>> | null = null;
    try {
      const first = renderAccessLine(entry({ rid: 'req-1' }));
      const second = renderAccessLine(entry({ rid: 'req-2' }));
      await log.record(entry({ rid: 'req-1' }));
      await pumpUntilSettled(clock, log.drain());
      expect(await partLines(dir)).toEqual([first]);
      await writeFile(join(dir, 'journal-000.jsonl'), '', 'utf8');
      // The stall is a background reaction: a drain whose lines already reached the parts settles
      // at registration, so the rewritten part's warning lands on a later tick. Pump until the
      // warning arrives, bounded so a drain that never reacts fails the assertion, not the clock.
      await log.drain();
      // The stall is a background reaction: a drain whose lines already reached the parts settles
      // at registration, so the rewritten part's warning lands on a later tick. Pump until the
      // warning arrives, bounded in wall time: the detecting tick's reads are real volume I/O,
      // and a busy volume stretches those milliseconds across hundreds of loop turns, so a count
      // of turns is the wrong unit for the bound.
      const deadline = Date.now() + 2_000;
      while (warnings.length === 0 && Date.now() < deadline) {
        clock.pump();
        await new Promise<void>((resolve) => setImmediate(resolve));
      }
      expect(warnings.length).toBeGreaterThan(0);
      await log.record(entry({ rid: 'req-2' }));
      await pumpUntilSettled(clock, log.drain());
      await log.close();
      expect(await journalFileNames(dir)).toEqual(['journal-000.jsonl']);
      expect(await readFile(join(dir, 'journal-000.jsonl'), 'utf8')).toBe(second);
      revived = await openFileAccessLog({ ...aged, dir, schedule: heldScheduler().schedule });
      expect(await partLines(dir)).toEqual([first, second]);
      expect(await journalFileNames(dir)).toEqual([]);
    } finally {
      process.off('warning', onWarning);
      if (revived !== null) await revived.close();
      await rm(dir, { recursive: true, force: true });
    }
  });
});

