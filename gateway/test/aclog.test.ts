import { describe, expect, it } from 'vitest';
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  ACCESS_RECORD_FIELDS,
  MAX_ACCESS_FILE_BYTES,
  MINIMUM_RETENTION_DAYS,
  openFileAccessLog,
  openMemoryAccessLog,
  parseAccessLine,
  renderAccessLine,
  type AccessRecord,
} from '../src/aclog.js';
import { MINIMUM_RETENTION_SECONDS } from '../src/store.js';

/**
 * The instant every record below carries, and the clock every log below is opened with: retention
 * is a fixed distance from now, so a log that read the wall clock would drop these records the day
 * this fixture aged out of its window.
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
  return mkdtemp(join(tmpdir(), 'ashaveri-aclog-'));
}

describe('the field allowlist', () => {
  it('renders exactly the approved fields, and nothing else', () => {
    const parsed = JSON.parse(renderAccessLine(entry())) as Record<string, unknown>;
    expect(Object.keys(parsed).sort()).toEqual([...ACCESS_RECORD_FIELDS].sort());
  });

  it('renders fields in the allowlist order, because a byte-level reader sees positions, not names', () => {
    const keys = Object.keys(JSON.parse(renderAccessLine(entry())) as Record<string, unknown>);
    expect(keys).toEqual([...ACCESS_RECORD_FIELDS]);
    // The assertion above moves with the array, so it cannot catch the array itself being
    // reordered. This literal is the approved wire order; changing it is a design decision.
    expect(keys).toEqual(['t', 'rid', 'cred', 'auth', 'scope', 'm', 'p', 'rcp', 'nce', 'st', 'dur', 'deny']);
  });

  it('a field outside the allowlist cannot reach the line, however the caller names it', () => {
    const smuggled = { ...entry(), authorization: 'Bearer x', prompt: 'hello' } as AccessRecord;
    const line = renderAccessLine(smuggled);
    expect(line).not.toContain('Bearer');
    expect(line).not.toContain('hello');
    expect(line).not.toContain('authorization');
    expect(line).not.toContain('prompt');
  });

  it('round-trips through parse', () => {
    const written = entry({ rcp: 'rcp-9', deny: 'SCOPE_DENIED', auth: 'bearer', cred: null, scope: null, nce: null });
    expect(parseAccessLine(renderAccessLine(written))).toEqual(written);
  });

  it('refuses a line that is not a record, rather than reading it as an empty one', () => {
    expect(() => parseAccessLine('not json')).toThrow();
    expect(() => parseAccessLine('{"t":1}')).toThrow(/missing field/u);
    expect(() => parseAccessLine('{"t":1,"rid":"a","cred":null,"auth":null,"scope":null,"m":"GET","p":"/x","rcp":null,"nce":null,"st":200,"dur":0,"deny":null,"extra":1}')).toThrow(/unknown field/u);
  });
});

describe('openMemoryAccessLog', () => {
  it('keeps records in order and drops those past the retention bound', () => {
    const log = openMemoryAccessLog({ days: 2, now: () => T0 });
    void log.record(entry({ rid: 'old', t: T0 - 3 * 86_400_000 }));
    void log.record(entry({ rid: 'new' }));
    void log.prune(T0);
    expect(log.entries().map((each) => each.rid)).toEqual(['new']);
  });

  it('reports the window it actually holds', async () => {
    const log = openMemoryAccessLog({ now: () => T0 });
    await log.record(entry({ t: T0 }));
    await log.record(entry({ t: T0 + 100_000, rid: 'req-2' }));
    expect(await log.window()).toEqual({ from: T0, to: T0 + 100_000, count: 2 });
    await log.close();
    expect(await log.window()).toEqual({ from: null, to: null, count: 0 });
  });

  it('prunes against the wall clock when the caller names no clock', async () => {
    const log = openMemoryAccessLog();
    await log.record(entry({ rid: 'stale', t: Date.now() - 200 * 86_400_000 }));
    await log.record(entry({ rid: 'fresh', t: Date.now() }));
    expect(log.entries().map((each) => each.rid)).toEqual(['fresh']);
    await log.close();
  });

  it('draws its cutoff at the exact millisecond, not at whole days like the file log', async () => {
    const cutoff = T0 - 2 * 86_400_000;
    const log = openMemoryAccessLog({ days: 2, now: () => T0 });
    await log.record(entry({ rid: 'one-ms-too-old', t: cutoff - 1 }));
    await log.record(entry({ rid: 'exactly-at-cutoff', t: cutoff }));
    await log.record(entry({ rid: 'one-ms-fresh', t: cutoff + 1 }));
    expect(log.entries().map((each) => each.rid)).toEqual(['one-ms-fresh']);
    await log.close();
  });

  it('defaults to the six-month floor, not to less', async () => {
    // One millisecond short of the floor's own window, so a shorter default drops the record.
    const log = openMemoryAccessLog({ now: () => T0 + MINIMUM_RETENTION_DAYS * 86_400_000 - 1 });
    await log.record(entry());
    const held = await log.window();
    expect(held.count).toBe(1);
    expect(MINIMUM_RETENTION_DAYS).toBe(184);
    expect(MINIMUM_RETENTION_DAYS * 86_400).toBe(MINIMUM_RETENTION_SECONDS);
    await log.close();
  });
});

describe('openFileAccessLog', () => {
  it('appends JSONL, one line per record, and flushes on close', async () => {
    const dir = await tempDir();
    const log = await openFileAccessLog({ dir, days: 184, now: () => T0 });
    await log.record(entry());
    await log.record(entry({ rid: 'req-2', st: 401, deny: 'AUTH_UNKNOWN', cred: null, auth: null, scope: null }));
    await log.close();
    const files = await readdir(dir);
    expect(files).toHaveLength(1);
    expect(files[0]).toMatch(/^access-\d{4}-\d{2}-\d{2}-\d{3}\.jsonl$/u);
    const lines = (await readFile(join(dir, files[0] as string), 'utf8')).trimEnd().split('\n');
    expect(lines).toHaveLength(2);
    expect(parseAccessLine(lines[1] as string)).toMatchObject({ rid: 'req-2', st: 401, deny: 'AUTH_UNKNOWN' });
    await rm(dir, { recursive: true, force: true });
  });

  it('names the day in UTC, so a rotated file is findable by date alone', async () => {
    const dir = await tempDir();
    const log = await openFileAccessLog({ dir, days: 184, now: () => Date.UTC(2026, 8, 16, 0, 0, 1) });
    await log.record(entry({ t: Date.UTC(2026, 8, 15, 23, 59, 59) }));
    await log.record(entry({ t: Date.UTC(2026, 8, 16, 0, 0, 1), rid: 'req-2' }));
    await log.drain();
    const files = (await log.files()).map((path) => path.split(/[\\/]/u).pop());
    await log.close();
    expect(files.some((name) => name?.includes('2026-09-15'))).toBe(true);
    expect(files.some((name) => name?.includes('2026-09-16'))).toBe(true);
    await rm(dir, { recursive: true, force: true });
  });

  it('rolls to a new part at the size cap and keeps writing', async () => {
    const dir = await tempDir();
    const log = await openFileAccessLog({ dir, days: 184, maxBytesPerFile: 400, now: () => T0 });
    for (let i = 0; i < 12; i++) {
      await log.record(entry({ rid: `req-${String(i)}` }));
    }
    await log.drain();
    const files = await log.files();
    await log.close();
    expect(files.length).toBeGreaterThan(1);
    const total = (
      await Promise.all(files.map(async (path) => (await readFile(path, 'utf8')).trimEnd().split('\n')))
    ).flat();
    expect(total).toHaveLength(12);
    expect(MAX_ACCESS_FILE_BYTES).toBeGreaterThanOrEqual(400);
    await rm(dir, { recursive: true, force: true });
  });

  it('deletes files past the retention bound, by their own names, and reports the shorter window', async () => {
    const dir = await tempDir();
    const old = join(dir, 'access-2000-01-01-000.jsonl');
    await writeFile(old, `${renderAccessLine(entry({ t: Date.UTC(2000, 0, 1) }))}\n`, 'utf8');
    const log = await openFileAccessLog({ dir, days: 184, now: () => T0 });
    await log.record(entry());
    await log.drain();
    expect((await log.files()).some((path) => path.endsWith('access-2000-01-01-000.jsonl'))).toBe(false);
    const held = await log.window();
    expect(held.count).toBe(1);
    expect(held.from).toBe(T0);
    await log.close();
    await rm(dir, { recursive: true, force: true });
  });

  it('leaves a file it cannot name alone, rather than deleting it', async () => {
    const dir = await tempDir();
    await writeFile(join(dir, 'notes.txt'), 'keep me\n', 'utf8');
    const log = await openFileAccessLog({ dir, days: 184, now: () => T0 });
    await log.record(entry());
    await log.drain();
    expect(await readFile(join(dir, 'notes.txt'), 'utf8')).toBe('keep me\n');
    await log.close();
    await rm(dir, { recursive: true, force: true });
  });

  it('survives a clock that moves backwards, because the day part is a name and not a counter', async () => {
    const dir = await tempDir();
    let clock = Date.UTC(2026, 8, 16, 12);
    const log = await openFileAccessLog({ dir, days: 184, now: () => clock });
    await log.record(entry({ t: clock }));
    clock = Date.UTC(2026, 8, 15, 12);
    await log.record(entry({ t: clock, rid: 'req-earlier' }));
    await log.drain();
    expect((await log.files()).length).toBeGreaterThan(1);
    await log.close();
    await rm(dir, { recursive: true, force: true });
  });

  it('prunes against the wall clock when the caller names no clock', async () => {
    const dir = await tempDir();
    const staleDay = new Date(Date.now() - 200 * 86_400_000).toISOString().slice(0, 10);
    const stale = join(dir, `access-${staleDay}-000.jsonl`);
    await writeFile(stale, renderAccessLine(entry({ t: Date.now() - 200 * 86_400_000 })), 'utf8');
    const log = await openFileAccessLog({ dir });
    await log.record(entry({ t: Date.now() }));
    await log.drain();
    expect((await log.files()).some((path) => path.includes(staleDay))).toBe(false);
    expect((await log.window()).count).toBe(1);
    await rm(dir, { recursive: true, force: true });
  });

  it('draws its cutoff at whole days, because a file is only named for a day: the cutoff day survives, the day before it goes', async () => {
    const dir = await tempDir();
    const atCutoff = T0 - 184 * 86_400_000;
    const oneDayEarlier = T0 - 185 * 86_400_000;
    const cutoffDay = new Date(atCutoff).toISOString().slice(0, 10);
    const earlierDay = new Date(oneDayEarlier).toISOString().slice(0, 10);
    await writeFile(join(dir, `access-${cutoffDay}-000.jsonl`), renderAccessLine(entry({ rid: 'cutoff-day', t: atCutoff })), 'utf8');
    await writeFile(join(dir, `access-${earlierDay}-000.jsonl`), renderAccessLine(entry({ rid: 'earlier-day', t: oneDayEarlier })), 'utf8');
    const log = await openFileAccessLog({ dir, days: 184, now: () => T0 });
    await log.record(entry({ rid: 'fresh' }));
    await log.drain();
    const names = (await log.files()).map((path) => path.split(/[\\/]/u).pop());
    expect(names).toContain(`access-${cutoffDay}-000.jsonl`);
    expect(names.some((name) => name?.includes(earlierDay))).toBe(false);
    const held = await log.window();
    expect(held.count).toBe(2);
    expect(held.from).toBe(atCutoff);
    await log.close();
    await rm(dir, { recursive: true, force: true });
  });

  it('resolves drain() only once every queued write has landed on disk', async () => {
    const dir = await tempDir();
    const log = await openFileAccessLog({ dir, days: 184, now: () => T0 });
    // Sixty 8KB lines are sixty sequential file round trips: a drain() that resolved without
    // waiting for the queue would find a half-written directory when this reads the disk back.
    for (let i = 0; i < 60; i++) {
      void log.record(entry({ rid: `req-${String(i)}`, p: 'x'.repeat(8_192) }));
    }
    await log.drain();
    const names = await readdir(dir);
    const lines = (
      await Promise.all(names.map(async (name) => (await readFile(join(dir, name), 'utf8')).trimEnd().split('\n')))
    ).flat();
    expect(lines.filter((line) => line.length > 0)).toHaveLength(60);
    await log.close();
    await rm(dir, { recursive: true, force: true });
  });

  it('a failed write reaches its own caller and cannot silence the records after it', async () => {
    const dir = await tempDir();
    const day = new Date(T0).toISOString().slice(0, 10);
    const target = join(dir, `access-${day}-000.jsonl`);
    await mkdir(target);
    const log = await openFileAccessLog({ dir, days: 184, now: () => T0 });
    await expect(log.record(entry({ rid: 'poisoned' }))).rejects.toThrow(/EISDIR/u);
    await rm(target, { recursive: true, force: true });
    await log.record(entry({ rid: 'after' }));
    await log.drain();
    expect((await log.files()).map((path) => path.split(/[\\/]/u).pop())).toEqual([`access-${day}-000.jsonl`]);
    expect(parseAccessLine((await readFile(target, 'utf8')).trimEnd()).rid).toBe('after');
    expect((await log.window()).count).toBe(1);
    // A day named outside the Date range poisons the queue too, from inside the queued task.
    await expect(log.record(entry({ rid: 'far-future', t: 8_640_000_000_000_001 }))).rejects.toThrow(RangeError);
    await log.record(entry({ rid: 'after-that', t: T0 + 60_000 }));
    await log.drain();
    expect((await log.window()).count).toBe(2);
    await log.close();
    await rm(dir, { recursive: true, force: true });
  });

  it('refuses to call an unreadable part a shorter window', async () => {
    const dir = await tempDir();
    const log = await openFileAccessLog({ dir, days: 184, maxBytesPerFile: 250, now: () => T0 });
    await log.record(entry({ rid: 'req-1' }));
    await log.record(entry({ rid: 'req-2', st: 401 }));
    await log.record(entry({ rid: 'req-3', st: 500 }));
    await log.drain();
    const parts = await log.files();
    expect(parts).toHaveLength(3);
    expect((await log.window()).count).toBe(3);
    const unreadable = parts[0] as string;
    await rm(unreadable, { force: true });
    await mkdir(unreadable);
    // Records hidden behind an unreadable part must cost the operator an error, not a silent discount.
    await expect(log.window()).rejects.toThrow(/EISDIR/u);
    expect((await log.files()).length).toBe(3);
    await log.close();
    await rm(dir, { recursive: true, force: true });
  });

  it('lists parts oldest-first, ascending within a day and across a day boundary', async () => {
    const dir = await tempDir();
    const dayA = Date.UTC(2026, 8, 15, 12);
    const dayB = Date.UTC(2026, 8, 16, 12);
    const log = await openFileAccessLog({ dir, days: 184, maxBytesPerFile: 250, now: () => dayB });
    await log.record(entry({ t: dayA }));
    await log.record(entry({ t: dayA, rid: 'req-2' }));
    await log.record(entry({ t: dayA, rid: 'req-3' }));
    await log.record(entry({ t: dayB, rid: 'req-4' }));
    await log.drain();
    const names = (await log.files()).map((path) => path.split(/[\\/]/u).pop());
    expect(names).toEqual([
      'access-2026-09-15-000.jsonl',
      'access-2026-09-15-001.jsonl',
      'access-2026-09-15-002.jsonl',
      'access-2026-09-16-000.jsonl',
    ]);
    await log.close();
    await rm(dir, { recursive: true, force: true });
  });

  it('rejects a record whose rendering throws, instead of throwing across a Promise-typed call', async () => {
    const dir = await tempDir();
    const log = await openFileAccessLog({ dir, days: 184, now: () => T0 });
    const trap: AccessRecord = {
      ...entry(),
      get t(): number {
        throw new Error('a getter on an allowlisted key must reject, not escape');
      },
    };
    await expect(log.record(trap)).rejects.toThrow('a getter on an allowlisted key');
    await log.record(entry({ rid: 'after' }));
    await log.drain();
    expect((await log.window()).count).toBe(1);
    await log.close();
    await rm(dir, { recursive: true, force: true });
  });

  it('sweeps again when the day rolls over, because once per day is not once per process', async () => {
    const dir = await tempDir();
    const cutoffDay = new Date(T0 - 184 * 86_400_000).toISOString().slice(0, 10);
    await writeFile(join(dir, `access-${cutoffDay}-000.jsonl`), renderAccessLine(entry({ rid: 'boundary', t: T0 - 184 * 86_400_000 })), 'utf8');
    let clock = T0;
    const log = await openFileAccessLog({ dir, days: 184, now: () => clock });
    await log.record(entry());
    expect((await log.files()).some((path) => path.includes(cutoffDay))).toBe(true);
    clock = T0 + 2 * 86_400_000;
    await log.record(entry({ rid: 'next-day', t: clock }));
    await log.drain();
    expect((await log.files()).some((path) => path.includes(cutoffDay))).toBe(false);
    await log.close();
    await rm(dir, { recursive: true, force: true });
  });

  it('ages a scrub marker out with the day it belongs to, and never treats one as a part', async () => {
    const dir = await tempDir();
    const at = Date.parse('2026-03-01T00:00:00Z');
    await writeFile(join(dir, 'scrub-2026-01-01-000.jsonl'), '{"t":1,"credential":"a","removed":2,"files":1}\n', 'utf8');
    await writeFile(join(dir, 'access-2026-01-01-000.jsonl'), '', 'utf8');
    // A marker inside the window stays on disk, so this is the case that says what the log does
    // with one it can still see: nothing. Its `t` is the moment a scrub ran, not a request.
    await writeFile(join(dir, 'scrub-2026-03-01-000.jsonl'), `{"t":${at},"credential":"a","removed":0,"files":0}\n`, 'utf8');
    const log = await openFileAccessLog({ dir, days: 30, now: () => at });
    // Opening does not sweep and drain() only waits for the queue, so one record carries the day
    // roll that does, exactly as it does behind a live gateway.
    await log.record(entry({ rid: 'after-sweep', t: at }));
    const names = await readdir(dir);
    expect(names).not.toContain('scrub-2026-01-01-000.jsonl');
    expect(names).not.toContain('access-2026-01-01-000.jsonl');
    expect(names).toContain('scrub-2026-03-01-000.jsonl');
    expect((await log.files()).map((path) => path.split(/[\\/]/u).pop())).toEqual(['access-2026-03-01-000.jsonl']);
    expect((await log.window()).count).toBe(1);
    await log.close();
    await rm(dir, { recursive: true, force: true });
  });

  it('reports a sweep it cannot finish and tries it again on the next record', async () => {
    const dir = await tempDir();
    const at = Date.parse('2026-03-01T00:00:00Z');
    // A directory wearing a part's name: `unlink` fails on it for a reason, on Linux with EISDIR
    // and on Windows with EPERM, and neither is the vanished-file case the sweep is allowed to
    // ignore. Naming the file rather than the code is what makes this portable.
    const poison = join(dir, 'access-2026-01-01-000.jsonl');
    await mkdir(poison);
    await writeFile(join(dir, 'access-2026-01-02-000.jsonl'), renderAccessLine(entry({ t: Date.parse('2026-01-02T00:00:00Z') })), 'utf8');
    const log = await openFileAccessLog({ dir, days: 30, now: () => at });
    await expect(log.record(entry({ rid: 'first', t: at }))).rejects.toThrow(/access-2026-01-01-000\.jsonl/u);
    // The sweep stopped at the name it could not delete, so the younger aged part is still there.
    expect(await readdir(dir)).toContain('access-2026-01-02-000.jsonl');
    await rm(poison, { recursive: true, force: true });
    await log.record(entry({ rid: 'second', t: at + 60_000 }));
    // A sweep that failed is not a sweep that ran: the same day retries it, and both records the
    // two requests wrote are on disk, because the append happens before the sweep.
    expect(await readdir(dir)).not.toContain('access-2026-01-02-000.jsonl');
    expect((await log.window()).count).toBe(2);
    await log.close();
    await rm(dir, { recursive: true, force: true });
  });
});
