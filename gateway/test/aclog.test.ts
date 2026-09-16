import { describe, expect, it } from 'vitest';
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
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

  it('defaults to the six-month floor, not to less', async () => {
    // One millisecond short of the floor's own window, so a shorter default drops the record.
    const log = openMemoryAccessLog({ now: () => T0 + MINIMUM_RETENTION_DAYS * 86_400_000 - 1 });
    await log.record(entry());
    const held = await log.window();
    expect(held.count).toBe(1);
    expect(MINIMUM_RETENTION_DAYS).toBe(184);
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

  it('leaves a file it cannot name alone, and says so in the window rather than deleting it', async () => {
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
});
