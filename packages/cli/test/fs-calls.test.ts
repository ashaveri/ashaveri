import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { writeAtomically } from '../src/atomic.js';
import { accesslogScrub } from '../src/commands/accesslog.js';

/**
 * A scripted `node:fs/promises`, so that four facts about the writers are decided by the arguments a
 * call passed and the order the calls arrived in rather than by the host that happens to run them.
 * What a host can decline to show is not small: a umask decides whether a masked create is
 * distinguishable from a corrected one, a uid decides whether a permission bit binds at all, and
 * Windows reports every file as `0666`, so three of the mode rules this file holds could only ever be
 * read as predictions about a real volume. A race is worse still, because a real one needs two
 * processes and a scheduler that cooperates, and the outcome under test is which bytes the loser
 * published. The script below fixes a umask, answers `wx` with `EEXIST`, applies a mask to a create
 * and leaves a `chmod` to correct it, and lets a case queue a write behind the next read of one name,
 * which is the only way an append can be made to land exactly between this run's read and its own
 * comparison. What it cannot do is say what a real file system does with those arguments, and every
 * rule here is paired with a case in another file that reads bits off a volume where a volume will
 * show them.
 */

/** Outside any repository: nothing below ever reaches a disk. */
const DIR = join(tmpdir(), 'ashaveri-scripted-access-log');

const host = vi.hoisted(() => ({
  entries: new Map<string, { bytes: number[]; mode: number; directory: boolean }>(),
  calls: [] as Array<{ op: string; path: string; mode: number | null; flag: string | null }>,
  /** The create-time mask, fixed rather than inherited, because being one host is the whole point. */
  umask: 0o022,
  /** Bytes a waiting writer adds after the next read of a name, one entry per queued write. */
  queued: new Map<string, string[]>(),
  /** Names written to after every read, which is a writer that never stops. */
  always: new Set<string>(),
  /** Bytes a second writer leaves at a destination after this run's own rename moved over it. */
  landsAfter: new Map<string, string>(),
  /** Bytes a gateway appends at the destination after the rename, on top of what this run published. */
  appendsAfter: new Map<string, string>(),
  /** Names that are gone the moment this run renames onto them, which is a retention sweep. */
  vanishesAfter: new Set<string>(),
  renameFails: null as string | null,
}));

vi.mock('node:fs/promises', () => {
  // Inside the factory on purpose: a module-scope table is still in its temporal dead zone when this
  // factory runs, because the factory answers an import that the file's own statements have not
  // reached yet. The writers pass `error.message` straight through to an operator, so the shape of it
  // is the code's, not a fixture's.
  const reasons: Record<string, string> = {
    EEXIST: 'file already exists',
    EISDIR: 'illegal operation on a directory',
    ENOENT: 'no such file or directory',
    EPERM: 'operation not permitted',
  };

  function fail(code: string, syscall: string, path: string): never {
    const error = new Error(`${code}: ${reasons[code] ?? code}, ${syscall} '${path}'`) as Error & { code: string };
    error.code = code;
    throw error;
  }

  function note(op: string, path: string, mode: number | null = null, flag: string | null = null): void {
    host.calls.push({ op, path, mode, flag });
  }

  function isDirectory(path: string): boolean {
    const entry = host.entries.get(path);
    return entry !== undefined && entry.directory;
  }

  function writtenTo(path: string): boolean {
    return host.entries.has(path);
  }

  function append(path: string, text: string): void {
    const entry = host.entries.get(path);
    if (entry === undefined) return;
    entry.bytes.push(...Buffer.from(text, 'utf8'));
  }

  return {
    async readdir(path: string): Promise<string[]> {
      note('readdir', path);
      if (!isDirectory(path) && !writtenTo(path)) fail('ENOENT', 'scandir', path);
      return [...host.entries.keys()]
        .filter((each) => dirname(each) === path)
        .map((each) => each.slice(path.length + 1));
    },

    async readFile(path: string): Promise<Buffer> {
      note('readFile', path);
      const entry = host.entries.get(path);
      if (entry === undefined) fail('ENOENT', 'open', path);
      if (entry.directory) fail('EISDIR', 'open', path);
      // The answer is taken before the queue is drained, so a scripted append lands after this read
      // the way a real one lands after a real read: nothing sees the new bytes on the way out.
      const bytes = Buffer.from(entry.bytes);
      const queued = host.queued.get(path);
      if (queued !== undefined && queued.length > 0) {
        append(path, queued.shift() as string);
        if (queued.length === 0) host.queued.delete(path);
      }
      if (host.always.has(path)) append(path, '{"t":1772000000000,"rid":"rid-tail","cred":"svc-tail"}\n');
      return bytes;
    },

    async stat(path: string): Promise<{ mode: number; size: number; isDirectory: () => boolean }> {
      note('stat', path);
      const entry = host.entries.get(path);
      if (entry === undefined) fail('ENOENT', 'stat', path);
      return { mode: entry.mode, size: entry.bytes.length, isDirectory: () => entry.directory };
    },

    async writeFile(path: string, data: unknown, options: unknown): Promise<void> {
      const given = (options ?? {}) as { mode?: number; flag?: string };
      note('writeFile', path, given.mode ?? null, given.flag ?? null);
      if (writtenTo(path) && (given.flag ?? 'w').includes('x')) fail('EEXIST', 'open', path);
      if (!isDirectory(dirname(path))) fail('ENOENT', 'open', path);
      // A create's mode is a request the mask answers, which is the whole reason a `chmod` follows it.
      host.entries.set(path, {
        bytes: [...Buffer.from(String(data), 'utf8')],
        mode: (given.mode ?? 0o666) & ~host.umask,
        directory: false,
      });
    },

    async chmod(path: string, mode: number): Promise<void> {
      note('chmod', path, mode);
      const entry = host.entries.get(path);
      if (entry === undefined) fail('ENOENT', 'chmod', path);
      entry.mode = mode & 0o7777;
    },

    async rename(from: string, to: string): Promise<void> {
      note('rename', from);
      if (host.renameFails !== null) fail(host.renameFails, 'rename', to);
      const entry = host.entries.get(from);
      if (entry === undefined) fail('ENOENT', 'rename', from);
      if (isDirectory(to)) fail('EISDIR', 'rename', to);
      // A rename moves the inode and the mode it ended up with, which is why the mode a writer
      // publishes is the mode the next append finds rather than the one the writer read.
      host.entries.delete(from);
      host.entries.set(to, entry);
      // The three states a publish cannot see from inside itself: somebody else's copy at the name
      // already, that copy grown by an append, and no name at all. None of them is reachable on a host
      // on a schedule a test does not own, and all three are what the read after the rename is there to
      // find out.
      const peer = host.landsAfter.get(to);
      if (peer !== undefined) {
        const moved = host.entries.get(to);
        if (moved !== undefined) moved.bytes = [...Buffer.from(peer, 'utf8')];
      }
      const appended = host.appendsAfter.get(to);
      if (appended !== undefined) host.entries.get(to)?.bytes.push(...Buffer.from(appended, 'utf8'));
      if (host.vanishesAfter.has(to)) host.entries.delete(to);
    },

    async unlink(path: string): Promise<void> {
      note('unlink', path);
      const entry = host.entries.get(path);
      if (entry === undefined) fail('ENOENT', 'unlink', path);
      if (entry.directory) fail('EPERM', 'unlink', path);
      host.entries.delete(path);
    },
  };
});

/** One record line, in the shape the scrub reads: the credential is the only field it looks at. */
function one(rid: string, cred: string): string {
  return `${JSON.stringify({ t: 1_772_000_000_000, rid, cred })}\n`;
}

function lines(...records: Array<[string, string]>): string {
  return records.map(([rid, cred]) => one(rid, cred)).join('');
}

/** The log directory as the script sees it: one name, its bytes, and the mode it carries. */
function scriptFile(name: string, text: string, mode: number): string {
  const path = join(DIR, name);
  host.entries.set(path, { bytes: [...Buffer.from(text, 'utf8')], mode, directory: false });
  return path;
}

function callsOf(op: string, path: string): Array<{ op: string; path: string; mode: number | null; flag: string | null }> {
  return host.calls.filter((each) => each.op === op && each.path === path);
}

function bytesAt(path: string): string {
  const entry = host.entries.get(path);
  if (entry === undefined) throw new Error(`the script holds no name '${path}'`);
  return Buffer.from(entry.bytes).toString('utf8');
}

function modeAt(path: string): number {
  const entry = host.entries.get(path);
  if (entry === undefined) throw new Error(`the script holds no name '${path}'`);
  return entry.mode & 0o777;
}

function markerAt(path: string): { parts: Array<{ name: string; beforeBytes: number; afterBytes: number }>; removed: number } {
  return JSON.parse(bytesAt(path)) as {
    parts: Array<{ name: string; beforeBytes: number; afterBytes: number }>;
    removed: number;
  };
}

const clock = (): number => Date.parse('2026-02-26T00:00:00Z');
const MARKER = join(DIR, 'scrub-2026-02-26-000.jsonl');
const temporaryFor = (path: string): string => `${path}.tmp-${String(process.pid)}`;

beforeEach(() => {
  host.entries.clear();
  host.entries.set(DIR, { bytes: [], mode: 0o755, directory: true });
  host.calls.length = 0;
  host.umask = 0o022;
  host.queued.clear();
  host.always.clear();
  host.landsAfter.clear();
  host.appendsAfter.clear();
  host.vanishesAfter.clear();
  host.renameFails = null;
});

describe('the arguments a write reaches the volume with', () => {
  it('keeps the nine permission bits and drops everything above them, twice over', async () => {
    // A `stat` mode carries twelve bits and the top three are the set-user-id, set-group-id and sticky
    // ones, which are not readability settings a scrub means to publish. On a real volume that is only
    // observable where a file system reports the fourth digit at all, so what is asserted here is the
    // argument both writers hand down: a dropped mask reaches a create and a `chmod` alike, and both
    // are named below.
    const path = join(DIR, 'credentials.json');
    await writeAtomically(path, '{"version":1}\n', 0o4600, 'cannot write example file');
    const temporary = temporaryFor(path);
    expect(callsOf('writeFile', temporary)).toHaveLength(1);
    expect(callsOf('chmod', temporary)).toHaveLength(1);
    expect(callsOf('writeFile', temporary)[0]?.mode).toBe(0o600);
    expect(callsOf('chmod', temporary)[0]?.mode).toBe(0o600);
    expect(modeAt(path)).toBe(0o600);
  });

  it('corrects the create mode with a chmod, because a masked create is not the mode it asked for', async () => {
    // The scripted umask is `022`, the common one, and the reason a bare create of a `0666` part lands
    // at `0644`: a scrub that renamed that back over the log would take the group's read away from a
    // deployment that had granted it. `0666` is the mode where a create and a create-then-correct
    // differ under this umask, so the second call is what this case reads rather than a coincidence
    // about the first.
    const part = scriptFile('access-2026-02-24-000.jsonl', lines(['rid-1', 'svc-a'], ['rid-2', 'svc-b']), 0o666);
    const result = await accesslogScrub(DIR, 'svc-a', clock);
    expect(result.removed).toBe(1);
    expect(modeAt(part)).toBe(0o666);
    const temporary = temporaryFor(part);
    expect(callsOf('writeFile', temporary)[0]?.mode).toBe(0o666);
    expect(callsOf('chmod', temporary).map((each) => each.mode)).toEqual([0o666]);
  });

  it('creates the marker at its own name, at `0600`, and never at the mode of the part beside it', async () => {
    // The receipt names a credential and a count, so the bits a log part carries would hand both to
    // anyone who can read the directory. Under a umask of `0077` a create at `0666` lands at `0600`
    // and a host reading bits afterwards cannot tell the two apart, which is why this script runs at
    // `022` and why the argument is named beside the landed mode. `wx` at the final name is the claim
    // that keeps an earlier run's receipt, and a publish that went through a temporary and a rename
    // would satisfy a mode check while destroying that. Nothing corrects the mode afterwards, which is
    // the other half of the bargain: a create can only be masked down by a umask, so what lands is
    // this mode or a stricter one, and a `chmod` would be free to raise it back up.
    scriptFile('access-2026-02-24-000.jsonl', lines(['rid-1', 'svc-a'], ['rid-2', 'svc-b']), 0o666);
    const result = await accesslogScrub(DIR, 'svc-a', clock);
    expect(result.marker).toBe('scrub-2026-02-26-000.jsonl');
    const published = callsOf('writeFile', MARKER);
    expect(published).toHaveLength(1);
    expect(published[0]?.mode).toBe(0o600);
    expect(published[0]?.flag).toBe('wx');
    expect(modeAt(MARKER)).toBe(0o600);
    expect(callsOf('chmod', MARKER)).toEqual([]);
  });

  it('takes its own temporary back when the rename is what answers `EEXIST`', async () => {
    // A temporary holding log bytes must not survive a failed publish, and the one case that has to
    // survive is an `EEXIST` from the create, which names a file this call never owned. No real volume
    // is obliged to answer a rename with `EEXIST` at all, so the flag that tells those two failures
    // apart has no gate on a host; here the create succeeds and the rename is what refuses.
    const path = join(DIR, 'credentials.json');
    const temporary = temporaryFor(path);
    host.renameFails = 'EEXIST';
    await expect(writeAtomically(path, '{"version":1}\n', 0o600, 'cannot write example file')).rejects.toThrow(
      /cannot write example file .*EEXIST/u,
    );
    expect(host.entries.has(temporary)).toBe(false);
    expect(callsOf('unlink', temporary)).toHaveLength(1);
  });
});

describe('a part that is written to while the scrub works through it', () => {
  it('retries, and publishes the later bytes with the append in them', async () => {
    // Named for what it asserts: the retry that succeeds, not the refusal. The queued record lands
    // behind the run's first read of the part, which is the state a gateway's append produces, and the
    // comparison before the rename is what notices. Dropping that comparison leaves this volume
    // missing a record nobody asked to have removed, and the run's receipt reading as a success,
    // because the bytes it published are exactly the bytes it reads back afterwards.
    const part = scriptFile(
      'access-2026-02-24-000.jsonl',
      lines(['rid-1', 'svc-a'], ['rid-2', 'svc-b'], ['rid-3', 'svc-a']),
      0o600,
    );
    host.queued.set(part, [lines(['rid-late', 'svc-c'])]);
    const result = await accesslogScrub(DIR, 'svc-a', clock);
    expect(result).toEqual({ removed: 2, files: 1, marker: 'scrub-2026-02-26-000.jsonl' });
    // The appended record survived the erasure that ran beside it, which is the whole property.
    expect(bytesAt(part)).toBe(lines(['rid-2', 'svc-b'], ['rid-late', 'svc-c']));
    const temporary = temporaryFor(part);
    // Two turns at one part, the first turn's copy thrown away: the counts below are what make the
    // retry visible rather than inferred, and they also say the run refiltered the newer bytes instead
    // of merging its own stale opinion into them.
    expect(callsOf('writeFile', temporary)).toHaveLength(2);
    expect(callsOf('unlink', temporary)).toHaveLength(1);
    const receipt = markerAt(MARKER);
    // The receipt is written from the bytes the run that published actually read, so its before length
    // is the length after the append, not before it.
    expect(receipt.parts[0]?.beforeBytes).toBe(Buffer.byteLength(lines(['rid-1', 'svc-a'], ['rid-2', 'svc-b'], ['rid-3', 'svc-a'], ['rid-late', 'svc-c'])));
    expect(receipt.parts[0]?.afterBytes).toBe(Buffer.byteLength(bytesAt(part)));
    expect(receipt.removed).toBe(2);
  });

  it('refuses a part that never holds still, naming it, and publishes nothing to it', async () => {
    // The other way the loop ends, named for that. A writer on every read is a deployment under a load
    // this command was not built to outrun, and the bound is what turns that into a sentence instead
    // of a loop: three turns, then a refusal that says which part and says this run published nothing
    // there. Every record it did not erase is still on the volume, and the refusal is what tells the
    // operator to go and look rather than to trust a count.
    const part = scriptFile('access-2026-02-24-000.jsonl', lines(['rid-1', 'svc-a'], ['rid-2', 'svc-b']), 0o600);
    host.always.add(part);
    const failure = await accesslogScrub(DIR, 'svc-a', clock).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(Error);
    const message = (failure as Error).message;
    expect(message).toContain(`cannot rewrite access log part '${part}'`);
    expect(message).toContain('would not hold still across 3 attempts');
    const temporary = temporaryFor(part);
    expect(callsOf('writeFile', temporary)).toHaveLength(3);
    expect(callsOf('unlink', temporary)).toHaveLength(3);
    // Nothing was published, so nothing left the volume, and no receipt was written for an erasure
    // that did not happen.
    expect(host.entries.has(temporary)).toBe(false);
    expect(bytesAt(part)).toContain('"rid":"rid-1"');
    expect(host.entries.has(MARKER)).toBe(false);
  });

  it('refuses a name that holds somebody else\'s copy when it reads it back after publishing', async () => {
    // The comparison before the rename cannot see this one: it passed, and the state that follows it
    // is a second scrub's rename landing on the same name, which is the shape two runs of this command
    // take up on a day with work for both. The bytes at the name are then not the bytes this run
    // published, and they hold the record this run took out, so the receipt this run was about to write
    // would name a file nobody has. Reading the destination back is the only way to find that out, and
    // refusing is the only answer that leaves the other run's evidence unchallenged.
    const part = scriptFile('access-2026-02-24-000.jsonl', lines(['rid-1', 'svc-a'], ['rid-2', 'svc-b']), 0o600);
    const held = lines(['rid-1', 'svc-a'], ['rid-2', 'svc-b'], ['rid-peer', 'svc-c']);
    host.landsAfter.set(part, held);
    const failure = await accesslogScrub(DIR, 'svc-a', clock).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(Error);
    const message = (failure as Error).message;
    expect(message).toContain(`cannot confirm access log part '${part}'`);
    expect(message).toContain(`the bytes there are ${String(Buffer.byteLength(held))} of them and do not begin with the`);
    // Records this run did remove are gone, so a run that cannot say what is at the name says nothing
    // about counts and writes no receipt either way.
    expect(host.entries.has(MARKER)).toBe(false);
    expect(bytesAt(part)).toBe(held);
  });

  it('keeps an append that lands after the rename, and receipts the grown part', async () => {
    // The other half of the same read-back, and the one a serving gateway produces: it opens the part
    // per record, so a line can arrive after this run's copy is already at the name. Those bytes are on
    // the volume, this run's bytes are under them, and the erasure landed, so a run that answered this
    // with a refusal exited 2 over a record nobody asked it about and left its own receipt unfiled.
    // Measured on the host with a real writer, this shape was the majority of the mismatches.
    const part = scriptFile('access-2026-02-24-000.jsonl', lines(['rid-1', 'svc-a'], ['rid-2', 'svc-b']), 0o600);
    const after = lines(['rid-2', 'svc-b']);
    const late = lines(['rid-late', 'svc-c']);
    host.appendsAfter.set(part, late);
    const result = await accesslogScrub(DIR, 'svc-a', clock);
    expect(result).toEqual({ removed: 1, files: 1, marker: 'scrub-2026-02-26-000.jsonl' });
    expect(bytesAt(part)).toBe(after + late);
    const receipt = markerAt(MARKER);
    // The after-pair is the name read back, which at this instant is two writers' bytes, and the count
    // is still the one record this run took out.
    expect(receipt.parts[0]?.afterBytes).toBe(Buffer.byteLength(after + late));
    expect(receipt.removed).toBe(1);
    expect(callsOf('writeFile', temporaryFor(part))).toHaveLength(1);
  });

  it('receipts a part whose record came back, with a count of nothing and the part named', async () => {
    // The subject using a serving deployment is the worst case for a count: this run takes one record
    // out and the gateway writes two in, so the raw difference is minus one and the honest number is
    // zero. The part is still one this run rewrote, and a receipt that omitted it would leave the
    // volume holding records for a credential someone filed an erasure about with no paper naming it.
    // This is also the only gate on the count being a difference that cannot go negative, and on a run
    // deciding that it landed something from the parts it completed rather than from that count.
    const part = scriptFile('access-2026-02-24-000.jsonl', lines(['rid-1', 'svc-a'], ['rid-2', 'svc-b']), 0o600);
    const after = lines(['rid-2', 'svc-b']);
    const back = lines(['rid-new', 'svc-a'], ['rid-newer', 'svc-a']);
    host.appendsAfter.set(part, back);
    const result = await accesslogScrub(DIR, 'svc-a', clock);
    expect(result).toEqual({ removed: 0, files: 1, marker: 'scrub-2026-02-26-000.jsonl' });
    expect(bytesAt(part)).toBe(after + back);
    const receipt = markerAt(MARKER);
    expect(receipt.removed).toBe(0);
    expect(receipt.parts.map((each) => each.name)).toEqual(['access-2026-02-24-000.jsonl']);
    expect(receipt.parts[0]?.beforeBytes).toBe(Buffer.byteLength(lines(['rid-1', 'svc-a'], ['rid-2', 'svc-b'])));
    expect(receipt.parts[0]?.afterBytes).toBe(Buffer.byteLength(after + back));
  });

  it('refuses a name the sweep took between the publish and the read that confirms it', async () => {
    // The other thing a rename does not report: a name that was there and is not any more, which here
    // is the retention sweep aged the part out between the two calls. Un-wrapped, this is the
    // operating system's own `ENOENT` reaching the terminal as a stack over an exit code that reads as
    // a crash, from a run that had already erased the record.
    const part = scriptFile('access-2026-02-24-000.jsonl', lines(['rid-1', 'svc-a'], ['rid-2', 'svc-b']), 0o600);
    host.vanishesAfter.add(part);
    const failure = await accesslogScrub(DIR, 'svc-a', clock).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(Error);
    const message = (failure as Error).message;
    expect(message).toContain(`cannot confirm access log part '${part}'`);
    expect(message).toContain('ENOENT');
    expect(host.entries.has(part)).toBe(false);
    expect(host.entries.has(MARKER)).toBe(false);
  });
});
