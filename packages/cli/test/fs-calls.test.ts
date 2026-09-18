import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { writeAtomically } from '../src/atomic.js';
import { accesslogScrub } from '../src/commands/accesslog.js';

/**
 * A scripted `node:fs/promises`, so that the writer rules are decided by the arguments a call passed
 * and the order the calls arrived in rather than by the host that happens to run them.
 * What a host can decline to show is not small: a umask decides whether a masked create is
 * distinguishable from a corrected one, a uid decides whether a permission bit binds at all, and
 * Windows reports a writable file as `0666` whatever its bits and a read-only one as `0444`, so three of
 * the mode rules this file holds could only ever be
 * read as predictions about a real volume. A race is worse still, because a real one needs two
 * processes and a scheduler that cooperates, and the outcome under test is which bytes the loser
 * published. The script below fixes a umask, answers `wx` with `EEXIST`, applies a mask to a create and
 * leaves a `chmod` to correct it, lets a case queue a write behind the next read of one name, which is
 * how an append is made to land exactly between this run's read and its own comparison, and lets a case
 * say how many names hold a part's bytes, which is how a rewrite's false claim is reached without a
 * second process. What it cannot do is say what a real file system does with those arguments. Each of
 * the three mode rules has a partner case in `test/atomic.test.ts` or `test/accesslog.test.ts` that
 * reads bits off a volume, and every one of those partners is gated to a POSIX host: on Windows the
 * argument capture in this file is not one of a pair, it is the only witness there is. The rules below
 * have no volume partner for the shape they are asserted in here, which is the point of scripting them:
 * an `EEXIST` that reaches a rename, an append landing between two calls of one run, a name that is gone
 * or unopenable when it is read back, a net-zero rewrite followed by a part the open refuses, a part
 * whose name is shared with a second name or is a link, a link whose target is gone, a link planted
 * between two attempts at one part, a name that changes character or is gone between this run's read
 * and its next question, and a directory carrying the link count a Linux volume answers for one. Of
 * those, the ones about a name's own character are reachable on a volume before a run starts, and
 * `test/accesslog.test.ts` holds those cases; the rest need a second writer that arrives on a test's
 * schedule, which no host is obliged to provide.
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
  /** Names whose open answers `EACCES` once this run has renamed onto them, its own publish unreadable. */
  unreadableAfter: new Set<string>(),
  /** Where a name in `unreadableAfter` goes at the rename: an open refuses it from then on. */
  refused: new Set<string>(),
  /** How many names hold a file's bytes, which is a backup tool's shape and not a race. */
  sharedNames: new Map<string, number>(),
  /** Names that are a symlink rather than the file itself. */
  symlinked: new Set<string>(),
  /** Names whose `lstat` answers a link and whose `stat` answers `ENOENT`, a link to nothing. */
  dangling: new Set<string>(),
  /** Names one `lstat` finds as themselves and every later one finds as a link, which is a link planted
   * while this run was working. The value counts the asks, because the answer has to change on one. */
  plantedLink: new Map<string, number>(),
  /** Names the first read finds as a file and every `stat` after it finds as a directory. */
  turnsToDirectory: new Set<string>(),
  /** Names the listing still hands over that every open and every `stat` answers `ENOENT` for. */
  gone: new Set<string>(),
  /** Names this run reads whole and the sweep takes before its next question about them. */
  goneBeforeCheck: new Set<string>(),
  /** Names whose `stat` and `lstat` answer `EACCES` while the bytes behind them stay readable. */
  inspectRefuses: new Set<string>(),
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
    EACCES: 'permission denied',
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

  /** The answer for a name that is itself a link: no mode of its own and nothing countable through it. */
  function linkStats(): Stats {
    return {
      mode: 0o777,
      size: 0,
      nlink: 1,
      isFile: () => false,
      isDirectory: () => false,
      isSymbolicLink: () => true,
    };
  }

  /**
   * What both stat calls answer with: the bytes' facts, whether the name is itself, and whether what is
   * there is a regular file, which is the only thing a link count is a fact about.
   */
  interface Stats {
    mode: number;
    size: number;
    nlink: number;
    isFile: () => boolean;
    isDirectory: () => boolean;
    isSymbolicLink: () => boolean;
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
      if (host.gone.has(path)) fail('ENOENT', 'open', path);
      // An open follows the link too, so a link to nothing cannot be read.
      if (host.dangling.has(path)) fail('ENOENT', 'open', path);
      const entry = host.entries.get(path);
      if (entry === undefined) fail('ENOENT', 'open', path);
      if (entry.directory) fail('EISDIR', 'open', path);
      if (host.refused.has(path)) fail('EACCES', 'open', path);
      // The answer is taken before the queue is drained, so a scripted append lands after this read
      // the way a real one lands after a real read: nothing sees the new bytes on the way out.
      const bytes = Buffer.from(entry.bytes);
      // A name can change character between this run's read and the next question it asks, which is the
      // only way the check under test reaches a name that is not a regular file: the read that comes
      // before it would otherwise refuse the directory in its own words first.
      if (host.turnsToDirectory.has(path)) entry.directory = true;
      // A name the sweep takes after the bytes are in this run's hand, which is the state the
      // shared-name check answers with silence about: the read had already succeeded, so the refusal
      // belongs to whichever step asks the next question.
      if (host.goneBeforeCheck.has(path)) host.entries.delete(path);
      const queued = host.queued.get(path);
      if (queued !== undefined && queued.length > 0) {
        append(path, queued.shift() as string);
        if (queued.length === 0) host.queued.delete(path);
      }
      if (host.always.has(path)) append(path, '{"t":1772000000000,"rid":"rid-tail","cred":"svc-tail"}\n');
      return bytes;
    },

    async stat(path: string): Promise<Stats> {
      note('stat', path);
      if (host.inspectRefuses.has(path)) fail('EACCES', 'stat', path);
      if (host.gone.has(path)) fail('ENOENT', 'stat', path);
      // `stat` follows the link, and a link to nothing has nothing at the end of it to report.
      if (host.dangling.has(path)) fail('ENOENT', 'stat', path);
      const entry = host.entries.get(path);
      if (entry === undefined) fail('ENOENT', 'stat', path);
      // `stat` follows a link, so the bytes and the mode it reports are the file's, and the name's own
      // character is invisible to it. That is exactly why the check under test asks `lstat` as well.
      return {
        mode: entry.mode,
        size: entry.bytes.length,
        nlink: host.sharedNames.get(path) ?? 1,
        isFile: () => !entry.directory,
        isDirectory: () => entry.directory,
        isSymbolicLink: () => false,
      };
    },

    async lstat(path: string): Promise<Stats> {
      note('lstat', path);
      if (host.inspectRefuses.has(path)) fail('EACCES', 'lstat', path);
      if (host.gone.has(path)) fail('ENOENT', 'lstat', path);
      // A link that was not there when this run first asked. The counter is the whole fixture: the
      // guard's answer has to change between one attempt at a part and the next, because that is the
      // only way a run that asks once per part differs from one that asks once per attempt.
      const asks = host.plantedLink.get(path);
      if (asks !== undefined) host.plantedLink.set(path, asks + 1);
      if (asks !== undefined && asks >= 1) return linkStats();
      if (host.symlinked.has(path) || host.dangling.has(path)) return linkStats();
      const entry = host.entries.get(path);
      if (entry === undefined) fail('ENOENT', 'lstat', path);
      return {
        mode: entry.mode,
        size: entry.bytes.length,
        nlink: host.sharedNames.get(path) ?? 1,
        isFile: () => !entry.directory,
        isDirectory: () => entry.directory,
        isSymbolicLink: () => false,
      };
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
      // The four states a publish cannot see from inside itself: somebody else's copy at the name
      // already, that copy grown by an append, no name at all, and a name this run can no longer open.
      // None of them is reachable on a host on a schedule a test does not own, and all four are what the
      // read after the rename is there to find out. The name's own character is a different case: a link
      // at a name is a state a volume can be put in before a run starts, and `test/accesslog.test.ts`
      // plants one. This script holds the symlink answer only so the order of the two questions is
      // visible, which is what no volume case can settle.
      const peer = host.landsAfter.get(to);
      if (peer !== undefined) {
        const moved = host.entries.get(to);
        if (moved !== undefined) moved.bytes = [...Buffer.from(peer, 'utf8')];
      }
      const appended = host.appendsAfter.get(to);
      if (appended !== undefined) host.entries.get(to)?.bytes.push(...Buffer.from(appended, 'utf8'));
      if (host.vanishesAfter.has(to)) host.entries.delete(to);
      if (host.unreadableAfter.has(to)) host.refused.add(to);
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

/** A name shaped like a part that is a directory, which the listing hands over like any other. */
function scriptDir(name: string): string {
  const path = join(DIR, name);
  host.entries.set(path, { bytes: [], mode: 0o755, directory: true });
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

/**
 * The mode as the script holds it, over four digits rather than three. A three-digit reader cannot see
 * the bit this file's first case is about, so a drop that failed would land at `0o4600` and still read
 * back as `0o600` here.
 */
function modeAt(path: string): number {
  const entry = host.entries.get(path);
  if (entry === undefined) throw new Error(`the script holds no name '${path}'`);
  return entry.mode & 0o7777;
}

function markerAt(path: string): { parts: Array<{ name: string; beforeBytes: number; afterBytes: number }>; removed: number; files: number } {
  return JSON.parse(bytesAt(path)) as {
    parts: Array<{ name: string; beforeBytes: number; afterBytes: number }>;
    removed: number;
    files: number;
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
  host.unreadableAfter.clear();
  host.refused.clear();
  host.sharedNames.clear();
  host.symlinked.clear();
  host.dangling.clear();
  host.plantedLink.clear();
  host.turnsToDirectory.clear();
  host.gone.clear();
  host.goneBeforeCheck.clear();
  host.inspectRefuses.clear();
  host.renameFails = null;
});

describe('the arguments a write reaches the volume with', () => {
  it('keeps the nine permission bits and drops everything above them, twice over', async () => {
    // A `stat` mode carries twelve bits and the top three are the set-user-id, set-group-id and sticky
    // ones, which are not readability settings a scrub means to publish. This case holds three
    // witnesses to the drop: the argument the create receives, the argument the `chmod` receives, and
    // the mode the script is left holding at the name, read over four digits so a bit that survived the
    // ceiling would show here. The first two are what a Windows host can be given, since it reports a
    // writable file as `0666` whatever its bits and cannot separate a landed mode from a masked create;
    // the third is this script's own arithmetic, which says the writer asked for `0600` and not that a
    // volume agreed.
    // `test/atomic.test.ts` reads a landed fourth digit off a real volume, and is gated to a POSIX host
    // for exactly that reason. The other writer's create argument is named in the marker case below.
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
    // at `0644`: a scrub that renamed that back over the log would take the group's write away from a
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
    // survive is an `EEXIST` from the create, which names a file this call never owned. The two halves
    // of that distinction are gated one apiece: the `EEXIST` that came from the create is the taken-name
    // case in `test/atomic.test.ts`, whose temporary is planted on a real volume, and the half that asks
    // whether the failing call was the create is this one, where the create succeeds and the rename is
    // what refuses. No real volume is obliged to answer a rename with `EEXIST` at all, which is why the
    // half that needs one is scripted.
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
    // The appended record survived the erasure that ran beside it, which is the whole property. One
    // expectation, read by two readers: the bytes at the name and the length the receipt names for them.
    const kept = lines(['rid-2', 'svc-b'], ['rid-late', 'svc-c']);
    expect(bytesAt(part)).toBe(kept);
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
    expect(receipt.parts[0]?.afterBytes).toBe(Buffer.byteLength(kept));
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
    // The gateway appends one record at a time to the name, so a line arriving after this run's rename
    // is the expected state of a serving log rather than an exceptional one.
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
    // A scrub run against a deployment that is still serving is the worst case for a count: this run
    // takes one record out and the gateway writes two in, so the raw difference is minus one and the
    // honest number is zero. The part is still one this run rewrote, and a receipt that omitted it
    // would leave the volume holding records for a credential someone filed an erasure about with no
    // paper naming it. What this case holds alone is the success route deciding it landed something from
    // the parts it completed rather than from that count. The floor it also exercises is reached a second
    // time by the halfway refusal at the end of this block, where the same zero is carried into a marker
    // that this run files and then refuses over a part it cannot read.
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

  it('receipts a name the sweep took between the publish and the read that confirms it', async () => {
    // The other thing a rename does not report: a name that was there and is not any more, which here
    // is the retention sweep aged the part out between the two calls. This run's erasure landed and
    // somebody else's deletion finished it, so the after-facts are the empty file's and the count is
    // every subject record this run read out. Refusing here would spend a completed erasure on a fact no
    // operator can act on: the run would exit 2, name a part that no longer exists, and file no marker
    // for records that are genuinely gone. The alternative this replaced did exit 2, with a usage error
    // about a missing file, so the difference is the receipt and not the exit code.
    const part = scriptFile('access-2026-02-24-000.jsonl', lines(['rid-1', 'svc-a'], ['rid-2', 'svc-b']), 0o600);
    host.vanishesAfter.add(part);
    const result = await accesslogScrub(DIR, 'svc-a', clock);
    expect(result).toEqual({ removed: 1, files: 1, marker: 'scrub-2026-02-26-000.jsonl' });
    expect(host.entries.has(part)).toBe(false);
    const receipt = markerAt(MARKER);
    expect(receipt.removed).toBe(1);
    expect(receipt.files).toBe(1);
    expect(receipt.parts[0]?.afterBytes).toBe(0);
    expect(receipt.parts[0]?.beforeBytes).toBe(Buffer.byteLength(lines(['rid-1', 'svc-a'], ['rid-2', 'svc-b'])));
  });

  it('refuses a name it published into and can no longer open, and carries the count in the sentence', async () => {
    // The fourth state, and the one no receipt can be written for: the bits of a live log's directory
    // moved under this run between its rename and its read. What the run knows is two facts and nothing
    // more, its own rename returned and this read failed, which is why the sentence names exactly those
    // two. It has to carry the count as well, because the marker that would have held it is never filed,
    // and an operator left with only this line has to be able to tell that the erasure happened and how
    // many records it took. That the bytes at the name are this run's is the script's doing, asserted
    // below as a check on the script; no read of the product establishes it on a real volume.
    const part = scriptFile(
      'access-2026-02-24-000.jsonl',
      lines(['rid-1', 'svc-a'], ['rid-2', 'svc-b'], ['rid-3', 'svc-a']),
      0o600,
    );
    host.unreadableAfter.add(part);
    const failure = await accesslogScrub(DIR, 'svc-a', clock).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(Error);
    const message = (failure as Error).message;
    expect(message).toContain(`cannot confirm access log part '${part}'`);
    expect(message).toContain('EACCES');
    expect(message).toContain('left none of the 2 records it had read there');
    expect(message).toContain('no marker has been filed for it');
    expect(bytesAt(part)).toBe(lines(['rid-2', 'svc-b']));
    expect(host.entries.has(MARKER)).toBe(false);
  });

  it('says that count as one record when the part it published held one', async () => {
    // The same sentence's other arm, gated because it is operator-facing text and a plural glued to `1`
    // is the mistake the branch is there to avoid. What is counted is the subject's records in the bytes
    // this run read, so a part that keeps one line of somebody else's still says one.
    const part = scriptFile('access-2026-02-24-000.jsonl', lines(['rid-1', 'svc-a'], ['rid-2', 'svc-b']), 0o600);
    host.unreadableAfter.add(part);
    const failure = await accesslogScrub(DIR, 'svc-a', clock).catch((error: unknown) => error);
    expect((failure as Error).message).toContain('left none of the 1 record it had read there');
  });

  it('receipts a part whose records came back when a later part cannot be read at all', async () => {
    // The catch route decides whether this run landed something by asking whether it rewrote anything,
    // and the two questions part company here: the first part is a net-zero rewrite, so the count this
    // route would carry is zero while the volume holds a part this run did publish. A run that tested the
    // count instead rethrows and files nothing, which leaves a rewritten part with no receipt naming it:
    // the paper that says whose credential this run was asked about, and what the bytes beside that
    // credential's records were when it looked. The second part is a name shaped like a log part that is
    // a directory, which is the listing handing over something no open can read.
    const rewritten = scriptFile('access-2026-02-24-000.jsonl', lines(['rid-1', 'svc-a'], ['rid-2', 'svc-b']), 0o600);
    const directory = scriptDir('access-2026-02-25-000.jsonl');
    host.appendsAfter.set(rewritten, lines(['rid-new', 'svc-a'], ['rid-newer', 'svc-a']));
    const failure = await accesslogScrub(DIR, 'svc-a', clock).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(Error);
    const message = (failure as Error).message;
    expect(message).toContain(`cannot read access log part '${directory}'`);
    expect(message).toContain('EISDIR');
    expect(message).toContain("the removals that landed are marked in 'scrub-2026-02-26-000.jsonl'");
    const receipt = markerAt(MARKER);
    expect(receipt.removed).toBe(0);
    expect(receipt.files).toBe(1);
    expect(receipt.parts.map((each) => each.name)).toEqual(['access-2026-02-24-000.jsonl']);
  });
});

describe('a part whose name is not the file itself', () => {
  it('refuses a part a second name also holds, before publishing anything at it', async () => {
    // `rename` replaces a name and not the bytes behind it, so a part that a second name also holds is
    // one this run can take records out of at one name while the other keeps every line. The marker's
    // `removed` would then read as records leaving the volume, and nothing would have left. This is a
    // backup tool's shape rather than an attacker's: a snapshot-style backup hard-links an append-only
    // log it does not want to copy twice. `test/accesslog.test.ts` plants a second name on a real volume
    // and reads the link count back, which is the half no script can settle; what this case holds is the
    // order, that nothing is written, renamed or unlinked at a shared name. Not that the part goes
    // unread: whether a part holds one of the subject's records is not knowable before the read, and a
    // check that will not wait for it refuses a log the subject never wrote to.
    const part = scriptFile('access-2026-02-24-000.jsonl', lines(['rid-1', 'svc-a'], ['rid-2', 'svc-b']), 0o600);
    host.sharedNames.set(part, 2);
    const failure = await accesslogScrub(DIR, 'svc-a', clock).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(Error);
    const message = (failure as Error).message;
    expect(message).toContain(`cannot scrub access log part '${part}'`);
    expect(message).toContain('2 names hold those bytes');
    expect(callsOf('readFile', part)).toHaveLength(1);
    expect(callsOf('writeFile', temporaryFor(part))).toEqual([]);
    // The only rename that could put bytes at a part name starts at this run's own temporary, so that is
    // the call to look for. A part is never a rename's source, which makes the part's own name here an
    // assertion that can never fail.
    expect(callsOf('rename', temporaryFor(part))).toEqual([]);
    expect(callsOf('unlink', part)).toEqual([]);
    expect(bytesAt(part)).toBe(lines(['rid-1', 'svc-a'], ['rid-2', 'svc-b']));
    expect(host.entries.has(MARKER)).toBe(false);
  });

  it('walks past a shared name the subject has never written to', async () => {
    // The other half of the order above, and the one the first version of the check got wrong. A backup
    // that hard-links a whole log leaves every part of every other customer sharing a name, and asking
    // the link question of those parts refuses an erasure that is about to be honest, for a file this
    // run would not have touched at all. This is the same discipline a read-only part earns two cases
    // up: the checks a part owes are decided by whether this run has something to remove from it.
    const shared = scriptFile('access-2026-02-24-000.jsonl', lines(['rid-9', 'svc-b'], ['rid-10', 'svc-b']), 0o600);
    const subject = scriptFile('access-2026-02-25-000.jsonl', lines(['rid-1', 'svc-a'], ['rid-2', 'svc-b']), 0o600);
    host.sharedNames.set(shared, 2);
    const result = await accesslogScrub(DIR, 'svc-a', clock);
    expect(result.removed).toBe(1);
    expect(markerAt(MARKER).parts.map((each) => each.name)).toEqual(['access-2026-02-25-000.jsonl']);
    expect(bytesAt(shared)).toBe(lines(['rid-9', 'svc-b'], ['rid-10', 'svc-b']));
    expect(callsOf('lstat', shared)).toEqual([]);
    expect(bytesAt(subject)).toBe(lines(['rid-2', 'svc-b']));
  });

  it('refuses a part whose name is a symlink, because the file it points at keeps the records', async () => {
    // The other way a name and its bytes come apart. A rewrite here publishes over the link, which
    // replaces the link with this run's file and leaves the target holding every record the receipt
    // names as removed. `stat` cannot see this at all, since it follows the link and reports the
    // target's facts, so the check has to ask `lstat` as well, and this case is the one that notices a
    // run that stops asking it. `test/accesslog.test.ts` reaches the same rule over a real link, on a
    // POSIX host only because making one there needs a privilege Windows withholds from a test.
    const part = scriptFile('access-2026-02-24-000.jsonl', lines(['rid-1', 'svc-a'], ['rid-2', 'svc-b']), 0o600);
    host.symlinked.add(part);
    const failure = await accesslogScrub(DIR, 'svc-a', clock).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(Error);
    const message = (failure as Error).message;
    expect(message).toContain(`cannot scrub access log part '${part}'`);
    expect(message).toContain('the name is a symlink');
    expect(message).toContain('asked to remove');
    expect(callsOf('lstat', part)).toHaveLength(1);
    expect(callsOf('writeFile', temporaryFor(part))).toEqual([]);
    expect(callsOf('rename', temporaryFor(part))).toEqual([]);
    expect(callsOf('unlink', part)).toEqual([]);
    expect(host.entries.has(MARKER)).toBe(false);
  });

  it('asks the link question again on a second attempt, when a link appeared between them', async () => {
    // The guard is asked once per attempt rather than once per part, and this is the state that claim is
    // about: the first look found the file the listing named, a gateway appended to it so this run starts
    // again from a fresh read, and in between a backup or an operator replaced the name with a link. A
    // run that asked once would publish over that link on the second turn and receipt records that still
    // stand at the file the name points at, which is the false claim the guard exists to stop. The
    // queued append is what makes a second attempt happen, and the count below is the whole point: an
    // answer that has to change between two asks needs two asks.
    const part = scriptFile('access-2026-02-24-000.jsonl', lines(['rid-1', 'svc-a'], ['rid-2', 'svc-b']), 0o600);
    host.queued.set(part, [lines(['rid-late', 'svc-c'])]);
    host.plantedLink.set(part, 0);
    const failure = await accesslogScrub(DIR, 'svc-a', clock).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(Error);
    const message = (failure as Error).message;
    expect(message).toContain(`cannot scrub access log part '${part}'`);
    expect(message).toContain('the name is a symlink');
    expect(callsOf('lstat', part)).toHaveLength(2);
    expect(callsOf('rename', temporaryFor(part))).toEqual([]);
    expect(callsOf('unlink', part)).toEqual([]);
    expect(bytesAt(part)).toBe(lines(['rid-1', 'svc-a'], ['rid-2', 'svc-b'], ['rid-late', 'svc-c']));
    expect(host.entries.has(MARKER)).toBe(false);
  });

  it('names a link to nothing as the link it is, not as a file that has gone', async () => {
    // `stat` follows a link, so when the target is gone the answer to "what stands at this name" is
    // `ENOENT`, and a check that consulted that answer would stay silent and let the read report the
    // name as missing. An operator reading "no such file or directory" about a part the listing just
    // handed over goes looking for a deletion, when what is there is a link to somewhere else. So the
    // name's own character is decided by `lstat` alone, before anything follows it.
    //
    // This is the one route that reaches the link sentence without having read a line: the open failed,
    // so nothing was filtered, nothing was published and nothing is being reported as removed. The
    // guard's version of the sentence says where those records stand, and importing that here would
    // describe bytes this run never saw, so this case holds the read route's own wording by refusing
    // the guard's.
    const part = scriptFile('access-2026-02-24-000.jsonl', lines(['rid-1', 'svc-a'], ['rid-2', 'svc-b']), 0o600);
    host.dangling.add(part);
    const failure = await accesslogScrub(DIR, 'svc-a', clock).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(Error);
    const message = (failure as Error).message;
    expect(message).toContain('the name is a symlink');
    expect(message).not.toContain('no such file');
    expect(message).not.toContain('names hold those bytes');
    expect(message).not.toContain('asked to remove');
    expect(message).not.toContain('cannot inspect');
    expect(message).not.toContain('cannot read the permissions');
    expect(host.entries.has(MARKER)).toBe(false);
  });

  it('leaves a name the sweep took before the first read to the read that owns it', async () => {
    // The listing is a moment old by the time it is used, so a name it hands over can be gone before
    // this run ever opens it. That is the read's refusal to make, and its sentence names the part as
    // something the run tried to read. The shared-name check is not reached at all on this route: the
    // arm of it that answers `ENOENT` with silence is gated by the case below, which is the state that
    // arm exists for. What separates this one from the link above is that a missing name is reported as
    // missing, so the run's own link question is asked and answers nothing, and an operator watching a
    // retention sweep is not told about a symlink.
    const part = scriptFile('access-2026-02-24-000.jsonl', lines(['rid-1', 'svc-a'], ['rid-2', 'svc-b']), 0o600);
    host.gone.add(part);
    const failure = await accesslogScrub(DIR, 'svc-a', clock).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(Error);
    const message = (failure as Error).message;
    expect(message).toContain(`cannot read access log part '${part}'`);
    expect(message).toContain('ENOENT');
    expect(message).not.toContain('the name is a symlink');
    expect(message).not.toContain('cannot inspect');
    expect(message).not.toContain('names hold those bytes');
    expect(host.entries.has(MARKER)).toBe(false);
  });

  it('leaves a name the sweep took after the read to the step that reads its bits', async () => {
    // The state the check's silence is for, now that the read comes first: the bytes were this run's to
    // hold, and the name went while it was deciding what else to ask. Answering that with a sentence
    // about inspecting the part would name a link problem to an operator watching a retention sweep, and
    // the run would still have to refuse one step later anyway, because the mode cannot be read from a
    // name that is not there. So the silence here is what keeps the one true refusal in one place.
    const part = scriptFile('access-2026-02-24-000.jsonl', lines(['rid-1', 'svc-a'], ['rid-2', 'svc-b']), 0o600);
    host.goneBeforeCheck.add(part);
    const failure = await accesslogScrub(DIR, 'svc-a', clock).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(Error);
    const message = (failure as Error).message;
    expect(message).toContain(`cannot read the permissions of access log part '${part}'`);
    expect(message).not.toContain('cannot inspect');
    expect(message).not.toContain('names hold those bytes');
    expect(message).not.toContain('the name is a symlink');
    expect(host.entries.has(MARKER)).toBe(false);
  });

  it('refuses a name whose permissions it cannot read, instead of guessing that nothing shares it', async () => {
    // The check asks a question of the directory, and a directory can answer it with `EACCES`. A
    // missing link count read as a link count of one would be the guess this refuses: the run would go
    // on to publish a receipt about bytes it never established it owned alone, so the failure to look
    // has to be the failure to proceed, and it has to name the part.
    const part = scriptFile('access-2026-02-24-000.jsonl', lines(['rid-1', 'svc-a'], ['rid-2', 'svc-b']), 0o600);
    host.inspectRefuses.add(part);
    const failure = await accesslogScrub(DIR, 'svc-a', clock).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(Error);
    const message = (failure as Error).message;
    expect(message).toContain(`cannot inspect access log part '${part}'`);
    expect(message).toContain('EACCES');
    expect(callsOf('rename', temporaryFor(part))).toEqual([]);
    expect(host.entries.has(MARKER)).toBe(false);
  });

  it('asks the link question of no name that is not a file', async () => {
    // A directory's `nlink` counts the entries inside it, not names holding it: 2 on an empty one and one
    // more per subdirectory, so asking the shared-name question of one answers with a number that means
    // something else. That is why the count is scripted here at the value a Linux volume gives a
    // directory: this host answers 1, which is how a full suite stayed green on one machine and went red
    // on the other. The guard's own `isFile` answer, for a name the read found as a file and the next
    // question found as something else, is the case below. What this one holds is the order: the listing
    // hands over a directory, the read refuses it in the operating system's words, and no link question
    // is asked of it at all.
    const directory = scriptDir('access-2026-02-25-000.jsonl');
    host.sharedNames.set(directory, 3);
    const failure = await accesslogScrub(DIR, 'svc-a', clock).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(Error);
    const message = (failure as Error).message;
    expect(message).toContain(`cannot read access log part '${directory}'`);
    expect(callsOf('lstat', directory)).toEqual([]);
    expect(message).not.toContain('names hold those bytes');
    expect(message).not.toContain('cannot inspect');
    expect(host.entries.has(MARKER)).toBe(false);
  });

  it('leaves a name that becomes a directory behind to the step that reads its bits', async () => {
    // The route the case above cannot reach now that the read comes first: a name the read finds as the
    // file it asked for and the link question finds as something else, because a sweep or an operator
    // moved a directory into place between the two. The count is scripted at the Linux answer, so a run
    // that asked the link question of a directory would refuse with a sentence about names holding bytes,
    // which is a claim about a link count the directory is not reporting. The refusal that is true here
    // belongs to the step that reads the bits it was about to publish.
    const part = scriptFile('access-2026-02-24-000.jsonl', lines(['rid-1', 'svc-a'], ['rid-2', 'svc-b']), 0o600);
    host.turnsToDirectory.add(part);
    host.sharedNames.set(part, 3);
    const failure = await accesslogScrub(DIR, 'svc-a', clock).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(Error);
    const message = (failure as Error).message;
    expect(message).toContain(`cannot read the permissions of access log part '${part}'`);
    expect(message).toContain('it is a directory');
    expect(message).not.toContain('names hold those bytes');
    expect(host.entries.has(MARKER)).toBe(false);
  });
});
