import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import { ACCESS_PART_NAME, parseAccessLine, renderAccessLine, RETENTION_SWEEP_NAME, type AccessRecord } from '@ashaveri/signerd';
import { ACCESS_FILE, accesslogScrub, chooseScrubName, modeOf } from '../src/commands/accesslog.js';

const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
const tempDir = mkdtempSync(join(tmpdir(), 'ashaveri-scrub-'));

/**
 * Whether the host is one where a permission bit is an obstacle at all. A process running as uid `0`
 * is told nothing by a mode: the write a fixture below is trying to stop simply happens, and the
 * refusal the case waits for never arrives. So this is not a configuration of a supported host but a
 * different host, and a case that depends on the bit is skipped on it rather than allowed to report a
 * build that is fine as broken.
 */
const modeBitsBind = !(typeof process.getuid === 'function' && process.getuid() === 0);

afterAll(() => {
  rmSync(tempDir, { recursive: true, force: true });
});

/** The instant every record below carries, so a scrubbed line is findable by its id alone. */
const T0 = 1_772_000_000_000;
/** The day `--now` above stamps a marker with, and the name every marker assertion quotes. */
const SCRUB_DAY = '2026-02-26';
const SCRUBBED_AT = `${SCRUB_DAY}T00:00:00Z`;

function record(over: Partial<AccessRecord>): AccessRecord {
  return {
    t: T0,
    rid: 'rid-1',
    cred: 'svc-a',
    auth: 'pop',
    scope: 'complete',
    m: 'POST',
    p: '/v1/chat/completions',
    rcp: null,
    nce: 'AAAAAAAAAAAAAAAAAAAAAA',
    st: 200,
    dur: 12,
    deny: null,
    ...over,
  };
}

/**
 * The log directory is written with the gateway's own renderer, so the command under test is
 * checked against the bytes a deployment produces rather than against a writer it shares with them.
 */
function dirWith(lines: Map<string, AccessRecord[]>): string {
  const dir = mkdtempSync(join(tempDir, 'case-'));
  for (const [name, records] of lines) {
    writeFileSync(join(dir, name), records.map((each) => renderAccessLine(each)).join(''));
  }
  return dir;
}

function run(args: string[]) {
  // Every case here is an exit path, so the deadline is what turns a handle that never closes into
  // the named failure below rather than a CI job that waits forever.
  const result = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    timeout: 8000,
    killSignal: 'SIGKILL',
  });
  expect(result.error).toBeUndefined();
  return { status: result.status, stdout: result.stdout ?? '', stderr: result.stderr ?? '' };
}

function scrub(dir: string, credential: string, ...extra: string[]) {
  return run(['accesslog', 'scrub', '--access-log', dir, '--credential', credential, '--now', SCRUBBED_AT, ...extra]);
}

function markers(dir: string): string[] {
  return readdirSync(dir).filter((each) => each.startsWith('scrub-'));
}

function markerOf(dir: string): { t: number; credential: string; removed: number; files: number } {
  const names = markers(dir);
  expect(names).toHaveLength(1);
  return markerNamed(dir, names[0] as string);
}

function markerNamed(dir: string, name: string): { t: number; credential: string; removed: number; files: number } {
  return JSON.parse(readFileSync(join(dir, name), 'utf8').trim()) as {
    t: number;
    credential: string;
    removed: number;
    files: number;
  };
}

describe('ashaveri accesslog scrub', () => {
  it('drops the credential records and writes one marker', () => {
    const dir = dirWith(
      new Map([
        ['access-2026-02-24-000.jsonl', [record({}), record({ cred: 'svc-b', rid: 'rid-2' }), record({ rid: 'rid-3' })]],
        ['access-2026-02-25-000.jsonl', [record({ cred: 'svc-b', rid: 'rid-4' })]],
      ]),
    );
    const result = scrub(dir, 'svc-a');
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('removed 2 records for svc-a');
    expect(result.stdout).toContain('marker');
    const kept = readFileSync(join(dir, 'access-2026-02-24-000.jsonl'), 'utf8');
    expect(kept).toContain('rid-2');
    expect(kept).not.toContain('rid-1');
    expect(kept).not.toContain('rid-3');
    expect(readFileSync(join(dir, 'access-2026-02-25-000.jsonl'), 'utf8')).toContain('rid-4');
    expect(markers(dir)).toEqual(['scrub-2026-02-26-000.jsonl']);
    expect(markerOf(dir)).toEqual({ t: Date.parse(SCRUBBED_AT), credential: 'svc-a', removed: 2, files: 1 });
  });

  it('reports zero and writes no marker when the credential never appears', () => {
    const dir = dirWith(new Map([['access-2026-02-24-000.jsonl', [record({ cred: 'svc-b' })]]]));
    const before = readFileSync(join(dir, 'access-2026-02-24-000.jsonl'), 'utf8');
    const result = scrub(dir, 'svc-z');
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('removed 0 records for svc-z');
    expect(markers(dir)).toEqual([]);
    // Nothing matched, so nothing was rewritten: the claim that a scrub leaves untouched lines as
    // they were reads strongest on the run that touched no line at all.
    expect(readFileSync(join(dir, 'access-2026-02-24-000.jsonl'), 'utf8')).toBe(before);
  });

  it('prints json when asked, with the same counts the prose carries', () => {
    const dir = dirWith(
      new Map([['access-2026-02-24-000.jsonl', [record({ rid: 'rid-1' }), record({ rid: 'rid-2', cred: 'svc-b' })]]]),
    );
    const result = scrub(dir, 'svc-a', '--json');
    expect(result.status).toBe(0);
    const out = JSON.parse(result.stdout) as { removed: number; files: number; marker: string | null };
    expect(out).toEqual({ removed: 1, files: 1, marker: 'scrub-2026-02-26-000.jsonl' });
    expect(result.stdout).not.toContain('removed 1 record');
  });

  it('leaves a part with nothing to remove unwritten, last byte included', () => {
    // No trailing newline on purpose: this is the shape a part has while an append is in flight, and
    // a scrub that rewrote files it found nothing in would move that byte and reopen the window the
    // no-lock warning is about. The rewrite is only owed to parts that actually held a record.
    const dir = mkdtempSync(join(tempDir, 'untouched-'));
    const path = join(dir, 'access-2026-02-24-000.jsonl');
    const text = renderAccessLine(record({ cred: 'svc-b', rid: 'rid-keep' })).trimEnd();
    writeFileSync(path, text);
    expect(scrub(dir, 'svc-a').stdout).toContain('removed 0 records for svc-a');
    expect(readFileSync(path, 'utf8')).toBe(text);
  });

  it('refuses a directory that holds no access files, rather than reporting success', () => {
    const dir = mkdtempSync(join(tempDir, 'empty-'));
    const result = run(['accesslog', 'scrub', '--access-log', dir, '--credential', 'svc-a']);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('--access-log holds no access-*.jsonl files');
  });

  it('names the credential that is being scrubbed and nothing about what they did', () => {
    const dir = dirWith(new Map([['access-2026-02-24-000.jsonl', [record({})]]]));
    const result = scrub(dir, 'svc-a');
    expect(result.status).toBe(0);
    const text = readdirSync(dir)
      .map((each) => readFileSync(join(dir, each), 'utf8'))
      .join('');
    expect(text).not.toContain('/v1/chat/completions');
    expect(text).not.toContain('rid-1');
  });

  it('erases a fully scrubbed part instead of leaving it under another name', () => {
    const dir = dirWith(
      new Map([
        ['access-2026-02-24-000.jsonl', [record({ rid: 'rid-1' }), record({ rid: 'rid-2' })]],
        ['access-2026-02-25-000.jsonl', [record({ cred: 'svc-b', rid: 'rid-3' })]],
      ]),
    );
    expect(scrub(dir, 'svc-a').status).toBe(0);
    // A renamed copy would keep every removed line on the volume under a name the gateway's
    // retention can never match again, which is the opposite of the erasure that was asked for.
    expect(readdirSync(dir).sort()).toEqual(['access-2026-02-25-000.jsonl', 'scrub-2026-02-26-000.jsonl']);
    // Both counts, not just the file: the part that vanished held two records, and a marker that
    // left them out would understate the erasure the operator is asked to prove.
    expect(markerOf(dir)).toEqual({ t: Date.parse(SCRUBBED_AT), credential: 'svc-a', removed: 2, files: 1 });
  });

  it('keeps a line it cannot read byte for byte while removing the record beside it', () => {
    const dir = mkdtempSync(join(tempDir, 'raw-'));
    const unreadable = 'this line is not JSON at all, and nothing may decide it is empty\n';
    const other = renderAccessLine(record({ cred: 'svc-b', rid: 'rid-keep' }));
    const target = join(dir, 'access-2026-02-24-000.jsonl');
    writeFileSync(target, `${unreadable}${renderAccessLine(record({}))}${other}`);
    const result = scrub(dir, 'svc-a');
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('removed 1 record for svc-a');
    const text = readFileSync(target, 'utf8');
    expect(text).toContain(unreadable.trimEnd());
    expect(text).toContain(other.trimEnd());
    expect(text).not.toContain('rid-1');
    // A line the twelve-field allowlist does not know would not survive a parse-and-render round
    // trip, so the kept lines have to travel as the strings that were read off disk.
    expect(parseAccessLine(other.trimEnd())).toMatchObject({ rid: 'rid-keep' });
    expect(() => parseAccessLine(unreadable.trimEnd())).toThrow();
  });

  it('numbers a second marker for the same day after the first', () => {
    const dir = dirWith(
      new Map([['access-2026-02-24-000.jsonl', [record({ cred: 'svc-a', rid: 'rid-1' }), record({ cred: 'svc-b', rid: 'rid-2' })]]]),
    );
    expect(scrub(dir, 'svc-a').status).toBe(0);
    expect(scrub(dir, 'svc-b').status).toBe(0);
    expect(markers(dir).sort()).toEqual(['scrub-2026-02-26-000.jsonl', 'scrub-2026-02-26-001.jsonl']);
  });

  it('refuses a directory that is not there, naming the path it was given', () => {
    const result = scrub(join(tempDir, 'no-such-dir'), 'svc-a');
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('cannot read --access-log directory');
  });

  it.runIf(modeBitsBind)('refuses a part it cannot rewrite, naming the part and leaving no temporary behind', () => {
    // The two platforms refuse for different reasons, so the fixture branches: Windows marks a
    // read-only file and rejects the rename onto it, while a POSIX rename is a directory operation
    // that ignores the file's own bits, so the directory has to be the un-writable thing and the
    // failure lands on the write instead. Both routes end in the same catch, and what is being pinned
    // is the shape of the answer. Either route is an obstacle only to a process the operating system
    // will let be told what to do, so the case is skipped for a uid of zero. Uncaught, this is the
    // case where the operating system's message, which repeats the directory the operator typed,
    // reaches the terminal as a multi-line stack beside a leftover `.tmp-` file no retention sweep
    // will ever match.
    const dir = dirWith(
      new Map([['access-2026-02-24-000.jsonl', [record({ cred: 'svc-a', rid: 'rid-1' }), record({ cred: 'svc-b', rid: 'rid-2' })]]]),
    );
    const part = join(dir, 'access-2026-02-24-000.jsonl');
    if (process.platform === 'win32') chmodSync(part, 0o444);
    else chmodSync(dir, 0o500);
    let result: { status: number | null; stdout: string; stderr: string };
    try {
      result = scrub(dir, 'svc-a');
    } finally {
      chmodSync(dir, 0o700);
      chmodSync(part, 0o600);
    }
    expect(result.status).toBe(2);
    expect(result.stderr).toContain(`cannot rewrite access log part '${part}'`);
    expect(result.stderr).not.toMatch(/^\s+at /mu);
    expect(result.stderr.trimEnd().split('\n')).toHaveLength(2);
    expect(result.stdout).toBe('');
    expect(readdirSync(dir)).toEqual(['access-2026-02-24-000.jsonl']);
    expect(readFileSync(part, 'utf8')).toContain('svc-a');
  });

  it.runIf(process.platform !== 'win32')('leaves a rewritten part readable by whoever the deployment made it readable to', () => {
    // The scrub renames its own copy over a file a running gateway is appending to, so the copy has to
    // arrive with the original's permission bits. `gateway/src/aclog.ts` creates parts with the default
    // mode, and a rewrite that imposed `0600` would leave that writer unable to append, which the
    // gateway reports as a warning rather than a failure. `0666` is the value that makes the test about
    // the `chmod` and not about the create: a create mode is masked by the process umask, so under the
    // common `022` a missing `chmod` lands on `0644` here. Under a umask of zero the two are the same
    // file, and this case cannot tell them apart.
    const dir = dirWith(
      new Map([['access-2026-02-24-000.jsonl', [record({ cred: 'svc-a', rid: 'rid-1' }), record({ cred: 'svc-b', rid: 'rid-2' })]]]),
    );
    const part = join(dir, 'access-2026-02-24-000.jsonl');
    chmodSync(part, 0o666);
    const result = scrub(dir, 'svc-a');
    expect(result.status).toBe(0);
    expect(statSync(part).mode & 0o777).toBe(0o666);
    expect(readFileSync(part, 'utf8')).not.toContain('svc-a');
  });

  it('refuses a name the listing calls a part but the open does not', () => {
    // A directory whose name matches the log pattern is the portable way to make one part
    // unreadable: both systems answer a read of a directory with a refusal, and no permission bit is
    // involved, so this fails the same way on a Windows laptop and in a Linux CI job. The listing is
    // taken first and the read happens per file, which is also the shape of a real rotation racing a
    // sweep. A refusal to read one part must name that part; un-caught it is an exit 1 stack. The
    // other half is what a stopped run leaves behind: the first part is already scrubbed here, so a
    // run that reports only its failure looks exactly like a run that removed nothing, and the
    // marker for the record that is genuinely gone has to exist and be named on the line.
    const dir = dirWith(new Map([['access-2026-02-24-000.jsonl', [record({ cred: 'svc-a', rid: 'rid-1' })]]]));
    mkdirSync(join(dir, 'access-2026-02-24-001.jsonl'));
    const result = scrub(dir, 'svc-a');
    expect(result.status).toBe(2);
    expect(result.stderr).toContain(`cannot read access log part '${join(dir, 'access-2026-02-24-001.jsonl')}'`);
    expect(result.stderr).not.toMatch(/^\s+at /mu);
    expect(result.stderr.trimEnd().split('\n')).toHaveLength(2);
    expect(result.stdout).toBe('');
    const marker = markers(dir);
    expect(marker).toHaveLength(1);
    expect(markerOf(dir)).toEqual({
      t: Date.parse(SCRUBBED_AT),
      credential: 'svc-a',
      removed: 1,
      files: 1,
    });
    expect(result.stderr).toContain(`the removals that landed are marked in '${String(marker[0])}'`);
    expect(existsSync(join(dir, 'access-2026-02-24-000.jsonl'))).toBe(false);
  });

  it.runIf(process.platform !== 'win32' && modeBitsBind)('refuses an emptied part it cannot delete, instead of claiming an erasure', () => {
    // An erasure that did not happen has to arrive as a refusal naming the file, because the exit code
    // is the only evidence an operator has that the record is gone. Un-caught it is an exit 1 stack
    // that repeats the directory path, which reads as a crash in a program that deleted nothing.
    // This obstacle is POSIX-only, and the reason is measured rather than assumed: the read-only
    // attribute does not stop this deletion on Windows (the part was removed under it, and the
    // restore below then found no file to restore), and on either system unlink is an operation on the
    // directory, so on POSIX the directory is what loses its write permission, and that obstacle holds
    // only for a uid the operating system lets be refused. On Windows the same
    // wrap is reachable only through a permission the file system has to be told about, so the
    // rewrite case above is what guards this file's shared error shape on that platform.
    const dir = dirWith(new Map([['access-2026-02-24-000.jsonl', [record({ cred: 'svc-a', rid: 'rid-1' })]]]));
    const part = join(dir, 'access-2026-02-24-000.jsonl');
    chmodSync(dir, 0o500);
    let result: { status: number | null; stdout: string; stderr: string };
    try {
      result = scrub(dir, 'svc-a');
    } finally {
      chmodSync(dir, 0o700);
      if (existsSync(part)) chmodSync(part, 0o600);
    }
    expect(result.status).toBe(2);
    expect(result.stderr).toContain(`cannot remove emptied access log part '${part}'`);
    expect(result.stderr).not.toMatch(/^\s+at /mu);
    expect(result.stdout).toBe('');
    expect(readFileSync(part, 'utf8')).toContain('svc-a');
    expect(markers(dir)).toEqual([]);
  });

  it('leaves a file the log does not own alone in the directory', () => {
    const dir = dirWith(new Map([['access-2026-02-24-000.jsonl', [record({})]]]));
    writeFileSync(join(dir, 'notes.txt'), 'not a log part\n');
    mkdirSync(join(dir, 'a-subdirectory'));
    expect(scrub(dir, 'svc-a').status).toBe(0);
    expect(readFileSync(join(dir, 'notes.txt'), 'utf8')).toBe('not a log part\n');
    expect(readdirSync(dir).sort()).toEqual(['a-subdirectory', 'notes.txt', 'scrub-2026-02-26-000.jsonl']);
  });
});

/**
 * A day's whole allotment of marker names, filled. This is the obstacle that makes a marker write fail
 * on any host and for any reason the operator will recognise: a permission bit in the same directory
 * would stop the part rewrite first, which is the route the cases above already take, and a full day
 * stops only the marker.
 */
function fillDay(dir: string, day: string): number {
  for (let seq = 0; seq < 1000; seq += 1) {
    writeFileSync(join(dir, `scrub-${day}-${String(seq).padStart(3, '0')}.jsonl`), '');
  }
  return 1000;
}

/** One part with the credential in it and another subject's record beside it, so a count can be wrong. */
function onePart(cred: string, other: string): Map<string, AccessRecord[]> {
  return new Map([['access-2026-02-24-000.jsonl', [record({ cred }), record({ cred: other, rid: 'rid-keep' })]]]);
}

describe('a scrub whose own write is refused', () => {
  const clock = () => Date.parse(SCRUBBED_AT);

  it('certifies nothing when the rewrite is refused, and touches no name it did not make', async () => {
    const dir = dirWith(onePart('svc-a', 'svc-b'));
    const part = join(dir, 'access-2026-02-24-000.jsonl');
    const planted = `${part}.tmp-${String(process.pid)}`;
    writeFileSync(planted, "not this writer's file\n");
    const failure = await accesslogScrub(dir, 'svc-a', clock).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(Error);
    const message = (failure as Error).message;
    expect(message).toContain(`cannot rewrite access log part '${part}'`);
    expect(message).not.toContain('marked in');
    // Both halves of the writer's discipline are here. A count taken during the scan would have
    // written this run's marker, and an unlink that does not ask whether the name is its own would
    // have removed the one it did not write.
    expect(readdirSync(dir).sort()).toEqual([part.slice(dir.length + 1), planted.slice(dir.length + 1)]);
    expect(readFileSync(part, 'utf8')).toContain('svc-a');
    expect(readFileSync(planted, 'utf8')).toBe("not this writer's file\n");
  });

  it('carries the counts in the refusal when the marker is the write that fails', () => {
    // The erasure has landed by now and cannot be taken back, so a bare sentence about a file the
    // operator has never heard of would leave them with a run that removed records and reported
    // nothing about it. Spawning the published command is the point: the numbers have to survive the
    // exit code, the two-line guard and the escaping on their way out, and only this route reads them.
    // Three records in two parts, because an assertion where both counts read `1` would still pass
    // with the two operands of the sentence swapped.
    const dir = dirWith(
      new Map([
        ['access-2026-02-24-000.jsonl', [record({}), record({ rid: 'rid-2' }), record({ cred: 'svc-b', rid: 'rid-keep' })]],
        ['access-2026-02-24-001.jsonl', [record({ rid: 'rid-3' })]],
      ]),
    );
    expect(fillDay(dir, SCRUB_DAY)).toBe(1000);
    const result = scrub(dir, 'svc-a');
    expect(result.status).toBe(2);
    // The obstacle is a filled day, so the first sentence is the one `chooseScrubName` refuses with,
    // and it has to carry the counts the same way a failed write does: either way the records are gone
    // and no receipt exists.
    expect(result.stderr).toContain('a thousand markers for 2026-02-26');
    expect(result.stderr).toContain('3 records removed from 2 files with no marker written');
    expect(result.stderr.trimEnd().split('\n')).toHaveLength(2);
    expect(result.stdout).toBe('');
    // The removals are the ones the sentence counts, and no marker was added to the filled day.
    expect(readFileSync(join(dir, 'access-2026-02-24-000.jsonl'), 'utf8')).not.toContain('"cred":"svc-a"');
    // Its only record erased, the second part is deleted rather than rewritten, and that removal is the
    // second file of "from 2 files".
    expect(existsSync(join(dir, 'access-2026-02-24-001.jsonl'))).toBe(false);
    expect(markers(dir)).toHaveLength(1000);
  });

  it('carries the counts when a later part fails after an earlier one was already rewritten', () => {
    // The route the marker inside the `catch` does not cover: the receipt it tries to write fails for
    // the same reason the directory is short, and the error the operator then sees is the first one,
    // which names no count at all. Records are gone, no marker exists, and re-running reports zero
    // because the erased lines are no longer on disk to match. A volume that fills mid-erasure hits
    // this, and so does a day whose markers are all taken.
    const dir = dirWith(
      new Map([['access-2026-02-24-000.jsonl', [record({}), record({ rid: 'rid-2' }), record({ cred: 'svc-b', rid: 'rid-keep' })]]]),
    );
    mkdirSync(join(dir, 'access-2026-02-24-001.jsonl'));
    fillDay(dir, SCRUB_DAY);
    const result = scrub(dir, 'svc-a');
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('cannot read access log part');
    expect(result.stderr).toContain('2 records removed from 1 file with no marker written');
    expect(readFileSync(join(dir, 'access-2026-02-24-000.jsonl'), 'utf8')).not.toContain('"cred":"svc-a"');
    expect(markers(dir)).toHaveLength(1000);
  });

  it('refuses a --now whose day no retention sweep can match, before touching a part', () => {
    // `toISOString()` leaves four-digit years behind for anything outside them, so `--now` could name a
    // marker nothing will ever collect: a credential id, written by the erasure that was supposed to
    // remove one, left on the volume past the window that aged its subject out. Refusing after the
    // erasure would be the other bad option, so the day is settled before a part is opened.
    const dir = dirWith(onePart('svc-a', 'svc-b'));
    const part = join(dir, 'access-2026-02-24-000.jsonl');
    const result = run([
      'accesslog', 'scrub', '--access-log', dir, '--credential', 'svc-a', '--now', '+275760-09-13T00:00:00Z',
    ]);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('four digits');
    expect(result.stderr).not.toContain('marked in');
    expect(readFileSync(part, 'utf8')).toContain('svc-a');
    expect(markers(dir)).toEqual([]);
  });

  it('steps past a marker another run already left at the next name', () => {
    // Two scrubs of the same day are one listing apart from each other, and a publish that replaces
    // whatever is at the chosen name destroys the first run's evidence while printing the second one's.
    // The marker is the only receipt an erasure has, so it is created new or not at all. What this case
    // can reach is the sequential route only: one process lists the directory, so the name it picks is
    // already absent from the listing it read. The concurrent route, where two runs list the same free
    // name and one publishes after the other, has no deterministic gate at this height, because nothing
    // here can put a file at a name in the instant between this program's listing and its write. That
    // half is held one level down, by the case on the publish primitive in `test/atomic.test.ts`, which
    // is where the claim that a taken name is refused rather than replaced is actually decided.
    const dir = dirWith(onePart('svc-a', 'svc-b'));
    const first = `scrub-${SCRUB_DAY}-000.jsonl`;
    writeFileSync(join(dir, first), '{"credential":"someone-else","removed":40}\n');
    const result = scrub(dir, 'svc-a');
    expect(result.status).toBe(0);
    expect(result.stdout).toContain(`scrub-${SCRUB_DAY}-001.jsonl`);
    expect(readFileSync(join(dir, first), 'utf8')).toBe('{"credential":"someone-else","removed":40}\n');
    expect(markerNamed(dir, `scrub-${SCRUB_DAY}-001.jsonl`)).toEqual({
      t: Date.parse(SCRUBBED_AT),
      credential: 'svc-a',
      removed: 1,
      files: 1,
    });
    expect(RETENTION_SWEEP_NAME.test(first)).toBe(true);
  });
});

describe('the marker a scrub leaves behind', () => {
  it.runIf(process.platform !== 'win32')('is written at the mode the scrub owns, whatever the part it joined was created with', () => {
    // Windows reports `0666` for every file it holds, so neither mode reading below is observable there
    // and the case could only ever fail. No other case reads a marker's bits, so this is the gate on the
    // mode the receipt is written at. The part is set to `0666` first: the gateway creates parts with
    // the process default, and a fixture that inherited its mode from the umask would let a marker at
    // the part's own mode pass this case on a host whose umask happens to be `0077`.
    const dir = dirWith(onePart('svc-a', 'svc-b'));
    const part = join(dir, 'access-2026-02-24-000.jsonl');
    chmodSync(part, 0o666);
    expect(scrub(dir, 'svc-a').status).toBe(0);
    const names = markers(dir);
    expect(names).toHaveLength(1);
    expect(statSync(join(dir, names[0] as string)).mode & 0o777).toBe(0o600);
    expect(statSync(part).mode & 0o777).toBe(0o666);
  });
});

/**
 * The marker's name is the erasure's receipt, and a name the retention sweep cannot match is a
 * credential id left on the volume past the window that erased its subject. The published CLI cannot
 * import the sweep at run time, so `RETENTION_SWEEP_NAME` comes from the gateway here rather than a
 * second copy of the pattern being written out below; that import is the only thing that pins this
 * program's idea of a collectable name to the gateway's.
 */
describe('chooseScrubName', () => {
  /**
   * The publisher this chooser is allowed to call. `offered` is what makes the refusals assertable: a
   * chooser that wrote at a name the listing had already reported taken would look the same in the
   * returned name and differ only in the bytes it destroyed on the way.
   */
  function claimer(taken: (name: string) => boolean = () => false) {
    const offered: string[] = [];
    return {
      offered,
      claim: async (name: string) => {
        offered.push(name);
        return !taken(name);
      },
    };
  }

  const slot = (seq: number) => `scrub-${SCRUB_DAY}-${String(seq).padStart(3, '0')}.jsonl`;
  const allSlots = Array.from({ length: 1_000 }, (_, seq) => slot(seq));

  it('fills a day within the digits the sweep matches, then refuses', async () => {
    const free = claimer();
    const lastOfAll = await chooseScrubName(allSlots.slice(0, 999), SCRUB_DAY, free.claim);
    expect(lastOfAll).toBe(allSlots[999]);
    expect(RETENTION_SWEEP_NAME.test(lastOfAll)).toBe(true);
    expect(free.offered).toEqual([allSlots[999]]);

    const full = claimer();
    await expect(chooseScrubName(allSlots, SCRUB_DAY, full.claim)).rejects.toThrow(
      /a thousand markers for 2026-02-26/u,
    );
    // A day with no slot left is a refusal before it is a write: publishing anywhere would be at a
    // name that already carries someone else's receipt.
    expect(full.offered).toEqual([]);
  });

  it('steps over a marker that exists rather than renaming over it', async () => {
    const free = claimer();
    expect(await chooseScrubName([slot(0), 'access-2026-02-26-000.jsonl'], SCRUB_DAY, free.claim)).toBe(slot(1));
    expect(free.offered).toEqual([slot(1)]);
  });

  it('takes the next slot when a name the listing called free turns out to be taken', async () => {
    // The route a listing cannot see: two scrubs of the same day read the same directory, both settle
    // on the first free slot, and one of them has to be told so. A chooser that trusts the listing
    // here writes over the other run's marker, which is the erasure receipt this program exists to
    // keep. The race itself needs two processes and no deterministic gate; the response to it does
    // not, and `test/atomic.test.ts` holds the half where a taken name comes back as a refusal.
    const raced = claimer((name) => name === slot(0));
    expect(await chooseScrubName([], SCRUB_DAY, raced.claim)).toBe(slot(1));
    expect(raced.offered).toEqual([slot(0), slot(1)]);
  });

  it('refuses a day the sweep has no digits for', async () => {
    // The command reaches a four-digit day from its own clock, so this is the guard on the exported
    // rule rather than the operator's route: an argument that is not a day must not become a name.
    const free = claimer();
    for (const day of ['+275760-09-13', '-000001-01-01', '+275760-09', '2026-2-6', '26-02-26', '']) {
      await expect(chooseScrubName([], day, free.claim), day).rejects.toThrow(/four digits/u);
    }
    expect(free.offered).toEqual([]);
    expect(await chooseScrubName([], '0000-01-01', free.claim)).toBe('scrub-0000-01-01-000.jsonl');
  });
});

/**
 * The mode a rewritten part carries is read from the part, because the scrub has no way to know what
 * the deployment made it. Both halves are gated here rather than through a spawned run: the only
 * obstacle that makes `stat` refuse on a name a listing produced is a permission bit, and the same bit
 * stops the write that follows a step later, so the command never reaches this code on its way out.
 */
describe('the mode a scrub reads off a part', () => {
  it('refuses a name whose permissions it cannot read, instead of inventing a mode for it', async () => {
    // A `0600` default would be the plausible mistake, and it is the one that quietly re-modes a file
    // a running gateway wrote at the process default: the rewrite lands readable by nobody else, the
    // append that follows it fails, and the erasure that asked for the rewrite reports a success.
    await expect(modeOf(join(tempDir, 'no-such-part.jsonl'))).rejects.toThrow(
      /cannot read the permissions of access log part/u,
    );
  });

  it.runIf(process.platform !== 'win32')('takes the nine permission bits and nothing above them', async () => {
    // Windows reports every file as `0666`, so a mode it holds cannot be distinguished from one a
    // create allowed. The fourth digit is the point: a set-user-id mode read through this function
    // would be handed to the writer as though it were a readability setting.
    const dir = dirWith(onePart('svc-a', 'svc-b'));
    const part = join(dir, 'access-2026-02-24-000.jsonl');
    chmodSync(part, 0o4600);
    expect(await modeOf(part)).toBe(0o600);
    chmodSync(part, 0o600);
  });
});

/**
 * This program keeps its own copy of the gateway's part pattern, because the published CLI cannot
 * depend on that package at run time, and the copy is the one that decides which files an erasure
 * reaches. A drift is not loud in either direction: widen the gateway's half and the scrub skips real
 * parts while printing a count and naming a marker; widen this half and the scrub opens names the
 * retention sweep will never collect. Both patterns are read from the gateway here, so neither copy is
 * being compared to a transcription of itself.
 */
describe('the names a scrub will open', () => {
  const table: Array<[string, boolean]> = [
    ['access-2026-02-24-000.jsonl', true],
    ['access-0000-01-01-000.jsonl', true],
    ['access-9999-12-31-999.jsonl', true],
    ['scrub-2026-02-24-000.jsonl', false],
    ['access-2026-02-24-00.jsonl', false],
    ['access-2026-02-24-0000.jsonl', false],
    ['access-2026-2-24-000.jsonl', false],
    ['access-+275760-09-13-000.jsonl', false],
    ['access-2026-02-24-000.jsonl.tmp-4242', false],
    ['access-2026-02-24-000.json', false],
    ['xaccess-2026-02-24-000.jsonl', false],
    ['notes.txt', false],
  ];

  it('are the names the gateway writes its parts under, and no others', () => {
    for (const [name, isPart] of table) {
      expect(ACCESS_FILE.test(name), name).toBe(isPart);
      expect(ACCESS_PART_NAME.test(name), name).toBe(isPart);
      // A name the scrub opens has to be one the sweep collects, or the bytes an erasure left behind
      // are held on the volume under a name nothing will ever age out.
      if (isPart) expect(RETENTION_SWEEP_NAME.test(name), name).toBe(true);
    }
  });
});
