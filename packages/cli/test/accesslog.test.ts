import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import { parseAccessLine, renderAccessLine, type AccessRecord } from '@ashaveri/signerd';

const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
const tempDir = mkdtempSync(join(tmpdir(), 'ashaveri-scrub-'));

afterAll(() => {
  rmSync(tempDir, { recursive: true, force: true });
});

/** The instant every record below carries, so a scrubbed line is findable by its id alone. */
const T0 = 1_772_000_000_000;
const SCRUBBED_AT = '2026-02-26T00:00:00Z';

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
  return JSON.parse(readFileSync(join(dir, names[0] as string), 'utf8').trim()) as {
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

  it('refuses a part it cannot rewrite, naming the part and leaving no temporary behind', () => {
    // The two platforms refuse for different reasons, so the fixture branches: Windows marks a
    // read-only file and rejects the rename onto it, while a POSIX rename is a directory operation
    // that ignores the file's own bits, so the directory has to be the un-writable thing and the
    // failure lands on the write instead. Both routes end in the same catch, and what is being
    // pinned is the shape of the answer. Uncaught, this is the case where the operating system's
    // message, which repeats the directory the operator typed, reaches the terminal as a multi-line
    // stack beside a leftover `.tmp-` file no retention sweep will ever match.
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

  it.runIf(process.platform !== 'win32')('refuses an emptied part it cannot delete, instead of claiming an erasure', () => {
    // An erasure that did not happen has to arrive as a refusal naming the file, because the exit code
    // is the only evidence an operator has that the record is gone. Un-caught it is an exit 1 stack
    // that repeats the directory path, which reads as a crash in a program that deleted nothing.
    // This obstacle is POSIX-only, and the reason is measured rather than assumed: the read-only
    // attribute does not stop this deletion on Windows (the part was removed under it, and the
    // restore below then found no file to restore), and on either system unlink is an operation on the
    // directory, so on POSIX the directory is what loses its write permission. On Windows the same
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
