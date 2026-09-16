import { spawnSync } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import {
  EMPTY_BODY_SHA256_HEX,
  signPopAuthorization,
  toBase64Url,
  type PopFields,
} from '@ashaveri/receipt';
import {
  CredentialStore,
  loadCredentialFile,
  MAX_CREDENTIALS,
  parseCredentialFile,
  serializeCredentialFile,
  type CredentialFile,
} from '@ashaveri/signerd';

const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
const tempDir = mkdtempSync(join(tmpdir(), 'ashaveri-credential-'));
let counter = 0;

/** An hour apart, so `revokedAt > createdAt` is a fact about two stamps and not about scheduling. */
const ADDED_AT = '2026-02-24T00:00:00Z';
const REVOKED_AT = '2026-02-24T01:00:00Z';

function runCli(args: string[]) {
  // Every case below is an exit path, so a process still alive after eight seconds is a bug rather
  // than a slow machine. The deadline is what turns a handle that never closes into the named
  // failure on the next line instead of a CI job that waits forever.
  const result = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    timeout: 8000,
    killSignal: 'SIGKILL',
  });
  expect(result.error).toBeUndefined();
  return { status: result.status, stdout: result.stdout ?? '', stderr: result.stderr ?? '' };
}

function freshFile(text?: string): string {
  const path = join(tempDir, `creds-${String(++counter)}.json`);
  if (text !== undefined) writeFileSync(path, text);
  return path;
}

function modeOf(path: string): number {
  return statSync(path).mode & 0o777;
}

function addArgs(path: string, ...extra: string[]) {
  return ['credential', 'add', '--credentials', path, '--now', ADDED_AT, ...extra];
}

/**
 * The characters in the guard's own class, looked at one code point at a time. A newline is left out
 * because a row is allowed to end with one, and each case that cares about that pairs this with the
 * number of lines the output has: the two together say the only newlines are the ones written here.
 * The two line separators are in the class because a line-splitting reader obeys them and the control
 * range does not contain them, which is the whole reason they are spelled out in the guard.
 */
function rawInvisible(text: string): string[] {
  return [...text].filter(
    (each) => each !== '\n' && /[\p{Cc}\p{Cf}\u{2028}\u{2029}\u{e0000}-\u{e007f}]/u.test(each),
  );
}

/** How many lines a reader that splits on any of the four line terminators would count. */
function jsLines(text: string): number {
  return text.split(/[\n\r\u2028\u2029]/u).filter((each) => each.length > 0).length;
}

afterAll(() => {
  rmSync(tempDir, { recursive: true, force: true });
});

describe('ashaveri keygen', () => {
  it('prints a public key and one private key, and no secret in between', () => {
    const result = runCli(['keygen', '--id', 'svc-7']);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('id:             svc-7');
    expect(result.stdout).toMatch(/publicKey:      [A-Za-z0-9_-]{43}/);
    expect(result.stdout).toMatch(/privateKeyHex:  [0-9a-f]{64}/);
    expect(result.stdout).toContain('Give the public key to credential add. The private half leaves this terminal');
  });

  it('prints json when asked, with no prose to parse around it', () => {
    const result = runCli(['keygen', '--id', 'svc-json', '--json']);
    expect(result.status).toBe(0);
    const out = JSON.parse(result.stdout) as Record<string, unknown>;
    expect(Object.keys(out).sort()).toEqual(['id', 'privateKeyHex', 'publicKey']);
    expect(out).toMatchObject({ id: 'svc-json' });
    expect(out['publicKey']).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    expect(out['privateKeyHex']).toMatch(/^[0-9a-f]{64}$/u);
    expect(result.stdout).not.toContain('Give the public key');
  });
});

describe('ashaveri credential add', () => {
  it('creates a file and one pop record, and prints the secret once', () => {
    const path = freshFile();
    const result = runCli(addArgs(path, '--id', 'svc-1', '--scopes', 'complete,read', '--label', 'pilot'));
    expect(result.status).toBe(0);
    expect(result.stdout).toMatch(/privateKeyHex:\s+[0-9a-f]{64}/);
    const file = parseCredentialFile(readFileSync(path, 'utf8'));
    expect(file.credentials).toHaveLength(1);
    const record = file.credentials[0];
    expect(record).toMatchObject({ id: 'svc-1', kind: 'pop', scopes: ['complete', 'read'], label: 'pilot' });
    // A parsed record holds decoded bytes, so the public key is 32 bytes here and the 43-character
    // base64url text only exists in the file; the length below is about bytes, not characters.
    expect(record?.publicKey).toHaveLength(32);
    expect(record?.secretHash).toBeUndefined();
    expect(record?.createdAt).toBe(Math.floor(Date.parse(ADDED_AT) / 1000));
    // The deployment writes this file with 0600 because it can carry a label; the assertion is
    // gated because Windows reports the mode a volume granted rather than the one asked for, and
    // the write path, including the explicit chmod, is identical on both.
    if (process.platform !== 'win32') expect(modeOf(path)).toBe(0o600);
  });

  it('reads a key that begins with a dash when the value is spelled as an option argument', () => {
    // A base64url key is 43 characters of an alphabet that contains a dash, so one key in sixty-four
    // that keygen hands out begins with one. Passed with a space, that value is not read as this
    // option's argument at all; the cases that enroll a generated key pass the `=` form for that
    // reason, and this is the case that says so rather than leaving it to which key was generated.
    const path = freshFile();
    const dashLeading = `-${'A'.repeat(42)}`;
    const spaced = runCli(addArgs(path, '--id', 'dash-a', '--public-key', dashLeading));
    expect(spaced.status).toBe(2);
    expect(spaced.stderr).toContain("Option '--public-key' argument is ambiguous");
    expect(() => readFileSync(path)).toThrow();
    const equals = runCli(addArgs(path, '--id', 'dash-b', `--public-key=${dashLeading}`));
    expect(equals.status).toBe(0);
    expect(parseCredentialFile(readFileSync(path, 'utf8')).credentials[0]?.publicKey).toEqual(
      new Uint8Array(Buffer.from(dashLeading, 'base64url')),
    );
  });

  it('enrolls a public key the caller generated, without ever seeing a private one', () => {
    const path = freshFile();
    const generated = runCli(['keygen']);
    const publicKey = /publicKey:\s+([A-Za-z0-9_-]{43})/.exec(generated.stdout)?.[1];
    // The `=` form because this key is random: one key in sixty-four begins with a dash, and a
    // space-separated argument starting that way is not read as an option's value.
    const result = runCli(addArgs(path, '--id', 'only-pub', `--public-key=${publicKey as string}`));
    expect(result.status).toBe(0);
    expect(result.stdout).not.toMatch(/[0-9a-f]{64}/);
    expect(result.stdout).toContain('stored the public key only');
    expect(parseCredentialFile(readFileSync(path, 'utf8')).credentials[0]?.publicKey).toEqual(
      new Uint8Array(Buffer.from(publicKey as string, 'base64url')),
    );
  });

  it('adds a bearer credential whose stored half is a hash', () => {
    const path = freshFile();
    const result = runCli(addArgs(path, '--id', 'b-1', '--kind', 'bearer'));
    expect(result.stdout).toMatch(/secret:\s+[A-Za-z0-9_-]{43}/);
    const text = readFileSync(path, 'utf8');
    // The hex form lives in the file, and `publicKey` is the 43-character base64url text there: a
    // parsed record holds neither, because both fields are decoded by the time anyone can read one.
    expect(text).toMatch(/"secretHash": "[0-9a-f]{64}"/);
    expect(text).not.toMatch(/"publicKey"/);
    const record = parseCredentialFile(text).credentials[0];
    expect(record).toMatchObject({ id: 'b-1', kind: 'bearer' });
    expect(record?.secretHash).toHaveLength(32);
    expect(record?.publicKey).toBeUndefined();
  });

  it('defaults a new credential id to the prefix the gateway uses', () => {
    const path = freshFile();
    runCli(addArgs(path));
    runCli(addArgs(path, '--kind', 'bearer'));
    const ids = parseCredentialFile(readFileSync(path, 'utf8')).credentials.map((each) => each.id);
    expect(ids[0]).toMatch(/^pop-[0-9a-f]{8}$/u);
    expect(ids[1]).toMatch(/^bearer-[0-9a-f]{8}$/u);
  });

  it('refuses an id already in the file', () => {
    const path = freshFile();
    runCli(addArgs(path, '--id', 'dup'));
    const again = runCli(addArgs(path, '--id', 'dup'));
    expect(again.status).toBe(2);
    expect(again.stderr).toContain("credential 'dup' already exists");
    expect(parseCredentialFile(readFileSync(path, 'utf8')).credentials).toHaveLength(1);
  });

  it('refuses an unknown scope before writing anything', () => {
    const path = freshFile();
    const result = runCli(addArgs(path, '--id', 'x', '--scopes', 'export'));
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('--scopes must be a subset of read,complete');
    expect(() => readFileSync(path)).toThrow();
  });

  it('refuses a rate the gateway would refuse the whole file for', () => {
    const path = freshFile();
    const result = runCli(addArgs(path, '--id', 'r', '--rate', 'perMinute=0,burst=120'));
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('--rate perMinute and burst must be integers of at least 1');
    expect(() => readFileSync(path)).toThrow();
  });

  it('refuses an id the gateway cannot name a record by, before writing it', () => {
    const path = freshFile();
    const result = runCli(addArgs(path, '--id', 'client 1'));
    expect(result.status).toBe(2);
    expect(result.stderr).toContain("--id 'client 1' is outside [A-Za-z0-9_-]{1,64}");
    expect(() => readFileSync(path)).toThrow();
  });

  it('refuses a public key the gateway would reject the file for', () => {
    // 42 characters carry 31 bytes: the last chunk of two contributes one byte, so this is a key
    // that is well-formed base64url and still not an Ed25519 public key.
    const short = freshFile();
    const tooShort = runCli(addArgs(short, '--id', 'k', '--public-key', `${'A'.repeat(40)}AA`));
    expect(tooShort.status).toBe(2);
    expect(tooShort.stderr).toContain('--public-key decodes to 31 bytes, not 32');
    expect(() => readFileSync(short)).toThrow();

    const alphabet = freshFile();
    const notBase64Url = runCli(addArgs(alphabet, '--id', 'k', '--public-key', `${'A'.repeat(43)}=`));
    expect(notBase64Url.status).toBe(2);
    expect(notBase64Url.stderr).toContain('--public-key is not unpadded base64url');
    expect(() => readFileSync(alphabet)).toThrow();
  });

  it('refuses to rewrite a file it cannot parse, and leaves it byte for byte', () => {
    const corrupt = '{"version":1,"credentials": [';
    const path = freshFile(corrupt);
    const result = runCli(['credential', 'revoke', '--credentials', path, '--id', 'any', '--now', REVOKED_AT]);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('refusing to rewrite a file this program cannot read');
    expect(readFileSync(path, 'utf8')).toBe(corrupt);
  });

  it('refuses a credential path it cannot read instead of calling it empty', () => {
    // A directory is the portable non-ENOENT failure: Linux reports EISDIR and Windows EPERM. If any
    // read error were treated as the missing-file case, a wrong path would be answered with an empty
    // listing and exit 0, which reads as a command that succeeded over a file it never opened.
    const dir = mkdtempSync(join(tempDir, 'a-directory-'));
    const listed = runCli(['credential', 'list', '--credentials', dir]);
    expect(listed.status).toBe(2);
    expect(listed.stderr).toContain('cannot read');
    expect(listed.stderr).toContain(dir);
    expect(listed.stdout).toBe('');
  });

  it('refuses a credential path it cannot write', () => {
    // The parent directory is missing, so the temporary name this program writes before the rename
    // cannot be created. Un-caught, that is an exit 1 and a stack trace whose first line repeats the
    // path in the `fs` module's own sentence, which is the shape the exit-2 guard exists to keep to
    // two lines. The next case takes the other half of the same writer, where the temporary exists and
    // the rename onto the real name is what fails: on Windows by marking the destination read-only,
    // and on POSIX only through a name that cannot take a rename at all, since a rename there is a
    // directory operation that ignores the destination file's own bits. The `stdout` assertion is a
    // forward guard rather than a live one, since this command prints the new credential only after
    // the file has taken it.
    const missing = join(tempDir, `no-such-dir-${String(++counter)}`, 'creds.json');
    const added = runCli(addArgs(missing));
    expect(added.status).toBe(2);
    expect(added.stderr).toContain(`cannot write the credential file '${missing}'`);
    expect(added.stderr).not.toMatch(/^\s+at /mu);
    expect(added.stdout).not.toMatch(/secret|private key/iu);
  });

  it('refuses a credential file it cannot replace, and takes its temporary with the refusal', () => {
    // A `revoke` that could read the file but not write it back is the one that matters: the stamp
    // would be applied in memory, printed as a completed revocation, and gone when the process exits.
    // The two platforms need different obstacles because a POSIX rename is a directory operation that
    // ignores the destination file's own permission bits, so Windows is where the rename itself can be
    // blocked, by marking the destination read-only; on POSIX the directory is made un-writable, which
    // stops the write that comes first. Either way the assertions are the same, and the one about the
    // directory listing is what proves the failed write did not leave a `.tmp-<pid>` credential file,
    // holding a fresh secret, next to the one the operator can see.
    const path = freshFile();
    expect(runCli(addArgs(path, '--id', 'keep-me', '--kind', 'bearer', '--scopes', 'read')).status).toBe(0);
    const dir = join(path, '..');
    if (process.platform === 'win32') chmodSync(path, 0o444);
    else chmodSync(dir, 0o500);
    let added: { status: number | null; stdout: string; stderr: string };
    let revoked: { status: number | null; stdout: string; stderr: string };
    try {
      added = runCli(addArgs(path, '--id', 'never-lands', '--kind', 'bearer', '--scopes', 'read'));
      revoked = runCli(['credential', 'revoke', '--credentials', path, '--id', 'keep-me', '--now', REVOKED_AT]);
    } finally {
      chmodSync(dir, 0o700);
      chmodSync(path, 0o600);
    }
    for (const [name, result] of [['add', added], ['revoke', revoked]] as const) {
      expect(result.status, name).toBe(2);
      expect(result.stderr, name).toContain(`cannot write the credential file '${path}'`);
      expect(result.stderr, name).not.toMatch(/^\s+at /mu);
      expect(result.stdout, name).not.toMatch(/secret|private key/iu);
    }
    const base = path.slice(dir.length + 1);
    expect(readdirSync(dir).filter((each) => each.startsWith(base))).toEqual([base]);
    const stored = parseCredentialFile(readFileSync(path, 'utf8'));
    expect(stored.credentials.map((each) => each.id)).toEqual(['keep-me']);
    expect(stored.credentials[0]?.revokedAt).toBeUndefined();
  });

  it('names the field of a record it cannot read, instead of crashing on it', () => {
    // Every other field of this record is valid, so the scopes check is the only thing that can
    // fire. A parsed record is typed as carrying scopes, which is what lets an unvalidated cast
    // reach `list` and die there with exit 1 and a stack trace: the same shape of surprise the
    // gateway would have had, moved one program earlier. A missing `scopes` and a `scopes: []` are
    // different files, and only the first one is refused here.
    const path = freshFile(
      `{"version":1,"credentials":[{"id":"no-scopes","kind":"bearer","secretHash":"${'0'.repeat(64)}","createdAt":1772000000}]}\n`,
    );
    const listed = runCli(['credential', 'list', '--credentials', path]);
    expect(listed.status).toBe(2);
    expect(listed.stderr).toContain('credentials[0].scopes must be an array of read and complete');
    expect(listed.stderr).not.toContain('unexpected error');
    expect(listed.stdout).toBe('');
  });

  it('refuses to add to a file holding a record the gateway would refuse', () => {
    const path = freshFile(
      `{"version":1,"credentials":[{"id":"no-scopes","kind":"pop","publicKey":"${'A'.repeat(43)}","createdAt":1772000000}]}\n`,
    );
    const before = readFileSync(path, 'utf8');
    const result = runCli(addArgs(path, '--id', 'fresh'));
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('credentials[0].scopes');
    // The rewrite is the danger: adding a valid record to a file the gateway will not load would
    // look like a successful edit and read as a deployment that has forgotten every credential.
    expect(readFileSync(path, 'utf8')).toBe(before);
  });

  it('prints json when asked, and keeps the prose off stdout', () => {
    const path = freshFile();
    const result = runCli(addArgs(path, '--id', 'j', '--label', 'svc', '--rate', 'perMinute=60,burst=120', '--json'));
    expect(result.status).toBe(0);
    const out = JSON.parse(result.stdout) as Record<string, unknown>;
    expect(Object.keys(out).sort()).toEqual(
      ['createdAt', 'id', 'kind', 'label', 'privateKeyHex', 'publicKey', 'rate', 'scopes'],
    );
    expect(out).toMatchObject({ id: 'j', label: 'svc', kind: 'pop', scopes: 'read,complete', rate: { perMinute: 60, burst: 120 } });
    expect(out['publicKey']).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    expect(out['privateKeyHex']).toMatch(/^[0-9a-f]{64}$/u);
    // The sentence that says not to keep the secret is the one line a captured stdout should not
    // carry with it, so it travels on the terminal and not in the object.
    expect(result.stderr).toContain('exists only in this terminal');
    expect(readFileSync(path, 'utf8')).not.toContain(String(out['privateKeyHex']));
  });

  it('writes a rate the gateway loads back unchanged', async () => {
    const path = freshFile();
    const added = runCli(addArgs(path, '--id', 'rated', '--rate', 'perMinute=60,burst=120'));
    expect(added.status).toBe(0);
    expect(added.stdout).toContain('rate:           perMinute=60,burst=120');
    // Every other refusal above is the CLI guessing what the gateway wants. This is the check: the
    // file this write produced goes through the gateway's own loader and the rate survives it.
    const loaded = await loadCredentialFile(path);
    expect(loaded.credentials[0]?.rate).toEqual({ perMinute: 60, burst: 120 });
  });

  it('refuses a file that lists one id twice', () => {
    const one = `{"id":"twice","kind":"bearer","secretHash":"${'0'.repeat(64)}","scopes":["read"],"createdAt":1772000000}`;
    const path = freshFile(`{"version":1,"credentials":[${one},${one}]}\n`);
    const listed = runCli(['credential', 'list', '--credentials', path]);
    expect(listed.status).toBe(2);
    expect(listed.stderr).toContain("lists 'twice' twice");
    // A revocation over this file would stamp the first record and leave the second signing, so the
    // write is refused as well rather than reported as a success.
    const revoked = runCli(['credential', 'revoke', '--credentials', path, '--id', 'twice', '--now', REVOKED_AT]);
    expect(revoked.status).toBe(2);
    expect(revoked.stderr).toContain("lists 'twice' twice");
  });

  it('refuses the credential that would take the file past what a gateway scans', () => {
    // Built from the gateway's own ceiling, imported rather than restated: this case is also the
    // assertion that the CLI's re-declared copy of the number has not drifted.
    const filler = { kind: 'bearer', secretHash: '0'.repeat(64), scopes: ['read'], createdAt: 1_772_000_000 };
    const records = Array.from({ length: MAX_CREDENTIALS }, (_, index) => ({ ...filler, id: `c${String(index)}` }));
    const path = freshFile(JSON.stringify({ version: 1, credentials: records }));
    const before = readFileSync(path, 'utf8');
    const result = runCli(addArgs(path, '--id', 'one-too-many'));
    expect(result.status).toBe(2);
    expect(result.stderr).toContain(`already holds ${String(MAX_CREDENTIALS)} credentials`);
    expect(readFileSync(path, 'utf8')).toBe(before);
  });
});

describe('ashaveri credential revoke and list', () => {
  it('stamps revokedAt and keeps the record', () => {
    const path = freshFile();
    runCli(addArgs(path, '--id', 'gone'));
    const result = runCli(['credential', 'revoke', '--credentials', path, '--id', 'gone', '--now', REVOKED_AT]);
    expect(result.status).toBe(0);
    const record = parseCredentialFile(readFileSync(path, 'utf8')).credentials[0];
    expect(record?.revokedAt).toEqual(expect.any(Number));
    expect(record?.id).toBe('gone');
    expect(record?.revokedAt).toBeGreaterThan(record?.createdAt ?? 0);
  });

  it('names an id that is not there', () => {
    const path = freshFile();
    runCli(addArgs(path, '--id', 'here'));
    const result = runCli(['credential', 'revoke', '--credentials', path, '--id', 'nobody', '--now', REVOKED_AT]);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain("no credential with id 'nobody'");
  });

  it('lists without leaking a key or a hash', () => {
    const path = freshFile();
    runCli(addArgs(path, '--id', 'svc-a', '--label', 'alpha'));
    runCli(addArgs(path, '--id', 'svc-b', '--kind', 'bearer'));
    const listed = runCli(['credential', 'list', '--credentials', path]);
    expect(listed.stdout).toContain('svc-a');
    expect(listed.stdout).toContain('alpha');
    expect(listed.stdout).not.toMatch(/[0-9a-f]{64}/);
    expect(listed.stdout).not.toMatch(/[A-Za-z0-9_-]{43}/);
  });

  it('prints json without a key, a hash, or the file itself', () => {
    const path = freshFile();
    runCli(addArgs(path, '--id', 'svc-a', '--label', 'alpha'));
    runCli(addArgs(path, '--id', 'svc-b', '--kind', 'bearer'));
    const listed = runCli(['credential', 'list', '--credentials', path, '--json']);
    expect(listed.status).toBe(0);
    const views = JSON.parse(listed.stdout) as Record<string, unknown>[];
    expect(views).toHaveLength(2);
    expect(Object.keys(views[0] as Record<string, unknown>).sort()).toEqual(['createdAt', 'id', 'kind', 'label', 'scopes']);
    expect(Object.keys(views[1] as Record<string, unknown>).sort()).toEqual(['createdAt', 'id', 'kind', 'scopes']);
    expect(views[0]).toMatchObject({ id: 'svc-a', label: 'alpha', kind: 'pop', scopes: 'read,complete' });
    expect(listed.stdout).not.toMatch(/[0-9a-f]{64}/);
    expect(listed.stdout).not.toMatch(/[A-Za-z0-9_-]{43}/);
  });

  it('refuses a revokedAt the gateway would refuse the record for', () => {
    // Every other field is one this reader accepts, so the only thing that can fire is the revokedAt
    // check. Without it this record prints `revoked 'a' at tomorrow` and exits 0 over a file the
    // gateway will not load, and the revocation the operator believes they made wrote nothing.
    const path = freshFile(
      `{"version":1,"credentials":[{"id":"a","kind":"bearer","secretHash":"${'0'.repeat(64)}","scopes":["read"],"createdAt":1772000000,"revokedAt":"tomorrow"}]}\n`,
    );
    const before = readFileSync(path, 'utf8');
    const listed = runCli(['credential', 'list', '--credentials', path]);
    expect(listed.status).toBe(2);
    expect(listed.stderr).toContain('credentials[0].revokedAt must be a number of seconds when present');
    expect(listed.stdout).toBe('');
    const revoked = runCli(['credential', 'revoke', '--credentials', path, '--id', 'a', '--now', REVOKED_AT]);
    expect(revoked.status).toBe(2);
    expect(revoked.stderr).toContain('credentials[0].revokedAt');
    expect(readFileSync(path, 'utf8')).toBe(before);
  });

  it('prints a revocation as json, and shows revokedAt in a listing', () => {
    const path = freshFile();
    runCli(addArgs(path, '--id', 'gone', '--label', 'alpha'));
    const revoked = runCli(['credential', 'revoke', '--credentials', path, '--id', 'gone', '--now', REVOKED_AT, '--json']);
    expect(revoked.status).toBe(0);
    const record = JSON.parse(revoked.stdout) as Record<string, unknown>;
    expect(Object.keys(record).sort()).toEqual(['createdAt', 'id', 'kind', 'label', 'revokedAt', 'scopes']);
    expect(record['revokedAt']).toBe(Math.floor(Date.parse(REVOKED_AT) / 1000));

    const listed = runCli(['credential', 'list', '--credentials', path, '--json']);
    const [first] = JSON.parse(listed.stdout) as Record<string, unknown>[];
    expect(Object.keys(first as Record<string, unknown>).sort()).toEqual(
      ['createdAt', 'id', 'kind', 'label', 'revokedAt', 'scopes'],
    );
    // The stamp is the whole answer to an erasure or a dispute, so a listing that dropped it would
    // read as a credential that never was revoked.
    expect(first?.revokedAt).toBe(record['revokedAt']);
  });

  it('keeps a label with a newline inside its own row', () => {
    // Nothing on the write side stops this: a label is free text, and a file can also arrive from an
    // editor. Printed raw, the second half of it is a row on the terminal that no record occupies.
    const path = freshFile();
    const added = runCli(addArgs(path, '--id', 'a', '--label', 'alpha\nFORGED  bearer  read  1  1  forged row'));
    expect(added.status).toBe(0);
    const listed = runCli(['credential', 'list', '--credentials', path]);
    expect(listed.status).toBe(0);
    const lines = listed.stdout.split('\n').filter((each) => each.length > 0);
    expect(lines).toHaveLength(2);
    expect(lines[1]).toContain('"alpha\\nFORGED');
    // The quoted label still carries the forged words, so the claim is about rows: nothing on the
    // terminal starts a second one.
    expect(lines.filter((each) => each.startsWith('FORGED'))).toHaveLength(0);
  });

  it('survives a file the gateway wrote, and the gateway survives ours', async () => {
    const path = freshFile(
      serializeCredentialFile({ version: 1, credentials: [{ id: 'gateway-made', kind: 'bearer', scopes: ['read'], secretHash: new Uint8Array(32).fill(4), createdAt: 1_772_000_000 }] }),
    );
    const added = runCli(addArgs(path, '--id', 'cli-made'));
    expect(added.status).toBe(0);
    const text = readFileSync(path, 'utf8');
    const fromGateway = parseCredentialFile(text);
    expect(fromGateway.credentials.map((each) => each.id)).toEqual(['gateway-made', 'cli-made']);
    // The published package re-declares the shape because signerd is private; reading the file back
    // through the gateway's own loader is the assertion that stops the two copies drifting apart.
    const loaded = await loadCredentialFile(path);
    const store = new CredentialStore({ file: loaded });
    expect(store.credentials().map((each) => each.id)).toEqual(['gateway-made', 'cli-made']);
  });
});

describe('a credential file the gateway can serve', () => {
  it('admits a proof of possession signed by the key keygen handed out', () => {
    const generated = runCli(['keygen']);
    const publicKey = /publicKey:\s+([A-Za-z0-9_-]{43})/.exec(generated.stdout)?.[1];
    const privateKeyHex = /privateKeyHex:\s+([0-9a-f]{64})/.exec(generated.stdout)?.[1];
    const path = freshFile();
    const added = runCli(addArgs(path, '--id', 'e2e-pop', `--public-key=${publicKey as string}`));
    expect(added.status).toBe(0);
    const store = new CredentialStore({ file: parseCredentialFile(readFileSync(path, 'utf8')) });
    const ts = Math.floor(Date.parse(ADDED_AT) / 1000);
    const nonce = new Uint8Array(16).fill(7);
    const fields: PopFields = {
      ts,
      nonce,
      method: 'GET',
      target: '/v1/deployment-manifest',
      bodyDigestHex: EMPTY_BODY_SHA256_HEX,
    };
    const admission = store.admit({
      method: 'GET',
      url: '/v1/deployment-manifest',
      headers: {
        authorization: signPopAuthorization(fields, 'e2e-pop', new Uint8Array(Buffer.from(privateKeyHex as string, 'hex'))),
        'x-ashaveri-nonce': toBase64Url(nonce),
      },
      body: null,
      nowSeconds: ts,
    });
    expect(admission).toMatchObject({ credentialId: 'e2e-pop', auth: 'pop' });
  });

  it('admits the bearer secret it printed, and only that secret', () => {
    const path = freshFile();
    const added = runCli(addArgs(path, '--id', 'e2e-bearer', '--kind', 'bearer'));
    const secret = /secret:\s+([A-Za-z0-9_-]{43})/.exec(added.stdout)?.[1];
    const store = new CredentialStore({
      file: parseCredentialFile(readFileSync(path, 'utf8')) as CredentialFile,
      allowBearer: true,
    });
    const admission = store.admit({
      method: 'GET',
      url: '/v1/deployment-manifest',
      headers: { authorization: `Bearer ${secret as string}` },
      body: null,
    });
    expect(admission).toMatchObject({ credentialId: 'e2e-bearer', auth: 'bearer' });
    expect(() =>
      store.admit({
        method: 'GET',
        url: '/v1/deployment-manifest',
        headers: { authorization: `Bearer ${toBase64Url(new Uint8Array(32))}` },
        body: null,
      }),
    ).toThrow();
  });
});

describe('what the CLI is allowed to print', () => {
  it('refuses a label that is not a string, because the table prints it', () => {
    // `list` reads `label` for the row, `--json` for the object, and `revoke` for the record echo, so
    // a label is a field this program makes a promise about in exactly the way `revokedAt` is. A
    // number prints as itself and an array prints as its joined elements, which is a row describing a
    // value the file does not hold.
    const path = freshFile(
      `{"version":1,"credentials":[{"id":"a","kind":"bearer","secretHash":"${'0'.repeat(64)}","scopes":["read"],"createdAt":1772000000,"label":42}]}\n`,
    );
    const listed = runCli(['credential', 'list', '--credentials', path]);
    expect(listed.status).toBe(2);
    expect(listed.stderr).toContain('credentials[0].label must be a string when present');
    expect(listed.stdout).not.toContain('42');
    expect(() => parseCredentialFile(readFileSync(path, 'utf8'))).toThrow(/label/u);
  });

  it('lists and revokes a credential whose scopes are empty', () => {
    // The gateway loads this record and serves it, but only for a route whose scope is `any`, so it is
    // a manifest-only credential rather than a mistake. A CLI that refuses to read it cannot revoke it
    // either, which makes the stricter rule the unsafe one.
    const path = freshFile(
      `{"version":1,"credentials":[{"id":"manifest-only","kind":"bearer","secretHash":"${'0'.repeat(64)}","scopes":[],"createdAt":1772000000}]}\n`,
    );
    const listed = runCli(['credential', 'list', '--credentials', path]);
    expect(listed.status).toBe(0);
    expect(listed.stdout).toContain('manifest-only');
    const revoked = runCli(['credential', 'revoke', '--credentials', path, '--id', 'manifest-only', '--now', REVOKED_AT]);
    expect(revoked.status).toBe(0);
    expect(parseCredentialFile(readFileSync(path, 'utf8')).credentials[0]).toMatchObject({
      scopes: [],
      revokedAt: Date.parse(REVOKED_AT) / 1000,
    });
  });

  it('still refuses to add a credential with no scope', () => {
    // The read side above accepts an empty list because a file can arrive from an editor. The write
    // side has no reason to create one from a command line, and `--scopes ''` is far more likely a
    // dropped argument than a manifest-only credential.
    const path = freshFile();
    const added = runCli(addArgs(path, '--id', 'none', '--scopes', ''));
    expect(added.status).toBe(2);
    expect(added.stderr).toContain('--scopes must name at least one scope');
    expect(() => readFileSync(path)).toThrow();
  });

  it('refuses a file longer than a gateway will load, before it prints a row about it', () => {
    // This is one half of the assertion that the CLI's re-declared copy of the ceiling has not
    // drifted: the file is built from the gateway's own exported number, and a longer one has to be
    // refused here while the sibling case above refuses nothing at exactly that length.
    const path = freshFile(
      `{"version":1,"credentials":[${Array.from({ length: MAX_CREDENTIALS + 1 }, (_, i) =>
        `{"id":"c${String(i)}","kind":"bearer","secretHash":"${'0'.repeat(64)}","scopes":["read"],"createdAt":1772000000}`,
      ).join(',')}]}\n`,
    );
    const listed = runCli(['credential', 'list', '--credentials', path]);
    expect(listed.status).toBe(2);
    expect(listed.stderr).toContain(`${String(MAX_CREDENTIALS + 1)} records`);
    expect(listed.stderr).toContain(String(MAX_CREDENTIALS));
    expect(listed.stdout).toBe('');
  });

  it('keeps a newline inside the row a label was printed on', () => {
    // `add` echoes the record it just wrote, and the label is free text: a second line out of that
    // field reads as a second credential to anyone scanning the terminal on the way to a password
    // manager, which is the same forgery the table column already refuses.
    const path = freshFile();
    const added = runCli(addArgs(path, '--label', 'alpha\nFORGED  bearer  read  1  1  forged row'));
    expect(added.status).toBe(0);
    expect(added.stdout).not.toMatch(/^FORGED/mu);
    expect(added.stdout).toContain('label:          "alpha\\nFORGED');
  });

  it('escapes a label the terminal would otherwise obey', () => {
    // Three different holes in one column. `a\u0085b` is the C1 range, which the old detection class
    // never matched at all; `\u202e` reorders the characters after it, so a row can read as something
    // else; and a quote and a backslash have to survive being copied back into an editor. JSON
    // quoting handles the last two and neither of the first two, which is why the cell escapes what
    // the stringifier leaves raw.
    const path = freshFile();
    runCli(addArgs(path, '--id', 'c1', '--label', 'a\u0085b'));
    runCli(addArgs(path, '--id', 'bidi', '--label', 're\u202est'));
    runCli(addArgs(path, '--id', 'quotes', '--label', 'say "x" \\ y'));
    const listed = runCli(['credential', 'list', '--credentials', path]);
    expect(listed.status).toBe(0);
    const lines = listed.stdout.split('\n').filter((each) => each.length > 0);
    expect(lines).toHaveLength(4);
    expect(lines[1]).toContain('\\u0085');
    expect(lines[2]).toContain('\\u202e');
    expect(lines[3]).toContain('\\"x\\"');
    expect(lines[3]).toContain('\\\\ y');
    expect(listed.stdout).not.toMatch(/[\u0080-\u009f\u2028\u2029\u202a-\u202e\u2060-\u2064]/u);
  });

  it('escapes what a terminal hides or obeys, in the row and in the object', () => {
    // The class the guard carries and the list an earlier version enumerated are not the same set. A
    // zero-width space and a right-to-left mark are format characters rather than control ones, so a
    // class built from the control ranges never saw them; DEL sits above the C0 range that class
    // stopped at; a tag character is astral, which is where an escape written per code point rather
    // than per code unit hands back the high half alone; and a soft hyphen is invisible without being
    // a control at all. The object form is in the same case because `JSON.stringify` is the step that
    // left every one of them raw.
    const shapes = ['a\u200bb', 'a\u200fb', 'a\u061cb', 'a\u00adb', 'a\ufeffb', 'a\u007fb', `a\u{e0020}b`, 'a\u2066b'];
    const escapes = ['\\u200b', '\\u200f', '\\u061c', '\\u00ad', '\\ufeff', '\\u007f', '\\udb40\\udc20', '\\u2066'];
    const path = freshFile();
    shapes.forEach((label, index) => {
      const added = runCli(addArgs(path, '--id', `u${String(index)}`, '--label', label));
      expect(added.status, shapes[index]).toBe(0);
    });

    const listed = runCli(['credential', 'list', '--credentials', path]);
    expect(listed.status).toBe(0);
    expect(listed.stdout.split('\n').filter((each) => each.length > 0)).toHaveLength(shapes.length + 1);
    expect(rawInvisible(listed.stdout)).toEqual([]);
    for (const escape of escapes) expect(listed.stdout, escape).toContain(escape);

    const machine = runCli(['credential', 'list', '--credentials', path, '--json']);
    expect(rawInvisible(machine.stdout)).toEqual([]);
    // An escape is the other spelling of the same character, so the two forms have to agree: what the
    // object carries is the label the file holds, and the row is that label rendered.
    const views = JSON.parse(machine.stdout) as { label: string }[];
    expect(views.map((each) => each.label)).toEqual(shapes);
  });

  it('escapes the two characters that end a line without being a control', () => {
    // A reader that splits text on lines obeys four characters, and the control ranges hold only two
    // of them: U+2028 and U+2029 are category Zl and Zp, and `JSON.stringify` leaves both raw inside
    // its own quotes. So the row a label is printed on, and the object the same label is serialized
    // into, each need the range the class would otherwise have missed. Counting the lines twice, once
    // on newlines and once on all four terminators, is what makes this case able to fail: an escaped
    // separator gives the same count both ways, and a raw one gives one more row than was written.
    const shapes = [
      'a\u2028FORGED  bearer  read  1  1  forged row',
      'a\u2029FORGED  bearer  read  1  1  forged row',
    ];
    const path = freshFile();
    shapes.forEach((label, index) => {
      const added = runCli(addArgs(path, '--id', `sep${String(index)}`, '--label', label));
      expect(added.status, shapes[index]).toBe(0);
      expect(added.stdout, shapes[index]).not.toMatch(/^FORGED/mu);
      expect(jsLines(added.stdout), shapes[index]).toBe(added.stdout.split('\n').filter((each) => each.length > 0).length);
    });

    const listed = runCli(['credential', 'list', '--credentials', path]);
    expect(listed.status).toBe(0);
    const rows = listed.stdout.split('\n').filter((each) => each.length > 0);
    expect(rows).toHaveLength(3);
    expect(jsLines(listed.stdout)).toBe(rows.length);
    expect(rawInvisible(listed.stdout)).toEqual([]);
    expect(listed.stdout).toContain('\\u2028');
    expect(listed.stdout).toContain('\\u2029');

    const machine = runCli(['credential', 'list', '--credentials', path, '--json']);
    expect(rawInvisible(machine.stdout)).toEqual([]);
    expect(jsLines(machine.stdout)).toBe(machine.stdout.split('\n').filter((each) => each.length > 0).length);
    const views = JSON.parse(machine.stdout) as { label: string }[];
    expect(views.map((each) => each.label)).toEqual(shapes);
  });

  it('keeps a refusal about a token on one line, wherever the token came from', () => {
    // A message that names what it refused has to carry the token, and four of these tokens are
    // repeated back by the operating system inside its own error text, so the guard sits where a
    // message becomes a line rather than at each call site. `--access-log` is the case that proves
    // the difference: its refusal holds both this program's path and the `fs` module's.
    const path = freshFile();
    // Each row carries the escape its token has to come back as, because the two separators are the
    // ones the guard's first class missed: a refusal that counts its newlines and obeys them would
    // pass with a raw separator still in the message.
    const refusals: Array<[string, string[], string]> = [
      ['--kind', ['credential', 'add', '--credentials', path, '--kind', 'pop\nFORGED kind'], '\\u000aFORGED'],
      ['--public-key', ['credential', 'add', '--credentials', path, '--public-key', 'zz\nFORGED key'], '\\u000aFORGED'],
      ['--now', ['credential', 'add', '--credentials', path, '--now', 'someday\nFORGED clock'], '\\u000aFORGED'],
      ['--access-log', ['accesslog', 'scrub', '--access-log', `no/such\nFORGED dir`, '--credential', 'a'], '\\u000aFORGED'],
      ['a command', ['\nFORGED command'], '\\u000aFORGED'],
      ['--kind and U+2028', ['credential', 'add', '--credentials', path, '--kind', 'pop\u2028FORGED kind'], '\\u2028FORGED'],
      ['--public-key and U+2029', ['credential', 'add', '--credentials', path, '--public-key', 'zz\u2029FORGED key'], '\\u2029FORGED'],
      ['--access-log and U+2028', ['accesslog', 'scrub', '--access-log', `no/such\u2028FORGED dir`, '--credential', 'a'], '\\u2028FORGED'],
    ];
    for (const [name, args, escape] of refusals) {
      const result = runCli(args);
      expect(result.status, name).toBe(2);
      expect(result.stderr, name).toContain(escape);
      expect(jsLines(result.stderr), name).toBe(
        result.stderr.split('\n').filter((each) => each.length > 0).length,
      );
      expect(jsLines(result.stderr), name).toBe(2);
      expect(result.stderr, name).not.toMatch(/^FORGED/mu);
    }
  });

  it('refuses a revoke id it would otherwise print back, and says which flag it came from', () => {
    const path = freshFile();
    runCli(addArgs(path, '--id', 'here'));
    const spaced = runCli(['credential', 'revoke', '--credentials', path, '--id', 'client 1', '--now', REVOKED_AT]);
    expect(spaced.status).toBe(2);
    expect(spaced.stderr).toContain("--id 'client 1' is outside [A-Za-z0-9_-]{1,64}");
    // Refused as a bad name rather than as a missing record: the second sentence would carry the same
    // token, and a token carrying a newline is a second stderr line whose every word this program
    // wrote. The escape is what the message keeps instead of the character.
    const forged = runCli(['credential', 'revoke', '--credentials', path, '--id', 'x\nFORGED revocation', '--now', REVOKED_AT]);
    expect(forged.status).toBe(2);
    expect(forged.stderr).toContain('is outside [A-Za-z0-9_-]{1,64}');
    expect(forged.stderr).toContain("\\u000aFORGED revocation'");
    expect(forged.stderr).not.toMatch(/^FORGED/mu);
    expect(readFileSync(path, 'utf8')).not.toContain('revokedAt');
  });

  it('refuses a keygen id the gateway would refuse a record for', () => {
    const bad = runCli(['keygen', '--id', 'ok\nFORGED keygen row']);
    expect(bad.status).toBe(2);
    expect(bad.stderr).toContain('--id');
    expect(bad.stdout).not.toContain('FORGED');
    const space = runCli(['keygen', '--id', 'not valid']);
    expect(space.status).toBe(2);
    expect(space.stderr).toContain("--id 'not valid' is outside [A-Za-z0-9_-]{1,64}");
    const good = runCli(['keygen', '--id', 'svc-a']);
    expect(good.status).toBe(0);
    expect(good.stdout).toMatch(/^id:\s+svc-a$/mu);
  });

  it('refuses a scrub credential that is not a credential id', () => {
    const dir = join(tempDir, `scrub-id-${String(++counter)}`);
    mkdirSync(dir);
    writeFileSync(join(dir, 'access-2026-02-24-000.jsonl'), '');
    const result = runCli(['accesslog', 'scrub', '--access-log', dir, '--credential', 'svc-a\nFORGED scrub row']);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('--credential');
    expect(result.stdout).not.toContain('FORGED');
  });

  it('carries the one-time warning on stderr when keygen prints JSON', () => {
    // `credential add --json` puts its notice there for the same reason: stdout has to be the object
    // and nothing else, and a private half that leaves no warning anywhere is a private half an
    // operator assumes a file holds.
    const result = runCli(['keygen', '--json']);
    expect(result.status).toBe(0);
    expect(() => JSON.parse(result.stdout)).not.toThrow();
    expect(result.stdout).not.toMatch(/terminal/i);
    expect(result.stderr).toMatch(/private half/i);
  });

  it('warns once on stdout for each human-facing add, and on stderr for each machine one', () => {
    // Every one of the three kinds hands over something that exists nowhere else afterwards: a
    // generated private key, a bearer secret, or the news that no secret passed through at all. A
    // shape that loses its sentence is a shape an operator reads as a quiet success.
    const shapes: Array<[string, string[], RegExp]> = [
      ['generated key', ['--id', 'w-pop'], /private key exists only in this terminal/u],
      ['enrolled public key', ['--id', 'w-pub', '--public-key', 'A'.repeat(43)], /stored the public key only/u],
      ['bearer secret', ['--id', 'w-bearer', '--kind', 'bearer'], /secret exists only in this terminal/u],
    ];
    for (const [name, args, notice] of shapes) {
      const human = runCli(addArgs(freshFile(), ...args));
      expect(human.status, name).toBe(0);
      expect(human.stdout, name).toMatch(notice);
      const machine = runCli(addArgs(freshFile(), ...args, '--json'));
      expect(machine.status, name).toBe(0);
      expect(() => JSON.parse(machine.stdout), name).not.toThrow();
      expect(machine.stdout, name).not.toMatch(notice);
      expect(machine.stderr, name).toMatch(notice);
    }
  });

  it('states the scrub loss as the parts it rewrites, not as the whole directory', () => {
    const help = runCli(['--help']);
    expect(help.stdout).toMatch(/appended to a part between reading it and rewriting that part/u);
    expect(help.stdout).not.toMatch(/every record appended while the scrub works through the directory/u);
    // A deleted part is still a part the scrub acted on, and the file counter moves on that branch
    // too, so the help text may not promise a count that excludes it: the marker an operator files
    // as the answer to a request would understate the erasure by exactly the emptied part.
    expect(help.stdout).toMatch(/its\s+removals\s+counted\s+in\s+the\s+marker\s+beside\s+the\s+rest/u);
    expect(help.stdout).not.toMatch(/appear in no marker'?s count/u);
  });
});

describe('one record, two parsers', () => {
  /**
   * The CLI's reader mirrors the gateway's `parseRecord`, and a mirror goes stale silently: the day
   * the gateway gains a rule the reader does not have is the day `list` prints a healthy row over a
   * file that takes the deployment down. One entry per rule the gateway has, each differing from a
   * loadable record in exactly one field, driven through both parsers.
   */
  const BEARER_FIELDS = `"id":"a","kind":"bearer","secretHash":"${'0'.repeat(64)}","scopes":["read"]`;
  const BEARER = `${BEARER_FIELDS},"createdAt":1772000000`;
  const REFUSED: Array<[string, string]> = [
    ['a pop record with no public key', '"id":"a","kind":"pop","scopes":["read"],"createdAt":1772000000'],
    ['a public key that is 31 bytes', `"id":"a","kind":"pop","publicKey":"${'A'.repeat(42)}","scopes":["read"],"createdAt":1772000000`],
    ['a padded public key', `"id":"a","kind":"pop","publicKey":"${'A'.repeat(43)}=","scopes":["read"],"createdAt":1772000000`],
    ['a public key that is not a string', `"id":"a","kind":"pop","publicKey":7,"scopes":["read"],"createdAt":1772000000`],
    ['a bearer record with no secret hash', '"id":"a","kind":"bearer","scopes":["read"],"createdAt":1772000000'],
    ['an upper-case secret hash', `"id":"a","kind":"bearer","secretHash":"${'0'.repeat(63)}A","scopes":["read"],"createdAt":1772000000`],
    ['a short secret hash', `"id":"a","kind":"bearer","secretHash":"${'0'.repeat(63)}","scopes":["read"],"createdAt":1772000000`],
    ['scopes that are not a list', `"id":"a","kind":"bearer","secretHash":"${'0'.repeat(64)}","scopes":"read","createdAt":1772000000`],
    ['an unknown scope', `"id":"a","kind":"bearer","secretHash":"${'0'.repeat(64)}","scopes":["read","export"],"createdAt":1772000000`],
    ['an id with a space in it', `"id":"a b","kind":"bearer","secretHash":"${'0'.repeat(64)}","scopes":["read"],"createdAt":1772000000`],
    ['a kind that is neither', `"id":"a","kind":"apikey","secretHash":"${'0'.repeat(64)}","scopes":["read"],"createdAt":1772000000`],
    ['a label that is a number', `${BEARER},"label":42`],
    ['a rate that is not an object', `${BEARER},"rate":"fast"`],
    ['a rate of zero', `${BEARER},"rate":{"perMinute":0,"burst":5}`],
    ['a rate with no burst', `${BEARER},"rate":{"perMinute":5}`],
    ['a createdAt that is a string', `${BEARER_FIELDS},"createdAt":"yesterday"`],
    ['a revokedAt that is a string', `${BEARER},"revokedAt":"tomorrow"`],
    ['a revokedAt that is not finite', `${BEARER},"revokedAt":1e999`],
  ];

  for (const [name, fields] of REFUSED) {
    it(`refuses ${name}, and the gateway refuses it too`, () => {
      const text = `{"version":1,"credentials":[{${fields}}]}\n`;
      const listed = runCli(['credential', 'list', '--credentials', freshFile(text)]);
      expect(listed.status).toBe(2);
      expect(listed.stdout).toBe('');
      expect(() => parseCredentialFile(text)).toThrow();
    });
  }

  it('accepts the loadable record every entry above differs from', () => {
    // Without this the table proves nothing: a typo that malformed every entry would leave eighteen
    // passing assertions and no control.
    const text = `{"version":1,"credentials":[{"id":"a","kind":"pop","publicKey":"${'A'.repeat(43)}","scopes":["read"],"createdAt":1772000000,"label":"a label","rate":{"perMinute":60,"burst":120}}]}\n`;
    const listed = runCli(['credential', 'list', '--credentials', freshFile(text)]);
    expect(listed.status).toBe(0);
    expect(listed.stdout).toContain('a label');
    expect(parseCredentialFile(text).credentials[0]).toMatchObject({ id: 'a', rate: { perMinute: 60, burst: 120 } });
  });
});
