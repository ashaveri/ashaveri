import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
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

  it('enrolls a public key the caller generated, without ever seeing a private one', () => {
    const path = freshFile();
    const generated = runCli(['keygen']);
    const publicKey = /publicKey:\s+([A-Za-z0-9_-]{43})/.exec(generated.stdout)?.[1];
    const result = runCli(addArgs(path, '--id', 'only-pub', '--public-key', publicKey as string));
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

  it('names the field of a record it cannot read, instead of crashing on it', () => {
    // Every other field of this record is valid, so the scopes check is the only thing that can
    // fire. A parsed record is typed as carrying scopes, which is what lets an unvalidated cast
    // reach `list` and die there with exit 1 and a stack trace: the same shape of surprise the
    // gateway would have had, moved one program earlier.
    const path = freshFile(
      `{"version":1,"credentials":[{"id":"no-scopes","kind":"bearer","secretHash":"${'0'.repeat(64)}","createdAt":1772000000}]}\n`,
    );
    const listed = runCli(['credential', 'list', '--credentials', path]);
    expect(listed.status).toBe(2);
    expect(listed.stderr).toContain('credentials[0].scopes must be a non-empty array of read and complete');
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
    expect(listed.stderr).toContain('credentials[0].revokedAt must be a number of whole seconds when present');
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
    const added = runCli(addArgs(path, '--id', 'e2e-pop', '--public-key', publicKey as string));
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
