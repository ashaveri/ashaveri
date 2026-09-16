import { chmod, readFile, rename, writeFile } from 'node:fs/promises';
import { sha256Hex } from '@ashaveri/receipt';
import { UsageError } from './usage.js';

export type Scope = 'read' | 'complete';

export interface CredentialRate {
  perMinute: number;
  burst: number;
}

/**
 * The published copy of the gateway's credential record. It is a second declaration of the same
 * shape on purpose: `@ashaveri/signerd` is a private package and an installed CLI cannot depend on
 * it, so the alternative to copying the shape here is an installed CLI that writes credentials
 * nobody has checked it can read. `test/credential.test.ts` reads a file this writer produced back
 * through the gateway's own parser and admits a request against it, which is what keeps the two
 * honest. The text fields are the wire forms: an unpadded base64url public key and a lowercase hex
 * digest, because a `Uint8Array` has no JSON representation worth trusting.
 */
export interface CredentialRecord {
  id: string;
  kind: 'pop' | 'bearer';
  publicKey?: string;
  secretHash?: string;
  scopes: Scope[];
  label?: string;
  rate?: CredentialRate;
  createdAt: number;
  revokedAt?: number;
}

export interface CredentialFile {
  version: number;
  credentials: CredentialRecord[];
}

export const CREDENTIALS_FILE_VERSION = 1;

/**
 * Re-declared from `@ashaveri/signerd` for the same reason the record shape is: the gateway package
 * is private, so an installed CLI cannot import its way out of this. `test/credential.test.ts`
 * asserts the two numbers still agree.
 */
export const MAX_CREDENTIALS = 10_000;

/**
 * The gateway refuses a credential file it cannot parse as a whole, so a caller that meant to add
 * one record would otherwise be the reason nothing loads. A missing file is the empty case rather
 * than an error, because `credential add` on a fresh deployment is the first write.
 */
export async function readCredentialFile(path: string): Promise<CredentialFile> {
  let text: string;
  try {
    text = await readFile(path, 'utf8');
  } catch (err) {
    if (err instanceof Error && 'code' in err && err.code === 'ENOENT') {
      return { version: CREDENTIALS_FILE_VERSION, credentials: [] };
    }
    throw new UsageError(`cannot read ${path}: ${err instanceof Error ? err.message : String(err)}`);
  }
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new UsageError(`${path} is not valid JSON; refusing to rewrite a file this program cannot read`);
  }
  return normalizeFile(value, path);
}

/**
 * What `list` shows, what `add` compares a new id against, and what `revoke` finds a record by: the
 * five fields this program reads, and the id it reads all of them by. This is not a second copy of
 * the gateway's validator, and it does not try to be one. A rate, a label or a key this program
 * never reads travels through a rewrite untouched, so `test/credential.test.ts` reads a file it
 * wrote back through the gateway's parser.
 *
 * A field this program does read is a different case. `list` prints `revokedAt` and `revoke` finds a
 * record by `id`, so a string date or a repeated id is the CLI printing a revocation over a file the
 * gateway will not load: `"revokedAt": "tomorrow"` is a row that reads as a date, and the promise
 * after it is a write that changes nothing. Those two checks are here because this program is the
 * thing that made the promise.
 */
const CREDENTIAL_ID = /^[A-Za-z0-9_-]{1,64}$/u;

function checkedRecord(value: unknown, where: string): CredentialRecord {
  const record = typeof value === 'object' && value !== null ? (value as Record<string, unknown>) : {};
  const id = record['id'];
  if (typeof id !== 'string' || !CREDENTIAL_ID.test(id)) {
    throw new UsageError(`${where}.id must be 1 to 64 characters of [A-Za-z0-9_-]`);
  }
  const kind = record['kind'];
  if (kind !== 'pop' && kind !== 'bearer') {
    throw new UsageError(`${where}.kind must be pop or bearer`);
  }
  const scopes = record['scopes'];
  if (!Array.isArray(scopes) || scopes.length === 0 || !scopes.every((each) => each === 'read' || each === 'complete')) {
    throw new UsageError(`${where}.scopes must be a non-empty array of read and complete`);
  }
  const createdAt = record['createdAt'];
  if (typeof createdAt !== 'number' || !Number.isFinite(createdAt)) {
    throw new UsageError(`${where}.createdAt must be a number of whole seconds`);
  }
  const revokedAt = record['revokedAt'];
  if (revokedAt !== undefined && (typeof revokedAt !== 'number' || !Number.isFinite(revokedAt))) {
    throw new UsageError(`${where}.revokedAt must be a number of whole seconds when present`);
  }
  return value as CredentialRecord;
}

function normalizeFile(value: unknown, path: string): CredentialFile {
  if (typeof value !== 'object' || value === null || !Array.isArray((value as { credentials?: unknown }).credentials)) {
    throw new UsageError(`${path} is not a credential file: expected {"version":1,"credentials":[...]}`);
  }
  const raw = value as { version?: unknown; credentials: unknown[] };
  if (raw.version !== CREDENTIALS_FILE_VERSION) {
    throw new UsageError(`${path} has version ${String(raw.version)}, this build writes ${String(CREDENTIALS_FILE_VERSION)}`);
  }
  const credentials = raw.credentials.map((each, index) =>
    checkedRecord(each, `credentials[${String(index)}]`),
  );
  const seen = new Set<string>();
  for (const each of credentials) {
    // `revoke` finds a record with `find`, so without this a repeated id is a command that revokes
    // one of them, reports success, and leaves the other signing requests.
    if (seen.has(each.id)) {
      throw new UsageError(`${path} lists '${each.id}' twice; the gateway refuses a file with a duplicate id`);
    }
    seen.add(each.id);
  }
  return { version: CREDENTIALS_FILE_VERSION, credentials };
}

/**
 * Same directory, temporary name, rename. A reader that never sees a half-written file is the whole
 * point: the gateway re-reads this file when its mtime moves, and a record torn in half is a
 * deployment that has forgotten its credentials until the next restart.
 */
export async function writeCredentialFile(path: string, file: CredentialFile): Promise<void> {
  const tmp = `${path}.tmp-${String(process.pid)}`;
  await writeFile(tmp, `${JSON.stringify(file, null, 2)}\n`, { mode: 0o600 });
  // `writeFile`'s `mode` is skipped when the file already exists, which a retried write or an
  // operator's leftover temporary name can do, so the permission is set again rather than trusted.
  await chmod(tmp, 0o600);
  await rename(tmp, path);
}

/**
 * A bearer secret is 32 generated random bytes, so a plain SHA-256 is the right thing to store: a
 * slow KDF earns nothing against 256 bits of entropy. The gateway hashes the bytes its decoder gets
 * back from the base64url text it was handed, so this digest is of the same bytes and not of the
 * characters that spell them out.
 */
export function hashBearerSecret(secret: Uint8Array): string {
  return sha256Hex(secret);
}
