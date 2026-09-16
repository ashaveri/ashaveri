import { readFile } from 'node:fs/promises';
import { fromBase64Url, sha256Hex } from '@ashaveri/receipt';
import { writeAtomically } from './atomic.js';
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
 * is private, so an installed CLI cannot import its way out of this. Two cases in
 * `test/credential.test.ts` pin the number against the gateway's own exported copy from the inside
 * of behaviour rather than by comparing constants: a file of exactly this many records is refused
 * by `add`, and a file one record longer is refused by `list`. If the two numbers ever drift, one
 * of those two stops matching.
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
 * What `list` shows, what `add` compares a new id against, and what `revoke` finds a record by, plus
 * the fields that decide whether the file is loadable at all. This reader mirrors every rule the
 * gateway's `parseRecord` has, and the reason is measured rather than stylistic: `server.ts` reloads
 * this file ahead of admission and outside the request's own error handling, so a record that stops
 * parsing is a deployment answering 500 to every registered route, while a CLI that never checked
 * that field lists the file and reports a revocation as a success. A rule the gateway gains and this
 * reader does not is caught by the table in `test/credential.test.ts`, which drives a malformed
 * shape through both parsers and requires both to refuse it.
 *
 * Two places the wording differs on purpose. The gateway's messages are for a log line and this
 * program's are for an operator at a prompt, so the id rule is stated as a range instead of a code,
 * and a `revokedAt` here says "number of seconds" rather than "a number": the gateway's `asNumber`
 * takes `1.5` and `-0` without complaint, and a promise of whole seconds would be a rule neither
 * side enforces.
 */
const CREDENTIAL_ID = /^[A-Za-z0-9_-]{1,64}$/u;
const HEX32 = /^[0-9a-f]{64}$/u;
const PUBLIC_KEY_BYTES = 32;

/**
 * The gateway's id rule, stated once here because four commands repeat back an id they were handed:
 * `credential add` and `credential revoke` each name it in a sentence, `keygen` gives it a row of its
 * own, and `accesslog scrub` interpolates it into a count and into the marker it writes. An id
 * carrying a newline is a second line on the terminal that no record and no erasure occupies, and a
 * revocation is the line an operator keeps as evidence.
 */
export function checkId(value: string, flag: string): string {
  if (!CREDENTIAL_ID.test(value)) {
    throw new UsageError(`${flag} '${value}' is outside [A-Za-z0-9_-]{1,64}`);
  }
  return value;
}

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
  // An empty scope list is loadable and means manifest-only: `scopeSatisfied` grants an `any` route
  // to every credential and refuses `read` here, so this record can reach exactly one endpoint. The
  // gateway reads it, so this reader has to, or the CLI cannot revoke a credential it cannot list.
  const scopes = record['scopes'];
  if (!Array.isArray(scopes) || !scopes.every((each) => each === 'read' || each === 'complete')) {
    throw new UsageError(`${where}.scopes must be an array of read and complete`);
  }
  if (kind === 'pop') {
    const key = record['publicKey'];
    if (typeof key !== 'string') {
      throw new UsageError(`${where}.publicKey is not a string`);
    }
    // Decoded with the gateway's own reader, so a text it refuses is refused here for the same
    // reason: the alphabet, the padding, and a length that stands for no byte at all. What neither
    // side checks is the trailing bits of a final character, so a key stored in that form loads on
    // both and is canonical only when this program writes it.
    let bytes: Uint8Array;
    try {
      bytes = fromBase64Url(key);
    } catch (err) {
      throw new UsageError(`${where}.publicKey is not base64url: ${err instanceof Error ? err.message : String(err)}`);
    }
    if (bytes.length !== PUBLIC_KEY_BYTES) {
      throw new UsageError(`${where}.publicKey is ${String(bytes.length)} bytes, not ${String(PUBLIC_KEY_BYTES)}`);
    }
  } else {
    const hash = record['secretHash'];
    if (typeof hash !== 'string') {
      throw new UsageError(`${where}.secretHash is not a string`);
    }
    if (!HEX32.test(hash)) {
      throw new UsageError(`${where}.secretHash is not 64 hex characters`);
    }
  }
  const createdAt = record['createdAt'];
  if (typeof createdAt !== 'number' || !Number.isFinite(createdAt)) {
    throw new UsageError(`${where}.createdAt must be a number of seconds`);
  }
  const revokedAt = record['revokedAt'];
  if (revokedAt !== undefined && (typeof revokedAt !== 'number' || !Number.isFinite(revokedAt))) {
    throw new UsageError(`${where}.revokedAt must be a number of seconds when present`);
  }
  // `list` prints this field and `add` echoes it, which is what makes it a field this program makes
  // a promise about: a number there prints as itself and an array prints as its joined elements, so
  // the row describes a value the file does not hold.
  const label = record['label'];
  if (label !== undefined && typeof label !== 'string') {
    throw new UsageError(`${where}.label must be a string when present`);
  }
  const rate = record['rate'];
  if (rate !== undefined) {
    if (typeof rate !== 'object' || rate === null) {
      throw new UsageError(`${where}.rate must be an object of perMinute and burst`);
    }
    const { perMinute, burst } = rate as { perMinute?: unknown; burst?: unknown };
    for (const [name, limit] of [['perMinute', perMinute], ['burst', burst]] as const) {
      if (typeof limit !== 'number' || !Number.isInteger(limit) || limit < 1) {
        throw new UsageError(`${where}.rate.${name} must be an integer of at least 1`);
      }
    }
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
  // The ceiling used to live only on the write path, which left `list` printing a table of records
  // over a file no gateway will load and `revoke` reporting success against it. Checked here, before
  // a row is built, because the refusal is about the whole file and not about a record in it.
  if (raw.credentials.length > MAX_CREDENTIALS) {
    throw new UsageError(
      `${path} holds ${String(raw.credentials.length)} records, which exceeds the ${String(MAX_CREDENTIALS)} a gateway will scan per request`,
    );
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
 * Same directory, temporary name, rename. The gateway reloads this file when its mtime moves, and
 * the reload runs ahead of admission and outside the request's own error handling, so a reader that
 * catches a half-written file is a deployment answering 500 on every registered route until a whole
 * one replaces it. That window is what the rename closes, and it closes it without a restart.
 *
 * The mode is `0600` because the file holds a secret hash and a public key, and a directory that will
 * not take the write answers with the one-line refusal every other fixable failure gets, not with a
 * stack trace over the operator's path.
 */
export async function writeCredentialFile(path: string, file: CredentialFile): Promise<void> {
  await writeAtomically(path, `${JSON.stringify(file, null, 2)}\n`, 0o600, 'cannot write the credential file');
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
