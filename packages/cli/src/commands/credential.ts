import { randomBytes } from 'node:crypto';
import { fromBase64Url, generateSigningKey, toBase64Url, toHex } from '@ashaveri/receipt';
import {
  hashBearerSecret,
  readCredentialFile,
  writeCredentialFile,
  type CredentialFile,
  type CredentialRate,
  type CredentialRecord,
  type Scope,
} from '../records.js';
import { shortId } from './keygen.js';
import { UsageError } from '../usage.js';

/** The same id rule the gateway applies to every record in the file, stated here before a write. */
const CREDENTIAL_ID = /^[A-Za-z0-9_-]{1,64}$/u;
const PUBLIC_KEY_BYTES = 32;

const SUBCOMMANDS = ['add', 'revoke', 'list'] as const;

export interface CredentialFlags {
  credentials?: string;
  id?: string;
  kind?: string;
  scopes?: string;
  rate?: string;
  label?: string;
  'public-key'?: string;
  now?: string;
  json?: boolean;
}

export interface AddInput {
  credentials: string;
  id?: string;
  kind: 'pop' | 'bearer';
  scopes?: string;
  label?: string;
  rate?: string;
  publicKey?: string;
  now: () => number;
}

function parseKind(raw: string | undefined): 'pop' | 'bearer' {
  const kind = raw ?? 'pop';
  if (kind !== 'pop' && kind !== 'bearer') {
    throw new UsageError(`--kind must be pop or bearer, got '${kind}'`);
  }
  return kind;
}

function parseScopes(raw: string | undefined): Scope[] {
  const parts = (raw ?? 'read,complete')
    .split(',')
    .map((each) => each.trim())
    .filter((each) => each.length > 0);
  const out: Scope[] = [];
  for (const part of parts) {
    if (part !== 'read' && part !== 'complete') {
      throw new UsageError('--scopes must be a subset of read,complete');
    }
    if (!out.includes(part)) out.push(part);
  }
  if (out.length === 0) throw new UsageError('--scopes must name at least one scope');
  return out;
}

function parseRate(raw: string | undefined): CredentialRate | undefined {
  if (raw === undefined) return undefined;
  const match = /^perMinute=(\d+),burst=(\d+)$/u.exec(raw);
  if (match === null) throw new UsageError('--rate must look like perMinute=60,burst=120');
  const perMinute = Number(match[1]);
  const burst = Number(match[2]);
  // The gateway refuses a record whose rate is not a positive integer, which would take the whole
  // file down at its next start, so `perMinute=0` has to be caught here rather than stored.
  if (!Number.isSafeInteger(perMinute) || perMinute < 1 || !Number.isSafeInteger(burst) || burst < 1) {
    throw new UsageError('--rate perMinute and burst must be integers of at least 1');
  }
  return { perMinute, burst };
}

/**
 * One operator typo in a public key is not a local mistake: the gateway refuses a credential file
 * whose record will not parse, so a bad key here takes the deployment down at its next restart, and
 * a running gateway keeps serving on the file it loaded before until the edit is reverted. Decoding
 * with the same reader the gateway uses is the point, and the canonical re-encoding is what stops a
 * text whose trailing bits are set from naming a key that looks different than it verifies.
 */
function parsePublicKey(raw: string): string {
  let bytes: Uint8Array;
  try {
    bytes = fromBase64Url(raw);
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    throw new UsageError(`--public-key is not unpadded base64url: ${reason}`);
  }
  if (bytes.length !== PUBLIC_KEY_BYTES) {
    throw new UsageError(`--public-key decodes to ${bytes.length} bytes, not ${PUBLIC_KEY_BYTES}`);
  }
  return toBase64Url(bytes);
}

function checkId(id: string): string {
  if (!CREDENTIAL_ID.test(id)) {
    throw new UsageError(`--id '${id}' is outside [A-Za-z0-9_-]{1,64}`);
  }
  return id;
}

export interface AddResult {
  readonly record: CredentialRecord;
  /** The only moment the secret exists outside the caller's own memory. */
  readonly secret: { publicKey?: string; privateKeyHex?: string; bearerSecret?: string };
}

export async function credentialAdd(input: AddInput): Promise<AddResult> {
  const { kind } = input;
  const file = await readCredentialFile(input.credentials);
  const id = checkId(input.id ?? `${kind === 'pop' ? 'pop' : 'bearer'}-${shortId()}`);
  if (file.credentials.some((each) => each.id === id)) {
    throw new UsageError(`credential '${id}' already exists in ${input.credentials}`);
  }
  const scopes = parseScopes(input.scopes);
  const rate = parseRate(input.rate);
  if (input.publicKey !== undefined && kind !== 'pop') {
    throw new UsageError('--public-key belongs with --kind pop; a bearer credential stores a hash of a secret');
  }
  const createdAt = Math.floor(input.now() / 1000);
  const secret: { publicKey?: string; privateKeyHex?: string; bearerSecret?: string } = {};
  let publicKey: string | undefined;
  let secretHash: string | undefined;
  if (kind === 'bearer') {
    const bytes = randomBytes(32);
    secretHash = hashBearerSecret(bytes);
    secret.bearerSecret = toBase64Url(bytes);
  } else if (input.publicKey !== undefined) {
    publicKey = parsePublicKey(input.publicKey);
    secret.publicKey = publicKey;
  } else {
    const key = generateSigningKey();
    publicKey = toBase64Url(key.publicKey);
    secret.publicKey = publicKey;
    secret.privateKeyHex = toHex(key.privateKey);
  }
  const record: CredentialRecord = {
    id,
    kind,
    ...(publicKey === undefined ? {} : { publicKey }),
    ...(secretHash === undefined ? {} : { secretHash }),
    scopes,
    ...(input.label === undefined ? {} : { label: input.label }),
    ...(rate === undefined ? {} : { rate }),
    createdAt,
  };
  file.credentials.push(record);
  await writeCredentialFile(input.credentials, file);
  return { record, secret };
}

export async function credentialRevoke(path: string, id: string, now: () => number): Promise<CredentialRecord> {
  const file = await readCredentialFile(path);
  const record = file.credentials.find((each) => each.id === id);
  if (record === undefined) throw new UsageError(`no credential with id '${id}'`);
  if (record.revokedAt !== undefined) return record;
  record.revokedAt = Math.floor(now() / 1000);
  await writeCredentialFile(path, file);
  return record;
}

export async function credentialList(path: string): Promise<CredentialFile> {
  return readCredentialFile(path);
}

/**
 * What a listing may say, for both its output forms. The parsed record carries a public key and a
 * secret digest, and a digest base64url-encodes to the same shape as a bearer secret, so printing a
 * record is how the command that exists to avoid opening the file leaks exactly what it must not.
 * A label is here because it is the one field that can name a person, and the operator running this
 * is the person entitled to see it.
 */
export interface CredentialView {
  id: string;
  kind: string;
  scopes: string;
  label?: string;
  createdAt: number;
  revokedAt?: number;
}

function viewOf(record: CredentialRecord): CredentialView {
  return {
    id: record.id,
    kind: record.kind,
    scopes: record.scopes.join(','),
    ...(record.label === undefined ? {} : { label: record.label }),
    createdAt: record.createdAt,
    ...(record.revokedAt === undefined ? {} : { revokedAt: record.revokedAt }),
  };
}

export function credentialViews(file: CredentialFile): CredentialView[] {
  return file.credentials.map(viewOf);
}

function pad(value: string, width: number): string {
  return value.length > width ? value : `${value}${' '.repeat(width - value.length)}`;
}

function tableOf(views: CredentialView[]): string {
  const header = `${pad('ID', 24)}${pad('KIND', 8)}${pad('SCOPES', 16)}${pad('CREATED', 12)}${pad('REVOKED', 12)}LABEL`;
  const rows = views.map(
    (each) =>
      `${pad(each.id, 24)}${pad(each.kind, 8)}${pad(each.scopes, 16)}${pad(String(each.createdAt), 12)}${pad(each.revokedAt === undefined ? '' : String(each.revokedAt), 12)}${each.label ?? ''}`,
  );
  return `${[header, ...rows].join('\n')}\n`;
}

function print(label: string, value: string): void {
  process.stdout.write(`${label.padEnd(16)}${value}\n`);
}

function printRecord(record: CredentialRecord): void {
  print('id:', record.id);
  print('kind:', record.kind);
  print('scopes:', record.scopes.join(','));
  print('createdAt:', String(record.createdAt));
  if (record.label !== undefined) print('label:', record.label);
  if (record.rate !== undefined) print('rate:', `perMinute=${String(record.rate.perMinute)},burst=${String(record.rate.burst)}`);
}

async function runAdd(path: string, flags: CredentialFlags, now: () => number): Promise<number> {
  const { record, secret } = await credentialAdd({
    credentials: path,
    ...(flags.id === undefined ? {} : { id: flags.id }),
    kind: parseKind(flags.kind),
    ...(flags.scopes === undefined ? {} : { scopes: flags.scopes }),
    ...(flags.label === undefined ? {} : { label: flags.label }),
    ...(flags.rate === undefined ? {} : { rate: flags.rate }),
    ...(flags['public-key'] === undefined ? {} : { publicKey: flags['public-key'] }),
    now,
  });
  printRecord(record);
  if (secret.privateKeyHex !== undefined) {
    print('publicKey:', secret.publicKey ?? '');
    print('privateKeyHex:', secret.privateKeyHex);
    process.stdout.write(
      'The private key exists only in this terminal. Give it to the client as ASHAVERI_CREDENTIAL_SECRET and keep no copy here.\n',
    );
  } else if (secret.bearerSecret !== undefined) {
    print('secret:', secret.bearerSecret);
    process.stdout.write(
      'The secret exists only in this terminal, and it is the whole credential: a bearer-capable gateway has to be started with --allow-bearer.\n',
    );
  } else {
    print('publicKey:', secret.publicKey ?? '');
    process.stdout.write('stored the public key only; the private half never passed through this program.\n');
  }
  return 0;
}

async function runRevoke(path: string, flags: CredentialFlags, now: () => number): Promise<number> {
  const id = flags.id;
  if (id === undefined) throw new UsageError('credential revoke needs --id <id>');
  const record = await credentialRevoke(path, id, now);
  if (flags.json) {
    process.stdout.write(`${JSON.stringify(viewOf(record), null, 2)}\n`);
    return 0;
  }
  process.stdout.write(
    record.revokedAt === undefined
      ? `credential '${id}' is not revoked\n`
      : `revoked '${id}' at ${String(record.revokedAt)}; the gateway re-reads the file on its next request\n`,
  );
  return 0;
}

async function runList(path: string, flags: CredentialFlags): Promise<number> {
  const views = credentialViews(await credentialList(path));
  process.stdout.write(flags.json ? `${JSON.stringify(views, null, 2)}\n` : tableOf(views));
  return 0;
}

export async function runCredential(sub: string[], flags: CredentialFlags, now: () => number): Promise<number> {
  const name = sub[0];
  if (name !== 'add' && name !== 'revoke' && name !== 'list') {
    throw new UsageError(`expected a credential command: ${SUBCOMMANDS.join(', ')}`);
  }
  const path = flags.credentials;
  if (path === undefined) throw new UsageError(`credential ${name} needs --credentials <file>`);
  if (name === 'add') return runAdd(path, flags, now);
  if (name === 'revoke') return runRevoke(path, flags, now);
  return runList(path, flags);
}
