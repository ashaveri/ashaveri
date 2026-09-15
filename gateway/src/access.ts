import { readFile } from 'node:fs/promises';
import { randomBytes, randomUUID } from 'node:crypto';
import { fromBase64Url, signingKeyFromSeed, toBase64Url } from '@ashaveri/receipt';
import { fromHex, sha256, toHex } from './digest.js';

/**
 * Who may ask the gateway for what. A credential file lists the identities the gateway knows,
 * the scopes each one carries and the rate each one is held to; the route table says what each
 * registered route requires. Everything here is parsing and lookup material: it turns bytes on
 * disk into records and refuses, with a code and an HTTP status, whatever it cannot use.
 */

export type AccessErrorCode =
  | 'BAD_CREDENTIAL_FILE'
  | 'BAD_CREDENTIAL_RECORD'
  | 'DUPLICATE_CREDENTIAL_ID'
  | 'AUTH_MALFORMED'
  | 'AUTH_SCHEME'
  | 'AUTH_UNKNOWN'
  | 'AUTH_REVOKED'
  | 'AUTH_STALE'
  | 'AUTH_SIGNATURE'
  | 'NONCE_SEEN'
  | 'SCOPE_DENIED'
  | 'RATE_LIMITED';

const ERROR_STATUS: Record<AccessErrorCode, number> = {
  BAD_CREDENTIAL_FILE: 500,
  BAD_CREDENTIAL_RECORD: 500,
  DUPLICATE_CREDENTIAL_ID: 500,
  AUTH_MALFORMED: 401,
  AUTH_SCHEME: 401,
  AUTH_UNKNOWN: 401,
  AUTH_REVOKED: 401,
  AUTH_STALE: 401,
  AUTH_SIGNATURE: 401,
  NONCE_SEEN: 409,
  SCOPE_DENIED: 403,
  RATE_LIMITED: 429,
};

const ERROR_MESSAGE: Record<AccessErrorCode, string> = {
  BAD_CREDENTIAL_FILE: 'the credential file cannot be used',
  BAD_CREDENTIAL_RECORD: 'a credential record is malformed',
  DUPLICATE_CREDENTIAL_ID: 'two credential records share an id',
  AUTH_MALFORMED: 'the Authorization header could not be read',
  AUTH_SCHEME: 'the Authorization header uses an unsupported scheme',
  AUTH_UNKNOWN: 'no credential matches the Authorization header',
  AUTH_REVOKED: 'the credential has been revoked',
  AUTH_STALE: 'the request timestamp is outside the accepted window',
  AUTH_SIGNATURE: 'the proof of possession signature did not verify',
  NONCE_SEEN: 'this request nonce has already been presented',
  SCOPE_DENIED: 'the credential does not carry the scope this route requires',
  RATE_LIMITED: 'this credential is over its rate limit',
};

/**
 * The status each refusal answers with, so whatever writes the response reads the same mapping
 * the error was built from and the two cannot drift. A header this gateway cannot match to a
 * usable credential is a 401, because retrying a different route changes nothing; a credential
 * that is valid but lacks the scope the route asks for is a 403; a replayed nonce is a 409,
 * which the client clears by sending a fresh request; a rate limit is a 429 that pairs with
 * `retryAfterSeconds`. The credential-file codes are 500s: the file the operator installed is
 * what is broken, and no header a client sends can fix it.
 */
export function accessStatus(code: AccessErrorCode): number {
  return ERROR_STATUS[code];
}

export class AccessError extends Error {
  readonly code: AccessErrorCode;
  readonly status: number;
  readonly retryAfterSeconds: number | undefined;

  constructor(code: AccessErrorCode, detail?: string, retryAfterSeconds?: number) {
    super(detail === undefined ? ERROR_MESSAGE[code] : `${ERROR_MESSAGE[code]}: ${detail}`);
    this.name = 'AccessError';
    this.code = code;
    this.status = accessStatus(code);
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

export type Scope = 'read' | 'complete';
const SCOPES: readonly Scope[] = ['read', 'complete'];

export interface CredentialRate {
  perMinute: number;
  burst: number;
}

export interface CredentialRecord {
  id: string;
  kind: 'pop' | 'bearer';
  publicKey?: Uint8Array;
  secretHash?: Uint8Array;
  scopes: Scope[];
  label?: string;
  rate?: CredentialRate;
  createdAt: number;
  revokedAt?: number;
}

export interface CredentialFile {
  version: 1;
  credentials: CredentialRecord[];
}

export const CREDENTIALS_FILE_VERSION = 1;
export const MAX_CREDENTIALS = 10_000;
const CREDENTIAL_ID = /^[A-Za-z0-9_-]{1,64}$/u;
const ED25519_PUBLIC_KEY_BYTES = 32;
const HEX32 = /^[0-9a-f]{64}$/u;

function refuse(code: AccessErrorCode, detail: string): never {
  throw new AccessError(code, detail);
}

/** What went wrong, in one clause, without assuming the thrown value is an Error. */
function reason(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function isJsonObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function asRecord(value: unknown, where: string, code: AccessErrorCode): Record<string, unknown> {
  if (!isJsonObject(value)) {
    refuse(code, `${where} is not an object`);
  }
  return value;
}

function asString(value: unknown, field: string): string {
  if (typeof value !== 'string') refuse('BAD_CREDENTIAL_RECORD', `${field} is not a string`);
  return value;
}

function asNumber(value: unknown, field: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    refuse('BAD_CREDENTIAL_RECORD', `${field} is not a number`);
  }
  return value;
}

function isScope(value: string): value is Scope {
  return SCOPES.some((scope) => scope === value);
}

function parseScopes(value: unknown, where: string): Scope[] {
  if (!Array.isArray(value)) refuse('BAD_CREDENTIAL_RECORD', `${where}.scopes is not a list`);
  return value.map((entry, at) => {
    const text = asString(entry, `${where}.scopes[${at}]`);
    if (!isScope(text)) {
      refuse('BAD_CREDENTIAL_RECORD', `${where} has unknown scope '${text}'`);
    }
    return text;
  });
}

/**
 * The public key is stored in the same unpadded base64url the proof of possession uses, and the
 * decoded bytes are what a signature is checked against: two texts can decode to the same bytes,
 * so the width rule is stated about the bytes and not about the characters.
 */
function parseKeyField(value: unknown, field: string, width: number): Uint8Array {
  const text = asString(value, field);
  let bytes: Uint8Array;
  try {
    bytes = fromBase64Url(text, 'BAD_POP_HEADER');
  } catch (err) {
    refuse('BAD_CREDENTIAL_RECORD', `${field} is not base64url: ${reason(err)}`);
  }
  if (bytes.length !== width) {
    refuse('BAD_CREDENTIAL_RECORD', `${field} is ${bytes.length} bytes, not ${width}`);
  }
  return bytes;
}

function parseRate(value: unknown, where: string): CredentialRate {
  const raw = asRecord(value, `${where}.rate`, 'BAD_CREDENTIAL_RECORD');
  const perMinute = asNumber(raw['perMinute'], `${where}.rate.perMinute`);
  const burst = asNumber(raw['burst'], `${where}.rate.burst`);
  if (!Number.isInteger(perMinute) || perMinute < 1) {
    refuse('BAD_CREDENTIAL_RECORD', `${where}.rate.perMinute must be an integer of at least 1`);
  }
  if (!Number.isInteger(burst) || burst < 1) {
    refuse('BAD_CREDENTIAL_RECORD', `${where}.rate.burst must be an integer of at least 1`);
  }
  return { perMinute, burst };
}

function parseRecord(value: unknown, index: number): CredentialRecord {
  const where = `credentials[${index}]`;
  const raw = asRecord(value, where, 'BAD_CREDENTIAL_RECORD');

  const id = asString(raw['id'], `${where}.id`);
  if (!CREDENTIAL_ID.test(id)) {
    refuse('BAD_CREDENTIAL_RECORD', `${where}.id '${id}' is outside [A-Za-z0-9_-]{1,64}`);
  }

  const kind = asString(raw['kind'], `${where}.kind`);
  if (kind !== 'pop' && kind !== 'bearer') {
    refuse('BAD_CREDENTIAL_RECORD', `${where}.kind '${kind}' is not pop or bearer`);
  }

  const scopes = parseScopes(raw['scopes'], where);
  const createdAt = asNumber(raw['createdAt'], `${where}.createdAt`);
  const record: CredentialRecord = { id, kind, scopes, createdAt };
  if (kind === 'pop') {
    record.publicKey = parseKeyField(raw['publicKey'], `${where}.publicKey`, ED25519_PUBLIC_KEY_BYTES);
  } else {
    const hash = asString(raw['secretHash'], `${where}.secretHash`);
    if (!HEX32.test(hash)) {
      refuse('BAD_CREDENTIAL_RECORD', `${where}.secretHash is not 64 hex characters`);
    }
    record.secretHash = fromHex(hash);
  }

  const label = raw['label'];
  if (label !== undefined) record.label = asString(label, `${where}.label`);
  const revokedAt = raw['revokedAt'];
  if (revokedAt !== undefined) record.revokedAt = asNumber(revokedAt, `${where}.revokedAt`);
  const rate = raw['rate'];
  if (rate !== undefined) record.rate = parseRate(rate, where);
  return record;
}

export function parseCredentialFile(text: string): CredentialFile {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch (err) {
    refuse('BAD_CREDENTIAL_FILE', `not JSON: ${reason(err)}`);
  }
  const raw = asRecord(value, 'credential file', 'BAD_CREDENTIAL_FILE');
  if (raw['version'] !== CREDENTIALS_FILE_VERSION) {
    refuse('BAD_CREDENTIAL_FILE', `version ${String(raw['version'])}, this gateway writes ${CREDENTIALS_FILE_VERSION}`);
  }
  const list = raw['credentials'];
  if (!Array.isArray(list)) refuse('BAD_CREDENTIAL_FILE', 'credentials is not a list');
  if (list.length > MAX_CREDENTIALS) {
    refuse(
      'BAD_CREDENTIAL_FILE',
      `${list.length} records exceeds the ${MAX_CREDENTIALS} this gateway will scan per request`,
    );
  }
  const seen = new Set<string>();
  const credentials = list.map((entry, index) => {
    const record = parseRecord(entry, index);
    if (seen.has(record.id)) refuse('DUPLICATE_CREDENTIAL_ID', record.id);
    seen.add(record.id);
    return record;
  });
  return { version: CREDENTIALS_FILE_VERSION, credentials };
}

/**
 * A bearer secret is 32 generated random bytes, so a plain SHA-256 is the right store: a slow KDF
 * earns nothing when the input already has 256 bits of entropy, and this file is read once per
 * request rather than brute-forced offline against a human password.
 */
function hashSecret(secret: Uint8Array): Uint8Array {
  return sha256(secret);
}

export function serializeCredentialFile(file: CredentialFile): string {
  const body = {
    version: CREDENTIALS_FILE_VERSION,
    credentials: file.credentials.map((record) => ({
      id: record.id,
      kind: record.kind,
      ...(record.kind === 'pop' ? { publicKey: toBase64Url(record.publicKey ?? new Uint8Array(0)) } : {}),
      ...(record.kind === 'bearer' ? { secretHash: toHex(record.secretHash ?? new Uint8Array(0)) } : {}),
      scopes: [...record.scopes],
      ...(record.label === undefined ? {} : { label: record.label }),
      ...(record.rate === undefined ? {} : { rate: { perMinute: record.rate.perMinute, burst: record.rate.burst } }),
      createdAt: record.createdAt,
      ...(record.revokedAt === undefined ? {} : { revokedAt: record.revokedAt }),
    })),
  };
  return `${JSON.stringify(body, null, 2)}\n`;
}

export async function loadCredentialFile(path: string): Promise<CredentialFile> {
  let text: string;
  try {
    text = await readFile(path, 'utf8');
  } catch (err) {
    refuse('BAD_CREDENTIAL_FILE', `${path} could not be read: ${reason(err)}`);
  }
  try {
    return parseCredentialFile(text);
  } catch (err) {
    if (err instanceof AccessError) {
      throw new AccessError(err.code, `${path}: ${err.message}`);
    }
    throw err;
  }
}

function credentialId(prefix: string, id: string | undefined): string {
  return id ?? `${prefix}-${randomUUID().slice(0, 8)}`;
}

export function newPopCredential(input: {
  id?: string;
  label?: string;
  scopes?: Scope[];
  now?: number;
}): { record: CredentialRecord; privateKey: Uint8Array } {
  const key = signingKeyFromSeed(randomBytes(32));
  const record: CredentialRecord = {
    id: credentialId('pop', input.id),
    kind: 'pop',
    publicKey: key.publicKey,
    scopes: input.scopes ?? ['read', 'complete'],
    ...(input.label === undefined ? {} : { label: input.label }),
    createdAt: input.now ?? Math.floor(Date.now() / 1000),
  };
  return { record, privateKey: key.privateKey };
}

export function newBearerCredential(input: {
  id?: string;
  label?: string;
  scopes?: Scope[];
  now?: number;
}): { record: CredentialRecord; secret: Uint8Array } {
  const secret = randomBytes(32);
  const record: CredentialRecord = {
    id: credentialId('bearer', input.id),
    kind: 'bearer',
    secretHash: hashSecret(secret),
    scopes: input.scopes ?? ['read', 'complete'],
    ...(input.label === undefined ? {} : { label: input.label }),
    createdAt: input.now ?? Math.floor(Date.now() / 1000),
  };
  return { record, secret };
}

export type RouteScope = 'any' | 'read' | 'complete';

/**
 * Every route the gateway registers, and the least scope it accepts. A route that appears here but
 * not on the server costs nothing, and a route on the server but not here has no scope to check,
 * which the caller reports as a refusal rather than inventing one.
 */
export const ROUTE_SCOPES: Record<string, RouteScope> = {
  'GET /v1/deployment-manifest': 'any',
  'GET /v1/attestation': 'read',
  'GET /v1/attestation/gpu': 'read',
  'GET /v1/receipts/:id': 'read',
  'POST /v1/chat/completions': 'complete',
};

const RECEIPT_ID = /^[A-Za-z0-9_-]{1,64}$/u;

function matchesPath(pattern: string, path: string): boolean {
  const want = pattern.split('/');
  const have = path.split('/');
  if (want.length !== have.length) return false;
  return want.every((segment, index) => {
    if (!segment.startsWith(':')) return segment === have[index];
    if (segment === ':id') return RECEIPT_ID.test(have[index] ?? '');
    return (have[index] ?? '').length > 0;
  });
}

/**
 * HEAD is GET without a body, and Fastify answers it on every GET route, so it has to normalize
 * rather than appear unlisted. An unknown route returns undefined, which the caller reports as a
 * missing table row instead of inventing a scope.
 */
export function routeScope(method: string, url: string): RouteScope | undefined {
  const path = url.split('?', 1)[0] ?? url;
  const normalized = method === 'HEAD' ? 'GET' : method.toUpperCase();
  for (const [route, scope] of Object.entries(ROUTE_SCOPES)) {
    const [routeMethod, pattern] = route.split(' ');
    if (routeMethod !== normalized || pattern === undefined) continue;
    if (matchesPath(pattern, path)) return scope;
  }
  return undefined;
}

/** `read` on a route means either scope; the route table's one-way door. */
export function scopeSatisfied(granted: readonly Scope[], required: RouteScope): boolean {
  if (required === 'any') return true;
  if (required === 'complete') return granted.includes('complete');
  return granted.includes('read') || granted.includes('complete');
}
