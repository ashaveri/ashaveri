import { readFile, stat } from 'node:fs/promises';
import { randomBytes, randomUUID } from 'node:crypto';
import {
  EMPTY_BODY_SHA256_HEX,
  fromBase64Url,
  parsePopAuthorization,
  POP_NONCE_BYTES,
  POP_TIMESTAMP_TOLERANCE_SECONDS,
  ReceiptError,
  sha256Hex,
  signingKeyFromSeed,
  toBase64Url,
  verifyPopSignature,
  type PopAuthorization,
  type PopFields,
} from '@ashaveri/receipt';
import { fromHex, sha256, toHex } from './digest.js';

/**
 * Who may ask the gateway for what. A credential file lists the identities the gateway knows,
 * the scopes each one carries and the rate each one is held to; the route table says what each
 * registered route requires. Parsing, lookup and the admission decision therefore live in one
 * file: it turns bytes on disk into records, answers whether a request may be served from them,
 * and refuses with a code and an HTTP status whatever it cannot use.
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
  | 'AUTH_NONCE_MISSING'
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
  AUTH_NONCE_MISSING: 401,
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
  AUTH_NONCE_MISSING: 'the x-ashaveri-nonce header is absent or is not unpadded base64url of a 16-byte nonce',
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
  /**
   * Which credential this refusal is about, when the pipeline knew. The access record wants a
   * name and a message is not a place to read one from: prose is rewritten for the reader's
   * benefit, while this field is the string the store was asked about.
   */
  readonly credentialId: string | undefined;

  constructor(code: AccessErrorCode, detail?: string, retryAfterSeconds?: number, credentialId?: string) {
    super(detail === undefined ? ERROR_MESSAGE[code] : `${ERROR_MESSAGE[code]}: ${detail}`);
    this.name = 'AccessError';
    this.code = code;
    this.status = accessStatus(code);
    this.retryAfterSeconds = retryAfterSeconds;
    this.credentialId = credentialId;
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

/**
 * Thrown at registration, not at request time: a route nobody put in the table is a
 * route with no scope decision, and the only safe moment to find that out is before
 * the process can serve it.
 */
export class UndeclaredRouteError extends Error {
  constructor(route: string) {
    super(`ROUTE_UNDECLARED: ${route} has no row in the scope table, so it could not be admitted or refused`);
    this.name = 'UndeclaredRouteError';
  }
}

/**
 * The registration-time form of the lookup. A route is declared with a pattern, and a pattern is not
 * a request: `matchesPath` reads `:id` as a value slot, so the receipt route's own URL fails the
 * receipt-id rule it is there to enforce, and matching the table's rows against the table alone would
 * stop the process from booting. Naming the row is therefore tried first, and the request-shaped
 * match is left for a route whose URL is a literal the pipeline can still classify.
 */
export function requireRouteScope(method: string, url: string): RouteScope {
  const normalized = method === 'HEAD' ? 'GET' : method.toUpperCase();
  const scope = ROUTE_SCOPES[`${normalized} ${url}`] ?? routeScope(method, url);
  if (scope === undefined) throw new UndeclaredRouteError(`${method} ${url}`);
  return scope;
}

export const REPLAY_WINDOW_SECONDS = 900;
const REPLAY_MAX_ENTRIES = 65_536;
const SHA256_BYTES = 32;
const BEARER_PREFIX = 'Bearer ';

/** What a record without its own `rate` is held to. */
export const DEFAULT_RATE: CredentialRate = { perMinute: 60, burst: 120 };

/**
 * The replay key is the canonical encoding of the *decoded* nonce rather than the header text that
 * carried it: base64url ignores the unused bits of its last character, so two different texts can
 * decode to one nonce, and a set keyed on the text would let an attacker replay a signature under a
 * mutated header. A credential id is restricted to `[A-Za-z0-9_-]` and the base64url alphabet
 * contains no colon, so one key can never stand for two credentials.
 */
function nonceKey(credentialId: string, nonce: Uint8Array): string {
  return `${credentialId}:${toBase64Url(nonce)}`;
}

/**
 * Insertion-ordered expiry map, swept on insert and capped, so memory is fixed whatever the
 * traffic: an attacker who replays faster than the window drains cannot grow this set. The same
 * shape as the evidence cache in dstack.ts, for the same reason.
 */
export class ReplaySet {
  private readonly seen = new Map<string, number>();

  constructor(
    private readonly windowSeconds: number = REPLAY_WINDOW_SECONDS,
    private readonly maxEntries: number = REPLAY_MAX_ENTRIES,
    private readonly now: () => number = () => Date.now(),
  ) {}

  /** True when this key was already presented inside the window. */
  see(key: string): boolean {
    const at = this.now();
    const expiry = this.seen.get(key);
    if (expiry !== undefined) {
      if (expiry > at) return true;
      this.seen.delete(key);
    }
    this.seen.set(key, at + this.windowSeconds * 1000);
    if (this.seen.size > this.maxEntries) {
      // The oldest insertion is first in iteration order, so this drops the entries closest to
      // expiring rather than a random sample.
      const excess = this.seen.size - this.maxEntries;
      let dropped = 0;
      for (const entry of this.seen.keys()) {
        if (dropped >= excess) break;
        this.seen.delete(entry);
        dropped += 1;
      }
    }
    return false;
  }

  get size(): number {
    return this.seen.size;
  }
}

interface Bucket {
  tokens: number;
  updatedMs: number;
}

/**
 * Deliberately hand-rolled rather than a plugin: a new package in a measured container changes the
 * launch measurement, and the plugin's configuration surface is larger than the forty lines below.
 * Keyed per credential, refilled at perMinute/60 tokens per second, capped at burst.
 */
export class TokenBucket {
  private readonly buckets = new Map<string, Bucket>();

  take(key: string, rate: CredentialRate, nowMs: number = Date.now()): { allowed: boolean; retryAfterSeconds: number } {
    const bucket = this.buckets.get(key);
    const refillPerMs = rate.perMinute / 60_000;
    if (bucket === undefined) {
      this.buckets.set(key, { tokens: rate.burst - 1, updatedMs: nowMs });
      return { allowed: true, retryAfterSeconds: 0 };
    }
    // A clock that steps backwards would otherwise refill by a negative amount and spend tokens
    // nobody took, so the elapsed time is floored at nothing before it becomes tokens.
    const gained = Math.max(0, (nowMs - bucket.updatedMs) * refillPerMs);
    const refilled = Math.min(rate.burst, bucket.tokens + gained);
    if (refilled < 1) {
      bucket.tokens = refilled;
      bucket.updatedMs = nowMs;
      // A whole second, and never zero: a hint the client cannot act on invites it to retry
      // immediately, which is the traffic this is meant to hold back. A rate that never refills has
      // no finite answer, and this number is destined for a `Retry-After` header, so it is a number
      // even then.
      const waitMs = refillPerMs > 0 ? (1 - refilled) / refillPerMs : Number.MAX_SAFE_INTEGER;
      return { allowed: false, retryAfterSeconds: Math.max(1, Math.ceil(waitMs / 1000)) };
    }
    bucket.tokens = refilled - 1;
    bucket.updatedMs = nowMs;
    return { allowed: true, retryAfterSeconds: 0 };
  }
}

export interface AdmissionInput {
  method: string;
  url: string;
  headers: Record<string, string | string[] | undefined>;
  body: Uint8Array | null;
  /** Seconds since the epoch the request is stamped with; this clock's own second when absent. */
  nowSeconds?: number;
}

export interface Admission {
  credentialId: string;
  scope: RouteScope;
  auth: 'pop' | 'bearer';
  nonce: Uint8Array | null;
  /** The artifact this target names, for the one route that names one; `null` otherwise. */
  receiptId: string | null;
}

export interface CredentialStoreOptions {
  /** Read from disk, and re-read when the file's mtime moves. */
  path?: string;
  /** In-memory file, for tests and for --mock. Mutually exclusive with path. */
  file?: CredentialFile;
  allowBearer?: boolean;
  toleranceSeconds?: number;
  /** Milliseconds since the epoch: one clock for the tolerance, the replay window and the buckets. */
  now?: () => number;
}

function firstHeader(headers: AdmissionInput['headers'], name: string): string | undefined {
  const raw = headers[name];
  if (Array.isArray(raw)) return raw[0];
  return raw;
}

/** The secret a `Bearer` header carries, or nothing when the header is not one. */
function bearerSecret(header: string): string | undefined {
  if (!header.startsWith(BEARER_PREFIX)) return undefined;
  const secret = header.slice(BEARER_PREFIX.length).trim();
  return secret.length === 0 ? undefined : secret;
}

/** A bodyless request signs the empty byte string, whose digest is a published constant. */
function bodyDigest(body: Uint8Array | null): string {
  if (body === null || body.length === 0) return EMPTY_BODY_SHA256_HEX;
  return sha256Hex(body);
}

/** `/v1/receipts/<id>` is the only route whose path names an artifact, so it is the only receipt id admission reports. */
function receiptIdFrom(url: string): string | null {
  const path = url.split('?', 1)[0] ?? url;
  const match = /^\/v1\/receipts\/([A-Za-z0-9_-]{1,64})$/u.exec(path);
  return match?.[1] ?? null;
}

function constantTimeEquals(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let diff = 0;
  for (let i = 0; i < left.length; i++) diff |= (left[i] ?? 0) ^ (right[i] ?? 0);
  return diff === 0;
}

/** What a record grants, in the words a refusal gives back. */
function grantedScopes(scopes: readonly Scope[]): string {
  return scopes.length === 0 ? 'nothing' : scopes.join('+');
}

/**
 * The two halves of a scope refusal in one place: the row the credential does not satisfy, and the
 * row the table does not have. Only the second names the target, so the query is stripped on the
 * requests that are refused rather than on every one that arrives.
 */
function scopeDenial(scope: RouteScope | undefined, record: CredentialRecord, input: AdmissionInput): string {
  if (scope !== undefined) {
    return `${record.id} holds ${grantedScopes(record.scopes)}, this route needs ${scope}`;
  }
  const path = input.url.split('?', 1)[0] ?? input.url;
  return `no scope row for ${input.method} ${path}`;
}

/**
 * A header that is not an `Ashaveri-PoP` header at all is a scheme disagreement and says nothing
 * about a credential; one that names the scheme and still fails to parse is a client bug. Two
 * codes, because the two conditions ask two different people to change something.
 */
function parseAuthorization(header: string): PopAuthorization {
  try {
    return parsePopAuthorization(header);
  } catch (err) {
    if (err instanceof ReceiptError && err.code === 'AUTH_SCHEME_MISMATCH') {
      throw new AccessError('AUTH_SCHEME', 'the Authorization header is neither Ashaveri-PoP nor Bearer');
    }
    throw new AccessError('AUTH_MALFORMED', reason(err));
  }
}

/**
 * The nonce a request presents, which is both the replay-set key and the third term of the signing
 * string. It is read here rather than taken from the header's parameters because the signature
 * covers the nonce, not the text that spells it out.
 */
function presentedNonce(headers: AdmissionInput['headers']): Uint8Array {
  const header = firstHeader(headers, 'x-ashaveri-nonce');
  if (header === undefined) throw new AccessError('AUTH_NONCE_MISSING');
  let nonce: Uint8Array;
  try {
    nonce = fromBase64Url(header, 'BAD_POP_NONCE');
  } catch (err) {
    throw new AccessError('AUTH_NONCE_MISSING', reason(err));
  }
  if (nonce.length !== POP_NONCE_BYTES) {
    throw new AccessError('AUTH_NONCE_MISSING', `the nonce is ${nonce.length} bytes, not ${POP_NONCE_BYTES}`);
  }
  return nonce;
}

/**
 * The key a proof-of-possession record can be verified against, or nothing when it cannot. The
 * parser drops a stray `secretHash` beside a `pop` kind instead of refusing the record, and an
 * in-memory file never reaches that parser at all, so the store checks the shape it was handed: a
 * record whose key is the wrong width would otherwise fail the signature check and blame the client
 * for an edit to the operator's file.
 */
function popPublicKeyOf(record: CredentialRecord): Uint8Array | undefined {
  if (record.kind !== 'pop' || record.secretHash !== undefined) return undefined;
  const key = record.publicKey;
  if (key === undefined || key.length !== ED25519_PUBLIC_KEY_BYTES) return undefined;
  return key;
}

/**
 * The digest a bearer record can be matched against, or nothing when it cannot. A record that does
 * not match its own kind is dropped from the scan rather than refused by name, and a revoked one is
 * skipped as though it had never existed: `AUTH_UNKNOWN` is what a wrong secret already gets, so a
 * distinct answer for either would tell a prober which ids the file holds and which of them were
 * once live. A record whose digest is the wrong width could never match anything anyway.
 */
function bearerSecretHashOf(record: CredentialRecord): Uint8Array | undefined {
  if (record.kind !== 'bearer' || record.publicKey !== undefined) return undefined;
  const hash = record.secretHash;
  if (hash === undefined || hash.length !== SHA256_BYTES) return undefined;
  return hash;
}

interface Located {
  readonly presented: PopAuthorization;
  readonly record: CredentialRecord;
  readonly key: Uint8Array;
}

export class CredentialStore {
  private file: CredentialFile;
  private byId: Map<string, CredentialRecord>;
  private readonly replay: ReplaySet;
  private readonly buckets = new TokenBucket();
  private readonly path?: string;
  private readonly allowBearer: boolean;
  private readonly toleranceSeconds: number;
  private readonly now: () => number;
  private watchedMtimeMs = 0;
  private reloading: Promise<void> | undefined;

  constructor(options: CredentialStoreOptions) {
    if (options.path !== undefined && options.file !== undefined) {
      throw new AccessError('BAD_CREDENTIAL_FILE', 'a store reads either a file on disk or an in-memory one, not both');
    }
    if (options.path === undefined && options.file === undefined) {
      throw new AccessError('BAD_CREDENTIAL_FILE', 'a store needs a path or an in-memory file');
    }
    this.path = options.path;
    this.file = options.file ?? { version: CREDENTIALS_FILE_VERSION, credentials: [] };
    this.byId = new Map(this.file.credentials.map((entry) => [entry.id, entry]));
    this.allowBearer = options.allowBearer ?? false;
    this.toleranceSeconds = options.toleranceSeconds ?? POP_TIMESTAMP_TOLERANCE_SECONDS;
    this.now = options.now ?? (() => Date.now());
    this.replay = new ReplaySet(REPLAY_WINDOW_SECONDS, REPLAY_MAX_ENTRIES, this.now);
  }

  credentials(): CredentialRecord[] {
    return [...this.file.credentials];
  }

  /**
   * Reload when the file changed. Revocation that waits for a restart is not revocation, so the
   * gateway checks the mtime and re-reads in the background; a request in flight uses the file as of
   * its start, which is the same guarantee a restart would give with worse latency for everyone
   * else. A file that will not parse leaves the loaded records in place and the mtime unrecorded, so
   * the next request tries again: the half-written file in the middle of an operator's edit is one
   * failed reload rather than a deployment that has forgotten its credentials.
   */
  async reloadIfNeeded(): Promise<void> {
    const path = this.path;
    if (path === undefined) return;
    if (this.reloading !== undefined) {
      await this.reloading;
      return;
    }
    let mtimeMs: number;
    try {
      mtimeMs = (await stat(path)).mtimeMs;
    } catch {
      return;
    }
    if (mtimeMs === this.watchedMtimeMs) return;
    this.reloading = (async () => {
      const next = await loadCredentialFile(path);
      this.file = next;
      this.byId = new Map(next.credentials.map((entry) => [entry.id, entry]));
      this.watchedMtimeMs = mtimeMs;
    })();
    try {
      await this.reloading;
    } finally {
      this.reloading = undefined;
    }
  }

  /**
   * The five checks, cheapest rejection first: resolve the credential, prove the request holds the
   * key that credential names, prove the request is new, prove the route is one it may use, then
   * spend a token against its rate. The order is the contract rather than an optimization: a request
   * that fails two of them reports the earlier one, so a revoked credential is never asked to sign
   * anything and a credential with no scope for the route never spends budget it was not going to
   * use.
   */
  admit(input: AdmissionInput): Admission {
    // The table read is the cheapest step, so it still runs first, but it answers only at the scope
    // check: refusing a target outside the table before a credential is named would let anyone
    // enumerate which paths this gateway has scoped.
    const scope = routeScope(input.method, input.url);
    const header = firstHeader(input.headers, 'authorization');
    if (header === undefined || header.trim().length === 0) {
      throw new AccessError('AUTH_MALFORMED', 'no Authorization header');
    }
    const trimmed = header.trim();
    const secret = bearerSecret(trimmed);
    if (secret !== undefined) {
      if (!this.allowBearer) {
        throw new AccessError(
          'AUTH_SCHEME',
          'this deployment requires a proof of possession; a bearer-capable deployment sets --allow-bearer',
        );
      }
      return this.admitBearer(secret, scope, input);
    }
    const { presented, record, key } = this.locate(trimmed);

    const nowSeconds = input.nowSeconds ?? Math.floor(this.now() / 1000);
    const skew = Math.abs(nowSeconds - presented.ts);
    if (skew > this.toleranceSeconds) {
      // The id is already in hand from `locate`, and it goes on the refusal: a stale request is one
      // from a credential this file knows, and a record that names none cannot be traced back to it.
      throw new AccessError(
        'AUTH_STALE',
        `the request is stamped ${skew}s from this clock, outside the ${this.toleranceSeconds}s tolerance: check the clock on the client or the deployment`,
        undefined,
        presented.credential,
      );
    }

    const nonce = presentedNonce(input.headers);
    const fields: PopFields = {
      ts: presented.ts,
      nonce,
      method: input.method.toUpperCase(),
      target: input.url,
      bodyDigestHex: bodyDigest(input.body),
    };
    if (!verifyPopSignature(fields, presented.signature, key)) {
      throw new AccessError('AUTH_SIGNATURE', presented.credential, undefined, presented.credential);
    }
    if (this.replay.see(nonceKey(presented.credential, nonce))) {
      throw new AccessError('NONCE_SEEN', presented.credential, undefined, presented.credential);
    }
    if (scope === undefined || !scopeSatisfied(record.scopes, scope)) {
      throw new AccessError('SCOPE_DENIED', scopeDenial(scope, record, input), undefined, record.id);
    }
    return this.charge(presented.credential, record, scope, input, 'pop', nonce);
  }

  /** Checks one and two of the pipeline: which record the header names, and whether it can be used. */
  private locate(header: string): Located {
    const presented = parseAuthorization(header);
    const record = this.byId.get(presented.credential);
    if (record === undefined) {
      // One refusal for an id this file never carried and an id it no longer trusts, so the answer
      // cannot be used to enumerate what a deployment has issued.
      throw new AccessError('AUTH_UNKNOWN', presented.credential, undefined, presented.credential);
    }
    if (record.kind !== 'pop') {
      throw new AccessError('AUTH_SCHEME', `${presented.credential} is a bearer credential`, undefined, presented.credential);
    }
    if (record.revokedAt !== undefined) {
      throw new AccessError('AUTH_REVOKED', presented.credential, undefined, presented.credential);
    }
    const key = popPublicKeyOf(record);
    if (key === undefined) {
      throw new AccessError(
        'BAD_CREDENTIAL_RECORD',
        `${presented.credential} carries no ${ED25519_PUBLIC_KEY_BYTES}-byte public key for its kind`,
      );
    }
    return { presented, record, key };
  }

  /**
   * Bearer admission. The secret itself is never stored, so the only way to find whose it is comes
   * from hashing what was presented and comparing every digest in the file with a loop that does not
   * exit early on the first differing byte. A secret that is not base64url at all decodes to bytes
   * that match nothing, which is the same refusal a wrong secret gets.
   */
  private admitBearer(secret: string, scope: RouteScope | undefined, input: AdmissionInput): Admission {
    const wanted = hashSecret(new Uint8Array(Buffer.from(secret, 'base64url')));
    for (const record of this.byId.values()) {
      if (record.revokedAt !== undefined) continue;
      const stored = bearerSecretHashOf(record);
      if (stored === undefined || !constantTimeEquals(wanted, stored)) continue;
      if (scope === undefined || !scopeSatisfied(record.scopes, scope)) {
        throw new AccessError('SCOPE_DENIED', scopeDenial(scope, record, input), undefined, record.id);
      }
      return this.charge(record.id, record, scope, input, 'bearer', null);
    }
    throw new AccessError('AUTH_UNKNOWN', 'no bearer credential matches the presented secret');
  }

  /** The last check for both kinds, and the answer: what was granted, and what it may be spent on. */
  private charge(
    id: string,
    record: CredentialRecord,
    scope: RouteScope,
    input: AdmissionInput,
    auth: Admission['auth'],
    nonce: Uint8Array | null,
  ): Admission {
    const taken = this.buckets.take(id, record.rate ?? DEFAULT_RATE, this.now());
    if (!taken.allowed) {
      throw new AccessError('RATE_LIMITED', id, taken.retryAfterSeconds, id);
    }
    return { credentialId: id, scope, auth, nonce, receiptId: receiptIdFrom(input.url) };
  }
}
