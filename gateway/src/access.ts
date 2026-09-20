import { readFile, stat } from 'node:fs/promises';
import { createHmac, hkdfSync, randomBytes, randomUUID } from 'node:crypto';
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
  type SigningKey,
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

/**
 * What the access log records: every code a caller can be told, plus the reasons that never leave this
 * process. `AccessErrorCode` has three things keyed on it, `ERROR_STATUS` and `ERROR_MESSAGE` below and
 * the caller-facing table `docs/error-codes.md` holds row for row, so a reason only the deployer ever
 * reads gets a type of its own rather than a status it never answers with and a sentence no caller is
 * ever told. Nothing here keeps such a reason out of a response, and `server.ts` says what does.
 */
export type DenyCode = AccessErrorCode | 'PEER_RATE_LIMITED';

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
  // Names no credential on purpose: this is the one code two different buckets answer with, and the
  // connection's is refused before any credential is read, so a caller-facing sentence that asserted
  // one would print a fact the pipeline does not know. Which limit was spent is the detail's job.
  RATE_LIMITED: 'this request is over a rate limit',
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
  /**
   * The code the access log records, which is what this gateway decided, as distinct from `code`,
   * which is what the caller is told. The two are the same value everywhere except where a refusal is
   * collapsed: a name this file does not carry is answered to its caller as a failed signature, and an
   * operator diagnosing a misconfigured client still needs to read that the name was unknown. The other
   * way they differ, where neither is cover for the other, is the connection's rate bound, and
   * `chargePeer` says why that one splits. Either way it is the record that differs: the status and the
   * words the caller sees are `code`'s.
   */
  readonly logCode: DenyCode;
  readonly status: number;
  readonly retryAfterSeconds: number | undefined;
  /**
   * Which credential this refusal is about, when the pipeline knew. The access record wants a
   * name and a message is not a place to read one from: prose is rewritten for the reader's
   * benefit, while this field is the string the store was asked about.
   */
  readonly credentialId: string | undefined;
  /**
   * The detail as it was handed in, before this code's sentence was prefixed to it. A caller that
   * re-wraps an error to add where it came from writes here and not into `message`, because
   * `message` already carries that sentence and prepending it again prints the clause twice.
   */
  readonly detail: string | undefined;

  constructor(
    code: AccessErrorCode,
    detail?: string,
    retryAfterSeconds?: number,
    credentialId?: string,
    logCode?: DenyCode,
  ) {
    super(detail === undefined ? ERROR_MESSAGE[code] : `${ERROR_MESSAGE[code]}: ${detail}`);
    this.name = 'AccessError';
    this.code = code;
    this.logCode = logCode ?? code;
    this.status = accessStatus(code);
    this.retryAfterSeconds = retryAfterSeconds;
    this.credentialId = credentialId;
    this.detail = detail;
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
  // A credential that may send completions must also be able to fetch the receipt for them, because
  // `GET /v1/receipts/:id` is granted to `read`. The receipt is the interpretation tool this product
  // ships: an oversight duty is met with the evidence in hand, and a deployment that can complete
  // what it cannot read has built that failure in. So `complete` alone is not a credential shape,
  // and it is refused here, where a credential enters, rather than at admission, where the route
  // table's plain lookup would have to become a set-inclusion test. The id is safe to print: the
  // wire character set was checked above, and this sentence goes to a log line.
  if (scopes.includes('complete') && !scopes.includes('read')) {
    refuse(
      'BAD_CREDENTIAL_RECORD',
      `${where}.scopes of '${id}' grants 'complete' without 'read', so it could send completions whose receipt it cannot fetch`,
    );
  }
  const createdAt = asNumber(raw['createdAt'], `${where}.createdAt`);
  const record: CredentialRecord = { id, kind, scopes, createdAt };
  if (kind === 'pop') {
    record.publicKey = parseKeyField(raw['publicKey'], `${where}.publicKey`, ED25519_PUBLIC_KEY_BYTES);
  } else {
    const hash = asString(raw['secretHash'], `${where}.secretHash`);
    if (!HEX32.test(hash)) {
      refuse('BAD_CREDENTIAL_RECORD', `${where}.secretHash is not 64 hex characters`);
    }
    // Node's base64url decoder drops the characters it does not know instead of refusing them, so a token
    // made of punctuation spells no bytes at all and digests to this one value. A record carrying it is
    // therefore opened by every such token, which is the opposite of a credential, and there are 2^64 of
    // them. `newBearerCredential` draws 32 random bytes and cannot write one, so this refuses a typed or a
    // pasted file and nothing this repository produces. `EMPTY_BODY_SHA256_HEX` names the same thirty-two
    // bytes for the other thing they are the digest of: the body a bodyless request signs.
    if (hash === EMPTY_BODY_SHA256_HEX) {
      refuse(
        'BAD_CREDENTIAL_RECORD',
        `${where}.secretHash is the digest of no bytes, which a bearer token that decodes to nothing presents`,
      );
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
      // The path goes on the detail, not on the message, because the message already opens with the
      // clause this constructor prefixes: writing it there printed the same sentence twice.
      throw new AccessError(err.code, err.detail === undefined ? path : `${path}: ${err.detail}`);
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

/**
 * Every id this gateway mints satisfies this, and every id the route accepts is checked against
 * it. Exported because the mint's promise is a promise about this pattern, and a gate that holds a
 * second copy of the regular expression is a gate that can pass while the two drift.
 */
export const RECEIPT_ID = /^[A-Za-z0-9_-]{1,64}$/u;

/**
 * A receipt id is the presenting credential's tag and then sixteen freshly drawn bytes: forty-eight
 * lower-case hex characters, inside the sixty-four this pattern allows, so the route rule is
 * unchanged and the prefix compare needs no case fold.
 *
 * The tag is `HMAC-SHA256(namespaceKey, credentialId)` truncated to eight bytes and printed as hex.
 * The value it replaced is not a tag and never was one: the gateway used to publish the id the
 * inference server chose, so a server that answers with a counter or a timestamp would have put
 * every receipt this deployment has signed behind numbers another tenant could walk, since the
 * route asked only whether the caller holds `read`. Unguessability is now this gateway's own job.
 *
 * The namespace key is an HKDF over the deployment's Ed25519 seed, so it is derived at boot from a
 * secret the deployment already holds and rotates on redeploy, nothing new is written to disk, and
 * a tenant cannot compute another tenant's tag without that seed. The credential *id* is the tag's
 * input rather than the credential's key, because an id survives a credential's key rotation: a
 * tenant that changes its own key still addresses the receipts it minted before.
 */
export const RECEIPT_ID_TAG_BYTES = 8;
export const RECEIPT_ID_TAG_HEX_CHARS = RECEIPT_ID_TAG_BYTES * 2;
export const RECEIPT_ID_RANDOM_BYTES = 16;
/** `tag || random`, counted in characters. */
export const RECEIPT_ID_CHARS = (RECEIPT_ID_TAG_BYTES + RECEIPT_ID_RANDOM_BYTES) * 2;

const HKDF_KEY_BYTES = 32;
const ED25519_SEED_BYTES = 32;

/**
 * Mixed into the derivation so that changing the scheme moves to a different namespace rather than
 * silently colliding with an old deployment's ids. Both carry a version: editing either re-namespaces
 * every id in existence, which is the same consequence a signing-key rotation already has, so they
 * change together with the rule and not on their own.
 */
export const RECEIPT_NAMESPACE_SALT = 'ashaveri-receipt-namespace-v1';
export const RECEIPT_NAMESPACE_INFO = 'ashaveri-receipt-id-tag-v1';

function utf8Bytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

/** The namespace key for one deployment. Called once per process, by `ReceiptNamespace`. */
export function deriveReceiptNamespaceKey(seed: Uint8Array): Uint8Array {
  const derived = hkdfSync(
    'sha256',
    seed,
    utf8Bytes(RECEIPT_NAMESPACE_SALT),
    utf8Bytes(RECEIPT_NAMESPACE_INFO),
    HKDF_KEY_BYTES,
  );
  // Node's declared return type has moved between ArrayBuffer and Buffer across releases, so both
  // spellings are accepted here rather than one of them asserted.
  return derived instanceof Uint8Array ? derived : new Uint8Array(derived);
}

/**
 * The minting and the checking half of one rule, held by the gateway that serves the receipts. One
 * instance per process, built from the deployment the receipts are signed with.
 */
export class ReceiptNamespace {
  private readonly key: Uint8Array;
  /**
   * One HMAC per credential id per process, so a request pays a string compare and nothing else.
   * Keyed only from credentials the store has already admitted, never from a URL or a header, so
   * nothing a caller sends can grow it: its ceiling is the credential file's own record count.
   */
  private readonly tags = new Map<string, string>();

  constructor(signingKey: SigningKey) {
    // `SigningKey.privateKey` *is* the 32-byte seed, which is what makes it a usable HKDF input:
    // `signingKeyFromSeed` in `packages/receipt` is the only other writer of the field and it
    // enforces the same width, so a key this repository can build always passes this check.
    if (signingKey.privateKey.length !== ED25519_SEED_BYTES) {
      throw new ReceiptError(
        'BAD_SIGNING_KEY',
        `the receipt namespace needs a ${ED25519_SEED_BYTES}-byte Ed25519 seed, got ${String(signingKey.privateKey.length)} bytes`,
      );
    }
    this.key = deriveReceiptNamespaceKey(signingKey.privateKey);
  }

  /** The sixteen hex characters that stand for this credential inside an id. */
  tagFor(credentialId: string): string {
    const known = this.tags.get(credentialId);
    if (known !== undefined) return known;
    const tag = createHmac('sha256', this.key)
      .update(utf8Bytes(credentialId))
      .digest()
      .subarray(0, RECEIPT_ID_TAG_BYTES)
      .toString('hex');
    this.tags.set(credentialId, tag);
    return tag;
  }

  /** A fresh id for one completion under `tag`: the tag, then sixteen bytes nobody else can predict. */
  mint(tag: string): string {
    return `${tag}${randomBytes(RECEIPT_ID_RANDOM_BYTES).toString('hex')}`;
  }

  /**
   * Whether this id was minted for this credential. A mismatch gets no distinct answer: the caller is
   * held to the same refusal as one asking for an id that never existed, which is the whole point of
   * checking a tag rather than ownership state. The compare is the file's existing constant-time one,
   * because the value it checks is derived from a secret and a short-circuit on the first differing
   * character is a signal a prober can read. An id shorter than the tag compares unequal by length,
   * so no separate width rule is needed, and a matching prefix on an id this gateway never wrote
   * still finds no bytes to serve.
   */
  carries(id: string, tag: string): boolean {
    return constantTimeEquals(
      Buffer.from(id.slice(0, RECEIPT_ID_TAG_HEX_CHARS), 'utf8'),
      Buffer.from(tag, 'utf8'),
    );
  }
}

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
 * What a connection address is held to ahead of every credential, so that an unauthenticated guess
 * costs something other than the asking. Measured on this workspace's `@noble/curves` under node 24: one
 * `verifyPopSignature` over a forged 64-byte signature is ~183 microseconds, so ~5,500 a second fills a
 * single core.
 *
 * The size comes from what a deployment carries, not from what a guesser fails to do, and it has to be
 * read against the traffic shape this repository ships: `server.ts` takes the address off the socket and
 * no header, so behind one reverse proxy every legitimate request arrives from one address and spends
 * from one bucket. A credential without its own `rate` is held to `DEFAULT_RATE`, 60 a minute, so fifteen
 * credentials running their own defaults are 900 requests a minute, and a bound set at 900 refuses a
 * deployment's correctly signed aggregate on the same arithmetic that empties a guessing loop. The floor
 * has to sit above the traffic and below the cost, and this is where both hold.
 *
 * Six thousand a minute is a hundred requests a second from one address, so a hundred verifications a
 * second, which is 18.3 milliseconds of crypto in every second and 1.8 per cent of one core. The two
 * thousand burst is 366 milliseconds, the most one peer can demand of a core at once, and an address
 * asking past it is refused for the cost its next request would have spent rather than the cost it saves,
 * a map lookup. Reaching either half means asking a hundred requests a second of one address, or two
 * thousand in the instant the bucket opened, and neither is what the credentials above do, while a loop
 * that wants five thousand guesses a second is answered `RATE_LIMITED` from the two thousand and first in
 * a row. What this bounds is what one connection can demand, not what all of them can: see
 * `MAX_TRACKED_PEERS`. An operator whose deployment is bigger than this sets both halves with
 * `--peer-rate`.
 */
export const DEFAULT_PEER_RATE: CredentialRate = { perMinute: 6000, burst: 2000 };

/**
 * How many connection addresses the peer bucket remembers. Nothing bounds who connects, so this cap is
 * what keeps a control on what a guess costs from opening a door onto memory: each entry is two
 * numbers, and the count is fixed whatever the traffic, as the replay set's cap is. A peer that is
 * evicted gets a full bucket back on its next request, which is the right loss: the cap holds memory
 * down rather than holding an address refused.
 */
const MAX_TRACKED_PEERS = 16_384;

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
 * Refilled at perMinute/60 tokens per second, capped at burst, one bucket per key: per credential for
 * the bucket admission takes last, and per connection address for the one it takes first.
 */
export class TokenBucket {
  private readonly buckets = new Map<string, Bucket>();

  /**
   * How many keys this map may hold. Left unlimited where the keys come from a credential file, which
   * `MAX_CREDENTIALS` already bounds, and set where they come from whoever connects, which nothing
   * else bounds: a counter that grew with the number of peers a process had ever met would replace a
   * control on what a request costs with a door onto memory, which is the trade this bucket exists to
   * avoid. Eviction gives up on the key presented least recently, so the peers who lose a bucket are
   * the quiet ones - who get a full one back - and not the busy one a bucket exists to hold.
   */
  constructor(private readonly maxKeys: number = Number.POSITIVE_INFINITY) {}

  take(key: string, rate: CredentialRate, nowMs: number = Date.now()): { allowed: boolean; retryAfterSeconds: number } {
    const bucket = this.buckets.get(key);
    const refillPerMs = rate.perMinute / 60_000;
    if (bucket === undefined) {
      this.buckets.set(key, { tokens: rate.burst - 1, updatedMs: nowMs });
      this.trim();
      return { allowed: true, retryAfterSeconds: 0 };
    }
    // Presentation order rather than insertion order: a touched key moves to the back of the map, so
    // the eviction in `trim` is least-recently-presented and not first-seen.
    this.buckets.delete(key);
    this.buckets.set(key, bucket);
    // A clock that steps backwards would otherwise refill by a negative amount and spend tokens
    // nobody took, so the elapsed time is floored at nothing before it becomes tokens.
    const gained = Math.max(0, (nowMs - bucket.updatedMs) * refillPerMs);
    const refilled = Math.min(rate.burst, bucket.tokens + gained);
    if (refilled < 1) {
      bucket.tokens = refilled;
      // The base moves forward and never back: a stamp taken from behind it would let the next
      // forward step recompute an interval this bucket has already paid out, so a clock that steps
      // back and returns would buy more than `burst`.
      bucket.updatedMs = Math.max(bucket.updatedMs, nowMs);
      // A whole second, and never zero: a hint the client cannot act on invites it to retry
      // immediately, which is the traffic this is meant to hold back. A rate that never refills has
      // no finite answer, and this number is destined for a `Retry-After` header, so it is a number
      // even then.
      const waitMs = refillPerMs > 0 ? (1 - refilled) / refillPerMs : Number.MAX_SAFE_INTEGER;
      return { allowed: false, retryAfterSeconds: Math.max(1, Math.ceil(waitMs / 1000)) };
    }
    bucket.tokens = refilled - 1;
    // The same rule on the grant, which is where a backwards step that spent a token is recorded.
    bucket.updatedMs = Math.max(bucket.updatedMs, nowMs);
    return { allowed: true, retryAfterSeconds: 0 };
  }

  /**
   * Drop back to the cap, oldest presentation first. A bucket that is given up on is not a refusal:
   * the next request from that key opens a fresh one at full burst, which is why the cap bounds
   * memory rather than behaviour, and why an unlimited map keyed on whoever happens to connect is the
   * one shape here that has to be impossible.
   */
  private trim(): void {
    if (this.buckets.size <= this.maxKeys) return;
    const excess = this.buckets.size - this.maxKeys;
    let dropped = 0;
    for (const entry of this.buckets.keys()) {
      if (dropped >= excess) break;
      this.buckets.delete(entry);
      dropped += 1;
    }
  }
}

export interface AdmissionInput {
  method: string;
  url: string;
  headers: Record<string, string | string[] | undefined>;
  body: Uint8Array | null;
  /** Seconds since the epoch the request is stamped with; this clock's own second when absent. */
  nowSeconds?: number;
  /**
   * The peer address of the connection this request arrived on, which is the key the request bound
   * taken ahead of any crypto is held on. The transport fills it from the socket and from nothing the
   * caller wrote: no header may supply an address, neither `Forwarded` nor `X-Forwarded-For`, because a
   * key a guesser chooses is a bucket a guesser empties or evades. Absent means no transport spoke - a
   * store handed requests directly - and a bucket with no key to charge is not charged at all, which is
   * why the gateway's own `preHandler` fills this on every request it admits.
   */
  peerAddress?: string;
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
  /**
   * What a connection address is held to before this store spends any crypto on it;
   * `DEFAULT_PEER_RATE` when unset, which is what the gateway's `--peer-rate` flag sets. Injectable for
   * the same reason the clock is, and for a sharper one: a property walk over a matrix of requests
   * inside one process is not a guessing loop, and a bound that refused it would read as a disclosure
   * failure. A harness held to no bound says so where it builds the store, rather than leaving the
   * number to be raised in the software until a test goes green.
   */
  peerRate?: CredentialRate;
  /**
   * Called once per Ed25519 verification this store performs. It takes no arguments, is given no
   * verdict, and its return value is unread, so it cannot become the branch the collapsed refusal must
   * never be: what it counts is that a verification happened, which is the only honest way to assert
   * that a shed guess spent no crypto. Nothing in the shipped gateway passes one.
   */
  countVerification?: () => void;
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
 * A record as the store holds it: the record `admit` reads, beside the one fact about it no request
 * has to be refused for learning - the key a proof of possession verifies against. `null` is a
 * record that carries no key because it is a bearer one, which after ingest is the only reason left
 * for a name the file does hold to be answered as a failed signature.
 */
interface Ingested {
  readonly record: CredentialRecord;
  readonly popKey: Uint8Array | null;
}

/**
 * The one place a record becomes something this store serves. Both routes reach it: the in-memory
 * file a test or `--mock` hands the constructor, and the disk read `reloadIfNeeded` installs. The
 * shape of a record is therefore a fact about start-up rather than about a request, which is what
 * `admit` needs: a refusal that answers 500 because of what a file says about one id is the most
 * distinguishable answer in the whole set, and the collapse cannot keep it on the request path
 * without keeping the question a prober asks with it.
 *
 * Both rules are taken from the parser rather than invented here, because an in-memory file never
 * passes through it:
 *
 * - A `pop` record's `secretHash` is dropped. `parseRecord` reads that field only on its `bearer`
 *   branch, so the same bytes on disk become a record that carries no such field, and only the
 *   route that bypasses the parser could hold one. Clearing it here makes the two paths agree about
 *   a policy the parser already has; the record is not repaired into anything the disk route would
 *   not have produced, it becomes the record the disk route would have produced.
 * - A `pop` record with no public key of the width its kind needs is refused, the way
 *   `parseKeyField` refuses one read from a file. It is not repaired: a key of the wrong width is
 *   the operator's file being wrong, and a store that served a different key than the record names
 *   would be a worse fault than a boot that refuses.
 *
 * Refused at ingest means never served, so `BAD_CREDENTIAL_RECORD` cannot be produced by a request
 * at all. The operator keeps the signal in the other direction: the message names the record, and
 * start-up exits on it while a reload that hits one keeps serving the records it already had. The
 * id is in that sentence because it is what a reader looks the file up by; on the disk route
 * `parseRecord` has already refused an id outside the wire character set, and on the in-memory
 * route the id is code the caller wrote rather than anything a request presented.
 */
function ingestCredential(record: CredentialRecord, index: number): Ingested {
  if (record.kind !== 'pop') return { record, popKey: null };
  const key = record.publicKey;
  if (key === undefined || key.length !== ED25519_PUBLIC_KEY_BYTES) {
    refuse(
      'BAD_CREDENTIAL_RECORD',
      `credentials[${index}] ('${record.id}') is a 'pop' record carrying ${
        key === undefined ? 'no publicKey' : `a ${key.length}-byte publicKey`
      }, not the ${ED25519_PUBLIC_KEY_BYTES} bytes its kind has to be verified against`,
    );
  }
  if (record.secretHash === undefined) return { record, popKey: key };
  // A copy rather than an edit in place, because the record belongs to whoever handed it in:
  // `--mock` and every test read back the records they built after the store has taken them.
  const { secretHash: _unread, ...carried } = record;
  return { record: carried, popKey: key };
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

/**
 * A key that is in no credential file, made once per process and never replaced. A request naming a
 * record this file does not carry is verified against this one before it is refused, so the refused
 * name and the refused signature run the same code path and perform the same single Ed25519
 * verification, and the answer a prober gets is the answer a client with a broken signature gets.
 *
 * The verification's own verdict is never read. A zero signature against a constant 32-byte key
 * verifies under the signing library's own defaults, because such a key is a point of small order,
 * and what refuses it is `verifyPopSignature`'s width checks and its strict option. Reading a
 * `true` from this path as permission to carry on, or reaching past that function for the library,
 * would hand a caller who named nothing an accepted signature and re-open the question this path
 * exists to close.
 */
const DUMMY_VERIFICATION_KEY = signingKeyFromSeed(randomBytes(ED25519_PUBLIC_KEY_BYTES)).publicKey;

interface Located {
  readonly record: CredentialRecord;
  readonly key: Uint8Array;
}

export class CredentialStore {
  private file: CredentialFile = { version: CREDENTIALS_FILE_VERSION, credentials: [] };
  private byId: Map<string, Ingested> = new Map();
  private readonly replay: ReplaySet;
  private readonly buckets = new TokenBucket();
  /** Keyed on the connection address rather than a credential, and capped because nothing caps who connects. */
  private readonly peerBuckets = new TokenBucket(MAX_TRACKED_PEERS);
  private readonly path?: string;
  private readonly allowBearer: boolean;
  private readonly toleranceSeconds: number;
  private readonly peerRate: CredentialRate;
  private readonly countVerification: (() => void) | undefined;
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
    this.install(options.file ?? { version: CREDENTIALS_FILE_VERSION, credentials: [] });
    this.allowBearer = options.allowBearer ?? false;
    this.toleranceSeconds = options.toleranceSeconds ?? POP_TIMESTAMP_TOLERANCE_SECONDS;
    this.peerRate = options.peerRate ?? DEFAULT_PEER_RATE;
    this.countVerification = options.countVerification;
    this.now = options.now ?? (() => Date.now());
    this.replay = new ReplaySet(REPLAY_WINDOW_SECONDS, REPLAY_MAX_ENTRIES, this.now);
  }

  /**
   * Take one parsed file as the records this store serves, through `ingestCredential`. Assignment
   * happens only once every record has been ingested, so a file with one unusable record in it
   * leaves the previously installed records in place rather than replacing them with a partial set.
   */
  private install(file: CredentialFile): void {
    const ingested = file.credentials.map(ingestCredential);
    this.file = { version: file.version, credentials: ingested.map((entry) => entry.record) };
    this.byId = new Map(ingested.map((entry) => [entry.record.id, entry]));
  }

  credentials(): CredentialRecord[] {
    return [...this.file.credentials];
  }

  /**
   * Reload when the file changed. Revocation that waits for a restart is not revocation, so the
   * gateway checks the mtime and re-reads in the background; a request in flight uses the file as of
   * its start, which is the same guarantee a restart would give with worse latency for everyone
   * else. A file that will not parse, or that parses into a record ingest refuses, leaves the loaded
   * records in place and the mtime unrecorded, so the next request tries again: the half-written
   * file in the middle of an operator's edit is one failed reload rather than a deployment that has
   * forgotten its credentials. The failure is reported either way, because the records that stopped
   * a reload from landing are the reason the operator has to read.
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
      this.install(next);
      this.watchedMtimeMs = mtimeMs;
    })();
    try {
      await this.reloading;
    } finally {
      this.reloading = undefined;
    }
  }

  /**
   * The checks, in the order the answers are safe to give. Name-independent refusals come first,
   * cheapest first: the connection's own request bound, then the header the caller wrote, the stamp it
   * carries, the nonce it presents. Among the name-dependent ones the only answer this gateway gives
   * before a signature verifies is the answer that a signature did not verify, which is also the answer
   * a name the file does not carry gets. What the file says about a credential it does hold - revoked,
   * replayed, out of scope, over budget - is told to the one party who can act on it, the caller that
   * proved it holds the key the header names. The order is therefore sorted by what it discloses rather
   * than by what it costs, and a request that fails two checks still reports the earlier one.
   */
  admit(input: AdmissionInput): Admission {
    // The connection's budget, taken ahead of reading anything out of the header. This is the one check
    // that runs before this store looks at what a caller wrote at all, and that is what makes it lawful
    // under the placement test: every request meets it, whoever it names and whatever its header says,
    // so a refusal here is a statement about the deployment and cannot be an answer about the file. It
    // sits above the crypto because that is the point of it - a guess is refused for the cost it would
    // have spent, one Ed25519 verification, and not for the cost it saves, a map lookup.
    this.chargePeer(input.peerAddress);
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
    const presented = parseAuthorization(trimmed);

    // Both of these read only what the caller wrote - the stamp in the header and the nonce beside it
    // - so both are a statement about the request rather than about the file, and both are owed to
    // every proof-of-possession request whoever it names. The nonce has to be read before the
    // signature is checked anyway, because it is a term of the signing string.
    const nowSeconds = input.nowSeconds ?? Math.floor(this.now() / 1000);
    const skew = Math.abs(nowSeconds - presented.ts);
    if (skew > this.toleranceSeconds) {
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

    // A name the file does not carry, and a bearer record named by a proof-of-possession request,
    // are both answered inside `locate`: one verification against a key that is in no file, then
    // this refusal, whatever that verification answered.
    const { record, key } = this.locate(presented, fields);
    if (!this.verify(fields, presented.signature, key)) {
      throw new AccessError('AUTH_SIGNATURE', presented.credential, undefined, presented.credential);
    }
    if (record.revokedAt !== undefined) {
      throw new AccessError('AUTH_REVOKED', presented.credential, undefined, presented.credential);
    }
    if (this.replay.see(nonceKey(presented.credential, nonce))) {
      throw new AccessError('NONCE_SEEN', presented.credential, undefined, presented.credential);
    }
    if (scope === undefined || !scopeSatisfied(record.scopes, scope)) {
      throw new AccessError('SCOPE_DENIED', scopeDenial(scope, record, input), undefined, record.id);
    }
    return this.charge(presented.credential, record, scope, input, 'pop', nonce);
  }

  /**
   * The record a header names and the key it can be verified against. A name this file does not
   * carry, and a name that carries a record of the other kind, are refused here through the dummy
   * verification, so neither answer is distinguishable from a failed signature; the true reason
   * survives only in the code the access log records. What the file says about a record it holds and
   * can verify is withheld until the signature proves the caller holds the key.
   *
   * Nothing here refuses a record for its shape. `ingestCredential` took the keys this map holds and
   * refused the ones it could not, so a `pop` name in it always has a key of the width the verifier
   * needs, and the only reason left for a record to offer no key is that it is a bearer one. A
   * refusal that answered 500 for one id and 401 for another is therefore not reachable from a
   * request: what the file says about a record it holds is told to a caller that verified, and a
   * record the file cannot be verified against never became part of the file.
   */
  private locate(presented: PopAuthorization, fields: PopFields): Located {
    const held = this.byId.get(presented.credential);
    if (held === undefined) {
      throw this.collapsedRefusal(presented, fields, 'AUTH_UNKNOWN');
    }
    if (held.popKey === null) {
      throw this.collapsedRefusal(presented, fields, 'AUTH_SCHEME');
    }
    return { record: held.record, key: held.popKey };
  }

  /**
   * The refusal a caller who cannot be answered about the file gets, whether the name it wrote is
   * absent or belongs to a record that offers no key to verify against: one verification, the same
   * one every other proof-of-possession request performs, against a key no credential file holds,
   * and then `AUTH_SIGNATURE` thrown for it unconditionally. Nothing here reads the verdict, because
   * a verdict this store could act on would be an answer about the file, and the answer a caller who
   * has proved nothing is owed is the one a caller with a bad signature already receives.
   */
  private collapsedRefusal(presented: PopAuthorization, fields: PopFields, logCode: AccessErrorCode): AccessError {
    this.verify(fields, presented.signature, DUMMY_VERIFICATION_KEY);
    return new AccessError('AUTH_SIGNATURE', presented.credential, undefined, presented.credential, logCode);
  }

  /**
   * The one place this store calls the verifier, so that "one Ed25519 verification performed" is a fact
   * that can be counted rather than inferred. Both paths reach it - a name the file carries is checked
   * against its own key, a name it does not against the dummy one - which is the collapse. The counter
   * is told only that a verification happened: it sees no verdict and can change none, so a measuring
   * seam cannot become the branch the paragraph above refuses.
   */
  private verify(fields: PopFields, signature: Uint8Array, key: Uint8Array): boolean {
    this.countVerification?.();
    return verifyPopSignature(fields, signature, key);
  }

  /**
   * The connection's budget, taken before any of what a request says is read. Now that an unknown name
   * is answered as a failed signature, a guess about a name costs this store one Ed25519 verification,
   * and the per-credential bucket cannot bound that because a guess is not holding a credential to
   * charge. So the charge goes on the address the socket reported, and a peer out of tokens is told so
   * plainly: `RATE_LIMITED`, with its 429 and its `retry-after`, the same words in a store that holds
   * the name and one that does not, because nothing about the answer depends on a name. That uniformity
   * is the whole of its lawful placement, and it is also what the caller learns: that a limit exists
   * and that they are inside it, which is a fact about this deployment rather than about an id.
   *
   * The answer's uniformity is one thing and the reason another. Two incidents reach this line and want
   * opposite fixes, one client asking too much of one address and one deployment whose whole population
   * shares a proxy, and the record separates them where the answer must not.
   *
   * The bucket is in memory, is never written to disk, and does not outlive the process. It is not a
   * field of the access record and cannot become one: the log's allowlist is closed, and an ephemeral
   * counter that sheds load is not the retention decision that allowlist is drawn around. Behind a
   * reverse proxy every peer address is the proxy's, which is why no header is asked for an address and
   * why this is not a per-client limit unless an operator puts a trusted proxy in front and passes the
   * real address on.
   */
  private chargePeer(peerAddress: string | undefined): void {
    // Nothing to charge, rather than a shared bucket for everyone the transport could not place: the
    // gateway's own transport fills this from the socket on every request, so the only stores that see
    // an absent address are the ones handed requests directly, which are tests and `--mock`.
    if (peerAddress === undefined) return;
    const taken = this.peerBuckets.take(peerAddress, this.peerRate, this.now());
    if (!taken.allowed) {
      // The detail says which bucket fired, because the retry differs: waiting refills this one, and a
      // different credential would not. It names no credential, since the caller has proved nothing,
      // and no address, since the response is not where a connection learns its own number. The fifth
      // argument is the reason that stays inside, for the reason the note above gives.
      throw new AccessError(
        'RATE_LIMITED',
        'this is the request bound held per connection address, ahead of any credential',
        taken.retryAfterSeconds,
        undefined,
        'PEER_RATE_LIMITED',
      );
    }
  }

  /**
   * Bearer admission. The secret itself is never stored, so the only way to find whose it is comes
   * from hashing what was presented and comparing every digest in the file with a loop that does not
   * exit early on the first differing byte. A secret that is not base64url at all decodes to no bytes,
   * and `parseRecord` refuses the one `secretHash` that is the digest of no bytes, so on a store read
   * from a credential file every such token gets the same refusal a wrong secret gets. A store handed
   * its records in memory never reaches that rule, and this scan drops a digest for its width and
   * nothing else, which is the case `bearer-decode.test.ts` pins rather than fixes.
   */
  private admitBearer(secret: string, scope: RouteScope | undefined, input: AdmissionInput): Admission {
    const wanted = hashSecret(new Uint8Array(Buffer.from(secret, 'base64url')));
    for (const { record } of this.byId.values()) {
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
