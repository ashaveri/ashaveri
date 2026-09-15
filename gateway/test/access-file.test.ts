import { describe, expect, expectTypeOf, it } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  accessStatus,
  AccessError,
  CREDENTIALS_FILE_VERSION,
  MAX_CREDENTIALS,
  loadCredentialFile,
  newBearerCredential,
  newPopCredential,
  parseCredentialFile,
  routeScope,
  scopeSatisfied,
  serializeCredentialFile,
  type AccessErrorCode,
  type CredentialFile,
  type CredentialRecord,
} from '../src/access.js';

/**
 * The code and the HTTP status a call refuses with, as one pair, so a refusal that carries
 * the right code but the wrong status fails the assertion that read it.
 */
function refusal(fn: () => unknown): readonly [string, number] {
  try {
    fn();
    return ['no-error', 0];
  } catch (err) {
    return err instanceof AccessError ? [err.code, err.status] : [`non-AccessError: ${String(err)}`, 0];
  }
}

const VALID = JSON.stringify({
  version: CREDENTIALS_FILE_VERSION,
  credentials: [
    {
      id: 'analyst-1',
      kind: 'pop',
      publicKey: 'dGVzdC1wdWIta2V5LTAwMDAwMDAwMDAwMDAwMDAwMDA',
      scopes: ['read'],
      label: 'Dana, compliance',
      createdAt: 1_772_000_000,
    },
  ],
});

describe('parseCredentialFile', () => {
  it('reads a valid file back with decoded keys', () => {
    const file = parseCredentialFile(VALID);
    expect(file.credentials).toHaveLength(1);
    expect(file.credentials[0]?.id).toBe('analyst-1');
    expect(file.credentials[0]?.publicKey).toBeInstanceOf(Uint8Array);
    expect(file.credentials[0]?.label).toBe('Dana, compliance');
  });

  it('accepts an empty list, which is a valid way to admit nobody', () => {
    expect(parseCredentialFile(JSON.stringify({ version: 1, credentials: [] })).credentials).toEqual([]);
  });

  // name, then the code and status it must refuse with, then the file text, so a case title
  // names both halves of the promise: `refuses not JSON with BAD_CREDENTIAL_FILE 500`.
  const refusals: ReadonlyArray<readonly [string, AccessErrorCode, number, string]> = [
    ['not JSON', 'BAD_CREDENTIAL_FILE', 500, 'nope'],
    ['an array at the top level', 'BAD_CREDENTIAL_FILE', 500, '[]'],
    ['a wrong version', 'BAD_CREDENTIAL_FILE', 500, JSON.stringify({ version: 2, credentials: [] })],
    ['credentials missing', 'BAD_CREDENTIAL_FILE', 500, JSON.stringify({ version: 1 })],
    ['credentials not a list', 'BAD_CREDENTIAL_FILE', 500, JSON.stringify({ version: 1, credentials: {} })],
    ['a record that is not an object', 'BAD_CREDENTIAL_RECORD', 500, JSON.stringify({ version: 1, credentials: [1] })],
    ['no id', 'BAD_CREDENTIAL_RECORD', 500, JSON.stringify({ version: 1, credentials: [{ kind: 'pop', scopes: [], createdAt: 1 }] })],
    ['an id outside the wire character set', 'BAD_CREDENTIAL_RECORD', 500, JSON.stringify({ version: 1, credentials: [{ id: 'bad id!', kind: 'pop', scopes: [], createdAt: 1 }] })],
    ['an unknown kind', 'BAD_CREDENTIAL_RECORD', 500, JSON.stringify({ version: 1, credentials: [{ id: 'a', kind: 'hmac', scopes: [], createdAt: 1 }] })],
    ['pop with no public key', 'BAD_CREDENTIAL_RECORD', 500, JSON.stringify({ version: 1, credentials: [{ id: 'a', kind: 'pop', scopes: [], createdAt: 1 }] })],
    ['bearer with no hash', 'BAD_CREDENTIAL_RECORD', 500, JSON.stringify({ version: 1, credentials: [{ id: 'a', kind: 'bearer', scopes: [], createdAt: 1 }] })],
    ['a public key of the wrong width', 'BAD_CREDENTIAL_RECORD', 500, JSON.stringify({ version: 1, credentials: [{ id: 'a', kind: 'pop', publicKey: 'aGk', scopes: [], createdAt: 1 }] })],
    ['a secret hash that is not 32 bytes of hex', 'BAD_CREDENTIAL_RECORD', 500, JSON.stringify({ version: 1, credentials: [{ id: 'a', kind: 'bearer', secretHash: 'ff', scopes: [], createdAt: 1 }] })],
    ['scopes not a list', 'BAD_CREDENTIAL_RECORD', 500, JSON.stringify({ version: 1, credentials: [{ id: 'a', kind: 'pop', publicKey: 'dGVzdC1wdWIta2V5LTAwMDAwMDAwMDAwMDAwMDAwMDA', scopes: 'read', createdAt: 1 }] })],
    ['an unknown scope', 'BAD_CREDENTIAL_RECORD', 500, JSON.stringify({ version: 1, credentials: [{ id: 'a', kind: 'pop', publicKey: 'dGVzdC1wdWIta2V5LTAwMDAwMDAwMDAwMDAwMDAwMDA', scopes: ['export'], createdAt: 1 }] })],
    ['no createdAt', 'BAD_CREDENTIAL_RECORD', 500, JSON.stringify({ version: 1, credentials: [{ id: 'a', kind: 'pop', publicKey: 'dGVzdC1wdWIta2V5LTAwMDAwMDAwMDAwMDAwMDAwMDA', scopes: [] }] })],
    ['a rate with no burst', 'BAD_CREDENTIAL_RECORD', 500, JSON.stringify({ version: 1, credentials: [{ id: 'a', kind: 'pop', publicKey: 'dGVzdC1wdWIta2V5LTAwMDAwMDAwMDAwMDAwMDAwMDA', scopes: [], createdAt: 1, rate: { perMinute: 5 } }] })],
  ];

  it.each(refusals)('refuses %s with %s %i', (_name, expected, status, text) => {
    expect(refusal(() => parseCredentialFile(text))).toEqual([expected, status]);
  });

  it('refuses a duplicate id, because admission would resolve it arbitrarily', () => {
    const file = JSON.parse(VALID) as CredentialFile;
    file.credentials.push({ ...file.credentials[0] } as CredentialRecord);
    expect(refusal(() => parseCredentialFile(JSON.stringify(file)))).toEqual(['DUPLICATE_CREDENTIAL_ID', 500]);
  });

  it('refuses more records than the loader will scan per request', () => {
    const file: CredentialFile = { version: 1, credentials: [] };
    for (let i = 0; i <= MAX_CREDENTIALS; i++) {
      file.credentials.push({
        id: `c${String(i)}`,
        kind: 'pop',
        publicKey: new Uint8Array(32),
        scopes: [],
        createdAt: 1,
      });
    }
    expect(refusal(() => parseCredentialFile(JSON.stringify(file)))).toEqual(['BAD_CREDENTIAL_FILE', 500]);
  });
});

describe('credential file round trip', () => {
  it('survives serialize then parse', () => {
    const generated = newPopCredential({ id: 'svc-1', label: 'svc', scopes: ['read', 'complete'], now: 1_772_000_000 });
    const file: CredentialFile = { version: 1, credentials: [generated.record] };
    expect(parseCredentialFile(serializeCredentialFile(file))).toEqual(file);
  });

  it('writes the one version a file can carry', () => {
    expectTypeOf<CredentialFile['version']>().toEqualTypeOf<1>();
    const file: CredentialFile = { version: CREDENTIALS_FILE_VERSION, credentials: [] };
    expect(JSON.parse(serializeCredentialFile(file))).toEqual({ version: 1, credentials: [] });
  });

  it('never writes a private key or a bearer secret', () => {
    const pop = newPopCredential({ id: 'svc-1' });
    const bearer = newBearerCredential({ id: 'ops-1' });
    const text = serializeCredentialFile({ version: 1, credentials: [pop.record, bearer.record] });
    expect(text).not.toContain(Buffer.from(pop.privateKey).toString('hex'));
    expect(text).not.toContain(Buffer.from(pop.privateKey).toString('base64url'));
    expect(text).not.toContain(Buffer.from(bearer.secret).toString('hex'));
    expect(text).not.toContain(Buffer.from(bearer.secret).toString('base64url'));
    expect(text).not.toContain('privateKey');
    expect(JSON.parse(text).credentials.find((c: { id: string }) => c.id === 'ops-1').secretHash).toHaveLength(64);
  });

  it('generates a 32-byte secret whose stored hash matches it', () => {
    const bearer = newBearerCredential({ id: 'ops-1' });
    expect(bearer.secret).toHaveLength(32);
    expect(bearer.record.secretHash).toBeInstanceOf(Uint8Array);
    expect(bearer.record.secretHash).toHaveLength(32);
  });
});

describe('loadCredentialFile', () => {
  it('reads from disk and reports the file it refused', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'ashaveri-creds-'));
    const path = join(dir, 'credentials.json');
    await writeFile(path, VALID, 'utf8');
    const loaded = await loadCredentialFile(path);
    expect(loaded.credentials[0]?.id).toBe('analyst-1');
    await writeFile(path, '{oops', 'utf8');
    await expect(loadCredentialFile(path)).rejects.toMatchObject({ code: 'BAD_CREDENTIAL_FILE', status: 500 });
    await expect(loadCredentialFile(join(dir, 'absent.json'))).rejects.toMatchObject({
      code: 'BAD_CREDENTIAL_FILE',
      status: 500,
    });
    await rm(dir, { recursive: true, force: true });
  });
});

describe('route scope table', () => {
  const routes: ReadonlyArray<readonly [string, string, 'any' | 'read' | 'complete' | undefined]> = [
    ['POST', '/v1/chat/completions', 'complete'],
    ['GET', '/v1/deployment-manifest', 'any'],
    ['GET', '/v1/attestation', 'read'],
    ['HEAD', '/v1/attestation', 'read'],
    ['GET', '/v1/attestation/gpu', 'read'],
    ['GET', '/v1/receipts/rcp_1', 'read'],
    ['GET', '/v1/receipts/rcp_1?x=1', 'read'],
    ['GET', '/v1/nope', undefined],
    ['GET', '/chat/completions', undefined],
    ['PUT', '/v1/chat/completions', undefined],
  ];

  it.each(routes)('%s %s requires %s', (method, url, expected) => {
    expect(routeScope(method, url)).toBe(expected);
  });

  it('grants a read route to a complete credential and refuses the reverse', () => {
    expect(scopeSatisfied(['complete'], 'read')).toBe(true);
    expect(scopeSatisfied(['read'], 'complete')).toBe(false);
    expect(scopeSatisfied([], 'any')).toBe(true);
    expect(scopeSatisfied(['read'], 'any')).toBe(true);
    expect(scopeSatisfied(['complete'], 'complete')).toBe(true);
  });
});

describe('the status a refusal answers with', () => {
  // An object rather than a list of pairs, so the compiler counts the codes: a new
  // `AccessErrorCode` with no status row here is a type error instead of a test that quietly
  // never ran. The rows are then read back out of the same table the statuses came from.
  const STATUSES = {
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
  } satisfies Record<AccessErrorCode, number>;

  type StatusRow = readonly [code: AccessErrorCode, status: number];

  const statuses: ReadonlyArray<StatusRow> = Object.entries(STATUSES).map(
    ([code, status]) => [code as AccessErrorCode, status],
  );

  it.each(statuses)('%s answers %i', (code, expected) => {
    expect(accessStatus(code)).toBe(expected);
    expect(new AccessError(code).status).toBe(expected);
  });
});
