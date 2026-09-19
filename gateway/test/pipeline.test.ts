import { afterAll, describe, expect, it } from 'vitest';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildGateway } from '../src/server.js';
import { CredentialStore, ROUTE_SCOPES, newBearerCredential, type CredentialRecord, type Scope } from '../src/access.js';
import { openMemoryAccessLog } from '../src/aclog.js';
import { CLOCK_SECONDS, credentialFileAt, generated, harness, type Generated, type Harness } from './helpers.js';

const bodies: Record<string, string | null> = {
  'POST /v1/chat/completions': '{"model":"mock-model-1","messages":[{"role":"user","content":"hello"}]}',
  'GET /v1/deployment-manifest': null,
  'GET /v1/attestation': null,
  'GET /v1/attestation/gpu': null,
  'GET /v1/receipts/:id': null,
};

const targets: Record<string, string> = {
  'POST /v1/chat/completions': '/v1/chat/completions',
  'GET /v1/deployment-manifest': '/v1/deployment-manifest',
  'GET /v1/attestation': '/v1/attestation',
  'GET /v1/attestation/gpu': '/v1/attestation/gpu?report_data=ab',
  'GET /v1/receipts/:id': '/v1/receipts/rcp_pipeline_test',
};

const ROUTES = Object.keys(ROUTE_SCOPES);

/** The paths the scope table names, which is the shape the gateway's registration tally reads as. */
const ROUTE_PATHS = new Set(ROUTES.map((route) => route.split(' ')[1]));

/** A key that is not the record's own: well-formed, and wrong, so only the proof can fail. */
const NOT_THE_RECORDS_KEY = new Uint8Array(32).fill(7);

function denyCode(json: Record<string, unknown>): string | undefined {
  const error = json['error'] as { code?: string } | undefined;
  return error?.code;
}

describe('the floor covers every route the instance has', () => {
  const open: Harness[] = [];

  function openWith(credentials: Generated[], extra: CredentialRecord[] = [], allowBearer = false): Promise<Harness> {
    return harness({ credentials, extra, allowBearer }).then((each) => {
      open.push(each);
      return each;
    });
  }

  afterAll(async () => {
    for (const each of open) await each.app.close();
  });

  it('every registered route appears in the scope table, and vice versa', async () => {
    const h = await openWith([]);
    const tree = h.app.printRoutes({ commonPrefix: false });
    const registered = new Set<string>();
    // printRoutes answers with a radix tree, not a list: a line's path is relative to its parent's,
    // and the glyphs that draw one level of branching occupy four columns, so the whole path has to
    // be rebuilt from the ancestors above it before it can name a row of the scope table.
    const ancestors: string[] = [];
    for (const line of tree.split('\n')) {
      const node = /^([│├└─ ]*)(\S+)\s+\(([^)]+)\)$/u.exec(line);
      const [, indent, segment, methods] = node ?? [];
      if (indent === undefined || segment === undefined || methods === undefined) continue;
      const depth = indent.length / 4 - 1;
      ancestors[depth] = segment;
      ancestors.length = depth + 1;
      for (const method of methods.split(', ')) registered.add(`${method} ${ancestors.join('')}`);
    }
    const declared = new Set(ROUTES);
    // printRoutes names HEAD as its own method; the table covers GET, so normalize
    // before comparing rather than adding a row that admits nothing new.
    const normalized = new Set([...registered].map((entry) => (entry.startsWith('HEAD ') ? `GET ${entry.slice(5)}` : entry)));
    for (const route of normalized) expect(declared.has(route), `route ${route} is registered but undeclared`).toBe(true);
    for (const route of declared) expect(normalized.has(route), `route ${route} is declared but not registered`).toBe(true);
  });

  it('the onRoute hook inspected every path the instance registers', async () => {
    const h = await openWith([]);
    // The tally is the only visible trace of the order: a hook registered below the routes would
    // check none of them, and every other assertion in this file would still pass. Comparing the
    // paths rather than their number is what makes the failure name the route that escaped.
    expect(h.app.scopeCheckedRoutes()).toEqual([...ROUTE_PATHS].sort());
  });

  it.each(ROUTES)('%s refuses a request with no credential', async (route) => {
    const [method] = route.split(' ');
    const h = await openWith([]);
    const response = await h.inject({ method: method as string, url: targets[route] as string });
    expect(response.statusCode).toBe(401);
    expect(denyCode(response.json)).toBe('AUTH_MALFORMED');
    expect(response.json['error']).toMatchObject({ type: 'authentication_error' });
  });

  it('an undeclared route stops the process at registration, not at request time', () => {
    const store = new CredentialStore({ file: { version: 1, credentials: [] } });
    const app = buildGateway({ access: store, accessLog: openMemoryAccessLog() });
    expect(() => app.get('/v1/not-in-the-table', async () => ({}))).toThrow(/ROUTE_UNDECLARED/u);
    return app.close();
  });

  it('a path outside the table answers the credential, never the path', async () => {
    const credential = generated('cred-outside-table', ['read']);
    const h = await openWith([credential]);
    // Both halves matter. A request that names no credential is refused for that reason alone, so an
    // anonymous walk cannot tell a scoped path from an unscoped one and this gateway's route list is
    // not readable from outside. The same path with a live credential does reach the scope check, and
    // a row the table never carried admits nothing: the refusal is the credential's, not a hint about
    // what else is here.
    const anonymous = await h.inject({ method: 'GET', url: '/v1/not-in-the-table' });
    expect(anonymous.statusCode).toBe(401);
    expect(denyCode(anonymous.json)).toBe('AUTH_MALFORMED');
    const presented = await h.inject({
      method: 'GET',
      url: '/v1/not-in-the-table',
      headers: h.signFor(credential.record.id, 'GET', '/v1/not-in-the-table', null),
    });
    expect(presented.statusCode).toBe(403);
    expect(denyCode(presented.json)).toBe('SCOPE_DENIED');
  });
});

type State =
  | 'absent-header'
  | 'unknown-credential'
  | 'bearer-presented'
  | 'valid-pop'
  | 'stale-ts'
  | 'forged-signature'
  | 'replayed-nonce'
  | 'insufficient-scope'
  | 'rate-exhausted'
  | 'revoked';

const STATES: readonly State[] = [
  'absent-header',
  'unknown-credential',
  'bearer-presented',
  'valid-pop',
  'stale-ts',
  'forged-signature',
  'replayed-nonce',
  'insufficient-scope',
  'rate-exhausted',
  'revoked',
];

const SCOPE_OF: Record<string, Scope[]> = {
  'POST /v1/chat/completions': ['complete'],
  'GET /v1/deployment-manifest': [],
  'GET /v1/attestation': ['read'],
  'GET /v1/attestation/gpu': ['read'],
  'GET /v1/receipts/:id': ['read'],
};

interface Cell {
  status: number;
  code: string | undefined;
  /** A state this route cannot reach, and why the cell is skipped rather than faked. */
  skip?: string;
}

/**
 * What each mock route answers to a request the floor admitted. The device route says
 * `404` because a mock deployment makes no device claim, and the receipts route says
 * `404` because the id is invented; both are the route's own honest answer through an
 * open floor, which is the point of the cell.
 */
const ADMITTED_STATUS: Record<string, number> = {
  'POST /v1/chat/completions': 200,
  'GET /v1/deployment-manifest': 200,
  'GET /v1/attestation': 200,
  'GET /v1/attestation/gpu': 404,
  'GET /v1/receipts/:id': 404,
};

function admittedStatus(route: string): number {
  const status = ADMITTED_STATUS[route];
  if (status === undefined) throw new Error(`no admitted status for ${route}`);
  return status;
}

function cell(route: string, state: State): Cell {
  const required = ROUTE_SCOPES[route];
  switch (state) {
    case 'absent-header':
      return { status: 401, code: 'AUTH_MALFORMED' };
    case 'unknown-credential':
      // A name this file does not carry is answered exactly as a signature that did not verify, so this
      // cell and `forged-signature` below are one refusal at the HTTP layer.
      return { status: 401, code: 'AUTH_SIGNATURE' };
    case 'bearer-presented':
      // The `Bearer` prefix is turned away by the scheme dispatch, which is a fact about the deployment.
      // The proof-of-possession half of this state names a bearer record, which has no key to verify
      // with, and is answered the same way a failed verification is.
      return { status: 401, code: 'AUTH_SIGNATURE' };
    case 'stale-ts':
      return { status: 401, code: 'AUTH_STALE' };
    case 'forged-signature':
      return { status: 401, code: 'AUTH_SIGNATURE' };
    case 'revoked':
      return { status: 401, code: 'AUTH_REVOKED' };
    case 'replayed-nonce':
      return { status: 409, code: 'NONCE_SEEN' };
    case 'rate-exhausted':
      return { status: 429, code: 'RATE_LIMITED' };
    case 'insufficient-scope':
      // Only a row of `any` has no scope to miss. A `read` row is just as missable as a
      // `complete` one, so skipping it here would leave the scope check ungated at the
      // HTTP layer on three of the five routes.
      return required === 'any'
        ? { status: 0, code: undefined, skip: 'this route accepts any scope, so a scope miss is unreachable' }
        : { status: 403, code: 'SCOPE_DENIED' };
    case 'valid-pop':
      // The route's own answer, which the floor must not disturb.
      return { status: admittedStatus(route), code: undefined };
  }
}

describe('the route matrix: five routes by ten states', () => {
  for (const route of ROUTES) {
    describe(route, () => {
      for (const state of STATES) {
        const expectation = cell(route, state);
        const name = `${state}${expectation.skip === undefined ? '' : ` (skipped: ${expectation.skip})`}`;
        const run = expectation.skip === undefined ? it : it.skip;
        run(name, async () => {
          // Every route in ROUTES has a body entry, so this read is total; the index type still
          // carries `undefined`, and a signer wants `string | null`, so a fixture that ever went
          // missing refuses here by route name rather than reaching the signer with nothing to hash.
          const body = bodies[route];
          if (body === undefined) throw new Error(`pipeline: no request-body fixture for ${route}`);
          const [method] = route.split(' ');
          const suited = state === 'insufficient-scope' ? [] : SCOPE_OF[route] ?? [];
          const credential = generated(`cred-${state}`, suited);
          const records: CredentialRecord[] = [credential.record];
          let allowBearer = false;
          // Its own id, not the PoP credential's: two records under one name would make the
          // refusal this state is about ambiguous about which one it found.
          const bearerId = `cred-${state}-bearer`;
          if (state === 'bearer-presented') {
            allowBearer = false;
            records.push(newBearerCredential({ id: bearerId, scopes: suited, now: CLOCK_SECONDS }).record);
          }
          if (state === 'revoked') credential.record.revokedAt = CLOCK_SECONDS - 1;
          if (state === 'rate-exhausted') credential.record.rate = { perMinute: 1, burst: 1 };
          const h = await harness({ credentials: [credential], extra: records.slice(1), allowBearer });
          const payload = body ?? undefined;
          const headers: Record<string, string> = {};
          if (state === 'absent-header') {
            // nothing to add
          } else if (state === 'unknown-credential') {
            Object.assign(headers, h.signFor('never-issued', method as string, targets[route] as string, body));
          } else if (state === 'bearer-presented') {
            // Two doors, two answers. A `Bearer` header is turned away by the scheme dispatch before any
            // record is looked up, which is a property of the deployment. A proof of possession naming a
            // bearer record is turned away the way a failed verification is, because a bearer record
            // carries no key for the proof to be checked against.
            const byPrefix = await h.inject({
              method: method as string,
              url: targets[route] as string,
              headers: { authorization: 'Bearer dGVzdA' },
              payload,
            });
            expect(byPrefix.statusCode, `${route} / bearer prefix`).toBe(401);
            expect(denyCode(byPrefix.json), `${route} / bearer prefix code`).toBe('AUTH_SCHEME');
            Object.assign(
              headers,
              h.signFor(bearerId, method as string, targets[route] as string, body, { key: NOT_THE_RECORDS_KEY }),
            );
          } else if (state === 'stale-ts') {
            Object.assign(headers, h.signFor(credential.record.id, method as string, targets[route] as string, body, { ts: CLOCK_SECONDS - 121 }));
          } else if (state === 'forged-signature') {
            // The id is one this store carries and the stamp is inside the window, so the request
            // gets as far as the proof itself and fails there. A signature check the HTTP layer
            // never exercises is a signature check a change to `access.ts` can delete unnoticed.
            Object.assign(
              headers,
              h.signFor(credential.record.id, method as string, targets[route] as string, body, {
                key: NOT_THE_RECORDS_KEY,
              }),
            );
          } else if (state === 'revoked' || state === 'insufficient-scope' || state === 'rate-exhausted' || state === 'valid-pop' || state === 'replayed-nonce') {
            Object.assign(headers, h.signFor(credential.record.id, method as string, targets[route] as string, body));
          }
          if (state === 'replayed-nonce') {
            const first = await h.inject({ method: method as string, url: targets[route] as string, headers, payload });
            expect([200, 404]).toContain(first.statusCode);
          }
          if (state === 'rate-exhausted') {
            // A fresh bucket always answers its first take, so the request this cell asserts on has
            // to be the second one. It is signed separately because a reused nonce would be refused
            // as a replay, which empties no bucket and proves nothing about the rate limit.
            const warmup = await h.inject({
              method: method as string,
              url: targets[route] as string,
              headers: h.signFor(credential.record.id, method as string, targets[route] as string, body),
              payload,
            });
            expect(warmup.statusCode).not.toBe(429);
          }
          const response = await h.inject({ method: method as string, url: targets[route] as string, headers, payload });
          expect(response.statusCode, `${route} / ${state}`).toBe(expectation.status);
          if (expectation.code !== undefined) expect(denyCode(response.json), `${route} / ${state} code`).toBe(expectation.code);
          if (state === 'bearer-presented') {
            // What the caller was told and what this gateway decided are two different codes here, and
            // this line is where the second one survives: the response says the proof did not verify,
            // the record says the name it carried is a bearer credential. The id is the caller's own
            // header, so the line keeps it either way.
            expect(h.log.entries().at(-1), `${route} / ${state} record`).toMatchObject({
              cred: bearerId,
              auth: null,
              deny: 'AUTH_SCHEME',
              st: 401,
            });
          }
          if (state === 'stale-ts') {
            // The stamp is read out of the header, so no name has to be known for the id to be: an
            // operator reading a spike of stale requests has to be able to say whose clock is the one
            // off, and the answer they need is in the line.
            expect(h.log.entries().at(-1), `${route} / ${state} record`).toMatchObject({
              cred: credential.record.id,
              deny: 'AUTH_STALE',
              st: 401,
            });
          }
          await h.app.close();
        });
      }
    });
  }
});

describe('what the floor writes and does not write', () => {
  it('logs one record per request, including a rejection, with the fields it decided', async () => {
    const credential = generated('log-1', ['complete']);
    const h = await harness({ credentials: [credential] });
    const payload = '{"model":"mock-model-1","messages":[{"role":"user","content":"hello"}]}';
    const headers = h.signFor('log-1', 'POST', '/v1/chat/completions', payload);
    await h.inject({ method: 'POST', url: '/v1/chat/completions', headers, payload });
    await h.inject({ method: 'GET', url: '/v1/deployment-manifest', headers: {} });
    const entries = h.log.entries();
    expect(entries).toHaveLength(2);
    expect(entries[0]).toMatchObject({ cred: 'log-1', auth: 'pop', scope: 'complete', st: 200, deny: null, m: 'POST', p: '/v1/chat/completions' });
    expect(entries[1]).toMatchObject({ cred: null, auth: null, scope: null, st: 401, deny: 'AUTH_MALFORMED' });
    expect(entries[0]?.nce).toEqual(expect.any(String));
    expect(entries[1]?.nce).toBeNull();
    expect(entries[0]?.dur).toBeGreaterThanOrEqual(0);
    await h.app.close();
  });

  it('names the receipt a read route was asked for, and only on that route', async () => {
    const credential = generated('log-rcp', ['read']);
    const h = await harness({ credentials: [credential] });
    const headers = h.signFor('log-rcp', 'GET', '/v1/receipts/rcp_named_here', null);
    await h.inject({ method: 'GET', url: '/v1/receipts/rcp_named_here', headers });
    expect(h.log.entries()[0]).toMatchObject({ rcp: 'rcp_named_here', st: 404 });
    await h.inject({ method: 'GET', url: '/v1/deployment-manifest', headers: h.signFor('log-rcp', 'GET', '/v1/deployment-manifest', null) });
    expect(h.log.entries().at(-1)).toMatchObject({ rcp: null });
    await h.app.close();
  });

  it('drops the query string from p, so report data never reaches the line', async () => {
    const credential = generated('log-q', ['read']);
    const h = await harness({ credentials: [credential] });
    const target = '/v1/attestation?report_data=deadbeef';
    await h.inject({ method: 'GET', url: target, headers: h.signFor('log-q', 'GET', target, null) });
    const entry = h.log.entries()[0];
    expect(entry?.p).toBe('/v1/attestation');
    expect(JSON.stringify(entry)).not.toContain('deadbeef');
    await h.app.close();
  });

  it('refuses with the code in the body and a Retry-After on the rate case', async () => {
    const credential = generated('log-rate', ['complete']);
    credential.record.rate = { perMinute: 1, burst: 1 };
    const h = await harness({ credentials: [credential] });
    const payload = '{"model":"mock-model-1","messages":[{"role":"user","content":"hello"}]}';
    const first = h.signFor('log-rate', 'POST', '/v1/chat/completions', payload, { nonce: new Uint8Array(16).fill(1) });
    const second = h.signFor('log-rate', 'POST', '/v1/chat/completions', payload, { nonce: new Uint8Array(16).fill(2) });
    expect((await h.inject({ method: 'POST', url: '/v1/chat/completions', headers: first, payload })).statusCode).toBe(200);
    const refused = await h.app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      headers: { ...second, 'content-type': 'application/json' },
      payload,
    });
    expect(refused.statusCode).toBe(429);
    expect(Number(refused.headers['retry-after'])).toBeGreaterThanOrEqual(1);
    await h.app.close();
  });
});

describe('the key a fixture credential is signed with', () => {
  it('derives a different key for two ids of the same length', () => {
    const left = generated('equal-length-a', ['complete']);
    const right = generated('equal-length-b', ['complete']);
    // Same width on purpose: a key read off the length of the id made these two one credential,
    // and an assertion about admitting either was an assertion about the other's key.
    expect(left.record.id).toHaveLength(right.record.id.length);
    expect(left.record.publicKey).not.toEqual(right.record.publicKey);
  });

  it('refuses a header signed for one credential with the key of another of the same length', async () => {
    const mine = generated('equal-length-a', ['complete']);
    const other = generated('equal-length-b', ['complete']);
    const h = await harness({ credentials: [mine] });
    const response = await h.inject({
      method: 'GET',
      url: '/v1/deployment-manifest',
      headers: h.signFor(mine.record.id, 'GET', '/v1/deployment-manifest', null, { key: other.privateKey }),
    });
    expect(response.statusCode).toBe(401);
    expect(denyCode(response.json)).toBe('AUTH_SIGNATURE');
    await h.app.close();
  });
});

describe('the credential file the floor reads before it admits', () => {
  it('takes a revocation on the next request rather than on the next restart', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'ashaveri-pipeline-'));
    const path = join(dir, 'credentials.json');
    const credential = generated('reload-1', ['read', 'complete']);
    try {
      await credentialFileAt(path, [credential.record]);
      const h = await harness({ credentials: [credential], storePath: path });
      // Read once here the way a deployment's start-up read would, so the only reload this
      // request path can be failing on is the one the gateway performs for itself.
      await h.store.reloadIfNeeded();
      const headers = h.signFor('reload-1', 'GET', '/v1/deployment-manifest', null);
      expect((await h.inject({ method: 'GET', url: '/v1/deployment-manifest', headers })).statusCode).toBe(200);
      await credentialFileAt(path, [{ ...credential.record, revokedAt: CLOCK_SECONDS - 1 }]);
      const refused = await h.inject({
        method: 'GET',
        url: '/v1/deployment-manifest',
        headers: h.signFor('reload-1', 'GET', '/v1/deployment-manifest', null),
      });
      expect(refused.statusCode).toBe(401);
      expect(denyCode(refused.json)).toBe('AUTH_REVOKED');
      await h.app.close();
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
