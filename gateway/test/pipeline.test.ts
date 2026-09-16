import { afterAll, describe, expect, it } from 'vitest';
import { buildGateway } from '../src/server.js';
import {
  CredentialStore,
  ROUTE_SCOPES,
  newBearerCredential,
  type CredentialRecord,
  type Scope,
} from '../src/access.js';
import { openMemoryAccessLog } from '../src/aclog.js';
import { CLOCK_SECONDS, generated, harness, type Generated, type Harness } from './helpers.js';

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

  it.each(ROUTES)('%s refuses a request with no credential', async (route) => {
    const [method, pattern] = route.split(' ');
    const h = await openWith([]);
    const response = await h.inject({ method: method as string, url: targets[route] as string });
    expect(response.statusCode).toBe(401);
    expect(denyCode(response.json)).toBe('AUTH_MALFORMED');
    expect(response.json['error']).toMatchObject({ type: 'authentication_error' });
    void pattern;
  });

  it('an undeclared route stops the process at registration, not at request time', () => {
    const store = new CredentialStore({ file: { version: 1, credentials: [] } });
    const app = buildGateway({ access: store, accessLog: openMemoryAccessLog() });
    expect(() => app.get('/v1/not-in-the-table', async () => ({}))).toThrow(/ROUTE_UNDECLARED/u);
    return app.close();
  });
});

type State =
  | 'absent-header'
  | 'unknown-credential'
  | 'bearer-presented'
  | 'valid-pop'
  | 'stale-ts'
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
      return { status: 401, code: 'AUTH_UNKNOWN' };
    case 'bearer-presented':
      return { status: 401, code: 'AUTH_SCHEME' };
    case 'stale-ts':
      return { status: 401, code: 'AUTH_STALE' };
    case 'revoked':
      return { status: 401, code: 'AUTH_REVOKED' };
    case 'replayed-nonce':
      return { status: 409, code: 'NONCE_SEEN' };
    case 'rate-exhausted':
      return { status: 429, code: 'RATE_LIMITED' };
    case 'insufficient-scope':
      return required === 'complete'
        ? { status: 403, code: 'SCOPE_DENIED' }
        : { status: 0, code: undefined, skip: 'this route accepts any scope, so a scope miss is unreachable' };
    case 'valid-pop':
      // The route's own answer, which the floor must not disturb.
      return { status: admittedStatus(route), code: undefined };
  }
}

describe('the route matrix: five routes by nine states', () => {
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
          if (state === 'bearer-presented') {
            allowBearer = false;
            records.push(newBearerCredential({ id: `cred-${state}`, scopes: suited, now: CLOCK_SECONDS }).record);
          }
          if (state === 'revoked') credential.record.revokedAt = CLOCK_SECONDS - 1;
          if (state === 'rate-exhausted') credential.record.rate = { perMinute: 1, burst: 1 };
          const h = await harness({ credentials: [credential], extra: records.slice(1), allowBearer });
          const headers: Record<string, string> = {};
          if (state === 'absent-header') {
            // nothing to add
          } else if (state === 'unknown-credential') {
            Object.assign(headers, h.signFor('never-issued', method as string, targets[route] as string, body));
          } else if (state === 'bearer-presented') {
            headers.authorization = 'Bearer dGVzdA';
          } else if (state === 'stale-ts') {
            Object.assign(headers, h.signFor(credential.record.id, method as string, targets[route] as string, body, { ts: CLOCK_SECONDS - 121 }));
          } else if (state === 'revoked' || state === 'insufficient-scope' || state === 'rate-exhausted' || state === 'valid-pop' || state === 'replayed-nonce') {
            Object.assign(headers, h.signFor(credential.record.id, method as string, targets[route] as string, body));
          }
          const payload = body ?? undefined;
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
