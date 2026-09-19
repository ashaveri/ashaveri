import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  EMPTY_BODY_SHA256_HEX,
  sha256Hex,
  signPopAuthorization,
  toBase64Url,
  type PopFields,
} from '@ashaveri/receipt';
import { CredentialStore } from '../src/access.js';
import {
  ACCESS_RECORD_FIELDS,
  openFileAccessLog,
  parseAccessLine,
  type AccessLog,
} from '../src/aclog.js';
import { buildGateway, type GatewayInstance } from '../src/server.js';
import { generated } from './helpers.js';

/**
 * Two strings that must never be found in the log, one for each way a completion can be answered:
 * buffered, where the body is read as a whole, and streamed, where the reply is hijacked and the
 * bytes leave through a raw socket. Named as canaries so a failure points at the string rather than
 * at a coincidence about the word "content".
 */
const CANARY_PROMPT = 'CANARY-PROMPT-9c1f4e-in-this-string-there-is-a-secret';
const CANARY_STREAM = 'CANARY-STREAM-9c1f4e-in-this-string-there-is-a-secret';

const KEY = generated('canary-1', ['complete', 'read']);
const SORTED_FIELDS = [...ACCESS_RECORD_FIELDS].sort();

/**
 * A proof of possession covers the method, the full request target including its query, and the
 * digest of the exact bytes sent, so the bytes signed and the bytes injected are one string. The
 * stamp is this second rather than the fixture's birthday, because the store here answers on the
 * wall clock and a frozen stamp would be refused as months stale before the signature was read. A
 * request carrying a body also names its media type, because Fastify picks the parser from that
 * header before the pipeline runs and would answer 415 to a signature it never got to read.
 *
 * The id and the key default to the fixture credential; passing them is for a header naming a
 * record this store has never carried, which is the one admission a test can invent without holding
 * anything.
 */
function popHeaders(
  method: string,
  target: string,
  body: string | null,
  nonce: Uint8Array,
  id: string = KEY.record.id,
  key: Uint8Array = KEY.privateKey,
): Record<string, string> {
  const fields: PopFields = {
    ts: Math.floor(Date.now() / 1000),
    nonce,
    method,
    target,
    bodyDigestHex: body === null ? EMPTY_BODY_SHA256_HEX : sha256Hex(new TextEncoder().encode(body)),
  };
  return {
    ...(body === null ? {} : { 'content-type': 'application/json' }),
    authorization: signPopAuthorization(fields, id, key),
    'x-ashaveri-nonce': toBase64Url(nonce),
  };
}

/** Distinct nonces, because the replay key is a credential and a nonce and these share one credential. */
function nonceFilled(byte: number): Uint8Array {
  return new Uint8Array(16).fill(byte);
}

function lines(text: string): string[] {
  return text.split('\n').filter((line) => line.length > 0);
}

let dir: string;
let log: AccessLog;
let app: GatewayInstance;

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), 'ashaveri-canary-'));
  log = await openFileAccessLog({ dir });
  app = buildGateway({
    access: new CredentialStore({ file: { version: 1, credentials: [KEY.record] } }),
    accessLog: log,
  });
});

afterAll(async () => {
  await app.close();
  await log.close();
  await rm(dir, { recursive: true, force: true });
});

/** Every byte the log wrote, read back off the volume rather than out of a test double. */
async function written(): Promise<string> {
  await log.drain();
  const names = await readdir(dir);
  const parts: string[] = [];
  for (const name of names.sort()) {
    parts.push(await readFile(join(dir, name), 'utf8'));
  }
  return parts.join('');
}

describe('what the access log never writes', () => {
  it('holds no prompt byte from a buffered completion', async () => {
    const body = JSON.stringify({
      model: 'mock-model-1',
      messages: [{ role: 'user', content: CANARY_PROMPT }],
    });
    const res = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      headers: popHeaders('POST', '/v1/chat/completions', body, nonceFilled(0x11)),
      payload: body,
    });
    expect(res.statusCode).toBe(200);
    const text = await written();
    expect(text.length).toBeGreaterThan(0);
    expect(text).not.toContain(CANARY_PROMPT);
    expect(text).not.toContain('messages');
    expect(text).not.toContain('"content"');
    expect(text).not.toContain('mock-model-1');
    expect(text).not.toContain('authorization');
    expect(text).not.toContain(toBase64Url(KEY.privateKey));
    // A field added to the twelve would pass every name check above, so this asks for the body's
    // own digest, the value a body-derived field would most plausibly carry.
    expect(text).not.toContain(sha256Hex(new TextEncoder().encode(body)));
    for (const line of lines(text)) {
      // Off the bytes rather than off `parseAccessLine`, whose return value carries the names it
      // chose to read no matter what the line held.
      expect(Object.keys(JSON.parse(line) as Record<string, unknown>).sort()).toEqual(SORTED_FIELDS);
    }
  });

  it('holds no prompt byte from a streamed completion, and one line for each request', async () => {
    const before = lines(await written()).length;
    const body = JSON.stringify({
      model: 'mock-model-1',
      messages: [{ role: 'user', content: CANARY_STREAM }],
      stream: true,
    });
    const streamed = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      headers: popHeaders('POST', '/v1/chat/completions', body, nonceFilled(0x22)),
      payload: body,
    });
    expect(streamed.headers['content-type']).toContain('text/event-stream');
    expect(streamed.body).toContain('data:');
    const refused = await app.inject({ method: 'GET', url: '/v1/deployment-manifest' });
    expect(refused.statusCode).toBe(401);

    const after = lines(await written());
    expect(after).toHaveLength(before + 2);
    expect(after.join('')).not.toContain(CANARY_STREAM);
    expect(after.join('')).not.toContain(sha256Hex(new TextEncoder().encode(body)));
    const admitted = parseAccessLine(after[before] as string);
    const denied = parseAccessLine(after[before + 1] as string);
    expect(admitted).toMatchObject({ cred: 'canary-1', auth: 'pop', st: 200, deny: null, p: '/v1/chat/completions' });
    expect(admitted.nce).not.toBeNull();
    expect(denied).toMatchObject({ cred: null, st: 401, deny: 'AUTH_MALFORMED' });
  });

  it('holds no query string, so report data cannot arrive through a path', async () => {
    const reportData = 'a'.repeat(64);
    const target = `/v1/attestation?report_data=${reportData}`;
    const res = await app.inject({
      method: 'GET',
      url: target,
      headers: popHeaders('GET', target, null, nonceFilled(0x33)),
    });
    expect(res.statusCode).toBe(200);
    const text = await written();
    expect(text).not.toContain(reportData);
    expect(text).not.toContain('report_data');
    expect(parseAccessLine(lines(text).at(-1) as string).p).toBe('/v1/attestation');
  });
});

/**
 * The other side of these bytes: the file an erasure is asked to clean has to hold the lines it
 * means to find. `packages/cli/test/accesslog.test.ts` pins the half where the erasure route reads
 * such a line back and removes it.
 */
describe('what a refusal leaves in the file an erasure reads', () => {
  it('names a collapsed refusal credential on the volume, so an erasure has a line to reach', async () => {
    // The promise this guards is that erasing a credential erases the lines naming it whether or not
    // that credential was ever admitted, and it is worth nothing if the refused name never reaches
    // disk. So this is the real handler and the real writer, read back off the volume: a literal
    // record handed to the writer would prove the writer and leave the refusal untested. A collapsed
    // answer that stopped naming the credential it turned away, or a record that lost the name on
    // its way to the line, is what this would let through.
    const invented = 'canary-never-issued';
    const before = lines(await written()).length;
    const refused = await app.inject({
      method: 'GET',
      url: '/v1/deployment-manifest',
      headers: popHeaders('GET', '/v1/deployment-manifest', null, nonceFilled(0x44), invented, generated(invented, []).privateKey),
    });
    expect(refused.statusCode).toBe(401);
    expect((JSON.parse(refused.body) as { error?: { code?: string } }).error?.code).toBe('AUTH_SIGNATURE');
    const after = lines(await written());
    expect(after).toHaveLength(before + 1);
    expect(parseAccessLine(after.at(-1) as string)).toMatchObject({
      cred: invented,
      auth: null,
      scope: null,
      st: 401,
      deny: 'AUTH_UNKNOWN',
    });
  });
});
