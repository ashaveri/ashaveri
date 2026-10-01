import { afterEach, describe, expect, it } from 'vitest';
import { decodeReceipt, sha256Hex, toHex, type ReceiptPayload } from '@ashaveri/receipt';
import {
  mockDeployment,
  type AttestationBundle,
  type BackendResponse,
  type CompletionBackend,
  type CompletionUsage,
  type Deployment,
} from '../src/index.js';
import { CLOCK_SECONDS, generated, harness, type Generated, type Harness } from './helpers.js';

/**
 * Who writes each member of a signed receipt, measured on a document a running gateway issued.
 *
 * The claim this holds is about authorship and not about what a member could be made to spell. An operator
 * can name a model after a person, and a handle and an ordinary word are the same bytes to a reader, so a
 * statement that no field could be made to carry one is not checkable of any list of fields. What is
 * checkable is where each member's value was taken from, and this file takes it from the only place a
 * reader of a served document can: one issuance, driven with a distinctive token in every slot a caller
 * controls, and the receipt it filed fetched back and decoded by the shipped reader.
 *
 * The slots a caller controls, each filled before a request leaves this file:
 * - the request body's message content (`PROMPT`), and one more copy of the token as the name of a body
 *   member sitting inside the first thirty-two bytes, so a request value that stopped being a digest is
 *   caught rather than hidden among bytes nobody reads;
 * - the `model` the client sends, which is the declared spelling exactly, because admission compares it
 *   whole against the ids this deployment lists and a name outside that list issues nothing; the last cell
 *   shows that refusal, which is why no request spelling can reach `mdl` at all;
 * - the `authorization` header, which names the credential, and that credential id is the token;
 * - the completion text the backend yields (`COMPLETION`), which reaches the client and the response digest;
 * - `x-ashaveri-nonce`, the one header naming bytes the caller chooses, which is the one payload member a
 *   caller does write, at sixteen bytes and no wider.
 *
 * Nothing here reads the gateway's assignments. The document is what `decodeReceipt` hands back for the
 * bytes the route served, and its members are walked by type, so a text member that arrives in the format
 * and is not in `ATTESTED_TEXT_POSITIONS` fails this case rather than passing unlooked-at.
 */

const CANARY = 'CANARY-4f7b2e9a';
const PROMPT = `${CANARY}-prompt-text-never-attested`;
const COMPLETION = `${CANARY}-completion-text-never-attested`;
const NOT_DECLARED = `${CANARY}-model-no-deployment-lists`;

/** What this deployment is configured to say it is. Neither value is reachable from a request. */
const ISSUER = 'ashaveri-provenance-issuer';
const INSTANCE = 'ashaveri-provenance-instance';

/** The model id this deployment declares, and the environment kind it states for its measurement. */
const DECLARED_MODEL = 'mock-model-1';
const DECLARED_TEE = 'software';

/**
 * The address the deployment's attestation provider hands back with one evidence bundle. This repository
 * fixes no such value: `gateway/src/server.ts` copies `url` out of whatever its deployment's provider
 * returned for the report data it was asked to bind, and a live deployment composes it from the platform's
 * own evidence service (`gateway/src/dstack.ts`).
 */
const PROVIDER_URL = 'https://evidence.invalid/provider-chosen-attestation';

/** The name the shipped clock source gives itself, which is the literal at `HOST_CLOCK_SOURCE`. */
const HOST_CLOCK_NAME = 'host clock';

/** The clause each anchor reason opens with, at the one site that builds an anchor (`notTakenInAnchor`). */
const COLLATERAL_REASON_OPEN = 'this gateway takes no collateral into issuance';
const VALIDITY_REASON_OPEN = 'this gateway records no validity context at issuance';

/** One request per arm, each carrying the token twice and inside its first thirty-two bytes. */
const BUFFERED_REQUEST_BODY = `{"${CANARY}":1,"model":"${DECLARED_MODEL}","messages":[{"role":"user","content":"${PROMPT}"}]}`;
const STREAM_REQUEST_BODY = `{"${CANARY}":1,"model":"${DECLARED_MODEL}","messages":[{"role":"user","content":"${PROMPT}"}],"stream":true}`;

/** The bytes this caller names for itself, presented as the nonce header and echoed as `nce`. */
const NONCE = Uint8Array.from({ length: 16 }, (_, i) => i + 1);

const DIGEST_BYTES = 32;
const NONCE_BYTES = 16;

const utf8 = (value: string): Uint8Array => new TextEncoder().encode(value);
const asText = (bytes: Uint8Array): string => new TextDecoder().decode(bytes);

/** Whether these bytes carry the token, read as bytes and not through a decoder's substitutions. */
function carriesToken(bytes: Uint8Array): boolean {
  const needle = utf8(CANARY);
  for (let at = 0; at + needle.length <= bytes.length; at += 1) {
    if (needle.every((one, offset) => bytes[at + offset] === one)) return true;
  }
  return false;
}

type Arm = 'buffered' | 'streamed';
type Scheme = 'none' | 'provenance-v1';

interface Issued {
  readonly arm: Arm;
  /** The marking scheme this gateway was started with, which is what `mk.sch` states. */
  readonly marking: Scheme;
  readonly payload: ReceiptPayload;
  /** The bytes the client was handed, whole: the caller's completion text is inside them. */
  readonly body: Uint8Array;
  readonly requestBody: string;
  /** Every text member of the served document, by the path the reader handed it back at. */
  readonly strings: Map<string, string>;
  /** Every byte member, same. */
  readonly bytes: Map<string, Uint8Array>;
}

/** One walk of one decoded payload, reaching every member of every map and every list inside it. */
function scan(
  node: unknown,
  prefix: readonly string[],
  into: { strings: Map<string, string>; bytes: Map<string, Uint8Array> },
): void {
  if (typeof node === 'string') {
    into.strings.set(prefix.join('.'), node);
    return;
  }
  if (ArrayBuffer.isView(node)) {
    into.bytes.set(prefix.join('.'), new Uint8Array(node.buffer, node.byteOffset, node.byteLength));
    return;
  }
  if (Array.isArray(node)) {
    for (const [at, one] of node.entries()) scan(one, [...prefix, String(at)], into);
    return;
  }
  if (node !== null && typeof node === 'object') {
    for (const [key, value] of Object.entries(node)) scan(value, [...prefix, key], into);
  }
}

/**
 * Every text position a payload of this format carries, named as the format names it, with the site that
 * wrote the value and what that site supplies. Eight of the eleven are the positions
 * `packages/receipt/receipt.cddl` leaves open to a `tstr`. The other three are labels the format closes to
 * an enumeration rather than free text, the environment kind and the two presence states, and they are
 * walked too because a claim about authored text is a claim about every string a document carries.
 *
 * Writing them out is the count this case checks against: a payload that gains a text member this table
 * does not name fails the walk below rather than being skipped by it, which is the only way a claim of this
 * kind keeps its teeth.
 */
const ATTESTED_TEXT_POSITIONS: readonly {
  readonly path: string;
  readonly source: string;
  readonly holds: (issued: Issued, value: string) => void;
}[] = [
  { path: 'iss', source: 'the deployment configuration', holds: (_issued, value) => expect(value).toBe(ISSUER) },
  { path: 'ins', source: 'the deployment configuration', holds: (_issued, value) => expect(value).toBe(INSTANCE) },
  { path: 'mdl', source: 'the model ids the operator declares', holds: (_issued, value) => expect(value).toBe(DECLARED_MODEL) },
  { path: 'att.url', source: "the deployment's attestation provider", holds: (_issued, value) => expect(value).toBe(PROVIDER_URL) },
  { path: 'mk.sch', source: 'the marking scheme this process started with', holds: (issued, value) => expect(value).toBe(issued.marking) },
  { path: 'sd.name', source: 'the clock source named at construction, or the shipped host claim', holds: (_issued, value) => expect(value).toBe(HOST_CLOCK_NAME) },
  { path: 'cva.collateral.reason', source: 'a literal at the one site that builds an anchor', holds: (_issued, value) => expect(value).toContain(COLLATERAL_REASON_OPEN) },
  { path: 'cva.validity.reason', source: 'a literal at the one site that builds an anchor', holds: (_issued, value) => expect(value).toContain(VALIDITY_REASON_OPEN) },
  { path: 'meas.tee', source: 'the deployment configuration, at a label the format enumerates', holds: (_issued, value) => expect(value).toBe(DECLARED_TEE) },
  { path: 'cva.collateral.presence', source: 'a literal at the one site that builds an anchor, at a label the format enumerates', holds: (_issued, value) => expect(value).toBe('not-taken-in') },
  { path: 'cva.validity.presence', source: 'a literal at the one site that builds an anchor, at a label the format enumerates', holds: (_issued, value) => expect(value).toBe('not-taken-in') },
];

/** The marking scheme each arm starts this gateway with, so `mk.sch` is a checked configuration value. */
const MARKINGS: Record<Arm, Scheme> = { buffered: 'none', streamed: 'provenance-v1' };

let session: Harness | undefined;

async function close(): Promise<void> {
  if (session !== undefined) {
    const closing = session;
    session = undefined;
    await closing.app.close();
  }
}

afterEach(close);

/**
 * One real issuance: a gateway built, a request signed and sent, and the receipt it filed fetched back the
 * way a client fetches it. Everything this file asserts is about the served document, so what a reader of a
 * real deployment can check is what fails here.
 */
async function issue(arm: Arm, requestBody: string = arm === 'buffered' ? BUFFERED_REQUEST_BODY : STREAM_REQUEST_BODY): Promise<Issued> {
  await close();
  const marking = MARKINGS[arm];
  const contentType = arm === 'buffered' ? 'application/json' : 'text/event-stream';
  const completionBody =
    arm === 'buffered'
      ? JSON.stringify({
          id: 'chatcmpl-provenance-1',
          object: 'chat.completion',
          created: CLOCK_SECONDS,
          model: DECLARED_MODEL,
          choices: [{ index: 0, message: { role: 'assistant', content: COMPLETION }, finish_reason: 'stop' }],
          usage: { prompt_tokens: 9, completion_tokens: 6, total_tokens: 15 },
        })
      : `data: ${JSON.stringify({
          id: 'chatcmpl-provenance-1',
          object: 'chat.completion.chunk',
          created: CLOCK_SECONDS,
          model: DECLARED_MODEL,
          choices: [{ index: 0, delta: { content: COMPLETION }, finish_reason: 'stop' }],
        })}\n\ndata: [DONE]\n\n`;

  const usage: CompletionUsage = { model: DECLARED_MODEL, promptTokens: 9, completionTokens: 6 };
  const backend: CompletionBackend = {
    async respond(): Promise<BackendResponse> {
      return {
        status: 200,
        contentType,
        chunks: (async function* (): AsyncGenerator<Uint8Array> {
          yield utf8(completionBody);
        })(),
        usage: Promise.resolve(usage),
      };
    },
  };

  // The deployment's attestation provider hands back this bundle. The gateway writes none of it: `issue`
  // takes the document, its stamp and its address from whatever the provider returned for the report data
  // it was asked to bind, which is the one member of a receipt no value in this repository fixes.
  const base: Deployment = mockDeployment({ issuer: ISSUER, instance: INSTANCE, model: DECLARED_MODEL });
  const deployment: Deployment = {
    ...base,
    async attestation(reportData: Uint8Array | null): Promise<AttestationBundle> {
      const bundle = await base.attestation(reportData);
      return { ...bundle, url: PROVIDER_URL };
    },
  };

  const credential: Generated = generated(`${CANARY}-cred`, ['complete', 'read']);
  session = await harness({ credentials: [credential], gateway: { deployment, backend, marking } });

  const target = '/v1/chat/completions';
  const served = await session.app.inject({
    method: 'POST' as 'GET',
    url: target,
    headers: {
      'content-type': 'application/json',
      ...session.signFor(credential.record.id, 'POST', target, requestBody, { nonce: NONCE }),
    },
    payload: requestBody,
  });
  expect(served.statusCode).toBe(200);
  const id = served.headers['x-ashaveri-receipt-id'] as string;
  expect(typeof id).toBe('string');

  const receiptTarget = `/v1/receipts/${id}`;
  const fetched = await session.app.inject({
    method: 'GET',
    url: receiptTarget,
    headers: session.signFor(credential.record.id, 'GET', receiptTarget, null),
  });
  expect(fetched.statusCode).toBe(200);

  const strings = new Map<string, string>();
  const bytes = new Map<string, Uint8Array>();
  const payload = decodeReceipt(new Uint8Array(fetched.rawPayload)).payload;
  scan(payload, [], { strings, bytes });
  return { arm, marking, payload, body: new Uint8Array(served.rawPayload), requestBody, strings, bytes };
}

/** The whole of one issuance's checks: what the caller wrote, and what the document says. */
function check(issued: Issued): void {
  const { payload, strings, bytes } = issued;

  // The token was in every slot this file could fill, and the caller's text reached the client: the digest
  // below is taken over bytes carrying it, so an absence further down is not an absence of input.
  expect(issued.requestBody.slice(0, DIGEST_BYTES)).toContain(CANARY);
  expect(issued.requestBody).toContain(PROMPT);
  expect(asText(issued.body)).toContain(COMPLETION);
  expect(toHex(payload.res)).toBe(sha256Hex(issued.body));

  // None of the text a document states is the caller's. The positions it holds are the positions named
  // above, so a member that arrived in the format and was never looked at fails here by name.
  expect([...strings.keys()].sort()).toEqual([...ATTESTED_TEXT_POSITIONS.map((one) => one.path)].sort());
  expect(strings.size).toBe(ATTESTED_TEXT_POSITIONS.length);
  for (const [path, value] of strings) {
    expect(value, `the text at ${path} carries a caller's words`).not.toContain(CANARY);
  }

  // And no byte member carries them either. The request and the response travel as digests at the widths
  // the format states, and the one member that is not a digest of something is the nonce this caller named.
  expect([...bytes.keys()].filter((one) => !one.startsWith('itm.')).sort()).toEqual(
    ['att.d', 'meas.m', 'mk.d', 'nce', 'req', 'res', 'wts'].sort(),
  );
  for (const [path, value] of bytes) {
    expect(carriesToken(value), `the bytes at ${path} carry a caller's words`).toBe(false);
    expect(value.byteLength, `${path} is not the width the format states`).toBe(path === 'nce' ? NONCE_BYTES : DIGEST_BYTES);
  }
  expect(payload.itm.length).toBeGreaterThan(0);
  expect([...bytes.keys()].filter((one) => one.startsWith('itm.')).length).toBe(payload.itm.length);

  // The caller's own member, stated as the member it is: the sixteen nonce bytes it presented, and no text
  // beside them anywhere in this document.
  expect(toHex(payload.nce)).toBe(toHex(NONCE));

  // Each position holds what the site named beside it supplies.
  for (const row of ATTESTED_TEXT_POSITIONS) {
    const value = strings.get(row.path);
    expect(typeof value, `${row.path}, authored by ${row.source}, is absent`).toBe('string');
    row.holds(issued, value as string);
  }
}

describe('who writes a receipt', () => {
  it('attests a buffered completion in what its deployment wrote and nothing else', async () => {
    check(await issue('buffered'));
  });

  it('attests a streamed completion in what its deployment wrote and nothing else', async () => {
    check(await issue('streamed'));
  });

  it('states one authored text for two callers who asked in different words', async () => {
    // The positive half, and the half that moves the moment a member starts tracking its request: two
    // issuances whose request bytes differ, holding text member for text member identical. A member written
    // out of a caller's words cannot survive this comparison, and the failure names which one moved.
    const buffered = await issue('buffered');
    const streamed = await issue('streamed');
    // The two runs digested different request bytes, so the equality below is one about two issuances and
    // not one about a document copied out twice.
    expect(toHex(streamed.payload.req)).not.toBe(toHex(buffered.payload.req));
    for (const row of ATTESTED_TEXT_POSITIONS) {
      if (row.path === 'mk.sch') continue;
      expect([row.path, buffered.strings.get(row.path)], `${row.path} differs between the two issuances`).toEqual([
        row.path,
        streamed.strings.get(row.path),
      ]);
    }
    expect(buffered.payload.mdl).toBe(streamed.payload.mdl);
  });

  it('issues nothing for a model name this deployment does not declare', async () => {
    // The `model` the client sends is the one caller-controlled slot that could be quoted into a signed
    // document, and admission is where it stops: the requested spelling is compared whole against the ids
    // this deployment lists, and a name outside that list is refused before a key is consulted. A request
    // carrying the token as its model therefore earns no receipt, which is why no request spelling reaches
    // `mdl` at all.
    await close();
    const credential: Generated = generated(`${CANARY}-cred`, ['complete', 'read']);
    session = await harness({ credentials: [credential], gateway: {} });
    const target = '/v1/chat/completions';
    const requestBody = `{"${CANARY}":1,"model":"${NOT_DECLARED}","messages":[{"role":"user","content":"${PROMPT}"}]}`;
    const res = await session.app.inject({
      method: 'POST' as 'GET',
      url: target,
      headers: {
        'content-type': 'application/json',
        ...session.signFor(credential.record.id, 'POST', target, requestBody, { nonce: NONCE }),
      },
      payload: requestBody,
    });
    expect(res.statusCode).toBe(400);
    expect(res.headers['x-ashaveri-receipt-id']).toBeUndefined();
  });
});
