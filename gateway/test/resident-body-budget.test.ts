import { Readable } from 'node:stream';
import net from 'node:net';
import { describe, expect, it } from 'vitest';
import type { CompletionBackend } from '../src/backend.js';
import { mockBackend } from '../src/backend.js';
import { ResidentBodyBudget } from '../src/resident-body.js';
import {
  DEFAULT_REQUEST_BODY_BUDGET_BYTES,
  DEFAULT_REQUEST_BODY_DRAIN_TIMEOUT_MS,
  DEFAULT_REQUEST_BODY_LIMIT_BYTES,
  type GatewayInstance,
} from '../src/server.js';
import { generated, harness, type Harness } from './helpers.js';

/**
 * The resident request-body budget: what one process holds of several request bodies at once, what it charges
 * for that hold, and what it gives back.
 *
 * `gateway/src/resident-body.ts` holds the arithmetic on one integer, and `gateway/src/server.ts` holds where
 * that integer is read, charged and released. The defect class this suite exists for is a leak: a charge that
 * is not given back on some exit leaves the resident figure higher than the process is holding, every request
 * adds to it, and the deployment reaches a state where a budget refuses everything while the traffic looks
 * merely heavy. That failure is invisible to a cell that only checks the refusal, so most of what follows
 * asserts the figure *after* a request is over, and asserts it is exactly the starting number rather than
 * merely small.
 *
 * Every case holds the budget in kilobytes and names the body widths it needs, so nothing here sends a
 * mebibyte: the shipped budget is proved by what a run reads when it states nothing (the cell that compares
 * the two shipped numbers, computed from the constants rather than repeating them) and by the inventory
 * reader in `test/configured-values.test.ts`, which is what pins the fallback site itself.
 *
 * A second family, `where in the arrival the budget is decided`, is written against the *moment* the question
 * is asked rather than the sum it is asked about. The charge is taken datum by datum as an upload arrives, so
 * those cells read this process's own accounting while a caller is still writing, and read the answer off a
 * real socket rather than off the injector: what a refused upload was told, and whether it was told at all, is
 * not observable from a payload handed to the route, and the one defect this branch exists to close was found
 * on a platform and not in a build.
 */

const CREDENTIAL = 'resident';
const MODEL = 'mock-model-1';
const TARGET = '/v1/chat/completions';
/** The budget these cells state: four thousand and ninety-six bytes held at once. */
const BUDGET = 4_096;
/** The size bound beside it, kept far above every body this file sends so the charge is what decides. */
const SIZE_BOUND = 64 * 1024;
/** A body that fits alone in `BUDGET` and leaves room, so the first of two requests is always admitted. */
const FITS = 1_500;
/** A second body that fits the process but not the budget beside `FITS`, so the sum is what refuses. */
const DOES_NOT_FIT = 3_000;
/**
 * The width one datum of a chunked upload arrives at. Three of these past `FITS` cross `BUDGET` on the
 * third, so a cell about *where* the decision is taken has room to say which datum took it.
 */
const CHUNK = 1_000;
/** One mebibyte: the unit the arrival cells state a budget in, so the crossing is a whole number of datums. */
const MEBIBYTE = 1024 * 1024;
/**
 * The width a datum of a real upload arrives at, which is the reader's own buffer rather than a fixture's
 * convenience. Sixteen of these are exactly `MEBIBYTE`, so a 1 MiB budget crosses on the seventeenth.
 */
const DATUM = 64 * 1024;
/** An upload wide enough to outgrow the socket's buffers, so the crossing is not near its end. */
const UPLOAD = 8 * MEBIBYTE;
/**
 * The upload the answer claim is written against: eight times `UPLOAD`, so that what stands between the
 * crossing datum and the end of the body is 63 MiB of bytes no socket pair on this host holds. Measured, not
 * assumed: the cell below was first run at `UPLOAD`, and at that width it passed against a build with the drain
 * disabled, because the whole over-run fitted into the buffers between the two sockets and the caller finished
 * writing before the answer went out. The failure this cell exists to catch is the one the sweep measured,
 * where the caller is still writing when the connection goes, and that needs an upload wider than the pipe.
 */
const REFUSED_UPLOAD = 64 * MEBIBYTE;
/** A drain bound short enough for a cell to wait on and long enough to tell apart from an instant answer. */
const DRAIN_MS = 250;
/** The wait this budget may state, read out of the answer rather than repeated here; see the cell that pins it. */
interface Refusal {
  readonly statusCode: number;
  readonly headers: Record<string, string | string[] | undefined>;
  readonly payload?: string;
  readonly error?: { readonly message?: string; readonly type?: string; readonly code?: string };
}

/**
 * Wait for the resident figure to reach the number a case claims, and fail where it never does.
 *
 * The release is owed on the two events a response's death is announced with, and those land after the answer
 * a caller awaits has resolved, so a bare read here would be a race rather than an assertion. Waiting is
 * honest about it: the figure has to arrive, and a build that never gives the bytes back is exactly the build
 * that never arrives.
 */
async function waitResident(app: GatewayInstance, bytes: number, why: string): Promise<void> {
  for (let attempt = 0; attempt < 250; attempt += 1) {
    if (app.residentBodyBytes() === bytes) return;
    await new Promise((resolve) => setTimeout(resolve, 2));
  }
  throw new Error(
    `never saw ${why}: the process holds ${String(app.residentBodyBytes())} bytes and the case claimed ${String(bytes)}`,
  );
}

/** A JSON completion body of exactly `bytes` bytes, ASCII, so its length is the number the charge is of. */
function requestBody(bytes: number): string {
  const head = `{"model":"${MODEL}","messages":[{"role":"user","content":"`;
  const tail = `"}]}`;
  if (bytes <= head.length + tail.length) throw new Error(`a body of ${String(bytes)} bytes cannot be a completion`);
  return head + 'x'.repeat(bytes - head.length - tail.length) + tail;
}

/** A body whose characters are fewer than its bytes: what the reader holds is the second number. */
function multibyteRequestBody(atLeast: number): string {
  const head = `{"model":"${MODEL}","messages":[{"role":"user","content":"`;
  const tail = `"}]}`;
  const filled = head + 'x'.repeat(atLeast) + tail;
  // Two accents, so the string's own length counts two where the bytes count four.
  return filled.replace('xxx', 'xéé');
}

interface Deferred<T> {
  readonly promise: Promise<T>;
  resolve: (value: T) => void;
}

function deferred<T>(): Deferred<T> {
  let resolve: (value: T) => void = () => undefined;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

/**
 * An upstream that holds every completion it is given until the case releases it, in arrival order.
 *
 * This is how a request is put in a state where the process genuinely holds its bytes: the charge is taken at
 * the reader and the release is owed when the response is finished with, so a cell that wants to see the
 * resident figure of a live request has to keep one alive, and a cell that wants to prove a release happened
 * has to be able to end exactly one of two of them. The backend also records what the process held at the
 * instant each call arrived, which is the only moment the charge is observable from inside a request.
 */
interface Gated {
  readonly backend: CompletionBackend;
  /** Hand the backend the reading it records on arrival, which only exists once the app is built. */
  observe(read: () => number): void;
  calls(): number;
  /** The resident figure at the instant of each arrival, in arrival order. */
  seen(): number[];
  /** Let the oldest completion still held answer. */
  release(): void;
  /** Let every held completion answer, for a cell that ended its request some other way. */
  releaseAll(): void;
}

function gatedBackend(): Gated {
  const inner = mockBackend();
  const waiting: Deferred<void>[] = [];
  const seen: number[] = [];
  let calls = 0;
  let read: () => number = () => {
    throw new Error('the gated upstream was asked before the harness handed it the resident reading');
  };
  return {
    calls: () => calls,
    seen: () => [...seen],
    observe: (fn) => {
      read = fn;
    },
    release: () => waiting.shift()?.resolve(),
    releaseAll: () => {
      while (waiting.length > 0) waiting.shift()?.resolve();
    },
    backend: {
      async respond(raw, request) {
        calls += 1;
        seen.push(read());
        const held = deferred<void>();
        waiting.push(held);
        await held.promise;
        return inner.respond(raw, request);
      },
    },
  };
}

interface Serving {
  readonly h: Harness;
  readonly upstream: Gated;
  /** What this process holds of the budget right now, the same integer the refusals are decided from. */
  resident(): number;
  send(body: string, options?: { headers?: Record<string, string>; sign?: boolean }): Promise<Refusal>;
  /** Wait for a condition the event loop has to reach, and fail the case where it never does. */
  waitFor(what: () => boolean, why: string): Promise<void>;
  /** Wait for the resident figure to fall to the number a cell claims, which is the release being asserted. */
  waitForResident(bytes: number, why: string): Promise<void>;
  close(): Promise<void>;
}

/**
 * A gateway with the budget and the size bound both stated, so a case decides nothing about which number was
 * met: the bound is far above every body here, and only the sum ever refuses. Hand `budget` nothing to leave
 * the option off, which is how the two cells about what a run states at the shell read the environment. Hand
 * `drain` a number to state the bound on the drain of an upload that was refused partway through, which is
 * the third of the three settings this file reads and the one the arrival cells below are written against.
 */
async function serving(
  budget: number | undefined,
  options: { limit?: number; drain?: number } = {},
): Promise<Serving> {
  const upstream = gatedBackend();
  const h = await harness({
    credentials: [generated(CREDENTIAL, ['complete', 'read'])],
    gateway: {
      ...(budget === undefined ? {} : { requestBodyBudgetBytes: budget }),
      requestBodyLimitBytes: options.limit ?? SIZE_BOUND,
      ...(options.drain === undefined ? {} : { requestBodyDrainTimeoutMs: options.drain }),
      backend: upstream.backend,
    },
  });
  upstream.observe(() => h.app.residentBodyBytes());
  async function send(body: string, sendOptions: { headers?: Record<string, string>; sign?: boolean } = {}) {
    const sign = sendOptions.sign ?? true;
    const response = await h.app.inject({
      method: 'POST',
      url: TARGET,
      headers: {
        'content-type': 'application/json',
        ...(sign ? {} : { authorization: 'Ashaveri-PoP credential=nope,ts=1772000000,nonce=abc,signature=deadbeef' }),
        ...(sign ? h.signFor(CREDENTIAL, 'POST', TARGET, body) : {}),
        ...sendOptions.headers,
      },
      payload: body,
    });
    // The route answers every refusal in one envelope, so the shape a caller branches on is read out of the
    // payload rather than off the response object: an answer that was the framework's own word for a body
    // past its bound would show up here as no envelope at all, which is the failure the cells below name.
    let error: Refusal['error'];
    try {
      error = (JSON.parse(response.payload) as { error?: Refusal['error'] }).error;
    } catch {
      error = undefined;
    }
    return {
      statusCode: response.statusCode,
      headers: response.headers as Record<string, string | string[] | undefined>,
      payload: response.payload,
      error,
    } satisfies Refusal;
  }
  async function waitFor(what: () => boolean, why: string): Promise<void> {
    for (let attempt = 0; attempt < 200; attempt += 1) {
      if (what()) return;
      await new Promise((resolve) => setTimeout(resolve, 2));
    }
    throw new Error(`never saw: ${why}`);
  }
  async function waitForResident(bytes: number, why: string): Promise<void> {
    await waitResident(h.app, bytes, why);
  }
  return {
    h,
    upstream,
    resident: () => h.app.residentBodyBytes(),
    send,
    waitFor,
    waitForResident,
    close: async () => {
      upstream.releaseAll();
      await h.app.close();
    },
  };
}

/** The refusal envelope, which is the route's shape for every admission answer and not the framework's. */
function refusalOf(answer: Refusal): Refusal['error'] {
  return answer.error;
}

/** The `retry-after` a refusal answers with, as one value whether the framework handed a list or not. */
function waitOf(answer: Refusal): string | undefined {
  const raw = answer.headers['retry-after'];
  return Array.isArray(raw) ? raw[0] : raw;
}

/**
 * What a caller on the other end of a real socket actually received.
 *
 * This is a different thing from `Refusal`, which is what the in-process injector reports: an injector can
 * never see the half of the failure this record exists for, because it hands the bytes to the route instead
 * of to a socket. Over a socket, an answer that never arrives is not a status code of its own: it is the
 * connection dying while the caller is still writing. So a cell about what a refused upload was *told* has
 * to carry both halves, which status came back and whether the socket had already gone by the time it did.
 * The measurement this suite was written after found the two shapes of answer differing by platform and by
 * nothing in the build, which is exactly the difference an injector hides.
 */
interface WireAnswer {
  /** The status line's number, or nothing where no status line ever arrived. */
  readonly status: number | undefined;
  /** The refusal code inside a whole envelope, or nothing where the envelope never completed. */
  readonly code: string | undefined;
  /** The `retry-after` on the head, read the same way `waitOf` reads it off an injected answer. */
  readonly wait: string | undefined;
  /** True where the socket died, or closed, with no whole answer ever having arrived. */
  readonly reset: boolean;
  /** Every byte that did arrive, for a cell that has to say what the caller was given. */
  readonly raw: string;
}

/** One `Transfer-Encoding: chunked` datum, framed the way the reader on the other end expects it. */
function chunkFrame(data: string): string {
  return `${Buffer.byteLength(data, 'utf8').toString(16)}\r\n${data}\r\n`;
}

/** The zero-length datum that ends a chunked body, and so ends the upload. */
const FINAL_CHUNK = '0\r\n\r\n';

/**
 * What the socket read until it saw a whole answer or died.
 *
 * Resolution is on whichever of those comes first, and that is the point: an answer that arrived and was
 * followed by a reset is a caller that was told, and an answer that never arrived is a caller that was
 * not, which are two different outcomes a status-only report would fold into one.
 */
function collectAnswer(socket: net.Socket): Promise<WireAnswer> {
  return new Promise((resolve) => {
    let got = '';
    let settled = false;
    const read = (died: boolean): void => {
      if (settled) return;
      const head = got.split('\r\n\r\n')[0] ?? '';
      const status = Number(/^HTTP\/1\.[01] (\d{3})/u.exec(head)?.[1]);
      const declared = Number(/content-length: (\d+)/iu.exec(head)?.[1]);
      const body = got.slice(head.length + 4);
      let code: string | undefined;
      try {
        code = (JSON.parse(body) as { error?: { code?: string } }).error?.code;
      } catch {
        code = undefined;
      }
      const complete = Number.isFinite(status) && Number.isFinite(declared) && code !== undefined &&
        Buffer.byteLength(body, 'utf8') >= declared;
      // Not a whole answer yet, and the socket is still up: keep reading. A caller refused mid-write must
      // not be reported as refused by an envelope that has not finished arriving, and a caller whose
      // socket is gone must not be reported as waiting for one that never will.
      if (!complete && !died) return;
      settled = true;
      resolve({
        status: Number.isFinite(status) ? status : undefined,
        code,
        wait: /retry-after: ([^\r]*)/iu.exec(head)?.[1],
        reset: !complete,
        raw: got,
      });
    };
    socket.on('data', (chunk: Buffer) => {
      got += chunk.toString('utf8');
      read(false);
    });
    socket.on('end', () => read(true));
    socket.on('close', () => read(true));
    socket.on('error', () => read(true));
  });
}


/** The request head of a chunked upload: no `content-length`, because the body is arriving as it is read. */
function uploadHead(headers: Record<string, string>): string {
  return (
    `POST ${TARGET} HTTP/1.1\r\n` +
    `host: 127.0.0.1\r\n` +
    `content-type: application/json\r\n` +
    `transfer-encoding: chunked\r\n` +
    `authorization: ${headers['authorization']}\r\n` +
    `x-ashaveri-nonce: ${headers['x-ashaveri-nonce']}\r\n\r\n`
  );
}

describe('the arithmetic on the one integer', () => {
  it('admits a charge that empties the budget exactly, and refuses the byte past it', () => {
    const budget = new ResidentBodyBudget(4_000);
    expect(budget.reserve(4_000).admitted, 'a body that reaches the bound is held, not refused').toBe(true);
    expect(budget.residentBytes, 'and the whole of the budget is now resident').toBe(4_000);
    const second = budget.reserve(1);
    expect(second.admitted, 'the byte past it is refused').toBe(false);
    expect(second.bytes, 'and the refusal says what those bytes were').toBe(1);
    expect(budget.residentBytes, 'a refusal charges nothing, so there is nothing to undo').toBe(4_000);
  });

  it('refuses a body past the whole budget with no wait at all, and a body refused on company with one', () => {
    const budget = new ResidentBodyBudget(1_000);
    const alone = budget.reserve(1_500);
    expect(alone.admitted, 'a body wider than the budget cannot be held by an empty process either').toBe(false);
    expect(alone.retryAfterSeconds, 'and no wait clears it, so none is named').toBeUndefined();
    expect(budget.residentBytes, 'nothing was charged for the refusal').toBe(0);
    const full = new ResidentBodyBudget(1_000);
    full.reserve(900);
    const beside = full.reserve(900);
    expect(beside.admitted, 'this one would fit an emptier process').toBe(false);
    expect(beside.retryAfterSeconds, 'so the answer states a wait').toBeTypeOf('number');
    expect(beside.retryAfterSeconds! >= 1, 'and the wait is a floor a client can act on, never zero').toBe(true);
  });

  it('takes a charge of nothing and refuses a charge that is not a whole number of bytes', () => {
    const budget = new ResidentBodyBudget(1_000);
    expect(budget.reserve(0).admitted, 'an empty body holds nothing, so it is always admitted').toBe(true);
    expect(() => budget.reserve(1.5), 'a fractional charge is not bytes taken in').toThrow(/whole number of bytes/u);
    expect(() => budget.reserve(-1), 'and neither is a negative one').toThrow(/whole number of bytes/u);
  });

  it('refuses to state a budget that is not a positive whole number of bytes', () => {
    for (const stated of [0, -1, 1.5, Number.NaN]) {
      expect(() => new ResidentBodyBudget(stated), String(stated)).toThrow(
        /requestBodyBudgetBytes is [^,]+, and a resident request-body budget is a positive whole number of bytes/u,
      );
    }
    expect(new ResidentBodyBudget(1).limitBytes, 'a budget below one body is a legal statement about a deployment').toBe(1);
  });

  it('gives a release back once, and floors the held figure at zero rather than go negative', () => {
    const budget = new ResidentBodyBudget(1_000);
    budget.reserve(600);
    budget.release(600);
    expect(budget.residentBytes, 'a release returns what the charge took').toBe(0);
    const warnings: unknown[][] = [];
    const emit = process.emitWarning;
    process.emitWarning = ((...args: unknown[]) => {
      warnings.push(args);
    }) as typeof process.emitWarning;
    try {
      budget.release(600);
    } finally {
      process.emitWarning = emit;
    }
    expect(budget.residentBytes, 'a second release moves nothing below zero').toBe(0);
    expect(warnings.map((args) => args[1]), 'and the fault is reported rather than swallowed').toEqual([
      { code: 'ASHAVERI_RESIDENT_BODY_RELEASE_UNDERFLOWS' },
    ]);
  });
});

describe('what the budget holds of a request, and what it gives back', () => {
  it('charges a completion while it is in flight and gives the same figure back when it is served', async () => {
    const s = await serving(BUDGET);
    try {
      expect(s.resident(), 'nothing is resident before a request').toBe(0);
      const inFlight = s.send(requestBody(FITS));
      await s.waitFor(() => s.upstream.calls() === 1, 'the completion reached the upstream');
      expect(s.resident(), 'the process holds this body while the completion runs').toBe(FITS);
      expect(s.upstream.seen()[0], 'and the upstream saw the charge already taken').toBe(FITS);
      s.upstream.release();
      const answer = await inFlight;
      expect(answer.statusCode, 'the completion is served').toBe(200);
      await s.waitForResident(0, 'a normal completion gives its bytes back');
    } finally {
      await s.close();
    }
  });

  it('gives back the figure one request charged and not the sum, while another is still held', async () => {
    const s = await serving(BUDGET);
    try {
      const first = s.send(requestBody(FITS));
      await s.waitFor(() => s.upstream.calls() === 1, 'the first completion is held by the upstream');
      const second = s.send(requestBody(1_200));
      await s.waitFor(() => s.upstream.calls() === 2, 'the second completion is held too');
      expect(s.resident(), 'two bodies are resident at once').toBe(FITS + 1_200);

      // Release the older completion: the figure has to fall by exactly that request's charge, which is the
      // one arithmetic a leak and a double release both hide behind a total that merely looks plausible.
      s.upstream.release();
      const answered = await first;
      expect(answered.statusCode, 'the released completion was served').toBe(200);
      expect(s.resident(), 'the body still in flight is the only thing left resident').toBe(1_200);

      s.upstream.release();
      await second;
      await s.waitForResident(0, 'and the last request gives the rest back');
    } finally {
      await s.close();
    }
  });

  it('gives the charge back when the pipeline refuses the request after the reader took it', async () => {
    const s = await serving(BUDGET);
    try {
      // A well-formed body and a header no credential file can answer to: the bytes are charged at the
      // reader, and the refusal comes after them from the admission line.
      const answer = await s.send(requestBody(FITS), { sign: false });
      expect(answer.statusCode, 'the request is refused on its credential, not on the budget').toBe(401);
      expect(refusalOf(answer)?.code, 'and the code is the admission one').not.toBe('RESIDENT_BODY_BUDGET_EXCEEDED');
      await s.waitForResident(0, 'a refusal raised after the charge still gives the bytes back');
    } finally {
      await s.close();
    }
  });

  it('gives the charge back when the upstream fails', async () => {
    const broken = await harness({
      credentials: [generated(CREDENTIAL, ['complete', 'read'])],
      gateway: {
        requestBodyBudgetBytes: BUDGET,
        requestBodyLimitBytes: SIZE_BOUND,
        backend: {
          async respond() {
            throw new Error('the inference server went away');
          },
        },
      },
    });
    try {
      const response = await broken.app.inject({
        method: 'POST',
        url: TARGET,
        headers: { 'content-type': 'application/json', ...broken.signFor(CREDENTIAL, 'POST', TARGET, requestBody(FITS)) },
        payload: requestBody(FITS),
      });
      expect(response.statusCode, 'a failed upstream is answered as a failure, not as a hold').toBeGreaterThanOrEqual(500);
      await waitResident(broken.app, 0, 'the bytes behind the failed completion are given back');
    } finally {
      await broken.app.close();
    }
  });

  it('gives the charge back when the client goes away while the completion is still running', async () => {
    const s = await serving(BUDGET);
    const socket = new net.Socket();
    try {
      const address = await s.h.app.listen({ port: 0, host: '127.0.0.1' });
      const port = Number(new URL(address).port);
      const body = requestBody(FITS);
      const headers = s.h.signFor(CREDENTIAL, 'POST', TARGET, body);
      await new Promise<void>((resolve, reject) => {
        socket.once('connect', resolve);
        socket.once('error', reject);
        socket.connect(port, '127.0.0.1');
      });
      socket.write(
        `POST ${TARGET} HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-type: application/json\r\ncontent-length: ${String(
          Buffer.byteLength(body),
        )}\r\nauthorization: ${headers['authorization']}\r\nx-ashaveri-nonce: ${headers['x-ashaveri-nonce']}\r\n\r\n${body}`,
      );
      await s.waitFor(() => s.upstream.calls() === 1, 'the body was read and the completion is running');
      expect(s.resident(), 'the process holds the body of a client that has not yet gone away').toBe(FITS);

      // The answer can never be written to a socket that is gone, so `finish` is not the event this exit
      // arrives on: the release has to come from `close`, which is the other half of the pair.
      socket.destroy();
      await s.waitForResident(0, 'a client that went away mid-completion gives its bytes back');
    } finally {
      socket.destroy();
      await s.close();
    }
  });

  it('gives the charge back when a streamed answer ends early', async () => {
    const ending = await harness({
      credentials: [generated(CREDENTIAL, ['complete', 'read'])],
      gateway: {
        requestBodyBudgetBytes: BUDGET,
        requestBodyLimitBytes: SIZE_BOUND,
        backend: {
          async respond() {
            return {
              status: 200,
              contentType: 'text/event-stream',
              // One frame and then the iterator ends: no completion event and no sentinel, so this gateway
              // writes what arrived and stops, having bypassed `onSend` by hijacking the reply.
              chunks: (async function* () {
                yield Buffer.from('data: {"piece":"early"}\n\n');
              })(),
              usage: Promise.resolve({ model: MODEL, promptTokens: 1, completionTokens: 1 }),
            };
          },
        },
      },
    });
    try {
      const body = requestBody(FITS).replace('"}]}', '","stream":true}]}');
      const response = await ending.app.inject({
        method: 'POST',
        url: TARGET,
        headers: { 'content-type': 'application/json', ...ending.signFor(CREDENTIAL, 'POST', TARGET, body) },
        payload: body,
      });
      expect(response.statusCode, 'the frames that arrived were handed on').toBe(200);
      expect(response.payload, 'and the stream ended before any sentinel').not.toContain('[DONE]');
      await waitResident(ending.app, 0, 'a stream that ends early on a hijacked reply still gives its bytes back');
    } finally {
      await ending.app.close();
    }
  });

  it('refuses a second caller and still gives the first one back, which is the leak that looks like load', async () => {
    const s = await serving(BUDGET);
    try {
      const held = s.send(requestBody(FITS));
      await s.waitFor(() => s.upstream.calls() === 1, 'the first completion is in flight');
      const refused = await s.send(requestBody(DOES_NOT_FIT));
      expect(refused.statusCode, 'the second is refused on the sum').toBe(429);
      expect(s.resident(), 'and the refusal charged nothing, so only the first body is held').toBe(FITS);

      s.upstream.release();
      await held;
      await s.waitForResident(0, 'once the first finishes the budget is free again');
      const asking = s.send(requestBody(DOES_NOT_FIT));
      await s.waitFor(() => s.upstream.calls() === 2, 'the request refused on company is now admitted');
      s.upstream.release();
      const next = await asking;
      expect(next.statusCode, 'and it is served, which is what a wait answers').toBe(200);
      await s.waitForResident(0, 'the served request gives its own bytes back too');
    } finally {
      await s.close();
    }
  });
});

describe('the refusal the budget answers with', () => {
  it('refuses the sum past the budget 429 with its own code, and names the four numbers a caller needs', async () => {
    const s = await serving(BUDGET);
    try {
      const held = s.send(requestBody(FITS));
      await s.waitFor(() => s.upstream.calls() === 1, 'one body is resident');
      const answer = await s.send(requestBody(DOES_NOT_FIT));
      expect(answer.statusCode, 'the answer is a 429, not a 413 about the caller own bytes').toBe(429);
      expect(refusalOf(answer), 'the refusal is in the route shape, with an envelope').toBeDefined();
      expect(refusalOf(answer)?.code, 'and it names this refusal').toBe('RESIDENT_BODY_BUDGET_EXCEEDED');
      expect(refusalOf(answer)?.type, 'it keeps the type every answer with a wait already gives').toBe('authentication_error');
      const message = refusalOf(answer)?.message ?? '';
      expect(message, 'the budget').toContain(String(BUDGET));
      expect(message, 'what is resident at the instant the refusal was decided').toContain(String(FITS));
      expect(message, 'what this request asked for').toContain(String(DOES_NOT_FIT));
      expect(message, 'where the number comes from').toContain('ASHAVERI_REQUEST_BODY_BUDGET_BYTES');
      expect(message, 'and the option that states it').toContain('requestBodyBudgetBytes');
      expect(message, 'the shipped default is named too').toContain(String(DEFAULT_REQUEST_BODY_BUDGET_BYTES));
      expect(message, 'the wait is stated as a floor and not as a measurement').toContain('floor');

      // The wait figure is read out of the sentence rather than repeated here, and the header is made to
      // agree with it: a floor stated twice, once in prose and once in `retry-after`, is one number.
      const named = /wait of (\d+) seconds/u.exec(message);
      expect(named, 'the message names the wait it tells the caller to act on').not.toBeNull();
      expect(waitOf(answer), 'the header carries the same figure the sentence does').toBe(named?.[1]);

      s.upstream.release();
      await held;
    } finally {
      await s.close();
    }
  });

  it('issues no receipt, forwards nothing upstream, and records the refusal it answered with', async () => {
    const s = await serving(BUDGET);
    try {
      const held = s.send(requestBody(FITS));
      await s.waitFor(() => s.upstream.calls() === 1, 'the first completion reached the upstream');
      const answer = await s.send(requestBody(DOES_NOT_FIT));
      expect(answer.statusCode, 'the second is refused').toBe(429);
      expect(s.upstream.calls(), 'nothing was sent to the inference server for the refused request').toBe(1);
      expect(answer.headers['x-ashaveri-receipt-id'], 'and no receipt was issued for it').toBeUndefined();

      await s.waitFor(
        () => s.h.log.entries().some((entry) => entry.st === 429),
        'the access line for the refusal is written',
      );
      const lines = s.h.log.entries().filter((entry) => entry.st === 429);
      expect(lines.length, 'one line carries it').toBe(1);
      const line = lines[0]!;
      expect(line.p, 'on the route that was asked for').toBe(TARGET);
      expect(line.cred, 'the refusal named no credential, because it never read one').toBeNull();
      // The field records what this gateway decided about a request, and a request stopped at the reader
      // decided nothing about one. `BODY_TOO_LARGE` is documented with the same emptiness for the same
      // reason, and the status plus that emptiness is what tells the two refusals apart in the log.
      expect(line.deny, 'the deny field stays empty, as every reader-deecided refusal leaves it').toBeNull();
      expect(line.rcp, 'and the line carries no receipt').toBeNull();

      s.upstream.release();
      await held;
    } finally {
      await s.close();
    }
  });

  it('refuses a body past the whole budget with no wait, because no traffic would make room', async () => {
    const narrow = await serving(1_000, { limit: SIZE_BOUND });
    try {
      const answer = await narrow.send(requestBody(2_000));
      expect(answer.statusCode, 'a body the budget cannot hold is refused whatever else is in flight').toBe(429);
      expect(refusalOf(answer)?.code, 'with this code').toBe('RESIDENT_BODY_BUDGET_EXCEEDED');
      expect(waitOf(answer), 'and no `retry-after`, because none would clear it').toBeUndefined();
      const message = refusalOf(answer)?.message ?? '';
      expect(message, 'the sentence says a wait would not help').toContain('no wait clears');
      expect(message, 'and names the number the caller has to come down to').toContain('2000');
      expect(narrow.resident(), 'the refusal charged nothing, so the budget is still empty').toBe(0);
    } finally {
      await narrow.close();
    }
  });

  it('leaves an oversize body to the size bound, and gives back what the arrival charged before it answered', async () => {
    const s = await serving(BUDGET, { limit: 2_048 });
    try {
      const answer = await s.send(requestBody(4_000));
      expect(answer.statusCode, 'a body past the bound this process reads is a 413').toBe(413);
      expect(refusalOf(answer)?.code, 'and the size code, not the budget one').toBe('BODY_TOO_LARGE');
      expect(s.upstream.calls(), 'nothing reached the upstream').toBe(0);
      // This cell used to end by asserting that the budget was never touched, because the charge was taken
      // from a completed body and a body the size bound refused never completed. That sentence is not true
      // of an arrival bound and the cell is not relaxed to keep it saying so: the datum that crossed the
      // size bound is charged as it arrives, because arriving is what the bound is read against, and what
      // the size bound decides is only that the request is not served. So what this pairing holds is the
      // 413 *and* the charge given back, which is the same leak class every other cell in this file is
      // written against, and the reason the wait is a wait rather than a read.
      await s.waitForResident(0, 'the bytes the size bound refused are given back with the answer');
    } finally {
      await s.close();
    }
  });
});

describe('what is charged, rather than what was declared', () => {
  it('charges the bytes that arrived when the caller declared no length at all', async () => {
    const s = await serving(BUDGET);
    try {
      const body = requestBody(FITS);
      // A stream body carries no `Content-Length`, so the only number this process has is the one it reads:
      // a charge taken from a header would be nothing at all here, which is a budget that bounds nothing.
      const response = s.h.app.inject({
        method: 'POST',
        url: TARGET,
        headers: { 'content-type': 'application/json', ...s.h.signFor(CREDENTIAL, 'POST', TARGET, body) },
        payload: Readable.from([Buffer.from(body.slice(0, 512)), Buffer.from(body.slice(512))]),
      });
      await s.waitFor(() => s.upstream.calls() === 1, 'the chunked body was assembled and charged');
      expect(s.resident(), 'the whole of what arrived is resident').toBe(Buffer.byteLength(body));
      s.upstream.release();
      await response;
      await s.waitForResident(0, 'and it all comes back');
    } finally {
      await s.close();
    }
  });

  it('charges the width of the bytes and not the count of characters', async () => {
    const s = await serving(BUDGET);
    try {
      const body = multibyteRequestBody(900);
      const bytes = Buffer.byteLength(body, 'utf8');
      expect(bytes, 'the fixture has to be wider in bytes than in characters').toBeGreaterThan(body.length);
      const inFlight = s.send(body);
      await s.waitFor(() => s.upstream.calls() === 1, 'the body was read and charged');
      expect(s.resident(), 'what the process holds is the byte width').toBe(bytes);
      expect(s.resident(), 'and not the character count a string length would have given').not.toBe(body.length);
      s.upstream.release();
      await inFlight;
      await s.waitForResident(0, 'the same width comes back');
    } finally {
      await s.close();
    }
  });

  it('holds nothing a caller named but did not send, which is the other half of the same rule', async () => {
    const s = await serving(BUDGET);
    const socket = new net.Socket();
    try {
      const address = await s.h.app.listen({ port: 0, host: '127.0.0.1' });
      const port = Number(new URL(address).port);
      const body = requestBody(1_200);
      const headers = s.h.signFor(CREDENTIAL, 'POST', TARGET, body);
      await new Promise<void>((resolve, reject) => {
        socket.once('connect', resolve);
        socket.once('error', reject);
        socket.connect(port, '127.0.0.1');
      });
      // A declared length of five with twelve hundred bytes behind it. The parser keeps its own word, so what
      // this process is ever in a position to hold is the five bytes the caller named, and the rest arrives as
      // the start of a second request rather than as the end of this one. The charge cannot be the larger
      // number because the larger number is never taken in: that is the direction of the lie that would have
      // bought a hold, and the chunked case above is the direction where a header names nothing at all.
      socket.write(
        `POST ${TARGET} HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-type: application/json\r\ncontent-length: 5\r\n` +
          `authorization: ${headers['authorization']}\r\nx-ashaveri-nonce: ${headers['x-ashaveri-nonce']}\r\n\r\n${body}`,
      );
      const answered = await new Promise<string>((resolve) => {
        let got = '';
        socket.on('data', (chunk: Buffer) => {
          got += chunk.toString('utf8');
          if (got.includes('\r\n\r\n')) resolve(got);
        });
        socket.on('close', () => resolve(got));
        socket.on('error', () => resolve(got));
        setTimeout(() => resolve(got), 1_000);
      });
      expect(answered, 'a body that disagrees with its own length is not served').toMatch(/HTTP\/1\.1 [45]\d\d/u);
      expect(s.upstream.calls(), 'and nothing of it reached the inference server').toBe(0);
      await s.waitForResident(0, 'and the budget holds nothing at the end of it');
      expect(s.resident(), 'which is the figure a caller could not have chosen').toBe(0);
    } finally {
      socket.destroy();
      await s.close();
    }
  });
});

describe('where the budget sits in the admission line', () => {
  it('tells an unauthenticated caller the truth about capacity rather than about its credential', async () => {
    const s = await serving(BUDGET);
    try {
      const held = s.send(requestBody(FITS));
      await s.waitFor(() => s.upstream.calls() === 1, 'one body is resident');
      // No credential at all behind the header: the answer this caller gets is the budget's, because the
      // budget reads nothing a caller wrote about who they are and applies alike to everyone.
      const answer = await s.send(requestBody(DOES_NOT_FIT), { sign: false });
      expect(answer.statusCode, 'capacity is answered before the credential is').toBe(429);
      expect(refusalOf(answer)?.code, 'and not an admission refusal').toBe('RESIDENT_BODY_BUDGET_EXCEEDED');
      expect(answer.headers['x-ashaveri-receipt-id'], 'nothing was issued').toBeUndefined();
      s.upstream.release();
      await held;
    } finally {
      await s.close();
    }
  });

  it('refuses at the reader ahead of the route, so no scope and no rate bucket is spent', async () => {
    const s = await serving(BUDGET);
    try {
      const held = s.send(requestBody(FITS));
      await s.waitFor(() => s.upstream.calls() === 1, 'one body is resident');
      const answer = await s.send(requestBody(DOES_NOT_FIT));
      expect(answer.statusCode, 'the refusal is the budget, whoever the caller is').toBe(429);
      const lines = s.h.log.entries().filter((entry) => entry.st === 429);
      expect(lines.length, 'and it is the only line that answer wrote').toBe(1);
      expect(lines[0]?.scope, 'no scope was decided, so the record names none').toBeNull();
      expect(lines[0]?.auth, 'and no credential kind was proved').toBeNull();
      s.upstream.release();
      await held;
    } finally {
      await s.close();
    }
  });

  it('is a second 429 that the log tells apart from the buckets by the reason it leaves out', async () => {
    const s = await serving(BUDGET);
    try {
      const held = s.send(requestBody(FITS));
      await s.waitFor(() => s.upstream.calls() === 1, 'one body is resident');
      const refused = await s.send(requestBody(DOES_NOT_FIT));
      expect(refused.statusCode, 'the budget refused this one').toBe(429);
      const budgetLines = s.h.log.entries().filter((entry) => entry.st === 429);
      expect(
        budgetLines.map((entry) => entry.deny),
        'a 429 with an empty reason is this refusal, and the bucket refusals all name themselves',
      ).toEqual([null]);
      s.upstream.release();
      await held;
    } finally {
      await s.close();
    }
  });
});

describe('the budget a deployment states, three ways', () => {
  /**
   * Hold one completion and ask for a second, and answer with what the second one met.
   *
   * The second request has to be waited for on two different conditions, because a refusal settles it at the
   * reader while an admission leaves it queued behind the first at the upstream. Waiting on only one of those
   * is how a helper that releases nothing hangs a suite, and the figure a release is proved on is the one
   * every request here gives back.
   */
  async function meetSum(s: Serving, first: number, second: number): Promise<Refusal> {
    const before = s.upstream.calls();
    const held = s.send(requestBody(first));
    await s.waitFor(() => s.upstream.calls() === before + 1, 'the first completion is in flight');
    let answered = false;
    const asking = s.send(requestBody(second));
    void asking.then(() => {
      answered = true;
    });
    await s.waitFor(
      () => answered || s.upstream.calls() === before + 2,
      'the second request was either refused at the reader or admitted and held',
    );
    s.upstream.releaseAll();
    const refusal = await asking;
    await held;
    return refusal;
  }

  it('keeps the budget the option states when the environment states another', async () => {
    process.env['ASHAVERI_REQUEST_BODY_BUDGET_BYTES'] = String(BUDGET);
    const wider = BUDGET * 4;
    try {
      const s = await serving(wider);
      try {
        // Both sums sit between the two numbers on purpose: the first is past what the shell stated and
        // inside what the option states, so only the option can serve it, and the second is past the option,
        // so only the option can refuse it and print its own figure. A swap of the two reads in `server.ts`
        // turns the 200 into a 429 and prints the environment in the sentence that follows.
        const inside = await meetSum(s, FITS, DOES_NOT_FIT);
        expect(inside.statusCode, 'a sum the option can hold is served, whatever the shell stated').toBe(200);

        const past = await meetSum(s, 12_000, 8_000);
        expect(past.statusCode, 'and the option is the bound that refuses it').toBe(429);
        expect(
          refusalOf(past)?.message,
          'the sentence prints the option, never the environment',
        ).toContain(`no more than ${String(wider)} bytes`);
        await s.waitForResident(0, 'both completions gave their bytes back');
      } finally {
        await s.close();
      }
    } finally {
      delete process.env['ASHAVERI_REQUEST_BODY_BUDGET_BYTES'];
    }
  });

  it('reads the budget the environment states when no option names one', async () => {
    process.env['ASHAVERI_REQUEST_BODY_BUDGET_BYTES'] = String(BUDGET);
    const s = await serving(undefined);
    try {
      // A sum of four thousand and five hundred bytes is nothing to the shipped budget, so a refusal here can
      // only have come from the variable. This is the whole of the environment-over-default proof, and the
      // cell beside the two shipped constants below is what ties the default arm itself to the source.
      const answer = await meetSum(s, FITS, DOES_NOT_FIT);
      expect(answer.statusCode, 'the stated budget is the one this process holds itself to').toBe(429);
      expect(refusalOf(answer)?.message, 'and the refusal prints it').toContain(`no more than ${String(BUDGET)} bytes`);
      expect(refusalOf(answer)?.message, 'while naming what a run that stated neither reads').toContain(
        String(DEFAULT_REQUEST_BODY_BUDGET_BYTES),
      );
      await s.waitForResident(0, 'the completion that was admitted gave its bytes back');
    } finally {
      await s.close();
      delete process.env['ASHAVERI_REQUEST_BODY_BUDGET_BYTES'];
    }
  });

  it('serves the same sum when neither the option nor the environment states a budget', async () => {
    const s = await serving(undefined);
    try {
      const answer = await meetSum(s, FITS, DOES_NOT_FIT);
      expect(answer.statusCode, 'the shipped budget is far above a sum of kilobytes').toBe(200);
      expect(s.resident(), 'and what was held came back when the answer ended').toBe(0);
    } finally {
      await s.close();
    }
  });

  it('refuses to build on a budget the environment states badly, rather than serving the shipped one', async () => {
    for (const stated of ['not-a-budget', '0', '-1', '1024.5']) {
      process.env['ASHAVERI_REQUEST_BODY_BUDGET_BYTES'] = stated;
      try {
        await expect(
          harness({ credentials: [generated(CREDENTIAL, ['complete', 'read'])] }),
          `a deployment that believes it set ${stated} is not run on another bound`,
        ).rejects.toThrow(
          /ASHAVERI_REQUEST_BODY_BUDGET_BYTES states '[^']*', and a resident request-body budget is a positive whole number of bytes/u,
        );
      } finally {
        delete process.env['ASHAVERI_REQUEST_BODY_BUDGET_BYTES'];
      }
    }
  });

  it('refuses to build on a budget the option states badly, in the words the budget itself gives', async () => {
    for (const stated of [0, -4_096, 1.5]) {
      await expect(
        harness({
          credentials: [generated(CREDENTIAL, ['complete', 'read'])],
          gateway: { requestBodyBudgetBytes: stated },
        }),
        `an option of ${String(stated)} bytes is not a budget`,
      ).rejects.toThrow(
        `requestBodyBudgetBytes is ${String(stated)}, and a resident request-body budget is a positive whole number of bytes`,
      );
    }
  });

  it('leaves one whole request inside the budget it ships, whatever the size bound allows', () => {
    // Both figures are read off the constants, so this recomputes the shipped pairing rather than quoting it:
    // a budget that could not hold the largest body this gateway reads would refuse that body at any traffic,
    // which is the failure `docs/configured-values.md` tells an operator to avoid when they move either number.
    expect(
      DEFAULT_REQUEST_BODY_BUDGET_BYTES > DEFAULT_REQUEST_BODY_LIMIT_BYTES,
      `${String(DEFAULT_REQUEST_BODY_BUDGET_BYTES)} of budget cannot hold a ${String(DEFAULT_REQUEST_BODY_LIMIT_BYTES)} body`,
    ).toBe(true);
  });
});

describe('where in the arrival the budget is decided', () => {
  /**
   * The one cell family that cannot be run through the injector.
   *
   * `send` hands the route a body; these cells are about the bytes between the socket and the route, and
   * about what the caller on the far end of that socket was told. So the arrival is written datum by datum
   * over a real connection, and every figure is read off the gateway's own accounting while the upload is
   * still open, which is the state a charge taken after the body completed never reaches.
   */
  it('charges each datum as it arrives and refuses the one that crosses, before the upload ends', async () => {
    const s = await serving(BUDGET);
    const socket = new net.Socket();
    try {
      const address = await s.h.app.listen({ port: 0, host: '127.0.0.1' });
      const port = Number(new URL(address).port);
      // One body held open at the upstream, so the sum the upload joins is a known 1,500 and not a race
      // with whatever else this process happens to be serving.
      const held = s.send(requestBody(FITS));
      await s.waitFor(() => s.upstream.calls() === 1, 'one body is resident');

      const body = 'x'.repeat(CHUNK * 4);
      await new Promise<void>((resolve, reject) => {
        socket.once('connect', resolve);
        socket.once('error', reject);
        socket.connect(port, '127.0.0.1');
      });
      socket.write(uploadHead(s.h.signFor(CREDENTIAL, 'POST', TARGET, body)));
      const reading = collectAnswer(socket);

      socket.write(chunkFrame(body.slice(0, CHUNK)));
      await s.waitFor(() => s.resident() === FITS + CHUNK, 'the first datum is charged as it arrives');
      socket.write(chunkFrame(body.slice(CHUNK, CHUNK * 2)));
      await s.waitFor(() => s.resident() === FITS + CHUNK * 2, 'and so is the second');
      expect(s.upstream.calls(), 'none of this upload has reached the inference server').toBe(1);

      // The third datum takes the sum past 4,096 and is the one the refusal is decided at. The fourth and
      // the terminator go out behind it because a caller that was refused mid-upload is not a caller that
      // stopped writing, and what the cell is about is the difference between those two.
      socket.write(chunkFrame(body.slice(CHUNK * 2, CHUNK * 3)));
      socket.write(chunkFrame(body.slice(CHUNK * 3)));
      socket.write(FINAL_CHUNK);
      const answer = await reading;
      expect(answer.status, 'the crossing datum is refused').toBe(429);
      expect(answer.code, 'and by name').toBe('RESIDENT_BODY_BUDGET_EXCEEDED');
      expect(answer.reset, 'the caller was given the answer over the socket that asked').toBe(false);

      // Only the held body is left in the sum once the refused upload's own bytes are given back: the two
      // datums that were admitted are released with the request that carried them, and the crossing datum
      // and everything written behind it joined no sum at any point.
      await s.waitFor(() => s.resident() === FITS, 'the refused upload gives back the datums it had charged');
      expect(s.upstream.calls(), 'and nothing of the refused upload was forwarded').toBe(1);

      s.upstream.release();
      await held;
      await s.waitForResident(0, 'and the served request gives its own bytes back beside them');
    } finally {
      socket.destroy();
      await s.close();
    }
  });

  it('answers a caller that is still writing when the decision is taken, on this platform', async () => {
    // The shape the sweep found the answer dividing over: a 64 MiB chunked upload against a 1 MiB budget, so
    // the crossing is the seventeenth datum of 64 KiB and 63 MiB of body is still behind it. The widths are
    // chosen so that the bytes behind the crossing cannot be absorbed between the two sockets, which is what
    // made the answer platform-dependent where it was measured: 56 of 56 refused callers were answered on
    // Linux and 28 of 32 were not on this platform, in the same build with the same bodies. It divides on the
    // platform and not in the build, so the cell has to be run here rather than argued from a Linux column.
    const s = await serving(MEBIBYTE, { limit: REFUSED_UPLOAD + 4 * MEBIBYTE });
    const socket = new net.Socket();
    try {
      const address = await s.h.app.listen({ port: 0, host: '127.0.0.1' });
      const port = Number(new URL(address).port);
      await new Promise<void>((resolve, reject) => {
        socket.once('connect', resolve);
        socket.once('error', reject);
        socket.connect(port, '127.0.0.1');
      });
      const datum = 'x'.repeat(DATUM);
      const body = datum.repeat(REFUSED_UPLOAD / DATUM);
      socket.write(uploadHead(s.h.signFor(CREDENTIAL, 'POST', TARGET, body)));
      const reading = collectAnswer(socket);
      // Written as fast as the socket will take it and never paused, because the thing being proved is that
      // a caller does not have to stop being a caller just because this process decided it would not serve
      // it: the writes behind the crossing are the same writes a client that knew nothing would be making.
      // One datum is repeated rather than one body sliced, so the loop measures the pipe and not a copy.
      let fullest = 0;
      for (let index = 0; index < REFUSED_UPLOAD / DATUM; index += 1) {
        if (!socket.write(chunkFrame(datum))) fullest += 1;
      }
      socket.write(FINAL_CHUNK);
      const answer = await reading;
      expect(answer.raw.slice(0, 40), 'what came back on the socket').toContain('HTTP/1.1');
      expect(answer.reset, 'the upload was not cut off from its answer by its own size').toBe(false);
      expect(answer.status, 'the refused caller is answered with a status').toBe(429);
      expect(answer.code, 'and with the name this gateway defined').toBe('RESIDENT_BODY_BUDGET_EXCEEDED');
      expect(
        fullest,
        'the socket filled while the caller was writing, so this upload reached the caller only because this process went on reading it',
      ).toBeGreaterThan(0);
      expect(s.upstream.calls(), 'nothing of it was forwarded').toBe(0);
      await s.waitForResident(0, 'and the bytes the refusal turned away are not left on the budget');
    } finally {
      socket.destroy();
      await s.close();
    }
  });
});

describe('the drain of an upload the budget refused', () => {
  /**
   * Connect, write `datums` datums of a chunked upload, and then say nothing more.
   *
   * The silence is the cell: a caller that has stopped sending gives the drain no end to wait for, so what
   * answers it can only be the bound, and how long it takes to answer is the figure under test.
   */
  async function stallAnUpload(
    s: Serving,
    datums: number,
  ): Promise<{ readonly socket: net.Socket; readonly reading: Promise<WireAnswer>; readonly body: string }> {
    const address = await s.h.app.listen({ port: 0, host: '127.0.0.1' });
    const port = Number(new URL(address).port);
    const socket = new net.Socket();
    await new Promise<void>((resolve, reject) => {
      socket.once('connect', resolve);
      socket.once('error', reject);
      socket.connect(port, '127.0.0.1');
    });
    // Wider than the crossing by design, so the caller could have gone on: what stops the arrival here is
    // the caller deciding to, and not the body having run out.
    const body = 'x'.repeat(DATUM * (datums + 8));
    socket.write(uploadHead(s.h.signFor(CREDENTIAL, 'POST', TARGET, body)));
    const reading = collectAnswer(socket);
    for (let index = 0; index < datums; index += 1) {
      socket.write(chunkFrame(body.slice(index * DATUM, (index + 1) * DATUM)));
    }
    return { socket, reading, body };
  }

  it('writes the answer for a caller that stops sending, on the bound the environment states', async () => {
    process.env['ASHAVERI_REQUEST_BODY_DRAIN_TIMEOUT_MS'] = String(DRAIN_MS);
    const s = await serving(MEBIBYTE, { limit: UPLOAD + 4 * MEBIBYTE });
    let socket: net.Socket | undefined;
    try {
      // Sixteen datums of a 1 MiB budget is exactly the budget, so the seventeenth is the crossing and the
      // caller falling silent after the twentieth leaves the drain with an end that will never come.
      const stalled = await stallAnUpload(s, 20);
      socket = stalled.socket;
      const before = Date.now();
      const answer = await stalled.reading;
      const elapsed = Date.now() - before;
      expect(answer.status, 'a caller that stopped sending is still answered').toBe(429);
      expect(answer.code, 'by name').toBe('RESIDENT_BODY_BUDGET_EXCEEDED');
      expect(answer.reset, 'and the answer reaches it whole rather than as a dead socket').toBe(false);
      expect(elapsed, 'the answer came from the bound expiring, not from a body that finished').toBeGreaterThanOrEqual(
        DRAIN_MS / 2,
      );
      expect(elapsed, 'and the bound this process waited on is the one the shell stated').toBeLessThan(5_000);
      await s.waitForResident(0, 'the part of a stalled upload that was charged goes back with the answer');
    } finally {
      socket?.destroy();
      await s.close();
      delete process.env['ASHAVERI_REQUEST_BODY_DRAIN_TIMEOUT_MS'];
    }
  });

  it('keeps the drain bound the option states when the environment states another', async () => {
    // The swapped read in `server.ts` is the failure this pairing exists for: with the two reads in the wrong
    // order, the answer arrives at the environment's figure and the elapsed claim below is the one that says
    // so, because the option's bound is the shorter of the two and the cell would otherwise sit out eight
    // seconds of a patience nobody configured.
    process.env['ASHAVERI_REQUEST_BODY_DRAIN_TIMEOUT_MS'] = '8000';
    const s = await serving(MEBIBYTE, { limit: UPLOAD + 4 * MEBIBYTE, drain: DRAIN_MS });
    let socket: net.Socket | undefined;
    try {
      const stalled = await stallAnUpload(s, 20);
      socket = stalled.socket;
      const before = Date.now();
      const answer = await stalled.reading;
      const elapsed = Date.now() - before;
      expect(answer.status, 'the refused caller is answered').toBe(429);
      expect(elapsed, 'the option is the bound this process waited on, not the environment').toBeLessThan(2_000);
      expect(elapsed, 'and it is still a wait rather than an immediate hang-up').toBeGreaterThanOrEqual(DRAIN_MS / 2);
    } finally {
      socket?.destroy();
      await s.close();
      delete process.env['ASHAVERI_REQUEST_BODY_DRAIN_TIMEOUT_MS'];
    }
  });

  it('is the shipped bound when neither the option nor the environment states one', async () => {
    // The cheap half of proving a shipped default is to read it out of a sentence, and the honest half is to
    // show the process waiting on it. This cell asserts the second: two seconds of a stalled upload is a
    // seventh of the shipped bound and a hundred times any figure these cells state, so a build that read a
    // smaller number, or the test's own number, answers inside the window and reddens here.
    const s = await serving(MEBIBYTE, { limit: UPLOAD + 4 * MEBIBYTE });
    let socket: net.Socket | undefined;
    try {
      const stalled = await stallAnUpload(s, 20);
      socket = stalled.socket;
      const early = await Promise.race([
        stalled.reading.then(() => 'answered' as const),
        new Promise((resolve) => setTimeout(() => resolve('waiting'), 2_000)).then(() => 'waiting' as const),
      ]);
      expect(early, `a run that stated neither number waits on ${String(DEFAULT_REQUEST_BODY_DRAIN_TIMEOUT_MS)} ms`).toBe(
        'waiting',
      );
      await s.waitFor(
        () => s.resident() > 0,
        'the stalled upload still holds the datums it was charged while the bound runs',
      );
    } finally {
      socket?.destroy();
      await s.close();
    }
  });

  it('drains the rest of a refused upload without holding or charging a byte of it', async () => {
    // The size bound is set *below* the width of this upload, which is what gives the drain a witness: a build
    // that read the over-run and handed it on instead of dropping it would meet the framework's own refusal at
    // the bound and answer 413 `BODY_TOO_LARGE`, and the code asserted below would not be this gateway's word.
    // With the datum dropped where it is read, the budget's refusal is the only answer this request can get.
    const s = await serving(MEBIBYTE, { limit: 2 * MEBIBYTE });
    const socket = new net.Socket();
    try {
      const address = await s.h.app.listen({ port: 0, host: '127.0.0.1' });
      const port = Number(new URL(address).port);
      await new Promise<void>((resolve, reject) => {
        socket.once('connect', resolve);
        socket.once('error', reject);
        socket.connect(port, '127.0.0.1');
      });
      const datum = 'x'.repeat(DATUM);
      socket.write(uploadHead(s.h.signFor(CREDENTIAL, 'POST', TARGET, datum.repeat(UPLOAD / DATUM))));
      const reading = collectAnswer(socket);
      // Sixteen datums of a 1 MiB budget fill it exactly, so the seventeenth is the crossing and the figure
      // the reads below are taken against is a known one before any of the over-run is written.
      for (let index = 0; index < MEBIBYTE / DATUM; index += 1) {
        socket.write(chunkFrame(datum));
      }
      socket.write(chunkFrame(datum));
      await s.waitFor(() => s.resident() === MEBIBYTE, 'the budget is filled exactly at the crossing datum');

      // Read after every batch rather than on a timer: the drain of seven and a half megabytes over loopback
      // is over in tens of milliseconds, and a sampler on an interval measured here to fire at a quarter of
      // the figure it was watching. The waits below are what give the reads a window inside the drain, and
      // the claim stays an equality for the same reason it always was: a ceiling test that had read nothing
      // would pass, and this one cannot. Both edges are read, because a build that handed the drained bytes
      // back as it went would sit under the figure just as wrongly as one that charged them sits over it.
      let highest = s.resident();
      let lowest = s.resident();
      for (let start = MEBIBYTE + DATUM; start < UPLOAD; start += DATUM * 8) {
        for (let index = 0; index < 8; index += 1) {
          if (start + index * DATUM >= UPLOAD) break;
          socket.write(chunkFrame(datum));
        }
        await new Promise((resolve) => setTimeout(resolve, 0));
        const seen = s.resident();
        highest = Math.max(highest, seen);
        lowest = Math.min(lowest, seen);
      }
      socket.write(FINAL_CHUNK);
      const answer = await reading;
      expect(answer.code, 'the upload was refused by the budget, and not by the size bound under it').toBe(
        'RESIDENT_BODY_BUDGET_EXCEEDED',
      );
      expect(answer.reset, 'and it was answered').toBe(false);
      expect(highest, 'and the seven and a half megabytes of discarded datum behind the crossing joined no sum').toBe(
        MEBIBYTE,
      );
      expect(lowest, 'and none of them was handed back early either, which is the same figure held whole').toBe(
        MEBIBYTE,
      );
      await s.waitForResident(0, 'the accounting is back at its pre-request figure once the answer is written');
      expect(s.resident(), 'which is the same zero the cell started from').toBe(0);
    } finally {
      socket.destroy();
      await s.close();
    }
  });

  it('refuses to build on a drain bound the environment states badly, rather than serving the shipped one', async () => {
    for (const stated of ['not-a-bound', '0', '-1', '1024.5']) {
      process.env['ASHAVERI_REQUEST_BODY_DRAIN_TIMEOUT_MS'] = stated;
      try {
        await expect(
          harness({ credentials: [generated(CREDENTIAL, ['complete', 'read'])] }),
          `a deployment that believes it set ${stated} is not run on another bound`,
        ).rejects.toThrow(
          /ASHAVERI_REQUEST_BODY_DRAIN_TIMEOUT_MS states '[^']*', and a request-body drain bound is a positive whole number of milliseconds/u,
        );
      } finally {
        delete process.env['ASHAVERI_REQUEST_BODY_DRAIN_TIMEOUT_MS'];
      }
    }
  });
});

